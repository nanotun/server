package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/util"
)

// loopbackVPNWebSocketURL 本机 hy2 / REALITY 环回使用的 WebSocket URL（对外启用 TLS 时为 wss）。
func loopbackVPNWebSocketURL(listenAddr, wsPath string, useTLS bool) string {
	port := parseListenPort(listenAddr, ":8080")
	path := normalizeVPNWebSocketPath(wsPath)
	scheme := "ws"
	if useTLS {
		scheme = "wss"
	}
	return fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, port, path)
}

// loopbackVPNWebSocketDialTLS 环回 wss 时使用（本机自签证书无 127.0.0.1 SAN 时校验会失败，进程内固定跳过校验）。
func loopbackVPNWebSocketDialTLS() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
}

func normalizeVPNWebSocketPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return util.DefaultVPNWebSocketPath
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

// serverVPNDataPlaneTLSActive 为 true 时 [server] 监听为 TLS，环回使用 wss。
func serverVPNDataPlaneTLSActive(s *config.ServerConfig) bool {
	if s == nil {
		return false
	}
	return strings.TrimSpace(s.TLSCertFile) != "" && strings.TrimSpace(s.TLSKeyFile) != ""
}

func effectiveVPNWebSocketPath(cfg *config.Config) string {
	p := strings.TrimSpace(cfg.Server.VPNWebSocketPath)
	if p == "" {
		p = strings.TrimSpace(cfg.Server.Path)
	}
	return normalizeVPNWebSocketPath(p)
}

func buildVPNHTTPServeMux(wsPath string, gw *gatewayState, muxEnabled bool, muxOpts *smux.Config) *http.ServeMux {
	path := normalizeVPNWebSocketPath(wsPath)
	mux := http.NewServeMux()

	up := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		// G2(P2-2): VPN 客户端是 native(iOS/macOS/Windows/Linux),WebSocket 握手
		// **不**应携带 Origin header(浏览器才会自动加)。这里严格拒绝任何带 Origin
		// 的 Upgrade —— 挡住所有从浏览器发起的恶意 WS CSRF 尝试。
		// 调试时可临时把这里改 true(改之前请确认你确实需要)。
		CheckOrigin: strictWSCheckOrigin,
	}

	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			logrus.WithField("remote", r.RemoteAddr).WithError(err).Debug("VPN WebSocket Upgrade 失败")
			return
		}
		nc := util.NewWSStreamConn(ws)
		// 清掉 handshakeDeadlineListener 在 accept 时设的握手超时;后续数据面是长连接
		// 不需要 deadline,有应用层 keepalive / TCP keepalive 兜底。
		if dc, ok := nc.(interface{ SetDeadline(time.Time) error }); ok {
			_ = dc.SetDeadline(time.Time{})
		}
		enableTCPKeepAlive(nc)
		// per-connection goroutine:panic 仅影响本连接,不拖垮整进程。
		// nc.Close 在 safeGoroutine 的 recover 之后由 dispatchVPNIncoming 内的
		// defer 链兜底关闭(handleVPNLink 入口处有 defer raw.Close())。
		go safeGoroutine("dispatchVPNIncoming/"+nc.RemoteAddr().String(), func() {
			dispatchVPNIncoming(nc, gw, muxEnabled, muxOpts)
		})
	})

	// /health 改由 startHealthHTTPServer 独立 listener serve(默认 127.0.0.1:8081),
	// **不**再公开在数据面 wss listener 上 —— 防止外网探测 TUN/store 就绪状态。
	// 见 health.go。

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	return mux
}

// startVPNHTTPServer 返回的 cleanup 应在主 shutdown 流程里(SIGTERM 之后)调用,
// 用来给 HTTP 层一个 graceful close 窗口:
//   - 关闭所有 HTTP/1.1 keep-alive idle connection;
//   - **不**等待已经 Upgrade 为 WebSocket 的连接(Go runtime 在 Hijack 之后
//     从 srv 的 activeConns 里移除该 conn,Shutdown 不会跟踪它)—— 这些连接
//     由 vpnLn.Close → Serve 返回 → conn.Close 链路自己结束。
//
// 设置 5s 上限,避免某些卡在 ReadHeader 的恶意慢连接拖死整个进程退出。
func startVPNHTTPServer(ln net.Listener, wsPath string, gw *gatewayState, muxEnabled bool, muxOpts *smux.Config, errCh chan<- error) (cleanup func()) {
	srv := &http.Server{
		Handler:           buildVPNHTTPServeMux(wsPath, gw, muxEnabled, muxOpts),
		ReadHeaderTimeout: 15 * time.Second,
		// G8(P2-8): IdleTimeout 只影响 HTTP/1.1 keep-alive(非 Upgrade 的 GET /);
		// **Upgrade 成功后的 WebSocket 长连接不受此字段影响**(Go runtime 在 Upgrade
		// 时 detach connection,IdleTimeout 不再生效)。设这个值是为了让 monitor 之类
		// 探测完 / 后没读完就走的连接 60s 就清掉,不让它常驻 accept queue。
		IdleTimeout: 60 * time.Second,
	}
	logrus.Infof("VPN：WebSocket 监听 %s，路径 %s（Binary 承载链路帧）", ln.Addr().String(), normalizeVPNWebSocketPath(wsPath))
	// P1-7: VPN HTTP Serve 用 safeGlobalGoroutine 包,与 hysteria / keepalive 三路统一。
	// 这里 panic 极少(net/http 健壮),但万一 handler 内部 panic 漏过 recover middleware
	// 又往上抛,至少能走 graceful shutdown(撤 iptables / 关 TUN)。
	go safeGlobalGoroutine("vpnHTTPServe", globalContextCancel, func() {
		errCh <- srv.Serve(ln)
	})
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil && err != context.DeadlineExceeded {
			logrus.WithError(err).Warn("[vpn-listen] http.Server.Shutdown 报错")
		}
	}
}
