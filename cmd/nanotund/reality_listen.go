package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/sirupsen/logrus"
	"github.com/xtls/reality"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/util"
)

// buildRealityTLSConfig 构建与 Xray-core v26.3.27 GetREALITYConfig 一致的 *reality.Config。
func buildRealityTLSConfig(r *config.RealityConfig) (*reality.Config, error) {
	pk, err := config.DecodeRealityPrivateKey(r.PrivateKey)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{}
	rc := &reality.Config{
		DialContext:            dialer.DialContext,
		Show:                   r.Show,
		Type:                   strings.TrimSpace(r.Type),
		Dest:                   strings.TrimSpace(r.Dest),
		Xver:                   byte(r.Xver),
		PrivateKey:             pk,
		MinClientVer:           nil,
		MaxClientVer:           nil,
		SessionTicketsDisabled: true,
		ServerNames:            make(map[string]bool),
		ShortIds:               make(map[[8]byte]bool),
	}
	if rc.Type == "" {
		rc.Type = "tcp"
	}
	if r.MaxTimeDiffMs > 0 {
		rc.MaxTimeDiff = time.Duration(r.MaxTimeDiffMs) * time.Millisecond
	}

	for _, sn := range r.ServerNames {
		sn = strings.TrimSpace(sn)
		if sn != "" {
			rc.ServerNames[sn] = true
		}
	}
	for _, sid := range r.ShortIds {
		b, err := config.ParseRealityShortID(sid)
		if err != nil {
			return nil, err
		}
		rc.ShortIds[b] = true
	}

	seedB64 := strings.TrimSpace(r.Mldsa65SeedBase64)
	if seedB64 != "" {
		seed, err := decodeMldsa65SeedBase64(seedB64)
		if err != nil {
			return nil, err
		}
		_, key := mldsa65.NewKeyFromSeed(seed)
		rc.Mldsa65Key = key.Bytes()
	}

	return rc, nil
}

func decodeMldsa65SeedBase64(s string) (*[32]byte, error) {
	b, err := config.DecodeRealityMldsa65Seed(s)
	if err != nil {
		return nil, fmt.Errorf("mldsa65_seed_base64 %w", err)
	}
	var out [32]byte
	copy(out[:], b)
	return &out, nil
}

// bridgeRealityToPlainVPN REALITY 握手完成后的明文连接环回本机 [server].listen_addr（WebSocket 数据面）。
// smuxPool 非空时经环回 smux 单会话 OpenStream（与 hy2 共用 pool）；否则每 REALITY 客户端一次 Dial VPN WebSocket。
// 任一侧 io.Copy 结束（对端 EOF 等）时必须同时 Close 两侧，否则另一侧 Copy 会永久阻塞在 Read，
// 导致 localhost:8080 与环回对端长期 ESTABLISHED（斗篷/REALITY 常见泄漏）。
func bridgeRealityToPlainVPN(realityConn net.Conn, vpnListenAddr, vpnWsPath string, smuxPool *loopbackSmuxPool, loopbackWSTLS *tls.Config) {
	// 进入 bridge 时 reality 握手已完成 —— 立即清掉 realityAcceptDeadlineListener 设的
	// 握手 deadline,否则后续业务读写(可能长时间无流量)会因 deadline 到期 EOF。
	_ = realityConn.SetDeadline(time.Time{})
	enableTCPKeepAlive(realityConn)

	var plain io.ReadWriteCloser
	var err error
	if smuxPool != nil {
		var st net.Conn
		st, err = smuxPool.OpenStream()
		if err != nil {
			logrus.WithError(err).Warn("REALITY 经 smux OpenStream 失败")
			_ = realityConn.Close()
			return
		}
		plain = st
	} else {
		tlsOn := loopbackWSTLS != nil
		wsURL := loopbackVPNWebSocketURL(vpnListenAddr, vpnWsPath, tlsOn)
		var ws net.Conn
		ws, err = util.DialVPNWebSocket(wsURL, 15*time.Second, loopbackWSTLS)
		if err != nil {
			logrus.WithError(err).WithField("dial", wsURL).Warn("REALITY 握手成功后环回 VPN WebSocket 失败")
			_ = realityConn.Close()
			return
		}
		enableTCPKeepAlive(ws)
		plain = ws
	}

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = realityConn.Close()
			_ = plain.Close()
		})
	}
	defer closeBoth()

	// P0-2: bridge 两侧 io.Copy 都包 safeGoroutine。io.Copy 自身一般不会 panic,
	// 但底层 net.Conn 在边界场景(reality 库内部 / smux 库 / TLS 拆框)有过 nil deref
	// 历史。万一这里 panic,整个 nanotun 进程会退出 → 所有会话瞬断。
	// safeGoroutine 只 recover + log,不触发全局 shutdown(单条连接挂掉不影响别人)。
	go safeGoroutine("realityBridge/copyOut/"+realityConn.RemoteAddr().String(), func() {
		_, _ = io.Copy(plain, realityConn)
		closeBoth()
	})
	_, _ = io.Copy(realityConn, plain)
	closeBoth()
}

// startRealityVPNListener 在 [reality].listen_addr 非空时启动与 Xray 同栈的 REALITY 监听；
// 握手成功后环回本机 [server] 端口（smuxPool 非空时走 smux stream，与 hy2 一致）。
// 第二返回值为实际上报 TCP 端口（含 listen_addr 为 :0 时由内核分配）；未启用时 close 为 nil、端口为 0。
func startRealityVPNListener(cfg *config.Config, smuxPool *loopbackSmuxPool, loopbackWSTLS *tls.Config) (closeFn func(), tcpPort int, err error) {
	r := &cfg.Reality
	if strings.TrimSpace(r.ListenAddr) == "" {
		return nil, 0, nil
	}
	if err := r.Validate(); err != nil {
		return nil, 0, err
	}
	// xver 合法区间(0/1/2)由 r.Validate() 统一把关(见 config/reality.go),此处不再重复。

	rc, err := buildRealityTLSConfig(r)
	if err != nil {
		return nil, 0, err
	}

	base, err := net.Listen("tcp", strings.TrimSpace(r.ListenAddr))
	if err != nil {
		return nil, 0, err
	}
	if ta, ok := base.Addr().(*net.TCPAddr); ok && ta != nil {
		tcpPort = ta.Port
	}
	// E2(P1-2): REALITY 端口常用 :443 对公网,jump_host_firewall 不保护(见
	// jump_host_firewall.go 顶部 doc)。攻击者大量并发 TCP 连接 + 不完成 REALITY/TLS
	// 握手即可耗尽 goroutine / fd / RAM。两层防御:
	//   1) realityAcceptDeadlineListener 在 Accept() 返回前对 TCP conn 套 15s 截止时间,
	//      bridge 完成 REALITY 握手后由 bridgeRealityToPlainVPN 自己清掉(SetDeadline(time.Time{}));
	//   2) realityConcLimitListener(自定义) 把同时 in-flight 的握手数量封顶,默认 1024。
	//
	// 2026-05-22 fix:**不能**用 `netutil.LimitListener` —— 它返回的 `*limitListenerConn`
	// 只嵌入了 `net.Conn` 接口,没显式 forward `CloseWrite()` 方法,**不实现**
	// `xtls/reality` 库 Server() line 186 `raw.(CloseWriteConn)` 强类型断言所要求的
	// `CloseWriteConn` 接口。type assertion panic → reality 库 line 545 的
	// `defer func() { recover() }()` 静默吃掉 → conn 永远不被 close,内部 goroutine 退出 →
	// client TCP 一直 ESTABLISHED 不读不写,直到 ~90s 后系统 keepalive RST。同时
	// `netutil.LimitListener` 的 sem 槽位也不会被释放(因为 conn.Close 没被调用),
	// 攒到 1024 后 reality listener 完全死掉。
	//
	// 自己写的 `realityConcLimitListener` 显式 forward `CloseWrite()`,绕开断言陷阱。
	limitedBase := &realityAcceptDeadlineListener{Listener: base, handshakeTimeout: realityHandshakeTimeout}
	limitedBase2 := &realityConcLimitListener{
		Listener: limitedBase,
		sem:      make(chan struct{}, realityMaxConcurrent),
	}
	ln := reality.NewListener(limitedBase2, rc)
	vpnLoop := cfg.Server.ListenAddr
	wsPath := cfg.Server.VPNWebSocketPath
	tlsOn := serverVPNDataPlaneTLSActive(&cfg.Server)
	logrus.Infof("VPN：REALITY 监听 %s（对齐 Xray-core v26.3.27），dest=%s；握手成功后环回 %s；node_login 上报 tcp_port=%d，handshake 超时 %s，并发上限 %d", r.ListenAddr, r.Dest, loopbackVPNWebSocketURL(vpnLoop, wsPath, tlsOn), tcpPort, realityHandshakeTimeout, realityMaxConcurrent)
	if ca := strings.TrimSpace(r.ClientAddr); ca != "" {
		logrus.Infof("REALITY client_addr（仅文档/运维）: %s", ca)
	}

	go safeGlobalGoroutine("realityAccept", globalContextCancel, func() {
		// I6: 区分 temporary error 与 fatal error。
		//
		// 之前任何 Accept 错误都直接退监听 → 整个 REALITY 入口对所有客户端不可用。
		// 但实际上很多 Accept 错误是 transient(典型场景):
		//   - EMFILE / ENFILE: 进程或系统 fd 用尽,过几秒回收后能恢复;
		//   - ECONNABORTED: 客户端在 listen backlog 里就 RST,本次 Accept 失败但 listen 仍健康;
		//   - "too many open files": 同 EMFILE。
		// 这些都应该继续 Accept,只是需要 backoff 避免 hot-spin 把 CPU 拉满。
		//
		// 真正 fatal 的(应该退出 accept loop)是 listener 自己 Close —— Close 后 Accept 返
		// 回 net.ErrClosed。globalContext.Done 时我们会主动 ln.Close,这条路径正确退出;
		// 其它任何错误都 backoff 重试,让 REALITY 服务高可用。
		var backoff time.Duration
		const maxBackoff = 1 * time.Second
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					// 主动 Close 路径:静默退出,这是正常 shutdown。
					logrus.Info("REALITY Accept: listener 已关闭,退出 accept loop")
					return
				}
				// transient error:logrus.Warn 后短暂 backoff 再继续。
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
				logrus.WithError(err).Warnf("REALITY Accept 失败,%s 后重试(transient)", backoff)
				select {
				case <-time.After(backoff):
				case <-globalContext.Done():
					return
				}
				continue
			}
			backoff = 0 // 成功 Accept 重置 backoff
			go safeGoroutine("realityBridge/"+c.RemoteAddr().String(), func() {
				bridgeRealityToPlainVPN(c, vpnLoop, wsPath, smuxPool, loopbackWSTLS)
			})
		}
	})

	return func() { _ = ln.Close() }, tcpPort, nil
}

const (
	realityHandshakeTimeout = 15 * time.Second
	realityMaxConcurrent    = 1024
)

// realityAcceptDeadlineListener 在 Accept 返回前给 net.Conn 设 15s 截止时间,防止
// 攻击者大量发起 TCP 连接但不完成 REALITY/TLS 握手把握手 goroutine 拖死。
//
// bridgeRealityToPlainVPN 在握手成功 / 失败后**必须**调用 conn.SetDeadline(time.Time{})
// 清掉,否则后续业务读写会受这个 deadline 影响。当前 reality 库内部完成握手 +
// 我们的 bridge 在 SetupBridge 那一刻清 deadline。
type realityAcceptDeadlineListener struct {
	net.Listener
	handshakeTimeout time.Duration
}

func (l *realityAcceptDeadlineListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.handshakeTimeout > 0 {
		_ = c.SetDeadline(time.Now().Add(l.handshakeTimeout))
	}
	return c, nil
}

// realityConcLimitListener 自己实现的并发限制 listener,语义等价于
// `golang.org/x/net/netutil.LimitListener`,但**显式 forward `CloseWrite()`**
// 方法给底层 `*net.TCPConn`。
//
// 必须自己写而不是用 `netutil.LimitListener` 的原因:
// `xtls/reality.Server()` 在握手前会做 `raw.(CloseWriteConn)` 强类型断言
// (`reality/tls.go:186`,其中 `CloseWriteConn = net.Conn + CloseWrite() error`),
// 用于后面 hijack TCP 流到 dest 的 TCP splicing。
// `netutil.LimitListener` 返回 `*limitListenerConn{net.Conn, release}`,只嵌入
// `net.Conn` 接口而不嵌入具体 `*net.TCPConn`,所以**编译期不暴露 `CloseWrite()`
// 方法**,类型断言运行时 panic。reality 库内部 `defer recover()` 静默吃 panic,
// 导致 conn 永远不被 close,sem 槽位也不释放 —— 同一现象下你会观察到:
//  1. client TCP 建立 + 发 ClientHello + server 仅 kernel ACK,15s 内无任何
//     应用层数据返回(reality 早就 panic 退出 goroutine 了)
//  2. 90 秒后 client 看 `Connection reset by peer (errno 54)`,这是 server
//     side TCP keepalive 触发的兜底 RST
//  3. 累计 ~1024 次后整个 reality listener 完全卡死
type realityConcLimitListener struct {
	net.Listener
	sem chan struct{}
}

func (l *realityConcLimitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &realityConcLimitListenerConn{
		Conn:    c,
		release: func() { <-l.sem },
	}, nil
}

// realityConcLimitListenerConn:wrap net.Conn,close 时释放并发 sem 槽位,
// 并**显式实现 `CloseWrite()`** 让底层 `*net.TCPConn` 的 half-close 暴露出来,
// 使其满足 `xtls/reality.CloseWriteConn` 接口。
type realityConcLimitListenerConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (l *realityConcLimitListenerConn) Close() error {
	err := l.Conn.Close()
	l.releaseOnce.Do(l.release)
	return err
}

// CloseWrite forward 给底层 `*net.TCPConn`/`*net.UnixConn`(均实现此方法)。
// 若底层不实现(不应该发生,base.Accept 返回的是 TCPConn)则降级为 Close。
func (l *realityConcLimitListenerConn) CloseWrite() error {
	if cw, ok := l.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return l.Conn.Close()
}
