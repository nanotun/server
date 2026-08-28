package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// healthAllowPublicEnv 环境变量名:设为 "1" 时允许把 /health 暴露到非环回地址。
// 兜底逃生口 —— 但默认 P1-9 加固后非环回直接拒启。
const healthAllowPublicEnv = "NANOTUN_HEALTH_ALLOW_PUBLIC"

// startHealthHTTPServer 起一个独立的 HTTP 服务,专门 serve /health readiness probe。
//
// 设计原则:
//   - **不**和 VPN 数据面 wss 共用 listener,避免外网探测 TUN/store 就绪状态;
//   - 默认监听 127.0.0.1:8081,k8s/lb 通过 sidecar 反代或 ssh forward 拉;
//   - addr 留空 → 不启动;
//   - 非环回地址 → 默认**拒启**(P1-9),除非显式设 `NANOTUN_HEALTH_ALLOW_PUBLIC=1`
//     这一逃生口给极少数运维场景(如 k8s 同 namespace pod 互探,但仍强烈建议改走 sidecar)。
//
// 历史行为:之前只 Warn 不拒,有运维误配 0.0.0.0:8081 把就绪状态(TUN ready / store ready)
// 反射到公网,被扫描器拿来做指纹识别 / 锁定攻击窗口(故障期更容易撞墙)。
//
// 返回 cleanup func,main 中加入 defer 链。listener 起失败仅 Warn(健康检查丢了不阻塞业务)。
func startHealthHTTPServer(addr string, gw *gatewayState) (cleanup func()) {
	if strings.TrimSpace(addr) == "" {
		logrus.Info("[health] health_listen_addr is empty, health endpoint not enabled")
		return func() {}
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		logrus.Warnf("[health] health_listen_addr %q cannot be parsed, health endpoint not started: %v", addr, err)
		return func() {}
	}
	if !isLoopbackHost(host) {
		if !healthAllowPublicFromEnv() {
			logrus.WithFields(logrus.Fields{
				"addr": addr,
				"env":  healthAllowPublicEnv,
			}).Error("[health] refusing to start /health on a non-loopback address (P1-9 hardening); if exposure is really required set NANOTUN_HEALTH_ALLOW_PUBLIC=1, but 127.0.0.1:port + an internal reverse proxy is strongly recommended instead")
			return func() {}
		}
		logrus.Warnf("[health] health endpoint listening on non-loopback address %s (force-enabled via %s): the public internet can probe TUN/store readiness, prefer 127.0.0.1:port + an internal reverse proxy", addr, healthAllowPublicEnv)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           newHealthMux(gw),
		ReadHeaderTimeout: 5 * time.Second,
		// /health 本身就是探活,允许复用 keep-alive 减少 monitoring 对端的 TCP overhead。
		IdleTimeout: 60 * time.Second,
	}

	go safeGlobalGoroutine("healthHTTP", globalContextCancel, func() {
		logrus.Infof("[health] /health endpoint listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Warn("[health] HTTP server exited")
		}
	})

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// newHealthMux 建 /health 与 /metrics 的路由。单独抽出来是为了能不占端口地测处理器本身。
func newHealthMux(gw *gatewayState) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tunReady := sharedTUN != nil
		storeReady := gw == nil || gw.store == nil || gw.store.DB() != nil
		ok := tunReady && storeReady
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		fmt.Fprintf(w, `{"ok":%t,"tun":%t,"store":%t}`, ok, tunReady, storeReady)
	})
	// J3(2026-05-22):/metrics 走 Prometheus 文本格式(OpenMetrics 子集),
	// 复用已有的 counters,不引入 prometheus/client_golang 重依赖。
	// 同样限制在 health endpoint 之下,默认 127.0.0.1:8081 不外暴。
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writePrometheusMetrics(w, gw)
	})

	return mux
}

func isLoopbackHost(host string) bool {
	// 空 host 是 ":8081" 这种简写解析出来的,含义是**绑所有网卡**,不是环回。
	// 此前它被当成环回放行,于是 P1-9 那道「非环回拒启」只挡得住显式写的
	// 0.0.0.0:8081 / [::]:8081,却对最常用的 :8081 视而不见 —— 正是它要防的那种误配。
	// (addr 整体为空的情况调用方已先行返回,走不到这里。)
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// healthAllowPublicFromEnv 读 NANOTUN_HEALTH_ALLOW_PUBLIC,接受 "1" / "true" / "yes"
// (大小写不敏感,首尾去空格)。其它任何值都按「不允许」。
func healthAllowPublicFromEnv() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(healthAllowPublicEnv)))
	return v == "1" || v == "true" || v == "yes"
}
