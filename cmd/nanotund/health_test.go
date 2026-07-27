package main

// /health 与 /metrics 这层外壳的测试。
//
// 这两个端点会把 TUN / store 的就绪状态和全套运行指标吐出来,所以「绑在哪个地址上」
// 本身就是安全决策:P1-9 之后非环回地址默认拒启。但那道判断此前没有任何测试。

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestIsLoopbackHost 锁住「这个监听地址算不算只对本机开放」的判断。
//
// 关键用例是 ":8081" —— Go 里最常见的「绑所有网卡」简写,SplitHostPort 解出来
// host 是空串。它曾经被当成环回放行,于是 P1-9 那道加固只挡得住显式写的
// 0.0.0.0 / [::],对最常用的那种写法视而不见,而三者绑定行为完全相同。
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
		why  string
	}{
		{"127.0.0.1", true, "标准 IPv4 环回"},
		{"::1", true, "标准 IPv6 环回"},
		{"127.0.0.2", true, "整个 127/8 都是环回"},
		{"localhost", true, "习惯写法"},
		{"", false, "\":8081\" 的简写,绑所有网卡"},
		{"0.0.0.0", false, "显式通配"},
		{"::", false, "显式 IPv6 通配"},
		{"10.0.0.1", false, "内网地址,不是环回"},
		{"1.2.3.4", false, "公网地址"},
		{"example.com", false, "域名一律不当环回"},
	}
	for _, c := range cases {
		t.Run(c.host+"/"+c.why, func(t *testing.T) {
			if got := isLoopbackHost(c.host); got != c.want {
				t.Errorf("isLoopbackHost(%q)=%v,期望 %v(%s)", c.host, got, c.want, c.why)
			}
		})
	}
}

// TestStartHealthHTTPServer_RefusesWildcardBind 从**外部行为**确认通配地址起不来。
//
// 上面那条测的是判断函数,这条测的是它真的被接在了拒启分支上:
// startHealthHTTPServer 若在非环回地址上放行,端口就会被真正占住。
// 用一个固定端口来观察 —— 起得来就说明加固失效了。
func TestStartHealthHTTPServer_RefusesWildcardBind(t *testing.T) {
	t.Setenv(healthAllowPublicEnv, "") // 确保逃生口是关的

	for _, addr := range []string{":19631", "0.0.0.0:19632", "[::]:19633"} {
		t.Run(addr, func(t *testing.T) {
			cleanup := startHealthHTTPServer(addr, nil)
			defer cleanup()

			// 必须**给它时间起**再判定。服务是在 goroutine 里 ListenAndServe 的,
			// 起完就立刻探端口的话,探到「没监听」只是因为跑得比它快 ——
			// 这样即便加固失效测试也照样绿(验证时实测到过这个假绿)。
			if waitFor(2*time.Second, func() bool { return portIsListening(addr) }) {
				t.Errorf("health 在通配地址 %s 上起来了 —— TUN/store 就绪状态与全套运行指标暴露到公网,"+
					"这正是 P1-9 要挡的误配", addr)
			}
		})
	}
}

// TestStartHealthHTTPServer_AllowsLoopback 环回地址应当正常启动,别把加固做过头。
func TestStartHealthHTTPServer_AllowsLoopback(t *testing.T) {
	t.Setenv(healthAllowPublicEnv, "")

	const addr = "127.0.0.1:19634"
	cleanup := startHealthHTTPServer(addr, nil)
	defer cleanup()

	if !waitFor(5*time.Second, func() bool { return portIsListening(addr) }) {
		t.Errorf("health 在环回地址 %s 上没能启动 —— 加固误伤了正常配置", addr)
	}
}

// TestHealthAllowPublicFromEnv 逃生口的取值语义。
// 写错值(比如 "on"、"TRUE " 之外的东西)时必须按「不允许」处理,不能宽进。
func TestHealthAllowPublicFromEnv(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"1", true}, {"true", true}, {"TRUE", true}, {"yes", true},
		{" 1 ", true}, {"Yes", true},
		{"", false}, {"0", false}, {"false", false},
		{"on", false}, {"enable", false}, {"2", false}, {"y", false},
	}
	for _, c := range cases {
		t.Run("值="+c.val, func(t *testing.T) {
			t.Setenv(healthAllowPublicEnv, c.val)
			if got := healthAllowPublicFromEnv(); got != c.want {
				t.Errorf("%s=%q 时 healthAllowPublicFromEnv()=%v,期望 %v",
					healthAllowPublicEnv, c.val, got, c.want)
			}
		})
	}
}

// TestHealthMux_RejectsWriteMethods /health 与 /metrics 都是只读观测端点,
// 不该响应写方法。GET/HEAD 之外一律 405。
func TestHealthMux_RejectsWriteMethods(t *testing.T) {
	mux := newHealthMux(nil)

	for _, path := range []string{"/health", "/metrics"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			t.Run(method+path, func(t *testing.T) {
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
				if rec.Code != http.StatusMethodNotAllowed {
					t.Errorf("%s %s 返回 %d,期望 405", method, path, rec.Code)
				}
			})
		}
	}
}

// TestHealthMux_ReportsNotReadyWithoutTUN TUN 没就绪时 /health 必须返回 503。
//
// 这条决定了负载均衡器会不会把流量打到一个还没准备好的节点上,
// 返回 200 的话滚动升级期间会有一段时间把客户端往黑洞里送。
func TestHealthMux_ReportsNotReadyWithoutTUN(t *testing.T) {
	prev := sharedTUN
	sharedTUN = nil
	t.Cleanup(func() { sharedTUN = prev })

	mux := newHealthMux(nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("TUN 未就绪时 /health 返回 %d,期望 503 —— 负载均衡会把流量打到没准备好的节点上", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"ok":false`) || !strings.Contains(body, `"tun":false`) {
		t.Errorf("TUN 未就绪时响应体是 %s,应当如实报告 ok=false tun=false", body)
	}
}

// TestHealthMux_MetricsServesPrometheusText /metrics 要吐出 Prometheus 文本格式,
// 且带上正确的 Content-Type —— 抓取端靠它决定怎么解析。
func TestHealthMux_MetricsServesPrometheusText(t *testing.T) {
	mux := newHealthMux(nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics 返回 %d,期望 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type 是 %q,期望 text/plain 开头(Prometheus 文本格式)", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, "# TYPE") {
		t.Errorf("响应体里没有 \"# TYPE\",不像 Prometheus 文本格式:%.200s", body)
	}
}

// portIsListening 探一下这个地址能不能连上。用于判断服务到底起没起。
func portIsListening(addr string) bool {
	// 通配地址从本机连要换成环回来连。
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
