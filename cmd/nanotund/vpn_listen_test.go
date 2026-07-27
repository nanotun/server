package main

// VPN 数据面的**外壳**测试:HTTP 路由 + WebSocket Upgrade。
//
// 为什么单独写这一层:所有走连接路径的既有测试都是 net.Pipe 直接喂给 handleVPNLink,
// 这么做很划算(快、能配合 -race、不需要真 TUN 和 root),代价是 TLS、HTTP 路由、
// WebSocket Upgrade、Origin 校验这一整层外壳在每一个 Go 测试里都被绕过了。
// 三机 e2e 会跑到它,但只跑走得通的路径,从不试探「外壳收到意料之外的东西会怎样」。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ── Origin 校验 ─────────────────────────────────────────────────────────────

// TestStrictWSCheckOrigin 锁住 Origin 校验的语义。
//
// 这是一道**安全控制**:VPN 客户端都是原生程序(iOS/macOS/Windows/Linux),
// WebSocket 握手不会带 Origin;只有浏览器才会自动加。因此「带 Origin 就拒绝」
// 恰好挡住所有从浏览器发起的 WS CSRF —— 恶意页面无法伪造或删除这个头。
//
// 之所以值得为一行代码写测试:它的实现注释里明写着「调试时可临时把这里改 true」。
// 真有人改了忘了改回来,没有任何东西会拦住,而放开之后任何网页都能拿受害者的
// 网络身份去连 VPN 数据面。
func TestStrictWSCheckOrigin(t *testing.T) {
	cases := []struct {
		name      string
		setOrigin bool
		origin    string
		want      bool
	}{
		{"原生客户端不带 Origin,放行", false, "", true},
		{"浏览器带 Origin,拒绝", true, "https://evil.example", false},
		{"同源站点也一样拒绝(数据面不服务浏览器)", true, "https://vpn.example", false},
		{"沙箱页面的 null Origin,拒绝", true, "null", false},
		{"http 站点,拒绝", true, "http://evil.example", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/tunnel", nil)
			if c.setOrigin {
				r.Header.Set("Origin", c.origin)
			}
			if got := strictWSCheckOrigin(r); got != c.want {
				t.Errorf("strictWSCheckOrigin(Origin=%q)=%v,期望 %v", c.origin, got, c.want)
			}
		})
	}
}

// ── HTTP 路由 ───────────────────────────────────────────────────────────────

// TestVPNMux_NonUpgradeRequestGetsUpgradeRequired 普通 GET 打 WS 端点应当拿到 426,
// 而不是被当成 WebSocket 处理或者 panic。扫描器和误配的健康检查都会这么打。
func TestVPNMux_NonUpgradeRequestGetsUpgradeRequired(t *testing.T) {
	mux := buildVPNHTTPServeMux("/tunnel", nil, false, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tunnel", nil))

	if rec.Code != http.StatusUpgradeRequired {
		t.Errorf("普通 GET 打 WS 端点返回 %d,期望 426", rec.Code)
	}
}

// TestVPNMux_UnknownPathIs404 未知路径必须 404。
//
// 顺带守住一件事:/health 曾经挂在数据面这个 listener 上,后来专门挪到独立的
// 127.0.0.1 监听去了,就是为了不让外网探测 TUN/store 就绪状态。这里断言它在
// 数据面上确实拿不到,免得哪天有人图省事又给挂回来。
func TestVPNMux_UnknownPathIs404(t *testing.T) {
	mux := buildVPNHTTPServeMux("/tunnel", nil, false, nil)

	for _, path := range []string{"/", "/health", "/metrics", "/tunnel/extra", "/admin"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusNotFound {
				t.Errorf("GET %s 返回 %d,期望 404", path, rec.Code)
			}
		})
	}
}

// TestVPNMux_PathIsNormalized 配置里把路径写成不带前导斜杠(常见笔误)时,
// 监听的仍应是规范化之后的那个路径。
func TestVPNMux_PathIsNormalized(t *testing.T) {
	mux := buildVPNHTTPServeMux("tunnel", nil, false, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tunnel", nil))
	if rec.Code == http.StatusNotFound {
		t.Error("配置写成 \"tunnel\"(漏了前导斜杠)时 /tunnel 变成 404,路径没被规范化")
	}
}

// TestVPNMux_EmptyPathFallsBackToDefault 路径留空时应回落到默认值,而不是把
// 整个数据面挂到 "/" 上(那会让所有请求都进 Upgrade 分支)。
func TestVPNMux_EmptyPathFallsBackToDefault(t *testing.T) {
	mux := buildVPNHTTPServeMux("", nil, false, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("路径留空时 GET / 返回 %d,期望 404 —— 数据面不该落在根路径上", rec.Code)
	}
}

// ── 真实 Upgrade 握手 ───────────────────────────────────────────────────────

// TestVPNMux_BrowserOriginIsRejectedAtHandshake 走**真实的 WebSocket 握手**验证
// 带 Origin 的连接被拒。
//
// 与上面那条纯函数测试的区别:这条确认 CheckOrigin 真的被接到了 Upgrader 上。
// 只测 strictWSCheckOrigin 本身的话,哪天有人把 Upgrader 里那行 CheckOrigin 删了
// 或改成 func(*http.Request) bool { return true },纯函数测试照样全绿。
func TestVPNMux_BrowserOriginIsRejectedAtHandshake(t *testing.T) {
	srv := httptest.NewServer(buildVPNHTTPServeMux("/tunnel", nil, false, nil))
	defer srv.Close()

	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	hdr := http.Header{}
	hdr.Set("Origin", "https://evil.example")

	ws, resp, err := dialer.Dial(wsURL(srv.URL, "/tunnel"), hdr)
	if err == nil {
		_ = ws.Close()
		t.Fatal("带 Origin 的浏览器式握手竟然成功了 —— 任何网页都能拿受害者的网络身份连上数据面")
	}
	if resp == nil {
		t.Fatalf("握手失败但没拿到响应,无法确认是被 Origin 校验挡下的: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("带 Origin 的握手被拒,但状态码是 %d 而非 403 —— 可能不是 Origin 校验挡的", resp.StatusCode)
	}
}

// wsURL 把 httptest 的 http:// 基址换成 ws://。
func wsURL(base, path string) string {
	return "ws" + strings.TrimPrefix(base, "http") + path
}
