package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDeriveServerDialHostSuggestion — 2026-05-27 第二十一轮:settings 页 / dashboard
// 红 banner 在 server_dial_host 未配置时根据 admin 访问 URL 的 Host header 派生候选,
// 把"用户已经在地址栏上输的 host"一键预填进表单,降低首部署摩擦。
//
// 安全语义:r.Host 可被 admin 浏览器伪造 → 这里**只**作为表单 default value 显示
// (admin 看见才能点保存),保存路径仍走完整 ValidateServerDialHost+ProbeServerDialHost,
// 非法/不可达 host validate 失败入不了库。本测试保证派生时的语法校验与 store 的
// ValidateServerDialHost 一致 — 任何"语法过不了 ValidateServerDialHost"的输入必须
// 派生为空字符串(下游模板按"未配置"分支显示标准警告)。
func TestDeriveServerDialHostSuggestion(t *testing.T) {
	cases := []struct {
		name string
		host string
		want string
	}{
		// === 典型场景:admin 用 IP:port 访问 web 后台 ===
		{"ipv4 with port", "203.0.113.10:7443", "203.0.113.10"},
		{"ipv4 no port", "203.0.113.10", "203.0.113.10"},
		// === IPv6 带方括号(net.SplitHostPort 标准格式) ===
		{"ipv6 bracket with port", "[2001:db8::1]:7443", "2001:db8::1"},
		{"ipv6 bracket no port", "[2001:db8::1]", "2001:db8::1"},
		{"ipv6 plain no port", "2001:db8::1", "2001:db8::1"},
		// === 合法域名 ===
		{"hostname with port", "vpn.example.com:7443", "vpn.example.com"},
		{"hostname no port", "vpn.example.com", "vpn.example.com"},
		// === 派生应该为空的情况:语法不过 / 特殊 IP ===
		// localhost 是合法 hostname 但 store.ValidateServerDialHost 接受(label-only
		// 形态会被 hostname 末段字母规则放行) — 不在此 reject 列表。
		// 但 loopback IP(127.0.0.1)与 link-local(::1)是 rejectedSpecialIP,
		// ValidateServerDialHost 直接拒。
		{"loopback ipv4", "127.0.0.1:7443", ""},
		{"loopback ipv6", "[::1]:7443", ""},
		{"empty host", "", ""},
		{"only port", ":7443", ""},
		// label-末段纯数字 TLD(伪 hostname,iOS NEVPN 实际拒过) — ValidateServerDialHost
		// 必须拒;`test-203.0.113.10` 这种就是真实 bug 触发场景。
		{"pseudo hostname numeric tld", "test-203.0.113.10:7443", ""},
		// === 2026-05-27 第二十三轮 A4:语法合法但 DNS 必定 loopback 的 hostname
		// 走 suggestionHostnameBlacklist 拒,避免 dev 场景(浏览器输 localhost)
		// 看到一定失败的候选。lowercase 与大小写混合都要拒。
		{"localhost with port", "localhost:7443", ""},
		{"localhost no port", "localhost", ""},
		{"localhost uppercase", "LOCALHOST:7443", ""},
		{"localhost mixed case", "LocalHost:7443", ""},
		{"localhost.localdomain", "localhost.localdomain:7443", ""},
		{"ip6-localhost", "ip6-localhost:7443", ""},
		{"ip6-loopback", "ip6-loopback:7443", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com/settings", nil)
			req.Host = c.host
			got := deriveServerDialHostSuggestion(req)
			if got != c.want {
				t.Errorf("host=%q got=%q want=%q", c.host, got, c.want)
			}
		})
	}
}

// TestSanitizeReturnTo — 第八轮深扫 P1:开放重定向白名单收敛。验证 returnTo /
// Referer 都被收敛成站内安全 path,不会让钓鱼站借 mesh toggle 把已登录 admin
// 跳出去。
//
// 这个表本身就是「安全边界文档」:每条 case 注释里写明攻击场景与预期行为。
// 改 sanitizeReturnTo 之前先看这个表能否表达想要的新语义,避免悄悄 weaken 边界。
func TestSanitizeReturnTo(t *testing.T) {
	cases := []struct {
		name, returnTo, referer, want string
	}{
		// === returnTo 站内 path:直接通过 ===
		{"return_to plain root", "/", "", "/"},
		{"return_to with path", "/users", "", "/users"},
		{"return_to with query", "/users?show_disabled=1", "", "/users?show_disabled=1"},
		{"return_to trims whitespace", "  /admins  ", "", "/admins"},

		// === returnTo 攻击载荷:全部 fallback ===
		{"return_to protocol-relative", "//evil.com/x", "", "/"},
		{"return_to http absolute", "http://evil.com/x", "", "/"},
		{"return_to https absolute", "https://evil.com/x", "", "/"},
		{"return_to javascript", "javascript:alert(1)", "", "/"},
		{"return_to backslash trick", `/\evil.com/x`, "", "/"},
		{"return_to empty", "", "", "/"},

		// === returnTo 无效时 fallback 到 Referer 的 path-only ===
		// 站内 Referer:取 path,丢 host。即使 Referer 来自本站 ok,我们也只
		// 复用 path 部分 — Referer 头本身就不可强信赖,host 一律剥掉更稳。
		{"referer same-origin path", "", "https://vpn.example.com/dashboard", "/dashboard"},
		{"referer with query", "", "https://vpn.example.com/users?show_disabled=1",
			"/users?show_disabled=1"},
		// 跨域 Referer:host 被剥,只剩 path,等价跳回自家同 path。这是 OK
		// 的边界 — 不会引导用户跳第三方,最差情况是用户跳到「自家不存在的页面」
		// 触发 404,比开放重定向到攻击者控制的页面安全得多。
		{"referer cross-origin path stripped to self", "", "https://evil.com/totally/fake",
			"/totally/fake"},

		// === Referer 自身的攻击载荷 ===
		{"referer protocol-relative", "", "//evil.com/x", "/"},
		{"referer with fragment", "", "https://vpn.example.com/x#frag", "/x"},
		{"referer empty", "", "", "/"},
		// host-only(`https://evil.com`,无 path)→ Path == "" → fallback "/"
		{"referer host only", "", "https://evil.com", "/"},

		// === returnTo 优先于 Referer ===
		{"return_to wins over referer", "/me", "https://evil.com/", "/me"},

		// === 第九轮 P1:URL-encoded `\` (%5C) 绕过防御 ===
		// `%5C` 在字符串层看不到字面 `\`,Parse 后解码出来。我们 Parse 后再检一次,
		// 确保 `/%5Cevil.com/x` → `/\evil.com/x` 仍被拒 → fallback。
		{"return_to %5C bypass", "/%5Cevil.com/x", "", "/"},
		{"return_to %5C in middle", "/users/%5C%5Cevil.com", "", "/"},
		{"referer %5C bypass", "", "https://vpn.example.com/%5Cevil.com", "/"},

		// === 第九轮 P3:边界 case 补测,防回归 ===
		{"return_to with port-like path", "/users:8080/extra", "", "/users:8080/extra"}, // 站内 path 里冒号是合法 URL char
		{"referer with port", "", "https://vpn.example.com:8443/dashboard", "/dashboard"},
		{"referer with user info", "", "https://user:pass@host/dashboard", "/dashboard"}, // path-only 复用,user:pass 一起剥
		// `strings.TrimSpace` 把头尾控制字符(`\t`/`\r`/`\n`)trim 掉,Header 注入
		// 攻击面在 returnTo 入口就被吃掉,Go `http.Redirect` 也不需要再 strip。
		// 这是「副作用比预期更安全」,锁死语义防回归。
		{"return_to trailing tab trimmed", "/users\t", "", "/users"},
		{"return_to trailing CR trimmed", "/users\r", "", "/users"},
		{"return_to trailing LF trimmed", "/users\n", "", "/users"},
	}
	for _, tc := range cases {
		got := sanitizeReturnTo(tc.returnTo, tc.referer)
		if got != tc.want {
			t.Errorf("%s: sanitizeReturnTo(%q, %q) = %q, want %q",
				tc.name, tc.returnTo, tc.referer, got, tc.want)
		}
	}
}

// TestHandleDashboard_MethodGuard — 2026-05-27 第二十四轮 P3-3:
// routes.go 的 `case path == "/"` 把根路径分派到 handleDashboard,但原 handler
// 无 Method 限制 → POST/PUT/DELETE 也会渲染 dashboard HTML(无害但意图不清)。
// 非 GET/HEAD 必须返回 405 + `Allow: GET, HEAD` header,且不进入下游
// collectRuntime / collectDBStats(early return,降低无谓 DB/control 调用)。
//
// 注:本测试只覆盖 405 拒绝路径 — GET/HEAD 放行后走完整 dashboard 渲染需要
// wire control client / runtime stub,工作量与覆盖收益不成正比;放行的"正路"
// 由现有 dashboard e2e / smoke 路径覆盖。
func TestHandleDashboard_MethodGuard(t *testing.T) {
	cases := []struct{ method string }{
		{http.MethodPost},
		{http.MethodPut},
		{http.MethodDelete},
		{http.MethodPatch},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			s := newServerQRTestServer(t)
			admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
			req := httptest.NewRequest(tc.method, "/", nil)
			req = withAdminCtx(req, admin)
			w := httptest.NewRecorder()
			s.handleDashboard(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s /: status = %d, want 405", tc.method, w.Code)
			}
			if allow := w.Header().Get("Allow"); allow != "GET, HEAD" {
				t.Errorf("%s /: Allow header = %q, want %q", tc.method, allow, "GET, HEAD")
			}
		})
	}
}
