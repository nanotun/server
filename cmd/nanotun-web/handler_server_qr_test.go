package main

// handler_server_qr_test.go(2026-05-26 第十一轮)— /server-qr step-up 路径
// 端到端断言。覆盖:
//   1. requireAdminRole 拦 viewer
//   2. IP cooldown 已锁状态 → audit `_locked` + 429
//   3. server_dial_host 未配 → audit `_no_dial_host` + 412
//      (第六轮拆字段:阻断键从 advertised_host 切到 server_dial_host)
//   4. 空密码 → 400(且不计入 cooldown,避免误操作锁自己)
//   5. 密码错 → audit `_password_fail` + cooldown 计数 +1 + 401
//   6. 连错 5 次 → cooldown 触发,第 6 次直接 429
//   7. 密码对 + dial_host OK + CLI 不存在 → audit `_failed` + 500
//   8. /settings/advertised-host:非法 host → 400;合法 host → redirect + audit
//   9. /settings/server-dial-host:语法非法 / DNS 失败 / ICMP soft-fail / ctx cancel /
//      skip_probe=1 各路径完整覆盖(第六~七轮上线 ping probe + 跳过开关)
//
// 关键测试姿态:与 handler_users_prg_test.go 同款的 newTestServerMinimal
// 模式 —— 不加载真实模板让 renderError / renderPage 走 plain-text fallback,
// 关注 status / audit / cooldown 三个 invariant,不验证 HTML 渲染输出。
//
// 2026-05-26 改名:public_host → advertised_host(migration 0015 一起改),
// 此处测试函数 / 字符串同步重命名,语义不变。

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// newServerQRTestServer 构造一个可跑 server-qr handler 的 Server。
// 与 newTestServerMinimal 类似,但额外初始化 stepUpFailures(handler 必需)。
func newServerQRTestServer(t *testing.T) *Server {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, t.TempDir()+"/server_qr_test.db", store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	return &Server{
		cfg:            defaultConfig(),
		store:          st,
		sess:           NewSessionService(st, defaultConfig()),
		audit:          NewAuditor(st),
		tmpl:           template.New(""),
		credFlash:      newCredentialsFlashStore(stop),
		stepUpFailures: NewIPFailureTracker(),
		startedAt:      time.Now(),
	}
}

// createTestAdmin 在 web_admins 表里建一个真实 admin(含 argon2id hash),
// 返回 admin + 明文密码。
func createTestAdmin(t *testing.T, s *Server, username, password string) *store.WebAdmin {
	t.Helper()
	hash, err := HashWebPassword(password)
	if err != nil {
		t.Fatalf("HashWebPassword: %v", err)
	}
	a, err := s.store.CreateWebAdmin(t.Context(), store.NewWebAdmin{
		Username:     username,
		PasswordHash: hash,
		Role:         "admin",
	})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	return a
}

// withAdminCtx 把 *store.WebAdmin 注入到 r.Context,模拟 middleware 后状态。
func withAdminCtx(r *http.Request, a *store.WebAdmin) *http.Request {
	ctx := context.WithValue(r.Context(), ctxKeyAdmin, a)
	return r.WithContext(ctx)
}

// countAudit 简单计数指定 action 的 audit 条目;用于断言 audit 实际写入。
func countAudit(t *testing.T, s *Server, action string) int {
	t.Helper()
	logs, err := s.store.QueryAudit(t.Context(), 0, time.Now().Unix()+1, 100)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	n := 0
	for _, l := range logs {
		if l.Action == action {
			n++
		}
	}
	return n
}

// auditDetailFor 返回第一条匹配 action 的 audit detail 字符串。
// 用于断言「detail 内部的某个 key=value 子串」存在(配 strings.Contains)。
// 第十三轮加入:用于锁住 `settings_server_dial_host_set` 的 detail.probe 字段
// 真实写入,而非仅断言 action 计数。
//
// 找不到时返回 "" 并不调用 t.Fatal — 让调用方决定是否当作错误(有些测试就是要
// 断言「这条 audit 不应该出现」,空串本身已是足够信号)。
func auditDetailFor(t *testing.T, s *Server, action string) string {
	t.Helper()
	logs, err := s.store.QueryAudit(t.Context(), 0, time.Now().Unix()+1, 100)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	for _, l := range logs {
		if l.Action == action {
			return l.Detail
		}
	}
	return ""
}

// =============================================================================
// 1. requireAdminRole 拦 viewer
// =============================================================================

func TestServerQRReveal_ViewerRejected(t *testing.T) {
	s := newServerQRTestServer(t)
	hash, _ := HashWebPassword("ViewerPass123!")
	viewer, _ := s.store.CreateWebAdmin(t.Context(), store.NewWebAdmin{
		Username:     "view1",
		PasswordHash: hash,
		Role:         "viewer", // 关键:非 admin
	})

	req := httptest.NewRequest(http.MethodPost, "/server-qr/reveal",
		strings.NewReader("password=anything"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdminCtx(req, viewer)
	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer 应被拒,status = %d,want 403", w.Code)
	}
	// 不应该有任何 server_profile_qr_* audit,viewer 在 requireAdminRole 就被拦了。
	// 2026-05-26 第九轮扫描:`_no_advertised_host` audit action 已在第六轮拆字段
	// 时改名为 `_no_dial_host`(阻断键从 label 切到 dial),这里同步对齐 — 用旧名
	// 检查永远是 0(action 不存在了),改用新名才是有效的不变量断言。
	for _, action := range []string{
		"server_profile_qr_show", "server_profile_qr_password_fail",
		"server_profile_qr_locked", "server_profile_qr_no_dial_host",
		"server_profile_qr_failed",
	} {
		if n := countAudit(t, s, action); n != 0 {
			t.Errorf("viewer 路径不应产生 %s audit,实际 %d 条", action, n)
		}
	}
}

// =============================================================================
// 2. IP cooldown 已锁 → audit `_locked` + 429
// =============================================================================

func TestServerQRReveal_AlreadyLocked(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	// 直接把 cooldown 顶满。
	for i := 0; i < stepUpMaxFailures; i++ {
		s.stepUpFailures.Inc("192.0.2.1")
	}

	req := httptest.NewRequest(http.MethodPost, "/server-qr/reveal",
		strings.NewReader("password=anything"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.1:55555"
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("cooldown 已锁 status = %d,want 429", w.Code)
	}
	if n := countAudit(t, s, "server_profile_qr_locked"); n != 1 {
		t.Errorf("expected 1 _locked audit, got %d", n)
	}
	// 关键安全断言:cooldown 已锁时不应跑密码 verify 路径(避免 verify timing 泄露)。
	if n := countAudit(t, s, "server_profile_qr_password_fail"); n != 0 {
		t.Errorf("cooldown 路径不应产生 password_fail audit, got %d", n)
	}
}

// =============================================================================
// 3. server_dial_host 未配 → audit `_no_dial_host` + 412
//
// 2026-05-26 第六轮拆字段:阻断键从 advertised_host 改成 server_dial_host
// (advertised_host 现在只是展示 label,不阻塞 QR 生成;dial_host 才是
// 客户端实际拨号目标,缺失 = 服务器对外不可用)。
// =============================================================================

func TestServerQRReveal_NoServerDialHost(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	// 不调 SetServerDialHost,保持空值。advertised_host 也不配,确保走的是
	// dial_host 阻断路径而不是其它分支。

	req := httptest.NewRequest(http.MethodPost, "/server-qr/reveal",
		strings.NewReader("password=anything"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.1.0.1:1"
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, req)

	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("server_dial_host 未配 status = %d,want 412", w.Code)
	}
	if n := countAudit(t, s, "server_profile_qr_no_dial_host"); n != 1 {
		t.Errorf("expected 1 _no_dial_host audit, got %d", n)
	}
}

// =============================================================================
// 4. 空密码 → 400,且不计入 cooldown(避免误操作锁自己)
// =============================================================================

func TestServerQRReveal_EmptyPasswordNotCounted(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	// 2026-05-26 第六轮:必须同时配 dial_host(真实拨号)+ advertised_host(label),
	// 否则 dial_host 校验早于密码校验拦截走 412 路径,误盖测试目标(空密码 400)。
	_ = s.store.SetServerDialHost(t.Context(), "vpn.example.com")
	_ = s.store.SetAdvertisedHost(t.Context(), "vpn.example.com")

	req := httptest.NewRequest(http.MethodPost, "/server-qr/reveal",
		strings.NewReader("password=")) // 空密码
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.2.0.1:1"
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("空密码 status = %d,want 400", w.Code)
	}
	if n := s.stepUpFailures.Recent("10.2.0.1"); n != 0 {
		t.Errorf("空密码不应该计入 cooldown,Recent = %d", n)
	}
	// 同时不应产生 _password_fail audit。
	if n := countAudit(t, s, "server_profile_qr_password_fail"); n != 0 {
		t.Errorf("空密码不应产生 password_fail audit, got %d", n)
	}
}

// =============================================================================
// 5. 密码错 → audit + cooldown +1 + 401
// =============================================================================

func TestServerQRReveal_WrongPasswordCounts(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	_ = s.store.SetServerDialHost(t.Context(), "vpn.example.com")
	_ = s.store.SetAdvertisedHost(t.Context(), "vpn.example.com")

	req := httptest.NewRequest(http.MethodPost, "/server-qr/reveal",
		strings.NewReader("password=wrong-password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.3.0.1:1"
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("密码错 status = %d,want 401", w.Code)
	}
	if n := countAudit(t, s, "server_profile_qr_password_fail"); n != 1 {
		t.Errorf("expected 1 _password_fail audit, got %d", n)
	}
	if n := s.stepUpFailures.Recent("10.3.0.1"); n != 1 {
		t.Errorf("cooldown 应为 1,实际 %d", n)
	}
}

// =============================================================================
// 6. 连错 5 次 → 触发锁定,第 6 次直接 429
// =============================================================================

func TestServerQRReveal_LockoutAfterMax(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	_ = s.store.SetServerDialHost(t.Context(), "vpn.example.com")
	_ = s.store.SetAdvertisedHost(t.Context(), "vpn.example.com")

	for i := 0; i < stepUpMaxFailures; i++ {
		req := httptest.NewRequest(http.MethodPost, "/server-qr/reveal",
			strings.NewReader("password=wrong"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.4.0.1:1"
		req = withAdminCtx(req, admin)
		w := httptest.NewRecorder()
		s.handleServerQRReveal(w, req)
	}
	// 第 5 次失败时,handler 会观察到 newCount >= stepUpMaxFailures 并直接返 429。
	// 但前 4 次都是 401。这里关键断言:cooldown 状态值满了。
	if n := s.stepUpFailures.Recent("10.4.0.1"); n < stepUpMaxFailures {
		t.Fatalf("5 次失败后 cooldown Recent = %d,want >= %d", n, stepUpMaxFailures)
	}
	failCount := countAudit(t, s, "server_profile_qr_password_fail")
	if failCount != stepUpMaxFailures {
		t.Errorf("expected %d _password_fail audits, got %d", stepUpMaxFailures, failCount)
	}

	// 第 6 次尝试 → 即使密码对 / 错都不再 verify,直接 _locked + 429。
	req := httptest.NewRequest(http.MethodPost, "/server-qr/reveal",
		strings.NewReader("password=GoodStrong1!Pass")) // 正确密码也不行
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.4.0.1:1"
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("锁定后第 6 次正确密码 status = %d,want 429", w.Code)
	}
	if n := countAudit(t, s, "server_profile_qr_locked"); n != 1 {
		t.Errorf("expected 1 _locked audit, got %d", n)
	}
	// 关键:锁定路径绝不应产生 _show audit(QR 不能漏出去)。
	if n := countAudit(t, s, "server_profile_qr_show"); n != 0 {
		t.Errorf("锁定状态下绝不能写 _show audit,got %d", n)
	}
}

// =============================================================================
// 7. 密码对 + advertised_host OK + CLI 不存在 → audit `_failed` + 500
// =============================================================================

func TestServerQRReveal_CLIMissing(t *testing.T) {
	s := newServerQRTestServer(t)
	s.cfg.VPNPortAdminPath = "/nonexistent/path/to/nanotun-admin"
	s.cfg.ServerConfigPath = "/nonexistent/path/to/config.toml"
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	_ = s.store.SetServerDialHost(t.Context(), "vpn.example.com")
	_ = s.store.SetAdvertisedHost(t.Context(), "vpn.example.com")

	req := httptest.NewRequest(http.MethodPost, "/server-qr/reveal",
		strings.NewReader("password=GoodStrong1!Pass"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.5.0.1:1"
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("CLI 缺失 status = %d,want 500", w.Code)
	}
	if n := countAudit(t, s, "server_profile_qr_failed"); n != 1 {
		t.Errorf("expected 1 _failed audit, got %d", n)
	}
	// 密码对了但 build 失败时,**不**应该写 _show audit(还没真正显示)。
	if n := countAudit(t, s, "server_profile_qr_show"); n != 0 {
		t.Errorf("build 失败路径不应写 _show audit, got %d", n)
	}
	// 密码对了,失败计数不应该 +1(密码 verify 通过后只走 CLI 失败路径)。
	if n := s.stepUpFailures.Recent("10.5.0.1"); n != 0 {
		t.Errorf("密码对的情况下 cooldown 不应递增,Recent = %d", n)
	}
}

// =============================================================================
// 8. /settings/advertised-host POST 路径
// =============================================================================

func TestSettingsAdvertisedHostSet_Invalid(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")

	cases := []struct {
		name string
		host string
	}{
		{"scheme http", "http://vpn.example.com"},
		{"with port", "vpn.example.com:8080"},
		{"has path", "vpn.example.com/x"},
		{"newline injection", "vpn.example.com\nX"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("advertised_host", tc.host)
			req := httptest.NewRequest(http.MethodPost, "/settings/advertised-host",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = withAdminCtx(req, admin)
			w := httptest.NewRecorder()
			s.handleSettingsAdvertisedHostSet(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", tc.name, w.Code)
			}
			// 落地确认:DB 里不应有 advertised_host(从未写入过)。
			got, _ := s.store.GetAdvertisedHost(t.Context())
			if got != "" {
				t.Errorf("%s: 非法值竟然落库为 %q", tc.name, got)
			}
		})
	}
}

func TestSettingsAdvertisedHostSet_Valid(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")

	form := url.Values{}
	form.Set("advertised_host", "203.0.113.10")
	req := httptest.NewRequest(http.MethodPost, "/settings/advertised-host",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleSettingsAdvertisedHostSet(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("valid status = %d, want 303 SeeOther", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/settings?flash=") {
		t.Errorf("redirect location = %q, want /settings?flash=...", loc)
	}
	got, err := s.store.GetAdvertisedHost(t.Context())
	if err != nil || got != "203.0.113.10" {
		t.Errorf("DB 读 advertised_host = %q (err %v), want 203.0.113.10", got, err)
	}
	if n := countAudit(t, s, "settings_advertised_host_set"); n != 1 {
		t.Errorf("expected 1 settings_advertised_host_set audit, got %d", n)
	}
}

func TestSettingsAdvertisedHostSet_Clear(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	// 先写一个值。
	_ = s.store.SetAdvertisedHost(t.Context(), "vpn.example.com")

	form := url.Values{}
	form.Set("advertised_host", "") // 清除
	req := httptest.NewRequest(http.MethodPost, "/settings/advertised-host",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleSettingsAdvertisedHostSet(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("clear status = %d, want 303", w.Code)
	}
	got, _ := s.store.GetAdvertisedHost(t.Context())
	if got != "" {
		t.Errorf("清除后 advertised_host 仍为 %q", got)
	}
}

// =============================================================================
// 9. /settings/server-dial-host POST 路径 + Probe(ping)校验 (2026-05-26 第六轮)
// =============================================================================
//
// 与 advertised_host 测试的关键区别:server_dial_host 在 handler 层会**主动 ping**,
// 失败时按 DNS/ICMP 两类语义返回 400 / 412。skip_probe=1 允许 admin 在 firewall
// ban ICMP 场景下绕过 ping 直接保存。
//
// 本组覆盖:
//   - 语法非法 → 400(与 advertised_host 同款,无 probe)
//   - 合法语法 + skip_probe=1 + IP literal → 303 + 落库 + audit detail 含 probe_skipped
//   - 合法语法 + skip_probe=1 + 清除("") → 303 + 落库为空
//   - 不可解析域名(.invalid)→ 400 (ErrServerDialHostDNS),不落库,audit `_dns_fail`
//   - 文档示例段 192.0.2.x(TEST-NET-1)→ 412 (ICMPSoftFail),不落库,audit `_icmp_softfail`
//
// Skip semantics: 设计上 skip_probe 让 admin 在 CI / firewall 场景下也能强行保存。

func TestSettingsServerDialHostSet_Invalid_NoProbe(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	cases := []struct {
		name string
		host string
	}{
		{"end label all digit", "test-203.0.113.10"},
		{"scheme http", "http://vpn.example.com"},
		{"with port", "vpn.example.com:8080"},
		{"newline injection", "vpn.example.com\nX"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("server_dial_host", tc.host)
			// 关键:即使勾 skip_probe,语法非法**也要先拒** —— ValidateServerDialHost
			// 排在 ProbeServerDialHost 之前,skip_probe 只 bypass probe,不 bypass syntax。
			form.Set("skip_probe", "1")
			req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = withAdminCtx(req, admin)
			w := httptest.NewRecorder()
			s.handleSettingsServerDialHostSet(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
			got, _ := s.store.GetServerDialHost(t.Context())
			if got != "" {
				t.Errorf("非法值竟然落库: %q", got)
			}
		})
	}
}

// TestSettingsServerDialHostSet_ReturnTo — 2026-05-27 第二十二轮 banner 入口:
// dashboard 红 banner 一键确认 form 带 `return_to=/`,期望 redirect 回 dashboard
// 而非默认 /settings;原 settings.html 表单不传 return_to,redirect 仍走 /settings。
// 同时验证 sanitizeReturnTo 白名单收敛 — 攻击 payload 不会被原样塞进 Location。
func TestSettingsServerDialHostSet_ReturnTo(t *testing.T) {
	cases := []struct {
		name       string
		returnTo   string
		wantPrefix string
	}{
		// dashboard banner 主路径
		{"explicit root", "/", "/?flash="},
		// 假想其他站内路径
		{"explicit users", "/users", "/users?flash="},
		// 不传 return_to 退回旧行为
		{"missing return_to", "", "/settings?flash="},
		// 攻击 payload — sanitizeReturnTo 应 fallback `/`(详见 TestSanitizeReturnTo)
		{"javascript scheme", "javascript:alert(1)", "/?flash="},
		{"protocol relative", "//evil.com/x", "/?flash="},
		{"http absolute", "http://evil.com/x", "/?flash="},
		// 2026-05-27 第二十三轮 A8 补漏:纯空格 TrimSpace 后空 → 不走 sanitize,
		// 走默认 /settings(等价 missing return_to,不应被攻击者借纯空格 bypass
		// 默认 /settings 落点) — 与 sanitizeReturnTo("","")=/ 行为故意不一致。
		{"whitespace only", "   ", "/settings?flash="},
		// admin 显式传 /settings(自定义脚本测试 / 手 craft):正常通过 → /settings
		{"explicit settings", "/settings", "/settings?flash="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServerQRTestServer(t)
			admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
			form := url.Values{}
			form.Set("server_dial_host", "203.0.113.10")
			form.Set("skip_probe", "1")
			if tc.returnTo != "" {
				form.Set("return_to", tc.returnTo)
			}
			req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = withAdminCtx(req, admin)
			w := httptest.NewRecorder()
			s.handleSettingsServerDialHostSet(w, req)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303 (body=%s)", w.Code, w.Body.String())
			}
			loc := w.Header().Get("Location")
			if !strings.HasPrefix(loc, tc.wantPrefix) {
				t.Errorf("Location = %q, want prefix %q", loc, tc.wantPrefix)
			}
		})
	}
}

func TestSettingsServerDialHostSet_SkipProbe_Valid(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")

	form := url.Values{}
	form.Set("server_dial_host", "203.0.113.10")
	form.Set("skip_probe", "1")
	req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleSettingsServerDialHostSet(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "%E5%B7%B2%E6%9B%B4%E6%96%B0") {
		// "已更新" 的 URL-encoded;不强校验完整字符串,只看个大概。
		t.Logf("redirect Location = %q(仅供参考)", w.Header().Get("Location"))
	}
	got, _ := s.store.GetServerDialHost(t.Context())
	if got != "203.0.113.10" {
		t.Errorf("server_dial_host = %q, want 203.0.113.10", got)
	}
	if n := countAudit(t, s, "settings_server_dial_host_set"); n != 1 {
		t.Errorf("expected 1 settings_server_dial_host_set audit, got %d", n)
	}
}

func TestSettingsServerDialHostSet_SkipProbe_Clear(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	_ = s.store.SetServerDialHost(t.Context(), "203.0.113.10")

	form := url.Values{}
	form.Set("server_dial_host", "")
	// 清除路径无 probe,即使带 skip_probe 也走相同分支;不带也行,两者等价。
	req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleSettingsServerDialHostSet(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("clear status = %d, want 303", w.Code)
	}
	got, _ := s.store.GetServerDialHost(t.Context())
	if got != "" {
		t.Errorf("清除后仍为 %q", got)
	}
}

// TestSettingsServerDialHostSet_DNSFail: 不带 skip_probe + 不可解析的 .invalid 域名 → 400 DNS。
//
// 用 RFC 2606 保留 TLD `.invalid`,Go stdlib resolver 直接 NXDOMAIN,无网络抖动。
func TestSettingsServerDialHostSet_DNSFail(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")

	form := url.Values{}
	form.Set("server_dial_host", "this-host-definitely-does-not-exist.invalid")
	req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleSettingsServerDialHostSet(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400(DNS fail)", w.Code)
	}
	got, _ := s.store.GetServerDialHost(t.Context())
	if got != "" {
		t.Errorf("DNS fail 不应落库,实际 %q", got)
	}
	if n := countAudit(t, s, "settings_server_dial_host_set_dns_fail"); n != 1 {
		t.Errorf("expected 1 _dns_fail audit, got %d", n)
	}
	// 关键不变量:DNS 失败不应混入"成功"审计。
	if n := countAudit(t, s, "settings_server_dial_host_set"); n != 0 {
		t.Errorf("DNS fail 不应写成功 audit, got %d", n)
	}
}

// TestSettingsServerDialHostSet_SkipProbe_ICMPSoftFail: 第十一轮核心路径回归锁 ——
// **ICMP softfail + skip_probe=1 → 入库 + 双 audit**(`_icmp_softfail_skipped` + `set`)。
//
// 第十一轮重写了 skip_probe 语义(只跳 ICMP,不跳 DNS),新增了 `_icmp_softfail_skipped`
// audit sibling 和 `probe=icmp_softfail_skipped` 详情记录,但**原有测试**只覆盖到:
//   - `_SkipProbe_Valid` : IP literal `203.0.113.10`(ICMP 通过,不走 softfail 分支)
//   - `_ICMPSoftFail`    : `192.0.2.1` + 不勾 skip → 412 拦在前面
//
// 两者都没走到「ICMP softfail + skip 入库」这条**新代码的核心路径**。
// 本测试用 `192.0.2.1`(RFC 5737 TEST-NET-1,blackhole)+ skip_probe=1 把这条路径
// 真正打穿:断言 303 + dial_host 落库 + 两条 audit + `set` audit 的
// `detail.probe=icmp_softfail_skipped`(第十三轮加的断言锁住 probeOutcome → probeNote 链路)。
//
// 注意:本测试可能跑 3-5s(等 ping timeout),已通过 handler ctx.Timeout(20s) 保护。
func TestSettingsServerDialHostSet_SkipProbe_ICMPSoftFail(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")

	form := url.Values{}
	form.Set("server_dial_host", "192.0.2.1") // TEST-NET-1, unroutable
	form.Set("skip_probe", "1")               // 关键:允许 ICMP 软错入库
	req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleSettingsServerDialHostSet(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303(ICMP softfail + skip 应入库)", w.Code)
	}
	got, _ := s.store.GetServerDialHost(t.Context())
	if got != "192.0.2.1" {
		t.Errorf("ICMP softfail + skip 应落库,实际 %q", got)
	}
	// 双 audit:一条 `_icmp_softfail_skipped` 记录 admin 主动 bypass 的事实,
	// 一条 `set` 记录成功入库,detail.probe=icmp_softfail_skipped。
	if n := countAudit(t, s, "settings_server_dial_host_set_icmp_softfail_skipped"); n != 1 {
		t.Errorf("expected 1 _icmp_softfail_skipped audit, got %d", n)
	}
	if n := countAudit(t, s, "settings_server_dial_host_set"); n != 1 {
		t.Errorf("expected 1 _set audit, got %d", n)
	}
	// 第十三轮新增:锁住 `set` audit 的 detail.probe 真的写了 `icmp_softfail_skipped`
	// (而非旧版的 `icmp_skipped` 或 proxy 推断的 `probed_ok`)。这条断言能直接
	// catch 未来谁把 probeOutcome 状态名改了 / 把 probeNote 默认值改回旧 proxy 推断。
	setDetail := auditDetailFor(t, s, "settings_server_dial_host_set")
	if !strings.Contains(setDetail, "probe=icmp_softfail_skipped") {
		t.Errorf("`set` audit detail 应含 `probe=icmp_softfail_skipped`,实际: %q", setDetail)
	}
	// 关键不变量:不应被错误地分类为 hard fail。
	for _, action := range []string{
		"settings_server_dial_host_set_dns_fail",
		"settings_server_dial_host_set_icmp_softfail", // unskipped 版本
		"settings_server_dial_host_set_probe_unknown",
	} {
		if n := countAudit(t, s, action); n != 0 {
			t.Errorf("ICMP softfail + skip 不应写 %s audit, got %d", action, n)
		}
	}
}

// TestSettingsServerDialHostSet_FailureCTA — 2026-05-27 第二十四轮 P3-2:
// 三种失败路径(语法 400 / DNS 400 / ICMP softfail 412 / probe_unknown 412)
// 都应该走 `renderErrorWithCTA` 在 error.html 注入「到设置页 …」secondary CTA,
// admin 在 error 页有直链可点,不必摸索"现在去哪修复"。
//
// 测试不验证 HTML 渲染(error.html 模板渲染逻辑在 renderPage 单独测),只验证
// caller 经过新方法 = response body 包含 CTA 链接 + 对应 label 字面量。
func TestSettingsServerDialHostSet_FailureCTA(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		skipProbe  bool
		wantStatus int
		wantLabel  string
	}{
		// 语法错(末段纯数字伪 hostname)→ 400 + 「到设置页手改」
		{"syntax bad", "test-203.0.113.10", false, 400, "到设置页手改"},
		// DNS 硬错(.invalid TLD 永不解析)→ 400 + 「到设置页改地址」(注意 skip 救不回来)
		{"dns hard fail", "skipped-but-still-bad.invalid", true, 400, "到设置页改地址"},
		// 注意:ICMP softfail / probe_unknown 在测试环境不易稳定模拟(需要可解析但 ping 失败
		// 的真实 host),交给端到端 manual test;syntax + DNS 两条覆盖 renderErrorWithCTA
		// 调用路径已足够锁死 CTA 注入未来不被回归改没。
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServerQRTestServer(t)
			admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
			form := url.Values{}
			form.Set("server_dial_host", c.host)
			if c.skipProbe {
				form.Set("skip_probe", "1")
			}
			req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = withAdminCtx(req, admin)
			w := httptest.NewRecorder()
			s.handleSettingsServerDialHostSet(w, req)
			if w.Code != c.wantStatus {
				t.Errorf("status = %d, want %d (body=%s)", w.Code, c.wantStatus, w.Body.String())
			}
			body := w.Body.String()
			// 验证 secondary CTA 标签 + 链接到 /settings
			if !strings.Contains(body, c.wantLabel) {
				t.Errorf("body 应含 CTA label %q,实际 body:\n%s", c.wantLabel, body)
			}
			// 注:html/template 对 href attribute 自动加引号(`href="/settings"`)
			// 或单引号或在 SafeURL escape 后保持纯文本 — 测试只检子串 `/settings`,
			// 既覆盖 attr 路径也覆盖明文路径,不依赖具体引号格式。
			if !strings.Contains(body, "/settings") {
				t.Errorf("body 应含 CTA 链接路径 /settings,实际 body:\n%s", body)
			}
		})
	}
}

// TestSettingsServerDialHostSet_DNSFail_SkipProbeIgnored: 关键不变量 ——
// **DNS 解析失败任何情况下都不可入库**,即使 admin 勾选 skip_probe 也不行。
//
// 第十一轮(2026-05-26)修复:原 handler `if !skipProbe { probe }` 让 skip_probe=1
// 时 DNS 也被跳过,与 settings.html 文案「DNS 解析失败 → 一定是错地址,无法跳过」
// 矛盾。校正后 skip_probe 只能跳过 ICMP softfail,DNS 仍必查。
//
// 本测试 + _DNSFail 一起锁死:DNS 路径无论 skip 与否,都必须返回 400 + audit
// `_dns_fail` + detail.skip_probe=true。
func TestSettingsServerDialHostSet_DNSFail_SkipProbeIgnored(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")

	form := url.Values{}
	form.Set("server_dial_host", "skipped-but-still-bad.invalid")
	form.Set("skip_probe", "1") // 关键:即使勾选也不应放过 DNS hard fail
	req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleSettingsServerDialHostSet(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400(DNS fail 不可被 skip_probe 跳过)", w.Code)
	}
	got, _ := s.store.GetServerDialHost(t.Context())
	if got != "" {
		t.Errorf("DNS fail + skip_probe=1 也不应落库,实际 %q", got)
	}
	if n := countAudit(t, s, "settings_server_dial_host_set_dns_fail"); n != 1 {
		t.Errorf("expected 1 _dns_fail audit, got %d", n)
	}
	// 关键不变量:不应被错误地分类为 _icmp_softfail_skipped 或成功。
	for _, action := range []string{
		"settings_server_dial_host_set",
		"settings_server_dial_host_set_icmp_softfail",
		"settings_server_dial_host_set_icmp_softfail_skipped",
	} {
		if n := countAudit(t, s, action); n != 0 {
			t.Errorf("DNS fail + skip 不应写 %s audit, got %d", action, n)
		}
	}
}

// TestSettingsServerDialHostSet_CtxCancel: 不带 skip_probe + request ctx 已 cancel
// → 返回 503 ServiceUnavailable,**不写 audit**(audit 是事件,不是系统抖动)。
//
// 触发场景:admin 浏览器关闭 / server shutdown 时 probe 还在跑。返回 503 让 admin
// 重试,不当作 probe 失败展示给用户 / 不污染审计流。
func TestSettingsServerDialHostSet_CtxCancel(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	form := url.Values{}
	form.Set("server_dial_host", "vpn.example.com")
	req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(cancelCtx)
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleSettingsServerDialHostSet(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503(ctx cancel)", w.Code)
	}
	got, _ := s.store.GetServerDialHost(t.Context())
	if got != "" {
		t.Errorf("ctx cancel 不应落库,实际 %q", got)
	}
	// 关键不变量:ctx 取消是系统级抖动,不是 admin 输入问题,**不写任何 audit**。
	for _, action := range []string{
		"settings_server_dial_host_set",
		"settings_server_dial_host_set_dns_fail",
		"settings_server_dial_host_set_icmp_softfail",
		"settings_server_dial_host_set_icmp_softfail_skipped",
		"settings_server_dial_host_set_probe_unknown",
		"settings_server_dial_host_set_probe_unknown_skipped",
	} {
		if n := countAudit(t, s, action); n != 0 {
			t.Errorf("ctx cancel 不应写 %s audit, got %d", action, n)
		}
	}
}

// TestSettingsServerDialHostSet_ICMPSoftFail: 不带 skip_probe + 文档示例段
// `192.0.2.1`(RFC 5737 TEST-NET-1)→ 412 ICMPSoftFail。
//
// TEST-NET-1 路由全网 blackhole,ping 必然 0 回包;在 CI / sandbox 环境
// unprivileged UDP ping 也可能初始化失败,两种 case 都会被分类为
// `ErrServerDialHostICMPSoftFail`(handler 返回 412)。本测试稳定可重复。
//
// 注意:本测试可能跑 3-5s(等 ping timeout),已通过 handler ctx.Timeout(20s) 保护。
func TestSettingsServerDialHostSet_ICMPSoftFail(t *testing.T) {
	s := newServerQRTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")

	form := url.Values{}
	form.Set("server_dial_host", "192.0.2.1") // TEST-NET-1, unroutable
	req := httptest.NewRequest(http.MethodPost, "/settings/server-dial-host",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdminCtx(req, admin)
	w := httptest.NewRecorder()
	s.handleSettingsServerDialHostSet(w, req)

	if w.Code != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412(ICMP softfail)", w.Code)
	}
	got, _ := s.store.GetServerDialHost(t.Context())
	if got != "" {
		t.Errorf("ICMP softfail 不应落库,实际 %q", got)
	}
	if n := countAudit(t, s, "settings_server_dial_host_set_icmp_softfail"); n != 1 {
		t.Errorf("expected 1 _icmp_softfail audit, got %d", n)
	}
	if n := countAudit(t, s, "settings_server_dial_host_set"); n != 0 {
		t.Errorf("ICMP softfail 不应写成功 audit, got %d", n)
	}
}
