package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件覆盖登录的**第二因子**:POST /login/totp。
//
// 之前这里一条 handler 级测试都没有。auth_test.go 测的是密码步(AttemptLogin),
// session_pending_test.go 测的是 pending cookie 这个原语,两头都有,中间这段编排
// 是空的 —— 而「一码一用」恰恰只在这里落地:恢复码若不在登录成功时被烧掉,它就
// 从「一次性应急凭据」变成一句**永久免密**口令,而且用户完全无感。

const loginTestIP = "198.51.100.7"

// enableTOTPDirect 直接在库里把 2FA 装好(跳过 /me 那套自助流程,那边另有测试)。
// nRecovery 是要生成的恢复码条数 —— 每条都要过一次 argon2,不需要就传 1。
func enableTOTPDirect(t *testing.T, s *Server, admin *store.WebAdmin, nRecovery int) (string, []string) {
	t.Helper()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := s.store.SetWebAdminTOTPSecret(t.Context(), admin.ID, secret); err != nil {
		t.Fatalf("SetWebAdminTOTPSecret: %v", err)
	}
	plain, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if nRecovery > 0 && nRecovery < len(plain) {
		plain, hashes = plain[:nRecovery], hashes[:nRecovery]
	}
	if _, err := s.store.EnableWebAdminTOTP(t.Context(), admin.ID, secret, hashes, nowUnix()); err != nil {
		t.Fatalf("EnableWebAdminTOTP: %v", err)
	}
	return secret, plain
}

// issuePending 签一枚合法的 pending 2FA cookie(= 密码步已过)。
func issuePending(t *testing.T, s *Server, adminID int64, ip string) *http.Cookie {
	t.Helper()
	cur, err := s.store.GetWebAdmin(t.Context(), adminID)
	if err != nil || cur == nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	rec := httptest.NewRecorder()
	if err := s.sess.IssueTOTPPending(rec, adminID, ip, cur.PasswordHash); err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "pending") {
			return c
		}
	}
	t.Fatalf("没拿到 pending cookie: %v", rec.Header().Values("Set-Cookie"))
	return nil
}

// loginTOTPPost 造一个带 CSRF + pending cookie 的 POST /login/totp。
// pending 传 nil 表示「没有 pending」(用于测未过密码步的情形)。
func loginTOTPPost(t *testing.T, s *Server, form url.Values, ip string, pending *http.Cookie) *http.Request {
	t.Helper()
	issueW := httptest.NewRecorder()
	tok, err := s.sess.IssueCSRFToken(httptest.NewRequest(http.MethodGet, "/login/totp", nil), issueW)
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", tok)
	req := httptest.NewRequest(http.MethodPost, "/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range issueW.Result().Cookies() {
		req.AddCookie(c)
	}
	if pending != nil {
		req.AddCookie(pending)
	}
	req.RemoteAddr = ip + ":40000"
	return req
}

// hasSessionCookie 报告响应里是否颁发了会话 cookie(= 真的登录成功了)。
func hasSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "sess") && c.Value != "" && c.MaxAge >= 0 {
			return true
		}
	}
	return false
}

// =========================================================================
// 正向
// =========================================================================

// TestLoginTOTP_ValidCodeIssuesSession:6 位码正确 → 颁会话 + 302。
func TestLoginTOTP_ValidCodeIssuesSession(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	pending := issuePending(t, s, admin.ID, loginTestIP)

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeFor(t, secret)}}, loginTestIP, pending))
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d body=%q, 期望 302", w.Code, trimForLog(w.Body.String()))
	}
	if !hasSessionCookie(w) {
		t.Fatalf("登录成功却没颁会话 cookie")
	}
	assertAuditAction(t, s, "web.login.ok")
}

// TestLoginTOTP_RecoveryCodeWorksAndIsBurned:恢复码能登录,而且**只能用一次**。
//
// 这是整个 2FA 里最要命的一条不变量。恢复码不过 TOTP 那套时间步消费,唯一的
// 一次性保障就是登录成功时把它标记 used。这一步若失效(或顺序写错),那张纸上
// 的 10 条码就成了 10 句永久免密口令 —— 用户不会收到任何提示,页面上也照样
// 显示「已启用双因子」。
func TestLoginTOTP_RecoveryCodeWorksAndIsBurned(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	_, codes := enableTOTPDirect(t, s, admin, 2)

	// 第一次:用恢复码登录成功。
	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"recovery_code": {codes[0]}}, loginTestIP,
		issuePending(t, s, admin.ID, loginTestIP)))
	if w.Code != http.StatusFound || !hasSessionCookie(w) {
		t.Fatalf("恢复码首次登录 code=%d, 未颁会话", w.Code)
	}
	assertAuditAction(t, s, "web.totp.recovery_used")

	// 库里必须只剩另一条未用。
	left, err := s.store.ListUnusedRecoveryCodes(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("ListUnusedRecoveryCodes: %v", err)
	}
	if len(left) != 1 {
		t.Fatalf("用掉一条后剩 %d 条, 期望 1 条", len(left))
	}

	// 第二次:同一条码 + 全新 pending → 必须被拒。
	w = httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"recovery_code": {codes[0]}}, loginTestIP,
		issuePending(t, s, admin.ID, loginTestIP)))
	if hasSessionCookie(w) {
		t.Fatalf("用过的恢复码又登录成功了 —— 一码一用被打破")
	}
	if w.Code == http.StatusFound {
		t.Fatalf("用过的恢复码不该走成功跳转(code=%d)", w.Code)
	}

	// 另一条没用过的仍然有效。
	w = httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"recovery_code": {codes[1]}}, loginTestIP,
		issuePending(t, s, admin.ID, loginTestIP)))
	if !hasSessionCookie(w) {
		t.Fatalf("未用过的恢复码应当可用(code=%d)", w.Code)
	}
}

// TestLoginTOTP_CodeCannotBeReplayed:同一枚 6 位码在其有效窗口内只能用一次。
//
// 码有 ~90 秒的容忍窗,肩窥 / 中间人截获后在窗口内重放就能再登一次。
// 服务端记录已消费的时间步来堵这个口。
func TestLoginTOTP_CodeCannotBeReplayed(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	code := totpCodeFor(t, secret)

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s, url.Values{"code": {code}}, loginTestIP,
		issuePending(t, s, admin.ID, loginTestIP)))
	if !hasSessionCookie(w) {
		t.Fatalf("首次登录应当成功(code=%d)", w.Code)
	}

	// 同一枚码 + 全新 pending → 时间步已被消费,必须拒。
	w = httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s, url.Values{"code": {code}}, loginTestIP,
		issuePending(t, s, admin.ID, loginTestIP)))
	if hasSessionCookie(w) {
		t.Fatalf("同一枚 6 位码被重放成功")
	}
}

// =========================================================================
// pending 的边界
// =========================================================================

// TestLoginTOTP_WithoutPendingRedirectsToLogin:没过密码步就直接来提交码 → 回登录页。
//
// 少了这道检查,第二因子就能被单独攻击:攻击者完全不用知道密码,只要枚举 6 位码。
func TestLoginTOTP_WithoutPendingRedirectsToLogin(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeFor(t, secret)}}, loginTestIP, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d, 期望 302 回登录页", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("Location=%q, 期望回 /login", loc)
	}
	if hasSessionCookie(w) {
		t.Fatalf("没过密码步却拿到了会话")
	}
}

// TestLoginTOTP_PendingIsSingleUse:同一枚 pending 提交两次,第二次必须被拒。
//
// 截获重放 / 后退再提交 / 并发双击都会命中这里。nonce 服务端一次性。
func TestLoginTOTP_PendingIsSingleUse(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	pending := issuePending(t, s, admin.ID, loginTestIP)

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeFor(t, secret)}}, loginTestIP, pending))
	if !hasSessionCookie(w) {
		t.Fatalf("首次应当成功(code=%d)", w.Code)
	}

	// 同一枚 pending 再来一次(码换成下一步的,排除「被码的重放保护挡下」的干扰)。
	w = httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeForStep(t, secret, 1)}}, loginTestIP, pending))
	if hasSessionCookie(w) {
		t.Fatalf("同一枚 pending 被复用成功")
	}
}

// TestLoginTOTP_PendingBoundToIP:pending 换个来源 IP 就失效。
func TestLoginTOTP_PendingBoundToIP(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	pending := issuePending(t, s, admin.ID, loginTestIP)

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeFor(t, secret)}}, "203.0.113.9", pending))
	if hasSessionCookie(w) {
		t.Fatalf("换 IP 后 pending 仍然可用")
	}
}

// TestLoginTOTP_PasswordChangeInvalidatesPending:应急改密要能当场斩断在途登录。
//
// pending 里签了签发时刻的密码指纹。「密码疑似泄露 → 立刻改密」之后,那些已经
// 过了密码步、只差一个码的在途请求必须全部作废,而不是等 5 分钟窗口自然过期。
func TestLoginTOTP_PasswordChangeInvalidatesPending(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	pending := issuePending(t, s, admin.ID, loginTestIP)

	newHash, err := HashWebPassword("BrandNewPass456!")
	if err != nil {
		t.Fatalf("HashWebPassword: %v", err)
	}
	if err := s.store.UpdateWebAdminPasswordHash(t.Context(), admin.ID, newHash); err != nil {
		t.Fatalf("UpdateWebAdminPasswordHash: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeFor(t, secret)}}, loginTestIP, pending))
	if hasSessionCookie(w) {
		t.Fatalf("改密后旧 pending 仍能完成登录")
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/login") {
		t.Fatalf("Location=%q, 期望回 /login 重走密码步", loc)
	}
	assertAuditAction(t, s, "web.totp.pending_stale")
}

// TestLoginTOTP_TOTPTurnedOffClearsPending:pending 期间 2FA 被关掉 → 回登录页。
func TestLoginTOTP_TOTPTurnedOffClearsPending(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	pending := issuePending(t, s, admin.ID, loginTestIP)
	if err := s.store.DisableWebAdminTOTP(t.Context(), admin.ID); err != nil {
		t.Fatalf("DisableWebAdminTOTP: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeFor(t, secret)}}, loginTestIP, pending))
	if hasSessionCookie(w) {
		t.Fatalf("2FA 已关,pending 不该还能颁会话")
	}
}

// TestLoginTOTP_DisabledAccountCannotFinishLogin:账号被停用 → pending 作废。
func TestLoginTOTP_DisabledAccountCannotFinishLogin(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	pending := issuePending(t, s, admin.ID, loginTestIP)
	if err := s.store.SetWebAdminEnabled(t.Context(), admin.ID, false); err != nil {
		t.Fatalf("SetWebAdminEnabled: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeFor(t, secret)}}, loginTestIP, pending))
	if hasSessionCookie(w) {
		t.Fatalf("已停用的账号完成了登录")
	}
}

// =========================================================================
// 失败计数与锁定
// =========================================================================

// TestLoginTOTP_WrongCodeLocksAccountEventually:码错累计到阈值 → 账号锁定。
//
// 第二因子只有 6 位十进制,不锁的话在 pending 窗口内可以直接跑字典。
// 这里连错 MaxLoginFailures 次,之后**即便码是对的**也必须被拒。
func TestLoginTOTP_WrongCodeLocksAccountEventually(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)

	for i := int64(0); i < s.cfg.MaxLoginFailures; i++ {
		w := httptest.NewRecorder()
		s.handleLoginTOTP(w, loginTOTPPost(t, s,
			url.Values{"code": {"000000"}}, loginTestIP,
			issuePending(t, s, admin.ID, loginTestIP)))
		if hasSessionCookie(w) {
			t.Fatalf("第 %d 次错码却登录成功", i+1)
		}
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.LockedUntil <= nowUnix() {
		t.Fatalf("连错 %d 次后账号未锁定(locked_until=%d)", s.cfg.MaxLoginFailures, cur.LockedUntil)
	}

	// 锁定期内,正确的码也不放行。
	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeFor(t, secret)}}, loginTestIP,
		issuePending(t, s, admin.ID, loginTestIP)))
	if hasSessionCookie(w) {
		t.Fatalf("锁定期内正确码也不该放行")
	}
	assertAuditAction(t, s, "web.totp.fail")
}

// TestLoginTOTP_EmptySubmitDoesNotCountTowardLockout:两个字段都空 = 误提交。
//
// 计入的话,连点几下提交就触发**账号级**锁定(15 分钟),比 IP 冷却重得多,
// 而用户一次码都没输错。
func TestLoginTOTP_EmptySubmitDoesNotCountTowardLockout(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	enableTOTPDirect(t, s, admin, 1)

	for i := int64(0); i < s.cfg.MaxLoginFailures+2; i++ {
		w := httptest.NewRecorder()
		s.handleLoginTOTP(w, loginTOTPPost(t, s, url.Values{}, loginTestIP,
			issuePending(t, s, admin.ID, loginTestIP)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("空提交 code=%d, 期望 401 回渲", w.Code)
		}
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.LockedUntil > nowUnix() {
		t.Fatalf("空提交把账号锁了(locked_until=%d)", cur.LockedUntil)
	}
	if cur.FailedLogins != 0 {
		t.Errorf("空提交累加了失败计数: %d", cur.FailedLogins)
	}
}

// =========================================================================
// 其它
// =========================================================================

// TestLoginTOTP_NextIsSanitized:登录后的跳转目标是用户可控的,不能跳出本站。
//
// 「登录成功后被送到钓鱼页」是钓鱼里最好使的一招 —— 用户刚输完密码和二次验证码,
// 对紧接着出现的页面几乎不设防。
func TestLoginTOTP_NextIsSanitized(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	// 每轮用一条新的恢复码:6 位码只有 ±1 个时间步的容忍窗,连登三次没有三枚
	// 互不重放的码可用。
	_, codes := enableTOTPDirect(t, s, admin, 3)

	for i, c := range []struct{ next, wantPrefix string }{
		{"https://evil.example.com/x", "/"},
		{"//evil.example.com/x", "/"},
		{"/devices", "/devices"},
	} {
		w := httptest.NewRecorder()
		s.handleLoginTOTP(w, loginTOTPPost(t, s, url.Values{
			"recovery_code": {codes[i]},
			"next":          {c.next},
		}, loginTestIP, issuePending(t, s, admin.ID, loginTestIP)))
		loc := w.Header().Get("Location")
		if strings.Contains(loc, "evil.example.com") {
			t.Fatalf("next=%q 把用户送出了本站: %q", c.next, loc)
		}
		if !strings.HasPrefix(loc, c.wantPrefix) {
			t.Errorf("next=%q → Location=%q, 期望以 %q 开头", c.next, loc, c.wantPrefix)
		}
	}
}

// TestLoginTOTP_RequiresCSRF:第二因子提交同样要过 CSRF。
func TestLoginTOTP_RequiresCSRF(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)

	req := httptest.NewRequest(http.MethodPost, "/login/totp",
		strings.NewReader("code="+totpCodeFor(t, secret)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(issuePending(t, s, admin.ID, loginTestIP))
	req.RemoteAddr = loginTestIP + ":40000"
	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("无 CSRF code=%d, 期望 403", w.Code)
	}
	if hasSessionCookie(w) {
		t.Fatalf("无 CSRF 却颁了会话")
	}
}

// TestLoginTOTP_RejectsOtherMethods:只认 GET(渲染表单)与 POST(提交)。
func TestLoginTOTP_RejectsOtherMethods(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	enableTOTPDirect(t, s, admin, 1)

	req := httptest.NewRequest(http.MethodDelete, "/login/totp", nil)
	req.AddCookie(issuePending(t, s, admin.ID, loginTestIP))
	req.RemoteAddr = loginTestIP + ":40000"
	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE code=%d, 期望 405", w.Code)
	}
}
