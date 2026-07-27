package main

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// 本文件覆盖登录的**密码步** handler:POST /login。
//
// auth_test.go 测的是 AttemptLogin 这个函数(认证判定本身),而 handler 这一层做的
// 是另一件事:判定通过之后**发什么**。开了 2FA 的账号只能拿到 pending 转场票、
// 不能拿会话;没开的直接发会话;跳转目标要收敛;还要顺手清掉浏览器里别人残留的
// pending。这些都不在 AttemptLogin 里,此前也没有测试碰过。

// loginPost 造一个 CSRF 与验证码都合法的 POST /login。
//
// 验证码走 encodeCaptchaCookie 自签(与 captcha_test.go 同法):图是给人看的,
// 测试只需要一张服务端认得的 cookie + 对应答案。验证码本身的强度另有测试。
func loginPost(t *testing.T, s *Server, form url.Values, ip string, extra ...*http.Cookie) *http.Request {
	t.Helper()
	issueW := httptest.NewRecorder()
	tok, err := s.sess.IssueCSRFToken(httptest.NewRequest(http.MethodGet, "/login", nil), issueW)
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", tok)
	answer, err := randomDigits(captchaDigits)
	if err != nil {
		t.Fatalf("randomDigits: %v", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	captchaCookie := &http.Cookie{
		Name: s.sess.cookieName(captchaCookieName),
		Value: encodeCaptchaCookie(s.sess.captchaHMACKey, answer, nonce,
			nowUnix()+captchaTTLSec),
	}
	form.Set("captcha", answer)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range issueW.Result().Cookies() {
		req.AddCookie(c)
	}
	req.AddCookie(captchaCookie)
	for _, c := range extra {
		req.AddCookie(c)
	}
	req.RemoteAddr = ip + ":40000"
	return req
}

// pendingCookieOf 从响应里取 pending 2FA cookie(没有则 nil)。
func pendingCookieOf(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "pending") {
			return c
		}
	}
	return nil
}

// =========================================================================

// TestLogin_NonTOTPAccountGetsSessionImmediately:没开 2FA 的账号,密码对就发会话。
func TestLogin_NonTOTPAccountGetsSessionImmediately(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	createTestAdmin(t, s, "alice", pw)

	w := httptest.NewRecorder()
	s.handleLogin(w, loginPost(t, s, url.Values{
		"username": {"alice"}, "password": {pw},
	}, loginTestIP))
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d body=%q, 期望 302", w.Code, trimForLog(w.Body.String()))
	}
	if !hasSessionCookie(w) {
		t.Fatalf("没开 2FA 的账号登录后应当直接拿到会话")
	}
	assertAuditAction(t, s, "web.login.ok")
}

// TestLogin_TOTPAccountGetsPendingNotSession:开了 2FA 的账号,密码对**也不能**发会话。
//
// 这一步发错了,2FA 就完全不存在了 —— 攻击者拿到密码即登录成功,第二因子页面
// 根本不会出现。属于「功能看起来正常、防护实际为零」那一类。
func TestLogin_TOTPAccountGetsPendingNotSession(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	enableTOTPDirect(t, s, admin, 1)

	w := httptest.NewRecorder()
	s.handleLogin(w, loginPost(t, s, url.Values{
		"username": {"alice"}, "password": {pw},
	}, loginTestIP))
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d, 期望 302", w.Code)
	}
	if hasSessionCookie(w) {
		t.Fatalf("开了 2FA 的账号只输密码就拿到了会话 —— 第二因子被跳过")
	}
	if pendingCookieOf(w) == nil {
		t.Fatalf("没有下发 pending 转场票")
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/login/totp") {
		t.Fatalf("Location=%q, 期望跳到 /login/totp", loc)
	}
	assertAuditAction(t, s, "web.login.password_ok_await_totp")
}

// TestLogin_WrongPasswordIssuesNothing:密码错既不发会话也不发 pending。
func TestLogin_WrongPasswordIssuesNothing(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	enableTOTPDirect(t, s, admin, 1)

	w := httptest.NewRecorder()
	s.handleLogin(w, loginPost(t, s, url.Values{
		"username": {"alice"}, "password": {"WrongPass456!"},
	}, loginTestIP))
	if hasSessionCookie(w) {
		t.Fatalf("密码错却发了会话")
	}
	if c := pendingCookieOf(w); c != nil && c.Value != "" {
		t.Fatalf("密码错却发了 pending 转场票")
	}
	assertAuditAction(t, s, "web.login.fail")
}

// TestLogin_UnknownUserIssuesNothing:不存在的用户名同样什么都不发。
func TestLogin_UnknownUserIssuesNothing(t *testing.T) {
	s := newMeTestServer(t)
	createTestAdmin(t, s, "alice", "AdminPass123!")

	w := httptest.NewRecorder()
	s.handleLogin(w, loginPost(t, s, url.Values{
		"username": {"nobody"}, "password": {"AdminPass123!"},
	}, loginTestIP))
	if hasSessionCookie(w) || pendingCookieOf(w) != nil {
		t.Fatalf("未知用户名却发了凭据")
	}
}

// TestLogin_NextIsSanitized:两条分支的跳转目标都要收敛到站内。
//
// 钓鱼站带着 next=https://evil/x 把受害者送来,登录成功后再弹回自己 —— 受害者
// 刚在真站输完密码,对下一个页面几乎不设防。
func TestLogin_NextIsSanitized(t *testing.T) {
	const pw = "AdminPass123!"
	for _, withTOTP := range []bool{false, true} {
		for _, c := range []struct{ next, wantPrefix string }{
			{"https://evil.example.com/x", "/"},
			{"//evil.example.com/x", "/"},
			{"/\\evil.example.com", "/"},
			{"/devices", "/devices"},
		} {
			s := newMeTestServer(t)
			admin := createTestAdmin(t, s, "alice", pw)
			wantPrefix := c.wantPrefix
			if withTOTP {
				enableTOTPDirect(t, s, admin, 1)
				wantPrefix = "/login/totp"
			}
			w := httptest.NewRecorder()
			s.handleLogin(w, loginPost(t, s, url.Values{
				"username": {"alice"}, "password": {pw}, "next": {c.next},
			}, loginTestIP))
			loc := w.Header().Get("Location")
			if strings.Contains(loc, "evil.example.com") {
				t.Fatalf("2fa=%v next=%q 把用户送出了本站: %q", withTOTP, c.next, loc)
			}
			if !strings.HasPrefix(loc, wantPrefix) {
				t.Errorf("2fa=%v next=%q → Location=%q, 期望以 %q 开头",
					withTOTP, c.next, loc, wantPrefix)
			}
		}
	}
}

// TestLogin_SuccessClearsAnotherAdminsPending:登录成功要清掉浏览器里残留的 pending。
//
// 具体场景(代码注释里记的那个):管理员 A 开了 2FA,在这台浏览器上过了密码步、
// 拿到一枚 5 分钟有效的 pending;紧接着管理员 B(没开 2FA)在同一浏览器登录成功。
// 若不清,A 的 pending 还活着 —— 谁只要拿到 A 的第二因子,就能直接完成 /login/totp
// 变成 A,**完全不用再输 A 的密码**。
func TestLogin_SuccessClearsAnotherAdminsPending(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	adminA := createTestAdmin(t, s, "alice", pw)
	secret, _ := enableTOTPDirect(t, s, adminA, 1)
	createTestAdmin(t, s, "bob", pw) // bob 没开 2FA

	// A 过密码步,拿到 pending。
	wA := httptest.NewRecorder()
	s.handleLogin(wA, loginPost(t, s, url.Values{
		"username": {"alice"}, "password": {pw},
	}, loginTestIP))
	pendingA := pendingCookieOf(wA)
	if pendingA == nil || pendingA.Value == "" {
		t.Fatalf("A 没拿到 pending")
	}

	// 同一浏览器上 B 登录成功。
	wB := httptest.NewRecorder()
	s.handleLogin(wB, loginPost(t, s, url.Values{
		"username": {"bob"}, "password": {pw},
	}, loginTestIP, pendingA))
	if !hasSessionCookie(wB) {
		t.Fatalf("B 应当登录成功(code=%d)", wB.Code)
	}
	cleared := pendingCookieOf(wB)
	if cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Fatalf("B 登录成功后没有清掉 A 的 pending: %+v", cleared)
	}

	// 反面确认:如果 A 的 pending 还能用,那枚票加上 A 的码就能变成 A。
	// 这里直接拿旧 cookie 去走第二因子,应当**已经**因为 cookie 被清而不再随请求发出;
	// 模拟「浏览器没听话、仍然带着旧 cookie」的最坏情况,至少不能出现新会话之外的旁路。
	wC := httptest.NewRecorder()
	s.handleLoginTOTP(wC, loginTOTPPost(t, s,
		url.Values{"code": {totpCodeFor(t, secret)}}, loginTestIP, pendingA))
	if wC.Code == http.StatusFound && hasSessionCookie(wC) {
		// 这一步在当前实现下**会**成功(pending 是签名 cookie,服务端只在响应里
		// 让浏览器丢弃它,并不维护黑名单)。记录下来而不判失败:清 cookie 是针对
		// 「同一个听话的浏览器」的防御,不是针对已经把 cookie 抄走的攻击者。
		t.Logf("提示:被清掉的 pending 若被手工重放仍可用 —— 清 cookie 只防同浏览器串号,"+
			"不构成对已窃取 cookie 的防御(pending 仍受 %d 秒 TTL 与 IP 绑定约束)", pending2FATTLSec)
	}
}

// TestLogin_RequiresCaptcha:没有验证码(或答错)时,密码根本不该被拿去比对。
//
// 验证码的算法本身在 captcha_test.go 里测过了,这里测的是**接线** —— /login 真的
// 把它挡在密码之前。掉了这道闸,撞库脚本就能直连 argon2:既能试密码,又是一台
// 免费的 CPU 消耗器。
func TestLogin_RequiresCaptcha(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	createTestAdmin(t, s, "alice", pw)

	// 用正常方式造请求,再把验证码答案改错 / 把 cookie 拿掉。
	for _, c := range []struct {
		name       string
		mangle     func(*http.Request)
		wrongInput bool
	}{
		{name: "答案错", wrongInput: true},
		{name: "没有验证码 cookie", mangle: func(r *http.Request) {
			// 重建 Cookie 头,滤掉 captcha。
			var kept []string
			for _, ck := range r.Cookies() {
				if ck.Name != s.sess.cookieName(captchaCookieName) {
					kept = append(kept, ck.Name+"="+ck.Value)
				}
			}
			r.Header.Set("Cookie", strings.Join(kept, "; "))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			form := url.Values{"username": {"alice"}, "password": {pw}}
			req := loginPost(t, s, form, loginTestIP)
			if c.wrongInput {
				// 重新编码 body,把 captcha 换成一个必错的答案。
				form.Set("captcha", "!!!!")
				body := form.Encode()
				req2 := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
				req2.Header = req.Header.Clone()
				req2.RemoteAddr = req.RemoteAddr
				req = req2
			}
			if c.mangle != nil {
				c.mangle(req)
			}
			w := httptest.NewRecorder()
			s.handleLogin(w, req)
			if hasSessionCookie(w) {
				t.Fatalf("验证码没过却发了会话(code=%d)", w.Code)
			}
		})
	}
}

// TestLogin_RequiresCSRF:密码步同样要过 CSRF。
func TestLogin_RequiresCSRF(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	createTestAdmin(t, s, "alice", pw)

	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("username=alice&password="+url.QueryEscape(pw)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = loginTestIP + ":40000"
	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("无 CSRF code=%d, 期望 403", w.Code)
	}
	if hasSessionCookie(w) {
		t.Fatalf("无 CSRF 却发了会话")
	}
}

// TestLogin_RejectsOtherMethods:只认 GET / POST。
func TestLogin_RejectsOtherMethods(t *testing.T) {
	s := newMeTestServer(t)
	// 必须先有 admin:一个 admin 都没有时任何方法都会被先跳到 /setup。
	createTestAdmin(t, s, "alice", "AdminPass123!")
	w := httptest.NewRecorder()
	s.handleLogin(w, httptest.NewRequest(http.MethodDelete, "/login", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE code=%d, 期望 405", w.Code)
	}
}
