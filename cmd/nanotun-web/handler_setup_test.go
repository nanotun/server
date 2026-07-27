package main

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件覆盖 /setup —— 全新部署里唯一一个**无需登录**就能写库的端点。
//
// 它的危险性来自那个 TOFU 窗口:从进程起来到首个管理员建成之间,任何能连上
// 这个端口的人 POST 一次就成了系统主人。所以这里要钉死的不是「表单好不好用」,
// 而是这扇门什么时候必须是关着的:
//   - 配置里关掉了 setup(首管由 CLI 下发)→ 永远 302 /login;
//   - 已经有任何管理员 → 永远 302 /login,GET 连表单都不给渲染;
//   - 抢建成功后再来一次 → 落败方也只能拿到 302,不能多建一个。
//
// 以及一条容易被忽略的:首位管理员必须是 admin 角色。若能被引导成 viewer,
// 表一非空 setup 即永久关闭,而 viewer 无权建 admin —— 控制台被永久锁成只读,
// 没有任何 Web 侧的补救路径。

// setupPost 造一个 CSRF + 验证码都合法的 POST /setup。
func setupPost(t *testing.T, s *Server, form url.Values) *http.Request {
	t.Helper()
	issueW := httptest.NewRecorder()
	tok, err := s.sess.IssueCSRFToken(httptest.NewRequest(http.MethodGet, "/setup", nil), issueW)
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
	form.Set("captcha", answer)

	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range issueW.Result().Cookies() {
		req.AddCookie(c)
	}
	req.AddCookie(&http.Cookie{
		Name: s.sess.cookieName(captchaCookieName),
		Value: encodeCaptchaCookie(s.sess.captchaHMACKey, answer, nonce,
			nowUnix()+captchaTTLSec),
	})
	req.RemoteAddr = "198.51.100.9:40000"
	return req
}

func goodSetupForm() url.Values {
	return url.Values{
		"username":         {"firstadmin"},
		"password":         {"S3tup-Passw0rd!x"},
		"password_confirm": {"S3tup-Passw0rd!x"},
	}
}

func countAdmins(t *testing.T, s *Server) int64 {
	t.Helper()
	n, err := s.store.CountWebAdmins(t.Context())
	if err != nil {
		t.Fatalf("CountWebAdmins: %v", err)
	}
	return n
}

// -------------------------------------------------------------------------
// 门什么时候是关着的
// -------------------------------------------------------------------------

func TestSetup_ClosedWhenAllowSetupIsFalse(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = false

	// 运维显式关掉 setup(首管改由 CLI provision)时,即便库是空的也不能开门。
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		var req *http.Request
		if m == http.MethodGet {
			req = httptest.NewRequest(http.MethodGet, "/setup", nil)
		} else {
			req = setupPost(t, s, goodSetupForm())
		}
		w := httptest.NewRecorder()
		s.handleSetup(w, req)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("%s: code=%d loc=%q, 期望 302 /login", m, w.Code, w.Header().Get("Location"))
		}
	}
	if n := countAdmins(t, s); n != 0 {
		t.Fatalf("关闭 setup 却建出了 %d 个管理员", n)
	}
}

func TestSetup_ClosedOnceAnyAdminExists(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true
	existing := createTestAdmin(t, s, "incumbent", "pw-incumbent-123")

	for _, m := range []string{http.MethodGet, http.MethodPost} {
		var req *http.Request
		if m == http.MethodGet {
			req = httptest.NewRequest(http.MethodGet, "/setup", nil)
		} else {
			req = setupPost(t, s, goodSetupForm())
		}
		w := httptest.NewRecorder()
		s.handleSetup(w, req)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("%s: code=%d loc=%q, 期望 302 /login", m, w.Code, w.Header().Get("Location"))
		}
	}
	if n := countAdmins(t, s); n != 1 {
		t.Fatalf("管理员数=%d, 期望仍是 1", n)
	}
	if adminByName(t, s, "firstadmin") != nil {
		t.Fatal("setup 在已初始化的系统上又建了一个管理员")
	}
	// 已有管理员必须原样不动(没被改密 / 改角色)。
	if got := mustGetAdmin(t, s, existing.ID); got.PasswordHash != existing.PasswordHash {
		t.Fatal("既有管理员的密码被动了")
	}
}

// 一个被禁用的管理员也算「已初始化」:否则把唯一管理员停用后,
// setup 会重新打开,任何人都能抢一个新的 admin 出来。
func TestSetup_DisabledAdminStillCountsAsInitialized(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true
	a := createTestAdmin(t, s, "sleeping", "pw-sleeping-1234")
	if err := s.store.SetWebAdminEnabled(t.Context(), a.ID, false); err != nil {
		t.Fatalf("SetWebAdminEnabled: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleSetup(w, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d, 期望 302 —— 停用的管理员也是管理员", w.Code)
	}
}

// -------------------------------------------------------------------------
// 正常首建
// -------------------------------------------------------------------------

func TestSetup_GETRendersFormWhenEmpty(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true

	w := httptest.NewRecorder()
	s.handleSetup(w, httptest.NewRequest(http.MethodGet, "/setup", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	// 表单要能真提交:CSRF 与验证码两个 cookie 都得下发。
	var hasCSRF, hasCaptcha bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case s.sess.cookieName(csrfCookieName):
			hasCSRF = true
		case s.sess.cookieName(captchaCookieName):
			hasCaptcha = true
		}
	}
	if !hasCSRF || !hasCaptcha {
		t.Fatalf("cookie 缺失: csrf=%v captcha=%v", hasCSRF, hasCaptcha)
	}
}

func TestSetup_CreatesFirstAdminAndLogsIn(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true

	w := httptest.NewRecorder()
	s.handleSetup(w, setupPost(t, s, goodSetupForm()))

	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" {
		t.Fatalf("code=%d loc=%q body=%q", w.Code, w.Header().Get("Location"),
			trimForLog(w.Body.String()))
	}
	got := adminByName(t, s, "firstadmin")
	if got == nil {
		t.Fatal("首个管理员没建出来")
	}
	if got.Role != "admin" {
		t.Fatalf("role=%q, 期望 admin", got.Role)
	}
	if !got.Enabled {
		t.Fatal("首个管理员应当是启用状态")
	}
	if strings.Contains(got.PasswordHash, "S3tup") {
		t.Fatal("密码没有被哈希")
	}
	// 建完直接登入,不该让人再去登录页手输一遍刚设的密码。
	var sessCookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == s.sess.cookieName(sessionCookieName) && c.Value != "" {
			sessCookie = c.Value
		}
	}
	if sessCookie == "" {
		t.Fatal("setup 成功却没有颁发会话")
	}
	if ws, err := s.store.GetWebSession(t.Context(), sessCookie); err != nil || ws.AdminID != got.ID {
		t.Fatalf("会话没落库或归属不对: %v", err)
	}
	assertAuditAction(t, s, "web.setup")
}

func TestSetup_FirstAdminIsForcedToAdminRole(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true

	// 表单里塞 role=viewer。handler 硬编码 admin,store 的 CreateFirstWebAdmin 再兜一层。
	// 这条一旦破了,系统会永久停在「只有一个 viewer、谁也提不了权」的死局。
	form := goodSetupForm()
	form.Set("role", "viewer")
	w := httptest.NewRecorder()
	s.handleSetup(w, setupPost(t, s, form))
	if w.Code != http.StatusFound {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if got := adminByName(t, s, "firstadmin"); got == nil || got.Role != "admin" {
		t.Fatalf("首个管理员角色=%v, 期望 admin", got)
	}
}

func TestSetup_StoreLayerAlsoForcesAdminRole(t *testing.T) {
	s := newMeTestServer(t)
	// 绕过 handler 直接调 DAL —— 任何绕过 handler 的路径(CLI、迁移脚本)也不能造出 viewer 首管。
	a, err := s.store.CreateFirstWebAdmin(t.Context(), store.NewWebAdmin{
		Username: "viaDAL", PasswordHash: "x", Role: "viewer",
	})
	if err != nil {
		t.Fatalf("CreateFirstWebAdmin: %v", err)
	}
	if a.Role != "admin" {
		t.Fatalf("role=%q, 期望 DAL 强制为 admin", a.Role)
	}
}

func TestSetup_SecondCreationIsClosedAtDAL(t *testing.T) {
	s := newMeTestServer(t)
	createTestAdmin(t, s, "incumbent", "pw-incumbent-123")

	// 并发下两个 POST 都可能过了 CountWebAdmins==0 的预检,靠这条 SQL 的原子性收口。
	_, err := s.store.CreateFirstWebAdmin(t.Context(), store.NewWebAdmin{
		Username: "racer", PasswordHash: "x",
	})
	if err != store.ErrSetupClosed {
		t.Fatalf("err=%v, 期望 ErrSetupClosed", err)
	}
	if adminByName(t, s, "racer") != nil {
		t.Fatal("竞争落败者也建出了一个管理员")
	}
}

// -------------------------------------------------------------------------
// 坏输入
// -------------------------------------------------------------------------

func TestSetup_RejectsBadInputWithoutCreating(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
	}{
		{"用户名为空", url.Values{
			"username": {""}, "password": {"S3tup-Passw0rd!x"}, "password_confirm": {"S3tup-Passw0rd!x"}}},
		{"用户名只有空白", url.Values{
			"username": {"   "}, "password": {"S3tup-Passw0rd!x"}, "password_confirm": {"S3tup-Passw0rd!x"}}},
		{"用户名不足 3 字符", url.Values{
			"username": {"ab"}, "password": {"S3tup-Passw0rd!x"}, "password_confirm": {"S3tup-Passw0rd!x"}}},
		{"两次密码不一致", url.Values{
			"username": {"firstadmin"}, "password": {"S3tup-Passw0rd!x"}, "password_confirm": {"Other-Passw0rd!x"}}},
		{"密码太弱", url.Values{
			"username": {"firstadmin"}, "password": {"123"}, "password_confirm": {"123"}}},
		{"密码为空", url.Values{
			"username": {"firstadmin"}, "password": {""}, "password_confirm": {""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			s.cfg.AllowSetup = true

			w := httptest.NewRecorder()
			s.handleSetup(w, setupPost(t, s, tc.form))

			if w.Code == http.StatusFound {
				t.Fatalf("竟然创建成功了(302 → %q)", w.Header().Get("Location"))
			}
			if n := countAdmins(t, s); n != 0 {
				t.Fatalf("建出了 %d 个管理员", n)
			}
			// 失败也不能顺手发一枚会话。
			for _, c := range w.Result().Cookies() {
				if c.Name == s.sess.cookieName(sessionCookieName) && c.Value != "" {
					t.Fatal("失败路径颁发了会话 cookie")
				}
			}
		})
	}
}

func TestSetup_RequiresCSRF(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true

	req := setupPost(t, s, goodSetupForm())
	// 篡改 form 里的 token,cookie 保持不变 → double-submit 不一致。
	body, _ := url.ParseQuery(readAllString(t, req))
	body.Set("csrf_token", "tampered.value")
	req2 := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(body.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Cookie", req.Header.Get("Cookie"))
	for _, c := range req.Cookies() {
		req2.AddCookie(c)
	}

	w := httptest.NewRecorder()
	s.handleSetup(w, req2)
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d, 期望 403", w.Code)
	}
	if n := countAdmins(t, s); n != 0 {
		t.Fatalf("CSRF 不过却建出了 %d 个管理员", n)
	}
}

func TestSetup_RequiresCaptcha(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true

	// 有 CSRF、没验证码。TOFU 窗口本来就短,验证码是拦自动化抢占脚本的第一道闸。
	issueW := httptest.NewRecorder()
	tok, err := s.sess.IssueCSRFToken(httptest.NewRequest(http.MethodGet, "/setup", nil), issueW)
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}
	form := goodSetupForm()
	form.Set("csrf_token", tok)
	req := httptest.NewRequest(http.MethodPost, "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range issueW.Result().Cookies() {
		req.AddCookie(c)
	}

	w := httptest.NewRecorder()
	s.handleSetup(w, req)
	if w.Code == http.StatusFound {
		t.Fatal("没有验证码也建成了首个管理员")
	}
	if n := countAdmins(t, s); n != 0 {
		t.Fatalf("建出了 %d 个管理员", n)
	}
	assertAuditAction(t, s, "web.setup.captcha_fail")
}

func TestSetup_RejectsOtherMethods(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true

	for _, m := range []string{http.MethodDelete, http.MethodPut, http.MethodPatch} {
		w := httptest.NewRecorder()
		s.handleSetup(w, httptest.NewRequest(m, "/setup", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: code=%d, 期望 405", m, w.Code)
		}
		if got := w.Header().Get("Allow"); got != "GET, POST" {
			t.Errorf("%s: Allow=%q", m, got)
		}
	}
}

// readAllString 把请求体读成字符串(仅测试内部用,请求体随后不再使用)。
func readAllString(t *testing.T, r *http.Request) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := r.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
