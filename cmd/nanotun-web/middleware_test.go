package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件覆盖 middleware.go —— Web UI 的门禁本身。
//
// 之前所有 handler 测试都是「把 admin 直接塞进 ctx」再调 handler,等于绕过了
// requireAuth / requireCSRFAndAuth。也就是说:每个页面的业务逻辑都测了,唯独
// 「谁能进这些页面」这条控制线一次都没跑过。这层要是破了(比如 admin 被禁用后
// 旧 cookie 仍然放行、或 CSRF token 能跨会话复用),下面测得再细也没有意义。
//
// 重点在四条不变量:
//   - 无 session:GET 引导去登录且带回跳,写方法直接 401,handler 一次都不能被调到;
//   - admin 被禁用 / session 被删:活着的 cookie 立即失效;
//   - 认证先于 CSRF:未登录的 POST 应该是 401(未登录),不是 403(token 不对);
//   - CSRF token 绑定 session:A 会话里签发的 token 拿到 B 会话用必须被拒(反 cookie-tossing)。

// spyHandler 记录自己有没有被调用,以及被调用时 ctx 里是什么。
// 中间件测试的核心断言是「next 到底有没有被放行」,光看状态码不够 ——
// handler 可能已经跑完副作用了才被后置逻辑改写成 4xx。
type spyHandler struct {
	called    int
	gotAdmin  *store.WebAdmin
	gotSID    string
	gotCSRF   string
	panicWith any
}

func (h *spyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called++
	h.gotAdmin = adminFromCtx(r.Context())
	if v, ok := r.Context().Value(ctxKeySessionID).(string); ok {
		h.gotSID = v
	}
	h.gotCSRF = csrfTokenFromCtx(r.Context())
	if h.panicWith != nil {
		panic(h.panicWith)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// loginAs 给 admin 真发一条 session,返回可直接塞进请求的 Cookie 头与 session id。
// 不走 /login(那条路有验证码与 2FA),这里只要「一个合法的登录态」。
func loginAs(t *testing.T, s *Server, admin *store.WebAdmin) (cookie, sid string) {
	t.Helper()
	w := httptest.NewRecorder()
	sid, err := s.sess.IssueSession(t.Context(), w, admin.ID, "10.0.0.1", "go-test")
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	return w.Header().Get("Set-Cookie"), sid
}

// getThrough 用给定 cookie 跑一次 GET,返回响应。cookie 可为空(未登录)。
func getThrough(h http.Handler, target, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// -------------------------------------------------------------------------
// requireAuth
// -------------------------------------------------------------------------

func TestRequireAuth_NoSessionGETRedirectsWithNext(t *testing.T) {
	s := newMeTestServer(t)
	spy := &spyHandler{}
	h := s.requireAuth(spy)

	w := getThrough(h, "/devices?q=a&page=2", "")

	if w.Code != http.StatusFound {
		t.Fatalf("code=%d, 期望 302", w.Code)
	}
	// urlQueryEscape 保留 '/' 与 ':',其余全转义 —— next 是原路径的可逆编码。
	if got, want := w.Header().Get("Location"), "/login?next=/devices%3Fq%3Da%26page%3D2"; got != want {
		t.Fatalf("Location=%q, 期望 %q", got, want)
	}
	if spy.called != 0 {
		t.Fatalf("未登录却把请求放进了 handler(called=%d)", spy.called)
	}
}

func TestRequireAuth_NoSelfLoopOnRootAndLogin(t *testing.T) {
	s := newMeTestServer(t)
	h := s.requireAuth(&spyHandler{})

	// "/" 与 /login* 不带 next:否则登录成功后又跳回登录页,肉眼看是「登不进去」。
	for _, target := range []string{"/", "/login", "/login?next=/devices"} {
		w := getThrough(h, target, "")
		if got := w.Header().Get("Location"); got != "/login" {
			t.Errorf("%s: Location=%q, 期望裸 /login(不带 next)", target, got)
		}
	}
}

func TestRequireAuth_ProtocolRelativeNextIsNeutralizedAtLogin(t *testing.T) {
	s := newMeTestServer(t)
	h := s.requireAuth(&spyHandler{})

	// 协议相对 URL:浏览器把 //evil.com/x 当作跳去另一个站。
	//
	// requireAuth **不**在这里过滤 —— 它照抄 r.URL.RequestURI()。对 `//evil.com/x`,
	// url.ParseRequestURI 不解析 authority,整串留在 Path 里,于是 next 里确实带着
	// evil.com。这不是漏洞,但也不是「中间件挡住了」:真正的闸门在消费端 /login 的
	// sanitizeReturnTo(显式拒绝 `//` 前缀)。这里把两层的衔接钉死 —— 哪天有人放宽
	// sanitizeReturnTo,这条会立刻响,而不是等着变成开放重定向。
	w := getThrough(h, "//evil.com/x", "")
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?next=") {
		t.Fatalf("Location=%q, 期望 /login?next=...", loc)
	}

	raw, err := url.ParseQuery(strings.TrimPrefix(loc, "/login?"))
	if err != nil {
		t.Fatalf("解析 Location query: %v", err)
	}
	next := raw.Get("next")
	if next != "//evil.com/x" {
		t.Fatalf("next=%q, 期望中间件原样透传 //evil.com/x", next)
	}
	if got := sanitizeReturnTo(next, ""); got != "/" {
		t.Fatalf("sanitizeReturnTo(%q)=%q, 期望回落到首页 /", next, got)
	}
}

func TestRequireAuth_NonGETWithoutSessionIs401(t *testing.T) {
	s := newMeTestServer(t)
	spy := &spyHandler{}
	h := s.requireAuth(spy)

	for _, m := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
		req := httptest.NewRequest(m, "/devices/1/delete", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		// 写方法不重定向:表单 POST 被 302 到登录页会丢掉整个 body,
		// 且 302 对 fetch/XHR 是静默的,401 才能让调用方看见「你没登录」。
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: code=%d, 期望 401", m, w.Code)
		}
	}
	if spy.called != 0 {
		t.Fatalf("未登录的写请求被放行了(called=%d)", spy.called)
	}
}

func TestRequireAuth_ValidSessionInjectsAdminAndSessionID(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "pw-alice-12345")
	cookie, sid := loginAs(t, s, admin)

	spy := &spyHandler{}
	w := getThrough(s.requireAuth(spy), "/devices", cookie)

	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, 期望 200", w.Code)
	}
	if spy.called != 1 {
		t.Fatalf("handler 调用 %d 次, 期望 1", spy.called)
	}
	if spy.gotAdmin == nil || spy.gotAdmin.ID != admin.ID {
		t.Fatalf("ctx 里的 admin=%+v, 期望 id=%d", spy.gotAdmin, admin.ID)
	}
	// session id 必须一并注入:CSRF 绑定与「登出其它设备」都靠它认自己。
	if spy.gotSID != sid {
		t.Fatalf("ctx 里的 session id=%q, 期望 %q", spy.gotSID, sid)
	}
}

func TestRequireAuth_DisabledAdminLosesLiveSession(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "bob", "pw-bob-12345678")
	cookie, _ := loginAs(t, s, admin)

	// 先确认这条 cookie 本来是好使的,免得下面的 302 是因为别的原因。
	if w := getThrough(s.requireAuth(&spyHandler{}), "/devices", cookie); w.Code != http.StatusOK {
		t.Fatalf("禁用前 code=%d, 期望 200", w.Code)
	}

	if err := s.store.SetWebAdminEnabled(t.Context(), admin.ID, false); err != nil {
		t.Fatalf("SetWebAdminEnabled: %v", err)
	}

	// 禁用一个管理员如果只挡住新登录、放过已经握在手里的 cookie,那「禁用」就是个摆设。
	spy := &spyHandler{}
	w := getThrough(s.requireAuth(spy), "/devices", cookie)
	if w.Code != http.StatusFound {
		t.Fatalf("禁用后 code=%d, 期望 302(视为未登录)", w.Code)
	}
	if spy.called != 0 {
		t.Fatalf("被禁用的 admin 仍被放行(called=%d)", spy.called)
	}
}

func TestRequireAuth_DeletedSessionIsRejected(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "carol", "pw-carol-1234567")
	cookie, sid := loginAs(t, s, admin)

	if err := s.store.DeleteWebSession(t.Context(), sid); err != nil {
		t.Fatalf("DeleteWebSession: %v", err)
	}

	spy := &spyHandler{}
	if w := getThrough(s.requireAuth(spy), "/devices", cookie); w.Code != http.StatusFound {
		t.Fatalf("code=%d, 期望 302", w.Code)
	}
	if spy.called != 0 {
		t.Fatalf("已删除的 session 仍被放行(called=%d)", spy.called)
	}
}

func TestRequireAuth_MalformedCookieIsRejected(t *testing.T) {
	s := newMeTestServer(t)
	name := s.sess.cookieName(sessionCookieName)

	// 长度明显不对的 id 在查库前就该被挡掉。
	for _, v := range []string{"", "short", strings.Repeat("x", 200)} {
		spy := &spyHandler{}
		w := getThrough(s.requireAuth(spy), "/devices", name+"="+v)
		if w.Code != http.StatusFound {
			t.Errorf("cookie=%q: code=%d, 期望 302", trimForLog(v), w.Code)
		}
		if spy.called != 0 {
			t.Errorf("cookie=%q 被放行了", trimForLog(v))
		}
	}
}

// -------------------------------------------------------------------------
// requireCSRFAndAuth
// -------------------------------------------------------------------------

// authedGETForCSRF 走一遍真实的 GET,拿到「这个 session 视图里」的 csrf token 与 cookie 串。
// 直接调 IssueCSRFToken 拿不到会话绑定(boundID 来自 ctx),必须过中间件。
func authedGETForCSRF(t *testing.T, s *Server, sessCookie string) (token, cookies string) {
	t.Helper()
	spy := &spyHandler{}
	w := getThrough(s.requireCSRFAndAuth(spy), "/acl", sessCookie)
	if w.Code != http.StatusOK {
		t.Fatalf("GET 取 token: code=%d", w.Code)
	}
	if spy.gotCSRF == "" {
		t.Fatalf("GET 之后 ctx 里没有 csrf token")
	}
	csrfCookie := ""
	for _, sc := range w.Result().Cookies() {
		if sc.Name == s.sess.cookieName(csrfCookieName) {
			csrfCookie = sc.Name + "=" + sc.Value
		}
	}
	if csrfCookie == "" {
		t.Fatalf("GET 没有下发 csrf cookie")
	}
	return spy.gotCSRF, sessCookie + "; " + csrfCookie
}

func TestRequireCSRFAndAuth_GETInjectsUsableToken(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "dave", "pw-dave-12345678")
	sessCookie, _ := loginAs(t, s, admin)

	token, cookies := authedGETForCSRF(t, s, sessCookie)

	// 这枚 token 必须真能用来提交,否则页面渲染出来就是个死表单。
	spy := &spyHandler{}
	req := postWithCookies(t, "/acl/new", url.Values{"csrf_token": {token}}, cookies)
	w := httptest.NewRecorder()
	s.requireCSRFAndAuth(spy).ServeHTTP(w, req)
	if w.Code != http.StatusOK || spy.called != 1 {
		t.Fatalf("带 GET 拿到的 token 提交: code=%d called=%d, 期望 200/1", w.Code, spy.called)
	}
}

func TestRequireCSRFAndAuth_GETIsIdempotentForToken(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "erin", "pw-erin-12345678")
	sessCookie, _ := loginAs(t, s, admin)

	first, cookies := authedGETForCSRF(t, s, sessCookie)

	// 浏览器加载一个页面会顺带发若干 GET(favicon、图片)。若每次 GET 都重签,
	// cookie 被最后一次覆盖,而表单里嵌的是第一次的值 —— 提交必然 403。
	spy := &spyHandler{}
	req := httptest.NewRequest(http.MethodGet, "/acl", nil)
	req.Header.Set("Cookie", cookies)
	w := httptest.NewRecorder()
	s.requireCSRFAndAuth(spy).ServeHTTP(w, req)
	if spy.gotCSRF != first {
		t.Fatalf("第二次 GET 换了 token(%q → %q),表单会与 cookie 错位",
			trimForLog(first), trimForLog(spy.gotCSRF))
	}
}

func TestRequireCSRFAndAuth_POSTWithoutTokenIsForbidden(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "frank", "pw-frank-1234567")
	sessCookie, _ := loginAs(t, s, admin)

	cases := []struct {
		name    string
		form    url.Values
		cookies string
	}{
		{"没有 csrf cookie 也没有 form token", url.Values{}, sessCookie},
		{"有 cookie 但 form 里没带", url.Values{}, ""},
		{"form token 与 cookie 不一致", url.Values{"csrf_token": {"aaaa.bbbb"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cookies := tc.cookies
			if cookies == "" {
				_, cookies = authedGETForCSRF(t, s, sessCookie)
			}
			spy := &spyHandler{}
			w := httptest.NewRecorder()
			s.requireCSRFAndAuth(spy).ServeHTTP(w,
				postWithCookies(t, "/acl/new", tc.form, cookies))

			if w.Code != http.StatusForbidden {
				t.Fatalf("code=%d, 期望 403", w.Code)
			}
			if spy.called != 0 {
				t.Fatalf("CSRF 不通过却调了 handler")
			}
		})
	}
}

func TestRequireCSRFAndAuth_TokenIsBoundToItsSession(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "grace", "pw-grace-1234567")

	// 同一个 admin 的两条会话:token 绑的是 session id,不是 admin。
	sessA, _ := loginAs(t, s, admin)
	sessB, _ := loginAs(t, s, admin)
	tokenA, cookiesA := authedGETForCSRF(t, s, sessA)

	// cookie-tossing:攻击者能往受害者浏览器塞 cookie,于是把「自洽的一对
	// cookie+form」整套换成自己那边签发的。若 token 不绑会话,这一步就成立了。
	csrfPart := strings.TrimPrefix(cookiesA, sessA+"; ")
	spy := &spyHandler{}
	w := httptest.NewRecorder()
	s.requireCSRFAndAuth(spy).ServeHTTP(w,
		postWithCookies(t, "/acl/new", url.Values{"csrf_token": {tokenA}},
			sessB+"; "+csrfPart))

	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d, 期望 403 —— A 会话的 token 不该在 B 会话里生效", w.Code)
	}
	if spy.called != 0 {
		t.Fatalf("跨会话的 csrf token 被接受了")
	}
}

func TestRequireCSRFAndAuth_AuthIsCheckedBeforeCSRF(t *testing.T) {
	s := newMeTestServer(t)
	spy := &spyHandler{}
	w := httptest.NewRecorder()
	// 既没登录也没 token。顺序错了会回 403「token 不对」,把 admin 引去查 CSRF,
	// 而真正的原因是会话过期 —— 这是最常见的一类误导性报错。
	s.requireCSRFAndAuth(spy).ServeHTTP(w,
		postWithCookies(t, "/acl/new", url.Values{}, ""))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d, 期望 401(未登录先于 CSRF 判定)", w.Code)
	}
	if spy.called != 0 {
		t.Fatalf("handler 被调用了")
	}
}

func TestRequireCSRFAndAuth_HeaderTokenAlsoWorks(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "heidi", "pw-heidi-1234567")
	sessCookie, _ := loginAs(t, s, admin)
	token, cookies := authedGETForCSRF(t, s, sessCookie)

	// X-CSRF-Token 是给 fetch/htmx 的替代路径,和表单字段等价。
	req := postWithCookies(t, "/acl/new", url.Values{}, cookies)
	req.Header.Set("X-CSRF-Token", token)
	spy := &spyHandler{}
	w := httptest.NewRecorder()
	s.requireCSRFAndAuth(spy).ServeHTTP(w, req)
	if w.Code != http.StatusOK || spy.called != 1 {
		t.Fatalf("code=%d called=%d, 期望 200/1", w.Code, spy.called)
	}
}

// postWithCookies 造一个 form POST,cookies 为完整 Cookie 头(可为空)。
func postWithCookies(t *testing.T, target string, form url.Values, cookies string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}
	return req
}

// -------------------------------------------------------------------------
// withRecover / withRequestLog / withCommonHeaders
// -------------------------------------------------------------------------

func TestWithRecover_PanicBecomes500(t *testing.T) {
	spy := &spyHandler{panicWith: "boom"}
	w := httptest.NewRecorder()

	// 不 recover 的话这一行会把整个进程带走 —— 一个页面的空指针不该让所有 admin 掉线。
	withRecover(spy).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "boom") {
		t.Fatalf("panic 详情泄漏到了响应体: %q", trimForLog(w.Body.String()))
	}
}

func TestWithRecover_NilPanicIsNotSwallowedIntoSuccess(t *testing.T) {
	// recover() 对 panic(nil) 在 Go 1.21+ 返回 *runtime.PanicNilError,非 nil,
	// 所以这一路也应被包成 500 而不是「看起来正常返回」。
	spy := &spyHandler{panicWith: (*int)(nil)}
	w := httptest.NewRecorder()
	withRecover(spy).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
}

func TestWithRequestLog_CountsByStatusClass(t *testing.T) {
	base4xx := totalErrors4xx.Load()
	base5xx := totalErrors5xx.Load()
	baseAll := totalRequests.Load()

	for _, code := range []int{200, 302, 404, 401, 500, 503} {
		h := withRequestLog(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	}

	if got := totalRequests.Load() - baseAll; got != 6 {
		t.Errorf("请求计数 +%d, 期望 +6", got)
	}
	if got := totalErrors4xx.Load() - base4xx; got != 2 {
		t.Errorf("4xx 计数 +%d, 期望 +2(404/401)", got)
	}
	if got := totalErrors5xx.Load() - base5xx; got != 2 {
		t.Errorf("5xx 计数 +%d, 期望 +2(500/503)", got)
	}
}

func TestStatusRecorder_ImplicitOKAndByteCount(t *testing.T) {
	// handler 直接 Write 不调 WriteHeader 时,net/http 隐式发 200;
	// recorder 若还停在 0,访问日志里会出现一片 status=0,4xx/5xx 统计也跟着失真。
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	n, err := rec.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write=(%d,%v)", n, err)
	}
	if rec.status != http.StatusOK {
		t.Errorf("status=%d, 期望 200", rec.status)
	}
	if rec.bytes != 5 {
		t.Errorf("bytes=%d, 期望 5", rec.bytes)
	}
	if _, err := rec.Write([]byte("!")); err != nil {
		t.Fatalf("第二次 Write: %v", err)
	}
	if rec.bytes != 6 {
		t.Errorf("bytes=%d, 期望累加到 6", rec.bytes)
	}
}

func TestWithCommonHeaders_CSPNonceIsPerRequestAndReachesCtx(t *testing.T) {
	var seen []string
	h := withCommonHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, cspNonceFromCtx(r.Context()))
	}))

	var headers []string
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
		headers = append(headers, w.Header().Get("Content-Security-Policy"))
		if w.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatalf("缺 X-Frame-Options")
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("缺 nosniff")
		}
	}

	if len(seen) != 2 || seen[0] == "" || seen[1] == "" {
		t.Fatalf("ctx 里的 nonce=%v, 期望两次都非空", seen)
	}
	// 复用 nonce 等于没有 nonce:攻击者抄一次就能一直用。
	if seen[0] == seen[1] {
		t.Fatalf("两次请求 nonce 相同(%q)", trimForLog(seen[0]))
	}
	for i, csp := range headers {
		if !strings.Contains(csp, "'nonce-"+seen[i]+"'") {
			t.Errorf("第 %d 次 CSP 里没有 ctx 中那枚 nonce", i)
		}
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("CSP 缺 frame-ancestors 'none'")
		}
	}
}

func TestWithCommonHeaders_ScriptSrcHasNoUnsafeInline(t *testing.T) {
	w := httptest.NewRecorder()
	withCommonHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

	csp := w.Header().Get("Content-Security-Policy")
	start := strings.Index(csp, "script-src")
	if start < 0 {
		t.Fatalf("CSP 里没有 script-src: %q", csp)
	}
	seg := csp[start:]
	if i := strings.Index(seg, ";"); i >= 0 {
		seg = seg[:i]
	}
	if strings.Contains(seg, "unsafe-inline") || strings.Contains(seg, "unsafe-eval") {
		t.Fatalf("script-src=%q 放开了 inline/eval,nonce 就白设了", seg)
	}
}

// -------------------------------------------------------------------------
// 小工具
// -------------------------------------------------------------------------

func TestURLQueryEscape(t *testing.T) {
	// 这个函数的产物直接拼进 `/login?next=...`。转义不足 → next 被 & 截断甚至
	// 注入额外 query 参数;转义过头 → 回跳地址对不上。
	cases := []struct{ in, want string }{
		{"", ""},
		{"/devices", "/devices"},
		{"/a-b_c.d~e:f", "/a-b_c.d~e:f"},
		{"/x?q=1", "/x%3Fq%3D1"},
		{"/x?a=1&b=2", "/x%3Fa%3D1%26b%3D2"},
		{"/a b", "/a%20b"},
		{"/x#frag", "/x%23frag"},
		{"/x%2f", "/x%252f"},
		{"中", "%E4%B8%AD"},
	}
	for _, tc := range cases {
		if got := urlQueryEscape(tc.in); got != tc.want {
			t.Errorf("urlQueryEscape(%q)=%q, 期望 %q", tc.in, got, tc.want)
		}
	}
}

func TestURLQueryEscape_MatchesNetURLForReservedChars(t *testing.T) {
	// 手写实现的价值只在少依赖,语义不该和标准库分家(斜杠与冒号是有意保留的例外)。
	for _, s := range []string{"a&b", "a=b", "a?b", "a b", "a+b", "a%b", "中文", "a#b"} {
		got := urlQueryEscape(s)
		want := url.QueryEscape(s)
		// net/url 把空格编成 '+',这里编成 %20,两者在 query 里等价。
		want = strings.ReplaceAll(want, "+", "%20")
		if !strings.EqualFold(got, want) {
			t.Errorf("urlQueryEscape(%q)=%q, net/url 为 %q", s, got, want)
		}
	}
}

func TestCtxAccessors_MissingValuesAreZero(t *testing.T) {
	ctx := context.Background()
	if adminFromCtx(ctx) != nil {
		t.Error("空 ctx 的 admin 应为 nil")
	}
	if csrfTokenFromCtx(ctx) != "" {
		t.Error("空 ctx 的 csrf token 应为空")
	}
	if cspNonceFromCtx(ctx) != "" {
		t.Error("空 ctx 的 nonce 应为空")
	}
	if got := currentAdminID(httptest.NewRequest(http.MethodGet, "/", nil)); got != 0 {
		t.Errorf("未登录请求的 currentAdminID=%d, 期望 0", got)
	}
	// 类型不匹配时也不能 panic(比如别处误用同一个 key 存了别的类型)。
	bad := context.WithValue(ctx, ctxKeyAdmin, "not-an-admin")
	if adminFromCtx(bad) != nil {
		t.Error("类型不符时应返回 nil")
	}
}

func TestCurrentAdminID_ReturnsLoggedInID(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "ivan", "pw-ivan-12345678")
	req := withAdminCtx(httptest.NewRequest(http.MethodGet, "/me", nil), admin)
	if got := currentAdminID(req); got != admin.ID {
		t.Fatalf("currentAdminID=%d, 期望 %d", got, admin.ID)
	}
}

func TestNewCSPNonce_IsRandomBase64(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		n := newCSPNonce()
		if len(n) != 24 { // 16 字节 std base64 = 24 字符(含一个 '=' 填充)
			t.Fatalf("nonce=%q 长度 %d, 期望 24", n, len(n))
		}
		if seen[n] {
			t.Fatalf("nonce 重复: %q", n)
		}
		seen[n] = true
	}
}
