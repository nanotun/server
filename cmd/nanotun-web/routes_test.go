package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件覆盖 routes.go —— 路由表本身,请求走完整的 routes() 栈。
//
// 在此之前所有测试(包括 pages_smoke_test)要么直调 handler,要么直调 routeAuthed,
// 全都跳过了 mux 与外层中间件。也就是说「每个 handler 做得对不对」测了很多遍,
// 「这个 handler 到底挂在哪、外面裹了什么」一次都没测过。这两件事是独立的:
// 某条写路径漏挂 requireCSRFAndAuth,它自己的 handler 测试照样全绿,线上却多出
// 一个免鉴权接口。
//
// 四条不变量:
//   - 公开路由清单是封闭的 —— 只有 healthz/metrics/favicon/setup/login/logout/static;
//   - 除此之外任何路径,匿名 GET 必须去登录页、匿名写必须 401(而不是落到 handler);
//   - 已登录的写请求仍要过 CSRF;
//   - 请求体在进 handler 前就被封顶(withBodyLimit 确实挂在最外层)。

// serveThrough 把请求丢进完整的 routes() 栈。
func serveThrough(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// routesFixture 在 smokeFixture(有模板、有数据、有假控制面)之上再拿到 routes()。
type routesFixture struct {
	*smokeFixture
	h http.Handler
}

func newRoutesFixture(t *testing.T) *routesFixture {
	t.Helper()
	f := newSmokeFixture(t)
	return &routesFixture{smokeFixture: f, h: f.s.routes()}
}

// authedWritePaths 是所有「必须登录 + 必须带 CSRF」的 POST 路径。
//
// 这份清单是手抄 routeAuthed 的,靠 TestRoutes_ListsCoverEveryDispatchBranch
// 盯着别漏 —— 清单漏一条,下面两个矩阵测试就默默少测一条路径。
var authedWritePaths = []string{
	"/users/new",
	"/users/1/disable",
	"/users/1/delete",
	"/users/1/reset-psk",
	"/devices/1/disable",
	"/leases/1/release",
	"/acl/new",
	"/acl/1/delete",
	"/routes/1/approve",
	"/routes/exit/designate",
	"/port-forwards/new",
	"/port-forwards/1/delete",
	"/me/password",
	"/admins/new",
	"/admins/1/disable",
	"/runtime/reload",
	"/runtime/kick",
	"/runtime/mesh-toggle",
	"/settings/rate",
	"/settings/advertised-host",
	"/settings/server-dial-host",
	"/server-qr/reveal",
}

// TestRoutes_ListsCoverEveryDispatchBranch 直接读 routes.go 源码,把 routeAuthed
// 里出现的每个 path 字面量抠出来,要求它至少被上面两份清单之一覆盖。
//
// 手抄的清单会腐化:新增一个 /foo/bar 写路径,清单不动,矩阵测试照样全绿 ——
// 新路径的鉴权就此无人看管。让测试自己去源码里对账,漏一条就红。
func TestRoutes_ListsCoverEveryDispatchBranch(t *testing.T) {
	src, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatalf("读 routes.go: %v", err)
	}
	covered := append(append([]string{}, readOnlyPages...), authedWritePaths...)

	for _, m := range regexp.MustCompile(`path == "([^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		if !slices.Contains(covered, m[1]) {
			t.Errorf("routeAuthed 有分支 %q,两份清单都没收录", m[1])
		}
	}
	for _, m := range regexp.MustCompile(`strings\.HasPrefix\(path, "([^"]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		hit := false
		for _, p := range covered {
			if strings.HasPrefix(p, m[1]) && p != m[1] {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("routeAuthed 有前缀分支 %q,清单里没有任何一条走得到它", m[1])
		}
	}
}

// -------------------------------------------------------------------------
// 公开路由清单
// -------------------------------------------------------------------------

func TestRoutes_PublicPathsNeedNoSession(t *testing.T) {
	f := newRoutesFixture(t)

	// 这几条是有意公开的。断言重点不是具体状态码(各有各的语义),而是
	// 「没有被 requireAuth 拦下」—— 即不是 401、也不是去 /login 的 302。
	for _, p := range []string{
		"/healthz", "/favicon.ico", "/login", "/login/totp", "/setup",
		"/static/style.css", "/static/app.js",
	} {
		t.Run(p, func(t *testing.T) {
			w := serveThrough(f.h, httptest.NewRequest(http.MethodGet, p, nil))
			if w.Code == http.StatusUnauthorized {
				t.Fatalf("公开路由却 401")
			}
			if loc := w.Header().Get("Location"); strings.HasPrefix(loc, "/login?next=") {
				t.Fatalf("公开路由被 requireAuth 拦去了登录页(Location=%q)", loc)
			}
		})
	}
}

func TestRoutes_HealthzAndFaviconAreCheap(t *testing.T) {
	f := newRoutesFixture(t)

	// 这两条会被负载均衡 / 浏览器高频打,不能有 DB 查询以外的副作用,
	// 更不能 500 —— healthz 挂了会被编排系统当成实例不健康直接摘掉。
	if w := serveThrough(f.h, httptest.NewRequest(http.MethodGet, "/healthz", nil)); w.Code != http.StatusOK {
		t.Fatalf("/healthz code=%d, 期望 200", w.Code)
	}
	w := serveThrough(f.h, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("/favicon.ico code=%d, 期望 204", w.Code)
	}
	if n := w.Body.Len(); n != 0 {
		t.Fatalf("204 却带了 %d 字节 body", n)
	}
}

// TestRoutes_FaviconDoesNotTouchCSRFCookie 锁死 routes.go 里 K4 那条注释描述的回归。
//
// 曾经 /favicon.ico 没有单独挂,落到 mux "/" → requireCSRFAndAuth。浏览器渲染登录页时
// 自动发的这个请求会顺手重签一次 csrf cookie,把用户眼前表单里嵌的 token 覆盖掉,
// 于是登录必然「CSRF: token 不匹配」。症状是「偶发登不进去」,极难查。
func TestRoutes_FaviconDoesNotTouchCSRFCookie(t *testing.T) {
	f := newRoutesFixture(t)
	admin := f.admin
	sessCookie, _ := loginAs(t, f.s, admin)
	_, cookies := authedGETForCSRF(t, f.s, sessCookie)

	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	req.Header.Set("Cookie", cookies)
	w := serveThrough(f.h, req)

	for _, ck := range w.Result().Cookies() {
		if ck.Name == f.s.sess.cookieName(csrfCookieName) {
			t.Fatalf("favicon 重签了 csrf cookie,会覆盖掉表单里的 token")
		}
	}
}

// -------------------------------------------------------------------------
// 未登录:读引导、写拒绝
// -------------------------------------------------------------------------

func TestRoutes_AnonymousGETGoesToLoginWithReturnPath(t *testing.T) {
	f := newRoutesFixture(t)

	for _, p := range readOnlyPages {
		t.Run(p, func(t *testing.T) {
			w := serveThrough(f.h, httptest.NewRequest(http.MethodGet, p, nil))
			if w.Code != http.StatusFound {
				t.Fatalf("code=%d, 期望 302(未登录引导)", w.Code)
			}
			loc := w.Header().Get("Location")
			if !strings.HasPrefix(loc, "/login") {
				t.Fatalf("Location=%q, 期望去 /login", loc)
			}
			// 根路径不带 next(否则登录后跳 "/" 是废话);其余都要能跳回来,
			// 不然 admin 每次会话过期都被丢回首页重新找路。
			if p != "/" && !strings.Contains(loc, "next=") {
				t.Fatalf("Location=%q 丢了 next,登录后回不到原页", loc)
			}
		})
	}
}

func TestRoutes_AnonymousWriteIs401NotRedirect(t *testing.T) {
	f := newRoutesFixture(t)

	for _, p := range authedWritePaths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, p,
				strings.NewReader("id=1&user_id=1&device_id=1"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := serveThrough(f.h, req)

			// 302 对 POST 是错的:浏览器不会重放 POST,表单静默丢失;
			// 更要紧的是 302 说明请求已经过了鉴权那一层。
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("code=%d, 期望 401", w.Code)
			}
		})
	}
}

// TestRoutes_AnonymousWriteLeavesNoTrace 确认拒绝发生在 handler 之前,
// 而不是「handler 跑完了再改状态码」。审计表是最灵敏的探针:任何写 handler
// 走到底都会留一行。
func TestRoutes_AnonymousWriteLeavesNoTrace(t *testing.T) {
	f := newRoutesFixture(t)
	before, err := f.s.store.CountAudit(t.Context())
	if err != nil {
		t.Fatalf("CountAudit: %v", err)
	}

	for _, p := range authedWritePaths {
		req := httptest.NewRequest(http.MethodPost, p,
			strings.NewReader("id=1&user_id=1&device_id=1&enabled=0"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		serveThrough(f.h, req)
	}

	after, err := f.s.store.CountAudit(t.Context())
	if err != nil {
		t.Fatalf("CountAudit: %v", err)
	}
	if after != before {
		t.Fatalf("匿名写请求留下了 %d 条审计,说明有 handler 被执行了", after-before)
	}
}

// -------------------------------------------------------------------------
// 已登录但无 CSRF
// -------------------------------------------------------------------------

func TestRoutes_AuthedWriteStillNeedsCSRF(t *testing.T) {
	f := newRoutesFixture(t)
	sessCookie, _ := loginAs(t, f.s, f.admin)

	for _, p := range authedWritePaths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, p,
				strings.NewReader("id=1&user_id=1&device_id=1"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Cookie", sessCookie)
			w := serveThrough(f.h, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("code=%d, 期望 403(缺 CSRF)", w.Code)
			}
		})
	}
}

// -------------------------------------------------------------------------
// dispatcher 的分支顺序
// -------------------------------------------------------------------------

// TestRoutes_ExitPrefixWinsOverGenericRoutePrefix 盯 routeAuthed 里那条顺序依赖:
// /routes/exit/... 必须排在 /routes/ 前面。两条 case 调换位置编译得过、
// 大部分测试也照过,只有出口节点这一个功能会碎 —— "exit" 会被 handleRouteAction
// 当成 device_id 去 ParseInt。
func TestRoutes_ExitPrefixWinsOverGenericRoutePrefix(t *testing.T) {
	f := newRoutesFixture(t)
	sessCookie, _ := loginAs(t, f.s, f.admin)
	tok, cookies := authedGETForCSRF(t, f.s, sessCookie)

	form := url.Values{"csrf_token": {tok}, "device_id": {itoa(f.dev.ID)}}
	w := serveThrough(f.h, postWithCookies(t, "/routes/exit/designate", form, cookies))

	if w.Code != http.StatusSeeOther && w.Code != http.StatusFound {
		t.Fatalf("code=%d body=%q, 期望重定向(designate 成功)", w.Code, trimForLog(w.Body.String()))
	}
	// 真的落库了才算走对了 handler:handleRouteAction 即便侥幸没报错也不会批 0/0。
	routes, err := f.s.store.ListRoutesByDevice(t.Context(), f.dev.ID)
	if err != nil {
		t.Fatalf("ListRoutesByDevice: %v", err)
	}
	got := false
	for _, r := range routes {
		if r.CIDR == "0.0.0.0/0" && r.Status == store.RouteStatusApproved {
			got = true
		}
	}
	if !got {
		t.Fatalf("0.0.0.0/0 没有被批准,请求可能落到了 handleRouteAction")
	}
}

func TestRoutes_UnknownPathIs404ForAuthedUser(t *testing.T) {
	f := newRoutesFixture(t)
	sessCookie, _ := loginAs(t, f.s, f.admin)

	req := httptest.NewRequest(http.MethodGet, "/nope/nothing-here", nil)
	req.Header.Set("Cookie", sessCookie)
	w := serveThrough(f.h, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("code=%d, 期望 404", w.Code)
	}
	// 404 页面会把路径回显出来,必须是转义过的 —— 否则就是个反射型 XSS。
	req = httptest.NewRequest(http.MethodGet, "/nope/<script>alert(1)</script>", nil)
	req.Header.Set("Cookie", sessCookie)
	if body := serveThrough(f.h, req).Body.String(); strings.Contains(body, "<script>alert(1)") {
		t.Fatal("404 页原样回显了路径里的 <script>")
	}
}

// -------------------------------------------------------------------------
// 请求体上限
// -------------------------------------------------------------------------

func TestWithBodyLimit_CapsAtOneMiB(t *testing.T) {
	// 上限本身是策略,不是实现细节:整个控制台只有纯表单请求(无文件上传,
	// server profile QR 由服务端生成),1 MiB 已经宽松得离谱。把它调大是个
	// 需要有人点头的决定 —— 下面的边界断言都以这个常量为基准,不钉死的话
	// 常量被改成 100 MiB 时测试会跟着一起变松,等于没测。
	if maxRequestBodyBytes != 1<<20 {
		t.Fatalf("请求体上限被改成 %d,DoS 面随之放大;确有需要请连同本断言一起改",
			maxRequestBodyBytes)
	}

	var readErr error
	var readN int
	h := withBodyLimit(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		readN, readErr = len(b), err
	}))

	// 正好到顶:必须完整读到,别把正常请求也误伤了。
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(strings.Repeat("a", maxRequestBodyBytes)))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if readErr != nil || readN != maxRequestBodyBytes {
		t.Fatalf("恰好 1 MiB 被拦了: n=%d err=%v", readN, readErr)
	}

	// 超一个字节:读到上限就该报错,而不是继续吞。
	req = httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(strings.Repeat("a", maxRequestBodyBytes+1)))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if readErr == nil {
		t.Fatalf("超限 body 被完整读进内存了(n=%d)", readN)
	}
	if readN > maxRequestBodyBytes {
		t.Fatalf("读进了 %d 字节,超过上限 %d", readN, maxRequestBodyBytes)
	}
}

// TestRoutes_BodyLimitIsWiredIntoTheStack 单测中间件本身不够 —— 它得真的在
// routes() 里,而且要在 handler 碰 body 之前。这里用同一个表单的大小两版做对照:
// 限额内正常处理,超限时连 csrf_token 都读不出来(整个 body 读失败)→ 403。
func TestRoutes_BodyLimitIsWiredIntoTheStack(t *testing.T) {
	f := newRoutesFixture(t)
	sessCookie, _ := loginAs(t, f.s, f.admin)
	tok, cookies := authedGETForCSRF(t, f.s, sessCookie)

	small := url.Values{"csrf_token": {tok}, "user_id": {itoa(f.user.ID)}, "action": {"deny"}}
	if w := serveThrough(f.h, postWithCookies(t, "/acl/new", small, cookies)); w.Code == http.StatusForbidden {
		t.Fatalf("限额内的正常表单被 403 了,对照组不成立: %q", trimForLog(w.Body.String()))
	}

	big := url.Values{"csrf_token": {tok}, "user_id": {itoa(f.user.ID)}, "action": {"deny"}}
	big.Set("pad", strings.Repeat("x", maxRequestBodyBytes+1))
	w := serveThrough(f.h, postWithCookies(t, "/acl/new", big, cookies))
	if w.Code != http.StatusForbidden {
		t.Fatalf("超限 body code=%d, 期望 403(body 读不完 → 取不到 csrf)", w.Code)
	}
}

// -------------------------------------------------------------------------
// 静态资源
// -------------------------------------------------------------------------

func TestRoutes_StaticServesAssetsWithCache(t *testing.T) {
	f := newRoutesFixture(t)

	w := serveThrough(f.h, httptest.NewRequest(http.MethodGet, "/static/style.css", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("style.css code=%d", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Fatal("style.css 是空的")
	}
	// embed.FS 的 ModTime 是零值,发不出 Last-Modified;没有 Cache-Control 的话
	// 每次导航都要整包重拉。
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=") {
		t.Fatalf("Cache-Control=%q, 缺 max-age", cc)
	}
}

// TestRoutes_StaticCannotEscapeItsRoot:FileServer 挂在 embed.FS 上,理论上出不去,
// 但这条断言的成本几乎为零,而一旦哪天换成 os.DirFS 就是直接的任意文件读取。
func TestRoutes_StaticCannotEscapeItsRoot(t *testing.T) {
	f := newRoutesFixture(t)

	for _, p := range []string{
		"/static/../main.go",
		"/static/..%2fmain.go",
		"/static/%2e%2e/%2e%2e/etc/passwd",
		"/static/./../../go.mod",
	} {
		t.Run(p, func(t *testing.T) {
			w := serveThrough(f.h, httptest.NewRequest(http.MethodGet, p, nil))
			body := w.Body.String()
			if strings.Contains(body, "package main") || strings.Contains(body, "module github.com/nanotun") {
				t.Fatalf("穿越成功了,读到了仓库文件: %q", trimForLog(body))
			}
		})
	}
}

// -------------------------------------------------------------------------
// 登出
// -------------------------------------------------------------------------

func TestRoutes_LogoutRejectsGET(t *testing.T) {
	f := newRoutesFixture(t)
	sessCookie, sid := loginAs(t, f.s, f.admin)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.Header.Set("Cookie", sessCookie)
	w := serveThrough(f.h, req)

	// GET 登出意味着任意第三方页面一个 <img src=".../logout"> 就能把 admin 踢下线。
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d, 期望 405", w.Code)
	}
	if _, err := f.s.store.GetWebSession(t.Context(), sid); err != nil {
		t.Fatalf("GET /logout 竟然真把会话销毁了: %v", err)
	}
}

func TestRoutes_LogoutDestroysSessionAndCookies(t *testing.T) {
	f := newRoutesFixture(t)
	sessCookie, sid := loginAs(t, f.s, f.admin)
	tok, cookies := authedGETForCSRF(t, f.s, sessCookie)

	w := serveThrough(f.h, postWithCookies(t, "/logout", url.Values{"csrf_token": {tok}}, cookies))

	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Fatalf("code=%d loc=%q, 期望 302 /login", w.Code, w.Header().Get("Location"))
	}
	// 库里删掉才算真登出 —— 只清 cookie 的话,抓到过 cookie 的人仍能继续用。
	if _, err := f.s.store.GetWebSession(t.Context(), sid); err == nil {
		t.Fatal("登出后 session 行还在")
	}
	// 两个 cookie 都要显式过期。浏览器按 (name, domain, path) 匹配,所以过期用的
	// Set-Cookie 必须与签发时同 path —— path 对不上就不是覆盖,是新增一条,
	// 旧的那条原封不动留在浏览器里继续发出去。
	for _, want := range []string{
		f.s.sess.cookieName(sessionCookieName),
		f.s.sess.cookieName(csrfCookieName),
	} {
		var got *http.Cookie
		for _, ck := range w.Result().Cookies() {
			if ck.Name == want && ck.MaxAge < 0 {
				got = ck
			}
		}
		if got == nil {
			t.Errorf("cookie %q 没有被过期", want)
			continue
		}
		if got.Path != "/" {
			t.Errorf("cookie %q 的过期指令 Path=%q,与签发时的 / 不一致,覆盖不到", want, got.Path)
		}
		if got.Value != "" {
			t.Errorf("cookie %q 过期时还带着值 %q", want, got.Value)
		}
	}
	// 旧 cookie 立刻失效。
	if w := serveThrough(f.h, getReq("/devices", sessCookie)); w.Code != http.StatusFound {
		t.Fatalf("登出后旧 cookie 仍能访问(code=%d)", w.Code)
	}
}

// TestRoutes_LogoutNeedsCSRF 盯的是反向的坑:/logout 是公开路由,不过
// requireCSRFAndAuth,它的 CSRF 校验是 handler 自己做的。这层要是丢了,
// 跨站表单就能把管理员反复踢下线。
func TestRoutes_LogoutNeedsCSRF(t *testing.T) {
	f := newRoutesFixture(t)
	sessCookie, sid := loginAs(t, f.s, f.admin)

	w := serveThrough(f.h, postWithCookies(t, "/logout", url.Values{}, sessCookie))
	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d, 期望 403", w.Code)
	}
	if _, err := f.s.store.GetWebSession(t.Context(), sid); err != nil {
		t.Fatalf("CSRF 没过却把会话销毁了: %v", err)
	}
}

func getReq(target, cookie string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	return req
}
