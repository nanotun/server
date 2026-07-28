package main

// web_tail_guards_test.go(第二十轮收尾)—— 散落在 render / routes / audit / i18n /
// middleware / 会话视图 / 一次性凭据 / dashboard 上的最后几处失败面与边界。
//
// 这些点单独看都很小,但都属于「坏了不会报错、只会悄悄给出一个错的结果」那一类:
//
//   - flash 签名 key 生成失败必须 panic:签不出名就意味着任何人都能给 ?flash= 塞文本;
//   - 路由表里那几条写路径必须真的接到对应 handler(挂错地方时 handler 自己的测试全绿);
//   - FormatDetail 的脱敏必须真的把 psk/password/secret/token 换掉,否则明文进审计表;
//   - GC 要真的清掉过期的一次性 PSK,而不只是「收到 stop 会退出」。

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// -------------------------------------------------------------------------
// render.go
// -------------------------------------------------------------------------

// flash 的 HMAC key 生成失败必须 panic。这道签名是 ?flash= 的唯一防线:
// 签不出来时若兜底成空 key(或空签名),任何人都能构造一条带任意文本的
// 链接让管理员看到「已删除用户 xxx」这种伪造横幅。
func TestMustRandomKey_PanicsRatherThanReturningAWeakKey(t *testing.T) {
	stubRandRead(t, 1)
	defer func() {
		if recover() == nil {
			t.Fatal("随机数故障却返回了一把 key —— flash 签名会变成人人可伪造")
		}
	}()
	_ = mustRandomKey(32)
}

// flashRedirect 要认出 path 自带的 query,用 & 而不是再加一个 ?。
// 拼错的话整段 flash 会变成前一个参数的值,横幅静默消失。
func TestFlashRedirect_AppendsToExistingQuery(t *testing.T) {
	for _, tc := range []struct{ path, wantSep string }{
		{"/users", "?"},
		{"/users?show_disabled=1", "&"},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		flashRedirect(w, r, tc.path, "干完了", "")
		loc := w.Header().Get("Location")
		if !strings.HasPrefix(loc, tc.path+tc.wantSep+"flash=") {
			t.Errorf("path=%q → Location=%q, 期望用 %q 连接", tc.path, loc, tc.wantSep)
		}
		// 签名必须带上,否则下一个 GET 会把这条横幅当伪造的丢掉。
		if !strings.Contains(loc, "flash_sig=") {
			t.Errorf("path=%q 的跳转没带签名: %q", tc.path, loc)
		}
	}
}

// 页面没给标题时要用应用名兜底,不能渲染出一个 <title></title> 空标签
// (浏览器标签页会显示 URL,多开几个后完全分不清)。
func TestRenderPage_FillsMissingTitle(t *testing.T) {
	s := newMeTestServer(t)
	// 用一张只回显标题的最小模板:真实页面模板各有必填数据,这里要测的只是
	// 「Title 空着时会不会被兜底」这一条。
	s.tmpl = template.Must(template.New("title-probe.html").Parse(`<title>{{.Title}}</title>`))
	s.tmplByLang = nil

	w := httptest.NewRecorder()
	s.renderPage(w, adminGetReq("/devices"), "title-probe.html", PageData{})
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if got := w.Body.String(); strings.Contains(got, "<title></title>") {
		t.Fatalf("标题空着就渲染出去了: %q", got)
	}
}

// 模板集损坏(Clone 失败)时必须 500。这条路径只有手工构造的 Server 会走到,
// 但它是「渲染失败」与「渲染出半截页面」的分界:错误页必须是完整的 500,
// 不能把已经写出去的部分留在响应里让浏览器渲染成残页。
func TestRenderPage_CloneFailureIs500(t *testing.T) {
	s := newMeTestServer(t)
	// html/template 在 Execute 之后就不允许 Clone 了 —— 拿一个已执行过的模板
	// 当 s.tmpl,并清掉按语言预建的集合,强制走 Clone 分支。
	spent := template.Must(template.New("spent").Parse("hi"))
	if err := spent.Execute(new(strings.Builder), nil); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	s.tmpl = spent
	s.tmplByLang = nil

	w := httptest.NewRecorder()
	s.renderPage(w, adminGetReq("/devices"), "devices.html", PageData{})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
}

// -------------------------------------------------------------------------
// routes.go:那几条写路径真的接到了对应 handler
// -------------------------------------------------------------------------

// 每条写路径都要能从完整栈走到自己的 handler。挂错地方(比如两条 case 顺序颠倒、
// 或路径写错一个字符)时,handler 自己的单测照样全绿,只有走完整 mux 才看得出来:
// 症状是按钮点了没反应(404),或者更糟 —— 落到另一个 handler 上。
func TestRoutes_WritePathsReachTheirHandlers(t *testing.T) {
	f := newRoutesFixture(t)
	stubProbe(t, nil) // server-dial-host 保存路径会拨测,测试里直接放行
	sessCookie, _ := loginAs(t, f.s, f.admin)
	tok, cookies := authedGETForCSRF(t, f.s, sessCookie)

	cases := []struct {
		path string
		form url.Values
	}{
		{"/runtime/reload", nil},
		{"/runtime/kick", url.Values{"kind": {"user"}, "id": {"1"}}},
		{"/runtime/mesh-toggle", url.Values{"to": {"on"}}},
		{"/settings/rate", url.Values{"rate_default_upload_mibs": {"8"}}},
		{"/settings/advertised-host", url.Values{"advertised_host": {"vpn.example.com"}}},
		{"/settings/server-dial-host", url.Values{"server_dial_host": {"203.0.113.10"}}},
		{"/server-qr/reveal", url.Values{"password": {"pw-root-12345678"}}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			form := url.Values{"csrf_token": {tok}}
			for k, vs := range tc.form {
				form[k] = vs
			}
			w := serveThrough(f.h, postWithCookies(t, tc.path, form, cookies))
			switch w.Code {
			case http.StatusNotFound:
				t.Fatalf("404 —— 这条路径没接到任何 handler")
			case http.StatusUnauthorized, http.StatusForbidden:
				t.Fatalf("code=%d —— 请求没走到 handler 就被拦下了", w.Code)
			case http.StatusMethodNotAllowed:
				t.Fatalf("405 —— 落到了一个不接受 POST 的 handler(挂错位置)")
			}
		})
	}

	// GET /settings 同理:它与 /settings/rate 只差一个后缀,前缀匹配写错就会互串。
	w := serveThrough(f.h, getReq("/settings", sessCookie))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /settings code=%d body=%q, 期望 200", w.Code, trimForLog(w.Body.String()))
	}
}

// -------------------------------------------------------------------------
// audit.go
// -------------------------------------------------------------------------

// 没接库的 Auditor 不能 panic:构造 Server 的某些路径(以及测试)可能不装
// auditor,而审计是被每个写 handler 无条件调用的 —— 一个 nil 解引用会把
// 整条业务路径带下线。
func TestAuditor_NilIsSilentNotFatal(t *testing.T) {
	var a *Auditor
	a.Write(t.Context(), nil, "probe", "", "")            // nil 接收者
	(&Auditor{}).Write(t.Context(), nil, "probe", "", "") // 有对象但没库
}

// 脱敏必须真的生效:这几个词一旦漏掉,PSK / 密码 / TOTP secret 就会明文进
// audit_logs —— 而审计表是设计上要长期保留、还会被导出给别人看的。
func TestFormatDetail_RedactsSecretsAndRejectsOddPairs(t *testing.T) {
	got := FormatDetail(
		"psk", "super-secret-psk",
		"new_password", "hunter2",
		"totp_secret", "JBSWY3DPEHPK3PXP",
		"api_token", "t0ken",
		"ip", "10.0.0.1",
	)
	for _, leak := range []string{"super-secret-psk", "hunter2", "JBSWY3DPEHPK3PXP", "t0ken"} {
		if strings.Contains(got, leak) {
			t.Errorf("明文 %q 进了审计明细: %s", leak, got)
		}
	}
	if !strings.Contains(got, "ip=10.0.0.1") {
		t.Errorf("非敏感字段被误脱敏了: %s", got)
	}
	// 奇数个参数是调用方写错了 —— 要给一个显眼的占位,而不是悄悄丢掉最后一项
	// (丢掉的话审计里会少一条关键信息,而且没人知道少了)。
	if got := FormatDetail("only_key"); !strings.Contains(got, "bad detail") {
		t.Errorf("奇数参数没被标记出来: %q", got)
	}
}

// -------------------------------------------------------------------------
// i18n.go
// -------------------------------------------------------------------------

func TestTrErr_NilErrorIsEmpty(t *testing.T) {
	// 调用方常写 tr(r,"前缀")+trErr(r,err),err 为 nil 时不能拼出 "<nil>"。
	if got := trErr(httptest.NewRequest(http.MethodGet, "/", nil), nil); got != "" {
		t.Fatalf("trErr(nil) = %q, 期望空串", got)
	}
}

// 语言 cookie 要被 withLang 认出来。不认的话每次导航都退回 Accept-Language,
// 用户的显式选择只在带 ?lang= 的那一次生效。
func TestWithLang_CookieDecidesLanguage(t *testing.T) {
	var seen string
	h := withLang(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = langFromCtx(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	req.Header.Set("Accept-Language", "zh-CN")
	req.AddCookie(&http.Cookie{Name: langCookieName, Value: "en"})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "en" {
		t.Fatalf("语言 = %q, 期望 cookie 里的 en 胜过 Accept-Language", seen)
	}

	// cookie 里是垃圾值时要落回 Accept-Language,而不是把垃圾当语言标签用。
	req = httptest.NewRequest(http.MethodGet, "/devices", nil)
	req.Header.Set("Accept-Language", "en-US")
	req.AddCookie(&http.Cookie{Name: langCookieName, Value: "kl!ngon"})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if seen != "en" {
		t.Fatalf("坏 cookie 时语言 = %q, 期望回落到 Accept-Language 的 en", seen)
	}
}

// -------------------------------------------------------------------------
// middleware.go
// -------------------------------------------------------------------------

// nonce 生成失败时返回空串:此时 CSP 里不含 nonce,内联脚本被拦、页面降级,
// 但**绝不能**回退到 unsafe-inline —— 宁可这一页 JS 失效,也不放开 XSS 兜底。
func TestNewCSPNonce_RandFailureDegradesToEmpty(t *testing.T) {
	stubRandRead(t, 1)
	if got := newCSPNonce(); got != "" {
		t.Fatalf("随机数故障却给出了 nonce=%q", got)
	}
}

// CSRF token 签不出来时,GET 页面仍要能渲染(降级为不带 token),而不是整页 500 ——
// 这是只读路径,让管理员至少还能看状态。
func TestRequireCSRFAndAuth_TokenIssueFailureStillRendersGET(t *testing.T) {
	f := newRoutesFixture(t)
	sessCookie, _ := loginAs(t, f.s, f.admin)
	stubRandRead(t, 1)

	w := serveThrough(f.h, getReq("/devices", sessCookie))
	if w.Code == http.StatusInternalServerError {
		t.Fatalf("CSRF 签不出来把只读页面也打成了 500: %q", trimForLog(w.Body.String()))
	}
}

// -------------------------------------------------------------------------
// handler_sessions.go / view_sessions.go
// -------------------------------------------------------------------------

func TestSessionList_MethodGuardAndAutoRefresh(t *testing.T) {
	s, _ := pfServer(t)

	w := httptest.NewRecorder()
	s.handleSessionList(w, newAdminPostRequest(t, "/sessions", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST code=%d, 期望 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "GET" {
		t.Errorf("Allow=%q, 期望 GET", allow)
	}

	// ?autorefresh=1 要真的把自动刷新打开(模板据此内嵌轮询脚本);
	// 认不出来的话勾选框看着是开的,页面其实不会自己刷新。
	for _, v := range []string{"1", "true", "on", "YES"} {
		w := httptest.NewRecorder()
		s.handleSessionList(w, adminGetReq("/sessions?autorefresh="+v))
		if w.Code != http.StatusOK {
			t.Fatalf("autorefresh=%s code=%d", v, w.Code)
		}
		if !strings.Contains(w.Body.String(), "autorefresh") {
			t.Errorf("autorefresh=%s 的页面里没有自动刷新的痕迹", v)
		}
	}
}

func TestParseUserIDStrWeb_OnlyAcceptsPositiveUForm(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"u12", 12},
		{" u7 ", 7},
		{"", 0},
		{"u", 0},
		{"12", 0},                    // 缺前缀
		{"unope", 0},                 // 不是数字
		{"u0", 0},                    // 0 不是合法用户 id
		{"u-3", 0},                   // 负数
		{"u99999999999999999999", 0}, // 溢出
	} {
		got, ok := parseUserIDStrWeb(tc.in)
		if tc.want == 0 {
			if ok {
				t.Errorf("parseUserIDStrWeb(%q) 竟解析成了 %d", tc.in, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("parseUserIDStrWeb(%q) = (%d, %v), 期望 %d", tc.in, got, ok, tc.want)
		}
	}
}

// -------------------------------------------------------------------------
// credentials_flash.go
// -------------------------------------------------------------------------

// 一次性 PSK 存在内存里,过期后必须真的被 GC 清掉 —— 留着等于把明文 PSK
// 一直攥在进程里,任何内存转储都能捞到。
func TestCredentialsFlashGC_ReallyPrunesExpiredEntries(t *testing.T) {
	orig := credentialsFlashGCInterval
	credentialsFlashGCInterval = 5 * time.Millisecond
	t.Cleanup(func() { credentialsFlashGCInterval = orig })

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	fs := newCredentialsFlashStore(stop)
	tok, err := fs.Stash(credentialsFlashPayload{Username: "alice", PSK: "secret-psk"}, 1)
	if err != nil {
		t.Fatalf("Stash: %v", err)
	}
	// 把它的到期时间推到过去,等 GC 那一跳。
	fs.mu.Lock()
	e := fs.entries[tok]
	e.expires = time.Now().Add(-time.Minute)
	fs.entries[tok] = e
	fs.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fs.mu.Lock()
		_, still := fs.entries[tok]
		fs.mu.Unlock()
		if !still {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("过期的一次性 PSK 一直留在内存里没被清掉")
}

// 拿不到 token 时必须报错。绝不能退化成「在 POST 响应里直接渲染 PSK」——
// 那样刷新页面会重发 POST 再 rotate 一次,用户刚抄下的 PSK 当场失效。
func TestFlashGenerateToken_RandFailureIsAnError(t *testing.T) {
	stubRandRead(t, 1)
	if tok, err := flashGenerateToken(); err == nil {
		t.Fatalf("随机数故障却给出了 token=%q", tok)
	}
}

// -------------------------------------------------------------------------
// handler_dashboard.go
// -------------------------------------------------------------------------

// 会话总数要用 server 给的 sessions_total(过滤后的总数),没有该字段的老 server
// 才退回 conn_count。用 len(sessions) 的话分页取 10 条就会显示「共 10 条」。
func TestDashboard_SessionTotalPrefersServerTotal(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want string
	}{
		{"新 server 给 sessions_total", `{"ok":true,"sessions":[],"sessions_total":137,"conn_count":9}`, "137"},
		{"老 server 只有 conn_count", `{"ok":true,"sessions":[],"conn_count":42}`, "42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			routes := controlOK()
			body := tc.json
			routes["/status"] = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}
			s.control = newFakeControl(t, routes).client

			w := httptest.NewRecorder()
			s.handleDashboard(w, adminGetReq("/"))
			if w.Code != http.StatusOK {
				t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("页面上找不到会话总数 %s", tc.want)
			}
		})
	}
}

// /status 回的不是 JSON 时,dashboard 要降级成「运行态未知」继续渲染,
// 而不是整页 500 —— 恰恰是数据面出问题的时候,管理员最需要打开这一页。
func TestDashboard_UnparsableStatusDegradesGracefully(t *testing.T) {
	s := newMeTestServer(t)
	routes := controlOK()
	routes["/status"] = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not json</html>"))
	}
	s.control = newFakeControl(t, routes).client

	w := httptest.NewRecorder()
	s.handleDashboard(w, adminGetReq("/"))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, 期望 200(降级渲染)", w.Code)
	}
}

// -------------------------------------------------------------------------
// handler_sysmon.go
// -------------------------------------------------------------------------

// 响应写不出去(客户端断开)时只记日志,不能 panic —— 轮询页每 2 秒一次请求,
// 用户切走标签页就会造出大量半途断开的连接。
func TestSysmonData_EncodeFailureIsLogged(t *testing.T) {
	s, _ := pfServer(t)
	w := &brokenWriter{header: http.Header{}}
	s.handleSysmonData(w, adminGetReq("/sysmon/data"))
	if !w.wrote {
		t.Fatal("根本没尝试写响应")
	}
}

// brokenWriter 的 Write 永远失败,用来模拟「客户端已经断开」。
type brokenWriter struct {
	header http.Header
	wrote  bool
}

func (b *brokenWriter) Header() http.Header { return b.header }
func (b *brokenWriter) WriteHeader(int)     {}
func (b *brokenWriter) Write(p []byte) (int, error) {
	b.wrote = true
	return 0, errors.New("客户端已断开")
}
