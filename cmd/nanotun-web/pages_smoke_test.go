package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件是所有只读页面的冒烟测试:带着真实数据把每一页渲染一遍。
//
// 为什么值得单独做一遍:这些页面的业务逻辑不复杂,但它们都要过 html/template。
// 模板里写错一个字段名(改了 struct 却忘了改模板)不会有编译错误,只会在
// admin 打开那一页时变成 500。之前这些 handler 全是零覆盖 —— 也就是说
// **整个控制台的每一页都从没被渲染验证过**。
//
// 断言有三条:能出 200、页面里有该有的数据、页面里没有不该有的东西
//(密码哈希 / PSK 哈希 / 模板报错残渣)。

// smokeFixture 铺一套「什么都有一点」的数据,让每个列表页都不是空表 ——
// 空表会绕过模板里 range 内部的所有字段引用,等于没测。
type smokeFixture struct {
	s      *Server
	admin  *store.WebAdmin
	viewer *store.WebAdmin
	user   *store.User
	dev    *store.Device
}

func newSmokeFixture(t *testing.T) *smokeFixture {
	t.Helper()
	s := newMeTestServer(t)
	routes := controlOK()
	for _, p := range []string{"/status", "/portforward/status", "/sysmon", "/rate/config"} {
		routes[p] = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"sessions":[],"devices":[]}`))
		}
	}
	fc := newFakeControl(t, routes)
	s.control = fc.client

	admin := createTestAdmin(t, s, "root", "pw-root-12345678")
	viewer := createTestAdmin(t, s, "peeker", "pw-peeker-12345")
	if err := s.store.SetWebAdminRoleEnsuringAdmin(t.Context(), viewer.ID, "viewer"); err != nil {
		t.Fatalf("降级 viewer: %v", err)
	}
	viewer = mustGetAdmin(t, s, viewer.ID)

	// PSK 哈希用一个显眼的哨兵串:共用的 newPRGTestUser 写的是 "h",
	// 单字符会在任何页面里被 Contains 命中,泄漏断言就成了永远失败的噪音。
	user, err := s.store.CreateUser(t.Context(), store.NewUser{
		Username: "alice", PSKHash: "$argon2id$SMOKE-PSK-SENTINEL-must-not-render$",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	dev, err := s.store.UpsertDevice(t.Context(), user.ID, "uuid-alice", "alice-box", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if _, err := s.store.UpsertLease(t.Context(), dev.ID, "10.66.0.5", "fd66::5", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if _, err := s.store.UpsertAdvertisedRoute(t.Context(), dev.ID, "192.168.7.0/24"); err != nil {
		t.Fatalf("UpsertAdvertisedRoute: %v", err)
	}
	if _, err := s.store.CreatePortForward(t.Context(), store.PortForward{
		PublicPort: 9001, Proto: "tcp", TargetDeviceUUID: dev.DeviceUUID,
		TargetIP: "10.66.0.5", TargetPort: 8000, Enabled: true,
	}); err != nil {
		t.Fatalf("CreatePortForward: %v", err)
	}
	if _, err := s.store.AddACLPairBasic(t.Context(), user.ID, 0, "deny"); err != nil {
		t.Fatalf("AddACLPairBasic: %v", err)
	}
	s.audit.Write(t.Context(), admin, "smoke.seed", "", "")

	return &smokeFixture{s: s, admin: admin, viewer: viewer, user: user, dev: dev}
}

// getPage 以给定身份 GET 一个已登录路径,走 routeAuthed 真实分发。
func (f *smokeFixture) getPage(t *testing.T, path string, as *store.WebAdmin) *httptest.ResponseRecorder {
	t.Helper()
	req := withAdminCtx(httptest.NewRequest(http.MethodGet, path, nil), as)
	w := httptest.NewRecorder()
	f.s.routeAuthed(w, req)
	return w
}

// readOnlyPages 是所有「打开就能看」的页面。
var readOnlyPages = []string{
	"/", "/users", "/devices", "/leases", "/acl", "/routes",
	"/port-forwards", "/sessions", "/me", "/audit", "/admins",
	"/settings", "/server-qr", "/sysmon", "/sysmon/data",
}

func TestPages_AllReadOnlyPagesRenderForAdmin(t *testing.T) {
	f := newSmokeFixture(t)

	for _, path := range readOnlyPages {
		t.Run(path, func(t *testing.T) {
			w := f.getPage(t, path, f.admin)
			if w.Code != http.StatusOK {
				t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
			}
			body := w.Body.String()
			if body == "" {
				t.Fatal("响应体是空的")
			}
			// html/template 遇到未知字段会把错误文本写进已输出的响应里,
			// 状态码仍然是 200 —— 只看 code 抓不到这一类。
			for _, marker := range []string{
				"can't evaluate field", "executing \"", "<no value>", "nil pointer evaluating",
			} {
				if strings.Contains(body, marker) {
					t.Fatalf("页面里有模板报错残渣 %q", marker)
				}
			}
		})
	}
}

func TestPages_NoSecretsLeakIntoHTML(t *testing.T) {
	f := newSmokeFixture(t)
	adminHash := mustGetAdmin(t, f.s, f.admin.ID).PasswordHash
	if adminHash == "" {
		t.Fatal("测试前提不成立:admin 没有密码哈希")
	}

	// 页面上出现哈希本身不等于能立刻登录,但它是离线爆破的原料,
	// 也是「模板里不小心 range 了整个 struct」最典型的症状。
	for _, path := range readOnlyPages {
		body := f.getPage(t, path, f.admin).Body.String()
		if strings.Contains(body, adminHash) {
			t.Errorf("%s 泄漏了管理员密码哈希", path)
		}
		if f.user.PSKHash != "" && strings.Contains(body, f.user.PSKHash) {
			t.Errorf("%s 泄漏了用户 PSK 哈希", path)
		}
	}
}

func TestPages_ListsActuallyContainTheirData(t *testing.T) {
	f := newSmokeFixture(t)

	// 只断言 200 的话,一个「永远渲染空表」的回归照样能过。
	cases := []struct{ path, want string }{
		{"/users", f.user.Username},
		{"/devices", f.dev.DeviceName},
		{"/leases", "10.66.0.5"},
		{"/routes", "192.168.7.0/24"},
		{"/port-forwards", "9001"},
		{"/admins", f.admin.Username},
		{"/audit", "smoke.seed"},
	}
	for _, tc := range cases {
		body := f.getPage(t, tc.path, f.admin).Body.String()
		if !strings.Contains(body, tc.want) {
			t.Errorf("%s 里找不到 %q", tc.path, tc.want)
		}
	}
}

func TestPages_ViewerSeesBusinessPagesButNotAdminLedger(t *testing.T) {
	f := newSmokeFixture(t)

	// viewer 的定位是只读业务视图:能看设备/租约/会话,不能看后台账号台账。
	for _, path := range []string{"/", "/users", "/devices", "/leases", "/acl",
		"/routes", "/sessions", "/me", "/audit", "/settings"} {
		w := f.getPage(t, path, f.viewer)
		if w.Code == http.StatusInternalServerError {
			t.Errorf("%s: viewer 打开报 500 body=%q", path, trimForLog(w.Body.String()))
		}
	}
	if w := f.getPage(t, "/admins", f.viewer); w.Code != http.StatusForbidden {
		t.Errorf("/admins: viewer code=%d, 期望 403", w.Code)
	}
}

func TestPages_UnknownPathIs404(t *testing.T) {
	f := newSmokeFixture(t)
	for _, path := range []string{"/nope", "/users/", "/admin", "/settings/xyz"} {
		w := f.getPage(t, path, f.admin)
		if w.Code == http.StatusOK {
			t.Errorf("%s 返回了 200", path)
		}
	}
}

func TestPages_ListsSurviveEmptyDatabase(t *testing.T) {
	// 反过来:一条数据都没有时也不能崩(全新部署第一次打开控制台就是这个状态)。
	s := newMeTestServer(t)
	s.control = newFakeControl(t, controlOK()).client
	admin := createTestAdmin(t, s, "root", "pw-root-12345678")

	for _, path := range readOnlyPages {
		req := withAdminCtx(httptest.NewRequest(http.MethodGet, path, nil), admin)
		w := httptest.NewRecorder()
		s.routeAuthed(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s: 空库下 code=%d body=%q", path, w.Code, trimForLog(w.Body.String()))
		}
	}
}

func TestPages_ListsSurviveUnreachableControlPlane(t *testing.T) {
	// server 挂了的时候,管理员最需要能打开控制台看配置。
	// 任何一页因为拉不到运行态就整页 500,都是在最不该失灵的时刻失灵。
	s := newMeTestServer(t)
	s.control = newFakeControl(t, controlBroken()).client
	admin := createTestAdmin(t, s, "root", "pw-root-12345678")
	devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")

	for _, path := range readOnlyPages {
		req := withAdminCtx(httptest.NewRequest(http.MethodGet, path, nil), admin)
		w := httptest.NewRecorder()
		s.routeAuthed(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s: 控制面不可达时 code=%d body=%q", path, w.Code,
				trimForLog(w.Body.String()))
		}
	}
}

// -------------------------------------------------------------------------
// /healthz 与 /metrics(无需登录)
// -------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	s := newMeTestServer(t)
	w := httptest.NewRecorder()
	s.handleHealthz(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if w.Body.Len() == 0 {
		t.Fatal("healthz 响应体为空")
	}
}

// metricsReq 造一个来自指定对端、可选带 Bearer 的 /metrics 请求。
func metricsReq(remote, bearer string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.RemoteAddr = remote
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

func TestMetricsAccessAllowed(t *testing.T) {
	// /metrics 暴露 uptime、请求/错误计数与管理员账号数。不是致命机密,但也不该
	// 匿名可拉 —— 尤其「管理员账号数」对踩点有用。门禁有两套口径,不能互相漏。
	cases := []struct {
		name    string
		token   string
		proxies []string
		remote  string
		bearer  string
		want    bool
	}{
		{"无 token:环回放行", "", nil, "127.0.0.1:5000", "", true},
		{"无 token:v6 环回放行", "", nil, "[::1]:5000", "", true},
		{"无 token:公网拒绝", "", nil, "203.0.113.9:5000", "", false},
		{"无 token:内网也拒绝", "", nil, "192.168.1.5:5000", "", false},
		{"无 token:地址解析不了就拒", "", nil, "garbage", "", false},
		// 挂在反代后面时 RemoteAddr 恒为反代自身(常是 127.0.0.1),
		// 再按环回放行等于把 /metrics 开放给全互联网。
		{"配了反代却没 token:环回也拒", "", []string{"127.0.0.1"}, "127.0.0.1:5000", "", false},
		{"有 token:正确 Bearer 放行(哪怕来自公网)", "s3cr3t", nil, "203.0.113.9:5000", "s3cr3t", true},
		{"有 token:反代场景下也放行", "s3cr3t", []string{"127.0.0.1"}, "127.0.0.1:5000", "s3cr3t", true},
		{"有 token:Bearer 不对", "s3cr3t", nil, "203.0.113.9:5000", "wrong", false},
		{"有 token:没带 Authorization", "s3cr3t", nil, "127.0.0.1:5000", "", false},
		{"有 token:环回也不能免检", "s3cr3t", nil, "127.0.0.1:5000", "", false},
	}
	for _, tc := range cases {
		s := newMeTestServer(t)
		s.cfg.MetricsToken = tc.token
		s.cfg.TrustedProxies = tc.proxies
		if got := s.metricsAccessAllowed(metricsReq(tc.remote, tc.bearer)); got != tc.want {
			t.Errorf("%s: 放行=%v, 期望 %v", tc.name, got, tc.want)
		}
	}
}

func TestMetrics_DeniedLooksLikeNotFound(t *testing.T) {
	s := newMeTestServer(t)
	w := httptest.NewRecorder()
	// 回 404 而不是 403:403 等于告诉扫描器「这里确实有个 /metrics」。
	s.handleMetrics(w, metricsReq("203.0.113.9:5000", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("code=%d, 期望 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "nanotun-web_") {
		t.Fatal("拒绝路径仍然吐出了指标内容")
	}
}

func TestMetrics_ExposesCountersWithoutSecrets(t *testing.T) {
	s := newMeTestServer(t)
	createTestAdmin(t, s, "root", "pw-root-12345678")

	w := httptest.NewRecorder()
	s.handleMetrics(w, metricsReq("127.0.0.1:5000", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	for _, want := range []string{
		"nanotun-web_uptime_seconds", "nanotun-web_requests_total",
		`nanotun-web_errors_total{class="4xx"}`, "nanotun-web_admins 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics 缺 %q", want)
		}
	}
	// 拉 metrics 不需要登录,里面绝不能带任何身份相关的东西。
	for _, forbidden := range []string{"password", "psk", "secret", "root"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("metrics 里出现了 %q: %q", forbidden, trimForLog(body))
		}
	}
}
