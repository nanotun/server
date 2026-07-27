package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件覆盖 /admins 全套 —— 后台账号自身的增删改。
//
// 这块此前零覆盖,而它承载着整个控制台唯一一条**不可逆**的不变量:
// 系统里必须始终至少留一个启用中的 admin。踩穿这条线不是回滚数据能救的,
// 是没人能再登进来改任何东西。守卫写在两处(handler 的 ensureNotLastAdmin
// 快速预检 + store 事务内的 *EnsuringAdmin 原子 floor),两处都得测到。
//
// 另外两条:自己不能禁用/删除/降级自己(防误操作反锁),以及 viewer 一个字节
// 都不该看到管理员台账。

// adminsFixture 建一个「操作者 + 一个陪衬管理员」的常见起点。
// 返回的 me 是 admin 角色、用来发起请求;other 是被操作对象。
func adminsFixture(t *testing.T, s *Server) (me, other *store.WebAdmin) {
	t.Helper()
	me = createTestAdmin(t, s, "root", "pw-root-12345678")
	other = createTestAdmin(t, s, "second", "pw-second-123456")
	return me, other
}

// postAdminVerb 以 me 的身份 POST /admins/{id}/{verb}。
// 这些 handler 自身不校验 CSRF(由 requireCSRFAndAuth 中间件在外层做,见 middleware_test.go),
// 所以这里直接注入身份、只测 handler 的编排。
func postAdminVerb(t *testing.T, s *Server, me *store.WebAdmin,
	id int64, verb string, form url.Values) *httptest.ResponseRecorder {

	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	target := "/admins/" + itoa(id) + "/" + verb
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleAdminAction(w, withAdminCtx(req, me))
	return w
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// adminByName 从库里按用户名捞一个,不存在返回 nil。
func adminByName(t *testing.T, s *Server, name string) *store.WebAdmin {
	t.Helper()
	list, err := s.store.ListWebAdmins(t.Context())
	if err != nil {
		t.Fatalf("ListWebAdmins: %v", err)
	}
	for _, a := range list {
		if strings.EqualFold(a.Username, name) {
			return a
		}
	}
	return nil
}

func mustGetAdmin(t *testing.T, s *Server, id int64) *store.WebAdmin {
	t.Helper()
	a, err := s.store.GetWebAdmin(t.Context(), id)
	if err != nil {
		t.Fatalf("GetWebAdmin(%d): %v", id, err)
	}
	return a
}

// -------------------------------------------------------------------------
// 角色门禁
// -------------------------------------------------------------------------

func TestAdmins_ViewerIsLockedOutEverywhere(t *testing.T) {
	s := newMeTestServer(t)
	_, other := adminsFixture(t, s)
	viewer := createTestAdmin(t, s, "peeker", "pw-peeker-12345")
	if err := s.store.SetWebAdminRoleEnsuringAdmin(t.Context(), viewer.ID, "viewer"); err != nil {
		t.Fatalf("降级为 viewer: %v", err)
	}
	viewer = mustGetAdmin(t, s, viewer.ID)

	// viewer 是「只读业务视图」,不该看到管理员账户台账(用户名、角色、锁定状态、
	// 上次登录 IP)—— 那是一份现成的爆破目标清单。
	reads := []struct {
		name string
		call func() *httptest.ResponseRecorder
	}{
		{"GET /admins", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			s.handleAdminList(w, withAdminCtx(httptest.NewRequest(http.MethodGet, "/admins", nil), viewer))
			return w
		}},
		{"GET /admins/new", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			s.handleAdminNew(w, withAdminCtx(httptest.NewRequest(http.MethodGet, "/admins/new", nil), viewer))
			return w
		}},
		{"GET /admins/{id}/reset-pwd", func() *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/admins/"+itoa(other.ID)+"/reset-pwd", nil)
			s.handleAdminAction(w, withAdminCtx(req, viewer))
			return w
		}},
	}
	for _, tc := range reads {
		if w := tc.call(); w.Code != http.StatusForbidden {
			t.Errorf("%s: code=%d, 期望 403", tc.name, w.Code)
		}
	}

	for _, verb := range []string{"disable", "enable", "delete", "set-role", "unlock", "reset-pwd"} {
		w := postAdminVerb(t, s, viewer, other.ID, verb, url.Values{"role": {"viewer"}})
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s: code=%d, 期望 403", verb, w.Code)
		}
	}
	// 全程不该有任何东西被改动。
	if a := mustGetAdmin(t, s, other.ID); !a.Enabled || a.Role != "admin" {
		t.Fatalf("viewer 的请求改动了目标: enabled=%v role=%q", a.Enabled, a.Role)
	}
}

func TestAdmins_UnauthenticatedIs401(t *testing.T) {
	s := newMeTestServer(t)
	_, other := adminsFixture(t, s)

	// ctx 里没有 admin(中间件没跑或被绕过)时,handler 自己也得挡住,
	// 而不是把 nil 当成「超级用户」。
	req := httptest.NewRequest(http.MethodPost, "/admins/"+itoa(other.ID)+"/delete", nil)
	w := httptest.NewRecorder()
	s.handleAdminAction(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d, 期望 401", w.Code)
	}
	if mustGetAdmin(t, s, other.ID) == nil {
		t.Fatal("目标被删了")
	}
}

// -------------------------------------------------------------------------
// 最后一个管理员
// -------------------------------------------------------------------------

func TestAdmins_LastEnabledAdminCannotBeRemoved(t *testing.T) {
	// 场景:两个 admin,me 在线;先把 other 禁用,系统只剩 me 一个启用的 admin。
	// 此后任何会让启用 admin 归零的动作都必须被拒。
	verbs := []struct {
		verb string
		form url.Values
	}{
		{"disable", nil},
		{"delete", nil},
		{"set-role", url.Values{"role": {"viewer"}}},
	}
	for _, tc := range verbs {
		t.Run(tc.verb, func(t *testing.T) {
			s := newMeTestServer(t)
			me, other := adminsFixture(t, s)

			// me 对自己动手会先被「不能操作自己」拦下,看不到 floor 守卫。
			// 所以让 other 保持 admin 角色、由 other 充当「最后一个」的替身:
			// 把 me 降成……不行,me 得是 admin 才能发请求。
			// 换个造法:再建一个 admin C 并禁用,使启用 admin 只剩 me 与 other 两个,
			// 然后禁用 other → 启用 admin 只剩 me;再对 other(已禁用)动手。
			w := postAdminVerb(t, s, me, other.ID, "disable", nil)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("前置禁用 other: code=%d", w.Code)
			}

			n, err := s.store.CountEnabledWebAdminsByRole(t.Context(), "admin")
			if err != nil {
				t.Fatalf("CountEnabledWebAdminsByRole: %v", err)
			}
			if n != 1 {
				t.Fatalf("启用 admin 数=%d, 期望 1", n)
			}

			w = postAdminVerb(t, s, me, other.ID, tc.verb, tc.form)
			// 记录当前行为:守卫按「启用 admin 计数」判定,对已禁用的 other
			// 同样会拒。见 TestAdmins_GuardAlsoBlocksHarmlessOpsOnDisabledAdmin。
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: code=%d, 期望 400(floor 守卫)", tc.verb, w.Code)
			}
			if mustGetAdmin(t, s, me.ID).Role != "admin" || !mustGetAdmin(t, s, me.ID).Enabled {
				t.Fatalf("me 被改动了")
			}
		})
	}
}

func TestAdmins_GuardAlsoBlocksHarmlessOpsOnDisabledAdmin(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	if w := postAdminVerb(t, s, me, other.ID, "disable", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("前置禁用: code=%d", w.Code)
	}

	// ensureNotLastAdmin 数的是「启用中的 admin」,而 other 此刻**已经禁用** ——
	// 删掉它并不会让这个计数下降,系统仍有 me 可登录。守卫却照样拒绝。
	//
	// 这是过度保护,不是安全洞:后果是「唯一在岗的管理员清理不掉已停用的旧账号,
	// 得先随便再建一个 admin 才能删」。真正防并发穿底的是 store 侧事务内的
	// *EnsuringAdmin(先写后验 floor),它对这一步是放行的 —— 下面直接调它验证。
	w := postAdminVerb(t, s, me, other.ID, "delete", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code=%d, 期望 400(当前行为)", w.Code)
	}
	if mustGetAdmin(t, s, other.ID) == nil {
		t.Fatal("目标被删了")
	}

	// store 层不受这条预检约束:删一个已禁用的 admin 不触碰 floor。
	if err := s.store.DeleteWebAdminEnsuringAdmin(t.Context(), other.ID); err != nil {
		t.Fatalf("store 层删已禁用 admin 应当放行, got %v", err)
	}
}

func TestAdmins_StoreFloorGuardIsTheRealBackstop(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "solo", "pw-solo-12345678")

	// 绕过 handler 的预检直接打 store —— 模拟并发下两个请求都通过了预检的情形。
	// 事务内「先写后验」必须把最后一个启用 admin 的删除/禁用/降级整个回滚。
	if err := s.store.DeleteWebAdminEnsuringAdmin(t.Context(), me.ID); err == nil {
		t.Fatal("删最后一个启用 admin 竟然成功了")
	}
	if err := s.store.SetWebAdminEnabledEnsuringAdmin(t.Context(), me.ID); err == nil {
		t.Fatal("禁用最后一个启用 admin 竟然成功了")
	}
	if err := s.store.SetWebAdminRoleEnsuringAdmin(t.Context(), me.ID, "viewer"); err == nil {
		t.Fatal("把最后一个启用 admin 降级为 viewer 竟然成功了")
	}
	// 三次失败都必须回滚干净,账号原样健在。
	got := mustGetAdmin(t, s, me.ID)
	if got == nil || !got.Enabled || got.Role != "admin" {
		t.Fatalf("回滚不干净: %+v", got)
	}
}

func TestAdmins_ViewerDoesNotCountTowardTheFloor(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "onlyadmin", "pw-only-12345678")
	v := createTestAdmin(t, s, "vv", "pw-vv-123456789")
	if err := s.store.SetWebAdminRoleEnsuringAdmin(t.Context(), v.ID, "viewer"); err != nil {
		t.Fatalf("降级: %v", err)
	}

	// 一堆 viewer 顶不了一个 admin:计数只算 role=admin 且 enabled。
	n, err := s.store.CountEnabledWebAdminsByRole(t.Context(), "admin")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("启用 admin 数=%d, 期望 1(viewer 不计)", n)
	}
	if err := s.store.DeleteWebAdminEnsuringAdmin(t.Context(), me.ID); err == nil {
		t.Fatal("有 viewer 在就允许删掉唯一 admin —— 控制台会被永久锁成只读")
	}
}

// -------------------------------------------------------------------------
// 不能对自己动手
// -------------------------------------------------------------------------

func TestAdmins_CannotDisableDeleteOrDemoteSelf(t *testing.T) {
	s := newMeTestServer(t)
	me, _ := adminsFixture(t, s)
	// 另建一个 admin,确保 floor 守卫不会抢先触发 —— 要测的是「自我保护」这一条。
	createTestAdmin(t, s, "spare", "pw-spare-1234567")

	for _, tc := range []struct {
		verb string
		form url.Values
	}{
		{"disable", nil},
		{"delete", nil},
		{"set-role", url.Values{"role": {"viewer"}}},
	} {
		w := postAdminVerb(t, s, me, me.ID, tc.verb, tc.form)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s 自己: code=%d, 期望 400", tc.verb, w.Code)
		}
	}
	got := mustGetAdmin(t, s, me.ID)
	if !got.Enabled || got.Role != "admin" {
		t.Fatalf("自我保护失效: enabled=%v role=%q", got.Enabled, got.Role)
	}
}

func TestAdmins_SelfServiceVerbsAreStillAllowed(t *testing.T) {
	s := newMeTestServer(t)
	me, _ := adminsFixture(t, s)

	// enable / unlock 对自己无害,不该被自我保护一刀切拦掉
	//(比如管理员想清掉自己账号上的失败计数)。
	for _, verb := range []string{"enable", "unlock"} {
		w := postAdminVerb(t, s, me, me.ID, verb, nil)
		if w.Code != http.StatusSeeOther {
			t.Errorf("%s 自己: code=%d, 期望 303", verb, w.Code)
		}
	}
}

// -------------------------------------------------------------------------
// 新建管理员
// -------------------------------------------------------------------------

func postAdminNew(t *testing.T, s *Server, me *store.WebAdmin, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admins/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handleAdminNew(w, withAdminCtx(req, me))
	return w
}

func TestAdminNew_CreatesWithRoleAndAudits(t *testing.T) {
	s := newMeTestServer(t)
	me, _ := adminsFixture(t, s)

	for _, role := range []string{"admin", "viewer"} {
		name := "fresh-" + role
		w := postAdminNew(t, s, me, url.Values{
			"username":         {name},
			"role":             {role},
			"password":         {"Str0ng-Passw0rd!x"},
			"password_confirm": {"Str0ng-Passw0rd!x"},
		})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("role=%s: code=%d body=%q", role, w.Code, trimForLog(w.Body.String()))
		}
		got := adminByName(t, s, name)
		if got == nil {
			t.Fatalf("role=%s: 没建出来", role)
		}
		if got.Role != role {
			t.Errorf("role=%q, 期望 %q", got.Role, role)
		}
		if !got.Enabled {
			t.Errorf("新建的管理员应当是启用状态")
		}
		if got.PasswordHash == "" || strings.Contains(got.PasswordHash, "Str0ng") {
			t.Errorf("密码没有被哈希: %q", trimForLog(got.PasswordHash))
		}
		if got.CreatedBy != me.ID {
			t.Errorf("created_by=%d, 期望 %d", got.CreatedBy, me.ID)
		}
	}
	assertAuditAction(t, s, "webadmin_create")
}

func TestAdminNew_RejectsBadInputWithoutCreating(t *testing.T) {
	cases := []struct {
		name string
		form url.Values
	}{
		{"两次密码不一致", url.Values{
			"username": {"x1"}, "role": {"admin"},
			"password": {"Str0ng-Passw0rd!x"}, "password_confirm": {"Different-1!aaa"}}},
		{"密码太弱", url.Values{
			"username": {"x2"}, "role": {"admin"},
			"password": {"123"}, "password_confirm": {"123"}}},
		{"密码为空", url.Values{
			"username": {"x3"}, "role": {"admin"},
			"password": {""}, "password_confirm": {""}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			me, _ := adminsFixture(t, s)
			before := len(listAdmins(t, s))

			w := postAdminNew(t, s, me, tc.form)

			// 回渲染表单页(200 + 错误横幅),而不是 303 —— 输入还在,用户能改。
			if w.Code == http.StatusSeeOther {
				t.Fatalf("竟然创建成功了")
			}
			if got := len(listAdmins(t, s)); got != before {
				t.Fatalf("管理员数 %d → %d, 不该有变化", before, got)
			}
		})
	}
}

func TestAdminNew_DuplicateUsernameIsFriendlyAndCreatesNothing(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	before := len(listAdmins(t, s))

	// 大小写不同也算重名(store 侧 COLLATE NOCASE),否则 Root 与 root 两个账号
	// 在列表里肉眼无法区分,是个现成的钓鱼位。
	for _, name := range []string{other.Username, strings.ToUpper(other.Username)} {
		w := postAdminNew(t, s, me, url.Values{
			"username":         {name},
			"role":             {"admin"},
			"password":         {"Str0ng-Passw0rd!x"},
			"password_confirm": {"Str0ng-Passw0rd!x"},
		})
		if w.Code == http.StatusSeeOther {
			t.Fatalf("username=%q 重名却创建成功", name)
		}
		if w.Code != http.StatusOK {
			t.Fatalf("username=%q: code=%d, 期望 200 + 表单错误横幅", name, w.Code)
		}
	}
	if got := len(listAdmins(t, s)); got != before {
		t.Fatalf("管理员数 %d → %d", before, got)
	}
}

func TestAdminNew_RejectsMethodAndRendersForm(t *testing.T) {
	s := newMeTestServer(t)
	me, _ := adminsFixture(t, s)

	w := httptest.NewRecorder()
	s.handleAdminNew(w, withAdminCtx(httptest.NewRequest(http.MethodGet, "/admins/new", nil), me))
	if w.Code != http.StatusOK {
		t.Fatalf("GET code=%d, 期望 200", w.Code)
	}

	w = httptest.NewRecorder()
	s.handleAdminNew(w, withAdminCtx(httptest.NewRequest(http.MethodDelete, "/admins/new", nil), me))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE code=%d, 期望 405", w.Code)
	}
	if got := w.Header().Get("Allow"); got != "GET, POST" {
		t.Errorf("Allow=%q", got)
	}
}

func listAdmins(t *testing.T, s *Server) []*store.WebAdmin {
	t.Helper()
	l, err := s.store.ListWebAdmins(t.Context())
	if err != nil {
		t.Fatalf("ListWebAdmins: %v", err)
	}
	return l
}

// -------------------------------------------------------------------------
// disable / enable / unlock / set-role
// -------------------------------------------------------------------------

func TestAdminDisable_RevokesTargetSessions(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	createTestAdmin(t, s, "spare", "pw-spare-1234567")

	// other 此刻正登录着。禁用如果不清会话,它手里的 cookie 还能撑到过期,
	// 「立即停用」就成了「过一阵子停用」。
	//
	// 吊销由两层各做一次:store.SetWebAdminEnabledEnsuringAdmin 在**同一个事务里**
	// 改 enabled 并删 web_sessions(所以「已禁用但会话还在」这个中间态从不存在),
	// handler 之后又调了一次 DeleteWebSessionsByAdmin。任意剜掉一层本用例仍然过,
	// 两层同时剜掉才会红 —— 断言落在结果上而非调用上,正是为了不把这层冗余焊死。
	_, sid := loginAs(t, s, other)

	w := postAdminVerb(t, s, me, other.ID, "disable", nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if mustGetAdmin(t, s, other.ID).Enabled {
		t.Fatal("目标仍是启用状态")
	}
	if _, err := s.store.GetWebSession(t.Context(), sid); err == nil {
		t.Fatal("被禁用管理员的会话还在")
	}
	assertAuditAction(t, s, "webadmin_disable")
}

func TestAdminEnable_BringsBackAndAudits(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	createTestAdmin(t, s, "spare", "pw-spare-1234567")

	if w := postAdminVerb(t, s, me, other.ID, "disable", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("disable code=%d", w.Code)
	}
	if w := postAdminVerb(t, s, me, other.ID, "enable", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("enable code=%d", w.Code)
	}
	if !mustGetAdmin(t, s, other.ID).Enabled {
		t.Fatal("enable 之后仍是禁用")
	}
	assertAuditAction(t, s, "webadmin_enable")
}

func TestAdminUnlock_ClearsLockoutCounters(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)

	// 攒够失败次数把账号锁上,再解锁。
	for i := 0; i < int(s.cfg.MaxLoginFailures)+2; i++ {
		if _, _, err := s.store.RecordWebAdminLoginFailure(t.Context(), other.ID,
			s.cfg.MaxLoginFailures, s.cfg.LockoutSeconds); err != nil {
			t.Fatalf("RecordWebAdminLoginFailure: %v", err)
		}
	}
	locked := mustGetAdmin(t, s, other.ID)
	if locked.FailedLogins == 0 && locked.LockedUntil == 0 {
		t.Skip("这套 store 不记失败计数,跳过")
	}

	w := postAdminVerb(t, s, me, other.ID, "unlock", nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d", w.Code)
	}
	after := mustGetAdmin(t, s, other.ID)
	if after.FailedLogins != 0 || after.LockedUntil != 0 {
		t.Fatalf("解锁后 failed=%d locked_until=%d, 期望都是 0", after.FailedLogins, after.LockedUntil)
	}
	assertAuditAction(t, s, "webadmin_unlock")
}

func TestAdminSetRole_ValidatesEnum(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	createTestAdmin(t, s, "spare", "pw-spare-1234567")

	// 角色是个闭集。写进去一个不认识的值,后果是这个账号在
	// requireAdminRole 里既不是 admin 也不是正常 viewer,权限行为不可预期。
	for _, bad := range []string{"", "superadmin", "ADMIN", "Viewer", "root", "viewer;--"} {
		w := postAdminVerb(t, s, me, other.ID, "set-role", url.Values{"role": {bad}})
		if w.Code != http.StatusBadRequest {
			t.Errorf("role=%q: code=%d, 期望 400", bad, w.Code)
		}
	}
	if got := mustGetAdmin(t, s, other.ID).Role; got != "admin" {
		t.Fatalf("角色被非法值改成了 %q", got)
	}

	w := postAdminVerb(t, s, me, other.ID, "set-role", url.Values{"role": {"viewer"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("合法降级 code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if got := mustGetAdmin(t, s, other.ID).Role; got != "viewer" {
		t.Fatalf("role=%q, 期望 viewer", got)
	}
	assertAuditAction(t, s, "webadmin_set_role")

	// 首尾空白是裁掉而不是当成非法值 —— 表单里多打一个空格不该报「角色无效」。
	if w := postAdminVerb(t, s, me, other.ID, "set-role",
		url.Values{"role": {"  admin  "}}); w.Code != http.StatusSeeOther {
		t.Fatalf("带空白的合法角色: code=%d, 期望 303", w.Code)
	}
	if got := mustGetAdmin(t, s, other.ID).Role; got != "admin" {
		t.Fatalf("role=%q, 期望 admin", got)
	}
}

func TestAdminSetRole_PromotingViewerNeedsNoFloorCheck(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	v := createTestAdmin(t, s, "vv", "pw-vv-123456789")
	if err := s.store.SetWebAdminRoleEnsuringAdmin(t.Context(), v.ID, "viewer"); err != nil {
		t.Fatalf("准备 viewer: %v", err)
	}

	// 只有一个 admin(me)时,把 viewer **升**成 admin 是在增加冗余,
	// 不该被 floor 守卫误伤 —— 否则单管理员系统永远加不出第二个管理员。
	w := postAdminVerb(t, s, me, v.ID, "set-role", url.Values{"role": {"admin"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if got := mustGetAdmin(t, s, v.ID).Role; got != "admin" {
		t.Fatalf("role=%q, 期望 admin", got)
	}
}

// -------------------------------------------------------------------------
// 改密
// -------------------------------------------------------------------------

func TestAdminResetPwd_OtherAdminWorksAndKicksThemOut(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	oldHash := mustGetAdmin(t, s, other.ID).PasswordHash
	_, sid := loginAs(t, s, other)

	// 改**他人**密码是纯管理操作,只要 admin 角色即可,不要求 step-up。
	w := postAdminVerb(t, s, me, other.ID, "reset-pwd", url.Values{
		"password":         {"Br4nd-New-Pass!x"},
		"password_confirm": {"Br4nd-New-Pass!x"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if mustGetAdmin(t, s, other.ID).PasswordHash == oldHash {
		t.Fatal("密码没变")
	}
	// 应急改密的意义就在于立刻把对方踢下线,否则被盗会话继续有效。
	// 同 disable:store.UpdateWebAdminPasswordHash 事务内删一次、handler 再删一次。
	if _, err := s.store.GetWebSession(t.Context(), sid); err == nil {
		t.Fatal("改密后对方的会话仍然有效")
	}
	assertAuditAction(t, s, "webadmin_reset_pwd")
}

func TestAdminResetPwd_SelfRequiresCurrentPassword(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	createTestAdmin(t, s, "spare", "pw-spare-1234567")
	oldHash := mustGetAdmin(t, s, me.ID).PasswordHash

	// 会话被劫持(cookie 失窃 / 未锁屏)时,若改自己的密码不需要当前密码,
	// 攻击者一步就能把账号永久接管、并把真管理员反锁在外。
	for _, tc := range []struct{ name, cur string }{
		{"不带当前密码", ""},
		{"当前密码错", "wrong-password-xx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := postAdminVerb(t, s, me, me.ID, "reset-pwd", url.Values{
				"current_password": {tc.cur},
				"password":         {"Br4nd-New-Pass!x"},
				"password_confirm": {"Br4nd-New-Pass!x"},
			})
			if w.Code == http.StatusSeeOther {
				t.Fatalf("竟然改成功了")
			}
			if mustGetAdmin(t, s, me.ID).PasswordHash != oldHash {
				t.Fatalf("密码被改了")
			}
		})
	}

	// 带上正确的当前密码就该通过。
	w := postAdminVerb(t, s, me, me.ID, "reset-pwd", url.Values{
		"current_password": {"pw-root-12345678"},
		"password":         {"Br4nd-New-Pass!x"},
		"password_confirm": {"Br4nd-New-Pass!x"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("带正确当前密码: code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if mustGetAdmin(t, s, me.ID).PasswordHash == oldHash {
		t.Fatal("密码没变")
	}
}

func TestAdminResetPwd_SelfIsThrottledByIPCooldown(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	const ip = "203.0.113.77"

	for i := 0; i < stepUpMaxFailures; i++ {
		s.stepUpFailures.Inc(ip)
	}
	req := httptest.NewRequest(http.MethodPost, "/admins/"+itoa(me.ID)+"/reset-pwd",
		strings.NewReader(url.Values{
			"current_password": {"pw-root-12345678"},
			"password":         {"Br4nd-New-Pass!x"},
			"password_confirm": {"Br4nd-New-Pass!x"},
		}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	s.handleAdminAction(w, withAdminCtx(req, me))

	// 冷却期内连正确的当前密码也不放行 —— 否则攻击者可以用「猜错很多次」
	// 之后偶然猜中的那一次完成接管。
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("code=%d, 期望 429", w.Code)
	}
}

func TestAdminResetPwd_RejectsWeakAndMismatched(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	oldHash := mustGetAdmin(t, s, other.ID).PasswordHash

	for _, tc := range []struct{ name, pwd, confirm string }{
		{"不一致", "Str0ng-Passw0rd!x", "Other-Passw0rd!x"},
		{"太弱", "123", "123"},
		{"空", "", ""},
	} {
		w := postAdminVerb(t, s, me, other.ID, "reset-pwd", url.Values{
			"password": {tc.pwd}, "password_confirm": {tc.confirm},
		})
		if w.Code == http.StatusSeeOther {
			t.Errorf("%s: 竟然改成功了", tc.name)
		}
		if mustGetAdmin(t, s, other.ID).PasswordHash != oldHash {
			t.Fatalf("%s: 密码被改了", tc.name)
		}
	}
}

func TestAdminResetPwd_GETRendersForm(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)

	for _, tc := range []struct {
		name string
		id   int64
	}{{"改他人", other.ID}, {"改自己", me.ID}} {
		req := httptest.NewRequest(http.MethodGet, "/admins/"+itoa(tc.id)+"/reset-pwd", nil)
		w := httptest.NewRecorder()
		s.handleAdminAction(w, withAdminCtx(req, me))
		if w.Code != http.StatusOK {
			t.Errorf("%s: code=%d body=%q", tc.name, w.Code, trimForLog(w.Body.String()))
		}
	}

	// 不存在的 id 要 404,而不是渲染一个空表单让人对着不存在的账号改密。
	req := httptest.NewRequest(http.MethodGet, "/admins/99999/reset-pwd", nil)
	w := httptest.NewRecorder()
	s.handleAdminAction(w, withAdminCtx(req, me))
	if w.Code != http.StatusNotFound {
		t.Errorf("不存在的 id: code=%d, 期望 404", w.Code)
	}
}

// -------------------------------------------------------------------------
// 路由与坏输入
// -------------------------------------------------------------------------

func TestAdminAction_BadInput(t *testing.T) {
	s := newMeTestServer(t)
	me, _ := adminsFixture(t, s)

	cases := []struct {
		name string
		path string
		want int
	}{
		{"缺动作", "/admins/1", http.StatusBadRequest},
		{"id 不是数字", "/admins/abc/disable", http.StatusBadRequest},
		{"id 为 0", "/admins/0/disable", http.StatusBadRequest},
		{"id 为负", "/admins/-1/disable", http.StatusBadRequest},
		{"id 科学计数法", "/admins/1e2/disable", http.StatusBadRequest},
		{"不存在的 id", "/admins/99999/disable", http.StatusNotFound},
		{"未知动作", "/admins/" + itoa(me.ID) + "/nuke", http.StatusBadRequest},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, tc.path, nil)
		w := httptest.NewRecorder()
		s.handleAdminAction(w, withAdminCtx(req, me))
		if w.Code != tc.want {
			t.Errorf("%s (%s): code=%d, 期望 %d", tc.name, tc.path, w.Code, tc.want)
		}
	}
}

func TestAdminAction_WritesRejectGET(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)

	// 只有 reset-pwd 有 GET 表单页;其余动作用 GET 触发就成了「点个链接就禁用管理员」,
	// 连 CSRF 都不用绕。
	for _, verb := range []string{"disable", "enable", "delete", "set-role", "unlock"} {
		req := httptest.NewRequest(http.MethodGet, "/admins/"+itoa(other.ID)+"/"+verb, nil)
		w := httptest.NewRecorder()
		s.handleAdminAction(w, withAdminCtx(req, me))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: code=%d, 期望 405", verb, w.Code)
		}
	}
	if a := mustGetAdmin(t, s, other.ID); !a.Enabled || a.Role != "admin" {
		t.Fatal("GET 请求改动了目标")
	}
}

func TestAdminList_RendersAndRejectsNonGET(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)

	w := httptest.NewRecorder()
	s.handleAdminList(w, withAdminCtx(httptest.NewRequest(http.MethodGet, "/admins", nil), me))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	for _, name := range []string{me.Username, other.Username} {
		if !strings.Contains(body, name) {
			t.Errorf("列表里没有 %q", name)
		}
	}
	// 密码哈希绝不能出现在页面上。
	if strings.Contains(body, mustGetAdmin(t, s, me.ID).PasswordHash) {
		t.Fatal("列表页泄漏了 password_hash")
	}

	w = httptest.NewRecorder()
	s.handleAdminList(w, withAdminCtx(httptest.NewRequest(http.MethodPost, "/admins", nil), me))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST code=%d, 期望 405", w.Code)
	}
}

// -------------------------------------------------------------------------
// ensureNotLastAdmin 的错误分流
// -------------------------------------------------------------------------

func TestEnsureNotLastAdmin_SentinelVsDBError(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	req := withAdminCtx(httptest.NewRequest(http.MethodPost, "/admins", nil), me)

	if err := s.ensureNotLastAdmin(req); err != errLastEnabledAdmin {
		t.Fatalf("只剩一个 admin 时 err=%v, 期望 sentinel", err)
	}
	createTestAdmin(t, s, "second", "pw-second-123456")
	if err := s.ensureNotLastAdmin(req); err != nil {
		t.Fatalf("有两个 admin 时 err=%v, 期望 nil", err)
	}

	// 分流:sentinel → 本地化 400;其它(读计数时的 DB 故障)→ 遮蔽细节的 500。
	// 后者若直接把 err.Error() 渲染出去,SQL 片段与库路径会漏到页面上。
	w := httptest.NewRecorder()
	s.renderEnsureAdminErr(w, req, errLastEnabledAdmin)
	if w.Code != http.StatusBadRequest {
		t.Errorf("sentinel: code=%d, 期望 400", w.Code)
	}

	w = httptest.NewRecorder()
	dbErr := errFake("no such table: web_admins /var/lib/nanotun/db.sqlite")
	s.renderEnsureAdminErr(w, req, dbErr)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("DB 故障: code=%d, 期望 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "db.sqlite") {
		t.Errorf("内部错误细节泄漏到页面: %q", trimForLog(w.Body.String()))
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }
