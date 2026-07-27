package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件覆盖两个「按一下就改变数据面行为」的运行时开关:
//
//	POST /runtime/reload        → 让 server 重载 ACL 快照
//	POST /runtime/mesh-toggle   → 全网组网总闸
//
// 组网总闸是这两者里更要紧的:它决定「设备之间能不能互相看见」。这里的核心风险不是
// 写不进库,而是**库与数据面劈叉** —— 侧栏按钮读 DB 显示「已关闭」,而 server 手里
// 仍是旧快照照放流量。handler 为此把 reload 改成了同步 + 失败时 warn 横幅,下面把
// 「落库成功但 reload 失败」这条路径单独钉住。

func runtimeServer(t *testing.T, routes map[string]http.HandlerFunc) (*Server, *fakeControl) {
	t.Helper()
	s := newMeTestServer(t)
	fc := newFakeControl(t, routes)
	s.control = fc.client
	return s, fc
}

func postRuntime(t *testing.T, s *Server, me *store.WebAdmin, path string,
	form url.Values, h func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {

	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, withAdminCtx(req, me))
	return w
}

func meshIs(t *testing.T, s *Server) bool {
	t.Helper()
	v, err := s.store.GetMeshEnabled(t.Context())
	if err != nil {
		t.Fatalf("GetMeshEnabled: %v", err)
	}
	return v
}

// -------------------------------------------------------------------------
// /runtime/reload
// -------------------------------------------------------------------------

func TestRuntimeReload_HappyPath(t *testing.T) {
	s, fc := runtimeServer(t, controlOK())
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	w := postRuntime(t, s, me, "/runtime/reload", nil, s.handleRuntimeReload)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if !fc.sawPath("/reload") {
		t.Fatalf("没有通知 server 重载, 收到的请求: %v", fc.requests())
	}
	assertAuditAction(t, s, "runtime_reload_acl_ok")
}

func TestRuntimeReload_ControlFailureIsSurfaced(t *testing.T) {
	s, _ := runtimeServer(t, controlBroken())
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	// server 没重载成功却回 303「已重载」,管理员会以为规则生效了。
	w := postRuntime(t, s, me, "/runtime/reload", nil, s.handleRuntimeReload)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("code=%d, 期望 502", w.Code)
	}
	assertAuditAction(t, s, "runtime_reload_acl_fail")
}

func TestRuntimeReload_ReturnToStaysOnSite(t *testing.T) {
	s, _ := runtimeServer(t, controlOK())
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	for _, tc := range []struct{ in, want string }{
		{"/acl", "/acl"},
		{"//evil.com/x", "/"},
		{"https://evil.com/x", "/"},
		{"", "/"},
	} {
		w := postRuntime(t, s, me, "/runtime/reload",
			url.Values{"return_to": {tc.in}}, s.handleRuntimeReload)
		loc := w.Header().Get("Location")
		if !strings.HasPrefix(loc, tc.want) {
			t.Errorf("return_to=%q → Location=%q, 期望以 %q 开头", tc.in, loc, tc.want)
		}
		if strings.Contains(loc, "evil.com") {
			t.Errorf("return_to=%q 造成开放重定向: %q", tc.in, loc)
		}
	}
}

func TestRuntimeReload_Gates(t *testing.T) {
	s, fc := runtimeServer(t, controlOK())
	createTestAdmin(t, s, "root", "pw-root-12345678")
	viewer := createTestAdmin(t, s, "peeker", "pw-peeker-12345")
	if err := s.store.SetWebAdminRoleEnsuringAdmin(t.Context(), viewer.ID, "viewer"); err != nil {
		t.Fatalf("降级: %v", err)
	}
	viewer = mustGetAdmin(t, s, viewer.ID)

	if w := postRuntime(t, s, viewer, "/runtime/reload", nil, s.handleRuntimeReload); w.Code != http.StatusForbidden {
		t.Errorf("viewer code=%d, 期望 403", w.Code)
	}
	w := httptest.NewRecorder()
	s.handleRuntimeReload(w, withAdminCtx(
		httptest.NewRequest(http.MethodGet, "/runtime/reload", nil),
		mustGetAdmin(t, s, viewer.ID)))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET code=%d, 期望 405", w.Code)
	}
	if fc.sawPath("/reload") {
		t.Fatal("被拒的请求仍然通知了 server")
	}
}

func TestRuntimeReload_NoControlSocketDoesNotPanic(t *testing.T) {
	s := newMeTestServer(t)
	s.control = nil // 未配 control socket 的部署
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	// 这条路径不像 try*Background 那样在入口挡 nil,直接就调方法。
	// 真出现 nil 就是解引用崩,把整页(经 withRecover 兜住的话是 500)打掉。
	w := postRuntime(t, s, me, "/runtime/reload", nil, s.handleRuntimeReload)
	if w.Code == http.StatusSeeOther {
		t.Fatalf("没有控制面却报成功")
	}
}

// -------------------------------------------------------------------------
// /runtime/mesh-toggle
// -------------------------------------------------------------------------

func TestMeshToggle_ExplicitTargetWins(t *testing.T) {
	s, _ := runtimeServer(t, controlOK())
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	// 显式 to= 的各种写法都要认;认错了就是「点开却关了」。
	for _, tc := range []struct {
		to   string
		want bool
	}{
		{"on", true}, {"true", true}, {"1", true}, {"yes", true}, {"ON", true},
		{"off", false}, {"false", false}, {"0", false}, {"no", false}, {" Off ", false},
	} {
		w := postRuntime(t, s, me, "/runtime/mesh-toggle",
			url.Values{"to": {tc.to}}, s.handleRuntimeMeshToggle)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("to=%q: code=%d body=%q", tc.to, w.Code, trimForLog(w.Body.String()))
		}
		if got := meshIs(t, s); got != tc.want {
			t.Errorf("to=%q → mesh=%v, 期望 %v", tc.to, got, tc.want)
		}
	}
}

func TestMeshToggle_NoTargetFlipsCurrent(t *testing.T) {
	s, _ := runtimeServer(t, controlOK())
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	start := meshIs(t, s)
	for i := 0; i < 3; i++ {
		if w := postRuntime(t, s, me, "/runtime/mesh-toggle", nil,
			s.handleRuntimeMeshToggle); w.Code != http.StatusSeeOther {
			t.Fatalf("第 %d 次 code=%d", i, w.Code)
		}
		want := start
		if i%2 == 0 {
			want = !start
		}
		if got := meshIs(t, s); got != want {
			t.Fatalf("第 %d 次翻转后 mesh=%v, 期望 %v", i, got, want)
		}
	}
	assertAuditAction(t, s, "mesh_toggle")
}

func TestMeshToggle_UnknownTargetValueFlipsRatherThanGuessing(t *testing.T) {
	s, _ := runtimeServer(t, controlOK())
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	before := meshIs(t, s)

	// to=maybe 落到 default 分支 = 当作没传,按取反处理。
	// 关键是**不能**把无法识别的值默默当成 "on" —— 那是一次意外的全网打通。
	w := postRuntime(t, s, me, "/runtime/mesh-toggle",
		url.Values{"to": {"maybe"}}, s.handleRuntimeMeshToggle)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d", w.Code)
	}
	if got := meshIs(t, s); got != !before {
		t.Fatalf("mesh=%v, 期望翻转为 %v", got, !before)
	}
}

func TestMeshToggle_ReloadFailureStillPersistsButWarns(t *testing.T) {
	s, _ := runtimeServer(t, controlBroken())
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	w := postRuntime(t, s, me, "/runtime/mesh-toggle",
		url.Values{"to": {"off"}}, s.handleRuntimeMeshToggle)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	// 管理员意图已明确,DB 不回滚。
	if meshIs(t, s) {
		t.Fatal("落库失败:mesh 仍是开启")
	}
	// 但必须把「数据面还没生效」喊出来,而不是一条绿色的「已关闭」。
	loc := w.Header().Get("Location")
	if got := flashKindOf(t, loc); got != "warn" {
		t.Fatalf("flash_kind=%q, 期望 warn —— 库改了、数据面没改,这是要人跟进的状态", got)
	}
	assertAuditAction(t, s, "mesh_toggle")
}

func TestMeshToggle_SuccessIsNotWarned(t *testing.T) {
	s, _ := runtimeServer(t, controlOK())
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	// 反过来:reload 成功时不该无脑挂 warn,否则真出问题时管理员已经对黄条免疫了。
	w := postRuntime(t, s, me, "/runtime/mesh-toggle",
		url.Values{"to": {"off"}}, s.handleRuntimeMeshToggle)
	if got := flashKindOf(t, w.Header().Get("Location")); got == "warn" {
		t.Fatalf("reload 成功却报 warn")
	}
}

func TestMeshToggle_ReturnToStaysOnSite(t *testing.T) {
	s, _ := runtimeServer(t, controlOK())
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	for _, tc := range []struct{ name, returnTo, referer string }{
		{"站内 path", "/devices", ""},
		{"协议相对", "//evil.com/x", ""},
		{"绝对 URL", "https://evil.com/x", ""},
		{"来自钓鱼站的 Referer", "", "https://evil.example.com/phish"},
	} {
		form := url.Values{"to": {"on"}}
		if tc.returnTo != "" {
			form.Set("return_to", tc.returnTo)
		}
		req := httptest.NewRequest(http.MethodPost, "/runtime/mesh-toggle",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if tc.referer != "" {
			req.Header.Set("Referer", tc.referer)
		}
		w := httptest.NewRecorder()
		s.handleRuntimeMeshToggle(w, withAdminCtx(req, me))

		loc := w.Header().Get("Location")
		if strings.Contains(loc, "evil") {
			t.Errorf("%s: Location=%q 跳出了站外", tc.name, loc)
		}
		if !strings.HasPrefix(loc, "/") {
			t.Errorf("%s: Location=%q 不是站内 path", tc.name, loc)
		}
	}
}

func TestMeshToggle_NoControlSocketPersistsAndWarns(t *testing.T) {
	s := newMeTestServer(t)
	s.control = nil
	me := createTestAdmin(t, s, "root", "pw-root-12345678")

	// 同 /runtime/reload:没配控制面时不能崩,要走「已落库但数据面未生效」那条 warn 路径。
	w := postRuntime(t, s, me, "/runtime/mesh-toggle",
		url.Values{"to": {"off"}}, s.handleRuntimeMeshToggle)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if meshIs(t, s) {
		t.Fatal("没落库")
	}
	if got := flashKindOf(t, w.Header().Get("Location")); got != "warn" {
		t.Fatalf("flash_kind=%q, 期望 warn", got)
	}
}

func TestMeshToggle_Gates(t *testing.T) {
	s, fc := runtimeServer(t, controlOK())
	createTestAdmin(t, s, "root", "pw-root-12345678")
	viewer := createTestAdmin(t, s, "peeker", "pw-peeker-12345")
	if err := s.store.SetWebAdminRoleEnsuringAdmin(t.Context(), viewer.ID, "viewer"); err != nil {
		t.Fatalf("降级: %v", err)
	}
	viewer = mustGetAdmin(t, s, viewer.ID)
	before := meshIs(t, s)

	if w := postRuntime(t, s, viewer, "/runtime/mesh-toggle", url.Values{"to": {"off"}},
		s.handleRuntimeMeshToggle); w.Code != http.StatusForbidden {
		t.Errorf("viewer code=%d, 期望 403", w.Code)
	}
	w := httptest.NewRecorder()
	s.handleRuntimeMeshToggle(w, withAdminCtx(
		httptest.NewRequest(http.MethodGet, "/runtime/mesh-toggle", nil), viewer))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET code=%d, 期望 405", w.Code)
	}
	// 组网总闸不能被只读账号或一个 GET 链接拨动。
	if meshIs(t, s) != before {
		t.Fatal("被拒的请求改变了组网状态")
	}
	if fc.sawPath("/reload") {
		t.Fatal("被拒的请求仍然通知了 server")
	}
}
