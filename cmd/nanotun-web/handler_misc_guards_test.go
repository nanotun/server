package main

// handler_misc_guards_test.go(第二十轮)—— 杂项 handler 的失败侧:
// /audit、/settings、/runtime/*、/healthz。
//
// 这几个入口的共同点是「出错时最容易被写成静默降级」,而它们恰好都在管理员
// 判断现场状态时被依赖:
//
//   - 审计读失败渲染成空表 = 告诉管理员「这段时间没人做过任何操作」;
//   - settings 读失败渲染成空表 = 「这台机器没有任何配置」;
//   - mesh toggle 读当前值失败又没带显式 to,取反就可能把隔离总闸误**打开**;
//   - /healthz 探活在库都 ping 不通时还回 ok,会让编排系统一直把流量打进来。
//
// 另外补 sanitizeReturnTo 的三条编码绕过(%zz / %2F / %0d%0a):
// handler_misc_test.go 的表钉住了字面形态,这里补 url.Parse **解码后**才现形的那些
// —— 开放重定向白名单是安全边界,少一层就是一个可用的钓鱼跳板。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// breakAppSettingsTable 把 app_settings 改名,让所有读它的 SQL 都报「no such table」。
// 用于验证「读失败」与「读到空」被区别对待。
func breakAppSettingsTable(t *testing.T, s *Server) {
	t.Helper()
	if _, err := s.store.DB().ExecContext(t.Context(),
		`ALTER TABLE app_settings RENAME TO app_settings_hidden`); err != nil {
		t.Fatalf("藏掉 app_settings: %v", err)
	}
}

// -------------------------------------------------------------------------
// /audit
// -------------------------------------------------------------------------

// 审计读不出来必须报错。渲染成空表等于宣称「这段时间没有任何管理操作」——
// 这正是事后追责时最不该出现的假象。
func TestAuditList_ReadFailureIsNotAnEmptyLog(t *testing.T) {
	s := newMeTestServer(t)
	s.audit.WriteFromRequest(adminGetReq("/x"), "probe_action", "", "")
	// 把表藏起来:查询本身就失败,与「查得到但一条都不匹配」是两件事。
	if _, err := s.store.DB().ExecContext(t.Context(),
		`ALTER TABLE audit_logs RENAME TO audit_logs_hidden`); err != nil {
		t.Fatalf("藏掉 audit_logs: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleAuditList(w, adminGetReq("/audit"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if strings.Contains(w.Body.String(), "probe_action") {
		t.Fatal("出错页里还渲染了半截日志")
	}
}

// 翻页链接:offset 比 limit 小时「上一页」要落回 0,而不是算出负数 offset
// (负 offset 会被 handler 自己夹回 0,但链接里带着负数很难看且容易被当成 bug)。
func TestAuditList_PrevLinkClampsToZero(t *testing.T) {
	s := newMeTestServer(t)
	for i := 0; i < 4; i++ {
		s.audit.WriteFromRequest(adminGetReq("/x"), "probe_action", "", "")
	}

	w := httptest.NewRecorder()
	// offset=1 < limit=2 → 上一页应是 offset=0(链接里不带 offset 参数)。
	s.handleAuditList(w, adminGetReq("/audit?limit=2&offset=1"))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	if strings.Contains(body, "offset=-") {
		t.Fatal("上一页链接里出现了负 offset")
	}
	if !strings.Contains(body, "/audit?") {
		t.Fatal("没渲染出翻页链接")
	}
}

// -------------------------------------------------------------------------
// /settings
// -------------------------------------------------------------------------

func TestSettingsList_MethodAndRoleGuards(t *testing.T) {
	s := newMeTestServer(t)

	w := httptest.NewRecorder()
	s.handleSettingsList(w, newAdminPostRequest(t, "/settings", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /settings code=%d, 期望 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "GET" {
		t.Errorf("Allow=%q, 期望 GET", allow)
	}

	// settings 页会 dump 整张 app_settings(含运维元数据),只读账号不该看到。
	w = httptest.NewRecorder()
	s.handleSettingsList(w, viewerReq(http.MethodGet, "/settings"))
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer GET /settings code=%d, 期望 403", w.Code)
	}
}

// 配置表读不出来要报错。渲染成空表等于「这台机器没有任何配置」,管理员会照着
// 这个假象重设 dial host / 限速,而实际值还在库里生效。
func TestSettingsList_ReadFailureIsNotAnEmptyTable(t *testing.T) {
	s := newMeTestServer(t)
	breakAppSettingsTable(t, s)

	w := httptest.NewRecorder()
	s.handleSettingsList(w, adminGetReq("/settings"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
}

func TestSettingsRateSet_RoleGuardAndWriteFailure(t *testing.T) {
	t.Run("viewer 改不了默认限速", func(t *testing.T) {
		s, fc := pfServer(t)
		w := httptest.NewRecorder()
		req := viewerReq(http.MethodPost, "/settings/rate")
		s.handleSettingsRateSet(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("code=%d, 期望 403", w.Code)
		}
		if controlHits(fc, "/rate/refresh") != 0 {
			t.Fatal("viewer 被拒后仍广播了限速刷新")
		}
	})

	t.Run("写不进去要报 500", func(t *testing.T) {
		s, fc := pfServer(t)
		abortSQLiteWrites(t, s, "no_settings_write", "app_settings", "INSERT", "")

		form := url.Values{
			"rate_default_upload_mibs":   {"8"},
			"rate_default_download_mibs": {"16"},
		}
		w := httptest.NewRecorder()
		s.handleSettingsRateSet(w, newAdminPostRequest(t, "/settings/rate", form))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		got, err := s.store.GetRateDefaults(t.Context())
		if err != nil {
			t.Fatalf("GetRateDefaults: %v", err)
		}
		if got.UploadBPS != 0 || got.DownloadBPS != 0 {
			t.Fatalf("写失败却落了库: %+v", got)
		}
		if controlHits(fc, "/rate/refresh") != 0 {
			t.Fatal("没写成却广播了限速刷新")
		}
	})
}

// -------------------------------------------------------------------------
// /runtime/mesh-toggle
// -------------------------------------------------------------------------

// 没带显式 to 时,「当前值」读失败绝不能猜:GetMeshEnabled 出错时返回的是 true,
// 取反得 false 看着还算保守,但反过来(库里本是 false)就会把隔离总闸误打开。
// 这条路径必须直接报错让管理员重试。
func TestMeshToggle_ReadCurrentFailureRefusesToGuess(t *testing.T) {
	s, fc := pfServer(t)
	breakAppSettingsTable(t, s)

	w := httptest.NewRecorder()
	s.handleRuntimeMeshToggle(w, newAdminPostRequest(t, "/runtime/mesh-toggle", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if controlHits(fc, "/reload") != 0 {
		t.Fatal("读失败却已经通知数据面重载")
	}
}

// 落库失败要报 500 并留下 mesh_toggle_fail 审计;不能只报个 flash 就跳走,
// 那样侧栏按钮(读库)会显示旧状态,而管理员以为已经改了。
func TestMeshToggle_WriteFailureIsReportedAndAudited(t *testing.T) {
	s, fc := pfServer(t)
	// 先写一次让键存在,这样后面拦 UPDATE 才拦得到(SettingsSet 走 upsert)。
	if err := s.store.SetMeshEnabled(t.Context(), true); err != nil {
		t.Fatalf("前置写入: %v", err)
	}
	abortSQLiteWrites(t, s, "no_mesh_write", "app_settings", "UPDATE OF value", "")

	form := url.Values{"to": {"off"}}
	w := httptest.NewRecorder()
	s.handleRuntimeMeshToggle(w, newAdminPostRequest(t, "/runtime/mesh-toggle", form))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	on, err := s.store.GetMeshEnabled(t.Context())
	if err != nil {
		t.Fatalf("GetMeshEnabled: %v", err)
	}
	if !on {
		t.Fatal("写失败却真的关掉了组网")
	}
	assertAuditAction(t, s, "mesh_toggle_fail")
	if controlHits(fc, "/reload") != 0 {
		t.Fatal("没写成却通知了数据面重载")
	}
}

// -------------------------------------------------------------------------
// /runtime/kick
// -------------------------------------------------------------------------

func TestRuntimeKick_MethodAndRoleGuards(t *testing.T) {
	s, fc := pfServer(t)

	w := httptest.NewRecorder()
	s.handleRuntimeKick(w, adminGetReq("/runtime/kick"))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET code=%d, 期望 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "POST" {
		t.Errorf("Allow=%q, 期望 POST", allow)
	}

	w = httptest.NewRecorder()
	s.handleRuntimeKick(w, viewerReq(http.MethodPost, "/runtime/kick"))
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer code=%d, 期望 403", w.Code)
	}
	if controlHits(fc, "/kick") != 0 {
		t.Fatal("被守卫拦下后仍向数据面发了踢线")
	}
}

func TestRuntimeReload_RoleGuard(t *testing.T) {
	s, fc := pfServer(t)
	w := httptest.NewRecorder()
	s.handleRuntimeReload(w, viewerReq(http.MethodPost, "/runtime/reload"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d, 期望 403", w.Code)
	}
	if controlHits(fc, "/reload") != 0 {
		t.Fatal("viewer 被拒后仍触发了重载")
	}
}

// -------------------------------------------------------------------------
// /healthz
// -------------------------------------------------------------------------

// 库 ping 不通时必须 503,且不能把 SQLite 的错误原文(含库文件路径)吐给匿名访客
// —— /healthz 是公开路由。回 ok 更糟:编排系统会一直把流量打进这台机器。
func TestHealthz_DBDownIs503AndLeaksNothing(t *testing.T) {
	s := newMeTestServer(t)
	if err := s.store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleHealthz(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d body=%q, 期望 503", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	if strings.Contains(body, "ok") {
		t.Fatalf("库已经不通了还回 ok: %q", body)
	}
	for _, leak := range []string{".db", "sql:", "sqlite"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Fatalf("公开探活响应里泄露了内部细节(%q): %q", leak, body)
		}
	}
}

// -------------------------------------------------------------------------
// 回跳白名单:url.Parse 解码后才现形的绕过
// -------------------------------------------------------------------------

// handler_misc_test.go 的表覆盖了字面形态。这里补三类**编码后**的载荷:
// 它们在字符串层面都长得像正常站内 path,只有 Parse 解码后才露出真面目。
func TestSanitizeReturnTo_EncodedBypassesAreRejected(t *testing.T) {
	cases := []struct{ name, returnTo, referer, want string }{
		// 坏转义:url.Parse 直接报错。报错时若"当作合法"往下走,后面的 Path
		// 检查全是空值,等于整条白名单失效。
		{"return_to 坏转义", "/%zz", "", "/"},
		// %2F 解码成 `/`:字符串层看到的是 "/%2Fevil.com",只有一个前导斜杠;
		// 解码后 Path = "//evil.com",浏览器会当成 https://evil.com。
		{"return_to %2F 变协议无关", "/%2Fevil.com", "", "/"},
		{"referer %2F 变协议无关", "", "https://vpn.example.com/%2Fevil.com", "/"},
		// 双重编码 CRLF:解码后 Path 里带真实 CR/LF。白名单不该放行控制字符。
		{"return_to 编码 CRLF", "/users%0d%0aSet-Cookie:%20x=1", "", "/"},
		{"referer 编码 CRLF", "", "https://vpn.example.com/x%0d%0ay", "/"},
		// Referer 是相对路径(不以 / 开头)时不能拿来回跳:拼出来的目标不确定。
		{"referer 相对路径", "", "users/1", "/"},
	}
	for _, tc := range cases {
		if got := sanitizeReturnTo(tc.returnTo, tc.referer); got != tc.want {
			t.Errorf("%s: sanitizeReturnTo(%q, %q) = %q, 期望 %q",
				tc.name, tc.returnTo, tc.referer, got, tc.want)
		}
	}
}

// safeReturnToOrFallback 的 fallback 是调用方写死的字面量,所以信任它 ——
// 但仍要兜住「调用方漏传 / 传错」的情况,不能把 "" 或 "//evil.com" 直接
// 当成 Location 发出去。
func TestSafeReturnToOrFallback_BadFallbackDegradesToRoot(t *testing.T) {
	cases := []struct{ name, returnTo, referer, fallback, want string }{
		{"正常 fallback", "", "", "/devices/7", "/devices/7"},
		{"漏传 fallback", "", "", "", "/"},
		{"fallback 不是站内 path", "", "", "https://evil.com/x", "/"},
		{"fallback 协议无关", "", "", "//evil.com/x", "/"},
		{"return_to 优先于 fallback", "/users", "", "/devices/7", "/users"},
		{"referer 优先于 fallback", "", "https://vpn.example.com/acl", "/devices/7", "/acl"},
	}
	for _, tc := range cases {
		got := safeReturnToOrFallback(tc.returnTo, tc.referer, tc.fallback)
		if got != tc.want {
			t.Errorf("%s: = %q, 期望 %q", tc.name, got, tc.want)
		}
	}
}
