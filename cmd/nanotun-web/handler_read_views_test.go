package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 只读页面的过滤 / 权限 / 分发逻辑。这些地方出错不会报错,只会"少显示了点东西"
// 或者"多显示了点东西",而后者在遥测和禁用账号这两处是有安全含义的。

// 默认只列启用中的账号:禁用账号是「已处置」的,混在列表里会被误当成还在服务。
// 想看必须显式要求。
func TestHandleUserList_HidesDisabledUnlessAsked(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "listadmin", "pw-listadmin-12345")

	active := newPRGTestUser(t, s, "still-active")
	gone := newPRGTestUser(t, s, "已停用的账号")
	if err := s.store.DisableUser(t.Context(), gone.ID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	_ = active

	render := func(target string) string {
		req := withAdminCtx(httptest.NewRequest(http.MethodGet, target, nil), admin)
		w := httptest.NewRecorder()
		s.handleUserList(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s code=%d body=%q", target, w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	body := render("/users")
	if !strings.Contains(body, "still-active") {
		t.Fatal("启用中的账号没列出来")
	}
	if strings.Contains(body, "已停用的账号") {
		t.Fatal("默认列表里出现了已停用账号 —— 会被误当成还在服务中")
	}

	// 几种写法都要认,运维的书签和前端控件不一定用同一种。
	for _, q := range []string{"?show_disabled=1", "?all=1", "?show_disabled=true",
		"?show_disabled=yes", "?show_disabled=on", "?all=ON", "?show_disabled=%201%20"} {
		if !strings.Contains(render("/users"+q), "已停用的账号") {
			t.Errorf("%s 应展开已停用账号", q)
		}
	}
	// 明确不是 truthy 的一律按关闭处理。参数名本身大小写敏感(?ALL=1 不算),
	// 只有取值不区分大小写 —— 记在这里免得下次有人以为是 bug。
	for _, q := range []string{"?show_disabled=0", "?show_disabled=", "?show_disabled=maybe",
		"?all=no", "?ALL=1"} {
		if strings.Contains(render("/users"+q), "已停用的账号") {
			t.Errorf("%s 不该展开已停用账号 —— 只有明确要求才暴露", q)
		}
	}
}

func TestHandleUserList_FiltersByNameCaseInsensitively(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "filteradmin", "pw-filteradmin-1234")
	newPRGTestUser(t, s, "Alice")
	newPRGTestUser(t, s, "bob")

	render := func(target string) string {
		req := withAdminCtx(httptest.NewRequest(http.MethodGet, target, nil), admin)
		w := httptest.NewRecorder()
		s.handleUserList(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s code=%d", target, w.Code)
		}
		return w.Body.String()
	}

	body := render("/users?q=ali")
	if !strings.Contains(body, "Alice") {
		t.Fatal("大小写不敏感的子串匹配没生效")
	}
	if strings.Contains(body, ">bob<") {
		t.Fatal("过滤条件没起作用,不相关的账号也列出来了")
	}

	// 空白 query 等于不过滤 —— 不能把整个列表清空。
	all := render("/users?q=%20%20")
	if !strings.Contains(all, "Alice") || !strings.Contains(all, "bob") {
		t.Fatal("只有空白的过滤条件应视作不过滤")
	}

	if body := render("/users?q=谁也不叫这个名字"); strings.Contains(body, "Alice") {
		t.Fatal("匹配不上还列出来了")
	}
}

func TestHandleUserList_RejectsNonGET(t *testing.T) {
	s := newTestServerMinimal(t)
	w := httptest.NewRecorder()
	s.handleUserList(w, newAdminPostRequest(t, "/users", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d want 405", w.Code)
	}
	if a := w.Header().Get("Allow"); a != "GET" {
		t.Fatalf("Allow=%q", a)
	}
}

// 宿主机 CPU / 内存 / 网卡属于基础设施遥测,只读账号不该看到。
func TestHandleSysmon_IsAdminOnly(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "sysadmin", "pw-sysadmin-12345")
	viewer := &store.WebAdmin{ID: 999, Username: "readonly", Role: "viewer"}

	for _, tc := range []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"页面", "/sysmon", s.handleSysmon},
		{"数据端点", "/sysmon/data", s.handleSysmonData},
	} {
		t.Run(tc.name+"/admin 能看", func(t *testing.T) {
			req := withAdminCtx(httptest.NewRequest(http.MethodGet, tc.path, nil), admin)
			w := httptest.NewRecorder()
			tc.handler(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
			}
		})
		t.Run(tc.name+"/viewer 看不到", func(t *testing.T) {
			req := withAdminCtx(httptest.NewRequest(http.MethodGet, tc.path, nil), viewer)
			w := httptest.NewRecorder()
			tc.handler(w, req)
			if w.Code == http.StatusOK {
				t.Fatal("只读账号拿到了宿主机遥测")
			}
		})
		t.Run(tc.name+"/只收 GET", func(t *testing.T) {
			req := withAdminCtx(httptest.NewRequest(http.MethodPost, tc.path, nil), admin)
			w := httptest.NewRecorder()
			tc.handler(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("code=%d want 405", w.Code)
			}
		})
	}
}

// 控制面连不上时,数据端点仍要回 200 并把问题写进 JSON —— 前端靠这个显示横幅;
// 回 5xx 会让 fetch 走 catch 分支,页面变成一片空白。
func TestHandleSysmonData_ReportsControlPlaneFailureInsideTheJSON(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "sysdata", "pw-sysdata-123456")
	s.control = newControlClient("/tmp/绝对不存在的.sock")

	req := withAdminCtx(httptest.NewRequest(http.MethodGet, "/sysmon/data", nil), admin)
	w := httptest.NewRecorder()
	s.handleSysmonData(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code=%d,控制面不可用也该回 200 把错误编在 JSON 里", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type=%q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control=%q,遥测不能被缓存,否则页面一直显示旧数字", cc)
	}
	var resp sysmonDataResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v(body=%s)", err, w.Body.String())
	}
	if resp.VPNAvailable {
		t.Fatal("控制面根本连不上,不该报告 VPN 可用")
	}
	if resp.VPNError == "" {
		t.Fatal("要把失败原因写进 vpn_error,否则页面上只是数字不动,没人知道为什么")
	}
	if resp.ServerUptimeSeconds != -1 {
		t.Fatalf("uptime=%d,不可用时应为 -1(前端据此显 \"—\" 而不是 \"0s\")", resp.ServerUptimeSeconds)
	}
	if resp.TimestampMS <= 0 {
		t.Fatal("ts_ms 缺失,前端算不了差分速率")
	}
}

// /me/totp/* 的分发:认得的动作转给对应 handler,认不得的给 404 而不是静默成功。
func TestHandleMeAction_DispatchesOnlyKnownTOTPVerbs(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "meaction", "pw-meaction-12345")

	for _, path := range []string{"/me", "/me/totp", "/me/别的东西/setup", "/me/totp/自爆"} {
		t.Run(path, func(t *testing.T) {
			req := withAdminCtx(httptest.NewRequest(http.MethodGet, path, nil), admin)
			w := httptest.NewRecorder()
			s.handleMeAction(w, req)
			if w.Code != http.StatusNotFound {
				t.Fatalf("code=%d want 404 —— 认不得的动作静默成功比报错危险", w.Code)
			}
		})
	}

	// 认得的动作要真的被分发出去(具体行为由各自的用例覆盖,这里只看没落到 404)。
	for _, verb := range []string{"setup", "enable", "disable", "regen-codes", "codes"} {
		t.Run("verb="+verb, func(t *testing.T) {
			req := withAdminCtx(httptest.NewRequest(http.MethodGet, "/me/totp/"+verb, nil), admin)
			w := httptest.NewRecorder()
			s.handleMeAction(w, req)
			if w.Code == http.StatusNotFound {
				t.Fatalf("%q 是已知动作,却落到了 404", verb)
			}
		})
	}
}

func TestChoose_PicksByCondition(t *testing.T) {
	if got := choose(true, "是", "否"); got != "是" {
		t.Fatalf("got %q", got)
	}
	if got := choose(false, "是", "否"); got != "否" {
		t.Fatalf("got %q", got)
	}
}
