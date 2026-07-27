package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 本文件覆盖 Web 侧其余「改状态」的 handler:限速默认值、踢线、建用户、平台白名单。
// 这些操作 CLI 侧都有测试,Web 侧此前一条没有 —— 而两条路各写各的表单解析。

// waitForControlPath 等后台 goroutine 把请求发到控制面(rate refresh 是异步的)。
func waitForControlPath(t *testing.T, fc *fakeControl, path string) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fc.sawPath(path) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// =========================================================================
// POST /settings/rate
// =========================================================================

// TestHandleSettingsRateSet_PersistsAndNotifies 正向:落库 + 通知数据面热更。
//
// 只落库不通知的话,页面显示新限速、在线连接却还按旧速率跑到重连为止 ——
// 与 ACL「建了没生效」同一类静默劈叉。
func TestHandleSettingsRateSet_PersistsAndNotifies(t *testing.T) {
	s := newTestServerMinimal(t)
	fc := newFakeControl(t, controlOK())
	s.control = fc.client

	form := url.Values{
		"rate_default_upload_mibs":   {"10"},
		"rate_default_download_mibs": {"20"},
		"rate_burst_kib":             {"256"},
	}
	w := httptest.NewRecorder()
	s.handleSettingsRateSet(w, newAdminPostRequest(t, "/settings/rate", form))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	got, err := s.store.GetRateDefaults(t.Context())
	if err != nil {
		t.Fatalf("GetRateDefaults: %v", err)
	}
	// 单位换算按 parseRateMiBs / parseBurstKiB:MiB/s → B/s,KiB → B。
	// 精确钉死而不是只查非零 —— 上下行写反、或换算掉了个 8 倍(bit/byte),
	// 都是「限速看着生效了、实际差一个量级」的静默偏差。
	if want := int64(10 * 1024 * 1024); got.UploadBPS != want {
		t.Errorf("上行 = %d, 期望 %d", got.UploadBPS, want)
	}
	if want := int64(20 * 1024 * 1024); got.DownloadBPS != want {
		t.Errorf("下行 = %d, 期望 %d", got.DownloadBPS, want)
	}
	if want := int64(256 * 1024); got.BurstBytes != want {
		t.Errorf("burst = %d, 期望 %d", got.BurstBytes, want)
	}
	if !waitForControlPath(t, fc, "/rate/refresh") {
		t.Fatalf("改完限速没通知数据面热更, 控制面收到: %v", fc.requests())
	}
}

// TestHandleSettingsRateSet_BadInputDoesNotPersist 非法输入必须整条打回。
// 静默落 0 在限速语义里通常等于「不限速」—— 一次手滑就把限速取消了。
//
// 注意这里**不**把科学计数法当非法:限速字段有意用 ParseFloat(要支持 "1.5" MiB/s),
// "1e3" 就是 1000,没有语义翻转。这与 ACL 的用户 ID / 端口字段相反 —— 那边 "1e3"
// 会静默变 0,而 0 在 ACL 里是「任意」,所以那边必须严格拒绝(见 parseFormInt64Strict)。
// 两处口径不同是有理由的,别顺手「统一」掉。
func TestHandleSettingsRateSet_BadInputDoesNotPersist(t *testing.T) {
	base := url.Values{
		"rate_default_upload_mibs":   {"10"},
		"rate_default_download_mibs": {"20"},
		"rate_burst_kib":             {"256"},
	}
	for _, c := range []struct{ field, value string }{
		{"rate_default_upload_mibs", "abc"},
		{"rate_default_download_mibs", "-5"},
		{"rate_burst_kib", "-1"},
		{"rate_default_upload_mibs", "10x"},
		{"rate_default_upload_mibs", "99999999999"}, // 超上限
		{"rate_burst_kib", "99999999999"},           // 超上限
	} {
		t.Run(c.field+"="+c.value, func(t *testing.T) {
			s := newTestServerMinimal(t)
			s.control = newFakeControl(t, controlOK()).client
			before, _ := s.store.GetRateDefaults(t.Context())

			form := url.Values{}
			for k, v := range base {
				form[k] = append([]string(nil), v...)
			}
			form.Set(c.field, c.value)
			w := httptest.NewRecorder()
			s.handleSettingsRateSet(w, newAdminPostRequest(t, "/settings/rate", form))

			if w.Code == http.StatusSeeOther {
				t.Errorf("%s=%q 被接受了(303)", c.field, c.value)
			}
			if w.Code >= 500 {
				t.Errorf("%s=%q → %d, 用户输入错误应是 4xx", c.field, c.value, w.Code)
			}
			after, _ := s.store.GetRateDefaults(t.Context())
			if after != before {
				t.Fatalf("%s=%q 被拒后限速仍被改动: %+v → %+v", c.field, c.value, before, after)
			}
		})
	}
}

// TestHandleSettingsRateSet_RejectsNonPOST 写操作不接受 GET。
func TestHandleSettingsRateSet_RejectsNonPOST(t *testing.T) {
	s := newTestServerMinimal(t)
	req := newAdminPostRequest(t, "/settings/rate", nil)
	req.Method = http.MethodGet
	w := httptest.NewRecorder()
	s.handleSettingsRateSet(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d, 期望 405", w.Code)
	}
}

// =========================================================================
// POST /runtime/kick
// =========================================================================

// TestHandleRuntimeKick_CallsControlAndAudits 正向:调控制面 + 审计留痕 + 303。
func TestHandleRuntimeKick_CallsControlAndAudits(t *testing.T) {
	s := newTestServerMinimal(t)
	fc := newFakeControl(t, controlOK())
	s.control = fc.client

	form := url.Values{"kind": {"user"}, "id": {"7"}, "reason": {"手工封禁"}}
	w := httptest.NewRecorder()
	s.handleRuntimeKick(w, newAdminPostRequest(t, "/runtime/kick", form))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	if !fc.sawPath("/kick") {
		t.Fatalf("没有真的调控制面 kick: %v", fc.requests())
	}
	assertAuditAction(t, s, "runtime_kick_ok")
}

// TestHandleRuntimeKick_ControlFailureIsSurfaced 控制面失败必须如实报错。
//
// 若把失败也当成功回 303,管理员会以为已经把人踢下线了 —— 封禁场景下这是
// 「以为断了其实还在跑」,比报错严重得多。
func TestHandleRuntimeKick_ControlFailureIsSurfaced(t *testing.T) {
	s := newTestServerMinimal(t)
	fc := newFakeControl(t, controlBroken())
	s.control = fc.client

	form := url.Values{"kind": {"session"}, "id": {"abc123"}}
	w := httptest.NewRecorder()
	s.handleRuntimeKick(w, newAdminPostRequest(t, "/runtime/kick", form))
	if w.Code == http.StatusSeeOther {
		t.Fatal("控制面失败却回了 303 —— 管理员会以为已经踢下线")
	}
	if w.Code < 400 {
		t.Fatalf("控制面失败应回 4xx/5xx, 实际 %d", w.Code)
	}
	assertAuditAction(t, s, "runtime_kick_fail")
}

// TestHandleRuntimeKick_RequiresKindAndID 缺字段时不能去骚扰控制面。
func TestHandleRuntimeKick_RequiresKindAndID(t *testing.T) {
	for _, form := range []url.Values{
		{},
		{"kind": {"user"}},
		{"id": {"7"}},
		{"kind": {"  "}, "id": {"7"}},
	} {
		s := newTestServerMinimal(t)
		fc := newFakeControl(t, controlOK())
		s.control = fc.client
		w := httptest.NewRecorder()
		s.handleRuntimeKick(w, newAdminPostRequest(t, "/runtime/kick", form))
		if w.Code != http.StatusBadRequest {
			t.Errorf("表单 %v: code=%d, 期望 400", form, w.Code)
		}
		if fc.sawPath("/kick") {
			t.Errorf("表单 %v 不完整却已经发起了 kick", form)
		}
	}
}

// =========================================================================
// POST /users/{id}/set-platforms —— 与 CLI set-platforms 对等的 Web 入口
// =========================================================================

// TestHandleUserAction_SetPlatforms 落库 + 审计 + 303。
func TestHandleUserAction_SetPlatforms(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "plat-web")
	id := strconv.FormatInt(u.ID, 10)

	form := url.Values{"platforms": {"macos", "ios"}}
	w := httptest.NewRecorder()
	s.handleUserAction(w, newAdminPostRequest(t, "/users/"+id+"/set-platforms", form))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	got, err := s.store.GetUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.AllowedPlatforms != "macos,ios" {
		t.Fatalf("白名单 = %q, 期望 macos,ios", got.AllowedPlatforms)
	}
	assertAuditAction(t, s, "user_platforms_set")
}

// TestHandleUserAction_SetPlatformsRejectsUnknown 伪造平台名整条拒绝,且原白名单不动。
// 这是 curl 直发能碰到的路径 —— 复选框 UI 挡不住手拼请求。
func TestHandleUserAction_SetPlatformsRejectsUnknown(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "plat-bad")
	id := strconv.FormatInt(u.ID, 10)
	if err := s.store.SetUserAllowedPlatforms(t.Context(), u.ID, "macos"); err != nil {
		t.Fatalf("预置白名单: %v", err)
	}

	form := url.Values{"platforms": {"macos", "plan9"}}
	w := httptest.NewRecorder()
	s.handleUserAction(w, newAdminPostRequest(t, "/users/"+id+"/set-platforms", form))
	if w.Code == http.StatusSeeOther {
		t.Fatal("含伪造平台名的提交被接受了")
	}
	got, err := s.store.GetUser(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.AllowedPlatforms != "macos" {
		t.Fatalf("被拒后白名单被改成了 %q, 应保持 macos", got.AllowedPlatforms)
	}
}

// =========================================================================
// POST /users/new
// =========================================================================

// TestHandleUserNew_CreatesUser 正向建号:落库 + PRG(303)。
func TestHandleUserNew_CreatesUser(t *testing.T) {
	s := newTestServerMinimal(t)
	form := url.Values{
		"username":  {"newbie"},
		"platforms": append([]string(nil), canonicalPlatformsForForm()...),
	}
	w := httptest.NewRecorder()
	s.handleUserNew(w, newAdminPostRequest(t, "/users/new", form))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	u, err := s.store.GetUserByUsername(t.Context(), "newbie")
	if err != nil {
		t.Fatalf("建号后查不到该用户: %v", err)
	}
	// 全勾 = 不限,不应写成六平台白名单(与 platformsFromForm 的塌缩规则一致)。
	if u.AllowedPlatforms != "" {
		t.Fatalf("全勾平台应存为不限(空串), 实际 %q", u.AllowedPlatforms)
	}
	if u.PSKHash == "" {
		t.Fatal("新用户没有 PSK 哈希")
	}
}

// TestHandleUserNew_DuplicateUsernameDoesNotCreateSecond 重名不能建出第二个号。
func TestHandleUserNew_DuplicateUsernameDoesNotCreateSecond(t *testing.T) {
	s := newTestServerMinimal(t)
	newPRGTestUser(t, s, "taken")

	form := url.Values{"username": {"taken"}}
	w := httptest.NewRecorder()
	s.handleUserNew(w, newAdminPostRequest(t, "/users/new", form))
	if w.Code == http.StatusSeeOther {
		t.Fatal("重名建号被接受了")
	}
	users, err := s.store.ListUsers(t.Context())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	n := 0
	for _, u := range users {
		if u.Username == "taken" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("用户名 taken 有 %d 个, 应只有 1 个", n)
	}
}

// TestHandleUserNew_RejectsEmptyUsername 空用户名不能建号。
func TestHandleUserNew_RejectsEmptyUsername(t *testing.T) {
	for _, name := range []string{"", "   "} {
		s := newTestServerMinimal(t)
		w := httptest.NewRecorder()
		s.handleUserNew(w, newAdminPostRequest(t, "/users/new", url.Values{"username": {name}}))
		if w.Code == http.StatusSeeOther {
			t.Errorf("用户名 %q 被接受了", name)
		}
		users, _ := s.store.ListUsers(t.Context())
		if len(users) != 0 {
			t.Errorf("用户名 %q 被拒后仍建出了 %d 个用户", name, len(users))
		}
	}
}

// canonicalPlatformsForForm 复制一份 canonical 平台名,供表单「全勾」使用。
func canonicalPlatformsForForm() []string {
	out := make([]string, 0, 8)
	for _, c := range platformChecksFor(nil) {
		out = append(out, c.Name)
	}
	return out
}

// assertAuditAction 断言审计表里出现过某个 action。
func assertAuditAction(t *testing.T, s *Server, action string) {
	t.Helper()
	now := time.Now().Unix()
	logs, err := s.store.QueryAudit(t.Context(), 0, now+1, 200)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	var seen []string
	for _, l := range logs {
		if l.Action == action {
			return
		}
		seen = append(seen, l.Action)
	}
	t.Fatalf("审计里没有 %q, 实际有: %s", action, strings.Join(seen, ", "))
}
