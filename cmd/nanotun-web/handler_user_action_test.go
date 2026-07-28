package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// /users/{id}/{verb} 是 Web 侧改用户状态的总入口:停用、启用、删除、重置 PSK、
// 并发上限。这些操作 CLI 侧都有测试,Web 侧此前只覆盖了 set-platforms 一支。
//
// 测法沿用同目录的成例:绕过 session/CSRF 中间件直接调 handler(那两层由
// middleware_test.go + routes_test.go 负责),这里只钉「路径怎么解析、库里变成
// 什么样、审计写了什么」。

func userActionReq(t *testing.T, id int64, verb string, form url.Values) *http.Request {
	t.Helper()
	target := "/users/" + strconv.FormatInt(id, 10)
	if verb != "" {
		target += "/" + verb
	}
	return newAdminPostRequest(t, target, form)
}

func mustGetUser(t *testing.T, s *Server, id int64) *store.User {
	t.Helper()
	u, err := s.store.GetUser(t.Context(), id)
	if err != nil {
		t.Fatalf("GetUser(%d): %v", id, err)
	}
	return u
}

// 审计里没有这条记录,事后就查不出是谁把账号停掉的。
func assertAudited(t *testing.T, s *Server, action string) {
	t.Helper()
	rows, err := s.store.QueryAuditByAction(t.Context(), 0, 1<<62, action, 10)
	if err != nil {
		t.Fatalf("QueryAuditByAction(%q): %v", action, err)
	}
	if len(rows) == 0 {
		t.Fatalf("没有写下 %q 审计 —— 事后查不出是谁做的这次改动", action)
	}
}

func TestHandleUserAction_DisableAndEnableAreReversibleAndAudited(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "alice")

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "disable", nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("disable code=%d body=%q", w.Code, w.Body.String())
	}
	if mustGetUser(t, s, u.ID).DisabledAt == 0 {
		t.Fatal("库里没被停用 —— 页面显示成功但账号照样能登录,是最糟的那种偏差")
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/users/"+strconv.FormatInt(u.ID, 10)) {
		t.Fatalf("应重定向回详情页,got %q", loc)
	}
	if flashTextOf(t, loc) == "" {
		t.Fatal("重定向要带上 flash,否则详情页上什么反馈都没有,管理员不知道点没点成")
	}
	assertAudited(t, s, "user_disable")

	w = httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "enable", nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("enable code=%d body=%q", w.Code, w.Body.String())
	}
	if mustGetUser(t, s, u.ID).DisabledAt != 0 {
		t.Fatal("重新启用没生效")
	}
	assertAudited(t, s, "user_enable")
}

func TestHandleUserAction_DeleteRemovesTheRow(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "bob")

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "delete", nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
	}
	if _, err := s.store.GetUser(t.Context(), u.ID); err == nil {
		t.Fatal("用户还在库里")
	}
	// 删完回列表页,不是回一个已经不存在的详情页。
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/users?") && loc != "/users" {
		t.Fatalf("应重定向回列表页,got %q", loc)
	}
	assertAudited(t, s, "user_delete")
}

// 停用的账号不允许重置 PSK:rotate 之后周期扫描照样会把它踢下线,等于发了张废卡,
// 还会在库里留下一个「已禁用但带着新凭证」的账号。
func TestHandleUserAction_ResetPSKRefusesDisabledAccounts(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "carol")
	if err := s.store.DisableUser(t.Context(), u.ID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	before := mustGetUser(t, s, u.ID)

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "reset-psk", nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("code=%d,期望 409 —— 给禁用账号发新凭证是自相矛盾的操作", w.Code)
	}
	if mustGetUser(t, s, u.ID).PSKHash != before.PSKHash {
		t.Fatal("被拒绝了,PSK 却已经被改掉 —— 用户手里那张卡白白作废了")
	}
}

func TestHandleUserAction_ResetPSKRotatesAndHandsOffViaOneTimeToken(t *testing.T) {
	// 这条要真渲染一次性展示页,所以用带模板的 server。
	s := newMeTestServer(t)
	u := newPRGTestUser(t, s, "dave")
	before := mustGetUser(t, s, u.ID)

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "reset-psk", nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
	}

	after := mustGetUser(t, s, u.ID)
	if after.PSKHash == before.PSKHash {
		t.Fatal("PSK 没换 —— 「重置」点了个寂寞")
	}
	if after.CredentialID == "" {
		t.Fatal("老账号首次 rotate 应顺手补上 credential_id,否则客户端扫码绑不上")
	}

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/reset-psk-result?token=") {
		t.Fatalf("应重定向到一次性展示页,got %q", loc)
	}
	// 明文 PSK 绝不能出现在重定向 URL 里 —— 那会进浏览器历史、进反向代理日志。
	if strings.Contains(loc, after.PSKHash) {
		t.Fatalf("重定向 URL 里带上了凭证材料: %q", loc)
	}
	assertAudited(t, s, "user_reset_psk")

	// token 是一次性的:第二次访问必须 410。
	tokenQ := loc[strings.Index(loc, "token=")+len("token="):]
	getReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet,
			"/users/"+strconv.FormatInt(u.ID, 10)+"/reset-psk-result?token="+tokenQ, nil)
		admin := &store.WebAdmin{ID: 1, Username: "tester", Role: "admin"}
		return req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, admin))
	}
	w1 := httptest.NewRecorder()
	s.handleUserAction(w1, getReq())
	if w1.Code != http.StatusOK {
		t.Fatalf("第一次取用应成功,code=%d body=%q", w1.Code, w1.Body.String())
	}
	w2 := httptest.NewRecorder()
	s.handleUserAction(w2, getReq())
	if w2.Code != http.StatusGone {
		t.Fatalf("同一个 token 第二次应 410,got %d —— 一次性契约破了,凭证能被反复读出来", w2.Code)
	}
}

func TestHandleUserAction_SetMaxSessionsValidatesTheRange(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "erin")

	cases := []struct {
		name string
		raw  string
		want int
		why  string
	}{
		{"跟随全局", "0", http.StatusSeeOther, ""},
		{"具体上限", "3", http.StatusSeeOther, ""},
		{"该账号不限", "-1", http.StatusSeeOther, ""},
		{"带空白也接受", "  5  ", http.StatusSeeOther, ""},
		{"小于 -1", "-2", http.StatusBadRequest, "只有 -1 有「不限」的含义,-2 是手滑"},
		{"超过上限", strconv.Itoa(store.MaxSessionsCap + 1), http.StatusBadRequest, ""},
		{"不是数字", "很多", http.StatusBadRequest, ""},
		{"空", "", http.StatusBadRequest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleUserAction(w, userActionReq(t, u.ID, "set-max-sessions",
				url.Values{"max_sessions": {tc.raw}}))
			if w.Code != tc.want {
				t.Fatalf("code=%d want %d(%s) body=%q", w.Code, tc.want, tc.why, w.Body.String())
			}
		})
	}

	// 最后一次成功的值要真的落库。
	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "set-max-sessions", url.Values{"max_sessions": {"4"}}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d", w.Code)
	}
	if got := mustGetUser(t, s, u.ID).MaxSessions; got != 4 {
		t.Fatalf("库里是 %d,期望 4", got)
	}
	assertAudited(t, s, "user_max_sessions_set")
}

// 老前端还可能 POST 过来的、已经搬到设备维度的动作,要给一个明确的「没了」,
// 而不是静默 404 或者假装成功。
func TestHandleUserAction_RetiredVerbSaysSoExplicitly(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "frank")

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "set-fixed-vip", url.Values{"vip": {"10.0.0.9"}}))
	if w.Code != http.StatusGone {
		t.Fatalf("code=%d,期望 410 —— 静默成功会让管理员以为固定 IP 设上了", w.Code)
	}
}

func TestHandleUserAction_RejectsMalformedPathsAndMethods(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "grace")
	idStr := strconv.FormatInt(u.ID, 10)

	t.Run("id 不是数字", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleUserAction(w, newAdminPostRequest(t, "/users/abc/disable", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400", w.Code)
		}
	})

	t.Run("id 为 0", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleUserAction(w, newAdminPostRequest(t, "/users/0/disable", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400", w.Code)
		}
	})

	t.Run("缺 id", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleUserAction(w, newAdminPostRequest(t, "/users", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400", w.Code)
		}
	})

	t.Run("用户不存在", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleUserAction(w, newAdminPostRequest(t, "/users/999999/disable", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("code=%d want 404", w.Code)
		}
	})

	t.Run("不认识的动作", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleUserAction(w, userActionReq(t, u.ID, "自爆", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400 —— 未知动作静默成功比报错危险得多", w.Code)
		}
	})

	t.Run("详情页只收 GET", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleUserAction(w, newAdminPostRequest(t, "/users/"+idStr, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code=%d want 405", w.Code)
		}
		if a := w.Header().Get("Allow"); a != "GET" {
			t.Fatalf("Allow=%q,应告诉调用方该用什么方法", a)
		}
	})

	t.Run("写动作不收 GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users/"+idStr+"/disable", nil)
		admin := &store.WebAdmin{ID: 1, Username: "tester", Role: "admin"}
		w := httptest.NewRecorder()
		s.handleUserAction(w, req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, admin)))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code=%d want 405 —— 停用账号能被一个 <img src> 触发就太糟了", w.Code)
		}
		if a := w.Header().Get("Allow"); a != "POST" {
			t.Fatalf("Allow=%q", a)
		}
	})

	t.Run("写动作不收 PUT", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/users/"+idStr+"/disable", nil)
		admin := &store.WebAdmin{ID: 1, Username: "tester", Role: "admin"}
		w := httptest.NewRecorder()
		s.handleUserAction(w, req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, admin)))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code=%d want 405", w.Code)
		}
	})
}

// viewer 只能看不能改。这一层如果漏了,一个只读账号就能停用别人的账号。
func TestHandleUserAction_ViewerCannotWrite(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "heidi")

	req := userActionReq(t, u.ID, "disable", nil)
	viewer := &store.WebAdmin{ID: 2, Username: "readonly", Role: "viewer"}
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, viewer))

	w := httptest.NewRecorder()
	s.handleUserAction(w, req)
	if w.Code == http.StatusSeeOther {
		t.Fatal("只读账号把用户停用了")
	}
	if mustGetUser(t, s, u.ID).DisabledAt != 0 {
		t.Fatal("只读账号的操作居然落库了")
	}
}
