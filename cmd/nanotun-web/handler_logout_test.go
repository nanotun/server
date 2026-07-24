package main

// handler_logout_test.go - /logout 的会话绑定 CSRF 回归(第五轮深扫 HIGH)。
//
// 背景:/logout 是公开路由(不过 requireCSRFAndAuth),不会注入 ctxKeySessionID;而退出按钮的
// csrf_token 是在已登录页里签发的(绑定 session id)。修复前 handleLogout 用空 boundID 校验必然
// mismatch → 恒 403,session 从不销毁,登出按钮实际失效。本测试锁死修复后的行为。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

func recorderCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestHandleLogout_SessionBoundCSRF_Succeeds(t *testing.T) {
	st := newTestStore(t)
	cfg := defaultConfig()
	cfg.SessionTTLSec = 3600
	ctx := t.Context()

	hash, _ := HashWebPassword("strongPass1!aa")
	a, err := st.CreateWebAdmin(ctx, store.NewWebAdmin{Username: "logoutuser", PasswordHash: hash})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}

	sess := NewSessionService(st, cfg)
	srv := &Server{store: st, audit: NewAuditor(st), sess: sess}

	// 1) 发一个 session,拿到 session cookie。
	wIssue := httptest.NewRecorder()
	if _, err := sess.IssueSession(ctx, wIssue, a.ID, "10.0.0.1", "ua"); err != nil {
		t.Fatalf("issue session: %v", err)
	}
	sessCookie := recorderCookie(t, wIssue, sess.cookieName(sessionCookieName))
	if sessCookie == nil {
		t.Fatal("missing session cookie")
	}

	// 找到 session id(csrf token 要绑定它)。
	rLookup := httptest.NewRequest(http.MethodGet, "/", nil)
	rLookup.AddCookie(sessCookie)
	_, ws, err := sess.LookupSession(ctx, rLookup)
	if err != nil {
		t.Fatalf("lookup session: %v", err)
	}

	// 2) 模拟已登录页渲染:签发**绑定 session id** 的 csrf token(+ 写 csrf cookie)。
	rRender := httptest.NewRequest(http.MethodGet, "/", nil).
		WithContext(context.WithValue(ctx, ctxKeySessionID, ws.ID))
	wCSRF := httptest.NewRecorder()
	tok, err := sess.IssueCSRFToken(rRender, wCSRF)
	if err != nil {
		t.Fatalf("issue csrf: %v", err)
	}
	// 第七轮深扫 MED:CSRF cookie 现按 cookieSecure 加 __Host- 前缀(见 SessionService.cookieName),
	// 故这里按**有效名**取回,而不是裸常量。
	csrfCookie := recorderCookie(t, wCSRF, sess.cookieName(csrfCookieName))
	if csrfCookie == nil {
		t.Fatal("missing csrf cookie")
	}

	// 3) POST /logout,带 session + csrf cookie + csrf_token 表单字段(浏览器点退出按钮的等价请求)。
	form := url.Values{"csrf_token": {tok}}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessCookie)
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()

	srv.handleLogout(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("logout should 302 redirect, got %d body=%q", rec.Code, rec.Body.String())
	}
	// session 必须已被销毁。
	if _, _, err := sess.LookupSession(ctx, rLookup); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session should be destroyed after logout, got %v", err)
	}
}

// 无 csrf_token 仍应 403(不能因为修复而放松 CSRF)。
func TestHandleLogout_MissingCSRF_Forbidden(t *testing.T) {
	st := newTestStore(t)
	cfg := defaultConfig()
	cfg.SessionTTLSec = 3600
	ctx := t.Context()
	hash, _ := HashWebPassword("strongPass1!aa")
	a, _ := st.CreateWebAdmin(ctx, store.NewWebAdmin{Username: "logoutuser2", PasswordHash: hash})
	sess := NewSessionService(st, cfg)
	srv := &Server{store: st, audit: NewAuditor(st), sess: sess}

	wIssue := httptest.NewRecorder()
	if _, err := sess.IssueSession(ctx, wIssue, a.ID, "10.0.0.1", "ua"); err != nil {
		t.Fatalf("issue session: %v", err)
	}
	sessCookie := recorderCookie(t, wIssue, sess.cookieName(sessionCookieName))

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(sessCookie)
	rec := httptest.NewRecorder()
	srv.handleLogout(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("logout without csrf should 403, got %d", rec.Code)
	}
}
