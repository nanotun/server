package main

// handler_users_prg_test.go(第三轮深扫 P2-4):
//
// PRG flash 链路的 HTTP 端到端断言。`credentialsFlashStore` 单测在
// `credentials_flash_test.go` 已经覆盖了 stash/pop/kind/TTL,但 handler 这一层
// 「token + UserID 双因子守门」、「第二次 GET → 410 Gone」是 P2-4 报告里明确
// 点名的盲区。本测试**不**构造完整 admin session / 模板,因为只要 `s.tmpl` 没有
// `error.html`,`renderError` 会走 plain-text fallback(`render.go:125-128`),
// 不需要 layout / partials / fmtTime 等模板函数堆栈,handler 走的就是「失败路径」
// 一条线 — 这正是要保护的安全分支。
//
// happy path(token + UserID 匹配 → 渲染 user_created.html)涉及全套模板 +
// admin context + CSRF,留给将来加一个 `newTestServerFull` helper 时一起做。
// 这里**至少**确保了:
//
//   1. token 不存在 / 已过期 / 空 → 410 Gone(不能透出 PSK)
//   2. token 命中但 UserID 不匹配 → 410 Gone(防 referer / history 错位)
//   3. token 命中、kind 错配 → 410 Gone(referer 泄漏后枚举攻击)
//   4. 同一 token 第二次 Pop → 410 Gone(一次性消费契约)

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// newTestServerMinimal 构造最小 *Server 用于 PRG handler 测试。
//
// 故意**不**载入真实模板:让 `renderError` 走 `s.tmpl.Lookup("error.html") == nil`
// 的 plain-text fallback 分支。`tmpl` 字段非 nil 是必要的(`renderError` 调
// `s.tmpl.Lookup` 会 nil-deref),所以给它一个空 *template.Template。
func newTestServerMinimal(t *testing.T) *Server {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, t.TempDir()+"/web_prg_test.db", store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	return &Server{
		store:     st,
		audit:     NewAuditor(st),
		tmpl:      template.New(""),
		credFlash: newCredentialsFlashStore(stop),
		startedAt: time.Now(),
	}
}

func newPRGTestUser(t *testing.T, s *Server, username string) *store.User {
	t.Helper()
	u, err := s.store.CreateUser(t.Context(),
		store.NewUser{Username: username, PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser %q: %v", username, err)
	}
	return u
}

// TestHandleUserCreatedFlash_TokenMissing:无 token / 空 token / 未知 token → 410 Gone。
//
// 这是「攻击者拼 URL 但没 referrer」最常见的情形。
func TestHandleUserCreatedFlash_TokenMissing(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "alice")

	tests := []struct {
		name string
		url  string
	}{
		{"no_token_param", "/users/1/created"},
		{"empty_token", "/users/1/created?token="},
		{"unknown_token", "/users/1/created?token=does-not-exist"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req = req.WithContext(context.Background())
			w := httptest.NewRecorder()
			s.handleUserCreatedFlash(w, req, u)
			if w.Code != http.StatusGone {
				t.Errorf("status = %d, want %d (Gone)", w.Code, http.StatusGone)
			}
		})
	}
}

// TestHandleUserCreatedFlash_UserIDMismatch:token 合法但 URL 上的 user 不是 stash
// 时绑定的 user → 410 Gone。
//
// 防止 admin 把别人的 created token 拼到本 URL 上看到不属于他的 PSK。
func TestHandleUserCreatedFlash_UserIDMismatch(t *testing.T) {
	s := newTestServerMinimal(t)
	alice := newPRGTestUser(t, s, "alice")
	bob := newPRGTestUser(t, s, "bob")

	tok, err := s.credFlash.Stash(credentialsFlashPayload{
		Kind:     credentialsFlashKindUserCreated,
		UserID:   alice.ID,
		Username: "alice",
		PSK:      "PLAIN_ALICE",
	})
	if err != nil {
		t.Fatalf("Stash: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/users/2/created?token="+tok, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	s.handleUserCreatedFlash(w, req, bob) // 把 bob 当成 URL 上 {id}=2 的 user

	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d (Gone) on UserID mismatch", w.Code, http.StatusGone)
	}
	// 关键安全断言:PSK 明文绝不能出现在 body 里。
	body := w.Body.String()
	if body != "" && (containsCaseSensitive(body, "PLAIN_ALICE") || containsCaseSensitive(body, "alice")) {
		t.Fatalf("user mismatch 响应体不应泄漏 alice 的 PSK / username:\n%s", body)
	}
	// **第四轮深扫 P2-b**:UserID 校验顺序回归保护。当前 handler 顺序是
	// `Pop → UserID 校验` — Pop 已经把 token 消费掉了,即便 UserID mismatch
	// 也不会泄漏 PSK。但如果有人重构把 UserID 校验挪到 Pop 之前,token 就
	// **不会**被消费,可以无限重放试不同 URL 上的 {id}。这里断言 mismatch
	// 后 store.Len()==0,把这条 invariant 锁住。
	if s.credFlash.Len() != 0 {
		t.Fatalf("UserID mismatch 后 token 必须已被消费,Len=%d(若有人重构校验顺序,这条会挂)",
			s.credFlash.Len())
	}
}

// TestHandleUserCreatedFlash_SecondPopGone:第一次 GET 已消费 token,第二次 GET → 410。
//
// 这是 PRG「一次性」契约的核心:admin 误按浏览器后退 / 刷新不能让 PSK 反复出现。
// happy path 走的是 renderUserCreated → renderPage("user_created.html"),没有模板
// 会失败到 500(`render.go:104-106`)— 我们只断言「第二次必须 410」,第一次的
// 200 / 500 都不影响 token 已被 Pop 这件事。
func TestHandleUserCreatedFlash_SecondPopGone(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "carol")

	tok, _ := s.credFlash.Stash(credentialsFlashPayload{
		Kind:   credentialsFlashKindUserCreated,
		UserID: u.ID,
		PSK:    "PLAIN_CAROL",
	})

	// 第一次:token + UserID 全对。无模板 → 500,但 token 已被 Pop。
	req1 := httptest.NewRequest(http.MethodGet, "/users/1/created?token="+tok, nil)
	req1 = req1.WithContext(context.Background())
	w1 := httptest.NewRecorder()
	s.handleUserCreatedFlash(w1, req1, u)
	// 关键:第一次 Pop 成功后 store.Len() 必须 == 0。
	if s.credFlash.Len() != 0 {
		t.Fatalf("第一次 GET 后 token 未被消费,Len=%d", s.credFlash.Len())
	}

	// 第二次:同一 token → 410。
	req2 := httptest.NewRequest(http.MethodGet, "/users/1/created?token="+tok, nil)
	req2 = req2.WithContext(context.Background())
	w2 := httptest.NewRecorder()
	s.handleUserCreatedFlash(w2, req2, u)
	if w2.Code != http.StatusGone {
		t.Fatalf("第二次 GET status = %d,want %d (Gone) — PRG 一次性契约破坏", w2.Code, http.StatusGone)
	}
}

// TestHandleUserResetPSKResultFlash_KindMismatch:user_created kind 的 token 拼到
// reset-psk-result GET → 410 Gone,且 token 立即从 store 删除(第三轮深扫安全收紧)。
func TestHandleUserResetPSKResultFlash_KindMismatch(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "dave")

	tok, _ := s.credFlash.Stash(credentialsFlashPayload{
		Kind:   credentialsFlashKindUserCreated, // 写入 user_created
		UserID: u.ID,
		PSK:    "PLAIN_DAVE",
	})

	// GET reset-psk-result 路径(kind = user_reset_psk),会去 Pop(token, user_reset_psk),
	// kind 不匹配 → store 立即删 + handler 410。
	req := httptest.NewRequest(http.MethodGet, "/users/1/reset-psk-result?token="+tok, nil)
	req = req.WithContext(context.Background())
	w := httptest.NewRecorder()
	s.handleUserResetPSKResultFlash(w, req, u)

	if w.Code != http.StatusGone {
		t.Fatalf("kind 错配 status = %d,want %d (Gone)", w.Code, http.StatusGone)
	}
	if s.credFlash.Len() != 0 {
		t.Fatalf("kind 错配后 entry 未被消费(安全收紧回归),Len=%d", s.credFlash.Len())
	}
}

// containsCaseSensitive:HTTP body 字符串子串查找,避免 import "strings" 上方已经引入。
func containsCaseSensitive(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
