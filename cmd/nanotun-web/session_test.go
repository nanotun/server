package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

func TestIssueAndLookupSession(t *testing.T) {
	st := newTestStore(t)
	cfg := defaultConfig()
	cfg.SessionTTLSec = 3600

	ctx := t.Context()
	hash, _ := HashWebPassword("strongPass1!aa")
	a, _ := st.CreateWebAdmin(ctx, store.NewWebAdmin{Username: "z", PasswordHash: hash})

	sess := NewSessionService(st, cfg)
	w := httptest.NewRecorder()

	if err := sess.IssueSession(ctx, w, a.ID, "10.0.0.1", "test-ua"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	setCookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(setCookie, sessionCookieName) {
		t.Fatalf("missing session cookie: %s", setCookie)
	}

	// 构造模拟带 cookie 的请求,验证 Lookup
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", setCookie)

	gotAdmin, gotSess, err := sess.LookupSession(ctx, r)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if gotAdmin == nil || gotAdmin.ID != a.ID {
		t.Fatalf("admin id mismatch: %+v", gotAdmin)
	}
	if gotSess == nil || gotSess.AdminID != a.ID {
		t.Fatalf("session admin id mismatch")
	}
}

func TestLookupSession_NoCookie(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, _, err := sess.LookupSession(t.Context(), r)
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("expected ErrNoSession, got %v", err)
	}
}

func TestLookupSession_DisabledAdminInvalidates(t *testing.T) {
	st := newTestStore(t)
	ctx := t.Context()
	cfg := defaultConfig()
	hash, _ := HashWebPassword("strongPass1!aa")
	a, _ := st.CreateWebAdmin(ctx, store.NewWebAdmin{Username: "u", PasswordHash: hash})
	sess := NewSessionService(st, cfg)
	w := httptest.NewRecorder()
	_ = sess.IssueSession(ctx, w, a.ID, "ip", "ua")
	cookie := w.Header().Get("Set-Cookie")

	_ = st.SetWebAdminEnabled(ctx, a.ID, false)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", cookie)
	if _, _, err := sess.LookupSession(ctx, r); !errors.Is(err, ErrNoSession) {
		t.Fatalf("disabled admin should be no-session, got %v", err)
	}
}

func TestVerifyCSRFToken(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())

	w := httptest.NewRecorder()
	tok, err := sess.IssueCSRFToken(w)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	cookie := w.Header().Get("Set-Cookie")

	t.Run("missing cookie", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("csrf_token="+tok))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := sess.VerifyCSRFToken(r); err == nil {
			t.Fatal("expected csrf error")
		}
	})
	t.Run("missing form", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		r.Header.Set("Cookie", cookie)
		if err := sess.VerifyCSRFToken(r); err == nil {
			t.Fatal("expected csrf error")
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("csrf_token=wrong"))
		r.Header.Set("Cookie", cookie)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := sess.VerifyCSRFToken(r); err == nil {
			t.Fatal("expected csrf error")
		}
	})
	t.Run("match", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("csrf_token="+tok))
		r.Header.Set("Cookie", cookie)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := sess.VerifyCSRFToken(r); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
	t.Run("GET is bypassed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if err := sess.VerifyCSRFToken(r); err != nil {
			t.Fatalf("GET should bypass: %v", err)
		}
	})
}

func TestEnsureCSRFToken_ReusesExistingCookie(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())

	// 第一次:没 cookie,EnsureCSRFToken 应当新签。
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/login", nil)
	tok1, err := sess.EnsureCSRFToken(r1, w1)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	cookie := w1.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, csrfCookieName) || !strings.Contains(cookie, tok1) {
		t.Fatalf("first cookie shape unexpected: %s", cookie)
	}

	// 第二次:带着上一次的 cookie GET,应该复用同一个 token。
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	r2.Header.Set("Cookie", cookie)
	tok2, err := sess.EnsureCSRFToken(r2, w2)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if tok1 != tok2 {
		t.Fatalf("token should be reused; got %q vs %q", tok1, tok2)
	}
	// 第二次也应该再下发一份 Set-Cookie(值相同),续期 MaxAge。
	cookie2 := w2.Header().Get("Set-Cookie")
	if !strings.Contains(cookie2, tok1) {
		t.Fatalf("expected reused cookie value, got %s", cookie2)
	}

	// 第三次:cookie 畸形(过短),应该新签盖掉。
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/login", nil)
	r3.Header.Set("Cookie", csrfCookieName+"=tooShort")
	tok3, err := sess.EnsureCSRFToken(r3, w3)
	if err != nil {
		t.Fatalf("third ensure: %v", err)
	}
	if tok3 == "tooShort" || tok3 == tok1 {
		t.Fatalf("malformed cookie should not be reused; got %q", tok3)
	}
}

func TestGenerateRandomTokenUnique(t *testing.T) {
	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		tok, err := generateRandomToken(32)
		if err != nil {
			t.Fatalf("gen: %v", err)
		}
		if seen[tok] {
			t.Fatal("token collision")
		}
		seen[tok] = true
	}
}
