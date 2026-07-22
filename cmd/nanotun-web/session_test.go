package main

import (
	"context"
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
	issueReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	tok, err := sess.IssueCSRFToken(issueReq, w)
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

// TestCSRFToken_SessionBound 覆盖第三轮深扫 L1:CSRF token 绑定到 session id,
// 关掉 cookie-tossing —— 即便 cookie==form 自洽,绑到别的 session 的 token 也被拒。
func TestCSRFToken_SessionBound(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())

	// 攻击者用自己的 session A 拿到一套自洽的 (cookie, form) token。
	wA := httptest.NewRecorder()
	rA := httptest.NewRequest(http.MethodGet, "/", nil).
		WithContext(context.WithValue(context.Background(), ctxKeySessionID, "session-A"))
	tokA, err := sess.IssueCSRFToken(rA, wA)
	if err != nil {
		t.Fatalf("issue A: %v", err)
	}
	cookieA := wA.Header().Get("Set-Cookie")

	// 重放到受害者(session B)上下文 —— 模拟 cookie-tossing。cookie==form 但签名对 B 不合法 → 拒。
	rB := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("csrf_token="+tokA))
	rB.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rB.Header.Set("Cookie", cookieA)
	rB = rB.WithContext(context.WithValue(rB.Context(), ctxKeySessionID, "session-B"))
	if err := sess.VerifyCSRFToken(rB); err == nil {
		t.Fatal("cookie-tossing:绑到 session A 的 token 必须被 session B 拒绝")
	}

	// 同一 session A 上校验通过。
	rA2 := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("csrf_token="+tokA))
	rA2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rA2.Header.Set("Cookie", cookieA)
	rA2 = rA2.WithContext(context.WithValue(rA2.Context(), ctxKeySessionID, "session-A"))
	if err := sess.VerifyCSRFToken(rA2); err != nil {
		t.Fatalf("同 session 校验应通过: %v", err)
	}
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

func TestClientIP_TrustedProxy(t *testing.T) {
	// 保存并在结束时恢复全局(同包测试串行修改包级状态)。
	saved := trustedProxyNets
	t.Cleanup(func() { trustedProxyNets = saved })

	mkReq := func(remote, xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}

	t.Run("no trusted proxies: XFF ignored", func(t *testing.T) {
		setTrustedProxies(nil)
		if got := clientIP(mkReq("203.0.113.9:443", "1.2.3.4")); got != "203.0.113.9" {
			t.Fatalf("default posture must use direct peer, got %q", got)
		}
	})

	t.Run("direct peer trusted: rightmost untrusted from XFF", func(t *testing.T) {
		nets, err := parseTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1"})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		setTrustedProxies(nets)
		// client → nginx(203.0.113.x, untrusted, appears left) ... 但直连是 10.x 可信,
		// XFF = "client, internal-proxy";从右往左第一个非可信即真实客户端。
		if got := clientIP(mkReq("10.0.0.5:5555", "198.51.100.7, 10.0.0.9")); got != "198.51.100.7" {
			t.Fatalf("want real client 198.51.100.7, got %q", got)
		}
	})

	t.Run("direct peer NOT trusted: XFF is ignored (spoof-proof)", func(t *testing.T) {
		nets, _ := parseTrustedProxies([]string{"10.0.0.0/8"})
		setTrustedProxies(nets)
		// 直连对端是公网(不可信),即使伪造 XFF 也不采信。
		if got := clientIP(mkReq("203.0.113.50:1234", "1.1.1.1")); got != "203.0.113.50" {
			t.Fatalf("spoofed XFF must be ignored, got %q", got)
		}
	})

	t.Run("all XFF entries trusted: falls back to leftmost", func(t *testing.T) {
		nets, _ := parseTrustedProxies([]string{"10.0.0.0/8"})
		setTrustedProxies(nets)
		if got := clientIP(mkReq("10.0.0.5:5555", "10.0.0.1, 10.0.0.2")); got != "10.0.0.1" {
			t.Fatalf("want leftmost 10.0.0.1, got %q", got)
		}
	})

	t.Run("IPv6 direct peer + bracketed remote", func(t *testing.T) {
		nets, _ := parseTrustedProxies([]string{"::1/128"})
		setTrustedProxies(nets)
		if got := clientIP(mkReq("[::1]:8443", "2001:db8::9")); got != "2001:db8::9" {
			t.Fatalf("want 2001:db8::9, got %q", got)
		}
	})

	t.Run("multiple XFF headers are aggregated (Header.Add)", func(t *testing.T) {
		nets, _ := parseTrustedProxies([]string{"10.0.0.0/8"})
		setTrustedProxies(nets)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.5:5555"
		// 攻击者塞入伪造首值,可信跳把真实客户端用 Add 追加为第二条 header。
		r.Header.Add("X-Forwarded-For", "8.8.8.8")
		r.Header.Add("X-Forwarded-For", "198.51.100.7")
		if got := clientIP(r); got != "198.51.100.7" {
			t.Fatalf("multi-header XFF must aggregate; want 198.51.100.7, got %q", got)
		}
	})
}

func TestParseTrustedProxies_RejectsGarbage(t *testing.T) {
	if _, err := parseTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1"}); err != nil {
		t.Fatalf("valid entries should parse: %v", err)
	}
	for _, bad := range []string{"not-an-ip", "10.0.0.0/99", "999.1.1.1", "1.2.3.4/"} {
		if _, err := parseTrustedProxies([]string{bad}); err == nil {
			t.Errorf("parseTrustedProxies(%q) should fail-fast, got nil", bad)
		}
	}
	// 深扫第十轮 LOW:全零前缀等于信任所有对端,必须拒绝。
	for _, zero := range []string{"0.0.0.0/0", "::/0"} {
		if _, err := parseTrustedProxies([]string{zero}); err == nil {
			t.Errorf("parseTrustedProxies(%q) should reject zero-length prefix, got nil", zero)
		}
	}
}

func TestSplitTrustedProxies_Sentinel(t *testing.T) {
	for _, clear := range []string{"", "none", "off", "  NONE  ", "Off"} {
		if got := splitTrustedProxies(clear); got != nil {
			t.Errorf("splitTrustedProxies(%q) = %v, want nil (cleared)", clear, got)
		}
	}
	got := splitTrustedProxies("127.0.0.1, 10.0.0.0/8")
	if len(got) != 2 || got[0] != "127.0.0.1" || got[1] != "10.0.0.0/8" {
		t.Fatalf("splitTrustedProxies parsed wrong: %v", got)
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
