package main

// session_pending_test.go - pending-2FA 绑定密码指纹(第五轮深扫 HIGH)。
//
// 契约:pending cookie 里签着**签发时**的密码指纹;密码轮换后,当前密码指纹与之不符,
// handler 据此作废旧 pending → 攻击者即便已过密码步、持有 pending,也无法在密码被改后完成 TOTP 步。

import (
	"crypto/subtle"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTOTPPending_BindsPasswordFingerprint(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())

	const ip = "203.0.113.5"
	const hashOld = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAA$oldoldoldoldoldoldoldoldoldoldoldoldoldo"
	const hashNew = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAA$newnewnewnewnewnewnewnewnewnewnewnewnewn"

	w := httptest.NewRecorder()
	if err := sess.IssueTOTPPending(w, 42, ip, hashOld); err != nil {
		t.Fatalf("issue pending: %v", err)
	}
	ck := recorderCookie(t, w, pending2FACookieName)
	if ck == nil {
		t.Fatal("missing pending cookie")
	}

	r := httptest.NewRequest(http.MethodPost, "/login/totp", nil)
	r.RemoteAddr = ip + ":12345"
	r.AddCookie(ck)

	gotID, gotFp, gotNonce, err := sess.LookupTOTPPending(r)
	if err != nil {
		t.Fatalf("lookup pending: %v", err)
	}
	if gotNonce == "" {
		t.Fatal("pending nonce should be non-empty")
	}
	if gotID != 42 {
		t.Fatalf("adminID = %d, want 42", gotID)
	}
	// 旧密码指纹应匹配(pending 是用它签发的)。
	if wantOld := passwordFingerprint(hashOld); subtle.ConstantTimeCompare(gotFp[:], wantOld[:]) != 1 {
		t.Fatal("pending fingerprint should match the issuing password")
	}
	// 密码轮换后:当前指纹与 pending 里签的不同 → handler 会作废旧 pending。
	if wantNew := passwordFingerprint(hashNew); subtle.ConstantTimeCompare(gotFp[:], wantNew[:]) == 1 {
		t.Fatal("pending fingerprint must NOT match a rotated password (rotation would not invalidate pending)")
	}
}

// pending cookie 从别的 IP 重放仍应验签失败(IP 绑定回归,确保加了指纹字段后 IP AAD 仍生效)。
func TestTOTPPending_RejectsForeignIP(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())

	w := httptest.NewRecorder()
	if err := sess.IssueTOTPPending(w, 7, "198.51.100.1", "somehash"); err != nil {
		t.Fatalf("issue pending: %v", err)
	}
	ck := recorderCookie(t, w, pending2FACookieName)

	r := httptest.NewRequest(http.MethodPost, "/login/totp", nil)
	r.RemoteAddr = "10.10.10.10:9999" // 不同 IP
	r.AddCookie(ck)

	if _, _, _, err := sess.LookupTOTPPending(r); err == nil {
		t.Fatal("pending replay from a different IP should fail verification")
	}
}

// TestTOTPPending_ServerSideSingleUse(第七轮深扫 MED):同一 pending nonce 一旦被
// MarkPendingConsumed 标记,再次 LookupTOTPPending 即便 HMAC / IP / exp 全对也必须失败 —— 服务端一次性。
func TestTOTPPending_ServerSideSingleUse(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())

	const ip = "203.0.113.9"
	w := httptest.NewRecorder()
	if err := sess.IssueTOTPPending(w, 11, ip, "somehash"); err != nil {
		t.Fatalf("issue pending: %v", err)
	}
	ck := recorderCookie(t, w, pending2FACookieName)

	r := httptest.NewRequest(http.MethodPost, "/login/totp", nil)
	r.RemoteAddr = ip + ":5555"
	r.AddCookie(ck)

	_, _, nonce, err := sess.LookupTOTPPending(r)
	if err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	// 首次消费应成功,二次消费应失败(并发/重放语义)。
	if !sess.MarkPendingConsumed(nonce) {
		t.Fatal("first MarkPendingConsumed should succeed")
	}
	if sess.MarkPendingConsumed(nonce) {
		t.Fatal("second MarkPendingConsumed must fail (already consumed)")
	}
	// 消费后同一 cookie 再 lookup 必须被拒。
	r2 := httptest.NewRequest(http.MethodPost, "/login/totp", nil)
	r2.RemoteAddr = ip + ":5556"
	r2.AddCookie(ck)
	if _, _, _, err := sess.LookupTOTPPending(r2); err == nil {
		t.Fatal("lookup after consume must fail (server-side single-use)")
	}
}