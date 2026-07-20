package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/nanotun/server/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "nanotun_test.db"), store.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

func TestValidatePasswordStrength(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool // true = should pass
	}{
		{"too short", "abc123", false},
		{"only letters", "abcdefghijklmn", false},
		{"only digits", "012345678912", false},
		{"len ok + 2 classes", "abcdef123456", true},
		{"len ok + letters + symbols", "abcdefghij!!", true},
		{"contains newline", "abcdef123456\n!!", false},
		{"too long", string(make([]byte, 300)), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePasswordStrength(c.in)
			if c.want && err != nil {
				t.Fatalf("should pass but got %v", err)
			}
			if !c.want && err == nil {
				t.Fatal("should fail but nil")
			}
		})
	}
}

func TestAttemptLogin_HappyPath(t *testing.T) {
	st := newTestStore(t)
	ctx := t.Context()

	pwd := "GoodStrong1!Pass"
	hash, err := HashWebPassword(pwd)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, err = st.CreateWebAdmin(ctx, store.NewWebAdmin{
		Username:     "root",
		PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}

	cfg := defaultConfig()
	res := AttemptLogin(ctx, st, cfg, "root", pwd, "10.0.0.1")
	if res.Err != nil {
		t.Fatalf("login: %v", res.Err)
	}
	if res.Admin == nil || res.Admin.Username != "root" {
		t.Fatalf("admin not returned: %+v", res.Admin)
	}
}

func TestAttemptLogin_UnknownUser(t *testing.T) {
	st := newTestStore(t)
	cfg := defaultConfig()
	res := AttemptLogin(t.Context(), st, cfg, "ghost", "whatever", "10.0.0.1")
	if !errors.Is(res.Err, ErrAuthBadCredentials) {
		t.Fatalf("expected ErrAuthBadCredentials, got %v", res.Err)
	}
}

func TestAttemptLogin_BadPassword(t *testing.T) {
	st := newTestStore(t)
	ctx := t.Context()
	hash, _ := HashWebPassword("CorrectHorse1!")
	_, _ = st.CreateWebAdmin(ctx, store.NewWebAdmin{Username: "bob", PasswordHash: hash})
	cfg := defaultConfig()

	res := AttemptLogin(ctx, st, cfg, "bob", "wrongpwd", "10.0.0.1")
	if !errors.Is(res.Err, ErrAuthBadCredentials) {
		t.Fatalf("expected ErrAuthBadCredentials, got %v", res.Err)
	}
	got, _ := st.GetWebAdminByUsername(ctx, "bob")
	if got.FailedLogins != 1 {
		t.Fatalf("FailedLogins=%d, want 1", got.FailedLogins)
	}
}

func TestAttemptLogin_LockoutAfterMaxFailures(t *testing.T) {
	st := newTestStore(t)
	ctx := t.Context()
	hash, _ := HashWebPassword("CorrectHorse1!")
	_, _ = st.CreateWebAdmin(ctx, store.NewWebAdmin{Username: "carol", PasswordHash: hash})
	cfg := defaultConfig()
	cfg.MaxLoginFailures = 3
	cfg.LockoutSeconds = 600

	for i := 0; i < 3; i++ {
		_ = AttemptLogin(ctx, st, cfg, "carol", "bad", "10.0.0.1")
	}
	// 锁定后即便密码正确也拒
	res := AttemptLogin(ctx, st, cfg, "carol", "CorrectHorse1!", "10.0.0.1")
	if !errors.Is(res.Err, ErrAuthLocked) {
		t.Fatalf("expected ErrAuthLocked, got %v", res.Err)
	}
	if res.LockedUntil == 0 {
		t.Fatalf("LockedUntil should be set")
	}
}

func TestAttemptLogin_DisabledUser(t *testing.T) {
	st := newTestStore(t)
	ctx := t.Context()
	hash, _ := HashWebPassword("CorrectHorse1!")
	a, _ := st.CreateWebAdmin(ctx, store.NewWebAdmin{Username: "dave", PasswordHash: hash})
	if err := st.SetWebAdminEnabled(ctx, a.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	cfg := defaultConfig()
	res := AttemptLogin(ctx, st, cfg, "dave", "CorrectHorse1!", "10.0.0.1")
	if !errors.Is(res.Err, ErrAuthDisabled) {
		t.Fatalf("expected ErrAuthDisabled, got %v", res.Err)
	}
}

// TestAttemptLogin_TOTPAccount_PasswordDoesNotResetCounter 是 H1(深扫第八轮)的回归:
// 对启用了 TOTP 的账号,密码正确只是登录第一步,AttemptLogin **绝不能**在此处
// RecordWebAdminLoginSuccess —— 否则 failed_logins/locked_until 被清零,attacker 每次重发
// 正确密码就把 TOTP 步累积的失败计数抹掉,6 位码锁定形同虚设。
func TestAttemptLogin_TOTPAccount_PasswordDoesNotResetCounter(t *testing.T) {
	st := newTestStore(t)
	ctx := t.Context()
	pwd := "GoodStrong1!Pass"
	hash, _ := HashWebPassword(pwd)
	a, err := st.CreateWebAdmin(ctx, store.NewWebAdmin{Username: "totpuser", PasswordHash: hash})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	// 启用 TOTP(需要先有 secret,再 enable)。
	if err := st.SetWebAdminTOTPSecret(ctx, a.ID, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("set secret: %v", err)
	}
	if _, err := st.EnableWebAdminTOTP(ctx, a.ID, []string{"h1", "h2"}, nowUnix()); err != nil {
		t.Fatalf("enable totp: %v", err)
	}

	cfg := defaultConfig()
	cfg.MaxLoginFailures = 5
	cfg.LockoutSeconds = 600

	// 模拟 TOTP 步失败累积 3 次(handler_auth 里走 RecordWebAdminLoginFailure)。
	for i := 0; i < 3; i++ {
		if _, _, err := st.RecordWebAdminLoginFailure(ctx, a.ID, cfg.MaxLoginFailures, cfg.LockoutSeconds); err != nil {
			t.Fatalf("record failure: %v", err)
		}
	}
	// 关键:重发正确密码走 AttemptLogin。它必须成功(通过第一步),但**不得**清零计数。
	res := AttemptLogin(ctx, st, cfg, "totpuser", pwd, "10.0.0.1")
	if res.Err != nil {
		t.Fatalf("password step should pass for TOTP account, got %v", res.Err)
	}
	got, _ := st.GetWebAdmin(ctx, a.ID)
	if got.FailedLogins != 3 {
		t.Fatalf("TOTP 账号密码步不该重置计数器: FailedLogins=%d, want 3", got.FailedLogins)
	}
}

// TestAttemptLogin_NonTOTPAccount_PasswordResetsCounter 是上面的对照:非 TOTP 账号
// 密码正确即完成登录,照常复位 failed_logins。
func TestAttemptLogin_NonTOTPAccount_PasswordResetsCounter(t *testing.T) {
	st := newTestStore(t)
	ctx := t.Context()
	pwd := "GoodStrong1!Pass"
	hash, _ := HashWebPassword(pwd)
	a, _ := st.CreateWebAdmin(ctx, store.NewWebAdmin{Username: "plainuser", PasswordHash: hash})
	cfg := defaultConfig()
	cfg.MaxLoginFailures = 5
	cfg.LockoutSeconds = 600

	for i := 0; i < 3; i++ {
		_, _, _ = st.RecordWebAdminLoginFailure(ctx, a.ID, cfg.MaxLoginFailures, cfg.LockoutSeconds)
	}
	res := AttemptLogin(ctx, st, cfg, "plainuser", pwd, "10.0.0.1")
	if res.Err != nil {
		t.Fatalf("login: %v", res.Err)
	}
	got, _ := st.GetWebAdmin(ctx, a.ID)
	if got.FailedLogins != 0 {
		t.Fatalf("非 TOTP 账号密码正确应复位计数器: FailedLogins=%d, want 0", got.FailedLogins)
	}
}

func TestConstantTimeStringEqual(t *testing.T) {
	if !ConstantTimeStringEqual("abc", "abc") {
		t.Fatal("equal failed")
	}
	if ConstantTimeStringEqual("abc", "abd") {
		t.Fatal("unequal should fail")
	}
	if ConstantTimeStringEqual("abc", "abcd") {
		t.Fatal("length-diff should fail")
	}
}

// 防止 nowUnix 静默回归
func TestNowUnixSane(t *testing.T) {
	if nowUnix() < 1_600_000_000 {
		t.Fatal("clock looks wrong")
	}
}

// 验证 password hash 是 PHC argon2id 形式,与 nanotun/auth.HashPSK 同格式。
func TestHashWebPasswordFormat(t *testing.T) {
	h, err := HashWebPassword("StrongPass1!aaa")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if len(h) < 50 || h[:9] != "argon2id$" {
		t.Fatalf("hash format wrong: %s", h)
	}
	ok, _ := VerifyWebPassword("StrongPass1!aaa", h)
	if !ok {
		t.Fatal("verify same psk should ok")
	}
	ok, _ = VerifyWebPassword("Wrong!", h)
	if ok {
		t.Fatal("verify wrong should fail")
	}
}

// keep ctx import warning silenced if ever removed
var _ = context.Background
