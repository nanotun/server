package store

import (
	"strings"
	"testing"
)

// 简单覆盖 0009 引入的 TOTP DAL:enable/disable/regen 的事务一致性和恢复码生命周期。

func TestWebAdminTOTP_EnableDisableRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, err := s.CreateWebAdmin(ctx, NewWebAdmin{
		Username: "totp_admin", PasswordHash: "argon2id$dummy$$$$dummy", Role: "admin",
	})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	if a.TOTPEnabled {
		t.Fatal("新建 admin 不应该 TOTPEnabled")
	}

	// 第 1 步:写 secret(setup)
	if err := s.SetWebAdminTOTPSecret(ctx, a.ID, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("SetWebAdminTOTPSecret: %v", err)
	}
	a2, err := s.GetWebAdmin(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if a2.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("secret 未保存: %q", a2.TOTPSecret)
	}
	if a2.TOTPEnabled {
		t.Fatal("setup 阶段不该 enabled")
	}

	// 第 2 步:enable + 10 个恢复码
	hashes := []string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10"}
	now := int64(1779513195)
	n, err := s.EnableWebAdminTOTP(ctx, a.ID, hashes, now)
	if err != nil {
		t.Fatalf("EnableWebAdminTOTP: %v", err)
	}
	if n != 10 {
		t.Fatalf("插入恢复码数 = %d, want 10", n)
	}
	a3, _ := s.GetWebAdmin(ctx, a.ID)
	if !a3.TOTPEnabled || a3.TOTPEnabledAt != now {
		t.Fatalf("enabled 状态错: enabled=%v enabled_at=%d", a3.TOTPEnabled, a3.TOTPEnabledAt)
	}
	if cnt, _ := s.CountUnusedRecoveryCodes(ctx, a.ID); cnt != 10 {
		t.Fatalf("CountUnusedRecoveryCodes = %d, want 10", cnt)
	}

	// 用一条恢复码 → 剩 9
	codes, err := s.ListUnusedRecoveryCodes(ctx, a.ID)
	if err != nil {
		t.Fatalf("ListUnusedRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("List 长度 = %d, want 10", len(codes))
	}
	if err := s.MarkRecoveryCodeUsed(ctx, codes[0].ID, "1.2.3.4", now+10); err != nil {
		t.Fatalf("MarkRecoveryCodeUsed: %v", err)
	}
	if cnt, _ := s.CountUnusedRecoveryCodes(ctx, a.ID); cnt != 9 {
		t.Fatalf("使用 1 条后 Count = %d, want 9", cnt)
	}
	// 再用同一条 → 应该 ErrNotFound(WHERE used_at=0 防双花)
	if err := s.MarkRecoveryCodeUsed(ctx, codes[0].ID, "1.2.3.4", now+20); err == nil {
		t.Fatal("同一条恢复码重复 mark 应当返回 error")
	}

	// disable → secret 清,恢复码全删
	if err := s.DisableWebAdminTOTP(ctx, a.ID); err != nil {
		t.Fatalf("DisableWebAdminTOTP: %v", err)
	}
	a4, _ := s.GetWebAdmin(ctx, a.ID)
	if a4.TOTPEnabled || a4.TOTPSecret != "" || a4.TOTPEnabledAt != 0 {
		t.Fatalf("disable 后状态错: enabled=%v secret=%q enabled_at=%d",
			a4.TOTPEnabled, a4.TOTPSecret, a4.TOTPEnabledAt)
	}
	if cnt, _ := s.CountUnusedRecoveryCodes(ctx, a.ID); cnt != 0 {
		t.Fatalf("disable 后恢复码 Count = %d, want 0", cnt)
	}
}

func TestWebAdminTOTP_Regenerate(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{
		Username: "regen_admin", PasswordHash: "argon2id$dummy$$$$dummy", Role: "admin",
	})
	_ = s.SetWebAdminTOTPSecret(ctx, a.ID, "JBSWY3DPEHPK3PXP")
	_, _ = s.EnableWebAdminTOTP(ctx, a.ID,
		[]string{"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10"}, 100)

	// 用掉两条
	codes, _ := s.ListUnusedRecoveryCodes(ctx, a.ID)
	_ = s.MarkRecoveryCodeUsed(ctx, codes[0].ID, "ip", 110)
	_ = s.MarkRecoveryCodeUsed(ctx, codes[1].ID, "ip", 120)
	if c, _ := s.CountUnusedRecoveryCodes(ctx, a.ID); c != 8 {
		t.Fatalf("用掉 2 条后 = %d, want 8", c)
	}

	// regen → 10 条全新
	if err := s.RegenerateRecoveryCodes(ctx, a.ID,
		[]string{"b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10"}, 130); err != nil {
		t.Fatalf("RegenerateRecoveryCodes: %v", err)
	}
	if c, _ := s.CountUnusedRecoveryCodes(ctx, a.ID); c != 10 {
		t.Fatalf("regen 后 = %d, want 10", c)
	}
	codes2, _ := s.ListUnusedRecoveryCodes(ctx, a.ID)
	for _, c := range codes2 {
		// 新一批 hash 全是 "b<n>" 前缀
		if !strings.HasPrefix(c.CodeHash, "b") {
			t.Fatalf("regen 后还有老 hash: %q", c.CodeHash)
		}
	}
	// admin 自身的 totp_enabled 不应被 regen 改动
	a2, _ := s.GetWebAdmin(ctx, a.ID)
	if !a2.TOTPEnabled {
		t.Fatal("regen 不应该关掉 totp_enabled")
	}
}

func TestWebAdminTOTP_EnableRejectsWithoutSecret(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{
		Username: "no_secret", PasswordHash: "argon2id$dummy$$$$dummy", Role: "admin",
	})
	// 不调 SetWebAdminTOTPSecret,直接 Enable → 应当 ErrNotFound
	if _, err := s.EnableWebAdminTOTP(ctx, a.ID,
		[]string{"h"}, 100); err != ErrNotFound {
		t.Fatalf("无 secret 时 EnableWebAdminTOTP err = %v, want ErrNotFound", err)
	}
}
