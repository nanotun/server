package store

import (
	"errors"
	"testing"
)

const dummyPwdHash = "argon2id$v=19$m=65536,t=2,p=4$YWFhYWFhYWFhYWFhYWFhYQ$YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYg"

// TestCreateFirstWebAdmin 覆盖原子首建:空表可建,建成后再建拿 ErrSetupClosed(而非再插一行)。
func TestCreateFirstWebAdmin(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	a, err := s.CreateFirstWebAdmin(ctx, NewWebAdmin{Username: "first", PasswordHash: dummyPwdHash})
	if err != nil {
		t.Fatalf("CreateFirstWebAdmin(empty table): %v", err)
	}
	if a == nil || a.Username != "first" || a.Role != "admin" {
		t.Fatalf("unexpected first admin: %+v", a)
	}

	// 表已非空:必须拒(ErrSetupClosed),且不新增行。
	if _, err := s.CreateFirstWebAdmin(ctx, NewWebAdmin{Username: "second", PasswordHash: dummyPwdHash}); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("expected ErrSetupClosed on non-empty table, got %v", err)
	}
	n, err := s.CountWebAdmins(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("web_admins 应只有 1 行(原子首建拒了第二次),got %d", n)
	}
}

// TestWebAdminCRUD 覆盖创建 / 重名 / 查询 / 改密 / 角色 / 启停 / 删除全链路。
func TestWebAdminCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	a, err := s.CreateWebAdmin(ctx, NewWebAdmin{
		Username:     "root",
		PasswordHash: dummyPwdHash,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a.Username != "root" || a.Role != "admin" || !a.Enabled {
		t.Fatalf("Create returned %+v", a)
	}

	if _, err := s.CreateWebAdmin(ctx, NewWebAdmin{
		Username:     "root",
		PasswordHash: dummyPwdHash,
	}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}

	got, err := s.GetWebAdminByUsername(ctx, "root")
	if err != nil || got.ID != a.ID {
		t.Fatalf("GetByUsername mismatch: %+v err=%v", got, err)
	}

	if err := s.UpdateWebAdminPasswordHash(ctx, a.ID, dummyPwdHash+"x"); err != nil {
		t.Fatalf("update pwd: %v", err)
	}
	got, _ = s.GetWebAdmin(ctx, a.ID)
	if got.PasswordHash != dummyPwdHash+"x" {
		t.Fatal("password hash not updated")
	}

	if err := s.SetWebAdminRole(ctx, a.ID, "viewer"); err != nil {
		t.Fatalf("set role: %v", err)
	}
	got, _ = s.GetWebAdmin(ctx, a.ID)
	if got.Role != "viewer" {
		t.Fatalf("role = %q, want viewer", got.Role)
	}

	if err := s.SetWebAdminEnabled(ctx, a.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	got, _ = s.GetWebAdmin(ctx, a.ID)
	if got.Enabled {
		t.Fatal("admin should be disabled")
	}

	if err := s.DeleteWebAdmin(ctx, a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetWebAdmin(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestWebAdminLoginCounter(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{
		Username:     "bob",
		PasswordHash: dummyPwdHash,
	})

	for i := int64(1); i <= 4; i++ {
		failed, lockUntil, err := s.RecordWebAdminLoginFailure(ctx, a.ID, 5, 900)
		if err != nil {
			t.Fatalf("failure i=%d: %v", i, err)
		}
		if failed != i {
			t.Fatalf("failed=%d want %d", failed, i)
		}
		if lockUntil != 0 {
			t.Fatalf("should not lock yet at i=%d, lockUntil=%d", i, lockUntil)
		}
	}
	failed, lockUntil, err := s.RecordWebAdminLoginFailure(ctx, a.ID, 5, 900)
	if err != nil {
		t.Fatalf("5th failure: %v", err)
	}
	if failed != 5 || lockUntil == 0 {
		t.Fatalf("5th failure should lock: failed=%d lockUntil=%d", failed, lockUntil)
	}

	if err := s.RecordWebAdminLoginSuccess(ctx, a.ID, "10.0.0.1"); err != nil {
		t.Fatalf("success: %v", err)
	}
	got, _ := s.GetWebAdmin(ctx, a.ID)
	if got.FailedLogins != 0 || got.LockedUntil != 0 || got.LastLoginIP != "10.0.0.1" || got.LastLoginAt == 0 {
		t.Fatalf("login success not recorded: %+v", got)
	}
}

func TestWebSessionLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{
		Username:     "alice",
		PasswordHash: dummyPwdHash,
	})

	sid := "abc123_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := s.CreateWebSession(ctx, WebSession{
		ID:        sid,
		AdminID:   a.ID,
		ExpiresAt: nowUnix() + 3600,
		IP:        "10.0.0.2",
		UserAgent: "test-ua",
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	got, err := s.GetWebSession(ctx, sid)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.AdminID != a.ID {
		t.Fatalf("admin id mismatch: %d != %d", got.AdminID, a.ID)
	}

	// 过期 session 取不到
	expired := "expired_session_id_xxxxxxxxxxxxxxxxxxxxxx"
	_ = s.CreateWebSession(ctx, WebSession{
		ID: expired, AdminID: a.ID, ExpiresAt: 1,
	})
	if _, err := s.GetWebSession(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for expired, got %v", err)
	}

	// prune 把过期的清掉
	if n, err := s.PruneExpiredWebSessions(ctx); err != nil || n != 1 {
		t.Fatalf("prune: n=%d err=%v", n, err)
	}

	// admin 删除应 CASCADE 把 session 一起删
	if err := s.DeleteWebAdmin(ctx, a.ID); err != nil {
		t.Fatalf("delete admin: %v", err)
	}
	if _, err := s.GetWebSession(ctx, sid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session should be cascade-deleted, got %v", err)
	}
}
