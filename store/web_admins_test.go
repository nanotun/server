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

// TestWebAdminAdminFloorGuard 覆盖第四轮深扫 HIGH(last-admin TOCTOU):禁用 / 删除 / 降级最后一个
// enabled admin 必须返回 ErrLastAdmin 且**不改变**数据(事务回滚);有备用 admin 时正常放行。
func TestWebAdminAdminFloorGuard(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	a1, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "admin1", PasswordHash: dummyPwdHash, Role: "admin"})
	if err != nil {
		t.Fatalf("create admin1: %v", err)
	}

	// 只有一个 enabled admin:禁用 / 删除 / 降级都应被拒(ErrLastAdmin)。
	if err := s.SetWebAdminEnabledEnsuringAdmin(ctx, a1.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin: want ErrLastAdmin, got %v", err)
	}
	if err := s.SetWebAdminRoleEnsuringAdmin(ctx, a1.ID, "viewer"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: want ErrLastAdmin, got %v", err)
	}
	if err := s.DeleteWebAdminEnsuringAdmin(ctx, a1.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: want ErrLastAdmin, got %v", err)
	}
	// 被拒后必须仍是 enabled admin(回滚生效)。
	got, err := s.GetWebAdmin(ctx, a1.ID)
	if err != nil {
		t.Fatalf("reload admin1: %v", err)
	}
	if !got.Enabled || got.Role != "admin" {
		t.Fatalf("被拒操作不应改数据,got enabled=%v role=%q", got.Enabled, got.Role)
	}

	// 加第二个 admin 后,禁用第一个应成功(仍剩一个 enabled admin)。
	if _, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "admin2", PasswordHash: dummyPwdHash, Role: "admin"}); err != nil {
		t.Fatalf("create admin2: %v", err)
	}
	if err := s.SetWebAdminEnabledEnsuringAdmin(ctx, a1.ID); err != nil {
		t.Fatalf("disable admin1 with a spare admin present: %v", err)
	}
	// 现在又只剩 admin2 一个 enabled admin:再删它应被拒。
	n, err := s.CountEnabledWebAdminsByRole(ctx, "admin")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("应只剩 1 个 enabled admin,got %d", n)
	}

	// 不存在的 id → ErrNotFound(区别于 ErrLastAdmin)。
	if err := s.SetWebAdminEnabledEnsuringAdmin(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disable missing admin: want ErrNotFound, got %v", err)
	}
}

// TestRecordWebAdminLoginFailure_SlidingWindowDecay 覆盖第三轮深扫 M1:
//   - 窗口内连续失败会累积并在阈值处锁定;
//   - 距上次失败超过窗口(lockSeconds)后,单次失败被衰减为 1,**不**触发重锁(修永久 DoS);
//   - 成功登录清零计数与 last_failure_at。
func TestRecordWebAdminLoginFailure_SlidingWindowDecay(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// 可控时钟。
	orig := nowUnix
	var clock int64 = 1_000_000
	nowUnix = func() int64 { return clock }
	t.Cleanup(func() { nowUnix = orig })

	a, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "root", PasswordHash: dummyPwdHash})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	const maxFailures = 5
	const window = 900 // = lockSeconds

	// 窗口内连打 5 次:第 5 次触发锁定。
	var lastFailed, lastLock int64
	for i := 1; i <= maxFailures; i++ {
		clock += 10 // 均在窗口内
		lastFailed, lastLock, err = s.RecordWebAdminLoginFailure(ctx, a.ID, maxFailures, window)
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if lastFailed != int64(i) {
			t.Fatalf("failure %d: failed_logins=%d, want %d", i, lastFailed, i)
		}
	}
	if lastLock == 0 {
		t.Fatal("第 5 次失败应触发锁定(locked_until>0)")
	}

	// 模拟锁定窗口过去:下一次失败必须被衰减为 1,且**不**重锁。
	clock += window + 1
	failed, lock, err := s.RecordWebAdminLoginFailure(ctx, a.ID, maxFailures, window)
	if err != nil {
		t.Fatalf("post-window failure: %v", err)
	}
	if failed != 1 {
		t.Fatalf("窗口过后单次失败应衰减为 1,got %d(永久 DoS 回归!)", failed)
	}
	if lock != 0 {
		t.Fatalf("窗口过后单次失败不应重新锁定,got locked_until=%d", lock)
	}

	// 成功登录清零。
	if err := s.RecordWebAdminLoginSuccess(ctx, a.ID, "1.2.3.4"); err != nil {
		t.Fatalf("RecordSuccess: %v", err)
	}
	got, err := s.GetWebAdmin(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if got.FailedLogins != 0 || got.LockedUntil != 0 {
		t.Fatalf("成功后应清零,got failed=%d locked=%d", got.FailedLogins, got.LockedUntil)
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
