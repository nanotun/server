package store

import (
	"errors"
	"testing"
)

// TestSetUserMaxSessions:0021 按账号会话上限的读写与参数校验。
func TestSetUserMaxSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u, err := s.CreateUser(ctx, NewUser{Username: "cap-user", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.MaxSessions != 0 {
		t.Fatalf("新建默认应跟随全局(=0),got %d", u.MaxSessions)
	}

	for _, n := range []int{5, -1, 0, 20} {
		if err := s.SetUserMaxSessions(ctx, u.ID, n); err != nil {
			t.Fatalf("SetUserMaxSessions(%d): %v", n, err)
		}
		got, err := s.GetUser(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if got.MaxSessions != n {
			t.Fatalf("MaxSessions=%d, want %d", got.MaxSessions, n)
		}
	}

	if err := s.SetUserMaxSessions(ctx, u.ID, -2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("<-1 应 ErrInvalid,got %v", err)
	}
	if err := s.SetUserMaxSessions(ctx, u.ID, MaxSessionsCap+1); !errors.Is(err, ErrInvalid) {
		t.Fatalf(">MaxSessionsCap 应 ErrInvalid,got %v", err)
	}
	if err := s.SetUserMaxSessions(ctx, 999999, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("未知 user 应 ErrNotFound,got %v", err)
	}
}

// TestPruneWebSessionsKeepingRecent_ExcludesExpired 第十五轮深扫 MED:keep-set 只在**有效**会话里取最近 keep
// 条 —— 一条 created_at 较新但已过期(或超绝对上限)的死会话不占 keep 名额、不再挤掉一条仍有效的较旧会话,
// 且死行被顺带即时回收。
func TestPruneWebSessionsKeepingRecent_ExcludesExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "prune_admin", PasswordHash: dummyPwdHash})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	now := nowUnix()
	mk := func(id string, createdAt, expiresAt int64) {
		t.Helper()
		if err := s.CreateWebSession(ctx, WebSession{
			ID: id, AdminID: a.ID, CreatedAt: createdAt, LastSeenAt: createdAt, ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	const (
		validOld   = "sess_valid_old_aaaaaaaaaaaaaaaaaaaaaaaaaa"
		expiredNew = "sess_expired_new_bbbbbbbbbbbbbbbbbbbbbbbbb"
		validNew   = "sess_valid_new_cccccccccccccccccccccccccc"
	)
	mk(validOld, now-100, now+3600) // 有效,created_at 最旧
	mk(expiredNew, now-10, now-1)   // 已过期(expires_at 过去),created_at 较新
	mk(validNew, now, now+3600)     // 有效,最新

	// keep=2:旧实现 keep-set 按 created_at 取前 2 = {validNew, expiredNew} → 误删仍有效的 validOld。
	// 新实现只在有效会话里取前 2 = {validNew, validOld} → 删掉过期的 expiredNew。
	if _, err := s.PruneWebSessionsKeepingRecent(ctx, a.ID, 2); err != nil {
		t.Fatalf("prune: %v", err)
	}
	exists := func(id string) bool {
		var n int
		if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM web_sessions WHERE id=?`, id).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", id, err)
		}
		return n > 0
	}
	if !exists(validOld) {
		t.Fatal("仍有效的较旧会话不应被删(不该被过期死会话挤掉 keep 名额)")
	}
	if !exists(validNew) {
		t.Fatal("最新有效会话应保留")
	}
	if exists(expiredNew) {
		t.Fatal("已过期死会话应被回收(不占 keep 名额)")
	}
}
