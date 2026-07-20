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
	if err := s.SetUserMaxSessions(ctx, 999999, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("未知 user 应 ErrNotFound,got %v", err)
	}
}
