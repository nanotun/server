package store

import (
	"testing"
	"time"
)

// E1:BatchTouchDevices 把 ids 列表里的 device 全部刷成 now;空 ids 不报错。
func TestBatchTouchDevices(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d1, err := s.UpsertDevice(ctx, u.ID, "uuid-1", "m1", "linux")
	if err != nil {
		t.Fatal(err)
	}
	d2, err := s.UpsertDevice(ctx, u.ID, "uuid-2", "m2", "linux")
	if err != nil {
		t.Fatal(err)
	}
	d3, err := s.UpsertDevice(ctx, u.ID, "uuid-3", "m3", "linux")
	if err != nil {
		t.Fatal(err)
	}

	// 把 d1, d2 推到 5s 前;d3 留在 now。
	old := time.Now().Add(-5 * time.Second).Unix()
	if _, err := s.DB().ExecContext(ctx, `UPDATE devices SET last_seen_at=? WHERE id IN (?,?)`, old, d1.ID, d2.ID); err != nil {
		t.Fatal(err)
	}

	if err := s.BatchTouchDevices(ctx, []int64{d1.ID, d2.ID}); err != nil {
		t.Fatal(err)
	}

	// 验证 d1, d2 被刷新到 ~now;d3 不动(应该已经 ~now)。
	rows, err := s.DB().QueryContext(ctx, `SELECT id, last_seen_at FROM devices WHERE id IN (?,?,?)`, d1.ID, d2.ID, d3.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	gotByID := map[int64]int64{}
	for rows.Next() {
		var id, seen int64
		_ = rows.Scan(&id, &seen)
		gotByID[id] = seen
	}
	now := time.Now().Unix()
	for _, id := range []int64{d1.ID, d2.ID, d3.ID} {
		if got := gotByID[id]; got < now-2 || got > now+2 {
			t.Fatalf("device %d last_seen_at=%d 不在 now±2 范围", id, got)
		}
	}
}

func TestBatchTouchDevices_EmptyNoop(t *testing.T) {
	s := newTestStore(t)
	if err := s.BatchTouchDevices(t.Context(), nil); err != nil {
		t.Fatalf("empty 应返回 nil, got %v", err)
	}
}
