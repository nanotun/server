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

// TestDeleteDevice_KeepsPortForwardOfSameUUIDUnderOtherUser 覆盖第二十三轮深扫 MED:清理孤儿端口转发时只按
// UUID 匹配会误删别的用户的转发 —— device_uuid 仅在 UNIQUE(user_id, device_uuid) 内唯一,跨 user 允许同 UUID
// (GetDeviceByUUIDAny 撞多行回 ErrAmbiguousDevice 正是为此)。管理员为消解这种冲突而删掉后注册那台时,
// 不该动到先注册那位的转发。
func TestDeleteDevice_KeepsPortForwardOfSameUUIDUnderOtherUser(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const sharedUUID = "shared-uuid-collision"

	alice, err := s.CreateUser(ctx, NewUser{Username: "alice-pf", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	eve, err := s.CreateUser(ctx, NewUser{Username: "eve-pf", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertDevice(ctx, alice.ID, sharedUUID, "alice-box", "linux"); err != nil {
		t.Fatal(err)
	}
	eveDev, err := s.UpsertDevice(ctx, eve.ID, sharedUUID, "eve-box", "linux")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreatePortForward(ctx, PortForward{
		Proto: "tcp", PublicPort: 18080, TargetDeviceUUID: sharedUUID, TargetIP: "10.0.0.7", TargetPort: 80, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	// 删掉 Eve 那台(UUID 仍被 Alice 的设备持有)→ 转发必须保留。
	if err := s.DeleteDevice(ctx, eveDev.ID); err != nil {
		t.Fatal(err)
	}
	pfs, err := s.ListPortForwards(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pfs) != 1 {
		t.Fatalf("同 UUID 仍被别的用户的设备持有,转发不应被清:剩余 %d 条", len(pfs))
	}

	// 再删 Alice 那台 → UUID 彻底消失,此时才该清掉孤儿转发。
	aliceDev, err := s.GetDeviceByUUID(ctx, alice.ID, sharedUUID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDevice(ctx, aliceDev.ID); err != nil {
		t.Fatal(err)
	}
	pfs, err = s.ListPortForwards(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pfs) != 0 {
		t.Fatalf("UUID 已彻底消失,孤儿转发应被清:剩余 %d 条", len(pfs))
	}
}
