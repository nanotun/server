package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// TestRunLeaseGCLoop_PrunesIdle 验证 runLeaseGCLoop 启动时立刻跑一次回收。
// 用 idle=1s + 一个 last_seen=2s 前的 device + 它的 lease,跑一次后 lease 应被删,
// device 行保留(GcOrphanLeases 文档承诺)。
func TestRunLeaseGCLoop_PrunesIdle(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "lease_gc.db"), store.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	u, err := st.CreateUser(ctx, store.NewUser{Username: "lg", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "1b1f25fc-3a45-4d80-8d9b-30a6f7c5e8a1", "Mac", "darwin")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	_, err = st.UpsertLease(ctx, dev.ID, "10.0.0.99", "", false)
	if err != nil {
		t.Fatalf("upsert lease: %v", err)
	}
	// 把 device.last_seen_at 后退 5s 让回收条件命中。
	if _, err := st.DB().ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE id = ?`, time.Now().Add(-5*time.Second).Unix(), dev.ID); err != nil {
		t.Fatal(err)
	}

	loopCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	// idle=1s, interval=10s — interval 不重要,runLeaseGCLoop 进入立刻 doOnce 一次,
	// 然后被 loopCtx 50ms 后 ctx.Done 退出。
	runLeaseGCLoop(loopCtx, st, 1*time.Second, 10*time.Second)

	// lease 应已删除。
	rows, err := st.DB().QueryContext(ctx, `SELECT COUNT(*) FROM leases WHERE device_id=?`, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var n int
	if rows.Next() {
		_ = rows.Scan(&n)
	}
	if n != 0 {
		t.Fatalf("expected lease cleared, got %d", n)
	}
}

// E1:lease_gc 跑之前必须先 BatchTouchDevices,active session 持有的 device
// 不应被回收(过去 30 天没登录但 session 一直在线的场景)。
func TestRunLeaseGCLoop_ActiveSessionProtected(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "lease_gc_active.db"), store.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	u, _ := st.CreateUser(ctx, store.NewUser{Username: "longlife", PSKHash: "h"})
	dev, _ := st.UpsertDevice(ctx, u.ID, "11111111-2222-4333-8444-555555555555", "Server", "linux")
	_, _ = st.UpsertLease(ctx, dev.ID, "10.0.0.100", "", false)

	// device.last_seen_at 故意推到 5s 前(超出 idle=1s)。
	if _, err := st.DB().ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE id = ?`, time.Now().Add(-5*time.Second).Unix(), dev.ID); err != nil {
		t.Fatal(err)
	}

	// 安装一条 active conn,deviceID 指向这个 device。
	c := &Connection{connIDStr: "active-1", userID: userIDFromStoreID(u.ID), deviceID: dev.ID, tunnelDone: make(chan struct{})}
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connByUserAddLocked(c)
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, c.connIDStr)
		connByUserDeleteLocked(c)
		connIDMapMu.Unlock()
	})

	loopCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	runLeaseGCLoop(loopCtx, st, 1*time.Second, 10*time.Second)

	rows, err := st.DB().QueryContext(ctx, `SELECT COUNT(*) FROM leases WHERE device_id=?`, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var n int
	if rows.Next() {
		_ = rows.Scan(&n)
	}
	if n != 1 {
		t.Fatalf("active session 的 lease 不应被回收, got count=%d", n)
	}
}
