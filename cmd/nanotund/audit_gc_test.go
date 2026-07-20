package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// TestRunAuditGCLoop_DeletesOldRows 写入老 / 新两条 audit,跑 prune 后只剩新条。
func TestRunAuditGCLoop_DeletesOldRows(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "audit_gc.db")
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// 写两条 audit
	if err := st.Audit(ctx, "1.2.3.4", "login.success", "u1", ""); err != nil {
		t.Fatalf("Audit 1: %v", err)
	}
	if err := st.Audit(ctx, "1.2.3.4", "login.fail.bad_psk", "", ""); err != nil {
		t.Fatalf("Audit 2: %v", err)
	}

	// cutoff = 现在,删掉所有(at < now);Audit 写入用 nowUnix(),刚写完 at <= now,有可能 cutoff == at,
	// 走 `<` 谓词会保留刚写的;为了让本测试有可重复结果,我们用 cutoff = now + 1
	// (即「未来一秒之前的全删」)。
	cutoff := time.Now().Add(time.Second).Unix()
	n, err := st.PruneAuditBefore(ctx, cutoff)
	if err != nil {
		t.Fatalf("PruneAuditBefore: %v", err)
	}
	if n != 2 {
		t.Fatalf("pruned %d, want 2", n)
	}

	total, err := st.CountAudit(ctx)
	if err != nil {
		t.Fatalf("CountAudit: %v", err)
	}
	if total != 0 {
		t.Fatalf("after prune total=%d, want 0", total)
	}
}

// TestRunAuditGCLoop_RespectsCtxCancel 启动 loop -> 立刻取消 ctx -> 应当 < 200ms 退出。
func TestRunAuditGCLoop_RespectsCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dbPath := filepath.Join(t.TempDir(), "audit_gc_cancel.db")
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 长 interval,等 ctx 取消打断
		runAuditGCLoop(ctx, st, 24*time.Hour, time.Hour)
	}()

	time.Sleep(20 * time.Millisecond) // 给 goroutine 一点起步时间
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runAuditGCLoop 未在 ctx 取消后退出")
	}
}

// TestPruneAuditBefore_NilSafe 调用方很可能传 nil store / 0 cutoff,函数应当不 panic。
func TestPruneAuditBefore_NilSafe(t *testing.T) {
	var s *store.Store
	if _, err := s.PruneAuditBefore(context.Background(), 0); err == nil {
		t.Fatal("PruneAuditBefore on nil store should error")
	}
	if _, err := s.CountAudit(context.Background()); err == nil {
		t.Fatal("CountAudit on nil store should error")
	}
}
