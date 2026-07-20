package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// H2 regression:flush 应当把本轮 count=0 的 bucket 从 sync.Map 里删掉,
// 否则一个 port scan 一次就能塞 65k entries 永不释放,长跑内存增长。
func TestACLDropAggregates_FlushDeletesIdleBuckets(t *testing.T) {
	aclDropAggBuckets.Range(func(k, _ any) bool {
		aclDropAggBuckets.Delete(k)
		return true
	})

	// 灌 100 个不同 port 的一次性 drop。
	for port := uint16(1000); port < 1100; port++ {
		recordACLDrop("user", 1, 2, "tcp", port)
	}
	countBefore := 0
	aclDropAggBuckets.Range(func(_, _ any) bool { countBefore++; return true })
	if countBefore != 100 {
		t.Fatalf("setup: bucket count = %d, want 100", countBefore)
	}

	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "drop_agg_gc.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// 第一次 flush:把 count 全 Swap 到 0(并写 audit_logs)。
	flushACLDropAggregates(ctx, st)
	// 第二次 flush:本轮所有 bucket count=0,应当全部被 Delete。
	flushACLDropAggregates(ctx, st)

	countAfter := 0
	aclDropAggBuckets.Range(func(_, _ any) bool { countAfter++; return true })
	if countAfter != 0 {
		t.Fatalf("第二次 flush 后应清空 idle bucket,实际还剩 %d", countAfter)
	}

	// 再灌一次,验证 Delete 后 LoadOrStore 重建路径正常。
	recordACLDrop("user", 1, 2, "tcp", 1042)
	revived := 0
	aclDropAggBuckets.Range(func(_, _ any) bool { revived++; return true })
	if revived != 1 {
		t.Fatalf("Delete 后 recordACLDrop 应能重建 bucket,实际 %d", revived)
	}
}

func TestACLDropAggregates_AccumulateAndFlush(t *testing.T) {
	// 清空,避免被并行测试污染。
	aclDropAggBuckets.Range(func(k, _ any) bool {
		aclDropAggBuckets.Delete(k)
		return true
	})

	for i := 0; i < 5; i++ {
		recordACLDrop("user", 1, 2, "tcp", 22)
	}
	recordACLDrop("exit_gate", 1, 0, "udp", 53)

	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "drop_agg.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	flushACLDropAggregates(ctx, st)

	rows, err := st.QueryAudit(ctx, 0, time.Now().Add(time.Minute).Unix(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var aggCount int
	for _, r := range rows {
		if r.Action == "acl_drop_agg" {
			aggCount++
		}
	}
	if aggCount < 2 {
		t.Fatalf("expected at least 2 acl_drop_agg rows, got %d (rows=%+v)", aggCount, rows)
	}

	// 二次 flush 应当看不到新行(bucket 已清零)。
	flushACLDropAggregates(ctx, st)
	rows2, _ := st.QueryAudit(ctx, 0, time.Now().Add(time.Minute).Unix(), 50)
	var aggCount2 int
	for _, r := range rows2 {
		if r.Action == "acl_drop_agg" {
			aggCount2++
		}
	}
	if aggCount2 != aggCount {
		t.Fatalf("second flush should not add rows, got %d → %d", aggCount, aggCount2)
	}
}

func TestRunACLDropAuditFlushLoop_ExitsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "drop_loop.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		runACLDropAuditFlushLoop(ctx, st, 100*time.Millisecond)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop did not exit within 1s of ctx cancel")
	}
}
