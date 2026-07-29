package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 审计表的回收循环失效时,现象是磁盘慢慢被吃掉:audit_logs 只增不删,几个月后 DB 涨到几个 G,
// 而每次登录都要往这张表写一行 —— 表越大写越慢,最后拖慢的是登录本身。
//
// 这条循环有三处必须成立:进来先跑一次(不等第一个 tick,否则 interval 是 24h 的部署重启一次就
// 等一天)、一次 DB 失败之后还要接着跑(瞬时错误不该永久停掉回收)、ctx 取消要立刻退出(不然
// shutdown 被一条正在跑的 DELETE 拖住)。

func auditGCStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "audit_guards.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return st
}

// TestRunAuditGCLoop_PrunesImmediatelyAndKeepsTicking 首轮不等 tick,之后按 interval 继续。
func TestRunAuditGCLoop_PrunesImmediatelyAndKeepsTicking(t *testing.T) {
	st := auditGCStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := st.Audit(ctx, "1.2.3.4", "login.success", "u1", ""); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// retention 取负值 → cutoff 落在一秒之后,刚写的行都算过期(audit 时间戳是秒级的,
		// 取 0 会卡在「at == cutoff、谓词是严格小于」这个边界上)。interval 很短,好观察第二轮。
		runAuditGCLoop(ctx, st, -time.Second, 20*time.Millisecond)
	}()

	// 第一轮必须在「一个 interval 之内」就发生 —— 它不等 tick。
	waitAuditCount(t, st, 0, time.Second)

	// 再写一行,它应当在下一个 tick 被收掉,证明循环真的在转(而不是只跑了开头那一次)。
	if err := st.Audit(ctx, "1.2.3.4", "login.fail.bad_psk", "", ""); err != nil {
		t.Fatal(err)
	}
	waitAuditCount(t, st, 0, 2*time.Second)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后没退出 —— shutdown 会被这条循环拖住")
	}
}

// TestRunAuditGCLoop_KeepsGoingAfterADBFailure 一次 DB 失败不许永久停掉回收。
func TestRunAuditGCLoop_KeepsGoingAfterADBFailure(t *testing.T) {
	st := auditGCStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 关掉库:这一轮 prune 必然报错。循环必须扛住,而不是 return 掉。
	_ = st.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runAuditGCLoop(ctx, st, 0, 10*time.Millisecond)
	}()

	// 给它几个 tick 的时间:若第一次报错就退出,done 会提前关。
	select {
	case <-done:
		t.Fatal("一次 DB 失败就退出了循环 —— 之后再也不会回收,磁盘只增不减")
	case <-time.After(150 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后没退出")
	}
}

// TestRunAuditGCLoop_NilCtxStillWorks 传 nil ctx 不许 panic。
//
// 这条循环的 ctx 来自进程级全局,启动早期(或测试里)可能还是 nil。在 select 上用 nil ctx
// 会直接 panic,把整条 goroutine 带走 —— 而它是 safeGlobalGoroutine 包着的,后果是
// 进程级 cancel 被触发,server 直接停机。
func TestRunAuditGCLoop_NilCtxStillWorks(t *testing.T) {
	st := auditGCStore(t)
	if err := st.Audit(context.Background(), "1.2.3.4", "login.success", "u1", ""); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// retention 取负值 → cutoff 落在一秒之后。audit 的时间戳是秒级的,刚写的行 at 很可能
		// 正好等于 now,用 0 会因为谓词是严格小于而留下它 —— 这里要验的是「循环有没有跑」,
		// 不该被这个边界干扰。
		//nolint:staticcheck // 这里就是要传 nil ctx
		runAuditGCLoop(nil, st, -time.Second, time.Hour)
	}()
	waitAuditCount(t, st, 0, 2*time.Second)
	// 循环本身不会退(interval 一小时、ctx 永不取消),用例到此为止即可 —— 关键是它没 panic
	// 且真的 prune 了一次。
	select {
	case <-done:
		t.Fatal("nil ctx 下循环提前退出了")
	default:
	}
}

// TestStartAuditGC_NoStoreIsANoop 没有 store 时必须是干净的 no-op(且 cleanup 不为 nil)。
func TestStartAuditGC_NoStoreIsANoop(t *testing.T) {
	stop := startAuditGC(nil)
	if stop == nil {
		t.Fatal("返回了 nil cleanup —— 调用方 defer 它就是 panic")
	}
	stop()
}

func waitAuditCount(t *testing.T, st *store.Store, want int64, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var last int64 = -1
	for time.Now().Before(deadline) {
		n, err := st.CountAudit(context.Background())
		if err == nil {
			last = n
			if n == want {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等了 %v,audit_logs 仍是 %d 行(want %d)—— 回收没发生", within, last, want)
}
