package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ACL 丢包审计的聚合桶。
//
// 这套东西存在的意义是「丢包要能查」,但它自己跑在数据面热路径上,所以它的失效方式是**把服务
// 拖垮**而不是少记一条日志:每个 (src,dst,proto,port,kind) 组合一个桶,一次端口扫描就能塞进
// 六万多个桶。所以有个基数上限,超了以后新组合折叠进单一 overflow 桶 —— 数目仍如实累计,只是
// 不再细分维度。这批用例钉的就是这条上限真的在,以及 flush / target 命名不会因此错乱。

// resetACLDropBuckets 清空聚合桶与基数计数(全局状态)。
func resetACLDropBuckets(t *testing.T) {
	t.Helper()
	clear := func() {
		aclDropAggBuckets.Range(func(k, _ any) bool {
			aclDropAggBuckets.Delete(k)
			return true
		})
		aclDropAuditBucketCount.Store(0)
	}
	clear()
	t.Cleanup(clear)
}

func countACLDropBuckets() int {
	n := 0
	aclDropAggBuckets.Range(func(_, _ any) bool { n++; return true })
	return n
}

// TestRecordACLDrop_FoldsIntoOverflowInsteadOfExplodingTheMap 基数上限必须真的封住。
//
// 没有这条上限,一个客户端扫一遍端口就在 map 里留下六万多个桶 —— 而 flush 周期是 60s,这一分钟
// 里内存一路涨。折叠之后维度信息确实丢了(target 变 `<overflow>`),但丢包**数目**仍准确,
// 而且这种情形本身就说明「有人在扫端口」,细分维度也没有排障价值。
func TestRecordACLDrop_FoldsIntoOverflowInsteadOfExplodingTheMap(t *testing.T) {
	resetACLDropBuckets(t)

	// 假装已经到达上限(不必真塞 4096 个桶:计数器就是那道闸的输入)。
	aclDropAuditBucketCount.Store(aclDropAuditMaxBuckets)

	const scanPorts = 200
	for p := 0; p < scanPorts; p++ {
		recordACLDrop("user", 1, 2, "tcp", uint16(1000+p))
	}

	if n := countACLDropBuckets(); n != 1 {
		t.Fatalf("到达上限后又建了 %d 个桶,期望全部折叠进 1 个 overflow 桶 —— "+
			"一次端口扫描就能塞进六万多个桶,60s flush 周期内内存一路涨", n)
	}
	v, ok := aclDropAggBuckets.Load(aclDropOverflowKey)
	if !ok {
		t.Fatal("折叠进的不是 overflow 桶")
	}
	if got := v.(*aclDropBucket).count.Load(); got != scanPorts {
		t.Errorf("overflow 桶计数 %d,期望 %d —— 维度可以合并,数目不能丢", got, scanPorts)
	}
}

// TestRecordACLDrop_StillSplitsDimensionsBelowTheCap 上限以下要照常细分。
//
// 与上面配对:折叠只该在到达上限后发生。提前折叠等于永远只有一个 `<overflow>` 桶,审计里再也
// 看不出「谁到谁、什么协议被丢」,这套东西就白做了。
func TestRecordACLDrop_StillSplitsDimensionsBelowTheCap(t *testing.T) {
	resetACLDropBuckets(t)

	recordACLDrop("user", 1, 2, "tcp", 443)
	recordACLDrop("user", 1, 2, "tcp", 80)
	recordACLDrop("user", 1, 2, "tcp", 443) // 同组合 → 累加,不新建

	if n := countACLDropBuckets(); n != 2 {
		t.Fatalf("桶数 %d,期望 2(两个端口各一个,重复的那次并入)", n)
	}
	if got := aclDropAuditBucketCount.Load(); got != 2 {
		t.Errorf("基数计数 %d,期望 2 —— 计数漂了会让上限提前或永不触发", got)
	}
}

// TestACLDropAuditTarget_NamesEachKindReadably target 命名的三种形状。
//
// audit 里这一列是人排障时唯一的线索。exit 类丢包的「目的」不是某个用户而是公网出口,
// 硬塞一个 dst user id 会让人以为是用户间的规则拦的,查错方向。
func TestACLDropAuditTarget_NamesEachKindReadably(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  aclDropBucketKey
		want string
	}{
		{"折叠桶", aclDropOverflowKey, "<overflow>"},
		{"出口 ACL", aclDropBucketKey{kind: "exit_acl", srcUserID: 5, dstUserID: 9}, "<exit>"},
		{"出口闸", aclDropBucketKey{kind: "exit_gate", srcUserID: 5}, "<exit>"},
		{"来源未知", aclDropBucketKey{kind: "user", srcUserID: 0, dstUserID: 9}, "<unknown>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := aclDropAuditTarget(tc.key)
			if !strings.Contains(got, tc.want) {
				t.Errorf("target=%q,应含 %q", got, tc.want)
			}
		})
	}
}

// TestStartACLDropAuditFlusher_ClampsAndSkipsWithoutAStore 启动这条 goroutine 的两个前提。
//
// interval<=0 会让 time.NewTicker 直接 panic —— 那是进程级崩溃,而这个值来自配置。
// 没有 store 时必须 no-op:起了循环也只能对着 nil store 调 Audit。
func TestStartACLDropAuditFlusher_ClampsAndSkipsWithoutAStore(t *testing.T) {
	t.Run("没有 store 直接 no-op", func(t *testing.T) {
		startACLDropAuditFlusher(nil, time.Second)()
		startACLDropAuditFlusher(&gatewayState{}, time.Second)() // 不该 panic
	})

	t.Run("interval 非正数要夹取而不是 panic", func(t *testing.T) {
		resetACLDropBuckets(t)
		withTestGlobalContext(t)
		gw := newRouteTestGateway(t)
		// 夹取成默认的 60s,所以这条 goroutine 在用例生命周期内不会真 flush;
		// 关键是它没有因为 NewTicker(0) 把进程带走。
		stop := startACLDropAuditFlusher(gw, 0)
		t.Cleanup(stop)
	})
}

// TestRunACLDropAuditFlushLoop_FlushesOnTickAndToleratesANilContext 定时 flush 与 nil ctx。
//
// 定时那一下是这套统计唯一的落库时机(另一次是退出前补写)。它不动,审计里就永远只有进程退出
// 那一刻的数据 —— 长跑的服务等于完全没有丢包记录。
func TestRunACLDropAuditFlushLoop_FlushesOnTickAndToleratesANilContext(t *testing.T) {
	resetACLDropBuckets(t)
	gw := newRouteTestGateway(t)

	recordACLDrop("user", 1, 2, "tcp", 443)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runACLDropAuditFlushLoop(ctx, gw.store, 5*time.Millisecond)
	}()

	// 等定时 flush 把桶清空(flush 会 Swap(0) 并删掉空桶)。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && countACLDropBuckets() > 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if n := countACLDropBuckets(); n != 0 {
		t.Errorf("定时 flush 没落库(还剩 %d 个桶) —— 长跑的服务审计里就只有退出那一刻的数据", n)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ctx 取消后循环没退出")
	}

	t.Run("nil ctx 不崩", func(t *testing.T) {
		// 传 nil ctx 时内部要兜成 Background,否则 select 上直接 panic(空 ctx 的 Done() 是 nil
		// channel,读它会永久阻塞;但 ctx.Done() 本身就先 nil 解引用了)。
		//
		// 兜成 Background 的循环没法再取消,所以这里给一个长到不会触发的 interval:它会停在
		// select 上不再碰 store,用例结束时随进程一起走 —— 比让它每 5ms 去 flush 一个已关闭的
		// store 安全得多。
		go runACLDropAuditFlushLoop(nil, gw.store, time.Hour) //nolint:staticcheck // 就是要测 nil
		time.Sleep(20 * time.Millisecond)
		if countACLDropBuckets() != 0 {
			t.Error("nil ctx 那条循环不该动桶(长 interval 下它只该停在 select 上)")
		}
	})
}
