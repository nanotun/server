package main

import (
	"fmt"
	"testing"
	"time"
)

// 这张表决定每个源 IP 的 PoW 难度,也就是暴破一个账号的实际代价。它的失效方式都不报错:
//
//   - 空 IP 若被当成一个正常键,所有「取不到对端地址」的失败会堆到同一个键上,而那个键不属于任何人。
//     难度按它计算的话,受害者是下一个恰好也取不到地址的连接;更糟的是真正的攻击 IP 的失败被分流走了。
//   - 单 IP 的失败列表若不截断,一个 IP 灌几十万次失败就能让每次 Count 扫一条长列表(持锁),
//     而难度早在 32 次就顶到上限了 —— 多存的部分只有成本没有收益。
//   - Prune 若把「窗口内还有效的项」一起丢掉,难度会在攻击进行中被重置回 base,自适应等于没有。

// TestIPFailureTracker_IgnoresTheEmptyKeyEverywhere 三个入口都必须无视空 IP。
func TestIPFailureTracker_IgnoresTheEmptyKeyEverywhere(t *testing.T) {
	tr := NewIPFailureTracker()

	tr.MarkFailure("")
	if tr.Size() != 0 {
		t.Fatalf("空 IP 建了表项(size=%d)—— 所有取不到对端地址的失败会堆到同一个不属于任何人的键上", tr.Size())
	}
	if got := tr.Count(""); got != 0 {
		t.Errorf("空 IP 的失败数 = %d,want 0", got)
	}

	// 有真实条目时,空 IP 的操作不该动到它们。
	tr.MarkFailure("203.0.113.9")
	before := tr.Count("203.0.113.9")
	tr.MarkFailure("")
	tr.MarkSuccess("")
	if got := tr.Count("203.0.113.9"); got != before {
		t.Errorf("空 IP 的操作改动了真实条目(%d → %d)", before, got)
	}
}

// TestIPFailureTracker_CapsOneIPsListWithoutLosingTheRecentOnes 单 IP 截断保留较新的。
func TestIPFailureTracker_CapsOneIPsListWithoutLosingTheRecentOnes(t *testing.T) {
	tr := NewIPFailureTracker()
	const ip = "198.51.100.7"
	for i := 0; i < maxFailuresPerIP*3; i++ {
		tr.MarkFailure(ip)
	}
	if got := tr.Count(ip); got != maxFailuresPerIP {
		t.Fatalf("失败列表长度 = %d,want 上限 %d —— 不截断的话一个 IP 灌几十万次就能让每次 Count 持锁扫长列表,而难度早已顶格",
			got, maxFailuresPerIP)
	}
}

// TestIPFailureTracker_MarkSuccessHalvesInsteadOfClearing 成功一次是减半,不是清零。
//
// 清零会把 NAT 后的场景做成免费通道:攻击者与合法用户共用出口 IP,合法用户每成功登录一次就把
// 攻击者积累的难度抹平。减半既让正常用户几次之后恢复 base 体验,又让攻击者的成本不会归零。
func TestIPFailureTracker_MarkSuccessHalvesInsteadOfClearing(t *testing.T) {
	tr := NewIPFailureTracker()
	const ip = "198.51.100.20"
	for i := 0; i < 8; i++ {
		tr.MarkFailure(ip)
	}
	tr.MarkSuccess(ip)
	if got := tr.Count(ip); got != 4 {
		t.Fatalf("成功一次后剩 %d 条,want 4(减半)—— 清零会让 NAT 后的攻击者靠别人的成功登录抹平自己的成本", got)
	}

	// 只剩一条时直接清掉,省一个 map entry。
	tr2 := NewIPFailureTracker()
	tr2.MarkFailure("198.51.100.21")
	tr2.MarkSuccess("198.51.100.21")
	if tr2.Size() != 0 {
		t.Errorf("只剩一条时没把表项删掉,size=%d", tr2.Size())
	}
}

// TestIPFailureTracker_PruneKeepsWhatIsStillInsideTheWindow 只砍过期的,窗口内的要留。
func TestIPFailureTracker_PruneKeepsWhatIsStillInsideTheWindow(t *testing.T) {
	tr := NewIPFailureTracker()
	const ip = "192.0.2.44"
	now := time.Now()
	// 手工塞一条「两条早已过期 + 两条还在窗口内」的列表:Prune 之后必须只剩后两条。
	tr.mu.Lock()
	tr.entries[ip] = []time.Time{
		now.Add(-2 * ipFailureWindow),
		now.Add(-ipFailureWindow - time.Minute),
		now.Add(-time.Second),
		now,
	}
	tr.mu.Unlock()

	tr.Prune()

	if got := tr.Count(ip); got != 2 {
		t.Fatalf("Prune 后窗口内还剩 %d 条,want 2 —— 连有效项一起丢掉的话,难度会在攻击进行中被重置回 base", got)
	}
	if tr.Size() == 0 {
		t.Error("整条表项被删了 —— 这个 IP 的自适应难度直接归零")
	}

	// 全部过期的表项要整条删掉,否则表只增不减。
	tr.mu.Lock()
	tr.entries["192.0.2.45"] = []time.Time{now.Add(-3 * ipFailureWindow)}
	tr.mu.Unlock()
	tr.Prune()
	if got := tr.Count("192.0.2.45"); got != 0 {
		t.Errorf("全过期的表项没被清掉,还报 %d 条", got)
	}
}

// TestIPFailureTracker_NewIPsStillGetRecordedWhenTheTableIsFull 表满时也要记下新 IP 的失败。
//
// 这是第 19 轮修过的 fail-open:表满就丢弃新失败,于是攻击者先用上万个源 IP 把表灌满,之后
// 自己那个 IP 的失败一条都不被记录 → 难度冻在 base,自适应 PoW 整体失效。
func TestIPFailureTracker_NewIPsStillGetRecordedWhenTheTableIsFull(t *testing.T) {
	tr := NewIPFailureTracker()
	for i := 0; i < maxTrackedIPs; i++ {
		tr.MarkFailure(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256))
	}
	if tr.Size() != maxTrackedIPs {
		t.Fatalf("前置条件不成立:表里 %d 条,期望灌满到 %d", tr.Size(), maxTrackedIPs)
	}

	const attacker = "203.0.113.200"
	tr.MarkFailure(attacker)
	if got := tr.Count(attacker); got == 0 {
		t.Fatal("表满之后新 IP 的失败被丢弃 —— 攻击者先灌表就能让自己的失败不被记录,自适应难度冻在 base")
	}
	if tr.Size() > maxTrackedIPs {
		t.Errorf("表涨到 %d 条,超过上限 %d —— 内存无上界", tr.Size(), maxTrackedIPs)
	}
}
