package main

import (
	"fmt"
	"testing"
)

// TestIPFailureTracker_SizeCap 覆盖第三轮深扫 L7:新 IP 数受 maxTrackedIPs 软上限约束,
// 跨 IP 洪泛无法把 map 撑到无限大;已存在 IP 的快路径仍正常累加。
func TestIPFailureTracker_SizeCap(t *testing.T) {
	tr := NewIPFailureTracker()

	// 灌入远超上限的不同 IP(全是新鲜失败,Prune 无法回收 → 触发 evict-on-insert)。
	for i := 0; i < maxTrackedIPs+500; i++ {
		tr.Inc(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	if got := tr.size.Load(); got > maxTrackedIPs {
		t.Fatalf("size=%d 超过软上限 %d(map 无界回归)", got, maxTrackedIPs)
	}

	// 第四轮深扫 MED:map 满时新 IP 必须**仍被追踪**(fail-closed),不能返回 0 把 PoW 信号丢掉。
	// 否则 attacker 灌满 map 后用真实 IP 免 PoW。
	if n := tr.Inc("198.51.100.7"); n != 1 {
		t.Fatalf("map 满时新 IP 仍应被追踪(Inc 返回 1),got %d —— fail-open 回归!", n)
	}
	if got := tr.Recent("198.51.100.7"); got != 1 {
		t.Fatalf("满表驱逐后新 IP 的 Recent 应为 1,got %d", got)
	}

	// 已存在 IP 的快路径仍能累加(不受上限影响)。
	tr2 := NewIPFailureTracker()
	const ip = "203.0.113.9"
	if n := tr2.Inc(ip); n != 1 {
		t.Fatalf("first Inc=%d, want 1", n)
	}
	if n := tr2.Inc(ip); n != 2 {
		t.Fatalf("second Inc=%d, want 2", n)
	}
	if got := tr2.Recent(ip); got != 2 {
		t.Fatalf("Recent=%d, want 2", got)
	}
}
