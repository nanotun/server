package main

import (
	"fmt"
	"testing"
)

// TestIPFailureTracker_SizeCap 覆盖第三轮深扫 L7:新 IP 数受 maxTrackedIPs 软上限约束,
// 跨 IP 洪泛无法把 map 撑到无限大;已存在 IP 的快路径仍正常累加。
func TestIPFailureTracker_SizeCap(t *testing.T) {
	tr := NewIPFailureTracker()

	// 灌入远超上限的不同 IP(全是新鲜失败,Prune 无法回收 → 触发丢弃)。
	for i := 0; i < maxTrackedIPs+500; i++ {
		tr.Inc(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	if got := tr.size.Load(); got > maxTrackedIPs {
		t.Fatalf("size=%d 超过软上限 %d(map 无界回归)", got, maxTrackedIPs)
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
