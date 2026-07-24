package main

import (
	"fmt"
	"testing"
)

// TestIPFailureTracker_FailClosedOnCap(第十九轮深扫 MED):map 触顶后,**新** IP 的失败仍必须被记录(驱逐一个
// 旧 entry 腾位),而非静默丢弃 —— 否则攻击者先用上万个不同源 IP 灌满 map,真实攻击 IP 的失败会一起被丢,
// Count 冻结在 0、ComputeDifficulty 停在 base 难度(fail-open)。修复后应 fail-closed:新失败被记且 map 规模有界。
func TestIPFailureTracker_FailClosedOnCap(t *testing.T) {
	tr := NewIPFailureTracker()
	// 灌满到上限(全部窗口内,prune 无法回收)。
	for i := 0; i < maxTrackedIPs; i++ {
		tr.MarkFailure(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256))
	}
	if tr.Size() != maxTrackedIPs {
		t.Fatalf("灌满后 Size 应为 %d,实际 %d", maxTrackedIPs, tr.Size())
	}

	// 新 IP:必须被记录(fail-closed),不能被静默丢弃。
	const newIP = "203.0.113.7"
	tr.MarkFailure(newIP)
	if tr.Count(newIP) == 0 {
		t.Fatal("map 满时新 IP 的失败被静默丢弃(fail-open 回归):Count 应 > 0")
	}
	// 驱逐一个换一个:map 规模仍钉在上限,不无限膨胀。
	if tr.Size() > maxTrackedIPs {
		t.Fatalf("驱逐后 Size 不应超过上限 %d,实际 %d", maxTrackedIPs, tr.Size())
	}
}

// TestIPFailureTracker_ExistingIPBypassesCap 确认:map 已满时,**已在表内**的 IP 直接累加,不触发驱逐
// (合法用户重试 / 真实攻击 IP 一旦进表就不受灌表影响)。
func TestIPFailureTracker_ExistingIPBypassesCap(t *testing.T) {
	tr := NewIPFailureTracker()
	for i := 0; i < maxTrackedIPs-1; i++ {
		tr.MarkFailure(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256))
	}
	const hot = "198.51.100.9"
	tr.MarkFailure(hot) // 第 cap 个 entry → map 正好填满
	if tr.Size() != maxTrackedIPs {
		t.Fatalf("应正好填满:Size=%d want %d", tr.Size(), maxTrackedIPs)
	}
	// hot 已在表内:再失败一次应直接累加,不触发驱逐 → Size 不变、Count 递增。
	tr.MarkFailure(hot)
	if got := tr.Count(hot); got != 2 {
		t.Fatalf("已在表内的 IP 失败应累加到 2,实际 %d", got)
	}
	if tr.Size() != maxTrackedIPs {
		t.Fatalf("累加已在表内 IP 不应改变 map 规模:Size=%d want %d", tr.Size(), maxTrackedIPs)
	}
}
