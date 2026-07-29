package main

import (
	"fmt"
	"testing"
	"time"
)

// 防重放表与失败追踪表都只在内存里,清扫是它们唯一的上界。停了不报错:PoW 照常出题验题,
// 只是这两张表随每次登录尝试单调增长 —— 一台被持续灌登录的 server 会慢慢吃满内存,
// 最后 OOM 被 systemd 拉起,现场只留下一条 oom-kill,看不出跟 PoW 有任何关系。
//
// (「stop 关闭立刻退出」与单次 pruneExpired 已由 TestPoWService_GCRemovesExpiredReplayEntriesAndStopsOnSignal
// 钉住;这里补的是「每一拍都清」——只在进循环时清一次的实现在那条用例里同样是绿的。)

// TestPoWRunGC_KeepsPruningOnEveryTick 每一拍都要真清,而不是只清第一次。
func TestPoWRunGC_KeepsPruningOnEveryTick(t *testing.T) {
	old := powGCInterval
	t.Cleanup(func() { powGCInterval = old })
	powGCInterval = 20 * time.Millisecond

	svc, err := NewPoWService(make([]byte, 32), NewIPFailureTracker(), 1, 8, 14, 2, 22, 300)
	if err != nil {
		t.Fatalf("NewPoWService: %v", err)
	}

	stop := make(chan struct{})
	go svc.RunGC(stop)
	t.Cleanup(func() { close(stop) })

	// 连续两轮都塞一批「早已过期」的 challenge,每轮都必须被清掉 ——
	// 只在进循环时清一次的实现会在第二轮留下垃圾。
	for round := 0; round < 2; round++ {
		expired := time.Now().Add(-time.Hour).Unix()
		for i := 0; i < 8; i++ {
			svc.powUsed.Store(fmt.Sprintf("chal-%d-%d", round, i), expired)
		}
		deadline := time.Now().Add(3 * time.Second)
		for svc.powUsedCount() > 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if n := svc.powUsedCount(); n != 0 {
			t.Fatalf("第 %d 轮之后防重放表里还剩 %d 条过期项 —— 清扫只跑了一次,"+
				"这张表会随每次登录尝试单调增长,最后 OOM,而现场只留一条 oom-kill", round+1, n)
		}
	}
}
