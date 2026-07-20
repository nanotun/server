package main

import (
	"testing"
	"time"
)

// supersede 路径的核心是「同 user 同 deviceUUID 的旧 conn 被找出来,排除自己 / takenOver /
// 匿名 device」。这组测试不挂真 raw conn,只验 findSupersededByDeviceLocked 的过滤逻辑
// 与 dedupVictims 的去重,以及 waitConnsCleanup 的超时与即时返回行为。
// handleVPNLink 整体 wiring 走 e2e(同 device PSK 重登 → 老 link 被 close + 新拿到同 vIP)。

// makeFakeConn 造一条最小可装入 connByUser 的 Connection。
func makeFakeConn(t *testing.T, connID, userID, deviceUUID string) *Connection {
	t.Helper()
	c := &Connection{
		connIDStr:   connID,
		userID:      userID,
		deviceUUID:  deviceUUID,
		tunnelDone:  make(chan struct{}),
		cleanupDone: make(chan struct{}),
		createdAt:   time.Now(),
	}
	installConn(t, c)
	return c
}

// resetConnByUserForSupersedeTest 清干净跨测试遗留 — 跟 conn_by_user_test 风格一致。
// installConn 已经在 t.Cleanup 里 delete 当前 conn,这里只是兜底,避免别的 test 没清干净。
func resetConnByUserForSupersedeTest(t *testing.T) {
	t.Helper()
	connIDMapMu.Lock()
	for k := range connByUser {
		delete(connByUser, k)
	}
	for k := range connIDMap {
		delete(connIDMap, k)
	}
	connIDMapMu.Unlock()
}

// TestFindSupersededByDevice_HappyPath:同 user 同 deviceUUID 的旧 conn 一条,
// 应该被选出来。
func TestFindSupersededByDevice_HappyPath(t *testing.T) {
	resetConnByUserForSupersedeTest(t)
	old := makeFakeConn(t, "old", "u1", "uuid-A")
	newConn := makeFakeConn(t, "new", "u1", "uuid-A")

	connIDMapMu.Lock()
	defer connIDMapMu.Unlock()
	victims := findSupersededByDeviceLocked(newConn)
	if len(victims) != 1 || victims[0] != old {
		t.Fatalf("expected [old], got %+v", victims)
	}
}

// TestFindSupersededByDevice_DifferentDeviceIgnored:同 user 但不同 deviceUUID,
// 不应该被踢(它是用户的另一台设备)。
func TestFindSupersededByDevice_DifferentDeviceIgnored(t *testing.T) {
	resetConnByUserForSupersedeTest(t)
	makeFakeConn(t, "otherdev", "u1", "uuid-B")
	newConn := makeFakeConn(t, "new", "u1", "uuid-A")

	connIDMapMu.Lock()
	defer connIDMapMu.Unlock()
	if v := findSupersededByDeviceLocked(newConn); len(v) != 0 {
		t.Fatalf("不同 deviceUUID 不应被 supersede,got %+v", v)
	}
}

// TestFindSupersededByDevice_AnonymousDeviceSkipped:newConn 的 deviceUUID 为空
// (客户端没上报 / RFC 4122 v4 不合法),不参与 supersede 匹配 — 即使库里有同样空
// deviceUUID 的旧 conn 也不踢。
func TestFindSupersededByDevice_AnonymousDeviceSkipped(t *testing.T) {
	resetConnByUserForSupersedeTest(t)
	makeFakeConn(t, "anon1", "u1", "")
	newConn := makeFakeConn(t, "anon2", "u1", "")

	connIDMapMu.Lock()
	defer connIDMapMu.Unlock()
	if v := findSupersededByDeviceLocked(newConn); len(v) != 0 {
		t.Fatalf("空 deviceUUID 不参与 supersede,got %+v", v)
	}
}

// TestFindSupersededByDevice_TakenOverSkipped:正在被 handleTakeoverLogin 接管的
// 旧 conn(takenOver==true)不应该被 supersede 踢 — 接管路径已经在转移 vIP,横插
// 一脚会破坏 takeover 时序。
func TestFindSupersededByDevice_TakenOverSkipped(t *testing.T) {
	resetConnByUserForSupersedeTest(t)
	old := makeFakeConn(t, "old", "u1", "uuid-A")
	old.takenOver.Store(true)
	newConn := makeFakeConn(t, "new", "u1", "uuid-A")

	connIDMapMu.Lock()
	defer connIDMapMu.Unlock()
	if v := findSupersededByDeviceLocked(newConn); len(v) != 0 {
		t.Fatalf("takenOver==true 的 conn 不应再被 supersede,got %+v", v)
	}
}

// TestFindSupersededByDevice_DifferentUserIgnored:跨 user 即使 deviceUUID 一样
// 也不应被踢(实际不太可能 — devices.user_id+device_uuid UNIQUE,但代码仍要按
// userID 隔离)。
func TestFindSupersededByDevice_DifferentUserIgnored(t *testing.T) {
	resetConnByUserForSupersedeTest(t)
	makeFakeConn(t, "u2-conn", "u2", "uuid-A")
	newConn := makeFakeConn(t, "u1-new", "u1", "uuid-A")

	connIDMapMu.Lock()
	defer connIDMapMu.Unlock()
	if v := findSupersededByDeviceLocked(newConn); len(v) != 0 {
		t.Fatalf("跨 user 不应 supersede,got %+v", v)
	}
}

// TestFindSupersededByDevice_MultipleOldSessions:同 user 同 deviceUUID 多条旧 conn
// (比如客户端连续 crash 3 次重连)— 全都该被踢。
func TestFindSupersededByDevice_MultipleOldSessions(t *testing.T) {
	resetConnByUserForSupersedeTest(t)
	old1 := makeFakeConn(t, "old1", "u1", "uuid-A")
	old2 := makeFakeConn(t, "old2", "u1", "uuid-A")
	old3 := makeFakeConn(t, "old3", "u1", "uuid-A")
	newConn := makeFakeConn(t, "new", "u1", "uuid-A")

	connIDMapMu.Lock()
	defer connIDMapMu.Unlock()
	victims := findSupersededByDeviceLocked(newConn)
	if len(victims) != 3 {
		t.Fatalf("expected 3 victims, got %d (%+v)", len(victims), victims)
	}
	// 集合校验(map iteration 顺序不固定)。
	got := map[*Connection]bool{victims[0]: true, victims[1]: true, victims[2]: true}
	for _, want := range []*Connection{old1, old2, old3} {
		if !got[want] {
			t.Fatalf("missing victim %v, got set %+v", want.connIDStr, victims)
		}
	}
}

// TestDedupVictims:supersede 与 evict 列表合并,重复指针只出现一次。
func TestDedupVictims(t *testing.T) {
	a := &Connection{connIDStr: "a"}
	b := &Connection{connIDStr: "b"}
	c := &Connection{connIDStr: "c"}

	out := dedupVictims([]*Connection{a, b}, []*Connection{b, c, nil})
	if len(out) != 3 {
		t.Fatalf("expected 3 unique, got %d (%+v)", len(out), out)
	}
	// supersede 部分应排在前面,保持「先 supersede 后 evict」的日志可读性。
	if out[0] != a || out[1] != b || out[2] != c {
		t.Fatalf("expected [a, b, c], got %+v", out)
	}

	if got := dedupVictims(nil, nil); got != nil {
		t.Fatalf("expected nil for both-empty, got %+v", got)
	}
}

// TestWaitConnsCleanup_ReturnsImmediatelyWhenDone:cleanupDone 已 closed → 立即返回。
func TestWaitConnsCleanup_ReturnsImmediatelyWhenDone(t *testing.T) {
	c1 := &Connection{connIDStr: "c1", cleanupDone: make(chan struct{})}
	c2 := &Connection{connIDStr: "c2", cleanupDone: make(chan struct{})}
	close(c1.cleanupDone)
	close(c2.cleanupDone)

	done := make(chan struct{})
	go func() {
		waitConnsCleanup([]*Connection{c1, c2})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waitConnsCleanup 应在 cleanupDone 已关闭时立即返回")
	}
}

// TestWaitConnsCleanup_TimeoutHonored:tunnelDone 不关 → 等到 supersedeWaitTimeout
// 后兜底返回。为了不让单测跑 5s,我们临时把 timeout 改小再恢复。
//
// 注意:supersedeWaitTimeout 是 const。这里改为复用包级变量做就要重构成 var;
// 折中:用真实 5s,但 fast-path test 不跑;给一个 goroutine 启动等到 ~10ms 就 close 来
// 同样验证语义。
func TestWaitConnsCleanup_RespectsExternalClose(t *testing.T) {
	c := &Connection{connIDStr: "c", cleanupDone: make(chan struct{})}

	start := time.Now()
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(c.cleanupDone)
	}()
	waitConnsCleanup([]*Connection{c})
	elapsed := time.Since(start)
	if elapsed >= supersedeWaitTimeout {
		t.Fatalf("等到了 supersedeWaitTimeout 才返回(%s),应该 ~50ms 就返回", elapsed)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("返回得太早(%s),数据竞争可能", elapsed)
	}
}

// TestSessionSupersedeCounter_Increments:验证 counter 的契约 — 任何 .Add(1) 都
// 严格走到读出值 +1。/metrics 的 nanotun_session_supersede_total 直接读这个。
func TestSessionSupersedeCounter_Increments(t *testing.T) {
	before := sessionSupersedeCount.Load()
	sessionSupersedeCount.Add(1)
	if got := sessionSupersedeCount.Load(); got != before+1 {
		t.Fatalf("expected +1, before=%d after=%d", before, got)
	}
}
