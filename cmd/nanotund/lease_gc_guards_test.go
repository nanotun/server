package main

import (
	"context"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// idle lease 的定时回收。
//
// 这条循环的危险不在「回收得不够干净」(那只是地址池慢慢变少),而在**回收错了**:一个客户端已经
// 连了两个月没断线,它的 vIP 被当成 idle 回收掉,下一个登录的设备就会拿到同一个地址。表现是两台
// 机器同一地址、时通时不通,而回收发生在半夜、日志里只有一行「回收完成」。
//
// 成因是两张表的时间口径不一致:回收看 devices.last_seen_at,而老路径只在**登录时**刷它 ——
// 长会话期间它一直是登录那一刻的值。所以回收前必须先把所有在线会话的 device 顶到 now
// (E1,2026-05-22 现场)。这批用例钉的就是这一步真的在,以及关掉 / 夹取那几条开关。

// seedIdleLease 造一个 last_seen_at 很久以前的设备 + 一条它的 lease,返回 deviceID。
func seedIdleLease(t *testing.T, st *store.Store, username, vip string, lastSeenAgo time.Duration) int64 {
	t.Helper()
	ctx := t.Context()
	u, err := st.CreateUser(ctx, store.NewUser{Username: username, PSKHash: "h"})
	if err != nil {
		t.Fatalf("建用户: %v", err)
	}
	d, err := st.UpsertDevice(ctx, u.ID, "22222222-2222-4222-8222-"+username[:1]+"00000000000", "dev-"+username, "linux")
	if err != nil {
		t.Fatalf("建设备: %v", err)
	}
	if _, err := st.UpsertLease(ctx, d.ID, vip, "", false); err != nil {
		t.Fatalf("建 lease: %v", err)
	}
	old := time.Now().Add(-lastSeenAgo).Unix()
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devices SET last_seen_at=? WHERE id=?`, old, d.ID); err != nil {
		t.Fatalf("回拨 last_seen_at: %v", err)
	}
	return d.ID
}

func leaseCount(t *testing.T, st *store.Store, deviceID int64) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM leases WHERE device_id=?`, deviceID).Scan(&n); err != nil {
		t.Fatalf("数 lease: %v", err)
	}
	return n
}

// TestLeaseGC_NeverReclaimsTheAddressOfALongLivedSession 长在线会话的地址不能被回收。
//
// 这是 2026-05-22 那次现场的回归:回收依据是 devices.last_seen_at,而它只在登录时刷,于是连了
// 超过 idle 天数的会话看起来「很久没露面」。回收掉它的 vIP 之后,下一个登录的设备会拿到同一个
// 地址 —— 两台机器同址,时通时不通。所以回收前要先把在线会话的 device 顶到 now。
func TestLeaseGC_NeverReclaimsTheAddressOfALongLivedSession(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)

	// 两个设备都「很久没露面」,但只有 online 那个有在线会话。
	onlineDev := seedIdleLease(t, gw.store, "online", "10.80.0.10", 90*24*time.Hour)
	goneDev := seedIdleLease(t, gw.store, "gone", "10.80.0.11", 90*24*time.Hour)

	c := &Connection{userID: "u-online", connIDStr: "long-lived", deviceID: onlineDev}
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, c.connIDStr)
		connIDMapMu.Unlock()
	})

	// 跑一轮:idle 取 1 天,两个设备的 last_seen_at 都远早于它。
	// 用短超时而不是提前取消 —— doOnce 从这个 ctx 派生子 ctx,提前取消会让那条 DELETE
	// 直接报 context canceled(回收根本没执行,而断言看起来像「保护生效了」)。
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	runLeaseGCLoop(ctx, gw.store, 24*time.Hour, time.Hour)

	if leaseCount(t, gw.store, onlineDev) != 1 {
		t.Error("回收掉了一个长在线会话的 vIP —— 下一个登录的设备会拿到同一个地址,两台机器同址、时通时不通")
	}
	if leaseCount(t, gw.store, goneDev) != 0 {
		t.Error("真正 idle 的 lease 没被回收 —— 地址池会一直被离线设备占着")
	}
}

// TestStartLeaseGCLoop_RespectsTheOffSwitchAndClampsTheInterval 开关与夹取。
//
// idleDays<=0 是**显式关闭**(运维不想让自动回收动地址池,靠 CLI 手动跑)。误把它当默认值处理就
// 违背了配置意图。intervalHours<=0 则必须夹取:time.NewTicker(0) 直接 panic,而这个值来自配置。
func TestStartLeaseGCLoop_RespectsTheOffSwitchAndClampsTheInterval(t *testing.T) {
	t.Run("没有 store 时 no-op", func(t *testing.T) {
		startLeaseGCLoop(nil, 30, 24)()
		startLeaseGCLoop(&gatewayState{}, 30, 24)()
	})

	t.Run("idleDays<=0 是显式关闭", func(t *testing.T) {
		resetServerGlobals(t)
		withTestGlobalContext(t)
		gw := newRouteTestGateway(t)
		dev := seedIdleLease(t, gw.store, "offsw", "10.81.0.10", 90*24*time.Hour)

		startLeaseGCLoop(gw, 0, 24)()
		time.Sleep(50 * time.Millisecond)

		if leaseCount(t, gw.store, dev) != 1 {
			t.Error("显式关闭了自动回收却还是回收了 —— 配置意图被无视")
		}
	})

	t.Run("intervalHours<=0 要夹取而不是 panic", func(t *testing.T) {
		resetServerGlobals(t)
		withTestGlobalContext(t)
		gw := newRouteTestGateway(t)
		// 夹取成默认 24h,所以这条 goroutine 只会跑一次 doOnce 就停在 select 上。
		startLeaseGCLoop(gw, 30, 0)()
		time.Sleep(50 * time.Millisecond)
	})
}

// TestRunLeaseGCLoop_KeepsGoingAfterADBFailure 一次回收失败不该让整条循环停掉。
//
// 回收是长期任务,库抖一下就退出循环意味着「从此再也不回收」—— 地址池被离线设备慢慢占满,
// 而唯一的线索是很久以前的一条 Warn。
func TestRunLeaseGCLoop_KeepsGoingAfterADBFailure(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	dev := seedIdleLease(t, gw.store, "afterfail", "10.82.0.10", 90*24*time.Hour)

	// idle<=0 会让 GcOrphanLeases 直接返回错误(它拒绝非正的 idle)。
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runLeaseGCLoop(ctx, gw.store, 0, 5*time.Millisecond)
	}()
	time.Sleep(60 * time.Millisecond) // 足够跑好几轮失败
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ctx 取消后循环没退出")
	}
	if leaseCount(t, gw.store, dev) != 1 {
		t.Error("idle 非法时不该删任何东西")
	}
}
