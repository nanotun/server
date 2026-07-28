package main

// buildExitsList 的取舍面。
//
// 这个列表就是客户端下拉里能看到的出口。它判错不会报任何错,只会表现成两种「玄学」:
//
//   - 少列:用户唯一的出口一掉线就从下拉里消失,再也选不回来(深扫第二轮真踩过 ——
//     根因是「当前无在线出口」时提前 return,把第 ④ 步补离线出口的逻辑一起跳过了);
//   - 多列:已离场 / 已被接管 / 已被顶掉的会话仍显示 Online,用户选中后流量直接黑洞。
//
// 所以这里钉的是四段式的每一段各自负责挡住什么,以及「DB 查不动时宁可不列」这条保守取向。
// 用例都不去碰第 ③ 步与发送之间那个残余窗口(靠 exitsBroadcastMu 串行化收敛),
// 能在进程内确定性复现的是「快照时活着、复核时已经不算在线」这一类状态翻转。

import (
	"context"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// registerExitConn 造一个「在跑出口」的会话并登记进 connIDMap / by-device 索引。
// tweak 用来在登记后把它改成各种「其实不该算在线」的状态。
func registerExitConn(t *testing.T, connID string, deviceID int64, uuid string, tweak func(*Connection)) *Connection {
	t.Helper()
	c := &Connection{userID: "u1", connIDStr: connID, deviceID: deviceID, deviceUUID: uuid}
	c.advertisedExit.Store(true)
	if tweak != nil {
		tweak(c)
	}
	connIDMapMu.Lock()
	connIDMap[connID] = c
	connByDeviceAddLocked(c)
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, connID)
		connIDMapMu.Unlock()
	})
	return c
}

// findExit 在列表里按 uuid 找一条。
func findExit(list []util.ExitInfo, uuid string) (util.ExitInfo, bool) {
	for _, e := range list {
		if e.DeviceUUID == uuid {
			return e, true
		}
	}
	return util.ExitInfo{}, false
}

// TestBuildExitsList_NoStore 无 store 时返回 nil —— 这条是给「还没起 gateway」的
// 早期调用兜底,不能 panic。
func TestBuildExitsList_NoStore(t *testing.T) {
	prev := gatewayInstance
	t.Cleanup(func() { gatewayInstance = prev })

	gatewayInstance = nil
	if got := buildExitsList(context.Background()); got != nil {
		t.Fatalf("无 gateway 应返回 nil, got %v", got)
	}
	gatewayInstance = &gatewayState{}
	if got := buildExitsList(context.Background()); got != nil {
		t.Fatalf("无 store 应返回 nil, got %v", got)
	}
}

// TestBuildExitsList_ApprovedButOfflineStillListed 钉住那条回归:**没有任何在线出口**时
// 也必须把已批准的离线出口列出来(Online=false)。
//
// 这是「少列」里最伤的一种:用户只有一个出口,它一掉线下拉就空了,连重新选中等它上线
// 都做不到。实现上的诱惑是「候选为空就早退」,这条用例专门堵那个早退。
func TestBuildExitsList_ApprovedButOfflineStillListed(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	const uuid = "44444444-4444-4444-8444-444444444444"
	seedApprovedExitDevice(t, st, uuid)

	list := buildExitsList(context.Background())
	e, ok := findExit(list, uuid)
	if !ok {
		t.Fatalf("已批准但离线的出口必须留在列表里(供下拉置灰可选), got %+v", list)
	}
	if e.Online {
		t.Fatal("离线出口的 Online 应为 false")
	}
	if e.DeviceName == "" {
		t.Fatal("应带上设备展示名,否则下拉里只有一串 uuid")
	}
}

// TestBuildExitsList_OnlineExitTakesPrecedence 在线出口列为 Online=true,
// 且不会因为 DB 里同时有它的 approved 路由而重复出现一条离线项。
func TestBuildExitsList_OnlineExitTakesPrecedence(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	const uuid = "55555555-5555-4555-8555-555555555555"
	devID := seedApprovedExitDevice(t, st, uuid)
	registerExitConn(t, "exit-online", devID, uuid, nil)

	list := buildExitsList(context.Background())
	n := 0
	for _, e := range list {
		if e.DeviceUUID == uuid {
			n++
			if !e.Online {
				t.Fatal("在跑的出口应为 Online=true")
			}
		}
	}
	if n != 1 {
		t.Fatalf("同一出口应只出现一条(在线优先),实际 %d 条: %+v", n, list)
	}
}

// TestBuildExitsList_NotApprovedNotListed 只宣告、未获批准的出口不列 ——
// 列出来等于让用户选一个 admin 还没点头的出口,选中后必然 fail-closed。
func TestBuildExitsList_NotApprovedNotListed(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	ctx := context.Background()
	const uuid = "66666666-6666-4666-8666-666666666666"

	// 造设备 + 宣告 0/0 但**不批准**。
	u, err := st.CreateUser(ctx, store.NewUser{Username: "pendingowner", PSKHash: "h"})
	if err != nil {
		t.Fatalf("建用户: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, uuid, "pending-exit", "linux")
	if err != nil {
		t.Fatalf("建设备: %v", err)
	}
	if _, err := st.UpsertAdvertisedRoute(ctx, dev.ID, "0.0.0.0/0"); err != nil {
		t.Fatalf("宣告: %v", err)
	}
	registerExitConn(t, "exit-pending", dev.ID, uuid, nil)

	if _, ok := findExit(buildExitsList(ctx), uuid); ok {
		t.Fatal("未获批准的出口不该出现在下拉里")
	}
}

// TestBuildExitsList_DBUnavailableListsNothing 钉住那条保守取向:approved 查不动时
// 宁可不列,也不列出一个未经核实的出口。
//
// 反方向(查不动就当已批准)会在 DB 抖动的瞬间把任意宣告了 0/0 的设备暴露成可选出口。
func TestBuildExitsList_DBUnavailableListsNothing(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	ctx := context.Background()
	const uuid = "77777777-7777-4777-8777-777777777777"
	devID := seedApprovedExitDevice(t, st, uuid)
	registerExitConn(t, "exit-dberr", devID, uuid, nil)

	// 先确认正常情况下它是列得出来的,否则下面的「没列出来」证明不了任何事。
	if _, ok := findExit(buildExitsList(ctx), uuid); !ok {
		t.Fatal("前置条件不成立:正常情况下这个出口本应在列表里")
	}

	if _, err := st.DB().ExecContext(ctx,
		`ALTER TABLE subnet_routes RENAME TO subnet_routes_gone`); err != nil {
		t.Fatalf("藏掉 subnet_routes: %v", err)
	}
	if got := buildExitsList(ctx); len(got) != 0 {
		t.Fatalf("查不动 approved 时不该列出任何出口, got %+v", got)
	}
}

// TestBuildExitsList_StaleConnStatesExcluded 钉住第 ③ 步复核挡掉的三类「其实不该算在线」:
// 被接管、被顶掉(superseded)、以及在快照之后从 connIDMap 里消失的。
//
// 这三类的共同点是 conn 对象还在、advertisedExit 还是 true,只有那几个 flag 能区分。
// 漏判的后果是列表显示 Online 而链路已死 —— 用户选中后出口流量直接黑洞,而且因为
// 显示在线,他不会怀疑是出口的问题。
func TestBuildExitsList_StaleConnStatesExcluded(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(t *testing.T, c *Connection){
		"已被接管": func(t *testing.T, c *Connection) { c.takenOver.Store(true) },
		"已被顶掉": func(t *testing.T, c *Connection) { c.superseded.Store(true) },
		"撤回了出口声明": func(t *testing.T, c *Connection) { c.advertisedExit.Store(false) },
	}
	for name, mark := range cases {
		t.Run(name, func(t *testing.T) {
			resetConnByDeviceForTest(t)
			st := egressTestStore(t)
			const uuid = "88888888-8888-4888-8888-888888888888"
			devID := seedApprovedExitDevice(t, st, uuid)
			c := registerExitConn(t, "exit-stale", devID, uuid, nil)

			mark(t, c)
			e, ok := findExit(buildExitsList(ctx), uuid)
			if ok && e.Online {
				t.Fatal("这个会话已经不算在跑出口了,不该显示 Online —— 用户选中后会黑洞")
			}
			// 它仍是已批准出口,所以应当作为**离线**项留在下拉里(可选、置灰)。
			if !ok {
				t.Fatal("已批准的出口即使当前会话失效,也该以 Online=false 留在下拉里")
			}
		})
	}

	t.Run("快照之后从 connIDMap 消失", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		st := egressTestStore(t)
		const uuid = "99999999-9999-4999-8999-999999999999"
		devID := seedApprovedExitDevice(t, st, uuid)
		c := registerExitConn(t, "exit-gone", devID, uuid, nil)

		// 模拟「② 期间该会话下线」:conn 对象本身没变,但已不在 map 里。
		connIDMapMu.Lock()
		delete(connIDMap, c.connIDStr)
		connIDMapMu.Unlock()

		e, ok := findExit(buildExitsList(ctx), uuid)
		if ok && e.Online {
			t.Fatal("已离场的会话不该显示 Online")
		}
	})
}

// TestBuildExitsList_ApprovedSubnetIsNotAnExit 钉住第 ④ 步的过滤:批准一条 LAN 子网路由
// **不等于**批准当公网出口。漏了这层过滤,admin 点一下「批准 192.168.7.0/24」就顺手把那台
// 设备摆进了所有用户的出口下拉里。
func TestBuildExitsList_ApprovedSubnetIsNotAnExit(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	ctx := context.Background()
	const lanUUID = "a1a1a1a1-1111-4111-8111-a1a1a1a1a1a1"

	u, err := st.CreateUser(ctx, store.NewUser{Username: "lanonly", PSKHash: "h"})
	if err != nil {
		t.Fatalf("建用户: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, lanUUID, "lan-dev", "linux")
	if err != nil {
		t.Fatalf("建设备: %v", err)
	}
	if _, err := st.UpsertAdvertisedRoute(ctx, dev.ID, "192.168.7.0/24"); err != nil {
		t.Fatalf("宣告: %v", err)
	}
	if err := st.SetRouteStatus(ctx, dev.ID, "192.168.7.0/24", store.RouteStatusApproved, ""); err != nil {
		t.Fatalf("批准: %v", err)
	}

	// 同时放一个真出口进去,证明列表本身在工作(否则「没列出 LAN 设备」也可能是列表整个空了)。
	const exitUUID = "b2b2b2b2-2222-4222-8222-b2b2b2b2b2b2"
	seedApprovedExitDevice(t, st, exitUUID)

	list := buildExitsList(ctx)
	if _, ok := findExit(list, exitUUID); !ok {
		t.Fatalf("前置条件不成立:真出口应当在列表里, got %+v", list)
	}
	if _, ok := findExit(list, lanUUID); ok {
		t.Fatalf("只批了 192.168.7.0/24 的设备不该进出口下拉, got %+v", list)
	}
}

// TestIsRunningExitConn 直接钉那条判据 —— buildExitsList 的 ① 与 ③ 都用它。
//
// 单独测它的理由:③ 是「② 查 DB 那段时间里状态翻转了」的兜底,而单测没法确定性地
// 在 ①③ 之间插入一次翻转(要么得给生产代码加一个纯为开窗存在的钩子)。判据抽出来之后,
// 至少「判据本身认不认这几种失效状态」是钉住的;至于 ③ 到底有没有被调用,靠的是
// e2e 里出口接管/重登那几条真实时序。
func TestIsRunningExitConn(t *testing.T) {
	mk := func(tweak func(*Connection)) *Connection {
		c := &Connection{connIDStr: "x", deviceID: 7, deviceUUID: "u"}
		c.advertisedExit.Store(true)
		if tweak != nil {
			tweak(c)
		}
		return c
	}

	if !isRunningExitConn(mk(nil)) {
		t.Fatal("在跑出口的会话应判为 true")
	}
	cases := map[string]func(*Connection){
		"nil 会话":     nil, // 单独处理
		"撤回了出口声明":    func(c *Connection) { c.advertisedExit.Store(false) },
		"已被接管":       func(c *Connection) { c.takenOver.Store(true) },
		"已被顶掉":       func(c *Connection) { c.superseded.Store(true) },
		"没有 deviceID": func(c *Connection) { c.deviceID = 0 },
	}
	for name, tweak := range cases {
		t.Run(name, func(t *testing.T) {
			if tweak == nil {
				if isRunningExitConn(nil) {
					t.Fatal("nil 会话必须判为 false")
				}
				return
			}
			if isRunningExitConn(mk(tweak)) {
				t.Fatal("这种状态不该算「在跑出口」—— 列进下拉后选中即黑洞")
			}
		})
	}
}

// dedupExitsByUUID 本身已有 TestDedupExitsByUUID_KeepsTheOnlineOneAndDropsPlaceholders
// (daemon_helpers_test.go)钉住,这里不重复。
