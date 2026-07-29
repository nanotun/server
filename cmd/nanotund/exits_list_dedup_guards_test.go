package main

import (
	"context"
	"testing"
)

// 同一台设备可以有多条会话在线(一台机器多开、或接管过渡期间新旧并存)。出口列表的两处细节要盯住:
//
//   - 查 DB 时按 device 去重。不去重的话,一台机器多开 N 条会话就等于对同一个 device 做 N 次
//     GetDevice + 查批准路由;每次广播都乘一遍 N,而广播是在持 exitsBroadcastMu 时做的。
//   - 列表里也只能出现一条。同一个出口在下拉里出现两次,用户根本无法区分该选哪个。

// TestBuildExitsList_ManySessionsOfOneDeviceCollapseToOneEntry 同设备多会话 → 一条,DB 只查一次。
func TestBuildExitsList_ManySessionsOfOneDeviceCollapseToOneEntry(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	const uuid = "66666666-6666-4666-8666-666666666666"
	devID := seedApprovedExitDevice(t, st, uuid)

	// 一台机器上开了四条会话,全都在宣告出口。
	for i, id := range []string{"multi-a", "multi-b", "multi-c", "multi-d"} {
		_ = i
		registerExitConn(t, id, devID, uuid, nil)
	}

	list := buildExitsList(context.Background())
	n := 0
	for _, e := range list {
		if e.DeviceUUID == uuid {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("同一台设备的四条会话产出 %d 条出口项 —— 下拉里同一个出口出现多次,用户无从选择: %+v", n, list)
	}
}

// TestPushInitialExitsList_SkipsClientsWithoutExitPermission 无出口权限的新连接不推列表。
//
// 初始推送发生在登录握手里。给没有权限的用户推,一是把「谁能当出口、此刻谁在线」这份情报送了出去,
// 二是白占一次持 exitsBroadcastMu 的窗口 —— 而那把锁串行着全站的出口列表广播。
func TestPushInitialExitsList_SkipsClientsWithoutExitPermission(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	const uuid = "77777777-7777-4777-8777-777777777777"
	devID := seedApprovedExitDevice(t, st, uuid)
	registerExitConn(t, "exit-for-push", devID, uuid, nil)

	// 没有出口权限:一个字节都不该写。
	noPerm := newDeadlineRecordingLink()
	denied := &Connection{connIDStr: "push-no-perm", userID: "u2"}
	denied.linkConn = noPerm
	pushInitialExitsList(context.Background(), denied)
	if len(noPerm.written()) != 0 {
		t.Fatalf("给无出口权限的新连接推了 %d 字节 —— 那份「谁能当出口」的情报按策略不该给它", len(noPerm.written()))
	}

	// 有权限:必须收到,否则客户端一连上时下拉是空的,要等到下一次出口上下线才会填上。
	link := newDeadlineRecordingLink()
	allowed := &Connection{connIDStr: "push-allowed", userID: "u3", exitAllowed: true}
	allowed.linkConn = link
	pushInitialExitsList(context.Background(), allowed)
	if len(link.written()) == 0 {
		t.Fatal("有出口权限的新连接没收到初始出口列表 —— 刚连上时下拉是空的,要等下一次出口上下线才填上")
	}

	// nil 连接不许 panic:这条会在登录路径上被调用。
	pushInitialExitsList(context.Background(), nil)
}
