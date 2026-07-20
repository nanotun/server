package main

import (
	"context"
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
)

// newPFRebuildManager 造一个仅够 rebuildFRPTargetTable 用的 portForwardManager（带 store + mesh 网段），
// 并保存/还原全局 frpTargetTable，隔离用例。不碰 portForwardMgr / 不起真实监听。
func newPFRebuildManager(t *testing.T, gw *gatewayState) *portForwardManager {
	t.Helper()
	m := &portForwardManager{
		gw:     gw,
		meshV4: netip.MustParsePrefix("10.201.0.0/16").Masked(), // vIP 段：判 node 目标 vs LAN 目标
	}
	prev := frpTargetTable.Load()
	t.Cleanup(func() { frpTargetTable.Store(prev) })
	return m
}

// mustCreateSecondDevice 造第二个用户 + 设备（自定义 UUID），返回 deviceID。用于歧义/多设备用例。
func mustCreateSecondDevice(t *testing.T, gw *gatewayState, username, uuid string) int64 {
	t.Helper()
	ctx := t.Context()
	u, err := gw.store.CreateUser(ctx, store.NewUser{Username: username, PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	d, err := gw.store.UpsertDevice(ctx, u.ID, uuid, "dev2", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	return d.ID
}

// rebuildFRPTargetTable 正路：LAN 目标按 UUID 解析出 deviceID 入表；node 目标（vIP）与未知 UUID 不入表。
func TestRebuildFRPTargetTable_LANOnlyResolvedByUUID(t *testing.T) {
	gw := newRouteTestGateway(t)
	_, deviceID := mustCreateUserAndDevice(t, gw, "alice")
	const uuid = "11111111-1111-4111-8111-111111111111" // mustCreateUserAndDevice 固定 UUID
	m := newPFRebuildManager(t, gw)

	rows := []store.PortForward{
		{PublicPort: 2222, TargetDeviceUUID: uuid, TargetIP: "192.168.8.5", TargetPort: 22},                                   // LAN 目标 → 入表
		{PublicPort: 2223, TargetDeviceUUID: uuid, TargetIP: "10.201.0.6", TargetPort: 22},                                    // node 目标(vIP) → 不入表
		{PublicPort: 2224, TargetDeviceUUID: "ffffffff-ffff-4fff-8fff-ffffffffffff", TargetIP: "192.168.9.5", TargetPort: 22}, // 未知设备 → 不入表
	}
	m.rebuildFRPTargetTable(context.Background(), rows)

	if dev, ok := lookupFRPTarget(netip.MustParseAddr("192.168.8.5")); !ok || dev != deviceID {
		t.Fatalf("LAN 目标应入表且解析到 deviceID=%d, got dev=%d ok=%v", deviceID, dev, ok)
	}
	if _, ok := lookupFRPTarget(netip.MustParseAddr("10.201.0.6")); ok {
		t.Fatal("node 目标(vIP)不应进精确表(走正常 vIP demux)")
	}
	if _, ok := lookupFRPTarget(netip.MustParseAddr("192.168.9.5")); ok {
		t.Fatal("未知设备 UUID 不应入表(数据面回落子网解析)")
	}
}

// 同一 LAN IP 被两条映射指向**两台已注册的不同设备**（歧义）→ 保留先见者、忽略后者（确定性 tiebreak），不 panic。
// 真正走 rebuildFRPTargetTable 里 `dup && existing != dev` 分支。
func TestRebuildFRPTargetTable_DuplicateIPKeepsFirst(t *testing.T) {
	gw := newRouteTestGateway(t)
	_, deviceA := mustCreateUserAndDevice(t, gw, "alice") // UUID = 111...
	deviceB := mustCreateSecondDevice(t, gw, "bob", "22222222-2222-4222-8222-222222222222")
	const uuidA = "11111111-1111-4111-8111-111111111111"
	const uuidB = "22222222-2222-4222-8222-222222222222"
	m := newPFRebuildManager(t, gw)

	// 两条映射同 IP、指向不同设备：先见者(A) 应留存，后者(B) 被忽略。
	rows := []store.PortForward{
		{PublicPort: 2222, TargetDeviceUUID: uuidA, TargetIP: "192.168.8.5", TargetPort: 22},
		{PublicPort: 2223, TargetDeviceUUID: uuidB, TargetIP: "192.168.8.5", TargetPort: 80},
	}
	m.rebuildFRPTargetTable(context.Background(), rows)

	dev, ok := lookupFRPTarget(netip.MustParseAddr("192.168.8.5"))
	if !ok || dev != deviceA {
		t.Fatalf("歧义 IP 应保留先见者 deviceA=%d(而非后者 deviceB=%d), got dev=%d ok=%v", deviceA, deviceB, dev, ok)
	}
}

// ctx 已取消 → resolveDeviceID 的 DB 查询失败 → LAN 目标被跳过、发布**残缺**表。这正是 reloadPortForwards 用
// context.WithoutCancel 切断取消传播的原因（DB 写已提交，不该因控制端 HTTP 超时而丢精确路由 → #5 回归）。
func TestRebuildFRPTargetTable_CancelledCtxYieldsPartial(t *testing.T) {
	gw := newRouteTestGateway(t)
	mustCreateUserAndDevice(t, gw, "alice")
	const uuid = "11111111-1111-4111-8111-111111111111"
	m := newPFRebuildManager(t, gw)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 预取消，模拟控制端请求已断开

	rows := []store.PortForward{
		{PublicPort: 2222, TargetDeviceUUID: uuid, TargetIP: "192.168.8.5", TargetPort: 22},
	}
	m.rebuildFRPTargetTable(ctx, rows)

	if _, ok := lookupFRPTarget(netip.MustParseAddr("192.168.8.5")); ok {
		t.Fatal("取消 ctx 下 resolveDeviceID 应失败 → 该条被跳过(残缺表)；本用例锁定 detach 修复的动机")
	}
}
