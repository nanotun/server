package main

import (
	"net/netip"
	"testing"
)

// setFRPTargetTableForTest 装一份 FRP 精确路由表快照并在用例结束还原，隔离全局态。
func setFRPTargetTableForTest(t *testing.T, m map[netip.Addr]int64) {
	t.Helper()
	prev := frpTargetTable.Load()
	frpTargetTable.Store(&m)
	t.Cleanup(func() { frpTargetTable.Store(prev) })
}

// #5 核心：同一网段被多台设备宣告（子网表里 device 1 是最小 deviceID），但 FRP 映射**指定**了 device 2。
// forwardServerOriginatedToSubnet 应按精确表投给 device 2（而非按子网猜测投给最小 deviceID=1）。
func TestForwardServerOriginated_FRPTargetOverridesSubnet(t *testing.T) {
	resetConnByDeviceForTest(t)
	// 子网表：同一 /24 被 device 1 和 device 2 都宣告（重叠）。lookupSubnetRoute 会取最小 deviceID=1。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{
		mkEntry("192.168.8.0/24", 1),
		mkEntry("192.168.8.0/24", 2),
	})
	// FRP 精确表：192.168.8.5 → 映射指定的 device 2。
	setFRPTargetTableForTest(t, map[netip.Addr]int64{
		netip.MustParseAddr("192.168.8.5"): 2,
	})
	ch1 := addAdvertiserConn(t, 1, "advA", "10.0.0.1")
	ch2 := addAdvertiserConn(t, 2, "advB", "10.0.0.2")

	if !forwardServerOriginatedToSubnet(netip.MustParseAddr("192.168.8.5"), mkIPv4(netip.MustParseAddr("192.168.8.5"))) {
		t.Fatal("命中 FRP 精确表 + 指定设备在线应投递(返回 true)")
	}
	if len(ch1) != 0 {
		t.Fatal("绝不能投给按子网猜测的最小 deviceID(device 1)")
	}
	if len(ch2) != 1 {
		t.Fatalf("应投给 FRP 映射指定的 device 2, ch2=%d", len(ch2))
	}
}

// FRP 精确表命中但**指定设备离线** → 丢弃（droppedOffline++），**绝不**回落子网解析改投另一台在线设备。
func TestForwardServerOriginated_FRPTargetOfflineNoFallback(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{
		mkEntry("192.168.8.0/24", 1), // device 1 在线（子网兜底会选它）
		mkEntry("192.168.8.0/24", 2),
	})
	setFRPTargetTableForTest(t, map[netip.Addr]int64{
		netip.MustParseAddr("192.168.8.5"): 2, // 指定 device 2，但它离线
	})
	ch1 := addAdvertiserConn(t, 1, "advA", "10.0.0.1") // 只有 device 1 在线

	before := subnetRouteDroppedOffline.Load()
	if forwardServerOriginatedToSubnet(netip.MustParseAddr("192.168.8.5"), mkIPv4(netip.MustParseAddr("192.168.8.5"))) {
		t.Fatal("指定设备离线应丢弃(返回 false)")
	}
	if subnetRouteDroppedOffline.Load() != before+1 {
		t.Fatal("指定设备离线应计入 subnetRouteDroppedOffline")
	}
	if len(ch1) != 0 {
		t.Fatal("指定设备离线时**绝不能**回落子网解析改投 device 1(那正是 #5 要消除的错投)")
	}
}

// dst 不在 FRP 精确表 → 回落 lookupSubnetRoute 兜底（非 FRP 的 server 自发 LAN 包，行为不变）。
func TestForwardServerOriginated_FallbackToSubnet(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.9.0/24", 3)})
	setFRPTargetTableForTest(t, map[netip.Addr]int64{}) // 空精确表
	ch3 := addAdvertiserConn(t, 3, "advC", "10.0.0.3")

	if !forwardServerOriginatedToSubnet(netip.MustParseAddr("192.168.9.5"), mkIPv4(netip.MustParseAddr("192.168.9.5"))) {
		t.Fatal("未命中精确表应回落子网解析并投递")
	}
	if len(ch3) != 1 {
		t.Fatalf("子网兜底应投给 device 3, ch3=%d", len(ch3))
	}
}

// 审批门控：FRP 精确表命中、指定设备在线且**本会话仍宣告**该网段，但 admin 已**撤销**其子网批准
// （subnetRouteTable 不再覆盖 dst）→ 丢弃（droppedNotApproved++），不因「设备仍在 advertise」而漏发。
// 证明 FRP 路径与客户端来包路径同口径：撤销审批即时对 FRP 生效，无需等 portforward reload。
func TestForwardServerOriginated_FRPTargetNotApprovedDrops(t *testing.T) {
	resetConnByDeviceForTest(t)
	// 审批表为空（admin 已撤销 device 2 对 192.168.8.0/24 的批准）。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{})
	setFRPTargetTableForTest(t, map[netip.Addr]int64{
		netip.MustParseAddr("192.168.8.5"): 2,
	})
	// device 2 在线且**本会话仍宣告** 192.168.8.0/24（会话闸本会放行）——但审批已撤销，仍必须丢。
	ch2 := addAdvertiserConnWithRoutes(t, 2, "advB", "10.0.0.2", []string{"192.168.8.0/24"})

	before := subnetRouteDroppedNotApproved.Load()
	if forwardServerOriginatedToSubnet(netip.MustParseAddr("192.168.8.5"), mkIPv4(netip.MustParseAddr("192.168.8.5"))) {
		t.Fatal("审批已撤销应丢弃(返回 false)，不能因设备仍 advertise 而漏发")
	}
	if subnetRouteDroppedNotApproved.Load() != before+1 {
		t.Fatal("撤销审批应计入 subnetRouteDroppedNotApproved")
	}
	if len(ch2) != 0 {
		t.Fatal("审批已撤销时绝不应投递(否则撤销对 FRP 不生效)")
	}
}

// FRP 精确表命中，但指定设备**已收窄**不再宣告覆盖 dst 的网段 → 丢弃（droppedNotAdvertised++），防未 NAT 漏进其 LAN。
func TestForwardServerOriginated_FRPTargetNarrowedDrops(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("10.8.0.0/24", 2)})
	setFRPTargetTableForTest(t, map[netip.Addr]int64{
		netip.MustParseAddr("10.8.0.5"): 2,
	})
	// device 2 当前只宣告 192.168.1.0/24（收窄，去掉了 10.8.0.0/24）。
	ch2 := addAdvertiserConnWithRoutes(t, 2, "advB", "10.0.0.2", []string{"192.168.1.0/24"})

	before := subnetRouteDroppedNotAdvertised.Load()
	if forwardServerOriginatedToSubnet(netip.MustParseAddr("10.8.0.5"), mkIPv4(netip.MustParseAddr("10.8.0.5"))) {
		t.Fatal("指定设备已收窄不再宣告该网段应丢弃(返回 false)")
	}
	if subnetRouteDroppedNotAdvertised.Load() != before+1 {
		t.Fatal("收窄未宣告应计入 subnetRouteDroppedNotAdvertised")
	}
	if len(ch2) != 0 {
		t.Fatal("收窄后的网段绝不应投递(否则未 NAT 漏进其 LAN)")
	}
}
