package main

import "testing"

// buildRoutesList：从 subnetRouteTable 派生列表，Online 反映宣告方是否有活跃会话（离线也列出）。
func TestBuildRoutesList_OnlineFlag(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{
		mkEntry("192.168.1.0/24", 77),
		mkEntry("10.10.0.0/16", 88),
	})
	// gatewayInstance 置无 store：本测试只验 CIDR + Online（设备名需 store，另测）。
	prevGW := gatewayInstance
	gatewayInstance = &gatewayState{}
	t.Cleanup(func() { gatewayInstance = prevGW })

	// 77 在线，88 离线。
	addAdvertiserConn(t, 77, "adv77", "10.0.0.9")

	list := buildRoutesList(t.Context())
	if len(list) != 2 {
		t.Fatalf("应有 2 条子网路由，得 %d", len(list))
	}
	online := map[string]bool{}
	seen := map[string]bool{}
	for _, r := range list {
		online[r.CIDR] = r.Online
		seen[r.CIDR] = true
	}
	if !seen["192.168.1.0/24"] || !seen["10.10.0.0/16"] {
		t.Fatalf("列表应含两条网段，得 %+v", list)
	}
	if !online["192.168.1.0/24"] {
		t.Fatal("192.168.1.0/24 的宣告方(77)在线，Online 应为 true")
	}
	if online["10.10.0.0/16"] {
		t.Fatal("10.10.0.0/16 的宣告方(88)离线，Online 应为 false")
	}
}

// 空表 → 空列表（不 panic）。
func TestBuildRoutesList_Empty(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, nil)
	if list := buildRoutesList(t.Context()); len(list) != 0 {
		t.Fatalf("空表应返回空列表，得 %+v", list)
	}
}
