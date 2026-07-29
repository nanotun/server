package main

import (
	"net/netip"
	"testing"
)

// 子网路由的丢包路径:丢了以后**不能回退**。
//
// 这个函数的返回值决定调用方还走不走后面的链路(出口 / server 自出口)。所以「按策略丢弃」必须
// 返回 true —— 返回 false 意味着一个发往内网 192.168.x 的包会继续往下走,最后从 server 的公网
// 网卡发出去。这不只是不通:内网地址与内网访问意图都泄漏到了公网上,而且发生在「宣告方队列满」
// 「包超长」这类临时状况下,现象是间歇的,极难查。
//
// 反过来,「不归我管」的两种情形必须返回 false(nil 会话、解析不出五元组),否则这些包会被子网
// 路由这条路吞掉,再也到不了它们该去的地方。

// TestForwardPacketToSubnetRoute_NeverFallsBackAfterDeciding 决定丢弃之后不许回退。
func TestForwardPacketToSubnetRoute_NeverFallsBackAfterDeciding(t *testing.T) {
	t.Run("包超长时丢弃而不回退", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.20.0/24", 88)})
		addAdvertiserConn(t, 88, "adv-oversize", "10.0.0.20")

		a := &Connection{userID: "1", connIDStr: "a", deviceID: 11}
		big := make([]byte, tunBufSize+1)
		copy(big, mkIPv4(netip.MustParseAddr("192.168.20.5")))

		before := subnetRouteDroppedOversize.Load()
		if !forwardPacketToSubnetRoute(a, big) {
			t.Fatal("超长包返回了 false —— 它会继续走出口 / server 链路,把一个内网包从公网网卡发出去")
		}
		if subnetRouteDroppedOversize.Load() != before+1 {
			t.Error("丢了却没记 oversize 计数 —— 这类间歇丢包不计数就完全查不到")
		}
	})

	t.Run("宣告方队列满时丢弃而不回退", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.21.0/24", 89)})
		tunCh := addAdvertiserConn(t, 89, "adv-full", "10.0.0.21")
		// 把宣告方的队列塞满:后续投递必然失败。
		for len(tunCh) < cap(tunCh) {
			tunCh <- poolShapedTunPacket(nil)
		}

		a := &Connection{userID: "1", connIDStr: "a", deviceID: 11}
		pkt := mkIPv4(netip.MustParseAddr("192.168.21.5"))
		before := subnetRouteDroppedFull.Load()
		if !forwardPacketToSubnetRoute(a, pkt) {
			t.Fatal("队列满时返回了 false —— 内网包会被改道从公网发出去")
		}
		if subnetRouteDroppedFull.Load() != before+1 {
			t.Error("丢了却没记 full 计数")
		}
	})
}

// TestForwardPacketToSubnetRoute_LeavesAloneWhatIsNotItsBusiness 不归它管的要放回原链路。
func TestForwardPacketToSubnetRoute_LeavesAloneWhatIsNotItsBusiness(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.22.0/24", 90)})

	if forwardPacketToSubnetRoute(nil, mkIPv4(netip.MustParseAddr("192.168.22.5"))) {
		t.Error("nil 会话被当成已处理 —— 包被这条路吞掉了")
	}
	a := &Connection{userID: "1", connIDStr: "a", deviceID: 11}
	if forwardPacketToSubnetRoute(a, []byte{0x45}) {
		t.Error("解析不出五元组的包被当成已处理 —— 它该交给后面的闸门 fail-closed,不该在这里静默消失")
	}
}

// TestDeliverServerOriginatedToDevice_ChecksTheAdvertisedSetAndTheQueue server 主动发起的那条路。
//
// 这条路用于 server 自己造包发往某宣告方背后的 LAN(如探测)。它要过两道:目的必须落在宣告方
// **当前**宣告的前缀集里(库里批准过 ≠ 它现在还在宣告),以及队列不能满。
func TestDeliverServerOriginatedToDevice_ChecksTheAdvertisedSetAndTheQueue(t *testing.T) {
	t.Run("落在当前宣告集内则投递", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.30.0/24", 95)})
		tunCh := addAdvertiserConnWithRoutes(t, 95, "adv-srv", "10.0.0.30", []string{"192.168.30.0/24"})

		pkt := mkIPv4(netip.MustParseAddr("192.168.30.7"))
		if !deliverServerOriginatedToDevice(95, netip.MustParseAddr("192.168.30.7"), pkt) {
			t.Fatal("目的落在宣告集内却没投递")
		}
		select {
		case <-tunCh:
		default:
			t.Error("包没进宣告方队列")
		}
	})

	t.Run("落在宣告集外则丢", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.31.0/24", 96)})
		addAdvertiserConnWithRoutes(t, 96, "adv-srv2", "10.0.0.31", []string{"192.168.99.0/24"})

		before := subnetRouteDroppedNotAdvertised.Load()
		dst := netip.MustParseAddr("192.168.31.7")
		if deliverServerOriginatedToDevice(96, dst, mkIPv4(dst)) {
			t.Error("目的不在宣告方当前宣告的前缀集里却投递了 —— 库里批准过不等于它现在还在宣告")
		}
		if subnetRouteDroppedNotAdvertised.Load() != before+1 {
			t.Error("没记 not_advertised 计数")
		}
	})

	t.Run("队列满则丢", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.32.0/24", 97)})
		tunCh := addAdvertiserConnWithRoutes(t, 97, "adv-srv3", "10.0.0.32", []string{"192.168.32.0/24"})
		for len(tunCh) < cap(tunCh) {
			tunCh <- poolShapedTunPacket(nil)
		}

		before := subnetRouteDroppedFull.Load()
		dst := netip.MustParseAddr("192.168.32.7")
		if deliverServerOriginatedToDevice(97, dst, mkIPv4(dst)) {
			t.Error("队列满却报告投递成功 —— 调用方会以为包已经在路上")
		}
		if subnetRouteDroppedFull.Load() != before+1 {
			t.Error("没记 full 计数")
		}
	})
}
