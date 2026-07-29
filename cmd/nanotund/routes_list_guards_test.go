package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// 子网路由列表是客户端 UI 上「哪些网段现在能走」的唯一来源,而它的 Online 位不能只看「设备有会话」。
//
// 一台机器可以连上来但**这次没带 --advertise-routes**(或重连时收窄了宣告集),而 DB 里的批准还在。
// 此时把它标成在线,用户就会看到一条标着「可用」的网段,流量却在数据面被丢 —— 而数据面丢包的判据
// 恰恰是同一份当前宣告集。UI 说能走、包却不通,是最难查的一类:两侧都"正常"。

// TestDeviceServesSubnetRoute_TrustsTheCurrentAdvertisement 判据取当前宣告集,不是 DB 批准。
func TestDeviceServesSubnetRoute_TrustsTheCurrentAdvertisement(t *testing.T) {
	pfx := netip.MustParsePrefix("192.168.44.0/24")

	t.Run("宣告集覆盖该网段", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		addAdvertiserConnWithRoutes(t, 44, "adv-ok", "10.0.0.44", []string{"192.168.44.0/24"})
		if !deviceServesSubnetRoute(44, pfx) {
			t.Error("宣告方在线且宣告集覆盖该网段,却报不可用")
		}
	})

	t.Run("重连后收窄了宣告集", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		// DB 批准仍在(表里有这条),但这次连上来只宣告了另一段。
		addAdvertiserConnWithRoutes(t, 45, "adv-narrow", "10.0.0.45", []string{"192.168.99.0/24"})
		if deviceServesSubnetRoute(45, pfx) {
			t.Error("当前宣告集不含该网段却报可用 —— UI 说能走,数据面照旧丢包")
		}
	})

	t.Run("宣告方不在跑子网路由", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		// 普通客户端连入 / 本次只跑 --exit-node:设备在线,但不是子网路由器。
		addAdvertiserConn(t, 46, "adv-plain", "10.0.0.46")
		connIDMapMu.RLock()
		adv := lookupSubnetAdvertiserConnByDevice(46)
		connIDMapMu.RUnlock()
		if adv == nil && deviceServesSubnetRoute(46, pfx) {
			t.Error("没有在跑子网路由的会话却报可用")
		}
	})

	t.Run("宣告方离线", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		if deviceServesSubnetRoute(47, pfx) {
			t.Error("宣告方根本不在线却报可用")
		}
	})

	t.Run("宣告集未知时保守放行", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		// 在跑子网路由但宣告集为空/未知(老客户端不上报明细)。这里与数据面同口径:
		// 未知 → 放行。判反方向的代价是老客户端的全部网段在 UI 上一律显示不可用。
		addAdvertiserConnWithRoutes(t, 48, "adv-unknown", "10.0.0.48", nil)
		if !deviceServesSubnetRoute(48, pfx) {
			t.Error("宣告集未知时报了不可用 —— 与数据面『nil 放行』的兜底口径不一致")
		}
	})
}

// TestBroadcastRoutesList_SkipsSupersededSessions 广播只发给还活着的会话。
//
// 被接管的旧会话对象还在表里等清理,而它的链路已经交给新会话在用。往它写一帧,轻则白写,重则
// 与新会话的写并发抢同一条链路 —— 客户端会读到一帧夹在中间的乱序数据。
func TestBroadcastRoutesList_SkipsSupersededSessions(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.60.0/24", 60)})
	prevGW := gatewayInstance
	gatewayInstance = &gatewayState{}
	t.Cleanup(func() { gatewayInstance = prevGW })

	live := newFakeLinkConn()
	alive := &Connection{connIDStr: "routes-alive", userID: "1", linkConn: live, tunnelDone: make(chan struct{}), createdAt: time.Now()}
	deadLink := newFakeLinkConn()
	takenOver := &Connection{connIDStr: "routes-old", userID: "1", linkConn: deadLink, tunnelDone: make(chan struct{}), createdAt: time.Now()}
	takenOver.takenOver.Store(true)

	connIDMapMu.Lock()
	connIDMap[alive.connIDStr] = alive
	connIDMap[takenOver.connIDStr] = takenOver
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, alive.connIDStr)
		delete(connIDMap, takenOver.connIDStr)
		connIDMapMu.Unlock()
	})

	broadcastRoutesList(t.Context())

	if len(live.writeBuf) == 0 {
		t.Error("在线会话没收到路由列表 —— 它的 UI 会一直是空的")
	}
	if len(deadLink.writeBuf) != 0 {
		t.Error("往已被接管的旧会话写了帧 —— 那条链路现在归新会话,并发写会让客户端读到乱序数据")
	}
}

// TestSendRoutesListTo_IsSafeWithoutALink 没有链路时安全跳过。
//
// 会话对象在建立链路之前 / 清理之后都可能没有 linkConn。这条推送是 best-effort,不该因此崩掉
// 调用它的广播循环 —— 那会让**其余所有**在线客户端也拿不到列表。
func TestSendRoutesListTo_IsSafeWithoutALink(t *testing.T) {
	routes := []util.SubnetRouteInfo{{CIDR: "192.168.70.0/24", Online: true}}
	sendRoutesListTo(nil, routes)
	sendRoutesListTo(&Connection{connIDStr: "no-link"}, routes)
	pushInitialRoutesList(t.Context(), nil)
}
