package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/nanotun/server/util"
)

// 「admin 改了批准，宣告方在线」这条路径。
//
// 它做两件表面无关的事,漏掉任何一件都不报错:
//
//   - 推一帧 RouteApproveStatus,让宣告方 UI 的「待审批 → 已批准」实时翻转。不推的话,宣告方
//     一直显示 pending —— 用户以为没批,反复重发声明。
//   - 刷新会话上的**源地址伪装豁免闸**(advertisedExitApproved / advertisedSubnetApproved)。
//     这个闸决定该会话能不能以非自身 vIP 的源地址发包(出口 NAT / LAN 回程要用)。批准后不刷,
//     宣告方合法的回程流量会被一路丢到它下次重连;撤销后不刷,则是特权多留了同样久。
//
// 两者都只在「宣告方在线时被 admin 改批准」这个时序里才需要 —— 重连会重走登录那条路。

// registerAdvertiser 把一条宣告方会话挂进 connIDMap(收尾摘掉),返回它与它的 fake 链路。
func registerAdvertiser(t *testing.T, sid string, deviceID int64, exit, subnet bool) (*Connection, *routeFakeConn) {
	t.Helper()
	fake := &routeFakeConn{}
	c := &Connection{userID: "u-" + sid, connIDStr: sid, deviceID: deviceID, linkConn: fake}
	c.advertisedExit.Store(exit)
	c.advertisedSubnetRoutes.Store(subnet)
	connIDMapMu.Lock()
	connIDMap[sid] = c
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, sid)
		connIDMapMu.Unlock()
	})
	return c, fake
}

// approveExitRoute 让某设备名下的默认路由变成 approved(模拟 admin designate exit)。
func approveExitRoute(t *testing.T, deviceID int64, cidr string) {
	t.Helper()
	st := gatewayInstance.store
	if _, err := st.UpsertAdvertisedRoute(t.Context(), deviceID, cidr); err != nil {
		t.Fatalf("落宣告路由: %v", err)
	}
	if err := st.SetRouteStatus(t.Context(), deviceID, cidr, util.RouteStatusApproved, ""); err != nil {
		t.Fatalf("置 approved: %v", err)
	}
}

// TestBroadcastRouteApproveStatus_RefreshesTheSpoofExemptionOfOnlineAdvertisers 在线宣告方要被刷新。
func TestBroadcastRouteApproveStatus_RefreshesTheSpoofExemptionOfOnlineAdvertisers(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "exit-adv")

	c, fake := registerAdvertiser(t, "adv-exit", devID, true, false)
	if c.advertisedExitApproved.Load() {
		t.Fatal("前置条件不成立:豁免闸本该还是关的")
	}

	// admin 批准之后再广播 —— 正是「宣告方在线时被批准」那个时序。
	approveExitRoute(t, devID, "0.0.0.0/0")
	broadcastRouteApproveStatusToAdvertisers(context.Background())

	if !c.advertisedExitApproved.Load() {
		t.Error("批准后没刷新伪装豁免闸 —— 宣告方合法的出口回程流量会被一路丢到它下次重连")
	}
	if len(fake.bytes()) == 0 {
		t.Error("没给宣告方推审批状态帧 —— 它的 UI 会一直停在 pending,用户以为没批而反复重发声明")
	}
}

// TestBroadcastRouteApproveStatus_ClosesTheExemptionWhenApprovalIsRevoked 撤销要立刻收紧。
//
// 与上面方向相反,而这一侧更敏感:撤销后闸门不关,等于该会话继续能以别人的源地址发包,
// 一直到它下次重连。
func TestBroadcastRouteApproveStatus_ClosesTheExemptionWhenApprovalIsRevoked(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "revoked-adv")

	c, _ := registerAdvertiser(t, "adv-revoked", devID, true, false)
	c.advertisedExitApproved.Store(true) // 之前批过

	// 库里那条出口路由被改回 pending(admin revoke)。
	approveExitRoute(t, devID, "0.0.0.0/0")
	if err := gw.store.SetRouteStatus(t.Context(), devID, "0.0.0.0/0", util.RouteStatusPending, "revoked"); err != nil {
		t.Fatalf("置回 pending: %v", err)
	}
	broadcastRouteApproveStatusToAdvertisers(context.Background())

	if c.advertisedExitApproved.Load() {
		t.Error("撤销批准后豁免闸还开着 —— 该会话继续能以非自身 vIP 的源地址发包,直到它下次重连")
	}
}

// TestBroadcastRouteApproveStatus_SkipsSessionsThatShouldNotGetIt 三类会话不该收到。
//
// 普通客户端收到一帧空的审批状态只是噪声;但给**已被接管 / 已被顶替**的会话写,是往一条正在
// 拆除的链路上同步写(本函数持 linkWrMu 并带写超时),会顶住同样要拿这把锁的 kick / keepalive。
func TestBroadcastRouteApproveStatus_SkipsSessionsThatShouldNotGetIt(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "skip-adv")
	approveExitRoute(t, devID, "0.0.0.0/0")

	_, plain := registerAdvertiser(t, "plain", devID, false, false) // 没宣告过任何东西
	taken, takenFake := registerAdvertiser(t, "taken", devID, true, false)
	taken.takenOver.Store(true)
	sup, supFake := registerAdvertiser(t, "superseded", devID, true, false)
	sup.superseded.Store(true)

	broadcastRouteApproveStatusToAdvertisers(context.Background())

	for _, tc := range []struct {
		name string
		fake *routeFakeConn
	}{
		{"普通客户端", plain},
		{"已被接管的会话", takenFake},
		{"已被顶替的会话", supFake},
	} {
		if len(tc.fake.bytes()) != 0 {
			t.Errorf("%s 也收到了审批状态帧 —— 往正在拆除的链路同步写会顶住同样要 linkWrMu 的 kick / keepalive", tc.name)
		}
	}
}

// TestSendRouteApproveStatusForDevice_OnlyFilterAndFullTable only 过滤与全表两种用法。
//
// only 用于「刚 upsert 完这几条,只回这几条」;为空时回全表(重连后同步整个状态)。过滤失效会把
// 该设备名下所有路由都回给客户端,UI 上表现为「明明只声明了一条,却列出一堆历史条目」。
func TestSendRouteApproveStatusForDevice_OnlyFilterAndFullTable(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "filter-adv")
	approveExitRoute(t, devID, "192.168.70.0/24")
	approveExitRoute(t, devID, "192.168.71.0/24")

	decode := func(t *testing.T, only []string) []util.RouteStatusEntry {
		t.Helper()
		fake := &routeFakeConn{}
		c := &Connection{userID: "u", deviceID: devID, linkConn: fake}
		if err := sendRouteApproveStatusForDevice(t.Context(), c, only); err != nil {
			t.Fatalf("发审批状态: %v", err)
		}
		typ, body, err := util.ReadLinkFrame(bytes.NewReader(fake.bytes()))
		if err != nil {
			t.Fatalf("读回帧: %v", err)
		}
		if typ != util.LinkTypeRouteApproveStatus {
			t.Fatalf("帧类型 %v,期望 RouteApproveStatus", typ)
		}
		rs, err := util.ParseRouteApproveStatus(body)
		if err != nil {
			t.Fatalf("解审批状态: %v", err)
		}
		return rs.Updated
	}

	t.Run("only 只回列表里的", func(t *testing.T) {
		got := decode(t, []string{"192.168.71.0/24"})
		if len(got) != 1 || got[0].CIDR != "192.168.71.0/24" {
			t.Fatalf("回了 %+v,期望只有 192.168.71.0/24", got)
		}
	})

	t.Run("only 为空回全表", func(t *testing.T) {
		if got := decode(t, nil); len(got) != 2 {
			t.Fatalf("回了 %d 条,期望全表 2 条", len(got))
		}
	})

	t.Run("没有 deviceID 直接不发", func(t *testing.T) {
		fake := &routeFakeConn{}
		c := &Connection{userID: "u", linkConn: fake} // deviceID = 0
		if err := sendRouteApproveStatusForDevice(t.Context(), c, nil); err != nil {
			t.Fatalf("匿名会话不该报错: %v", err)
		}
		if len(fake.bytes()) != 0 {
			t.Error("没有 deviceID 也发了帧 —— 那帧内容必然属于别人或为空")
		}
	})
}
