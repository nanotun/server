package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// 审批状态这条路上还剩三处各自独立的静默失效。
//
//   - 出口宣告帧到达时,若该设备**已经**被批准过(admin 先批、客户端后重发声明),要当场打开伪装豁免闸
//     并广播出口列表。不做的话:宣告方的出口回程流量被当伪装丢掉,而使用方的出口列表里看不到它 ——
//     两侧都表现为「批了但用不了」,且日志上一切正常。
//   - 子网侧的豁免闸有一个额外前提:只在路由表**确已加载**时才据其改写。表还没加载就写,会把一个其实
//     已批准的宣告方的豁免误清成 false(启动初 / reload 瞬间),它的 LAN 回程流量断到下次重连。
//   - 推给客户端的每条审批项带一个时间戳,取「宣告时间」与「批准时间」里更晚的那个。取错了,客户端 UI
//     会把刚批准的项显示成很久以前 —— 用户以为看到的是旧状态,继续等。

// deadlineRouteConn 是带写超时记录的假链路,用来验 sendRouteApproveStatusForDevice 真的加了写上限。
type deadlineRouteConn struct {
	routeFakeConn
	setCalls int
	lastDL   time.Time
	cleared  bool
}

func (c *deadlineRouteConn) SetWriteDeadline(t time.Time) error {
	c.setCalls++
	if t.IsZero() {
		c.cleared = true
		return nil
	}
	c.lastDL = t
	return nil
}

// TestHandleRouteAdvertiseFrame_OpensTheExemptionWhenTheDeviceIsAlreadyApproved 已批准的设备重发声明时当场生效。
func TestHandleRouteAdvertiseFrame_OpensTheExemptionWhenTheDeviceIsAlreadyApproved(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "preapproved-exit")

	// admin 先批准,客户端之后才(重连/重发)送来出口声明。
	approveExitRoute(t, devID, "0.0.0.0/0")

	fake := &routeFakeConn{}
	c := &Connection{userID: "1", connIDStr: "exit-readvertise", deviceID: devID, linkConn: fake}
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, c.connIDStr)
		connIDMapMu.Unlock()
	})

	// 等出口列表广播落地后再让 t.Cleanup 还原 gatewayInstance —— 那条广播是分离 goroutine。
	watcher := registerExitsWatcher(t)

	body, err := json.Marshal(util.RouteAdvertise{
		Schema: util.RouteSchemaCurrent,
		Exit:   true,
		Routes: []string{"0.0.0.0/0", util.ExitDefaultRouteV6},
	})
	if err != nil {
		t.Fatal(err)
	}
	handleRouteAdvertiseFrame(context.Background(), c, body)

	if !c.advertisedExit.Load() {
		t.Fatal("出口标没打上")
	}
	if !c.advertisedExitV6.Load() {
		t.Error("本帧带了 ::/0 却没记 v6 出网能力 —— 发往它的公网 v6 会被就地回 ICMPv6 unreachable")
	}
	if !c.advertisedExitApproved.Load() {
		t.Error("设备早已批准,却没打开伪装豁免闸 —— 它的出口回程流量(非自身 vIP 作源)会被当伪装丢掉")
	}
	// 已批准的出口重发声明后必须广播出口列表,否则使用方的下拉里看不到这台在线出口;
	// 同时这也是同步点 —— 那条 goroutine 读 gatewayInstance,不等它就还原是真实的 data race。
	awaitExitsBroadcast(t, watcher)
}

// TestBroadcastRouteApproveStatus_LeavesTheSubnetExemptionAloneUntilTheTableIsLoaded 表未加载时不许改写子网豁免闸。
func TestBroadcastRouteApproveStatus_LeavesTheSubnetExemptionAloneUntilTheTableIsLoaded(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "subnet-adv")

	t.Run("表未加载:保留上次已知值", func(t *testing.T) {
		prevTable := subnetRouteTable.Load()
		subnetRouteTable.Store(nil)
		t.Cleanup(func() { subnetRouteTable.Store(prevTable) })

		c, _ := registerAdvertiser(t, "subnet-unloaded", devID, false, true)
		c.advertisedSubnetApproved.Store(true) // 上次已确证批准过

		broadcastRouteApproveStatusToAdvertisers(context.Background())

		if !c.advertisedSubnetApproved.Load() {
			t.Error("路由表未加载时把豁免闸清掉了 —— 一个其实已批准的子网路由器,其 LAN 回程流量会断到下次重连")
		}
	})

	t.Run("表已加载:按表改写", func(t *testing.T) {
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.50.0/24", devID)})

		c, _ := registerAdvertiser(t, "subnet-loaded", devID, false, true)
		broadcastRouteApproveStatusToAdvertisers(context.Background())
		if !c.advertisedSubnetApproved.Load() {
			t.Error("表里明明有它,豁免闸却没打开")
		}

		// 表里没有它 = 已撤销,必须立刻收紧。
		other, _ := registerAdvertiser(t, "subnet-revoked", devID+9999, false, true)
		other.advertisedSubnetApproved.Store(true)
		broadcastRouteApproveStatusToAdvertisers(context.Background())
		if other.advertisedSubnetApproved.Load() {
			t.Error("表里已无它却仍开着豁免闸 —— 撤销后它还能以非自身 vIP 的源地址发包")
		}
	})
}

// TestSendRouteApproveStatusForDevice_UsesTheLaterTimestampAndBoundsTheWrite 时间戳取更晚者,且写有上限。
func TestSendRouteApproveStatusForDevice_UsesTheLaterTimestampAndBoundsTheWrite(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "ts-adv")

	// 宣告在先、批准在后:客户端该看到的是**批准**那一刻。两个时间戳都是秒级,同一秒内落库会相等 ——
	// 那样「取错了字段」根本看不出来,所以把宣告时间显式推到一小时前,让两者严格有序。
	approveExitRoute(t, devID, "10.99.0.0/24")
	if _, err := gw.store.DB().ExecContext(t.Context(),
		`UPDATE subnet_routes SET advertised_at = approved_at - 3600 WHERE device_id = ? AND cidr = ?`,
		devID, "10.99.0.0/24"); err != nil {
		t.Fatalf("把宣告时间推到一小时前: %v", err)
	}
	rows, err := gw.store.ListRoutesByDevice(t.Context(), devID)
	if err != nil {
		t.Fatal(err)
	}
	var wantAt int64
	for _, r := range rows {
		if r.CIDR == "10.99.0.0/24" {
			wantAt = r.ApprovedAt
			if r.ApprovedAt <= r.AdvertisedAt {
				t.Fatalf("前置条件不成立:ApprovedAt(%d) 不严格晚于 AdvertisedAt(%d)", r.ApprovedAt, r.AdvertisedAt)
			}
		}
	}
	if wantAt == 0 {
		t.Fatal("库里没查到那条已批准路由")
	}

	link := &deadlineRouteConn{}
	c := &Connection{userID: "1", connIDStr: "ts-sess", deviceID: devID, linkConn: link}
	if err := sendRouteApproveStatusForDevice(t.Context(), c, nil); err != nil {
		t.Fatalf("推审批状态: %v", err)
	}

	typ, frameBody, err := util.ReadLinkFrame(bytes.NewReader(link.bytes()))
	if err != nil {
		t.Fatalf("读回帧: %v", err)
	}
	if typ != util.LinkTypeRouteApproveStatus {
		t.Fatalf("帧类型 %v,期望 RouteApproveStatus", typ)
	}
	rs, err := util.ParseRouteApproveStatus(frameBody)
	if err != nil {
		t.Fatalf("解审批状态: %v", err)
	}
	entries := rs.Updated
	var got int64 = -1
	for _, e := range entries {
		if e.CIDR == "10.99.0.0/24" {
			got = e.At
		}
	}
	if got != wantAt {
		t.Errorf("审批项时间戳 = %d,want %d(批准时刻)—— 客户端 UI 会把刚批准的项显示成旧状态", got, wantAt)
	}

	if link.setCalls == 0 || link.lastDL.IsZero() {
		t.Error("没给这次写加超时 —— 客户端停止读取就能让这次写永久阻塞,顶死同样要 linkWrMu 的 kick / keepalive")
	}
	if !link.cleared {
		t.Error("写完没撤掉 deadline —— 它会残留到这条链路后续所有写上")
	}
}
