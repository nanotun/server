package main

// 出口裁决的拒绝面。
//
// 这一层判错的后果全是静默的:要么把用户明确想避开的「从 server 公网 IP 出网」偷偷
// 给他(fail-open 泄漏),要么把本该走原链路的 mesh 流量当公网包扔给出口节点(黑洞)。
// 两种都不报错、不掉线,只是"网怪怪的"。所以这里钉的是**边界与不可判定**两类:
//
//   - forwardPacketToExitNode 的四道尚未被覆盖的闸:空会话、包头解析不出、目的落在
//     mesh 网段但当前无在线归属、包超过 TUN 缓冲。
//   - resolveApprovedExitDeviceID / deviceHasApprovedExitRoute 的 **ok=false 语义**:
//     「查不动」必须与「确实未批准」区分开。混为一谈的话,一次 DB 抖动就会把仍然有效的
//     出口会话误撤销 —— 用户那头看到的是网突然断了,日志里什么都没有。
//   - restoreFailClosedBindings 的几条 continue:isolate 模式下不许绕过、CAS 失败
//     (客户端自己已改选)不许硬拽回来。

import (
	"context"
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// mkIPv4Sized 造一个总长 n 字节的合法 IPv4/TCP 包(头 20B,其余填充)。
// parsePacketTuple 不校验 IP 头里的 total length 字段,只看 IHL 与实际切片长度,
// 所以填充内容无关紧要 —— 这里要的只是「一个能过前面所有闸、但超过 tunBufSize 的包」。
func mkIPv4Sized(dst netip.Addr, n int) []byte {
	if n < 20 {
		n = 20
	}
	p := make([]byte, n)
	p[0] = 0x45
	p[9] = 6
	d := dst.As4()
	copy(p[16:20], d[:])
	return p
}

// TestForwardPacketToExitNode_NilConnAndUnparsablePacket 钉住两条「根本没法判定」的入口:
// 都必须返回 false(交回调用方走原链路),而不是当成已处理默默丢掉。
//
// 方向很要紧:这两条返 true 会让包凭空消失且不计任何计数器 —— 排查时看不到任何线索。
func TestForwardPacketToExitNode_NilConnAndUnparsablePacket(t *testing.T) {
	resetConnByDeviceForTest(t)

	if forwardPacketToExitNode(nil, mkIPv4(netip.MustParseAddr("8.8.8.8"))) {
		t.Fatal("nil 会话必须返回 false(交回原链路),返 true 等于把包吞了还不留计数")
	}

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	a.egressDeviceID.Store(77) // 已绑出口:确保不是被 egress==0 那条提前挡下的

	for name, pkt := range map[string][]byte{
		"空包":           {},
		"只有一个字节":       {0x45},
		"声称是 v4 但不足头长": {0x45, 0, 0, 0, 0},
		"版本号是 7":       append([]byte{0x75}, make([]byte, 30)...),
	} {
		t.Run(name, func(t *testing.T) {
			if forwardPacketToExitNode(a, pkt) {
				t.Fatalf("解析不出五元组的包必须返回 false,got true(包被静默吞掉)")
			}
		})
	}
}

// TestForwardPacketToExitNode_MeshCIDRDstWithoutOwnerIsDropped 钉住第十六轮那条守卫:
// 目的**落在 server 自己的 mesh 网段内**、但当前没有在线归属(对端离线 / 从未登录),
// 必须就地 fail-closed 丢弃,而不是当公网包转发给 peer 出口。
//
// 转发出去有两重坏处:把内部 mesh 编址泄漏给出口节点,且在出口侧注定黑洞。
// isLocalMeshDst 只认「在线 vIP + 网关」,所以这类地址会漏到 isMeshCIDRAddr 这一层来。
func TestForwardPacketToExitNode_MeshCIDRDstWithoutOwnerIsDropped(t *testing.T) {
	resetConnByDeviceForTest(t)
	setServerGatewayAddrs("10.201.0.1/16", "fd00:200::1/64")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	a.egressDeviceID.Store(77) // 绑了 peer 出口(该出口并不在线,用来证明拦截发生在更早)

	before := exitForwardDroppedMeshDst.Load()
	beforeOffline := exitForwardDroppedOffline.Load()

	// 10.201.9.9 在 mesh 网段内,既不是网关也没有在线归属。
	if !forwardPacketToExitNode(a, mkIPv4(netip.MustParseAddr("10.201.9.9"))) {
		t.Fatal("mesh 网段内的无主地址应 fail-closed 返回 true(丢弃),不该回退 server 自出口")
	}
	if got := exitForwardDroppedMeshDst.Load(); got != before+1 {
		t.Fatalf("exitForwardDroppedMeshDst 应 +1(%d → %d)", before, got)
	}
	// 必须是被 meshDst 这条拦下的,不是漏到后面才因为「出口离线」丢掉 ——
	// 两者都返 true,只有计数器能区分,而排查时看的正是计数器。
	if got := exitForwardDroppedOffline.Load(); got != beforeOffline {
		t.Fatalf("不该记成「出口离线」丢包(%d → %d):那说明包漏过了 mesh 网段守卫", beforeOffline, got)
	}

	// 对照:同样没有在线归属,但地址在 mesh 网段**外** → 正常走出口路径(此处出口离线,记 offline)。
	if !forwardPacketToExitNode(a, mkIPv4(netip.MustParseAddr("8.8.8.8"))) {
		t.Fatal("公网目的仍应由出口路径处理")
	}
	if got := exitForwardDroppedOffline.Load(); got != beforeOffline+1 {
		t.Fatalf("公网目的 + 出口离线应记 offline(%d → %d)", beforeOffline, got)
	}
	if got := exitForwardDroppedMeshDst.Load(); got != before+1 {
		t.Fatal("公网目的不该记进 meshDst —— 别把守卫写成「一律拦」")
	}
}

// TestForwardPacketToExitNode_OversizePacketDropped 钉住超长包的处置:大于 tunBufSize
// 的包丢弃并计数,不能塞进出口会话的 TunChan(对端按 tunBufSize 读,超长要么被截断成
// 半个包、要么把读循环搞乱)。
//
// 这条排在「出口在线」之后,所以用例必须先把出口备齐 —— 否则会被 offline 提前拦下,
// 覆盖率看着亮了而断言其实验的是另一条路。
func TestForwardPacketToExitNode_OversizePacketDropped(t *testing.T) {
	resetConnByDeviceForTest(t)

	tunCh := make(chan *util.TunPacket, 4)
	exit := &Connection{deviceID: 77, connIDStr: "exit1"}
	exit.advertisedExit.Store(true)
	ips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: tunCh}}
	exit.clientIPs.Store(&ips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	a.egressDeviceID.Store(77)

	before := exitForwardDroppedOversize.Load()
	beforeFwd := exitForwarded.Load()

	if !forwardPacketToExitNode(a, mkIPv4Sized(netip.MustParseAddr("8.8.8.8"), tunBufSize+1)) {
		t.Fatal("超长包应返回 true(已处理:丢弃)")
	}
	if got := exitForwardDroppedOversize.Load(); got != before+1 {
		t.Fatalf("exitForwardDroppedOversize 应 +1(%d → %d)", before, got)
	}
	if got := exitForwarded.Load(); got != beforeFwd {
		t.Fatal("超长包不该被计入已转发")
	}
	if len(tunCh) != 0 {
		t.Fatal("超长包不该进出口会话的 TunChan")
	}

	// 边界对照:正好 tunBufSize 必须放行(判据是 > 不是 >=,写反了会把最大包也丢掉)。
	if !forwardPacketToExitNode(a, mkIPv4Sized(netip.MustParseAddr("8.8.8.8"), tunBufSize)) {
		t.Fatal("恰好 tunBufSize 的包应被处理")
	}
	if got := exitForwardDroppedOversize.Load(); got != before+1 {
		t.Fatal("恰好 tunBufSize 不该记成超长 —— 边界判成了 >=")
	}
	if got := exitForwarded.Load(); got != beforeFwd+1 {
		t.Fatalf("恰好 tunBufSize 应转发成功(%d → %d)", beforeFwd, got)
	}
}

// mustCreateUserAndDevice 给每台设备用的是同一个硬编码 UUID,想区分两台设备就得自己造。
const (
	lanOnlyUUID  = "22222222-2222-4222-8222-222222222222"
	realExitUUID = "33333333-3333-4333-8333-333333333333"
)

func mustCreateDeviceWithUUID(t *testing.T, gw *gatewayState, username, uuid string) int64 {
	t.Helper()
	ctx := t.Context()
	u, err := gw.store.CreateUser(ctx, store.NewUser{Username: username, PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser %s: %v", username, err)
	}
	d, err := gw.store.UpsertDevice(ctx, u.ID, uuid, username+"-dev", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice %s: %v", username, err)
	}
	return d.ID
}

// withEgressTestGateway 装一个带 store 的 gatewayInstance,返回它。
func withEgressTestGateway(t *testing.T) *gatewayState {
	t.Helper()
	gw := newRouteTestGateway(t)
	old := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = old })
	return gw
}

// TestResolveApprovedExitDeviceID_CannotDetermineVsNotApproved 把「查不动」与「确实不是
// 已批准出口」分开钉住 —— 这两者返回的 deviceID 都是 0,唯一的区别是第二个返回值。
//
// 混淆的后果:调用方(选择期与复核期)会把一次 DB 抖动当成「这个出口没批准」,
// 于是要么回退 server 自出口(泄漏用户想避开的出网 IP),要么撤销一个仍然有效的绑定。
func TestResolveApprovedExitDeviceID_CannotDetermineVsNotApproved(t *testing.T) {
	ctx := context.Background()

	t.Run("无 store 时是「查不动」而非「未批准」", func(t *testing.T) {
		old := gatewayInstance
		gatewayInstance = &gatewayState{} // 有 gateway 但没 store
		t.Cleanup(func() { gatewayInstance = old })
		if id, ok := resolveApprovedExitDeviceID(ctx, "any-uuid"); id != 0 || ok {
			t.Fatalf("无 store 应返回 (0,false)=查不动, got (%d,%v)", id, ok)
		}
	})

	t.Run("gatewayInstance 为 nil 同样是查不动", func(t *testing.T) {
		old := gatewayInstance
		gatewayInstance = nil
		t.Cleanup(func() { gatewayInstance = old })
		if id, ok := resolveApprovedExitDeviceID(ctx, "any-uuid"); id != 0 || ok {
			t.Fatalf("无 gateway 应返回 (0,false), got (%d,%v)", id, ok)
		}
	})

	t.Run("空 UUID 是明确的「不是出口」", func(t *testing.T) {
		withEgressTestGateway(t)
		if id, ok := resolveApprovedExitDeviceID(ctx, "   "); id != 0 || !ok {
			t.Fatalf("空 UUID 应返回 (0,true)=确定不是出口, got (%d,%v)", id, ok)
		}
	})

	t.Run("查过了但确实没批准", func(t *testing.T) {
		gw := withEgressTestGateway(t)
		mustCreateUserAndDevice(t, gw, "noexit")
		if id, ok := resolveApprovedExitDeviceID(ctx, "11111111-1111-4111-8111-111111111111"); id != 0 || !ok {
			t.Fatalf("无 approved 出口路由应返回 (0,true), got (%d,%v)", id, ok)
		}
	})

	t.Run("只批了 LAN 路由的设备不是出口", func(t *testing.T) {
		gw := withEgressTestGateway(t)
		// 两台设备:一台只有已批准的 LAN 子网宣告,一台有已批准的全网路由。
		// 前者必须解析不到 —— 「批准了子网路由」与「批准当公网出口」是两回事,
		// 混起来等于 admin 批一条内网段就顺手给了对方一个公网出口资格。
		lanDev := mustCreateDeviceWithUUID(t, gw, "lanonly", lanOnlyUUID)
		exitDev := mustCreateDeviceWithUUID(t, gw, "realexit", realExitUUID)
		approve := func(devID int64, cidr string) {
			if _, err := gw.store.UpsertAdvertisedRoute(ctx, devID, cidr); err != nil {
				t.Fatalf("宣告 %s: %v", cidr, err)
			}
			if err := gw.store.SetRouteStatus(ctx, devID, cidr, store.RouteStatusApproved, ""); err != nil {
				t.Fatalf("批准 %s: %v", cidr, err)
			}
		}
		approve(lanDev, "192.168.7.0/24")
		approve(exitDev, "0.0.0.0/0")

		if id, ok := resolveApprovedExitDeviceID(ctx, lanOnlyUUID); id != 0 || !ok {
			t.Fatalf("只批了 192.168.7.0/24 的设备不该被解析成出口, got (%d,%v)", id, ok)
		}
		if id, ok := resolveApprovedExitDeviceID(ctx, realExitUUID); !ok || id != exitDev {
			t.Fatalf("批了 0.0.0.0/0 的设备应解析到 %d, got (%d,%v)", exitDev, id, ok)
		}
	})

	t.Run("DB 查不动时是 (0,false)", func(t *testing.T) {
		gw := withEgressTestGateway(t)
		if _, err := gw.store.DB().ExecContext(ctx,
			`ALTER TABLE subnet_routes RENAME TO subnet_routes_gone`); err != nil {
			t.Fatalf("藏掉 subnet_routes: %v", err)
		}
		if id, ok := resolveApprovedExitDeviceID(ctx, "11111111-1111-4111-8111-111111111111"); id != 0 || ok {
			t.Fatalf("DB 错误应返回 (0,false)=查不动, got (%d,%v)", id, ok)
		}
	})
}

// TestDeviceHasApprovedExitRoute_CannotDetermineVsNotApproved 同上,针对按 deviceID 的那条查询。
func TestDeviceHasApprovedExitRoute_CannotDetermineVsNotApproved(t *testing.T) {
	ctx := context.Background()

	t.Run("deviceID 为 0 是查不动", func(t *testing.T) {
		withEgressTestGateway(t)
		if approved, ok := deviceHasApprovedExitRoute(ctx, 0); approved || ok {
			t.Fatalf("deviceID=0 应返回 (false,false), got (%v,%v)", approved, ok)
		}
	})

	t.Run("无 store 是查不动", func(t *testing.T) {
		old := gatewayInstance
		gatewayInstance = &gatewayState{}
		t.Cleanup(func() { gatewayInstance = old })
		if approved, ok := deviceHasApprovedExitRoute(ctx, 5); approved || ok {
			t.Fatalf("无 store 应返回 (false,false), got (%v,%v)", approved, ok)
		}
	})

	t.Run("DB 查不动也是 (false,false)", func(t *testing.T) {
		gw := withEgressTestGateway(t)
		_, devID := mustCreateUserAndDevice(t, gw, "dberr")
		if _, err := gw.store.DB().ExecContext(ctx,
			`ALTER TABLE subnet_routes RENAME TO subnet_routes_gone`); err != nil {
			t.Fatalf("藏掉 subnet_routes: %v", err)
		}
		approved, ok := deviceHasApprovedExitRoute(ctx, devID)
		if approved || ok {
			t.Fatalf("DB 错误应返回 (false,false)=查不动, got (%v,%v)", approved, ok)
		}
	})

	t.Run("查过了确实没批准", func(t *testing.T) {
		gw := withEgressTestGateway(t)
		_, devID := mustCreateUserAndDevice(t, gw, "pending")
		// 有宣告但仍是 pending:未批准 ≠ 查不动,ok 必须为 true。
		if _, err := gw.store.UpsertAdvertisedRoute(ctx, devID, "0.0.0.0/0"); err != nil {
			t.Fatalf("宣告出口: %v", err)
		}
		approved, ok := deviceHasApprovedExitRoute(ctx, devID)
		if approved || !ok {
			t.Fatalf("pending 出口应返回 (false,true), got (%v,%v)", approved, ok)
		}
	})
}

// TestRestoreFailClosedBindings_RefusalPaths 钉住自动接回的几条「不接」:
//
//   - isolate 模式下经 peer 出口本就被禁,接回等于从这条路径上绕过隔离;
//   - 客户端自己已经改了出口(egressDeviceID 不再是哨兵)时,CAS 必须失败并放手 ——
//     否则会把一个已经回落 server 的会话硬拽回 peer 出口,而用户那头刚刚才切过去。
func TestRestoreFailClosedBindings_RefusalPaths(t *testing.T) {
	ctx := context.Background()
	const uuid = "11111111-1111-4111-8111-111111111111"

	// 备好一个「已批准出口」的库,让「不接」只可能来自被测的那条判定。
	newApprovedGateway := func(t *testing.T) int64 {
		t.Helper()
		gw := withEgressTestGateway(t)
		_, devID := mustCreateUserAndDevice(t, gw, "exitowner")
		if _, err := gw.store.UpsertAdvertisedRoute(ctx, devID, "0.0.0.0/0"); err != nil {
			t.Fatalf("宣告出口: %v", err)
		}
		if err := gw.store.SetRouteStatus(ctx, devID, "0.0.0.0/0", store.RouteStatusApproved, ""); err != nil {
			t.Fatalf("批准出口: %v", err)
		}
		return devID
	}

	t.Run("空 pending 直接返回", func(t *testing.T) {
		restoreFailClosedBindings(ctx, nil) // 不该 panic,也不该碰 gatewayInstance
	})

	t.Run("isolate 模式下不接回", func(t *testing.T) {
		devID := newApprovedGateway(t)
		prev := clientIsolateMode.Swap(true)
		t.Cleanup(func() { clientIsolateMode.Store(prev) })

		c := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
		c.egressDeviceID.Store(egressFailClosed)
		c.desiredExitUUID.Store(uuid)

		restoreFailClosedBindings(ctx, []exitBinding{{c: c, dev: devID}})
		if got := c.egressDeviceID.Load(); got != egressFailClosed {
			t.Fatalf("isolate 下必须保持 fail-closed, got %d", got)
		}
	})

	t.Run("没记住想要哪个出口就不接", func(t *testing.T) {
		devID := newApprovedGateway(t)
		c := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
		c.egressDeviceID.Store(egressFailClosed)
		c.desiredExitUUID.Store("") // 忘了/从未记住

		restoreFailClosedBindings(ctx, []exitBinding{{c: c, dev: devID}})
		if got := c.egressDeviceID.Load(); got != egressFailClosed {
			t.Fatalf("没有 desiredExitUUID 时不该接回, got %d", got)
		}
	})

	t.Run("客户端已自行改选时 CAS 失败要放手", func(t *testing.T) {
		devID := newApprovedGateway(t)
		c := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
		// 关键:已经不是哨兵了(比如收到 revoked 后按 --exit-fallback-server 回落 server)。
		c.egressDeviceID.Store(0)
		c.desiredExitUUID.Store(uuid)

		restoreFailClosedBindings(ctx, []exitBinding{{c: c, dev: devID}})
		if got := c.egressDeviceID.Load(); got != 0 {
			t.Fatalf("客户端已自行回落 server,不该被拽回 peer 出口(egress=%d)", got)
		}
	})

	t.Run("选到自己当出口不接", func(t *testing.T) {
		devID := newApprovedGateway(t)
		c := &Connection{userID: "u1", connIDStr: "a", deviceID: devID} // 自己就是那台出口
		c.egressDeviceID.Store(egressFailClosed)
		c.desiredExitUUID.Store(uuid)

		restoreFailClosedBindings(ctx, []exitBinding{{c: c, dev: devID}})
		if got := c.egressDeviceID.Load(); got != egressFailClosed {
			t.Fatalf("自环不该被接回, got %d", got)
		}
	})

	// 反面对照:条件都满足时**必须**接回 —— 否则上面五条「不接」可以由一个
	// 什么都不做的实现全部满足。
	t.Run("条件齐备时接回并写回 desired", func(t *testing.T) {
		devID := newApprovedGateway(t)
		fake := &routeFakeConn{}
		c := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, linkConn: fake}
		c.egressDeviceID.Store(egressFailClosed)
		c.desiredExitUUID.Store(uuid)

		restoreFailClosedBindings(ctx, []exitBinding{{c: c, dev: devID}})
		if got := c.egressDeviceID.Load(); got != devID {
			t.Fatalf("出口已批回来,应接回设备 %d, got %d", devID, got)
		}
		if got := c.desiredExitDeviceID.Load(); got != devID {
			t.Fatalf("desiredExitDeviceID 应同步为 %d, got %d", devID, got)
		}
		// 光把服务端的绑定改回来不够:客户端不知道自己已经恢复,还会一直以为在 fail-closed。
		// 所以必须回一帧 accepted ack。
		if len(fake.bytes()) == 0 {
			t.Fatal("接回后应回一帧 EgressSelectAck,否则客户端无从得知已恢复")
		}
	})
}
