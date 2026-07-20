package main

import (
	"testing"

	"github.com/nanotun/server/util"
)

// 出口机切网络 fresh 重登录黑洞修复的回归测试。
//
// 复现的 bug：同 device 全新登录触发 supersede（关旧链路 + 异步 cleanup），旧 conn 被关但**不设 takenOver、不清
// advertisedExit**；新 conn 尚未重发 RouteAdvertise（advertisedExit=false）。在「已踢未清」窗口里,旧 conn 是该
// device 唯一 advertisedExit&&!takenOver 会话 → lookupRunningExitConnByDevice 确定性选中它 → 请求方出口流量被
// 投进旧 conn 已关闭的链路黑洞。修法：supersede/evict 判定时立即对旧 conn 置 superseded=true,使所有 by-device
// lookup 立刻跳过它。本组测试直接操纵 connByDevice + superseded 标志验证 lookup 语义。

// installDeviceConn 把 conn 装进 connByDevice 索引(带 t.Cleanup 清理),供 by-device lookup 测试用。
// 与 supersede_test.go 的 installConn 互补：那个只装 connIDMap/connByUser,本函数补 connByDevice。
func installDeviceConn(t *testing.T, c *Connection) {
	t.Helper()
	connIDMapMu.Lock()
	connByDeviceAddLocked(c)
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		connByDeviceDeleteLocked(c)
		connIDMapMu.Unlock()
	})
}

// TestLookupRunningExitConnByDevice_SkipsSuperseded：核心回归——同 device 的「旧出口会话(advertisedExit,已被 supersede
// 标 superseded)」与「新会话(尚未 advertise)」并存时,lookupRunningExitConnByDevice 必须**跳过**旧会话。修复前它会
// 返回旧(已关闭)会话 → 黑洞;修复后返回 nil(fail-closed,请求方收 exit_offline,待新会话 advertise 后恢复)。
func TestLookupRunningExitConnByDevice_SkipsSuperseded(t *testing.T) {
	const dev = int64(9001)
	oldC := &Connection{connIDStr: "old-exit", deviceID: dev}
	oldC.advertisedExit.Store(true)
	oldC.superseded.Store(true) // 被同 device fresh 重登踢旧,标记待清理
	newC := &Connection{connIDStr: "new-exit", deviceID: dev}
	// 新会话尚未重发 RouteAdvertise → advertisedExit 默认 false。
	installDeviceConn(t, oldC)
	installDeviceConn(t, newC)

	if got := lookupRunningExitConnByDevice(dev); got != nil {
		t.Fatalf("superseded 旧出口会话不应被选中(应 fail-closed 返回 nil,待新会话 advertise),got connIDStr=%q", got.connIDStr)
	}
}

// TestLookupRunningExitConnByDevice_PicksNewAfterAdvertise：新会话重发 advertise（advertisedExit=true）后,
// 即便旧 superseded 会话仍在 map,lookup 也必须返回**新**会话(旧的被 superseded 跳过)。
func TestLookupRunningExitConnByDevice_PicksNewAfterAdvertise(t *testing.T) {
	const dev = int64(9002)
	oldC := &Connection{connIDStr: "old-exit2", deviceID: dev}
	oldC.advertisedExit.Store(true)
	oldC.superseded.Store(true)
	newC := &Connection{connIDStr: "new-exit2", deviceID: dev}
	newC.advertisedExit.Store(true) // 新会话已重发 advertise
	installDeviceConn(t, oldC)
	installDeviceConn(t, newC)

	got := lookupRunningExitConnByDevice(dev)
	if got != newC {
		var name string
		if got != nil {
			name = got.connIDStr
		} else {
			name = "<nil>"
		}
		t.Fatalf("应返回新出口会话 new-exit2,got %q", name)
	}
}

// TestLookupActiveConnByDevice_SkipsSuperseded：在线判定同样跳过 superseded（buildExitsList 的 Online 与
// routes-list 的 online 靠它;被踢会话不该算在线出口/子网）。
func TestLookupActiveConnByDevice_SkipsSuperseded(t *testing.T) {
	const dev = int64(9003)
	oldC := &Connection{connIDStr: "old-active", deviceID: dev}
	oldC.superseded.Store(true)
	installDeviceConn(t, oldC)

	if got := lookupActiveConnByDevice(dev); got != nil {
		t.Fatalf("superseded 会话不应算在线,got connIDStr=%q", got.connIDStr)
	}

	newC := &Connection{connIDStr: "new-active", deviceID: dev}
	installDeviceConn(t, newC)
	if got := lookupActiveConnByDevice(dev); got != newC {
		t.Fatalf("应返回未被踢的新会话 new-active")
	}
}

// TestLookupSubnetAdvertiserConnByDevice_SkipsSuperseded：子网路由转发目标同样跳过 superseded（与出口同类黑洞）。
func TestLookupSubnetAdvertiserConnByDevice_SkipsSuperseded(t *testing.T) {
	const dev = int64(9004)
	oldC := &Connection{connIDStr: "old-subnet", deviceID: dev}
	oldC.advertisedSubnetRoutes.Store(true)
	oldC.superseded.Store(true)
	installDeviceConn(t, oldC)

	if got := lookupSubnetAdvertiserConnByDevice(dev); got != nil {
		t.Fatalf("superseded 子网路由会话不应被选为转发目标,got connIDStr=%q", got.connIDStr)
	}
}

// TestDeliverIPPacketToConn_ClosedTunChanNoPanic：并发下线保护回归——目标会话被并发 cleanup（drainAndCloseTunChan
// close 了 TunChan）后,forwardPacketToExitNode / forwardPacketToSubnetRoute 经 lookup 拿到的 target 指针仍可能
// 走到 deliverIPPacketToConn 的 send;向已关闭 channel send 会 panic（select default 不兜）。deliver 内 recover
// 必须兜住 → 返回 false（投递失败,调用方计 drop），绝不 panic（否则打崩请求方的 handleVPNLink goroutine → 误断
// 请求方连接：出口机一掉线,用它出网的人也跟着断）。
func TestDeliverIPPacketToConn_ClosedTunChanNoPanic(t *testing.T) {
	ch := make(chan *util.TunPacket, 1)
	close(ch) // 模拟 cleanup 已 drainAndCloseTunChan
	c := &Connection{connIDStr: "closing-exit"}
	ips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.2", TunChan: ch}}
	c.clientIPs.Store(&ips)

	// 不应 panic;应返回 false（投递失败）。若 recover 缺失,本行会 panic 让测试 FAIL。
	if delivered := deliverIPPacketToConn(c, []byte{0x45, 0, 0, 0}); delivered {
		t.Fatal("向已关闭 TunChan 投递应返回 false（失败）")
	}
}

// TestDeliverIPPacketToConn_OpenTunChanDelivers：正常（未关闭、有容量）TunChan 应投递成功,确认 recover 改造
// 未破坏正常路径。
func TestDeliverIPPacketToConn_OpenTunChanDelivers(t *testing.T) {
	ch := make(chan *util.TunPacket, 1)
	c := &Connection{connIDStr: "live-exit"}
	ips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.3", TunChan: ch}}
	c.clientIPs.Store(&ips)

	if delivered := deliverIPPacketToConn(c, []byte{0x45, 0, 0, 0}); !delivered {
		t.Fatal("向正常 TunChan 投递应返回 true")
	}
	select {
	case pkt := <-ch:
		if pkt == nil {
			t.Fatal("投递的包不应为 nil")
		}
	default:
		t.Fatal("TunChan 应收到投递的包")
	}
}
