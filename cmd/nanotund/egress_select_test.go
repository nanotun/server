package main

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// resetConnByDeviceForTest 清空 by-device 索引,避免跨测试污染。
func resetConnByDeviceForTest(t *testing.T) {
	t.Helper()
	connIDMapMu.Lock()
	for k := range connByDevice {
		delete(connByDevice, k)
	}
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		for k := range connByDevice {
			delete(connByDevice, k)
		}
		connIDMapMu.Unlock()
	})
}

// mkIPv4 造一个最小合法 IPv4 包(20B 头, TCP), dst 取传入地址。
func mkIPv4(dst netip.Addr) []byte {
	p := make([]byte, 20)
	p[0] = 0x45 // version 4, IHL 5
	p[9] = 6    // TCP
	d := dst.As4()
	copy(p[16:20], d[:])
	return p
}

// 出口在线 + 公网目的 → 转发到出口会话的 TunChan,返回 true。
func TestForwardPacketToExitNode_OnlineInternet(t *testing.T) {
	resetConnByDeviceForTest(t)

	tunCh := make(chan *util.TunPacket, 4)
	exit := &Connection{deviceID: 77, connIDStr: "exit1"}
	exit.advertisedExit.Store(true) // 真在跑出口（forwardPacketToExitNode 现要求 advertisedExit，否则 fail-closed）
	ips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: tunCh}}
	exit.clientIPs.Store(&ips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	a.egressDeviceID.Store(77)
	before := exitForwarded.Load()
	beforeBytes := exitForwardedBytes.Load()

	pkt := mkIPv4(netip.MustParseAddr("8.8.8.8")) // 公网目的(非 vIP)
	if !forwardPacketToExitNode(a, pkt) {
		t.Fatal("公网目的 + 出口在线应返回 true(已由 exit 路径处理)")
	}
	select {
	case got := <-tunCh:
		if got == nil || got.N != len(pkt) {
			t.Fatalf("投递到出口 TunChan 的包异常: %+v", got)
		}
	default:
		t.Fatal("包未投递到出口会话 TunChan")
	}
	if exitForwarded.Load() != before+1 {
		t.Fatal("exitForwarded 计数未自增")
	}
	if exitForwardedBytes.Load() != beforeBytes+uint64(len(pkt)) {
		t.Fatal("exitForwardedBytes 未按包长自增(M6 单列计量)")
	}
	if !a.exitFwdAudited {
		t.Fatal("首次成功经出口转发应置位 exitFwdAudited(审计一次)")
	}
}

// M6 带宽帽:猛灌超过初始 burst 的字节后,per-session 速率帽应开始丢包(exitForwardDroppedRate 自增),
// 被放行的包仍累加 exitForwardedBytes。
func TestForwardPacketToExitNode_RateCapDrops(t *testing.T) {
	resetConnByDeviceForTest(t)
	// 64 B/s 速率帽;burst=max(64,tunBufSize)=tunBufSize。t.Cleanup 复位,隔离其它测试。
	prev := exitForwardRateBPS.Swap(64)
	t.Cleanup(func() { exitForwardRateBPS.Store(prev) })

	// 持续清空出口 TunChan,隔离出「速率帽丢」(否则 deliver 因满会记 DroppedFull)。
	tunCh := make(chan *util.TunPacket, 8)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-tunCh:
			case <-done:
				return
			}
		}
	}()
	t.Cleanup(func() { close(done) })

	exit := &Connection{deviceID: 77, connIDStr: "exit1"}
	exit.advertisedExit.Store(true) // 真在跑出口（forwardPacketToExitNode 现要求 advertisedExit）
	ips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: tunCh}}
	exit.clientIPs.Store(&ips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	a.egressDeviceID.Store(77)
	pkt := mkIPv4(netip.MustParseAddr("8.8.8.8"))
	beforeRate := exitForwardDroppedRate.Load()
	beforeBytes := exitForwardedBytes.Load()

	// 桶初始满(burst=tunBufSize)。灌远超 burst 的字节量,必触发速率帽丢弃。
	iters := tunBufSize/len(pkt) + 2000
	for i := 0; i < iters; i++ {
		forwardPacketToExitNode(a, pkt)
	}
	if exitForwardDroppedRate.Load() <= beforeRate {
		t.Fatal("猛灌超过 burst 后应触发出口转发速率帽丢弃(exitForwardDroppedRate 未自增)")
	}
	if exitForwardedBytes.Load() <= beforeBytes {
		t.Fatal("被放行的包应累加 exitForwardedBytes")
	}
}

// 未选出口 → 返回 false(走 server 自出口原路径)。
func TestForwardPacketToExitNode_NoEgress(t *testing.T) {
	resetConnByDeviceForTest(t)
	a := &Connection{userID: "u1", connIDStr: "a"} // egressDeviceID 默认 0 = 未选出口
	if forwardPacketToExitNode(a, mkIPv4(netip.MustParseAddr("8.8.8.8"))) {
		t.Fatal("未选出口应返回 false")
	}
}

// 目的是某 vIP(mesh 流量)→ 返回 false,绝不当公网出口转发。
func TestForwardPacketToExitNode_MeshNotForwarded(t *testing.T) {
	resetConnByDeviceForTest(t)
	peerVIP := netip.MustParseAddr("10.7.7.7")
	registerVIPOwners([]netip.Addr{peerVIP}, 999, 1)
	t.Cleanup(func() { unregisterVIPOwners([]netip.Addr{peerVIP}, 1) })

	a := &Connection{userID: "u1", connIDStr: "a", exitAllowed: true}
	a.egressDeviceID.Store(77)
	if forwardPacketToExitNode(a, mkIPv4(peerVIP)) {
		t.Fatal("目的为 vIP 的 mesh 流量不应走 exit(应返回 false 走原路径)")
	}
}

// 修复回归:目的是 server 自身网关地址(如 MagicDNS gateway:53)→ 返回 false,绝不当公网出口转发给 peer 出口。
// 此前只排除 vIP、**漏了网关** → 选 peer 出口的会话会把发往网关的 DNS 查询转发给出口节点 → 到不了 server 本地
// resolver → magic/公网 DNS 全断(Android 网关-only DNS 下更是彻底断)。isLocalMeshDst 现同时放行 vIP + 网关。
func TestForwardPacketToExitNode_GatewayNotForwarded(t *testing.T) {
	resetConnByDeviceForTest(t)
	setServerGatewayAddrs("10.201.0.1/16", "fd00:200::1/64") // 模拟 TUN 已配网关
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	a.egressDeviceID.Store(77) // 已绑某 peer 出口
	// 发往网关自身(v4,如 gateway:53 DNS) → 不应转发给出口(应返回 false 走本地/原路径)。
	if forwardPacketToExitNode(a, mkIPv4(netip.MustParseAddr("10.201.0.1"))) {
		t.Fatal("目的为 server 网关地址(如 MagicDNS gateway:53)不应走 exit(应返回 false)")
	}
	// 对照:发往真公网仍应走出口(返回 true,离线则 fail-closed)——确保没把「排除网关」写成「排除一切」。
	if !forwardPacketToExitNode(a, mkIPv4(netip.MustParseAddr("8.8.8.8"))) {
		t.Fatal("公网目的仍应由 exit 路径处理(返回 true),排除网关不应影响公网转发")
	}
}

// 修复回归:无出口权限用户发往 server 网关(如 MagicDNS gateway:53)的包不应被「公网出口闸」拦截——否则该用户
// 在全隧道下连 magic DNS 都做不了。isLocalMeshDst 放行网关地址。
func TestExitDeniedForPacket_GatewayAllowed(t *testing.T) {
	setServerGatewayAddrs("10.201.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })
	c := &Connection{userID: "u1", exitAllowed: false} // 无出口权限
	if !c.exitDeniedForPacket(mkIPv4(netip.MustParseAddr("8.8.8.8"))) {
		t.Fatal("无出口权限用户发往公网应被拦截(deny=true)")
	}
	if c.exitDeniedForPacket(mkIPv4(netip.MustParseAddr("10.201.0.1"))) {
		t.Fatal("无出口权限用户发往 server 网关(MagicDNS)不应被拦截(deny 应为 false)")
	}
}

// 选了出口但出口离线 → fail-closed:返回 true(丢弃),不回退 server 自出口。
func TestForwardPacketToExitNode_OfflineFailClosed(t *testing.T) {
	resetConnByDeviceForTest(t)
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	a.egressDeviceID.Store(88)
	before := exitForwardDroppedOffline.Load()
	if !forwardPacketToExitNode(a, mkIPv4(netip.MustParseAddr("8.8.8.8"))) {
		t.Fatal("出口离线应 fail-closed 返回 true(丢弃),不回退 server 自出口")
	}
	if exitForwardDroppedOffline.Load() != before+1 {
		t.Fatal("exitForwardDroppedOffline 计数未自增")
	}
}

// M6:出口离线时,数据面对每个丢包都 fail-closed,但只在首个丢包回一帧 EgressSelectAck{exit_offline},
// 重新 EgressSelect 后复位、可再通知。
func TestForwardPacketToExitNode_OfflineNotifiesOnce(t *testing.T) {
	resetConnByDeviceForTest(t)
	fake := newFakeLinkConn()
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true, linkConn: fake}
	a.egressDeviceID.Store(88)
	pkt := mkIPv4(netip.MustParseAddr("8.8.8.8"))

	// 第一次离线丢包 → 置位 + 写一帧通知。
	if !forwardPacketToExitNode(a, pkt) {
		t.Fatal("出口离线应 fail-closed 返回 true")
	}
	if !a.exitOfflineNotified {
		t.Fatal("首次离线丢包后应置位 exitOfflineNotified")
	}
	firstLen := len(fake.writeBuf)
	if firstLen < 3 {
		t.Fatalf("首次离线应写出一帧 EgressSelectAck 通知,实际仅 %d 字节", firstLen)
	}
	// 解析帧头:[2B 大端长度 L][1B type][payload]，L = 1 + len(payload)。
	if fake.writeBuf[2] != util.LinkTypeEgressSelectAck {
		t.Fatalf("通知帧类型应为 EgressSelectAck(%d),实际 %d", util.LinkTypeEgressSelectAck, fake.writeBuf[2])
	}
	L := int(fake.writeBuf[0])<<8 | int(fake.writeBuf[1])
	ack, err := util.ParseEgressSelectAck(fake.writeBuf[3 : 2+L])
	if err != nil {
		t.Fatalf("解析 EgressSelectAck 失败: %v", err)
	}
	if ack.Accepted || ack.Reason != "exit_offline" {
		t.Fatalf("通知应为 {accepted:false, reason:exit_offline},实际 %+v", ack)
	}

	// 第二次离线丢包 → 仍 fail-closed,但不重复通知(一次性闸生效,writeBuf 不增长)。
	if !forwardPacketToExitNode(a, pkt) {
		t.Fatal("第二次离线仍应 fail-closed 返回 true")
	}
	if len(fake.writeBuf) != firstLen {
		t.Fatalf("出口持续离线时不应对每个丢包重复通知:writeBuf %d→%d", firstLen, len(fake.writeBuf))
	}

	// 重新 EgressSelect(回 server)→ 复位一次性闸,下次再下线可再通知。
	body, err := util.MarshalEgressSelect("server")
	if err != nil {
		t.Fatalf("构造 EgressSelect 失败: %v", err)
	}
	handleEgressSelectFrame(t.Context(), a, body)
	if a.exitOfflineNotified {
		t.Fatal("重新 EgressSelect 后应复位 exitOfflineNotified")
	}
}

// egressTestStore 起临时 store 并把 gatewayInstance 指过去(保存/恢复),供选择路径(resolveApprovedExitDeviceID)查库。
func egressTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "egress.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	prev := gatewayInstance
	gatewayInstance = &gatewayState{store: st}
	t.Cleanup(func() { gatewayInstance = prev })
	return st
}

// seedApprovedExitDevice 造一个用户 + 出口设备(approved 0/0),返回 deviceID。**不注册任何 conn**(即"离线")。
func seedApprovedExitDevice(t *testing.T, st *store.Store, uuid string) int64 {
	t.Helper()
	ctx := t.Context()
	hash, err := auth.HashPSK("p")
	if err != nil {
		t.Fatalf("hash psk: %v", err)
	}
	u, err := st.CreateUser(ctx, store.NewUser{Username: "owner-" + uuid[:8], PSKHash: hash})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, uuid, "exit-dev", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if _, err := st.UpsertAdvertisedRoute(ctx, dev.ID, "0.0.0.0/0"); err != nil {
		t.Fatalf("upsert route: %v", err)
	}
	if err := st.SetRouteStatus(ctx, dev.ID, "0.0.0.0/0", util.RouteStatusApproved, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	return dev.ID
}

func parseLastEgressAck(t *testing.T, fake *fakeLinkConn) *util.EgressSelectAck {
	t.Helper()
	if len(fake.writeBuf) < 3 || fake.writeBuf[2] != util.LinkTypeEgressSelectAck {
		t.Fatalf("应回一帧 EgressSelectAck,实得 %d 字节", len(fake.writeBuf))
	}
	L := int(fake.writeBuf[0])<<8 | int(fake.writeBuf[1])
	ack, err := util.ParseEgressSelectAck(fake.writeBuf[3 : 2+L])
	if err != nil {
		t.Fatalf("解析 ack: %v", err)
	}
	return ack
}

// 新策略(按授权绑定):选「已批准的出口设备」即绑定 deviceID —— **即便该出口当前离线**(无活跃会话)也绑,
// 在不在线交给数据面决定走/阻断。验证「授权决定绑定,在不在线不在选择这步卡」。
func TestEgressSelect_BindsApprovedExitEvenWhenOffline(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	const exitUUID = "11111111-2222-4333-8444-555555555555"
	devID := seedApprovedExitDevice(t, st, exitUUID)
	// 故意不注册任何 conn → 出口"离线"。

	fake := newFakeLinkConn()
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true, linkConn: fake}
	body, err := util.MarshalEgressSelect(exitUUID)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	handleEgressSelectFrame(t.Context(), a, body)

	if a.egressDeviceID.Load() != devID {
		t.Fatalf("选已批准出口(即便离线)应绑定 deviceID=%d,实际 %d", devID, a.egressDeviceID.Load())
	}
	ack := parseLastEgressAck(t, fake)
	if !ack.Accepted || ack.Egress != exitUUID {
		t.Fatalf("应 {accepted:true, egress:%s},实际 %+v", exitUUID, ack)
	}
}

// Phase 2(撤销实时):revalidateExitBindings —— 绑定的出口仍被批准则不动;被撤销则即时重置回 server(0)+ ack revoked。
func TestRevalidateExitBindings_RevokedResetToServer(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	const exitUUID = "22222222-3333-4444-8555-666666666666"
	devID := seedApprovedExitDevice(t, st, exitUUID)

	fake := newFakeLinkConn()
	a := &Connection{userID: "u1", connIDStr: "a-reval", exitAllowed: true, linkConn: fake}
	a.egressDeviceID.Store(devID)
	connIDMapMu.Lock()
	connIDMap[a.connIDStr] = a
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, a.connIDStr)
		connIDMapMu.Unlock()
	})

	// 仍被批准 → 不重置。
	if n := revalidateExitBindings(t.Context()); n != 0 {
		t.Fatalf("仍被批准时不应重置任何会话,实际重置 %d", n)
	}
	if a.egressDeviceID.Load() != devID {
		t.Fatalf("仍被批准的出口应保持绑定,实际 %d", a.egressDeviceID.Load())
	}

	// 撤销 C(删 approved 0/0 路由,即不再是已批准出口)。
	if err := st.DeleteRoute(t.Context(), devID, "0.0.0.0/0"); err != nil {
		t.Fatalf("delete route: %v", err)
	}

	// revalidate → 绑定它的 A 即时重置回 server(0)+ ack revoked。
	if n := revalidateExitBindings(t.Context()); n != 1 {
		t.Fatalf("撤销后应重置 1 个会话,实际 %d", n)
	}
	if a.egressDeviceID.Load() != 0 {
		t.Fatalf("撤销后绑定它的会话应重置回 server(0),实际 %d", a.egressDeviceID.Load())
	}
	ack := parseLastEgressAck(t, fake)
	if ack.Accepted || ack.Reason != "revoked" {
		t.Fatalf("应回 {accepted:false, reason:revoked},实际 %+v", ack)
	}
}

// 深扫修复回归(high):revalidateExitBindings 在 DB 出错(无法判定是否仍批准)时**不得误撤销**已绑定的出口——
// 否则一次 DB 抖动就把在用会话踢回 server。这里关掉 store 制造 DB 错误,断言绑定保持不变。
func TestRevalidateExitBindings_DBErrorKeepsBinding(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	const exitUUID = "44444444-5555-4666-8777-888888888888"
	devID := seedApprovedExitDevice(t, st, exitUUID)

	fake := newFakeLinkConn()
	a := &Connection{userID: "u1", connIDStr: "a-dberr", exitAllowed: true, linkConn: fake}
	a.egressDeviceID.Store(devID)
	connIDMapMu.Lock()
	connIDMap[a.connIDStr] = a
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, a.connIDStr)
		connIDMapMu.Unlock()
	})

	// 关掉 store → ListRoutesByDevice 出错 → deviceHasApprovedExitRoute 返 ok=false(无法判定)。
	_ = st.Close()
	if n := revalidateExitBindings(t.Context()); n != 0 {
		t.Fatalf("DB 出错(无法判定)时不应撤销任何绑定,实际重置 %d", n)
	}
	if a.egressDeviceID.Load() != devID {
		t.Fatalf("DB 出错应保留绑定(不误伤),实际 egressDeviceID=%d", a.egressDeviceID.Load())
	}
	if len(fake.writeBuf) != 0 {
		t.Fatalf("DB 出错不应回 revoked 通知,实际写了 %d 字节", len(fake.writeBuf))
	}
}

// 新策略:选一个**未批准/已撤销/未知**的出口 → 不绑定,回退 server(egressDeviceID=0)+ ack not_approved。
// 用「先绑着别的出口(egressDeviceID=77)」验证「无效 → 重置回 server」。
func TestEgressSelect_UnapprovedFallsBackToServer(t *testing.T) {
	resetConnByDeviceForTest(t)
	_ = egressTestStore(t) // 空库:任何 UUID 都不是已批准出口。

	fake := newFakeLinkConn()
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true, linkConn: fake}
	a.egressDeviceID.Store(77) // 假装之前已绑某出口,选无效出口应把它重置回 0(server)。
	body, err := util.MarshalEgressSelect("99999999-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	handleEgressSelectFrame(t.Context(), a, body)

	if a.egressDeviceID.Load() != 0 {
		t.Fatalf("选未批准出口应回退 server(egressDeviceID=0),实际 %d", a.egressDeviceID.Load())
	}
	ack := parseLastEgressAck(t, fake)
	if ack.Accepted || ack.Reason != "not_approved" {
		t.Fatalf("应 {accepted:false, reason:not_approved},实际 %+v", ack)
	}
}

// 退化:选到自己当出口 → 返回 false(回退 server 自出口,防自环)。
func TestForwardPacketToExitNode_SelfExitFallsBack(t *testing.T) {
	resetConnByDeviceForTest(t)
	self := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	self.egressDeviceID.Store(11)
	connIDMapMu.Lock()
	connByDeviceAddLocked(self)
	connIDMapMu.Unlock()
	if forwardPacketToExitNode(self, mkIPv4(netip.MustParseAddr("8.8.8.8"))) {
		t.Fatal("选到自己当出口应返回 false(回退 server 自出口)")
	}
}

// mkIPv6 造一个最小合法 IPv6 包(40B 头 + 20B TCP SYN), src/dst 取传入地址。
func mkIPv6(src, dst netip.Addr) []byte {
	p := make([]byte, 60)
	p[0] = 0x60                            // version 6
	binary.BigEndian.PutUint16(p[4:6], 20) // payload length = TCP 头
	p[6] = 6                               // next header = TCP
	p[7] = 64                              // hop limit
	s := src.As16()
	d := dst.As16()
	copy(p[8:24], s[:])
	copy(p[24:40], d[:])
	binary.BigEndian.PutUint16(p[40:42], 12345) // src port
	binary.BigEndian.PutUint16(p[42:44], 443)   // dst port
	p[40+13] = 0x02                             // SYN
	return p
}

// icmpv6ChecksumFolds 独立重算 ICMPv6 校验和(伪首部 + ICMP 负载),含既有校验和字段折叠后应为 0xffff。
// 用于验证 buildICMPv6DestUnreach 的校验和正确(否则使用方内核会静默丢弃 ICMP、仍卡 30s)。
func icmpv6ChecksumFolds(pkt []byte) bool {
	if len(pkt) < 40 {
		return false
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if 40+payloadLen > len(pkt) {
		return false
	}
	var sum uint32
	add := func(b []byte) {
		i := 0
		for ; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if i < len(b) {
			sum += uint32(b[i]) << 8
		}
	}
	add(pkt[8:24])  // src
	add(pkt[24:40]) // dst
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(payloadLen))
	add(lenbuf[:])
	add([]byte{0, 0, 0, 58}) // 3 零 + next header
	add(pkt[40 : 40+payloadLen])
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

func TestIsPublicV6Addr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"2606:4700:4700::1111", true}, // Cloudflare 公网 v6
		{"2001:4860:4860::8888", true}, // Google 公网 v6
		{"240e::1", true},              // 中国电信公网 v6
		{"fd00:200::14", false},        // mesh ULA
		{"fdbc:4a60::1", false},        // 4via6/ULA
		{"fe80::1", false},             // link-local
		{"::1", false},                 // loopback
		{"8.8.8.8", false},             // IPv4
		{"::ffff:8.8.8.8", false},      // v4-mapped
	}
	for _, c := range cases {
		got := isPublicV6Addr(netip.MustParseAddr(c.addr))
		if got != c.want {
			t.Errorf("isPublicV6Addr(%s)=%v, want %v", c.addr, got, c.want)
		}
	}
}

func TestBuildICMPv6DestUnreach(t *testing.T) {
	src := netip.MustParseAddr("fd00:200::14")         // 使用方 v6 vIP
	dst := netip.MustParseAddr("2606:4700:4700::1111") // 公网 v6 目的
	orig := mkIPv6(src, dst)
	pkt, ok := buildICMPv6DestUnreach(orig)
	if !ok {
		t.Fatal("合法 v6 包应能构造 ICMPv6 unreachable")
	}
	if pkt[0]>>4 != 6 {
		t.Fatalf("外层非 IPv6: 0x%02x", pkt[0])
	}
	if pkt[6] != 58 {
		t.Fatalf("next header 应为 58(ICMPv6),实得 %d", pkt[6])
	}
	// 外层 src=原目的、dst=原源(经隧道原路回到使用方)。
	if got := netip.AddrFrom16([16]byte(pkt[8:24])); got != dst {
		t.Fatalf("ICMP 外层 src 应为原目的 %s,实得 %s", dst, got)
	}
	if got := netip.AddrFrom16([16]byte(pkt[24:40])); got != src {
		t.Fatalf("ICMP 外层 dst 应为原源 %s,实得 %s", src, got)
	}
	// 校验和必须正确(否则使用方内核静默丢弃)。
	if !icmpv6ChecksumFolds(pkt) {
		t.Fatal("ICMPv6 校验和不正确(折叠后应为 0xffff)")
	}
	// 结构上应解析为 Destination Unreachable / Code 0(no route),且内嵌引发包含原始包头。
	msg, err := icmp.ParseMessage(58, pkt[40:])
	if err != nil {
		t.Fatalf("解析 ICMPv6 失败: %v", err)
	}
	if msg.Type != ipv6.ICMPTypeDestinationUnreachable || msg.Code != 0 {
		t.Fatalf("应为 DestinationUnreachable/Code0,实得 type=%v code=%d", msg.Type, msg.Code)
	}
	du, ok := msg.Body.(*icmp.DstUnreach)
	if !ok || len(du.Data) < 40 {
		t.Fatalf("ICMP body 应含内嵌引发包(≥40B v6 头),实得 %+v", msg.Body)
	}
	if du.Data[6] != 6 { // 内嵌原包 next header = TCP
		t.Fatalf("内嵌引发包应为原始 TCP/v6 包,next header 实得 %d", du.Data[6])
	}
}

// 短包 / 非 v6 不应构造(防越界 panic)。
func TestBuildICMPv6DestUnreach_RejectsInvalid(t *testing.T) {
	if _, ok := buildICMPv6DestUnreach(make([]byte, 10)); ok {
		t.Fatal("短包不应构造 ICMP")
	}
	v4 := mkIPv4(netip.MustParseAddr("8.8.8.8"))
	if _, ok := buildICMPv6DestUnreach(v4); ok {
		t.Fatal("IPv4 包不应构造 ICMPv6")
	}
}

// 出口在线但**无 v6 出网**(advertisedExitV6=false)+ 公网 v6 目的:不转发给出口,改给使用方回 ICMPv6 unreachable,
// dropped_no_v6 自增,返回 true(fail-closed,不回退 server)。
func TestForwardPacketToExitNode_PublicV6NoV6Exit(t *testing.T) {
	resetConnByDeviceForTest(t)
	exitCh := make(chan *util.TunPacket, 4)
	exit := &Connection{deviceID: 88, connIDStr: "exit-v4only"}
	exit.advertisedExit.Store(true) // 真在跑出口
	// advertisedExitV6 默认 false = 无 v6 出网
	eips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: exitCh}}
	exit.clientIPs.Store(&eips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	reqCh := make(chan *util.TunPacket, 4)
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	aips := []util.VirtualIPAssignment{{VirtualIP: "fd00:200::14", TunChan: reqCh}}
	a.clientIPs.Store(&aips)
	a.egressDeviceID.Store(88)

	before := exitForwardDroppedNoV6.Load()
	pkt := mkIPv6(netip.MustParseAddr("fd00:200::14"), netip.MustParseAddr("2606:4700:4700::1111"))
	if !forwardPacketToExitNode(a, pkt) {
		t.Fatal("公网 v6 + 无 v6 出口应返回 true(已处理)")
	}
	if exitForwardDroppedNoV6.Load() != before+1 {
		t.Fatalf("dropped_no_v6 应自增,实得 %d→%d", before, exitForwardDroppedNoV6.Load())
	}
	select {
	case <-exitCh:
		t.Fatal("公网 v6 不应转发给无 v6 出口")
	default:
	}
	select {
	case got := <-reqCh:
		if got == nil || got.N < 48 {
			t.Fatalf("使用方收到的 ICMP 回包异常: %+v", got)
		}
		icmpPkt := got.Buf[:got.N]
		if icmpPkt[6] != 58 {
			t.Fatalf("回包应为 ICMPv6(next header 58),实得 %d", icmpPkt[6])
		}
		if !icmpv6ChecksumFolds(icmpPkt) {
			t.Fatal("回给使用方的 ICMPv6 校验和不正确")
		}
	default:
		t.Fatal("使用方未收到 ICMPv6 unreachable 回包")
	}
}

// server 自出口 v6 fast-fail 纯决策:仅「已探明 + server 无 v6 + 公网 v6 目的」为真。
func TestShouldServerFastFailV6(t *testing.T) {
	pub := netip.MustParseAddr("2606:4700:4700::1111")
	mesh := netip.MustParseAddr("fd00:200::14")
	v4 := netip.MustParseAddr("8.8.8.8")
	cases := []struct {
		name        string
		dst         netip.Addr
		serverHasV6 bool
		known       bool
		want        bool
	}{
		{"公网v6+无v6+已探明→fast-fail", pub, false, true, true},
		{"公网v6+有v6→放行", pub, true, true, false},
		{"公网v6+未探明→放行(保守)", pub, false, false, false},
		{"mesh v6→放行", mesh, false, true, false},
		{"v4→放行", v4, false, true, false},
	}
	for _, c := range cases {
		if got := shouldServerFastFailV6(c.dst, c.serverHasV6, c.known); got != c.want {
			t.Errorf("%s: shouldServerFastFailV6=%v want %v", c.name, got, c.want)
		}
	}
}

// server 自出口 + server 无 v6 + 公网 v6:回 ICMPv6 unreachable 给使用方,serverEgressDroppedNoV6 自增,返回 true。
func TestServerSelfEgressV6FastFail(t *testing.T) {
	// 直接置探测缓存为「已探明 + 无 v6」(不启动后台探测 goroutine,测试可控);Cleanup 复位。
	prevKnown := serverV6EgressKnown.Swap(true)
	prevHas := serverV6EgressHas.Swap(false)
	t.Cleanup(func() {
		serverV6EgressKnown.Store(prevKnown)
		serverV6EgressHas.Store(prevHas)
	})

	reqCh := make(chan *util.TunPacket, 4)
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	aips := []util.VirtualIPAssignment{{VirtualIP: "fd00:200::14", TunChan: reqCh}}
	a.clientIPs.Store(&aips)
	// egressDeviceID 默认 0 = server 自出口。

	before := serverEgressDroppedNoV6.Load()
	pkt := mkIPv6(netip.MustParseAddr("fd00:200::14"), netip.MustParseAddr("2606:4700:4700::1111"))
	if !serverSelfEgressV6FastFail(a, pkt) {
		t.Fatal("server 无 v6 + 公网 v6 应返回 true(已回 ICMP 并丢弃)")
	}
	if serverEgressDroppedNoV6.Load() != before+1 {
		t.Fatalf("serverEgressDroppedNoV6 应自增,实得 %d→%d", before, serverEgressDroppedNoV6.Load())
	}
	select {
	case got := <-reqCh:
		if got == nil || got.N < 48 {
			t.Fatalf("使用方收到的 ICMP 回包异常: %+v", got)
		}
		icmpPkt := got.Buf[:got.N]
		if icmpPkt[6] != 58 {
			t.Fatalf("回包应为 ICMPv6(next header 58),实得 %d", icmpPkt[6])
		}
		if !icmpv6ChecksumFolds(icmpPkt) {
			t.Fatal("回给使用方的 ICMPv6 校验和不正确")
		}
	default:
		t.Fatal("使用方未收到 ICMPv6 unreachable 回包")
	}

	// mesh v6 目的(ULA,非公网)→ 不 fast-fail(放行走 server 自出口)。
	if serverSelfEgressV6FastFail(a, mkIPv6(netip.MustParseAddr("fd00:200::14"), netip.MustParseAddr("fd00:200::99"))) {
		t.Fatal("mesh v6 目的不应 fast-fail")
	}
	// v4 目的 → 不 fast-fail。
	if serverSelfEgressV6FastFail(a, mkIPv4(netip.MustParseAddr("8.8.8.8"))) {
		t.Fatal("v4 目的不应 fast-fail")
	}
}

// server 有 v6(serverV6EgressHas=true):公网 v6 照旧走 server 自出口,不 fast-fail(无回归)。
func TestServerSelfEgressV6FastFail_HasV6NoRegression(t *testing.T) {
	prevKnown := serverV6EgressKnown.Swap(true)
	prevHas := serverV6EgressHas.Swap(true) // server 有 v6
	t.Cleanup(func() {
		serverV6EgressKnown.Store(prevKnown)
		serverV6EgressHas.Store(prevHas)
	})
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	pkt := mkIPv6(netip.MustParseAddr("fd00:200::14"), netip.MustParseAddr("2606:4700:4700::1111"))
	if serverSelfEgressV6FastFail(a, pkt) {
		t.Fatal("server 有 v6 时公网 v6 应放行走 server 自出口(不 fast-fail)")
	}
}

// v6 能力未探明(Known=false):保守放行,不 fast-fail(启动极短窗口的旧行为)。
func TestServerSelfEgressV6FastFail_UnknownConservative(t *testing.T) {
	prevKnown := serverV6EgressKnown.Swap(false) // 未探明
	prevHas := serverV6EgressHas.Load()
	t.Cleanup(func() {
		serverV6EgressKnown.Store(prevKnown)
		serverV6EgressHas.Store(prevHas)
	})
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	pkt := mkIPv6(netip.MustParseAddr("fd00:200::14"), netip.MustParseAddr("2606:4700:4700::1111"))
	if serverSelfEgressV6FastFail(a, pkt) {
		t.Fatal("v6 能力未探明时应保守放行(不 fast-fail)")
	}
}

// 出口在线且**有 v6 出网**(advertisedExitV6=true)+ 公网 v6 目的:照常转发给出口(无回归)。
func TestForwardPacketToExitNode_PublicV6WithV6Exit(t *testing.T) {
	resetConnByDeviceForTest(t)
	exitCh := make(chan *util.TunPacket, 4)
	exit := &Connection{deviceID: 88, connIDStr: "exit-v6"}
	exit.advertisedExit.Store(true)
	exit.advertisedExitV6.Store(true) // 有 v6 出网 → 照常转发
	eips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: exitCh}}
	exit.clientIPs.Store(&eips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true}
	a.egressDeviceID.Store(88)
	pkt := mkIPv6(netip.MustParseAddr("fd00:200::14"), netip.MustParseAddr("2606:4700:4700::1111"))
	before := exitForwarded.Load()
	if !forwardPacketToExitNode(a, pkt) {
		t.Fatal("有 v6 出口应返回 true(已转发)")
	}
	select {
	case got := <-exitCh:
		if got == nil || got.N != len(pkt) {
			t.Fatalf("投递到出口的 v6 包异常: %+v", got)
		}
	default:
		t.Fatal("有 v6 出口应把公网 v6 转发给出口")
	}
	if exitForwarded.Load() != before+1 {
		t.Fatal("exitForwarded 未自增")
	}
}
