package main

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// tcpPacketV4 造一个最小 IPv4/TCP 报文（20B IP 头 + 4B 端口），供源反欺骗守卫解析 (src, srcPort, dstPort)。
func tcpPacketV4(t *testing.T, src, dst netip.Addr, srcPort, dstPort uint16) []byte {
	t.Helper()
	p := make([]byte, 24)
	p[0] = 0x45
	p[9] = 6 // TCP
	s, d := src.As4(), dst.As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[20:22], srcPort)
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	return p
}

// lanReplyFixture 搭出「一台已批准共享 192.168.88.0/24 的设备 + 一条 LAN 目标端口映射」的现场，
// 并把 server 网关地址设成 10.201.0.1，返回该设备对应的会话。
func lanReplyFixture(t *testing.T) (*Connection, int64) {
	t.Helper()
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })
	prevTbl := subnetRouteTable.Load()
	prevVia6 := via6SiteTable.Load()
	t.Cleanup(func() { subnetRouteTable.Store(prevTbl); via6SiteTable.Store(prevVia6) })

	_, deviceID := mustCreateUserAndDevice(t, gw, "pfuser")
	const uuid = "11111111-1111-4111-8111-111111111111"

	lan := netip.MustParsePrefix("192.168.88.0/24")
	if _, err := gw.store.UpsertAdvertisedRoute(t.Context(), deviceID, lan.String()); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if err := gw.store.SetRouteStatus(t.Context(), deviceID, lan.String(), store.RouteStatusApproved, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	setServerGatewayAddrs("10.201.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })
	rebuildSubnetRouteTable(t.Context())

	m := newPFRebuildManager(t, gw)
	prevReplies := frpLANReplyTable.Load()
	t.Cleanup(func() { frpLANReplyTable.Store(prevReplies) })
	m.rebuildFRPTargetTable(t.Context(), []store.PortForward{
		{PublicPort: 18081, Proto: "tcp", TargetDeviceUUID: uuid, TargetIP: "192.168.88.1", TargetPort: 8088, Enabled: true},
	})

	c := &Connection{deviceID: deviceID}
	c.advertisedSubnetApproved.Store(true)
	advertised := []netip.Prefix{lan}
	c.advertisedRoutes.Store(&advertised)
	vips := []util.VirtualIPAssignment{{VirtualIP: "10.201.0.3"}}
	c.clientIPs.Store(&vips)
	return c, deviceID
}

// TestConnSourceSpoofed_AllowsFRPLANReply:FRP LAN 目标的回程(src=target_ip:target_port、dst=server 网关)
// 必须放行。三机实测 2026-07-26:加固「非 vIP 源 + 目的网关一律判伪造」后,LAN 目标端口转发一个包都回不来
// (C 回了 SYN-ACK,server 计成 src_spoof_drops,外部 curl 挂死),而 web 上状态仍显示 listening。
func TestConnSourceSpoofed_AllowsFRPLANReply(t *testing.T) {
	c, _ := lanReplyFixture(t)
	pkt := tcpPacketV4(t, netip.MustParseAddr("192.168.88.1"), netip.MustParseAddr("10.201.0.1"), 8088, 43210)
	if connSourceSpoofed(c, pkt) {
		t.Fatal("已发布的 LAN 目标回程被判伪造 —— LAN 目标端口转发不可用")
	}
}

// 放通必须窄:同一台设备、同一 LAN IP,但**没被发布**的端口(如 53)发往网关仍判伪造。
// 这条锁住 MagicDNS 信任锚不被已批准的子网中继方借 LAN 源绕过。
func TestConnSourceSpoofed_StillBlocksUnpublishedPortToGateway(t *testing.T) {
	c, _ := lanReplyFixture(t)
	for _, srcPort := range []uint16{53, 8089, 22} {
		pkt := tcpPacketV4(t, netip.MustParseAddr("192.168.88.1"), netip.MustParseAddr("10.201.0.1"), srcPort, 53)
		if !connSourceSpoofed(c, pkt) {
			t.Errorf("srcPort=%d 未被发布,发往网关应判伪造", srcPort)
		}
	}
	// 发布过的端口、但源 IP 换成同网段里别的主机 → 也不该放行。
	pkt := tcpPacketV4(t, netip.MustParseAddr("192.168.88.9"), netip.MustParseAddr("10.201.0.1"), 8088, 43210)
	if !connSourceSpoofed(c, pkt) {
		t.Error("源 IP 不是被发布的那台 LAN 主机,发往网关应判伪造")
	}
}

// 映射指向的是**另一台**设备时,本会话不得借它放通(防一台宣告方蹭别人发布的端点)。
func TestConnSourceSpoofed_LANReplyBoundToMappedDevice(t *testing.T) {
	c, deviceID := lanReplyFixture(t)
	c.deviceID = deviceID + 999
	pkt := tcpPacketV4(t, netip.MustParseAddr("192.168.88.1"), netip.MustParseAddr("10.201.0.1"), 8088, 43210)
	if !connSourceSpoofed(c, pkt) {
		t.Fatal("映射指定的是别的设备,本会话不应被放通")
	}
}

// 协议不符(映射是 tcp,报文是 udp)不放通。
func TestFRPLANReplyFromDevice_ProtoMustMatch(t *testing.T) {
	_, deviceID := lanReplyFixture(t)
	src := netip.MustParseAddr("192.168.88.1")
	if !frpLANReplyFromDevice(deviceID, src, pktTuple{proto: "tcp", srcPort: 8088, hasL4Ports: true}) {
		t.Fatal("tcp 应命中")
	}
	if frpLANReplyFromDevice(deviceID, src, pktTuple{proto: "udp", srcPort: 8088, hasL4Ports: true}) {
		t.Error("udp 报文不应命中 tcp 映射")
	}
	// 端口不可判定(分片/截断)时不放通。
	if frpLANReplyFromDevice(deviceID, src, pktTuple{proto: "tcp", srcPort: 8088}) {
		t.Error("hasL4Ports=false 不应命中")
	}
	if frpLANReplyFromDevice(0, src, pktTuple{proto: "tcp", srcPort: 8088, hasL4Ports: true}) {
		t.Error("匿名会话(deviceID=0)不应命中")
	}
}

// parsePacketTuple 现在要同时解出 srcPort（本修复的前提）。
func TestParsePacketTuple_ParsesSrcPort(t *testing.T) {
	pkt := tcpPacketV4(t, netip.MustParseAddr("192.168.88.1"), netip.MustParseAddr("10.201.0.1"), 8088, 43210)
	got, ok := parsePacketTuple(pkt)
	if !ok || got.srcPort != 8088 || got.dstPort != 43210 || !got.hasL4Ports {
		t.Fatalf("srcPort/dstPort 解析错误: %+v ok=%v", got, ok)
	}
}
