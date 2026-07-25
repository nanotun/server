package main

import (
	"net"
	"net/netip"
	"testing"
)

// exit_mode=isolate 下 MagicDNS 不得把**别人**的 vIP 解析出来。
//
// isolate 的承诺比 mesh-off / ACL 都强(FORWARD 上是一条无差别的 `-i tun0 -o tun0 DROP`,
// 连同一 user 的两台设备也不通),而解析层此前只看 mesh 总开关(只拦跨 user)和 ACL。
// 三机实测(2026-07-25):isolate 下 A 查 vultr.u4.lan 照样拿到 10.201.0.3,ping / TCP 却全不通 ——
// 既是「解析成功、连接超时」的排障陷阱,也是跨 user 的设备存在性泄漏。
func TestMagicNameDeniedByIsolate(t *testing.T) {
	self4 := netip.MustParseAddr("10.201.0.77")
	self6 := netip.MustParseAddr("fd00:200::3")
	peerSameUser := netip.MustParseAddr("10.201.0.90")
	peerOtherUser := netip.MustParseAddr("10.201.0.3")

	const selfConn, sameUserPeerConn, otherConn = uint32(11), uint32(12), uint32(99)
	registerVIPOwners([]netip.Addr{self4, self6}, 2, selfConn)
	registerVIPOwners([]netip.Addr{peerSameUser}, 2, sameUserPeerConn) // 同 user,另一台设备
	registerVIPOwners([]netip.Addr{peerOtherUser}, 4, otherConn)
	t.Cleanup(func() {
		unregisterVIPOwners([]netip.Addr{self4, self6}, selfConn)
		unregisterVIPOwners([]netip.Addr{peerSameUser}, sameUserPeerConn)
		unregisterVIPOwners([]netip.Addr{peerOtherUser}, otherConn)
	})

	asker := &net.UDPAddr{IP: self4.AsSlice(), Port: 5353}
	unknown := &net.UDPAddr{IP: net.ParseIP("10.201.0.250"), Port: 5353}

	prev := clientIsolateMode.Load()
	t.Cleanup(func() { clientIsolateMode.Store(prev) })

	// mesh 模式:本 gate 完全不介入。
	clientIsolateMode.Store(false)
	if magicNameDeniedByIsolate(asker, []netip.Addr{peerOtherUser}) {
		t.Error("非 isolate 不该拦")
	}

	clientIsolateMode.Store(true)
	if !magicNameDeniedByIsolate(asker, []netip.Addr{peerOtherUser}) {
		t.Error("isolate 下跨 user 对端应拒解析")
	}
	// 同 user 的另一台设备在 isolate 下同样不可达,不能因为 user 相同就放过
	// (mesh-off 那条 gate 只比 user,漏的正是这一格)。
	if !magicNameDeniedByIsolate(asker, []netip.Addr{peerSameUser}) {
		t.Error("isolate 下同 user 的另一台设备也应拒解析")
	}
	// 自查本机名合法且有用:v4 / v6 同属一个会话,跨族也该放行。
	if magicNameDeniedByIsolate(asker, []netip.Addr{self4}) {
		t.Error("查自己的 v4 不该被拦")
	}
	if magicNameDeniedByIsolate(asker, []netip.Addr{self6}) {
		t.Error("查自己的 v6(同一会话)不该被拦")
	}
	// 一组答案里只要有自己的地址就照常作答。
	if magicNameDeniedByIsolate(asker, []netip.Addr{self4, self6}) {
		t.Error("双栈自查不该被拦")
	}

	// fail-open 兜底:查询方不在归属表(server 自查 / 会话清理竞态)、或压根没解析出地址 → 不拦。
	if magicNameDeniedByIsolate(unknown, []netip.Addr{peerOtherUser}) {
		t.Error("查询方 vIP 未登记时应 fail-open")
	}
	if magicNameDeniedByIsolate(asker, nil) {
		t.Error("无答案时应 fail-open")
	}
}
