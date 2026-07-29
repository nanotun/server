package main

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"

	"github.com/nanotun/server/util"
)

// 这一帧 ICMPv6 的作用是让客户端**立刻**失败,而不是让它通。
//
// server 本机没有 v6 公网出网时,使用方发往公网 v6 的包无处可去。什么都不回,客户端就要干等
// connect 超时 —— Happy Eyeballs 是 300ms 级的抢跑,QUIC 更是要等十几秒才回落,用户看到的是
// 「打开网页转半分钟」。回一帧 no-route 则让内核当场把那条连接置 ENETUNREACH,连接秒失败、
// 立刻回落 IPv4。
//
// 所以这帧的每处细节都是「能不能被内核采纳」:整包必须裁进 IPv6 最小 MTU 1280(超了会在路上被
// 丢,等于没回),校验和必须对(错了内核静默丢弃),而构造不出来的时候绝不能投一段半成品出去。

// TestBuildICMPv6DestUnreach_StaysWithinTheMinimumMTU 超长引发包必须被裁掉。
func TestBuildICMPv6DestUnreach_StaysWithinTheMinimumMTU(t *testing.T) {
	src := netip.MustParseAddr("fd00:200::14")
	dst := netip.MustParseAddr("2606:4700:4700::1111")

	// 一个 1500 字节的原始外发包(以太网 MTU 满载,现实里很常见)。
	orig := mkIPv6(src, dst)
	orig = append(orig, make([]byte, 1500-len(orig))...)
	binary.BigEndian.PutUint16(orig[4:6], uint16(len(orig)-40))

	pkt, ok := buildICMPv6DestUnreach(orig)
	if !ok {
		t.Fatal("满载的合法 v6 包应能构造 ICMPv6 unreachable")
	}
	if len(pkt) > 1280 {
		t.Fatalf("整包 %d 字节,超出 IPv6 最小 MTU 1280 —— 这帧会在路上被丢,客户端仍要干等超时", len(pkt))
	}
	if !icmpv6ChecksumFolds(pkt) {
		t.Fatal("裁剪后校验和不对 —— 使用方内核会静默丢弃它")
	}
	// 裁剪之后仍要留住足够的引发包:内核靠内嵌的原始包头把这条错误关联到具体那条连接上,
	// 少于一个 v6 头就无从关联,连接照旧干等。
	msg, err := icmp.ParseMessage(58, pkt[40:])
	if err != nil {
		t.Fatalf("解析 ICMPv6 失败: %v", err)
	}
	if msg.Type != ipv6.ICMPTypeDestinationUnreachable {
		t.Fatalf("type = %v, want DestinationUnreachable", msg.Type)
	}
	du, ok := msg.Body.(*icmp.DstUnreach)
	if !ok || len(du.Data) < 40 {
		t.Fatalf("内嵌引发包不足一个 v6 头,内核无从关联到具体连接: %+v", msg.Body)
	}
}

// TestSendICMPv6NoRouteToConn_OnlySendsSomethingUsable 投递侧的三种情形。
func TestSendICMPv6NoRouteToConn_OnlySendsSomethingUsable(t *testing.T) {
	mkConn := func() (*Connection, chan *util.TunPacket) {
		ch := make(chan *util.TunPacket, 4)
		c := &Connection{connIDStr: "icmp-user"}
		ips := []util.VirtualIPAssignment{{VirtualIP: "fd00:200::14", TunChan: ch}}
		c.clientIPs.Store(&ips)
		return c, ch
	}

	t.Run("合法原包:原路回到使用方", func(t *testing.T) {
		c, ch := mkConn()
		src := netip.MustParseAddr("fd00:200::14")
		dst := netip.MustParseAddr("2606:4700:4700::1111")
		sendICMPv6NoRouteToConn(c, mkIPv6(src, dst))
		select {
		case pkt := <-ch:
			b := pkt.Buf[:pkt.N]
			if got := netip.AddrFrom16([16]byte(b[24:40])); got != src {
				t.Fatalf("这帧的目的应是使用方 vIP %s,实得 %s —— 发错人等于没发", src, got)
			}
		default:
			t.Fatal("没有投递 —— 使用方只能干等 connect 超时")
		}
	})

	t.Run("原包构造不出错误帧时什么都不投", func(t *testing.T) {
		c, ch := mkConn()
		// v4 包 / 短包都不该构造出 ICMPv6:投一段半成品进去,使用方内核解不开,
		// 白占一次下行,严重时还会被当成畸形包。
		sendICMPv6NoRouteToConn(c, mkIPv4(netip.MustParseAddr("8.8.8.8")))
		sendICMPv6NoRouteToConn(c, make([]byte, 8))
		if len(ch) != 0 {
			t.Fatalf("构造不出错误帧却投了 %d 帧", len(ch))
		}
	})

	t.Run("会话为 nil 时安全返回", func(t *testing.T) {
		// 数据面拿到的会话可能刚好在清理中。这条路是 best-effort,不该因此崩掉整条读循环。
		src := netip.MustParseAddr("fd00:200::14")
		sendICMPv6NoRouteToConn(nil, mkIPv6(src, netip.MustParseAddr("2606:4700:4700::1111")))
		if deliverIPPacketToConn(nil, []byte{0x60}) {
			t.Error("往 nil 会话投包却报告成功")
		}
	})
}

// TestRevalidateExitBindings_SkipsSessionsThatWereTakenOver 被接管的旧会话不参与复核。
//
// 客户端漫游 / 重连时,同一 sid 会有一个旧会话对象被标记 takenOver、由新会话继承状态。旧对象还在
// 表里(等清理),它的 egressDeviceID 也还留着。若复核时把它算进去,一次 `exit revoke` 就会对着这个
// 已经没人用的对象写 revoked ack —— 而它的 linkConn 已经是新会话在用的那条链路,客户端会收到一帧
// 针对自己**当前有效**绑定的撤销通知,当场把出口放掉。
func TestRevalidateExitBindings_SkipsSessionsThatWereTakenOver(t *testing.T) {
	resetConnByDeviceForTest(t)
	st := egressTestStore(t)
	const exitUUID = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
	devID := seedApprovedExitDevice(t, st, exitUUID)

	fake := newFakeLinkConn()
	old := &Connection{userID: "u1", connIDStr: "a-taken-over", exitAllowed: true, linkConn: fake}
	old.egressDeviceID.Store(devID)
	old.takenOver.Store(true)
	connIDMapMu.Lock()
	connIDMap[old.connIDStr] = old
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, old.connIDStr)
		connIDMapMu.Unlock()
	})

	// 撤销这个出口。
	if err := st.DeleteRoute(t.Context(), devID, "0.0.0.0/0"); err != nil {
		t.Fatalf("delete route: %v", err)
	}
	if n := revalidateExitBindings(t.Context()); n != 0 {
		t.Fatalf("被接管的旧会话不该参与复核,实际重置 %d 个", n)
	}
	if got := old.egressDeviceID.Load(); got != devID {
		t.Fatalf("旧会话的绑定被改动了(%d) —— 它已交给新会话继承,不该在这里被写", got)
	}
}
