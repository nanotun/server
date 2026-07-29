package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// 本文件钉住 runLinkTunnel 读循环里那串「命中即 continue」。
//
// 循环体是一条依次表决的链:出口 DNS 回包截获 → 源反欺骗 → 子网路由 → 出口闸 → ACL →
// peer 出口 → v6 秒回落 → …… 落到最后才写 server 自己的 TUN。每一道判据返回 true 都意味着
// 「这个包已经有人处理了」,后面必须 continue。
//
// 漏掉 continue 不会报错、不会丢包、日志上什么都看不出来 —— 只是这个包被**处理两次**:
// 一次按它该走的路,一次从 server 自己的公网出口再发一遍。后果按判据分别是:内网包从公网网卡
// 出去、用户以为在走出口节点而实际暴露的是 server 的 IP、v6 包既回了 unreachable 又进内核黑洞。
// 判据自己的单测覆盖不到这层:它们只验返回值,而「返回 true 之后调用方有没有停下来」在函数外。

// ipv6TCP 造一份 IPv6+TCP 报文(src/dst 可控),用于 v6 相关判据。
func ipv6TCP(src, dst string) []byte {
	return mkIPv6(netip.MustParseAddr(src), netip.MustParseAddr(dst))
}

// recvIPPacket 等服务端主动回给客户端的一个 IP 包,并顺带收掉 barrier 的 Pong。
//
// 不能用 barrier 那套「收到 Pong 就算前面的都处理完了」:Pong 由 readLoop 直接写链路,而这类回包
// 走本会话的 TunChan → demux goroutine,两条路谁先落到链路上没有定序。所以这里要一直收到「Pong 和
// 回包都到手」为止 —— 提前返回会把没读走的那帧留在 net.Pipe 里,服务端写它时无人接,整条链路就卡死了
// (第一版正是如此:下一次 barrier 的 Ping 写不进去,报成 i/o timeout)。
func (h *linkHarness) recvIPPacket(within time.Duration) []byte {
	h.t.Helper()
	h.send(util.LinkTypePing, []byte("barrier"))
	deadline := time.Now().Add(within)
	var got []byte
	pong := false
	for got == nil || !pong {
		left := time.Until(deadline)
		if left <= 0 {
			h.t.Fatal("没等到服务端回的 IP 包")
		}
		typ, payload, err := readLinkFrameWithDeadline(h.client, left)
		if err != nil {
			h.t.Fatalf("等服务端回包: %v", err)
		}
		switch typ {
		case util.LinkTypeIPPacket:
			got = append([]byte(nil), payload...)
		case util.LinkTypePong:
			pong = true
		default:
			h.t.Fatalf("收到意料之外的帧 typ=%d", typ)
		}
	}
	return got
}

// TestRunLinkTunnel_SubnetRouteVerdictStopsThePacketRightThere 验子网路由判据命中后不再往下走。
//
// dst 命中一条已批准的内网网段,而宣告方此刻不在线 → 判据丢包并返回 true。少了 continue,这个
// 「本该进某台机器 LAN 的内网包」会继续走到 server 自出口 → 从公网网卡发出去(SNAT 后带着
// server 的公网 IP 去敲 192.168/10/172 —— 到不了任何地方,但在上游看得见,而且是 server 在扫内网)。
func TestRunLinkTunnel_SubnetRouteVerdictStopsThePacketRightThere(t *testing.T) {
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.77.0/24", 4242)})
	h := newLinkHarness(t, harnessRemote, nil)
	// 宣告方 device 4242 没有任何在线会话(resetServerGlobals 已清 connByDevice)。

	before := subnetRouteDroppedOffline.Load()
	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "192.168.77.5", 445, 16, 0))
	h.barrier()

	if got := subnetRouteDroppedOffline.Load(); got != before+1 {
		t.Fatalf("宣告方离线丢包计数 %d → %d,应 +1(说明包确实归了子网路由这条路)", before, got)
	}
	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("子网路由已判过的包又写了 %d 次 server TUN —— 内网包会从公网网卡发出去", n)
	}
}

// TestRunLinkTunnel_ExitNodeVerdictStopsThePacketRightThere 验 peer 出口判据命中后不再往下走。
//
// 会话选了 peer 出口而那台出口此刻不在线 → 判据 fail-closed 丢包并返回 true。少了 continue,
// 包会回退到 server 自出口:用户选了「从香港那台出去」,实际却从 server 的 IP 出去了 —— 出口
// 选择被静默旁路,而客户端 UI 上出口仍是绿的。这正是「选出口」这个功能唯一要保证的性质。
func TestRunLinkTunnel_ExitNodeVerdictStopsThePacketRightThere(t *testing.T) {
	resetConnByDeviceForTest(t)
	h := newLinkHarness(t, harnessRemote, func(c *Connection) {
		c.deviceID = 11
		c.egressDeviceID.Store(77) // 已绑 device 77 当出口,而它没有在线会话
	})

	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "8.8.8.8", 53, 16, 0))
	h.barrier()

	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("出口判据已处理的包又写了 %d 次 server TUN —— 用户选的出口被绕过,暴露的是 server 的 IP", n)
	}
}

// TestRunLinkTunnel_V6FastFailVerdictStopsThePacketRightThere 验 v6 秒回落命中后不再往下走。
//
// server 本机没有 v6 出网,客户端却往公网 v6 发包 → 判据回一条 ICMPv6 unreachable 让它立刻
// 回落 v4,并返回 true。少了 continue,同一个包还会写进 server TUN 被内核黑洞 —— 客户端一边
// 收到「此路不通」一边又有包悬在内核里,而黑洞那份没有任何反馈,表现是首包必卡一个 RTO。
func TestRunLinkTunnel_V6FastFailVerdictStopsThePacketRightThere(t *testing.T) {
	prevKnown := serverV6EgressKnown.Swap(true)
	prevHas := serverV6EgressHas.Swap(false)
	t.Cleanup(func() {
		serverV6EgressKnown.Store(prevKnown)
		serverV6EgressHas.Store(prevHas)
	})

	const vip6 = "fd00:80::5"
	h := newLinkHarness(t, harnessRemote, func(c *Connection) {
		ips := append(*c.clientIPs.Load(), util.VirtualIPAssignment{
			VirtualIP: vip6, Gateway: "fd00:80::1/64",
		})
		c.clientIPs.Store(&ips)
	})

	before := serverEgressDroppedNoV6.Load()
	h.send(util.LinkTypeIPPacket, ipv6TCP(vip6, "2606:4700:4700::1111"))

	icmp := h.recvIPPacket(3 * time.Second)
	if len(icmp) < 48 || icmp[6] != 58 {
		t.Fatalf("回给客户端的应是 ICMPv6(next header 58),实得 %d 字节 nh=%d", len(icmp), icmp[6])
	}
	if got := serverEgressDroppedNoV6.Load(); got != before+1 {
		t.Fatalf("无 v6 丢包计数 %d → %d,应 +1(说明包确实归了秒回落这条路)", before, got)
	}
	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("已回 ICMPv6 的 v6 包又写了 %d 次 server TUN —— 那一份在内核里黑洞,没有任何反馈", n)
	}
}

// TestRunLinkTunnel_InterceptedExitDNSResponseGoesNoFurther 验出口 DNS 回包被截获后不再往下走。
//
// 这条回包的源是公网 :53(不是本会话的 vIP),截获判据故意排在源反欺骗**之前**。截获成功后必须
// continue:少了 continue,它接着会被反欺骗判为「冒充」记一次 srcSpoofDropCount —— 计数本身不影响
// 数据面,但这个计数器是排查横向冒充的唯一信号,每一次出口 DNS 查询都往里灌一条噪声,真冒充的
// 信号就淹了(与「全隧道回程另计一个计数器」是同一件事的两面)。
func TestRunLinkTunnel_InterceptedExitDNSResponseGoesNoFurther(t *testing.T) {
	setServerGatewayAddrs("10.80.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })

	// 走真正的注册入口:截获成功那一步会自己摘掉等待者并把 in-flight 减回去,手工加减会记两次账
	// (第一版就是这么写的,结果把 in-flight 压成负数,连累后面所有出口 DNS 用例)。
	answers := make(chan []byte, 1)
	relayPort, ok := registerExitDNSWaiter(answers, nil, 0, false)
	if !ok {
		t.Fatal("注册出口 DNS 等待者失败")
	}
	t.Cleanup(func() { unregisterExitDNSWaiter(relayPort) })

	h := newLinkHarness(t, harnessRemote, nil)

	// 出口把公网 DNS 应答送回来:src=8.8.8.8:53 → dst=server 网关:关联端口。
	resp := ipv4UDP("8.8.8.8", "10.80.0.1", relayPort, 32, 0)
	binary.BigEndian.PutUint16(resp[20:22], 53) // src port = 53
	beforeSpoof := srcSpoofDropCount.Load()
	h.send(util.LinkTypeIPPacket, resp)
	h.barrier()

	select {
	case got := <-answers:
		if len(got) == 0 {
			t.Fatal("等待中的 resolver 收到空应答")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("等待中的 resolver 没收到这条应答(截获没生效,本用例的前提就不成立)")
	}
	if got := srcSpoofDropCount.Load(); got != beforeSpoof {
		t.Fatalf("已截获的出口 DNS 回包又被反欺骗记了一次冒充(%d → %d)—— 每次出口 DNS 查询都往冒充计数器里灌噪声",
			beforeSpoof, got)
	}
	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("已截获的回包又写了 %d 次 server TUN", n)
	}
}
