package main

import (
	"net"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// v6 出网探测的两段判据。
//
// 这两段回答的是同一个问题:server 本机到底有没有真的 v6 出网。答错的方向只有一个是危险的 ——
// 判「有」而实际没有:所有公网 v6 流量会被照单写进 server TUN,在内核里黑洞,客户端没有任何反馈,
// 只能干等到超时(浏览器上是「某些网站要卡十几秒才回落」)。判「没有」而实际有,只是退化成 v4-only,
// 不影响可用性。所以两段都是宁可判「没有」。
//
// 探测目标是包级 var,这里把它指到环回地址 —— 环回是「路由通、地址有、但绝不是公网出网」的现成样本,
// 正好用来验两段判据不会被它蒙过去。真公网 v6 的那一侧只能靠有 v6 的机器验(e2e 地盘)。

// v6LoopbackTargets 把探测目标换成环回,并在用例结束后还原。
func v6LoopbackTargets(t *testing.T) {
	t.Helper()
	prev := serverV6ProbeTargets
	serverV6ProbeTargets = []string{"::1"}
	t.Cleanup(func() { serverV6ProbeTargets = prev })
}

// requireV6Loopback 这台机器没有可用的 v6 环回时跳过 —— 否则用例什么都没验(每一步都在最开头就失败)。
func requireV6Loopback(t *testing.T) {
	t.Helper()
	conn, err := net.Dial("udp6", "[::1]:53")
	if err != nil {
		t.Skipf("这台机器没有可用的 v6 环回: %v", err)
	}
	_ = conn.Close()
}

// TestProbeServerIPv6Route_LoopbackIsNotAnEgressSource 路由级那一段:源地址必须是真·全局单播。
//
// 只看「UDP connect 成功」的话,几乎每台机器都会被判成有 v6 出网 —— 有 ::1 就有 v6 路由,connect
// 一个公网 v6 目的也照样"成功"(UDP connect 只做路由查找,不发包)。判据必须落在 OS 选出的**源地址**
// 上:环回、链路本地、文档保留段都不算数。
func TestProbeServerIPv6Route_LoopbackIsNotAnEgressSource(t *testing.T) {
	requireV6Loopback(t)
	v6LoopbackTargets(t)

	if probeServerIPv6Route() {
		t.Fatal("对着环回也判成「有 v6 出网源」—— 那这台机器上所有公网 v6 流量都会被写进 TUN 黑洞,客户端只能干等超时")
	}
}

// TestVerifyServerIPv6RoundTrip_NoAnswerMeansNoV6 端到端那一段:没收到回包就不算通。
//
// 这一段存在的全部理由就是防「假 v6」:有 GUA 地址、有默认路由、就是出不去(家用路由器 RA 误发
// 2001:db8::/64 是实测样本)。把判据放松成「dial 成功就算通」,假 v6 环境会被判成有 v6 —— 而 dial
// 对 UDP 从来不会失败。这里让两个探测手段(UDP :53 查询、TCP :443 握手)都打在没人监听的环回上,
// 两条都必须判「不通」。
func TestVerifyServerIPv6RoundTrip_NoAnswerMeansNoV6(t *testing.T) {
	requireV6Loopback(t)
	// 本机若真有 DNS 在 [::1]:53 上听(开发机上常见),这条用例的前提就不成立。
	if probe, err := net.DialTimeout("udp6", "[::1]:53", time.Second); err == nil {
		_ = probe.SetDeadline(time.Now().Add(300 * time.Millisecond))
		_, _ = probe.Write([]byte{0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		buf := make([]byte, 64)
		if n, rerr := probe.Read(buf); rerr == nil && n > 0 {
			_ = probe.Close()
			t.Skip("这台机器的 [::1]:53 上有真 DNS 在听,探测目标指到环回就不再是「没人应答」")
		}
		_ = probe.Close()
	}
	v6LoopbackTargets(t)

	if verifyServerIPv6RoundTrip() {
		t.Fatal("没有任何回包却判成「v6 往返可用」—— 假 v6 环境会被判成有 v6,所有公网 v6 流量进黑洞")
	}
}

// TestSendEgressSelectAck_SurvivesAConnectionWithNoLink 没有链路的会话不能把回执写崩。
//
// 这条回执是 best-effort 的:出口复核在循环里逐个会话内联发,而循环取到的会话可能刚刚断开(linkConn
// 已被清成 nil)。这里不兜住就是一次 nil 解引用 —— panic 发生在**复核循环**里,一个断线的会话会带走
// 整轮复核,后面排队的会话一个都收不到撤销通知,继续把包发给已经无权的出口。
func TestSendEgressSelectAck_SurvivesAConnectionWithNoLink(t *testing.T) {
	ack := util.EgressSelectAck{Accepted: true}
	sendEgressSelectAck(nil, ack)                         // 连会话都没有
	sendEgressSelectAck(&Connection{connIDStr: "x"}, ack) // 会话在,链路已经清掉了
}
