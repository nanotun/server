package main

import (
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 快照构建是 ACL 的地基:数据面每个包都只看这份快照,构建时把一条规则放错桶,后面所有判定都跟着错,
// 而 `acl list` 显示的仍是库里那份正确的配置 —— 两边永远对不上账,却谁也不报错。
//
// 这里钉住三件事:
//   - 未知的 default 值必须收敛成 deny。它是这份快照的兜底动作;规范化方向错了就是**整台 server 变成
//     默认放行**,一次配置笔误(或未来某个绕过 readSettings 的调用方)即可触发。
//   - 出口规则里 src_user_id=0 是「对所有用户生效」的通配写法,必须进通配桶。放进 by-src 桶(键 0)的话
//     没人能命中它 —— 管理员配的那条出口限制静默失效。
//   - 规则表里出现 nil 项时要跳过而不是崩:它会掀翻整条 reload,让快照永远停在旧版本。

// TestBuildACLSnapshot_UnknownDefaultCollapsesToDeny 未知的 default 一律收敛成 deny。
func TestBuildACLSnapshot_UnknownDefaultCollapsesToDeny(t *testing.T) {
	for _, in := range []string{"", "ALLOW", "permit", "whatever", store.ACLDeny} {
		snap := buildACLSnapshot(nil, in)
		if snap.defaultAction != store.ACLDeny {
			t.Errorf("default=%q → %q,want deny —— 兜底方向错成放行等于整台 server 默认不设防", in, snap.defaultAction)
		}
	}
	// 明确的 allow 要原样保留,否则 default=allow 的部署会被莫名收紧成全拒。
	if snap := buildACLSnapshot(nil, store.ACLAllow); snap.defaultAction != store.ACLAllow {
		t.Errorf("default=allow 被改成了 %q —— 这会让 default=allow 的部署突然全站不通", snap.defaultAction)
	}
}

// TestBuildACLSnapshot_PutsWildcardAndNilRulesWhereTheyBelong 通配出口规则进通配桶,nil 项跳过。
func TestBuildACLSnapshot_PutsWildcardAndNilRulesWhereTheyBelong(t *testing.T) {
	rules := []*store.ACLPair{
		nil, // 一条脏数据不该掀翻整次 reload
		{SrcUserID: 0, DstKind: store.ACLDstKindExit, Action: store.ACLDeny, Proto: "tcp", DstPortLo: 25, DstPortHi: 25},
		{SrcUserID: 7, DstKind: store.ACLDstKindExit, Action: store.ACLAllow},
	}
	snap := buildACLSnapshot(rules, store.ACLAllow)

	if !snap.hasExitRules {
		t.Fatal("有出口规则却没置 hasExitRules —— 出口方向的裁决会被整体跳过")
	}
	if len(snap.exitWild) != 1 {
		t.Fatalf("src_user_id=0 的通配出口规则进了 %d 条通配桶,want 1 —— 它落到 by-src[0] 就永远没人命中,管理员配的出口限制静默失效", len(snap.exitWild))
	}
	if got := snap.exitBySrc[7]; len(got) != 1 {
		t.Fatalf("指定用户的出口规则没进 by-src 桶,got %d 条", len(got))
	}
	if _, wrong := snap.exitBySrc[0]; wrong {
		t.Error("通配规则同时落进了 by-src[0] —— 同一条规则会被算两次")
	}
}

// TestAclAllows_FailsOpenBeforeTheFirstSnapshotLoads 快照还没装好时 CLI 判定必须放行。
//
// aclAllows 是 CLI / control socket 的「这两个用户能不能互通」问答口。启动初快照为 nil,此时报 deny
// 会让运维在排查时看到一屏「全都不通」,据此去改配置 —— 而数据面那侧同样的 nil 会 fail-open 放行,
// 两边说法相反。
func TestAclAllows_FailsOpenBeforeTheFirstSnapshotLoads(t *testing.T) {
	withACLSnapshotForTest(t, nil)

	if !aclAllows(3, 9) {
		t.Error("快照未加载时报了 deny —— 与数据面 fail-open 的口径相反,运维会照着错的结论改配置")
	}
	// 自查恒放行,这条与快照无关。
	if !aclAllows(5, 5) {
		t.Error("同一用户之间被判 deny")
	}
}

// TestRuleMatchesPacket_PortRulesNeverTouchPortlessTraffic 带端口的规则不该压到 ICMP 这类无端口流量上。
//
// 若带端口的规则对 ICMP 也算命中,一条「deny tcp 22」会顺带把 ping 一起封掉 —— 管理员看着规则里
// 写的是 tcp,却发现 ICMP 也不通,几乎不可能想到是这里。
func TestRuleMatchesPacket_PortRulesNeverTouchPortlessTraffic(t *testing.T) {
	// 端口范围特意从 0 起:ICMP 的 dstPort 恒为 0,只有落在范围内时「带端口的规则命中了无端口流量」
	// 这件事才真的可观测 —— 否则端口比较那一步会顺手把它挡掉,看不出防线在不在。
	portRule := ruleEntry{action: store.ACLDeny, portLo: 0, portHi: 1024, hasPorts: true}

	icmp := pktTuple{proto: "icmp", dst: netip.MustParseAddr("10.0.0.2")}
	if ruleMatchesPacket(portRule, icmp) {
		t.Error("带端口的规则命中了 ICMP —— 一条 deny tcp 0-1024 会把 ping 一起封掉")
	}
	if rulePortIndeterminate(portRule, icmp) {
		t.Error("ICMP 被判成「端口不可判定」→ fail-closed 丢包,同样是把 ping 误封")
	}

	// tcp 且端口可判定:该命中就得命中,否则这条规则等于没配。
	tcp := pktTuple{proto: "tcp", dstPort: 22, hasL4Ports: true, dst: netip.MustParseAddr("10.0.0.2")}
	if !ruleMatchesPacket(portRule, tcp) {
		t.Error("deny 0-1024 没命中真正发往 22 端口的 tcp 包")
	}
	// tcp 但端口不可判定(分片非首片):端口 deny 必须 fail-closed,否则分片即绕过。
	frag := pktTuple{proto: "tcp", hasL4Ports: false, dst: netip.MustParseAddr("10.0.0.2")}
	if !rulePortIndeterminate(portRule, frag) {
		t.Error("非首片没被判成端口不可判定 —— 把流量分片就能绕过端口 deny")
	}
	// 端口 allow 不参与这条 fail-closed(否则合法分片会被误丢)。
	allowRule := ruleEntry{action: store.ACLAllow, portLo: 22, portHi: 22, hasPorts: true}
	if rulePortIndeterminate(allowRule, frag) {
		t.Error("端口 allow 规则也走了 fail-closed —— 合法的分片流量会被误丢")
	}
}

// TestConnSourceSpoofed_SkipsUnparsableVIPsWithoutLosingTheCheck vIP 字符串坏掉时不能连校验一起丢。
//
// 会话的 vIP 列表里若有一条解析不出的字符串(旧库脏数据 / 半初始化状态),跳过它是对的;但不能因为
// 「一条都没解析成功」就把整个源地址校验当作不适用 —— 那样这条会话可以拿任意源地址发包。
func TestConnSourceSpoofed_SkipsUnparsableVIPsWithoutLosingTheCheck(t *testing.T) {
	resetConnByDeviceForTest(t)

	c := &Connection{userID: "1", connIDStr: "spoof-badvip"}
	ips := []util.VirtualIPAssignment{
		{VirtualIP: "not-an-ip"},
		{VirtualIP: "10.60.0.5"},
	}
	c.clientIPs.Store(&ips)

	// 用自己那条能解析的 vIP 作源 → 合法。
	if connSourceSpoofed(c, mkV4SrcDst([4]byte{10, 60, 0, 5}, [4]byte{10, 60, 0, 9})) {
		t.Error("拿自己的 vIP 作源被判成伪装 —— 这条会话的正常流量全被丢掉")
	}
	// 拿别的地址作源 → 必须判伪装(脏数据不能把这道校验整体作废)。
	if !connSourceSpoofed(c, mkV4SrcDst([4]byte{10, 60, 0, 77}, [4]byte{10, 60, 0, 9})) {
		t.Error("非自身 vIP 作源没被判伪装 —— 一条坏掉的 vIP 记录把整道源地址校验作废了")
	}
}

// TestUnregisterVIPOwners_EmptyInputTouchesNothing 空输入不该动那张写时复制的表。
func TestUnregisterVIPOwners_EmptyInputTouchesNothing(t *testing.T) {
	addr := netip.MustParseAddr("10.61.0.4")
	registerVIPOwners([]netip.Addr{addr}, 42, 7)
	t.Cleanup(func() { unregisterVIPOwners([]netip.Addr{addr}, 7) })

	unregisterVIPOwners(nil, 7)
	if uid, ok := lookupVIPOwner(addr); !ok || uid != 42 {
		t.Fatalf("空输入把表改了(got uid=%d ok=%v)—— 现有会话的流量会查不到归属而被误判", uid, ok)
	}
}

// mkV4SrcDst 造一个指定源/目的的 UDP over IPv4 报文(20 字节头 + 8 字节 UDP 头)。
func mkV4SrcDst(src, dst [4]byte) []byte {
	return []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		src[0], src[1], src[2], src[3],
		dst[0], dst[1], dst[2], dst[3],
		0x12, 0x34, 0x00, 0x35,
		0x00, 0x08, 0x00, 0x00,
	}
}
