package main

import (
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
)

// 帮助:把一份测试规则装载为当前 snapshot,默认动作为 ACLAllow。
func loadACLForTest(rules []*store.ACLPair, defaultAction string) {
	aclCurrent.Store(buildACLSnapshot(rules, defaultAction))
}

// 校验 buildACLSnapshot 把规则正确分桶(user/exit 各自的 exact / wildSrc / wildDst / all)。
func TestBuildACLSnapshot_BucketsUser(t *testing.T) {
	rules := []*store.ACLPair{
		{SrcUserID: 1, DstUserID: 2, Action: store.ACLDeny, DstKind: store.ACLDstKindUser},
		{SrcUserID: 1, DstUserID: 3, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
		{SrcUserID: 0, DstUserID: 5, Action: store.ACLDeny, DstKind: store.ACLDstKindUser},
		{SrcUserID: 6, DstUserID: 0, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
		{SrcUserID: 0, DstUserID: 0, Action: store.ACLDeny, DstKind: store.ACLDstKindUser},
	}
	s := buildACLSnapshot(rules, store.ACLAllow)
	if !s.hasUserRules {
		t.Fatal("hasUserRules=false")
	}
	if len(s.userExact[aclPair{1, 2}]) == 0 || s.userExact[aclPair{1, 2}][0].action != store.ACLDeny {
		t.Fatalf("deny exact (1,2) missing or wrong: %+v", s.userExact)
	}
	if len(s.userExact[aclPair{1, 3}]) == 0 || s.userExact[aclPair{1, 3}][0].action != store.ACLAllow {
		t.Fatal("allow exact (1,3) missing")
	}
	if len(s.userByDst[5]) == 0 || s.userByDst[5][0].action != store.ACLDeny {
		t.Fatal("deny wildSrc dst=5 missing")
	}
	if len(s.userBySrc[6]) == 0 || s.userBySrc[6][0].action != store.ACLAllow {
		t.Fatal("allow wildDst src=6 missing")
	}
	if len(s.userAll) == 0 || s.userAll[0].action != store.ACLDeny {
		t.Fatal("userAll deny missing")
	}
}

// 空规则集 + default=allow → 全放行(与历史行为一致)。
func TestACLAllows_EmptyRuleSet_AllowsAll(t *testing.T) {
	loadACLForTest(nil, store.ACLAllow)
	if !aclAllows(1, 2) {
		t.Fatal("empty rule set should allow")
	}
}

// 空规则集 + default=deny → 跨用户全拒(白名单语义)。
func TestACLAllows_EmptyRuleSet_DefaultDeny(t *testing.T) {
	loadACLForTest(nil, store.ACLDeny)
	if aclAllows(1, 2) {
		t.Fatal("empty + default=deny should drop (1→2)")
	}
	if !aclAllows(7, 7) {
		t.Fatal("default=deny must still allow same-user (7→7)")
	}
}

// src==dst 永远允许,即便有 deny-all 规则。
func TestACLAllows_SameUserAlwaysAllowed(t *testing.T) {
	loadACLForTest([]*store.ACLPair{
		{SrcUserID: 0, DstUserID: 0, Action: store.ACLDeny, DstKind: store.ACLDstKindUser},
	}, store.ACLAllow)
	if !aclAllows(7, 7) {
		t.Fatal("src==dst should always allow even under deny-all")
	}
}

// deny 优先于 allow。
func TestACLAllows_DenyPriority(t *testing.T) {
	loadACLForTest([]*store.ACLPair{
		{SrcUserID: 1, DstUserID: 2, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
		{SrcUserID: 1, DstUserID: 2, Action: store.ACLDeny, DstKind: store.ACLDstKindUser},
	}, store.ACLAllow)
	if aclAllows(1, 2) {
		t.Fatal("explicit deny should win over allow")
	}
}

// 深扫第十二轮 MED:normalizeACLAction 只把「allow(不分大小写/首尾空白)」判为 allow,
// 其余(含 "Deny"/"DENY"/带空白的 deny / 空串 / permit / 任意脏值)一律归到 deny(fail-closed)。
func TestNormalizeACLAction(t *testing.T) {
	for _, v := range []string{"allow", "ALLOW", " allow ", "Allow", "\tallow\n"} {
		if got := normalizeACLAction(v); got != store.ACLAllow {
			t.Errorf("normalizeACLAction(%q) = %q, want allow", v, got)
		}
	}
	for _, v := range []string{"deny", "DENY", " deny ", "Deny", "", "  ", "permit", "reject", "0", "garbage"} {
		if got := normalizeACLAction(v); got != store.ACLDeny {
			t.Errorf("normalizeACLAction(%q) = %q, want deny", v, got)
		}
	}
}

// 深扫第十二轮 MED:逐条规则 action 归一化的端到端验证。手抠 DB / 坏 SQL 写入的非规范
// action(大小写 / 空白 / 未知词)此前会因 `e.action != "deny"` 被当 allow 命中,放行本该
// 阻断的跨用户流量。归一化后:非 allow 的一律 fail-closed 到 deny;allow 的大小写/空白变体仍放行。
func TestACLAllows_NonCanonicalAction_FailsClosed(t *testing.T) {
	// default=allow 时,只有真正判为 deny 才会拦下 —— 用来暴露「非规范 deny 被当 allow」的旧缺口。
	for _, act := range []string{"Deny", "DENY", "deny ", " deny", "permit", "", "garbage"} {
		loadACLForTest([]*store.ACLPair{
			{SrcUserID: 1, DstUserID: 2, Action: act, DstKind: store.ACLDstKindUser},
		}, store.ACLAllow)
		if aclAllows(1, 2) {
			t.Fatalf("non-canonical action %q should fail closed to deny (was fail-open)", act)
		}
	}
	// 反向:default=deny 时,allow 的大小写/空白变体仍应放行(不能误伤合法规则)。
	for _, act := range []string{"allow", "ALLOW", " Allow "} {
		loadACLForTest([]*store.ACLPair{
			{SrcUserID: 1, DstUserID: 2, Action: act, DstKind: store.ACLDstKindUser},
		}, store.ACLDeny)
		if !aclAllows(1, 2) {
			t.Fatalf("case/space variant of allow %q should be allowed", act)
		}
	}
}

// 有规则集但都不匹配 + default=allow → 放行(v3 语义)。
func TestACLAllows_DefaultActionAllowFallback(t *testing.T) {
	loadACLForTest([]*store.ACLPair{
		{SrcUserID: 1, DstUserID: 2, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
	}, store.ACLAllow)
	if !aclAllows(3, 4) {
		t.Fatal("non-matching (3,4) should fallback to default=allow")
	}
}

// 有规则集但都不匹配 + default=deny → 默认拒绝(白名单)。
func TestACLAllows_DefaultActionDenyFallback(t *testing.T) {
	loadACLForTest([]*store.ACLPair{
		{SrcUserID: 1, DstUserID: 2, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
	}, store.ACLDeny)
	if aclAllows(3, 4) {
		t.Fatal("non-matching (3,4) should fallback to default=deny")
	}
}

// wildSrc(src=*,dst=X) deny 命中。
func TestACLAllows_WildSrcDeny(t *testing.T) {
	loadACLForTest([]*store.ACLPair{
		{SrcUserID: 0, DstUserID: 9, Action: store.ACLDeny, DstKind: store.ACLDstKindUser},
	}, store.ACLDeny)
	if aclAllows(5, 9) {
		t.Fatal("wildSrc deny (*→9) should drop (5,9)")
	}
	if aclAllows(5, 10) {
		t.Fatal("non-matching (5,10) should fallback to default=deny")
	}
}

// allowAll 通配。
func TestACLAllows_AllowAllWildcard(t *testing.T) {
	loadACLForTest([]*store.ACLPair{
		{SrcUserID: 0, DstUserID: 0, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
	}, store.ACLDeny)
	if !aclAllows(99, 100) {
		t.Fatal("allowAll should let everyone through even with default=deny")
	}
}

// vipOwner register/unregister/lookup 配套。
func TestVIPOwner_RoundTrip(t *testing.T) {
	a := netip.MustParseAddr("10.200.0.5")
	b := netip.MustParseAddr("10.200.0.6")
	registerVIPOwners([]netip.Addr{a, b}, 42)
	if uid, ok := lookupVIPOwner(a); !ok || uid != 42 {
		t.Fatalf("lookup a got %d,%v want 42,true", uid, ok)
	}
	if uid, ok := lookupVIPOwner(b); !ok || uid != 42 {
		t.Fatalf("lookup b got %d,%v want 42,true", uid, ok)
	}
	unregisterVIPOwners([]netip.Addr{a})
	if _, ok := lookupVIPOwner(a); ok {
		t.Fatal("a should be gone after unregister")
	}
	if _, ok := lookupVIPOwner(b); !ok {
		t.Fatal("b should still be present")
	}
	unregisterVIPOwners([]netip.Addr{b})
}

// userID=0 → 一律跳过 ACL(测试场景 / connIDStr parse 失败)。
func TestVIPOwner_RegisterIgnoresZeroUserID(t *testing.T) {
	a := netip.MustParseAddr("10.200.0.7")
	registerVIPOwners([]netip.Addr{a}, 0)
	if _, ok := lookupVIPOwner(a); ok {
		t.Fatal("userID=0 should be a no-op")
	}
}

// parsePacketTuple 正确解析 IPv4 / IPv6 + tcp/udp dst port。
func TestParsePacketTuple(t *testing.T) {
	// IPv4 UDP 包,IHL=5,proto=17(UDP),dstIP=10.0.0.99,dstPort=53。
	ipv4 := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		1, 2, 3, 4,
		10, 0, 0, 99,
		0x12, 0x34, 0x00, 0x35, // src 4660, dst 53
		0x00, 0x08, 0x00, 0x00,
	}
	tu, ok := parsePacketTuple(ipv4)
	if !ok || tu.dst.String() != "10.0.0.99" || tu.proto != "udp" || tu.dstPort != 53 {
		t.Fatalf("ipv4 udp parse got %+v %v, want 10.0.0.99 udp 53 true", tu, ok)
	}

	// IPv4 TCP 包,dstPort=22。
	ipv4tcp := []byte{
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00,
		1, 2, 3, 4,
		10, 0, 0, 9,
		0x10, 0x00, 0x00, 0x16,
		0, 0, 0, 0, 0, 0, 0, 0,
		0x50, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	tu, ok = parsePacketTuple(ipv4tcp)
	if !ok || tu.proto != "tcp" || tu.dstPort != 22 {
		t.Fatalf("ipv4 tcp parse got %+v %v, want tcp 22", tu, ok)
	}

	// IPv6 无 L4(NextHeader=59 No Next Header)
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60
	ipv6[6] = 59
	ipv6[24] = 0xfd
	ipv6[39] = 0xcd
	tu, ok = parsePacketTuple(ipv6)
	if !ok || !tu.dst.Is6() || tu.proto != "" || tu.dstPort != 0 {
		t.Fatalf("ipv6 nh=59 parse got %+v %v, want valid ipv6 with no proto", tu, ok)
	}
}

// 数据面 enforcement 端到端:user-kind 规则。
func TestACLDropPacketDirected_UserKind(t *testing.T) {
	registerVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, 1)
	registerVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, 2)
	defer unregisterVIPOwners([]netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
	})
	loadACLForTest([]*store.ACLPair{
		{SrcUserID: 1, DstUserID: 2, Action: store.ACLDeny, DstKind: store.ACLDstKindUser},
	}, store.ACLAllow)

	udpPkt := func(srcIP, dstIP [4]byte) []byte {
		return []byte{
			0x45, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x00, 0x00,
			0x40, 0x11, 0x00, 0x00,
			srcIP[0], srcIP[1], srcIP[2], srcIP[3],
			dstIP[0], dstIP[1], dstIP[2], dstIP[3],
			0x12, 0x34, 0x00, 0x35,
			0x00, 0x08, 0x00, 0x00,
		}
	}
	if !aclDropPacketDirected(1, udpPkt([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2})) {
		t.Fatal("expected drop for (1→2) deny")
	}
	if aclDropPacketDirected(2, udpPkt([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})) {
		t.Fatal("default=allow + (2→1) no rule should pass")
	}
	if aclDropPacketDirected(1, udpPkt([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 1})) {
		t.Fatal("same-user packet (1→1) should not be dropped")
	}
	if aclDropPacketDirected(1, udpPkt([4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8})) {
		t.Fatal("default=allow exit packet should not be dropped without exit rules")
	}
	if aclDropPacketDirected(0, udpPkt([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2})) {
		t.Fatal("srcUserID=0 should skip enforcement")
	}
}

// 端口 + 协议精细规则:deny TCP:22 但 allow 其它端口。
func TestACLDropPacketDirected_PortProto(t *testing.T) {
	registerVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.10")}, 10)
	registerVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.11")}, 11)
	defer unregisterVIPOwners([]netip.Addr{
		netip.MustParseAddr("10.0.0.10"),
		netip.MustParseAddr("10.0.0.11"),
	})
	loadACLForTest([]*store.ACLPair{
		{SrcUserID: 10, DstUserID: 11, Action: store.ACLDeny, Proto: "tcp", DstPortLo: 22, DstPortHi: 22, DstKind: store.ACLDstKindUser},
	}, store.ACLAllow)

	tcpPkt := func(srcIP, dstIP [4]byte, dstPort uint16) []byte {
		return []byte{
			0x45, 0x00, 0x00, 0x28,
			0x00, 0x00, 0x00, 0x00,
			0x40, 0x06, 0x00, 0x00,
			srcIP[0], srcIP[1], srcIP[2], srcIP[3],
			dstIP[0], dstIP[1], dstIP[2], dstIP[3],
			0x10, 0x00, byte(dstPort >> 8), byte(dstPort & 0xff),
			0, 0, 0, 0, 0, 0, 0, 0,
			0x50, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	}
	// TCP:22 → drop
	if !aclDropPacketDirected(10, tcpPkt([4]byte{10, 0, 0, 10}, [4]byte{10, 0, 0, 11}, 22)) {
		t.Fatal("expected drop for tcp:22")
	}
	// TCP:80 → 默认 allow
	if aclDropPacketDirected(10, tcpPkt([4]byte{10, 0, 0, 10}, [4]byte{10, 0, 0, 11}, 80)) {
		t.Fatal("tcp:80 should pass under default=allow")
	}
	// UDP:22 → 默认 allow(proto 不匹配)
	udpPkt := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		10, 0, 0, 10,
		10, 0, 0, 11,
		0x12, 0x34, 0x00, 0x16,
		0x00, 0x08, 0x00, 0x00,
	}
	if aclDropPacketDirected(10, udpPkt) {
		t.Fatal("udp:22 should pass — rule is tcp:22")
	}
}

// 出口规则:disable_exit-by-rule。
func TestACLDropPacketDirected_ExitKind(t *testing.T) {
	registerVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.20")}, 20)
	defer unregisterVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.20")})

	loadACLForTest([]*store.ACLPair{
		{SrcUserID: 20, Action: store.ACLDeny, DstKind: store.ACLDstKindExit},
	}, store.ACLAllow)

	exitPkt := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		10, 0, 0, 20,
		8, 8, 8, 8,
		0x12, 0x34, 0x00, 0x35,
		0x00, 0x08, 0x00, 0x00,
	}
	if !aclDropPacketDirected(20, exitPkt) {
		t.Fatal("user 20 → 8.8.8.8 should be dropped by exit rule")
	}
}

// 出口规则 + default=deny:除非显式 allow 否则全拒。
func TestACLDropPacketDirected_ExitDefaultDeny(t *testing.T) {
	registerVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.21")}, 21)
	defer unregisterVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.21")})

	loadACLForTest(nil, store.ACLDeny)
	pkt := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		10, 0, 0, 21,
		1, 1, 1, 1,
		0x12, 0x34, 0x00, 0x35,
		0x00, 0x08, 0x00, 0x00,
	}
	if !aclDropPacketDirected(21, pkt) {
		t.Fatal("default=deny should drop exit packet without exit allow rules")
	}
}

// ----------------------------------------------------------------
// mesh 总开关(2026-05-23 引入)— 关闭组网模式后跨用户流量必须被截下来,
// 不论 ACL 规则怎么配,且同用户内部与出口流量不受影响。
// ----------------------------------------------------------------

// loadACLWithMesh 装一份 snapshot 同时显式设 meshEnabled。其它测试 helper
// 默认 meshEnabled=true(buildACLSnapshot 已经这样初始化),所以本 helper
// 只在「想测 off 行为」时调用。
func loadACLWithMesh(rules []*store.ACLPair, defaultAction string, meshEnabled bool) {
	snap := buildACLSnapshot(rules, defaultAction)
	snap.meshEnabled = meshEnabled
	aclCurrent.Store(snap)
}

// mesh OFF + 没有任何 ACL 规则 → 跨用户必丢,不管 default 是 allow 还是 deny。
func TestACLAllows_MeshOffDropsCrossUser(t *testing.T) {
	loadACLWithMesh(nil, store.ACLAllow, false) // 即便 default=allow 也丢
	if aclAllows(1, 2) {
		t.Fatal("mesh off + default=allow: cross-user should still be denied")
	}
	if !aclAllows(7, 7) {
		t.Fatal("mesh off must still allow same-user (7→7)")
	}
}

// mesh OFF 状态下,即便配了 explicit allow 规则,数据面也必须丢。
// 这是 mesh 总开关「比 ACL 还硬」的关键语义保证 —— 防止 admin 关组网后,
// 老的 allow 规则继续放行流量造成误期望。
func TestACLAllows_MeshOffBypassesExplicitAllow(t *testing.T) {
	loadACLWithMesh([]*store.ACLPair{
		{SrcUserID: 1, DstUserID: 2, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
		{SrcUserID: 0, DstUserID: 0, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
	}, store.ACLAllow, false)
	if aclAllows(1, 2) {
		t.Fatal("mesh off should hard-drop even explicit allow")
	}
}

// 数据面 enforcement:mesh off → 跨用户包必丢,同用户包正常,出口包正常,
// meshOffDropCount 计数器递增。
func TestACLDropPacketDirected_MeshOff(t *testing.T) {
	registerVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.30")}, 30)
	registerVIPOwners([]netip.Addr{netip.MustParseAddr("10.0.0.31")}, 31)
	defer unregisterVIPOwners([]netip.Addr{
		netip.MustParseAddr("10.0.0.30"),
		netip.MustParseAddr("10.0.0.31"),
	})

	// mesh OFF + 显式 allow 规则,数据面必须忽略 allow 直接丢。
	loadACLWithMesh([]*store.ACLPair{
		{SrcUserID: 30, DstUserID: 31, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
	}, store.ACLAllow, false)

	udpPkt := func(srcIP, dstIP [4]byte) []byte {
		return []byte{
			0x45, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x00, 0x00,
			0x40, 0x11, 0x00, 0x00,
			srcIP[0], srcIP[1], srcIP[2], srcIP[3],
			dstIP[0], dstIP[1], dstIP[2], dstIP[3],
			0x12, 0x34, 0x00, 0x35,
			0x00, 0x08, 0x00, 0x00,
		}
	}

	before := meshOffDropCount.Load()
	if !aclDropPacketDirected(30, udpPkt([4]byte{10, 0, 0, 30}, [4]byte{10, 0, 0, 31})) {
		t.Fatal("mesh off: cross-user 30→31 must be dropped even with explicit allow rule")
	}
	if got := meshOffDropCount.Load(); got != before+1 {
		t.Fatalf("meshOffDropCount: got %d, want %d (before+1)", got, before+1)
	}

	// 同用户内部仍然通(注册同 userID=30 的另一个 VIP 比较麻烦,用 src==dst 验证)。
	if aclDropPacketDirected(30, udpPkt([4]byte{10, 0, 0, 30}, [4]byte{10, 0, 0, 30})) {
		t.Fatal("mesh off must NOT drop same-user (30→30) packets")
	}

	// 出口流量(dst 不属于任何 VIP)必须正常通过 —— mesh off 不影响出口路径。
	if aclDropPacketDirected(30, udpPkt([4]byte{10, 0, 0, 30}, [4]byte{8, 8, 8, 8})) {
		t.Fatal("mesh off must NOT drop exit traffic (30 → 8.8.8.8)")
	}
}

// 切回 mesh ON → 之前 drop 的流量重新通过。验证 toggle 是可逆的。
func TestACLAllows_MeshToggleRoundTrip(t *testing.T) {
	rules := []*store.ACLPair{
		{SrcUserID: 0, DstUserID: 0, Action: store.ACLAllow, DstKind: store.ACLDstKindUser},
	}
	// 先 OFF — 应该丢
	loadACLWithMesh(rules, store.ACLAllow, false)
	if aclAllows(5, 6) {
		t.Fatal("mesh off should deny")
	}
	// 切回 ON — 应该按规则放行
	loadACLWithMesh(rules, store.ACLAllow, true)
	if !aclAllows(5, 6) {
		t.Fatal("mesh on with allow rule should pass")
	}
}

// parseUserIDStr 正反例。
func TestParseUserIDStr(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"u1", 1},
		{"u12345", 12345},
		{"u0", 0},
		{"", 0},
		{"abc", 0},
		{"u", 0},
		{"u-1", 0},
		{"123", 0},
	}
	for _, c := range cases {
		got := parseUserIDStr(c.in)
		if got != c.want {
			t.Errorf("parseUserIDStr(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
