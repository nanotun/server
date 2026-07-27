package main

import (
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
)

// evaluateExit 是「谁能用出口、走什么 proto/端口」的裁决器,此前只有一条 blanket deny 走到过(28.6%)。
// 出口是整套系统唯一通往公网的口子,这里判错就是要么放行本该拦的、要么把用户的上网整个掐断。

// exitSnap 造一份只关心 exit 规则的快照。
func exitSnap(defaultAction string, bySrc map[int64][]ruleEntry, wild []ruleEntry) *aclSnapshot {
	return &aclSnapshot{
		hasExitRules:  len(bySrc) > 0 || len(wild) > 0,
		exitBySrc:     bySrc,
		exitWild:      wild,
		defaultAction: defaultAction,
		meshEnabled:   true,
	}
}

// tcpTo 造一个「端口已知」的 tcp tuple。
func tcpTo(port uint16) pktTuple {
	return pktTuple{
		src:        netip.MustParseAddr("10.0.0.7"),
		dst:        netip.MustParseAddr("8.8.8.8"),
		proto:      "tcp",
		dstPort:    port,
		hasL4Ports: true,
	}
}

// tcpNoPorts 造一个「是 tcp 但端口不可判定」的 tuple(非首片 / 截断头)。
func tcpNoPorts() pktTuple {
	t := tcpTo(0)
	t.hasL4Ports = false
	return t
}

func allowRule(proto string, lo, hi uint16) ruleEntry {
	return ruleEntry{action: store.ACLAllow, proto: proto, portLo: lo, portHi: hi, hasPorts: lo != 0 || hi != 0}
}

func denyRule(proto string, lo, hi uint16) ruleEntry {
	return ruleEntry{action: store.ACLDeny, proto: proto, portLo: lo, portHi: hi, hasPorts: lo != 0 || hi != 0}
}

func TestEvaluateExit_ArbitratesSrcRulesWildcardsAndDefault(t *testing.T) {
	const src = int64(7)

	cases := []struct {
		name    string
		bySrc   map[int64][]ruleEntry
		wild    []ruleEntry
		tuple   pktTuple
		deflt   string
		want    string
		because string
	}{
		{
			name:    "src 端口 allow 命中",
			bySrc:   map[int64][]ruleEntry{src: {allowRule("tcp", 443, 443)}},
			tuple:   tcpTo(443),
			deflt:   store.ACLDeny,
			want:    store.ACLAllow,
			because: "白名单里显式放了 443,就得放行",
		},
		{
			name:    "src 端口 allow 但端口对不上",
			bySrc:   map[int64][]ruleEntry{src: {allowRule("tcp", 443, 443)}},
			tuple:   tcpTo(80),
			deflt:   store.ACLDeny,
			want:    store.ACLDeny,
			because: "只放了 443,80 应落回 default=deny",
		},
		{
			name:    "src 端口 allow 但 proto 对不上",
			bySrc:   map[int64][]ruleEntry{src: {allowRule("tcp", 443, 443)}},
			tuple:   pktTuple{proto: "udp", dstPort: 443, hasL4Ports: true},
			deflt:   store.ACLDeny,
			want:    store.ACLDeny,
			because: "规则限了 tcp,udp/443 不该蹭到放行",
		},
		{
			name:    "src blanket deny",
			bySrc:   map[int64][]ruleEntry{src: {denyRule("", 0, 0)}},
			tuple:   tcpTo(443),
			deflt:   store.ACLAllow,
			want:    store.ACLDeny,
			because: "显式 deny 压过 default=allow",
		},
		{
			name:    "别人的 src 规则不该影响本人",
			bySrc:   map[int64][]ruleEntry{99: {denyRule("", 0, 0)}},
			tuple:   tcpTo(443),
			deflt:   store.ACLAllow,
			want:    store.ACLAllow,
			because: "exitBySrc 必须按 src 索引,不能串号",
		},
		{
			name:    "只有通配 allow",
			wild:    []ruleEntry{allowRule("", 0, 0)},
			tuple:   tcpTo(80),
			deflt:   store.ACLDeny,
			want:    store.ACLAllow,
			because: "src=* 的 allow 桶必须被扫到",
		},
		{
			name:    "只有通配 deny",
			wild:    []ruleEntry{denyRule("", 0, 0)},
			tuple:   tcpTo(80),
			deflt:   store.ACLAllow,
			want:    store.ACLDeny,
			because: "src=* 的 deny 桶必须被扫到",
		},
		{
			name:    "src allow 命中但通配 deny —— deny 赢",
			bySrc:   map[int64][]ruleEntry{src: {allowRule("tcp", 443, 443)}},
			wild:    []ruleEntry{denyRule("", 0, 0)},
			tuple:   tcpTo(443),
			deflt:   store.ACLAllow,
			want:    store.ACLDeny,
			because: "deny-first:精确桶放行不能盖过通配 deny",
		},
		{
			name:    "通配 deny 但 proto 不匹配 → 不算命中",
			wild:    []ruleEntry{denyRule("udp", 0, 0)},
			tuple:   tcpTo(443),
			deflt:   store.ACLAllow,
			want:    store.ACLAllow,
			because: "deny udp 不该殃及 tcp",
		},
		{
			name:    "无任何规则命中 → 落 default=allow",
			bySrc:   map[int64][]ruleEntry{src: {allowRule("tcp", 443, 443)}},
			tuple:   tcpTo(8080),
			deflt:   store.ACLAllow,
			want:    store.ACLAllow,
			because: "都没命中就该用 defaultAction",
		},
		{
			name:    "空规则集 → 落 default=deny",
			tuple:   tcpTo(80),
			deflt:   store.ACLDeny,
			want:    store.ACLDeny,
			because: "白名单模型下没放行就是拒",
		},
		{
			name:    "端口不可判定 + src 端口 deny → fail-closed",
			bySrc:   map[int64][]ruleEntry{src: {denyRule("tcp", 22, 22)}},
			tuple:   tcpNoPorts(),
			deflt:   store.ACLAllow,
			want:    store.ACLDeny,
			because: "分片藏端口绕过 deny 是真实攻击手法,必须 fail-closed",
		},
		{
			name:    "端口不可判定 + 通配桶端口 deny → fail-closed",
			wild:    []ruleEntry{denyRule("tcp", 22, 22)},
			tuple:   tcpNoPorts(),
			deflt:   store.ACLAllow,
			want:    store.ACLDeny,
			because: "通配桶的端口 deny 同样不能被分片绕过",
		},
		{
			name:    "端口不可判定 + 端口 allow → 不 fail-closed",
			bySrc:   map[int64][]ruleEntry{src: {allowRule("tcp", 22, 22)}},
			tuple:   tcpNoPorts(),
			deflt:   store.ACLAllow,
			want:    store.ACLAllow,
			because: "fail-closed 只对 deny 生效,否则合法分片流量会被误杀",
		},
		{
			name:  "L4 完全解不出 + 纯 proto deny → fail-closed",
			bySrc: map[int64][]ruleEntry{src: {denyRule("tcp", 0, 0)}},
			tuple: pktTuple{
				src:          netip.MustParseAddr("10.0.0.7"),
				dst:          netip.MustParseAddr("8.8.8.8"),
				l4Unresolved: true,
			},
			deflt:   store.ACLAllow,
			want:    store.ACLDeny,
			because: "扩展头耗尽把 TCP 藏在链后,同样不能放行",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evaluateExit(exitSnap(c.deflt, c.bySrc, c.wild), src, c.tuple)
			if got != c.want {
				t.Fatalf("evaluateExit = %q, want %q —— %s", got, c.want, c.because)
			}
		})
	}
}

// 出口规则按端口放行时,端到端(经 aclDropPacketDirected)也要一致:443 通、80 拒。
// 直接测 evaluateExit 只能证明裁决器对,这条证明它确实被热路径调用了。
func TestACLDropPacketDirected_ExitPortScopedAllow(t *testing.T) {
	const uid = int64(77)
	vip := netip.MustParseAddr("10.0.0.77")
	registerVIPOwners([]netip.Addr{vip}, uid, 1)
	t.Cleanup(func() { unregisterVIPOwners([]netip.Addr{vip}, 1) })

	prev := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(prev) })
	aclCurrent.Store(exitSnap(store.ACLDeny,
		map[int64][]ruleEntry{uid: {allowRule("tcp", 443, 443)}}, nil))

	if aclDropPacketDirected(uid, ipv4TCPTo("8.8.8.8", 443)) {
		t.Error("显式放行的 tcp/443 出口流量被丢了")
	}
	if !aclDropPacketDirected(uid, ipv4TCPTo("8.8.8.8", 80)) {
		t.Error("default=deny 下未放行的 tcp/80 应被丢")
	}
}

// ipv4TCPTo 造一份最小 IPv4+TCP 报文(20B IP 头 + 4B 端口)。
func ipv4TCPTo(dst string, dstPort uint16) []byte {
	d := netip.MustParseAddr(dst).As4()
	p := []byte{
		0x45, 0x00, 0x00, 0x18,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, // TTL=64, proto=TCP(6)
		10, 0, 0, 77,
		d[0], d[1], d[2], d[3],
		0x30, 0x39, byte(dstPort >> 8), byte(dstPort & 0xff),
	}
	return p
}

// -------------------------------------------------- 解析不出的报文 fail-closed

// 过了上游校验却仍解不出 tuple 的畸形包(版本号既不是 4 也不是 6)→ 丢,不放。
func TestACLDropPacketDirected_UnparsablePacketFailsClosed(t *testing.T) {
	prev := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(prev) })
	aclCurrent.Store(&aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: true})

	weird := []byte{0x50, 0x00, 0x00, 0x14, 0, 0, 0, 0} // version nibble = 5
	before := aclDropCount.Load()
	if !aclDropPacketDirected(1, weird) {
		t.Fatal("解析不出的包必须 fail-closed 丢弃")
	}
	if got := aclDropCount.Load(); got != before+1 {
		t.Fatalf("acl drop 计数 %d → %d,应 +1", before, got)
	}
	// 反证:无 user 上下文时不做 enforcement,同一个包放行。
	if aclDropPacketDirected(0, weird) {
		t.Fatal("srcUserID=0 是无上下文路径,不该在这里丢包")
	}
}

// ---------------------------------------------- IPv6 扩展头链的截断 / 越界

func TestParsePacketTuple_IPv6TruncatedChainsAreUnresolved(t *testing.T) {
	// base 造一份 IPv6 头,nextHeader 由调用方指定,后面接 tail。
	base := func(nextHeader byte, tail ...byte) []byte {
		p := make([]byte, 40, 40+len(tail))
		p[0] = 0x60
		p[6] = nextHeader
		p[7] = 64
		p[8], p[9], p[10], p[11] = 0x20, 0x01, 0x0d, 0xb8
		p[23] = 0x01
		p[24], p[25], p[26], p[27] = 0x20, 0x01, 0x0d, 0xb8
		p[39] = 0x02
		return append(p, tail...)
	}

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"Dest-Opts 头只剩 1 字节(读不出 Hdr-Ext-Len)", base(60, 0x06)},
		{"Dest-Opts 的 Hdr-Ext-Len 指到包外", base(60, 0x06, 0xff)},
		{"Fragment 头被截断(不足 8 字节)", base(44, 0x06, 0x00, 0x00)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parsePacketTuple(c.pkt)
			if !ok {
				t.Fatal("IPv6 报文本身合法,不该整包判失败")
			}
			if !got.l4Unresolved {
				t.Fatal("链解不到 L4 时必须打 l4Unresolved,否则端口 deny 会被绕过")
			}
			if got.hasL4Ports {
				t.Fatal("没解到 L4 却声称拿到了端口")
			}
		})
	}
}

// IPv6 非首片:能确定是 TCP,但不该声称拿到了端口(那 4 字节是净荷)。
func TestParsePacketTuple_IPv6NonFirstFragmentHasNoPorts(t *testing.T) {
	p := make([]byte, 40, 56)
	p[0] = 0x60
	p[6] = 44 // Fragment
	p[7] = 64
	p[8], p[9], p[10], p[11] = 0x20, 0x01, 0x0d, 0xb8
	p[23] = 0x01
	p[24], p[25], p[26], p[27] = 0x20, 0x01, 0x0d, 0xb8
	p[39] = 0x02
	// Fragment 头:next=TCP(6),offset=185(<<3 = 0x05c8),后面跟 4 字节「看起来像端口」的净荷。
	p = append(p, 6, 0x00, 0x05, 0xc8, 0x00, 0x00, 0x00, 0x01)
	p = append(p, 0x00, 0x50, 0x01, 0xbb) // 净荷:碰巧长得像 80 → 443

	got, ok := parsePacketTuple(p)
	if !ok {
		t.Fatal("合法 IPv6 分片不该判失败")
	}
	if got.proto != "tcp" {
		t.Fatalf("proto=%q,want tcp", got.proto)
	}
	if got.hasL4Ports {
		t.Fatal("非首片不含 L4 头,把净荷当端口会让 ACL 判错")
	}
	if got.dstPort != 0 {
		t.Fatalf("dstPort=%d,非首片应保持 0", got.dstPort)
	}
}

// ------------------------------------------------------------ 日志摘要

func TestACLSummaryForLog_CountsEveryBucket(t *testing.T) {
	prev := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(prev) })

	aclCurrent.Store(&aclSnapshot{
		defaultAction: store.ACLDeny,
		meshEnabled:   false,
		userExact: map[aclPair][]ruleEntry{
			{src: 1, dst: 2}: {allowRule("", 0, 0), denyRule("tcp", 22, 22)},
		},
		userBySrc: map[int64][]ruleEntry{1: {allowRule("", 0, 0)}},
		userByDst: map[int64][]ruleEntry{2: {denyRule("", 0, 0)}},
		userAll:   []ruleEntry{allowRule("", 0, 0)},
		exitBySrc: map[int64][]ruleEntry{1: {denyRule("", 0, 0), allowRule("tcp", 443, 443)}},
		exitWild:  []ruleEntry{allowRule("", 0, 0)},
	})

	f := aclSummaryForLog()
	want := map[string]any{
		"mesh_enabled":   false,
		"default_action": store.ACLDeny,
		"user_exact":     2, // 同一 pair 下两条都要算上,不是「有几个 key」
		"user_by_src":    1,
		"user_by_dst":    1,
		"user_all":       1,
		"exit_by_src":    2,
		"exit_wild":      1,
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("%s = %v(%T), want %v(%T)", k, f[k], f[k], v, v)
		}
	}
}

func TestACLSummaryForLog_NilSnapshotSaysSo(t *testing.T) {
	prev := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(prev) })
	aclCurrent.Store(nil)

	if got := aclSummaryForLog()["snapshot"]; got != "nil" {
		t.Fatalf(`快照为 nil 时应报 snapshot="nil",got %v`, got)
	}
}
