package main

import (
	"net"
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
	"golang.org/x/net/dns/dnsmessage"
)

// withACLSnapshotFor 装一份 ACL 快照,收尾还原(全局状态,别污染同包其它用例)。
func withACLSnapshotFor(t *testing.T, snap *aclSnapshot) {
	t.Helper()
	prev := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(prev) })
	aclCurrent.Store(snap)
}

// withVIPOwners 把一组 vIP 登记到某 user 名下,收尾摘掉。
func withVIPOwners(t *testing.T, userID int64, connID uint32, addrs ...netip.Addr) {
	t.Helper()
	registerVIPOwners(addrs, userID, connID)
	t.Cleanup(func() { unregisterVIPOwners(addrs, connID) })
}

// denyAllSnapshot 造一份「默认拒绝、且有 user 规则」的快照。
//
// hasUserRules 必须为真:整段裁决有 fast-path,规则集为空时直接放行,defaultAction 根本不看。
// 这也是「default=deny 却发现谁都能连」这类现场的成因。
func denyAllSnapshot() *aclSnapshot {
	return &aclSnapshot{
		hasUserRules:  true,
		userAll:       []ruleEntry{{action: store.ACLDeny}},
		defaultAction: store.ACLDeny,
		meshEnabled:   true,
	}
}

func udpFrom(ip string) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 5353} }

// TestMagicNameDeniedByACL_FailsOpenWheneverItCannotTell 拿不准的时候必须放行。
//
// 这道闸的作用是堵信息泄漏:ACL 判定 A→B 完全不可达时,A 不该能用 MagicDNS 把 B 的设备名解析成
// vIP(否则等于给了一个探测对方存在性与地址的接口,尽管数据面随后会丢包)。但它的每一处「查不到」
// 都必须 fail-open —— 判错方向的代价是**同用户自己的设备名突然解析不出来**,而现场只看得到
// 「DNS 挂了」,没人会想到是 ACL 的锅。
func TestMagicNameDeniedByACL_FailsOpenWheneverItCannotTell(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "bob", "laptop", "10.99.0.20", "")
	const suffix = "ts.net"
	const name = "laptop.bob." + suffix

	t.Run("快照未初始化", func(t *testing.T) {
		withACLSnapshotFor(t, nil)
		withVIPOwners(t, 1, 1, netip.MustParseAddr("10.99.0.10"))
		if magicNameDeniedByACL(t.Context(), gw, udpFrom("10.99.0.10"), name, suffix) {
			t.Error("ACL 快照还没装好就拦解析 —— 启动那几十毫秒里所有 magic 名都查不到")
		}
	})

	t.Run("查询方 vIP 不在归属表", func(t *testing.T) {
		withACLSnapshotFor(t, denyAllSnapshot())
		// 不登记 10.99.0.11:反查不到 srcUser。
		if magicNameDeniedByACL(t.Context(), gw, udpFrom("10.99.0.11"), name, suffix) {
			t.Error("反查不到查询方归属就拦 —— 登记稍晚一步的新会话会解析不出任何名字")
		}
	})

	t.Run("名字解析不出目标归属", func(t *testing.T) {
		withACLSnapshotFor(t, denyAllSnapshot())
		withVIPOwners(t, 1, 2, netip.MustParseAddr("10.99.0.12"))
		if magicNameDeniedByACL(t.Context(), gw, udpFrom("10.99.0.12"), "nosuch.nobody."+suffix, suffix) {
			t.Error("名字本身查不到归属时不该走 ACL 判定(该走后面的 NXDOMAIN 路径)")
		}
	})

	t.Run("peer 地址畸形", func(t *testing.T) {
		withACLSnapshotFor(t, denyAllSnapshot())
		if magicNameDeniedByACL(t.Context(), gw, &net.UDPAddr{}, name, suffix) {
			t.Error("拿不到 peer 地址就拦解析")
		}
	})

	t.Run("同用户自查照常放行", func(t *testing.T) {
		withACLSnapshotFor(t, denyAllSnapshot())
		u, err := gw.store.GetUserByUsername(t.Context(), "bob")
		if err != nil || u == nil {
			t.Fatalf("取 bob 失败: %v", err)
		}
		withVIPOwners(t, u.ID, 3, netip.MustParseAddr("10.99.0.20"))
		if magicNameDeniedByACL(t.Context(), gw, udpFrom("10.99.0.20"), name, suffix) {
			t.Error("default=deny 下连自己的设备名都解析不出来了 —— ACL 只该管跨用户")
		}
	})
}

// TestMagicNameDeniedByACL_BlocksTheProbeWhenTheACLReallySaysNo 该拦的时候必须拦住。
//
// 上面全是 fail-open,所以必须有这一条配对:ACL 真的判定跨用户完全不可达时,解析必须变 NXDOMAIN。
// 少了它,前面那些「拿不准就放行」的兜底就等于把整道闸拆了。
func TestMagicNameDeniedByACL_BlocksTheProbeWhenTheACLReallySaysNo(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "alice", "laptop", "10.98.0.10", "")
	seedDevice(t, gw.store, "bob", "phone", "10.98.0.20", "")
	const suffix = "ts.net"

	alice, err := gw.store.GetUserByUsername(t.Context(), "alice")
	if err != nil || alice == nil {
		t.Fatalf("取 alice 失败: %v", err)
	}
	withACLSnapshotFor(t, denyAllSnapshot())
	withVIPOwners(t, alice.ID, 7, netip.MustParseAddr("10.98.0.10"))

	if !magicNameDeniedByACL(t.Context(), gw, udpFrom("10.98.0.10"), "phone.bob."+suffix, suffix) {
		t.Error("ACL 判定完全不可达,却仍把对方设备名解析成 vIP —— " +
			"这就是一个探测对方存在性与地址的接口,数据面丢包也已经泄漏了")
	}
}

// TestMagicNameOwnerUserID_ResolvesBothNameShapesAndGivesUpQuietly 目标归属反查的两种名字形状。
//
// 它是上面那道 ACL 闸的输入。返回错的 user 比返回「查不到」危险得多:错成查询方自己就等于放行
// (泄漏),错成别人就等于把本该放行的名字拦掉(自己的设备名解析不出来)。
func TestMagicNameOwnerUserID_ResolvesBothNameShapesAndGivesUpQuietly(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "carol", "nas", "10.97.0.30", "")
	const suffix = "ts.net"
	ctx := t.Context()

	carol, err := gw.store.GetUserByUsername(ctx, "carol")
	if err != nil || carol == nil {
		t.Fatalf("取 carol 失败: %v", err)
	}

	t.Run("普通 host.user 名", func(t *testing.T) {
		got, ok := magicNameOwnerUserID(ctx, gw.store, "nas.carol."+suffix, suffix)
		if !ok || got != carol.ID {
			t.Fatalf("得到 (%d,%v),期望 (%d,true)", got, ok, carol.ID)
		}
	})

	t.Run("用户不存在", func(t *testing.T) {
		if _, ok := magicNameOwnerUserID(ctx, gw.store, "nas.nobody."+suffix, suffix); ok {
			t.Error("用户不存在却报出了归属 —— 上游会拿这个假 user 去做 ACL 判定")
		}
	})

	t.Run("名字形状不对", func(t *testing.T) {
		if _, ok := magicNameOwnerUserID(ctx, gw.store, "just-one-label", suffix); ok {
			t.Error("非法名字却报出了归属")
		}
	})

	t.Run("4via6 站点不存在", func(t *testing.T) {
		// 形状合法(<v4-dashed>via<siteID>)但 site 没登记过 → 只能安静放弃。
		if _, ok := magicNameOwnerUserID(ctx, gw.store, "192-168-1-10via7."+suffix, suffix); ok {
			t.Error("站点不存在却报出了归属")
		}
	})

	t.Run("store 为 nil", func(t *testing.T) {
		if _, ok := magicNameOwnerUserID(ctx, nil, "nas.carol."+suffix, suffix); ok {
			t.Error("没有 store 也报出归属 —— 这会让 ACL 判定基于凭空的 user")
		}
	})
}

// TestBuildMagicDNSAnswer_NeverPutsTheWrongFamilyInTheAnswer 按查询类型过滤地址族。
//
// 双栈设备的 lease 里两族地址都有,而一次查询只问一族。不过滤有两种坏法,都不小:
// A 查询里遇到 v6 地址会对它调 As4() —— **直接 panic**(与 alloc.go 那条同一族问题);
// AAAA 查询里塞进 v4-mapped 地址则会答出 ::ffff:10.x,客户端拿它发 v6 报文必然不通。
// 正确行为是跳过不匹配的那一族,答一个空 answer 的 NOERROR(客户端自会转查另一族)。
func TestBuildMagicDNSAnswer_NeverPutsTheWrongFamilyInTheAnswer(t *testing.T) {
	v4 := netip.MustParseAddr("10.96.0.5")
	v6 := netip.MustParseAddr("fd00:96::5")
	mapped := netip.MustParseAddr("::ffff:10.96.0.5")

	ask := func(t *testing.T, typ dnsmessage.Type, addrs []netip.Addr) []dnsmessage.Resource {
		t.Helper()
		q := dnsmessage.Question{
			Name:  dnsmessage.MustNewName("nas.carol.ts.net."),
			Type:  typ,
			Class: dnsmessage.ClassINET,
		}
		raw, err := buildMagicDNSAnswer(0x1234, q, addrs)
		if err != nil {
			t.Fatalf("构造应答失败: %v", err)
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(raw); err != nil {
			t.Fatalf("应答解不开: %v", err)
		}
		return msg.Answers
	}

	t.Run("A 查询只答 v4", func(t *testing.T) {
		ans := ask(t, dnsmessage.TypeA, []netip.Addr{v6, v4})
		if len(ans) != 1 {
			t.Fatalf("答了 %d 条,期望只有 v4 那一条", len(ans))
		}
		a, ok := ans[0].Body.(*dnsmessage.AResource)
		if !ok {
			t.Fatalf("答的不是 A 记录: %T", ans[0].Body)
		}
		if got := netip.AddrFrom4(a.A); got != v4 {
			t.Errorf("答出 %v,期望 %v", got, v4)
		}
	})

	t.Run("AAAA 查询只答 v6", func(t *testing.T) {
		ans := ask(t, dnsmessage.TypeAAAA, []netip.Addr{v4, mapped, v6})
		if len(ans) != 1 {
			t.Fatalf("答了 %d 条,期望只有 v6 那一条(v4 与 v4-mapped 都该跳过)", len(ans))
		}
		aaaa, ok := ans[0].Body.(*dnsmessage.AAAAResource)
		if !ok {
			t.Fatalf("答的不是 AAAA 记录: %T", ans[0].Body)
		}
		if got := netip.AddrFrom16(aaaa.AAAA); got != v6 {
			t.Errorf("答出 %v,期望 %v", got, v6)
		}
	})

	t.Run("A 查询遇到纯 v6 地址答空而不是崩", func(t *testing.T) {
		// 只有 v6 地址的设备被问 A:必须答空 answer 的 NOERROR,客户端随后转查 AAAA。
		// 少了那层过滤,这里就是 As4() panic —— 一次查询打掉整个 DNS goroutine。
		ans := ask(t, dnsmessage.TypeA, []netip.Addr{v6})
		if len(ans) != 0 {
			t.Errorf("答了 %d 条,期望空 answer", len(ans))
		}
	})

	t.Run("v4-mapped 按 v4 答出", func(t *testing.T) {
		// lease 里存的可能是 ::ffff: 形态,它语义上就是 v4,A 查询要认它并答成点分四段。
		ans := ask(t, dnsmessage.TypeA, []netip.Addr{mapped})
		if len(ans) != 1 {
			t.Fatalf("答了 %d 条,期望 1 条", len(ans))
		}
		a := ans[0].Body.(*dnsmessage.AResource)
		if got := netip.AddrFrom4(a.A); got != v4 {
			t.Errorf("答出 %v,期望 %v", got, v4)
		}
	})

	t.Run("空地址列表答空 answer", func(t *testing.T) {
		if ans := ask(t, dnsmessage.TypeAAAA, nil); len(ans) != 0 {
			t.Errorf("空地址列表却答了 %d 条", len(ans))
		}
	})
}
