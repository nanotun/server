package main

import (
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 规则裁决与源地址反欺骗的两处收口。
//
// evaluateUser 那侧钉的是「端口不可判定时按 deny 收敛」:分片报文 / 截断头链拿不到端口,如果
// 当成「不匹配」跳过,那么一条 `deny tcp:22` 就能被分片绕过 —— 攻击者只要把包分片,端口封锁形同
// 不存在。connSourceSpoofed 那侧钉的是它的**优先级顺序**:冒充另一在线会话的 vIP 必须一律拒,
// 哪怕本会话是已批准的出口 / 子网转发者(它们的合法回程源是外网 / 内网地址,不可能等于别人的 vIP)。

// denyPortRule 造一条「deny tcp 到某端口」的精确规则快照。
func denyPortRule(src, dst int64, port uint16) *aclSnapshot {
	return &aclSnapshot{
		hasUserRules: true,
		userExact: map[aclPair][]ruleEntry{
			{src: src, dst: dst}: {{
				action:   store.ACLDeny,
				proto:    "tcp",
				portLo:   port,
				portHi:   port,
				hasPorts: true,
			}},
		},
		defaultAction: store.ACLAllow,
		meshEnabled:   true,
	}
}

// mkV4Frag 造一个「非首片」的 IPv4 TCP 分片:fragment offset 非 0,所以拿不到端口。
func mkV4Frag(dst netip.Addr) []byte {
	p := mkV4Proto(dst, 6, 22)
	p[6] = 0x00
	p[7] = 0x10 // fragment offset != 0 → 非首片
	return p
}

// TestEvaluateUser_PortDenyIsNotBypassableByFragmentation 端口封锁不能被分片绕过。
//
// 一条 `deny tcp:22` 的意义就是 22 端口进不来。非首片分片里没有 TCP 头,拿不到端口 —— 此时若
// 判「规则不匹配」,包就落到 default=allow 被放行,而目的端会把分片重组出完整的 22 端口连接。
// 于是攻击者只要分片就能穿过封锁,而日志上什么都看不到。所以端口不可判定时对 deny 规则收敛为拒。
func TestEvaluateUser_PortDenyIsNotBypassableByFragmentation(t *testing.T) {
	const srcUser, dstUser = int64(31), int64(32)
	dst := netip.MustParseAddr("10.94.0.32")
	snap := denyPortRule(srcUser, dstUser, 22)

	t.Run("首片按端口正常裁决", func(t *testing.T) {
		tp, ok := parsePacketTuple(mkV4Proto(dst, 6, 22))
		if !ok {
			t.Fatal("解析失败")
		}
		if got := evaluateUser(snap, srcUser, dstUser, tp); got != store.ACLDeny {
			t.Fatalf("裁决 %q,期望 deny", got)
		}
	})

	t.Run("非首片分片也要拒", func(t *testing.T) {
		tp, ok := parsePacketTuple(mkV4Frag(dst))
		if !ok {
			t.Fatal("解析失败")
		}
		if tp.hasL4Ports {
			t.Fatal("前置条件不成立:非首片不该有端口")
		}
		if got := evaluateUser(snap, srcUser, dstUser, tp); got != store.ACLDeny {
			t.Errorf("裁决 %q,期望 deny —— 端口拿不到就放行的话,分片一下就能穿过 22 端口封锁", got)
		}
	})

	t.Run("端口不同的包照常放行", func(t *testing.T) {
		tp, _ := parsePacketTuple(mkV4Proto(dst, 6, 443))
		if got := evaluateUser(snap, srcUser, dstUser, tp); got != store.ACLAllow {
			t.Errorf("裁决 %q,期望 allow —— 只封了 22,别的端口不该受影响", got)
		}
	})

	t.Run("命中 allow 例外时不落 default", func(t *testing.T) {
		allowSnap := &aclSnapshot{
			hasUserRules:  true,
			userExact:     map[aclPair][]ruleEntry{{src: srcUser, dst: dstUser}: {{action: store.ACLAllow}}},
			defaultAction: store.ACLDeny,
			meshEnabled:   true,
		}
		tp, _ := parsePacketTuple(mkV4Proto(dst, 6, 443))
		if got := evaluateUser(allowSnap, srcUser, dstUser, tp); got != store.ACLAllow {
			t.Errorf("裁决 %q,期望 allow —— 白名单里的显式 allow 例外被 default=deny 吃掉了", got)
		}
	})
}

// TestACLDeniesSubnetRoute_FailsClosedOnMeshOffAndUnparsable 子网路由那侧的两条收敛。
//
// 子网路由是「把别人网段的流量交给某台设备转发」,天然跨用户。所以 mesh 总开关一关就整条拒 ——
// 它不是 ACL 白名单,是整网组网开关,配了什么 allow 都不该放行。解析不出的包同样拒(与 demux
// 那侧同口径)。反过来,自指与无上下文必须放行,否则同一用户自己的子网路由也不通了。
func TestACLDeniesSubnetRoute_FailsClosedOnMeshOffAndUnparsable(t *testing.T) {
	const srcUser, dstUser = int64(41), int64(42)
	pkt := mkV4Proto(netip.MustParseAddr("192.168.42.7"), 6, 443)

	t.Run("mesh 关掉时整条拒", func(t *testing.T) {
		withACLSnapshotFor(t, &aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: false})
		if !aclDeniesSubnetRoute(srcUser, dstUser, pkt) {
			t.Error("mesh 总开关关了仍放行子网路由 —— 那个开关的语义是整网锁死,不是 ACL 白名单")
		}
	})

	t.Run("解析不出的包拒", func(t *testing.T) {
		withACLSnapshotFor(t, &aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: true})
		if !aclDeniesSubnetRoute(srcUser, dstUser, []byte{0x45}) {
			t.Error("解析不出五元组的包被放行 —— 它绕过了整个裁决")
		}
	})

	t.Run("快照未装好时放行", func(t *testing.T) {
		withACLSnapshotFor(t, nil)
		if aclDeniesSubnetRoute(srcUser, dstUser, pkt) {
			t.Error("快照还没装好就拦 —— 启动那一下所有子网路由不通")
		}
	})

	t.Run("自指与无上下文放行", func(t *testing.T) {
		withACLSnapshotFor(t, &aclSnapshot{defaultAction: store.ACLDeny, meshEnabled: true})
		if aclDeniesSubnetRoute(srcUser, srcUser, pkt) {
			t.Error("同一用户自己的子网路由被白名单拦了")
		}
		if aclDeniesSubnetRoute(0, dstUser, pkt) || aclDeniesSubnetRoute(srcUser, 0, pkt) {
			t.Error("没有 user 上下文时按白名单拦了 —— 该交给后续闸门处理,不在这里误杀")
		}
	})

	t.Run("白名单语义:无规则也拒", func(t *testing.T) {
		withACLSnapshotFor(t, &aclSnapshot{defaultAction: store.ACLDeny, meshEnabled: true})
		if !aclDeniesSubnetRoute(srcUser, dstUser, pkt) {
			t.Error("default=deny 且无规则时放行了 —— 白名单模式没生效")
		}
	})
}

// TestConnSourceSpoofed_NeverLetsAnyoneBorrowAnotherSessionsVIP 冒充他人 vIP 一律拒。
//
// 这条的优先级高于「已批准出口 / 子网转发者豁免」,顺序写反就是一个可利用的漏洞:出口宣告方
// 本来被允许用任意非 vIP 源地址(它要中继外网回程),但如果豁免判在冒充判之前,它就能以**另一个
// VPN 客户端的 vIP** 作源注入伪造回包 —— 对受害者来说那些包看起来来自它信任的对端。
// 合法的出口 / LAN 回程源永远是外网 / 内网地址,不可能等于另一个客户端的 vIP,所以这条没有误伤。
func TestConnSourceSpoofed_NeverLetsAnyoneBorrowAnotherSessionsVIP(t *testing.T) {
	victim := netip.MustParseAddr("10.95.0.50")
	withVIPOwners(t, 50, 950, victim)

	newConn := func(ownVIP string, exitApproved, subnetApproved bool) *Connection {
		c := &Connection{userID: "u"}
		if ownVIP != "" {
			ips := []util.VirtualIPAssignment{{VirtualIP: ownVIP}}
			c.clientIPs.Store(&ips)
		}
		c.advertisedExitApproved.Store(exitApproved)
		c.advertisedSubnetApproved.Store(subnetApproved)
		return c
	}
	// 借用受害者 vIP 作源的包。
	spoof := func() []byte {
		p := mkV4Proto(netip.MustParseAddr("10.95.0.99"), 6, 443)
		s := victim.As4()
		copy(p[12:16], s[:])
		return p
	}

	for _, tc := range []struct {
		name                         string
		exitApproved, subnetApproved bool
	}{
		{"普通会话", false, false},
		{"已批准的出口转发者", true, false},
		{"已批准的子网转发者", false, true},
	} {
		t.Run(tc.name+"冒充他人 vIP", func(t *testing.T) {
			c := newConn("10.95.0.51", tc.exitApproved, tc.subnetApproved)
			if !connSourceSpoofed(c, spoof()) {
				t.Error("放过了以另一在线会话 vIP 作源的包 —— 可据此向受害者注入「来自可信对端」的伪造回包")
			}
		})
	}

	t.Run("自己的 vIP 作源合法", func(t *testing.T) {
		c := newConn("10.95.0.51", false, false)
		p := mkV4Proto(netip.MustParseAddr("10.95.0.99"), 6, 443)
		copy(p[12:16], []byte{10, 95, 0, 51})
		if connSourceSpoofed(c, p) {
			t.Error("会话用自己的 vIP 作源被判伪造 —— 那是最常见的正常流量")
		}
	})

	t.Run("已批准出口用外网源地址合法", func(t *testing.T) {
		// 出口中继回程的源是外网地址(不属于任何 vIP),必须放行,否则出口功能整个不通。
		c := newConn("10.95.0.51", true, false)
		p := mkV4Proto(netip.MustParseAddr("10.95.0.51"), 6, 443)
		copy(p[12:16], []byte{93, 184, 216, 34})
		if connSourceSpoofed(c, p) {
			t.Error("已批准出口用外网源地址被判伪造 —— 出口回程整个不通")
		}
	})

	t.Run("未批准的宣告方不享有豁免", func(t *testing.T) {
		// 只发过 advertise 帧、还没被 admin 批准的会话不能自我豁免,否则任何认证客户端
		// 发一帧就能绕过源地址校验。
		c := newConn("10.95.0.51", false, false)
		p := mkV4Proto(netip.MustParseAddr("10.95.0.99"), 6, 443)
		copy(p[12:16], []byte{93, 184, 216, 34})
		if !connSourceSpoofed(c, p) {
			t.Error("未批准的宣告方也能用任意源地址 —— 发一帧 RouteAdvertise 就绕过了 M2")
		}
	})

	t.Run("入口守卫", func(t *testing.T) {
		if connSourceSpoofed(nil, spoof()) {
			t.Error("nil 会话被判伪造")
		}
		if connSourceSpoofed(newConn("10.95.0.51", false, false), []byte{0x45}) {
			t.Error("解析不出的包在这一环被判伪造 —— 这一环只管源地址,畸形包交给 ACL 那侧 fail-closed")
		}
		if connSourceSpoofed(newConn("", false, false), spoof()) == false {
			t.Error("尚未持有任何 vIP 的会话冒充他人 vIP 仍该拒")
		}
	})
}
