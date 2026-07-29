package main

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
)

// demux 热路径上的两件事:把包头解成五元组,再据此裁决丢不丢。
//
// 这两步的坏法方向相反,所以要分别钉:
//   - 解析多认了(把畸形包当合法):后面的裁决基于错的 dst / port,可能把该丢的放过去;
//   - 解析少认了(把合法包判不可解析):按 fail-closed 一律丢,表现是「某类流量整个不通」。
// 裁决那侧同理:快照没装好时误丢 = 启动那几十毫秒全网不通;而 default=deny 白名单没生效 =
// 管理员以为配了白名单,实际全网互通照旧 —— 后者不报错、不掉包,只有翻规则才看得出来。

// mkV4Proto 造一个 IPv4 包:指定协议号与目的地址,可选带 L4 端口。
func mkV4Proto(dst netip.Addr, proto byte, dstPort uint16) []byte {
	p := make([]byte, 24)
	p[0] = 0x45 // version 4, IHL 5
	p[9] = proto
	d := dst.As4()
	copy(p[16:20], d[:])
	if dstPort != 0 {
		binary.BigEndian.PutUint16(p[22:24], dstPort)
	}
	return p
}

// TestParsePacketTuple_RejectsAHeaderLengthItCannotTrust IHL 越界必须判不可解析。
//
// IHL 是攻击面:它决定从哪个偏移读 L4 端口。信了一个大于报文长度的 IHL,后面读端口就是越界
// (panic 或读到垃圾);信了小于 20 的 IHL,则会把 IP 头自身的字节当成端口来匹配 ACL。这里
// 判不可解析,调用方按 fail-closed 丢掉 —— 这类包已经过了 ValidIPPacket,正常流量里不该出现。
func TestParsePacketTuple_RejectsAHeaderLengthItCannotTrust(t *testing.T) {
	base := mkV4Proto(netip.MustParseAddr("10.90.0.9"), 6, 443)

	t.Run("IHL 小于 20 字节", func(t *testing.T) {
		p := append([]byte(nil), base...)
		p[0] = 0x44 // IHL=4 → 16 字节,比最小 IP 头还短
		if _, ok := parsePacketTuple(p); ok {
			t.Error("IHL < 20 却当成合法包 —— 后面会把 IP 头自身的字节当端口去匹配 ACL")
		}
	})

	t.Run("IHL 超出报文长度", func(t *testing.T) {
		p := append([]byte(nil), base...)
		p[0] = 0x4f // IHL=15 → 60 字节,而报文只有 24
		if _, ok := parsePacketTuple(p); ok {
			t.Error("IHL 超出报文长度却当成合法包 —— 按它去读端口就是越界读")
		}
	})

	t.Run("IHL 正好等于报文长度", func(t *testing.T) {
		// 边界:头部占满整个报文(没有 L4 载荷)。这是合法的,只是没有端口可读。
		p := make([]byte, 24)
		p[0] = 0x46 // IHL=6 → 24 字节
		p[9] = 6
		copy(p[16:20], []byte{10, 90, 0, 9})
		tp, ok := parsePacketTuple(p)
		if !ok {
			t.Fatal("头部占满报文是合法的,不该判不可解析")
		}
		if tp.hasL4Ports {
			t.Error("没有 L4 载荷却报告有端口 —— 那个端口值来自越界或填充字节")
		}
	})
}

// TestParsePacketTuple_ClassifiesICMPSoThatICMPRulesCanMatch ICMP 必须被分类出来。
//
// 认不出 proto 的包,任何带 proto 维度的规则都匹配不上 —— 于是 `icmp deny` 规则形同不存在,
// ping 照通(而管理员在界面上看到规则明明在那儿)。v4 的 icmp 与 v6 的 icmpv6 是两个协议号,
// 要分别认。
func TestParsePacketTuple_ClassifiesICMPSoThatICMPRulesCanMatch(t *testing.T) {
	t.Run("IPv4 ICMP", func(t *testing.T) {
		tp, ok := parsePacketTuple(mkV4Proto(netip.MustParseAddr("10.90.0.9"), 1, 0))
		if !ok {
			t.Fatal("ICMP 包判不可解析")
		}
		if tp.proto != "icmp" {
			t.Errorf("proto=%q,期望 icmp —— 认不出来的话 icmp deny 规则匹配不上,ping 照通", tp.proto)
		}
		if tp.hasL4Ports {
			t.Error("ICMP 没有端口概念,却报告有端口")
		}
	})

	t.Run("IPv6 ICMPv6", func(t *testing.T) {
		p := mkIPv6(netip.MustParseAddr("fd00:90::1"), netip.MustParseAddr("fd00:90::2"))
		p[6] = 58 // next header = ICMPv6
		tp, ok := parsePacketTuple(p)
		if !ok {
			t.Fatal("ICMPv6 包判不可解析")
		}
		if tp.proto != "icmpv6" {
			t.Errorf("proto=%q,期望 icmpv6", tp.proto)
		}
		if tp.l4Unresolved {
			t.Error("ICMPv6 是确定的上层分类,不该标成 L4 不可判 —— 那会让端口维度的裁决 fail-closed")
		}
	})
}

// TestACLDropDirected_DefaultDenyStillAppliesWithoutAnyUserRules 白名单语义:没有规则也要拒。
//
// 这是最容易写反的一处。整段裁决有个 fast-path:user 规则集为空时跳过引擎 —— 但**跳过引擎不等于
// 放行**。default=deny 的语义是白名单(只有显式 allow 才通),规则集为空就意味着「谁都不在白名单里」,
// 必须全丢。写反的后果是静默的:管理员切到白名单模式、还没来得及加 allow 例外,以为已经全锁了,
// 实际全网互通照旧,而任何界面上都看不出来。
func TestACLDropDirected_DefaultDenyStillAppliesWithoutAnyUserRules(t *testing.T) {
	const srcUser, dstUser = int64(11), int64(22)
	dst := netip.MustParseAddr("10.91.0.22")
	pkt := mkV4Proto(dst, 6, 443)
	withVIPOwners(t, dstUser, 91, dst)

	t.Run("default=deny 全丢", func(t *testing.T) {
		withACLSnapshotFor(t, &aclSnapshot{defaultAction: store.ACLDeny, meshEnabled: true})
		if !aclDropPacketDirected(srcUser, pkt) {
			t.Error("default=deny 且无任何 user 规则时放行了跨用户流量 —— " +
				"管理员以为切到白名单已经全锁,实际全网互通照旧")
		}
	})

	t.Run("default=allow 放行", func(t *testing.T) {
		withACLSnapshotFor(t, &aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: true})
		if aclDropPacketDirected(srcUser, pkt) {
			t.Error("default=allow 且无规则却丢包 —— 默认配置下整个 mesh 不通")
		}
	})

	t.Run("同用户内部不受 default 影响", func(t *testing.T) {
		withACLSnapshotFor(t, &aclSnapshot{defaultAction: store.ACLDeny, meshEnabled: true})
		if aclDropPacketDirected(dstUser, pkt) {
			t.Error("白名单模式把同一用户自己两台设备之间也拦了 —— user ACL 只该管跨用户")
		}
	})
}

// TestACLDropDirected_FailsOpenBeforeTheSnapshotIsLoaded 快照没装好时放行。
//
// 启动早期(以及 reload 的极短窗口)快照可能还是 nil。这时候丢包等于「服务刚起来那一下全网不通」,
// 而 ACL 的目的是长期约束,不是保护这几十毫秒。所以这里唯一正确的选择是放行。
func TestACLDropDirected_FailsOpenBeforeTheSnapshotIsLoaded(t *testing.T) {
	dst := netip.MustParseAddr("10.92.0.22")
	withVIPOwners(t, 22, 92, dst)
	withACLSnapshotFor(t, nil)

	if aclDropPacketDirected(11, mkV4Proto(dst, 6, 443)) {
		t.Error("ACL 快照还没装好就开始丢包 —— 服务刚起来那一下全网不通")
	}
}

// TestACLDropDirected_DropsPacketsItCannotParse 解析不出的包 fail-closed。
//
// 与上面那条 fail-open 方向相反,值得一起看:快照缺失是「我们自己还没准备好」,放行;而包解析不出
// 是「这个包本身可疑」—— 它已经过了 readLoop 的 ValidIPPacket,还解不出五元组说明是畸形的,
// 放过去就等于让一个绕过了裁决的包进入 mesh。丢,并且要记一条 unparsable 便于排障。
func TestACLDropDirected_DropsPacketsItCannotParse(t *testing.T) {
	withACLSnapshotFor(t, &aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: true})

	before := aclDropCount.Load()
	if !aclDropPacketDirected(11, []byte{0x45}) { // 只有一个字节,解不出任何东西
		t.Error("解析不出五元组的包被放过去了 —— 它绕过了整个裁决")
	}
	if aclDropCount.Load() == before {
		t.Error("丢了却没计数 —— /status 上看不出在丢包,排障时无从下手")
	}
}

// TestACLDropDirected_SkipsEnforcementWithoutAUserContext 无 user 上下文时不裁决。
//
// srcUserID==0 表示调用方没能确定这个包属于谁(异常路径 / 内部路径)。此时按 user 维度裁决没有
// 意义:拿 0 去比对规则会命中「src=*」类规则,把内部流量按跨用户规则误丢。
func TestACLDropDirected_SkipsEnforcementWithoutAUserContext(t *testing.T) {
	dst := netip.MustParseAddr("10.93.0.22")
	withVIPOwners(t, 22, 93, dst)
	withACLSnapshotFor(t, &aclSnapshot{defaultAction: store.ACLDeny, meshEnabled: true})

	if aclDropPacketDirected(0, mkV4Proto(dst, 6, 443)) {
		t.Error("没有 user 上下文也按白名单丢了 —— 内部路径的流量会被按跨用户规则误伤")
	}
}
