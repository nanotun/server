package main

import (
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// setSubnetRouteTableForTest 直接装一份子网路由表快照,并在用例结束后还原,隔离全局态。
func setSubnetRouteTableForTest(t *testing.T, entries []subnetRouteEntry) {
	t.Helper()
	prev := subnetRouteTable.Load()
	subnetRouteTable.Store(&entries)
	t.Cleanup(func() { subnetRouteTable.Store(prev) })
}

// mkEntry 造一条 subnetRouteEntry(prefix 取归一形态)。
func mkEntry(cidr string, deviceID int64) subnetRouteEntry {
	return subnetRouteEntry{prefix: netip.MustParsePrefix(cidr).Masked(), deviceID: deviceID}
}

// addAdvertiserConn 造一条「在线宣告方会话」(deviceID + TunChan)并加入 by-device 索引,返回其 TunChan。
func addAdvertiserConn(t *testing.T, deviceID int64, connID, vip string) chan *util.TunPacket {
	return addAdvertiserConnU(t, deviceID, connID, vip, "")
}

// addAdvertiserConnU 同 addAdvertiserConn,但带 userID(SR-M4 ACL 用例需宣告方 user 才能裁决「请求方×宣告方」)。
// 置 advertisedSubnetRoutes=true:模拟「真在跑子网路由器(已发 advertise、装了 NAT)」的会话——
// forwardPacketToSubnetRoute 只投给这类会话(SR-M4 深扫)。
func addAdvertiserConnU(t *testing.T, deviceID int64, connID, vip, userID string) chan *util.TunPacket {
	t.Helper()
	ch := make(chan *util.TunPacket, 4)
	c := &Connection{deviceID: deviceID, connIDStr: connID, userID: userID}
	c.advertisedSubnetRoutes.Store(true)
	ips := []util.VirtualIPAssignment{{VirtualIP: vip, TunChan: ch}}
	c.clientIPs.Store(&ips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(c)
	connIDMapMu.Unlock()
	return ch
}

// withACLForTest 装一份 ACL 快照并在用例结束还原,隔离全局 aclCurrent。
func withACLForTest(t *testing.T, load func()) {
	t.Helper()
	prev := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(prev) })
	load()
}

// 最长前缀匹配:更具体的 /24 应盖过 /8;无覆盖返回 false。
func TestLookupSubnetRoute_LongestPrefixWins(t *testing.T) {
	setSubnetRouteTableForTest(t, []subnetRouteEntry{
		mkEntry("10.0.0.0/8", 1),
		mkEntry("10.1.2.0/24", 2),
	})

	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("10.1.2.5")); !ok || dev != 2 {
		t.Fatalf("10.1.2.5 应命中最长前缀 /24(dev=2),得到 dev=%d ok=%v", dev, ok)
	}
	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("10.9.9.9")); !ok || dev != 1 {
		t.Fatalf("10.9.9.9 应命中 /8(dev=1),得到 dev=%d ok=%v", dev, ok)
	}
	if _, ok := lookupSubnetRoute(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("8.8.8.8 无覆盖路由应返回 ok=false")
	}
}

// 深扫#14:同一 CIDR 被误批给两台设备时,LPM 同长度 tiebreak 取**最小 deviceID**(确定性),不受切片/DB 行序影响。
// 正常部署无重复 CIDR;本用例钉死误配下的可预期性(两种插入序都选最小 deviceID)。
func TestLookupSubnetRoute_DuplicateCIDRDeterministic(t *testing.T) {
	// 大 deviceID 在前、小在后。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{
		mkEntry("192.168.1.0/24", 9),
		mkEntry("192.168.1.0/24", 3),
	})
	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("192.168.1.5")); !ok || dev != 3 {
		t.Fatalf("重复 CIDR 应确定性取最小 deviceID=3,得到 dev=%d ok=%v", dev, ok)
	}
	// 反序(小在前、大在后)结果应一致。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{
		mkEntry("192.168.1.0/24", 3),
		mkEntry("192.168.1.0/24", 9),
	})
	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("192.168.1.5")); !ok || dev != 3 {
		t.Fatalf("反序下重复 CIDR 仍应取最小 deviceID=3,得到 dev=%d ok=%v", dev, ok)
	}
}

// v4 dst 不应命中 v6 路由(地址族隔离,netip.Prefix.Contains 天然处理)。
func TestLookupSubnetRoute_FamilyIsolation(t *testing.T) {
	setSubnetRouteTableForTest(t, []subnetRouteEntry{
		mkEntry("2001:db8::/32", 5),
	})
	if _, ok := lookupSubnetRoute(netip.MustParseAddr("192.168.1.5")); ok {
		t.Fatal("v4 dst 不应命中 v6 路由")
	}
	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("2001:db8::1")); !ok || dev != 5 {
		t.Fatalf("v6 dst 应命中 v6 路由(dev=5),得到 dev=%d ok=%v", dev, ok)
	}
}

// 命中已批准网段 + 宣告方在线 → 投递到宣告方 TunChan,返回 true,计数自增。
func TestForwardPacketToSubnetRoute_OnlineDelivers(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)})
	tunCh := addAdvertiserConn(t, 77, "adv1", "10.0.0.9")

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	before := subnetRouteForwarded.Load()
	beforeBytes := subnetRouteForwardedBytes.Load()

	pkt := mkIPv4(netip.MustParseAddr("192.168.1.5")) // 宣告方背后的内网 IP(非 vIP)
	if !forwardPacketToSubnetRoute(a, pkt) {
		t.Fatal("命中已批准网段 + 宣告方在线应返回 true(已由子网路由路径处理)")
	}
	select {
	case got := <-tunCh:
		if got == nil || got.N != len(pkt) {
			t.Fatalf("投递到宣告方 TunChan 的包异常: %+v", got)
		}
	default:
		t.Fatal("包未投递到宣告方会话 TunChan")
	}
	if subnetRouteForwarded.Load() != before+1 {
		t.Fatal("subnetRouteForwarded 计数未自增")
	}
	if subnetRouteForwardedBytes.Load() != beforeBytes+uint64(len(pkt)) {
		t.Fatal("subnetRouteForwardedBytes 未按包长自增")
	}
}

// dst 不命中任何已批准网段 → 返回 false(交回出口 / server 原链路)。
func TestForwardPacketToSubnetRoute_NoMatch(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)})
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	if forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("8.8.8.8"))) {
		t.Fatal("无匹配子网路由应返回 false(走原链路)")
	}
}

// 命中网段但宣告方离线 → 丢弃(返回 true,不回退 server),droppedOffline 自增。
func TestForwardPacketToSubnetRoute_OfflineDrops(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 88)}) // 88 无在线会话
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	before := subnetRouteDroppedOffline.Load()
	if !forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("宣告方离线应返回 true(丢弃,不把内网包回退 server 误发公网)")
	}
	if subnetRouteDroppedOffline.Load() != before+1 {
		t.Fatal("subnetRouteDroppedOffline 计数未自增")
	}
}

// SR-M4 深扫:宣告方设备**在线但本次未 --advertise-routes**(advertisedSubnetRoutes=false，如历史 approved 某网段却以普通
// 客户端连入,没装 subnet NAT)→ 按「无 NAT-ready 宣告方」丢弃,**绝不**投给它(否则未 NAT 的 mesh vIP 包漏进其 LAN +
// 无回程黑洞)。droppedOffline 自增,不投递。
func TestForwardPacketToSubnetRoute_ConnectedButNotAdvertising(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)})
	// 造一条在线会话但**不**置 advertisedSubnetRoutes(普通客户端连入,没跑 --advertise-routes)。
	ch := make(chan *util.TunPacket, 4)
	c := &Connection{deviceID: 77, connIDStr: "plain", userID: "u2"} // advertisedSubnetRoutes 默认 false
	ips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: ch}}
	c.clientIPs.Store(&ips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(c)
	connIDMapMu.Unlock()

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	before := subnetRouteDroppedOffline.Load()
	if !forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("宣告方在线但未跑子网路由器应返回 true(按无 NAT-ready 丢弃,不回退 server)")
	}
	if subnetRouteDroppedOffline.Load() != before+1 {
		t.Fatal("connected-but-not-advertising 应计入 subnetRouteDroppedOffline")
	}
	select {
	case <-ch:
		t.Fatal("未跑子网路由器的会话绝不应收到转发包(否则未 NAT 漏进其 LAN + 黑洞)")
	default:
	}
}

// 第 7 轮深扫(per-CIDR 门控):宣告方**当前只宣告** 192.168.1.0/24,但 DB 里 10.8.0.0/24 的批准仍在(设备收窄了宣告、
// 陈旧批准未清)。发往 10.8.0.5 → 宣告方在跑(布尔真)但当前不宣告该网段 → 丢弃(droppedNotAdvertised),绝不投递(否则
// 未 NAT 漏进其 LAN / 黑洞);发往仍在宣告集内的 192.168.1.5 → 正常投递(回归保护:门控不误伤集内流量)。
func TestForwardPacketToSubnetRoute_NotCurrentlyAdvertisedDrops(t *testing.T) {
	resetConnByDeviceForTest(t)
	// 两条网段都在**已批准**表里、都指向 device 77。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{
		mkEntry("192.168.1.0/24", 77),
		mkEntry("10.8.0.0/24", 77),
	})
	tunCh := addAdvertiserConn(t, 77, "adv1", "10.0.0.9")
	// 宣告方**当前只宣告** 192.168.1.0/24(收窄,去掉了 10.8.0.0/24)。
	adv := lookupSubnetAdvertiserConnByDevice(77)
	if adv == nil {
		t.Fatal("测试前置:应能取到在跑宣告方会话")
	}
	pfxs := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	adv.advertisedRoutes.Store(&pfxs)

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}

	// 发往当前不再宣告的 10.8.0.5 → 丢弃 + droppedNotAdvertised 自增,不投递。
	before := subnetRouteDroppedNotAdvertised.Load()
	if !forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("10.8.0.5"))) {
		t.Fatal("命中已批准但当前不宣告的网段应返回 true(按 not-advertised 丢弃)")
	}
	if subnetRouteDroppedNotAdvertised.Load() != before+1 {
		t.Fatal("subnetRouteDroppedNotAdvertised 计数未自增")
	}
	select {
	case <-tunCh:
		t.Fatal("当前不宣告的网段绝不应投递到宣告方 TunChan(否则未 NAT 漏进其 LAN)")
	default:
	}

	// 发往仍在宣告集内的 192.168.1.5 → 正常投递。
	if !forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("仍在宣告集内的网段应正常投递(返回 true)")
	}
	select {
	case <-tunCh:
	default:
		t.Fatal("宣告集内的网段应投递到宣告方 TunChan")
	}
}

// 目的是某 vIP(mesh 流量)→ 返回 false,即便该 vIP 落在某条子网路由内(vIP 优先于子网路由)。
func TestForwardPacketToSubnetRoute_MeshVIPWins(t *testing.T) {
	resetConnByDeviceForTest(t)
	// 故意让子网路由覆盖该 vIP 地址,验证 vIP 优先。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("10.7.0.0/16", 77)})
	addAdvertiserConn(t, 77, "adv1", "10.0.0.9")
	peerVIP := netip.MustParseAddr("10.7.7.7")
	registerVIPOwners([]netip.Addr{peerVIP}, 999, 1)
	t.Cleanup(func() { unregisterVIPOwners([]netip.Addr{peerVIP}, 1) })

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	if forwardPacketToSubnetRoute(a, mkIPv4(peerVIP)) {
		t.Fatal("目的为 vIP 的 mesh 流量应返回 false(vIP 优先于子网路由,走原 mesh demux)")
	}
}

// 自指:宣告方访问自己宣告的网段 → 返回 false(本机直达,无需中转)。
func TestForwardPacketToSubnetRoute_SelfNotForwarded(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 11)})
	addAdvertiserConn(t, 11, "self", "10.0.0.9")
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11} // 与宣告方同 device
	if forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("宣告方访问自己宣告的网段应返回 false(本机直达,不经 server 中转)")
	}
}

// SR-M4:ACL 拒绝「请求方 user × 宣告方 user」→ 子网路由丢弃(不投递),droppedACL 自增。
// 语义:访问某宣告方背后的子网 == 能否与该宣告方 user 私有互通,故 u1→u2 deny 同时挡 u1 访问 u2 宣告的子网。
func TestForwardPacketToSubnetRoute_ACLDenyDrops(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)})
	tunCh := addAdvertiserConnU(t, 77, "adv1", "10.0.0.9", "u2") // 宣告方 user=2
	withACLForTest(t, func() {
		loadACLForTest([]*store.ACLPair{
			{SrcUserID: 1, DstUserID: 2, Action: store.ACLDeny, DstKind: store.ACLDstKindUser},
		}, store.ACLAllow)
	})

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	before := subnetRouteDroppedACL.Load()
	if !forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("ACL 拒绝应返回 true(已由子网路由路径丢弃)")
	}
	if subnetRouteDroppedACL.Load() != before+1 {
		t.Fatal("subnetRouteDroppedACL 计数未自增")
	}
	select {
	case <-tunCh:
		t.Fatal("ACL 拒绝的包不应投递到宣告方 TunChan")
	default:
	}
}

// SR-M4:ACL 允许(默认 allow、无规则)→ 正常投递(回归保护:ACL 接入不误伤放行流量)。
func TestForwardPacketToSubnetRoute_ACLAllowDelivers(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)})
	tunCh := addAdvertiserConnU(t, 77, "adv1", "10.0.0.9", "u2")
	withACLForTest(t, func() { loadACLForTest(nil, store.ACLAllow) })

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	if !forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("ACL 允许应返回 true 并投递")
	}
	select {
	case <-tunCh:
	default:
		t.Fatal("ACL 允许的包应投递到宣告方 TunChan")
	}
}

// SR-M4:mesh 总开关关 → 子网路由(跨用户私有连通)一并拒(admin 关组网即整网锁死)。
func TestForwardPacketToSubnetRoute_MeshOffDrops(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)})
	tunCh := addAdvertiserConnU(t, 77, "adv1", "10.0.0.9", "u2")
	withACLForTest(t, func() { loadACLWithMesh(nil, store.ACLAllow, false) })

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	before := subnetRouteDroppedACL.Load()
	if !forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("mesh off 应丢弃(返回 true)")
	}
	if subnetRouteDroppedACL.Load() != before+1 {
		t.Fatal("mesh off 应计入 subnetRouteDroppedACL")
	}
	select {
	case <-tunCh:
		t.Fatal("mesh off 的包不应投递")
	default:
	}
}

// SR-M4:宣告方无 userID(user=0,如测试/兜底场景)→ ACL 放行(与 aclDropPacketDirected src==0 口径一致),不误伤。
func TestForwardPacketToSubnetRoute_NoUserAllows(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)})
	tunCh := addAdvertiserConn(t, 77, "adv1", "10.0.0.9") // 宣告方无 userID
	withACLForTest(t, func() {
		// 即便存在 deny 规则,dstUser=0 也应放行(无合法 user 上下文不裁决)。
		loadACLForTest([]*store.ACLPair{
			{SrcUserID: 1, DstUserID: 2, Action: store.ACLDeny, DstKind: store.ACLDstKindUser},
		}, store.ACLAllow)
	})

	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	if !forwardPacketToSubnetRoute(a, mkIPv4(netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("宣告方无 user 应放行投递(返回 true)")
	}
	select {
	case <-tunCh:
	default:
		t.Fatal("宣告方无 user 时包应正常投递")
	}
}

// ————————————————————— SR-VIA6：4via6 数据面 —————————————————————

// setVia6SiteTableForTest 装一份 siteID→deviceID 快照并在用例结束还原,隔离全局态。
func setVia6SiteTableForTest(t *testing.T, m map[uint16]int64) {
	t.Helper()
	prev := via6SiteTable.Load()
	via6SiteTable.Store(&m)
	t.Cleanup(func() { via6SiteTable.Store(prev) })
}

// mkVia6 造一个最小 IPv6 TCP 包,dst = encode4via6(siteID, v4)。与 mkIPv4 对称(无 L4 载荷,dstPort=0)。
func mkVia6(siteID uint16, v4 netip.Addr) []byte {
	addr, ok := encode4via6(siteID, v4)
	if !ok {
		panic("mkVia6: bad v4")
	}
	p := make([]byte, 40)
	p[0] = 0x60 // version 6
	p[6] = 6    // Next Header = TCP
	d := addr.As16()
	copy(p[24:40], d[:])
	return p
}

// addAdvertiserConnWithRoutes 造在线宣告方会话并设其当前宣告的 v4 CIDR 集(per-CIDR 门控用)。
func addAdvertiserConnWithRoutes(t *testing.T, deviceID int64, connID, vip string, cidrs []string) chan *util.TunPacket {
	t.Helper()
	ch := make(chan *util.TunPacket, 4)
	c := &Connection{deviceID: deviceID, connIDStr: connID}
	c.advertisedSubnetRoutes.Store(true)
	pfxs := make([]netip.Prefix, 0, len(cidrs))
	for _, s := range cidrs {
		pfxs = append(pfxs, netip.MustParsePrefix(s).Masked())
	}
	c.advertisedRoutes.Store(&pfxs)
	ips := []util.VirtualIPAssignment{{VirtualIP: vip, TunChan: ch}}
	c.clientIPs.Store(&ips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(c)
	connIDMapMu.Unlock()
	return ch
}

// 4via6 命中 siteID + 宣告方在线 → 投**原样 v6 包**给宣告方 TunChan,forwarded++。
func TestForwardPacketToSubnetRoute_Via6OnlineDelivers(t *testing.T) {
	resetConnByDeviceForTest(t)
	setVia6SiteTableForTest(t, map[uint16]int64{7: 77})
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)}) // 管理员已批准 device 77 的 192.168.1.0/24（数据面 4via6 审批门控前提）
	tunCh := addAdvertiserConn(t, 77, "adv1", "10.0.0.9")
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	before := subnetRouteForwarded.Load()
	pkt := mkVia6(7, netip.MustParseAddr("192.168.1.5"))
	if !forwardPacketToSubnetRoute(a, pkt) {
		t.Fatal("4via6 命中 siteID + 宣告方在线应返回 true")
	}
	select {
	case got := <-tunCh:
		if got == nil || got.N != len(pkt) {
			t.Fatalf("投递到宣告方的 4via6 v6 包异常: %+v", got)
		}
	default:
		t.Fatal("4via6 包未投递到宣告方 TunChan")
	}
	if subnetRouteForwarded.Load() != before+1 {
		t.Fatal("subnetRouteForwarded 未自增")
	}
}

// 4via6 的 siteID 未知(陈旧/未分配站点)→ 丢弃(DroppedNoSite++,返回 true,不回退 server 误发公网)。
func TestForwardPacketToSubnetRoute_Via6UnknownSiteDrops(t *testing.T) {
	resetConnByDeviceForTest(t)
	setVia6SiteTableForTest(t, map[uint16]int64{7: 77}) // 只登记 site 7
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	before := subnetRouteDroppedNoSite.Load()
	if !forwardPacketToSubnetRoute(a, mkVia6(999, netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("未知 siteID 应返回 true(丢弃,不回退 server)")
	}
	if subnetRouteDroppedNoSite.Load() != before+1 {
		t.Fatal("subnetRouteDroppedNoSite 未自增")
	}
}

// siteID 有映射但宣告方离线 → 丢弃(DroppedOffline++)。
func TestForwardPacketToSubnetRoute_Via6OfflineDrops(t *testing.T) {
	resetConnByDeviceForTest(t)
	setVia6SiteTableForTest(t, map[uint16]int64{7: 88})                              // 88 无在线会话
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 88)}) // 已批准（先过审批门控，才测到离线丢弃）
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	before := subnetRouteDroppedOffline.Load()
	if !forwardPacketToSubnetRoute(a, mkVia6(7, netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("宣告方离线应返回 true(丢弃)")
	}
	if subnetRouteDroppedOffline.Load() != before+1 {
		t.Fatal("subnetRouteDroppedOffline 未自增")
	}
}

// 消歧核心:两站点宣告同一 v4,靠不同 siteID 路由到不同宣告方设备。
func TestForwardPacketToSubnetRoute_Via6Disambiguation(t *testing.T) {
	resetConnByDeviceForTest(t)
	setVia6SiteTableForTest(t, map[uint16]int64{1: 101, 2: 102})
	// 两站点设备均**已批准**该网段（数据面 4via6 审批门控前提）。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 101), mkEntry("192.168.1.0/24", 102)})
	ch1 := addAdvertiserConn(t, 101, "advA", "10.0.0.1")
	ch2 := addAdvertiserConn(t, 102, "advB", "10.0.0.2")
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}
	v4 := netip.MustParseAddr("192.168.1.5") // 两站点相同的内网 IP

	if !forwardPacketToSubnetRoute(a, mkVia6(1, v4)) {
		t.Fatal("site1 应投递")
	}
	if !forwardPacketToSubnetRoute(a, mkVia6(2, v4)) {
		t.Fatal("site2 应投递")
	}
	if len(ch1) != 1 || len(ch2) != 1 {
		t.Fatalf("同 v4 不同 site 应各投给对应设备: ch1=%d ch2=%d", len(ch1), len(ch2))
	}
}

// per-CIDR **会话**门控用**解出的 v4** 判断:两段均**已批准**(过审批门控)、但会话当前只宣告 192.168.1.0/24(收窄去掉
// 10.0.0.0/24)时,4via6(site,192.168.1.5) 投递;4via6(site,10.0.0.5)(已批准但会话不再宣告)→ DroppedNotAdvertised。
func TestForwardPacketToSubnetRoute_Via6PerCIDRGate(t *testing.T) {
	resetConnByDeviceForTest(t)
	setVia6SiteTableForTest(t, map[uint16]int64{5: 55})
	// 两段都**已批准**(先过数据面审批门控 deviceAdvertisesV4),但会话当前只宣告 192.168.1.0/24(收窄) —— 专测会话 per-CIDR 门控。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 55), mkEntry("10.0.0.0/24", 55)})
	addAdvertiserConnWithRoutes(t, 55, "adv1", "10.0.0.9", []string{"192.168.1.0/24"})
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}

	if !forwardPacketToSubnetRoute(a, mkVia6(5, netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("解出的 v4 已批准且在会话宣告集内应投递")
	}
	beforeNA := subnetRouteDroppedNotAdvertised.Load()
	if !forwardPacketToSubnetRoute(a, mkVia6(5, netip.MustParseAddr("10.0.0.5"))) {
		t.Fatal("解出的 v4 已批准但会话已收窄不再宣告应返回 true(按 not-advertised 丢弃)")
	}
	if subnetRouteDroppedNotAdvertised.Load() != beforeNA+1 {
		t.Fatal("subnetRouteDroppedNotAdvertised 未自增(会话收窄 per-CIDR 门控未生效)")
	}
}

// SR-VIA6 安全（审批必须在数据面强制）：解出的 v4 不在宣告方**管理员已批准**网段 → DroppedNotApproved。防 authenticated
// peer 构造裸 fdbc:4a60::<site>:<任意v4> 越权 relay 到「自宣告但未批准」网段 / SSRF。与 per-CIDR 会话门控区分（后者是
// 「已批准但会话收窄」）；此处 10.0.0.0/24 **未批准**(不在 subnetRouteTable)，即便会话宣告了也应在审批门控被拦下。
func TestForwardPacketToSubnetRoute_Via6ApprovalGate(t *testing.T) {
	resetConnByDeviceForTest(t)
	setVia6SiteTableForTest(t, map[uint16]int64{5: 55})
	// device 55 仅**已批准** 192.168.1.0/24；会话却宣告了 10.0.0.0/24(自宣告未过审批)——审批门控应拦下 10.0.0.5。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 55)})
	addAdvertiserConnWithRoutes(t, 55, "adv1", "10.0.0.9", []string{"192.168.1.0/24", "10.0.0.0/24"})
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}

	before := subnetRouteDroppedNotApproved.Load()
	if !forwardPacketToSubnetRoute(a, mkVia6(5, netip.MustParseAddr("10.0.0.5"))) {
		t.Fatal("未获管理员批准的 v4 应返回 true(丢弃,不回退 server)")
	}
	if subnetRouteDroppedNotApproved.Load() != before+1 {
		t.Fatal("subnetRouteDroppedNotApproved 未自增(数据面 4via6 审批门控未生效)")
	}
	// 对照：已批准的 192.168.1.5 应正常投递(不计 NotApproved)。
	if !forwardPacketToSubnetRoute(a, mkVia6(5, netip.MustParseAddr("192.168.1.5"))) {
		t.Fatal("已批准的 v4 应投递")
	}
	if subnetRouteDroppedNotApproved.Load() != before+1 {
		t.Fatal("已批准的 v4 不应计入 NotApproved")
	}
}

// 端到端(s1-routeslist):approve 某子网 → rebuildSubnetRouteTable 应给宣告方分配 siteID、建 via6SiteTable,
// 且 buildRoutesList 把该条的 SiteID 填成分配值。覆盖「approve→分配→下发」整链。
func TestVia6_RebuildAssignsSiteIDAndBuildFillsIt(t *testing.T) {
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })
	// rebuild 直接 Store 全局表,测试后还原,避免污染其它用例。
	prevTbl := subnetRouteTable.Load()
	prevVia6 := via6SiteTable.Load()
	t.Cleanup(func() { subnetRouteTable.Store(prevTbl); via6SiteTable.Store(prevVia6) })

	_, deviceID := mustCreateUserAndDevice(t, gw, "carol")
	if _, err := gw.store.UpsertAdvertisedRoute(t.Context(), deviceID, "192.168.1.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := gw.store.SetRouteStatus(t.Context(), deviceID, "192.168.1.0/24", store.RouteStatusApproved, ""); err != nil {
		t.Fatal(err)
	}

	rebuildSubnetRouteTable(t.Context())

	// rebuild 应已分配 siteID(幂等查询取回),且 via6SiteTable 能反查回该 device。
	sid, err := gw.store.GetOrAssignSiteID(t.Context(), deviceID)
	if err != nil {
		t.Fatalf("GetOrAssignSiteID: %v", err)
	}
	if sid == 0 {
		t.Fatal("rebuild 后 approved 宣告方应已分配非 0 siteID")
	}
	if dev, ok := lookupVia6Site(sid); !ok || dev != deviceID {
		t.Fatalf("lookupVia6Site(%d) = (%d,%v), 期望 (%d,true)", sid, dev, ok, deviceID)
	}

	// buildRoutesList 应含该网段且 SiteID = 分配值。
	list := buildRoutesList(t.Context())
	found := false
	for _, r := range list {
		if r.CIDR == "192.168.1.0/24" {
			found = true
			if r.SiteID != sid {
				t.Fatalf("buildRoutesList SiteID = %d, 期望 %d", r.SiteID, sid)
			}
		}
	}
	if !found {
		t.Fatal("buildRoutesList 应含 192.168.1.0/24")
	}
}
