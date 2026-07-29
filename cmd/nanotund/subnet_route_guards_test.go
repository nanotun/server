package main

import (
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 子网路由的两类闸门。
//
// 一、**载入时的过滤**。转发表是从 DB 里 approved 的行重建出来的,但「approved」不等于「可转发」:
//     批准动作发生在过去,而校验规则会变严。历史上批准过的公网 / 宽段 CIDR 若照收,就绕过了出口闸
//     和出口 ACL(confused deputy:让 server 拿自己的公网出口去替客户端访问任意地址);与本机 mesh
//     网段交叠的 CIDR 若照收,发往「当前离线的 mesh 地址」的包会被中继进对端 LAN(跨信任域泄漏)。
//     两者都不报错、`route list` 里也照样显示 approved —— 只能靠转发表里没有它来判断。
//
// 二、**表未加载时的方向**。这几个判据在启动瞬间与 reload 窗口里会读到空表,此时「不属于」和
//     「暂时不知道」无法区分,于是每一处都必须显式选一个方向,而且方向不能选反:
//       - 投递门控(deviceApprovedForDst)fail-closed → 表没建好就不投,宁可少送一个包;
//       - 反源欺骗里的 4via6 收窄(via6SrcOwnedByConn)fail-open → 表没建好就不收窄,否则启动
//         瞬间会把合法回程全杀掉。
//     选反的后果一正一反:前者反了是撤销审批后 FRP 仍能打进 LAN,后者反了是每次 reload 抖一下
//     就断一批连接。这两个方向此前一条断言都没有。

// TestRebuild_SkipsPublicPrefixesThatWouldBypassTheExitGate 第十一轮那条 MED 的回归。
//
// 写路径(NormalizeAdvertisedCIDR)只管新宣告,不回溯存量;所以「旧代码期批准过的公网段」或
// 「绕过 CLI 直写 DB 的行」只能在载入时挡。挡不住的话,那条路由会让请求方经由宣告方访问公网 ——
// 既绕过出口节点的选路,也绕过出口 ACL。
func TestRebuild_SkipsPublicPrefixesThatWouldBypassTheExitGate(t *testing.T) {
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })
	prevTbl := subnetRouteTable.Load()
	prevVia6 := via6SiteTable.Load()
	t.Cleanup(func() { subnetRouteTable.Store(prevTbl); via6SiteTable.Store(prevVia6) })
	setServerGatewayAddrs("10.201.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })

	_, deviceID := mustCreateUserAndDevice(t, gw, "eve")

	// 直写 DB 绕过归一:这正是本闸要兜的那条路(历史批准 / 手工 SQL)。
	for _, cidr := range []string{"1.1.1.0/24", "0.0.0.0/1", "192.168.9.0/24"} {
		if _, err := gw.store.DB().ExecContext(t.Context(),
			`INSERT INTO subnet_routes(device_id, cidr, status, advertised_at, approved_at)
			 VALUES(?,?,?,strftime('%s','now'),strftime('%s','now'))`,
			deviceID, cidr, util.RouteStatusApproved); err != nil {
			t.Fatalf("直写 %s: %v", cidr, err)
		}
	}

	rebuildSubnetRouteTable(t.Context())

	for _, addr := range []string{"1.1.1.1", "8.8.8.8"} {
		if dev, ok := lookupSubnetRoute(netip.MustParseAddr(addr)); ok {
			t.Errorf("公网地址 %s 命中了子网路由(device=%d)—— 这条路径绕开出口闸与出口 ACL", addr, dev)
		}
	}
	// 同批的私有段必须照常生效:否则这个闸门就成了「一条坏数据废掉整张表」。
	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("192.168.9.5")); !ok || dev != deviceID {
		t.Fatalf("同批的私有段应生效,got (%d,%v)", dev, ok)
	}
}

// TestRebuild_SkipsExitDefaultRoutesAndUnparsableRows 载入时的另两类跳过。
//
// 0/0 与 ::/0 是出口节点特例,由出口路径处理;把它们收进子网路由表会让**任何**目的地址都命中
// 最短前缀匹配 —— 客户端的全部公网流量都被中继给这台宣告方,而它并没有被批准做出口。
func TestRebuild_SkipsExitDefaultRoutesAndUnparsableRows(t *testing.T) {
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })
	prevTbl := subnetRouteTable.Load()
	prevVia6 := via6SiteTable.Load()
	t.Cleanup(func() { subnetRouteTable.Store(prevTbl); via6SiteTable.Store(prevVia6) })
	setServerGatewayAddrs("10.201.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })

	_, deviceID := mustCreateUserAndDevice(t, gw, "frank")
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "不是-CIDR", "192.168.11.0/24"} {
		if _, err := gw.store.DB().ExecContext(t.Context(),
			`INSERT INTO subnet_routes(device_id, cidr, status, advertised_at, approved_at)
			 VALUES(?,?,?,strftime('%s','now'),strftime('%s','now'))`,
			deviceID, cidr, util.RouteStatusApproved); err != nil {
			t.Fatalf("直写 %s: %v", cidr, err)
		}
	}

	rebuildSubnetRouteTable(t.Context())

	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("203.0.113.9")); ok {
		t.Errorf("0/0 被收进子网路由表 —— 任意公网目的都会被中继给 device=%d", dev)
	}
	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("2001:db8::1")); ok {
		t.Errorf("::/0 被收进子网路由表(device=%d)", dev)
	}
	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("192.168.11.5")); !ok || dev != deviceID {
		t.Fatalf("坏数据不该带走同批的好路由,got (%d,%v)", dev, ok)
	}
}

// TestRebuild_KeepsTheOldTableWhenTheDBIsUnreadable 读不到 DB 时保留旧表。
//
// 重建失败若把表清空,等于把**已经在用的**内网路由全部黑洞掉:所有子网流量瞬间不可达,而原因
// 只是一次 DB 抖动。保留旧表是「陈旧但可用」,清空是「立刻全断」。
func TestRebuild_KeepsTheOldTableWhenTheDBIsUnreadable(t *testing.T) {
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })
	prevTbl := subnetRouteTable.Load()
	prevVia6 := via6SiteTable.Load()
	t.Cleanup(func() { subnetRouteTable.Store(prevTbl); via6SiteTable.Store(prevVia6) })
	setServerGatewayAddrs("10.201.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })

	_, deviceID := mustCreateUserAndDevice(t, gw, "grace")
	if _, err := gw.store.UpsertAdvertisedRoute(t.Context(), deviceID, "192.168.13.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := gw.store.SetRouteStatus(t.Context(), deviceID, "192.168.13.0/24", store.RouteStatusApproved, ""); err != nil {
		t.Fatal(err)
	}
	rebuildSubnetRouteTable(t.Context())
	if _, ok := lookupSubnetRoute(netip.MustParseAddr("192.168.13.5")); !ok {
		t.Fatal("前置条件:这条路由应先生效")
	}

	// 把表藏起来 → 重建时 DB 读失败。
	if _, err := gw.store.DB().ExecContext(t.Context(),
		`ALTER TABLE subnet_routes RENAME TO subnet_routes_gone`); err != nil {
		t.Fatalf("藏表: %v", err)
	}
	rebuildSubnetRouteTable(t.Context())

	if dev, ok := lookupSubnetRoute(netip.MustParseAddr("192.168.13.5")); !ok || dev != deviceID {
		t.Fatal("DB 读不动时把转发表清空了 —— 一次数据库抖动会让所有内网路由同时黑洞")
	}
}

// TestApprovalGates_FailClosedWhenTheTableIsNotLoaded 投递侧的判据在表未加载时必须一律 false。
//
// 这三个函数都是「dst 是否在某设备已批准网段内」的读侧,调用点分别是 FRP 自发包的审批门控、
// 4via6 生成前的可达性校验、和反源欺骗。表没建好时返回 true 就等于短暂地对所有目的地址开门。
func TestApprovalGates_FailClosedWhenTheTableIsNotLoaded(t *testing.T) {
	prev := subnetRouteTable.Load()
	subnetRouteTable.Store(nil)
	t.Cleanup(func() { subnetRouteTable.Store(prev) })

	v4 := netip.MustParseAddr("192.168.20.5")
	if deviceApprovedForDst(7, v4) {
		t.Error("表未加载时 deviceApprovedForDst 必须回 false —— 它是 FRP 打进 LAN 前的唯一审批闸")
	}
	if deviceAdvertisesV4(7, v4) {
		t.Error("表未加载时 deviceAdvertisesV4 必须回 false")
	}
	if deviceApprovedPrefixContains(7, v4) {
		t.Error("表未加载时 deviceApprovedPrefixContains 必须回 false")
	}
	// deviceID==0(调用方还不知道对面是哪台设备)一律 false:0 不是任何设备,匹配上就等于
	// 给「不知道是谁」放行。这里故意在表里放一条 device_id=0 的项 —— 正常 DB 有外键约束
	// 造不出它,但这个函数接受的是任意一张表,而「未知设备撞上一条零值行」正是它要挡的形状。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.20.0/24", 0)})
	if deviceApprovedPrefixContains(0, v4) {
		t.Error("deviceID=0 不该匹配任何网段,哪怕表里真有一条零值行")
	}

	// 有表但不含该设备 → 仍是 false;这条排除「恒回 false」的实现。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.20.0/24", 7)})
	if !deviceApprovedForDst(7, v4) {
		t.Error("装了表之后正主必须匹配上")
	}
	if deviceApprovedForDst(8, v4) {
		t.Error("别的设备不该匹配上别人的网段")
	}
	if deviceAdvertisesV4(7, netip.MustParseAddr("192.168.99.1")) {
		t.Error("网段外的地址不该匹配")
	}
}

// TestDeviceAdvertisesV4_IgnoresV6Prefixes 4via6 只嵌 v4,所以这个判据必须只看 v4 前缀。
// 拿 v6 前缀去 Contains 一个 v4 地址恒 false,看着无害;但反过来若把 v6 段也算进来,
// MagicDNS 会为「该设备其实到不了的 v4」生成 4via6 地址 —— 用户解析出来却连不上。
func TestDeviceAdvertisesV4_IgnoresV6Prefixes(t *testing.T) {
	setSubnetRouteTableForTest(t, []subnetRouteEntry{
		mkEntry("fd00:beef::/48", 11),
		mkEntry("192.168.30.0/24", 11),
	})
	if deviceAdvertisesV4(11, netip.MustParseAddr("192.168.30.9")) != true {
		t.Error("v4 段内的地址应命中")
	}
	if deviceAdvertisesV4(11, netip.MustParseAddr("192.168.31.9")) {
		t.Error("v4 段外的地址不该命中")
	}
}

// TestVia6SrcOwnedByConn_FailsOpenOnlyWhileTheTablesAreCold 4via6 反源欺骗的收窄方向。
//
// 这是唯一一处**故意 fail-open** 的:表没就绪时不收窄。收窄了会在每次 reload 窗口里误杀合法
// 4via6 回程(请求方连的就是 4via6 地址,回包源地址必然是它)。但表一旦就绪,判据必须收紧到
// 「自己的 site + 自己已批准的网段」—— 否则一个宣告方可以拿别人 site 的地址冒充另一个站点的
// 内网主机,或拿自己 pending/已撤销网段的地址向 mesh 对端注包。
func TestVia6SrcOwnedByConn_FailsOpenOnlyWhileTheTablesAreCold(t *testing.T) {
	const myDev, otherDev int64 = 21, 22
	const mySite, otherSite uint16 = 1, 2
	v4 := netip.MustParseAddr("192.168.40.7")
	src := mk4via6Addr(t, mySite, v4)

	c := &Connection{deviceID: myDev, connIDStr: "adv"}

	t.Run("会话没有 device 时不放行", func(t *testing.T) {
		setVia6SiteTableForTest(t, map[uint16]int64{mySite: myDev})
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.40.0/24", myDev)})
		if via6SrcOwnedByConn(nil, src) {
			t.Error("nil 会话不该被认作源的主人")
		}
		if via6SrcOwnedByConn(&Connection{}, src) {
			t.Error("deviceID=0 的会话不该被认作源的主人")
		}
	})

	t.Run("源不是 4via6 地址时不归它管", func(t *testing.T) {
		setVia6SiteTableForTest(t, map[uint16]int64{mySite: myDev})
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.40.0/24", myDev)})
		if via6SrcOwnedByConn(c, netip.MustParseAddr("fd00::1")) {
			t.Error("非 4via6 的源不该从这条路径拿到放行")
		}
	})

	t.Run("表还没就绪时放行(不误杀合法回程)", func(t *testing.T) {
		prevSite := via6SiteTable.Load()
		prevTbl := subnetRouteTable.Load()
		via6SiteTable.Store(nil)
		subnetRouteTable.Store(nil)
		t.Cleanup(func() { via6SiteTable.Store(prevSite); subnetRouteTable.Store(prevTbl) })
		if !via6SrcOwnedByConn(c, src) {
			t.Error("表未就绪时必须放行 —— 收窄会在每次 reload 窗口里断掉一批 4via6 回程")
		}
	})

	t.Run("表就绪后按 site + 已批准网段收紧", func(t *testing.T) {
		setVia6SiteTableForTest(t, map[uint16]int64{mySite: myDev, otherSite: otherDev})
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.40.0/24", myDev)})

		if !via6SrcOwnedByConn(c, src) {
			t.Error("自己 site、自己已批准网段的源必须放行")
		}
		// 别人的 site:冒充另一个站点的内网主机。
		if via6SrcOwnedByConn(c, mk4via6Addr(t, otherSite, v4)) {
			t.Error("拿别人 site 的地址当源必须被拒 —— 那是冒充另一个站点")
		}
		// 未知 site。
		if via6SrcOwnedByConn(c, mk4via6Addr(t, 250, v4)) {
			t.Error("未知 site 的源必须被拒")
		}
		// 自己 site,但内嵌 v4 不在已批准网段内(pending / 已撤销)。
		if via6SrcOwnedByConn(c, mk4via6Addr(t, mySite, netip.MustParseAddr("192.168.41.7"))) {
			t.Error("内嵌 v4 不在已批准网段内必须被拒 —— 否则多报几条网段就能拿它们当源注包")
		}
	})
}

// mk4via6Addr 造一个 4via6 地址(siteID + 内嵌 v4),复用数据面自己的编码器,避免测试与实现
// 各写一份编码而悄悄对不上。
func mk4via6Addr(t *testing.T, siteID uint16, v4 netip.Addr) netip.Addr {
	t.Helper()
	pkt := mkVia6(siteID, v4)
	tup, ok := parsePacketTuple(pkt)
	if !ok {
		t.Fatalf("构造 4via6 包失败")
	}
	return tup.dst
}

// TestDeliverServerOriginatedToDevice_RefusesEverythingItCannotVouchFor server 自发 LAN 包的三道闸。
//
// 这条路径的来源是 FRP:公网端口上的外部流量,由 server 自己发起投递。它与客户端来包路径共用
// 审批口径,靠的就是这里读 always-current 的转发表 —— 精确表(frpTargetTable)只在 portforward
// reload 时构建、且不校验审批,所以撤销审批后能不能立刻挡住,全看这道闸。
func TestDeliverServerOriginatedToDevice_RefusesEverythingItCannotVouchFor(t *testing.T) {
	const devID int64 = 31
	dst := netip.MustParseAddr("192.168.50.9")
	payload := mkIPv4(dst)

	t.Run("未批准的目的:不投", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.50.0/24", devID)})
		addAdvertiserConn(t, devID, "adv-approved", "10.0.0.31")
		before := subnetRouteDroppedNotApproved.Load()
		if deliverServerOriginatedToDevice(devID, netip.MustParseAddr("192.168.99.9"), payload) {
			t.Error("目的不在已批准网段内还投出去了 —— 撤销审批后 FRP 仍能打进 LAN 就是这么来的")
		}
		if subnetRouteDroppedNotApproved.Load() != before+1 {
			t.Error("应记 subnetRouteDroppedNotApproved")
		}
	})

	t.Run("宣告方离线:不投,也不改投别人", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.50.0/24", devID)})
		before := subnetRouteDroppedOffline.Load()
		if deliverServerOriginatedToDevice(devID, dst, payload) {
			t.Error("宣告方不在线时不该投递")
		}
		if subnetRouteDroppedOffline.Load() != before+1 {
			t.Error("应记 subnetRouteDroppedOffline")
		}
	})

	t.Run("包太大:不投", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.50.0/24", devID)})
		addAdvertiserConn(t, devID, "adv-oversize", "10.0.0.31")
		before := subnetRouteDroppedOversize.Load()
		if deliverServerOriginatedToDevice(devID, dst, mkIPv4Sized(dst, tunBufSize+1)) {
			t.Error("超过 TUN 缓冲的包不该投递")
		}
		if subnetRouteDroppedOversize.Load() != before+1 {
			t.Error("应记 subnetRouteDroppedOversize")
		}
	})

	t.Run("会话当前已不宣告该网段:不投", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.50.0/24", devID)})
		// 会话仍在线,但它当前宣告的是另一段(收窄过) → 未 NAT 的包不该漏进它的 LAN。
		addAdvertiserConnWithRoutes(t, devID, "adv-narrowed", "10.0.0.31", []string{"192.168.60.0/24"})
		before := subnetRouteDroppedNotAdvertised.Load()
		if deliverServerOriginatedToDevice(devID, dst, payload) {
			t.Error("会话已收窄掉该网段,不该再往它投")
		}
		if subnetRouteDroppedNotAdvertised.Load() != before+1 {
			t.Error("应记 subnetRouteDroppedNotAdvertised")
		}
	})

	// 反面对照:三闸全过必须真的投出去,否则上面全部可以由「永远返回 false」满足。
	t.Run("三闸都过:投出去并计数", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.50.0/24", devID)})
		ch := addAdvertiserConn(t, devID, "adv-ok", "10.0.0.31")
		before := subnetRouteForwarded.Load()
		if !deliverServerOriginatedToDevice(devID, dst, payload) {
			t.Fatal("三闸都过时必须投递")
		}
		select {
		case pkt := <-ch:
			if pkt.N != len(payload) {
				t.Errorf("投出去的包长度不对: %d", pkt.N)
			}
		default:
			t.Fatal("包没进宣告方的 TunChan")
		}
		if subnetRouteForwarded.Load() != before+1 {
			t.Error("应记 subnetRouteForwarded")
		}
	})
}

// TestForwardServerOriginatedToSubnet_NoRouteMeansNoDelivery 没有匹配路由时不投递 ——
// 绝不能回退成「从 server 自己的公网出口发出去」:那会把一个本该进内网的包泄漏到公网。
func TestForwardServerOriginatedToSubnet_NoRouteMeansNoDelivery(t *testing.T) {
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.70.0/24", 41)})
	if forwardServerOriginatedToSubnet(netip.MustParseAddr("192.168.99.9"),
		mkIPv4(netip.MustParseAddr("192.168.99.9"))) {
		t.Error("无匹配路由时不该回报已投递")
	}
}
