package main

import (
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/store"
)

// MagicDNS 上的三道「解析口径对齐数据面」的闸(mesh 总开关 / 用户 ACL / isolate)都是**信息面**对齐,
// 不是安全边界 —— 硬闸是 FORWARD 上的 DROP。所以它们统一 fail-open:拿不准就不拦。
//
// 这一组钉的是「拿不准」的几种具体形状。搞反方向的代价很具体:把 fail-open 写成 fail-closed,
// server 本机自查、会话清理竞态窗口、库抖一下,都会变成「合法的名字突然 NXDOMAIN」——
// 而 DNS 的否定结果会被客户端 stub resolver 缓存,故障比实际窗口活得久。

// TestMagicNameGates_FailOpenWhenTheQuerierAddressIsUnusable:查询方地址取不出来时三道闸全部放行。
//
// 什么时候会取不出来:server 本机自查(经环回发的查询)、测试注入、以及 UDPAddr.IP 长度既非 4 也非 16
// 的畸形形状。这几种都不该被当成「有人在探别人的设备」。
func TestMagicNameGates_FailOpenWhenTheQuerierAddressIsUnusable(t *testing.T) {
	// 把两道总开关都置成「最想拦」的状态,这样一旦 fail-open 缺失就会立刻变色。
	prevIso := clientIsolateMode.Load()
	clientIsolateMode.Store(true)
	t.Cleanup(func() { clientIsolateMode.Store(prevIso) })

	prevSnap := aclCurrent.Load()
	meshOff := &aclSnapshot{meshEnabled: false}
	aclCurrent.Store(meshOff)
	t.Cleanup(func() { aclCurrent.Store(prevSnap) })

	other := netip.MustParseAddr("10.201.0.31")
	const otherConn = uint32(4242)
	registerVIPOwners([]netip.Addr{other}, 7, otherConn)
	t.Cleanup(func() { unregisterVIPOwners([]netip.Addr{other}, otherConn) })

	gw := newTestGatewayForUserInvalidate(t)

	peers := []struct {
		name string
		addr *net.UDPAddr
	}{
		{"peer 为 nil", nil},
		{"peer 没有 IP", &net.UDPAddr{Port: 5353}},
		{"peer 的 IP 长度畸形", &net.UDPAddr{IP: net.IP{10, 201, 0}, Port: 5353}},
	}
	for _, p := range peers {
		t.Run(p.name, func(t *testing.T) {
			if magicNameDeniedByMeshOff(t.Context(), gw, p.addr, "desktop.bob.lan", "lan") {
				t.Error("mesh 总开关闸应 fail-open —— 拦下来会让 server 本机自查也 NXDOMAIN")
			}
			if magicNameDeniedByACL(t.Context(), gw, p.addr, "desktop.bob.lan", "lan") {
				t.Error("ACL 闸应 fail-open")
			}
			if magicNameDeniedByIsolate(p.addr, []netip.Addr{other}) {
				t.Error("isolate 闸应 fail-open")
			}
			// 上游转发的 TTL 早期钳制同理:认不出查询方属于哪条会话就不钳(维持上游原 TTL)。
			if magicDNSInEarlyClampWindow(p.addr) {
				t.Error("认不出会话时不该判定落在早期钳制窗口内")
			}
		})
	}
}

// TestRunMagicDNSLoop_DropsInsteadOfBlockingWhenTheInFlightPoolIsFull:in-flight 池打满时,
// 读循环必须**当场丢包并继续读**,不能阻塞在占坑上。
//
// 阻塞的后果比丢包严重得多:持续灌包的攻击者能把 ReadFromUDP 的内核接收队列堵满 → 丢包发生在
// 内核里,server 侧一条日志一个计数都没有,排障时什么都看不见。就地丢包则至少留下计数,
// 而客户端的 stub resolver 本来就会自然超时重试。也正因为如此,这里**不**回 SERVFAIL ——
// 回一个错误码会让客户端立刻放弃这个上游。
func TestRunMagicDNSLoop_DropsInsteadOfBlockingWhenTheInFlightPoolIsFull(t *testing.T) {
	withTestGlobalContext(t)
	port := freeUDPPort(t)
	gw := magicDNSGatewayOn(t, port)
	seedDevice(t, gw.store, "alice", "laptop", "100.64.0.7", "")
	withACLSnapshotForTest(t, meshOnAllowAll())

	cleanup := startMagicDNS(gw, "127.0.0.1")
	t.Cleanup(cleanup)

	cli, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	query := buildDNSQuery(t, "laptop.alice.lan", dnsmessage.TypeA)

	// 先确认这条链路本来是能答的,否则下面「没收到应答」的断言会因为别的原因通过。
	if _, err := cli.Write(query); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := cli.Read(make([]byte, 1500)); err != nil {
		t.Fatalf("前置条件:正常情况下应答得上来,got %v", err)
	}

	// 占满全局 in-flight 池。
	var held []func()
	t.Cleanup(func() {
		for _, rel := range held {
			rel()
		}
	})
	for {
		release, ok := tryAcquireMagicDNSSlot(netip.MustParseAddr("10.201.0.123"), false)
		if !ok {
			break
		}
		held = append(held, release)
		if len(held) > 4096 {
			t.Fatal("in-flight 池似乎没有上限,占不满")
		}
	}

	// 池满期间发的这一条用一个专属 txn id,好在后面认出「它是被丢了,还是被排队later 补答」。
	const droppedID, freshID uint16 = 0xd0d0, 0x0f0f
	before := magicDNSInflightDropCount.Load()
	if _, err := cli.Write(buildDNSQueryID(t, "laptop.alice.lan", dnsmessage.TypeA, droppedID)); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if n, rerr := cli.Read(make([]byte, 1500)); rerr == nil {
		t.Fatalf("池满时不该有任何应答(包括 SERVFAIL),却收到 %d 字节", n)
	}
	if got := magicDNSInflightDropCount.Load(); got <= before {
		t.Errorf("丢包必须记数(否则间歇性丢查询查不到),计数仍是 %d", got)
	}

	// 放掉所有位。此时读循环必须已经把那条查询**丢掉**了 —— 如果它是阻塞等位(而不是丢包),
	// 这会儿就会补答上来,而客户端早已超时重试,这个迟到的应答落在一个没人等的端口上。
	for _, rel := range held {
		rel()
	}
	held = nil

	// 再发一条新查询(不同 txn id)。收到的第一个应答必须是**新**那条 —— 排队补答的实现会先吐旧的。
	if _, err := cli.Write(buildDNSQueryID(t, "laptop.alice.lan", dnsmessage.TypeA, freshID)); err != nil {
		t.Fatal(err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("腾出位置后应立刻恢复作答 —— 读循环疑似卡死: %v", err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(buf[:n])
	if err != nil {
		t.Fatalf("应答不是合法 DNS 报文: %v", err)
	}
	if hdr.ID == droppedID {
		t.Fatal("池满时那条查询被排队later 补答了 —— 它应当就地丢弃(阻塞等位会让攻击者把内核接收队列堵满)")
	}
	if hdr.ID != freshID {
		t.Fatalf("应答的 txn id = %#x,want %#x", hdr.ID, freshID)
	}
}

// TestMagicNameOwnerUserID_OrphanSiteMappingHasNoOwner:4via6 站点映射指向一台已不存在的设备时
// (老库删设备没连带清、手工改过库),必须报「查不出归属」→ 闸放行,而不是把 user 0 当答案。
//
// 把 0 当答案的后果:mesh OFF 时 `dstUser(0) != srcUser` 恒成立 → 这个名字被判成「别人的」,
// 连宣告方自己查自己的站点名都会 NXDOMAIN。
func TestMagicNameOwnerUserID_OrphanSiteMappingHasNoOwner(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "orphan_site.db"), store.Options{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// 造一条孤儿站点映射:site_id 存在,device_id 指向不存在的设备。外键平时会拦住这种写入,
	// 关掉它是为了复现「库里已经有这种行」的既成状态(旧版本删设备时没连带清)。
	if _, err := st.DB().ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatalf("关外键: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO via6_sites(site_id, device_id, created_at) VALUES(31, 999777, 0)`); err != nil {
		t.Fatalf("插孤儿站点: %v", err)
	}

	if _, ok := magicNameOwnerUserID(ctx, st, "192-168-88-7via31.lan", "lan"); ok {
		t.Fatal("站点映射指向不存在的设备时,不该报出一个归属 user")
	}

	// 落到闸上:查不出归属 → 放行(交给正常路径回 NXDOMAIN/NODATA,而不是被闸判成别人的名字)。
	prevSnap := aclCurrent.Load()
	aclCurrent.Store(&aclSnapshot{meshEnabled: false})
	t.Cleanup(func() { aclCurrent.Store(prevSnap) })

	asker := netip.MustParseAddr("10.201.0.44")
	const askerConn = uint32(515)
	registerVIPOwners([]netip.Addr{asker}, 9, askerConn)
	t.Cleanup(func() { unregisterVIPOwners([]netip.Addr{asker}, askerConn) })
	peer := &net.UDPAddr{IP: asker.AsSlice(), Port: 5353}

	gw := &gatewayState{store: st}
	if magicNameDeniedByMeshOff(ctx, gw, peer, "192-168-88-7via31.lan", "lan") {
		t.Error("归属查不出来时 mesh 闸应放行")
	}
}

// TestLookupMagicHost_ADamagedDeviceTableResolvesToNothingNotToSomethingWrong:设备表读不动时
// (迁移中途 / 库损坏),解析必须整条失败,而不是拿着空设备集往下走。
//
// 往下走的形状是「查不到设备 → NXDOMAIN」,与本函数返回 false 表面一样;区别在于 mesh 闸随后
// 拿这个 false 决定**不拦**(拿不准不拦),而不是把库故障翻译成「这个名字属于别人」。
func TestLookupMagicHost_ADamagedDeviceTableResolvesToNothingNotToSomethingWrong(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "broken_devices.db"), store.Options{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "bob", PSKHash: "h"}); err != nil {
		t.Fatal(err)
	}
	// 用户表还好、设备表读不动:这是「迁移跑了一半」最典型的形状。
	if _, err := st.DB().ExecContext(ctx, `DROP TABLE devices`); err != nil {
		t.Fatalf("drop devices: %v", err)
	}

	if addrs, ok := lookupMagicHost(ctx, st, "bob", "desktop"); ok || len(addrs) != 0 {
		t.Fatalf("设备表读不动时应报解析失败,got addrs=%v ok=%v", addrs, ok)
	}
	if _, ok := magicNameOwnerUserID(ctx, st, "desktop.bob.lan", "lan"); !ok {
		// 归属只查 users 表,设备表坏了不影响它 —— 这条断言防的是「把两件事耦在一起」。
		t.Error("普通 host.user 名的归属只依赖 users 表,不该被设备表故障带下水")
	}
}

// TestMagicHostExists_IsolateAlsoHidesSitesFromNonAddressQueries:非 A/AAAA 查询(MX/TXT/SRV…)走
// 「主机存在→NODATA / 不存在→NXDOMAIN」的本地作答。isolate 下这条路径也必须拒答别人的 4via6 站点名 ——
// 否则 A/AAAA 被拦住了,换个 qtype 照样能把「这台设备/这个站点存在」探出来。
func TestMagicHostExists_IsolateAlsoHidesSitesFromNonAddressQueries(t *testing.T) {
	ctx := t.Context()
	gw, siteID, advertiserVIP := via6SiteFixtureForGuards(t)

	name := "192-168-88-7via" + strconv.Itoa(int(siteID)) + ".lan"

	prevIso := clientIsolateMode.Load()
	t.Cleanup(func() { clientIsolateMode.Store(prevIso) })

	// 先确认这个站点名在 mesh 模式下确实解析得到(否则下面的断言是空过的)。
	clientIsolateMode.Store(false)
	if !magicHostExists(ctx, gw, nil, name, "lan") {
		t.Fatalf("站点名 %s 在 mesh 下应解析得到 —— 否则本用例的 isolate 断言毫无意义", name)
	}

	// 查询方是另一台客户端(不是宣告方自己)。
	asker := netip.MustParseAddr("10.201.0.66")
	const askerConn, advConn = uint32(701), uint32(702)
	registerVIPOwners([]netip.Addr{asker}, 5, askerConn)
	registerVIPOwners([]netip.Addr{advertiserVIP}, 6, advConn)
	t.Cleanup(func() {
		unregisterVIPOwners([]netip.Addr{asker}, askerConn)
		unregisterVIPOwners([]netip.Addr{advertiserVIP}, advConn)
	})
	peer := &net.UDPAddr{IP: asker.AsSlice(), Port: 5353}

	clientIsolateMode.Store(true)
	if magicHostExists(ctx, gw, peer, name, "lan") {
		t.Error("isolate 下别人的 4via6 站点名连「存在与否」也不该答 —— 换个 qtype 就能绕过 A/AAAA 那道闸")
	}
	// peer 为 nil(server 本机自查)时跳过 isolate 判定,照常作答。
	if !magicHostExists(ctx, gw, nil, name, "lan") {
		t.Error("peer 为 nil 时应跳过 isolate 判定")
	}
}

// via6SiteFixtureForGuards 造一台「已批准宣告 192.168.88.0/24、已分配 4via6 站点」的宣告方设备,
// 返回可用的 gatewayState、站点 ID 与宣告方 vIP。
func via6SiteFixtureForGuards(t *testing.T) (*gatewayState, uint16, netip.Addr) {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "via6_guard.db"), store.Options{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	user, err := st.CreateUser(ctx, store.NewUser{Username: "router", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := st.UpsertDevice(ctx, user.ID, "cccccccc-3333-4333-8333-cccccccccccc", "lan-router", "linux")
	if err != nil {
		t.Fatal(err)
	}
	const cidr = "192.168.88.0/24"
	if _, err := st.UpsertAdvertisedRoute(ctx, dev.ID, cidr); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRouteStatus(ctx, dev.ID, cidr, "approved", ""); err != nil {
		t.Fatal(err)
	}
	siteID, err := st.GetOrAssignSiteID(ctx, dev.ID)
	if err != nil {
		t.Fatalf("assign site id: %v", err)
	}
	// 「已批准宣告集」在数据面是一张内存表(admin 改路由后经 reload 重建),解析路径查的是它 ——
	// 不装的话 deviceAdvertisesV4 恒 false,4via6 名压根解析不出来,后面的断言就都是空过。
	prev := subnetRouteTable.Load()
	tbl := []subnetRouteEntry{{prefix: netip.MustParsePrefix(cidr), deviceID: dev.ID}}
	subnetRouteTable.Store(&tbl)
	t.Cleanup(func() { subnetRouteTable.Store(prev) })

	advertiserVIP := netip.MustParseAddr("10.201.0.9")
	return &gatewayState{store: st}, siteID, advertiserVIP
}
