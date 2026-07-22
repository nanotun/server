package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/util"
)

// interceptTestEnv 搭一对会话：绑定出口的使用方（带 TunChan 收注入应答）+ 在跑出口（带 TunChan 收注入查询）。
func interceptTestEnv(t *testing.T, exitDev int64, exitHasV6 bool) (client *Connection, clientTun, exitTun chan *util.TunPacket, clientVIP netip.Addr) {
	t.Helper()
	resetConnByDeviceForTest(t)
	resetExitDNSCacheForTest(t)

	exitTun = make(chan *util.TunPacket, 8)
	exit := &Connection{deviceID: exitDev, connIDStr: "exit-intercept"}
	exit.advertisedExit.Store(true)
	exit.advertisedExitV6.Store(exitHasV6)
	eips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: exitTun}}
	exit.clientIPs.Store(&eips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	clientVIP = netip.MustParseAddr("10.0.0.7")
	clientTun = make(chan *util.TunPacket, 8)
	client = &Connection{connIDStr: "client-intercept", deviceID: 5}
	client.egressDeviceID.Store(exitDev)
	cips := []util.VirtualIPAssignment{{VirtualIP: clientVIP.String(), TunChan: clientTun}}
	client.clientIPs.Store(&cips)
	connIDMapMu.Lock()
	connIDMap[client.connIDStr] = client
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, client.connIDStr)
		connIDMapMu.Unlock()
	})
	return client, clientTun, exitTun, clientVIP
}

// mkClientDNSPacket 造一个「客户端直发公共 resolver」的 IPv4 UDP :53 查询包。
func mkClientDNSPacket(t *testing.T, srcVIP netip.Addr, srcPort uint16, resolver netip.Addr, dnsQuery []byte) []byte {
	t.Helper()
	pkt, ok := buildIPv4UDP(srcVIP, srcPort, resolver, 53, dnsQuery)
	if !ok {
		t.Fatal("构造客户端 DNS 查询包失败")
	}
	return pkt
}

// recvTunPacket 从 TunChan 收一个包（带超时）。
func recvTunPacket(t *testing.T, ch chan *util.TunPacket, what string) []byte {
	t.Helper()
	select {
	case p := <-ch:
		out := make([]byte, p.N)
		copy(out, p.Buf[:p.N])
		return out
	case <-time.After(3 * time.Second):
		t.Fatalf("超时：未收到 %s", what)
		return nil
	}
}

// TestInterceptExitBoundDNS_AAAAStripInjectsNODATA：v4-only 出口下，绑定会话直发 8.8.8.8 的 AAAA 查询应被
// 数据面拦截、就地回 NODATA（伪装成 8.8.8.8:53 的回包注入客户端 TunChan），**不**转发给出口——这是修
// 「直查公共 DNS 绕过 AAAA 剥离 → 客户端拿真 AAAA → 公网 v6 连接被丢 → Happy Eyeballs 卡顿」的核心断言。
func TestInterceptExitBoundDNS_AAAAStripInjectsNODATA(t *testing.T) {
	client, clientTun, exitTun, clientVIP := interceptTestEnv(t, 101, false /* v4-only */)
	resolver := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	query := buildDNSQuery(t, "v6site.example.com", dnsmessage.TypeAAAA)
	pkt := mkClientDNSPacket(t, clientVIP, 5555, resolver, query)

	stripBefore := magicDNSAAAAStripCount.Load()
	interceptBefore := magicDNSInterceptCount.Load()
	if !forwardPacketToExitNode(client, pkt) {
		t.Fatal("UDP :53 查询应由 exit 路径处理（返回 true）")
	}
	if got := magicDNSInterceptCount.Load(); got != interceptBefore+1 {
		t.Fatalf("intercept 计数应 +1, before=%d after=%d", interceptBefore, got)
	}
	if got := magicDNSAAAAStripCount.Load(); got != stripBefore+1 {
		t.Fatalf("AAAA strip 计数应 +1, before=%d after=%d", stripBefore, got)
	}
	select {
	case <-exitTun:
		t.Fatal("AAAA strip 不应向出口转发任何包")
	default:
	}
	reply := recvTunPacket(t, clientTun, "注入客户端的 NODATA 应答")
	srcIP, dstIP, sp, dp, udp, ok := parseIPv4UDPForReturn(reply)
	if !ok || srcIP != resolver || sp != 53 || dstIP != clientVIP || dp != 5555 {
		t.Fatalf("应答应伪装成 %v:53 → %v:5555, got %v:%d → %v:%d", resolver, clientVIP, srcIP, sp, dstIP, dp)
	}
	h, ans := parseDNSResponse(t, udp)
	if h.ID != 0x4242 || !h.Response || h.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 {
		t.Fatalf("应为 NODATA(NOERROR/0 answer, id=0x4242), got id=%#x rcode=%v ans=%d", h.ID, h.RCode, len(ans))
	}
}

// TestInterceptExitBoundDNS_CacheHitServesInline：缓存已有 (出口,A,qname) 结果时，直发 8.8.8.8 的 A 查询应
// 同步从缓存作答（注入客户端），不再向出口注入任何查询——数据面拦截与网关 MagicDNS 路径共享同一张缓存表。
func TestInterceptExitBoundDNS_CacheHitServesInline(t *testing.T) {
	client, clientTun, exitTun, clientVIP := interceptTestEnv(t, 102, true)
	resolver := netip.AddrFrom4([4]byte{114, 114, 114, 114})

	cached := netip.MustParseAddr("198.51.100.10")
	key := exitDNSCacheKey(102, dnsmessage.TypeA, "cached.example.com")
	exitDNSCachePut(key, buildExitDNSCacheEntry([]netip.Addr{cached}, dnsmessage.RCodeSuccess, 60))

	query := buildDNSQuery(t, "cached.example.com", dnsmessage.TypeA)
	pkt := mkClientDNSPacket(t, clientVIP, 40001, resolver, query)

	hitBefore := magicDNSExitCacheHitCount.Load()
	if !forwardPacketToExitNode(client, pkt) {
		t.Fatal("UDP :53 查询应由 exit 路径处理（返回 true）")
	}
	if got := magicDNSExitCacheHitCount.Load(); got != hitBefore+1 {
		t.Fatalf("缓存命中计数应 +1, before=%d after=%d", hitBefore, got)
	}
	select {
	case <-exitTun:
		t.Fatal("缓存命中不应向出口注入查询")
	default:
	}
	reply := recvTunPacket(t, clientTun, "缓存命中的注入应答")
	srcIP, _, sp, _, udp, ok := parseIPv4UDPForReturn(reply)
	if !ok || srcIP != resolver || sp != 53 {
		t.Fatalf("应答 src 应为原 resolver %v:53, got %v:%d", resolver, srcIP, sp)
	}
	_, ans := parseDNSResponse(t, udp)
	if len(ans) != 1 {
		t.Fatalf("应有 1 条 A answer, got %d", len(ans))
	}
	a, isA := ans[0].Body.(*dnsmessage.AResource)
	if !isA || netip.AddrFrom4(a.A) != cached {
		t.Fatalf("A 记录应为缓存值 %v, got %+v", cached, ans[0].Body)
	}
}

// TestInterceptExitBoundDNS_ColdResolvesViaExit：缓存冷时，直发公共 resolver 的 A 查询应改写成「经出口解析」
// （注入出口的查询 src=网关:关联端口、dst=名义 resolver:53、载荷=原查询字节），拿回应答后伪装原 resolver 回包
// 注入客户端。端到端穿过 singleflight + 关联端口截获，验证异步冷路径完整闭环。
func TestInterceptExitBoundDNS_ColdResolvesViaExit(t *testing.T) {
	client, clientTun, exitTun, clientVIP := interceptTestEnv(t, 103, true)
	setServerGatewayAddrs("10.201.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })
	gw := netip.AddrFrom4([4]byte{10, 201, 0, 1})
	resolver := netip.AddrFrom4([4]byte{8, 8, 8, 8})

	query := buildDNSQuery(t, "cold.example.com", dnsmessage.TypeA)
	pkt := mkClientDNSPacket(t, clientVIP, 51234, resolver, query)

	if !forwardPacketToExitNode(client, pkt) {
		t.Fatal("UDP :53 查询应由 exit 路径处理（返回 true）")
	}

	// 出口应收到注入的查询包（异步 goroutine 发出）。
	injected := recvTunPacket(t, exitTun, "注入出口的查询包")
	srcIP, dstIP, corrPort, dp, udp, ok := parseIPv4UDPForReturn(injected)
	if !ok || srcIP != gw || dp != 53 {
		t.Fatalf("注入查询应为 网关:关联端口 → resolver:53, got %v:%d → %v:%d", srcIP, corrPort, dstIP, dp)
	}
	if string(udp) != string(query) {
		t.Fatal("注入出口的应是原始查询字节")
	}

	// 模拟出口回包 → 被关联端口截获 → 异步 goroutine 拿到结果 → 注入客户端。
	// H1：截获须由「查询被投递到的那条出口会话」触发，故取该 device 的出口 conn 传入（与生产一致：
	// 回包沿出口链路到达其 readLoop）。
	exitConn := lookupRunningExitConnByDevice(103)
	if exitConn == nil {
		t.Fatal("找不到出口会话")
	}
	respPayload := buildDNSResponseA(t, "cold.example.com", 60, "198.51.100.20")
	respPkt, bok := buildIPv4UDP(resolver, 53, gw, corrPort, respPayload)
	if !bok {
		t.Fatal("构造出口回包失败")
	}
	if !interceptExitDNSResponseIfPending(exitConn, respPkt) {
		t.Fatal("出口回包应被关联端口截获")
	}

	reply := recvTunPacket(t, clientTun, "注入客户端的最终应答")
	rSrc, rDst, rsp, rdp, rudp, rok := parseIPv4UDPForReturn(reply)
	if !rok || rSrc != resolver || rsp != 53 || rDst != clientVIP || rdp != 51234 {
		t.Fatalf("最终应答应伪装成 %v:53 → %v:51234, got %v:%d → %v:%d", resolver, clientVIP, rSrc, rsp, rDst, rdp)
	}
	h, ans := parseDNSResponse(t, rudp)
	if h.ID != 0x4242 || len(ans) != 1 {
		t.Fatalf("应答异常 id=%#x ans=%d", h.ID, len(ans))
	}
	a, isA := ans[0].Body.(*dnsmessage.AResource)
	if !isA || netip.AddrFrom4(a.A) != netip.MustParseAddr("198.51.100.20") {
		t.Fatalf("A 记录应为出口解析结果, got %+v", ans[0].Body)
	}
	// 结果应已落缓存（下一条同名查询免出口往返）。
	if _, hit := exitDNSCacheGet(exitDNSCacheKey(103, dnsmessage.TypeA, "cold.example.com")); !hit {
		t.Fatal("经出口解析的结果应写入共享缓存")
	}
}

// TestInterceptExitBoundDNS_NonDNSFallsThrough：目的 :53 但载荷不是 DNS 查询（垃圾字节 / 应答帧）→ 不拦截，
// 照旧原样转发给出口（出口 DNAT 兜底），绝不丢包。
func TestInterceptExitBoundDNS_NonDNSFallsThrough(t *testing.T) {
	client, clientTun, exitTun, clientVIP := interceptTestEnv(t, 104, true)
	resolver := netip.AddrFrom4([4]byte{8, 8, 8, 8})

	// 载荷太短、不是合法 DNS 报文。
	garbage := mkClientDNSPacket(t, clientVIP, 6000, resolver, []byte("xyz"))
	if !forwardPacketToExitNode(client, garbage) {
		t.Fatal("非 DNS 的 :53 包仍应由 exit 路径原样转发（返回 true）")
	}
	got := recvTunPacket(t, exitTun, "原样转发的非 DNS 包")
	if string(got) != string(garbage) {
		t.Fatal("非 DNS 包应原样转发给出口")
	}

	// 应答帧（QR=1）也不拦截（如客户端本机对外提供 DNS 服务的回包）。
	respBytes := buildDNSResponseA(t, "x.example.com", 60, "1.2.3.4")
	respPkt := mkClientDNSPacket(t, clientVIP, 6001, resolver, respBytes)
	if !forwardPacketToExitNode(client, respPkt) {
		t.Fatal("DNS 应答帧仍应由 exit 路径原样转发（返回 true）")
	}
	got2 := recvTunPacket(t, exitTun, "原样转发的 DNS 应答帧")
	if string(got2) != string(respPkt) {
		t.Fatal("DNS 应答帧应原样转发给出口")
	}
	select {
	case <-clientTun:
		t.Fatal("不拦截时不应向客户端注入任何应答")
	default:
	}
}

// TestClampDNSResponseTTLs：早期竞速窗口的 TTL 钳制——Answer/Authority/Additional 的 TTL 钳到上限，
// OPT 伪 RR（TTL 字段是 EDNS flags）跳过；已经 ≤ 上限的应答原样返回（changed=false）。
func TestClampDNSResponseTTLs(t *testing.T) {
	n := dnsmessage.MustNewName("clamp.example.com.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x77, Response: true, RCode: dnsmessage.RCodeSuccess})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := b.AResource(dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 300},
		dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	// OPT 伪 RR：TTL 字段承载扩展 rcode/flags（这里设 DO 位），钳制必须跳过它。
	var opt dnsmessage.ResourceHeader
	if err := opt.SetEDNS0(1232, dnsmessage.RCodeSuccess, true); err != nil {
		t.Fatal(err)
	}
	if err := b.OPTResource(opt, dnsmessage.OPTResource{}); err != nil {
		t.Fatal(err)
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}

	out, changed := clampDNSResponseTTLs(raw, 2)
	if !changed {
		t.Fatal("TTL 300 > 2 应发生钳制")
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatalf("钳制后的应答应仍可解析: %v", err)
	}
	if len(m.Answers) != 1 || m.Answers[0].Header.TTL != 2 {
		t.Fatalf("Answer TTL 应被钳到 2, got %+v", m.Answers)
	}
	if len(m.Additionals) != 1 || m.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		t.Fatalf("OPT 应保留, got %+v", m.Additionals)
	}
	if m.Additionals[0].Header.TTL == 2 {
		t.Fatal("OPT 的 TTL(EDNS flags) 不应被钳制")
	}

	// 已 ≤ 上限：原样返回。
	out2, changed2 := clampDNSResponseTTLs(out, 5)
	if changed2 {
		t.Fatal("TTL 已 ≤ 上限不应再改")
	}
	if string(out2) != string(out) {
		t.Fatal("未改动时应返回原字节")
	}

	// 非法字节：fail-safe 原样返回。
	if _, ch := clampDNSResponseTTLs([]byte{1, 2, 3}, 2); ch {
		t.Fatal("不可解析的应答不应声称有改动")
	}
}

// TestMagicDNSInEarlyClampWindow：会话注册后 < 窗口 → 钳；超窗 / 查不到会话 → 不钳。
func TestMagicDNSInEarlyClampWindow(t *testing.T) {
	vip := netip.MustParseAddr("10.0.0.42")
	c := &Connection{connIDStr: "clamp-conn", createdAt: time.Now()}
	cips := []util.VirtualIPAssignment{{VirtualIP: vip.String()}}
	c.clientIPs.Store(&cips)
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, c.connIDStr)
		connIDMapMu.Unlock()
	})

	peer := &net.UDPAddr{IP: vip.AsSlice(), Port: 4444}
	if !magicDNSInEarlyClampWindow(peer) {
		t.Fatal("新会话（刚注册）应在早期钳制窗口内")
	}
	c.createdAt = time.Now().Add(-magicDNSEarlyClampWindow - time.Second)
	if magicDNSInEarlyClampWindow(peer) {
		t.Fatal("超窗会话不应再钳")
	}
	unknown := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 99), Port: 4444}
	if magicDNSInEarlyClampWindow(unknown) {
		t.Fatal("查不到会话不应钳")
	}
}
