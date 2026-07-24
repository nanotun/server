package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/util"
)

// resetExitDNSCacheForTest 清空经出口结果缓存（全局，测试间隔离）。singleflight.Group 在每次 Do 完成后自动忘记
// key，无需重置。
func resetExitDNSCacheForTest(t *testing.T) {
	t.Helper()
	exitDNSCacheMu.Lock()
	exitDNSCache = make(map[string]exitDNSCacheEntry)
	exitDNSCacheLastSweep = time.Time{}
	exitDNSCacheMu.Unlock()
}

// buildDNSResponseA 造一个 A 应答报文（UDP 载荷），供测试模拟「出口回来的 DNS 响应」。
func buildDNSResponseA(t *testing.T, name string, ttl uint32, ips ...string) []byte {
	t.Helper()
	n := dnsmessage.MustNewName(name + ".")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, Response: true, RCode: dnsmessage.RCodeSuccess})
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
	for _, ip := range ips {
		a := netip.MustParseAddr(ip).As4()
		if err := b.AResource(dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.AResource{A: a}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseExitDNSResult(t *testing.T) {
	raw := buildDNSResponseA(t, "cdn.example.com", 60, "1.2.3.4", "5.6.7.8")
	addrs, rcode, ttl, ok := parseExitDNSResult(raw)
	if !ok {
		t.Fatal("解析应成功")
	}
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v, 期望 Success", rcode)
	}
	if ttl != 60 {
		t.Fatalf("minTTL = %d, 期望 60", ttl)
	}
	if len(addrs) != 2 || addrs[0] != netip.MustParseAddr("1.2.3.4") || addrs[1] != netip.MustParseAddr("5.6.7.8") {
		t.Fatalf("addrs = %v", addrs)
	}
	// 坏包（截断）→ ok=false。
	if _, _, _, bad := parseExitDNSResult([]byte{0x00, 0x01}); bad {
		t.Fatal("截断报文应解析失败")
	}
}

func TestBuildExitDNSCacheEntryTTLClamp(t *testing.T) {
	within := func(got, want time.Duration) bool { return got > want-2*time.Second && got <= want }
	// 正答复：TTL 夹在 [min,max]。
	e := buildExitDNSCacheEntry([]netip.Addr{netip.MustParseAddr("1.2.3.4")}, dnsmessage.RCodeSuccess, 5)
	if d := time.Until(e.expires); !within(d, exitDNSCacheMinTTL) {
		t.Fatalf("TTL=5 应夹到 min=%v, 实际剩 %v", exitDNSCacheMinTTL, d)
	}
	e = buildExitDNSCacheEntry([]netip.Addr{netip.MustParseAddr("1.2.3.4")}, dnsmessage.RCodeSuccess, 100000)
	if d := time.Until(e.expires); !within(d, exitDNSCacheMaxTTL) {
		t.Fatalf("超大 TTL 应夹到 max=%v, 实际剩 %v", exitDNSCacheMaxTTL, d)
	}
	e = buildExitDNSCacheEntry([]netip.Addr{netip.MustParseAddr("1.2.3.4")}, dnsmessage.RCodeSuccess, 120)
	if d := time.Until(e.expires); !within(d, 120*time.Second) {
		t.Fatalf("TTL=120 应原样, 实际剩 %v", d)
	}
	// 否定 / 空答复：用负缓存 TTL。
	e = buildExitDNSCacheEntry(nil, dnsmessage.RCodeSuccess, 300) // Success 但 0 addr = NODATA
	if d := time.Until(e.expires); !within(d, exitDNSCacheNegTTL) {
		t.Fatalf("NODATA 应用负缓存 TTL=%v, 实际剩 %v", exitDNSCacheNegTTL, d)
	}
	e = buildExitDNSCacheEntry(nil, dnsmessage.RCodeNameError, 300)
	if d := time.Until(e.expires); !within(d, exitDNSCacheNegTTL) {
		t.Fatalf("NXDOMAIN 应用负缓存 TTL=%v, 实际剩 %v", exitDNSCacheNegTTL, d)
	}
}

func TestExitDNSRcodeCacheable(t *testing.T) {
	if !exitDNSRcodeCacheable(dnsmessage.RCodeSuccess) {
		t.Fatal("NOERROR 应可缓存")
	}
	if !exitDNSRcodeCacheable(dnsmessage.RCodeNameError) {
		t.Fatal("NXDOMAIN 应可缓存")
	}
	for _, rc := range []dnsmessage.RCode{
		dnsmessage.RCodeServerFailure,
		dnsmessage.RCodeRefused,
		dnsmessage.RCodeNotImplemented,
		dnsmessage.RCodeFormatError,
	} {
		if exitDNSRcodeCacheable(rc) {
			t.Fatalf("软失败 rcode=%v 不应缓存", rc)
		}
	}
}

func TestExitDNSCacheGetPutExpiry(t *testing.T) {
	resetExitDNSCacheForTest(t)
	key := exitDNSCacheKey(7, dnsmessage.TypeA, "a.example.com")
	// 新鲜项命中。
	exitDNSCachePut(key, exitDNSCacheEntry{rcode: dnsmessage.RCodeSuccess, addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, expires: time.Now().Add(time.Minute)})
	if _, ok := exitDNSCacheGet(key); !ok {
		t.Fatal("新鲜项应命中")
	}
	// 过期项当未命中。
	expired := exitDNSCacheKey(7, dnsmessage.TypeA, "b.example.com")
	exitDNSCachePut(expired, exitDNSCacheEntry{rcode: dnsmessage.RCodeSuccess, expires: time.Now().Add(-time.Second)})
	if _, ok := exitDNSCacheGet(expired); ok {
		t.Fatal("过期项不应命中")
	}
	// 不同出口 → 不同 key，互相隔离。
	if exitDNSCacheKey(7, dnsmessage.TypeA, "a.example.com") == exitDNSCacheKey(8, dnsmessage.TypeA, "a.example.com") {
		t.Fatal("不同出口 deviceID 应产生不同 key")
	}
}

// TestTryResolvePublicViaExit_CachesAndServesFromCache：第一次经出口解析成功后写入缓存；第二次同 (出口,qtype,qname)
// 查询应**命中缓存**、不再向出口 TunChan 注入查询，并以当前 qid 正确回写。
func TestTryResolvePublicViaExit_CachesAndServesFromCache(t *testing.T) {
	resetConnByDeviceForTest(t)
	resetExitDNSCacheForTest(t)
	setServerGatewayAddrs("10.201.0.1/16", "")
	gw := netip.AddrFrom4([4]byte{10, 201, 0, 1})

	const exitDev int64 = 77
	exitTun := make(chan *util.TunPacket, 4)
	exit := &Connection{deviceID: exitDev, connIDStr: "exit-cache"}
	exit.advertisedExit.Store(true)
	exit.advertisedExitV6.Store(true)
	eips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: exitTun}}
	exit.clientIPs.Store(&eips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen srv: %v", err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen cli: %v", err)
	}
	defer cli.Close()
	peer := cli.LocalAddr().(*net.UDPAddr)

	client := &Connection{connIDStr: "client-cache"}
	client.egressDeviceID.Store(exitDev)
	cips := []util.VirtualIPAssignment{{VirtualIP: peer.IP.String()}}
	client.clientIPs.Store(&cips)
	connIDMapMu.Lock()
	connIDMap[client.connIDStr] = client
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, client.connIDStr)
		connIDMapMu.Unlock()
	})

	q := dnsmessage.Question{Name: dnsmessage.MustNewName("cdn.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	query := buildDNSQuery(t, "cdn.example.com", dnsmessage.TypeA)
	const qid uint16 = 0x4242

	// 第一次（缓存冷）：后台跑解析，主线程模拟出口回包。
	done := make(chan bool, 1)
	go func() { done <- tryResolvePublicViaExit(srv, peer, query, q, qid) }()

	var corrPort uint16
	select {
	case pkt := <-exitTun:
		_, _, sp, dp, _, ok := parseIPv4UDPForReturn(pkt.Buf[:pkt.N])
		if !ok || dp != 53 {
			t.Fatalf("注入出口的查询包异常 dp=%d ok=%v", dp, ok)
		}
		corrPort = sp
	case <-time.After(2 * time.Second):
		t.Fatal("超时：未见注入出口的查询包")
	}

	respPayload := buildDNSResponseA(t, "cdn.example.com", 120, "1.2.3.4", "5.6.7.8")
	respPkt, ok := buildIPv4UDP(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53, gw, corrPort, respPayload)
	if !ok {
		t.Fatal("构造出口回包失败")
	}
	if !interceptExitDNSResponseIfPending(exit, respPkt) {
		t.Fatal("出口回包应被截获")
	}
	if !<-done {
		t.Fatal("第一次经出口解析应返回 true")
	}

	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("读第一次响应失败: %v", err)
	}
	h, ans := parseDNSResponse(t, buf[:n])
	if h.ID != qid || h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("第一次响应异常 id=%#x rcode=%v", h.ID, h.RCode)
	}
	if len(ans) != 2 {
		t.Fatalf("第一次响应应有 2 条 A, got %d", len(ans))
	}

	key := exitDNSCacheKey(exitDev, dnsmessage.TypeA, "cdn.example.com")
	if _, hit := exitDNSCacheGet(key); !hit {
		t.Fatal("第一次解析后缓存应已填充")
	}

	// 第二次：应命中缓存 → 不再注入出口。
	hitBefore := magicDNSExitCacheHitCount.Load()
	if !tryResolvePublicViaExit(srv, peer, query, q, qid) {
		t.Fatal("第二次应命中缓存并返回 true")
	}
	if got := magicDNSExitCacheHitCount.Load(); got != hitBefore+1 {
		t.Fatalf("缓存命中计数应 +1 before=%d after=%d", hitBefore, got)
	}
	select {
	case <-exitTun:
		t.Fatal("命中缓存不应再向出口 TunChan 注入查询")
	default:
	}
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	n2, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("读缓存响应失败: %v", err)
	}
	h2, ans2 := parseDNSResponse(t, buf[:n2])
	if h2.ID != qid || len(ans2) != 2 {
		t.Fatalf("缓存响应异常 id=%#x ans=%d", h2.ID, len(ans2))
	}
}

// buildDNSResponseRcode 造一个仅有 header（无 answer）的指定 rcode 应答，模拟出口回来的 SERVFAIL 等软失败。
func buildDNSResponseRcode(t *testing.T, name string, rcode dnsmessage.RCode) []byte {
	t.Helper()
	n := dnsmessage.MustNewName(name + ".")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, Response: true, RCode: rcode})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestTryResolvePublicViaExit_ServfailNotCached：出口回 SERVFAIL（软失败）时应把 SERVFAIL serve 给当前调用方，
// 但**不写缓存** —— 下一条相同查询不会命中缓存、会重新经出口解析（校验：解析后缓存里没有该 key）。
func TestTryResolvePublicViaExit_ServfailNotCached(t *testing.T) {
	resetConnByDeviceForTest(t)
	resetExitDNSCacheForTest(t)
	setServerGatewayAddrs("10.201.0.1/16", "")
	gw := netip.AddrFrom4([4]byte{10, 201, 0, 1})

	const exitDev int64 = 79
	exitTun := make(chan *util.TunPacket, 4)
	exit := &Connection{deviceID: exitDev, connIDStr: "exit-servfail"}
	exit.advertisedExit.Store(true)
	exit.advertisedExitV6.Store(true)
	eips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: exitTun}}
	exit.clientIPs.Store(&eips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen srv: %v", err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen cli: %v", err)
	}
	defer cli.Close()
	peer := cli.LocalAddr().(*net.UDPAddr)

	client := &Connection{connIDStr: "client-servfail"}
	client.egressDeviceID.Store(exitDev)
	cips := []util.VirtualIPAssignment{{VirtualIP: peer.IP.String()}}
	client.clientIPs.Store(&cips)
	connIDMapMu.Lock()
	connIDMap[client.connIDStr] = client
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, client.connIDStr)
		connIDMapMu.Unlock()
	})

	q := dnsmessage.Question{Name: dnsmessage.MustNewName("flaky.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	query := buildDNSQuery(t, "flaky.example.com", dnsmessage.TypeA)
	const qid uint16 = 0x4242

	done := make(chan bool, 1)
	go func() { done <- tryResolvePublicViaExit(srv, peer, query, q, qid) }()

	var corrPort uint16
	select {
	case pkt := <-exitTun:
		_, _, sp, _, _, ok := parseIPv4UDPForReturn(pkt.Buf[:pkt.N])
		if !ok {
			t.Fatal("注入出口的查询包解析失败")
		}
		corrPort = sp
	case <-time.After(2 * time.Second):
		t.Fatal("超时：未见注入出口的查询包")
	}

	respPayload := buildDNSResponseRcode(t, "flaky.example.com", dnsmessage.RCodeServerFailure)
	respPkt, ok := buildIPv4UDP(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53, gw, corrPort, respPayload)
	if !ok {
		t.Fatal("构造出口回包失败")
	}
	if !interceptExitDNSResponseIfPending(exit, respPkt) {
		t.Fatal("出口回包应被截获")
	}
	if !<-done {
		t.Fatal("SERVFAIL 也应 serve（返回 true），只是不缓存")
	}

	// 客户端应收到 SERVFAIL。
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("读 SERVFAIL 响应失败: %v", err)
	}
	h, _ := parseDNSResponse(t, buf[:n])
	if h.ID != qid || h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("响应应为 SERVFAIL, got id=%#x rcode=%v", h.ID, h.RCode)
	}

	// 关键：SERVFAIL 不应落缓存。
	key := exitDNSCacheKey(exitDev, dnsmessage.TypeA, "flaky.example.com")
	if _, hit := exitDNSCacheGet(key); hit {
		t.Fatal("SERVFAIL 不应被缓存（应可立即重试）")
	}
}

// TestTryResolvePublicViaExit_SingleflightCollapsesConcurrent：N 条**并发**的相同 (出口,qtype,qname) 查询
// （模拟 iOS 烂网下的丢包重发风暴）应塌缩成**恰好一条**经出口往返；全部返回 true 且各自收到应答。
func TestTryResolvePublicViaExit_SingleflightCollapsesConcurrent(t *testing.T) {
	resetConnByDeviceForTest(t)
	resetExitDNSCacheForTest(t)
	setServerGatewayAddrs("10.201.0.1/16", "")
	gw := netip.AddrFrom4([4]byte{10, 201, 0, 1})

	const exitDev int64 = 78
	exitTun := make(chan *util.TunPacket, 16) // 够大：若误发多条注入，能全部被捕获以判失败
	exit := &Connection{deviceID: exitDev, connIDStr: "exit-sf"}
	exit.advertisedExit.Store(true)
	exit.advertisedExitV6.Store(true)
	eips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: exitTun}}
	exit.clientIPs.Store(&eips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen srv: %v", err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen cli: %v", err)
	}
	defer cli.Close()
	peer := cli.LocalAddr().(*net.UDPAddr)

	client := &Connection{connIDStr: "client-sf"}
	client.egressDeviceID.Store(exitDev)
	cips := []util.VirtualIPAssignment{{VirtualIP: peer.IP.String()}}
	client.clientIPs.Store(&cips)
	connIDMapMu.Lock()
	connIDMap[client.connIDStr] = client
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, client.connIDStr)
		connIDMapMu.Unlock()
	})

	q := dnsmessage.Question{Name: dnsmessage.MustNewName("burst.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	query := buildDNSQuery(t, "burst.example.com", dnsmessage.TypeA)
	const qid uint16 = 0x4242

	const N = 8
	results := make(chan bool, N)
	for i := 0; i < N; i++ {
		go func() { results <- tryResolvePublicViaExit(srv, peer, query, q, qid) }()
	}

	// 取第一条（应是唯一一条）注入出口的查询包，拿关联端口。
	var corrPort uint16
	select {
	case pkt := <-exitTun:
		_, _, sp, _, _, ok := parseIPv4UDPForReturn(pkt.Buf[:pkt.N])
		if !ok {
			t.Fatal("注入出口的查询包解析失败")
		}
		corrPort = sp
	case <-time.After(2 * time.Second):
		t.Fatal("超时：未见注入出口的查询包")
	}

	// 给其余 goroutine 充分时间汇入 singleflight（成为等待者，而非各自再发一条）。
	time.Sleep(200 * time.Millisecond)
	select {
	case <-exitTun:
		t.Fatal("并发相同查询应塌缩成一条经出口往返，却出现第二条注入")
	default:
	}

	// 投递出口回包，唤醒 leader → 全部等待者共享结果。
	respPayload := buildDNSResponseA(t, "burst.example.com", 90, "9.9.9.9")
	respPkt, ok := buildIPv4UDP(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53, gw, corrPort, respPayload)
	if !ok {
		t.Fatal("构造出口回包失败")
	}
	if !interceptExitDNSResponseIfPending(exit, respPkt) {
		t.Fatal("出口回包应被截获")
	}

	// 全部 goroutine 应返回 true。
	for i := 0; i < N; i++ {
		select {
		case okr := <-results:
			if !okr {
				t.Fatalf("第 %d 条并发查询返回 false（应全部命中经出口/缓存）", i)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("第 %d 条并发查询超时未返回", i)
		}
	}

	// 每条查询都应收到一份应答（共享同一 peer/cli）。
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	got := 0
	for i := 0; i < N; i++ {
		n, _, rerr := cli.ReadFromUDP(buf)
		if rerr != nil {
			break
		}
		h, ans := parseDNSResponse(t, buf[:n])
		if h.ID != qid || len(ans) != 1 {
			t.Fatalf("并发应答异常 id=%#x ans=%d", h.ID, len(ans))
		}
		got++
	}
	if got != N {
		t.Fatalf("应收到 %d 份应答，实际 %d", N, got)
	}

	// 收尾再确认没有额外注入（总注入 == 1）。
	select {
	case <-exitTun:
		t.Fatal("收尾发现额外注入，塌缩未生效")
	default:
	}
}

// TestBuildRawDNSResponseFor_QuestionLenMismatch(第十九轮深扫 LOW):就地改写缓存原始应答前,必须确认
// cachedRaw 的 question 段与当前查询**线格等长**。若坏/恶意出口回了一份 question 段更短的应答且被以本 query
// 的 key 缓存,原位 copy(out[12:qEnd], query[12:qEnd]) 会越过 cachedRaw 真实 question 末尾覆写进答复区、污染答案。
// 修复后:长度不一致 → 返回 nil(调用方回 SERVFAIL);等长 → 正常改写。
func TestBuildRawDNSResponseFor_QuestionLenMismatch(t *testing.T) {
	hdr := make([]byte, 12) // 12B DNS 头(全零,内容无关)
	// question 线格:len 前缀标签 + root(0) + qtype(A) + qclass(IN)。
	qA := []byte{0x01, 'a', 0x00, 0x00, 0x01, 0x00, 0x01}       // qname "a" → question 末尾偏移 19
	qAA := []byte{0x02, 'a', 'a', 0x00, 0x00, 0x01, 0x00, 0x01} // qname "aa" → question 末尾偏移 20
	ans := []byte{0xC0, 0x0C}                                   // 2 字节「答复区」填充(指向偏移 12 的压缩指针形态)

	catBytes := func(parts ...[]byte) []byte {
		out := []byte{}
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}

	query := catBytes(hdr, qAA) // 当前查询 question = "aa",qEnd=20

	// cachedRaw 的 question 是 "a"(末尾 19)但整包 len=21 ≥ qEnd(20):旧「仅 len 检查」会放行并污染答复区。
	cachedShorter := catBytes(hdr, qA, ans)
	if out := buildRawDNSResponseFor(query, 0x1234, cachedShorter); out != nil {
		t.Fatal("cachedRaw question 段与 query 不等长应返回 nil(SERVFAIL)")
	}

	// question 等长("aa" vs "aa")→ 正常改写:txn id 覆写为当前 qid,长度与 cachedRaw 一致。
	cachedMatch := catBytes(hdr, qAA, ans)
	out := buildRawDNSResponseFor(query, 0x1234, cachedMatch)
	if out == nil {
		t.Fatal("question 段等长应成功改写,不应返回 nil")
	}
	if len(out) != len(cachedMatch) {
		t.Fatalf("改写后长度应与 cachedRaw 一致:got %d want %d", len(out), len(cachedMatch))
	}
	if out[0] != 0x12 || out[1] != 0x34 {
		t.Fatalf("改写后 txn id 应为当前 qid 0x1234,实际 %#x%02x", out[0], out[1])
	}
}
