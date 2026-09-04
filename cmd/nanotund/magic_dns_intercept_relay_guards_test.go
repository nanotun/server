package main

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// 截获路径的异步那一半:缓存冷的时候要绕一趟出口。这里钉两条只在「冷 + 非 A/AAAA」和「出口不回话」
// 时才走到的分支,它们的失败方式都不会报错:
//
//   - HTTPS/SVCB 必须走 raw 中继(原样带回并就地改 txn id)。走错成 A/AAAA 那条解析路径的话,
//     ipv4hint / ech 全被丢掉 —— 浏览器拿到一条没有 hint 的 HTTPS 记录,回落到 A 查询,
//     于是 ECH 静默失效、连接特征暴露,而 DNS「是通的」。
//   - 出口不回话必须 SERVFAIL(fail-closed)。回退到 server 本地上游看上去更「可用」,但客户端
//     明明选了出口,却拿到 server 机房地理位置的解析结果 —— 流量从出口出去、目标 IP 却在另一个洲,
//     表现为慢和偶发失败,没有任何一条日志说破。

// echHintPayload 冒充 HTTPS 记录 rdata 里的 ipv4hint/ech —— 用一段可搜索的字节确认它原样穿过中继。
var echHintPayload = []byte{0x00, 0x01, 0x00, 0x08, 'E', 'C', 'H', '-', 'H', 'I', 'N', 'T'}

// mkRawHTTPSResp 造一份 question 为 HTTPS、答复区是一条未知类型(HTTPS)记录的应答。
func mkRawHTTPSResp(t *testing.T, qid uint16, name string, rdata []byte) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: qid, Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := b.UnknownResource(
		dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET, TTL: 60},
		dnsmessage.UnknownResource{Type: dnsmessage.TypeHTTPS, Data: rdata},
	); err != nil {
		t.Fatal(err)
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestInterceptExitBoundDNS_RelaysHTTPSThroughTheExitVerbatim HTTPS 走 raw 中继,hint 一字不丢。
func TestInterceptExitBoundDNS_RelaysHTTPSThroughTheExitVerbatim(t *testing.T) {
	client, clientTun, exitTun, clientVIP := interceptTestEnv(t, 111, true)
	setServerGatewayAddrs("10.201.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })
	gw := netip.AddrFrom4([4]byte{10, 201, 0, 1})
	resolver := netip.AddrFrom4([4]byte{8, 8, 8, 8})

	before := magicDNSViaExitRelayCount.Load()

	query := buildDNSQueryFull(t, "ech.example.com", dnsmessage.TypeHTTPS, dnsmessage.ClassINET)
	if !forwardPacketToExitNode(client, mkClientDNSPacket(t, clientVIP, 44001, resolver, query)) {
		t.Fatal("HTTPS 查询也该由 exit 截获路径接管")
	}

	injected := recvTunPacket(t, exitTun, "注入出口的 HTTPS 查询")
	srcIP, _, corrPort, dp, udp, ok := parseIPv4UDPForReturn(injected)
	if !ok || srcIP != gw || dp != 53 {
		t.Fatalf("注入查询应为 网关:关联端口 → resolver:53, got %v → :%d", srcIP, dp)
	}
	if string(udp) != string(query) {
		t.Fatal("经出口中继的必须是原始查询字节 —— 重新编码会丢掉客户端带的 EDNS 选项")
	}

	exitConn := lookupRunningExitConnByDevice(111)
	if exitConn == nil {
		t.Fatal("找不到出口会话")
	}
	// 出口那边的真实应答:一条 HTTPS 记录,rdata 里塞上我们要确认「一字不丢」的 hint 载荷。
	upstream := mkRawHTTPSResp(t, 0x4242, "ech.example.com.", echHintPayload)
	respPkt, bok := buildIPv4UDP(resolver, 53, gw, corrPort, upstream)
	if !bok {
		t.Fatal("构造出口回包失败")
	}
	if !interceptExitDNSResponseIfPending(exitConn, respPkt) {
		t.Fatal("出口回包应被关联端口截获")
	}

	reply := recvTunPacket(t, clientTun, "注入客户端的 HTTPS 应答")
	rSrc, rDst, rsp, rdp, rudp, rok := parseIPv4UDPForReturn(reply)
	if !rok || rSrc != resolver || rsp != 53 || rDst != clientVIP || rdp != 44001 {
		t.Fatalf("应答应伪装成 %v:53 → %v:44001, got %v:%d → %v:%d", resolver, clientVIP, rSrc, rsp, rDst, rdp)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(rudp)
	if err != nil {
		t.Fatalf("解析客户端应答: %v", err)
	}
	if hdr.ID != 0x4242 {
		t.Fatalf("txn id = %#x,want 客户端那条查询的 0x4242 —— 对不上的话 stub 直接丢弃", hdr.ID)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	ah, err := p.AnswerHeader()
	if err != nil {
		t.Fatalf("应答里没有答复记录: %v —— 空答复会让浏览器回落到 A 查询,ECH 静默失效", err)
	}
	if ah.Type != dnsmessage.TypeHTTPS {
		t.Fatalf("答复记录类型 = %v,want HTTPS", ah.Type)
	}
	if !bytes.Contains(rudp, echHintPayload) {
		t.Fatal("HTTPS 记录的 rdata 没有原样带回 —— ipv4hint / ech 被重编码丢掉,ECH 静默失效而 DNS「是通的」")
	}
	if got := magicDNSViaExitRelayCount.Load(); got == before {
		t.Error("raw 中继计数没动 —— 排查「HTTPS 到底走没走出口」时这个计数器是唯一线索")
	}

	// 结果要落共享缓存:下一条同名 HTTPS 查询不该再花 2s 的出口往返。
	if _, hit := exitDNSCacheGet(exitDNSCacheKey(111, dnsmessage.TypeHTTPS, "ech.example.com")); !hit {
		t.Error("raw 中继结果没写缓存 —— 每条 HTTPS 查询都要占一个 2s 在途位")
	}
}

// TestInterceptExitBoundDNS_SilentExitBecomesSERVFAILNotLocalGeo 出口不回话 → SERVFAIL,不回退本地。
func TestInterceptExitBoundDNS_SilentExitBecomesSERVFAILNotLocalGeo(t *testing.T) {
	client, clientTun, exitTun, clientVIP := interceptTestEnv(t, 112, true)
	setServerGatewayAddrs("10.201.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })
	resolver := netip.AddrFrom4([4]byte{8, 8, 8, 8})

	before := magicDNSExitServfailCount.Load()

	query := buildDNSQuery(t, "blackhole.example.com", dnsmessage.TypeA)
	if !forwardPacketToExitNode(client, mkClientDNSPacket(t, clientVIP, 44002, resolver, query)) {
		t.Fatal("查询应被接管")
	}
	// 查询确实发出去了,只是出口那边永远不回话(链路黑洞 / 上游不可达)。
	recvTunPacket(t, exitTun, "注入出口的查询包")

	// 等出口往返超时(exitDNSWaitTimeout)后应答才会出现。
	var reply []byte
	select {
	case p := <-clientTun:
		reply = append(reply, p.Buf[:p.N]...)
	case <-time.After(exitDNSWaitTimeout + 3*time.Second):
		t.Fatal("出口超时后一个应答都没注入 —— 客户端只能干等自己的 stub 超时,期间那个名字完全不可用")
	}
	_, _, _, _, rudp, rok := parseIPv4UDPForReturn(reply)
	if !rok {
		t.Fatal("注入的应答包解析不了")
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(rudp)
	if err != nil {
		t.Fatalf("解析应答: %v", err)
	}
	if hdr.ID != 0x4242 {
		t.Fatalf("txn id = %#x,want 0x4242", hdr.ID)
	}
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode = %v,want SERVFAIL —— 回退 server 本地上游的话,客户端明明选了出口"+
			"却拿到 server 机房地理的解析结果,表现只是「慢」而没有任何日志说破", hdr.RCode)
	}
	if got := magicDNSExitServfailCount.Load(); got == before {
		t.Error("出口失败计数没动 —— 这个计数器是判断「出口 DNS 是不是在大面积失败」的唯一入口")
	}

	// 失败绝不能进缓存:否则一次抖动会把这个名字钉死到缓存 TTL 结束。
	if _, hit := exitDNSCacheGet(exitDNSCacheKey(112, dnsmessage.TypeA, "blackhole.example.com")); hit {
		t.Error("出口失败的结果被写进了共享缓存 —— 一次抖动会让这个名字在整个 TTL 内都解析失败")
	}
}
