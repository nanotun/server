package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/util"
)

// verifyOnesComplement 对一段字节做反码求和，返回 0 表示校验和自洽（含校验和字段在内重算应为 0）。
func verifyOnesComplement(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TestBuildIPv4UDPRoundTrip(t *testing.T) {
	src := netip.AddrFrom4([4]byte{10, 201, 0, 1})
	dst := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	payload := []byte("\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00query-bytes")
	pkt, ok := buildIPv4UDP(src, 45000, dst, 53, payload)
	if !ok {
		t.Fatal("buildIPv4UDP 失败")
	}
	if got := len(pkt); got != 20+8+len(payload) {
		t.Fatalf("总长 = %d, 期望 %d", got, 20+8+len(payload))
	}
	// IPv4 头校验和自洽。
	if c := verifyOnesComplement(pkt[0:20]); c != 0 {
		t.Fatalf("IPv4 头校验和不自洽: %#x", c)
	}
	// 解析回来字段一致。
	gotSrc, gotDst, sp, dp, gotPayload, pok := parseIPv4UDPForReturn(pkt)
	if !pok {
		t.Fatal("parseIPv4UDPForReturn 失败")
	}
	if gotSrc != src || gotDst != dst {
		t.Fatalf("IP 不一致: src=%v dst=%v", gotSrc, gotDst)
	}
	if sp != 45000 || dp != 53 {
		t.Fatalf("端口不一致: src=%d dst=%d", sp, dp)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("载荷不一致: %q", gotPayload)
	}
	// UDP 校验和自洽：伪首部 + UDP 段一起反码求和应为 0。
	var sum uint32
	sa := src.As4()
	da := dst.As4()
	sum += uint32(sa[0])<<8 | uint32(sa[1])
	sum += uint32(sa[2])<<8 | uint32(sa[3])
	sum += uint32(da[0])<<8 | uint32(da[1])
	sum += uint32(da[2])<<8 | uint32(da[3])
	sum += 17
	sum += uint32(len(pkt) - 20)
	for i := 20; i+1 < len(pkt); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	if len(pkt)%2 == 1 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if c := ^uint16(sum); c != 0 {
		t.Fatalf("UDP 校验和不自洽: %#x", c)
	}
}

// TestBuildIPv4UDPChecksumReferenceVector 用独立实现（Python/scapy 语义）预先算好的期望值校验，
// 防止实现与测试共用同一套（可能出错的）求和公式互相"自洽"。此前伪首部漏加 dst 后两字节，
// 导致所有注入出口的 DNS 查询被真实解析器按坏校验和静默丢弃（OpenWrt 出口 2s 超时的根因）。
func TestBuildIPv4UDPChecksumReferenceVector(t *testing.T) {
	src := netip.AddrFrom4([4]byte{10, 201, 0, 1})
	dst := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	payload := []byte("\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x05baidu\x03com\x00\x00\x01\x00\x01")
	pkt, ok := buildIPv4UDP(src, 40414, dst, 53, payload)
	if !ok {
		t.Fatal("buildIPv4UDP 失败")
	}
	if got := binary.BigEndian.Uint16(pkt[26:28]); got != 0xdee4 {
		t.Fatalf("UDP 校验和 = %#04x, 参考值 0xdee4", got)
	}
	if got := binary.BigEndian.Uint16(pkt[10:12]); got != 0x1fd9 {
		t.Fatalf("IPv4 头校验和 = %#04x, 参考值 0x1fd9", got)
	}
}

func TestBuildIPv4UDPRejectsV6(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::1")
	v4 := netip.AddrFrom4([4]byte{8, 8, 8, 8})
	if _, ok := buildIPv4UDP(v6, 45000, v4, 53, []byte("x")); ok {
		t.Fatal("src 为 v6 应拒绝")
	}
	if _, ok := buildIPv4UDP(v4, 45000, v6, 53, []byte("x")); ok {
		t.Fatal("dst 为 v6 应拒绝")
	}
}

func TestInterceptExitDNSCorrelation(t *testing.T) {
	setServerGatewayAddrs("10.201.0.1/16", "")
	gw := netip.AddrFrom4([4]byte{10, 201, 0, 1})

	ch := make(chan []byte, 1)
	port, ok := registerExitDNSWaiter(ch)
	if !ok {
		t.Fatal("registerExitDNSWaiter 失败")
	}
	defer unregisterExitDNSWaiter(port)

	if exitDNSInflight.Load() == 0 {
		t.Fatal("注册后 in-flight 应 > 0")
	}

	// 模拟出口回包：src=8.8.8.8:53 → dst=网关:关联端口。
	answer := []byte("\xab\xcd\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00answer")
	resp, _ := buildIPv4UDP(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53, gw, port, answer)

	if !interceptExitDNSResponseIfPending(resp) {
		t.Fatal("应截获该回包")
	}
	select {
	case got := <-ch:
		if string(got) != string(answer) {
			t.Fatalf("交回的载荷不一致: %q", got)
		}
	default:
		t.Fatal("等待者未收到载荷")
	}
	// 截获后应已摘除等待者、in-flight 归零。
	if exitDNSInflight.Load() != 0 {
		t.Fatalf("截获后 in-flight 应归零, 实际 %d", exitDNSInflight.Load())
	}
}

func TestInterceptExitDNSRejectsNon53Source(t *testing.T) {
	setServerGatewayAddrs("10.201.0.1/16", "")
	gw := netip.AddrFrom4([4]byte{10, 201, 0, 1})
	ch := make(chan []byte, 1)
	port, ok := registerExitDNSWaiter(ch)
	if !ok {
		t.Fatal("registerExitDNSWaiter 失败")
	}
	defer unregisterExitDNSWaiter(port)

	// 源端口非 53（伪造应答）→ 不应截获。
	bad, _ := buildIPv4UDP(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 12345, gw, port, []byte("evil"))
	if interceptExitDNSResponseIfPending(bad) {
		t.Fatal("源端口非 53 不应被截获")
	}
	// 等待者仍在。
	if exitDNSInflight.Load() == 0 {
		t.Fatal("未截获时等待者应仍在")
	}
}

func TestInterceptExitDNSNoInflightFastPath(t *testing.T) {
	// 无 in-flight 时应立即返回 false（热路径快速通过）。
	if exitDNSInflight.Load() != 0 {
		t.Skip("有并发 in-flight，跳过")
	}
	gw := netip.AddrFrom4([4]byte{10, 201, 0, 1})
	setServerGatewayAddrs("10.201.0.1/16", "")
	pkt, _ := buildIPv4UDP(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53, gw, 45000, []byte("x"))
	if interceptExitDNSResponseIfPending(pkt) {
		t.Fatal("无 in-flight 时不应截获")
	}
}

// TestTryResolvePublicViaExit_StripAAAAWhenExitNoV6：所选出口**无 v6 出网**（advertisedExitV6=false）时，
// AAAA 查询应**就地回 NODATA**（NOERROR/0-answer）而**不绕出口**——省一个 in-flight 占位、也砍掉苹果端一半的
// 经出口查询量。校验：返回 true、AAAA-strip 计数 +1、in-flight 未变、出口 TunChan 未收到注入包、响应为 NODATA。
func TestTryResolvePublicViaExit_StripAAAAWhenExitNoV6(t *testing.T) {
	resetConnByDeviceForTest(t)

	// 出口会话：在跑出口，但无 v6 出网（advertisedExitV6 默认 false）。
	const exitDev int64 = 88
	exitTun := make(chan *util.TunPacket, 4)
	exit := &Connection{deviceID: exitDev, connIDStr: "exit-v4only"}
	exit.advertisedExit.Store(true)
	eips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9", TunChan: exitTun}}
	exit.clientIPs.Store(&eips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	// 一对本地 UDP socket：srv 端写响应，cli 端读。
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

	// 使用方会话：vIP == peer.IP（让 exitDeviceForClientVIP 命中）、选定出口 exitDev。
	client := &Connection{connIDStr: "client-strip"}
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

	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}
	// 复用现有 helper（内建 ID=0x4242），question 名与上面的 q 对齐。
	query := buildDNSQuery(t, "example.com", dnsmessage.TypeAAAA)
	const qid uint16 = 0x4242

	stripBefore := magicDNSAAAAStripCount.Load()
	inflightBefore := exitDNSInflight.Load()

	if !tryResolvePublicViaExit(srv, peer, query, q, qid) {
		t.Fatal("v4-only 出口 + AAAA 应就地命中（回 NODATA），返回 true")
	}
	if got := magicDNSAAAAStripCount.Load(); got != stripBefore+1 {
		t.Fatalf("AAAA strip 计数应 +1，before=%d after=%d", stripBefore, got)
	}
	if got := exitDNSInflight.Load(); got != inflightBefore {
		t.Fatalf("不应绕出口，in-flight 不应变化：before=%d after=%d", inflightBefore, got)
	}
	select {
	case <-exitTun:
		t.Fatal("不应向出口 TunChan 投递任何包")
	default:
	}

	// 读回响应，校验 NODATA：NOERROR + 0 answers + 回显 ID。
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("读 NODATA 响应失败: %v", err)
	}
	h, ans := parseDNSResponse(t, buf[:n])
	if h.ID != qid {
		t.Fatalf("响应 ID = %#x, 期望 %#x", h.ID, qid)
	}
	if !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("应为 NOERROR 响应, got response=%v rcode=%v", h.Response, h.RCode)
	}
	if len(ans) != 0 {
		t.Fatalf("NODATA 应无 answer, got %d", len(ans))
	}
}

// TestTryResolvePublicViaExit_NotStrippedWhenExitHasV6：所选出口**有 v6 出网**（advertisedExitV6=true）时，
// AAAA **不**走就地 NODATA 分支，而是照常尝试绕出口解析（保住 AAAA 的 CDN 就近调度）。这里把出口 clientIPs 的
// TunChan 置空 → deliverIPPacketToConn 立即失败 → resolveExitDNS 快速返回 false（不等 exitDNSWaitTimeout），
// 绑定出口的会话解析失败 → fail-closed 回 SERVFAIL（返回 true，exit_servfail 计数 +1），**不**回退本地上游
// （防 server 地理答案污染客户端缓存）。校验：AAAA-strip 计数**未**变化（证明没走 strip 分支）。
func TestTryResolvePublicViaExit_NotStrippedWhenExitHasV6(t *testing.T) {
	resetConnByDeviceForTest(t)
	setServerGatewayAddrs("10.201.0.1/16", "")

	const exitDev int64 = 91
	exit := &Connection{deviceID: exitDev, connIDStr: "exit-v6"}
	exit.advertisedExit.Store(true)
	exit.advertisedExitV6.Store(true)
	eips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.9"}} // TunChan=nil → deliver 立即失败
	exit.clientIPs.Store(&eips)
	connIDMapMu.Lock()
	connByDeviceAddLocked(exit)
	connIDMapMu.Unlock()

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen srv: %v", err)
	}
	defer srv.Close()

	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 12345}
	client := &Connection{connIDStr: "client-v6"}
	client.egressDeviceID.Store(exitDev)
	cips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.7"}}
	client.clientIPs.Store(&cips)
	connIDMapMu.Lock()
	connIDMap[client.connIDStr] = client
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, client.connIDStr)
		connIDMapMu.Unlock()
	})

	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeAAAA,
		Class: dnsmessage.ClassINET,
	}
	query := buildDNSQuery(t, "example.com", dnsmessage.TypeAAAA)

	stripBefore := magicDNSAAAAStripCount.Load()
	servfailBefore := magicDNSExitServfailCount.Load()
	if !tryResolvePublicViaExit(srv, peer, query, q, 0x4242) {
		t.Fatal("绑定出口的会话解析失败应 fail-closed 回 SERVFAIL（返回 true），不回退本地上游")
	}
	if got := magicDNSExitServfailCount.Load(); got != servfailBefore+1 {
		t.Fatalf("exit_servfail 计数应 +1, before=%d after=%d", servfailBefore, got)
	}
	if got := magicDNSAAAAStripCount.Load(); got != stripBefore {
		t.Fatalf("出口有 v6 时不应走 AAAA-strip 分支，计数变化 before=%d after=%d", stripBefore, got)
	}
}

// TestTryResolvePublicViaExit_ServfailWhenExitOffline：绑定了出口但该出口**无在跑会话**（离线）时，
// 公网查询应回 SERVFAIL（返回 true、exit_servfail +1），**不**回退 server 本地上游——数据面本就 fail-closed，
// 回 server 地理的答案只会污染客户端 OS 缓存（「第一次打开卡住、刷新才好」的根因之一）。
func TestTryResolvePublicViaExit_ServfailWhenExitOffline(t *testing.T) {
	resetConnByDeviceForTest(t)

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

	// 使用方绑定了 deviceID=93 的出口，但没有任何在跑出口会话（离线）。
	client := &Connection{connIDStr: "client-offline"}
	client.egressDeviceID.Store(93)
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

	q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	query := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
	const qid uint16 = 0x4242

	servfailBefore := magicDNSExitServfailCount.Load()
	if !tryResolvePublicViaExit(srv, peer, query, q, qid) {
		t.Fatal("出口离线应返回 true（回 SERVFAIL），不回退本地上游")
	}
	if got := magicDNSExitServfailCount.Load(); got != servfailBefore+1 {
		t.Fatalf("exit_servfail 计数应 +1, before=%d after=%d", servfailBefore, got)
	}
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("读 SERVFAIL 响应失败: %v", err)
	}
	h, _ := parseDNSResponse(t, buf[:n])
	if h.ID != qid || h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("应为 SERVFAIL, got id=%#x rcode=%v", h.ID, h.RCode)
	}

	// HTTPS 中继路径同语义。
	qh := dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}
	queryH := buildDNSQuery(t, "example.com", dnsmessage.TypeHTTPS)
	if !tryRelayPublicViaExit(srv, peer, queryH, qh, qid) {
		t.Fatal("出口离线时 HTTPS 中继也应返回 true（回 SERVFAIL）")
	}
	if got := magicDNSExitServfailCount.Load(); got != servfailBefore+2 {
		t.Fatalf("HTTPS 路径 exit_servfail 计数应再 +1, got %d", got-servfailBefore)
	}
}

// buildHTTPSResponseRaw 造一个带 HTTPS(type65) RR 的**原始**应答报文（不求 SvcParams 完整语义，只要求字节可回写、
// 且 txn id / question 与查询一致），模拟出口对 HTTPS 查询原样转发回来的应答。
func buildHTTPSResponseRaw(t *testing.T, name string, qid uint16) []byte {
	t.Helper()
	n := dnsmessage.MustNewName(name + ".")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: qid, Response: true, RCode: dnsmessage.RCodeSuccess})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	// UnknownResource：把 HTTPS RR 的 rdata 当不透明字节塞进去（本模块中继不解析 SvcParams，故内容不重要，
	// 只要能被使用方原样收到）。这里用一段占位 rdata。
	rh := dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET, TTL: 120}
	if err := b.UnknownResource(rh, dnsmessage.UnknownResource{Type: dnsmessage.TypeHTTPS, Data: []byte{0x00, 0x01, 0x02, 0x03}}); err != nil {
		t.Fatal(err)
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestTryRelayPublicViaExit_RelaysRawResponse：选了出口的会话发 HTTPS 查询时，应经出口**原样中继**——注入一条查询到
// 出口 TunChan、把出口回来的原始应答字节**逐字节**回写给使用方（不解析、不改写），via_exit_relay 计数 +1。
func TestTryRelayPublicViaExit_RelaysRawResponse(t *testing.T) {
	resetConnByDeviceForTest(t)
	resetExitDNSCacheForTest(t)
	setServerGatewayAddrs("10.201.0.1/16", "")
	gw := netip.AddrFrom4([4]byte{10, 201, 0, 1})

	const exitDev int64 = 71
	exitTun := make(chan *util.TunPacket, 4)
	exit := &Connection{deviceID: exitDev, connIDStr: "exit-https"}
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

	client := &Connection{connIDStr: "client-https"}
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

	const qid uint16 = 0x4242
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("cdn.example.com."), Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}
	query := buildDNSQuery(t, "cdn.example.com", dnsmessage.TypeHTTPS)

	relayBefore := magicDNSViaExitRelayCount.Load()
	done := make(chan bool, 1)
	go func() { done <- tryRelayPublicViaExit(srv, peer, query, q, qid) }()

	var corrPort uint16
	select {
	case pkt := <-exitTun:
		srcIP, _, sp, dp, udp, ok := parseIPv4UDPForReturn(pkt.Buf[:pkt.N])
		if !ok || dp != 53 {
			t.Fatalf("注入出口的查询包异常 dp=%d ok=%v", dp, ok)
		}
		if srcIP != gw {
			t.Fatalf("注入包 src 应为网关 %v, got %v", gw, srcIP)
		}
		if string(udp) != string(query) {
			t.Fatal("注入出口的应是**原始查询字节**（透明中继）")
		}
		corrPort = sp
	case <-time.After(2 * time.Second):
		t.Fatal("超时：未见注入出口的 HTTPS 查询包")
	}

	respPayload := buildHTTPSResponseRaw(t, "cdn.example.com", qid)
	respPkt, ok := buildIPv4UDP(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53, gw, corrPort, respPayload)
	if !ok {
		t.Fatal("构造出口回包失败")
	}
	if !interceptExitDNSResponseIfPending(respPkt) {
		t.Fatal("出口回包应被截获")
	}
	if !<-done {
		t.Fatal("HTTPS 经出口中继应返回 true")
	}

	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("读中继响应失败: %v", err)
	}
	// 关键：使用方收到的应是出口回来的**原始应答字节**——本次 qid/question 与 leader 查询一致，就地改写为无操作，
	// 故逐字节等于出口原始应答。
	if string(buf[:n]) != string(respPayload) {
		t.Fatal("中继响应应与出口原始应答逐字节一致")
	}
	if got := magicDNSViaExitRelayCount.Load(); got != relayBefore+1 {
		t.Fatalf("via_exit_relay 计数应 +1, before=%d after=%d", relayBefore, got)
	}

	// 第二次：换一个**不同 qid**再查同 (出口,HTTPS,qname)——应命中缓存，不再注入出口，且返回的应答里 txn id 被就地
	// 改写成新 qid（证明 buildRawDNSResponseFor 的改写逻辑正确、可跨 qid 复用同一份原始应答）。
	const qid2 uint16 = 0x1357
	query2 := buildDNSQueryID(t, "cdn.example.com", dnsmessage.TypeHTTPS, qid2)
	hitBefore := magicDNSExitCacheHitCount.Load()
	if !tryRelayPublicViaExit(srv, peer, query2, q, qid2) {
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
	// 直接看原始字节（本模块透明中继不解析 SvcParams，测试也不做全量 Unpack）：txn id 应被就地改写为 qid2、
	// QR 位置位；除头 2 字节外，其余应与原始应答一致（question 同名等长、answer 段原样）。
	if n2 < 12 {
		t.Fatalf("缓存响应过短: %d", n2)
	}
	if gotID := binary.BigEndian.Uint16(buf[0:2]); gotID != qid2 {
		t.Fatalf("缓存命中响应的 txn id 应被改写为 %#x, got %#x", qid2, gotID)
	}
	if buf[2]&0x80 == 0 {
		t.Fatal("缓存命中响应应置 QR(Response) 位")
	}
	if string(buf[2:n2]) != string(respPayload[2:]) {
		t.Fatal("除 txn id 外，缓存命中响应应与原始应答一致（question 等长同名 + answer 原样）")
	}
}

// buildDNSQueryID 同 buildDNSQuery，但可指定 txn id（用于验证缓存命中时的 id 就地改写）。
func buildDNSQueryID(t *testing.T, name string, qtype dnsmessage.Type, id uint16) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTryRelayPublicViaExit_NoExitFallsThrough：未选出口（egress==0）时应返回 false（调用方回退本地上游），
// 不向任何出口注入查询。
func TestTryRelayPublicViaExit_NoExitFallsThrough(t *testing.T) {
	resetConnByDeviceForTest(t)
	setServerGatewayAddrs("10.201.0.1/16", "")

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen srv: %v", err)
	}
	defer srv.Close()

	// peer 不对应任何选了出口的会话 → exitDeviceForClientVIP 返回 0。
	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 200), Port: 12345}
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("cdn.example.com."), Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}
	query := buildDNSQuery(t, "cdn.example.com", dnsmessage.TypeHTTPS)

	if tryRelayPublicViaExit(srv, peer, query, q, 0x4242) {
		t.Fatal("未选出口应返回 false（回退本地上游）")
	}
}
