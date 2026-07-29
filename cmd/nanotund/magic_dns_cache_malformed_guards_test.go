package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// 这一组钉的是「经出口回来的应答坏成什么样都不能被当成好答案入共享缓存」。
//
// 为什么重要:出口 DNS 缓存是按 (出口设备|qtype|归一化 qname) 共享的 —— 一条被错误接受的应答会被
// 复用给该出口后面所有查同名的客户端。而应答来自另一台客户端机器(出口节点),它可能被攻破、可能跑着
// 魔改客户端,截断/畸形应答是它能塞进来的最便宜的东西。解析路径的每条 return false 都是这道闸。

// truncateAfterAnswerHeader 造一份「答复区头齐全、rdata 被截断」的应答:先按正常方式打一份,
// 再从尾部砍掉几个字节。AnswerHeader 能读出来(声明了 rdlength),读 rdata 时必然失败。
func truncateAfterAnswerHeader(t *testing.T, name string, typ dnsmessage.Type, drop int) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
	switch typ {
	case dnsmessage.TypeA:
		if err := b.AResource(rh, dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}); err != nil {
			t.Fatal(err)
		}
	case dnsmessage.TypeAAAA:
		var v6 [16]byte
		v6[0], v6[1], v6[15] = 0x20, 0x01, 0x01
		if err := b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: v6}); err != nil {
			t.Fatal(err)
		}
	default:
		if err := b.TXTResource(rh, dnsmessage.TXTResource{TXT: []string{"hello"}}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if drop >= len(raw) {
		t.Fatalf("砍掉的字节(%d)不能多于报文长度(%d)", drop, len(raw))
	}
	return raw[:len(raw)-drop]
}

// TestParseExitDNSResult_TruncatedAnswersAreNotHalfAccepted:A / AAAA 的 rdata 被截断、以及未知类型
// (这里用 TXT)的 RR 跳不过去时,必须整份判失败,而不是「拿到前半截地址就算成功」。
//
// 后者的后果是**半条答案进共享缓存**:调用方看到 ok=true 就按正答复缓存,之后同一出口下所有查同名的
// 客户端都拿到这半截结果(缺 IP 的域名连不上,且要等 TTL 过期才自愈)。
func TestParseExitDNSResult_TruncatedAnswersAreNotHalfAccepted(t *testing.T) {
	cases := []struct {
		name string
		resp []byte
	}{
		{"A 的 rdata 被截断", truncateAfterAnswerHeader(t, "a.example.com.", dnsmessage.TypeA, 2)},
		{"AAAA 的 rdata 被截断", truncateAfterAnswerHeader(t, "a.example.com.", dnsmessage.TypeAAAA, 6)},
		{"未知类型的 rdata 被截断(跳不过去)", truncateAfterAnswerHeader(t, "a.example.com.", dnsmessage.TypeTXT, 3)},
		{"整份报文只有半个头", []byte{0x12, 0x34, 0x81, 0x80}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addrs, _, _, ok := parseExitDNSResult(tc.resp)
			if ok {
				t.Fatalf("坏应答被判成解析成功(addrs=%v) —— 半条答案会进共享出口 DNS 缓存", addrs)
			}
		})
	}
}

// TestParseRawDNSMeta_TruncatedAnswerIsNotCacheable:HTTPS/SVCB 走的是「原样中继 + 只抽 rcode/TTL」
// 的路径,同样不能把截断的应答当成可缓存。它连 rdata 都不解,唯一的闸就是 SkipAnswer 的错误检查。
func TestParseRawDNSMeta_TruncatedAnswerIsNotCacheable(t *testing.T) {
	resp := truncateAfterAnswerHeader(t, "svc.example.com.", dnsmessage.TypeTXT, 3)
	if _, _, ok := parseRawDNSMeta(resp); ok {
		t.Fatal("答复区截断的原始应答被判成可缓存 —— 它会以本次查询的 key 留在共享缓存里")
	}
	if _, _, ok := parseRawDNSMeta([]byte{0x00}); ok {
		t.Fatal("连报文头都不完整也被判成可缓存")
	}
}

// TestDNSQuestionEnd_RejectsMalformedQuestionSections:就地改写(把缓存的原始应答改成当前 qid +
// question)全靠这个偏移。它算错一点,copy 就会越过 question 末尾覆写进答复区 —— 客户端拿到的是
// 被污染的答案。所以每种畸形都必须报「算不出」,不能返回一个凑出来的偏移。
func TestDNSQuestionEnd_RejectsMalformedQuestionSections(t *testing.T) {
	hdr := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	cases := []struct {
		name string
		msg  []byte
	}{
		{"比报文头还短", hdr[:8]},
		{"标签长度越过报文末尾", append(append([]byte(nil), hdr...), 0x05, 'a', 'b')},
		{"question 里出现压缩指针", append(append([]byte(nil), hdr...), 0xc0, 0x0c)},
		{"根标签之后缺 qtype/qclass", append(append([]byte(nil), hdr...), 0x01, 'a', 0x00, 0x00)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if end, ok := dnsQuestionEnd(tc.msg); ok {
				t.Fatalf("畸形 question 段被算出了结束偏移 %d(报文长 %d)", end, len(tc.msg))
			}
		})
	}
}

// TestServeRawExitDNSFromCache_UnrewritableCacheBecomesSERVFAIL:缓存里的原始应答改写不出来时
// (question 段与当前查询不等长 —— 坏出口能塞出这种东西),必须回 SERVFAIL,不能静默吞包:
// 客户端干等到 stub resolver 超时,比立刻拿到 SERVFAIL 换下一个上游慢一个数量级。
func TestServeRawExitDNSFromCache_UnrewritableCacheBecomesSERVFAIL(t *testing.T) {
	srv, cli := udpPairForCacheGuards(t)
	peer := cli.LocalAddr().(*net.UDPAddr)

	query := buildDNSQuery(t, "svc.example.com", dnsmessage.TypeHTTPS)
	// 缓存里存的是另一个(更短的)名字的应答 → question 段长度不一致 → 拒绝原位覆盖。
	cached := buildDNSQuery(t, "x.cn", dnsmessage.TypeHTTPS)
	const qid uint16 = 0x7788

	serveRawExitDNSFromCache(srv, peer, qid, query, exitDNSCacheEntry{raw: cached, rcode: dnsmessage.RCodeSuccess})

	hdr := readDNSHeaderForCacheGuards(t, cli)
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("改写不出来时应回 SERVFAIL,got %v", hdr.RCode)
	}
	if hdr.ID != qid {
		t.Fatalf("SERVFAIL 也必须回显当前 txn id:want %#x got %#x", qid, hdr.ID)
	}
}

// TestServeExitDNSFromCache_UnbuildableAnswerBecomesSERVFAIL:A/AAAA 侧同理 —— 从缓存重建应答失败时
// 退化成 SERVFAIL。用一个不合法(未完全限定)的 question 名把 builder 逼失败。
func TestServeExitDNSFromCache_UnbuildableAnswerBecomesSERVFAIL(t *testing.T) {
	srv, cli := udpPairForCacheGuards(t)
	peer := cli.LocalAddr().(*net.UDPAddr)

	// dnsmessage 的 name 必须以根标签结尾;这个不是,打包时必然报错。
	var bad dnsmessage.Name
	copy(bad.Data[:], "notqualified")
	bad.Length = uint8(len("notqualified"))
	q := dnsmessage.Question{Name: bad, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	const qid uint16 = 0x99aa

	entry := exitDNSCacheEntry{
		addrs: []netip.Addr{netip.AddrFrom4([4]byte{1, 2, 3, 4})},
		rcode: dnsmessage.RCodeSuccess,
	}
	serveExitDNSFromCache(srv, peer, qid, q, entry)

	hdr := readDNSHeaderForCacheGuards(t, cli)
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("重建应答失败时应回 SERVFAIL(不静默吞包),got %v", hdr.RCode)
	}
}

func udpPairForCacheGuards(t *testing.T) (srv, cli *net.UDPConn) {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen srv: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen cli: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return srv, cli
}

func readDNSHeaderForCacheGuards(t *testing.T, cli *net.UDPConn) dnsmessage.Header {
	t.Helper()
	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("没收到应答(静默吞包就是这个形状): %v", err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(buf[:n])
	if err != nil {
		t.Fatalf("回来的不是合法 DNS 报文: %v", err)
	}
	return hdr
}
