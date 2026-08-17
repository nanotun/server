package main

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// buildQueryWithEDNS 造一条带 OPT 伪 RR 的查询,声明 UDP 缓冲区为 bufSize。
func buildQueryWithEDNS(t *testing.T, name string, bufSize uint16) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatal(err)
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{{
			// OPT 伪 RR:Name 必须是根,Class 复用为请求方 UDP payload size。
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(bufSize)},
			Body:   &dnsmessage.OPTResource{},
		}},
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// buildBigDNSReply 造一份带 count 条 A 记录的应答(用来把报文撑过长度上限)。
func buildBigDNSReply(t *testing.T, query []byte, count int) []byte {
	t.Helper()
	id, q, ok := parseDNSQueryKey(query)
	if !ok {
		t.Fatal("查询解析不出 key")
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{q},
	}
	for i := 0; i < count; i++ {
		m.Answers = append(m.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, byte(i / 256), byte(i % 256)}},
		})
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// udpDNSReplyPair 起一对 UDP socket,返回「包了长度约束的写入器」和一个读回函数。
func udpDNSReplyPair(t *testing.T, query []byte) (*udpDNSReplyConn, *net.UDPAddr, func() []byte) {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	read := func() []byte {
		_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 65535)
		n, _, rerr := cli.ReadFromUDP(buf)
		if rerr != nil {
			t.Fatalf("没收到应答: %v", rerr)
		}
		return buf[:n]
	}
	return &udpDNSReplyConn{conn: srv, query: query}, cli.LocalAddr().(*net.UDPAddr), read
}

// TestUDPDNSReplyLimit_FollowsTheClientButKeepsBothBounds 钉住长度上限的取值口径。
//
// 三条边界各有其害:
//   - 无 OPT 时不回落到 512(RFC 1035 的协议保底值),会发出使用方根本收不下的报文;
//   - 不夹下界:有实现把 OPT.Class 填 0 或很小的值,照做会让几乎所有应答都被截断置 TC,把本可一次 UDP
//     完成的解析全推去 TCP(多一个 RTT,且 TCP 连接资源有限);
//   - 不夹上界:使用方常声明 65535 表示「我能收多大都行」,但那只是它的 recvfrom 缓冲区,路径 MTU 管不着 ——
//     真发 20KB 会被 IP 分片,分片丢失率高,表现又回到「静默超时」。
func TestUDPDNSReplyLimit_FollowsTheClientButKeepsBothBounds(t *testing.T) {
	if got := udpDNSReplyLimit(buildDNSQuery(t, "example.com", dnsmessage.TypeA)); got != magicDNSUDPFloor {
		t.Fatalf("无 EDNS 的查询上限应为 %d,got %d", magicDNSUDPFloor, got)
	}
	if got := udpDNSReplyLimit(buildQueryWithEDNS(t, "example.com", 1232)); got != 1232 {
		t.Fatalf("应尊重使用方声明的 1232,got %d", got)
	}
	if got := udpDNSReplyLimit(buildQueryWithEDNS(t, "example.com", 200)); got != magicDNSUDPFloor {
		t.Fatalf("小于 512 的声明必须夹到 %d,got %d", magicDNSUDPFloor, got)
	}
	if got := udpDNSReplyLimit(buildQueryWithEDNS(t, "example.com", 65535)); got != magicDNSUDPCeiling {
		t.Fatalf("超大声明必须夹到 %d,got %d", magicDNSUDPCeiling, got)
	}
	// 解不开的查询:按最保守的 512 处理,绝不能当成「没有上限」。
	if got := udpDNSReplyLimit([]byte{0x01, 0x02}); got != magicDNSUDPFloor {
		t.Fatalf("解不开的查询应保守取 %d,got %d", magicDNSUDPFloor, got)
	}
}

// TestBuildTruncatedDNSReply_RebuildsAValidEmptyAnswerWithTC:截断必须**重新打包**,不能把字节切短。
// 切短会得到一帧「header 声称有 N 条记录、数据却被砍掉一半」的报文,使用方一律按 FORMERR 丢弃,
// 等于又回到静默失败 —— 而 TC 的全部意义就是让使用方明确知道「答案在,只是太大,请走 TCP」。
func TestBuildTruncatedDNSReply_RebuildsAValidEmptyAnswerWithTC(t *testing.T) {
	query := buildDNSQuery(t, "many.example.com", dnsmessage.TypeA)
	big := buildBigDNSReply(t, query, 200)
	if len(big) <= magicDNSUDPFloor {
		t.Fatalf("造的应答不够大(%d B),这条用例就没在测截断", len(big))
	}

	out := buildTruncatedDNSReply(big, magicDNSUDPFloor)
	if out == nil {
		t.Fatal("应能构出截断应答")
	}
	if len(out) > magicDNSUDPFloor {
		t.Fatalf("截断后仍超上限:%d > %d", len(out), magicDNSUDPFloor)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatalf("截断应答必须仍是合法 DNS 报文(否则使用方直接丢弃): %v", err)
	}
	if !m.Header.Truncated {
		t.Fatal("TC 位必须置上 —— 这是使用方改走 TCP 的唯一信号")
	}
	if !m.Header.Response {
		t.Fatal("QR 必须是应答")
	}
	if len(m.Answers) != 0 {
		t.Fatalf("截断应答不该带 answer,got %d 条", len(m.Answers))
	}
	// question 必须回显:多数 stub resolver 会拿它和自己发出的查询比对,不符就丢(0x20 校验同理)。
	if len(m.Questions) != 1 || m.Questions[0].Name.String() != "many.example.com." {
		t.Fatalf("question 必须原样回显,got %+v", m.Questions)
	}
	// qid 必须保持:换了 txn id 使用方会当成不相关的报文丢掉,于是它永远收不到 TC、也就永远不会走 TCP。
	if m.Header.ID != 0x4242 {
		t.Fatalf("txn id 必须保持 0x4242,got %#x", m.Header.ID)
	}
}

// TestBuildTruncatedDNSReply_ReturnsNilWhenTheReplyCannotBeParsed:解不开的应答(只可能来自上游坏包)
// 返回 nil,让调用方原样发出 —— 与其静默吞掉,不如交给使用方自己判断(它可能比我们更宽容)。
func TestBuildTruncatedDNSReply_ReturnsNilWhenTheReplyCannotBeParsed(t *testing.T) {
	if out := buildTruncatedDNSReply([]byte{0xde, 0xad, 0xbe, 0xef}, magicDNSUDPFloor); out != nil {
		t.Fatalf("解不开的应答应返回 nil,got %d 字节", len(out))
	}
}

// TestUDPDNSReplyConn_TruncatesOversizedRepliesOnTheWire 端到端:所有 UDP 应答路径都经这个写入器,
// 所以这里验证的是**整条 UDP 侧**的行为 —— 超长应答落到线上时已经是「空应答 + TC=1」。
//
// 反面(照原样 sendto)的后果不是「使用方收到一个大包」,而是**静默超时**:报文在路径上被分片丢弃,
// 使用方只会原样重试 UDP,一直失败,且服务端侧看不出任何异常。
func TestUDPDNSReplyConn_TruncatesOversizedRepliesOnTheWire(t *testing.T) {
	query := buildDNSQuery(t, "many.example.com", dnsmessage.TypeA)
	w, peer, read := udpDNSReplyPair(t, query)

	big := buildBigDNSReply(t, query, 200)
	if _, err := w.WriteToUDP(big, peer); err != nil {
		t.Fatalf("写应答: %v", err)
	}
	got := read()
	if len(got) > magicDNSUDPFloor {
		t.Fatalf("线上报文仍超 512(%d B)—— 会被路径丢弃,使用方表现为超时", len(got))
	}
	var m dnsmessage.Message
	if err := m.Unpack(got); err != nil {
		t.Fatalf("线上报文必须合法: %v", err)
	}
	if !m.Header.Truncated {
		t.Fatal("超长应答必须带 TC=1")
	}
}

// TestUDPDNSReplyConn_LeavesRepliesWithinTheLimitAlone:上限之内的应答必须**原样**发出。
// 少了这条断言,一个「一律截断」的实现也能通过上面的用例 —— 而那会把每一次解析都推去 TCP,
// 多一个 RTT 且吃光 TCP 连接坑位。
func TestUDPDNSReplyConn_LeavesRepliesWithinTheLimitAlone(t *testing.T) {
	for name, tc := range map[string]struct {
		query   []byte
		records int
	}{
		// 小应答:根本不触发上限判断(也顺带验证「≤512 时不解析查询」这条快路径没把报文改坏)。
		"远小于 512": {query: buildDNSQuery(t, "small.example.com", dnsmessage.TypeA), records: 1},
		// 超过 512 但在使用方声明的 1232 之内:必须原样发,不能按 512 去截。
		"超过 512 但在 EDNS 声明之内": {query: buildQueryWithEDNS(t, "mid.example.com", 1232), records: 40},
	} {
		t.Run(name, func(t *testing.T) {
			w, peer, read := udpDNSReplyPair(t, tc.query)
			resp := buildBigDNSReply(t, tc.query, tc.records)
			if _, err := w.WriteToUDP(resp, peer); err != nil {
				t.Fatalf("写应答: %v", err)
			}
			got := read()
			if string(got) != string(resp) {
				t.Fatalf("上限之内的应答必须原样发出:发了 %d B,收到 %d B", len(resp), len(got))
			}
			var m dnsmessage.Message
			if err := m.Unpack(got); err != nil {
				t.Fatal(err)
			}
			if m.Header.Truncated {
				t.Fatal("没超上限就不该置 TC")
			}
			if len(m.Answers) != tc.records {
				t.Fatalf("answer 应完整保留 %d 条,got %d", tc.records, len(m.Answers))
			}
		})
	}
}

// TestUDPDNSReplyConn_KeepsTheOPTRecordWhenTruncating:RFC 6891 §6.2.3 —— 带 TC 的应答也应带 OPT,
// 否则使用方会以为我们不支持 EDNS,后续查询可能退回 512 缓冲区,反而更容易触发截断。
func TestUDPDNSReplyConn_KeepsTheOPTRecordWhenTruncating(t *testing.T) {
	query := buildQueryWithEDNS(t, "many.example.com", 512)
	id, q, ok := parseDNSQueryKey(query)
	if !ok {
		t.Fatal("查询解析不出 key")
	}
	// 造一份「带 OPT 的大应答」,模拟上游对 EDNS 查询的回复。
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true},
		Questions: []dnsmessage.Question{q},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232},
			Body:   &dnsmessage.OPTResource{},
		}},
	}
	for i := 0; i < 200; i++ {
		m.Answers = append(m.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, byte(i / 256), byte(i % 256)}},
		})
	}
	big, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}

	out := buildTruncatedDNSReply(big, magicDNSUDPFloor)
	if out == nil {
		t.Fatal("应能构出截断应答")
	}
	var got dnsmessage.Message
	if err := got.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if len(got.Additionals) != 1 || got.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		t.Fatalf("截断应答应保留 OPT 伪 RR,got %+v", got.Additionals)
	}
}
