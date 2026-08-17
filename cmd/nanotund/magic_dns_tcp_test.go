package main

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nanotun/server/config"
	"golang.org/x/net/dns/dnsmessage"
)

// dialMagicDNSTCP 连到本机 magic DNS 的 TCP/53(测试端口)。
func dialMagicDNSTCP(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatalf("连 TCP DNS: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// writeTCPDNSQuery 按 RFC 1035 §4.2.2 发一条「2 字节长度 + 查询」。
func writeTCPDNSQuery(t *testing.T, c net.Conn, query []byte) {
	t.Helper()
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := c.Write(frame); err != nil {
		t.Fatalf("写 TCP 查询: %v", err)
	}
}

// readTCPDNSReply 读一条长度前缀应答。ok=false = 对端关了连接 / 超时(调用方据此断言"没有应答")。
func readTCPDNSReply(t *testing.T, c net.Conn, wait time.Duration) ([]byte, bool) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, false
	}
	return body, true
}

// TestStartMagicDNSTCP_ResolvesAMeshNameOverTCP 走一遍真实链路:真起 TCP listener → 真发长度前缀查询 →
// 拿到 vIP → cleanup 后 listener 关闭。
//
// 这条是本文件唯一同时穿过 startMagicDNSTCP / runMagicDNSTCPAcceptLoop / serveMagicDNSTCPConn /
// tcpDNSReplyConn 的用例;下面那些边界用例都证不了「该答的时候真能答」。
func TestStartMagicDNSTCP_ResolvesAMeshNameOverTCP(t *testing.T) {
	withTestGlobalContext(t)
	port := freeUDPPort(t)
	gw := magicDNSGatewayOn(t, port)
	seedDevice(t, gw.store, "alice", "laptop", "100.64.0.7", "")
	withACLSnapshotForTest(t, meshOnAllowAll())

	cleanup := startMagicDNSTCP(gw, "127.0.0.1")
	t.Cleanup(cleanup)

	c := dialMagicDNSTCP(t, port)
	writeTCPDNSQuery(t, c, buildDNSQuery(t, "laptop.alice.lan", dnsmessage.TypeA))
	raw, ok := readTCPDNSReply(t, c, 3*time.Second)
	if !ok {
		t.Fatal("TCP 上没收到应答 —— 截断应答的回落路径不通,大应答就彻底无解了")
	}
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		t.Fatalf("应答解析失败(长度前缀算错会让载荷错位): %v", err)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("要 1 条 answer,got %d", len(m.Answers))
	}
	a, isA := m.Answers[0].Body.(*dnsmessage.AResource)
	if !isA {
		t.Fatalf("answer 不是 A 记录: %T", m.Answers[0].Body)
	}
	if got := net.IP(a.A[:]).String(); got != "100.64.0.7" {
		t.Fatalf("vIP 应为 100.64.0.7,got %s", got)
	}
}

// TestServeMagicDNSTCPConn_AnswersSeveralQueriesOnOneConnection:RFC 7766 §6.2.1 允许在同一连接上连发多条
// 查询。不支持复用会让使用方每条查询重连一次(多一次 TCP 握手 RTT);更糟的是,若实现只读第一条就关连接,
// 使用方后续查询会拿到 RST 并可能把整个解析器标记为不可用。
func TestServeMagicDNSTCPConn_AnswersSeveralQueriesOnOneConnection(t *testing.T) {
	withTestGlobalContext(t)
	port := freeUDPPort(t)
	gw := magicDNSGatewayOn(t, port)
	seedDevice(t, gw.store, "alice", "laptop", "100.64.0.7", "")
	withACLSnapshotForTest(t, meshOnAllowAll())
	t.Cleanup(startMagicDNSTCP(gw, "127.0.0.1"))

	c := dialMagicDNSTCP(t, port)
	for i, id := range []uint16{0x1111, 0x2222, 0x3333} {
		writeTCPDNSQuery(t, c, buildDNSQueryID(t, "laptop.alice.lan", dnsmessage.TypeA, id))
		raw, ok := readTCPDNSReply(t, c, 3*time.Second)
		if !ok {
			t.Fatalf("第 %d 条查询没应答 —— 连接被提前关了", i+1)
		}
		var m dnsmessage.Message
		if err := m.Unpack(raw); err != nil {
			t.Fatalf("第 %d 条应答解析失败: %v", i+1, err)
		}
		// txn id 必须逐条对上:错位说明帧边界算错(把上一条的应答当成本条)。
		if m.Header.ID != id {
			t.Fatalf("第 %d 条应答 txn id 应为 %#x,got %#x —— 帧错位", i+1, id, m.Header.ID)
		}
	}
}

// TestServeMagicDNSTCPConn_ClosesOnAbsurdLengthPrefix:长度前缀声明了一个大得离谱的值时必须直接关连接,
// 不能按它去 make([]byte, n) 然后等对端慢慢喂 —— 那正是「声明 64KB、只发 1 字节」的内存占用型攻击。
// 也不能试图重新对齐字节流:一旦错位就无法可靠恢复,关掉让使用方重连才是正确处置。
func TestServeMagicDNSTCPConn_ClosesOnAbsurdLengthPrefix(t *testing.T) {
	withTestGlobalContext(t)
	port := freeUDPPort(t)
	gw := magicDNSGatewayOn(t, port)
	withACLSnapshotForTest(t, meshOnAllowAll())
	t.Cleanup(startMagicDNSTCP(gw, "127.0.0.1"))

	for name, prefix := range map[string]uint16{
		"超过单条查询上限": magicDNSTCPMaxQuerySize + 1,
		"长度为 0":    0,
	} {
		t.Run(name, func(t *testing.T) {
			c := dialMagicDNSTCP(t, port)
			var lenBuf [2]byte
			binary.BigEndian.PutUint16(lenBuf[:], prefix)
			if _, err := c.Write(lenBuf[:]); err != nil {
				t.Fatalf("写长度前缀: %v", err)
			}
			if _, ok := readTCPDNSReply(t, c, 2*time.Second); ok {
				t.Fatal("不该有任何应答")
			}
			// 连接必须已被服务端关闭(读到 EOF),而不是挂着等我们把声明的字节喂完。
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("连接仍开着 —— 非法长度前缀必须立刻断连")
			}
		})
	}
}

// TestRunMagicDNSTCPAcceptLoop_ClosesConnectionsOverTheCap:超过并发连接上限的新连接必须**当场关掉**,
// 而不是排进 accept 队列等位。排队会把压力藏起来(队列堆积 → 内核丢 SYN,服务端一条日志一个计数都没有);
// 立刻关闭则让使用方马上知道并回退 UDP 或重试,同时留下 rejected 计数供观测。
func TestRunMagicDNSTCPAcceptLoop_ClosesConnectionsOverTheCap(t *testing.T) {
	withTestGlobalContext(t)
	port := freeUDPPort(t)
	gw := magicDNSGatewayOn(t, port)
	seedDevice(t, gw.store, "alice", "laptop", "100.64.0.7", "")
	withACLSnapshotForTest(t, meshOnAllowAll())

	prev := magicDNSTCPMaxConns
	magicDNSTCPMaxConns = 1
	t.Cleanup(func() { magicDNSTCPMaxConns = prev })
	before := magicDNSTCPRejectedCount.Load()
	t.Cleanup(startMagicDNSTCP(gw, "127.0.0.1"))

	// 第一条连接占住唯一的坑:发一条查询并拿到应答,确保它已被 serve 循环接管(仍在 idle 超时内挂着)。
	first := dialMagicDNSTCP(t, port)
	writeTCPDNSQuery(t, first, buildDNSQuery(t, "laptop.alice.lan", dnsmessage.TypeA))
	if _, ok := readTCPDNSReply(t, first, 3*time.Second); !ok {
		t.Fatal("第一条连接就没答上 —— 后面的上限断言无从谈起")
	}

	second := dialMagicDNSTCP(t, port)
	writeTCPDNSQuery(t, second, buildDNSQuery(t, "laptop.alice.lan", dnsmessage.TypeA))
	if _, ok := readTCPDNSReply(t, second, 2*time.Second); ok {
		t.Fatal("超上限的连接不该被 serve")
	}
	if got := magicDNSTCPRejectedCount.Load(); got <= before {
		t.Fatalf("超上限拒连必须记数(便于运维发现打满),before=%d after=%d", before, got)
	}
}

// TestStartMagicDNSTCP_NoOpPaths 钉住每条 no-op:都必须返回**可调用**的 cleanup(main 里是 defer 无条件调的,
// 返回 nil 会 panic 在关机路径上),且**没有真的起 listener**。
//
// 「非法 listen_addr 也不能起」尤其要紧:addr.IP=nil 会被 ListenTCP 当成 0.0.0.0,把本该只在 TUN 上听的
// 内网 DNS 摆到所有网卡(含公网口)。
func TestStartMagicDNSTCP_NoOpPaths(t *testing.T) {
	port := freeUDPPort(t)
	cases := map[string]func(t *testing.T) (*gatewayState, string){
		"gw 为 nil":    func(t *testing.T) (*gatewayState, string) { return nil, "127.0.0.1" },
		"store 为 nil": func(t *testing.T) (*gatewayState, string) { return &gatewayState{cfg: &config.Config{}}, "127.0.0.1" },
		"cfg 为 nil": func(t *testing.T) (*gatewayState, string) {
			gw := newMagicDNSGateway(t)
			gw.cfg = nil
			return gw, "127.0.0.1"
		},
		"配置里没打开": func(t *testing.T) (*gatewayState, string) {
			return newMagicDNSGateway(t), "127.0.0.1"
		},
		"listen_addr 为空(TUN 未就绪)": func(t *testing.T) (*gatewayState, string) {
			return magicDNSGatewayOn(t, port), ""
		},
		"listen_addr 不是合法 IP": func(t *testing.T) (*gatewayState, string) {
			return magicDNSGatewayOn(t, port), "tun0"
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			gw, addr := mk(t)
			cleanup := startMagicDNSTCP(gw, addr)
			if cleanup == nil {
				t.Fatal("cleanup 不能是 nil —— main 在关机路径上无条件 defer 调它")
			}
			probe, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
			if err != nil {
				t.Fatalf("端口 %d 已被占用 —— 这条路径其实起了 listener: %v", port, err)
			}
			_ = probe.Close()
			cleanup()
			cleanup() // 幂等:关机路径重复调不该炸
		})
	}
}

// TestStartMagicDNSTCP_ListenFailureIsNotFatal:TCP/53 被别人占着(systemd-resolved 等)时只跳过,
// 绝不能崩,更不能拖垮**已经可用的 UDP** 解析 —— TCP 是 UDP 的补充。
func TestStartMagicDNSTCP_ListenFailureIsNotFatal(t *testing.T) {
	occupied, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port

	cleanup := startMagicDNSTCP(magicDNSGatewayOn(t, port), "127.0.0.1")
	if cleanup == nil {
		t.Fatal("失败时也要返回可调用的 cleanup")
	}
	cleanup()
}

// TestTCPDNSReplyConn_WritesLengthPrefixedFramesInOnePiece 钉住两件事:
//  1. 长度前缀是大端的载荷长度,且**长度+载荷一次写出** —— 分两次写一旦中间失败就留下「长度已宣告、载荷缺失」
//     的半帧,这条连接上后续所有查询全部错位;
//  2. 返回的字节数是**DNS 载荷**长度,不含前缀 —— 调用方(与 UDP 共用)按 WriteToUDP 语义理解这个返回值。
func TestTCPDNSReplyConn_WritesLengthPrefixedFramesInOnePiece(t *testing.T) {
	srv, cli := net.Pipe()
	t.Cleanup(func() { _ = srv.Close(); _ = cli.Close() })

	payload := []byte("hello-dns-payload")
	type res struct {
		n   int
		err error
	}
	done := make(chan res, 1)
	go func() {
		w := &tcpDNSReplyConn{conn: srv}
		n, err := w.WriteToUDP(payload, nil)
		done <- res{n, err}
	}()

	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	var lenBuf [2]byte
	if _, err := io.ReadFull(cli, lenBuf[:]); err != nil {
		t.Fatalf("读长度前缀: %v", err)
	}
	if got := int(binary.BigEndian.Uint16(lenBuf[:])); got != len(payload) {
		t.Fatalf("长度前缀应为 %d,got %d", len(payload), got)
	}
	body := make([]byte, len(payload))
	if _, err := io.ReadFull(cli, body); err != nil {
		t.Fatalf("读载荷: %v", err)
	}
	if string(body) != string(payload) {
		t.Fatalf("载荷不符: %q", body)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("写失败: %v", r.err)
	}
	if r.n != len(payload) {
		t.Fatalf("返回字节数应是 DNS 载荷长度 %d(不含 2 字节前缀),got %d", len(payload), r.n)
	}
}

// TestTCPDNSReplyConn_RefusesRepliesTooLongToFrame:长度前缀只有 16 位,超过 65535 的应答无法表达。
// 此时必须**报错不发**:发一个「长度字段与实际不符」的帧会让对端连接彻底错位,比不发严重得多。
// (上游给不出这么大的 DNS 应答,出现即说明链路异常。)
func TestTCPDNSReplyConn_RefusesRepliesTooLongToFrame(t *testing.T) {
	srv, cli := net.Pipe()
	t.Cleanup(func() { _ = srv.Close(); _ = cli.Close() })
	go func() { _, _ = io.Copy(io.Discard, cli) }()

	w := &tcpDNSReplyConn{conn: srv}
	if _, err := w.WriteToUDP(make([]byte, 0x10000), nil); err == nil {
		t.Fatal("超过 65535 的应答必须报错,不能发出一个长度字段对不上的帧")
	}
}

// startFakeUpstreamTCP 在 127.0.0.1:port 上起一个只说 DNS-over-TCP 的假上游(长度前缀成帧)。
// port 用调用方从 startFakeUpstream 拿到的同一个端口号 —— UDP 与 TCP 端口空间独立,同号可共存,
// 于是同一个 upstream 地址串既能被 UDP 问也能被 TCP 问,正是真实上游的样子。
func startFakeUpstreamTCP(t *testing.T, port int, reply func(query []byte) []byte) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatalf("假上游 TCP 监听 %d: %v", port, err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		defer close(done)
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var lenBuf [2]byte
				if _, rerr := io.ReadFull(c, lenBuf[:]); rerr != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
				if _, rerr := io.ReadFull(c, q); rerr != nil {
					return
				}
				out := reply(q)
				if out == nil {
					return
				}
				frame := make([]byte, 2+len(out))
				binary.BigEndian.PutUint16(frame[:2], uint16(len(out)))
				copy(frame[2:], out)
				_, _ = c.Write(frame)
			}()
		}
	}()
}

// buildTCReply 造一份「TC=1、没有 answer」的应答 —— 上游那边也装不下时给出的东西。
func buildTCReply(t *testing.T, query []byte) []byte {
	t.Helper()
	id, q, ok := parseDNSQueryKey(query)
	if !ok {
		t.Fatal("查询解析不出 key")
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, Response: true, Truncated: true},
		Questions: []dnsmessage.Question{q},
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestQueryUpstreamOnce_RetriesOverTCPWhenTheUpstreamTruncates:上游回 TC=1 时必须改用 TCP 向同一上游重查。
//
// 少了这一步,那份**残缺**应答会被原样转给使用方,而且:
//   - 走 TCP 来问我们的使用方(它正是因为 UDP 被截断才改的 TCP)会再拿到一次 TC → 彻底无解;
//   - 上游应答缓存还会把这份残缺答案存下来,喂给之后所有人。
func TestQueryUpstreamOnce_RetriesOverTCPWhenTheUpstreamTruncates(t *testing.T) {
	query := buildDNSQuery(t, "big.example.com", dnsmessage.TypeA)
	addr, udpHits := startFakeUpstream(t, func(q []byte) [][]byte {
		return [][]byte{buildTCReply(t, q)}
	})
	port := mustPortOf(t, addr)
	var tcpHits int
	startFakeUpstreamTCP(t, port, func(q []byte) []byte {
		tcpHits++
		full, err := buildReply(q, "93.184.216.34", 300)
		if err != nil {
			return nil
		}
		return full
	})

	before := magicDNSUpstreamTCPRetryCount.Load()
	resp, ok := queryUpstreamOnce(t.Context(), query, magicDNSResolved{suffix: "lan", upstream: []string{addr}})
	if !ok {
		t.Fatal("应拿到应答")
	}
	if dnsReplyTruncated(resp) {
		t.Fatal("重查之后返回的应答不该还带 TC —— 说明没走 TCP 重查")
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("应拿到 TCP 那边的完整答案(1 条 A),got %d 条", len(m.Answers))
	}
	if udpHits.Load() != 1 {
		t.Fatalf("UDP 应先问一次,got %d", udpHits.Load())
	}
	if tcpHits != 1 {
		t.Fatalf("TCP 应重查一次,got %d", tcpHits)
	}
	if got := magicDNSUpstreamTCPRetryCount.Load(); got != before+1 {
		t.Fatalf("TCP 重查要记数(便于发现上游 EDNS 缓冲区偏小),before=%d after=%d", before, got)
	}
}

// TestQueryUpstreamOnce_KeepsTheTruncatedReplyWhenTCPRetryFails:TCP 重查失败(上游不听 TCP / 超时)时
// 仍把那份 TC 应答转出去,不要升级成 SERVFAIL。
//
// 「有记录但太大」比「解析坏了」更接近事实:使用方看到 TC 至少会自己再走一次 TCP;回 SERVFAIL 则会让
// 它把这个解析器整体标记为不可用,连本来正常的域名一起受累。
func TestQueryUpstreamOnce_KeepsTheTruncatedReplyWhenTCPRetryFails(t *testing.T) {
	query := buildDNSQuery(t, "big.example.com", dnsmessage.TypeA)
	addr, _ := startFakeUpstream(t, func(q []byte) [][]byte {
		return [][]byte{buildTCReply(t, q)}
	})
	// 故意不起 TCP 假上游 → 重查必然失败。
	resp, ok := queryUpstreamOnce(t.Context(), query, magicDNSResolved{suffix: "lan", upstream: []string{addr}})
	if !ok {
		t.Fatal("TCP 重查失败也要把 UDP 那份应答转出去,不能整体判失败")
	}
	if !dnsReplyTruncated(resp) {
		t.Fatal("转出去的应该就是上游那份 TC 应答")
	}
}

// TestDialAndQueryTCP_RejectsRepliesThatDoNotMatchTheQuery:TCP 握手能排除盲注,但「上游把别人的应答串给
// 我们」这类实现缺陷仍在,而这份答案会进缓存喂给后续所有使用方 —— 代价太大,必须同 UDP 路径一样校验
// TXID + question。
func TestDialAndQueryTCP_RejectsRepliesThatDoNotMatchTheQuery(t *testing.T) {
	query := buildDNSQueryID(t, "a.example.com", dnsmessage.TypeA, 0x1111)
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	// 应答的 TXID 与查询差 1,其余一模一样 —— 只有校验 TXID 才能识破。
	startFakeUpstreamTCP(t, port, func(q []byte) []byte {
		spoof, serr := buildSpoofReply(q, "1.2.3.4")
		if serr != nil {
			return nil
		}
		return spoof
	})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if _, err := dialAndQueryTCP(t.Context(), addr, query, magicDNSUpstreamTCPTimeout); err == nil {
		t.Fatal("TXID 不符的应答必须被拒,不能当成正常答案(它会进缓存)")
	}
}

// TestDnsReplyTruncated_ReadsTheTCBit:TC 位是 flags 高字节的 0x02。读错位(比如去读 AA / RD)会让整个
// 「上游截断 → TCP 重查」的判断彻底失灵,而失灵是静默的。
func TestDnsReplyTruncated_ReadsTheTCBit(t *testing.T) {
	query := buildDNSQuery(t, "x.example.com", dnsmessage.TypeA)
	if !dnsReplyTruncated(buildTCReply(t, query)) {
		t.Fatal("TC=1 的应答必须被识别")
	}
	full, err := buildReply(query, "1.2.3.4", 300)
	if err != nil {
		t.Fatal(err)
	}
	if dnsReplyTruncated(full) {
		t.Fatal("普通应答不该被判成截断(否则每条应答都会多一次 TCP 重查)")
	}
	// 短于头部的碎片:判 false,交由后续解析各自处置,不能 panic 在索引上。
	if dnsReplyTruncated([]byte{0x00}) {
		t.Fatal("残包应判 false")
	}
}

func mustPortOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestMagicDNSPeerFromTCP_CarriesIPAndPortAcross:既有的 ACL / 组网隔离 / 限流 / ECS 会话查找全按
// 「使用方 vIP」判断。TCP 对端必须被如实翻译成等价的 *net.UDPAddr,否则这些策略在 TCP 上会看到错的
// 客户端 —— 那等于开了一条绕过 ACL 的旁路。
func TestMagicDNSPeerFromTCP_CarriesIPAndPortAcross(t *testing.T) {
	in := &net.TCPAddr{IP: net.ParseIP("100.64.0.7"), Port: 5300}
	got := magicDNSPeerFromTCP(in)
	if got == nil {
		t.Fatal("合法 TCP 地址必须能翻译")
	}
	if !got.IP.Equal(in.IP) || got.Port != in.Port {
		t.Fatalf("IP/端口必须原样搬运,got %s", got.String())
	}
	// 非 TCPAddr / 无 IP → nil,调用方放弃该连接(而不是拿一个零值地址去过 ACL)。
	if magicDNSPeerFromTCP(&net.UDPAddr{IP: net.ParseIP("100.64.0.7")}) != nil {
		t.Fatal("非 *net.TCPAddr 必须返回 nil")
	}
	if magicDNSPeerFromTCP(&net.TCPAddr{Port: 53}) != nil {
		t.Fatal("无 IP 的地址必须返回 nil")
	}
}
