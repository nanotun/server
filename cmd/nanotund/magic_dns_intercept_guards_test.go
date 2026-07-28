package main

// 数据面 :53 拦截的拒绝面。
//
// 这条路径与别处不同:它**从数据面手里抢包**。判错的方向有两个,代价不对称:
//
//   - 该拦的没拦(返 false):包照旧转发给出口,由出口本地 resolver 作答 —— 只是丢一次
//     AAAA 剥离和缓存的机会,DNS 不断。这是安全的失败方向,所以限流满、解析不出、
//     非 DNS 查询帧一律走这边。
//   - 不该拦的拦了(返 true 而没安排应答):客户端的包被**吞掉**,它只能等到 stub
//     resolver 超时。所以返 true 的每条路径都必须真的安排了一帧应答。
//
// 这里钉的是第一类的判据(什么不该接管)与 buildInterceptDNSResponse 的四条构造分支
// —— 后者是「返了 true 之后到底回了什么」的唯一出口。

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestInterceptExitBoundDNSQuery_NotTakenOverPaths 逐条钉「不接管」。
//
// 每条都断言两件事:返回 false,且**没有**记进 magicDNSInterceptCount —— 计数记错了,
// /status 上「拦截了多少」这个数就不能用来判断这条路径有没有在工作。
func TestInterceptExitBoundDNSQuery_NotTakenOverPaths(t *testing.T) {
	client, clientTun, exitTun, clientVIP := interceptTestEnv(t, 77, true)
	exitConn := lookupRunningExitConnByDevice(77)
	if exitConn == nil {
		t.Fatal("前置条件:出口会话应当在跑")
	}
	resolver := netip.MustParseAddr("8.8.8.8")
	query := buildDNSQuery(t, "example.com", dnsmessage.TypeA)

	cases := map[string][]byte{
		"不是 IPv4 UDP(载荷根本不是包)": {0x60, 0x00, 0x00},
		"目的端口不是 53": func() []byte {
			pkt, ok := buildIPv4UDP(clientVIP, 40000, resolver, 5353, query)
			if !ok {
				t.Fatal("构包失败")
			}
			return pkt
		}(),
		"源端口为 0":   mkClientDNSPacket(t, clientVIP, 0, resolver, query),
		"载荷不是 DNS": mkClientDNSPacket(t, clientVIP, 40000, resolver, []byte{0x01, 0x02, 0x03}),
		"是 DNS 应答帧而不是查询": func() []byte {
			// 客户端本机跑了 DNS 服务、它的回包也是 UDP 源自 :53 之外……这里造的是
			// 一个 QR=1 的帧:接管它没有意义,而且会把一个正常的应答吞掉。
			body := make([]byte, 12)
			body[2] = 0x80 // QR=1
			return mkClientDNSPacket(t, clientVIP, 40000, resolver, body)
		}(),
		"没有 question 段": func() []byte {
			body := make([]byte, 12) // 只有 header,QDCOUNT=0
			return mkClientDNSPacket(t, clientVIP, 40000, resolver, body)
		}(),
		"question 的 class 不是 INET": mkClientDNSPacket(t, clientVIP, 40000, resolver,
			buildDNSQueryFull(t, "example.com", dnsmessage.TypeA, dnsmessage.ClassCHAOS)),
	}

	for name, pkt := range cases {
		t.Run(name, func(t *testing.T) {
			before := magicDNSInterceptCount.Load()
			if interceptExitBoundDNSQuery(client, exitConn, 77, pkt) {
				t.Fatal("这种包不该被接管 —— 接管了就要负责作答,否则客户端只能等超时")
			}
			if magicDNSInterceptCount.Load() != before {
				t.Fatal("没接管却记了拦截计数 —— /status 上这个数就不能用来判断本路径是否在工作")
			}
			// 也不该有任何注入或转发副作用。
			select {
			case <-clientTun:
				t.Fatal("不该往客户端注入任何包")
			case <-exitTun:
				t.Fatal("本函数不负责转发,不该往出口写包")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// TestInterceptExitBoundDNSQuery_RateLimitFallsThrough 限流满时必须**不接管**(返 false),
// 让调用方照旧把包转发给出口 —— 出口 DNAT 会兜住,DNS 不断。
//
// 反面(返 true 而没安排应答)会把客户端的查询直接吞掉:突发流量下表现成 DNS 大面积超时,
// 而正是突发流量才会打满限流。方向错了会把「降级」变成「故障放大」。
func TestInterceptExitBoundDNSQuery_RateLimitFallsThrough(t *testing.T) {
	client, clientTun, _, clientVIP := interceptTestEnv(t, 78, true)
	exitConn := lookupRunningExitConnByDevice(78)
	if exitConn == nil {
		t.Fatal("前置条件:出口会话应当在跑")
	}

	// 占满全局 in-flight 池:tryAcquireMagicDNSSlot 会在第一步就失败。
	var held []func()
	t.Cleanup(func() {
		for _, rel := range held {
			rel()
		}
	})
	for {
		release, ok := tryAcquireMagicDNSSlot(clientVIP, false)
		if !ok {
			break
		}
		held = append(held, release)
		if len(held) > 4096 {
			t.Fatal("in-flight 池似乎没有上限,占不满")
		}
	}

	pkt := mkClientDNSPacket(t, clientVIP, 40000, netip.MustParseAddr("8.8.8.8"),
		buildDNSQuery(t, "example.com", dnsmessage.TypeA))
	if interceptExitBoundDNSQuery(client, exitConn, 78, pkt) {
		t.Fatal("限流满时必须返回 false 照旧转发,不能接管后又不作答 —— " +
			"那会把突发期的 DNS 全部吞掉")
	}
	select {
	case <-clientTun:
		t.Fatal("限流满时不该注入任何应答")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestBuildInterceptDNSResponse_AllFourShapes 钉住应答构造的四条分支。这个函数是「已接管」
// 之后唯一的出口:任何一条返回 nil 都等于把客户端的查询吞掉。
func TestBuildInterceptDNSResponse_AllFourShapes(t *testing.T) {
	query := buildDNSQueryFull(t, "example.com", dnsmessage.TypeHTTPS, dnsmessage.ClassINET)
	_, q, ok := parseDNSQueryKey(query)
	if !ok {
		t.Fatal("前置条件:查询应当解析出 question")
	}

	t.Run("raw 项就地改写", func(t *testing.T) {
		cached := mkRawResp(t, 0x1111, "example.com.", dnsmessage.TypeHTTPS, 60, 1)
		out := buildInterceptDNSResponse(0x7777, q, query, exitDNSCacheEntry{
			raw: cached, rcode: dnsmessage.RCodeSuccess,
		})
		if out == nil {
			t.Fatal("raw 项应当能改写出应答")
		}
		var p dnsmessage.Parser
		hdr, err := p.Start(out)
		if err != nil {
			t.Fatalf("产出的应答解析不了: %v", err)
		}
		if hdr.ID != 0x7777 {
			t.Fatalf("txn id = %#x, want 0x7777", hdr.ID)
		}
	})

	t.Run("raw 项改写失败退 SERVFAIL", func(t *testing.T) {
		// question 段长度不匹配 → buildRawDNSResponseFor 返 nil。此时**必须**回一帧
		// SERVFAIL,不能返 nil:返 nil 客户端就只能等超时,而 SERVFAIL 它会立刻重试。
		out := buildInterceptDNSResponse(0x7777, q, query, exitDNSCacheEntry{
			raw: mkRawResp(t, 1, "a.io.", dnsmessage.TypeHTTPS, 60, 1), rcode: dnsmessage.RCodeSuccess,
		})
		if out == nil {
			t.Fatal("改写失败也必须回一帧 SERVFAIL,不能静默吞包")
		}
		var p dnsmessage.Parser
		hdr, err := p.Start(out)
		if err != nil {
			t.Fatal(err)
		}
		if hdr.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("rcode = %v, want SERVFAIL", hdr.RCode)
		}
	})

	t.Run("addrs 项重建应答", func(t *testing.T) {
		aq := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
		_, aQuestion, _ := parseDNSQueryKey(aq)
		out := buildInterceptDNSResponse(0x8888, aQuestion, aq, exitDNSCacheEntry{
			rcode: dnsmessage.RCodeSuccess,
			addrs: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		})
		if out == nil {
			t.Fatal("addrs 项应当能重建应答")
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(out); err != nil {
			t.Fatalf("Unpack: %v", err)
		}
		if msg.Header.ID != 0x8888 || len(msg.Answers) != 1 {
			t.Fatalf("id=%#x answers=%d", msg.Header.ID, len(msg.Answers))
		}
	})

	t.Run("否定 rcode 原样回", func(t *testing.T) {
		// NXDOMAIN 必须原样回,不能被折成 SERVFAIL:前者是「这个名字确定不存在」,
		// 客户端会缓存并停止重试;后者是软失败,客户端会一直重试同一个不存在的名字。
		out := buildInterceptDNSResponse(0x9999, q, query, exitDNSCacheEntry{
			rcode: dnsmessage.RCodeNameError,
		})
		if out == nil {
			t.Fatal("否定答复也要回一帧")
		}
		var p dnsmessage.Parser
		hdr, err := p.Start(out)
		if err != nil {
			t.Fatal(err)
		}
		if hdr.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("rcode = %v, want NXDOMAIN(不能折成 SERVFAIL:那会让客户端反复重试)", hdr.RCode)
		}
	})
}

// TestInjectDNSReplyToClient_RefusesOversize 注入前的两道门:构包失败、包超过 TUN 缓冲。
// 超长包塞进 TunChan 会让对端按 tunBufSize 读到半个包。
func TestInjectDNSReplyToClient_RefusesOversize(t *testing.T) {
	client, clientTun, _, clientVIP := interceptTestEnv(t, 79, true)
	resolver := netip.MustParseAddr("8.8.8.8")

	// 超过 tunBufSize 的应答:不注入。
	injectDNSReplyToClient(client, resolver, clientVIP, 40000, make([]byte, tunBufSize+1))
	select {
	case <-clientTun:
		t.Fatal("超长应答不该被注入 —— 对端按 tunBufSize 读会拿到半个包")
	case <-time.After(50 * time.Millisecond):
	}

	// 构包失败(伪装源是 v6 地址,buildIPv4UDP 会拒):同样不注入,且不 panic。
	injectDNSReplyToClient(client, netip.MustParseAddr("fd00::1"), clientVIP, 40000, []byte{1, 2, 3})
	select {
	case <-clientTun:
		t.Fatal("构包失败时不该注入")
	case <-time.After(50 * time.Millisecond):
	}

	// 反面对照:正常大小的应答必须注入,否则上面两条可以由「什么都不注入」满足。
	injectDNSReplyToClient(client, resolver, clientVIP, 40000, make([]byte, 64))
	pkt := recvTunPacket(t, clientTun, "正常大小的注入应答")
	src, dst, sp, dp, _, ok := parseIPv4UDPForReturn(pkt)
	if !ok {
		t.Fatal("注入的包应当是合法 IPv4 UDP")
	}
	// 伪装方向必须是「原 resolver:53 → 客户端 vIP:原源端口」,客户端 stub 才认。
	if src != resolver || sp != 53 {
		t.Fatalf("源应伪装成 %v:53, got %v:%d", resolver, src, sp)
	}
	if dst != clientVIP || dp != 40000 {
		t.Fatalf("目的应是 %v:40000, got %v:%d", clientVIP, dst, dp)
	}
}
