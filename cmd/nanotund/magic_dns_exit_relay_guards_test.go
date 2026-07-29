package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// 经出口解析这条路的失效方式不是「查不到」,而是**悄悄回退成 server 本地上游的答案**。
//
// 一个绑了 peer 出口的会话,它的公网流量全从出口走。若 DNS 却由 server 本地解析,CDN 会按
// server 的地理位置给边缘节点 —— 那些节点对出口而言可能是烂路由甚至根本不可达,而客户端 OS
// 已经把这份答案缓存起来了,换回直连之后还要继续误导它一段。所以整段代码的口径是:**一旦确定
// 这条会话绑了出口,就必须由出口作答;出口给不出答案就 SERVFAIL**,不许拿 server 的答案顶上。
//
// 这些失败分支平时不出现(出口在线、应答正常),真出现时又只表现为「有些网站慢」,所以必须逐条钉住。

// readbackFrom 从 UDP 连接上读一帧并解析出 DNS 头。
func readbackFrom(t *testing.T, c *net.UDPConn, wait time.Duration) (dnsmessage.Header, bool) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 1500)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return dnsmessage.Header{}, false
	}
	var p dnsmessage.Parser
	hdr, perr := p.Start(buf[:n])
	if perr != nil {
		return dnsmessage.Header{}, false
	}
	return hdr, true
}

// TestExitDNS_UnusableExitAnswerIsServfailAndNeverCached 出口给不出可用答案时的三种情形。
//
// 三条都必须:回 SERVFAIL、报告「已由本路径作答」(返回 true,调用方不许再走本地上游)、且**不落缓存**。
// 缓存是全 egress 共享的,把一份解析不出来的应答记进去,受害面是这台出口上所有客户端。
func TestExitDNS_UnusableExitAnswerIsServfailAndNeverCached(t *testing.T) {
	const qname = "cdn.example.com"

	cases := []struct {
		name  string
		qtype dnsmessage.Type
		// call 发起一次查询(A/AAAA 走解析路径,HTTPS 走原样中继路径)。
		call func(d *exitDNSDrive, q dnsmessage.Question, query []byte) bool
	}{
		{
			name:  "A 查询:答复区截断",
			qtype: dnsmessage.TypeA,
			call: func(d *exitDNSDrive, q dnsmessage.Question, query []byte) bool {
				return tryResolvePublicViaExit(d.srv, d.peer, query, q, 0x4242)
			},
		},
		{
			name:  "HTTPS 查询:答复区截断",
			qtype: dnsmessage.TypeHTTPS,
			call: func(d *exitDNSDrive, q dnsmessage.Question, query []byte) bool {
				return tryRelayPublicViaExit(d.srv, d.peer, query, q, 0x4242)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newExitDNSDrive(t)
			q := dnsmessage.Question{
				Name:  dnsmessage.MustNewName(qname + "."),
				Type:  tc.qtype,
				Class: dnsmessage.ClassINET,
			}
			query := buildDNSQueryFull(t, qname, tc.qtype, dnsmessage.ClassINET)

			done := make(chan bool, 1)
			go func() { done <- tc.call(d, q, query) }()

			corrPort := d.awaitInjectedQuery(t)
			// 头与 question 都对得上(过得了投递侧的绑定校验),但答复区被截断 ——
			// 只有真正去解析答复区的那一步才会发现。
			full := mkRawResp(t, 0x4242, qname+".", tc.qtype, 300, 1)
			respPkt, ok := buildIPv4UDP(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 53, d.gw, corrPort, full[:len(full)-6])
			if !ok {
				t.Fatal("构造出口回包失败")
			}
			if !interceptExitDNSResponseIfPending(d.exit, respPkt) {
				t.Fatal("这份包在端口 / 会话 / TXID 上都是正主,投递本身应当成功")
			}

			select {
			case handled := <-done:
				if !handled {
					t.Fatal("解析不出来时返回了 false —— 调用方会拿 server 本地上游的地理答案顶上")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("超时:没等到判定")
			}
			hdr, got := readbackFrom(t, d.cli, time.Second)
			if !got {
				t.Fatal("客户端什么都没收到 —— 它只能干等到自己超时")
			}
			if hdr.RCode != dnsmessage.RCodeServerFailure {
				t.Fatalf("rcode = %v, want SERVFAIL", hdr.RCode)
			}
			if _, hit := exitDNSCacheGet(exitDNSCacheKey(d.exitDev, tc.qtype, normalizeQName(q))); hit {
				t.Error("解析不出来的应答落进了全 egress 共享缓存")
			}
		})
	}

	t.Run("server 没有 v4 网关时不投递也不回退", func(t *testing.T) {
		d := newExitDNSDrive(t)
		// 纯 v6 部署:构不出那条 IPv4+UDP 的注入包。
		serverGatewayAddrs.Store(nil)

		q := dnsmessage.Question{
			Name:  dnsmessage.MustNewName(qname + "."),
			Type:  dnsmessage.TypeHTTPS,
			Class: dnsmessage.ClassINET,
		}
		query := buildDNSQueryFull(t, qname, dnsmessage.TypeHTTPS, dnsmessage.ClassINET)
		if !tryRelayPublicViaExit(d.srv, d.peer, query, q, 0x4242) {
			t.Fatal("注入不出去时返回了 false —— 会退回 server 本地上游解析")
		}
		hdr, got := readbackFrom(t, d.cli, time.Second)
		if !got || hdr.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("应就地 SERVFAIL, got=%v ok=%v", hdr.RCode, got)
		}
		if len(d.exitTun) != 0 {
			t.Error("构不出包却往出口投了东西")
		}
	})

	t.Run("出口迟迟不作答", func(t *testing.T) {
		d := newExitDNSDrive(t)
		q := dnsmessage.Question{
			Name:  dnsmessage.MustNewName(qname + "."),
			Type:  dnsmessage.TypeHTTPS,
			Class: dnsmessage.ClassINET,
		}
		query := buildDNSQueryFull(t, qname, dnsmessage.TypeHTTPS, dnsmessage.ClassINET)

		done := make(chan bool, 1)
		go func() { done <- tryRelayPublicViaExit(d.srv, d.peer, query, q, 0x4242) }()
		d.awaitInjectedQuery(t) // 查询确实注入了,但我们不喂回包

		select {
		case handled := <-done:
			if !handled {
				t.Fatal("超时后返回了 false —— 又变成 server 本地上游作答")
			}
		case <-time.After(exitDNSWaitTimeout + 3*time.Second):
			t.Fatal("等待超时上限没有生效,这一条会一直挂着")
		}
		hdr, got := readbackFrom(t, d.cli, time.Second)
		if !got || hdr.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("应回 SERVFAIL, got=%v ok=%v", hdr.RCode, got)
		}
	})
}

// TestHandleMagicDNSPacket_RoutesHTTPSAndSVCBThroughTheExitToo HTTPS/SVCB 也必须走出口。
//
// 浏览器现在对每个站点并发查 A/AAAA 与 HTTPS(65)/SVCB(64),而 HTTPS RR 里的 ipv4hint/ipv6hint
// 同样被 CDN 按解析位置就近下发。只把 A/AAAA 引到出口、让 HTTPS 走 server 本地上游,等于留了
// 一条同病的旁路 —— 浏览器优先用 hint 直连,结果还是 server 地理的边缘节点。
func TestHandleMagicDNSPacket_RoutesHTTPSAndSVCBThroughTheExitToo(t *testing.T) {
	gw := newMagicDNSGateway(t)
	// upstream 为空:若这条查询没被引到出口,就只能落到「无上游 → NOTIMP」。两个 rcode 正好把
	// 「引到出口了」和「漏给本地上游了」分开。
	r := magicDNSResolved{suffix: "nanotun.net", port: 53}

	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeHTTPS, dnsmessage.TypeSVCB} {
		t.Run(qtype.String(), func(t *testing.T) {
			resetConnByDeviceForTest(t)
			resetExitDNSCacheForTest(t)
			// 会话绑了出口但兑现不了 → 经出口路径就地 SERVFAIL。
			registerFailClosedConn(t, "127.0.0.1", egressFailClosed)

			query := buildDNSQueryFull(t, "cdn.example.com", qtype, dnsmessage.ClassINET)
			mustRCode(t, gw, r, query, dnsmessage.RCodeServerFailure)
		})
	}

	t.Run("没有就近语义的类型仍走原路", func(t *testing.T) {
		resetConnByDeviceForTest(t)
		resetExitDNSCacheForTest(t)
		registerFailClosedConn(t, "127.0.0.1", egressFailClosed)

		// MX 不存在「按解析位置就近」,没理由为它多绕一趟出口(每条最多占位
		// exitDNSWaitTimeout)。无上游 → NOTIMP。
		query := buildDNSQueryFull(t, "cdn.example.com", dnsmessage.TypeMX, dnsmessage.ClassINET)
		mustRCode(t, gw, r, query, dnsmessage.RCodeNotImplemented)
	})
}

// TestExitDNS_RefusesWhenEveryCorrelationPortIsTaken 关联端口耗尽时必须拒,而不是复用。
//
// 关联端口是「出口回包属于哪条在途查询」的唯一凭据。端口耗尽时若复用一个已占用的端口,两条查询
// 的应答就会互串 —— A 拿到 B 的答案,而两边看起来都成功了。所以这里只能拒(随后 SERVFAIL)。
func TestExitDNS_RefusesWhenEveryCorrelationPortIsTaken(t *testing.T) {
	d := newExitDNSDrive(t)

	// 把整段关联端口占满。
	blocked := make(chan []byte, 1)
	exitDNSMu.Lock()
	for p := int(exitDNSPortLo); p <= int(exitDNSPortHi); p++ {
		if _, used := exitDNSWaiters[uint16(p)]; !used {
			exitDNSWaiters[uint16(p)] = &exitDNSWaiter{ch: blocked}
		}
	}
	exitDNSMu.Unlock()
	t.Cleanup(func() {
		exitDNSMu.Lock()
		for p := int(exitDNSPortLo); p <= int(exitDNSPortHi); p++ {
			if w, ok := exitDNSWaiters[uint16(p)]; ok && w.ch == blocked {
				delete(exitDNSWaiters, uint16(p))
			}
		}
		exitDNSMu.Unlock()
	})

	if port, ok := registerExitDNSWaiter(make(chan []byte, 1), d.exit, 1, true); ok {
		t.Fatalf("端口占满仍分配出了 %d —— 两条在途查询的应答会互串", port)
	}

	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("cdn.example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	query := buildDNSQueryFull(t, "cdn.example.com", dnsmessage.TypeA, dnsmessage.ClassINET)
	if !tryResolvePublicViaExit(d.srv, d.peer, query, q, 0x4242) {
		t.Fatal("登记不上等待者时返回了 false —— 又落回 server 本地上游")
	}
	hdr, got := readbackFrom(t, d.cli, time.Second)
	if !got || hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("应就地 SERVFAIL, got=%v ok=%v", hdr.RCode, got)
	}
	if len(d.exitTun) != 0 {
		t.Error("没拿到关联端口却已经往出口投了查询 —— 回包无从对应")
	}
}

// TestExitDNS_MalformedPeerAddressFallsThrough peer 地址取不出来时交回原链路。
//
// 这里取的是发起查询那台客户端的 vIP,用来反查它选了哪个出口。地址畸形意味着「无从判断」,
// 此时返回 true 而不作答会让客户端干等到超时;正确处置是交回调用方走本地上游。
func TestExitDNS_MalformedPeerAddressFallsThrough(t *testing.T) {
	d := newExitDNSDrive(t)
	bogus := &net.UDPAddr{IP: net.IP{1, 2, 3}} // 既不是 4 字节也不是 16 字节

	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("cdn.example.com."),
		Type:  dnsmessage.TypeHTTPS,
		Class: dnsmessage.ClassINET,
	}
	query := buildDNSQueryFull(t, "cdn.example.com", dnsmessage.TypeHTTPS, dnsmessage.ClassINET)
	if tryRelayPublicViaExit(d.srv, bogus, query, q, 0x4242) {
		t.Error("peer 地址畸形时报告「已作答」,而它并没有作答 —— 客户端只能干等")
	}
	if _, ok := netipAddrFromUDP(bogus); ok {
		t.Error("3 字节的 IP 不该被当成合法地址")
	}
}
