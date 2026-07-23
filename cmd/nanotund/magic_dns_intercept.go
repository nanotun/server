package main

// 数据面 :53 拦截（2026-07-17）：绑定出口会话「直发公共 resolver」的 DNS 查询接管。
//
// 问题：MagicDNS 只拦得住「发往网关」的查询。server 下发的 DNS 列表里网关之后还有公共 resolver 兜底
// （8.8.8.8 / 114.114.114.114 等），且用户也可能手配公共 DNS——这些查询以**普通数据包**（UDP :53）经
// forwardPacketToExitNode 原样转发给出口，由出口内核 DNAT 解析后原路回包，完全绕过 MagicDNS：
//   1. AAAA 不被剥离：v4-only 出口下客户端拿到真 AAAA → 发起公网 v6 连接 → 数据面 dropped_no_v6 →
//      Happy Eyeballs 干等（实测 iOS 会话 5836 个 v6 包被丢的来源）；
//   2. 经出口解析的加速层（缓存 + 单飞）也吃不到。
//
// 修法：在 forwardPacketToExitNode 里认出「IPv4 UDP dst:53 的 DNS 查询」，不再原样转发，改走与网关路径
// 同一套「经出口解析」机器（resolveExitDNSAddrsCached / resolveExitDNSRawCached，共享缓存 + 单飞 +
// in-flight 限流），并把应答**伪装成原 resolver 的回包**（src=原目的 IP:53 → dst=客户端 vIP:原源端口）
// 注入客户端 TunChan——客户端 stub 无感知。v4-only 出口的 AAAA 就地回 NODATA（与网关路径一致）。
//
// 语义不变性：出口两种实现（OpenWrt 内核 DNAT / exit_forward.rs udp_relay）本就对**任意目的**的 :53 全量
// 接管、由出口本地解析——客户端查 8.8.8.8 实际也是出口 ISP DNS 作答。本拦截只是把同一件事挪到 server 侧做，
// 顺带补上 AAAA 剥离与缓存，不改变「答案反映出口地理」的既有语义。
//
// 边界：
//   - 只拦 IPv4 UDP（v6 DNS 在 v4-only 出口早被 ICMPv6 fast-fail 掐掉；v6-capable 出口的 v6 DNS 照旧转发）；
//   - TCP :53（极少）照旧转发，出口 DNAT 兜底；
//   - in-flight 限流满 → 不拦截、照旧转发（DNS 不断，只丢一次 AAAA 剥离/缓存的机会）；
//   - 绝不阻塞数据面 readLoop：冷路径（要经出口往返，最多 exitDNSWaitTimeout）拷贝查询字节后丢给 goroutine。

import (
	"net/netip"
	"sync/atomic"

	"golang.org/x/net/dns/dnsmessage"
)

// magicDNSInterceptCount：被本路径拦截接管的 UDP :53 查询数（观测用，供 /status 汇总）。
var magicDNSInterceptCount atomic.Uint64

// interceptExitBoundDNSQuery 尝试把绑定出口会话 c 的一个数据面包当 DNS 查询接管。调用方（forwardPacketToExitNode）
// 已确认：egress 已绑定、exitConn 在跑、目的非 mesh 本地、UDP 且 dstPort==53。
// 返回 true = 已接管（应答会同步或异步注入 c 的 TunChan），调用方不再转发本包；false = 不是可接管的 DNS 查询
// （非 IPv4 / 非查询帧 / 解析失败 / 限流满），调用方照旧原样转发给出口。
func interceptExitBoundDNSQuery(c *Connection, exitConn *Connection, egress int64, payload []byte) bool {
	srcIP, dstIP, srcPort, dstPort, udp, ok := parseIPv4UDPForReturn(payload)
	if !ok || dstPort != 53 || srcPort == 0 {
		return false
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(udp)
	if err != nil || hdr.Response {
		return false // 非 DNS / 是应答帧（如客户端本机跑 DNS 服务的回包）→ 不接管
	}
	q, err := p.Question()
	if err != nil || q.Class != dnsmessage.ClassINET {
		return false
	}
	magicDNSInterceptCount.Add(1)

	// v4-only 出口的 AAAA：就地回 NODATA（与网关路径 tryResolvePublicViaExit 的 strip 分支同语义）——
	// 这正是本拦截要堵的头号漏洞：直查 8.8.8.8 拿到真 AAAA → 公网 v6 连接被数据面丢弃 → Happy Eyeballs 卡顿。
	if q.Type == dnsmessage.TypeAAAA && !exitConn.advertisedExitV6.Load() {
		if resp, berr := buildMagicDNSAnswer(hdr.ID, q, nil); berr == nil {
			injectDNSReplyToClient(c, dstIP, srcIP, srcPort, resp)
		}
		magicDNSAAAAStripCount.Add(1)
		return true
	}

	key := exitDNSCacheKey(egress, q.Type, normalizeQName(q))
	// 缓存命中：同步构应答并注入（无阻塞调用，不占 in-flight 位）。与网关路径共享同一张缓存表——
	// 两条路径互相暖缓存。
	if e, hit := exitDNSCacheGet(key); hit {
		if resp := buildInterceptDNSResponse(hdr.ID, q, udp, e); resp != nil {
			injectDNSReplyToClient(c, dstIP, srcIP, srcPort, resp)
		}
		magicDNSExitCacheHitCount.Add(1)
		return true
	}

	// 缓存冷：要经出口往返（最多 exitDNSWaitTimeout），绝不能在数据面 readLoop 上等 → 限流 + 异步。
	// 限流键 = 客户端 vIP，与网关路径共享同一份 per-client 预算。
	release, acquired := tryAcquireMagicDNSSlot(srcIP, true)
	if !acquired {
		return false // 限流满 → 不接管，照旧原样转发（出口 DNAT 兜底，DNS 不断）
	}
	// payload/udp 底层是链路读缓冲，本函数返回后即被复用 —— 拷出独立的查询字节供 goroutine 使用。
	query := make([]byte, len(udp))
	copy(query, udp)
	qid := hdr.ID
	// 第八轮深扫 LOW:经出口 DNS 截获的 per-query goroutine 同样必须走 safeGoroutine,任何 panic 只 recover 不掀进程
	// (与 magic_dns.go 网关路径一致)。release 内层 defer,panic 时先归还在途配额再被 recover。
	go safeGoroutine("magic_dns_intercept", func() {
		defer release()
		var e exitDNSCacheEntry
		var rok bool
		if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA {
			e, rok = resolveExitDNSAddrsCached(key, exitConn, query)
		} else {
			e, rok = resolveExitDNSRawCached(key, exitConn, query)
		}
		if !rok {
			// 经出口失败 → SERVFAIL（与网关路径的 fail-closed 语义一致：绝不回 server 地理的答案，客户端重试）。
			magicDNSExitServfailCount.Add(1)
			if resp := buildMagicDNSStatusBytes(qid, dnsmessage.RCodeServerFailure, q); resp != nil {
				injectDNSReplyToClient(c, dstIP, srcIP, srcPort, resp)
			}
			return
		}
		if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA {
			magicDNSViaExitCount.Add(1)
		} else {
			magicDNSViaExitRelayCount.Add(1)
		}
		if resp := buildInterceptDNSResponse(qid, q, query, e); resp != nil {
			injectDNSReplyToClient(c, dstIP, srcIP, srcPort, resp)
		}
	})
	return true
}

// buildInterceptDNSResponse 按缓存项类型构造应答字节：raw 项（HTTPS/SVCB 等）就地改写 txn id + question；
// addrs 项（A/AAAA）用当前 qid/question 重建；否定 rcode 回状态帧。构造失败退化 SERVFAIL（不静默吞包）。
func buildInterceptDNSResponse(qid uint16, q dnsmessage.Question, query []byte, e exitDNSCacheEntry) []byte {
	if e.raw != nil {
		if out := buildRawDNSResponseFor(query, qid, e.raw); out != nil {
			return out
		}
		return buildMagicDNSStatusBytes(qid, dnsmessage.RCodeServerFailure, q)
	}
	if e.rcode == dnsmessage.RCodeSuccess {
		if resp, err := buildMagicDNSAnswer(qid, q, e.addrs); err == nil {
			return resp
		}
		return buildMagicDNSStatusBytes(qid, dnsmessage.RCodeServerFailure, q)
	}
	return buildMagicDNSStatusBytes(qid, e.rcode, q)
}

// injectDNSReplyToClient 把 DNS 应答伪装成「原 resolver 的回包」（src=原目的 IP:53 → dst=客户端 vIP:原源端口）
// 注入客户端会话的 TunChan。best-effort：构包失败 / 通道满即丢（客户端 stub 自会重试），绝不阻塞。
func injectDNSReplyToClient(c *Connection, fromResolver, clientVIP netip.Addr, clientPort uint16, dnsResp []byte) {
	pkt, ok := buildIPv4UDP(fromResolver, 53, clientVIP, clientPort, dnsResp)
	if !ok || len(pkt) > tunBufSize {
		return
	}
	deliverIPPacketToConn(c, pkt)
}
