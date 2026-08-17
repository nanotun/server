package main

// magic DNS「server 本地上游转发」路径的应答缓存 + 单飞（forwardMagicDNSToUpstream 的加速层）。
//
// 背景（真机实测 2026-08-17，重庆客户端 → 新加坡 server）：Windows 全隧道下客户端此前按 RTT 择优、
// 绕开网关 magic DNS 直用 8.8.8.8（~200ms），导致服务端 ECS 地理纠偏形同虚设；客户端侧改用 NRPT
// catch-all 把**全部**公网域名压回 magic DNS 后纠偏生效，但每条查询都要 server→上游 一次往返
// （实测 ~480ms，含 ECS 回源），比原先慢一倍多。这一层把重复查询摊平：同一网段的同一问题只回源一次。
//
// 与出口方向的 exitDNSCache（magic_dns_cache.go）**并列但互不共享**——两者的地理隔离维度不同：
//   - exitDNSCache：按出口 deviceID 隔离（答案地理 = 出口所在地）；
//   - 本缓存：按 ECS 网段隔离（答案地理 = 使用方所在地，由 ECS 决定）。
//
// 正确性 / 边界（逐条对应下面的实现）：
//   - key 含 ECS 网段（ecsScopeForPeer，与实际注入共用 ecsClientIPForPeer）→ 绝不跨地理串味。
//   - key 含 EDNS UDP payload size 与 DO 位：缓存的是**上游按某个缓冲区大小裁剪过**的原始应答，
//     发给声明更小缓冲区的使用方会超包被丢；DO 位不同则 DNSSEC 记录有无不同。计入 key 即免除这两类错配。
//   - 查询**自带 ECS** 时不缓存：那份答案取决于客户端自己给的网段，而本缓存的 key 只反映我们注入的网段，
//     同网段不同自带 ECS 的两个客户端会互相污染。这类查询直接回源（占比极低，仅递归解析器会这么发）。
//   - 只缓存**确定性 rcode**（NOERROR / NXDOMAIN，复用 exitDNSRcodeCacheable）；SERVFAIL / REFUSED 等
//     软失败不缓存，免得把一次上游抖动放大成一段时间的硬失败。
//   - 命中时用**当前查询自己的 qid + question** 就地改写缓存的原始应答（buildRawDNSResponseFor，含
//     0x20 大小写随机化与 question 段等长校验）→ txn id / question 回显永远与来包一致。
//   - 命中时把 TTL 钳到**本条缓存的剩余寿命**：否则一条 TTL=300 的应答在缓存里躺了 299s 后仍宣称 300s，
//     使用方侧实际有效期被放大到近两倍。会话早期竞速窗口的钳制（magicDNSEarlyClampTTL）取二者更小值 ——
//     该钳制是**按使用方会话**判定的，故只能在 serve 时做，绝不能把钳过的应答写进缓存去污染其他使用方。
//   - 无界增长防护：条目上限 + 惰性清扫（不起后台 goroutine），到顶且无可清理则本次不缓存。

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	// 正缓存 TTL 取上游应答的最小 TTL，夹在 [min,max]。与 exitDNSCache 同口径：太短没意义（往返照旧），
	// 太长会拖慢 CDN 节点变更的收敛。
	upstreamDNSCacheMinTTL = 15 * time.Second
	upstreamDNSCacheMaxTTL = 300 * time.Second
	// 负缓存（NXDOMAIN / NODATA）TTL 短一些，避免把「刚注册还没生效的域名」的否定答案缓存太久。
	upstreamDNSCacheNegTTL = 30 * time.Second
	// 条目上限。key 维度 = 网段 × qname × qtype × EDNS 参数；全隧道下使用方会把所有公网域名都打过来，
	// 故比 exit 侧留更大余量。单条 ~300B（原始应答字节），5 万条 ≈ 十几 MB。
	upstreamDNSCacheMaxEntries = 50000
	// 惰性清扫间隔：写入时若距上次清扫超过本值就顺手扫掉过期项，省一个常驻 goroutine。
	upstreamDNSCacheSweepInterval = 60 * time.Second
)

// upstreamDNSCacheEntry 存**上游回来的原始应答字节**（不解析 rdata，故天然适配 A/AAAA 之外的
// MX/TXT/HTTPS/SVCB 等所有转发类型）。raw 创建后只读，多 goroutine 并发读安全。
type upstreamDNSCacheEntry struct {
	raw     []byte
	rcode   dnsmessage.RCode
	expires time.Time
}

var (
	upstreamDNSCacheMu        sync.RWMutex
	upstreamDNSCache          = make(map[string]upstreamDNSCacheEntry)
	upstreamDNSCacheLastSweep time.Time
	// upstreamDNSGroup 对「回源上游」做单飞：key 与缓存一致。缓存冷时同一 key 的并发查询（含丢包重发
	// 风暴、苹果端 A+AAAA+HTTPS 齐发）只发一条上游查询，其余等待共享结果。
	upstreamDNSGroup singleflight.Group
	// magicDNSUpstreamCacheHitCount：上游应答缓存命中数（免掉一次上游往返），供 /status 观测命中率。
	magicDNSUpstreamCacheHitCount atomic.Uint64
)

// upstreamDNSCacheKey 组 key：ECS 网段 | qtype | qclass | 归一化 qname | EDNS 缓冲区 | DO 位。
// 各维度的必要性见文件头注释。
func upstreamDNSCacheKey(scope string, q dnsmessage.Question, ednsBuf uint16, do bool) string {
	doFlag := "0"
	if do {
		doFlag = "1"
	}
	return scope + "|" + strconv.Itoa(int(q.Type)) + "|" + strconv.Itoa(int(q.Class)) + "|" +
		normalizeQName(q) + "|" + strconv.Itoa(int(ednsBuf)) + "|" + doFlag
}

// parseUpstreamCacheEDNS 从查询里取出「影响应答形态」的 EDNS 参数：UDP payload size、DO 位，
// 以及是否**自带 ECS**。没有 OPT 伪 RR → buf=0（等价于 RFC 1035 的 512B 语义）、do=false。
// ok=false = 查询解不开（调用方按不可缓存处理，直接回源）。
func parseUpstreamCacheEDNS(query []byte) (ednsBuf uint16, do bool, hasECS bool, ok bool) {
	var m dnsmessage.Message
	if err := m.Unpack(query); err != nil {
		return 0, false, false, false
	}
	for i := range m.Additionals {
		if m.Additionals[i].Header.Type != dnsmessage.TypeOPT {
			continue
		}
		// OPT 伪 RR 复用 header 字段：Class = 请求方 UDP payload size，TTL 高位字节含 DO 位。
		ednsBuf = uint16(m.Additionals[i].Header.Class)
		do = m.Additionals[i].Header.TTL&(1<<15) != 0
		if body, isOpt := m.Additionals[i].Body.(*dnsmessage.OPTResource); isOpt {
			for _, o := range body.Options {
				if o.Code == ecsOptionCode {
					hasECS = true
				}
			}
		}
		break
	}
	return ednsBuf, do, hasECS, true
}

// upstreamDNSCacheKeyFor 为一条即将回源的查询算出缓存 key。cacheable=false = 本次不走缓存/单飞
// （查询解不开、无 question、或自带 ECS），调用方直接回源，行为与加缓存之前完全一致。
func upstreamDNSCacheKeyFor(query []byte, scope string) (key string, cacheable bool) {
	_, q, ok := parseDNSQueryKey(query)
	if !ok || q.Name.Length == 0 {
		return "", false
	}
	ednsBuf, do, hasECS, ok := parseUpstreamCacheEDNS(query)
	if !ok || hasECS {
		return "", false
	}
	return upstreamDNSCacheKey(scope, q, ednsBuf, do), true
}

// upstreamDNSCacheGet 取一条未过期的缓存。过期即当未命中（不在读锁下删，交给惰性清扫 / 下次写入覆盖）。
func upstreamDNSCacheGet(key string) (upstreamDNSCacheEntry, bool) {
	upstreamDNSCacheMu.RLock()
	e, ok := upstreamDNSCache[key]
	upstreamDNSCacheMu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return upstreamDNSCacheEntry{}, false
	}
	return e, true
}

// upstreamDNSCachePut 写入一条缓存。惰性清扫 + 上限保护，绝不无界增长。
func upstreamDNSCachePut(key string, e upstreamDNSCacheEntry) {
	upstreamDNSCacheMu.Lock()
	now := time.Now()
	if now.Sub(upstreamDNSCacheLastSweep) >= upstreamDNSCacheSweepInterval || len(upstreamDNSCache) >= upstreamDNSCacheMaxEntries {
		for k, v := range upstreamDNSCache {
			if now.After(v.expires) {
				delete(upstreamDNSCache, k)
			}
		}
		upstreamDNSCacheLastSweep = now
	}
	if len(upstreamDNSCache) >= upstreamDNSCacheMaxEntries {
		upstreamDNSCacheMu.Unlock()
		return // 满且无可清理 → 本次不缓存（宁可放弃一次加速，也不无界占内存）
	}
	upstreamDNSCache[key] = e
	upstreamDNSCacheMu.Unlock()
}

// buildUpstreamDNSCacheEntry 把上游原始应答打包成缓存项并算出到期时刻。Success 且有答复（ttl>0）用上游
// 最小 TTL 夹 [min,max]；否则（NODATA / NXDOMAIN）用较短负缓存 TTL。ok=false = 应答不可解析或 rcode
// 不确定 → 不缓存。
func buildUpstreamDNSCacheEntry(raw []byte) (upstreamDNSCacheEntry, bool) {
	rcode, minTTL, ok := parseRawDNSMeta(raw)
	if !ok || !exitDNSRcodeCacheable(rcode) {
		return upstreamDNSCacheEntry{}, false
	}
	d := upstreamDNSCacheNegTTL
	if rcode == dnsmessage.RCodeSuccess && minTTL > 0 {
		d = time.Duration(minTTL) * time.Second
		if d < upstreamDNSCacheMinTTL {
			d = upstreamDNSCacheMinTTL
		}
		if d > upstreamDNSCacheMaxTTL {
			d = upstreamDNSCacheMaxTTL
		}
	}
	return upstreamDNSCacheEntry{raw: raw, rcode: rcode, expires: time.Now().Add(d)}, true
}

// upstreamDNSCacheServeTTL 算出命中缓存时应把应答 TTL 钳到多少秒：取「本条缓存的剩余寿命」与（若在
// 会话早期竞速窗口内）magicDNSEarlyClampTTL 的更小值。剩余寿命不足 1s 时取 1（0 会让使用方完全不缓存、
// 每次都回源，反而放大负载）。
func upstreamDNSCacheServeTTL(e upstreamDNSCacheEntry, earlyClamp bool) uint32 {
	remain := time.Until(e.expires).Seconds()
	if remain < 1 {
		remain = 1
	}
	ttl := uint32(remain)
	if earlyClamp && magicDNSEarlyClampTTL < ttl {
		ttl = magicDNSEarlyClampTTL
	}
	return ttl
}

// serveUpstreamDNSFromCache 用当前查询的 qid + question 就地改写缓存的原始应答，按 upstreamDNSCacheServeTTL
// 钳 TTL 后回写给使用方。改写失败（question 段与缓存不等长等，见 buildRawDNSResponseFor 的校验）→ 退化成
// SERVFAIL，绝不吐可能被污染的答案、也不静默吞包。
func serveUpstreamDNSFromCache(conn magicDNSReplyConn, peer *net.UDPAddr, clientQuery []byte, e upstreamDNSCacheEntry, earlyClamp bool) {
	qid := dnsQueryID(clientQuery)
	out := buildRawDNSResponseFor(clientQuery, qid, e.raw)
	if out == nil {
		magicDNSServfailCount.Add(1)
		_ = writeMagicDNSStatus(conn, peer, qid, dnsmessage.RCodeServerFailure, nil, dnsmessage.Question{})
		return
	}
	if clamped, changed := clampDNSResponseTTLs(out, upstreamDNSCacheServeTTL(e, earlyClamp)); changed {
		out = clamped
		if earlyClamp {
			magicDNSEarlyClampCount.Add(1)
		}
	}
	_, _ = conn.WriteToUDP(out, peer)
}
