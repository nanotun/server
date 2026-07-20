package main

// exit-node DNS 结果缓存（direction 1 的加速层）。
//
// 背景：经出口解析（tryResolvePublicViaExit）每条最多 block exitDNSWaitTimeout（2s），且要走「server→出口→权威
// DNS→出口→server」四段链路。在**丢包严重的使用方链路**（实测 iOS WiFi TX 重传率 72%）上，stub resolver 会把同一
// 主机名重发多次，每条重发都独立触发一次经出口解析、各占一个 in-flight 位最多 2s → 页面迟迟打不开。
//
// 两层加速（都以「出口地理」为界，绝不跨出口串味）：
//   1. 结果缓存：把经出口解析出的 (地址集 + rcode) 按 (出口 deviceID, qtype, qname) 缓存一小段（正/负都缓存）。
//      同一浏览会话内的重复查询、以及同出口不同使用方的相同域名，直接命中、即时应答，免掉 2s 往返与 in-flight 占位。
//   2. 单飞（singleflight）：缓存冷时，同一 key 的并发查询（含重发风暴）只发**一条**经出口解析，其余等待共享结果——
//      把「一个页面几十条 + 丢包重发」塌缩成一次出口往返，省端口 / 省 in-flight / 免重复打权威。
//
// 正确性 / 边界：
//   - key 含出口 deviceID → 天然隔离「不同出口的地理结果」；使用方切出口即换 key，不会拿到旧出口的就近地址。
//   - 缓存的是**解析结果**（[]netip.Addr + rcode），命中时用**当前查询自己的 qid + question** 重建应答
//     （buildMagicDNSAnswer / writeMagicDNSStatus）→ txn id 与 question 永远与来包一致，不受 0x20 大小写随机化影响。
//   - 只缓存**成功的 DNS 事务**（含 NXDOMAIN / NODATA 这类合法否定答复，负缓存 TTL 更短）；经出口**投递失败 /
//     超时**不缓存（那是链路抖动，缓存下来会把一次偶发丢包放大成一段时间的假失败）。
//   - 无界增长防护：条目上限 + 惰性清扫（不起后台 goroutine），到顶且无可清理则本次不缓存。

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	// 正缓存 TTL 取上游应答的最小 TTL，夹在 [min,max]：太短没意义（重复往返照旧），太长会拖慢「出口迁移 / CDN
	// 节点下线」的收敛。15s~300s 既能吃掉一个浏览会话内的重复查询，也能较快跟上变化。
	exitDNSCacheMinTTL = 15 * time.Second
	exitDNSCacheMaxTTL = 300 * time.Second
	// 负缓存（NXDOMAIN / NODATA / 空答复）TTL：短一些，避免把「刚上线还没生效的域名」否定答案缓存太久。
	exitDNSCacheNegTTL = 30 * time.Second
	// 条目上限：域名×出口有界（热门站点为主），单条 ~200B，2 万条 ≈ 数 MB。到顶即先清扫、仍满则本次不缓存。
	exitDNSCacheMaxEntries = 20000
	// 惰性清扫间隔：每次写入时若距上次清扫超过本值就顺手扫掉过期项，省一个常驻 goroutine。
	exitDNSCacheSweepInterval = 60 * time.Second
)

// errExitDNSResolveFailed：经出口解析投递失败 / 超时的哨兵错误。经 singleflight 传给所有等待者 → 一起 fail-open
// 回退 server 本地上游。**不**进缓存（链路抖动不该被放大成一段假失败）。
var errExitDNSResolveFailed = errors.New("exit dns resolve failed")

// exitDNSCacheEntry 是一条缓存结果，服务两条路径（按 qtype 天然分流，同 key 不混）：
//   - A/AAAA（tryResolvePublicViaExit）：存**解析出的地址集** addrs，命中时用 buildMagicDNSAnswer 按查询 qtype 重建。
//   - HTTPS/SVCB（tryRelayPublicViaExit）：本模块不解析 SvcParams，改存出口回来的**原始应答字节** raw，命中时用
//     buildRawDNSResponseFor 按当前查询的 qid + question 就地改写后回写（见其注释里的 0x20/长度一致性论证）。
//
// raw==nil → 走 addrs 重建；raw!=nil → 走 raw 改写。两者互斥（由填充路径保证）。
type exitDNSCacheEntry struct {
	addrs   []netip.Addr
	raw     []byte // 仅 HTTPS/SVCB 中继路径填充（原始应答字节，只读、创建后不改）
	rcode   dnsmessage.RCode
	expires time.Time
}

var (
	exitDNSCacheMu        sync.RWMutex
	exitDNSCache          = make(map[string]exitDNSCacheEntry)
	exitDNSCacheLastSweep time.Time
	// exitDNSGroup 对「经出口解析」做单飞：key 与缓存一致（出口 deviceID|qtype|qname）。
	exitDNSGroup singleflight.Group
	// magicDNSExitCacheHitCount：经出口结果缓存命中的查询数（观测用，供 /status 汇总）。
	magicDNSExitCacheHitCount atomic.Uint64
)

// exitDNSCacheKey 用 (出口 deviceID, qtype, 归一化 qname) 组 key。含出口 → 隔离不同出口的地理结果。
func exitDNSCacheKey(egress int64, qtype dnsmessage.Type, qname string) string {
	return strconv.FormatInt(egress, 10) + "|" + strconv.Itoa(int(qtype)) + "|" + qname
}

// exitDNSCacheGet 取一条未过期的缓存。过期即当未命中（不在读锁下删，交给惰性清扫 / 下次写入覆盖）。
func exitDNSCacheGet(key string) (exitDNSCacheEntry, bool) {
	exitDNSCacheMu.RLock()
	e, ok := exitDNSCache[key]
	exitDNSCacheMu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return exitDNSCacheEntry{}, false
	}
	return e, true
}

// exitDNSCachePut 写入一条缓存。惰性清扫 + 上限保护，绝不无界增长。
func exitDNSCachePut(key string, e exitDNSCacheEntry) {
	exitDNSCacheMu.Lock()
	now := time.Now()
	if now.Sub(exitDNSCacheLastSweep) >= exitDNSCacheSweepInterval || len(exitDNSCache) >= exitDNSCacheMaxEntries {
		for k, v := range exitDNSCache {
			if now.After(v.expires) {
				delete(exitDNSCache, k)
			}
		}
		exitDNSCacheLastSweep = now
	}
	if len(exitDNSCache) >= exitDNSCacheMaxEntries {
		exitDNSCacheMu.Unlock()
		return // 满且无可清理 → 本次不缓存（宁可放弃一次加速，也不无界占内存）
	}
	exitDNSCache[key] = e
	exitDNSCacheMu.Unlock()
}

// exitDNSRcodeCacheable 判断某 rcode 是否可安全缓存。只有**确定性答复**可缓存：
//   - NOERROR（含 NODATA：Success + 0 addr）：域名 / 记录的确定状态；
//   - NXDOMAIN（NameError）：域名确定不存在。
//
// SERVFAIL / REFUSED / NOTIMP / FORMERR 等是**软 / 瞬时失败**（出口上游抖动、限流等），缓存下来会把一次偶发失败
// 放大成一段时间（负缓存 TTL）的硬失败、且抵消 fail-open —— 故不缓存：serve 给当前这批并发调用方后即忘，下一条
// 查询重新经出口解析（仍有单飞塌缩兜住突发）。
func exitDNSRcodeCacheable(rcode dnsmessage.RCode) bool {
	return rcode == dnsmessage.RCodeSuccess || rcode == dnsmessage.RCodeNameError
}

// buildExitDNSCacheEntry 把解析结果打包成缓存项并算出到期时刻。正答复用上游最小 TTL（夹 min/max），
// 否定 / 空答复用较短的负缓存 TTL。
func buildExitDNSCacheEntry(addrs []netip.Addr, rcode dnsmessage.RCode, ttl uint32) exitDNSCacheEntry {
	var d time.Duration
	if rcode == dnsmessage.RCodeSuccess && len(addrs) > 0 {
		d = time.Duration(ttl) * time.Second
		if d < exitDNSCacheMinTTL {
			d = exitDNSCacheMinTTL
		}
		if d > exitDNSCacheMaxTTL {
			d = exitDNSCacheMaxTTL
		}
	} else {
		d = exitDNSCacheNegTTL
	}
	return exitDNSCacheEntry{addrs: addrs, rcode: rcode, expires: time.Now().Add(d)}
}

// parseExitDNSResult 从经出口回来的**原始 DNS 应答**里抽出 A/AAAA 地址集、rcode、答复区最小 TTL。
// 只解 A/AAAA（CNAME 等其它 RR 跳过）——命中缓存时用 buildMagicDNSAnswer 以「查询名直接挂 A/AAAA」重建，
// 对使用方是合法应答，且与既有 magic-host 合成路径一致。解析失败（截断 / 非法）→ ok=false（调用方按解析失败处理：
// 归一成 errExitDNSResolveFailed → 不缓存、fail-open 回退 server 本地上游）。
func parseExitDNSResult(resp []byte) (addrs []netip.Addr, rcode dnsmessage.RCode, ttl uint32, ok bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		return nil, 0, 0, false
	}
	rcode = hdr.RCode
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0, 0, false
	}
	var minTTL uint32
	haveTTL := false
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, 0, 0, false
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, 0, 0, false
			}
			addrs = append(addrs, netip.AddrFrom4(r.A))
			if !haveTTL || ah.TTL < minTTL {
				minTTL, haveTTL = ah.TTL, true
			}
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, 0, 0, false
			}
			addrs = append(addrs, netip.AddrFrom16(r.AAAA))
			if !haveTTL || ah.TTL < minTTL {
				minTTL, haveTTL = ah.TTL, true
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, 0, 0, false
			}
		}
	}
	return addrs, rcode, minTTL, true
}

// serveExitDNSFromCache 用**当前查询的 qid + question** 从缓存结果重建并回写应答（保证 txn id / question 与来包一致）。
// 成功答复（含 NODATA：Success + 空 addrs）走 buildMagicDNSAnswer；否定答复（NXDOMAIN 等）回对应 rcode 状态帧。
func serveExitDNSFromCache(conn *net.UDPConn, peer *net.UDPAddr, qid uint16, q dnsmessage.Question, e exitDNSCacheEntry) {
	if e.rcode == dnsmessage.RCodeSuccess {
		if resp, err := buildMagicDNSAnswer(qid, q, e.addrs); err == nil {
			_, _ = conn.WriteToUDP(resp, peer)
			return
		}
		// 重建失败（极少）→ 退化成 SERVFAIL，不静默吞包。
		_ = writeMagicDNSStatus(conn, peer, qid, dnsmessage.RCodeServerFailure, nil, q)
		return
	}
	_ = writeMagicDNSStatus(conn, peer, qid, e.rcode, nil, q)
}

// normalizeQName 把 question name 归一成「小写、去尾点」，作为缓存 key 的一部分（与解析路径一致）。
func normalizeQName(q dnsmessage.Question) string {
	return strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
}

// ─────────────────────────── HTTPS/SVCB 中继路径：原始应答缓存 + 就地改写 ───────────────────────────

// parseRawDNSMeta 从一份**原始 DNS 应答**里只抽 rcode 与答复区**最小 TTL**（不解析任何 RR 的 rdata，故适配 HTTPS/SVCB
// 等本模块不解析的类型）。0 answer（NODATA）时 have=false、minTTL=0，由 buildRawExitDNSCacheEntry 归为负缓存。
func parseRawDNSMeta(resp []byte) (rcode dnsmessage.RCode, minTTL uint32, ok bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil {
		return 0, 0, false
	}
	rcode = hdr.RCode
	if err := p.SkipAllQuestions(); err != nil {
		return 0, 0, false
	}
	have := false
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return 0, 0, false
		}
		if !have || ah.TTL < minTTL {
			minTTL, have = ah.TTL, true
		}
		if err := p.SkipAnswer(); err != nil {
			return 0, 0, false
		}
	}
	return rcode, minTTL, true
}

// buildRawExitDNSCacheEntry 把中继回来的**原始应答字节**打包成缓存项。TTL 规则与 A/AAAA 版一致：Success 且有答复
// （ttl>0）用上游最小 TTL 夹 [min,max]；否则（NODATA / NXDOMAIN）用较短负缓存 TTL。raw 直接持有（调用方给的已是
// interceptExitDNSResponseIfPending 复制出的独立切片，创建后只读、不再改，故多 goroutine 并发读安全）。
func buildRawExitDNSCacheEntry(raw []byte, rcode dnsmessage.RCode, ttl uint32) exitDNSCacheEntry {
	d := exitDNSCacheNegTTL
	if rcode == dnsmessage.RCodeSuccess && ttl > 0 {
		d = time.Duration(ttl) * time.Second
		if d < exitDNSCacheMinTTL {
			d = exitDNSCacheMinTTL
		}
		if d > exitDNSCacheMaxTTL {
			d = exitDNSCacheMaxTTL
		}
	}
	return exitDNSCacheEntry{raw: raw, rcode: rcode, expires: time.Now().Add(d)}
}

// dnsQuestionEnd 返回一份 DNS 报文里 question 段结束的偏移（= 12 + qname 线格长 + 4）。用于就地改写：question 段
// 在报文头(12B)之后。question 里出现压缩指针属非法（bail）。
func dnsQuestionEnd(msg []byte) (int, bool) {
	if len(msg) < 12 {
		return 0, false
	}
	pos := 12
	for {
		if pos >= len(msg) {
			return 0, false
		}
		l := int(msg[pos])
		if l == 0 {
			pos++ // 根标签
			break
		}
		if l&0xc0 != 0 {
			return 0, false // question 段不该有压缩指针
		}
		pos += 1 + l
		if pos > len(msg) {
			return 0, false
		}
	}
	if pos+4 > len(msg) { // qtype(2) + qclass(2)
		return 0, false
	}
	return pos + 4, true
}

// buildRawDNSResponseFor 基于缓存的**原始应答** cachedRaw，产出一份"txn id 与 question 与当前查询一致"的应答：
// 拷贝 cachedRaw → 覆盖 [0:2] 为当前 qid → 用当前查询的 question 段覆盖 cachedRaw 的 question 段。
//
// 为何只改这两处即正确（0x20 大小写随机化 / 长度一致性）：
//   - cachedRaw 由同一 key（egress|qtype|归一化 qname）的某条查询解析而来，其 qname 与当前查询**归一化相等** →
//     线格标签结构相同 → question 段**字节长度完全相同**（0x20 只翻大小写、不改长度；尾点在线格上都是根标签 0）。
//     故当前查询的 [12:qEnd] 与 cachedRaw 的 [12:qEnd] 等长，可原位覆盖。
//   - 客户端的 0x20 校验只看**question 段回显**是否逐字节等于所发（大小写敏感）——覆盖后天然满足；答复区 RR 的 owner
//     名多为指向偏移 12 的压缩指针（不参与 0x20 校验），其大小写随之变成当前查询的，无碍。
//
// 失败（当前查询 question 不可解析 / cachedRaw 过短）→ 返回 nil，调用方回 SERVFAIL（不静默吞包）。
func buildRawDNSResponseFor(query []byte, qid uint16, cachedRaw []byte) []byte {
	qEnd, ok := dnsQuestionEnd(query)
	if !ok || len(cachedRaw) < qEnd {
		return nil
	}
	out := make([]byte, len(cachedRaw))
	copy(out, cachedRaw)
	out[0] = byte(qid >> 8)
	out[1] = byte(qid)
	copy(out[12:qEnd], query[12:qEnd])
	return out
}

// serveRawExitDNSFromCache 用当前查询的 qid + question 就地改写缓存的原始应答并回写给使用方。改写失败退化成 SERVFAIL。
func serveRawExitDNSFromCache(conn *net.UDPConn, peer *net.UDPAddr, qid uint16, query []byte, e exitDNSCacheEntry) {
	if out := buildRawDNSResponseFor(query, qid, e.raw); out != nil {
		_, _ = conn.WriteToUDP(out, peer)
		return
	}
	_ = writeMagicDNSStatus(conn, peer, qid, dnsmessage.RCodeServerFailure, nil, dnsmessage.Question{})
}
