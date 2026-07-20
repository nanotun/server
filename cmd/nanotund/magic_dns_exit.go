package main

// exit-node DNS 地理修正（direction 1）。
//
// 问题：使用方选了 peer 出口做公网出网时，其**公网域名** DNS 若仍由 server 本地 magic resolver 转发到 server 自己
// 配置的上游解析，CDN 会按「server 的地理位置」就近调度 —— 给出对**出口**是烂路由的边缘节点。实测（重庆出口）：
// server 海外解析 → CDN 返回 155.102.209.x / 47.246.58.x（经重庆出口 ~27% 连接失败）；而经出口本地解析 →
// 198.51.100.x（本地运营商边缘，100% 稳）。根因是「DNS 解析位置 ≠ 流量出口位置」，与吞吐 / MTU 无关。
//
// 修法（server 侧，无需改出口）：公网查询若来自「选了 peer 出口」的会话，不走 server 本地上游，而是把这条 DNS
// 查询**经该出口转发**——复用出口数据面已有的 :53 接管（exit_forward.rs 的 udp_relay：出口机 getaddrinfo 本地解析，
// 反映出口地理）。做法：把一份伪造的 UDP/53 查询包（src=server 网关:关联端口，dst=公共 resolver:53）投进出口会话的
// TunChan；出口解析后回包（src=公共 resolver:53，dst=server 网关:关联端口）沿出口链路回到 server，在 readLoop 里
// 按「关联端口」截获、交回等待的 resolver goroutine（不写 TUN，避免内核 rp_filter/conntrack 吞掉这条「无出向 conntrack
// 记录」的回包）。*.lan 仍由本地 magic 拦截，不受影响。
//
// 失败语义（2026-07-17 起 fail-closed）：**绑定了出口**的会话，出口无在跑会话 / 投递失败 / 超时 → 回 SERVFAIL 让
// 客户端 stub 重试，**绝不**回退 server 本地上游——否则失败瞬间会用「server 地理」的答案污染客户端 OS 缓存
// （overseas CDN 边缘对墙内出口是烂路由 / 不可达，实测 iOS「页面卡住要刷新」的根因之一），且此时数据面本就
// fail-closed（出口离线流量全丢），回一个"能解析却连不上"的地址毫无意义。未绑定出口的会话不受影响（照走本地上游）。

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// exitDNSNominalResolver 是注入查询的**名义**目的地址。出口一律接管任何目的的 :53（见 exit_forward.rs udp_relay），
// 故此 IP 只是名义值：
//   - 出口开了 DNS 接管（dns_resolvers 非空，常态）→ 出口机 getaddrinfo 本地解析（反映出口地理）；
//   - 出口未开接管（少见）→ 真发给这个公共 resolver，它同样按出口公网 IP 就近应答。两种路径结果都对。
var exitDNSNominalResolver = netip.AddrFrom4([4]byte{8, 8, 8, 8})

const (
	// 关联端口区间（IANA 动态/私有端口段），把「注入的查询」与「出口回来的响应」关联起来。避开知名端口。
	exitDNSPortLo uint16 = 40000
	exitDNSPortHi uint16 = 60000
	// 经出口解析的等待上限：出口→权威 DNS 往返 + 两段链路 RTT。超时即回退 server 本地上游。
	// 2026-07-15：由 3s 降到 2s。此值与 magicDNSInflightCap 共同决定「经出口查询」的吞吐（cap/timeout）——
	// 每条经出口查询在 resolveExitDNS 里最多 block 本值、期间一直占着一个 in-flight 位。苹果端每个主机名并发
	// A+AAAA，一个页面瞬间几十条经出口查询涌入，占位太久 → 池满 → 新查询被 drop、mDNSResponder 重发 → 页面
	// 不秒开（实测 iOS/mac 选出口后卡的主因）。缩短占位上限让位子更快回收；超时仍 fail-open 回退本地上游，只是
	// 丢一次「经出口地理修正」的机会，不影响「至少能解析」。
	exitDNSWaitTimeout = 2 * time.Second
)

// exitDNS 关联表：关联端口 → 等待响应的 channel。零 in-flight 时 readLoop 的截获检查仅一次 atomic load。
var (
	exitDNSMu       sync.Mutex
	exitDNSWaiters  = make(map[uint16]chan []byte)
	exitDNSInflight atomic.Int64
	exitDNSPortCtr  atomic.Uint32
	// magicDNSViaExitCount：成功经出口解析的公网查询数（观测用，供 /status 汇总）。
	magicDNSViaExitCount atomic.Uint64
	// magicDNSAAAAStripCount：所选出口**无 v6 出网**时，被就地回 NODATA（不绕出口、省一个 in-flight 占位）
	// 的 AAAA 查询数（观测用，供 /status 汇总）。
	magicDNSAAAAStripCount atomic.Uint64
	// magicDNSViaExitRelayCount：经出口**原样中继**（不解析 / 不缓存，当前用于 HTTPS/SVCB）的公网查询数
	// （观测用，供 /status 汇总）。与 magicDNSViaExitCount（A/AAAA，解析 + 缓存）分开计，便于区分两条路径量。
	magicDNSViaExitRelayCount atomic.Uint64
	// magicDNSExitServfailCount：绑定出口的会话经出口解析失败（离线/超时/投递失败）→ 回 SERVFAIL 的次数。
	// 持续增长 = 出口链路不健康（掉线/拥塞），客户端 DNS 在重试。
	magicDNSExitServfailCount atomic.Uint64
)

// writeExitDNSServfail 给绑定出口但经出口解析失败的查询回 SERVFAIL（fail-closed，不落缓存）。
// 客户端 stub resolver 会自然重试；出口恢复后重试即拿到出口地理的答案，OS 缓存不被 server 地理污染。
func writeExitDNSServfail(conn *net.UDPConn, peer *net.UDPAddr, qid uint16, q dnsmessage.Question) {
	magicDNSExitServfailCount.Add(1)
	_ = writeMagicDNSStatus(conn, peer, qid, dnsmessage.RCodeServerFailure, nil, q)
}

// tryResolvePublicViaExit 若查询来自「选了 peer 出口」的会话，则把该公网查询经出口解析并把响应回给使用方，返回
// true（调用方到此为止）。仅「未选出口」返回 false（调用方走 server 本地上游）；**已绑定出口**的会话若出口不在跑 /
// 投递失败 / 超时 → 回 SERVFAIL 并返回 true（fail-closed，见文件头注释：绝不用 server 地理答案污染客户端缓存）。
func tryResolvePublicViaExit(conn *net.UDPConn, peer *net.UDPAddr, query []byte, q dnsmessage.Question, qid uint16) bool {
	if conn == nil || peer == nil || len(query) == 0 {
		return false
	}
	vip, ok := netipAddrFromUDP(peer)
	if !ok {
		return false
	}
	egress := exitDeviceForClientVIP(vip)
	if egress == 0 {
		return false // 未选 peer 出口（走 server 自出口）→ 本地上游解析即可
	}
	exitConn := lookupRunningExitConnByDevice(egress)
	if exitConn == nil {
		// 出口离线：数据面对真流量本就 fail-closed 丢包，这里回 SERVFAIL 与之对齐——解析出的地址反正连不上，
		// 回 server 地理的答案只会在出口恢复后继续毒害 OS 缓存。客户端 exit_fallback_server 回退 server 后
		// egress 变 0，自然走上面的本地上游分支。
		writeExitDNSServfail(conn, peer, qid, q)
		return true
	}
	// v6 能力感知：所选出口**无 v6 公网出网**（advertisedExitV6=false，最近一帧 exit advertise 不含 ::/0）时，
	// AAAA 记录注定无用——数据面对发往它的公网 v6 目的回 ICMPv6 unreachable、出口 udp_relay 也会 strip_aaaa。
	// 此时**不绕出口**：省掉一个最多 exitDNSWaitTimeout 的 in-flight 占位，也把苹果端「每主机名 A+AAAA」的
	// 经出口查询量直接砍掉一半；就地回 NODATA（NOERROR / 0 answer）让使用方立即用 A(v4)、Happy Eyeballs 不卡。
	// 与既有「v4-only 出口剥 AAAA、秒回落 v4」策略一致。出口**有 v6** → 照常绕出口解析（保住 AAAA 的 CDN 就近
	// 调度），无回归。仅 A/AAAA 会走到这里（handleMagicDNSPacket 已把其它类型 forward 到上游）。
	if q.Type == dnsmessage.TypeAAAA && !exitConn.advertisedExitV6.Load() {
		if resp, berr := buildMagicDNSAnswer(qid, q, nil); berr == nil {
			_, _ = conn.WriteToUDP(resp, peer)
		}
		magicDNSAAAAStripCount.Add(1)
		return true
	}

	// 加速层：结果缓存 + 单飞（见 magic_dns_cache.go）。key 含出口 deviceID → 不跨出口串味。
	key := exitDNSCacheKey(egress, q.Type, normalizeQName(q))
	if e, hit := exitDNSCacheGet(key); hit {
		serveExitDNSFromCache(conn, peer, qid, q, e)
		magicDNSExitCacheHitCount.Add(1)
		return true
	}
	// 缓存冷：同 key 的并发查询（含丢包重发风暴）塌缩成一条经出口解析，其余等待共享**解析结果**（[]addr+rcode）。
	// 每个调用方各自用自己的 qid/question 重建应答，故 leader 与 waiter 的 query 字节即便有大小写 / txn 差异也无碍。
	// 投递失败 / 超时 / 应答不可解析都归一成 errExitDNSResolveFailed → 所有调用方一起收 SERVFAIL（fail-closed，
	// 不缓存：链路抖动 / 罕见坏包不该被放大成一段假失败；客户端重试即再走一次经出口解析）。
	// 只有**确定性答复**（NOERROR / NXDOMAIN）写缓存；SERVFAIL 等软失败仅 serve 当前这批并发调用方、不落缓存
	// （见 exitDNSRcodeCacheable），避免一次瞬时失败被负缓存放大成一段硬失败。
	e, ok := resolveExitDNSAddrsCached(key, exitConn, query)
	if !ok {
		writeExitDNSServfail(conn, peer, qid, q) // 经出口解析失败 → SERVFAIL（不回退本地上游，防地理污染）
		return true
	}
	serveExitDNSFromCache(conn, peer, qid, q, e)
	magicDNSViaExitCount.Add(1)
	return true
}

// resolveExitDNSAddrsCached：A/AAAA 经出口解析的核心（singleflight 塌缩 + 确定性答复落缓存），不做任何 I/O 回写，
// 供 MagicDNS 网关路径（tryResolvePublicViaExit）与数据面 :53 拦截路径（interceptExitBoundDNSQuery）共用。
// 返回 (缓存项, true)；投递失败 / 超时 / 应答不可解析 → (零值, false)。
func resolveExitDNSAddrsCached(key string, exitConn *Connection, query []byte) (exitDNSCacheEntry, bool) {
	res, err, _ := exitDNSGroup.Do(key, func() (any, error) {
		raw, rok := resolveExitDNS(exitConn, query)
		if !rok {
			return nil, errExitDNSResolveFailed
		}
		addrs, rcode, ttl, pok := parseExitDNSResult(raw)
		if !pok {
			return nil, errExitDNSResolveFailed
		}
		e := buildExitDNSCacheEntry(addrs, rcode, ttl)
		if exitDNSRcodeCacheable(rcode) {
			exitDNSCachePut(key, e)
		}
		return e, nil
	})
	if err != nil {
		return exitDNSCacheEntry{}, false
	}
	e, castok := res.(exitDNSCacheEntry)
	return e, castok
}

// tryRelayPublicViaExit 把一条**非 A/AAAA**的公网查询（当前用于 HTTPS(65)/SVCB(64)）按所选出口**原样中继**：
// 转发原始查询字节 → 拿回原始应答字节 → 直接回给使用方（不解析、不改写、不缓存）。
//
// 为何要中继：浏览器对每个站点会并发发 HTTPS(SVCB) 查询，其 RR 里带 ipv4hint/ipv6hint + alpn/ech。这些 hint 同样被
// CDN 按「解析位置」就近——若仍由 server 本地上游解析（server 地理），会给出对**出口**是烂路由的 hint，与 A/AAAA
// 未修地理前同病。经出口中继让 hint 反映出口地理，把地理修正从 A/AAAA 补齐到 HTTPS，与 tryResolvePublicViaExit 一致。
// 出口两种实现都能处理任意 qtype：内核 DNAT 出口（OpenWrt）对 :53 全量重定向；用户态出口（exit_forward.rs）对 HTTPS
// 走 dns_forward_udp 原样转发给出口本地 resolver。
//
// 与 A/AAAA 路径（tryResolvePublicViaExit）的区别：SVCB/HTTPS 记录结构复杂（SvcParams: alpn/ech/hint...），本模块坚持
// 「透明中继、不解析」，故缓存/单飞共享的是**原始应答字节**而非拆出的 []addr；命中时用 buildRawDNSResponseFor 就地把
// txn id + question 改写成当前查询的（等长 + 0x20 论证见该函数注释），从而安全地在**不同 qid / 不同 0x20 大小写**的并发
// 与后续查询间复用同一份原始应答。缓存 key 含出口 deviceID → 不跨出口串味；只缓存确定性答复（NOERROR/NXDOMAIN），
// SERVFAIL 等软失败仅 serve 当前这批、不落缓存（同 A/AAAA）。
//
// 返回 true = 已中继并回应答（调用方到此为止）；仅「未选出口」返回 false（调用方走 server 本地上游）。**已绑定
// 出口**的会话若出口不在跑 / 投递失败 / 超时 → 回 SERVFAIL 并返回 true（fail-closed，防 HTTPS RR 的 ipv4hint/
// ipv6hint 被 server 地理答案污染——hint 与 A/AAAA 同病，只堵 A/AAAA 不堵 HTTPS 等于没堵）。
func tryRelayPublicViaExit(conn *net.UDPConn, peer *net.UDPAddr, query []byte, q dnsmessage.Question, qid uint16) bool {
	if conn == nil || peer == nil || len(query) == 0 {
		return false
	}
	vip, ok := netipAddrFromUDP(peer)
	if !ok {
		return false
	}
	egress := exitDeviceForClientVIP(vip)
	if egress == 0 {
		return false // 未选 peer 出口 → 本地上游解析即可
	}
	exitConn := lookupRunningExitConnByDevice(egress)
	if exitConn == nil {
		writeExitDNSServfail(conn, peer, qid, q) // 出口离线 → SERVFAIL（与数据面 fail-closed 对齐）
		return true
	}

	// 加速层：原始应答缓存 + 单飞（与 A/AAAA 共用同一张表 / 同一 singleflight，key 含 qtype 故天然不与 A/AAAA 混）。
	key := exitDNSCacheKey(egress, q.Type, normalizeQName(q))
	if e, hit := exitDNSCacheGet(key); hit {
		serveRawExitDNSFromCache(conn, peer, qid, query, e)
		magicDNSExitCacheHitCount.Add(1)
		return true
	}
	e, ok := resolveExitDNSRawCached(key, exitConn, query)
	if !ok {
		writeExitDNSServfail(conn, peer, qid, q) // 投递失败 / 超时 / 应答不可解析 → SERVFAIL（不回退本地上游）
		return true
	}
	serveRawExitDNSFromCache(conn, peer, qid, query, e)
	magicDNSViaExitRelayCount.Add(1)
	return true
}

// resolveExitDNSRawCached：非 A/AAAA（HTTPS/SVCB 等）经出口**原样中继**的核心（singleflight + 原始应答落缓存），
// 不做任何 I/O 回写，供网关路径与数据面 :53 拦截路径共用。返回 (缓存项, true)；失败 → (零值, false)。
func resolveExitDNSRawCached(key string, exitConn *Connection, query []byte) (exitDNSCacheEntry, bool) {
	res, err, _ := exitDNSGroup.Do(key, func() (any, error) {
		raw, rok := resolveExitDNS(exitConn, query)
		if !rok {
			return nil, errExitDNSResolveFailed
		}
		rcode, ttl, pok := parseRawDNSMeta(raw)
		if !pok {
			return nil, errExitDNSResolveFailed
		}
		e := buildRawExitDNSCacheEntry(raw, rcode, ttl)
		if exitDNSRcodeCacheable(rcode) {
			exitDNSCachePut(key, e)
		}
		return e, nil
	})
	if err != nil {
		return exitDNSCacheEntry{}, false
	}
	e, castok := res.(exitDNSCacheEntry)
	return e, castok
}

// resolveExitDNS 把一条 DNS 查询经 exitConn 转发到出口解析，返回响应（完整 DNS 应答报文，txn id 原样保留）。
// 失败（无 v4 网关 / 构包失败 / 超包 / 投递失败 / 超时）→ (nil,false)。
func resolveExitDNS(exitConn *Connection, query []byte) ([]byte, bool) {
	g := serverGatewayAddrs.Load()
	if g == nil || !g.v4.IsValid() {
		return nil, false // 无 v4 网关（纯 v6 部署等）→ 回退本地上游
	}
	ch := make(chan []byte, 1)
	port, ok := registerExitDNSWaiter(ch)
	if !ok {
		return nil, false // 关联端口耗尽（极端并发）→ 回退
	}
	defer unregisterExitDNSWaiter(port)

	pkt, ok := buildIPv4UDP(g.v4, port, exitDNSNominalResolver, 53, query)
	if !ok || len(pkt) > tunBufSize {
		return nil, false
	}
	if !deliverIPPacketToConn(exitConn, pkt) {
		return nil, false // 出口 TunChan 满 / 已下线
	}
	select {
	case resp := <-ch:
		return resp, len(resp) > 0
	case <-time.After(exitDNSWaitTimeout):
		return nil, false
	}
}

// registerExitDNSWaiter 分配一个未占用的关联端口并登记等待者。返回 (port, true)；无空闲端口时 (0,false)。
func registerExitDNSWaiter(ch chan []byte) (uint16, bool) {
	span := uint32(exitDNSPortHi-exitDNSPortLo) + 1
	exitDNSMu.Lock()
	defer exitDNSMu.Unlock()
	for i := 0; i < 128; i++ {
		p := exitDNSPortLo + uint16(exitDNSPortCtr.Add(1)%span)
		if _, used := exitDNSWaiters[p]; used {
			continue
		}
		exitDNSWaiters[p] = ch
		exitDNSInflight.Add(1)
		return p, true
	}
	return 0, false
}

// unregisterExitDNSWaiter 摘除等待者（幂等：截获路径可能已先摘除）。
func unregisterExitDNSWaiter(port uint16) {
	exitDNSMu.Lock()
	if _, ok := exitDNSWaiters[port]; ok {
		delete(exitDNSWaiters, port)
		exitDNSInflight.Add(-1)
	}
	exitDNSMu.Unlock()
}

// interceptExitDNSResponseIfPending 若 payload 是「经出口转发的 DNS 查询」的响应（出口→server：src=任意:53、
// dst=server v4 网关:关联端口，且该端口有等待者），截获其 UDP 载荷交回等待 goroutine，返回 true（调用方 continue，
// 不写 TUN）。零 in-flight 时仅一次 atomic load 即返回，热路径几乎无开销。
func interceptExitDNSResponseIfPending(payload []byte) bool {
	if exitDNSInflight.Load() == 0 {
		return false
	}
	_, dstIP, srcPort, dstPort, udp, ok := parseIPv4UDPForReturn(payload)
	if !ok || srcPort != 53 {
		return false // 只认「来自 :53」的回包（防使用方伪造应答注入关联端口）
	}
	if dstPort < exitDNSPortLo || dstPort > exitDNSPortHi {
		return false
	}
	g := serverGatewayAddrs.Load()
	if g == nil || !g.v4.IsValid() || dstIP != g.v4 {
		return false
	}
	exitDNSMu.Lock()
	ch, waiting := exitDNSWaiters[dstPort]
	if waiting {
		delete(exitDNSWaiters, dstPort) // 一次性：先摘除，防重复投递 / 与 resolveExitDNS 的 defer 双减
		exitDNSInflight.Add(-1)
	}
	exitDNSMu.Unlock()
	if !waiting {
		return false
	}
	// 复制 UDP 载荷：payload 底层是链路读缓冲，readLoop 之后会复用/归还。
	cp := make([]byte, len(udp))
	copy(cp, udp)
	select {
	case ch <- cp:
	default: // 等待者已超时退出（不应发生，摘除后仍兜底），丢弃
	}
	return true
}

// exitDeviceForClientVIP 返回该客户端 vIP 所属会话选定的出口 deviceID（egressDeviceID）；0 = 未选出口 / 未找到。
// 低频（仅公网 DNS 查询触发），扫 connIDMap 可接受；数据面热路径不走这里。
func exitDeviceForClientVIP(vip netip.Addr) int64 {
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	for _, c := range connIDMap {
		if c == nil || c.takenOver.Load() {
			continue
		}
		for _, a := range c.safeClientIPs() {
			if pa, err := netip.ParseAddr(a.VirtualIP); err == nil && pa == vip {
				return c.egressDeviceID.Load()
			}
		}
	}
	return 0
}

// connCreatedAtForClientVIP 返回该客户端 vIP 所属会话的注册时刻（createdAt）。found=false = 未找到会话。
// 供「会话早期竞速窗口 TTL 钳制」判定用；低频（仅上游转发路径触发），扫 connIDMap 可接受。
func connCreatedAtForClientVIP(vip netip.Addr) (time.Time, bool) {
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	for _, c := range connIDMap {
		if c == nil || c.takenOver.Load() {
			continue
		}
		for _, a := range c.safeClientIPs() {
			if pa, err := netip.ParseAddr(a.VirtualIP); err == nil && pa == vip {
				return c.createdAt, true
			}
		}
	}
	return time.Time{}, false
}

// netipAddrFromUDP 把 *net.UDPAddr 的 IP 转成 netip.Addr（v4-mapped 归一为 v4）。
func netipAddrFromUDP(u *net.UDPAddr) (netip.Addr, bool) {
	if u == nil || u.IP == nil {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(u.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// buildIPv4UDP 构造一份 IPv4+UDP 报文（计算 IPv4 头校验和与 UDP 校验和）。payload 即 UDP 数据（此处为 DNS 查询）。
func buildIPv4UDP(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, payload []byte) ([]byte, bool) {
	if !src.Is4() || !dst.Is4() {
		return nil, false
	}
	if len(payload) > 0xffff-28 {
		return nil, false
	}
	total := 20 + 8 + len(payload)
	b := make([]byte, total)
	// IPv4 头（20B，无选项）。
	b[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[6:8], 0x4000) // DF
	b[8] = 64                                  // TTL
	b[9] = 17                                  // protocol = UDP
	sa := src.As4()
	da := dst.As4()
	copy(b[12:16], sa[:])
	copy(b[16:20], da[:])
	binary.BigEndian.PutUint16(b[10:12], exitDNSIPv4Checksum(b[0:20]))
	// UDP 头（8B）+ 数据。
	udpLen := 8 + len(payload)
	binary.BigEndian.PutUint16(b[20:22], srcPort)
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	binary.BigEndian.PutUint16(b[24:26], uint16(udpLen))
	copy(b[28:], payload)
	binary.BigEndian.PutUint16(b[26:28], exitDNSUDPChecksumV4(sa, da, b[20:]))
	return b, true
}

// parseIPv4UDPForReturn 解析 IPv4+UDP 回包，取 src/dst IP、src/dst 端口、UDP 载荷。非 IPv4/UDP 或截断 → ok=false。
func parseIPv4UDPForReturn(p []byte) (srcIP, dstIP netip.Addr, srcPort, dstPort uint16, udpPayload []byte, ok bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || ihl+8 > len(p) {
		return
	}
	if p[9] != 17 { // UDP
		return
	}
	udpLen := int(binary.BigEndian.Uint16(p[ihl+4 : ihl+6]))
	if udpLen < 8 || ihl+udpLen > len(p) {
		return
	}
	var s, d [4]byte
	copy(s[:], p[12:16])
	copy(d[:], p[16:20])
	srcPort = binary.BigEndian.Uint16(p[ihl : ihl+2])
	dstPort = binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
	udpPayload = p[ihl+8 : ihl+udpLen]
	return netip.AddrFrom4(s), netip.AddrFrom4(d), srcPort, dstPort, udpPayload, true
}

// exitDNSIPv4Checksum 计算 IPv4 头部校验和（对 20B 头做反码求和）。
func exitDNSIPv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// exitDNSUDPChecksumV4 计算 IPv4 上 UDP 校验和（伪首部 + UDP 头 + 数据）。结果为 0 时按 RFC 768 用全 1 表示。
func exitDNSUDPChecksumV4(src, dst [4]byte, udp []byte) uint16 {
	var sum uint32
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	sum += 17 // protocol
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	if cs == 0 {
		cs = 0xffff
	}
	return cs
}
