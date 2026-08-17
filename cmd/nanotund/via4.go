package main

// via4（DNS46 + NAT46，SR-VIA4）：给 4via6 名字合成 **A 记录**，让「不发 AAAA 查询」的客户端也能用 via 名。
//
// 为什么需要（2026-08-17 iOS 真机结论，详见 blackhorse-mac PacketTunnelProvider 的 IOS-MESH-AAAA 注释）：
// Apple 平台在系统**没有 v6 默认路由**时全面抑制 AAAA 查询（AI_ADDRCONFIG 语义，mDNSResponder 日志
// "AAAA records are unusable"）。iOS 仅组网模式的物理网络多为 v4-only、隧道又只装窄路由 → AAAA-only 的
// 4via6 名字永远解析不出。客户端侧三种绕法（注 ::/0、/0 排除、enforceRoutes）全在真机上撞死（公网 v4
// 吸入隧道 / NECP 拒连），唯一正解是「别做 AAAA-only」——与 Tailscale 的 magicdns-aaaa 默认关闭同哲学。
//
// 方案：magic DNS 收到 via 名（<v4-dashed>via<siteID>.<suffix>）的 **A 查询**时，从专用 v4 池（默认
// 100.100.0.0/16，CGNAT 段，不与家庭/企业 LAN 冲突）分配一个池地址，登记 池地址 ⇔ (siteID, 目标v4)
// 映射并作为 A 记录返回；池网段经 routes-list 下发（客户端把它当普通已批准子网路由装进隧道，零客户端
// 改动）。数据面收到发往池地址的 v4 包 → 查映射改写成 4via6 v6 包（SIIT，RFC 7915 精简版）→ 汇入
// **现有的** forwardPacketToSubnetRoute 路径（站点路由 / 审批校验 / per-CIDR 门控 / ACL 全部复用）；
// 宣告方回程的 v6 包按「返程标记地址」拦截、反译回 v4 投给发起方。
//
// 返程为什么能做到**无状态**（无端口 NAT 表）：出向改写时把发起方的 v4 vIP 编进 v6 源地址（下方
// via4ReturnMarker 布局），宣告方 netstack 应答时按惯例对调 src/dst → 返程包的 dst 自带发起方身份、
// src（= 目标的 4via6 地址）自带 (siteID, 目标v4) → 两侧都可确定性还原，端口原样透传。
// 代价：不同发起方天然隔离（v6 src 不同），同发起方同目标的端口空间与直连一致，无冲突。
//
// 映射表为什么仍要存在：v4 池地址只有 32 位，装不下 (siteID 16 + 目标 32)，必须查表。表是**租约制**
// （DNS 应答 TTL=30s 让客户端频繁回来续；映射闲置 via4IdleTTL 后可被回收，池满时 LRU 驱逐），
// 重启丢表 → 池地址重新分配，进行中的连接断开（客户端重查 DNS 即恢复）——与 NAT64 部署的常识一致。
//
// 边界 / 已知限制：
//   - v4 分片包不翻译（丢弃计数）：mesh 内 TCP 由 MSS 钳制兜底，UDP > via4MaxV4Len 同样丢弃计数
//     （典型受害者是 >1200 字节的 UDP，LAN 场景罕见；后续可补 ICMPv4 Frag-Needed）。
//   - ICMP 只翻译 echo（ping 可用）；其它 ICMP 类型丢弃计数。
//   - IPv4 选项（IHL>5）随头重建被剥掉（RFC 7915 允许）。
//   - 池路由生效前提与原生 4via6 完全一致：客户端开着 accept-routes（fdbc:4a60::/64 也是这么装的）。

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/config"
)

// via4 统计（/status 的 MagicDNSStats 暴露聚合值；细分丢弃原因给排障用）。
var (
	via4AllocCount        atomic.Uint64 // DNS A 查询触发的新映射分配数
	via4EvictCount        atomic.Uint64 // 池满驱逐数（持续增长 = 池太小或站点·目标组合爆炸）
	via4ForwardedCount    atomic.Uint64 // 出向翻译并投递成功的包数
	via4ReturnedCount     atomic.Uint64 // 返程翻译并投回发起方的包数
	via4DropNoMapping     atomic.Uint64 // 池段 dst 无映射（映射被驱逐 / 客户端拿着陈旧 DNS 答案）
	via4DropUntranslate   atomic.Uint64 // 不可翻译（分片 / 超长 / 不支持的协议或 ICMP 类型 / 头非法）
	via4DropUnrouted      atomic.Uint64 // 翻译成功但子网路由路径未投递（自指 / 宣告方判定拒绝）
	via4DropReturnUnknown atomic.Uint64 // 返程标记包反译失败（src 非 4via6 / 映射缺失）
)

// via4IdleTTL：映射闲置多久后**可以**被驱逐（惰性回收——只在池满分配时清扫，不起后台 goroutine）。
// 取 4h：远大于常见长连接的静默期（TCP keepalive 默认 2h），闲置驱逐几乎不会误伤活连接；
// 真被驱逐的活连接下一包命中 via4DropNoMapping，客户端应用层重连 + 重查 DNS（TTL 30s）即自愈。
const via4IdleTTL = 4 * time.Hour

// via4MSSCeiling：翻译流的 TCP MSS 钳制上限。瓶颈是**客户端** mesh TUN 的 MTU（实测 1280，SYN 携带
// mss=1240）：v4 满包 1280 翻成 v6 变 1300 会超链路 → 把 MSS 钳到 1280-40(v6头)-20(tcp头)=1220，
// 保证翻译后 v6 包 ≤ 1280。两个方向的 SYN 都钳（LAN 侧服务器常给 1460）。
const via4MSSCeiling = 1220

// via4MaxV4Len：出向 v4 包长度上限（翻成 v6 后 +20 必须 ≤ 客户端 mesh MTU 1280）。超长且不可分片
// 处理（本实现不做翻译期分片）→ 丢弃计数。TCP 由 MSS 钳制天然不会触顶，UDP 罕见触顶。
const via4MaxV4Len = 1280 - 20

// via4ReturnMarker：返程 v6 地址的标记字节（b[8:10]），与真 4via6 的 reserved==0 区分。
// 布局：[via6Prefix 64][0x46 0xf4][0 0][发起方 v4 vIP 32]。落在同一个 fdbc:4a60::/64 内 →
// 客户端已装的 /64 路由天然覆盖、宣告方 netstack 应答可达；即使拦截缺位误入 4via6 站点路由，
// decode4via6 会得 siteID=0（b[10:12]=0，恒无效站点）→ 按 NoSite 丢弃，绝不误投。
const (
	via4ReturnMarker0 = 0x46
	via4ReturnMarker1 = 0xf4
)

// encodeVia4Return 把发起方 v4 vIP 编进返程 v6 地址（做翻译后 v6 包的 src）。
func encodeVia4Return(clientV4 netip.Addr) (netip.Addr, bool) {
	if !clientV4.Is4() {
		return netip.Addr{}, false
	}
	var b [16]byte
	p := via6Prefix.Addr().As16()
	copy(b[0:8], p[0:8])
	b[8] = via4ReturnMarker0
	b[9] = via4ReturnMarker1
	// b[10], b[11] = 0（保证误入站点路由时 siteID=0 无效）
	v4 := clientV4.As4()
	copy(b[12:16], v4[:])
	return netip.AddrFrom16(b), true
}

// decodeVia4Return 识别返程标记地址并解出发起方 v4 vIP。非标记地址 → ok=false。
func decodeVia4Return(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() || addr.Is4In6() || !via6Prefix.Contains(addr) {
		return netip.Addr{}, false
	}
	b := addr.As16()
	if b[8] != via4ReturnMarker0 || b[9] != via4ReturnMarker1 || b[10] != 0 || b[11] != 0 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
}

// via4Key：一个映射的语义身份 = (站点, 站点内目标 v4)。
type via4Key struct {
	siteID uint16
	v4     netip.Addr
}

// via4Mapping：池地址 ⇔ key 的一条租约。lastUsed 由 DNS 命中与数据面翻译双向 touch（atomic，读路径无锁）。
type via4Mapping struct {
	key      via4Key
	pool     netip.Addr
	lastUsed atomic.Int64 // unix nano
}

// via4Table：池 + 双向映射。mu 只保护 map 结构（分配/驱逐低频）；数据面查询走 RLock + atomic touch。
type via4Table struct {
	pool netip.Prefix
	mu   sync.RWMutex
	byKey  map[via4Key]*via4Mapping
	byPool map[netip.Addr]*via4Mapping
	cursor netip.Addr // 顺序分配游标（回绕扫描）
}

// via4State：运行态单例。nil = 功能关闭（默认关闭需显式 via4_pool="off"；magic_dns.enabled=false 也关闭）。
var via4State atomic.Pointer[via4Table]

// resolveVia4Pool 把配置字符串归一为 (池前缀, 是否启用)：
//   - ""            → 默认池 100.100.0.0/16（CGNAT 段，magic_dns 开着即启用——via 名开箱即用）
//   - "off"（不分大小写） → 显式关闭
//   - 其它          → 必须是合法 IPv4 CIDR（config.Validate 已 fail-fast，这里防御性复核）
func resolveVia4Pool(c config.MagicDNSConfig) (netip.Prefix, bool) {
	if !c.Enabled {
		return netip.Prefix{}, false
	}
	s := strings.ToLower(strings.TrimSpace(c.Via4Pool))
	if s == "off" {
		return netip.Prefix{}, false
	}
	if s == "" {
		s = config.DefaultVia4Pool
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p.Bits() > 28 {
		logrus.WithField("via4_pool", c.Via4Pool).Warn("[via4] 池配置非法（应为 IPv4 CIDR 且 ≤ /28），via4 关闭")
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// initVia4 在 magic DNS 启动后初始化 via4（server.go 启动路径调用一次）。meshCIDRs 用于冲突校验：
// 池与 mesh 网段重叠会让池地址被当 vIP demux，直接拒绝启用。
func initVia4(c config.MagicDNSConfig, meshCIDRs []string) {
	pool, ok := resolveVia4Pool(c)
	if !ok {
		via4State.Store(nil)
		return
	}
	for _, cs := range meshCIDRs {
		if cs == "" {
			continue
		}
		if mp, err := netip.ParsePrefix(cs); err == nil && mp.Addr().Is4() {
			if mp.Overlaps(pool) {
				logrus.WithFields(logrus.Fields{"via4_pool": pool.String(), "mesh": cs}).
					Error("[via4] 池与 mesh 网段重叠，via4 关闭（请换池网段）")
				via4State.Store(nil)
				return
			}
		}
	}
	t := &via4Table{
		pool:   pool,
		byKey:  make(map[via4Key]*via4Mapping),
		byPool: make(map[netip.Addr]*via4Mapping),
		cursor: pool.Addr(),
	}
	via4State.Store(t)
	logrus.WithField("pool", pool.String()).Info("[via4] 4via6 A 记录合成（DNS46+NAT46）已启用")
}

// via4PoolPrefix 返回启用中的池前缀（routes-list 下发用）。
func via4PoolPrefix() (netip.Prefix, bool) {
	t := via4State.Load()
	if t == nil {
		return netip.Prefix{}, false
	}
	return t.pool, true
}

// via4LookupOrAllocate：DNS A 查询路径——取 (siteID, 目标v4) 的池地址，无则分配。
// 调用方（magic_dns.go via6 分支）已完成站点存在性 / 宣告网段 / ACL / isolate 校验。
func via4LookupOrAllocate(siteID uint16, v4 netip.Addr) (netip.Addr, bool) {
	t := via4State.Load()
	if t == nil || !v4.Is4() {
		return netip.Addr{}, false
	}
	key := via4Key{siteID: siteID, v4: v4}
	t.mu.RLock()
	if m, ok := t.byKey[key]; ok {
		m.lastUsed.Store(time.Now().UnixNano())
		addr := m.pool
		t.mu.RUnlock()
		return addr, true
	}
	t.mu.RUnlock()
	return t.allocate(key)
}

// allocate 在写锁下分配一个空闲池地址；池满时驱逐 lastUsed 最旧的映射复用其地址。
func (t *via4Table) allocate(key via4Key) (netip.Addr, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if m, ok := t.byKey[key]; ok { // 双检：RLock 与 Lock 之间可能有并发分配
		m.lastUsed.Store(time.Now().UnixNano())
		return m.pool, true
	}
	addr, ok := t.nextFreeLocked()
	if !ok {
		addr, ok = t.evictOldestLocked()
		if !ok {
			return netip.Addr{}, false // 池空间为 0（配置极端小且全被占）——理论不可达
		}
	}
	m := &via4Mapping{key: key, pool: addr}
	m.lastUsed.Store(time.Now().UnixNano())
	t.byKey[key] = m
	t.byPool[addr] = m
	via4AllocCount.Add(1)
	return addr, true
}

// nextFreeLocked 从游标起回绕扫描一个未占用地址。跳过网络地址与广播地址（末地址）——
// 有些客户端栈会拒绝把 x.x.x.0 / 广播当单播目标。
func (t *via4Table) nextFreeLocked() (netip.Addr, bool) {
	first := t.pool.Addr().Next() // 跳过网络地址
	// 池内可用地址数（/16 → 65534）。回绕扫一圈找不到即满。
	total := 1 << (32 - t.pool.Bits())
	if total <= 2 {
		return netip.Addr{}, false
	}
	cur := t.cursor
	if !t.pool.Contains(cur) || cur == t.pool.Addr() {
		cur = first
	}
	for i := 0; i < total-2; i++ {
		if !t.pool.Contains(cur) || isVia4Broadcast(t.pool, cur) {
			cur = first
		}
		if _, used := t.byPool[cur]; !used {
			t.cursor = cur.Next()
			return cur, true
		}
		cur = cur.Next()
	}
	return netip.Addr{}, false
}

// isVia4Broadcast 报告 addr 是否是池的广播地址（末地址）。
func isVia4Broadcast(pool netip.Prefix, addr netip.Addr) bool {
	a := addr.As4()
	p := pool.Addr().As4()
	bits := pool.Bits()
	for i := 0; i < 4; i++ {
		var host byte
		switch {
		case bits >= (i+1)*8:
			host = 0
		case bits <= i*8:
			host = 0xff
		default:
			host = 0xff >> (bits - i*8)
		}
		if a[i] != p[i]|host {
			return false
		}
	}
	return true
}

// evictOldestLocked 驱逐 lastUsed 最旧的映射（优先驱逐闲置超 via4IdleTTL 的；没有则硬驱逐最旧），
// 返回腾出的池地址。
func (t *via4Table) evictOldestLocked() (netip.Addr, bool) {
	var oldest *via4Mapping
	for _, m := range t.byPool {
		if oldest == nil || m.lastUsed.Load() < oldest.lastUsed.Load() {
			oldest = m
		}
	}
	if oldest == nil {
		return netip.Addr{}, false
	}
	delete(t.byKey, oldest.key)
	delete(t.byPool, oldest.pool)
	via4EvictCount.Add(1)
	return oldest.pool, true
}

// via4PoolToKey：数据面出向——池地址反查 (siteID, 目标v4)，命中即 touch 租约。
func (t *via4Table) via4PoolToKey(pool netip.Addr) (via4Key, bool) {
	t.mu.RLock()
	m, ok := t.byPool[pool]
	t.mu.RUnlock()
	if !ok {
		return via4Key{}, false
	}
	m.lastUsed.Store(time.Now().UnixNano())
	return m.key, true
}

// via4KeyToPool：数据面返程——(siteID, 目标v4) 反查池地址（做反译后 v4 包的 src），命中即 touch。
func (t *via4Table) via4KeyToPool(key via4Key) (netip.Addr, bool) {
	t.mu.RLock()
	m, ok := t.byKey[key]
	t.mu.RUnlock()
	if !ok {
		return netip.Addr{}, false
	}
	m.lastUsed.Store(time.Now().UnixNano())
	return m.pool, true
}

// via4DataPlane：readLoop 数据面挂钩（uid fail-closed 之后、forwardPacketToSubnetRoute 之前调）。
// 返回 true = 本包归 via4 处理（已投递或按策略丢弃），调用方 continue；false = 与 via4 无关。
// 头部用裸字节快判（版本 + dst），不命中的包只多几次比较，不做完整解析。
func via4DataPlane(c *Connection, uid int64, payload []byte) bool {
	t := via4State.Load()
	if t == nil || len(payload) < 20 {
		return false
	}
	switch payload[0] >> 4 {
	case 4:
		dst := netip.AddrFrom4([4]byte(payload[16:20]))
		if !t.pool.Contains(dst) {
			return false
		}
		// 出向：发起方 v4 → 池地址。查映射 → SIIT 改写成 4via6 v6 包 → 走现有子网路由路径
		// （站点路由 / 审批 / per-CIDR / ACL 复用；返回 false 只剩自指或表竞态 → 丢弃，
		// 绝不落回出口路径把池段包发上公网）。
		key, ok := t.via4PoolToKey(dst)
		if !ok {
			via4DropNoMapping.Add(1)
			return true
		}
		src := netip.AddrFrom4([4]byte(payload[12:16]))
		v6pkt, ok := translateVia4ToV6(payload, key, src)
		if !ok {
			via4DropUntranslate.Add(1)
			return true
		}
		if forwardPacketToSubnetRoute(c, v6pkt) {
			via4ForwardedCount.Add(1)
		} else {
			via4DropUnrouted.Add(1)
		}
		return true
	case 6:
		if len(payload) < 40 {
			return false
		}
		dst, ok := netip.AddrFromSlice(payload[24:40])
		if !ok {
			return false
		}
		clientV4, ok := decodeVia4Return(dst)
		if !ok {
			return false
		}
		// 返程：宣告方应答（src=目标的 4via6 地址，dst=返程标记）。反译回 v4 →
		// 与原生 4via6 回程同口径过一次定向 ACL（宣告方 user → 发起方 user）→
		// 经 TUN hairpin 投回发起方（与 mesh vIP 回程 / 原生子网回程完全同路径）。
		v4pkt, ok := translateVia4ToV4(payload, t, clientV4)
		if !ok {
			via4DropReturnUnknown.Add(1)
			return true
		}
		if aclDropPacketDirected(uid, v4pkt) {
			return true
		}
		pkt := tunPktBufPool.Get().([]byte)
		n := copy(pkt, v4pkt)
		select {
		case tunWriteChan <- pkt[:n]:
			via4ReturnedCount.Add(1)
		default:
			tunWriteDropCount.Add(1)
			tunPktBufPool.Put(pkt)
		}
		return true
	}
	return false
}
