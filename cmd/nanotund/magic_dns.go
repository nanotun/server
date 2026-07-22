package main

// P2#11 Magic DNS(2026-05-22):server 内置 UDP DNS server,把 peer 主机名解析成 vIP。
//
// 设计:
//   - 监听 UDP <listenAddr>:<listenPort>(典型 TUN gateway IP:5353)。
//   - 拦截 *.<DomainSuffix> 类查询(例如 "alice-mac.alice.lan"),
//     拆 host + user → 查 store(devices + leases)→ 拼 A/AAAA 响应。
//   - 其它域名转发到上游(若配置 upstream_v4/v6),无 upstream → SERVFAIL。
//   - 永远不做递归,不解 NS,不签 DNSSEC;就是个 stub forwarder + magic 拦截器。
//
// 安全 / 边界:
//   - DNS server 仅 listen 在 gateway IP(TUN 内可达),不暴露 WAN。
//   - 任何已建 VPN 的客户端可以查全表 —— 与 Magic DNS 的"组网工具透明性"语义一致。
//     真正的访问控制由 store/acl + iptables 完成,不在 DNS 这一层加限制。
//   - 把上游 DNS 查询并发上限设为 64(单 server 防 DoS),超出后直接 SERVFAIL。
//   - hostname 在写入 DB 时已 truncate(DeviceNameMaxLen=128),不做二次校验。
//
// 与 [tun].dns_servers_v4 / v6 的关系:
//   - magic_dns.enabled=false → 完全跳过本模块,客户端 DNSServersV4 维持 [tun] 值;
//   - magic_dns.enabled=true  → 启动 UDP listener;客户端 DNSServersV4 在登录路径上
//     被 prepend 一个"gateway_ip"条目(见 server.go 中 dnsForClient 改造,本期 server 端
//     先实现 DNS 服务,客户端 prepend 逻辑由 server.go 在下一处提交补齐)。
//
// 该模块依赖:
//   - gw.store    : 查 user / device / lease;
//   - listenAddr  : 通常等于 TUN gateway IP(server 启动时确定);
//   - dnsmessage  : golang.org/x/net/dns/dnsmessage,纯 Go 解析 DNS 报文,不引入 cgo。

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 统计指标(/health 暴露,便于运维看 Magic DNS 是否健康)。
var (
	magicDNSQueryCount       atomic.Uint64
	magicDNSMagicHitCount    atomic.Uint64
	magicDNSUpstreamCount    atomic.Uint64
	magicDNSServfailCount    atomic.Uint64
	magicDNSUnknownNameCount atomic.Uint64
	magicDNSMalformedCount   atomic.Uint64
	// F1(2026-05-22):in-flight concurrency cap 触顶时 drop 的次数。
	// 触顶 = 同时有 magicDNSInflightCap 个 query 还没回完,新 query 直接 drop。
	// 客户端 stub resolver 会自然 timeout 重试,服务端不写 SERVFAIL 回包以省 CPU。
	magicDNSInflightDropCount atomic.Uint64
	// magicDNSPerClientDropCount：单客户端在途上限（magicDNSPerClientCap）触顶时 drop 的次数。
	// 与 InflightDrops 区分：这是「某个客户端刷太猛、只丢它自己的多余查询」，不影响其它用户。
	magicDNSPerClientDropCount atomic.Uint64
	// magicDNSEarlyClampCount：会话早期窗口内被钳短 TTL 的上游应答数（见 magicDNSEarlyClampWindow）。
	magicDNSEarlyClampCount atomic.Uint64
	// magicDNSServerAAAAStripCount：server 自出口路径（会话未绑 peer 出口）且 server 本机无 v6 公网出网时，
	// 被就地回 NODATA 的 AAAA 查询数。与出口路径的 magicDNSAAAAStripCount 分开计，便于区分两条路径。
	magicDNSServerAAAAStripCount atomic.Uint64
	// magicDNSMeshOffNXCount（2026-07-19）：组网总开关 OFF 时被就地 NXDOMAIN 的**跨用户** magic 名查询数。
	// 与数据面 meshOffDropCount 对齐口径——解析层不再给出「连不上的地址」。
	magicDNSMeshOffNXCount atomic.Uint64
)

// 会话早期「竞速窗口」TTL 钳制（2026-07-17）。
//
// 问题：客户端连上隧道后，OS（尤其苹果 mDNSResponder）**立刻**开始发 DNS 查询，而 EgressSelect（出口绑定）帧
// 要在链路就绪后才发出/处理——这几百毫秒~几秒的窗口里会话尚未绑定出口（egress==0），公网查询全部由 server 本地
// 上游作答（server 地理，如新加坡）。若客户端随后绑定了墙内出口，这批「错地理」的答案已按上游 TTL（几十秒~几分钟）
// 写进客户端 OS 缓存 → 首屏连到 overseas CDN 边缘，经墙内出口是烂路由/不可达 → 「第一次打开卡住、刷新才好」
// （iOS 隧道频繁重建，每次唤醒都重演一遍，故 iOS 感知远比桌面差）。
//
// 修法：会话建立后的前 magicDNSEarlyClampWindow 内，凡由 **server 本地上游**作答的响应，把 TTL 钳到
// magicDNSEarlyClampTTL——即便答案地理错了，也在几秒内过期，客户端重查时绑定已完成 → 经出口拿到正确地理。
// 代价仅是新会话头几秒多几次重查，对永不绑出口的会话影响可忽略。经出口路径（tryResolvePublicViaExit）不钳
// （其答案地理本来就对）。
const (
	magicDNSEarlyClampWindow = 15 * time.Second
	magicDNSEarlyClampTTL    = 2 // 秒
)

// magicDNSPerClient 记录每个客户端（键=vIP）当前在途的 DNS query 数，用于 magicDNSPerClientCap 限流。
// 键空间受 mesh vIP 数量约束（有界）；在途计数归零时由 release() 用 CompareAndDelete **就地驱逐**
// 空条目（第三轮深扫 L10），避免 vIP 长期 churn 下 map 只增不减地缓慢泄漏。
var magicDNSPerClient sync.Map // netip.Addr -> *atomic.Int32

// magicDNSInflightCap 是**全服务器**同时在处理的 DNS query 总量上限（单一全局信号量，所有客户端 / 会话 / 查询
// 类型共用）。它只是**总量天花板**（护内存 + 关联端口区间 40000-60000 ≈ 2 万上限），不是吞吐限制——Go goroutine
// 极廉价，4096 个即便都阻塞在 select（经出口等 exitDNSWaitTimeout）也不过 ~数十 MB。
//
// 历史：原为 64（配 forwardMagicDNSToUpstream 的 800ms 超时 ≈ 80 QPS），对「组网内部 .lan 查询」够用；但
// direction-1「经出口解析」每条最多占位 exitDNSWaitTimeout（2s），且苹果端每主机名并发 A+AAAA+HTTPS，一个页面
// 瞬间几十上百条 → 64 位很快占满 → 新查询被 drop、mDNSResponder 重发 → 不秒开。64 定得过于保守。
//
// 关键：**公平性 / 抗单点滥用不靠掐全局总量，而靠 magicDNSPerClientCap 按客户端限流**——否则一个用户猛刷就能占满
// 全局池、饿死其他所有人（这才是原设计的真缺陷）。全局池放大 + 每客户端限流后：可服务的并发客户端数 ≈
// magicDNSInflightCap / magicDNSPerClientCap，且单客户端再怎么突发也只占自己那一份。4096 / 64 ≈ 同时 64 个
// 客户端满速突发；实际多数查询远快于 2s、占坑短，有效并发客户端数更高。需要更多可继续调大（成本极低）。
const magicDNSInflightCap = 4096

// magicDNSPerClientCap 是**单个客户端**（按 vIP 归并其多个源端口）同时在途的 DNS query 上限。防止一个客户端
// （尤其苹果端一次页面并发几十条 A+AAAA+HTTPS）占满全局池、拖垮其他用户——这是「按来源限流」的正确 DoS 姿势。
// 64 足够覆盖单个页面的正常突发；超出的只丢**该客户端自己**的多余查询（它自然重试），不波及别人。
const magicDNSPerClientCap = 64

// magicDNSInflight 是 channel-based semaphore;cap = magicDNSInflightCap。
// runMagicDNSLoop 主循环里非阻塞 `sem <- struct{}{}`,失败即 drop。
// handleMagicDNSPacket 完成后 `<-sem`。
var magicDNSInflight = make(chan struct{}, magicDNSInflightCap)

// MagicDNSStats 返回当前累计计数,主要给 /status 端点用。
type MagicDNSStats struct {
	Queries       uint64 `json:"queries"`
	MagicHit      uint64 `json:"magic_hit"`
	Upstream      uint64 `json:"upstream"`
	Servfail      uint64 `json:"servfail"`
	UnknownName   uint64 `json:"unknown_name"`
	Malformed     uint64 `json:"malformed"`
	InflightDrops uint64 `json:"inflight_drops"`
	// PerClientDrops：单客户端在途上限触顶被丢的查询数（只影响那个刷太猛的客户端，不波及其他人）。
	PerClientDrops uint64 `json:"per_client_drops"`
	// ViaExit：命中「经 peer 出口解析」的公网查询数（direction 1，A/AAAA，解析 + 缓存，见 magic_dns_exit.go）。
	ViaExit uint64 `json:"via_exit"`
	// ViaExitRelay：经出口**原样中继**（HTTPS/SVCB，不解析 / 不缓存）的公网查询数（direction 1）。
	ViaExitRelay uint64 `json:"via_exit_relay"`
	// AAAAStrip：所选出口无 v6 出网时就地回 NODATA（不绕出口）的 AAAA 查询数（direction 1）。
	AAAAStrip uint64 `json:"aaaa_strip"`
	// AAAAStripServer：server 自出口（未绑 peer 出口）且 server 本机无 v6 公网出网时就地回 NODATA 的 AAAA 查询数。
	AAAAStripServer uint64 `json:"aaaa_strip_server"`
	// ExitCacheHits：经出口结果缓存命中的查询数（免掉一次经出口往返，见 magic_dns_cache.go）。
	ExitCacheHits uint64 `json:"exit_cache_hits"`
	// ExitServfail：绑定出口的会话经出口解析失败（离线/超时）→ 回 SERVFAIL 的次数（fail-closed，不再回退
	// server 本地上游）。持续增长 = 出口链路不健康。
	ExitServfail uint64 `json:"exit_servfail"`
	// EarlyTTLClamp：会话早期竞速窗口内被钳短 TTL 的上游应答数（防「绑出口前的 server 地理答案」长期污染客户端缓存）。
	EarlyTTLClamp uint64 `json:"early_ttl_clamp"`
	// InterceptDNS：数据面拦截的「绑定出口会话直发公共 resolver 的 UDP :53 查询」数（改经出口解析 + AAAA 剥离，
	// 堵住绕过网关 MagicDNS 的 8.8.8.8 等直查，见 magic_dns_intercept.go）。
	InterceptDNS uint64 `json:"intercept_dns"`
	// MeshOffNX：组网总开关 OFF 时被就地 NXDOMAIN 的跨用户 magic 名查询数（与数据面 mesh_off drop 同口径）。
	MeshOffNX uint64 `json:"mesh_off_nxdomain"`
}

func snapshotMagicDNSStats() MagicDNSStats {
	return MagicDNSStats{
		Queries:         magicDNSQueryCount.Load(),
		MagicHit:        magicDNSMagicHitCount.Load(),
		Upstream:        magicDNSUpstreamCount.Load(),
		Servfail:        magicDNSServfailCount.Load(),
		UnknownName:     magicDNSUnknownNameCount.Load(),
		Malformed:       magicDNSMalformedCount.Load(),
		InflightDrops:   magicDNSInflightDropCount.Load(),
		PerClientDrops:  magicDNSPerClientDropCount.Load(),
		ViaExit:         magicDNSViaExitCount.Load(),
		ViaExitRelay:    magicDNSViaExitRelayCount.Load(),
		AAAAStrip:       magicDNSAAAAStripCount.Load(),
		AAAAStripServer: magicDNSServerAAAAStripCount.Load(),
		ExitCacheHits:   magicDNSExitCacheHitCount.Load(),
		ExitServfail:    magicDNSExitServfailCount.Load(),
		EarlyTTLClamp:   magicDNSEarlyClampCount.Load(),
		InterceptDNS:    magicDNSInterceptCount.Load(),
		MeshOffNX:       magicDNSMeshOffNXCount.Load(),
	}
}

// magicDNSDefaults 把 config 上的零值翻译成实际生效值。
type magicDNSResolved struct {
	suffix   string // 不带前缀点,小写
	port     uint16
	upstream []string
}

func resolveMagicDNSConfig(c config.MagicDNSConfig) magicDNSResolved {
	suf := strings.ToLower(strings.Trim(strings.TrimSpace(c.DomainSuffix), "."))
	if suf == "" {
		suf = "lan"
	}
	port := c.ListenPort
	if port == 0 {
		// P_a1_fix(2026-05-22):默认 53,不是 5353。
		// 原因:客户端通过 LoginResp 拿到的 DNS server 列表(SaltMsg.dns_servers_v4)
		// 只是 IP 字符串(无 port),OS 的 stub resolver 永远把查询打到 :53。
		// 默认 5353 会让"启用 magic_dns"的运维以为生效了,实际 server 在 :5353
		// 上空跑一个 listener,客户端从来打不到。server 进程已经 root(TUN 需要),
		// 绑 :53 没成本;运维想换 5353 → 显式 listen_port=5353 + 自己解决客户端
		// stub resolver 如何打非 53 端口的问题(典型方案:不要 prepend gateway,
		// 用 dnsmasq / systemd-resolved 当转发器),server 端会在 magicDNSExtraDNS
		// 路径上为非 53 端口跳过 prepend + 打 Warn,避免误报"生效"。
		port = 53
	}
	up := make([]string, 0, len(c.UpstreamV4)+len(c.UpstreamV6))
	for _, s := range c.UpstreamV4 {
		if s = strings.TrimSpace(s); s != "" {
			if !strings.Contains(s, ":") {
				s = s + ":53"
			}
			up = append(up, s)
		}
	}
	for _, s := range c.UpstreamV6 {
		if s = strings.TrimSpace(s); s != "" {
			if !strings.Contains(s, "]:") {
				s = "[" + strings.Trim(s, "[]") + "]:53"
			}
			up = append(up, s)
		}
	}
	return magicDNSResolved{suffix: suf, port: port, upstream: up}
}

// startMagicDNS 在 listenAddr 上启动 UDP DNS server。
//
// listenAddr 为空(典型:TUN 未配 / 仅 IPv6)时直接 no-op,返回 cleanup 也是 no-op。
// gw.store 为 nil(测试)时也直接 no-op。
//
// 返回值:cleanup 函数,主进程 defer 调用以关 socket;失败时返回的 cleanup 仍可调用(no-op)。
func startMagicDNS(gw *gatewayState, listenAddr string) func() {
	if gw == nil || gw.store == nil || gw.cfg == nil {
		return func() {}
	}
	if !gw.cfg.Server.MagicDNS.Enabled {
		return func() {}
	}
	if listenAddr == "" {
		logrus.Warn("[magic-dns] listen_addr 为空(TUN gateway 未就绪),跳过 Magic DNS 启动")
		return func() {}
	}
	resolved := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	addr := net.UDPAddr{
		IP:   net.ParseIP(listenAddr),
		Port: int(resolved.port),
	}
	if addr.IP == nil {
		logrus.WithField("listen_addr", listenAddr).Error("[magic-dns] listen_addr 不是合法 IP,跳过启动")
		return func() {}
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		logrus.WithError(err).WithField("addr", addr.String()).Error("[magic-dns] 启动 UDP DNS server 失败")
		return func() {}
	}
	logrus.WithFields(logrus.Fields{
		"addr":     addr.String(),
		"suffix":   resolved.suffix,
		"upstream": resolved.upstream,
	}).Info("[magic-dns] 已启动")

	go safeGlobalGoroutine("magicDNS", globalContextCancel, func() {
		runMagicDNSLoop(globalContext, gw, conn, resolved)
	})
	return func() { _ = conn.Close() }
}

// runMagicDNSLoop 主循环:阻塞读 UDP → handleMagicDNSPacket → 写响应。
//
// 每个 query 在自己的 goroutine 里处理(简单 fan-out;DNS 报文最大 512B / EDNS 4KB,
// 不需要复杂队列)。读取 UDP 报文 + 限制大小,避免内存压力。
func runMagicDNSLoop(ctx context.Context, gw *gatewayState, conn *net.UDPConn, r magicDNSResolved) {
	buf := make([]byte, 1500) // 一般 DNS query ≤ 512B;1500 给 EDNS 留余量
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue // 借此 tick 检查 ctx.Done
			}
			logrus.WithError(err).Debug("[magic-dns] ReadFromUDP 错误")
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])

		// F1:in-flight 上限。全局池满 / 单客户端超限即 drop,绝不阻塞主 read loop
		// (否则 attacker 持续灌包能把 ReadFromUDP 队列堵满 → 内核丢包,反而隐藏问题);
		// drop 只走计数,不回 SERVFAIL,客户端 stub resolver 会自然 timeout 重试。
		clientKey, haveKey := netipAddrFromUDP(peer)
		release, ok := tryAcquireMagicDNSSlot(clientKey, haveKey)
		if !ok {
			continue
		}
		go func() {
			defer release()
			handleMagicDNSPacket(ctx, gw, conn, peer, query, r)
		}()
	}
}

// tryAcquireMagicDNSSlot 为来自 clientKey 的一条查询占坑：先抢**全局**位（护总内存 / 关联端口），再抢**每客户端**
// 位（护公平 / 抗单点滥用）。两者都拿到才放行。
//   - 全局满 → (nil,false)，记 magicDNSInflightDropCount；
//   - 单客户端超 magicDNSPerClientCap → 归还刚拿到的全局位，(nil,false)，记 magicDNSPerClientDropCount；
//   - 成功 → (release,true)，调用方**必须**在处理完 defer release() 归还两个位。
//
// haveKey=false（peer 无法解析出 vIP，正常不会发生）时跳过每客户端限流、仅受全局约束。
func tryAcquireMagicDNSSlot(clientKey netip.Addr, haveKey bool) (release func(), ok bool) {
	select {
	case magicDNSInflight <- struct{}{}:
	default:
		magicDNSInflightDropCount.Add(1)
		return nil, false
	}
	var clientCnt *atomic.Int32
	if haveKey {
		v, _ := magicDNSPerClient.LoadOrStore(clientKey, new(atomic.Int32))
		clientCnt = v.(*atomic.Int32)
		if clientCnt.Add(1) > magicDNSPerClientCap {
			clientCnt.Add(-1)
			<-magicDNSInflight
			magicDNSPerClientDropCount.Add(1)
			return nil, false
		}
	}
	return func() {
		<-magicDNSInflight
		if clientCnt != nil {
			if clientCnt.Add(-1) == 0 {
				// 归零即驱逐(第三轮深扫 L10):否则 vIP 随租约释放 / 重分配长期 churn 时,map 里会堆积
				// 一堆计数为 0 的空 *atomic.Int32,寿命等于进程 —— 单条极小但只增不减,长跑服务下缓慢泄漏。
				//
				// 必须用 CompareAndDelete(而非 Delete):仅当「当前存的仍是本计数器指针」时才删。若此刻有并发
				// LoadOrStore 拿到**同一**指针并 Add(1),CAD 仍可能删掉一个刚变正的计数器 → 该指针被后续查询
				// 继续用(orphaned),而新查询 LoadOrStore 出新计数器。后果仅是该客户端瞬时可多占一份(≤2×cap),
				// 全局池(magicDNSInflightCap)仍封顶,属可接受的软上限松弛;且 orphaned 指针的 Add(-1) 归零时
				// CAD 因指针不匹配(map 已换新指针)会安全空操作,不会误删活跃项。
				magicDNSPerClient.CompareAndDelete(clientKey, clientCnt)
			}
		}
	}, true
}

// handleMagicDNSPacket 处理一个 UDP 报文。失败路径都写 SERVFAIL,绝不静默吞包。
//
// 解析顺序:
//  1. dnsmessage.Parser 解头 + 第一个 Question;
//  2. Question.Type/Class 必须是 A/AAAA + IN;
//  3. Question.Name 拆 host.user.<suffix>;
//  4. magic 命中 → 查 store → 拼 RR;否则 → upstream forward;
//  5. 写响应。
func handleMagicDNSPacket(ctx context.Context, gw *gatewayState, conn *net.UDPConn, peer *net.UDPAddr, query []byte, r magicDNSResolved) {
	magicDNSQueryCount.Add(1)

	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		magicDNSMalformedCount.Add(1)
		return
	}
	q, err := p.Question()
	if err != nil {
		magicDNSMalformedCount.Add(1)
		_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeFormatError, nil, dnsmessage.Question{})
		return
	}

	switch q.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		// 走下面正常路径
	default:
		name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
		// mesh 内网名（*.<suffix>）的**非 A/AAAA** 查询：必须本地作答，**绝不外发公网上游**。原实现一律 forward
		// 到公网 resolver → ① 内网主机名（如 mac.alice.lan）明文泄漏给公网 DNS；② 公网对 .lan 回 NXDOMAIN（"整个
		// 名字不存在"），部分 stub/resolver 会聚合负缓存该名 → 连累**同名 A/AAAA** 查询被否掉，mesh 名解析时好时坏。
		// 浏览器现在每次导航都并发查 HTTPS，命中概率远高于过去的 MX/TXT，故必须堵。主机存在 → NODATA（NOERROR/0
		// answer，本地权威、不泄漏、不给 NXDOMAIN）；不存在 → NXDOMAIN。两者都不出网。
		if isMagicDomain(name, r.suffix) {
			// mesh-off 一致性(2026-07-19):跨用户 magic 名与 A/AAAA 路径同口径 NXDOMAIN(见下方注释)。
			if magicNameDeniedByMeshOff(ctx, gw, peer, name, r.suffix) {
				magicDNSMeshOffNXCount.Add(1)
				_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeNameError, nil, q)
				return
			}
			if magicHostExists(ctx, gw, name, r.suffix) {
				_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeSuccess, nil, q)
			} else {
				magicDNSUnknownNameCount.Add(1)
				_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeNameError, nil, q)
			}
			return
		}
		// direction 1（HTTPS/SVCB 地理修正）：浏览器对每站点并发查 HTTPS(65)/SVCB(64)，其 RR 内的
		// ipv4hint/ipv6hint 同样被 CDN 按解析位置就近。公网名若来自「选了 peer 出口」的会话，也经**出口**中继解析
		// （让 hint 反映出口地理，与下方 A/AAAA 的 tryResolvePublicViaExit 一致，避免只修了 A/AAAA 却漏了 HTTPS）。
		// 命中即到此为止，出口不可用/超时 fail-open 回退下面的 upstream。其它类型 (MX/TXT/PTR/…) 无「按解析位置就近」
		// 语义，维持原样 forward。
		if q.Class == dnsmessage.ClassINET && (q.Type == dnsmessage.TypeHTTPS || q.Type == dnsmessage.TypeSVCB) {
			if tryRelayPublicViaExit(conn, peer, query, q, hdr.ID) {
				return
			}
		}
		// 其它类型(MX / TXT / PTR / ...) 一律 forward(若有 upstream)否则 NOTIMP。
		if len(r.upstream) > 0 {
			forwardMagicDNSToUpstream(ctx, conn, peer, query, r)
			return
		}
		_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeNotImplemented, nil, q)
		return
	}
	if q.Class != dnsmessage.ClassINET {
		_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeNotImplemented, nil, q)
		return
	}

	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	if isMagicDomain(name, r.suffix) {
		// mesh-off 一致性(2026-07-19 深扫瑕疵修复):组网总开关 OFF 时,**跨用户**的 magic 名直接
		// NXDOMAIN——此前照常解析出 vIP/4via6 地址,而数据面必丢(mesh_off),客户端表现为「域名解析
		// 成功、连接却超时」,排障时极易误判成网络故障。解析层与数据面对齐:同用户名字照常解析,
		// 跨用户查不到名字、秒得 NXDOMAIN,故障面清晰。开关恢复 ON 后立即恢复解析(读的是 ACL 快照)。
		if magicNameDeniedByMeshOff(ctx, gw, peer, name, r.suffix) {
			magicDNSMeshOffNXCount.Add(1)
			_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeNameError, nil, q)
			return
		}
		// SR-VIA6：先试 4via6 主机名 "<v4-dashed>via<siteID>.<suffix>"（Tailscale 式，如 192-168-1-10via7）→ 该站点内网
		// 主机的 4via6 AAAA。site_id 全局唯一（via6_sites AUTOINCREMENT），名字不含 user/device → 天然无重名歧义。
		// 命中(单段、形如 <v4-dashed>via<digits>)即走 4via6；否则落到下方普通 "host.user" 设备 vIP 查询。
		if v4, siteID, okv := parseVia6Hostname(name, r.suffix); okv {
			addr, ok := lookupVia6Addr(ctx, gw.store, siteID, v4)
			if !ok {
				magicDNSUnknownNameCount.Add(1)
				_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeNameError, nil, q)
				return
			}
			// addr 是 4via6(v6)：AAAA 查询返回它；A 查询按类型过滤得空 answer（NOERROR/0，OS 自会转查 AAAA）。
			resp, err := buildMagicDNSAnswer(hdr.ID, q, []netip.Addr{addr})
			if err != nil {
				magicDNSServfailCount.Add(1)
				_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeServerFailure, nil, q)
				return
			}
			magicDNSMagicHitCount.Add(1)
			_, _ = conn.WriteToUDP(resp, peer)
			return
		}
		host, user, ok := parseMagicHostname(name, r.suffix)
		if !ok {
			magicDNSUnknownNameCount.Add(1)
			_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeNameError, nil, q)
			return
		}
		addrs, ok := lookupMagicHost(ctx, gw.store, user, host)
		if !ok || len(addrs) == 0 {
			magicDNSUnknownNameCount.Add(1)
			_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeNameError, nil, q)
			return
		}
		resp, err := buildMagicDNSAnswer(hdr.ID, q, addrs)
		if err != nil {
			magicDNSServfailCount.Add(1)
			_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeServerFailure, nil, q)
			return
		}
		magicDNSMagicHitCount.Add(1)
		_, _ = conn.WriteToUDP(resp, peer)
		return
	}

	// direction 1（exit-node DNS 地理修正）：公网域名若来自「选了 peer 出口」的会话，经**出口**解析（反映出口
	// 地理，修 CDN 就近调度到对出口是烂路由的边缘节点）。命中即到此为止；未选出口 / 出口不可用 / 超时 → fail-open
	// 回退下面的 server 本地上游。详见 magic_dns_exit.go。
	if tryResolvePublicViaExit(conn, peer, query, q, hdr.ID) {
		return
	}
	// v6 能力感知（server 自出口，与出口路径 tryResolvePublicViaExit 的 strip 分支同语义）：会话未绑出口时公网名
	// 由 server 本地上游解析，若 **server 本机无 v6 公网出网**（60s 端到端探测，见 egress_select.go），AAAA 答案
	// 注定无用——数据面 serverSelfEgressV6FastFail 会对发往它的公网 v6 回 ICMPv6 unreachable。就地回 NODATA：
	// 客户端立即用 A(v4)，省掉「拿 AAAA → 发 v6 → 等 ICMPv6 打回」的整个来回，也砍掉苹果端一半上游查询量。
	// magic 名（vIP/4via6）在上面已作答不受影响；探测未出结果（启动极短窗口）保守不剥。
	if shouldStripAAAAForServerSelf(q.Type, serverV6EgressKnown.Load(), serverV6EgressHas.Load()) {
		if resp, berr := buildMagicDNSAnswer(hdr.ID, q, nil); berr == nil {
			_, _ = conn.WriteToUDP(resp, peer)
		}
		magicDNSServerAAAAStripCount.Add(1)
		return
	}
	// 非 magic suffix → 走 upstream(若有);否则 SERVFAIL。
	if len(r.upstream) == 0 {
		magicDNSServfailCount.Add(1)
		_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeServerFailure, nil, q)
		return
	}
	forwardMagicDNSToUpstream(ctx, conn, peer, query, r)
}

// isMagicDomain 判断 q name 是否以 ".<suffix>" 结尾(去尾点后比较)。
// 完全等于 suffix(查根域)不视为 magic,直接 forward。
func isMagicDomain(name, suffix string) bool {
	if name == "" || suffix == "" {
		return false
	}
	if name == suffix {
		return false
	}
	return strings.HasSuffix(name, "."+suffix)
}

// parseMagicHostname 拆 "host.user.<suffix>" → (host, user, true)。
// 多于 3 段(如 "a.b.c.lan")或少于 3 段(如 "alice.lan")都视为不合法,返回 ok=false。
// 这是有意的严格化:让 user-level 命名空间清晰,避免 hierarchical fallback 引发歧义。
func parseMagicHostname(name, suffix string) (host, user string, ok bool) {
	rest := strings.TrimSuffix(name, "."+suffix)
	if rest == "" {
		return "", "", false
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 2 {
		return "", "", false
	}
	host = strings.TrimSpace(parts[0])
	user = strings.TrimSpace(parts[1])
	if host == "" || user == "" {
		return "", "", false
	}
	return host, user, true
}

// parseVia6Hostname 拆 4via6 主机名 "<v4-dashed>via<siteID>.<suffix>"（Tailscale 式，如 192-168-1-10via7）
// → (目标内网 v4, siteID)。
//
// 为何用 siteID 而非设备名（对齐 Tailscale 4via6）：site_id 是 via6_sites 的 AUTOINCREMENT 主键、**全局唯一且稳定**，
// 而设备名（device_name）在同一用户下都可能重名 → 若把设备名塞进 4via6 名（旧式 <v4>.<device>.<user>）会因重名而
// 解析到错误站点甚至 fail-closed。故 4via6 名只含「目标 v4 + 数字 siteID」，与设备名/用户名彻底解耦、绝无歧义
// （原始 4via6 IPv6 本就只由 siteID+v4 构成、且全局可寻址，去掉 user 段不引入新的信息暴露；数据面仍受 ACL/宣告网段闸控）。
//
// 首段须是「点换连字符」的 IPv4（192-168-1-10 = 192.168.1.10），紧跟 "via" + 十进制 siteID(1..65535)。为可读性也接受
// "-via-" 变体（192-168-1-10-via-7）。rest 必须是**单段**（不含 "."，与 2 段的普通设备名查询区分）；否则 ok=false，
// 交回 parseMagicHostname 走普通 "host.user" 查询。
func parseVia6Hostname(name, suffix string) (v4 netip.Addr, siteID uint16, ok bool) {
	rest := strings.TrimSuffix(name, "."+suffix)
	if rest == "" || rest == name {
		return netip.Addr{}, 0, false
	}
	// 4via6 名是单段（v4-dashed + via + siteID），不含 "."。含 "." 的交回普通设备名查询。
	if strings.Contains(rest, ".") {
		return netip.Addr{}, 0, false
	}
	i := strings.Index(rest, "via")
	if i <= 0 {
		return netip.Addr{}, 0, false
	}
	left := strings.TrimSuffix(rest[:i], "-")             // v4-dashed（容忍 "-via-" 变体的前导 '-'）
	right := strings.TrimPrefix(rest[i+len("via"):], "-") // siteID（容忍 "-via-" 变体的尾随 '-'）
	if left == "" || right == "" {
		return netip.Addr{}, 0, false
	}
	ip, perr := netip.ParseAddr(strings.ReplaceAll(left, "-", "."))
	if perr != nil || !ip.Is4() {
		return netip.Addr{}, 0, false
	}
	sid, perr := strconv.ParseUint(right, 10, 16)
	if perr != nil || sid == 0 { // site_id AUTOINCREMENT 从 1 起，0 恒非法
		return netip.Addr{}, 0, false
	}
	return ip, uint16(sid), true
}

// lookupVia6Addr 把 (siteID, 目标内网 v4) → 该站点的 4via6 地址(供 AAAA 响应)。
// 按 siteID 反查宣告方设备（全局唯一、不依赖 user/device 名 → 无重名歧义）→ 校验目标 v4 在其**已批准宣告网段**内
// → encode4via6(siteID, v4)。站点未分配 / v4 不在宣告网段 → (_, false)，解析失败返 NameError。
func lookupVia6Addr(ctx context.Context, st *store.Store, siteID uint16, v4 netip.Addr) (netip.Addr, bool) {
	if st == nil {
		return netip.Addr{}, false
	}
	opCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	deviceID, err := st.DeviceIDBySiteID(opCtx, siteID)
	if err != nil {
		return netip.Addr{}, false // 未知/未分配 siteID
	}
	// P3：校验目标 v4 确在该宣告方**已批准的宣告网段**内。否则生成的 4via6 数据面会按 not-advertised 丢弃
	// （用户"解析出来却连不上"），此处直接判失败 → NameError，语义更清晰。
	if !deviceAdvertisesV4(deviceID, v4) {
		return netip.Addr{}, false
	}
	if addr, ok := encode4via6(siteID, v4); ok {
		return addr, true
	}
	return netip.Addr{}, false
}

// magicNameDeniedByMeshOff(2026-07-19 深扫瑕疵修复):组网总开关 OFF 时,判定某 magic 名查询是否
// 应被就地 NXDOMAIN——查询方(src vIP 归属 user)与名字目标归属 user 不同即拦。
//
// 口径与数据面完全一致:身份都来自 lookupVIPOwner 同一张表,开关都读 aclCurrent 快照。
// fail-open 三兜底(拦不准就不拦,绝不误伤):
//   - 查询方 vIP 不在归属表(server 本机自查 / 测试 / 会话清理竞态)→ 放行;
//   - 名字解析不出目标归属(格式非法 / 用户或站点不存在)→ 放行,交由正常路径回 NXDOMAIN/NODATA;
//   - mesh ON / 快照未初始化 → 放行。
//
// 注意这只是 UX 对齐(解析层不再报出「注定连不上」的地址),不是安全边界——数据面 mesh_off
// 丢包才是硬闸;即便这里放过了,流量也过不去。
func magicNameDeniedByMeshOff(ctx context.Context, gw *gatewayState, peer *net.UDPAddr, name, suffix string) bool {
	snap := aclCurrent.Load()
	if snap == nil || snap.meshEnabled {
		return false
	}
	vip, ok := netipAddrFromUDP(peer)
	if !ok {
		return false
	}
	srcUser, ok := lookupVIPOwner(vip)
	if !ok || srcUser == 0 {
		return false
	}
	dstUser, ok := magicNameOwnerUserID(ctx, gw.store, name, suffix)
	if !ok || dstUser == 0 {
		return false
	}
	return dstUser != srcUser
}

// magicNameOwnerUserID 解析 magic 名的「目标归属 user」:
//   - 4via6 站点名 <v4-dashed>via<siteID> → siteID → 宣告方 device → 其 user;
//   - 普通 host.user.<suffix> → username 反查 user。
//
// 解析不出(名字非法 / 不存在)返回 ok=false,调用方按「不拦」处理。低频路径(仅 mesh OFF 时才会走到)。
func magicNameOwnerUserID(ctx context.Context, st *store.Store, name, suffix string) (int64, bool) {
	if st == nil {
		return 0, false
	}
	opCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if _, siteID, okv := parseVia6Hostname(name, suffix); okv {
		deviceID, err := st.DeviceIDBySiteID(opCtx, siteID)
		if err != nil {
			return 0, false
		}
		d, err := st.GetDevice(opCtx, deviceID)
		if err != nil || d == nil {
			return 0, false
		}
		return d.UserID, true
	}
	_, user, ok := parseMagicHostname(name, suffix)
	if !ok {
		return 0, false
	}
	u, err := st.GetUserByUsername(opCtx, user)
	if err != nil || u == nil {
		return 0, false
	}
	return u.ID, true
}

// magicHostExists 判断某 magic 名（4via6 站点名或普通 host.user.<suffix>）当前是否解析得到地址——供**非 A/AAAA**
// 查询走「主机存在→NODATA / 不存在→NXDOMAIN」的本地作答（不外发公网上游）。复用 A/AAAA 路径同一套解析，只关心
// 「是否存在」不关心具体地址。低频（仅 mesh 名的非 A/AAAA 查询触发）。
func magicHostExists(ctx context.Context, gw *gatewayState, name, suffix string) bool {
	if gw == nil || gw.store == nil {
		return false
	}
	if v4, siteID, okv := parseVia6Hostname(name, suffix); okv {
		_, ok := lookupVia6Addr(ctx, gw.store, siteID, v4)
		return ok
	}
	host, user, ok := parseMagicHostname(name, suffix)
	if !ok {
		return false
	}
	addrs, ok := lookupMagicHost(ctx, gw.store, user, host)
	return ok && len(addrs) > 0
}

// lookupMagicHost 在 store 里找 (user, hostname) 对应的 vIP 集合。
//
// hostname 不一定等于 device_name —— 用户可能起了「Alice 的 MacBook」这种带空格 / 中文的名字。
// 这里做一次小写 + 把空格/下划线全部替换成连字符 - 的 normalize,与 magic 子域命名约定对齐;
// 比较时也对 device_name 做同样 normalize,允许跨字符集查询。
func lookupMagicHost(ctx context.Context, st *store.Store, user, hostname string) ([]netip.Addr, bool) {
	if st == nil {
		return nil, false
	}
	opCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	u, err := st.GetUserByUsername(opCtx, user)
	if err != nil {
		return nil, false
	}
	devices, err := st.ListDevicesByUser(opCtx, u.ID)
	if err != nil {
		return nil, false
	}
	wanted := normalizeMagicHost(hostname)
	// 正常情况下设备名每用户唯一（store.UpsertDevice 注册时按归一形去重），故至多一个匹配。但**存量**在唯一性
	// 强制生效前登记的重名设备可能仍并存 —— 此时按 device_id 升序取**最小(最早、稳定)**的那台，避免旧实现依赖
	// ListDevicesByUser 的 last_seen 顺序、导致「胜出者随上下线漂移」的非确定性错路由。存量设备下次注册即会被去重。
	var best *store.Device
	for _, d := range devices {
		if d == nil || normalizeMagicHost(d.DeviceName) != wanted {
			continue
		}
		if best == nil || d.ID < best.ID {
			best = d
		}
	}
	if best == nil {
		return nil, false
	}
	lease, err := st.GetLeaseByDevice(opCtx, best.ID)
	if err != nil || lease == nil {
		return nil, false
	}
	var out []netip.Addr
	if lease.VIPv4 != "" {
		if a, perr := netip.ParseAddr(lease.VIPv4); perr == nil {
			out = append(out, a)
		}
	}
	if lease.VIPv6 != "" {
		if a, perr := netip.ParseAddr(lease.VIPv6); perr == nil {
			out = append(out, a)
		}
	}
	return out, len(out) > 0
}

// normalizeMagicHost 归一化 magic 子域标签。委托 util.NormalizeMagicHost —— 与 store 的「每用户设备名唯一」
// 去重同一事实源，避免两处逻辑漂移（解析端与去重端对「是否同名」判定必须一致）。
func normalizeMagicHost(s string) string {
	return util.NormalizeMagicHost(s)
}

// buildMagicDNSAnswer 给一组 vIP 拼一个 A/AAAA 响应报文。q.Type 决定要哪一类。
func buildMagicDNSAnswer(qid uint16, q dnsmessage.Question, addrs []netip.Addr) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 qid,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: false,
		RCode:              dnsmessage.RCodeSuccess,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, a := range addrs {
		switch q.Type {
		case dnsmessage.TypeA:
			if !a.Is4() && !a.Is4In6() {
				continue
			}
			v4 := a.Unmap().As4()
			rh := dnsmessage.ResourceHeader{
				Name:  q.Name,
				Class: dnsmessage.ClassINET,
				TTL:   30,
			}
			if err := b.AResource(rh, dnsmessage.AResource{A: v4}); err != nil {
				return nil, err
			}
		case dnsmessage.TypeAAAA:
			if a.Is4() || a.Is4In6() {
				continue
			}
			v6 := a.As16()
			rh := dnsmessage.ResourceHeader{
				Name:  q.Name,
				Class: dnsmessage.ClassINET,
				TTL:   30,
			}
			if err := b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: v6}); err != nil {
				return nil, err
			}
		}
	}
	return b.Finish()
}

// buildMagicDNSStatusBytes 构一帧只有 header(无 answer)的响应字节,用于错误码。失败返回 nil。
func buildMagicDNSStatusBytes(qid uint16, rcode dnsmessage.RCode, q dnsmessage.Question) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:       qid,
		Response: true,
		RCode:    rcode,
	})
	if q.Name.Length > 0 {
		_ = b.StartQuestions()
		_ = b.Question(q)
	}
	raw, err := b.Finish()
	if err != nil {
		return nil
	}
	return raw
}

// writeMagicDNSStatus 写一帧只有 header(无 answer)的响应,用于错误码。
func writeMagicDNSStatus(conn *net.UDPConn, peer *net.UDPAddr, qid uint16, rcode dnsmessage.RCode, _ []netip.Addr, q dnsmessage.Question) error {
	raw := buildMagicDNSStatusBytes(qid, rcode, q)
	if raw == nil {
		return errors.New("build dns status failed")
	}
	_, err := conn.WriteToUDP(raw, peer)
	return err
}

// forwardMagicDNSToUpstream 简单串行尝试每个 upstream,首个收到响应即转回。
// 超时 800ms;失败 → SERVFAIL。会话早期窗口内的应答 TTL 被钳短（见 magicDNSEarlyClampWindow 注释）。
func forwardMagicDNSToUpstream(ctx context.Context, conn *net.UDPConn, peer *net.UDPAddr, query []byte, r magicDNSResolved) {
	clamp := magicDNSInEarlyClampWindow(peer)
	for _, up := range r.upstream {
		resp, err := dialAndQueryUDP(ctx, up, query, 800*time.Millisecond)
		if err != nil {
			continue
		}
		magicDNSUpstreamCount.Add(1)
		if clamp {
			if clamped, changed := clampDNSResponseTTLs(resp, magicDNSEarlyClampTTL); changed {
				resp = clamped
				magicDNSEarlyClampCount.Add(1)
			}
		}
		_, _ = conn.WriteToUDP(resp, peer)
		return
	}
	magicDNSServfailCount.Add(1)
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err == nil {
		_ = writeMagicDNSStatus(conn, peer, hdr.ID, dnsmessage.RCodeServerFailure, nil, dnsmessage.Question{})
	}
}

// magicDNSInEarlyClampWindow 判断该查询是否落在其会话的「早期竞速窗口」内（会话注册后 < magicDNSEarlyClampWindow）。
// 查不到会话（server 本机自查 / 测试 / 会话清理竞态）→ 不钳（维持原 TTL）。低频路径（仅上游转发触发），扫表可接受。
func magicDNSInEarlyClampWindow(peer *net.UDPAddr) bool {
	vip, ok := netipAddrFromUDP(peer)
	if !ok {
		return false
	}
	createdAt, found := connCreatedAtForClientVIP(vip)
	if !found {
		return false
	}
	return time.Since(createdAt) < magicDNSEarlyClampWindow
}

// clampDNSResponseTTLs 把一份 DNS 应答里 Answer/Authority/Additional 各 RR 的 TTL 钳到 ≤ maxTTL 秒，返回
// (可能重打包的应答, 是否有改动)。OPT 伪 RR（EDNS，TTL 字段是扩展 rcode/flags）跳过。解析 / 重打包失败 →
// 原样返回（fail-safe，宁可不钳也不能弄坏应答）。
func clampDNSResponseTTLs(raw []byte, maxTTL uint32) ([]byte, bool) {
	var m dnsmessage.Message
	if err := m.Unpack(raw); err != nil {
		return raw, false
	}
	changed := false
	for i := range m.Answers {
		if m.Answers[i].Header.TTL > maxTTL {
			m.Answers[i].Header.TTL = maxTTL
			changed = true
		}
	}
	for i := range m.Authorities {
		if m.Authorities[i].Header.TTL > maxTTL {
			m.Authorities[i].Header.TTL = maxTTL
			changed = true
		}
	}
	for i := range m.Additionals {
		if m.Additionals[i].Header.Type == dnsmessage.TypeOPT {
			continue
		}
		if m.Additionals[i].Header.TTL > maxTTL {
			m.Additionals[i].Header.TTL = maxTTL
			changed = true
		}
	}
	if !changed {
		return raw, false
	}
	out, err := m.Pack()
	if err != nil {
		return raw, false
	}
	return out, true
}

// dialAndQueryUDP 同步发一个 UDP DNS 报文到 addr,等待一次响应。
func dialAndQueryUDP(ctx context.Context, addr string, query []byte, timeout time.Duration) ([]byte, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// magicDNSExtraDNS 给 server.go 登录路径用:启用时返回应当 prepend 到客户端 DNS 列表的
// "gateway_ip" 条目。listenAddr 为空 / 未启用时返回空。
// 该地址通常等于 TUN gateway IP(不含端口) —— 客户端拿到后直接当 DNS server。
//
// 关键约束:只在 listen_port == 53 时才 prepend。原因见 resolveMagicDNSConfig
// 注释:客户端 OS stub resolver 永远打 :53,非 53 端口 prepend 后等于把客户端
// DNS 指到一个"看上去对其实查不到任何东西"的 IP,反而把原本能用的上游 DNS 也
// 屏蔽了。非 53 端口由运维通过 dnsmasq/systemd-resolved 之类转发器自行接入。
func magicDNSExtraDNS(gw *gatewayState, listenAddr string) string {
	if gw == nil || gw.cfg == nil || !gw.cfg.Server.MagicDNS.Enabled {
		return ""
	}
	if strings.TrimSpace(listenAddr) == "" {
		return ""
	}
	if net.ParseIP(listenAddr) == nil {
		return ""
	}
	r := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	if r.port != 53 {
		magicDNSNonStdPortWarnOnce.Do(func() {
			logrus.WithField("listen_port", r.port).Warn(
				"[magic-dns] listen_port != 53,跳过给客户端 prepend gateway DNS;客户端 OS stub resolver 默认打 :53,非 53 端口需要运维自行接转发器")
		})
		return ""
	}
	return listenAddr
}

// magicDNSNonStdPortWarnOnce 保证非 53 端口的告警只在第一次登录时打一次,
// 避免每条登录路径都刷一行,污染日志。
var magicDNSNonStdPortWarnOnce sync.Once

// magicDNSSuffixForClient 给 server.go 登录路径用：启用 MagicDNS 且 listen_port==53（与 magicDNSExtraDNS 的
// prepend 条件严格一致）时，返回应随 ConvSaltLite 下发的 domain_suffix，供客户端（尤其 mac meshOnly）把
// *.<suffix> 强制走隧道 DNS；否则返回空串（不下发）。非 53 端口客户端 OS stub 不会查网关，下发 suffix 无意义。
func magicDNSSuffixForClient(gw *gatewayState) string {
	if gw == nil || gw.cfg == nil || !gw.cfg.Server.MagicDNS.Enabled {
		return ""
	}
	r := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	if r.port != 53 {
		return ""
	}
	return r.suffix
}
