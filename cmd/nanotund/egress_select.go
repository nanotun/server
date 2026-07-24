package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nanotun/server/util"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/time/rate"
)

// exit-node 特性 — 使用方「公网出口选择」server 侧入口。
//
// handleEgressSelectFrame 在 runLinkTunnel 的 readLoop 中被调用(与 IPPacket 转发同一 goroutine);
// c.egressDeviceID 为 atomic.Int64(control-socket 的撤销复核会跨 goroutine 改它),接收一帧 LinkTypeEgressSelect 的 JSON body:
//   1. Egress 为空 / "server" → 退回 server 自出口(egressDeviceID=0),回 Ack(accepted, egress=server);
//   2. 否则按「授权」绑定:目标是 admin 已批准的出口设备(approved 0/0/::/0,**在线/离线均可**)+ 本会话 exit_allowed
//      → 置 egressDeviceID=该设备,回 Ack(accepted, egress=<uuid>);在不在线交给数据面决定走/阻断;
//   3. 目标不是已批准出口(撤销/未知)→ egressDeviceID=0(回退 server)+ Ack(rejected, not_approved)。
//
// 全段 best-effort:解析失败只 log + 计数,绝不 break readLoop。数据面真正转发在 M2(runLinkTunnel)。
//
// 协议规范见 docs/DESIGN_EXIT_NODE.md。

// 暴露给 /status / 测试观测的计数(best-effort)。
var (
	egressSelectAccepted atomic.Uint64 // 接受的出口选择次数(含退回 server)
	egressSelectRejected atomic.Uint64 // 拒绝次数(unknown/未批准/离线/exit_not_allowed)
	egressSelectFailed   atomic.Uint64 // 解析失败次数

	// 数据面 exit 转发计数(M2)。
	exitForwarded              atomic.Uint64 // 成功投递到出口节点会话的包数
	exitForwardedBytes         atomic.Uint64 // 成功转发的字节数(M6 单列计量:中转双倍带宽可观测)
	exitForwardDroppedOffline  atomic.Uint64 // 出口离线导致 fail-closed 丢弃的包数
	exitForwardDroppedFull     atomic.Uint64 // 出口会话 TunChan 满丢弃的包数
	exitForwardDroppedOversize atomic.Uint64 // 包超过 tunBufSize 丢弃(防截断损坏)
	exitForwardDroppedRate     atomic.Uint64 // 超过本会话出口转发速率帽丢弃的包数(M6 带宽帽)
	exitForwardDroppedNoV6     atomic.Uint64 // 目的是公网 v6 但所选出口无 v6 出网:回 ICMPv6 unreachable 后丢弃的包数
	exitForwardDroppedMeshDst  atomic.Uint64 // 第十六轮:目的落在本 mesh 网段但无在线归属(对端离线),不外泄给出口,就地丢
	// 第十九轮:目的是 mesh 内部专用地址(4via6 fdbc:4a60::/64,或落在某已批准子网路由 LAN 前缀内)但漏到出口路径
	// —— 典型是子网/4via6 宣告方**自指**在 forwardPacketToSubnetRoute 返回 false 后、若又选了 peer 出口就会到这里。
	// 这类内部目的绝非公网出口流量,fail-closed 就地丢弃(不外泄内部编址 / LAN 内容给出口节点)。
	exitForwardDroppedInternalDst atomic.Uint64

	// server 自出口(egress=server/默认)对公网 v6 的兜底:server 本机无 v6 公网出网时,把使用方发来的公网全局
	// 单播 v6 回 ICMPv6 unreachable 使其秒回落 v4(与 peer 出口的 exitForwardDroppedNoV6 同理,补 egress==0 路径)。
	serverEgressDroppedNoV6 atomic.Uint64
)

// server 自出口 v6 能力探测缓存:数据面热路径每包读,故用 atomic 缓存 + 后台 goroutine 定期探测(startServerV6EgressProbe),
// 绝不在数据面同步做 net.Dial。Known=false(尚未探测出结果)时保守放行(走 server 自出口,维持旧行为)。
var (
	serverV6EgressHas   atomic.Bool // 最近一次探测:server 本机是否有 v6 公网出网
	serverV6EgressKnown atomic.Bool // 是否已完成至少一次探测(false 时数据面保守放行)
)

// serverV6EgressProbeInterval:server 自出网 v6 能力的后台重探间隔。server 网络通常稳定,60s 足够反映
// 上/下线变化,又不至于频繁 net.Dial。
const serverV6EgressProbeInterval = 60 * time.Second

// exitForwardRateBPS(M6 带宽帽):每个使用出口的会话,经出口转发的公网流量速率上限(字节/秒)。
// 0 = 不限(默认)。出口中转占用 server 双倍带宽,可比常规链路更严地单独限速以防滥用。
// 启动时从 [server].exit_forward_rate_bps 读入一次(非 SIGHUP 热更);per-session 桶懒建,
// 非阻塞 AllowN 判定(超额丢包,fail-closed),不阻塞数据面 readLoop goroutine。
var exitForwardRateBPS atomic.Int64

// ExitNodeStats 暴露在 /status JSON 的子结构:出口节点选择(控制面) + 转发(数据面)计数。
//
// 全部源自 atomic.Uint64,跨 goroutine 读安全(/status handler 与数据面 readLoop 不同 goroutine)。
// 不含「当前活跃出口会话数」gauge:那需读各会话的 egressDeviceID(数据面 goroutine 同步写的 plain
// int64),跨 goroutine 读会触发竞态;计数器已足够观测,gauge 留待将来需要时改 atomic 字段再加。
type ExitNodeStats struct {
	// EgressSelect 控制帧处理结果。
	SelectAccepted uint64 `json:"select_accepted"`
	SelectRejected uint64 `json:"select_rejected"`
	SelectFailed   uint64 `json:"select_failed"`
	// 数据面转发计数。
	Forwarded       uint64 `json:"forwarded"`
	ForwardedBytes  uint64 `json:"forwarded_bytes"`
	DroppedOffline  uint64 `json:"dropped_offline"`
	DroppedFull     uint64 `json:"dropped_full"`
	DroppedOversize uint64 `json:"dropped_oversize"`
	DroppedRate     uint64 `json:"dropped_rate"`
	DroppedNoV6     uint64 `json:"dropped_no_v6"`
	DroppedMeshDst  uint64 `json:"dropped_mesh_dst"`
	// DroppedInternalDst:目的是 mesh 内部专用地址(4via6 / 已批准子网 LAN 前缀)却漏到出口路径,fail-closed 丢弃的包数。
	DroppedInternalDst uint64 `json:"dropped_internal_dst"`
	// ServerEgressDroppedNoV6:走 server 自出口、因 server 本机无 v6 而回 ICMPv6 unreachable 的公网 v6 包数。
	ServerEgressDroppedNoV6 uint64 `json:"server_egress_dropped_no_v6"`
	// RateCapBPS:当前生效的 per-session 出口转发速率帽(字节/秒);0 = 不限。
	RateCapBPS int64 `json:"rate_cap_bps"`
}

// snapshotExitNodeStats 在 /status 处快照计数,避免直接读 atomic 暴露包内符号。
func snapshotExitNodeStats() ExitNodeStats {
	return ExitNodeStats{
		SelectAccepted:          egressSelectAccepted.Load(),
		SelectRejected:          egressSelectRejected.Load(),
		SelectFailed:            egressSelectFailed.Load(),
		Forwarded:               exitForwarded.Load(),
		ForwardedBytes:          exitForwardedBytes.Load(),
		DroppedOffline:          exitForwardDroppedOffline.Load(),
		DroppedFull:             exitForwardDroppedFull.Load(),
		DroppedOversize:         exitForwardDroppedOversize.Load(),
		DroppedRate:             exitForwardDroppedRate.Load(),
		DroppedNoV6:             exitForwardDroppedNoV6.Load(),
		DroppedMeshDst:          exitForwardDroppedMeshDst.Load(),
		DroppedInternalDst:      exitForwardDroppedInternalDst.Load(),
		ServerEgressDroppedNoV6: serverEgressDroppedNoV6.Load(),
		RateCapBPS:              exitForwardRateBPS.Load(),
	}
}

// forwardPacketToExitNode 数据面:把使用方 c 的「公网出口」IP 包转发给其选定的出口节点会话
// (投递到出口 conn 的 TunChan，由出口客户端本机 NAT 出公网)。
//
// 返回 true = 本包已由 exit 路径处理(投递成功或按策略丢弃)，调用方**不应**再走 server 自出口;
// 返回 false = 未走 exit(调用方应回退 server 自出口的原有路径)。返 false 的情形仅:
//   - 本会话未选出口(egressDeviceID==0);
//   - 目的是某 vIP(mesh 互通流量，绝不能当公网出口转发);
//   - 退化选到自己当出口(自环防护)。
//
// **fail-closed**:出口离线 / 投递失败一律丢包并计数，绝不回退 server 自出口 —— 否则使用方以为
// 流量走了指定出口、实际从 server 公网 IP 泄漏，违背用户选择。
//
// M6 优雅处理:出口下线时仍 fail-closed 丢包(不静默回落明文),但在**首个**丢弃包上回一帧
// EgressSelectAck{reason:exit_offline}+WARN(经 c.exitOfflineNotified 一次性闸去重),让客户端
// 知道出口已掉线、可自行回落 server 自出口或提示用户;重新 EgressSelect 时复位闸。
func forwardPacketToExitNode(c *Connection, payload []byte) bool {
	if c == nil {
		return false
	}
	egress := c.egressDeviceID.Load() // 一次性读;control-socket 复核可能并发改它,Load 取一致快照。
	if egress == 0 {
		return false
	}
	// 退化:选到自己当出口(egress 指向本机 device)→ 回退 server 自出口避免自环。**提前**判,不依赖出口 conn 状态——
	// 否则下面的 advertisedExit 守卫会把「选了自己但自己没在跑出口」误判成 offline 丢包,而非回退 server。
	if c.deviceID != 0 && egress == c.deviceID {
		return false
	}
	// 仅转发「公网出口」流量:目的若是本 mesh 内部 / server 本地(某 vIP mesh 互通，**或 server 自身网关地址**)，
	// 照旧走 server TUN 让内核 + demux / 本地服务处理，绝不转发给出口节点。**含网关**是关键修复:发往网关:53 的
	// MagicDNS 查询若被当公网转发给 peer 出口，会到不了 server 本地 resolver → 选了 peer 出口即 DNS 全断。
	t, ok := parsePacketTuple(payload)
	if !ok {
		return false
	}
	if isLocalMeshDst(t.dst) {
		return false
	}
	// 第十六轮深扫 MED:目的落在 server 自身 mesh 网段(TUN CIDR)内、但当前**无在线归属**(对端离线 / 未登录)——
	// isLocalMeshDst 只认「在线 vIP + 网关」,这类地址会漏到此处被当公网转发给 peer 出口 → 把**内部 mesh 地址**
	// 泄漏给出口节点、且在出口侧注定黑洞。mesh 网段内地址绝非公网出口流量:fail-closed 就地丢弃(不转发、不回退
	// server 自出口),对端上线后经正常 mesh 投递即可。只收口 exit 路径,不动 subnet-route(其 per-CIDR 门控自有
	// 语义,避免误伤与 mesh 段重叠的合法内网宣告)。
	if isMeshCIDRAddr(t.dst) {
		exitForwardDroppedMeshDst.Add(1)
		return true
	}
	// 第十九轮深扫 MED(confused deputy):4via6(fdbc:4a60::/64)与「已批准子网路由 LAN 前缀」都是 mesh 内部
	// 专用目的,绝非公网出口流量。forwardPacketToSubnetRoute 对**自指**(宣告方访问自己宣告的网段 / 自己的
	// 4via6 site)返回 false 交回原链路,但在 server 上这类 dst 没有「本地投递」语义 —— 若该会话又选了 peer 出口,
	// 会漏到这里被当公网转发给出口节点,把内部 4via6 编址 / LAN 内容泄漏出去(跨信任域)。与 isMeshCIDRAddr 同款
	// fail-closed:就地丢弃。lookupSubnetRoute 命中即「dst 属某已批准 LAN 段」(其自身 vIP/网关已在 isLocalMeshDst
	// 排除),非出口流量;is4via6 命中即 mesh 专用 v6。二者都不回退 server 自出口(ULA 在公网注定黑洞)。
	if is4via6(t.dst) {
		exitForwardDroppedInternalDst.Add(1)
		return true
	}
	if _, ok := lookupSubnetRoute(t.dst); ok {
		exitForwardDroppedInternalDst.Add(1)
		return true
	}
	// 按 device 取「真在跑出口」会话(advertisedExit && !takenOver),与选择侧同口径。
	// 不用 lookupActiveConnByDevice 的「首个 !takenOver」:接管/重连窗口该 device 可能并存非出口会话,选中后转发会被
	// 路由到非出口会话 → 误判离线 fail-closed 全丢(EgressSelect 选上却不通)/ 转给没装 NAT 的会话黑洞(Bugbot 第二轮 #1)。
	exitConn := lookupRunningExitConnByDevice(egress)
	// 出口离线 / 该设备已无「在跑出口」会话(下线 / 接管换成普通会话 / 撤回声明)——fail-closed 丢弃(不回退 server 自出口)。
	if exitConn == nil {
		exitForwardDroppedOffline.Add(1)
		notifyExitOfflineOnce(c) // 一次性通知客户端(去重 + WARN);仍 fail-closed 丢包
		return true              // fail-closed:出口离线/已不跑出口丢弃，不回退 server 自出口
	}
	// v6 能力感知(修 v4-only 出口的公网 v6 黑洞):目的是**公网全局单播 v6**(2000::/3)但所选出口**无 v6 出网**
	// (最近一帧 exit advertise 不含 ::/0 → advertisedExitV6=false)时,若照旧把包转给它,出口本机没 v6 出网 → 黑洞,
	// 使用方 Happy Eyeballs / QUIC 卡 15~30s 才回落 v4(实测墙内 v4-only 出口打开带 AAAA 的站点极慢的根因)。
	// 这里**不转发**,改给**使用方**回一帧 ICMPv6 Destination Unreachable(no route),让其 v6 连接秒失败 → 立刻回落 v4。
	// 仅命中「公网 v6 + 无 v6 出口」:4via6(fd7a.. / ULA,非 2000::/3)、mesh 内部(上面 isLocalMeshDst 已放行)、
	// v4 一律不受影响;老出口客户端总宣告 ::/0 → advertisedExitV6=true → 不进本分支、无回归。
	if isPublicV6Addr(t.dst) && !exitConn.advertisedExitV6.Load() {
		exitForwardDroppedNoV6.Add(1)
		sendICMPv6NoRouteToConn(c, payload)
		return true // 已处理(回 ICMP + 丢弃):不回退 server 自出口(fail-closed,守住用户选定出口语义)
	}
	// DNS :53 接管(2026-07-17):绑定出口会话「直发公共 resolver」的 UDP DNS 查询不原样转发,改经出口解析机器
	// (与网关 MagicDNS 同一套缓存/单飞/AAAA 剥离),应答伪装成原 resolver 回包注入客户端——堵住「8.8.8.8 直查
	// 绕过 AAAA 剥离 → v4-only 出口下客户端拿真 AAAA → 公网 v6 连接被丢 → Happy Eyeballs 卡顿」。
	// 拦截失败(非 DNS 查询 / 限流满)→ 返回 false 落回下方原样转发,出口 DNAT 兜底。详见 magic_dns_intercept.go。
	if t.proto == "udp" && t.dstPort == 53 && interceptExitBoundDNSQuery(c, exitConn, egress, payload) {
		return true
	}
	if len(payload) > tunBufSize {
		exitForwardDroppedOversize.Add(1)
		return true
	}
	// M6 带宽帽:per-session 出口转发速率上限。非阻塞 AllowN(超额丢包,不阻塞本 readLoop goroutine);
	// 0 = 不限。出口中转占 server 双倍带宽,这里比常规链路更严地单独节流以防滥用。
	if !exitForwardRateAllow(c, len(payload)) {
		exitForwardDroppedRate.Add(1)
		return true // fail-closed:超帽丢弃,不回退 server 自出口
	}
	if deliverIPPacketToConn(exitConn, payload) {
		exitForwarded.Add(1)
		exitForwardedBytes.Add(uint64(len(payload)))
		auditExitForwardOnce(c) // 一次性审计:本会话首次经出口转发(防滥用追溯)
		// 成功转发即复位「离线已通知」闸:绑定的出口经历「离线→上线」自动恢复后,下次再离线应能再通知一次
		// (per-episode,而非整会话只通知一次)。同 readLoop goroutine 读写,无锁安全;每包一次裸 bool 写,开销可忽略。
		c.exitOfflineNotified = false
	} else {
		exitForwardDroppedFull.Add(1)
	}
	return true
}

// exitForwardRateAllow 判定本会话本包是否在出口转发速率帽内。rateBPS<=0 直接放行(不限)。
// per-session 令牌桶懒建(仅本 readLoop goroutine 读写 c.exitFwdLimiter,无需加锁);burst 取
// max(1s 速率, tunBufSize),保证至少能放过一个最大包(否则 AllowN(n) 在 n>burst 时恒 false)。
func exitForwardRateAllow(c *Connection, n int) bool {
	rateBPS := exitForwardRateBPS.Load()
	if rateBPS <= 0 {
		return true
	}
	if c.exitFwdLimiter == nil {
		burst := int(rateBPS)
		if burst < tunBufSize {
			burst = tunBufSize
		}
		c.exitFwdLimiter = rate.NewLimiter(rate.Limit(rateBPS), burst)
	}
	return c.exitFwdLimiter.AllowN(time.Now(), n)
}

// auditExitForwardOnce 在本会话首次成功经出口转发时记一条审计 INFO(防滥用追溯:谁经哪个出口出网)。
// 一次性:c.exitFwdAudited 已置位则直接返回,避免每包刷屏。重新 EgressSelect 时复位以便换出口后再审计。
// 与 forwardPacketToExitNode / handleEgressSelectFrame 同 readLoop goroutine,读写无锁安全。
func auditExitForwardOnce(c *Connection) {
	if c == nil || c.exitFwdAudited {
		return
	}
	c.exitFwdAudited = true
	logrus.WithFields(logrus.Fields{
		"user_id":        c.userID,
		"conn_id":        c.connIDStr,
		"device_id":      c.deviceID,
		"exit_device_id": c.egressDeviceID.Load(),
	}).Info("[egress] 会话开始经出口节点转发公网流量(审计)")
}

// notifyExitOfflineOnce 在选定出口首次离线丢包时,给使用方回一帧 EgressSelectAck{exit_offline}+WARN。
// 一次性:c.exitOfflineNotified 已置位则直接返回,避免对每个丢弃包刷屏(出口下线期间数据面会持续丢包)。
// 与 forwardPacketToExitNode / handleEgressSelectFrame 同 readLoop goroutine,读写 c.exitOfflineNotified 无锁安全。
func notifyExitOfflineOnce(c *Connection) {
	if c == nil || c.exitOfflineNotified {
		return
	}
	c.exitOfflineNotified = true
	logrus.WithFields(logrus.Fields{
		"user_id":        c.userID,
		"exit_device_id": c.egressDeviceID.Load(),
	}).Warn("[egress] 选定出口节点已离线,本会话公网流量 fail-closed 丢弃(已通知客户端)")
	sendEgressSelectAck(c, util.EgressSelectAck{Accepted: false, Reason: "exit_offline"})
}

// deliverIPPacketToConn 把一个原始 IP 包投递到目标会话的 TunChan(池化 *util.TunPacket，
// 与 tunDemuxToLink 的归还契约一致:消费者写完后 Put 回 tunReadBufPool / tunPacketPool)。
// 通道满则丢弃并立即归还缓冲，返回 false。
func deliverIPPacketToConn(target *Connection, payload []byte) (delivered bool) {
	if target == nil {
		return false
	}
	var ch chan *util.TunPacket
	for _, a := range target.safeClientIPs() {
		if a.TunChan != nil {
			ch = a.TunChan
			break
		}
	}
	if ch == nil {
		return false
	}
	buf := tunReadBufPool.Get().([]byte)
	n := copy(buf, payload)
	pkt := tunPacketPool.Get().(*util.TunPacket)
	pkt.Buf = buf
	pkt.N = n
	// 并发下线保护：调用方（forwardPacketToExitNode / forwardPacketToSubnetRoute）经 lookup*ByDevice 取到 target 后
	// 已释放 connIDMapMu，到这里的 send 之间 target 可能被并发 cleanup —— cleanupConnection 的 drainAndCloseTunChan
	// 会 close(ch)，向已关闭 channel send 会 **panic**（select 的 default 不兜 send-on-closed）。这条 send 是 exit/
	// subnet 转发**唯一**不经 demux register-map（unregister-before-close 保护）的 TunChan 写入方，故必须自兜：recover
	// 转为投递失败（归还池化对象 + return false，调用方计 drop）。否则并发下线的 target 会把**请求方**的 handleVPNLink
	// goroutine 打 panic —— 虽有 per-conn recover 兜底，但那会误断请求方连接（表现为「出口机一掉线，用它的人也跟着断」）。
	// superseded 门控已让「server 主动踢除」类下线在 lookup 阶段提前摘除、极大缩小本窗口；此处兜「客户端自断线（EOF/
	// keepalive 超时）→ cleanup」这条 superseded 覆盖不到的窗口。仅 panic 时进 recover，正常路径零额外开销（defer 除外）。
	defer func() {
		if r := recover(); r != nil {
			tunReadBufPool.Put(buf)
			tunPacketPool.Put(pkt)
			// delivered 保持 false：调用方（forwardPacketToExitNode / forwardPacketToSubnetRoute）的 else 分支已按
			// 「投递失败」计各自的 drop 计数，这里不重复计，避免双计。
			delivered = false
		}
	}()
	select {
	case ch <- pkt:
		return true
	default:
		tunReadBufPool.Put(buf)
		tunPacketPool.Put(pkt)
		return false
	}
}

// isPublicV6Addr 判断一个地址是否为**公网全局单播 IPv6**(2000::/3)。用于「出口无 v6 出网」门控:只有真公网 v6
// 目的才触发 ICMPv6 fast-fail;4via6(fd7a../ULA,不在 2000::/3)、mesh 内部、IPv4(含 v4-mapped)一律不命中。
func isPublicV6Addr(a netip.Addr) bool {
	if !a.Is6() || a.Is4In6() {
		return false
	}
	b := a.As16()
	return b[0]&0xe0 == 0x20
}

// buildICMPv6DestUnreach 用使用方**原始外发 v6 包** orig 构造一帧回给它的 ICMPv6 Destination Unreachable
// (Type 1 / Code 0 = no route to destination)。使用方内核收到后把对应连接置 ENETUNREACH → connect() 立即失败 →
// Happy Eyeballs / QUIC 立刻回落 IPv4(不再干等 15~30s 超时)。返回 (完整 IPv6 包, true);orig 非法则 (nil,false)。
//
// 报文形态(RFC 4443 §3.1):外层 IPv6(src=orig 的目的地、dst=orig 的源=使用方 vIP,故经隧道"原路"返回、使用方必收)+
// ICMPv6(4B 头 + 4B 未用 + 尽量多的引发包),整包裁到 IPv6 最小 MTU 1280 内。校验和用 IPv6 伪首部经 x/net/icmp 计算。
func buildICMPv6DestUnreach(orig []byte) ([]byte, bool) {
	if len(orig) < 40 || orig[0]>>4 != 6 {
		return nil, false
	}
	origSrc := make(net.IP, net.IPv6len)
	copy(origSrc, orig[8:24])
	origDst := make(net.IP, net.IPv6len)
	copy(origDst, orig[24:40])
	// ICMPv6 错误整包 ≤ 1280:外层 IPv6(40) + ICMPv6 头(4) + 未用字段(4) + 引发包数据。
	const maxData = 1280 - 40 - 4 - 4
	data := orig
	if len(data) > maxData {
		data = data[:maxData]
	}
	msg := icmp.Message{
		Type: ipv6.ICMPTypeDestinationUnreachable,
		Code: 0, // no route to destination
		Body: &icmp.DstUnreach{Data: data},
	}
	// ICMPv6 校验和覆盖 IPv6 伪首部;src=本包源(origDst)、dst=本包目的(origSrc=使用方 vIP)。
	icmpBytes, err := msg.Marshal(icmp.IPv6PseudoHeader(origDst, origSrc))
	if err != nil {
		return nil, false
	}
	pkt := make([]byte, 40+len(icmpBytes))
	pkt[0] = 0x60                                                // version=6, TC/FL=0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(icmpBytes))) // payload length
	pkt[6] = 58                                                  // next header = ICMPv6
	pkt[7] = 64                                                  // hop limit
	copy(pkt[8:24], origDst)                                     // src = 原目的(错误"来自"目的侧)
	copy(pkt[24:40], origSrc)                                    // dst = 使用方 vIP
	copy(pkt[40:], icmpBytes)
	return pkt, true
}

// sendICMPv6NoRouteToConn 给使用方会话 c 投递一帧针对其原始外发包 orig 的 ICMPv6 no-route(经其 TunChan 下行,
// 与正常下行包同路径,使用方内核照常处理 → 触发连接秒失败回落 v4)。best-effort:构造失败 / 通道满即丢,不阻塞。
func sendICMPv6NoRouteToConn(c *Connection, orig []byte) {
	if c == nil {
		return
	}
	pkt, ok := buildICMPv6DestUnreach(orig)
	if !ok {
		return
	}
	deliverIPPacketToConn(c, pkt)
}

// serverV6ProbeTargets:v6 出网探测目标(Google / Cloudflare / AliDNS 公共 DNS 的 v6 地址),路由级与端到端
// 两段共用。含 AliDNS(2400:3200::1)是为墙内部署的 server:Google/Cloudflare 可能双双不可达,若只探它们,
// 有真 v6 的墙内机器会被误判无 v6(误判方向安全——只是退化 v4-only,但能避免就避免)。
var serverV6ProbeTargets = []string{"2001:4860:4860::8888", "2606:4700:4700::1111", "2400:3200::1"}

// probeServerIPv6Egress 探测 **server 本机** 是否有 v6 公网出网。两段判定(对齐 Apple 客户端
// PacketTunnelProvider.exitHasIPv6Egress 的 EXIT-V6-EGRESS 根因修复,防「假 v6」):
//
//	① 路由级:对公网 v6 做 UDP connect(仅路由查找、不发包),要求 OS 选出的源地址是真·全局单播 2000::/3
//	  且非文档保留段 2001:db8::/32。原实现只做这一步——会被「有 GUA 地址 + 有默认路由却无实际可达出网」
//	  的假 v6 环境骗过(客户端侧实测家用路由器 RA 误发 2001:db8:1::/64 即此病),探测说有、数据面照转 → 黑洞。
//	② 端到端:真发一次往返(UDP DNS 查询,双目标都无响应再 TCP :443 握手兜底)确认公网 v6 真可达。
//
// **阻塞式**(最坏几秒超时),只在后台探测 goroutine 里跑,绝不进数据面。
func probeServerIPv6Egress() bool {
	if !probeServerIPv6Route() {
		return false
	}
	return verifyServerIPv6RoundTrip()
}

// probeServerIPv6Route ①路由级:UDP connect 只做路由查找,看 OS 能否为公网 v6 目的选出可用的全局单播源地址。
func probeServerIPv6Route() bool {
	for _, target := range serverV6ProbeTargets {
		conn, err := net.Dial("udp6", net.JoinHostPort(target, "53"))
		if err != nil {
			continue // 无 v6 路由 / NETUNREACH → 试下一个
		}
		la, _ := conn.LocalAddr().(*net.UDPAddr)
		_ = conn.Close()
		if la == nil || la.IP == nil {
			continue
		}
		if a, ok := netip.AddrFromSlice(la.IP); ok && isUsableV6EgressSrc(a.Unmap()) {
			return true
		}
	}
	return false
}

// isUsableV6EgressSrc 判断路由探测选出的源地址是否算「真 v6 出网源」:全局单播 2000::/3 **且非 RFC3849 文档
// 保留段 2001:db8::/32**(家用路由器 RA 误发的假 v6 实测就落在这段;与客户端 exitHasPhysicalGUAv6 同判据)。
func isUsableV6EgressSrc(a netip.Addr) bool {
	if !isPublicV6Addr(a) {
		return false
	}
	b := a.As16()
	return !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)
}

// verifyServerIPv6RoundTrip ②端到端:先向探测目标 :53 真发一条最小 DNS 查询等回包(内容不校验——即便应答被
// 污染,有回包就证明 v6 往返可用);双目标都无响应再对 :443 做 TCP 握手兜底(有些网络掐 UDP:53 但放 TCP)。
// 全部失败 → 判无真实出网。单目标超时 1.5s、最坏 ~6s,只在探测 goroutine 内阻塞。
func verifyServerIPv6RoundTrip() bool {
	const perTargetTimeout = 1500 * time.Millisecond
	for _, target := range serverV6ProbeTargets {
		if v6ProbeDNSRoundTrip(target, perTargetTimeout) {
			return true
		}
	}
	for _, target := range serverV6ProbeTargets {
		conn, err := net.DialTimeout("tcp6", net.JoinHostPort(target, "443"), perTargetTimeout)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

// v6ProbeDNSRoundTrip 向 target:53 发一条 A 查询并等任意回包。
func v6ProbeDNSRoundTrip(target string, timeout time.Duration) bool {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x7636, RecursionDesired: true}, // "v6"
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("www.google.com."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	query, err := msg.Pack()
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("udp6", net.JoinHostPort(target, "53"), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	return err == nil && n > 0
}

// v6SetupRetry:启动时 ip6tables/NAT66 安装失败(典型:server 的 v6 由 RA/DHCPv6 下发、晚于进程就绪)后的
// 补装钩子。server.go 启动路径在「有 v6 网段但安装失败」时注册;探测 goroutine 在探明有 v6 出网时调用,
// 成功即撤钩(只补装一次)。若不补装,会出现「60s 探测说有 v6、数据面照转,但 MASQUERADE 没装 → 公网 v6 以
// ULA 源出网被上游丢弃」的探测/NAT 脱节黑洞。钩子只在探测 goroutine 内串行调用,锁仅保护注册/撤除。
var (
	v6SetupRetryMu sync.Mutex
	v6SetupRetryFn func() bool
)

// armV6SetupRetry 注册 NAT66 补装钩子(fn 返回 true = 安装成功,钩子随之撤除)。
func armV6SetupRetry(fn func() bool) {
	v6SetupRetryMu.Lock()
	v6SetupRetryFn = fn
	v6SetupRetryMu.Unlock()
}

// runV6SetupRetryIfArmed 若补装钩子在册则执行一次;成功即撤钩,失败保留(下轮探测再试)。
func runV6SetupRetryIfArmed() {
	v6SetupRetryMu.Lock()
	fn := v6SetupRetryFn
	v6SetupRetryMu.Unlock()
	if fn == nil {
		return
	}
	if fn() {
		v6SetupRetryMu.Lock()
		v6SetupRetryFn = nil
		v6SetupRetryMu.Unlock()
	}
}

// startServerV6EgressProbe 启动常驻后台 goroutine:立即探一次 server 自身 v6 出网、之后每
// serverV6EgressProbeInterval 重探,结果写 atomic 供数据面 serverSelfEgressV6FastFail 读。stop 关闭即退出。
// main 在启动阶段调用一次(与 powSvc.RunGC 同处);探测在数据面之外做,数据面只读 atomic(零阻塞)。
func startServerV6EgressProbe(stop <-chan struct{}) {
	// 第十二轮深扫 LOW:此前是唯一未走 safeGlobalGoroutine 的常驻后台 goroutine。其 probe 循环做 net 拨测,
	// 一旦 panic 会以 Go 默认处理直接崩进程、绕过优雅关停(iptables 清理 / TUN 关闭 / WAL checkpoint)。
	// 与 leaseGC / auditGC / tunReadLoop 同款包裹:panic → globalContextCancel → main defer 链跑完 → systemd 拉起。
	go safeGlobalGoroutine("serverV6EgressProbe", globalContextCancel, func() {
		t := time.NewTicker(serverV6EgressProbeInterval)
		defer t.Stop()
		for {
			has := probeServerIPv6Egress()
			prev := serverV6EgressHas.Swap(has)
			first := !serverV6EgressKnown.Swap(true)
			if first || prev != has {
				logrus.WithField("has_ipv6_egress", has).Info(
					"[egress] server 自出口 v6 能力探测完成(无 v6 时对使用方公网 v6 回 ICMPv6 unreachable 秒回落 v4)")
				// 配置/能力脱节的显眼告警:配了 subnets_v6(已建 v6 网关,客户端会分到 v6 vIP)但本机实测无 v6 公网出网。
				// sharedTUNGatewayV6 在 main 启动 TUN 时写、本 goroutine 之后才启动,读安全。
				if !has && sharedTUNGatewayV6 != "" {
					logrus.Warn("[egress] 配置了 [tun].subnets_v6 但本机无 IPv6 公网出网:客户端仍会分到 v6 vIP," +
						"公网 v6 流量由数据面回 ICMPv6 unreachable 秒回落 v4,MagicDNS 剥 AAAA,公网 v6 DNS 不下发。" +
						"若本机确无 v6 请清空 subnets_v6;若应有 v6 请检查网卡/路由(探测含端到端往返,仅有地址/路由不算)")
				}
			}
			// 探明有 v6 → 若启动时 ip6tables/NAT66 装失败,补装(见 v6SetupRetryFn 注释)。
			// stop 已关(graceful shutdown 进行中)则不再补装,收窄「teardown sweep 与补装并发 → 规则被
			// 重新加回」的竞态窗口;已在途的安装无法打断,残留由下次启动的 C7 sweep 清理(幂等)。
			if has {
				select {
				case <-stop:
					return
				default:
					runV6SetupRetryIfArmed()
				}
			}
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	})
}

// shouldStripAAAAForServerSelf 纯决策(便于单测):server 自出口路径(会话未绑 peer 出口)的 MagicDNS 公网查询
// 是否应就地剥 AAAA 回 NODATA。仅当 (AAAA 查询) 且 (已探明 server v6 能力) 且 (server 无 v6) → true;
// 未探明(启动极短窗口)/ 有 v6 / 非 AAAA → false(保守不剥)。
func shouldStripAAAAForServerSelf(qtype dnsmessage.Type, known, has bool) bool {
	return qtype == dnsmessage.TypeAAAA && known && !has
}

// dnsV6ServersForClient:登录/接管路径下发 dns_servers_v6 前的能力过滤。已探明 server 无 v6 公网出网时,
// 剔除**公网**(2000::/3)v6 解析器——它们经隧道必被 serverSelfEgressV6FastFail 打回,下发只会让客户端每次
// 解析都白跑一趟;ULA/私网 v6 解析器(如 mesh 内自建 DNS)不依赖公网出网,保留。未探明 / 有 v6 → 原样返回。
func dnsV6ServersForClient(in []string) []string {
	if len(in) == 0 || !serverV6EgressKnown.Load() || serverV6EgressHas.Load() {
		return in
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if a, err := netip.ParseAddr(s); err == nil && isPublicV6Addr(a) {
			continue // 公网 v6 解析器 + server 无 v6 出网 → 剔除
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// shouldServerFastFailV6 纯决策(便于单测):走 server 自出口的包,是否应对其回 ICMPv6 unreachable。
// 仅当 (已探明 server v6 能力) 且 (server 无 v6) 且 (目的是公网全局单播 v6) 时为真。未探明 / 有 v6 / 非公网 v6 → false。
func shouldServerFastFailV6(dst netip.Addr, serverHasV6, known bool) bool {
	return known && !serverHasV6 && isPublicV6Addr(dst)
}

// serverSelfEgressV6FastFail 数据面:使用方走 **server 自出口**(未选 peer 出口)时,若 server 本机无 v6 出网且此包
// 目的是公网全局单播 v6,则不写 server TUN(那样会在 server 内核黑洞),改给使用方回 ICMPv6 unreachable → 其内核置
// ENETUNREACH → 连接秒失败、Happy Eyeballs 立刻回落 v4。返回 true=已处理(回 ICMP+丢弃),调用方 continue;false=照旧
// 走 server 自出口。仅补 forwardPacketToExitNode 返回 false(egress==0/自环回退)后的 server 自出口路径。
//
// 保守:v6 能力尚未探明(Known=false,启动极短窗口)→ 放行维持旧行为;mesh/4via6(ULA,非 2000::/3)/v4 一律不命中。
func serverSelfEgressV6FastFail(c *Connection, payload []byte) bool {
	if !serverV6EgressKnown.Load() {
		return false // 尚未探明 → 保守放行(走 server 自出口)
	}
	t, ok := parsePacketTuple(payload)
	if !ok {
		return false
	}
	if !shouldServerFastFailV6(t.dst, serverV6EgressHas.Load(), true) {
		return false
	}
	serverEgressDroppedNoV6.Add(1)
	sendICMPv6NoRouteToConn(c, payload)
	return true
}

func handleEgressSelectFrame(ctx context.Context, c *Connection, payload []byte) {
	if c == nil {
		return
	}
	es, err := util.ParseEgressSelect(payload)
	if err != nil {
		egressSelectFailed.Add(1)
		logrus.WithError(err).WithField("user_id", c.userID).Warn("[egress] 解析失败,丢弃")
		return
	}

	// 任意一次(重新)选择出口都复位一次性闸:切回 server / 换到新出口后,下线应能再通知一次、
	// 换出口后应能再记一条审计。放在解析成功后、各分支之前,覆盖所有会改变 egress 语义的路径。
	// 速率桶(exitFwdLimiter)不复位:出口转发速率帽是会话级预算,换出口不应清零桶。
	c.exitOfflineNotified = false
	c.exitFwdAudited = false

	// 退回 server 自出口:总是允许(无需 exit_allowed —— 是否真能出公网由数据面 exitDeniedForPacket 裁决)。
	if util.IsDefaultEgress(es.Egress) {
		c.egressDeviceID.Store(0)
		egressSelectAccepted.Add(1)
		sendEgressSelectAck(c, util.EgressSelectAck{Accepted: true, Egress: util.EgressDefault})
		return
	}

	// 选具体出口设备:本会话必须有出口权限。
	if !c.exitAllowed {
		egressSelectRejected.Add(1)
		sendEgressSelectAck(c, util.EgressSelectAck{Accepted: false, Reason: "exit_not_allowed"})
		return
	}

	// 选具体出口设备:按「**授权**」绑定 —— 只要目标是 admin 已批准的出口设备(approved 0/0 或 ::/0),无论它当前
	// 在线/离线都绑定到它(c.egressDeviceID=该设备 deviceID)。「在不在线」由数据面(lookupRunningExitConnByDevice)
	// 决定「走它 / 离线则 fail-closed 阻断等它回来自动恢复」,不在选择这步卡。语义:「选了 C 就一直认 C,只有 C 被
	// 撤销出口资格才回退 server」(详见 docs/DESIGN_EXIT_NODE.md)。出口设备可属于其他用户(Q1 全局),故按 UUID
	// 在「已批准出口设备集」里解析 deviceID(在线/离线均可解析,不依赖活跃会话)。
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	deviceID, ok := resolveApprovedExitDeviceID(dbCtx, es.Egress)
	if !ok {
		// DB 暂时查不动(无法判定是否已批准)→ **不改现状**(不静默回落 server、也不绑定),回 try_again 让客户端可重试。
		// 避免一次 DB 抖动就把用户从其选定出口踢回 server。
		egressSelectRejected.Add(1)
		sendEgressSelectAck(c, util.EgressSelectAck{Accepted: false, Reason: "try_again"})
		return
	}
	if deviceID == 0 {
		// 确实未批准 / 已撤销 / 未知 UUID —— 不是合法出口 → 回退 server 自出口(egressDeviceID=0)+ 通知。
		// 按设计:唯一回退 server 的触发就是「目标不再是被授权的出口」。
		c.egressDeviceID.Store(0)
		egressSelectRejected.Add(1)
		sendEgressSelectAck(c, util.EgressSelectAck{Accepted: false, Reason: "not_approved"})
		return
	}
	if c.deviceID != 0 && deviceID == c.deviceID {
		// 选到自己当出口:relay 模型下自选无意义(数据面 forwardPacketToExitNode 有自环防护、会回退 server)。
		// 这里**显式**回退 server + 回 rejected,避免「ack=accepted 却实际走 server」的口径不一致(深扫 #4)。
		c.egressDeviceID.Store(0)
		egressSelectRejected.Add(1)
		sendEgressSelectAck(c, util.EgressSelectAck{Accepted: false, Reason: "self"})
		return
	}

	// 已授权 → 绑定(在线/离线均绑)。数据面:在线在跑则走它;离线/没在跑则 fail-closed 阻断 + 它回来自动恢复
	// (或按客户端 exit_fallback_server 回退 server)。
	c.egressDeviceID.Store(deviceID)
	egressSelectAccepted.Add(1)
	logrus.WithFields(logrus.Fields{
		"user_id":        c.userID,
		"exit_device_id": deviceID,
	}).Info("[egress] 会话出口已绑定到出口设备(已授权;在线即走、离线则阻断等待)")
	sendEgressSelectAck(c, util.EgressSelectAck{Accepted: true, Egress: es.Egress})
}

// sendEgressSelectAck best-effort 回一帧 EgressSelectAck;写失败只 log。
func sendEgressSelectAck(c *Connection, ack util.EgressSelectAck) {
	// 深扫第十轮 MED(既有):linkConn 的 nil 判定走 linkWrMu(interface 读写都走该锁),
	// 用 safeLinkConn() race-free 预筛,写锁内再复核。见 sendExitsListTo 同款说明。
	if c == nil || c.safeLinkConn() == nil {
		return
	}
	body, err := util.MarshalEgressSelectAck(ack)
	if err != nil {
		return
	}
	c.linkWrMu.Lock()
	defer c.linkWrMu.Unlock()
	if c.linkConn == nil {
		return
	}
	// 深扫第五轮:与 sendExitsListTo 同口径钉 5s 写超时。revalidateExitBindings 在循环里**内联**回 revoked ack,
	// 一个 TCP 窗口满的被撤销客户端会卡在 Write、持着自己的 linkWrMu → 拖慢同一轮里排在后面的被撤销会话的 CAS 重置
	// (也卡其 tunDemux)。超时后该帧写失败(仅 Debug),不影响其它会话。defer LIFO:复位 deadline 在 Unlock 之前跑。
	if dl, ok := c.linkConn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = dl.SetWriteDeadline(time.Now().Add(5 * time.Second))
		defer func() { _ = dl.SetWriteDeadline(time.Time{}) }()
	}
	if werr := util.WriteLinkFrame(c.linkConn, util.LinkTypeEgressSelectAck, body); werr != nil {
		logrus.WithError(werr).WithField("user_id", c.userID).Debug("[egress] 回 Ack 失败")
	}
}

// resolveApprovedExitDeviceID 按 device UUID 在「admin 已批准的出口设备集」里解析 deviceID(**在线/离线均可**,
// 不依赖活跃会话):扫 approved 路由 → 滤出出口默认路由(0/0 / ::/0)→ 按 UUID 匹配设备。返回 0 = 该 UUID 不是
// (或不再是)已批准出口(撤销 / 未知 / 从未批准)。出口选择据此「按授权绑定」:授权才绑、撤销即回退 server;
// 「在不在线」交给数据面(lookupRunningExitConnByDevice)决定走/阻断,故这里不看在线状态。
// 低频控制路径,扫 approved 集 + per-device GetDevice 可接受;数据面热路径不走这里。
// 返回 (deviceID, ok):ok=false → **无法判定**(无 store / DB 查询出错),调用方不得当「未批准」回退 server(应保守、可重试);
// ok=true 时 deviceID=0 表示「确实不是已批准出口」(撤销/未知/从未批准),deviceID>0 即解析到的已批准出口设备。
func resolveApprovedExitDeviceID(ctx context.Context, uuid string) (int64, bool) {
	gw := gatewayInstance
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	if gw == nil || gw.store == nil {
		return 0, false // 无 store → 无法判定
	}
	if uuid == "" {
		return 0, true // 空 UUID = 明确不是出口
	}
	rows, err := gw.store.ListRoutesByStatus(ctx, util.RouteStatusApproved)
	if err != nil {
		return 0, false // DB 错误 → 无法判定
	}
	seen := make(map[int64]bool, len(rows))
	for _, r := range rows {
		if !util.IsExitDefaultRoute(r.CIDR) || seen[r.DeviceID] {
			continue
		}
		seen[r.DeviceID] = true
		if dev, derr := gw.store.GetDevice(ctx, r.DeviceID); derr == nil && dev != nil &&
			strings.EqualFold(dev.DeviceUUID, uuid) {
			return r.DeviceID, true
		}
	}
	return 0, true // 查过了,确实不是已批准出口
}

// deviceHasApprovedExitRoute 查 store:该设备是否有 approved 的全网路由(0.0.0.0/0 或 ::/0),即已被 admin 批准为公网出口。
// 返回 (approved, ok):
//   - ok=false → **无法判定**(无 store / DB 查询出错)。调用方**不得**把它当「未批准」处理(否则一次 DB 抖动就会
//     把仍有效的出口会话误撤销 / 选择误回退 server）—— 应保守保留现状。
//   - ok=true  → 已确切查到结果,approved 即「是否已批准为出口」。
func deviceHasApprovedExitRoute(ctx context.Context, deviceID int64) (approved bool, ok bool) {
	gw := gatewayInstance
	if gw == nil || gw.store == nil || deviceID == 0 {
		return false, false // 无 store / 无 deviceID → 无法判定
	}
	rows, err := gw.store.ListRoutesByDevice(ctx, deviceID)
	if err != nil {
		logrus.WithError(err).WithField("device_id", deviceID).Warn("[egress] 查出口路由失败")
		return false, false // DB 错误 → 无法判定(调用方据此保守,不误判为「未批准」)
	}
	for _, r := range rows {
		if r.Status == util.RouteStatusApproved && util.IsExitDefaultRoute(r.CIDR) {
			return true, true
		}
	}
	return false, true // 查过了,确实没有 approved 出口路由
}

// revalidateExitBindings 复核所有「已绑定出口」的会话:绑定的设备若已不再是 approved 出口(被 admin 撤销),
// **即时**把该会话出口重置回 server 自出口(egressDeviceID=0,原子写,与数据面安全并发)+ 回一帧 EgressSelectAck{revoked}
// 通知客户端。由 control-socket `/reload?what=exits` 触发(admin 撤销出口后调用),修「撤销对正在用的会话不实时生效」
// 的 gap。返回被重置的会话数。仍被批准的出口保持绑定不动。
func revalidateExitBindings(ctx context.Context) int {
	gw := gatewayInstance
	if gw == nil || gw.store == nil {
		return 0
	}
	// 快照所有「绑了出口」的会话(egressDeviceID != 0)。锁内只收集,锁外查库 + 写帧。
	connIDMapMu.RLock()
	type bound struct {
		c   *Connection
		dev int64
	}
	bs := make([]bound, 0, 8)
	for _, c := range connIDMap {
		if c == nil || c.takenOver.Load() {
			continue
		}
		if dev := c.egressDeviceID.Load(); dev != 0 {
			bs = append(bs, bound{c: c, dev: dev})
		}
	}
	connIDMapMu.RUnlock()
	if len(bs) == 0 {
		return 0
	}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	keepCache := make(map[int64]bool, len(bs))
	// 两段式(深扫第六轮 low):**先**把所有「确认被撤销」的会话 CAS 重置回 server —— 撤销即时生效,不被任意一个卡住
	// 客户端的 ack 写(虽各有 5s 写超时)拖慢后续会话的重置;**再**统一回 revoked 通知。
	resetConns := make([]*Connection, 0, len(bs))
	for _, b := range bs {
		keep, seen := keepCache[b.dev]
		if !seen {
			approved, q := deviceHasApprovedExitRoute(dbCtx, b.dev)
			// 保留绑定的条件:确实仍被批准 **或** 查不动(DB 出错,无法判定)——绝不因一次 DB 抖动误撤销在用出口。
			keep = approved || !q
			keepCache[b.dev] = keep
		}
		if keep {
			continue // 仍被批准 / 暂时无法判定 → 保持绑定。
		}
		// 撤销 / 不再批准 → 回退 server。CAS 防误伤:仅当它**仍**绑着这个被撤销的 dev 才重置
		// (期间客户端可能已自行改了出口;atomic CAS 与 readLoop 的 Store 安全并发)。
		if b.c.egressDeviceID.CompareAndSwap(b.dev, 0) {
			logrus.WithFields(logrus.Fields{
				"user_id":        b.c.userID,
				"conn_id":        b.c.connIDStr,
				"exit_device_id": b.dev,
			}).Warn("[egress] 出口资格被撤销,本会话已实时回退 server 自出口(待通知客户端)")
			resetConns = append(resetConns, b.c)
		}
	}
	// 通知阶段:重置已全部落定,这里逐个回 revoked ack(各带 5s 写超时;一个卡住客户端不再影响别人的撤销即时性)。
	for _, c := range resetConns {
		sendEgressSelectAck(c, util.EgressSelectAck{Accepted: false, Reason: "revoked"})
	}
	return len(resetConns)
}
