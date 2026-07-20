package main

import (
	"context"
	crand "crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"
	"golang.org/x/time/rate"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// enableTCPKeepAlive 对底层 *net.TCPConn 开启系统保活（含 WebSocket 下的 UnderlyingConn）。
func enableTCPKeepAlive(c net.Conn) {
	type underlying interface {
		UnderlyingConn() net.Conn
	}
	chain := c
	if u, ok := c.(underlying); ok {
		if base := u.UnderlyingConn(); base != nil {
			chain = base
		}
	}
	tcp, ok := chain.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(30 * time.Second)
}

// virtioNetHdrLen 与 Linux IFF_VNET_HDR 下 TUN 写时要求的 virtio_net_hdr 长度一致（wireguard/tun 写时要求 offset >= 此值）
const virtioNetHdrLen = 10

// tunBufSize 为 TUN 包 buffer 的实际大小；TUN MTU=1500，2048 足够覆盖且对齐友好，避免 64KB 浪费
const tunBufSize = 2048

// 已做优化：tunReadBufPool 复用 TUN 读缓冲；tunCopyBufPool 复用 TUN→stream CopyBuffer；TUN 包池化传递+消费者归还；
// demux 用 netip.Addr 做 map key（支持 IPv4/IPv6）；stream→TUN 经 tunWriteChan 单 goroutine 串行写；TUN 读经 tunReadChan+demux 到各连接 TunChan。
// 使用 golang.zx2c4.com/wireguard/tun 批量 Read/Write，减少 syscall。
// 说明:这三个 pool 用 []byte 而非 *[]byte,staticcheck SA6002 会提示"应该用
// pointer-like 入 pool"。我们刻意保留 []byte:
//   - SA6002 关心的是 Put 时 slice header (24B) 会 escape 到 heap,确实有开销;
//   - 但本仓 30+ 个 Get/Put 调用点 + pkt.Buf 字段(util.TunPacket)若改成 *[]byte
//     会导致 pkt.Buf=*[]byte → 每次访问都要 deref,且原始指针必须沿生命周期手动
//     携带(否则 Put 时找不到原始 *[]byte 句柄),refactor 风险远大于 24B/帧;
//   - 数据面热路径每个 Get/Put 已经在传 (1500B + 包头) 级别的 buffer,24B header
//     escape 占比 < 2%,远小于 syscall / copy 的成本。
//
// 真要消除 SA6002 提示请整改整个 Buf 链路;否则保留并以本注释 ack。
var (
	tunReadBufPool  = sync.Pool{New: func() interface{} { return make([]byte, tunBufSize) }}
	tunWriteBufPool = sync.Pool{New: func() interface{} { return make([]byte, virtioNetHdrLen+tunBufSize) }}
	tunPktBufPool   = sync.Pool{New: func() interface{} { return make([]byte, tunBufSize) }}
)

// gatewayState VPN 网关状态：配置与 conv_id 分配（与旧 KCP conv 语义一致，仅作会话键）
type gatewayState struct {
	cfg        *config.Config
	nextConvID atomic.Uint32

	// PSK 自托管模式注入:启动时由 initAuthBackend 初始化,store 与 authVerifier
	// 同进同出(同时为 nil 或同时非 nil)。当前所有部署都是 PSK,只有测试场景
	// (例如 setupGateway helper)会构造 nil store 的 gw。
	store        *store.Store
	authVerifier *auth.Verifier

	// P2#16(2026-05-24):VPN 登录前置 PoW 服务。**始终启用**;nil 仅在测试场景
	// (老 setupGateway helper / 单测构造 nil-store gw 时)出现,handleVPNLink
	// 路径会用 lazyPoWService() 兜底初始化,保证测试也能跑全流程。
	//
	// 进程级单例,HMAC key 启动随机不暴露,重启即失效是 invariant。
	powService *PoWService
}

// lazyPoWService 在 gw.powService 为 nil 时返回一个全局兜底实例。
//
// 设计:生产路径在 main 启动时显式 NewPoWService 注入 gw.powService;但测试场景
// 用 &gatewayState{...} 构造 gw 时通常不会赋这个字段,如果 handleVPNLink 走到
// PoW 路径就会 nil-deref。这里走 sync.Once 起一个全局 fallback,字段值与
// config 默认(failures_enable=0, base=8, ramp=14, step=2, ceiling=22, ttl=300s)。
func (gw *gatewayState) effectivePoWService() *PoWService {
	if gw != nil && gw.powService != nil {
		return gw.powService
	}
	return lazyPoWService()
}

// lazyPoWFallback 用 sync.Mutex 而非 sync.Once 保护:
//   - 生产路径 main 启动时显式赋 gw.powService,这里不会被命中;
//   - 测试路径通过 resetLazyPoWForTest() 在测试间清零,避免跨测试污染
//     (同一份 IPFailureTracker 在多测试间累积失败 / 同一份 hmacKey 让
//     上一测试的 PoWProof 被下一测试当 replay 拒绝);sync.Once 不可重置,
//     所以改用可重入的 Mutex + lazy init。
//
// **设计:lazyPoWService 创建的实例不启动 RunGC goroutine**
// (2026-05-24 round-4 scan 决议)
//   - 生产路径不达此分支(main 总会显式赋 gw.powService + 启 RunGC),
//     不影响实际 GC 行为;
//   - 测试路径每个测试 t.Cleanup → resetLazyPoWForTest 把整个实例
//     (含 powUsed 表)一起置 nil,下次 lazyPoWService() 重建,
//     不需要 RunGC 也能保证表不累积;
//   - 如果给 lazy 起 RunGC goroutine,需要 stop channel 才能干净退出 —
//     测试间每次 reset 都要 close 旧 stop channel 否则 goroutine 泄漏,
//     增加测试胶水代码却无生产收益。
var (
	lazyPoWMu       sync.Mutex
	lazyPoWFallback *PoWService
)

func lazyPoWService() *PoWService {
	lazyPoWMu.Lock()
	defer lazyPoWMu.Unlock()
	if lazyPoWFallback != nil {
		return lazyPoWFallback
	}
	svc, err := NewPoWService(nil, nil, 0, 8, 14, 2, 22, 300)
	if err != nil {
		// crypto/rand 失败 = 系统熵源损坏,继续运行只会让所有登录的 PoW 验签
		// 全部失败 / 全部成功(取决于 key 的零值行为)。直接 Fatal 让 systemd 拉起
		// 而非保留一个语义未定义的半残对象(P0:之前 svc=&PoWService{} 会让
		// handleVPNLink 后续 powSvc.failures.Count(ipHost) nil-deref panic)。
		logrus.WithError(err).Fatal("[pow] lazy fallback 初始化失败,熵源不可用,进程退出")
	}
	lazyPoWFallback = svc
	return lazyPoWFallback
}

// resetLazyPoWForTest 测试用:把 lazy fallback 清零,下次 lazyPoWService() 会重建。
// 不暴露给生产路径(只在 _test.go 文件里调)。
func resetLazyPoWForTest() {
	lazyPoWMu.Lock()
	defer lazyPoWMu.Unlock()
	lazyPoWFallback = nil
}

// Connection 单条 VPN 链路（TCP 帧）上的会话
//
// 智能模式 takeover（reality→hy2 等热切换）相关字段：
//   - takeoverSecret：登录成功时随机生成的 32B nonce hex；下发给客户端 LoginResp.TakeoverSecret，
//     新链路接管时回填到 LoginReq.TakeoverSecret 由本端 subtle.ConstantTimeCompare 校验。
//   - loginToken：本会话 LoginReq.Token（PR 3 仅做调试记录；实际身份校验依赖 takeoverSecret）。
//   - takenOver：被新链路接管后置 true；本 conn defer 跳过虚拟 IP 释放、TunChan 关闭与 SessionRelease。
//   - takeoverMu：保证「停老 demux → 转移 clientIPs → 启动新 demux → set takenOver」原子完成，避免双 demux 抢同一 TunChan。
//   - tunnelDone：runLinkTunnel 完整退出时被关闭；接管路径 <-oldConn.tunnelDone 等老链路完全释放 TunChan 后再启动新 demux。
type Connection struct {
	connID    uint32 // 会话标识（原 conv_id）
	connIDStr string // 进程内唯一会话标识(16B 十六进制);接管时新 conn 继承之
	userID    string // PSK 校验通过后的 user 标识(形如 "u<id>")
	// clientIPs:虚拟 IP 与 TunChan。
	//
	// S1(2026-05-26):atomic.Pointer 升级。
	//
	// 历史:登录路径 server.go vIP 分配在 c 已进 connIDMap 之后才写 c.clientIPs,
	// 中间有窗口期。R1 把 /status build info 移到锁外后,跟登录写 race 风险表面化
	// (go test -race 没抓只是因为测试 fake conn 不走真分配路径,生产并发可触发)。
	//
	// 修法:类比 c.rlConn,改 atomic.Pointer[[]util.VirtualIPAssignment]。
	// 写者一次 Store,读者 Load,Go memory model 保证 happens-before,零锁安全。
	//
	// 读 API:safeClientIPs() 返 slice 副本(或 nil),调用方按需 range。
	// 写入:c.clientIPs.Store(&assignments)(server.go:2149)+ takeover 路径
	// newConn.clientIPs.Store(&inheritedIPs)(server.go:2399 附近)。
	clientIPs atomic.Pointer[[]util.VirtualIPAssignment]
	linkConn  io.ReadWriteCloser // 限速封装后的连接，踢人时关闭
	linkWrMu  sync.Mutex         // 写链路帧串行化（多 TunChan 并发写）

	// P0-4(2026-05-22):用户级 enforcement 字段,登录时从 users 表读出并固化在
	// 本次会话上(后续 user 改了字段需要先踢线再重连,见 user invalidation P0-1)。
	//
	// exitAllowed=false 时,数据面 IPPacket 入口会直接丢弃「dst 不属于任何 vIP」
	// 的包(即出口公网流量),不论 ACL 是否放行,保证「企业级 user 默认不能用 VPN
	// 出公网」语义。同账号 / 跨账号 vIP 流量仍按 ACL 裁决。
	//
	// bwUpBPS / bwDownBPS:本会话允许的上下行字节速率,<=0 = 不限(即仅按 platform
	// 配置限速)。最终限速取 min(platform, user),0 当作 +∞ 处理。
	exitAllowed bool
	bwUpBPS     int64
	bwDownBPS   int64

	// maxSessionsAtLogin(0021):登录瞬时从 users.max_sessions 定格的按账号并发
	// 会话上限。0 = 跟随全局 [server].max_sessions_per_user;>0 = 覆盖全局;
	// -1 = 该账号显式不限。evictOldestSessionsLocked 以**新登录 conn** 上的这个
	// 快照为准;admin 改库后仅对未来登录生效(与全局热更同口径,现役会话不回踢)。
	maxSessionsAtLogin int

	// P2#12(2026-05-22):本会话所属 device 在 store 里的主键(devices.id)。
	// 客户端未上报合法 device_uuid 时为 0,此时 subnet_routes 上报会被静默忽略
	// (拒绝匿名 device 注册路由,避免脏数据)。
	deviceID int64

	// exit-node:本会话选定的「公网出口」目标设备的 devices.id;0 = 走 server 自出口(默认)。
	// 客户端经 LinkTypeEgressSelect 设定,server 校验「已被 admin 批准为出口(approved 0/0/::/0,在线/离线均可)
	// + 本会话 exit_allowed」后置位(按授权绑定,详见 docs/DESIGN_EXIT_NODE.md)。
	// atomic.Int64:本 conn 的 readLoop goroutine(EgressSelect 处理 + IPPacket 转发分支)读写,**且** control-socket
	// 的「出口撤销实时复核」(revalidateExitBindings)在另一 goroutine 把它重置为 0,故必须原子(数据面每包 Load,开销可忽略)。
	egressDeviceID atomic.Int64

	// exit-node(M6):选定出口下线时「已通知客户端一次」的一次性闸。与 egressDeviceID 同 goroutine 读写
	// (forwardPacketToExitNode 与 handleEgressSelectFrame 都在 readLoop),无需加锁。出口离线时数据面对
	// **每个**包都会丢弃,但只在首个丢包时回一帧 EgressSelectAck{reason:exit_offline}+WARN,避免刷屏;
	// 重新 EgressSelect(任意目标)时复位,使下次再下线能再通知一次。
	exitOfflineNotified bool

	// exit-node(M6 带宽帽):本会话出口转发的 per-session 令牌桶,懒建(仅当 exitForwardRateBPS>0)。
	// 仅本 readLoop goroutine 读写,无需加锁。换出口不清桶(会话级速率预算)。
	exitFwdLimiter *rate.Limiter

	// exit-node(M6 审计):本会话「已记一次出口转发审计」一次性闸。首次成功转发记一条 INFO,重新
	// EgressSelect 时复位(换出口后再审计)。同 readLoop goroutine 读写,无需加锁。
	exitFwdAudited bool

	// exit-node 选择器:本会话是否「真在跑出口」——即发过带 /0 的 RouteAdvertise{exit}(跑了 --exit-node)。
	// 用于出口列表(buildExitsList)与 EgressSelect 校验:只有 advertisedExit && approved 的设备才算「可选在线出口」,
	// 修掉「历史 approved 但本次以普通客户端连入、没装 NAT」被选中导致黑洞的洞。atomic.Bool:本会话 readLoop
	// 置位,而 buildExitsList / 广播在其它 goroutine 读,需原子。
	advertisedExit atomic.Bool

	// exit-node(v6 能力感知):本会话作出口时**是否真有 IPv6 公网出网**——即最近一帧 RouteAdvertise{exit} 是否含 ::/0。
	// 出口客户端现按真实 v6 出网条件宣告 ::/0(无 v6 只报 0.0.0.0/0);server 据此对「使用方公网 v6 目的 + 该出口无 v6」
	// 回一帧 ICMPv6 Destination Unreachable(见 forwardPacketToExitNode),让使用方 v6 秒失败、Happy Eyeballs 立刻回落
	// v4——根治「墙内 v4-only 出口承接不了的公网 v6 流量黑洞 15~30s」。仅在 advertisedExit=true 时有意义。
	// 老出口客户端(总宣告 ::/0)→ 恒 true → 维持旧行为(server 照转 v6),无回归。atomic.Bool:readLoop 置位、数据面读。
	advertisedExitV6 atomic.Bool

	// subnet route(SR-M4 深扫):本会话是否「真在跑子网路由器」——即发过带具体(非 0/0)CIDR 的 RouteAdvertise{exit:false}
	// (跑了 --advertise-routes、装了 dst 限定 NAT)。镜像 advertisedExit:forwardPacketToSubnetRoute 只把流量投给
	// advertisedSubnetRoutes && !takenOver 的会话,修掉「设备历史 approved 某网段、但本次以普通客户端连入(没装 subnet
	// NAT)」时仍被转发 → 未 NAT 的 mesh vIP 包漏进宣告方 LAN + 无回程黑洞的洞(与出口节点同类)。atomic.Bool:本会话
	// readLoop 置位,forwardPacketToSubnetRoute / lookupSubnetAdvertiserConnByDevice 在其它 goroutine 读。
	advertisedSubnetRoutes atomic.Bool

	// subnet route(第 7 轮深扫):本会话**当前宣告的具体(非 0/0)CIDR 集**(掩码归一)。advertisedSubnetRoutes 只是「是否
	// 在跑子网路由器」的粗布尔;本集用于 forwardPacketToSubnetRoute 的 per-CIDR 门控——设备的 NAT/FORWARD 只 dst 限定到
	// 当前 --advertise-routes,若设备**收窄**宣告(重连去掉 Y)但 DB 里 Y 的批准仍在,仅凭布尔 + DB 表会把 Y 转给它 → 未 NAT
	// 漏进其 LAN(宽松主机)/黑洞(加固主机),违背设备已收窄的意图。故转发前再校验 dst ∈ 本集。每次 RouteAdvertise 以**本帧为准
	// replace**(客户端发全量、非增量,故本帧即当前 NAT 全集;replace 使收窄经 fresh/takeover 两种重连都正确剔除、且无累积→无界
	// 增长)、随 takeover 继承(hot-switch 不重发 advertise 时靠继承)、空撤回/断开清。nil/空 = 未知 → 退回布尔行为(放行);生产中
	// 布尔置真必同帧填集,故不触发该退路。atomic.Pointer:整体替换(copy-on-write),每包热路径只读 Load + 线性 Contains(条数极少)。
	advertisedRoutes atomic.Pointer[[]netip.Prefix]

	// 0011(2026-05-23):per-device 限速快照,登录瞬时从 devices.rate_*_bps 读出。
	// <=0 = 该方向不在 device 层强制;实际生效值由 effectiveLinkRates 多级取 min 算出,
	// 并通过 rlConn 持有的 *rate.Limiter 落地。
	//
	// rlConn 是 linkConn 的具体类型(*rateLimitedConn)的直接引用,给 control sock
	// /rate/refresh 热更用 —— linkConn 是接口类型(io.ReadWriteCloser),想拿到
	// SetUploadLimit 得 type assert,登录路径上一次性 set 这个字段省得每次 refresh
	// 都断言。Load()==nil 表示该 conn 未走限速路径(早期 / 测试场景,容错保留)。
	//
	// 架构升级(2026-05-24):atomic.Pointer[rateLimitedConn] 替换裸指针。N38 race
	// 的根因是写后进 map 之间的窗口期,之前用 c.linkWrMu 短锁配合 safeRLConn() 防
	// 御;atomic.Pointer 读侧零锁(ns 级 atomic.Load),Pre-write/Post-write 顺
	// 序自带 happens-before,go test -race 永不报警。写侧仍在 linkWrMu 块内
	// (跟 linkConn 一起写),代码风格不动。c.linkConn 还是 interface 不能简单 atomic,
	// 保留 linkWrMu 走老路径。
	deviceRateUpBPS   int64
	deviceRateDownBPS int64
	rlConn            atomic.Pointer[rateLimitedConn]

	// 2026-05-23(supersede 机制):本会话所属 device 的 RFC 4122 v4 UUID(已 lowercase 归一)。
	// 来源是 store 里 UpsertDevice 成功后的 Device.DeviceUUID,**不要**直接读 loginReq.DeviceUUID,
	// 避免老格式 / 未归一字符串混入。
	//
	// 用途:登录路径用它做「同 user 同 device_uuid 单实例」检测 ——
	//   - 同一台设备(同 user 同 deviceUUID)再次登录时,把旧 conn 标记为 supersede 后异步 close,
	//     避免「客户端 crash 重启 / NAT 迁移 / 后台 wakeup」后两条会话并存到 5 min 才被 idle GC。
	//   - 空字符串 = 客户端没上报 device_uuid 或 upsert 失败:跳过 supersede(匿名 device 不应互踢)。
	deviceUUID string

	// deviceName 是 store.UpsertDevice **去重后**的最终设备名（每用户唯一，重名追加 "-N"）。来源同 deviceUUID——
	// authResult.Device.DeviceName（UpsertDevice 成功才非空）。经 ConvSaltLite 下发给客户端回显（Tailscale 式：
	// 本机报 "homepi" 被去重成 "homepi-1" 时 UI 显示服务端最终名）。空 = 匿名会话，客户端回退本地名。
	deviceName string

	// P0-1(2026-05-22):登录瞬时的 user.psk_hash 快照。
	// user_invalidate goroutine 周期对比这个值与库里的 psk_hash,不同 → reset-psk
	// 发生过,主动 close 本会话(close code = CloseCodeUserInvalidated)。
	// 留空时跳过 PSK 失效检测(测试 / 老路径)。
	pskHashAtLogin string

	// platformAtLogin(2026-07-18):登录时 LoginReq.Platform 的快照(客户端自报,
	// 不归一大小写 —— AllowsPlatform 匹配时两侧都会 ToLower)。用途:admin 改了
	// user.allowed_platforms 后,user_invalidate 周期扫描按它判定「在线会话是否
	// 已不合规」,不合规 → close(910) 主动踢(否则长连接 + takeover 热切换可以
	// 数周不重登,白名单变更形同虚设)。takeover 继承语义见 newConn literal。
	// 空 = 客户端没报 platform:已设白名单时视作不合规(与登录路径 AllowsPlatform
	// 对空串的判定一致)。struct literal 里设置,进 map 后只读,锁外读安全(见 U2)。
	platformAtLogin string

	takeoverSecret string      // 客户端将来通过 LoginReq.TakeoverSecret 发起接管时的口令（hex 64 字符）
	loginToken     string      // 本次登录时的 token（仅记录；身份校验走 takeoverSecret）
	takenOver      atomic.Bool // 是否已被同账号新链路接管（true 时 defer 跳过 vip / TunChan / SessionRelease 清理）
	// superseded：本会话已被 server **主动**判定为「即将 close」但其异步 cleanup 尚未完成。覆盖所有 server 发起、
	// 关链路后走异步 cleanup 的踢除路径：① 同 device 全新登录踢旧（supersede）；② 同 user 会话超限踢最老（evict）；
	// ③ admin kick（session/device/user）与 PSK 失效自动踢（均经 kickConnForUserInvalidate）。置位在关链路**之前**
	// （登录路径持 connIDMapMu 锁段内；kick 路径在 Close 前）——使旧会话**瞬间**从 by-device 转发目标
	// （lookupRunningExitConnByDevice / lookupSubnetAdvertiserConnByDevice）与在线判定（lookupActiveConnByDevice /
	// buildExitsList）里摘除，不必等 cleanup。注：客户端**自己**断线（readLoop EOF / keepalive 超时）不置此标志——
	// 那是「检测延迟」而非「server 已知即将 close」，由 cleanup 及时回收，superseded 不适用也无法提前预知。
	//
	// 修的 bug：出口机切网络走 fresh 重登录时，旧 conn 被 supersede（关链路 + 异步清理）但**不设 takenOver、也不清
	// advertisedExit**，而新 conn 尚未重发 RouteAdvertise（advertisedExit=false）——「已踢未清」窗口里旧 conn 是该
	// device 唯一 advertisedExit&&!takenOver 会话，lookupRunningExitConnByDevice 会**确定性**选中它，把请求方出口流量
	// 投进已关闭的旧链路黑洞（请求方还收不到 exit_offline，只是干丢包 → 出口时通时不通）。takenOver 路径无此问题（有
	// 原子过户 + 继承 advertisedExit）；本标志专补 supersede/evict 这条不设 takenOver 的关闭路径。一次性置真、不复位
	// （被踢会话即将销毁，不复用）。
	superseded atomic.Bool
	takeoverMu sync.Mutex    // 保护接管转移的原子性（防止 race 和重入）
	tunnelDone chan struct{} // runLinkTunnel 完整退出信号；初始化为 make(chan struct{})；运行末尾 close
	// cleanupDone 在 cleanupConnection **完整执行完**(vIP 释放 / TunChan 注销 / map 摘除)后 close。
	// 与 tunnelDone 的区别很关键:tunnelDone 只标志 runLinkTunnel 返回,而真正释放 vIP 的
	// cleanupConnection 是在其后由 handleVPNLink 的 defer 才跑的。supersede 的 waitConnsCleanup 必须
	// 等的是「vIP 已回收」这一刻(才能让新 conn 捡回同一 vIP),故等 cleanupDone 而非 tunnelDone。
	// 初始化为 make(chan struct{});cleanupConnection 用 sync.Once 保证只 close 一次。
	cleanupDone chan struct{}
	cleanupOnce sync.Once
	createdAt   time.Time // primary login 注册到 connIDMap 的时刻;per-user 会话上限做「踢最老」时按这个排序

	// G_wss_ping:服务端主动 Ping 后,客户端最近一次回 Pong 的时刻(UnixNano)。
	// 0 = 尚未收到任何 Pong;读写都走 atomic 以避免与 keepalive goroutine 抢锁。
	lastPongAtNano atomic.Int64
}

// exitDeniedForPacket 在数据面入口判断:本会话是否因为 user.exit_allowed=false
// 而要丢这个包。fast-path:
//   - 无 userID(测试 / 老接入):返回 false,保持历史行为不变;
//   - user 显式允许出口(exitAllowed=true):返回 false。
//
// 即使返回 false,后续仍会走 ACL(可能再 drop)。这里只是「user-level 出口闸」,
// 与 ACL 的 exit-kind 规则正交:user.exit_allowed 是会话级开关,ACL exit 规则
// 是更细的 proto/port 维度选择。
func (c *Connection) exitDeniedForPacket(packet []byte) bool {
	if c == nil || c.userID == "" || c.exitAllowed {
		return false
	}
	t, ok := parsePacketTuple(packet)
	if !ok {
		return false
	}
	// 本 mesh 内部 / server 本地(某 vIP **或 server 自身网关地址**)不受「公网出口闸」限制:mesh 互通与访问 server
	// 本机服务(如 MagicDNS gateway:53)对无出口权限用户同样应放行——否则无出口权限用户在全隧道下连 magic DNS 都做不了。
	if isLocalMeshDst(t.dst) {
		return false
	}
	return true
}

var (
	connections   = make(map[uint32]*Connection)
	connectionsMu sync.RWMutex

	connIDMap   = make(map[string]*Connection) // connIDStr → Connection，用于踢人时反查
	connIDMapMu sync.RWMutex

	// P3-a(2026-05-22):by-user 会话索引。
	// 与 connIDMap 同生共死,用于 evictOldestSessionsLocked 与按 user 踢线 O(N_user) 而非 O(N_total)。
	// 写者:登录路径(connByUserAddLocked)/ 接管路径(同样) / cleanupConnection / 显式踢线。
	// 读者:evictOldestSessionsLocked / control 端 kick by user / user_invalidate 扫描。
	// **必须**与 connIDMap 在同一 connIDMapMu 持锁段内同步修改,否则两者会漂移。
	connByUser = make(map[string]map[string]*Connection)

	// gatewayInstance 提供给一些非 main 入口(如 ACL goroutine / 后续 admin
	// callback)访问 gw.cfg / gw.store 的窗口。**仅** main 在初始化时写一次,
	// 所有读者都在写之后启动,语义上无 race。
	gatewayInstance *gatewayState
)

// 通过 -ldflags "-X main.serverVersion=v1.x.y -X main.serverBuildTime=... -X main.serverGitSHA=..."
// 在 build 阶段注入。本地 dev build(直接 `go build`)三者默认 "unknown",
// 但 init() 里会 fallback 到 debug/buildinfo 的 vcs.revision / vcs.time,
// 这样**任何方式 build 出来的二进制都有版本信息**,不会在 dashboard 看到 "unknown"。
// 参考 cmd/nanotund/build-on-server.sh 的 -ldflags 段。
var (
	serverVersion   = "unknown"
	serverBuildTime = "unknown"
	serverGitSHA    = "unknown"
)

// init: 若 ldflags 未注入(本地 go build / scp 部署等场景),从 debug/buildinfo
// 把 Go module 自动嵌入的 VCS 信息(go 1.18+)填进去,保证最低限度可观测。
//
// 注:`go test` 默认不把 vcs 信息嵌入 test binary,所以单测里这个分支没法直接走;
// 真正的 fallback 合并逻辑被抽到 `mergeFallbackVersion`(纯函数)里,在
// version_test.go 里单测覆盖。这里的 init 只做读 buildInfo + 调 merge 的胶水。
func init() {
	bi, _ := buildInfo() // 没 vcs 就给 0 值,mergeFallbackVersion 内部会兜底
	serverVersion, serverGitSHA, serverBuildTime = mergeFallbackVersion(
		serverVersion, serverGitSHA, serverBuildTime, bi,
	)
}

// mergeFallbackVersion: ldflags 注入值优先(显式 > 隐式),只在仍是默认 "unknown" 时
// 才用 buildInfo 回填。vcs.modified=true 时给 dev-<sha> 拼 "-dirty" 后缀。
//
// 输入:
//   - v / sha / ts:当前(可能被 ldflags 改过的)三个版本变量值;
//   - bi:从 debug.ReadBuildInfo() 解析出来的 vcs 信息(可能全空)。
//
// 输出:回填后的三个值。三者保证不为空字符串(最差情况留 "unknown" / "dev")。
func mergeFallbackVersion(v, sha, ts string, bi buildInfoSummary) (string, string, string) {
	if sha == "unknown" && bi.gitSHA != "" {
		sha = bi.gitSHA
	}
	if ts == "unknown" && bi.vcsTime != "" {
		ts = bi.vcsTime
	}
	if v == "unknown" {
		// 没 git tag,用 dev[-<sha>][-dirty];任何情况下都比 "unknown" 友好。
		fb := "dev"
		if bi.gitSHA != "" {
			fb = "dev-" + bi.gitSHA
		}
		if bi.dirty {
			fb += "-dirty"
		}
		v = fb
	}
	return v, sha, ts
}

type buildInfoSummary struct {
	gitSHA  string // 短 sha(7 字符)
	vcsTime string // RFC3339
	dirty   bool
}

func buildInfo() (buildInfoSummary, bool) {
	out := buildInfoSummary{}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return out, false
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			v := s.Value
			if len(v) > 7 {
				v = v[:7]
			}
			out.gitSHA = v
		case "vcs.time":
			out.vcsTime = s.Value
		case "vcs.modified":
			out.dirty = s.Value == "true"
		}
	}
	return out, true
}

// applyTunChanRegisterAction 在 demux goroutine 的 single-writer 上下文里更新 ip→chan map。
//
// action=0(register):无脑写入(map[ip]=chan)。允许覆盖 —— 同一 vIP 被新连接覆盖是
// 合法场景(同设备重连复用 vIP),老 chan 由其拥有者后续 cleanup 自己 drainAndClose。
//
// action=1(unregister)的 identity 比对(P0-3,2026-05-22 现场):
//   - 旧逻辑无条件 delete(map[ip]),问题:同 vIP 被新连接重新注册后,老 conn 的
//     cleanupConnection 跑 action=1 会把**新连接注册的 chan** 一起从 map 里删掉,
//     新连接 server→client 方向从此黑洞,client 看到 ping 100% timeout 但 server
//     侧链路正常(client→server 方向可走,client 还能正常 keepalive)。
//   - 新逻辑:action.tunChan 非 nil 时做 identity 比对,只有当前 map 里的 chan
//     == action.tunChan(也就是当年自己注册的那条)才真删;否则跳过(说明已被新
//     连接接管,保留新连接的注册)。
//   - 兼容性:历史调用方未填 tunChan 的(已全部迁移)走 fallback 无条件删 ——
//     生产代码已无此调用,本字段对外保留 nil 兜底只是为了让单测 / 边角调用不崩。
//
// 函数本身不加锁:由调用方(demux for-loop)保证 single-writer 语义。
func applyTunChanRegisterAction(m map[netip.Addr]chan *util.TunPacket, action registerTunReadChanAction) {
	if action.action == 0 {
		m[action.ip] = action.tunChan
		return
	}
	if action.tunChan == nil || m[action.ip] == action.tunChan {
		delete(m, action.ip)
		return
	}
	logrus.WithField("vip", action.ip.String()).Debug("[tunchan] 跳过 unregister:同 vIP 已被新连接接管,保留新 chan")
}

type registerTunReadChanAction struct {
	action int // 0=注册，1=删除
	ip     netip.Addr
	// action=0:写入 map 用的 chan;
	// action=1(P0-3,2026-05-22):**也必须填**自己当时注册的 chan ——
	// demux 删除前会做 identity 比对,只有 map 当前 chan == action.tunChan 才真删。
	// 否则跳过(说明同 vIP 已被新连接注册成新 chan,删了就把新连接的 down-path 也断了)。
	//
	// 现场触发的现象:iOS 重连(同 vIP)→ 老 conv_id cleanup 把新 conv_id 注册的 chan
	// 一起删了 → 客户端登录正常但 server→client 方向全部丢包,ping 100% loss。
	tunChan chan *util.TunPacket
	success chan struct{}
}

// 单 TUN 模式：一张虚拟网卡，多连接共享，按 clientIP demux
var (
	globalContext       context.Context
	globalContextCancel context.CancelFunc

	registerTunReadChan = make(chan registerTunReadChanAction, 800)
	// 缓冲过大会抬高突发时的 RSS；低速链路 1024×~2KB 量级仍够用
	tunReadChan   = make(chan *util.TunPacket, 1024)
	tunWriteChan  = make(chan []byte, 1024)
	tunPacketPool = sync.Pool{New: func() interface{} { return &util.TunPacket{} }}
	// tunWriteDropCount:tunWriteChan 满导致的丢包总数(readLoop 非阻塞投递失败)。
	// 回程数据面上唯一的用户态静默丢包点,暴露成 metric 才能在「客户端说卡」时排除/坐实
	// (2026-07 排查 CDN 回程黑洞时此处无计数,只能靠两端抓包对差集,代价极高)。
	tunWriteDropCount  atomic.Uint64
	sharedTUN          tun.Device
	sharedTUNGateway   string // IPv4 网关 CIDR，如 10.1.0.1/16
	sharedTUNGatewayV6 string // IPv6 网关 CIDR，如 fd00:vpn:200::1/64；为空表示未启用 IPv6
	clientIPUsedMu     sync.Mutex
	clientIPUsed       = make(map[string]bool) // 当前已占用的虚拟 IP（IPv4 和 IPv6 共用）
	tunRandSeed        atomic.Uint32           // 随机选合法网段
)

func loadConfig(path string) (config.Config, error) {
	var cfg config.Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	err = toml.Unmarshal(data, &cfg)
	if err != nil {
		return cfg, err
	}
	cfg.Server.VPNWebSocketPath = effectiveVPNWebSocketPath(&cfg)

	// J4(2026-05-22):strict 二次校验。lenient 已经把已知字段填好了,
	// 这一遍只是检测有没有写错的 / 废弃的字段(被 lenient 静默忽略的)。
	// 默认 WARN 不 fail;NANOTUN_CONFIG_STRICT=1 升级为 fatal。
	if strictErr := config.StrictCheck(data); strictErr != nil {
		if config.StrictModeEnabled() {
			return cfg, fmt.Errorf("config strict mode 拒绝(unset %s 可降级为 WARN): %w",
				config.StrictEnvVar, strictErr)
		}
		logrus.WithError(strictErr).Warnf(
			"[config] 配置中存在未知字段(可能是拼写错误或已废弃);设 %s=1 升级为 fatal",
			config.StrictEnvVar)
	}
	return cfg, nil
}

func parseCIDR(s string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(s)
	return ipnet, err
}

// maskFromGatewayCIDR 从网关 CIDR 提取掩码字符串：IPv4 返回 "255.255.0.0" 形式，IPv6 返回前缀长度 "64" 形式
func maskFromGatewayCIDR(gatewayCIDR string) string {
	prefix, err := netip.ParsePrefix(gatewayCIDR)
	if err != nil {
		_, ipnet, errOld := net.ParseCIDR(gatewayCIDR)
		if errOld == nil && ipnet != nil && len(ipnet.Mask) == 4 {
			m := ipnet.Mask
			return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
		}
		return ""
	}
	if prefix.Addr().Is4() {
		_, ipnet, errOld := net.ParseCIDR(gatewayCIDR)
		if errOld == nil && ipnet != nil {
			m := ipnet.Mask
			if len(m) == 4 {
				return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
			}
			if len(m) == 16 {
				return fmt.Sprintf("%d.%d.%d.%d", m[12], m[13], m[14], m[15])
			}
		}
	}
	return fmt.Sprintf("%d", prefix.Bits())
}

// ipToKey 将 IP 字符串转为 netip.Addr，用于 demux map key（支持 IPv4 和 IPv6）
func ipToKey(ipStr string) netip.Addr {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap() // 确保 IPv4-mapped IPv6 地址统一为 IPv4 形式
}

// gatewayCIDRFromSubnet 从网段 CIDR 得到网关 CIDR（网段内第一个主机地址），如 10.0.0.0/24 -> 10.0.0.1/24, fd00::/64 -> fd00::1/64
// 先对齐到网络地址（Masked），再 +1 得到网关，避免配置写成 10.0.0.1/24 等主机形式时偏移错误
func gatewayCIDRFromSubnet(subnet string) (string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", err
	}
	networkAddr := prefix.Masked().Addr()
	gateway := networkAddr.Next() // 网络地址 +1 = 网关
	if !gateway.IsValid() {
		return "", fmt.Errorf("cannot compute gateway for %s", subnet)
	}
	return fmt.Sprintf("%s/%d", gateway.String(), prefix.Bits()), nil
}

// sendRegisterActionAwait 把 register/unregister action 投递给 demux goroutine 并等待响应,
// 同时尊重 globalContext.Done() —— 这是 graceful shutdown 时关键的非阻塞兜底。
//
// 背景:demux 退出条件是 `<-globalContext.Done()`,而 cleanupConnection / vIP 分配回滚等
// 路径会向 demux 发 register/unregister 然后 wait `<-action.success`。如果 demux 已经先退,
// 这些 wait 永久 hang,systemd 收 SIGTERM 后只能 SIGKILL 兜底。
//
// 这个 helper 保证 shutdown 路径下这些等待都最多卡到 ctx cancel 就返回,主流程 defer 顺利跑完。
// 数据面副作用:demux 退出后,ip2Channel map 整体丢弃,没注销的 TunChan 不会被再使用(没人投递),
// drainAndCloseTunChan 仍然由本函数调用方负责 close 资源,所以无数据面泄漏。
func sendRegisterActionAwait(a registerTunReadChanAction) {
	select {
	case registerTunReadChan <- a:
	case <-globalContext.Done():
		return
	}
	select {
	case <-a.success:
	case <-globalContext.Done():
	}
}

// isProductionLinuxRoot 用来判断本进程是否运行在「真正的部署节点」。
//
// 当返回 true 时,server 启动期间任何 TUN/iptables 步骤失败都会 Fatal,而不是
// Warn 后继续 —— 避免「监听端口接得上但数据面是黑洞」的伪可用状态把运维误导。
// 非 Linux (macOS dev) 或非 root (CI sandbox / 容器 rootless) 仍然走 Warn 兜底,
// 不影响联调脚本和单测。Geteuid 在 Linux 是 syscall.Geteuid,简单 wrap。
func isProductionLinuxRoot() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return os.Geteuid() == 0
}

// parseListenPort 从 ":port" 或 "host:port" 解析 1–65535，用于 node_login 上报 tcp_port。
func parseListenPort(listenAddr, defaultAddr string) int {
	la := strings.TrimSpace(listenAddr)
	if la == "" {
		la = defaultAddr
	}
	host, port, err := net.SplitHostPort(la)
	if err != nil {
		if strings.HasPrefix(la, ":") {
			p, err2 := strconv.Atoi(strings.TrimPrefix(la, ":"))
			if err2 == nil && p >= 1 && p <= 65535 {
				return p
			}
		}
		util.FatalExit(util.ExitConfigParse, logrus.Fields{"listen_addr": listenAddr}, "[server] 无法从 listen 地址 %q 解析端口: %v", listenAddr, err)
	}
	_ = host
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		util.FatalExit(util.ExitConfigParse, logrus.Fields{"port": port}, "[server] 无效端口 %q", port)
	}
	return p
}

// validateVPNListenAddr 保证 listen_addr 的 host 与「环回桥接」自洽:必须是通配
// (空 / 0.0.0.0 / ::)或回环地址,否则 loopbackVPNWebSocketURL 的 127.0.0.1 拨号
// 到不了实际 listener,hy2/REALITY 会静默全断。非法值直接 fail-fast。
func validateVPNListenAddr(listenAddr string) {
	la := strings.TrimSpace(listenAddr)
	host, _, err := net.SplitHostPort(la)
	if err != nil {
		// ":8080" 这类无 host 的写法:SplitHostPort 报错但语义是「所有网卡」,放行。
		if strings.HasPrefix(la, ":") {
			return
		}
		util.FatalExit(util.ExitConfigParse, logrus.Fields{"listen_addr": listenAddr},
			"[server] 无法解析 listen 地址 %q: %v", listenAddr, err)
	}
	host = strings.TrimSpace(host)
	// 空 host / 通配地址:listener 覆盖所有网卡(含回环),环回拨号可达。
	if host == "" || host == "0.0.0.0" || host == "::" {
		return
	}
	addr, perr := netip.ParseAddr(host)
	if perr != nil {
		util.FatalExit(util.ExitConfigParse, logrus.Fields{"listen_addr": listenAddr, "host": host},
			"[server] listen 地址 host %q 不是合法 IP;请用回环(127.0.0.1 / ::1)或通配(0.0.0.0 / :: / 省略 host)", host)
	}
	if addr.IsLoopback() || addr.IsUnspecified() {
		return
	}
	util.FatalExit(util.ExitConfigSemantic, logrus.Fields{"listen_addr": listenAddr, "host": host},
		"[server] listen_addr 绑到非回环具体 IP %q,会导致 hy2/REALITY 环回桥接(拨 127.0.0.1)连接被拒;"+
			"请改用 127.0.0.1:<port>(推荐)或 0.0.0.0:<port>", host)
}

func main() {
	globalContext, globalContextCancel = context.WithCancel(context.Background())
	defer globalContextCancel()

	go func() {
		// demux 是关键全局 goroutine:之前直接 Fatal → 进程立即 os.Exit,defer 链跑不完
		// (iptables/TUN/DB WAL 都不清理)。改为 globalContextCancel,让 main 中的 defer
		// 链完整跑完一遍 graceful shutdown,再 systemd 拉起。
		defer func() {
			if r := recover(); r != nil {
				logrus.WithFields(logrus.Fields{
					"goroutine": "demux",
					"panic":     r,
					"stack":     string(debug.Stack()),
				}).Error("demux goroutine panic,触发 graceful shutdown")
				if globalContextCancel != nil {
					globalContextCancel()
				}
			}
		}()

		ip2Channel := make(map[netip.Addr]chan *util.TunPacket)
		for {
			select {
			case <-globalContext.Done():
				return
			case action := <-registerTunReadChan:
				applyTunChanRegisterAction(ip2Channel, action)
				action.success <- struct{}{}

			case pkt := <-tunReadChan:
				if pkt.N < 1 {
					tunReadBufPool.Put(pkt.Buf)
					tunPacketPool.Put(pkt)
					continue
				}
				ver := pkt.Buf[0] >> 4
				var destKey netip.Addr
				switch ver {
				case 4:
					if pkt.N < 20 {
						tunReadBufPool.Put(pkt.Buf)
						tunPacketPool.Put(pkt)
						continue
					}
					destKey = netip.AddrFrom4([4]byte{pkt.Buf[16], pkt.Buf[17], pkt.Buf[18], pkt.Buf[19]})
				case 6:
					if pkt.N < 40 {
						tunReadBufPool.Put(pkt.Buf)
						tunPacketPool.Put(pkt)
						continue
					}
					var addr16 [16]byte
					copy(addr16[:], pkt.Buf[24:40])
					destKey = netip.AddrFrom16(addr16)
				default:
					tunReadBufPool.Put(pkt.Buf)
					tunPacketPool.Put(pkt)
					continue
				}
				channel, ok := ip2Channel[destKey]
				if ok {
					select {
					case channel <- pkt:
					default:
						logrus.WithField("ip", destKey.String()).Trace("TUN 写入通道已满")
						tunReadBufPool.Put(pkt.Buf)
						tunPacketPool.Put(pkt)
					}
				} else {
					// dst 不是任何已知 vIP：可能是 **server 自身发起**（net.Dial）、目的为某已批准子网（LAN 后设备）的包——
					// 典型是 FRP 反向端口转发 dial LAN 目标（见 cmd/nanotund/port_forward.go）。按子网路由投给宣告方（其本机 NAT
					// 进 LAN）；deliverIPPacketToConn 内部已拷贝载荷，故无论投递与否都在此归还本 pkt 缓冲。未命中已批准子网
					// 的杂包（扫描/广播）在 forwardServerOriginatedToSubnet 里无锁快速返回 false，照旧丢弃。
					forwardServerOriginatedToSubnet(destKey, pkt.Buf[:pkt.N])
					tunReadBufPool.Put(pkt.Buf)
					tunPacketPool.Put(pkt)
				}
			}
		}
	}()

	logrus.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	// G5: 启动时打印 build 信息(若 ldflags 已注入)。即使没注入也照打,只是显示
	// "unknown",方便看启动日志立即区分多版本部署。
	logrus.WithFields(logrus.Fields{
		"version":    serverVersion,
		"build_time": serverBuildTime,
		"git_sha":    serverGitSHA,
	}).Info("nanotund 启动")

	configPath := flag.String("config", "config.toml", "配置文件路径")
	addrOverride := flag.String("addr", "", "监听地址（覆盖配置文件中的 listen_addr）")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		util.FatalExit(util.ExitConfigParse, logrus.Fields{"config_path": *configPath}, "加载配置 %s: %v", *configPath, err)
	}

	if cfg.Log.Level != "" {
		lvl, err := logrus.ParseLevel(cfg.Log.Level)
		if err != nil {
			logrus.Warnf("无效的 log.level %q，使用 info: %v", cfg.Log.Level, err)
			logrus.SetLevel(logrus.InfoLevel)
		} else {
			logrus.SetLevel(lvl)
		}
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	if cfg.Server.ListenAddr == "" {
		// 深扫第八轮 LOW:空值兜底默认从 ":8080"(所有网卡,公网可达)收窄到回环。
		// 数据面 WS listener 只被本机 hy2/REALITY 经环回桥接,无需对外暴露;示例配置
		// 已是 127.0.0.1:8080,这里让「配置项缺失」也落到同一安全默认,避免误公开。
		cfg.Server.ListenAddr = "127.0.0.1:8080"
	}
	if *addrOverride != "" {
		cfg.Server.ListenAddr = *addrOverride
	}
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		cfg.Server.ListenAddr = v
	}
	// 深扫第八轮 MED:环回桥接的自洽校验。hy2/REALITY 终结后经 loopbackVPNWebSocketURL
	// (硬编码 127.0.0.1)回连本机 WS listener。若 listen_addr 绑到一个**具体的非回环 IP**
	// (如 10.0.0.5:8080),listener 只在该 IP 上,127.0.0.1 的环回拨号必然 connection
	// refused —— hy2/REALITY 全线 login 失败且无启动期诊断。这里在启动早期显式校验:
	// host 必须为空 / 0.0.0.0 / :: / 回环地址;否则 fail-fast 给出明确原因。
	validateVPNListenAddr(cfg.Server.ListenAddr)
	// 深扫第八轮 MED:exit_mode 非空值必须是 mesh/isolate/off 之一,拼错即 fail-fast,
	// 不再静默退回 mesh(避免一个 typo 把隔离部署翻成跨用户互通)。
	if err := cfg.TUN.ValidateExitMode(); err != nil {
		util.FatalExit(util.ExitConfigSemantic, logrus.Fields{"exit_mode": cfg.TUN.ExitMode}, "%v", err)
	}

	tunCount := len(cfg.TUN.Subnets)
	tunCountV6 := len(cfg.TUN.SubnetsV6)
	if tunCount == 0 && tunCountV6 == 0 {
		util.FatalExit(util.ExitConfigSemantic, nil, "配置的 Subnets 和 SubnetsV6 均为空，至少配置一项")
	}
	if tunCount > 0 || tunCountV6 > 0 {
		deviceName := cfg.TUN.DeviceName
		if deviceName == "" {
			deviceName = "tun0"
		}
		tcpConnlimit := cfg.TUN.TCPConnlimitPerIP
		if tcpConnlimit <= 0 {
			tcpConnlimit = 40
		}
		udpConnlimit := cfg.TUN.UDPConnlimitPerIP
		if udpConnlimit <= 0 {
			udpConnlimit = 40
		}

		// 筛出与本机网段不冲突的合法 IPv4 网段
		var chosenSubnet, gatewayCIDR string
		if tunCount > 0 {
			var usableSubnets []string
			localSubnets, errLocal := GetLocalSubnets()
			if errLocal != nil {
				logrus.WithError(errLocal).Warn("获取本机网段失败，将不进行冲突过滤")
				usableSubnets = cfg.TUN.Subnets
			} else {
				for i := 0; i < tunCount; i++ {
					subnet, errParse := parseCIDR(cfg.TUN.Subnets[i])
					if errParse != nil {
						logrus.WithError(errParse).WithField("subnet", cfg.TUN.Subnets[i]).Warn("网段解析失败，跳过")
						continue
					}
					conflict := false
					for _, local := range localSubnets {
						if SubnetOverlaps(subnet, local) {
							conflict = true
							logrus.WithField("subnet", cfg.TUN.Subnets[i]).Info("网段与本机冲突，跳过")
							break
						}
					}
					if !conflict {
						usableSubnets = append(usableSubnets, cfg.TUN.Subnets[i])
					}
				}
			}
			if len(usableSubnets) == 0 {
				logrus.Warn("无可用 IPv4 网段（均与本机冲突），跳过 IPv4")
			} else {
				idx := int(tunRandSeed.Add(1)) % len(usableSubnets)
				chosenSubnet = usableSubnets[idx]
				gw, errGW := gatewayCIDRFromSubnet(chosenSubnet)
				if errGW != nil {
					logrus.WithError(errGW).Warn("IPv4 网关 CIDR 解析失败，跳过 IPv4")
				} else {
					gatewayCIDR = gw
				}
			}
		}

		// 筛出与本机 IPv6 网段不冲突的合法网段
		var chosenSubnetV6, gatewayCIDRv6 string
		if tunCountV6 > 0 {
			var usableSubnetsV6 []string
			localSubnetsV6, errLocalV6 := GetLocalSubnetsV6()
			if errLocalV6 != nil {
				logrus.WithError(errLocalV6).Warn("获取本机 IPv6 网段失败，将不进行冲突过滤")
				usableSubnetsV6 = cfg.TUN.SubnetsV6
			} else {
				for _, subnetStr := range cfg.TUN.SubnetsV6 {
					subnet, errParse := parseCIDR(subnetStr)
					if errParse != nil {
						logrus.WithError(errParse).WithField("subnet", subnetStr).Warn("IPv6 网段解析失败，跳过")
						continue
					}
					conflict := false
					for _, local := range localSubnetsV6 {
						if SubnetOverlaps(subnet, local) {
							conflict = true
							logrus.WithField("subnet", subnetStr).Info("IPv6 网段与本机冲突，跳过")
							break
						}
					}
					if !conflict {
						usableSubnetsV6 = append(usableSubnetsV6, subnetStr)
					}
				}
			}
			if len(usableSubnetsV6) > 0 {
				idxV6 := int(tunRandSeed.Add(1)) % len(usableSubnetsV6)
				chosenSubnetV6 = usableSubnetsV6[idxV6]
				gwV6, errGWv6 := gatewayCIDRFromSubnet(chosenSubnetV6)
				if errGWv6 != nil {
					logrus.WithError(errGWv6).Warn("IPv6 网关 CIDR 解析失败，跳过 IPv6")
				} else {
					gatewayCIDRv6 = gwV6
				}
			} else {
				logrus.Warn("无可用 IPv6 网段（均与本机冲突或无效），跳过 IPv6")
			}
		}

		if gatewayCIDR == "" && gatewayCIDRv6 == "" {
			util.FatalExit(util.ExitConfigSemantic, nil, "IPv4 和 IPv6 均无可用网段，TUN 转发将不可用")
		}
		// requireTUN: Linux + root 时认为是生产环境,任何 TUN/iptables 步骤失败都
		// 必须 Fatal —— 否则服务端会监听 :8080/:443/:8443,但客户端登录后没数据面,
		// 形成「TCP 接得上,流量黑洞」的伪可用状态,极易掩盖网卡/CAP_NET_ADMIN/防火墙
		// 配置错误。macOS / 非 root 场景(dev 自测)保留 Warn 兜底,方便联调。
		requireTUN := isProductionLinuxRoot()
		failTUN := func(err error, msg string) {
			if requireTUN {
				util.FatalExit(util.ExitNetworkSetup, logrus.Fields{"err": err.Error()}, "%s (Linux root 模式拒绝 silent skip,数据面不可用)", msg)
			}
			logrus.WithError(err).Warn(msg)
		}

		DeleteExistingTUN(deviceName)
		ifce, errOpen := openTUN(deviceName, gatewayCIDR, gatewayCIDRv6)
		if errOpen != nil {
			failTUN(errOpen, "创建虚拟网卡失败")
		} else {
			sharedTUN = ifce
			sharedTUNGateway = gatewayCIDR
			if gatewayCIDRv6 != "" {
				sharedTUNGatewayV6 = gatewayCIDRv6
			}
			// 记录 server 自身网关地址，供数据面 isLocalMeshDst 识别「发往网关自身」的包（如 MagicDNS
			// gateway:53），使其不被当公网流量转发给出口/子网路由器、也不受 exit_allowed 闸拦截。
			setServerGatewayAddrs(gatewayCIDR, gatewayCIDRv6)
			// 注:chosenSubnet / chosenSubnetV6 仅用于日志,后续不再保留为全局变量。
			// IPv4 转发 + iptables（仅当有 IPv4 网段时）
			// C7: SetupIptables / SetupIp6tables 内部启动时 sweep `nanotun_main` comment 的
			// 残留规则,统一在退出路径(main return 触发的 defer)调用 teardownMainIptablesRules
			// 撤掉,避免 SIGTERM / kill -9 / 升级后规则永久留在内核。
			iptablesInstalled := false
			if gatewayCIDR != "" {
				// MagicDNS 端口例外:启用时需先于出口 DNS 接管 :53 DNAT,并在 filter INPUT 放行
				// 客户端 → 网关:<port> 的查询(否则查询被 DNAT 到上游 / 被 -P INPUT DROP 挡)。
				// 见 setupMagicDNSException。未启用时 gwV4="" → SetupIptables 内 no-op。
				magicGwV4 := ""
				magicPort := 0
				if cfg.Server.MagicDNS.Enabled {
					magicGwV4 = gatewayAddrFromCIDR(gatewayCIDR)
					magicPort = int(resolveMagicDNSConfig(cfg.Server.MagicDNS).port)
				}
				if err := EnableIPForward(); err != nil {
					failTUN(err, "开启 ip_forward 失败")
				} else if wanIface, wanIP, errWan := GetWAN(); errWan != nil {
					failTUN(errWan, "获取 WAN 失败,跳过 iptables")
				} else if err := SetupIptables(deviceName, wanIface, wanIP, []string{chosenSubnet}, tcpConnlimit, udpConnlimit,
					cfg.TUN.ForwardBlockBT, cfg.TUN.ForwardBlockTracker6969, cfg.TUN.ForwardBlockSMTP25, cfg.TUN.ResolveExitMode(), cfg.TUN.ExitDNSRedirect,
					magicGwV4, magicPort); err != nil {
					failTUN(err, "配置 iptables 失败")
				} else {
					iptablesInstalled = true
				}
			}
			// IPv6 转发 + ip6tables（仅当有 IPv6 网段时;v6 缺失保持 Warn —— v6 在多数云厂商是可选项）
			v6SetupRetryArmed := false
			if gatewayCIDRv6 != "" {
				installV6Rules := func() bool {
					if err := EnableIPv6Forward(); err != nil {
						logrus.WithError(err).Warn("开启 IPv6 转发失败")
						return false
					}
					wanIfaceV6, wanIPv6, errWan := GetWANv6()
					if errWan != nil {
						logrus.WithError(errWan).Warn("获取 IPv6 WAN 失败,跳过 ip6tables")
						return false
					}
					if err := SetupIp6tables(deviceName, wanIfaceV6, wanIPv6, []string{chosenSubnetV6}, tcpConnlimit, udpConnlimit,
						cfg.TUN.ForwardBlockBT, cfg.TUN.ForwardBlockTracker6969, cfg.TUN.ForwardBlockSMTP25, cfg.TUN.ResolveExitMode(), cfg.TUN.ExitDNSRedirect); err != nil {
						logrus.WithError(err).Warn("配置 ip6tables 失败")
						return false
					}
					return true
				}
				if installV6Rules() {
					iptablesInstalled = true
				} else if isProductionLinuxRoot() {
					// 启动装失败常见于「server 的 v6(RA/DHCPv6)晚于进程就绪」:若不补装,60s 出网探测转"有 v6"后
					// 数据面照转公网 v6,但 MASQUERADE 没装 → ULA 源出网被上游丢弃(探测/NAT 脱节黑洞)。注册补装
					// 钩子,由探测 goroutine 在探明有 v6 出网时重试,成功即撤钩(见 egress_select.go)。
					// 仅生产 Linux root 注册:非 Linux / 非 root 下 stub 永远失败,重试只会每 60s 刷一遍 Warn。
					armV6SetupRetry(func() bool {
						ok := installV6Rules()
						if ok {
							logrus.Info("[egress] 探明 v6 出网后补装 ip6tables/NAT66 成功(启动时曾失败)")
						}
						return ok
					})
					v6SetupRetryArmed = true
				}
			}
			// C7: 退出时撤掉所有 mainIptComment 标记的 iptables / ip6tables 规则。
			// 仅在确实有 install 发生(或补装钩子在册、运行中可能补装)时注册,避免「装失败 + teardown 跑 sweep」
			// 浪费一次 fork-exec。
			if iptablesInstalled || v6SetupRetryArmed {
				defer func() {
					logrus.Info("[shutdown] 撤销 nanotun 安装的 iptables / ip6tables 规则")
					teardownMainIptablesRules()
				}()
			}
			// 关 TUN 让 dev.Read 立刻返回,tunReadLoop / tunWriteLoop 自然退出。
			// 注册在这里是为了让 LIFO defer 序里:authCleanup(关 DB) → sharedTUN.Close → 各 listener.Close
			// 之间有合理顺序。
			defer func() {
				if sharedTUN != nil {
					logrus.Info("[shutdown] 关闭 TUN")
					_ = sharedTUN.Close()
				}
			}()
			// 关键全局 goroutine:panic → 触发 graceful shutdown(关 TUN/iptables/DB WAL),
			// 让 systemd 拉起 fresh 实例,而不是裸 panic 让 Go runtime os.Exit。
			go safeGlobalGoroutine("tunReadLoop", globalContextCancel, func() {
				tunReadLoop(ifce)
			})
			go safeGlobalGoroutine("tunWriteLoop", globalContextCancel, func() {
				tunWriteLoop(ifce)
			})
			var logParts []string
			if gatewayCIDR != "" {
				logParts = append(logParts, fmt.Sprintf("IPv4 网段 %s 网关 %s", chosenSubnet, gatewayCIDR))
			}
			if gatewayCIDRv6 != "" {
				logParts = append(logParts, fmt.Sprintf("IPv6 网段 %s 网关 %s", chosenSubnetV6, gatewayCIDRv6))
			}
			logrus.Infof("TUN 已创建 %s，%s", deviceName, strings.Join(logParts, "，"))
		}
	}

	if err := cfg.Hysteria.ValidateHysteriaCredentials(); err != nil {
		util.FatalExit(util.ExitConfigSemantic, nil, "配置: %v", err)
	}

	certPath := strings.TrimSpace(cfg.Server.TLSCertFile)
	keyPath := strings.TrimSpace(cfg.Server.TLSKeyFile)
	if (certPath != "") != (keyPath != "") {
		util.FatalExit(util.ExitConfigSemantic, nil, "[server] tls_cert_file 与 tls_key_file 须同时配置或同时留空")
	}

	vpnTCPPort := parseListenPort(cfg.Server.ListenAddr, ":8080")

	gw := &gatewayState{cfg: &cfg}
	// 暴露 gw 给非 main 路径(metrics / audit / ACL reload 等)的只读窗口。
	// main 在所有 goroutine 启动之前写一次,后续不再修改,语义上无 race。
	gatewayInstance = gw

	// exit-node(M6 带宽帽):per-session 出口转发速率帽。所有数据面 goroutine 启动前写一次(无 race);
	// 非 SIGHUP 热更(改后需重启)。<=0 = 不限。
	if cfg.Server.ExitForwardRateBPS > 0 {
		exitForwardRateBPS.Store(cfg.Server.ExitForwardRateBPS)
		logrus.WithField("exit_forward_rate_bps", cfg.Server.ExitForwardRateBPS).
			Info("[egress] 已启用出口转发速率帽(per-session)")
	}

	// P2#16(2026-05-24):VPN 登录前置 PoW 服务。**始终启用**。
	// HMAC key 启动随机,nil 让 NewPoWService 内部 crypto/rand 生成 32B 一次性 key;
	// 其它公式参数从 [server.pow] 读,缺省零值由 NewPoWService 兜底成 (0/8/14/2/22/300)。
	pcfg := cfg.Server.Pow
	powSvc, errPoW := NewPoWService(
		nil, // hmac key:强制启动随机
		NewIPFailureTracker(),
		pcfg.FailuresEnable,
		pcfg.BaseDifficulty,
		pcfg.RampDifficulty,
		pcfg.StepPerFailure,
		pcfg.AdaptiveCeiling,
		pcfg.TTLSec,
	)
	if errPoW != nil {
		util.FatalExit(util.ExitConfigSemantic, logrus.Fields{"err": errPoW.Error()}, "初始化 PoW 服务失败: %v", errPoW)
	}
	gw.powService = powSvc
	// PoW 服务 GC goroutine:每 60s 扫一遍已过期 challenge_id + IP 失败窗口。
	// stop chan 用 globalContext.Done(),进程退出时跟随 cleanup。
	go powSvc.RunGC(globalContext.Done())

	// exit-node:探测 **server 自身** v6 公网出网能力(后台 goroutine,启动即探一次、之后定期重探)。
	// server 无 v6 时,数据面对「走 server 自出口的公网 v6」回 ICMPv6 unreachable 使使用方秒回落 v4
	// (补 peer 出口之外的 egress==0 路径;详见 serverSelfEgressV6FastFail)。探测在数据面之外,数据面只读 atomic。
	startServerV6EgressProbe(globalContext.Done())

	// per-IP 登录限速([server].login_rate_limit_per_min):0=不限制(默认)。
	// 防暴破主力是上面始终启用的 PoW + argon2id semaphore,这里只是可选兜底。
	globalLoginIPLimiter.SetRatePerMin(cfg.Server.LoginRateLimitPerMin)
	if cfg.Server.LoginRateLimitPerMin > 0 {
		logrus.WithField("login_rate_limit_per_min", cfg.Server.LoginRateLimitPerMin).
			Info("[login-ratelimit] per-IP 登录限速已启用")
	} else {
		logrus.Info("[login-ratelimit] per-IP 登录限速已关闭(login_rate_limit_per_min=0,不限制)")
	}

	// PSK 自托管模式:打开 SQLite、跑迁移、挂 authVerifier。失败直接 Fatal,
	// 不再有 legacy_backend 退路 —— 没 store 就启动不了。
	authCleanup, err := initAuthBackend(globalContext, gw)
	if err != nil {
		util.FatalExit(util.ExitDBInit, logrus.Fields{"err": err.Error()}, "初始化 auth 后端失败: %v", err)
	}
	defer authCleanup()

	vpnLn, errLn := net.Listen("tcp", cfg.Server.ListenAddr)
	if errLn != nil {
		util.FatalExit(util.ClassifyListenError(errLn), logrus.Fields{"listen_addr": cfg.Server.ListenAddr, "err": errLn.Error()}, "VPN Listen %s: %v", cfg.Server.ListenAddr, errLn)
	}
	defer vpnLn.Close()

	// E3(P1-3): 在 tls.NewListener 之前先套一层握手 deadline listener,Slow-loris /
	// 半开 TLS 连接最多挂 wssHandshakeTimeout 就被断开,后续 dispatchVPNIncoming 入口
	// 处再清 deadline。即使没开 TLS(http) 这层也对 HTTP 头 Slow-loris 有效。
	vpnLn = newHandshakeDeadlineListener(vpnLn, wssHandshakeTimeout)
	tlsOn := serverVPNDataPlaneTLSActive(&cfg.Server)
	if tlsOn {
		cert, errTLS := util.LoadAndCheckTLSKeyPair(certPath, keyPath, "vpn-wss")
		if errTLS != nil {
			util.FatalExit(util.ExitTLSCert, logrus.Fields{"cert": certPath, "key": keyPath, "err": errTLS.Error()}, "VPN TLS 加载证书 %s / %s: %v", certPath, keyPath, errTLS)
		}
		tlsSrv := util.NewServerTLSConfig(util.ServerTLSOptions{
			Certificates:           []tls.Certificate{cert},
			NextProtos:             []string{"http/1.1"},
			SessionTicketsDisabled: true,
		})
		vpnLn = tls.NewListener(vpnLn, tlsSrv)
		logrus.Infof("VPN：已在 %s 启用 TLS（WSS），证书 %s，握手超时 %s", cfg.Server.ListenAddr, certPath, wssHandshakeTimeout)
	}

	var loopbackWSTLS *tls.Config
	if tlsOn {
		loopbackWSTLS = loopbackVPNWebSocketDialTLS()
	}

	wsPath := cfg.Server.VPNWebSocketPath
	loopbackWSURL := loopbackVPNWebSocketURL(cfg.Server.ListenAddr, wsPath, tlsOn)

	muxEnabled := loopbackSmuxMultiplexEnabled(&cfg)
	var loopbackSmuxPoolRef *loopbackSmuxPool
	var muxOptsForAccept *smux.Config
	if muxEnabled {
		muxOptsForAccept = buildSmuxConfigFrom(cfg.Smux)
		loopbackSmuxPoolRef = newLoopbackSmuxPool(loopbackWSURL, muxOptsForAccept, loopbackWSTLS)
		logrus.Infof("VPN：%s；已启用环回 smux（hy2/REALITY 经 WebSocket 至多路 stream）", cfg.Server.ListenAddr)
	} else {
		logrus.Infof("VPN：%s，WebSocket 二进制链路帧", cfg.Server.ListenAddr)
	}

	hySrv, hyUDPPort, hyPortHopCleanup, errHy := startEmbeddedHysteria(&cfg, cfg.Server.ListenAddr, loopbackWSURL, loopbackSmuxPoolRef, loopbackWSTLS)
	if errHy != nil {
		util.FatalExit(util.ClassifyListenError(errHy), logrus.Fields{"err": errHy.Error()}, "Hysteria: %v", errHy)
	}
	if hyPortHopCleanup != nil {
		defer hyPortHopCleanup()
	}
	// 2026-07-17:hy2 独立 mTLS WSS 保活(:8444)已下线——数据面本身有 1s 链路 Ping/Pong
	// (保 QUIC 不空闲、刷 UDP NAT、8s 看门狗判死),这条 TCP 心跳与数据面五元组不同、
	// 断了也不触发主隧道重连,功能全被覆盖;删监听减一个公网端口与流量特征。
	// 旧客户端连 :8444 失败只影响其自身保活重试循环,不影响数据面。
	realityClose, realityTCPPort, errReality := startRealityVPNListener(&cfg, loopbackSmuxPoolRef, loopbackWSTLS)
	if errReality != nil {
		util.FatalExit(util.ClassifyListenError(errReality), logrus.Fields{"err": errReality.Error()}, "REALITY: %v", errReality)
	}
	if realityClose != nil {
		defer realityClose()
	}

	_ = hyUDPPort
	_ = realityTCPPort

	// C6_full(2026-05-22):若运维显式列出 jump_host_protected_ports,按多端口/多 proto
	// 部署 iptables 规则;否则退化为单 listen_addr TCP 端口(历史行为)。
	jumpSpecs := parseJumpHostProtectedPorts(cfg.Server.JumpHostProtectedPorts)
	if len(jumpSpecs) == 0 {
		jumpSpecs = []jumpHostPortSpec{{Proto: "tcp", Port: vpnTCPPort}}
	}
	jumpFW := newJumpHostFirewallWithSpecs(cfg.Server.JumpHostFirewall, jumpSpecs)
	defer jumpFW.Teardown()
	if cfg.Server.JumpHostFirewall {
		// 自托管 PSK 模式:从 [server].jump_host_allowed_ips 读静态名单,启动时
		// 一次性灌入 ipset;名单空 + 开启 firewall → Fatal,强迫运维做选择
		// (关掉 firewall 或填名单),避免「以为开了限制实际全网开放」陷阱。
		// ensureLoopbackIPv4Allowlist 会自动加 127.0.0.1,运维不必显式列。
		allowed := cfg.Server.JumpHostAllowedIPs
		if len(allowed) == 0 {
			util.FatalExit(util.ExitConfigSemantic, nil, "[server] 启用 jump_host_firewall 必须在 [server].jump_host_allowed_ips 提供跳板机 IPv4 名单(留空等于全网开放,这通常不是你想要的)。要么填名单,要么把 jump_host_firewall 设为 false。")
		}
		logrus.WithField("count", len(allowed)).Info("[server] 从 jump_host_allowed_ips 静态注入跳板机名单")
		jumpFW.Replace(allowed)
	}

	// 统一 graceful shutdown:收到 SIGTERM/SIGINT 后只做两件事,
	//   1) globalContextCancel()  → 让 demux / tunWriteLoop / 任何 ctx-aware goroutine 立刻退;
	//   2) vpnLn.Close()          → startVPNHTTPServer 的 Serve 返回 acceptErr → main return;
	// 不调 os.Exit,让 main return 后 LIFO defer 链按顺序撤销:
	//   hySrv.Close → jumpFW.Teardown → realityClose → keepaliveShutdown
	//   → hyPortHopCleanup → vpnLn.Close(no-op) → sharedTUN.Close → authCleanup(WAL checkpoint)
	//   → globalContextCancel(no-op)。
	// 之前 jump_host 分支用 os.Exit(0) 跳过所有 defer,导致 iptables / TUN / DB 全部不清,这里彻底修掉。
	shutdownOnce := sync.Once{}
	triggerShutdown := func(reason string) {
		shutdownOnce.Do(func() {
			logrus.Warnf("[shutdown] 触发优雅退出: %s", reason)
			// shutdown drain (Batch J):
			//   1. 先广播 LinkTypeClose 给所有 active session,让客户端 graceful 收尾,
			//      UI 上可显示「服务器维护中」而不是「突然断线」;
			//   2. 等待 shutdownDrainTimeout(默认 3s)让客户端收到 + 关 raw;
			//   3. globalContextCancel + vpnLn.Close,触发 main return + defer 链跑完整
			//      teardown(iptables 撤销 / TUN 关闭 / DB checkpoint 等)。
			//
			// 顺序很关键:必须在 globalContextCancel 之前广播,否则:
			//   - context cancel → tunDemuxToLink ctx.Done → 同一条 linkConn 上正在写 IP 包
			//     的 goroutine 退出 → linkConn 可能已被 cleanupConnection close → 广播写帧
			//     拿到 nil linkConn 或 EBADF。
			// 反过来「先广播再 cancel」:广播持 linkWrMu 串行化写,中间不会被 cancel 撕开,
			// 写完了再让 demux 退出,任何资源释放都晚于 Close 帧。
			broadcastShutdownClose(shutdownDrainTimeout)
			globalContextCancel()
			_ = vpnLn.Close()
		})
	}
	// G6: SIGHUP hot reload —— 仅对白名单字段(log.level / jump_host_allowed_ips /
	// acl_rules)真正生效;其它字段会 diff + WARN「需要重启」。详见 cmd/nanotund/reload.go。
	reload := &reloadState{
		configPath: *configPath,
		cfg:        &cfg,
		jumpFW:     jumpFW,
		store:      gw.store,
	}
	// P0-1: 启动时拉一次 ACL 快照。store 为 nil(测试场景)时函数内部走空快照分支。
	// 深扫第八轮 MED:启动装载失败改为 **fatal**,与 SIGHUP reload 的 fail-closed 对齐。
	// 旧行为(只 Warn + 数据面按 init() 空快照 default=allow 放行)意味着一次启动期 DB
	// 抖动就能让配置了 default-deny / mesh-off 的部署以「整网互通」姿态上线,且没有旧快照
	// 可保留(进程刚起)。此处 store 刚完成迁移、必然可读,再读失败即真实 DB 故障 ——
	// 直接退出,交给 systemd Restart= 重拉,绝不带着错误的 allow-all 快照服务流量。
	if n, err := reloadACLSnapshotFromStore(gw.store); err != nil {
		logrus.WithError(err).Fatal("[acl] 启动期 ACL 规则集装载失败,拒绝以默认放行姿态上线,进程退出")
	} else {
		logrus.WithField("rule_count", n).WithFields(aclSummaryForLog()).Info("[acl] 规则集已装载")
	}
	// J1(2026-05-22):cap=2 而非 1。Notify 注册了 3 个不同信号(INT/TERM/HUP),
	// 若 SIGHUP 与 SIGINT/SIGTERM 同时投递且 chan 满,Go signal 文档明确说会丢一个;
	// cap=2 让"reload 期间被强杀"这种边角场景仍能被信号处理 goroutine 看到。
	// 不必更大:连续多次 SIGTERM 的处理逻辑由 signal.Stop(见 G1)恢复默认 handler
	// 覆盖,不依赖 chan 缓冲。
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	// J2(2026-05-22):systemd Type=notify 集成。READY 必须在所有监听就绪之后发,
	// 这里时点已 OK(VPN listener / Hysteria / control socket / health 都已 startup)。
	// startSDWatchdog 在没 systemd / 没设 WatchdogSec= 时直接 no-op,不影响非 systemd 部署。
	sdNotifyReady()
	if startSDWatchdog(globalContext) {
		// 注:只在确实启用 watchdog 时才需要在 shutdown 路径上额外发 STOPPING,
		// 让 systemctl status 看到 deactivating 状态而不是「卡住几秒」。
		defer sdNotifyStopping()
	}
	go func() {
		// G1(2026-05-22):graceful shutdown 触发后 return 之前必须 signal.Stop,
		// 否则后续信号继续投递到 sigCh,而 chan cap=1 且没人 read,导致:
		//   - 运维急不可耐二次 ^C / kill -TERM 时,信号被 runtime 拦截入 sigCh
		//     但 default handler 已被 Notify 覆盖,**第二次 SIGTERM 看起来无效**;
		//   - drain 流程卡(比如某个 hy2 conn deadline 未到),用户只能 SIGKILL
		//     失去 LIFO defer 链 → iptables / TUN 规则残留。
		// signal.Stop 让默认 handler 恢复:第二次 SIGTERM 走默认动作直接杀进程,
		// 这是用户主动选择"强杀代价我接",符合最小惊讶原则。
		defer signal.Stop(sigCh)
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				logrus.Info("[reload] 收到 SIGHUP,开始 hot reload")
				_, _ = applyConfigReload(reload, loadConfig)
			default:
				triggerShutdown(fmt.Sprintf("收到信号 %v", sig))
				return
			}
		}
	}()
	if hySrv != nil {
		defer func() { _ = hySrv.Close() }()
		// P1-6: Hysteria Serve 用 safeGlobalGoroutine 包,panic 时触发 graceful
		// shutdown(走 LIFO defer:撤 iptables / 关 TUN / DB checkpoint)而不是裸
		// crash。Hysteria 库 panic 历史并不多,但走统一 wrapper 让所有 Serve
		// 路径行为一致。
		go safeGlobalGoroutine("hysteriaServe", globalContextCancel, func() {
			if err := hySrv.Serve(); err != nil {
				logrus.WithError(err).Error("Hysteria Serve 退出")
			}
		})
	}

	// G3: /health 独立 listener,默认 127.0.0.1:8081(在配置 HealthListenAddr 时生效)。
	// 留空表示不启用 health endpoint(部分极简部署不需要)。
	healthCleanup := startHealthHTTPServer(cfg.Server.HealthListenAddr, gw)
	defer healthCleanup()

	// P2-16: audit_logs prune goroutine。30 天保留 + 24h tick + 体积监控。
	// store 为 nil 时 no-op(测试场景兜底)。
	auditGCCleanup := startAuditGC(gw.store)
	defer auditGCCleanup()

	// P0-1(2026-05-22):user invalidation 扫描器。周期检查 user.disabled_at / psk_hash
	// 是否变化,主动踢已建立 session。默认 10s 扫一次,可经
	// [server].user_invalidate_interval_sec 覆盖(0 / 负数走默认)。
	userInvalidateCleanup := startUserInvalidationLoop(gw, time.Duration(gw.cfg.Server.UserInvalidateIntervalSec)*time.Second)
	defer userInvalidateCleanup()

	// P1#9(2026-05-22):lease_gc 定时回收 idle device 的 vIP。默认 30 天 idle,24h 一轮;
	// <=0 关闭定时回收(回归 admin CLI cron 模型)。
	leaseGCIdleDays := gw.cfg.Server.LeaseGCIdleDays
	if leaseGCIdleDays == 0 {
		leaseGCIdleDays = defaultLeaseGCIdleDays
	}
	leaseGCCleanup := startLeaseGCLoop(gw, leaseGCIdleDays, gw.cfg.Server.LeaseGCIntervalHours)
	defer leaseGCCleanup()

	// P1#6/7/8(2026-05-22):admin 控制面 unix socket。默认 /run/nanotun/control.sock,
	// 设 control_socket_path="off" 显式关闭。
	controlSocketCleanup := startControlSocket(gw.cfg.Server.ControlSocketPath, gw)
	defer controlSocketCleanup()

	// P2#13(2026-05-22):ACL drop 聚合 audit。每 60s flush 一批 bucket 到 audit_logs,
	// 不阻塞 per-packet 路径。
	aclDropAuditCleanup := startACLDropAuditFlusher(gw, 0)
	defer aclDropAuditCleanup()

	// P2#11(2026-05-22):Magic DNS。仅在 [server].magic_dns.enabled = true 时启动;
	// listen 在 TUN gateway IP 上(从 sharedTUNGateway CIDR 解出地址)。
	magicDNSCleanup := startMagicDNS(gw, gatewayAddrFromCIDR(sharedTUNGateway))
	defer magicDNSCleanup()

	// subnet route(SR-M1):数据面已接入。启动时构建一次「已批准子网路由表」(per-packet 最长前缀匹配的数据源);
	// 之后 admin 改路由经 control-socket /reload?what=routes 重建,连接上下线无需重建(在线性由 per-packet
	// lookupActiveConnByDevice 实时解析)。rebuild 内部会 INFO 打印当前生效路由条数。
	rebuildSubnetRouteTable(context.Background())

	// FRP 式反向端口转发：加载 enabled 映射、在公网端口起 TCP 监听，转发到 mesh 节点自身端口 / LAN 后设备。
	// admin 改映射经 control-socket /reload?what=portforward 实时启停。TUN 设备名供 LAN 目标装主机路由用。
	tunDevName := ""
	if sharedTUN != nil {
		if n, nerr := sharedTUN.Name(); nerr == nil {
			tunDevName = n
		}
	}
	portForwardCleanup := startPortForwardManager(gw, tunDevName)
	defer portForwardCleanup()

	acceptErr := make(chan error, 1)
	vpnHTTPShutdown := startVPNHTTPServer(vpnLn, wsPath, gw, muxEnabled, muxOptsForAccept, acceptErr)
	// I10: Serve 返回(因 Listener.Close)之后,显式 srv.Shutdown 给 HTTP/1.1 idle
	// keep-alive 连接一个 5s graceful close 窗口;WebSocket 升级后的连接由各自
	// cleanupConnection 路径处理。
	defer vpnHTTPShutdown()

	errAcc := <-acceptErr
	logrus.WithError(errAcc).Warn("VPN HTTP 服务退出")
}

// tunReadLoop 从共享 TUN 批量读包，投递池化包到 tunReadChan；消费者用完后归还 Buf 与 TunPacket
//
// P2-17: 退出有两条路径
//  1. dev.Read 错误返回(主路径:shutdown 时 main 会 dev.Close() 让 Read 立刻报错);
//  2. globalContext.Done() —— 兜底,防止极端场景下 dev.Close 异常 / 内核延迟回包
//     导致 Read 阻塞数秒。这里用 goroutine 监听 ctx,触发时主动 dev.Close,与 main
//     的 SIGTERM 路径双重保险。
func tunReadLoop(dev tun.Device) {
	batchSize := dev.BatchSize()
	if batchSize <= 0 {
		batchSize = 1
	}
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := 0; i < batchSize; i++ {
		bufs[i] = tunReadBufPool.Get().([]byte)
	}
	defer func() {
		for i := 0; i < batchSize; i++ {
			if bufs[i] != nil {
				tunReadBufPool.Put(bufs[i])
			}
		}
	}()
	// 监听 ctx;触发时关 dev 让 Read 立刻返回。done 通道防止 watchdog 在
	// Read 自然退出后还闲挂(避免重复关 dev 引起的 EBADF 告警噪声)。
	done := make(chan struct{})
	defer close(done)
	if globalContext != nil {
		go safeGoroutine("tunReadLoop/ctxWatch", func() {
			select {
			case <-globalContext.Done():
				_ = dev.Close()
			case <-done:
			}
		})
	}
	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			// ctx 已取消时 dev.Close 触发的 Read err 是预期路径,Debug 即可。
			if globalContext != nil && globalContext.Err() != nil {
				logrus.WithError(err).Debug("TUN 读循环退出(ctx cancelled)")
			} else {
				logrus.WithError(err).Warn("TUN 读循环退出")
			}
			return
		}
		for i := 0; i < n; i++ {
			pkt := tunPacketPool.Get().(*util.TunPacket)
			pkt.Buf = bufs[i]
			pkt.N = sizes[i]
			select {
			case tunReadChan <- pkt:
			default:
				logrus.Warn("TUN 读循环通道已满")
				tunReadBufPool.Put(pkt.Buf)
				tunPacketPool.Put(pkt)
			}
			bufs[i] = tunReadBufPool.Get().([]byte)
		}
	}
}

// drainAndCloseTunChan 关闭 channel 并排空未读的池化包、归还 pool，避免泄漏
func drainAndCloseTunChan(ch chan *util.TunPacket) {
	close(ch)
	for pkt := range ch {
		if pkt != nil {
			tunReadBufPool.Put(pkt.Buf)
			tunPacketPool.Put(pkt)
		}
	}
}

// tunWriteLoop 单 goroutine 串行批量写 TUN，避免多 goroutine 并发写同一 fd，减少 syscall。
// Linux 下 wireguard/tun 使用 IFF_VNET_HDR，Write 要求 offset >= virtioNetHdrLen，故在每包前预留 virtio 头再写。
func tunWriteLoop(dev tun.Device) {
	batchSize := dev.BatchSize()
	if batchSize <= 0 {
		batchSize = 1
	}
	writeBufs := make([][]byte, 0, batchSize)
	fullBufs := make([][]byte, 0, batchSize) // 用于归还 pool 的完整 buffer
	for {
		select {
		case <-globalContext.Done():
			return
		case pkt, ok := <-tunWriteChan:
			if !ok {
				return
			}
			writeBufs = writeBufs[:0]
			fullBufs = fullBufs[:0]
			// 第一包：拷贝到带 virtio 头空间的 buffer，拷贝完立即归还 pkt
			{
				buf := tunWriteBufPool.Get().([]byte)
				n := copy(buf[virtioNetHdrLen:], pkt)
				tunPktBufPool.Put(pkt[:cap(pkt)])
				writeBufs = append(writeBufs, buf[:virtioNetHdrLen+n])
				fullBufs = append(fullBufs, buf)
			}
			for len(writeBufs) < batchSize {
				select {
				case pkt2, ok2 := <-tunWriteChan:
					if !ok2 {
						goto flush
					}
					buf := tunWriteBufPool.Get().([]byte)
					n := copy(buf[virtioNetHdrLen:], pkt2)
					tunPktBufPool.Put(pkt2[:cap(pkt2)])
					writeBufs = append(writeBufs, buf[:virtioNetHdrLen+n])
					fullBufs = append(fullBufs, buf)
				default:
					goto flush
				}
			}
		flush:
			if len(writeBufs) > 0 {
				if _, err := dev.Write(writeBufs, virtioNetHdrLen); err != nil {
					logrus.WithError(err).Debug("TUN 写入失败")
				}
				for _, b := range fullBufs {
					tunWriteBufPool.Put(b)
				}
			}
		}
	}
}

// tunDemuxWriteDeadline 是 tunDemuxToLink 每次 WriteLinkFrame 的最大耗时上限。
//
// C3(2026-05-22):没有这个 deadline,客户端 TCP 接收窗口被填满 / NIC dropped /
// QUIC path stalled 时,内核 write 会无限阻塞,goroutine 持有 linkWrMu 一直不释放,
// 任何 kick / broadcast Close / takeover 路径都会跟着卡。5s 是「正常 GFW 抖动也能
// 写完一帧」与「不让单个慢客户端阻塞 kick 5s+」的折中。慢于此值的客户端我们直接断,
// 上层 cleanupConnection 会释放 vIP / TunChan,后续重连用新 link 重新协商。
const tunDemuxWriteDeadline = 5 * time.Second

// deadliner 是底层 conn 暴露 SetWriteDeadline 的最小接口。
// rateLimitedConn 在 C3 之后实现该方法,因此 c.linkConn 类型断言一定 ok=true;
// 兼容性兜底:若上层换其它 wrapper 没实现,这里 ok=false 自动退化为无截止时间(老行为),
// 不会破坏功能。
type deadliner interface {
	SetWriteDeadline(t time.Time) error
}

func tunDemuxToLink(ch <-chan *util.TunPacket, w io.Writer, mu *sync.Mutex, ctx context.Context) {
	// 一次性把 w 转成 deadliner;不能就退化为无截止时间。
	dl, _ := w.(deadliner)

	// C3:ctx 中断 watchdog。
	// 即便 per-write deadline 已经把单次写控制在 5s 内,我们仍想让 globalContextCancel
	// 在 SIGTERM / shutdown drain 路径上瞬时中断;否则一次 write 已经开始后,最坏要等到
	// 5s 才能让本 goroutine 退出,延后整个 LIFO defer 链(TUN close / iptables sweep /
	// DB checkpoint)。
	//
	// 实现:ctx.Done 时 SetWriteDeadline(过去时间)强制 in-flight write 返回 EAGAIN/Timeout,
	// 上层 for{} 立刻命中 ctx.Done 分支退出。done 通道防止 watchdog 在 demux 自然退出后
	// 仍调用 SetWriteDeadline(竞态:link 已 close,set 在 closed fd 上无害但徒费 syscall)。
	done := make(chan struct{})
	defer close(done)
	if dl != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = dl.SetWriteDeadline(time.Unix(1, 0))
			case <-done:
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-ch:
			if !ok {
				return
			}
			if pkt == nil {
				continue
			}
			body := pkt.Buf[:pkt.N]
			mu.Lock()
			if dl != nil {
				_ = dl.SetWriteDeadline(time.Now().Add(tunDemuxWriteDeadline))
			}
			err := util.WriteLinkFrame(w, util.LinkTypeIPPacket, body)
			if dl != nil {
				// 写完清掉 deadline,避免下次写之间(channel recv 阻塞期)旧 deadline 提前到期
				// 把下一次写直接判超时。
				_ = dl.SetWriteDeadline(time.Time{})
			}
			mu.Unlock()
			tunReadBufPool.Put(pkt.Buf)
			tunPacketPool.Put(pkt)
			if err != nil {
				return
			}
		}
	}
}

// runLinkTunnel 在单条 TCP 连接上双向转发：TunChan→类型5；类型5→tunWriteChan
//
// 退出（任一 readLoop 退出路径）时 close(c.tunnelDone)，供 takeover 路径
// `<-oldConn.tunnelDone` 同步等待老链路完全释放 TunChan 后再启动新 demux。
// 当 c.tunnelDone 为 nil（理论不应发生）时跳过 close，保持向后兼容。
func runLinkTunnel(ctx context.Context, rw io.ReadWriteCloser, c *Connection, remote string) {
	tunCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		if c.tunnelDone != nil {
			// 用 recover 防御「未初始化的 conn 重复进入」(理论不会发生) 引发 panic
			defer func() { _ = recover() }()
			close(c.tunnelDone)
		}
	}()
	var wg sync.WaitGroup
	// S1(2026-05-26):走 safeClientIPs() 助手 — 此时调用方(handleVPNLink /
	// handleTakeoverLogin)已经 Store 完成,Load 必返非 nil;但走 helper 风格统一,
	// 万一未来路径调换也安全。
	for _, a := range c.safeClientIPs() {
		if a.TunChan == nil {
			continue
		}
		ch := a.TunChan
		wg.Add(1)
		go func() {
			defer wg.Done()
			// per-vIP demux:panic 不应该拖垮整进程,只 log + 让本连接挂掉。
			// `cleanupConnection` 仍会跑(由 handleVPNLink 的 defer 兜底),释放 vIP / TunChan。
			safeGoroutine("tunDemuxToLink/"+remote, func() {
				tunDemuxToLink(ch, rw, &c.linkWrMu, tunCtx)
			})
		}()
	}
	// exit-node 选择器:exit_allowed 客户端连上后推一帧「当前可选出口列表」(初始)。best-effort,放 goroutine
	// 不阻塞 readLoop;非 exit_allowed 在内部直接跳过。之后出口上/下线由 broadcastExitsList 增量推。
	if c.exitAllowed {
		// 用 context.Background()(非可取消的 tunCtx):buildExitsList 自带 5s 超时,初始推送不应被「连上瞬间又断开」
		// 取消 tunCtx 而漏推(深扫 #5);写失败(链路已关)在 sendExitsListTo 内吞掉,无副作用。与 broadcastExitsList 同口径。
		go pushInitialExitsList(context.Background(), c)
	}
	// subnet route(SR-M3):给**所有**连上的客户端推一帧当前可用子网路由列表(任意用户都可能要访问内网资源,不限
	// exit_allowed;细粒度授权留 SR-M4 ACL)。context.Background() 同 exits——不被连上瞬断的 tunCtx 取消而漏推。
	go pushInitialRoutesList(context.Background(), c)

	// G_wss_ping:server→client 应用层 Ping/Pong 主动心跳。
	// 仅在 [server].data_plane_ping_interval > 0 时启动。详见 wss_keepalive.go。
	// DataPlanePingInterval 现在是 config.Duration(TOML 友好包装),需显式转回 time.Duration。
	if gw := gatewayInstance; gw != nil && gw.cfg != nil {
		interval := time.Duration(gw.cfg.Server.DataPlanePingInterval)
		miss := gw.cfg.Server.DataPlanePingMissThreshold
		if interval > 0 {
			if miss <= 0 {
				miss = defaultDataPlanePingMissThreshold
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				safeGoroutine("wssDataPlaneKeepalive/"+remote, func() {
					startWSSDataPlaneKeepalive(tunCtx, c, rw, remote, interval, miss)
				})
			}()
		}
	}
readLoop:
	for {
		typ, payload, err := util.ReadLinkFrame(rw)
		if err != nil {
			if err != io.EOF {
				logrus.WithField("remote", remote).WithError(err).Debug("链路读结束")
			}
			break
		}
		switch typ {
		case util.LinkTypeIPPacket:
			if !util.ValidIPPacket(payload) {
				continue
			}
			// exit-node DNS 地理修正(direction 1)回程截获:magic resolver 经出口转发的公网 DNS 查询,其响应
			// (出口→server,src=:53,dst=server 网关:关联端口)在此截获、交回等待的 resolver goroutine,不写 TUN
			// (避免内核 rp_filter/conntrack 吞掉这条无出向记录的回包)。零 in-flight 时仅一次 atomic load。见 magic_dns_exit.go。
			if interceptExitDNSResponseIfPending(payload) {
				continue
			}
			// subnet route(SR-M1):dst 命中某「已批准的内网网段」→ 投递给该网段的宣告方会话,由其本机转发进 LAN
			// (而非走 server 自出口把内网包误发公网)。优先级:vIP(mesh) > 具体子网路由 > 0/0 出口 > server
			// (vIP 优先在 forwardPacketToSubnetRoute 内排除)。**放在 user-level 出口闸之前**:访问已批准内网网段
			// 属私有组网连通,不应被「公网出口权限」(exit_allowed)闸拦。细粒度 per-user 子网 ACL 见 SR-M4;当前由
			// admin 审批该网段作为粗粒度授权(未批准的网段不进表、不转发)。返回 true = 已处理,本包到此为止。
			if forwardPacketToSubnetRoute(c, payload) {
				continue
			}
			// P0-4(2026-05-22):user-level 出口闸 fast-path。
			// 当 user.exit_allowed=false(c.exitAllowed=false)且 dst 不属于任何 vIP 时,
			// 直接丢包。本检查发生在 ACL enforcement 之前,避免 ACL 没配 exit 规则
			// 也能用 VPN 出公网(企业级常见默认 deny 出口语义)。
			if c.exitDeniedForPacket(payload) {
				exitGateDropCount.Add(1)
				// P2#13:把 user-level exit-gate drop 也喂给 acl-drop-audit 聚合,
				// 让 audit list 能区分「ACL 规则丢」与「user.exit_allowed 闸丢」。
				if t, ok := parsePacketTuple(payload); ok {
					recordACLDrop("exit_gate", parseUserIDStr(c.userID), 0, t.proto, t.dstPort)
				}
				continue
			}
			// P0-1: ACL 数据面 enforcement。fast-path:无规则 / src==dst / dst 非 vIP 时
			// 内部直接放行,只多两次 map lookup;有规则且命中 deny 时丢包,不写 tunWriteChan。
			// userID 是 store.users.id(int64),从 c.userID 反解("u<id>");解析失败按
			// 「无 user 上下文」处理(测试用例 / 客户端 connIDStr 异常等),不做 enforcement。
			if aclDropPacketDirected(parseUserIDStr(c.userID), payload) {
				continue
			}
			// exit-node(M2):本会话若选定了出口节点，且此包是公网出口流量(dst 非 vIP)，
			// 转发给出口节点会话由其本机 NAT 出公网，而非走 server 自出口。
			// 返回 true = 已由 exit 路径处理(投递/丢弃)，本包到此为止;false = 回退 server 自出口。
			if forwardPacketToExitNode(c, payload) {
				continue
			}
			// server 自出口(未选 peer 出口)兜底:server 本机无 v6 时,对公网 v6 目的回 ICMPv6 unreachable
			// 让使用方秒回落 v4,而非写进 server TUN 在内核黑洞(与 peer 出口的 v6 兜底同理,补 egress==0 路径)。
			if serverSelfEgressV6FastFail(c, payload) {
				continue
			}
			pkt := tunPktBufPool.Get().([]byte)
			n := copy(pkt, payload)
			select {
			case tunWriteChan <- pkt[:n]:
			default:
				tunWriteDropCount.Add(1)
				tunPktBufPool.Put(pkt)
			}
		case util.LinkTypeClose:
			cancel()
			_ = rw.Close()
			wg.Wait()
			return
		case util.LinkTypePing:
			logrus.WithFields(logrus.Fields{"remote": remote, "payload_len": len(payload)}).Info("收到链路 Ping，回复 Pong")
			c.linkWrMu.Lock()
			werr := util.WriteLinkFrame(rw, util.LinkTypePong, payload)
			c.linkWrMu.Unlock()
			if werr != nil {
				break readLoop
			}
		case util.LinkTypePong:
			// G_wss_ping:server-side keepalive 路径下需要记最近 Pong 时间,
			// 让 wssKeepaliveLoop 判活;legacy 路径(client→server Ping)的 Pong 也走这里,
			// 顺手记录无副作用(只是 lastPongAtNano 提前刷新)。
			c.lastPongAtNano.Store(time.Now().UnixNano())
		case util.LinkTypeRouteAdvertise:
			// P2#12 控制面:客户端上报本地能 forward 的子网。
			// 处理函数 best-effort,任何错误都只 log,不影响 IP 帧通路。
			handleRouteAdvertiseFrame(ctx, c, payload)
		case util.LinkTypeEgressSelect:
			// exit-node 控制面:使用方选择公网出口(server 自出口 / 某出口节点)。
			// best-effort:仅设置本会话 egressDeviceID + 回 Ack,不影响 IP 帧通路。
			handleEgressSelectFrame(ctx, c, payload)
		default:
			logrus.WithFields(logrus.Fields{"remote": remote, "type": typ}).Trace("链路上忽略非 IP 类型帧")
		}
	}
	cancel()
	_ = rw.Close()
	wg.Wait()
}

// openTUN 创建 TUN 设备并配置 IPv4 网关地址；若 gatewayCIDRv6 非空则同时配置 IPv6 地址
func openTUN(name, gatewayCIDR, gatewayCIDRv6 string) (tun.Device, error) {
	const defaultMTU = 1500
	dev, err := tun.CreateTUN(name, defaultMTU)
	if err != nil {
		logrus.WithError(err).WithField("tun", name).Warn("打开 TUN 失败")
		return nil, err
	}
	devName := name
	if n, errName := dev.Name(); errName == nil && n != "" {
		devName = n
	}
	// 配置 IPv4 地址（可选）
	if gatewayCIDR != "" {
		if err := exec.Command("ip", "addr", "add", gatewayCIDR, "dev", devName).Run(); err != nil {
			logrus.WithError(err).WithField("tun", devName).WithField("ip", gatewayCIDR).Debug("配置 IPv4 失败或已存在")
		} else {
			logrus.WithField("tun", devName).WithField("ip", gatewayCIDR).Info("TUN 已配置 IPv4")
		}
	}
	// 配置 IPv6 地址（可选）
	if gatewayCIDRv6 != "" {
		if err := exec.Command("ip", "-6", "addr", "add", gatewayCIDRv6, "dev", devName).Run(); err != nil {
			logrus.WithError(err).WithField("tun", devName).WithField("ip", gatewayCIDRv6).Debug("配置 IPv6 失败或已存在")
		} else {
			logrus.WithField("tun", devName).WithField("ip", gatewayCIDRv6).Info("TUN 已配置 IPv6")
		}
	}
	if err := exec.Command("ip", "link", "set", "dev", devName, "up").Run(); err != nil {
		logrus.WithError(err).WithField("tun", devName).Debug("ip link set up 失败（可忽略）")
	}
	return dev, nil
}

// localIPsForVPNAllocation 从 TCP 对端地址推导 IPv4 列表，用于决定本连接要分配几条 IPv4 虚拟地址（每条连接通常 1 条）。
//
// 命名提示:此处 "localIPs" 指 server 视角下「这条 TCP 连接的对端公网/内网 IPv4」,**与已废除的
// client→server `local_ips` 登录字段无关**(client 端字段 2026-05-24 全链路移除,server 端 LoginReq
// 历史上也从未声明该字段,wire 上不曾出现)。读代码时不要把这里的局部变量误判为「client 上送 IP 残留」。
func localIPsForVPNAllocation(c net.Conn) []string {
	addr := c.RemoteAddr()
	if addr == nil {
		return []string{""}
	}
	s := addr.String()
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []string{v4.String()}
		}
		return []string{ip.String()}
	}
	return []string{host}
}

// minPositiveBPS 取 platform 与 user 两个限速值的「更严」组合,语义:
//   - 两个都 > 0 → 取较小;
//   - 一个 > 0 → 取那个;
//   - 都 <= 0 → 返回 0(=「不限」)。
//
// P0-4 把 user.bandwidth_*_bps 接入限速,设计上不能让 user 写一个 1000Mbps
// "绕开" platform 全局 50Mbps 上限,所以是「叠加 min」而非「替换」。
func minPositiveBPS(platformBPS int, userBPS int64) int {
	uv := int(userBPS)
	if userBPS > int64(^uint(0)>>1) {
		uv = int(^uint(0) >> 1)
	}
	if uv <= 0 {
		return platformBPS
	}
	if platformBPS <= 0 {
		return uv
	}
	if uv < platformBPS {
		return uv
	}
	return platformBPS
}

// linkRatesForPlatform 先取全局 [server]/[kcp] 限速，再按登录 platform（小写）用 rate_limit_by_platform 中 >0 的项覆盖对应方向。
//
// 0012:gw == nil 或 gw.cfg == nil 时返回 0/0(= "toml 层不强制"),避免单测 / 还没装配
// 完成的 gatewayState 走数据面读 cfg 时 panic。生产路径 main.go 起 server 时一定有 cfg。
func linkRatesForPlatform(gw *gatewayState, platform string) (upload, download int) {
	if gw == nil || gw.cfg == nil {
		return 0, 0
	}
	upload = gw.cfg.Server.UploadRate
	if upload == 0 {
		upload = gw.cfg.KCP.UploadRate
	}
	download = gw.cfg.Server.DownloadRate
	if download == 0 {
		download = gw.cfg.KCP.DownloadRate
	}
	p := strings.ToLower(strings.TrimSpace(platform))
	if p == "" {
		return upload, download
	}
	// SIGHUP 可整体替换 RateLimitByPlatform 指针(见 reload.go);持读锁避免读到
	// 撕裂的 map header。快照拿到条目后即释放锁,后续只读栈上副本。
	hotReloadCfgMu.RLock()
	m := gw.cfg.Server.RateLimitByPlatform
	pl, ok := m[p]
	hotReloadCfgMu.RUnlock()
	if m == nil || !ok {
		return upload, download
	}
	if pl.UploadRate > 0 {
		upload = pl.UploadRate
	}
	if pl.DownloadRate > 0 {
		download = pl.DownloadRate
	}
	return upload, download
}

// effectiveLinkRates(0011, 2026-05-23):本会话最终生效的链路上下行限速(字节/秒)。
//
// 四级回退,取 min(0=+∞,任一层不限不影响其它层的硬 cap):
//
//  1. device 级 (devices.rate_*_bps,登录时落到 Connection.deviceRate*BPS)
//  2. 全局默认 (app_settings.rate_default_*_bps,web/CLI 热改)
//  3. toml [server].rate_limit_by_platform[<p>].* > [server].* > [kcp].*(本就是 linkRatesForPlatform 的语义)
//  4. user 级 (users.bandwidth_*_bps,登录时落到 Connection.bw*BPS;
//     历史已有 minPositiveBPS 接入,本函数仅返回 1-3 层,user 维度仍在 caller 与之取 min)
//
// 选择「都取 min」而不是「某一层完全覆盖」:
//   - 防止管理员误操作:把 app_settings 默认改大 / 清零,不会把 device 上更严的 cap 放宽;
//   - 与现有 user 级 BW(同样取 min)语义一致,运维心智简单 ——「任何地方写过更严的值就以更严的为准」。
//
// settingsDefault 通常每次调用都查 SQLite(读极轻,~us 级);如果未来发现频繁登录场景下成
// 为热点,可以在 server 启动时缓存 + control sock refresh 时 invalidate。当前规模(千用户级)
// 不优化。
//
// 注意:caller(handleVPNLink / handleTakeoverLogin)仍负责把 user-level bw 用
// minPositiveBPS 叠加上去 —— 本函数不查 users 表,deviceID / settings 已经够覆盖
// 本次新增需求,user 维度的代码保持原样不动。
func effectiveLinkRates(
	gw *gatewayState,
	platform string,
	deviceUpBPS, deviceDownBPS int64,
	defaults storeRateDefaultsView,
) (upload, download int) {
	upload, download = linkRatesForPlatform(gw, platform)
	if defaults.UploadBPS > 0 {
		upload = minPositiveInt(upload, int(defaults.UploadBPS))
	}
	if defaults.DownloadBPS > 0 {
		download = minPositiveInt(download, int(defaults.DownloadBPS))
	}
	if deviceUpBPS > 0 {
		upload = minPositiveInt(upload, int(deviceUpBPS))
	}
	if deviceDownBPS > 0 {
		download = minPositiveInt(download, int(deviceDownBPS))
	}
	return upload, download
}

// storeRateDefaultsView:effectiveLinkRates 不直接依赖 store.RateDefaults,避免在
// server 包顶层多一处 store 导入(本文件已经经常需要 noimport mock 测试)。
// 调用方把 store.GetRateDefaults 的结果手工灌进来即可。
type storeRateDefaultsView struct {
	UploadBPS   int64
	DownloadBPS int64
	// BurstBytes 0012:rate.Limiter 桶容量,0 = 沿用代码 default。
	BurstBytes int64
}

// effectiveBurst(0012, 2026-05-23 / N11 upper bound 2026-05-24):
// rate.Limiter 的 burst(token bucket 容量)。
//
//   - 入参 settingsBurst <= 0:沿用代码 default 64 KiB(历史值,hy2/REALITY 现网经验);
//   - 入参 < 4 KiB:夹到 4 KiB(实测过小时 limiter wait 抖动剧烈,影响吞吐);
//   - 入参 > 16 MiB:夹到 16 MiB(N11 安全 hardening,防止运维误输 1 GiB 让 limiter
//     累成超大 token bucket → 单条 conn 突发 1 GiB 无 cap;16 MiB ≈ 100ms 缓冲 1Gbps,
//     再大业务上消耗不掉,纯属攻击面);
//   - 入参 [4 KiB, 16 MiB]:原样使用。
//
// 不再用 const burstBytes;登录 / takeover / /rate/refresh 三条路径都从这里算。
const (
	defaultRateBurstBytes = 64 * 1024
	minRateBurstBytes     = 4 * 1024
	maxRateBurstBytes     = 16 * 1024 * 1024
)

func effectiveBurst(settingsBurst int64) int {
	if settingsBurst <= 0 {
		return defaultRateBurstBytes
	}
	if settingsBurst < minRateBurstBytes {
		return minRateBurstBytes
	}
	if settingsBurst > maxRateBurstBytes {
		return maxRateBurstBytes
	}
	return int(settingsBurst)
}

// minPositiveInt:0 / 负数当 +∞,选更严的非零值。与 minPositiveBPS(int64 版本)同义。
// 把 effectiveLinkRates 的 int 数学单独抽出来,方便单测验证「0 不影响其它层」。
func minPositiveInt(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func writeLinkLoginResp(w io.Writer, code int, message, userID string) error {
	body, err := util.MarshalLoginRespJSON(code, message, userID)
	if err != nil {
		return err
	}
	return util.WriteLinkFrame(w, util.LinkTypeLoginResp, body)
}

// writeCloseAndReturn 写一帧 LinkTypeClose 给客户端,带 code + reason,然后调用方
// (handleVPNLink 等)直接 return 让 defer raw.Close() 关掉连接。
//
// 用于 PoW 校验失败 / 状态机违规 / 限速等场景。
//
// **反指纹设计(P1, 2026-05-24 round-2 scan)**:
// PoW 路径**禁止**把内部失败分支(rate-limit / global-rate-limit / protocol /
// pow-failed)写到 reason 字段 — 那会让 attacker 抓 wire 后精确锁定自己处在
// 哪个防御层下,调整攻击策略(降速绕 powIPLimiter / 等 global limit 退潮 /
// 修协议结构)。
// 对外只暴露 code(412/500),内部细节走 audit_logs.detail 字段 + log Warn,
// 运维 + IR 都能查,但 attacker 在 wire 上看到的是同一个 close 帧。
//
// 因此 PoW path 调用方应当传 reason=""(目前规则是 PoW 全空,non-PoW 例外:
// user_invalidate / shutdown_drain 是给已登录用户的友好文案,allowed by design)。
func writeCloseAndReturn(w io.Writer, code int, reason string) {
	body, errM := util.MarshalCloseJSON(code, reason)
	if errM != nil {
		// 序列化 CloseMsg 不应失败,极端情况下 silently drop(defer raw.Close 仍兜底)。
		return
	}
	_ = util.WriteLinkFrame(w, util.LinkTypeClose, body)
}

// writeLinkLoginRespFull 与 writeLinkLoginResp 一致，但额外携带 sessionID（== connIDStr）与 takeoverSecret，
// primary 登录成功路径专用；客户端缓存后将来发起 takeover login 时回填。
func writeLinkLoginRespFull(w io.Writer, code int, message, userID, sessionID, takeoverSecret string) error {
	body, err := util.MarshalLoginRespFullJSON(code, message, userID, sessionID, takeoverSecret)
	if err != nil {
		return err
	}
	return util.WriteLinkFrame(w, util.LinkTypeLoginResp, body)
}

// generateTakeoverSecret 返回 32 字节随机 nonce 的 hex 字符串（64 字符）。
//
// 用 crypto/rand,与 util.GenerateID 同强度。**crypto/rand 失败时返回空串**:
// 调用方必须检查并把当次 takeover 路径直接拒掉。
//
// 老实现这里有个 "fallback 到时间戳 hex" 的分支 —— 但时间戳是可猜测的，回退路径会
// 把 takeover secret 的强度从 256 bit 砸到 ~30 bit (UnixNano 抖动)，attacker 拿到
// session_id (协议公开) 后可以暴力枚举 secret。crypto/rand 失败本身就是「机器熵
// 池坏了」的严重信号，更紧迫的事情是别让任何加密原语继续跑（其它路径也已各自处理）。
// evictOldestSessionsLocked 在 connIDMapMu 持写锁的条件下扫一遍同 userID 的活跃
// 会话,如果总数(含刚刚加入的 newConn)超过 max,**按 createdAt 从老到新**返回需要
// 淘汰的 Connection 列表。调用方在锁外异步关闭它们的 linkConn 触发 cleanup。
//
// 不计入计数的:
//   - takenOver==true 的老 conn(已经被 takeover 替换,等待 cleanup,逻辑上不占资源);
//   - superseded==true 的老 conn(server 已判定「即将 close」:同 device 重登互踢 /
//     admin kick / PSK 失效踢线,异步 cleanup 未完成)。不排除会导致垂死会话占配额、
//     按 createdAt「踢最老」误伤无辜活会话 —— 典型:cap=2 时 B(老,健康)+ A(同
//     device 重登被 supersede),新 conn C 一进来把 B 踢了,用户凭空少一条会话。
//     为此登录路径必须**先**给 supersede 受害者置 superseded,**再**调本函数;
//   - newConn 自身(它本来就是新加入的)。
//
// 返回空切片表示无需淘汰。出于性能考虑,该函数只在「同一 userID 注册到 connIDMap
// 时」调用一次,O(N) of map size,生产环境 N 通常 < 1000,可接受;真要 N 上万再
// 上 by-user index。
func evictOldestSessionsLocked(gw *gatewayState, newConn *Connection) []*Connection {
	if newConn == nil || newConn.userID == "" {
		return nil
	}
	max := effectiveMaxSessions(gw, newConn)
	if max <= 0 {
		return nil // 不限制(默认)
	}
	type entry struct {
		c  *Connection
		at time.Time
	}
	// P3-a:走 by-user 索引(N_user 通常 ≤ max),而非 O(N_total) 扫全表。
	sub := connByUser[newConn.userID]
	all := make([]entry, 0, len(sub))
	for _, c := range sub {
		if c == nil || c == newConn {
			continue
		}
		if c.takenOver.Load() || c.superseded.Load() {
			continue
		}
		all = append(all, entry{c: c, at: c.createdAt})
	}
	// 总数(含 newConn)
	total := len(all) + 1
	if total <= max {
		return nil
	}
	// 按 createdAt 升序排序,踢最老
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j].at.Before(all[j-1].at); j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	evictN := total - max
	out := make([]*Connection, 0, evictN)
	for i := 0; i < evictN && i < len(all); i++ {
		out = append(out, all[i].c)
	}
	return out
}

// effectiveMaxSessions 计算对本次新登录生效的并发会话上限(0021 两级叠加):
//
//	账号级 users.max_sessions(登录时定格在 conn.maxSessionsAtLogin):
//	   >0 → 直接用它(覆盖全局,可更松或更紧);
//	   -1 → 该账号显式不限,返回 0;
//	    0 → 跟随全局 [server].max_sessions_per_user:
//	         >0 → 用全局值;<=0(缺省)→ 不限制。
//
// 返回 <=0 表示不限制。注意全局缺省语义 2026-07-20 起从「0 = 5」改为「0 = 不限」:
// 要限流的部署显式配数字,老部署没配这个键的行为变化(5 → 不限)是本次需求的刻意选择。
func effectiveMaxSessions(gw *gatewayState, newConn *Connection) int {
	if v := newConn.maxSessionsAtLogin; v > 0 {
		return v
	} else if v < 0 {
		return 0
	}
	if gw != nil && gw.cfg != nil {
		// SIGHUP 可原地热更该字段(见 reload.go);持读锁避免与 reload 写竞争。
		hotReloadCfgMu.RLock()
		v := gw.cfg.Server.MaxSessionsPerUser
		hotReloadCfgMu.RUnlock()
		if v > 0 {
			return v
		}
	}
	return 0
}

func generateTakeoverSecret() string {
	var b [32]byte
	if _, err := crand.Read(b[:]); err != nil {
		logrus.WithError(err).Error("[takeover] crypto/rand 不可用,放弃生成 secret —— 当次登录将不下发 takeover_secret,客户端无法接管")
		return ""
	}
	return hex.EncodeToString(b[:])
}

// cleanupConnection 在 handleVPNLink 退出时清理本 conn 状态。
//
// 行为分两路：
//  1. !c.takenOver：自己没被新链路接管 → 完整释放虚拟 IP、TunChan、Conntrack；
//  2. c.takenOver：被同账号新链路接管 → connIDStr / clientIPs / TunChan 已经过户给新 conn；
//     仅删除 connections[c.connID]（这是本 conn 自己分配的 nanotun 内部 conv_id），其他全部跳过。
//
// 两路共同：connIDMap[c.connIDStr] 用 cur == c 守卫删除（接管路径下 cur 已被新 conn 覆盖，不会误删）。
//
// H2(B3 / P0): 必须在持有 takeoverMu 的情况下读 c.takenOver 并执行清理。
//
// 历史问题:如果 cleanupConnection 与 handleTakeoverLogin 并发跑,会出现以下窗口:
//
//	handleTakeoverLogin: inheritedIPs := copy(oldConn.clientIPs)   // 拷贝完
//	cleanupConnection : c.takenOver.Load() == false                // 此时还没 set
//	cleanupConnection : delete(clientIPUsed, vip)  + drainAndClose // 释放掉了
//	handleTakeoverLogin: oldConn.takenOver.Store(true) + ...       // 太迟
//	→ newConn 继续使用 inheritedIPs(里面是「服务器已认为可分配」的 vIP)
//	→ 下一次登录 alloc 路径会把这些 vIP 又分给别人
//	→ 同一个 vIP 同时给两台 device 用,路由黑洞 / IP 冲突。
//
// 现在 cleanupConnection 进入时先 Lock takeoverMu:
//   - 若 handleTakeoverLogin 还在执行,Lock 会阻塞 → 等它执行完(包括 takenOver.Store(true)
//   - close oldConn.linkConn);锁释放后这边读到 takenOver==true,走第 2 路径,跳过 vIP 释放。
//   - 若 handleTakeoverLogin 已经放弃接管(secret 不对 / 写 LoginResp 失败 / 等),takenOver
//     仍为 false,这里走第 1 路径,完整清理 —— 这是正确行为,因为 newConn 也没接到资源。
//   - 若没有 takeover 发生,Lock 几乎瞬时(零冲突),开销可忽略。
//
// 注意:这里**不**复用 takeoverMu 来保护 connections / connIDMap / clientIPUsed 这三个全局
// map,这些 map 仍各自由自己的锁保护;takeoverMu 仅保护「takenOver 标志位读+vIP 释放」这
// 一个原子段。锁顺序:**先** takeoverMu **后** connectionsMu / connIDMapMu / clientIPUsedMu。
func cleanupConnection(c *Connection) {
	if c == nil {
		return
	}
	// cleanupDone 在本函数返回时 close(无论走 !takenOver 完整清理还是 takenOver 跳过分支),
	// 标志「vIP 释放 / map 摘除已全部完成」。supersede 的 waitConnsCleanup 等这个信号而非
	// tunnelDone —— 后者只标志 runLinkTunnel 返回,vIP 尚未回收,等它会让新 conn 抢不到同一 vIP。
	// sync.Once 防御:cleanupConnection 理论只被 handleVPNLink 的 defer 调一次,但用 Once 兜底
	// 避免任何未来重入造成 close of closed channel panic。
	if c.cleanupDone != nil {
		defer c.cleanupOnce.Do(func() { close(c.cleanupDone) })
	}

	// 持有 c.takeoverMu 期间禁止 handleTakeoverLogin 改 c.takenOver。
	c.takeoverMu.Lock()
	defer c.takeoverMu.Unlock()

	if c.connIDStr != "" {
		connIDMapMu.Lock()
		if cur, ok := connIDMap[c.connIDStr]; ok && cur == c {
			delete(connIDMap, c.connIDStr)
		}
		// P3-a:同步移除 by-user 索引(connByUserDeleteLocked 内自带 cur == c 守卫)。
		connByUserDeleteLocked(c)
		// exit-node:by-device 索引同步移除(同样 cur==c 守卫)。
		connByDeviceDeleteLocked(c)
		connIDMapMu.Unlock()

		// exit-node 选择器:若本会话「真在跑出口」,它下线后从出口列表消失 → 广播给所有 exit_allowed 客户端,
		// 下拉实时去项。放 goroutine + background ctx(不阻塞 cleanup、不用已取消的会话 ctx);此时已移出 connIDMap,
		// 故 buildExitsList 不会再把它算进去。
		if c.advertisedExit.Load() {
			go broadcastExitsList(context.Background())
		}
		// subnet route:若下线的是**已批准子网路由**宣告方,它下线后 routes-list 里该设备应变 online=false。但 online
		// 仅在「客户端连入 / admin 改路由」时重算,宣告方下线不重算 → 已连接请求方手里停在旧的 online=true(陈旧)。
		// 此时已移出 connIDMap / connByDevice,broadcastRoutesList 重算 lookupActiveConnByDevice 即得正确 online
		// (该设备若无其它活跃会话则 false;仍有会话则保持 true)。放 goroutine + background ctx,与出口下线广播对齐;
		// deviceInSubnetRouteTable 门控使普通客户端下线不触发(仅已批准宣告方)。仅刷新展示,请求方保留已装路由不抖数据面。
		if deviceInSubnetRouteTable(c.deviceID) {
			go broadcastRoutesList(context.Background())
		}
	}

	if !c.takenOver.Load() {
		connectionsMu.Lock()
		if c.connID != 0 {
			cc, ok := connections[c.connID]
			if ok && cc == c {
				// S1(2026-05-26):atomic Load 拿快照,而非裸 cc.clientIPs。
				// cleanupConnection 跟登录路径已经互斥(takenOver 守卫),理论 race 窗口小,
				// 但走 helper 风格统一,后续代码改了也安全。
				ips := cc.safeClientIPs()
				if len(ips) > 0 {
					// P0-1: 释放 vIP 时同步注销 vipOwner 映射,避免「老 user 的 vIP 已分给新 user」
					// 期间 ACL enforcement 还按老 user 查。这一步在 clientIPUsedMu 持锁内做,
					// 与 delete(clientIPUsed, ...) 原子一致。
					addrs := make([]netip.Addr, 0, len(ips))
					clientIPUsedMu.Lock()
					for _, a := range ips {
						// P0-3(2026-05-22):带上 tunChan 让 demux 做 identity 比对。
						// 老连接 cleanup 时若同 vIP 已被新连接覆盖,demux 会保留新 chan,
						// 不再误删导致新连接 down 方向黑洞。
						delete(clientIPUsed, a.VirtualIP)
						action := registerTunReadChanAction{action: 1, ip: ipToKey(a.VirtualIP), tunChan: a.TunChan, success: make(chan struct{}, 1)}
						sendRegisterActionAwait(action)
						drainAndCloseTunChan(a.TunChan)
						// staticcheck SA4017 误报 stub no-op;Linux 版有副作用且返回 err,
						// 此处不关心成功条数,err 已在 _linux.go 内部 logrus 处理,这里
						// 显式丢弃。
						_, _ = ReleaseConntrackForIP(a.VirtualIP)
						if k := ipToKey(a.VirtualIP); k.IsValid() {
							addrs = append(addrs, k)
						}
					}
					clientIPUsedMu.Unlock()
					unregisterVIPOwners(addrs)
				}
				delete(connections, c.connID)
			}
		}
		connectionsMu.Unlock()
		return
	}

	// 接管路径：vip / TunChan / SessionRelease 全部跳过；只删自己的 connections 表项
	connectionsMu.Lock()
	if c.connID != 0 {
		cc, ok := connections[c.connID]
		if ok && cc == c {
			delete(connections, c.connID)
		}
	}
	connectionsMu.Unlock()
	logrus.WithFields(logrus.Fields{
		"conn_id_str": c.connIDStr,
		"conv_id":     c.connID,
	}).Info("[takeover] 老链路已被接管，跳过 vip / TunChan / SessionRelease 清理")
}

// handleVPNLink 首帧必须为 LoginReq；成功后下发 ConvSaltLite，再在同连接上转发 IP 包（类型 5）
//
// 智能模式 takeover：当 LoginReq.Purpose == "takeover" 时分流到 handleTakeoverLogin,
// 仅本端校验 secret + PSK,不会重新发起认证流。
func handleVPNLink(raw net.Conn, gw *gatewayState) {
	defer func() { _ = raw.Close() }()
	// H2(B3): per-connection panic 隔离。handleTakeoverLogin / handleVPNLink 内部任何
	// 一处 panic(比如 third-party 库的 nil deref / map race)都不应该让进程崩;同时
	// 所有 defer 在 panic 时也会执行,包括 cleanupConnection 与 rollbackNewConn(takeover
	// 路径),所以 newConn / oldConn 的 vIP / connections map 资源都能正确释放。
	defer func() {
		if r := recover(); r != nil {
			logrus.WithFields(logrus.Fields{
				"goroutine": "handleVPNLink",
				"remote":    raw.RemoteAddr().String(),
				"panic":     r,
				"stack":     string(debug.Stack()),
			}).Error("[handleVPNLink] panic 已捕获,本连接断开,进程继续")
		}
	}()
	enableTCPKeepAlive(raw)

	remote := raw.RemoteAddr().String()
	ipHost, _, splitErr := net.SplitHostPort(remote)
	if splitErr != nil {
		// 某些 conn 没 port(整体当 host),与 globalLoginIPLimiter 保持一致语义。
		ipHost = remote
	}

	// P2#16(2026-05-24):pre-login idle deadline。
	//
	// 覆盖整个握手期(PoWChallengeReq → PoWChallenge → LoginReq → LoginResp 完成)。
	// attacker 完成 WS 握手后挂着不发任何帧 / 解 PoW 拖时间是廉价 DoS,这里设 30s 上限。
	// LoginReq 走完后正常进入数据面,后续 keepalive 由 wssPingInterval / DataPlanePing 接管。
	//
	// SetDeadline 影响 read+write,登录成功路径下游会清理(reset 为 zero / WSS 路径自有
	// keepalive 心跳);异常路径 defer raw.Close() 兜底。
	const preLoginIdleTimeout = 30 * time.Second
	preLoginDeadline := time.Now().Add(preLoginIdleTimeout)
	if errDl := raw.SetDeadline(preLoginDeadline); errDl != nil {
		logrus.WithField("remote", remote).WithError(errDl).Debug("[login] 设 pre-login deadline 失败,继续(底层 conn 可能不支持)")
	}

	powSvc := gw.effectivePoWService()

	// I5: 登录前用受限上限(4KB)读首帧,防止攻击者用 64KB 大帧消耗服务器内存。
	// LoginReq 实际尺寸 < 1KB,留 4× 安全冗余;登录完成后恢复 64KB 上限,
	// 不影响后续 IP 包(最大 ~ MTU,远低于 64KB)。
	typ, payload, err := util.ReadLinkFramePreLogin(raw)
	if err != nil {
		logrus.WithField("remote", remote).WithError(err).Debug("读取首帧失败")
		return
	}

	// P2#16: 协议状态机第一步 — 首帧**必须**是 LinkTypePoWChallengeReq。
	//
	// 老客户端不带 PoW,首帧会发 LinkTypeLoginReq → 落入 default 分支静默断开(等价
	// "拒登,无 LoginResp")。这是预期行为:升级前老客户端会观察到「登录失败」,
	// 客户端升级到带 PoW 的版本后即可恢复。任何其它非 PoWChallengeReq 首帧也都按
	// 扫描器/fuzz 处理 — 不写 audit、不打 Warn,仅 Debug 即可。
	if typ != util.LinkTypePoWChallengeReq {
		logrus.WithFields(logrus.Fields{
			"remote": remote,
			"typ":    typ,
		}).Debug("[login] 首帧类型非 PoWChallengeReq(预期老客户端 / 端口扫描),静默断开")
		return
	}
	// PoWChallengeReq body 当前必须为空,但 server **不校验**(2026-05-24 round-4 scan
	// 决议)。理由:
	//   1) future-proof:server 加字段(如 client 偏好难度 hint / 客户端版本 tag)
	//      时不会破老 client(老 client 发空 body / 新 client 发带字段 body 都接受);
	//   2) 校验 body 非空会给 attacker 反指纹信号("我能区分 server 接不接受非空 body"
	//      → 推断 server 版本范围),破坏 round-2 的反指纹设计;
	//   3) ReadLinkFramePreLogin 已经在帧头限 4KB,attacker 灌 body 上界有限,
	//      globalPoWIPLimiter 60/min/IP 兜底,放大系数 ~0。
	_ = payload

	// 出题之前的 IP 速率限制(60/分钟/IP, burst 10)— 挡 challenge bombing。
	if ok, _ := globalPoWIPLimiter.AllowChallenge(remote); !ok {
		// 反指纹:reason 留空,不让 attacker 抓包分辨自己被哪一层挡了。
		writeCloseAndReturn(raw, util.CodePowFailed, "")
		// 不算 ipFailures(限速不是 PoW 失败,不该升下次难度让正常用户连坐);
		// 不写 audit_logs(限速日志已在 pow_limiter.go 内节流打 Warn)。
		return
	}
	// 全局出题速率限制(1000/秒, burst 100)— 跨 IP DoS 防御。
	if !AllowGlobalIssue() {
		logrus.WithField("remote", remote).Warn("[pow] 全局出题速率超限,拒绝出题")
		writeCloseAndReturn(raw, util.CodePowFailed, "")
		return
	}

	// 计算难度并出题。
	failures := powSvc.failures.Count(ipHost)
	difficulty := powSvc.ComputeDifficulty(failures)
	challenge, errIssue := powSvc.IssueChallenge(difficulty)
	if errIssue != nil {
		logrus.WithError(errIssue).WithField("remote", remote).Error("[pow] 出题失败")
		writeCloseAndReturn(raw, util.CodeServerError, "")
		return
	}
	chBody, errCh := util.MarshalLinkPoWChallengeJSON(
		challenge.ChallengeID, challenge.Salt, challenge.Difficulty, challenge.ExpiresAt, challenge.Signature,
	)
	if errCh != nil {
		logrus.WithError(errCh).WithField("remote", remote).Error("[pow] 序列化 challenge 失败")
		writeCloseAndReturn(raw, util.CodeServerError, "")
		return
	}
	if errW := util.WriteLinkFrame(raw, util.LinkTypePoWChallenge, chBody); errW != nil {
		logrus.WithError(errW).WithField("remote", remote).Debug("[pow] 写 challenge 失败")
		return
	}

	// 协议状态机第二步 — 等第二帧,**必须**是 LinkTypeLoginReq(不再接受
	// 二次 PoWChallengeReq,防滥用单连接反复出题)。
	typ, payload, err = util.ReadLinkFramePreLogin(raw)
	if err != nil {
		logrus.WithField("remote", remote).WithError(err).Debug("[login] 读 LoginReq 失败")
		return
	}
	if typ != util.LinkTypeLoginReq {
		logrus.WithFields(logrus.Fields{
			"remote": remote,
			"typ":    typ,
		}).Debug("[login] 第二帧非 LoginReq(状态机违规),断开")
		writeCloseAndReturn(raw, util.CodePowFailed, "")
		return
	}

	loginReq, err := util.ParseLoginReqLinkPayload(payload)
	if err != nil {
		// 反指纹(round-3 scan):此前这条路径发 LinkTypeLoginResp,跟其它 PoW 失败
		// 分支发的 LinkTypeClose **wire 形态不同**,attacker 可借此分辨"PoW 通过 +
		// JSON 解析错"这个独有状态。统一改成 close 412(同其它 PoW 失败)+ MarkFailure
		// + audit("reason=parse_failed"),让 attacker 在 wire 上看不到差异,且反复
		// 发恶意 JSON 也会升 PoW 难度。
		powSvc.failures.MarkFailure(ipHost)
		if gw != nil && gw.store != nil {
			_ = gw.store.Audit(context.Background(), remote, auditActionForLoginCode(util.CodePowFailed), "", "reason=parse_failed")
		}
		logrus.WithFields(logrus.Fields{
			"remote": remote,
			"err":    truncateForLog(err.Error(), 200),
		}).Warn("[pow] LoginReq 解析失败")
		writeCloseAndReturn(raw, util.CodePowFailed, "")
		return
	}

	// PoW 验证 — 校验签名 + 数学 + 防重放。serverWants 用刚出题时的难度,避免
	// attacker 拿同 IP 早先低难度 challenge 在高难度时段提交(虽然 HMAC 没出错,
	// 但 serverWants 卡死)。
	proof := PoWProof{
		ChallengeID: loginReq.Pow.ChallengeID,
		Salt:        loginReq.Pow.Salt,
		Difficulty:  loginReq.Pow.Difficulty,
		ExpiresAt:   loginReq.Pow.ExpiresAt,
		Signature:   loginReq.Pow.Signature,
		Nonce:       loginReq.Pow.Nonce,
	}
	if errPoW := powSvc.VerifyPoWProof(proof, difficulty); errPoW != nil {
		// PoW 失败也算这个 IP 的失败,下次难度跟着升,挡死循环重试 attacker。
		powSvc.failures.MarkFailure(ipHost)
		// 走 auditActionForLoginCode helper 跟 PSK / VPN_EXPIRED 等失败 action 命名一致,
		// 后续 `nanotun-admin audit list --action login.fail.pow` 可一键过滤。
		// 具体 PoW 失败原因(bad_sig / expired / replay / ...)写在 detail。
		if gw != nil && gw.store != nil {
			_ = gw.store.Audit(context.Background(), remote, auditActionForLoginCode(util.CodePowFailed), "", "reason="+errPoW.Error())
		}
		logrus.WithFields(logrus.Fields{
			"remote":     remote,
			"failures":   failures,
			"difficulty": difficulty,
			"reason":     errPoW.Error(),
		}).Debug("[pow] 校验失败")
		writeCloseAndReturn(raw, util.CodePowFailed, "")
		return
	}

	// PoW 通过 — 清掉 pre-login deadline(后续 authenticateLogin / 数据面有自己的超时)。
	if errDl := raw.SetDeadline(time.Time{}); errDl != nil {
		logrus.WithField("remote", remote).WithError(errDl).Debug("[login] 清 pre-login deadline 失败,继续")
	}

	// per-IP 登录速率限制(P0-2 配套):takeover 路径也要走限速,否则攻击者只要持续发
	// takeover 请求就能让目标连接的 argon2 verify(本批 D1 加的)持续触发。统一在分支
	// 之前做限速。
	if ok, _ := globalLoginIPLimiter.AllowLogin(remote); !ok {
		// P1-3: 429 限速也写 audit_logs,便于事后按 IP 关联到爆破/扫描行为。
		// actor=remote IP,target 留空(此刻还没解析出 user/name),detail 标 ratelimited。
		if gw != nil && gw.store != nil {
			_ = gw.store.Audit(context.Background(), remote, "login.fail.ratelimit", "", "code=429")
		}
		_ = writeLinkLoginResp(raw, 429, "登录请求过于频繁,请稍后再试", "")
		return
	}

	if loginReq.Purpose == util.PurposeTakeover {
		handleTakeoverLogin(raw, gw, loginReq, remote, ipHost)
		return
	}

	connIDStr := util.GenerateID()
	if connIDStr == "" {
		// crypto/rand 故障:不接受这条连接进入活跃集合,客户端会重连重试。
		// 不写 connIDMap、不分配 vIP,直接拒绝。
		logrus.WithField("remote", remote).Error("[login] 生成 connIDStr 失败,熵源不可用,拒绝登录")
		_ = writeLinkLoginResp(raw, util.CodeServerError, clientLoginMessageForCode(util.CodeServerError), "")
		return
	}

	logrus.WithFields(logrus.Fields{
		"remote":    remote,
		"platform":  loginReq.Platform,
		"transport": loginReq.Transport,
	}).Info("收到登录请求")

	authResult, authErr := authenticateLogin(gw, loginReq, connIDStr)
	if authErr != nil {
		// 日志保留原始 message(截断防爆),便于服务端排查;**不**透传给客户端,
		// 避免反射出 SQL 错误链 / 内部路径。
		logrus.WithFields(logrus.Fields{
			"remote":  remote,
			"code":    authErr.code,
			"raw_msg": truncateForLog(authErr.message, 200),
		}).Warn("登录验证失败")
		// G4: 登录失败写 audit_logs。actor 写 remote IP(不写 name 避免被拿来枚举用户),
		// detail 写 code,**不**记录 raw message(可能含 SQL 片段)。
		// K2(2026-05-21 事故后):action 名按 code 细分(login.fail.user_not_found /
		// login.fail.bad_psk / ...),让 `nanotun-admin audit list --action ...` 能直接定位。
		if gw != nil && gw.store != nil {
			_ = gw.store.Audit(context.Background(), remote, auditActionForLoginCode(authErr.code), "", fmt.Sprintf("code=%d", authErr.code))
		}
		// K2: user_not_found 每分钟 ≥ 阈值时升级到 ERROR,触发 log shipper 告警。
		// 单条 warn 已经在上面打了;这里只关心「速率异常」这个聚合信号。
		if authErr.code == util.CodeUserNotFound {
			noteLoginUserNotFound(nil)
		}
		// P2#16:PSK / 用户级校验失败也算 IP 失败 → 下次 PoW 难度跟着升,挡住
		// 持续暴力破解 attacker。不区分 user_not_found / bad_psk / vpn_expired —
		// 任何让 authenticate 走到这里的失败都消耗一次 IP 失败槽。
		// **不**包括:
		//   - CodeServerError:server 自身故障,不该惩罚正常用户;
		//   - CodePlatformNotAllowed:PSK 已验过、身份合法,只是平台被策略拒绝,
		//     合法用户换个端登录几次不该被抬高 PoW 难度 / 触发暴破风控。
		if authErr.code != util.CodeServerError && authErr.code != util.CodePlatformNotAllowed {
			powSvc.failures.MarkFailure(ipHost)
		}
		_ = writeLinkLoginResp(raw, authErr.code, clientLoginMessageForCode(authErr.code), "")
		return
	}
	// G4: 登录成功 audit
	if gw != nil && gw.store != nil {
		_ = gw.store.Audit(context.Background(), remote, "login.success", authResult.UserID, "")
	}
	// P2#16:登录成功 → 清零该 IP 失败计数,让下次登录回到 base_difficulty。
	powSvc.failures.MarkSuccess(ipHost)
	userID := authResult.UserID
	takeoverSecret := generateTakeoverSecret()
	// P0-4(2026-05-22):把 user-level enforcement 字段固化到 Connection。
	// 默认 exitAllowed=true(老库 / 测试路径,保持兼容);仅在登录拿到 user 行后
	// 按 user.ExitAllowed/Bandwidth* 覆盖。后续 user 改了字段,要先踢线再生效
	// (会话内不动态刷新,避免每包查库;P0-1 user invalidate 处理踢线)。
	//
	// invariant(U2, 2026-05-26):c 进 connIDMap (line ~2000) 之后,**异步**会被
	// 写的字段只有:
	//
	//   c.clientIPs  ← S1 atomic.Pointer.Store,见 line ~2171(vIP 分配后)
	//   c.linkConn   ← linkWrMu 内裸写,见 line ~2249
	//   c.rlConn     ← atomic.Pointer.Store 在同一 linkWrMu 块内
	//
	// 其它字段(deviceID / exitAllowed / bw*BPS / createdAt 等)都在本 struct literal
	// 或紧接的几行设置好,进 map 之后只读 — 锁外读不会 race。新增字段要么放进 literal
	// 要么走 atomic / mutex,不能像下面 c.deviceID 这样后写但又长生命周期裸读。
	c := &Connection{
		connIDStr:      connIDStr,
		userID:         userID,
		linkConn:       raw,
		takeoverSecret: takeoverSecret,
		loginToken:     loginReq.Token,
		tunnelDone:     make(chan struct{}),
		cleanupDone:    make(chan struct{}),
		createdAt:      time.Now(),
		exitAllowed:    true,
		// 平台白名单踢线用快照;此刻 AllowsPlatform 已放行过,快照必然合规,
		// 只有 admin 之后改白名单才可能让它变不合规(user_invalidate 扫到即踢)。
		platformAtLogin: loginReq.Platform,
	}
	if authResult.Device != nil {
		c.deviceID = authResult.Device.ID
		// 2026-05-23 supersede 用:authResult.Device 仅在 UpsertDevice 成功后才设置
		// (auth_login.go),所以「客户端没上报 / UUID 不合法 / 写库失败」三类自动走
		// 空字符串分支 → findSupersededByDeviceLocked 跳过,匿名 device 不互踢。
		c.deviceUUID = authResult.Device.DeviceUUID
		c.deviceName = authResult.Device.DeviceName // 去重后的最终名，经 ConvSaltLite 回显给客户端
		// 0011(2026-05-23):per-device 限速快照,登录瞬时凝固。
		// 后续 admin 改了 devices.rate_*_bps 通过 control socket /rate/refresh-device
		// 主动 push 到 c.rlConn,本字段也会被同步更新(防止 takeover 等路径再读到旧值)。
		c.deviceRateUpBPS = authResult.Device.RateUploadBPS
		c.deviceRateDownBPS = authResult.Device.RateDownloadBPS
	}
	if authResult.User != nil {
		c.exitAllowed = authResult.User.ExitAllowed
		c.bwUpBPS = authResult.User.BandwidthUpBPS
		c.bwDownBPS = authResult.User.BandwidthDownBPS
		c.maxSessionsAtLogin = authResult.User.MaxSessions
		// P0-1(2026-05-22):记录登录瞬时的 psk_hash 快照。
		// user_invalidate 周期性扫描时拿这个跟当下 users.psk_hash 比对,不同 → 视作
		// 「PSK 已被 reset」,主动踢线;字符串比对纳秒级,不需要再跑 argon2。
		c.pskHashAtLogin = authResult.User.PSKHash
	}
	connIDMapMu.Lock()
	connIDMap[connIDStr] = c
	connByUserAddLocked(c)   // P3-a:索引必须与 connIDMap 同步入库
	connByDeviceAddLocked(c) // exit-node:by-device 索引同步入库
	// 2026-05-23 supersede:同 user 同 deviceUUID 的旧 conn 全部要被踢。
	// 必须在持 connIDMapMu 锁内挑出 victims,锁外才 close —— 否则并发同 device
	// 登录可能各自只看到对方的「半 inserted」状态,漏踢。
	// findSupersededByDeviceLocked 已正确处理 newConn 自身排除 + takenOver 排除 +
	// deviceUUID 为空降级跳过(匿名 device 不互踢)。
	supersededConns := findSupersededByDeviceLocked(c)
	// exit-node/subnet route 黑洞修复:把「即将被 close」的旧会话**立即**标 superseded(仍持 connIDMapMu,close 之前)——
	// 使它瞬间从 by-device 转发目标(lookupRunningExitConnByDevice / lookupSubnetAdvertiserConnByDevice)与在线出口
	// (buildExitsList / lookupActiveConnByDevice)里摘除,不必等异步 cleanup。否则「已踢未清」窗口里,旧出口会话仍
	// advertisedExit&&!takenOver、而新会话尚未重发 advertise → 请求方出口流量被确定性投进旧会话已关闭的链路黑洞
	// (同 device 切网络 fresh 重登录的时通时不通根因)。atomic 一次性置真,不复位(被踢会话即将销毁)。见 Connection.superseded。
	//
	// 0021 深扫:置位必须在 evictOldestSessionsLocked **之前** —— evict 按 !superseded
	// 计数,若后置,supersede 受害者(垂死)会占配额,cap 边界上「同 device 重登」会
	// 让 evict 误踢另一台设备的健康会话(踢完才发现总数本来就没超)。
	for _, v := range supersededConns {
		if v != nil {
			v.superseded.Store(true)
		}
	}
	// E4(P1-7): 同一 userID 注册到 connIDMap 后,检查会话总数是否超过 max;超过则
	// 踢掉最老的。本步必须在 connIDMapMu 持锁内完成,否则两个并发登录可能各自看到
	// count==max-1 都通过,实际产生 max+1 个会话。
	evictedConns := evictOldestSessionsLocked(gw, c)
	for _, v := range evictedConns {
		if v != nil {
			v.superseded.Store(true)
		}
	}
	connIDMapMu.Unlock()

	// dedup:0021 深扫后 evict 已按 !superseded 过滤,理论上不会再与 supersede 命中
	// 同一条旧 conn;保留 dedup 作防御(改动 evict 过滤条件时不至于双关双记)。
	// 重合时优先记成 supersede(语义更精确)。
	supersededSet := make(map[*Connection]struct{}, len(supersededConns))
	for _, v := range supersededConns {
		if v != nil {
			supersededSet[v] = struct{}{}
		}
	}
	allVictims := dedupVictims(supersededConns, evictedConns)
	for _, victim := range allVictims {
		_, isSupersede := supersededSet[victim]
		fields := logrus.Fields{
			"userID":    userID,
			"victim_id": victim.connIDStr,
			"new_id":    c.connIDStr,
			"age":       time.Since(victim.createdAt).Round(time.Second).String(),
		}
		if isSupersede {
			fields["device_uuid"] = victim.deviceUUID
			logrus.WithFields(fields).Warn("[supersede] 同 device_uuid 重登,踢掉旧 conn")
			if gw != nil && gw.store != nil {
				_ = gw.store.Audit(context.Background(), remote, "kick_device_supersede", userID,
					"old_conn="+victim.connIDStr+",device_uuid="+victim.deviceUUID)
			}
			sessionSupersedeCount.Add(1)
		} else {
			logrus.WithFields(fields).Warn("[per-user-limit] 同账号会话数超限,踢最老的一条")
			// 0021 深扫:supersede 分支写 audit 而这里此前不写,admin 排查「会话为什么
			// 掉线」缺线索(尤其配了账号级上限后被动踢线变成常态化事件)。补齐同口径。
			if gw != nil && gw.store != nil {
				_ = gw.store.Audit(context.Background(), remote, "kick_session_limit", userID,
					"old_conn="+victim.connIDStr+",new_conn="+c.connIDStr)
			}
		}
		victim.linkWrMu.Lock()
		if victim.linkConn != nil {
			_ = victim.linkConn.Close()
		}
		victim.linkWrMu.Unlock()
	}

	// 仅 supersede victim 需要等 cleanup 完成 —— 它们持有的 vIP 和新 conn 的 device 是
	// 同一台,新 conn 走 alloc 前必须等老 conn 释放 clientIPUsed[vIP],否则
	// preferredLeasedVIPs 看到该 vIP 还被占,会跳过它去分一个新 vIP(违背「同 device
	// 重登 IP 不变」预期)。evict victim 是不同 device,vIP 与新 conn 无关,不用等。
	waitConnsCleanup(supersededConns)

	// `convID` 是 nanotun 内部 conv_id，下方分配循环写入；与 c.connID 同步保持一致。
	// 接管路径下新 conn 也会分配新的 convID（见 handleTakeoverLogin），与老 convID 不冲突。
	var convID uint32
	var assignmentsForMsg []util.VirtualIPAssignment

	defer cleanupConnection(c)

	if err := writeLinkLoginRespFull(raw, 0, "登录成功", userID, connIDStr, takeoverSecret); err != nil {
		logrus.WithField("remote", remote).WithError(err).Warn("发送登录响应失败")
		return
	}

	localIPs := localIPsForVPNAllocation(raw)

	// PSK + device 模式下，登录时尝试沿用之前的 vIP 租约（含 user.fixed_vip_*）。
	// 这里仅查询，不写入，写入留到 firstAllocCfg 真正用上之后由 AllocOrLeaseVIP 完成。
	leasedV4, leasedV6 := preferredLeasedVIPs(gw, authResult)
	// 把 db 里其他 device 的 lease 也算进「已占用」，避免新 device 撞 UNIQUE 写不进去。
	// 这一步在 connectionsMu 之外做(避免持有大锁等 SQLite),但 P1-10 下面进入临界区
	// 后还会再刷一遍快照消除 TOCTOU 窗口。
	dbResvV4, dbResvV6 := dbReservedVIPs(gw, leasedV4, leasedV6)

	connectionsMu.Lock()
	// P1-10: 锁内再刷一次 dbReservedVIPs 快照,消除「锁外读 + 锁内分配」之间
	// 别的设备写 lease 造成的 TOCTOU。两次读差不多 1–3ms,但只在持 connectionsMu
	// 的极短窗口里 —— 比起 UNIQUE 冲突后拒登 + 客户端重连成本,这点延迟很值。
	//
	// 失败(dbReservedVIPs 内部已经 Warn 并返回 nil/nil)时不影响:沿用锁外读的 dbResvV4/V6;
	// 同时也不破坏「DB 故障降级」语义。
	if freshV4, freshV6 := dbReservedVIPs(gw, leasedV4, leasedV6); freshV4 != nil || freshV6 != nil {
		dbResvV4, dbResvV6 = freshV4, freshV6
	}
	for {
		convID = gw.nextConvID.Add(1)
		if convID == 0 {
			continue
		}
		if _, exists := connections[convID]; !exists {
			c.connID = convID
			if sharedTUN != nil && (sharedTUNGateway != "" || sharedTUNGatewayV6 != "") {
				clientIPUsedMu.Lock()

				var assignments []util.VirtualIPAssignment

				if sharedTUNGateway != "" {
					maskStr := maskFromGatewayCIDR(sharedTUNGateway)
					allocFailed := false
					var ipv4LocalIPs []string
					for _, lip := range localIPs {
						ip := net.ParseIP(lip)
						if ip != nil && ip.To4() != nil {
							ipv4LocalIPs = append(ipv4LocalIPs, lip)
						}
					}
					if len(ipv4LocalIPs) == 0 {
						ipv4LocalIPs = []string{""}
					}
					for i := range ipv4LocalIPs {
						var netCfg ClientNetConfig
						var errAlloc error
						if i == 0 && leasedV4 != "" && !clientIPUsed[leasedV4] && sameSubnet(sharedTUNGateway, leasedV4) {
							netCfg = ClientNetConfig{ClientIP: leasedV4, Mask: maskStr, Gateway: gatewayAddrFromCIDR(sharedTUNGateway)}
						} else {
							netCfg, errAlloc = AllocClientIP(sharedTUNGateway, mergeUsedVIPs(clientIPUsed, dbResvV4), nil)
						}
						if errAlloc != nil {
							allocFailed = true
							break
						}
						vip := netCfg.ClientIP
						clientIPUsed[vip] = true
						virtualIpAssignment := util.VirtualIPAssignment{VirtualIP: vip, Mask: maskStr, Gateway: sharedTUNGateway, TunChan: make(chan *util.TunPacket, 512)}
						action := registerTunReadChanAction{action: 0, ip: ipToKey(vip), tunChan: virtualIpAssignment.TunChan, success: make(chan struct{}, 1)}
						sendRegisterActionAwait(action)
						assignments = append(assignments, virtualIpAssignment)
					}
					if allocFailed || len(assignments) != len(ipv4LocalIPs) {
						for _, a := range assignments {
							// P0-3:rollback 路径同样带 tunChan 做 identity 比对(虽然此时不太可能
							// 有别人注册过同 vIP —— 我们持着 clientIPUsedMu,且这是分配失败回退路径
							// —— 但保持一致性,以防 future refactor 引入并发)。
							delete(clientIPUsed, a.VirtualIP)
							action := registerTunReadChanAction{action: 1, ip: ipToKey(a.VirtualIP), tunChan: a.TunChan, success: make(chan struct{}, 1)}
							sendRegisterActionAwait(action)
							drainAndCloseTunChan(a.TunChan)
						}
						clientIPUsedMu.Unlock()
						connectionsMu.Unlock()
						logrus.WithField("remote", remote).Warnf("IPv4 虚拟 IP 原子分配失败：requested=%d assigned=%d", len(ipv4LocalIPs), len(assignments))
						return
					}
				}

				if sharedTUNGatewayV6 != "" {
					maskStrV6 := maskFromGatewayCIDR(sharedTUNGatewayV6)
					var netCfgV6 ClientNetConfig
					var errAllocV6 error
					if leasedV6 != "" && !clientIPUsed[leasedV6] && sameSubnet(sharedTUNGatewayV6, leasedV6) {
						netCfgV6 = ClientNetConfig{ClientIP: leasedV6, Mask: maskStrV6, Gateway: gatewayAddrFromCIDR(sharedTUNGatewayV6)}
					} else {
						netCfgV6, errAllocV6 = AllocClientIP(sharedTUNGatewayV6, mergeUsedVIPs(clientIPUsed, dbResvV6), nil)
					}
					if errAllocV6 != nil {
						logrus.WithField("remote", remote).WithError(errAllocV6).Warn("IPv6 虚拟 IP 分配失败，继续仅 IPv4")
					} else {
						vipV6 := netCfgV6.ClientIP
						clientIPUsed[vipV6] = true
						v6Assignment := util.VirtualIPAssignment{VirtualIP: vipV6, Mask: maskStrV6, Gateway: sharedTUNGatewayV6, TunChan: make(chan *util.TunPacket, 512)}
						action := registerTunReadChanAction{action: 0, ip: ipToKey(vipV6), tunChan: v6Assignment.TunChan, success: make(chan struct{}, 1)}
						sendRegisterActionAwait(action)
						assignments = append(assignments, v6Assignment)
					}
				}

				if len(assignments) > 0 {
					// S1(2026-05-26):atomic.Pointer 写,Store 之后 /status 锁外 Load 安全。
					c.clientIPs.Store(&assignments)
					assignmentsForMsg = assignments
				}
				clientIPUsedMu.Unlock()
			}
			connections[convID] = c
			break
		}
	}
	connectionsMu.Unlock()

	// PSK + device 模式：把本次分配的首个 vIP 写入 leases 表，下次同设备登录沿用。
	//
	// H1(P0-2/3): persistDeviceLease 现在区分 ErrDuplicate 与其它错误:
	//   - ErrDuplicate(vIP UNIQUE 冲突): 必须拒登,因为继续会导致数据面双重占用同一个
	//     vIP -> 路由黑洞。立刻 return -> defer cleanupConnection 自动释放 c.clientIPs
	//     里所有 vIP / TunChan,connIDMap / connections 项也会被清理。
	//   - 其它非冲突错误: persistDeviceLease 内部仅 Warn 并返回 nil,放行登录(lease 表
	//     存不下不影响本次会话的数据面)。
	//
	// 若 UNIQUE 冲突频繁触发,说明 alloc 路径漏算了 db 里的离线 lease,应排查
	// dbReservedVIPs / mergeUsedVIPs 是否被正确调用。
	// S1(2026-05-26):atomic Load 拿 snapshot;此时分配路径已 Store 完(line ~2149),
	// Load 必返 non-nil(除非全空,此时 ips=nil 跟 len 检查兼容)。
	ips := c.safeClientIPs()
	if err := persistDeviceLease(gw, authResult, ips); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			_ = writeLinkLoginResp(raw, 1, "服务器繁忙，请稍后重试", "")
			logrus.WithField("remote", remote).
				WithError(err).
				Error("[alloc] vIP 持久化撞 UNIQUE 冲突,已拒登并释放内存占用")
			return
		}
	}

	// P0-1: 注册 vIP→userID 映射,供 ACL enforcement 查 dst 拥有者。
	// authResult.User 通常非 nil(PSK 路径必产出 User);测试场景 store=nil
	// 时 authenticatePSK 直接返回 CodeServerError,不会走到这里。
	if authResult.User != nil && len(ips) > 0 {
		addrs := make([]netip.Addr, 0, len(ips))
		for _, a := range ips {
			if k := ipToKey(a.VirtualIP); k.IsValid() {
				addrs = append(addrs, k)
			}
		}
		registerVIPOwners(addrs, authResult.User.ID)
	}

	if convID == 0 || c == nil {
		logrus.WithField("remote", remote).Error("无法分配 convID")
		return
	}

	var uploadLimiter, downloadLimiter *rate.Limiter
	// 0011(2026-05-23):effective rate = min_positive(device, settings, toml-platform, toml-global, user-bw)
	// 先查 settings.default(SQLite,~us);store 不可用 / 查询失败时降级为零值(等于不在 settings 层强制)。
	// 0012:rate burst 也跟着 settings 一起读出来,后面 NewLimiter 用 effectiveBurst 兜底默认值/下限。
	rateDefaults := storeRateDefaultsView{}
	if gw != nil && gw.store != nil {
		if d, err := gw.store.GetRateDefaults(context.Background()); err == nil {
			rateDefaults = storeRateDefaultsView{UploadBPS: d.UploadBPS, DownloadBPS: d.DownloadBPS, BurstBytes: d.BurstBytes}
		}
	}
	upRate, downRate := effectiveLinkRates(gw, loginReq.Platform, c.deviceRateUpBPS, c.deviceRateDownBPS, rateDefaults)
	// P0-4:user 级 bw 仍取 min(0=+∞)。effectiveLinkRates 只覆盖 device/settings/toml,
	// user 维度故意留在这里 — 概念上 user 是「订阅 quota」,与 device 维度的「这台机器
	// 限速」语义独立,保留两次 min 让阅读路径更清晰。
	upRate = minPositiveBPS(upRate, c.bwUpBPS)
	downRate = minPositiveBPS(downRate, c.bwDownBPS)
	burstBytes := effectiveBurst(rateDefaults.BurstBytes)
	if upRate > 0 {
		uploadLimiter = rate.NewLimiter(rate.Limit(upRate), burstBytes)
	}
	if downRate > 0 {
		downloadLimiter = rate.NewLimiter(rate.Limit(downRate), burstBytes)
	}
	rwCtx := globalContext
	if rwCtx == nil {
		rwCtx = context.Background()
	}
	rwc := newRateLimitedConn(raw, uploadLimiter, downloadLimiter, rwCtx)
	// 在 c 已经进入 connIDMap 之后做 linkConn 替换:kick goroutine 可能并发读该字段。
	// 用 linkWrMu(同时兼任 linkConn 字段同步原语)包一下,避免 race detector 报警。
	c.linkWrMu.Lock()
	c.linkConn = rwc
	c.rlConn.Store(rwc) // 0011 control-sock /rate/refresh 热更直接用,免去 type assert
	c.linkWrMu.Unlock()

	dnsV4 := util.SanitizeDNSServersV4(gw.cfg.TUN.DNSServersV4)
	var dnsV6 []string
	if sharedTUNGatewayV6 != "" {
		// dnsV6ServersForClient:已探明 server 无 v6 公网出网时剔除公网 v6 解析器(经隧道必被 fast-fail 打回),
		// ULA/私网 v6 解析器保留。见 egress_select.go。
		dnsV6 = dnsV6ServersForClient(util.SanitizeDNSServersV6(gw.cfg.TUN.DNSServersV6))
	}
	// P2#11:Magic DNS 启用时,把 TUN gateway IP **prepend** 为头号 DNS,
	// 让 client 优先把 *.<suffix> 查询路由到 server 内置解析器。
	if extra := magicDNSExtraDNS(gw, gatewayAddrFromCIDR(sharedTUNGateway)); extra != "" {
		dnsV4 = append([]string{extra}, dnsV4...)
	}
	saltBody, err := util.MarshalConvSaltLiteJSON(assignmentsForMsg, dnsV4, dnsV6, magicDNSSuffixForClient(gw), c.deviceName)
	if err != nil {
		logrus.WithField("remote", remote).WithError(err).Warn("构造 ConvSaltLite 失败")
		return
	}
	c.linkWrMu.Lock()
	err = util.WriteLinkFrame(rwc, util.LinkTypeConvSaltMsg, saltBody)
	c.linkWrMu.Unlock()
	if err != nil {
		logrus.WithField("remote", remote).WithError(err).Warn("下发 ConvSaltLite 失败")
		return
	}
	logrus.WithField("remote", remote).WithField("conv_id", convID).Info("已下发 ConvSaltLite，进入链路隧道")

	tunnelCtx := globalContext
	if tunnelCtx == nil {
		tunnelCtx = context.Background()
	}
	runLinkTunnel(tunnelCtx, rwc, c, remote)
}

// handleTakeoverLogin 接管登录处理(仅本端校验 secret + PSK,不重新走完整登录流)。
//
// 时序设计（与 README 中「智能模式 takeover」一致）：
//  1. 校验 takeover_session_id 找到 oldConn；若不存在或 secret 不匹配，写一条普通的失败 LoginResp 后返回。
//     客户端识别失败后会静默关闭新链路（不 fire on_disconnected），8s 后再次尝试，原 reality 链路不受影响。
//  2. 持有 oldConn.takeoverMu，并在锁内浅拷贝 oldConn.clientIPs / connIDStr / userID / takeoverSecret 给 newConn；
//     给 newConn 分配独立的 nanotun 内部 conv_id（与老 conv_id 不冲突）；newConn 注册到 connections 表。
//  3. 写 LoginResp(code=0, session_id=老, takeover_secret=老) + ConvSaltLite(用老 vip) 到新链路；
//     若写失败（client 已断开等），回滚 newConn 的 connections 表注册并返回，oldConn 不受影响。
//  4. 写 LinkTypeTakenOver(JSON: new_session_id, new_transport) 到老链路（best-effort）。
//  5. CAS oldConn.takenOver = true；从此 oldConn defer (cleanupConnection) 跳过 vip / TunChan / SessionRelease 清理。
//  6. 覆盖 connIDMap[connIDStr] = newConn（守卫 cleanupConnection 不误删）。
//  7. Close oldConn.linkConn → 老 runLinkTunnel readLoop EOF → 老 demux 退出 → close oldConn.tunnelDone。
//  8. <-oldConn.tunnelDone（带超时）等老链路完整释放 TunChan 后再放新 demux 抢同一 chan。
//  9. 解锁 takeoverMu，进入 newConn 的 runLinkTunnel；defer cleanupConnection(newConn) 与 primary 路径一致。
//
// 注意：takeoverMu 在整个接管期间持有；正常情况下 7→8 的耗时由 close + readLoop 退出主导，
// 实测 < 100ms；为保险加 5s 超时（异常时记 warn 但仍继续，新 demux 与老 demux 并存的最坏后果是 IP 包乱序，
// 不会造成数据破坏）。
// auditTakeoverFail 把 takeover 各失败分支写入 audit_logs。reason 是固定枚举(避免 PII 泄漏),
// targetUserID 在「未到识别 oldConn」之前为空(empty_session_id / session_not_found),
// 后续分支拿到 oldConn 后必传。
//
// 命名空间统一为 "login.takeover.fail.<reason>",运维可用
// `nanotun-admin audit list --action-prefix login.takeover.fail` 一把抓所有 takeover 失败。
func auditTakeoverFail(gw *gatewayState, remote, reason, targetUserID string) {
	if gw == nil || gw.store == nil {
		return
	}
	_ = gw.store.Audit(context.Background(), remote,
		"login.takeover.fail."+reason, targetUserID, "")
}

func handleTakeoverLogin(raw net.Conn, gw *gatewayState, loginReq *util.LoginReq, remote string, ipHost string) {
	// markTakeoverAsIPFailure 跟 primary login fail 一样,把 attacker 类型的 takeover 失败
	// 也算进 PoW 难度计数 → 下次同 IP 连接的 PoW 难度跟着升。
	//
	// 只在「真 attacker 行为」分支调:secret_mismatch / session_not_found(枚举 sid)
	// / empty_secret(试空字符串) / psk_verify_fail / user_mismatch(跨用户接管)。
	// 「客户端 bug」分支(empty_session_id / already_taken_over 多发竞态)不算 — 这些
	// 是合法客户端在弱网下也可能发的请求,不该让正常用户被惩罚。
	markTakeoverAsIPFailure := func() {
		if gw == nil || ipHost == "" {
			return
		}
		if powSvc := gw.effectivePoWService(); powSvc != nil && powSvc.failures != nil {
			powSvc.failures.MarkFailure(ipHost)
		}
	}

	sid := loginReq.TakeoverSessionID
	if sid == "" {
		logrus.WithField("remote", remote).Warn("[takeover] LoginReq.takeover_session_id 为空")
		// P1-5: takeover 各失败分支统一写 audit_logs。actor=remote IP,target 留空,
		// detail 写失败原因。**不**写 secret/sid 全文,避免攻击者通过 audit log 反向
		// 枚举 / 验证已知 sid。
		auditTakeoverFail(gw, remote, "empty_session_id", "")
		_ = writeLinkLoginResp(raw, 1, "takeover failed: empty session id", "")
		return
	}

	connIDMapMu.RLock()
	oldConn, ok := connIDMap[sid]
	connIDMapMu.RUnlock()
	if !ok || oldConn == nil {
		logrus.WithFields(logrus.Fields{"remote": remote, "sid": sid}).Warn("[takeover] 未找到对应 oldConn")
		auditTakeoverFail(gw, remote, "session_not_found", "")
		// session_id 枚举攻击 → 升 PoW 难度。
		markTakeoverAsIPFailure()
		_ = writeLinkLoginResp(raw, 1, "takeover failed: session not found", "")
		return
	}

	oldConn.takeoverMu.Lock()
	// 深扫第八轮 MED:整段接管临界区靠 ~11 处手动 Unlock 释放锁,中间夹着 argon2 verify、
	// store.Audit、GetRateDefaults、JSON 编码等可能 panic 的调用。连接处理 goroutine 的
	// recover 会兜住 panic 保住进程,但 takeoverMu 会永久泄漏 —— oldConn.cleanupConnection
	// 阻塞在这把锁上永不返回,其 goroutine 泄漏、cleanupDone 永不关、vIP 永不回收、
	// connIDMap 残留僵尸,之后该设备每次重登都踢僵尸并另分 vIP(池永久缩水)。
	// 用幂等的 unlockTakeover + defer 兜底:所有原手动 Unlock 点改调 unlockTakeover(),
	// 保持每条路径原有的放锁时机(尤其成功路径必须在 runLinkTunnel 前放锁,否则整个会话
	// 生命周期都占着 takeoverMu);而 panic / 漏放锁的退出路径由 defer 补放。
	// takeoverMuHeld 只被本 goroutine 读写,无并发。
	takeoverMuHeld := true
	unlockTakeover := func() {
		if takeoverMuHeld {
			takeoverMuHeld = false
			oldConn.takeoverMu.Unlock()
		}
	}
	defer unlockTakeover()
	// TOCTOU 复验:上面 connIDMap 查到 oldConn 与这里 Lock(takeoverMu) 之间存在窗口,
	// oldConn 的链路可能刚断、cleanupConnection 已抢先拿到 takeoverMu 跑完「!takenOver」
	// 分支——它已经把 oldConn 从 connIDMap 摘除**并释放了 vIP**(delete(clientIPUsed,...))。
	// 此时若继续接管,会继承 oldConn.safeClientIPs() 里那些**已回收的 vIP**:新会话变僵尸
	// (TunChan 已 close、ip2Channel 已注销,下行黑洞),更糟的是这些 vIP 已回到空闲池,
	// 另一台设备的新登录可能被分到同一 vIP → 级联双分配。cleanupConnection 也持 takeoverMu
	// 且在同一把锁下删 connIDMap,故这里在锁内复验 connIDMap[sid] 仍等于 oldConn 即可判定
	// 「清理是否已抢先发生」。不等则按 session 已消失拒绝——这是良性竞态(断网重连),
	// 客户端会退回全新 primary login,不计 PoW 惩罚。
	connIDMapMu.RLock()
	cur, still := connIDMap[sid]
	connIDMapMu.RUnlock()
	if !still || cur != oldConn {
		unlockTakeover()
		logrus.WithFields(logrus.Fields{"remote": remote, "sid": sid}).Warn("[takeover] oldConn 已被清理(链路先于接管断开),拒绝接管")
		auditTakeoverFail(gw, remote, "session_cleaned", oldConn.userID)
		_ = writeLinkLoginResp(raw, 1, "takeover failed: session gone", "")
		return
	}
	if oldConn.takenOver.Load() {
		unlockTakeover()
		logrus.WithFields(logrus.Fields{"remote": remote, "sid": sid}).Warn("[takeover] oldConn 已被接管")
		auditTakeoverFail(gw, remote, "already_taken_over", oldConn.userID)
		// 多发竞态:不算攻击。
		_ = writeLinkLoginResp(raw, 1, "takeover failed: already taken over", "")
		return
	}
	// 防御「空 secret 全等」bypass:如果 oldConn 在登录时 crypto/rand 失败,takeoverSecret
	// 会是空串;此时若 attacker 拿到 session_id 发个空 secret,ConstantTimeCompare("", "") == 1
	// 会让 takeover 通过。两边都强制拒绝空 secret —— 这条路径在 generateTakeoverSecret
	// 已经成功的正常 server 上永远不会触发,只是兜底防 entropy-broken 机器。
	if oldConn.takeoverSecret == "" || loginReq.TakeoverSecret == "" {
		unlockTakeover()
		logrus.WithFields(logrus.Fields{"remote": remote, "sid": sid}).Warn("[takeover] secret 为空,拒绝接管")
		auditTakeoverFail(gw, remote, "empty_secret", oldConn.userID)
		// 试空字符串 secret 是典型 fuzz / bypass 尝试 → 升难度。
		markTakeoverAsIPFailure()
		_ = writeLinkLoginResp(raw, 1, "takeover failed: empty secret", "")
		return
	}
	if subtle.ConstantTimeCompare(
		[]byte(oldConn.takeoverSecret),
		[]byte(loginReq.TakeoverSecret),
	) != 1 {
		unlockTakeover()
		logrus.WithFields(logrus.Fields{"remote": remote, "sid": sid}).Warn("[takeover] secret 不匹配")
		auditTakeoverFail(gw, remote, "secret_mismatch", oldConn.userID)
		// 试错 secret → 升难度。secret 256-bit 暴破毫无意义,但代码上统一。
		markTakeoverAsIPFailure()
		_ = writeLinkLoginResp(raw, 1, "takeover failed: secret mismatch", "")
		return
	}

	// 在 secret 匹配通过之后,**再加一层 PSK 验证**:防止只持有 (session_id, secret) 的
	// 攻击者(从客户端内存 / 抓包 / log dump 拿到)不知道 PSK 也能接管会话。
	//
	//   - 完整跑 argon2id verify(authenticatePSK)。
	//   - 校验 result.UserID == oldConn.userID,防跨用户 takeover(攻击者用自己账号的 PSK
	//     + 偷来的 session_id+secret 来接管别人的会话)。
	authResult, authErr := authenticatePSK(gw, loginReq)
	if authErr != nil {
		unlockTakeover()
		logrus.WithFields(logrus.Fields{
			"remote": remote,
			"sid":    sid,
			"code":   authErr.code,
		}).Warn("[takeover] PSK 二次校验失败,拒绝接管")
		auditTakeoverFail(gw, remote, "psk_verify_fail", oldConn.userID)
		// PSK 试错 → 升难度。豁免与 primary login 对齐(见 handleVPNLink):
		//   - CodeServerError:server 自身故障;
		//   - CodePlatformNotAllowed:PSK 已验过、身份合法,只是平台被策略拒绝
		//     (admin 在会话存续期间改了白名单),不该按攻击者计惩罚。
		if authErr.code != util.CodeServerError && authErr.code != util.CodePlatformNotAllowed {
			markTakeoverAsIPFailure()
		}
		// 与 primary login 一致:对外只暴露 code,不透传内部 message(避免 SQL/路径泄漏)。
		_ = writeLinkLoginResp(raw, authErr.code, "takeover failed: auth", "")
		return
	}
	if authResult.UserID != oldConn.userID {
		unlockTakeover()
		logrus.WithFields(logrus.Fields{
			"remote":      remote,
			"sid":         sid,
			"want_userID": oldConn.userID,
			"got_userID":  authResult.UserID,
		}).Warn("[takeover] PSK 通过但 userID 与 oldConn 不一致,拒绝跨用户接管")
		auditTakeoverFail(gw, remote, "user_mismatch", oldConn.userID)
		// 跨用户接管尝试 → 升难度(典型攻击模式)。
		markTakeoverAsIPFailure()
		_ = writeLinkLoginResp(raw, 1, "takeover failed: user mismatch", "")
		return
	}

	// 浅拷贝：clientIPs / TunChan 整体过户（指针），用 cap=len(...) 避免误共享底层数组扩容。
	// S1(2026-05-26):走 safeClientIPs(),atomic Load 拿 oldConn 的快照,然后再深 copy。
	oldIPs := oldConn.safeClientIPs()
	inheritedIPs := make([]util.VirtualIPAssignment, len(oldIPs))
	copy(inheritedIPs, oldIPs)

	// 关键改动(D4 / P1-1): takeover 成功后**轮换** takeoverSecret,把旧 secret 一次性废掉。
	// 老 secret 已经匹配过一次,继续复用就违背了「一次性」原则:攻击者后续可以再发同样的
	// secret 一直 takeover。新生成 256-bit crypto/rand,写入新链路的 LoginResp 下发客户端,
	// 客户端从此用新 secret。如果生成失败(极罕见 / 熵源故障),保守地拒绝整个 takeover,
	// 而不是降级回旧 secret —— 安全优先。
	newSecret := generateTakeoverSecret()
	if newSecret == "" {
		unlockTakeover()
		logrus.WithFields(logrus.Fields{"remote": remote, "sid": sid}).Error("[takeover] 轮换 secret 失败(熵源故障?),拒绝接管")
		_ = writeLinkLoginResp(raw, 1, "takeover failed: server entropy", "")
		return
	}

	// invariant(U2, 2026-05-26):newConn 暴露给外部 goroutine 之前必须:
	//
	//   1) struct literal 构造完(下面这一坨);
	//   2) newConn.clientIPs.Store(&inheritedIPs)(下方 2453 行);
	//   3) 才能进 connections[cid] / connIDMap / connByUser* 三张 map(2483 / 2583 /
	//      2587 行)。
	//
	// 顺序破坏后果:外部 /status / route_advertise / cleanup 等通过 safeClientIPs()
	// 读 newConn 可能拿到 nil(因为 Store 还没跑),这条 takeover conn 的 vIP / TunChan
	// 临时不可见 — 不致命但 race-prone。Test 防线:TestSafeClientIPs_RaceRegression
	// 验 atomic 行为正确;此 invariant 靠人工 review 守护(没有自动 lint 能查到「
	// Store 必须在 map 注册之前」)。
	newConn := &Connection{
		connIDStr:      oldConn.connIDStr,
		userID:         oldConn.userID,
		linkConn:       raw,
		takeoverSecret: newSecret, // 新 secret,客户端将通过下方 LoginResp 收到
		loginToken:     loginReq.Token,
		tunnelDone:     make(chan struct{}),
		cleanupDone:    make(chan struct{}),
		createdAt:      time.Now(),
		// P0-4:takeover 继承 oldConn 上已经从 users 表读出来固化的 user-level
		// 字段,避免再查一次库;user.disable/reset-psk 想生效请通过 P0-1 踢线。
		exitAllowed:        oldConn.exitAllowed,
		bwUpBPS:            oldConn.bwUpBPS,
		bwDownBPS:          oldConn.bwDownBPS,
		maxSessionsAtLogin: oldConn.maxSessionsAtLogin,
		// 0011(2026-05-23):per-device 限速也继承,与上面 user-level 同语义 —
		// takeover 是「换底层链路、保业务身份」,任何限速维度都不应在切链路时被清零。
		deviceRateUpBPS:   oldConn.deviceRateUpBPS,
		deviceRateDownBPS: oldConn.deviceRateDownBPS,
		// P2#12:takeover 沿用 oldConn 的 deviceID(同 device 切链路场景);
		// authResult.Device 可用时优先(防御性,理论应与 old 一致)。
		deviceID: oldConn.deviceID,
		// takeover 保业务身份：设备名同 deviceID 一并继承，回显给客户端的名字切链路不变。
		deviceName: oldConn.deviceName,
		// P1-1(profile/credentials 解耦深扫)+ 第三轮深扫修正:
		// newConn.pskHashAtLogin 的语义应该是「**本次 login 实际使用的 PSK 的 hash**」
		// —— authenticatePSK 在本路径已成功,authResult.User.PSKHash 是 DB 当下真值,
		// 与客户端这次握手用的 PSK 等价。优先用它;authResult / User 为空时(理论
		// 不会到这一行,防御性 fallback)再退回 oldConn.pskHashAtLogin。
		//
		// 为什么不"继承 oldConn":如果 admin 在 oldConn 存续期间 reset_psk(oldConn
		// 的 hash 已陈旧,正等被 user_invalidate 扫到踢),takeover 客户端用新 PSK
		// 重连成功后,若继承 oldConn 旧 hash,**newConn 立刻又会被同周期扫到踢**
		// (hash != DB 当下 psk_hash) → 用户经历"踢-takeover-再被踢" 双重抖动。
		// 用 authResult.User.PSKHash 直接消除这个二次踢。
		//
		// 安全性不退步:authenticatePSK 已校验本次 PSK 与 DB 一致,等价于"DB 当下
		// hash"。哪怕 oldConn 没被踢、PSK 未变,authResult.User.PSKHash 与 oldConn.
		// pskHashAtLogin 也必然相等(同一个 DB 行 + 同一把 PSK)。
		pskHashAtLogin: func() string {
			if authResult != nil && authResult.User != nil && authResult.User.PSKHash != "" {
				return authResult.User.PSKHash
			}
			return oldConn.pskHashAtLogin
		}(),
		// 平台白名单踢线快照:takeover LoginReq 是客户端 base_login 的 clone,正常
		// 总带 platform(与 oldConn 相同);防御性兜底 —— 万一某版本客户端 takeover
		// 请求漏报 platform,继承 oldConn 快照,避免「已设白名单的合法会话」在热切换
		// 后因空 platform 被 user_invalidate 误踢。
		platformAtLogin: func() string {
			if loginReq.Platform != "" {
				return loginReq.Platform
			}
			return oldConn.platformAtLogin
		}(),
	}
	// S1(2026-05-26):clientIPs 是 atomic.Pointer 不能 struct literal,显式 Store。
	// takeover 路径继承 oldConn 已分配的 vIP 副本(inheritedIPs 在前面已 copy)。
	newConn.clientIPs.Store(&inheritedIPs)
	// exit-node(深扫第三轮 #1/#2):takeover = 「换底层链路、保业务身份」——出口会话态同 vIP/exitAllowed/deviceID 一样
	// **必须随接管过户**,否则:
	//   ① 选了出口的使用方:egressDeviceID 丢失(默认 0)→ 热切换后公网流量**静默改经 server 自出口**(违反零泄露 +
	//      「选了 C 就认 C」);
	//   ② 出口节点自己热切换:advertisedExit 丢失(默认 false)→ 不再被认作「在跑出口」,绑它的会话被 fail-closed 阻断 +
	//      从出口下拉消失(明明在线)。
	// 客户端在 lib 内部热切换(promote_to)只发 takeover LoginReq,**不重发** RouteAdvertise/EgressSelect,故只能服务端继承。
	// atomic 类型不能进 struct literal,显式 Store(与 clientIPs 同)。
	newConn.egressDeviceID.Store(oldConn.egressDeviceID.Load())
	newConn.advertisedExit.Store(oldConn.advertisedExit.Load())
	// v6 能力标同 advertisedExit 一并过户:热切换(promote_to)不重发 RouteAdvertise,若不继承则默认 false → 接管后
	// 一台**有 v6** 的出口会被误判为无 v6 → 对使用方公网 v6 错误回 ICMPv6 unreachable(v6 明明可用却被秒断回落 v4)。
	newConn.advertisedExitV6.Store(oldConn.advertisedExitV6.Load())
	// subnet route(SR-M4 深扫):子网路由器会话态同样必须随接管过户——热切换(promote_to)只发 takeover LoginReq、
	// **不重发** RouteAdvertise,若不继承则 newConn.advertisedSubnetRoutes 默认 false → 热切换后子网转发把它当「未装
	// NAT」整段丢弃黑洞(明明客户端 TUN/NAT 未拆、仍在服务),与 advertisedExit 同理。
	newConn.advertisedSubnetRoutes.Store(oldConn.advertisedSubnetRoutes.Load())
	// 同理:当前宣告 CIDR 集也随接管过户(热切换不重发 RouteAdvertise),否则 newConn 集为空 → 退回布尔放行,
	// 丢失收窄语义(虽不黑洞,但 per-CIDR 门控失效)。与 advertisedSubnetRoutes 布尔成对继承,保持二者一致。
	newConn.advertisedRoutes.Store(oldConn.advertisedRoutes.Load())
	if authResult != nil && authResult.Device != nil {
		newConn.deviceID = authResult.Device.ID
		newConn.deviceUUID = authResult.Device.DeviceUUID
		// 0011:authResult.Device 是 takeover 阶段最新查的 device 行,优先用它的
		// rate_*_bps 覆盖从 oldConn 继承的快照 — 否则 admin 在 oldConn 期间改了
		// device 限速,takeover 时机正好把旧值"复活",出现「人工降速,但 client
		// 换链路就解除」的奇怪现象。
		newConn.deviceRateUpBPS = authResult.Device.RateUploadBPS
		newConn.deviceRateDownBPS = authResult.Device.RateDownloadBPS
	} else {
		// 防御:authResult.Device 为 nil 时(老路径 / 测试 / device upsert 失败)
		// 沿用 oldConn 的 deviceUUID,保证 takeover 后新 conn 仍能被未来的 supersede
		// 逻辑正确匹配自己的下次重登。oldConn.deviceUUID 也可能为空,那就是空,无碍。
		newConn.deviceUUID = oldConn.deviceUUID
	}
	// G4: takeover audit。target 是被接管的 userID,actor 是发起 takeover 的 remote。
	if gw != nil && gw.store != nil {
		_ = gw.store.Audit(context.Background(), remote, "login.takeover", oldConn.userID, "sid="+sid)
	}

	// 分配独立的 conv_id（与老 conv_id 不冲突，让两个 conn 在 connections 表里互不干扰）
	connectionsMu.Lock()
	for {
		cid := gw.nextConvID.Add(1)
		if cid == 0 {
			continue
		}
		if _, exists := connections[cid]; !exists {
			newConn.connID = cid
			connections[cid] = newConn
			break
		}
	}
	connectionsMu.Unlock()

	// rollback 标志:成功路径会在「写 LoginResp + ConvSalt + close oldConn + 设置 takenOver」
	// 全部完成后置 false。任何中途 return / panic 都让 defer 自动回滚 newConn 在 connections
	// 表里的占位。
	rollbackNewConnNeeded := true
	rollbackNewConn := func() {
		connectionsMu.Lock()
		if cur, ok := connections[newConn.connID]; ok && cur == newConn {
			delete(connections, newConn.connID)
		}
		connectionsMu.Unlock()
	}
	defer func() {
		if rollbackNewConnNeeded {
			rollbackNewConn()
		}
	}()

	// 写 LoginResp + ConvSalt 到新链路；客户端收到后准备 promote。
	// 0011:takeover 路径同样走 effectiveLinkRates(device + settings + toml + user)。
	// 即便 oldConn 当年没 device-level 限速(老登录),takeover 时也会带上最新 db 状态。
	// 0012:burst 也同步读 settings。
	rateDefaults := storeRateDefaultsView{}
	if gw != nil && gw.store != nil {
		if d, err := gw.store.GetRateDefaults(context.Background()); err == nil {
			rateDefaults = storeRateDefaultsView{UploadBPS: d.UploadBPS, DownloadBPS: d.DownloadBPS, BurstBytes: d.BurstBytes}
		}
	}
	upRate, downRate := effectiveLinkRates(gw, loginReq.Platform,
		newConn.deviceRateUpBPS, newConn.deviceRateDownBPS, rateDefaults)
	// P0-4:user-level bw 叠加,避免「换链路就解除限速」。
	upRate = minPositiveBPS(upRate, newConn.bwUpBPS)
	downRate = minPositiveBPS(downRate, newConn.bwDownBPS)
	burstBytes := effectiveBurst(rateDefaults.BurstBytes)
	var uploadLimiter, downloadLimiter *rate.Limiter
	if upRate > 0 {
		uploadLimiter = rate.NewLimiter(rate.Limit(upRate), burstBytes)
	}
	if downRate > 0 {
		downloadLimiter = rate.NewLimiter(rate.Limit(downRate), burstBytes)
	}
	rwCtx := globalContext
	if rwCtx == nil {
		rwCtx = context.Background()
	}
	rwc := newRateLimitedConn(raw, uploadLimiter, downloadLimiter, rwCtx)
	// newConn 还没暴露给其它 goroutine(还没进 connIDMap),理论上不需要 lock;
	// 但为了保持「写 linkConn 一律持 linkWrMu」这一不变量,顺手锁一下,日后改路径不出 race。
	newConn.linkWrMu.Lock()
	newConn.linkConn = rwc
	newConn.rlConn.Store(rwc) // 0011 /rate/refresh 用
	newConn.linkWrMu.Unlock()

	if err := writeLinkLoginRespFull(rwc, 0, "takeover ok", newConn.userID, newConn.connIDStr, newConn.takeoverSecret); err != nil {
		logrus.WithFields(logrus.Fields{"remote": remote, "sid": sid}).WithError(err).Warn("[takeover] 写 LoginResp 失败，回滚")
		unlockTakeover()
		return
	}

	dnsV4 := util.SanitizeDNSServersV4(gw.cfg.TUN.DNSServersV4)
	var dnsV6 []string
	if sharedTUNGatewayV6 != "" {
		// 与登录路径同语义:server 无 v6 公网出网时剔除公网 v6 解析器(见 egress_select.go)。
		dnsV6 = dnsV6ServersForClient(util.SanitizeDNSServersV6(gw.cfg.TUN.DNSServersV6))
	}
	if extra := magicDNSExtraDNS(gw, gatewayAddrFromCIDR(sharedTUNGateway)); extra != "" {
		dnsV4 = append([]string{extra}, dnsV4...)
	}
	// S1(2026-05-26):takeover 路径 newConn.clientIPs 已 Store(line ~2438),Load 必非 nil。
	saltBody, err := util.MarshalConvSaltLiteJSON(newConn.safeClientIPs(), dnsV4, dnsV6, magicDNSSuffixForClient(gw), newConn.deviceName)
	if err != nil {
		logrus.WithFields(logrus.Fields{"remote": remote, "sid": sid}).WithError(err).Warn("[takeover] 构造 ConvSaltLite 失败，回滚")
		unlockTakeover()
		return
	}
	newConn.linkWrMu.Lock()
	err = util.WriteLinkFrame(rwc, util.LinkTypeConvSaltMsg, saltBody)
	newConn.linkWrMu.Unlock()
	if err != nil {
		logrus.WithFields(logrus.Fields{"remote": remote, "sid": sid}).WithError(err).Warn("[takeover] 下发 ConvSaltLite 失败，回滚")
		unlockTakeover()
		return
	}

	// best-effort 通知老链路：发 LinkTypeTakenOver 后客户端将不会触发 on_disconnected。
	takenOverBody, mErr := util.MarshalTakenOverJSON(oldConn.connIDStr, loginReq.Transport)
	if mErr == nil {
		oldConn.linkWrMu.Lock()
		// 深扫第六轮 MED:给这个「best-effort」通知钉 1s 写超时。它写的是**老链路**(takeover 常因老链路变差才触发),
		// 无超时则发送缓冲满时会**无限阻塞**,卡住其后的 connIDMap 切换 / takenOver 置位 / 关老链路 / 起 newConn,且全程
		// 持 takeoverMu —— 期间 connByDevice 仍解析到老 conn(newConn 未入表、advertisedExit 仍在),出口流量会被灌进
		// 已死老链路黑洞。对齐 kick/shutdown 的 1s(非必要通知,路径必须保持推进)。inline 复位(此段非 defer 作用域)。
		if dl, ok := oldConn.linkConn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = dl.SetWriteDeadline(time.Now().Add(1 * time.Second))
		}
		_ = util.WriteLinkFrame(oldConn.linkConn, util.LinkTypeTakenOver, takenOverBody)
		if dl, ok := oldConn.linkConn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = dl.SetWriteDeadline(time.Time{})
		}
		oldConn.linkWrMu.Unlock()
	}

	// 关键时刻：set takenOver=true 后老 conn 的 cleanupConnection 跳过 vip / SessionRelease 清理；
	// 同时覆盖 connIDMap，让任何后续 takeover 都看到 newConn。
	oldConn.takenOver.Store(true)
	connIDMapMu.Lock()
	connIDMap[newConn.connIDStr] = newConn
	// P3-a:by-user 索引同步切换 —— 先移除 oldConn(它已 takenOver,不会再被 evict),
	// 再加 newConn。两步在同一锁段内,evict/扫描不会观察到中间态。
	connByUserDeleteLocked(oldConn)
	connByUserAddLocked(newConn)
	// exit-node:by-device 索引随接管切换(先删 old 再加 new,同一锁段)。
	connByDeviceDeleteLocked(oldConn)
	connByDeviceAddLocked(newConn)
	connIDMapMu.Unlock()

	// H2(B3): 接管转移已完成(newConn 进 connIDMap + oldConn.takenOver=true),
	// 后续 close + tunnelDone 等待都是清理 oldConn 而非取消接管。从这里开始,
	// newConn 的生命周期由 cleanupConnection 接管,rollback 不能再删
	// connections[newConn.connID](会让 newConn 凭空消失)。
	// 深扫第八轮 MED:cleanup defer 必须**在这里**注册,而不是 runLinkTunnel 之前 ——
	// 否则「maps 已切换 → 注册 defer」之间(关老链路、等 tunnelDone 5s、日志等)一旦
	// panic,newConn 已入四张表却无人清理,成为永久僵尸(vIP 占用 + 设备重登异常)。
	rollbackNewConnNeeded = false
	defer cleanupConnection(newConn)

	// 关老 link → 老 readLoop EOF → 老 demux 退出 → close oldConn.tunnelDone。
	// 持 oldConn.linkWrMu 是为了与 kick goroutine 读 c.linkConn 串行化,避免 race。
	oldConn.linkWrMu.Lock()
	if oldConn.linkConn != nil {
		_ = oldConn.linkConn.Close()
	}
	oldConn.linkWrMu.Unlock()

	if oldConn.tunnelDone != nil {
		select {
		case <-oldConn.tunnelDone:
		case <-time.After(5 * time.Second):
			logrus.WithFields(logrus.Fields{
				"remote": remote, "sid": sid,
			}).Warn("[takeover] 老链路 5s 内未退出 runLinkTunnel；继续启动新 demux（最坏后果：IP 包短暂乱序）")
		}
	}

	unlockTakeover()

	logrus.WithFields(logrus.Fields{
		"remote":     remote,
		"sid":        sid,
		"old_convid": oldConn.connID,
		"new_convid": newConn.connID,
		"transport":  loginReq.Transport,
	}).Info("[takeover] 接管成功，进入新链路 runLinkTunnel")

	// 深扫第四轮 B:闭合「撤销恰好撞上接管」的窄竞态。若 newConn 继承了出口绑定(egressDeviceID!=0):接管已落定
	// (newConn 已入 connIDMap + oldConn 已 takenOver)后异步补一次复核——继承来的出口此刻若已被 admin 撤销,而撤销侧
	// 的 revalidateExitBindings 可能只扫到尚未 takenOver 的 oldConn、把 CAS 落在已死的 oldConn 而漏掉 newConn,这里
	// 补扫把 newConn 重置回 server 自出口 + 通知客户端。幂等且不误撤销(approved/DB 查不动都保留),仅有出口绑定才触发。
	if newConn.egressDeviceID.Load() != 0 {
		go revalidateExitBindings(context.Background())
	}

	tunnelCtx := globalContext
	if tunnelCtx == nil {
		tunnelCtx = context.Background()
	}
	runLinkTunnel(tunnelCtx, rwc, newConn, remote)
}
