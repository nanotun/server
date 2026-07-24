package main

// FRP 式反向端口转发管理器（server 侧发布 mesh 服务到公网端口）。
//
// 语义：外部公网客户端连 server 的 public_port（TCP）→ server 把连接转发到 mesh 节点自身端口（node 目标：
// target_ip = 设备 vIP）或其 LAN 后设备（LAN 目标：target_ip = LAN IP，须在该设备已批准宣告网段内）。
//
// 转发走 **server 自身内核经 TUN**：`net.Dial(target)` 复用 OS TCP 栈（io.Copy 代理），无需在 server 上写用户态
// TCP 栈：
//   - node 目标（vIP，在 mesh 网段内）：TUN 网关是 /16，vIP on-link → 内核直接把 SYN 写进 TUN → demux 按 vIP
//     投给节点会话；回程 节点→网关→readLoop→tunWriteChan→TUN→socket。零额外内核路由。
//   - LAN 目标（非 mesh 网段）：给 target_ip 装一条 /32(/128) 主机路由 `dev <tun>`，让 net.Dial 出 TUN；TUN demux
//     未命中 vIP 时由 forwardServerOriginatedToSubnet 投给子网宣告方（其本机 NAT 进 LAN）；回程经宣告方 rev-NAT →
//     网关 → readLoop → TUN → socket（内核 conntrack + 该 /32 路由满足 rp_filter）。
//
// 映射存 SQLite（store.PortForward，见 store/port_forwards.go），由 web 后台增删；增删后经 control-socket
// /reload?what=portforward 调 reloadPortForwards 实时启停监听。公网开放（frp 模型）：被转发服务自身负责鉴权。
//
// 防火墙：起监听时**自动**在 iptables/ip6tables 的 INPUT 首位放行该公网端口（`-I INPUT 1 ... -j ACCEPT`，带
// nanotun_pf comment），停监听时收回；启动时清理崩溃残留。默认 INPUT DROP + UFW 的机器上这是外部可达的前提，
// 管理员无需手动 ufw allow。best-effort：iptables 不可用时只 Warn、不阻断监听。

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nanotun/server/store"

	"github.com/sirupsen/logrus"
)

// 运行参数（本特性内自洽，暂不上配置文件）：
const (
	// maxConnsPerPortForward：单条公网映射的最大在途连接数。公网开放监听下无鉴权、每连接一对
	// goroutine + fd + 一条 mesh 拨号，无上限会被恶意大量半开连接拖垮（fd/goroutine 耗尽）。超限的新连接
	// 直接关闭（fail-close），已有连接不受影响。512 对单个 frp 式服务足够，异常流量则被挡在此闸。
	maxConnsPerPortForward = 512
	// portForwardKeepAlive：对入站/出站两端都开 TCP keepalive 的探测周期。用于**回收半开死连接**
	// （对端崩溃未发 FIN/RST）而不误杀「活着但空闲」的会话（如挂机 SSH），比一刀切 idle deadline 更稳。
	portForwardKeepAlive = 30 * time.Second
	// vipCacheTTL：node 目标「UUID→当前 vIP」解析的缓存有效期。连接建立不算高频，2s 足以在连接风暴下
	// 挡住重复 DB 查询，又能及时跟上 lease 漂移。
	vipCacheTTL = 2 * time.Second
)

// pfState：一条映射当前的运行态（供 web 后台展示，让「配置了但没真正生效」可见）。
type pfState string

const (
	pfStateListening   pfState = "listening"      // 监听已建立、正常转发
	pfStateBindFailed  pfState = "bind_failed"    // net.Listen 失败（端口被占用等）→ 外部连不上
	pfStateRouteFailed pfState = "route_degraded" // 监听 OK 但 LAN 目标主机路由没装上 → LAN 目标可能不可达
)

// portForwardStatus：单条映射运行态快照（control-socket /portforward/status 下发给 web）。
type portForwardStatus struct {
	PublicPort int     `json:"public_port"`
	Target     string  `json:"target"` // 配置的 target_ip:port（node 目标运行时可能改拨最新 vIP，此处仍示配置值）
	DeviceUUID string  `json:"device_uuid"`
	LAN        bool    `json:"lan"` // 是否 LAN 目标（装了 /32 主机路由）
	State      pfState `json:"state"`
	Err        string  `json:"err,omitempty"`
}

// portForwardEntry：一条活跃监听的运行态。
type portForwardEntry struct {
	pf             store.PortForward
	listener       net.Listener
	cancel         context.CancelFunc // 停这条监听：关 accept 循环 + 关所有在途连接
	lanRoute       bool               // 是否为该 target_ip 装了 /32(/128) 主机路由（停时按引用计数决定是否删）
	lanRouteFailed bool               // LAN 主机路由装失败（监听仍在，但 LAN 目标可能不可达）→ 运行态标 route_degraded
	sem            chan struct{}      // 并发连接闸（容量 = maxConnsPerPortForward），超限的新连接直接关闭
}

// portForwardManager：管理所有活跃的公网端口监听 + LAN 目标主机路由。
type portForwardManager struct {
	gw     *gatewayState
	tunDev string       // TUN 设备名（LAN 目标装主机路由用）
	meshV4 netip.Prefix // mesh v4 网段（判 target 是 vIP 还是 LAN）
	meshV6 netip.Prefix // mesh v6 网段

	// reloadMu：串行化整个 reload / stopAll（rebuildFRPTargetTable + 监听增删 + 全部阻塞 I/O）。**先于** mu 获取。
	// 两个作用：① 让每次 reload 端到端原子——避免并发 reload（admin 连续增删各触发一次 best-effort reload）把
	// frpTargetTable 的发布与监听态的应用交错（精确表反映旧快照、监听反映新快照）；② 使 reload/stopAll 序列**独占**
	// routeRef，故引用计数无需再持 mu。所有 DB / iptables / ip route / net.Listen 都在 reloadMu 下、mu 之外做。
	reloadMu sync.Mutex

	// mu：只护 active/status 两张 map，且**只在写入那一瞬**短锁（阻塞 I/O 一律放锁外，见 startEntry/stopEntry）。
	// 读者（portForwardStatusSnapshot 读 status、reloadPortForwards 读 len(active)）因此不会被 iptables 慢命令拖住。
	// routeRef 不由 mu 保护（见 reloadMu）。
	mu       sync.Mutex
	active   map[int]*portForwardEntry  // public_port → entry（mu）
	routeRef map[string]int             // 已装主机路由的 target_ip → 引用计数（reloadMu 独占；多映射共用同一 LAN IP 时不早删）
	status   map[int]*portForwardStatus // public_port → 运行态快照（mu；含 bind_failed 等未进 active 的失败态）

	// node 目标「UUID→当前 vIP」解析缓存（拨号时用；与 mu 分开，避免连接建立与 reload 争锁）。
	vipCacheMu sync.Mutex
	vipCache   map[string]vipCacheEntry
}

// vipCacheEntry：一台设备当前 vIP 的缓存值（fixed 优先、其次 lease，解析时按地址族取）。
type vipCacheEntry struct {
	v4, v6 string
	at     time.Time
}

// portForwardMgr 进程级单例（control-socket reload / status 与 main 共用）。nil = 未启用/未初始化。
// 用 atomic.Pointer 而非裸指针：main goroutine 写、control-socket goroutine 读，避免数据竞争（-race）。
var portForwardMgr atomic.Pointer[portForwardManager]

// frpTargetTable：FRP **LAN 目标 IP → 映射指定的宣告方 deviceID** 精确路由表（原子快照，demux 热路径只读）。
//
// 修 #5：LAN 目标包从 TUN 读回后在 demux 未命中任何 vIP，原先只能按 dst **子网**猜宣告方
// （lookupSubnetRoute，重叠网段取最小 deviceID）——校验绑定的是「你选的那台设备」，数据面却可能投给**另一台**
// 同网段宣告方。此表由端口转发管理器在 reload 时按每条映射的 target_device_uuid 解析出 deviceID 建立，让 demux
// **按映射指定的设备**精确投递，压过按子网猜测。node 目标（vIP）不入表（走正常 vIP demux）。
// nil = 未构建 / 无 LAN 映射。
var frpTargetTable atomic.Pointer[map[netip.Addr]int64]

// lookupFRPTarget 查 dst 是否为某条 FRP 映射**明确指向**的 LAN 目标，返回该映射指定的宣告方 deviceID。
// 只读 atomic 快照、无锁、无 DB。(0,false)=非 FRP 明确目标（demux 兜底回落到 lookupSubnetRoute）。
func lookupFRPTarget(dst netip.Addr) (int64, bool) {
	m := frpTargetTable.Load()
	if m == nil {
		return 0, false
	}
	dev, ok := (*m)[dst.Unmap()]
	return dev, ok
}

// startPortForwardManager 启动 FRP 端口转发管理器：加载 enabled 映射、起监听。返回 cleanup（停所有监听 + 删路由）。
// gw.store 为 nil（测试）时 no-op。
func startPortForwardManager(gw *gatewayState, tunDev string) func() {
	if gw == nil || gw.store == nil {
		return func() {}
	}
	m := &portForwardManager{
		gw:       gw,
		tunDev:   tunDev,
		active:   make(map[int]*portForwardEntry),
		routeRef: make(map[string]int),
		status:   make(map[int]*portForwardStatus),
		vipCache: make(map[string]vipCacheEntry),
	}
	if p, err := netip.ParsePrefix(sharedTUNGateway); err == nil {
		m.meshV4 = p.Masked()
	}
	if sharedTUNGatewayV6 != "" {
		if p, err := netip.ParsePrefix(sharedTUNGatewayV6); err == nil {
			m.meshV6 = p.Masked()
		}
	}
	// 启动时先清掉上次进程崩溃残留的本特性放行规则（对应端口现已不再映射的），再由 reload 为当前映射重新放行。
	flushStalePortForwardFirewallRules()
	portForwardMgr.Store(m)
	m.reload(context.Background())
	return func() { m.stopAll() }
}

// reloadPortForwards 供 control-socket /reload?what=portforward 调：按最新 DB 映射启停监听。返回当前活跃监听数。
// 管理器未启用返回 0。
func reloadPortForwards(ctx context.Context) int {
	m := portForwardMgr.Load()
	if m == nil {
		return 0
	}
	// reload 的 DB 查询 + 精确表构建**不应**受控制端 HTTP 请求生命周期左右：映射的 DB 写已提交，即便调用方（web
	// best-effort reload，5s 超时）已放弃/断连，server 也必须把监听与 frpTargetTable 收敛到最新态。若沿用会被取消
	// 的请求 ctx，rebuildFRPTargetTable 的 per-row resolveDeviceID 会中途失败 → 发布**残缺**精确表（部分 LAN 目标
	// 退回子网猜测，#5 回归）。故切断取消传播（保留原 ctx 的 value），另给足量超时预算兜底。
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	m.reload(rctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}

// portForwardStatusSnapshot 返回所有映射的当前运行态（供 control-socket /portforward/status 下发给 web）。
// 管理器未启用返回 nil。
func portForwardStatusSnapshot() []portForwardStatus {
	m := portForwardMgr.Load()
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]portForwardStatus, 0, len(m.status))
	for _, st := range m.status {
		out = append(out, *st)
	}
	return out
}

// isLANTarget 判断 target_ip 是否为「节点 LAN 后设备」（不在 mesh 网段 = 需装主机路由才能经 TUN 到达）。
// 解析失败保守当作 LAN（装路由更安全，最坏多一条精确 /32）。mesh vIP（在网段内）返回 false。
func (m *portForwardManager) isLANTarget(ip netip.Addr) bool {
	if ip.Is4() || ip.Is4In6() {
		return !(m.meshV4.IsValid() && m.meshV4.Contains(ip.Unmap()))
	}
	return !(m.meshV6.IsValid() && m.meshV6.Contains(ip))
}

// rebuildFRPTargetTable 从 enabled 映射重建「LAN 目标 IP → 指定宣告方 deviceID」精确路由表并原子发布（修 #5）。
// 只收 LAN 目标（node 目标走 vIP demux，不入表）。UUID 解析不出 deviceID（设备未注册/被删）的行跳过 —— 该 dst 的
// 包会在 demux 里回落到 lookupSubnetRoute 兜底。同一 LAN IP 被两条映射指向不同设备（歧义，web 校验应已拦）→ 保留
// 先见者 + Warn，保证确定性。
func (m *portForwardManager) rebuildFRPTargetTable(ctx context.Context, rows []store.PortForward) {
	tbl := make(map[netip.Addr]int64)
	for _, pf := range rows {
		addr, err := netip.ParseAddr(pf.TargetIP)
		if err != nil || !m.isLANTarget(addr) {
			continue
		}
		dev, ok := m.resolveDeviceID(ctx, pf.TargetDeviceUUID)
		if !ok {
			logrus.WithFields(logrus.Fields{"target_ip": pf.TargetIP, "device_uuid": pf.TargetDeviceUUID}).
				Warn("[port-forward] LAN 目标设备 UUID 解析不到 deviceID，本条不进精确路由表（回落按子网解析）")
			continue
		}
		key := addr.Unmap()
		if existing, dup := tbl[key]; dup && existing != dev {
			logrus.WithFields(logrus.Fields{"target_ip": pf.TargetIP, "kept_device": existing, "ignored_device": dev}).
				Warn("[port-forward] 同一 LAN 目标 IP 被指向不同设备（歧义），忽略后者；请删除冲突映射")
			continue
		}
		tbl[key] = dev
	}
	frpTargetTable.Store(&tbl)
}

// resolveDeviceID 按 UUID 解析 deviceID（供精确路由表构建）。低频（reload 时）直接查库，不缓存。
func (m *portForwardManager) resolveDeviceID(ctx context.Context, uuid string) (int64, bool) {
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	if uuid == "" || m.gw == nil || m.gw.store == nil {
		return 0, false
	}
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dev, err := m.gw.store.GetDeviceByUUIDAny(qctx, uuid)
	if err != nil || dev == nil {
		return 0, false
	}
	return dev.ID, true
}

// reload 按最新 enabled 映射对齐监听：停掉已删/已改的，起新的。
//
// 锁策略（修 Finding C：阻塞式 I/O 不占 m.mu）：reloadMu 串行化整个函数（rebuild + 监听增删），保证并发 reload
// 下 frpTargetTable 与监听态一致发布，并使本函数**独占** routeRef 与 start/stop 序列（故路由计数无需再持 m.mu）。
// 分三段：
//
//	① 决策（短锁 m.mu）：只读 active 算出「停哪些、起哪些」，不做任何 I/O、不改 map；
//	② 执行（**不持 m.mu**）：真正的阻塞操作（关 listener / iptables / ip route / net.Listen）在锁外做，stop/start
//	   只在写 active/status 那一瞬各自短锁 m.mu —— 于是 portForwardStatusSnapshot / reloadPortForwards 的计数
//	   不再被 iptables 慢命令拖住；
//	③ 清理（短锁 m.mu）：删掉「已不再期望」端口的残留运行态（bind_failed 等未进 active 的）。
func (m *portForwardManager) reload(ctx context.Context) {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	rows, err := m.gw.store.ListEnabledPortForwards(ctx)
	if err != nil {
		logrus.WithError(err).Warn("[port-forward] 读取映射失败，保留现有监听（不改动）")
		return
	}
	desired := make(map[int]store.PortForward, len(rows))
	for _, pf := range rows {
		desired[pf.PublicPort] = pf
	}

	// 重建 FRP LAN 目标 → 指定设备 的精确路由表（修 #5）。需 store 查询（UUID→deviceID），锁外做。
	m.rebuildFRPTargetTable(ctx, rows)

	// ① 决策：短锁只读 active，算出待停/待起（不做 I/O、不改 map）。
	m.mu.Lock()
	var toStop []*portForwardEntry
	stopPorts := make(map[int]bool)
	for port, ent := range m.active {
		d, ok := desired[port]
		if !ok || !samePortForward(ent.pf, d) {
			toStop = append(toStop, ent)
			stopPorts[port] = true
		}
	}
	var toStart []store.PortForward
	for port, pf := range desired {
		_, active := m.active[port]
		// 需起的：当前不在 active，或在 active 但已被判定要停（目标/协议变了 → 停旧起新）。含上次 bind_failed
		// （不在 active）本次仍期望的端口 —— 会被重试。
		if !active || stopPorts[port] {
			toStart = append(toStart, pf)
		}
	}
	m.mu.Unlock()

	// ② 执行：锁外做阻塞 I/O。先停后起（同一 public_port 停旧释放后再 net.Listen 起新，端口可复用）。
	for _, ent := range toStop {
		m.stopEntry(ent)
	}
	for _, pf := range toStart {
		m.startEntry(pf)
	}

	// ③ 清理：短锁删掉「已不再期望」端口的残留运行态。
	m.mu.Lock()
	for port := range m.status {
		if _, ok := desired[port]; !ok {
			delete(m.status, port)
		}
	}
	m.mu.Unlock()
}

// samePortForward 判断两条映射是否等价（不影响监听/目标即视为同一条，避免无谓重启）。public_port 已作 map key。
func samePortForward(a, b store.PortForward) bool {
	return a.Proto == b.Proto &&
		a.TargetDeviceUUID == b.TargetDeviceUUID &&
		a.TargetIP == b.TargetIP &&
		a.TargetPort == b.TargetPort
}

// setStatusLocked 记录一条映射的运行态（调用方持 m.mu）。target 传配置值即可。
func (m *portForwardManager) setStatusLocked(pf store.PortForward, lan bool, state pfState, errMsg string) {
	m.status[pf.PublicPort] = &portForwardStatus{
		PublicPort: pf.PublicPort,
		Target:     net.JoinHostPort(pf.TargetIP, strconv.Itoa(pf.TargetPort)),
		DeviceUUID: pf.TargetDeviceUUID,
		LAN:        lan,
		State:      state,
		Err:        errMsg,
	}
}

// setStatus 同 setStatusLocked，但自持短锁 m.mu（供 startEntry 的失败早退路径用——此时未持 m.mu）。
func (m *portForwardManager) setStatus(pf store.PortForward, lan bool, state pfState, errMsg string) {
	m.mu.Lock()
	m.setStatusLocked(pf, lan, state, errMsg)
	m.mu.Unlock()
}

// startEntry 起一条监听。调用方持 reloadMu、**不持 m.mu**：阻塞式 I/O（addRoute 的 ip route、net.Listen、
// openFirewallPort 的 iptables）在锁外做，仅在写 active/status 那一瞬短锁 m.mu。失败只 log + 回滚路由 + 记
// bind_failed 运行态，不影响其它映射。
func (m *portForwardManager) startEntry(pf store.PortForward) {
	targetAddr, err := netip.ParseAddr(pf.TargetIP)
	if err != nil {
		logrus.WithError(err).WithField("target_ip", pf.TargetIP).Warn("[port-forward] target_ip 非法，跳过")
		m.setStatus(pf, false, pfStateBindFailed, "target_ip 非法: "+err.Error())
		return
	}
	lan := m.isLANTarget(targetAddr)
	routeFailed := false
	if lan {
		routeFailed = !m.addRoute(targetAddr) // I/O：ip route（routeRef 由 reloadMu 独占）
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", pf.PublicPort)) // I/O：可能阻塞
	if err != nil {
		logrus.WithError(err).WithField("public_port", pf.PublicPort).Warn("[port-forward] 监听公网端口失败（端口占用？）")
		if lan {
			m.delRoute(targetAddr)
		}
		m.setStatus(pf, lan, pfStateBindFailed, "监听失败: "+err.Error())
		return
	}
	// 自动在防火墙放行该公网端口（默认 INPUT DROP + UFW 的机器上，这是外部可达的前提）。best-effort，失败不阻断监听。
	openFirewallPort(pf.PublicPort) // I/O：iptables
	ctx, cancel := context.WithCancel(globalContext)
	ent := &portForwardEntry{
		pf:             pf,
		listener:       ln,
		cancel:         cancel,
		lanRoute:       lan,
		lanRouteFailed: routeFailed,
		sem:            make(chan struct{}, maxConnsPerPortForward),
	}
	state := pfStateListening
	errMsg := ""
	if routeFailed {
		state = pfStateRouteFailed
		errMsg = "LAN 目标主机路由未装上（LAN 目标可能不可达）"
	}
	// 仅 map 写入用短锁：I/O 均已在锁外完成。
	m.mu.Lock()
	m.active[pf.PublicPort] = ent
	m.setStatusLocked(pf, lan, state, errMsg)
	m.mu.Unlock()

	name := "portForwardAccept:" + strconv.Itoa(pf.PublicPort)
	// 用 safeGoroutine（隔离恢复）而非 safeGlobalGoroutine：单条端口转发 accept 循环即便 panic，也只该挂掉这一条
	// 监听，绝不触发 globalContextCancel 拖垮整个 VPN server（其它映射 + 所有在线用户）。defer 关 listener：任何原因
	// 退出（含 panic 被 safeGoroutine 兜住）时都收掉 listener，避免留下「listener 开着却无人 accept」的悬挂端口
	// （新连接进内核 backlog 看似 hang）——改为 connection refused，语义更清晰。正常停止路径由 stopEntry 关，
	// 这里重复 Close 无害。
	go safeGoroutine(name, func() {
		defer func() { _ = ln.Close() }()
		acceptPortForward(ctx, ln, m, pf, ent.sem)
	})
	logrus.WithFields(logrus.Fields{
		"public_port": pf.PublicPort,
		"target":      net.JoinHostPort(pf.TargetIP, strconv.Itoa(pf.TargetPort)),
		"device_uuid": pf.TargetDeviceUUID,
		"lan_target":  lan,
	}).Info("[port-forward] 已启动公网端口转发监听")
}

// stopEntry 停一条监听：cancel（关 accept + 在途连接）+ 关 listener + 收防火墙 + 按引用计数删主机路由（均为
// 锁外 I/O），最后在短锁 m.mu 里从 active/status 摘除。调用方持 reloadMu、**不持 m.mu**。
func (m *portForwardManager) stopEntry(ent *portForwardEntry) {
	if ent == nil {
		return
	}
	ent.cancel()                         // 关 accept 循环 + 在途连接（非阻塞）
	_ = ent.listener.Close()             // I/O
	closeFirewallPort(ent.pf.PublicPort) // I/O：iptables，收回自动放行
	if ent.lanRoute {
		if a, err := netip.ParseAddr(ent.pf.TargetIP); err == nil {
			m.delRoute(a) // I/O：ip route（routeRef 由 reloadMu 独占）
		}
	}
	m.mu.Lock()
	delete(m.active, ent.pf.PublicPort)
	delete(m.status, ent.pf.PublicPort)
	m.mu.Unlock()
	logrus.WithField("public_port", ent.pf.PublicPort).Info("[port-forward] 已停止公网端口转发监听")
}

// stopAll 停所有监听（cleanup 用）。持 reloadMu 串行化（与 reload 互斥、独占 routeRef），短锁快照 active 后锁外逐个停。
func (m *portForwardManager) stopAll() {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	m.mu.Lock()
	ents := make([]*portForwardEntry, 0, len(m.active))
	for _, ent := range m.active {
		ents = append(ents, ent)
	}
	m.mu.Unlock()
	for _, ent := range ents {
		m.stopEntry(ent) // 内部短锁 m.mu 摘除 active/status
	}
}

// addRoute 给 LAN 目标 IP 装一条 /32(/128) 主机路由 `dev <tun>`（引用计数，首个才真装）。调用方持 reloadMu
// （routeRef 由本序列独占，无需 m.mu）。返回 true = 路由已就位（新装成功 / 已存在 / 被别的映射先装了）；
// false = 装失败（LAN 目标可能不可达）。
func (m *portForwardManager) addRoute(ip netip.Addr) bool {
	key := ip.String()
	if m.routeRef[key] > 0 {
		m.routeRef[key]++
		return true // 已被别的映射装过，视为就位
	}
	ok := true
	if err := hostRouteCmd("add", ip, m.tunDev); err != nil {
		// 「已存在」不算失败（幂等）：进程重启 / 手工装过时 `ip route add` 会报 File exists，路由其实是好的。
		if strings.Contains(strings.ToLower(err.Error()), "exists") {
			logrus.WithField("ip", key).Debug("[port-forward] LAN 目标主机路由已存在（视为就位）")
		} else {
			logrus.WithError(err).WithField("ip", key).Warn("[port-forward] 装 LAN 目标主机路由失败（LAN 目标可能不可达）")
			ok = false
		}
		// 仍记引用计数，停时对称清理；失败不阻断监听。
	}
	m.routeRef[key] = 1
	return ok
}

// delRoute 解引用主机路由，降到 0 才真删。调用方持 reloadMu（routeRef 由本序列独占，无需 m.mu）。
func (m *portForwardManager) delRoute(ip netip.Addr) {
	key := ip.String()
	n := m.routeRef[key]
	if n <= 1 {
		delete(m.routeRef, key)
		if err := hostRouteCmd("del", ip, m.tunDev); err != nil {
			logrus.WithError(err).WithField("ip", key).Debug("[port-forward] 删 LAN 目标主机路由失败（可能已不存在）")
		}
		return
	}
	m.routeRef[key] = n - 1
}

// hostRouteCmd 执行 `ip [-6] route add|del <ip>/32(/128) dev <tun>`。
func hostRouteCmd(op string, ip netip.Addr, dev string) error {
	if dev == "" {
		return fmt.Errorf("empty tun dev")
	}
	var cidr string
	args := []string{"route", op}
	if ip.Is4() || ip.Is4In6() {
		cidr = ip.Unmap().String() + "/32"
	} else {
		cidr = ip.String() + "/128"
		args = append([]string{"-6"}, args...)
	}
	args = append(args, cidr, "dev", dev)
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %v (%s)", args, err, string(out))
	}
	return nil
}

// portForwardFirewallComment 标记本特性装的 INPUT 放行规则，便于识别 / 清理（不误伤其它规则）。
const portForwardFirewallComment = "nanotun_pf"

// firewallRuleArgs 构造一条 INPUT 放行某 TCP dport 的 iptables 参数。op = "-I"（插到首位，确保在 ufw/默认 DROP 之前）
// 或 "-D"（删）。
func firewallRuleArgs(op string, port int) []string {
	args := []string{op, "INPUT"}
	if op == "-I" {
		args = append(args, "1")
	}
	return append(args, "-p", "tcp", "--dport", strconv.Itoa(port),
		"-m", "comment", "--comment", portForwardFirewallComment, "-j", "ACCEPT")
}

// delFirewallRuleAll 反复删同一条规则直到不再匹配（清掉可能的重复），best-effort。
func delFirewallRuleAll(bin string, port int) {
	for i := 0; i < 8; i++ {
		if err := exec.Command(bin, firewallRuleArgs("-D", port)...).Run(); err != nil {
			return // 没有更多匹配规则
		}
	}
}

// openFirewallPort 放行公网端口（iptables v4 + ip6tables v6）。先删净再插首位（幂等，防重复累积）。best-effort：
// 失败只 Warn，不阻断监听（也许 iptables 不可用 / 无 v6）。默认 INPUT DROP + UFW 的机器上，这一步是外部可达的前提。
func openFirewallPort(port int) {
	for _, bin := range []string{"iptables", "ip6tables"} {
		delFirewallRuleAll(bin, port)
		if out, err := exec.Command(bin, firewallRuleArgs("-I", port)...).CombinedOutput(); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{"bin": bin, "port": port, "out": strings.TrimSpace(string(out))}).
				Warn("[port-forward] 放行公网端口失败（外部可能连不上，请手动放行或检查 iptables）")
		}
	}
}

// closeFirewallPort 收回放行（best-effort，忽略不存在）。
func closeFirewallPort(port int) {
	for _, bin := range []string{"iptables", "ip6tables"} {
		delFirewallRuleAll(bin, port)
	}
}

// flushStalePortForwardFirewallRules 启动时清理**崩溃残留**的本特性放行规则（上次进程未优雅退出时留下的、
// 对应端口现已不再映射的 ACCEPT）。解析 `iptables -S INPUT` 里带本特性 comment 的 `-A` 行、取出其 --dport，再用
// **规范化参数**（firewallRuleArgs）逐个 -D 删除。best-effort：解析/删除失败忽略。之后 reload 会为**当前**映射重放行。
//
// 为什么不直接把 `-A` 行改 `-D` 回灌：不同 iptables 版本 `-S` 对 comment 的渲染不一（`--comment nanotun_pf` vs
// 带引号的 `--comment "nanotun_pf"`）。按空白 split 再回灌会把带引号的 comment 当成字面含引号的 token，`-D` 匹配不上
// → 陈旧规则删不掉。改为「解析出端口 → 用与添加时一致的规范参数删」，对两种渲染都稳。
func flushStalePortForwardFirewallRules() {
	for _, bin := range []string{"iptables", "ip6tables"} {
		out, err := exec.Command(bin, "-S", "INPUT").Output()
		if err != nil {
			continue
		}
		for _, port := range parseStalePortForwardPorts(string(out)) {
			delFirewallRuleAll(bin, port) // 用规范参数删，兼容 comment 带/不带引号两种渲染
		}
	}
}

// parseStalePortForwardPorts 从 `iptables -S INPUT` 输出解析出所有带本特性 comment 的 ACCEPT 规则的 --dport（去重）。
// 兼容 comment 带引号（`--comment "nanotun_pf"`）/不带引号（`--comment nanotun_pf`）两种渲染。
func parseStalePortForwardPorts(dump string) []int {
	var ports []int
	seen := make(map[int]bool)
	for _, line := range strings.Split(dump, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "-A" {
			continue
		}
		if !lineHasPortForwardComment(line) {
			continue
		}
		port, ok := dportFromRuleFields(fields)
		if !ok || seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	return ports
}

// lineHasPortForwardComment 判断一条 `iptables -S` 规则行是否带本特性 comment（兼容带引号/不带引号渲染）。
func lineHasPortForwardComment(line string) bool {
	c := portForwardFirewallComment
	return strings.Contains(line, "--comment "+c+" ") || // 不带引号，后面还有 -j ACCEPT
		strings.HasSuffix(line, "--comment "+c) || // 不带引号且在行尾（防御性）
		strings.Contains(line, `--comment "`+c+`"`) // 带引号
}

// dportFromRuleFields 从规则字段里取 --dport 的端口值。无 / 非法端口 → (0,false)。
func dportFromRuleFields(fields []string) (int, bool) {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--dport" {
			p, err := strconv.Atoi(fields[i+1])
			if err == nil && p > 0 && p <= 65535 {
				return p, true
			}
		}
	}
	return 0, false
}

// acceptPortForward 单条公网监听的 accept 循环：每来一个连接先过并发闸（sem），再起 goroutine 解析目标 + 拨号 +
// 双向拷贝。ctx 取消（停这条映射 / shutdown）时关 listener 让 Accept 立刻返回。
func acceptPortForward(ctx context.Context, ln net.Listener, m *portForwardManager, pf store.PortForward, sem chan struct{}) {
	publicPort := pf.PublicPort
	// ctx 取消时关 listener 让 Accept 立刻返回。用 done 让本 watcher 在 accept 循环因**任何**原因退出（含罕见的
	// 永久性非 ctx Accept 错误）时也一并退出，避免它一直 park 在 <-ctx.Done() 直到该映射被停（goroutine 悬挂）。
	done := make(chan struct{})
	defer close(done)
	// 第十四轮深扫 MED:包 safeGoroutine(全站「无裸 go」不变量)—— 仅做 listener 关闭 watch,panic 只 log。
	go safeGoroutine("portForwardAcceptWatch:"+strconv.Itoa(publicPort), func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	})
	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return // 正常停止
			default:
			}
			// 瞬时错误（fd 耗尽等）指数退避重试，避免忙循环刷 CPU。
			if ne, ok := err.(net.Error); ok && ne.Temporary() { //nolint:staticcheck // Temporary 足够区分可重试
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				logrus.WithError(err).WithField("public_port", publicPort).Debug("[port-forward] Accept 瞬时错误，退避重试")
				time.Sleep(tempDelay)
				continue
			}
			logrus.WithError(err).WithField("public_port", publicPort).Debug("[port-forward] Accept 结束")
			return
		}
		tempDelay = 0
		c := conn
		// 并发闸：超过 maxConnsPerPortForward 的新连接直接关（fail-close），挡恶意大量连接耗尽 fd/goroutine。
		select {
		case sem <- struct{}{}:
		default:
			_ = c.Close()
			logrus.WithField("public_port", publicPort).Debug("[port-forward] 并发连接数超上限，拒绝新连接")
			continue
		}
		go safeGoroutine("portForwardConn:"+strconv.Itoa(publicPort), func() {
			defer func() { <-sem }()
			// 拨号目标运行时解析：node 目标按 UUID 取**当前** vIP（跟随 lease 漂移），LAN 目标用配置 IP。
			// 解析不出安全目标（node 目标设备已删 / 无 lease）→ fail-close，绝不盲拨陈旧 vIP 误投他人。
			target, ok := m.resolveDialTarget(pf)
			if !ok {
				_ = c.Close()
				logrus.WithFields(logrus.Fields{"public_port": publicPort, "device_uuid": pf.TargetDeviceUUID}).
					Debug("[port-forward] 无法解析目标当前 vIP，拒绝连接（fail-close）")
				return
			}
			handlePortForwardConn(ctx, c, target)
		})
	}
}

// handlePortForwardConn 把一个入站公网连接转发到 mesh 目标：拨号（经 TUN 进 mesh）→ 双向拷贝。拨号失败 / ctx
// 取消即关闭（fail-close）。两端都开 TCP keepalive：回收对端崩溃留下的半开死连接，又不误杀「活着但空闲」的会话。
func handlePortForwardConn(ctx context.Context, in net.Conn, target string) {
	defer in.Close()
	setTCPKeepAlive(in)
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: portForwardKeepAlive}
	out, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		logrus.WithError(err).WithField("target", target).Debug("[port-forward] 拨号 mesh 目标失败")
		return
	}
	defer out.Close()

	// ctx 取消（停映射 / shutdown）时立即关两端，打断 io.Copy。
	stop := make(chan struct{})
	defer close(stop)
	// 第十四轮深扫 MED:三处包 safeGoroutine(全站「无裸 go」不变量)。pump 里 defer wg.Done() 在 fn 内,
	// panic 时先跑再冒泡到 recover → wg.Wait() 不会死锁;panic 只 log、不拖垮整进程。
	go safeGoroutine("portForwardConnWatch", func() {
		select {
		case <-ctx.Done():
			_ = in.Close()
			_ = out.Close()
		case <-stop:
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)
	go safeGoroutine("portForwardPump/out", func() {
		defer wg.Done()
		_, _ = io.Copy(out, in)
		if cw, ok := out.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite() // 半关：告诉目标上行已结束，让其回完剩余数据
		} else {
			_ = out.Close()
		}
	})
	go safeGoroutine("portForwardPump/in", func() {
		defer wg.Done()
		_, _ = io.Copy(in, out)
		if cw, ok := in.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = in.Close()
		}
	})
	wg.Wait()
}

// setTCPKeepAlive 对 *net.TCPConn 开 keepalive（周期 portForwardKeepAlive）。非 TCP 连接 no-op。
// 目的：回收对端崩溃/掉电留下的「半开死连接」（不发 FIN/RST），避免 goroutine + fd 悬挂到内核默认 ~2h。
func setTCPKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(portForwardKeepAlive)
	}
}

// resolveDialTarget 决定本次连接实际要拨的 mesh 目标地址，返回 (target, ok)；ok=false = 无法安全确定目标 →
// 调用方 fail-close（关连接）。
//   - LAN 目标：用配置的 target_ip（LAN 后设备 IP 是静态配置、不随 mesh 重分配，且投递走审批门控的子网路径会
//     重新校验设备+审批），可信 → 直接返回。
//   - node 目标：**只拨按 target_device_uuid 新鲜解析出的该设备当前 vIP**（同地址族，跟随 lease 漂移）。**绝不**
//     回退配置里的 vIP 快照：vIP 会随 lease GC / 设备删除被回收再分配给别的设备，而 demux 纯按 vIP 投递（不认
//     UUID）——盲拨陈旧 vIP 可能误投到**现归属另一设备**的会话（跨设备/跨租户）。故确认不了当前 vIP（设备已删 /
//     无 lease / DB 错）一律 fail-close。这是第 1 轮「按 UUID 运行时解析」的收口：把兜底从「盲拨陈旧 IP」改为「丢」。
func (m *portForwardManager) resolveDialTarget(pf store.PortForward) (string, bool) {
	addr, err := netip.ParseAddr(pf.TargetIP)
	if err != nil {
		return "", false
	}
	if m.isLANTarget(addr) {
		return net.JoinHostPort(pf.TargetIP, strconv.Itoa(pf.TargetPort)), true
	}
	v4, v6, ok := m.resolveDeviceVIP(pf.TargetDeviceUUID)
	if !ok {
		return "", false // 设备已删 / DB 错 → 不盲拨陈旧 vIP
	}
	cur := v4
	if !(addr.Is4() || addr.Is4In6()) {
		cur = v6
	}
	if cur == "" {
		return "", false // 设备当前无该地址族 vIP（lease 过期/未分配）→ 不盲拨陈旧配置 vIP
	}
	if cur != pf.TargetIP {
		logrus.WithFields(logrus.Fields{
			"public_port": pf.PublicPort,
			"device_uuid": pf.TargetDeviceUUID,
			"configured":  pf.TargetIP,
			"current_vip": cur,
		}).Debug("[port-forward] node 目标 vIP 已漂移，改拨设备当前 vIP")
	}
	return net.JoinHostPort(cur, strconv.Itoa(pf.TargetPort)), true
}

// resolveDeviceVIP 取某设备当前 vIP（fixed 优先、其次 lease），带 vipCacheTTL 短缓存挡连接风暴下的重复 DB 查询。
// 返回 ok=false 表示解析不出（UUID 空 / store 不可用 / 设备未注册）。
func (m *portForwardManager) resolveDeviceVIP(uuid string) (v4, v6 string, ok bool) {
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	if uuid == "" || m.gw == nil || m.gw.store == nil {
		return "", "", false
	}
	m.vipCacheMu.Lock()
	if e, hit := m.vipCache[uuid]; hit && time.Since(e.at) < vipCacheTTL {
		m.vipCacheMu.Unlock()
		return e.v4, e.v6, true
	}
	m.vipCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(globalContext, 3*time.Second)
	defer cancel()
	dev, err := m.gw.store.GetDeviceByUUIDAny(ctx, uuid)
	if err != nil || dev == nil {
		return "", "", false
	}
	// 第十九轮深扫 MED:FRP 反向拨号要打到设备**当前实际**所在的 vIP。lease 是每次登录由 persistDeviceLease
	// 写入的真实分配值(设备在线时即其当前 vIP);fixed_vip 是 admin 意图,在 split-brain(fixed 地址不可用、被迫
	// 分到别的)时与现实不符。故**优先用 lease**,fixed 仅在该族无 lease(设备从未登录 / 该族未分配)时兜底 ——
	// 拨到设备实际地址而非拨空。稳态下 lease==fixed,行为不变;仅在 fixed≠lease 时改拨到可达的 lease。
	if l, lerr := m.gw.store.GetLeaseByDevice(ctx, dev.ID); lerr == nil && l != nil {
		v4, v6 = l.VIPv4, l.VIPv6
	}
	if v4 == "" {
		v4 = dev.FixedVIPv4
	}
	if v6 == "" {
		v6 = dev.FixedVIPv6
	}
	m.vipCacheMu.Lock()
	m.vipCache[uuid] = vipCacheEntry{v4: v4, v6: v6, at: time.Now()}
	m.vipCacheMu.Unlock()
	return v4, v6, true
}
