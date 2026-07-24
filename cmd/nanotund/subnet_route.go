package main

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/nanotun/server/util"

	"github.com/sirupsen/logrus"
)

// subnet route 特性 — 数据面转发（SR-M1）。
//
// 「子网路由」让 mesh 里的会话访问某宣告方客户端**背后的内网网段**（那些自己装不了客户端的打印机 / NAS /
// 内网服务）：宣告方 advertise 一条具体 CIDR（如 192.168.1.0/24）、admin 批准后，使用方发往该网段的 IP 包由
// server 投递到宣告方会话的 TunChan，由宣告方本机转发 / NAT 进其 LAN（SR-M2）；回程是普通 type5（dst = 请求方
// vIP），沿用现有 vIP demux，无需新增帧。
//
// 与出口节点（exit-node）的关系：出口 = 宣告 0.0.0.0/0 / ::/0 的特例（转进**公网**）。子网路由 = 任意已批准
// CIDR（转进对应宣告方的 **LAN**）。两者复用同一转发原语 [deliverIPPacketToConn]，但选目标的依据不同：
//   - 出口按**会话级选择**（c.egressDeviceID，由 EgressSelect 绑定）；
//   - 子网路由按**目的地最长前缀匹配**（dst ∈ 哪条已批准 CIDR）解析宣告方，无需会话选择；
//
// 数据面优先级：vIP(mesh) > 具体子网路由 > 0/0 出口（若会话选了） > server 自出口。0/0 / ::/0 **不进**本表
// （由 forwardPacketToExitNode 处理），故本表只含「非默认路由的具体 CIDR」。
//
// 本表（approved 非 0/0 CIDR → 宣告方 deviceID）由 [rebuildSubnetRouteTable] 从 DB 构建，在启动 + admin 改路由
// （control-socket /reload?what=routes）时重建；**在线性**由 per-packet 的 [lookupActiveConnByDevice] 实时解析
// （连接上下线无需重建表）。每包热路径只读 atomic 快照 + 线性最长前缀匹配，不查 DB。

// 数据面 subnet route 转发计数（SR-M1，/status 观测；跨 goroutine 读安全）。
var (
	subnetRouteForwarded            atomic.Uint64 // 成功投递到宣告方会话的包数
	subnetRouteForwardedBytes       atomic.Uint64 // 成功转发字节数
	subnetRouteDroppedOffline       atomic.Uint64 // 宣告方离线（无在线会话）丢弃 —— 内网不可达，非安全 fail-closed
	subnetRouteDroppedFull          atomic.Uint64 // 宣告方会话 TunChan 满丢弃
	subnetRouteDroppedOversize      atomic.Uint64 // 包超 tunBufSize 丢弃（防截断损坏）
	subnetRouteDroppedACL           atomic.Uint64 // 被 ACL(请求方 user × 宣告方 user)拒绝丢弃（SR-M4，安全 fail-closed）
	subnetRouteDroppedNotAdvertised atomic.Uint64 // dst 属已批准 CIDR 但宣告方**当前不再宣告**该网段（收窄+陈旧批准）→ 丢弃（第 7 轮深扫）
	subnetRouteDroppedNoSite        atomic.Uint64 // SR-VIA6：4via6 dst 的 siteID 未知（陈旧/未分配站点）→ 丢弃（不回退 server 误发公网）
	subnetRouteDroppedNotApproved   atomic.Uint64 // dst 不在宣告方**管理员已批准**网段 → 丢弃（防审批绕过/SSRF）。两处：① SR-VIA6 4via6 解出的 v4；② FRP server 自发 LAN 包（deliverServerOriginatedToDevice，防撤销审批后 FRP 仍能打进 LAN）
)

// SubnetRouteStats 暴露在 /status JSON 的子结构：子网路由数据面（SR-M1）转发计数 + 当前生效路由条数。
type SubnetRouteStats struct {
	Routes               int    `json:"routes"` // 当前生效的已批准非 0/0 路由条数
	Forwarded            uint64 `json:"forwarded"`
	ForwardedBytes       uint64 `json:"forwarded_bytes"`
	DroppedOffline       uint64 `json:"dropped_offline"`
	DroppedFull          uint64 `json:"dropped_full"`
	DroppedOversize      uint64 `json:"dropped_oversize"`
	DroppedACL           uint64 `json:"dropped_acl"`            // SR-M4：ACL(请求方×宣告方 user)拒绝
	DroppedNotAdvertised uint64 `json:"dropped_not_advertised"` // 第 7 轮深扫：宣告方当前不再宣告该(陈旧批准的)网段
	DroppedNoSite        uint64 `json:"dropped_no_site"`        // SR-VIA6：4via6 siteID 未知（陈旧/未分配站点）
	DroppedNotApproved   uint64 `json:"dropped_not_approved"`   // SR-VIA6 安全：4via6 解出的 v4 不在管理员已批准网段（防审批绕过/SSRF）
}

func snapshotSubnetRouteStats() SubnetRouteStats {
	n := 0
	if tbl := subnetRouteTable.Load(); tbl != nil {
		n = len(*tbl)
	}
	return SubnetRouteStats{
		Routes:               n,
		Forwarded:            subnetRouteForwarded.Load(),
		ForwardedBytes:       subnetRouteForwardedBytes.Load(),
		DroppedOffline:       subnetRouteDroppedOffline.Load(),
		DroppedFull:          subnetRouteDroppedFull.Load(),
		DroppedOversize:      subnetRouteDroppedOversize.Load(),
		DroppedACL:           subnetRouteDroppedACL.Load(),
		DroppedNotAdvertised: subnetRouteDroppedNotAdvertised.Load(),
		DroppedNoSite:        subnetRouteDroppedNoSite.Load(),
		DroppedNotApproved:   subnetRouteDroppedNotApproved.Load(),
	}
}

// subnetRouteEntry：一条已批准的（非 0/0）子网路由 → 宣告方 deviceID。
type subnetRouteEntry struct {
	prefix   netip.Prefix
	deviceID int64
}

// subnetRouteTable：已批准非 0/0 子网路由表的原子快照（整体替换）。
// 每包热路径**只读**（Load），无锁；[rebuildSubnetRouteTable] 重建时整体 Store 新切片。
// nil = 尚未构建 / 无路由。
var subnetRouteTable atomic.Pointer[[]subnetRouteEntry]

// via6SiteTable：4via6 的 siteID→宣告方 deviceID 原子快照（SR-VIA6）。每包热路径**只读**（Load），无锁；
// [rebuildSubnetRouteTable] 从 store.ListVia6Sites（device→site）反转成 site→device 后整体 Store。
// nil = 尚未构建 / 无站点。与 subnetRouteTable 平行：前者按 v4 CIDR 最长前缀，此表按 4via6 v6 的 siteID 直查。
var via6SiteTable atomic.Pointer[map[uint16]int64]

// rebuildSubnetRouteTable 从 store 重建子网路由表：取所有 approved 路由，滤掉出口默认路由（0/0、::/0 由出口路径
// 处理），parse 成 netip.Prefix，原子替换快照。DB 出错则**保留旧表**（不黑洞已生效路由）。低频：启动 + admin
// 改路由时调（control-socket /reload?what=routes）。
func rebuildSubnetRouteTable(ctx context.Context) {
	gw := gatewayInstance
	if gw == nil || gw.store == nil {
		return
	}
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := gw.store.ListRoutesByStatus(dbCtx, util.RouteStatusApproved)
	if err != nil {
		logrus.WithError(err).Warn("[subnet-route] 重建路由表失败，保留旧表（不黑洞已生效路由）")
		return
	}
	tbl := make([]subnetRouteEntry, 0, len(rows))
	for _, r := range rows {
		if util.IsExitDefaultRoute(r.CIDR) {
			continue // 0/0 / ::/0 是出口节点特例，由 forwardPacketToExitNode 处理，不进子网路由表。
		}
		p, perr := netip.ParsePrefix(r.CIDR)
		if perr != nil {
			continue // 入库前已归一，理论上不会到这；防御性跳过坏数据。
		}
		masked := p.Masked()
		// 第十一轮深扫 MED:载入时复核私有/保留段(NormalizeAdvertisedCIDR 的写路径收敛不回溯存量)。
		// 旧代码期批准过的公网/宽段子网路由若留在转发表,会绕过出口闸 + 出口 ACL(confused-deputy);
		// 这里把它们挡在转发表外(不删库,admin 可重新处置 / 改走出口节点),并 warn 提示。
		if !util.PrefixWithinAdvertisable(masked) {
			logrus.WithFields(logrus.Fields{
				"cidr":      r.CIDR,
				"device_id": r.DeviceID,
			}).Warn("[subnet-route] 跳过非私有/保留段的历史 approved 子网路由(绕过出口闸风险):请重新审批为出口节点或删除")
			continue
		}
		// 第十八轮深扫 MED:拦掉与 server 自身 mesh 网段(TUN v4/v6 CIDR)交叠的 approved 子网路由。批准了一条
		// 覆盖 / 落入 mesh 网段的 CIDR(admin 误批、或该特性上线前的历史批准)会造成:发往「当前离线的 mesh
		// 地址」的包在子网路由查表(优先于 forwardPacketToExitNode 的离线-mesh fail-closed)命中该条 → 被中继给
		// 宣告方会话 → 泄漏进对端 LAN(跨信任域)。批准期(CLI/web)已用 mesh_cidrs 快照拒批,这里是数据面兜底,
		// 兜住「特性上线前的历史批准」与「绕过 CLI/web 直写 DB」。不删库(admin 可重新处置),仅 warn。
		if meshPrefixOverlaps(masked) {
			logrus.WithFields(logrus.Fields{
				"cidr":      r.CIDR,
				"device_id": r.DeviceID,
			}).Warn("[subnet-route] 跳过与本 mesh 网段交叠的 approved 子网路由(跨信任域泄漏风险):请删除或改用不重叠网段")
			continue
		}
		tbl = append(tbl, subnetRouteEntry{prefix: masked, deviceID: r.DeviceID})
		// SR-VIA6：确保该 approved 子网宣告方设备已分配稳定 siteID（幂等；供 4via6 消歧数据面 + routes-list 下发）。
		// 集中在此分配：不论 approve 来自 admin CLI 还是 web，都经 /reload?what=routes 触发本 rebuild。0/0 出口已在
		// 上面 continue 跳过，不占用 siteID（4via6 只对具体子网）。
		if _, serr := gw.store.GetOrAssignSiteID(dbCtx, r.DeviceID); serr != nil {
			logrus.WithError(serr).WithField("device_id", r.DeviceID).Warn("[subnet-route] 分配 4via6 siteID 失败")
		}
	}
	// SR-VIA6（深扫 #3）：先备好 siteID→deviceID 快照（含 ListVia6Sites DB 查询），再与 subnetRouteTable **相邻**
	// Store——把两个 atomic 的可见性窗口从「原来夹着一次 DB 查询」压到「两条 Store 语句之间」（纳秒级），杜绝窗口内
	// 「新 subnet 表 + 旧 via6 表」并存导致的 4via6 短暂 DroppedNoSite / 陈旧映射。DB 查 sites 出错则 newVia6=nil →
	// 保留旧 via6 表（仅 subnet 表更新，不黑洞已生效的 site 映射，与原降级语义一致）。
	var newVia6 *map[uint16]int64
	if sites, serr := gw.store.ListVia6Sites(dbCtx); serr != nil {
		logrus.WithError(serr).Warn("[subnet-route] 重建 4via6 site 表失败，保留旧表")
	} else {
		inv := make(map[uint16]int64, len(sites))
		for dev, sid := range sites {
			inv[sid] = dev
		}
		newVia6 = &inv
	}
	subnetRouteTable.Store(&tbl)
	if newVia6 != nil {
		via6SiteTable.Store(newVia6)
	}
	logrus.WithFields(logrus.Fields{"routes": len(tbl), "sites_updated": newVia6 != nil}).
		Info("[subnet-route] 已批准子网路由表 + 4via6 site 表已重建")
}

// deviceInSubnetRouteTable 报告该 deviceID 是否为**已批准子网路由**的宣告方（当前生效表里有其条目）。
// 只读 atomic 快照、无 DB 查询，供 routes-list 广播门控：宣告方设备上/下线只在「确是已批准宣告方」时才重推
// routes-list（刷新每条路由的 online），避免为无关设备频繁广播。deviceID==0 恒 false；表未构建返回 false。
// subnetRouteTableLoaded 报告已批准子网路由表是否已完成过至少一次加载(atomic 指针非 nil)。
//
// 第四轮深扫 MED(c_exit_approve 的子网对称项):advertisedSubnetApproved 是 M2 豁免闸,决定一个已批准子网
// 路由器能否以「非自身 vIP」的 LAN 回程源发包。此前它直接 Store(deviceInSubnetRouteTable(...)),而后者在
// 表尚未加载(ptr==nil,启动初 / reload 瞬间)时返回 false —— 会把一个**其实已批准**的宣告方的豁免误清成
// false,其合法回程流量被 connSourceSpoofed 丢弃直到下次重连。与出口侧 deviceHasApprovedExitRoute 的 (approved,ok)
// 语义对齐:仅当表确已加载时才据其改写豁免闸,未加载则**保留上次已知值**。
func subnetRouteTableLoaded() bool {
	return subnetRouteTable.Load() != nil
}

func deviceInSubnetRouteTable(deviceID int64) bool {
	if deviceID == 0 {
		return false
	}
	ptr := subnetRouteTable.Load()
	if ptr == nil {
		return false
	}
	for _, e := range *ptr {
		if e.deviceID == deviceID {
			return true
		}
	}
	return false
}

// lookupSubnetRoute 在已批准子网路由表里对 dst 做**最长前缀匹配**，返回宣告方 deviceID。
// 路由数极少（典型 < 数十条），线性扫 + 记最长掩码即可；返回 (0,false) = 无匹配。
// netip.Prefix.Contains 天然处理地址族（v4 dst 不会命中 v6 prefix，反之亦然）。
func lookupSubnetRoute(dst netip.Addr) (int64, bool) {
	ptr := subnetRouteTable.Load()
	if ptr == nil {
		return 0, false
	}
	bestBits := -1
	var bestDev int64
	for _, e := range *ptr {
		if !e.prefix.Contains(dst) {
			continue
		}
		b := e.prefix.Bits()
		// 最长前缀优先；**同长度时取最小 deviceID**（确定性 tiebreak）：同一 CIDR 被误批给两台设备时，选谁至少稳定
		// 可预期，消除切片/DB 行序带来的不确定（深扫#14）。正常部署无重复 CIDR，本分支不触发。
		if b > bestBits || (b == bestBits && e.deviceID < bestDev) {
			bestBits = b
			bestDev = e.deviceID
		}
	}
	if bestBits < 0 {
		return 0, false
	}
	return bestDev, true
}

// lookupVia6Site 按 4via6 的 siteID 直查宣告方 deviceID（SR-VIA6）。只读 atomic 快照、无 DB 查询；(0,false)=无此站点。
func lookupVia6Site(siteID uint16) (int64, bool) {
	m := via6SiteTable.Load()
	if m == nil {
		return 0, false
	}
	dev, ok := (*m)[siteID]
	return dev, ok
}

// deviceAdvertisesV4 报告 deviceID 是否在其**已批准的 v4 宣告网段**内覆盖 v4（SR-VIA6 / P3）。供 MagicDNS 生成
// 4via6 前校验：目标 v4 须确在该宣告方宣告集内，否则生成的 4via6 数据面会按 not-advertised 丢弃（用户"解析出来
// 却连不上"）。只读 atomic 快照、无 DB；只匹配 v4 前缀（4via6 只嵌 v4）。
func deviceAdvertisesV4(deviceID int64, v4 netip.Addr) bool {
	ptr := subnetRouteTable.Load()
	if ptr == nil {
		return false
	}
	for _, e := range *ptr {
		if e.deviceID == deviceID && e.prefix.Addr().Is4() && e.prefix.Contains(v4) {
			return true
		}
	}
	return false
}

// deviceApprovedForDst 报告 dst 是否落在 deviceID 的**管理员已批准**宣告网段内（读 always-current
// subnetRouteTable，admin 改路由经 /reload?what=routes 即时重建）。与 deviceAdvertisesV4 同源，但不限地址族
// （v4 / v6 LAN 目标皆可）。供 FRP server 自发 LAN 包的审批门控（deliverServerOriginatedToDevice）。
func deviceApprovedForDst(deviceID int64, dst netip.Addr) bool {
	ptr := subnetRouteTable.Load()
	if ptr == nil {
		return false
	}
	for _, e := range *ptr {
		if e.deviceID == deviceID && e.prefix.Contains(dst) {
			return true
		}
	}
	return false
}

// forwardServerOriginatedToSubnet 处理 **server 自身发起**（net.Dial，典型是 FRP 反向端口转发 dial LAN 目标，
// 见 cmd/nanotund/port_forward.go）、目的为某已批准子网（LAN 后设备）的包：这类包从 TUN 读回后在 demux 消费者里**未命中
// 任何 vIP**（dst 是 LAN IP 而非 mesh vIP），此处按子网路由投给宣告方会话，由其本机 NAT 进 LAN。
//
// 返回 true=已投递给宣告方；false=非已批准子网 / 宣告方离线 / 通道满（调用方照常回收缓冲并丢弃）。
//
// 与 [forwardPacketToSubnetRoute] 的区别：后者处理**客户端来包**（在 readLoop，带 per-user ACL / 自指 / per-CIDR
// 收窄门控）；本函数处理 **server 自发包**（在 TUN demux 消费者），src 是 server 网关（非某 user 的 vIP），不套用
// per-user ACL —— 映射由 admin 定义即视为已授权。仅做「已批准子网 ∩ 宣告方在跑」两道闸，够用且绝不黑洞。
//
// 性能：先做**无锁** lookupSubnetRoute（atomic 快照 + 线性最长前缀）；未命中直接返回，不触碰 connIDMapMu，
// 故 demux 消费者对「dst 既非 vIP 又非已批准子网」的常见杂包（扫描/广播）零额外锁开销。
//
// 选宣告方设备的两级策略（#5 彻底修）：
//  1. **精确**：dst 命中 FRP 精确路由表（lookupFRPTarget）→ 用该映射**指定**的 deviceID。这压过按子网猜测，
//     解决「同一网段被多台设备宣告时，校验绑定 B、数据面却按最小 deviceID 投给 A」的错投。命中精确表即**不再**
//     回落子网解析（宁可因所选设备离线/收窄而丢，也不静默改投另一台设备——那正是要消除的歧义）。
//  2. **兜底**：未命中精确表（非 FRP 明确目标的 server 自发 LAN 包）→ 退回 lookupSubnetRoute 按已批准子网最长前缀。
//
// 无论走哪级，最终都经 deliverServerOriginatedToDevice 的**审批门控**（dst 须在所选设备已批准网段内）——精确表不校验
// 审批、只在 portforward reload 时构建，故审批撤销/恢复由该门控读 always-current subnetRouteTable 即时生效。
func forwardServerOriginatedToSubnet(dst netip.Addr, payload []byte) bool {
	if dev, ok := lookupFRPTarget(dst); ok {
		return deliverServerOriginatedToDevice(dev, dst, payload)
	}
	dev, ok := lookupSubnetRoute(dst)
	if !ok {
		return false
	}
	return deliverServerOriginatedToDevice(dev, dst, payload)
}

// deliverServerOriginatedToDevice 把 server 自发、目的为 LAN 的包投递给**指定 deviceID** 的宣告方会话，附三道闸：
//   - 审批门控：dst 须落在该 deviceID 的**管理员已批准**宣告网段内（deviceApprovedForDst 读 always-current
//     subnetRouteTable）。FRP 精确表(frpTargetTable)只在 portforward reload 时构建、且**不校验审批**；若无此闸，
//     admin 撤销某设备的子网批准后、只要该设备仍在 --advertise-routes，FRP 公网端口仍会把外部流量投进其 LAN
//     （撤销对 FRP 不生效——与客户端来包路径 lookupSubnetRoute 的审批口径不一致）。此闸把 FRP 路径拉回同一口径：
//     撤销即时失效、重新批准即时恢复，无需等 portforward reload。**子网兜底路径下此检查恒真**（lookupSubnetRoute
//     已保证 dst∈该设备已批准网段），不改变其行为。
//   - 宣告方须有「真在跑子网路由器」的在线会话（lookupSubnetAdvertiserConnByDevice）；否则丢（离线不可达，不回退
//     server 误发公网、也不改投别的设备）。
//   - per-CIDR 覆盖门控：宣告方**本会话当前仍宣告**覆盖 dst 的网段；若它已收窄（去掉了该网段）而映射/批准还在，则丢
//     （防未 NAT 的包漏进其 LAN / 黑洞）。与 forwardPacketToSubnetRoute 的门控同口径。集为空 = 未知，放行（防御性兜底）。
//
// 返回 true=已投递；false=丢弃（调用方照常回收缓冲）。
func deliverServerOriginatedToDevice(deviceID int64, dst netip.Addr, payload []byte) bool {
	// 审批门控（务必在选目标/投递前）：dst 必须在该设备**管理员已批准**的宣告网段内。fail-closed（表未建 / 已撤销 →
	// 丢），与客户端来包路径同口径；杜绝「撤销审批后 FRP 仍能打进 LAN」。
	if !deviceApprovedForDst(deviceID, dst) {
		subnetRouteDroppedNotApproved.Add(1)
		return false
	}
	adv := lookupSubnetAdvertiserConnByDevice(deviceID)
	if adv == nil {
		subnetRouteDroppedOffline.Add(1)
		return false
	}
	if pfxs := adv.advertisedRoutes.Load(); pfxs != nil && len(*pfxs) > 0 {
		covered := false
		for _, p := range *pfxs {
			if p.Contains(dst) {
				covered = true
				break
			}
		}
		if !covered {
			subnetRouteDroppedNotAdvertised.Add(1)
			return false
		}
	}
	if len(payload) > tunBufSize {
		subnetRouteDroppedOversize.Add(1)
		return false
	}
	if deliverIPPacketToConn(adv, payload) {
		subnetRouteForwarded.Add(1)
		subnetRouteForwardedBytes.Add(uint64(len(payload)))
		return true
	}
	subnetRouteDroppedFull.Add(1)
	return false
}

// forwardPacketToSubnetRoute 数据面：把 c 发往「某已批准内网网段」的 IP 包投递给该网段的宣告方会话（由宣告方
// 本机转发 / NAT 进其 LAN）。
//
// 返回 true = 本包已由子网路由路径处理（投递成功 / 按策略丢弃），调用方**不应**再走后续（出口 / server）路径；
// 返回 false = 不归子网路由管（dst 是 vIP / 无匹配路由 / 自指），调用方继续原有链路。返 false 的情形：
//   - 目的是某 vIP（mesh 互通流量，**绝不**当子网路由转发；且子网路由 CIDR 可能与 mesh 段重叠 → vIP 优先）；
//   - dst 不命中任何已批准子网路由（落回出口 / server 自出口）；
//   - 自指（宣告方访问自己宣告的网段 → 本机直达，无需中转）。
//
// 宣告方离线（无在线会话）→ 丢弃（内网不可达；非安全 fail-closed，只是该 LAN 暂时够不到，且绝不回退 server
// 把内网包误发公网）。
func forwardPacketToSubnetRoute(c *Connection, payload []byte) bool {
	if c == nil {
		return false
	}
	t, ok := parsePacketTuple(payload)
	if !ok {
		return false
	}
	// 本 mesh 内部 / server 本地优先：dst 是某 vIP（mesh 互通）**或 server 自身网关地址**（如 MagicDNS gateway:53）
	// → 不归子网路由，让它走 server TUN + demux / 本地服务处理（网关地址不会命中任何 LAN 子网，此处属防御性收口）。
	if isLocalMeshDst(t.dst) {
		return false
	}
	// SR-VIA6：dst 可能是 4via6（v6，嵌 siteID + 原始 v4）或普通 v4 子网。前者按 siteID 直查宣告方、宣告集/自指用
	// **解出的 v4** 判断；后者按 v4 最长前缀。matchAddr = 用于「宣告集门控」的地址（4via6 → 解出的 v4；v4 → dst 本身）。
	var deviceID int64
	var matched bool
	matchAddr := t.dst
	if is4via6(t.dst) {
		siteID, v4, _ := decode4via6(t.dst)
		matchAddr = v4
		deviceID, matched = lookupVia6Site(siteID)
		if !matched {
			// 4via6 地址但 siteID 未知（陈旧 / 未分配站点）→ 丢弃（已归本路径，绝不回退 server 把内网 v6 误发公网）。
			subnetRouteDroppedNoSite.Add(1)
			return true
		}
		// SR-VIA6 安全（审批必须在数据面强制，不能只管发布）：解出的 v4 必须落在该设备**管理员已批准**的宣告网段内
		// （与 DNS lookupVia6Addr 的 deviceAdvertisesV4、普通 v4 路径的 lookupSubnetRoute 同口径）。4via6 原按 siteID 直查
		// 宣告方、**从不校验解出的 v4 是否已批准** → authenticated peer 构造裸 fdbc:4a60::<site>:<任意v4> 即可让宣告方 relay
		// 到「自宣告但未获管理员批准」网段内的 v4（绕过审批 / SSRF）。此处补上对称校验；未批准即丢（已归本路径，不回退 server）。
		if !deviceAdvertisesV4(deviceID, v4) {
			subnetRouteDroppedNotApproved.Add(1)
			return true
		}
	} else {
		deviceID, matched = lookupSubnetRoute(t.dst)
		if !matched {
			return false // 非 4via6 且无已批准 v4 子网路由覆盖 dst → 交回原链路（出口 / server）。
		}
	}
	// 自指：宣告方访问自己宣告的网段 → 本机直达，无需中转（也避免回环）。交回原链路。
	if c.deviceID != 0 && deviceID == c.deviceID {
		return false
	}
	// SR-M4 深扫：必须挑「真在跑子网路由器（advertisedSubnetRoutes && !takenOver）」的会话，而非 lookupActiveConnByDevice
	// 的「首个 !takenOver」——否则设备「历史 approved 某网段、但本次以普通客户端连入（没跑 --advertise-routes、没装
	// dst 限定 NAT）」时，会把包投给它 → 客户端无 NAT 转发，未 NAT 的 mesh vIP 包漏进其 LAN + 无回程黑洞（与出口节点
	// lookupRunningExitConnByDevice 同款修法）。接管/重连窗口（新会话尚未重发 advertise）亦按此判为「未就绪」→ 丢弃。
	advConn := lookupSubnetAdvertiserConnByDevice(deviceID)
	if advConn == nil {
		subnetRouteDroppedOffline.Add(1)
		return true // 无 NAT-ready 宣告方会话（下线 / 本次未 --advertise-routes / 重连窗口）→ 丢弃（不回退 server 误发公网）。
	}
	// 第 7 轮深扫（per-CIDR 门控）：dst 命中了**已批准**路由表 + 宣告方在跑（布尔），但还须确认宣告方**本会话当前仍宣告**
	// 该具体网段——宣告方的 NAT/FORWARD 只 dst 限定到当前 --advertise-routes，若它**收窄**了宣告（重连去掉 Y）而 DB 里 Y 的
	// 批准仍在，仅凭布尔 + DB 表会把 Y 投给它 → 未 NAT 漏进其 LAN（宽松主机）/黑洞（加固主机），违背设备已收窄的意图。
	// 集为 nil/空 = 未知（退回布尔行为放行；生产中布尔置真必同帧填集，故正常不触发该退路，仅防御性兜底不黑洞）。
	if pfxs := advConn.advertisedRoutes.Load(); pfxs != nil && len(*pfxs) > 0 {
		covered := false
		for _, p := range *pfxs {
			if p.Contains(matchAddr) {
				covered = true
				break
			}
		}
		if !covered {
			subnetRouteDroppedNotAdvertised.Add(1)
			return true // 宣告方当前不再宣告该网段（收窄 + 陈旧批准）→ 丢弃（已归本路径，不回退 server）。
		}
	}
	// SR-M4 ACL：子网路由 = 请求方经宣告方访问其 LAN → 按「请求方 user × 宣告方 user」+ proto/port 裁决（复用
	// mesh 语义：访问某宣告方背后的子网 == 能否与该宣告方 user 私有互通，故一条 A→B deny 同时挡 A 访问 B 的 vIP 和
	// B 宣告的子网）。deny → 安全 fail-closed 丢弃（已归本路径，不回退 server；防越权探他人内网）。宣告方 user 由
	// 其在线会话 advConn.userID 直接给出，无需 device→user DB 反查。
	//
	// ⚠️ 回程对称性（深扫记录）：LAN 设备的回包经宣告方本机 rev-NAT（dst 还原为请求方 vIP）后走**普通 vIP demux**
	// （dst 是 vIP → 本函数早已 return false 放行，不归子网路由路径），由 aclDropPacketDirected 按「宣告方 user →
	// 请求方 user」**再裁决一次**。故 default-deny 部署下子网连通需**双向**放行（A→D 前向 + D→A 回程），与 mesh
	// vIP↔vIP 完全同口径（无状态、按包定向）。default-allow / 宽松规则部署两向天然通过，无需额外配置。
	if aclDeniesSubnetRoute(parseUserIDStr(c.userID), parseUserIDStr(advConn.userID), payload) {
		subnetRouteDroppedACL.Add(1)
		return true
	}
	if len(payload) > tunBufSize {
		subnetRouteDroppedOversize.Add(1)
		return true
	}
	if deliverIPPacketToConn(advConn, payload) {
		subnetRouteForwarded.Add(1)
		subnetRouteForwardedBytes.Add(uint64(len(payload)))
	} else {
		subnetRouteDroppedFull.Add(1)
	}
	return true
}
