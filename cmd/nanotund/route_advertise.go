package main

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/nanotun/server/util"

	"github.com/sirupsen/logrus"
)

// P2#12 subnet route advertise — server 侧入口。
//
// handleRouteAdvertiseFrame 在 runLinkTunnel 的 readLoop 中被调用,接收一帧
// LinkTypeRouteAdvertise 的 JSON body,解析后:
//  1. CIDR 文本归一化(去无效 / 去 /0);
//  2. upsert 到 subnet_routes;空列表 → 删除所有 pending 条目;
//  3. 给客户端回一帧 LinkTypeRouteApproveStatus,告知当前每条 CIDR 的状态
//     (pending / approved / rejected)。
//
// 整段全部 best-effort:任何错误都只 log + 计数,绝不 break readLoop。
// audit 不在这里写,改去 cmdProfile 的 admin 路径 / 后续 server 内置审计上做。
//
// 安全 / 防御:
//   - c.deviceID == 0(客户端没上报合法 device_uuid)→ 直接拒绝,不入库,只 Warn;
//   - body 太大或 schema 错 → 计数 + 丢弃;
//   - 单帧最多接受 RouteAdvertiseMaxRoutes 条(默认 64),超出截断;
//   - store 超时取 5s,与 audit / user_invalidate 一致;
//
// 协议规范见 docs/DESIGN_SUBNET_ROUTES.md。
const RouteAdvertiseMaxRoutes = 64

// 暴露给 /status / 测试观测:计数 best-effort,允许丢失。
var (
	routeAdvAccepted  atomic.Uint64 // 接受并 upsert 成功的条数(归一后)
	routeAdvRejected  atomic.Uint64 // 因 CIDR 无效 / /0 拒绝的条数
	routeAdvAnonymous atomic.Uint64 // device_uuid 不可用导致整帧拒绝的次数
	routeAdvFailed    atomic.Uint64 // store 失败次数(汇总,不细分错误)
)

// RouteAdvertiseStats 暴露在 /status JSON 的子结构。
type RouteAdvertiseStats struct {
	Accepted  uint64 `json:"accepted"`
	Rejected  uint64 `json:"rejected"`
	Anonymous uint64 `json:"anonymous"`
	Failed    uint64 `json:"failed"`
}

// snapshotRouteAdvStats 在 /status 处快照计数,避免直接读 atomic 暴露包内符号。
func snapshotRouteAdvStats() RouteAdvertiseStats {
	return RouteAdvertiseStats{
		Accepted:  routeAdvAccepted.Load(),
		Rejected:  routeAdvRejected.Load(),
		Anonymous: routeAdvAnonymous.Load(),
		Failed:    routeAdvFailed.Load(),
	}
}

// normalizeAdvertisedCIDRForFrame 按帧是否为出口声明，选择允许 / 拒绝 0/0 的归一器。
func normalizeAdvertisedCIDRForFrame(raw string, exit bool) (string, error) {
	if exit {
		return util.NormalizeExitAdvertisedCIDR(raw)
	}
	return util.NormalizeAdvertisedCIDR(raw)
}

// maxAdvertisedRoutesPerConn 单会话「当前宣告 CIDR 集」union 累积上限。合法客户端单帧 ≤ RouteAdvertiseMaxRoutes(64)、
// 且通常只发一帧,256 给足 4× 余量;超出即为异常/滥用(反复发含不同 CIDR 的 advertise 帧无界累积)→ 截断,钉住
// forwardPacketToSubnetRoute 每包 Contains 扫描成本与内存上限(否则恶意宣告方可拖慢发往其已批准网段的数据面)。
const maxAdvertisedRoutesPerConn = 256

// unionPrefixes 把 newPfx 并入 prev(去重),返回**新**切片(copy-on-write:不改 prev 指向的底层数组,故并发读旧快照安全)。
// netip.Prefix 可比较,直接做 map 键去重。低频(仅 RouteAdvertise 帧),开销可忽略。超上限截断(保留最早入集的,见常量注释)。
func unionPrefixes(prev *[]netip.Prefix, newPfx []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{})
	out := make([]netip.Prefix, 0, len(newPfx))
	add := func(p netip.Prefix) {
		if len(out) >= maxAdvertisedRoutesPerConn {
			return
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	if prev != nil {
		for _, p := range *prev {
			add(p)
		}
	}
	for _, p := range newPfx {
		add(p)
	}
	return out
}

func handleRouteAdvertiseFrame(ctx context.Context, c *Connection, payload []byte) {
	if c == nil {
		return
	}
	if c.deviceID == 0 {
		routeAdvAnonymous.Add(1)
		logrus.WithField("user_id", c.userID).Warn(
			"[route_adv] device_uuid 缺失,拒绝路由声明;请客户端在 LoginReq.DeviceUUID 上送合法 UUIDv4")
		return
	}
	gw := gatewayInstance
	if gw == nil || gw.store == nil {
		return
	}

	ra, err := util.ParseRouteAdvertise(payload)
	if err != nil {
		routeAdvFailed.Add(1)
		logrus.WithError(err).WithField("user_id", c.userID).Warn("[route_adv] 解析失败,丢弃")
		return
	}

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// 空 routes = 客户端撤回所有 pending 声明(approved 保留,见 store 注释)。
	if len(ra.Routes) == 0 {
		if _, err := gw.store.DeleteAdvertisedRoutesForDevice(dbCtx, c.deviceID); err != nil {
			routeAdvFailed.Add(1)
			logrus.WithError(err).WithField("device_id", c.deviceID).
				Warn("[route_adv] 撤回 pending 路由失败")
		}
		_ = sendRouteApproveStatusForDevice(dbCtx, c, nil)
		// 撤回所有声明 = 本会话不再「真在跑出口」→ 清 advertisedExit;若之前在跑,广播让它从出口下拉消失,
		// 避免「已撤回声明却仍被当在跑出口、转发到它导致黑洞」(否则只能等下线才修)。
		if c.advertisedExit.Swap(false) {
			go broadcastExitsList(context.Background())
		}
		// 撤回出口 = 不再是出口 → 清 v6 能力标(避免残留 true 使数据面误判)。
		c.advertisedExitV6.Store(false)
		// subnet route(SR-M4 深扫):同理撤回 = 不再「真在跑子网路由器」→ 清 advertisedSubnetRoutes,使
		// forwardPacketToSubnetRoute 立即把发往其网段的包按「无 NAT-ready 宣告方」丢弃,而非投给已撤回声明的会话。
		c.advertisedSubnetRoutes.Store(false)
		// 第 7 轮深扫:同步清当前宣告 CIDR 集(撤回即不再路由任何网段)。
		c.advertisedRoutes.Store(nil)
		// M2:撤回即不再是批准转发者 → 清豁免闸,本会话立即回到「只能以自身 vIP 作源」。
		c.advertisedExitApproved.Store(false)
		c.advertisedSubnetApproved.Store(false)
		return
	}

	if len(ra.Routes) > RouteAdvertiseMaxRoutes {
		logrus.WithFields(logrus.Fields{
			"device_id": c.deviceID,
			"got":       len(ra.Routes),
			"max":       RouteAdvertiseMaxRoutes,
		}).Warn("[route_adv] 路由条数超限,截断")
		ra.Routes = ra.Routes[:RouteAdvertiseMaxRoutes]
	}

	upserted := make([]string, 0, len(ra.Routes))
	// subnet route(第 7 轮深扫):本会话「当前宣告的具体(非 0/0)CIDR 集」按**归一后**内容收集——**独立于 DB upsert 成败**。
	// 客户端 NAT/FORWARD dst 限定的是它发送/归一的网段,与服务器 DB 持久化无关;若绑定 upsert 成功,则 upsert 瞬时失败时
	// 一条**此前已批准、仍在转发表**里的网段会被 per-CIDR 门控(dst ∈ 当前宣告集)误判为「已不宣告」而丢弃(可用性回归)。
	advPfx := make([]netip.Prefix, 0, len(ra.Routes))
	for _, raw := range ra.Routes {
		// exit-node：ra.Exit=true 的帧允许携带 0/0 / ::/0（自荐为公网出口），走出口语境归一；
		// 否则照旧拒 /0，防普通设备误声明全网代理。两条路径都仅写 pending，须 admin 审批才生效。
		norm, nerr := normalizeAdvertisedCIDRForFrame(raw, ra.Exit)
		if nerr != nil {
			routeAdvRejected.Add(1)
			logrus.WithFields(logrus.Fields{
				"device_id": c.deviceID,
				"cidr":      raw,
				"err":       nerr.Error(),
			}).Warn("[route_adv] CIDR 不合法,跳过")
			continue
		}
		// 归一成功即计入「当前宣告集」(非 0/0),不等 upsert——见上方 advPfx 说明。
		if !util.IsExitDefaultRoute(norm) {
			if p, perr := netip.ParsePrefix(norm); perr == nil {
				advPfx = append(advPfx, p.Masked())
			}
		}
		if _, err := gw.store.UpsertAdvertisedRoute(dbCtx, c.deviceID, norm); err != nil {
			routeAdvFailed.Add(1)
			logrus.WithError(err).WithFields(logrus.Fields{
				"device_id": c.deviceID,
				"cidr":      norm,
			}).Warn("[route_adv] upsert 失败")
			continue
		}
		routeAdvAccepted.Add(1)
		upserted = append(upserted, norm)
	}

	_ = sendRouteApproveStatusForDevice(dbCtx, c, upserted)

	// exit-node 选择器(Q2):本会话声明了出口(带 /0 的 exit 帧)→ 打标「真在跑出口」。若该设备已被 admin 批准
	// 为出口,则它现在是「在线在跑的出口」→ 广播给所有 exit_allowed 客户端,出口下拉实时增项。
	// (首次声明多为 pending、未批准 → 不广播;待 admin 批准后,下次任意出口上下线 / 客户端重连时反映。)
	hasExitDefault := false
	hasExitV6 := false
	if ra.Exit {
		for _, n := range upserted {
			if util.IsExitDefaultRoute(n) {
				hasExitDefault = true
			}
			if n == util.ExitDefaultRouteV6 {
				hasExitV6 = true
			}
		}
	}
	if hasExitDefault {
		c.advertisedExit.Store(true)
		// v6 能力感知:本帧是否含 ::/0。出口客户端现按**真实 v6 出网**决定宣告 ::/0 与否(build_exit_advertise_json;
		// 无 v6 只报 0.0.0.0/0),且每次发**全量**出口路由 → 以本帧为准 replace(非累积)。无 v6 出口 → false →
		// forwardPacketToExitNode 对发往它的公网 v6 回 ICMPv6 unreachable、使用方秒回落 v4(修 v4-only 出口的 v6 黑洞)。
		// 老出口客户端总宣告 ::/0 → 恒 true → 维持旧行为、无回归。
		c.advertisedExitV6.Store(hasExitV6)
		// 已批准 → 它现在是「在线在跑的出口」,广播让出口下拉实时增项。DB 查不动(q=false)时不广播(待下次)。
		approved, q := deviceHasApprovedExitRoute(dbCtx, c.deviceID)
		// M2 豁免闸:只有**已确切查到且已批准**才允许该出口会话以非 vIP 源发包(见 connSourceSpoofed)。
		// q=false(DB 查不动)时保守置 false —— 宁可对一个可能合法的出口多做一次 vIP 源校验(它以自身 vIP
		// 作源的正常流量本就放行),也不放开一个未确证的豁免。
		if q {
			c.advertisedExitApproved.Store(approved)
		}
		if approved && q {
			go broadcastExitsList(context.Background())
		}
	}
	// subnet route(SR-M4 深扫):本帧声明了具体(非 0/0)CIDR → 本会话「真在跑子网路由器」(已装 dst 限定 NAT——客户端
	// 在发帧前就 apply 了),打标使 forwardPacketToSubnetRoute 认它为合法转发目标。
	// 用 advPfx(归一后、独立于 upsert 成败——见上方说明)同时驱动布尔标与 per-CIDR 集,二者保持一致。
	if len(advPfx) > 0 {
		c.advertisedSubnetRoutes.Store(true)
		// 第 9 轮深扫:以**本帧为准 replace**(非 union prev)。客户端每次发的是**全量**当前宣告集(send_route_advertise
		// 灌 advertise_routes 完整列表、非增量),故本帧即等于设备当前所 NAT 的全集。若 union 累积,则设备**收窄**宣告后经
		// **takeover 重连**(继承旧集 + 再收到新的窄帧)会把已移除网段留在集里 → per-CIDR 门控失效(fresh 重连因新会话空集重建
		// 侥幸不受影响,takeover 却漏)。replace 对 fresh/takeover 两种重连都正确剔除,且天然无累积→无界增长(集恒 ≤ 单帧 ≤64)。
		// unionPrefixes(nil,…) 复用为「去重 + 上限兜底」。hot-switch(promote_to 不重发 advertise)靠 takeover 继承,本分支不触发。
		replaced := unionPrefixes(nil, advPfx)
		c.advertisedRoutes.Store(&replaced)
		// ROUTES-ONLINE 刷新:routes-list 每条的 Online = 宣告方设备当前有活跃会话(lookupActiveConnByDevice)。
		// 但它仅在「客户端连入 / admin 改路由」时算过一次——宣告方**晚于**请求方上线(或重连)时,已连接请求方手里的
		// online 会停在旧的 false(UI 一直显示「离线」,即便宣告方明明在线)。本会话既已宣告具体网段、又确是**已批准**
		// 宣告方(在生效表里)→ 广播一帧让所有请求方刷新 online 圆点(与出口上线 broadcastExitsList 对齐)。
		// **仅刷新展示**:请求方装路由不看 online(accepted_cidrs_excluding_own 只按 own uuid / 拒 /0 过滤),故不抖数据面
		// 路由(离线包本就 server 侧丢)。未批准(不在表)时不广播——待 admin 批准触发 rebuild + broadcastRoutesList。
		inTable := deviceInSubnetRouteTable(c.deviceID)
		// M2 豁免闸:仅当本设备确在**已批准**子网路由生效表里时,才允许它以非 vIP 源(LAN 回程)发包。
		c.advertisedSubnetApproved.Store(inTable)
		if inTable {
			go broadcastRoutesList(context.Background())
		}
	}
	// 注意:**不**在「非出口帧 / 无 /0 的帧」里清 advertisedExit,亦**不**在「纯出口帧 / 无具体 CIDR 的帧」里清
	// advertisedSubnetRoutes —— 客户端表达「不再做出口 / 子网路由器」的途径只有两条:① 发空 advertise 撤回所有声明
	// (上面空 routes 分支已清两个标+出口广播);② 直接断开(连接从 connIDMap 移除,自然消失)。一个仍在服务的会话可能
	// 后续只发增量/另一类帧(不重列已声明项),此处若按「本帧没这类即清」会误把它踢出在跑集 → 黑洞(正是要修的那类)。
	// 故两个标都收窄为「仅显式空撤回 / 断开才清」(Bugbot 第三轮复核同款收口)。
}

// sendRouteApproveStatusForDevice 给客户端回一帧,带上 device 名下当前所有路由的状态。
// 若 only 非空,则只发 only 列表中存在的 CIDR(覆盖刚 upsert 的);为空时回全表。
//
// 客户端 UI 可据此渲染 pending → approved 状态变迁。
func sendRouteApproveStatusForDevice(ctx context.Context, c *Connection, only []string) error {
	gw := gatewayInstance
	if gw == nil || gw.store == nil || c == nil || c.deviceID == 0 {
		return nil
	}
	rows, err := gw.store.ListRoutesByDevice(ctx, c.deviceID)
	if err != nil {
		return err
	}
	filter := make(map[string]struct{}, len(only))
	for _, c := range only {
		filter[c] = struct{}{}
	}
	updated := make([]util.RouteStatusEntry, 0, len(rows))
	for _, r := range rows {
		if len(filter) > 0 {
			if _, ok := filter[r.CIDR]; !ok {
				continue
			}
		}
		at := r.AdvertisedAt
		if r.ApprovedAt > at {
			at = r.ApprovedAt
		}
		updated = append(updated, util.RouteStatusEntry{
			CIDR:   r.CIDR,
			Status: r.Status,
			Reason: r.Reason,
			At:     at,
		})
	}
	body, err := util.MarshalRouteApproveStatus(updated)
	if err != nil {
		return err
	}
	c.linkWrMu.Lock()
	defer c.linkWrMu.Unlock()
	// 写超时:本函数从 readLoop 同步调用(handleRouteAdvertiseFrame)且持 linkWrMu,若客户端停止读取会让写
	// 永久阻塞、顶死同样需要 linkWrMu 的 kick / evict / keepalive。借数据面 Ping 的 deadliner 机制加 5s 上限。
	if dl, ok := c.linkConn.(deadliner); ok {
		_ = dl.SetWriteDeadline(time.Now().Add(dataPlanePingWriteDeadline))
		defer func() { _ = dl.SetWriteDeadline(time.Time{}) }()
	}
	return util.WriteLinkFrame(c.linkConn, util.LinkTypeRouteApproveStatus, body)
}

// broadcastRouteApproveStatusToAdvertisers 给所有「本会话真在跑出口 / 子网路由器」的在线会话各推一帧其设备当前
// 路由审批状态快照(RouteApproveStatus)。admin 改批准(route approve / reject / delete、exit designate / revoke)后
// 调用,让**宣告方**客户端 UI 的「待审批 → 已批准 / 已拒绝」实时翻转——否则宣告方只在下次重连 / 重发声明时才收到
// sendRouteApproveStatusForDevice,审批态会长期停在 pending。
//
// 门控 advertisedExit || advertisedSubnetRoutes:仅推给「确实宣告过出口 / 子网」的会话,避免给无关普通客户端发空帧。
// 低频(仅 admin 改批准时);持 connIDMapMu RLock 收集指针,锁外逐个查库 + 写(sendRouteApproveStatusForDevice 内含 DB
// 查询与链路写,不可在持锁时做)。与 broadcastExitsList / broadcastRoutesList 同并发模式。
func broadcastRouteApproveStatusToAdvertisers(ctx context.Context) {
	connIDMapMu.RLock()
	targets := make([]*Connection, 0)
	for _, c := range connIDMap {
		// !superseded：跳过即将被踢除待清理的会话(无谓给死链路写审批帧;与 by-device lookup / buildExitsList 同口径)。
		if c != nil && !c.takenOver.Load() && !c.superseded.Load() && (c.advertisedExit.Load() || c.advertisedSubnetRoutes.Load()) {
			targets = append(targets, c)
		}
	}
	connIDMapMu.RUnlock()
	for _, c := range targets {
		_ = sendRouteApproveStatusForDevice(ctx, c, nil)
		// M2 豁免闸刷新:admin 在宣告方**在线时**批准/撤销出口 / 子网路由,须同步更新 connSourceSpoofed 用的
		// 已批准缓存——否则「登录时未批准(闸=false)→ 在线期间被批准」的会话,其合法的非 vIP 源回程流量会一直
		// 被误丢到下次重连(反之撤销后也应立即收紧)。仅在 DB 能确切判定(ok / deviceInSubnetRouteTable)时改写。
		if c.advertisedExit.Load() {
			if approved, ok := deviceHasApprovedExitRoute(ctx, c.deviceID); ok {
				c.advertisedExitApproved.Store(approved)
			}
		}
		if c.advertisedSubnetRoutes.Load() {
			c.advertisedSubnetApproved.Store(deviceInSubnetRouteTable(c.deviceID))
		}
	}
}
