package main

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/nanotun/server/util"

	"github.com/sirupsen/logrus"
)

// subnet route 选择器（SR-M3）：server → client 推送「当前可用的已批准子网路由列表」(LinkTypeRoutesList=22)。
//
// 设计（docs/DESIGN_SUBNET_ROUTES.md）：纯推送，客户端只听不问。
//   - 初始：客户端连上后 server 推一帧当前列表（pushInitialRoutesList，推给**所有**客户端——任意用户都可能要访问内网资源，
//     不像出口列表限 exit_allowed；细粒度 per-user 授权留 SR-M4 ACL）；
//   - 变更：admin 改路由批准（/reload?what=routes）后 broadcastRoutesList 重算并广播给所有在线会话。
//
// 数据来自 SR-M1 的 subnetRouteTable（已批准非 0/0 CIDR 快照）+ 在线性（lookupActiveConnByDevice）+ 设备名（GetDevice）。

// buildRoutesList 从 subnetRouteTable 快照派生「可用子网路由」列表，富化在线性与设备名。
// Online = 该宣告方当前有活跃会话；离线也列出（避免请求方路由频繁增删——发往离线宣告方的包在 server 侧丢弃）。
func buildRoutesList(ctx context.Context) []util.SubnetRouteInfo {
	ptr := subnetRouteTable.Load()
	if ptr == nil {
		return nil
	}
	tbl := *ptr
	if len(tbl) == 0 {
		return nil
	}
	gw := gatewayInstance
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// SR-VIA6：一次拉全部 device→siteID 映射，填进每条（请求方据此 + 内置前缀构造 4via6 地址）。查失败 → nil map，
	// 各条 SiteID 取零值 0（表示未分配），请求方回退纯 v4，不阻断列表下发。
	var via6Sites map[int64]uint16
	if gw != nil && gw.store != nil {
		via6Sites, _ = gw.store.ListVia6Sites(dbCtx)
	}
	type devInfo struct{ uuid, name string }
	// 按 device 缓存 GetDevice（同设备多网段只查一次）。
	devCache := make(map[int64]devInfo, len(tbl))
	out := make([]util.SubnetRouteInfo, 0, len(tbl))
	for _, e := range tbl {
		di, ok := devCache[e.deviceID]
		if !ok {
			if gw != nil && gw.store != nil {
				if dev, err := gw.store.GetDevice(dbCtx, e.deviceID); err == nil && dev != nil {
					// alias(0020):展示名优先管理员别名(与 exits-list 同口径)。
					di = devInfo{uuid: dev.DeviceUUID, name: dev.DisplayName()}
				}
			}
			devCache[e.deviceID] = di
		}
		out = append(out, util.SubnetRouteInfo{
			CIDR:       e.prefix.String(),
			DeviceUUID: di.uuid,
			DeviceName: di.name,
			// Online 必须与**数据面转发闸同口径**（deviceServesSubnetRoute）：宣告方须「真在跑子网路由器
			// （advertisedSubnetRoutes）且当前仍宣告该具体 CIDR」才算可达。此前用 lookupActiveConnByDevice（设备**有任意
			// 会话**即算在线），会把「设备在线但本次只跑 --exit-node / 未宣告该网段」误显示为"通"，而数据面
			// forwardPacketToSubnetRoute 实际按 lookupSubnetAdvertiserConnByDevice + per-CIDR 丢弃 → UI 显示通、发包却丢。
			Online: deviceServesSubnetRoute(e.deviceID, e.prefix),
			SiteID: via6Sites[e.deviceID], // 未分配 → 0
		})
	}
	return out
}

// deviceServesSubnetRoute 报告「该 device 此刻是否**真在为 prefix 提供子网路由**」——与数据面 forwardPacketToSubnetRoute
// 的转发闸完全同口径，供 buildRoutesList 的 Online 用，杜绝「列表显示通、实际发包被丢」：
//   - 无「真在跑子网路由器」会话（下线 / 本次只跑 --exit-node / 普通客户端连入）→ false；
//   - 有该会话但其**当前宣告集**不覆盖 prefix（重连收窄了宣告、DB 批准仍在）→ false；
//   - 宣告集为 nil/空（在跑但集未知）→ true（与数据面 nil→放行 的防御性兜底对齐）。
func deviceServesSubnetRoute(deviceID int64, prefix netip.Prefix) bool {
	advConn := lookupSubnetAdvertiserConnByDevice(deviceID)
	if advConn == nil {
		return false
	}
	pfxs := advConn.advertisedRoutes.Load()
	if pfxs == nil || len(*pfxs) == 0 {
		return true
	}
	for _, p := range *pfxs {
		if p.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

// sendRoutesListTo best-effort 给一条会话推一帧子网路由列表。
func sendRoutesListTo(c *Connection, routes []util.SubnetRouteInfo) {
	// 深扫第十轮 MED(既有):linkConn 的 nil 判定走 linkWrMu(interface 读写都走该锁),
	// 用 safeLinkConn() race-free 预筛,写锁内再复核。见 sendExitsListTo 同款说明。
	if c == nil || c.safeLinkConn() == nil {
		return
	}
	body, err := util.MarshalRoutesList(routes)
	if err != nil {
		return
	}
	c.linkWrMu.Lock()
	defer c.linkWrMu.Unlock()
	if c.linkConn == nil {
		return
	}
	// 与 sendExitsListTo 同口径钉 5s 写超时：避免一个卡死/写阻塞的客户端（TCP 窗口满）持 routesBroadcastMu 拖住
	// **所有**子网路由广播与初始推送。超时后该帧写失败（仅 Debug），不影响其它客户端。
	if dl, ok := c.linkConn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = dl.SetWriteDeadline(time.Now().Add(5 * time.Second))
		defer func() { _ = dl.SetWriteDeadline(time.Time{}) }()
	}
	if werr := util.WriteLinkFrame(c.linkConn, util.LinkTypeRoutesList, body); werr != nil {
		logrus.WithError(werr).WithField("user_id", c.userID).Debug("[routes] 推送子网路由列表失败")
	}
}

// routesBroadcastMu 串行化「重算 + 广播」（与 exitsBroadcastMu 独立，互不阻塞）：防较慢的旧广播覆盖较新广播。
// 低频（仅 admin 改路由 / 客户端连入），串行化开销可忽略。
var routesBroadcastMu sync.Mutex

// pushInitialRoutesList 给刚连上的客户端推一帧当前子网路由列表（推给**所有**客户端）。持 routesBroadcastMu 与
// broadcastRoutesList 保总序，避免初始推送（旧快照）落在一次 broadcast（新快照）之后覆盖回去。
func pushInitialRoutesList(ctx context.Context, c *Connection) {
	if c == nil {
		return
	}
	routesBroadcastMu.Lock()
	defer routesBroadcastMu.Unlock()
	sendRoutesListTo(c, buildRoutesList(ctx))
}

// broadcastRoutesList 重算并广播给所有在线会话（admin 改路由批准后调，低频）。先 RLock 内收集指针，锁外逐个写。
func broadcastRoutesList(ctx context.Context) {
	routesBroadcastMu.Lock()
	defer routesBroadcastMu.Unlock()
	routes := buildRoutesList(ctx)
	connIDMapMu.RLock()
	targets := make([]*Connection, 0, len(connIDMap))
	for _, c := range connIDMap {
		if c != nil && !c.takenOver.Load() {
			targets = append(targets, c)
		}
	}
	connIDMapMu.RUnlock()
	for _, c := range targets {
		sendRoutesListTo(c, routes)
	}
}
