package main

// exit-node 选择器:server → client 推送「当前可选出口设备列表」(LinkTypeExitsList=21)。
//
// 设计(docs/DESIGN_EXIT_NODE.md):纯推送,客户端只听不问。
//   - 初始:exit_allowed 客户端连上后,runLinkTunnel 推一帧当前列表(pushInitialExitsList);
//   - 变更:某「本会话真在跑出口」的设备上线(route_advertise 收到带 /0 的 exit 帧且已批准)/ 下线
//     (cleanupConnection 时 advertisedExit==true)→ broadcastExitsList 重算并广播给所有 exit_allowed 会话。
//
// 「可列出的出口」(buildExitsList):所有 approved 0/0/::/0 的设备都列出，其中 advertisedExit(本会话真在跑)∩在线的
// 标 Online=true，其余(已批准但当前离线)标 Online=false —— 离线出口也留在下拉里**可选**(靠稳定 device_uuid + 固定 vIP，
// 选中后回线上即生效；egress_select 已支持绑定离线已批准出口)。客户端据 Online 置灰显示「(离线)」。
// Q1=全局:不按归属过滤,任意 exit_allowed 用户可见/可用所有出口(单组织语义;多租户可后续按 ACL 收紧)。

import (
	"context"
	"sync"
	"time"

	"github.com/nanotun/server/util"

	"github.com/sirupsen/logrus"
)

// buildExitsList 构建可选出口列表：在线在跑的出口(Online=true) + 已批准但当前离线的出口(Online=false，本轮加)。
// 离线出口也列出、供客户端下拉置灰可选(设计意图，见文件头)。
//
// 四段式 + 锁外只查 DB:① RLock 快照候选(advertisedExit∩在线)→ ② 锁外查 approved + 设备名 → ③ **再次 RLock 复核**
// 收在线出口(Online=true) → ④ 锁外查全部 approved 出口设备，未在线者补 Online=false。② 期间出口可能下线/被接管/撤销声明,
// 每条候选 conn 仍在 map(同一指针)、仍 advertisedExit、未被接管,才收进列表。② 期间出口可能下线/被接管/撤销声明,
// 不复核就会把已离场的出口塞进列表、并可能覆盖更新的 broadcastExitsList(Bugbot #1)。复核到「发送」之间仍有极小窗口,
// 由 broadcastExitsList 的串行化(exitsBroadcastMu)进一步收敛。
func buildExitsList(ctx context.Context) []util.ExitInfo {
	gw := gatewayInstance
	if gw == nil || gw.store == nil {
		return nil
	}
	type cand struct {
		conn     *Connection
		deviceID int64
		uuid     string
	}
	connIDMapMu.RLock()
	cands := make([]cand, 0, 4)
	for _, c := range connIDMap {
		// !superseded：被同 device fresh 重登踢旧 / 会话超限踢除的旧 conn，虽仍 advertisedExit&&!takenOver 但即将关闭，
		// 不应作为「在线出口」列出（否则请求方下拉显示该出口 Online 而其链路已死、出口流量黑洞）。见 Connection.superseded。
		if c != nil && c.advertisedExit.Load() && c.deviceID != 0 && !c.takenOver.Load() && !c.superseded.Load() {
			cands = append(cands, cand{conn: c, deviceID: c.deviceID, uuid: c.deviceUUID})
		}
	}
	connIDMapMu.RUnlock()
	// 注意：cands 为空（当前无任何在线在跑的出口）时**不早退**——④ 仍要从 DB 把「已批准但离线」的出口补进列表
	// （Online=false，供下拉置灰可选）。早退会漏掉「全部已批准出口都当前离线」的情形：那时 cands 空、列表本应只剩
	// 离线出口，却因早退返回空 → 用户唯一的出口一掉线就从下拉消失、再也选不回来（深扫第二轮回归修复）。
	// cands 空时 ②③ 自然空转（不查 DB、out 空），④ 正常从 DB 补离线出口。

	// ② 锁外查 DB(approved + 设备名),按 device 去重(避免同设备多会话重复查)。
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	approved := make(map[int64]bool, len(cands))
	names := make(map[int64]string, len(cands))
	for _, cd := range cands {
		if _, done := approved[cd.deviceID]; done {
			continue
		}
		a, q := deviceHasApprovedExitRoute(dbCtx, cd.deviceID)
		isApproved := a && q // 列表保守:仅「确切查到已批准」才列出;DB 查不动(q=false)时不列(避免列出未经核实的出口)。
		approved[cd.deviceID] = isApproved
		if isApproved {
			if dev, err := gw.store.GetDevice(dbCtx, cd.deviceID); err == nil && dev != nil {
				// alias(0020):下发展示名优先管理员别名,回落客户端上报名。wire 字段不变,老客户端零改动。
				names[cd.deviceID] = dev.DisplayName()
			}
		}
	}

	// ③ 再次 RLock 复核存活:只收 conn 仍在 map(同一指针)+ 仍 advertisedExit + 未接管 + approved 的设备。
	connIDMapMu.RLock()
	seen := make(map[int64]bool, len(cands))
	out := make([]util.ExitInfo, 0, len(cands))
	for _, cd := range cands {
		if seen[cd.deviceID] || !approved[cd.deviceID] {
			continue
		}
		if cur, ok := connIDMap[cd.conn.connIDStr]; !ok || cur != cd.conn ||
			!cd.conn.advertisedExit.Load() || cd.conn.takenOver.Load() || cd.conn.superseded.Load() {
			continue // 该会话已离场 / 不再是在跑出口 / 已被踢除待清理
		}
		seen[cd.deviceID] = true
		out = append(out, util.ExitInfo{DeviceUUID: cd.uuid, DeviceName: names[cd.deviceID], Online: true})
	}
	connIDMapMu.RUnlock() // 锁外再做 ④ 的 DB 查询（不在 connIDMapMu 内查 DB，同 ②）。

	// ④ EXIT-OFFLINE-SELECTABLE（本轮）：把「已被 admin 批准为出口（0/0 或 ::/0）但当前**不在线**」的设备也列进来
	//    （Online=false）。设计意图：出口离线也应留在客户端下拉里**可选**——出口的稳定键是 device_uuid（+ 固定 vIP），
	//    选中后该设备回到线上并真跑 --exit-node 时即生效；egress_select 已支持绑定「已批准但当前离线」的出口（见
	//    TestEgressSelect_BindsApprovedExitEvenWhenOffline）。客户端下拉据 Online 置灰显示「（离线）」，仍可选中。
	//    与 admin `exit list` 同源：ListRoutesByStatus(approved) ∩ IsExitDefaultRoute。DB 查询在锁外做。
	if rows, err := gw.store.ListRoutesByStatus(dbCtx, util.RouteStatusApproved); err == nil {
		addedOffline := make(map[int64]bool)
		for _, r := range rows {
			if !util.IsExitDefaultRoute(r.CIDR) || seen[r.DeviceID] || addedOffline[r.DeviceID] {
				continue // 非出口路由 / 已作为在线出口收录 / 本轮已补
			}
			addedOffline[r.DeviceID] = true
			if dev, derr := gw.store.GetDevice(dbCtx, r.DeviceID); derr == nil && dev != nil && dev.DeviceUUID != "" {
				out = append(out, util.ExitInfo{DeviceUUID: dev.DeviceUUID, DeviceName: dev.DisplayName(), Online: false})
			}
		}
	}
	// 深扫：客户端下拉以 **device_uuid** 为键/值（选中即按 uuid 绑定出口），而上面 ②③④ 的去重都是按 **deviceID**。
	// 若 DB 中同一 device_uuid 对应多个 deviceID 行（设备重注册 / 历史脏数据 / uuid 无唯一约束），会产出多条同 uuid 的
	// ExitInfo → 前端下拉重复项（用户实测「vultr·45320000」出现 3 次）。这里按 uuid 做最终去重：**在线优先**（同 uuid
	// 既有在线又有离线时保留在线那条），空 uuid 丢弃（占位/历史脏数据，选了也无法绑定）。保序。
	return dedupExitsByUUID(out)
}

// dedupExitsByUUID 按 device_uuid 去重出口列表：同 uuid 保留一条，Online=true 优先覆盖已存的 Online=false；
// 空 uuid 丢弃。保持首次出现顺序（在线段在前，见 buildExitsList 的 ③ 在 ④ 之前）。
func dedupExitsByUUID(in []util.ExitInfo) []util.ExitInfo {
	idx := make(map[string]int, len(in))
	out := make([]util.ExitInfo, 0, len(in))
	for _, e := range in {
		if e.DeviceUUID == "" {
			continue
		}
		if i, ok := idx[e.DeviceUUID]; ok {
			// 已有同 uuid：若本条在线而已存离线，升级为在线（名字一并取在线条的）。
			if e.Online && !out[i].Online {
				out[i] = e
			}
			continue
		}
		idx[e.DeviceUUID] = len(out)
		out = append(out, e)
	}
	return out
}

// sendExitsListTo best-effort 给一条 exit_allowed 会话推一帧出口列表。
func sendExitsListTo(c *Connection, exits []util.ExitInfo) {
	// 深扫第十轮 MED(既有):c.linkConn 是 interface(双字),读写都必须走 linkWrMu。
	// 此前在锁外裸读 `c.linkConn == nil` 会与登录路径 `c.linkConn = rwc` 的赋值形成
	// data race。改用 safeLinkConn()(内部持 linkWrMu 读快照,race-free)做预筛,
	// 真正的 nil 判定再在下方写锁内复核(linkConn 一旦置位不会再被清空,无 TOCTOU)。
	if c == nil || !c.exitAllowed || c.safeLinkConn() == nil {
		return
	}
	body, err := util.MarshalExitsList(exits)
	if err != nil {
		return
	}
	c.linkWrMu.Lock()
	defer c.linkWrMu.Unlock()
	if c.linkConn == nil {
		return
	}
	// 深扫第四轮 C:这条链路写在 broadcastExitsList / pushInitialExitsList 持 exitsBroadcastMu 期间执行——给它钉一个
	// 写超时(对齐 user_invalidate 的 1s、tunDemux 的 5s),否则一个卡死/写阻塞的 exit_allowed 客户端(TCP 窗口满)会
	// 一直占着 exitsBroadcastMu,拖住**所有**出口列表广播与初始推送。超时后该帧写失败(仅 Debug 日志),不影响其它客户端。
	if dl, ok := c.linkConn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = dl.SetWriteDeadline(time.Now().Add(5 * time.Second))
		defer func() { _ = dl.SetWriteDeadline(time.Time{}) }()
	}
	if werr := util.WriteLinkFrame(c.linkConn, util.LinkTypeExitsList, body); werr != nil {
		logrus.WithError(werr).WithField("user_id", c.userID).Debug("[exits] 推送出口列表失败")
	}
}

// pushInitialExitsList 给「刚连上的 exit_allowed 客户端」推一帧当前出口列表。非 exit_allowed 直接跳过。
// 同样持 exitsBroadcastMu 与 broadcastExitsList **总序**:否则新客户端的初始推送(旧快照)可能在一次 broadcast
// (新快照)之后落到同一连接,把已下线出口恢复进下拉(Bugbot 第二轮 #2)。低频(每次连入一次),开销可忽略。
func pushInitialExitsList(ctx context.Context, c *Connection) {
	if c == nil || !c.exitAllowed {
		return
	}
	exitsBroadcastMu.Lock()
	defer exitsBroadcastMu.Unlock()
	sendExitsListTo(c, buildExitsList(ctx))
}

// exitsBroadcastMu 串行化「重算 + 广播」：出口上/下线是并发触发(advertise 的 readLoop goroutine / cleanup goroutine),
// 不串行化时两个广播可交错 —— 较慢的旧广播可能在较新广播之后落地,把陈旧列表覆盖回去(Bugbot #1 的排序面)。
// 低频,串行化开销可忽略。注:pushInitialExitsList(给单个新客户端推初始列表)不抢此锁,它不覆盖别人的列表。
var exitsBroadcastMu sync.Mutex

// broadcastExitsList 重算出口列表并广播给所有 exit_allowed 在线会话（出口上/下线时调用,低频）。
// 先快照目标 conn(RLock 内只收集指针),锁外逐个写,避免持 connIDMapMu 期间做链路写。
func broadcastExitsList(ctx context.Context) {
	exitsBroadcastMu.Lock()
	defer exitsBroadcastMu.Unlock()
	exits := buildExitsList(ctx)
	connIDMapMu.RLock()
	targets := make([]*Connection, 0, len(connIDMap))
	for _, c := range connIDMap {
		if c != nil && c.exitAllowed && !c.takenOver.Load() {
			targets = append(targets, c)
		}
	}
	connIDMapMu.RUnlock()
	for _, c := range targets {
		sendExitsListTo(c, exits)
	}
}
