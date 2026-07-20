package main

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// routes handlers — subnet route advertise(P2#12 控制面) + 出口节点一键指定。
//
//   GET  /routes                 → list(默认按 pending → approved → rejected 排序)
//   POST /routes/{device_id}/{cidr}/approve
//   POST /routes/{device_id}/{cidr}/reject?reason=
//   POST /routes/{device_id}/{cidr}/delete
//   POST /routes/exit/designate  → 一键指定出口(表单 device_id;等价 admin CLI `exit designate`)
//   POST /routes/exit/revoke     → 撤销出口(表单 device_id)
//
// 注意:CIDR 含 "/",URL 转义后形如 "10.0.0.0%2F24",handler 自己 unescape。

// exitView:routes 页「出口节点」卡片一行(有 approved 0/0 或 ::/0 的 device)。
type exitView struct {
	DeviceID   int64
	DeviceName string
	DeviceUUID string
	HasV4      bool
	HasV6      bool
	FixedVIPv4 string
	FixedVIPv6 string
}

// pendingExitView:客户端 --exit-node 自荐、尚未批准的出口(按 device 合并 v4/v6)。
// UI 不再暴露 0.0.0.0/0 技术细节,统一「批准作为出口」。
// 也复用于「已拒绝的出口自荐」列表(Reason 仅该场景使用)。
type pendingExitView struct {
	DeviceID     int64
	DeviceName   string
	DeviceUUID   string
	Platform     string
	HasV4        bool
	HasV6        bool
	AdvertisedAt int64
	Capable      bool   // 平台是否可作出口;不可则只给拒绝、不给批准
	Reason       string // rejected 场景:拒绝原因
}

func (s *Server) handleRouteList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	all, err := s.store.ListAllRoutes(r.Context())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "list routes: "+err.Error())
		return
	}
	// 设备名索引:routes 行 / 出口卡片 / 指定出口下拉都要展示人类可读名。
	devs, err := s.store.ListAllDevices(r.Context())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "list devices: "+err.Error())
		return
	}
	devByID := make(map[int64]*store.Device, len(devs))
	for _, d := range devs {
		devByID[d.ID] = d
	}
	// 按 status 分桶:
	//   - 出口 0/0 / ::/0 从「子网路由」表里拆出 —— 已批准进 EXIT 卡,待批进 PendingExits,
	//     避免管理员对着两行 CIDR 猜「这是不是出口」。
	//   - 普通 CIDR 仍走 Pending / Approved / Rejected。
	pending := make([]store.SubnetRoute, 0)
	approved := make([]store.SubnetRoute, 0)
	rejected := make([]store.SubnetRoute, 0)
	exitByDev := map[int64]*exitView{}
	exitOrder := make([]int64, 0)
	pendingExitByDev := map[int64]*pendingExitView{}
	pendingExitOrder := make([]int64, 0)
	rejectedExitByDev := map[int64]*pendingExitView{}
	rejectedExitOrder := make([]int64, 0)
	for _, x := range all {
		if util.IsExitDefaultRoute(x.CIDR) {
			switch x.Status {
			case store.RouteStatusApproved:
				ev, ok := exitByDev[x.DeviceID]
				if !ok {
					ev = &exitView{DeviceID: x.DeviceID}
					if d := devByID[x.DeviceID]; d != nil {
						ev.DeviceName = d.DisplayName()
						ev.DeviceUUID = d.DeviceUUID
						ev.FixedVIPv4 = d.FixedVIPv4
						ev.FixedVIPv6 = d.FixedVIPv6
					}
					exitByDev[x.DeviceID] = ev
					exitOrder = append(exitOrder, x.DeviceID)
				}
				switch x.CIDR {
				case util.ExitDefaultRouteV4:
					ev.HasV4 = true
				case util.ExitDefaultRouteV6:
					ev.HasV6 = true
				}
			case store.RouteStatusPending:
				pev, ok := pendingExitByDev[x.DeviceID]
				if !ok {
					pev = &pendingExitView{DeviceID: x.DeviceID}
					if d := devByID[x.DeviceID]; d != nil {
						pev.DeviceName = d.DisplayName()
						pev.DeviceUUID = d.DeviceUUID
						pev.Platform = d.Platform
						pev.Capable = store.IsExitCapablePlatform(d.Platform)
					}
					pendingExitByDev[x.DeviceID] = pev
					pendingExitOrder = append(pendingExitOrder, x.DeviceID)
				}
				if x.AdvertisedAt > pev.AdvertisedAt {
					pev.AdvertisedAt = x.AdvertisedAt
				}
				switch x.CIDR {
				case util.ExitDefaultRouteV4:
					pev.HasV4 = true
				case util.ExitDefaultRouteV6:
					pev.HasV6 = true
				}
			case store.RouteStatusRejected:
				// 已拒绝的出口自荐必须可见:UpsertAdvertisedRoute 冲突时只刷 advertised_at、
				// status 冻结在 rejected —— 客户端反复自荐也**不会**回到 pending。若这里不展示,
				// 误拒后 admin 会以为客户端没再自荐,且无 UI 入口恢复(只能靠 CLI)。
				rev, ok := rejectedExitByDev[x.DeviceID]
				if !ok {
					rev = &pendingExitView{DeviceID: x.DeviceID}
					if d := devByID[x.DeviceID]; d != nil {
						rev.DeviceName = d.DisplayName()
						rev.DeviceUUID = d.DeviceUUID
						rev.Platform = d.Platform
						rev.Capable = store.IsExitCapablePlatform(d.Platform)
					}
					rejectedExitByDev[x.DeviceID] = rev
					rejectedExitOrder = append(rejectedExitOrder, x.DeviceID)
				}
				if x.AdvertisedAt > rev.AdvertisedAt {
					rev.AdvertisedAt = x.AdvertisedAt
				}
				if rev.Reason == "" && x.Reason != "" {
					rev.Reason = x.Reason
				}
				switch x.CIDR {
				case util.ExitDefaultRouteV4:
					rev.HasV4 = true
				case util.ExitDefaultRouteV6:
					rev.HasV6 = true
				}
			}
			continue
		}
		switch x.Status {
		case store.RouteStatusPending:
			pending = append(pending, x)
		case store.RouteStatusApproved:
			approved = append(approved, x)
		case store.RouteStatusRejected:
			rejected = append(rejected, x)
		}
	}
	exits := make([]exitView, 0, len(exitOrder))
	for _, id := range exitOrder {
		exits = append(exits, *exitByDev[id])
	}
	pendingExits := make([]pendingExitView, 0, len(pendingExitOrder))
	for _, id := range pendingExitOrder {
		pendingExits = append(pendingExits, *pendingExitByDev[id])
	}
	rejectedExits := make([]pendingExitView, 0, len(rejectedExitOrder))
	for _, id := range rejectedExitOrder {
		// 同设备已有 approved(出口卡)或 pending(待批卡)行时不再重复展示 rejected 残留,
		// 避免一台设备同时出现在三张卡里让人困惑。
		if _, isExit := exitByDev[id]; isExit {
			continue
		}
		if _, isPending := pendingExitByDev[id]; isPending {
			continue
		}
		rejectedExits = append(rejectedExits, *rejectedExitByDev[id])
	}
	// 已禁用用户集合:其设备不能进出口候选 —— server 的 buildExitsList 会把「已批准
	// 但离线」的出口也推进所有客户端下拉(Online=false),而禁用用户根本连不上,
	// 指定了就是一个永远点不亮的死出口挂在所有人列表里。
	disabledUsers := map[int64]bool{}
	if users, uerr := s.store.ListUsersAll(r.Context()); uerr == nil {
		for _, u := range users {
			if u.DisabledAt != 0 {
				disabledUsers[u.ID] = true
			}
		}
	}
	// 指定出口下拉:只列能跑 --exit-node 的平台(linux/windows/macos/router=OpenWrt),
	// 并排除已是出口的设备与禁用用户的设备。iOS/Android 没有内核 NAT 能力,选了也只是焊一纸批准。
	candidates := make([]*store.Device, 0, len(devs))
	for _, d := range devs {
		if _, isExit := exitByDev[d.ID]; isExit {
			continue
		}
		if !store.IsExitCapablePlatform(d.Platform) {
			continue
		}
		if disabledUsers[d.UserID] {
			continue
		}
		candidates = append(candidates, d)
	}
	// 设备名 map 给 pending/approved/rejected 表展示(id → name;无名回落空串,模板补 "-")。
	// alias(0020):优先管理员别名。
	devNames := make(map[int64]string, len(devByID))
	for id, d := range devByID {
		devNames[id] = d.DisplayName()
	}
	s.renderPage(w, r, "routes_list.html", PageData{
		Title: tr(r, "page.routes.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:approve/reject/delete redirect 都写 flash
		Data: map[string]any{
			"Pending":        pending,
			"PendingExits":   pendingExits,
			"RejectedExits":  rejectedExits,
			"Approved":       approved,
			"Rejected":       rejected,
			"Exits":          exits,
			"ExitCandidates": candidates,
			"DevNames":       devNames,
		},
		Nav: NavContext{Active: "routes"},
	})
}

// handleExitAction:POST /routes/exit/designate | /routes/exit/revoke | /routes/exit/reject。
//
// designate 等价 admin CLI `exit designate <id>`(docs/DESIGN_EXIT_NODE.md):
//  1. upsert + approve 0.0.0.0/0 与 ::/0 —— 设备尚未自荐也能预先焊死,之后跑 --exit-node 连上即已批准;
//  2. 钉固定 vIP:默认把当前 lease 的 vIP 焊死(出口是基础设施,地址应稳定);无 lease / 已有 fixed 则保持不动;
//  3. best-effort 通知 server 即时把新出口推给客户端下拉。
//
// revoke:删 0/0 + ::/0(fixed vIP 保留 —— 需要清可去设备详情页),通知 server 把绑定它的会话踢回 server 自出口。
// reject:把该设备 pending 的 0/0 + ::/0 标为 rejected(客户端 --exit-node 自荐被拒)。
func (s *Server) handleExitAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	deviceID, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("device_id")), 10, 64)
	if err != nil || deviceID <= 0 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.invalidDeviceId"))
		return
	}
	d, err := s.store.GetDevice(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, tr(r, "err.deviceNotFound"))
			return
		}
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryFailed")+err.Error())
		return
	}

	segs := pathSegments(r.URL.Path) // [routes, exit, verb]
	if len(segs) < 3 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.unknownAction"))
		return
	}
	switch segs[2] {
	case "designate":
		// 与下拉过滤同口径:防绕过 UI 对手机 / 未知平台直接 POST designate。
		if !store.IsExitCapablePlatform(d.Platform) {
			s.renderError(w, r, http.StatusBadRequest,
				tr(r, "err.exitPlatformUnsupported", d.Platform))
			return
		}
		// 禁用用户的设备连不上 server,批了就是死出口挂进所有客户端下拉(buildExitsList
		// 连离线出口一起推)。先解禁再指定。
		if owner, oerr := s.store.GetUser(r.Context(), d.UserID); oerr != nil {
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryFailed")+oerr.Error())
			return
		} else if owner.DisabledAt != 0 {
			s.renderError(w, r, http.StatusBadRequest,
				tr(r, "err.exitOwnerDisabled", owner.Username))
			return
		}
		// 1) 批准 0/0 + ::/0(幂等:已存在只刷 advertised_at,再置 approved)。
		for _, cidr := range []string{util.ExitDefaultRouteV4, util.ExitDefaultRouteV6} {
			if _, err := s.store.UpsertAdvertisedRoute(r.Context(), deviceID, cidr); err != nil {
				s.renderError(w, r, http.StatusInternalServerError, "upsert route "+cidr+": "+err.Error())
				return
			}
			if err := s.store.SetRouteStatus(r.Context(), deviceID, cidr, store.RouteStatusApproved, ""); err != nil {
				s.renderError(w, r, http.StatusInternalServerError, "approve route "+cidr+": "+err.Error())
				return
			}
		}
		// 2) 钉固定 vIP:与 CLI 默认一致 —— 把当前 lease 的 vIP 焊死;某族已有 fixed / lease
		//    没该族地址则保持不动。冲突时**不整单失败**(出口路由已批),按「跳过钉 vIP」降级,
		//    flash 提示管理员去设备详情页手动处理。
		newV4, newV6 := d.FixedVIPv4, d.FixedVIPv6
		if lease, lerr := s.store.GetLeaseByDevice(r.Context(), deviceID); lerr == nil {
			if newV4 == "" && lease.VIPv4 != "" {
				newV4 = lease.VIPv4
			}
			if newV6 == "" && lease.VIPv6 != "" {
				newV6 = lease.VIPv6
			}
		}
		vipNote := ""
		if newV4 != d.FixedVIPv4 || newV6 != d.FixedVIPv6 {
			conflict := ""
			if newV4 != d.FixedVIPv4 {
				if c, cerr := s.checkFixedVIPConflict(r.Context(), newV4, deviceID); cerr == nil && c != "" {
					conflict = c
				}
			}
			if conflict == "" && newV6 != d.FixedVIPv6 {
				if c, cerr := s.checkFixedVIPConflict(r.Context(), newV6, deviceID); cerr == nil && c != "" {
					conflict = c
				}
			}
			if conflict != "" {
				vipNote = tr(r, "flash.exitDesignatedVipConflict")
			} else if err := s.store.SetDeviceFixedVIP(r.Context(), deviceID, newV4, newV6); err != nil {
				// UNIQUE 兜底等罕见失败:同样降级,不回滚已批准的出口路由。
				vipNote = tr(r, "flash.exitDesignatedVipFailed")
			}
		}
		if vipNote == "" && newV4 == "" && newV6 == "" {
			// 无 lease 也无 fixed(设备从未上线):出口照样批,提醒 vIP 尚未固定。
			vipNote = tr(r, "flash.exitDesignatedNoVip")
		}
		s.audit.WriteFromRequest(r, "exit_designate", FormatTarget("device", deviceID),
			FormatDetail("uuid", d.DeviceUUID, "fixed_v4", newV4, "fixed_v6", newV6))
		tryReloadExitsBackground(s.control)
		msg := tr(r, "flash.exitDesignated", deviceDisplayName(d)) + vipNote
		http.Redirect(w, r, "/routes?flash="+url.QueryEscape(msg), http.StatusSeeOther)

	case "revoke":
		removed := 0
		for _, cidr := range []string{util.ExitDefaultRouteV4, util.ExitDefaultRouteV6} {
			err := s.store.DeleteRoute(r.Context(), deviceID, cidr)
			switch {
			case err == nil:
				removed++
			case errors.Is(err, store.ErrNotFound):
				// 本就没有该族出口路由,跳过。
			default:
				s.renderError(w, r, http.StatusInternalServerError, "delete route "+cidr+": "+err.Error())
				return
			}
		}
		// mode=clear:同一动作的另一语义 —— 清除**已拒绝**的自荐记录(删行后客户端
		// 下次自荐重新落 pending)。数据操作与 revoke 完全一致,只有文案/审计不同。
		mode := strings.TrimSpace(r.FormValue("mode"))
		s.audit.WriteFromRequest(r, "exit_revoke", FormatTarget("device", deviceID),
			FormatDetail("uuid", d.DeviceUUID, "removed", removed, "mode", mode))
		tryReloadExitsBackground(s.control)
		msg := tr(r, "flash.exitRevoked", deviceDisplayName(d))
		if mode == "clear" {
			msg = tr(r, "flash.exitNominationCleared", deviceDisplayName(d))
		}
		http.Redirect(w, r, "/routes?flash="+url.QueryEscape(msg), http.StatusSeeOther)

	case "reject":
		// 拒绝客户端出口自荐:把 pending 的 0/0 + ::/0 一并标 rejected(一次按钮,不拆两行 CIDR)。
		// 只动 pending 行 —— SetRouteStatus 本身不看当前状态,若不加这道闸,绕过 UI 直 POST
		// 能把 approved 出口悄悄翻成 rejected(等价隐式撤销,还留下拒绝残留);撤销必须走 revoke。
		reason := strings.TrimSpace(r.FormValue("reason"))
		rejectedN := 0
		for _, cidr := range []string{util.ExitDefaultRouteV4, util.ExitDefaultRouteV6} {
			cur, gerr := s.store.GetRouteByDeviceCIDR(r.Context(), deviceID, cidr)
			switch {
			case errors.Is(gerr, store.ErrNotFound):
				continue // 该族没有记录,跳过
			case gerr != nil:
				s.renderError(w, r, http.StatusInternalServerError, "reject exit "+cidr+": "+gerr.Error())
				return
			}
			if cur.Status != store.RouteStatusPending {
				continue
			}
			if err := s.store.SetRouteStatus(r.Context(), deviceID, cidr, store.RouteStatusRejected, reason); err != nil {
				s.renderError(w, r, http.StatusInternalServerError, "reject exit "+cidr+": "+err.Error())
				return
			}
			rejectedN++
		}
		s.audit.WriteFromRequest(r, "exit_reject", FormatTarget("device", deviceID),
			FormatDetail("uuid", d.DeviceUUID, "rejected", rejectedN, "reason", reason))
		tryReloadExitsBackground(s.control)
		http.Redirect(w, r,
			"/routes?flash="+url.QueryEscape(tr(r, "flash.exitRejected", deviceDisplayName(d))),
			http.StatusSeeOther)

	default:
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.unknownAction"))
	}
}

// deviceDisplayName:flash 文案里的设备称呼 —— 别名 > 上报名 > device/{id}。
func deviceDisplayName(d *store.Device) string {
	if n := d.DisplayName(); n != "" {
		return n
	}
	return "device/" + strconv.FormatInt(d.ID, 10)
}

func (s *Server) handleRouteAction(w http.ResponseWriter, r *http.Request) {
	// 第十三轮深扫 P1:CIDR 必含 "/"。模板虽然用 urlquery 编码成 %2F,但 Go 在
	// url.Parse 阶段就把 %2F 解码回真斜杠放进 r.URL.Path —— 到这里 path 已是
	// /routes/5/10.42.0.0/24/approve(5 段)。旧代码按固定下标 segs[3] 取 verb,
	// 拿到的是掩码 "24",所有子网路由的 approve/reject/delete 一律 400「未知操作」。
	// 正确解法:verb 恒取最后一段,device_id 与 verb 之间的所有段拼回 CIDR
	// (IPv6 的冒号不受影响)。裸斜杠(curl 手拼)与编码形态由此同构。
	segs := pathSegments(r.URL.Path) // [routes, device_id, cidr..., verb]
	if len(segs) < 4 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "routes.needPathVerb"))
		return
	}
	deviceID, err := strconv.ParseInt(segs[1], 10, 64)
	if err != nil || deviceID <= 0 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.invalidDeviceId"))
		return
	}
	verb := segs[len(segs)-1]
	cidr := strings.Join(segs[2:len(segs)-1], "/")
	// 防御:上游代理若把 %2F 原样透传(双重编码等),这里兜底还原。
	cidr = strings.ReplaceAll(cidr, "%2F", "/")
	cidr = strings.ReplaceAll(cidr, "%2f", "/")

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	switch verb {
	case "approve":
		// 出口默认路由(0/0 / ::/0)与一键 designate 同口径:手机端不能真跑出口。
		// 第十六轮:闸口 fail-closed —— GetDevice 出错(瞬态 DB 故障)时拒绝而非放行,
		// 否则闸口在最不该失效的时刻(系统异常)恰好敞开。
		if util.IsExitDefaultRoute(cidr) {
			d, gerr := s.store.GetDevice(r.Context(), deviceID)
			switch {
			case errors.Is(gerr, store.ErrNotFound):
				// 设备已删 → 路由行也被级联删了,approve 无意义。
				s.renderError(w, r, http.StatusNotFound, tr(r, "err.deviceNotFound"))
				return
			case gerr != nil:
				s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryFailed")+gerr.Error())
				return
			}
			if !store.IsExitCapablePlatform(d.Platform) {
				s.renderError(w, r, http.StatusBadRequest,
					tr(r, "err.exitPlatformUnsupported", d.Platform))
				return
			}
		}
		if err := s.store.SetRouteStatus(r.Context(), deviceID, cidr, store.RouteStatusApproved, ""); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "approve: "+err.Error())
			return
		}
		s.audit.WriteFromRequest(r, "route_approve",
			FormatTarget("route", strconv.FormatInt(deviceID, 10)+"/"+cidr),
			FormatDetail("cidr", cidr))
		// 2026-07-19:补齐与 admin CLI 对等的 best-effort server 通知(此前 web 审批后
		// 要等客户端重连 / 下次路由变更才收敛)。出口路由(0/0、::/0)走 exits 重算,
		// 普通子网走 routes 重建。
		notifyRouteChangeBackground(s.control, cidr)
		// 第三轮深扫 P2-8:cidr 是 path 参数,虽 SetRouteStatus 已存入,但其原始形态
		// 可能含 `/`(被 path encode 成 `%2F`),拼到 query 时仍要 QueryEscape 防混乱。
		http.Redirect(w, r,
			"/routes?flash="+url.QueryEscape(tr(r, "flash.routeApproved", cidr)),
			http.StatusSeeOther)
	case "reject":
		reason := strings.TrimSpace(r.FormValue("reason"))
		if err := s.store.SetRouteStatus(r.Context(), deviceID, cidr, store.RouteStatusRejected, reason); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "reject: "+err.Error())
			return
		}
		s.audit.WriteFromRequest(r, "route_reject",
			FormatTarget("route", strconv.FormatInt(deviceID, 10)+"/"+cidr),
			FormatDetail("cidr", cidr, "reason", reason))
		notifyRouteChangeBackground(s.control, cidr)
		http.Redirect(w, r, "/routes?flash="+url.QueryEscape(tr(r, "flash.routeRejected")), http.StatusSeeOther)
	case "delete":
		if err := s.store.DeleteRoute(r.Context(), deviceID, cidr); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "delete: "+err.Error())
			return
		}
		s.audit.WriteFromRequest(r, "route_delete",
			FormatTarget("route", strconv.FormatInt(deviceID, 10)+"/"+cidr),
			FormatDetail("cidr", cidr))
		notifyRouteChangeBackground(s.control, cidr)
		http.Redirect(w, r, "/routes?flash="+url.QueryEscape(tr(r, "flash.routeDeleted")), http.StatusSeeOther)
	default:
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.unknownAction"))
	}
}

// notifyRouteChangeBackground:单条路由审批状态变化后的 best-effort server 通知,
// 与 admin CLI cmd_route.go 的分流一致:出口全网路由 → /reload?what=exits(重算出口
// 绑定 + 广播下拉);具体子网 → /reload?what=routes(重建已批准子网路由表)。
func notifyRouteChangeBackground(c *controlClient, cidr string) {
	if util.IsExitDefaultRoute(cidr) {
		tryReloadExitsBackground(c)
	} else {
		tryReloadRoutesBackground(c)
	}
}
