package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/nanotun/server/store"
	"github.com/sirupsen/logrus"
)

// devices handlers
//
//   GET  /devices                       → list(全表,按 user 分组)
//   GET  /devices/{id}                  → 详情(含 fixed_vip 表单)
//   POST /devices/{id}/delete           → 删除
//   POST /devices/{id}/set-fixed-vip    → 钉 fixed vIP(0008 起,device 维度)

func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 0008 起 store 有 ListAllDevices,N+1 query 干掉 — 但展示按 user 分组方便看,
	// 所以这里仍然走 ListUsers + ListDevicesByUser(每用户 1 query,小规模 OK)。
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.renderInternalError(w, r, "devices:list_users", err)
		return
	}
	// 产品方向(2026-05-24):列表页也展示 effective rate。
	// 一次 control fetch 拿 settings + toml;user.bandwidth 直接从 ListUsers 已拿到。
	// device.rate 在 ListDevicesByUser 已拿到。算 min 当场跑。
	// 控件不可达时 settings/toml 按 0 降级(等价于「该层不约束」),保留 device 自身 rate 展示。
	//
	// Q4+Q5(2026-05-25):err 不再吞 — 显式 log 让 troubleshooting 有线索;
	// ControlAvailable 也不再用 EffectiveBurst > 0 间接判定(语义不直观且耦合
	// server-side 默认值实现),改用 err == nil 直接 + s.control != nil。
	var (
		rateCfg   RateConfigSnapshot
		rateCfgOK bool
	)
	if s.control != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		cfg, err := s.control.RateConfig(ctx)
		cancel()
		if err != nil {
			// 不阻断渲染 — 用零值降级(EffectiveBurst=0 后续 effective 计算等价于「
			// settings/toml/user 这三层不约束」,只保留 device 自身 rate),但 log
			// 留痕让运维 grep "fetch RateConfig" 能定位是 socket 不可达还是 server side panic。
			logrus.WithError(err).Warn("[devices] fetch RateConfig from control socket")
		} else {
			rateCfg = cfg
			rateCfgOK = true
		}
	}
	// devView:模板需要 effective rate / human 字符串,go template 算不动 min,
	// 改成 handler 端预算好塞进结构体里(下游只 .EffUpHuman 字符串拼接,无逻辑)。
	type devView struct {
		*store.Device
		EffUpHuman   string
		EffDownHuman string
	}
	type row struct {
		User    *store.User
		Devices []devView
	}
	// 2026-07-19 易用性:?q= 过滤。命中用户名 → 保留该用户全部设备;否则按设备
	// 维度(名称/别名/UUID/平台/固定 vIP)过滤,全都不命中的用户整组隐藏。
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	q := strings.ToLower(query)
	rows := make([]row, 0, len(users))
	for _, u := range users {
		ds, _ := s.store.ListDevicesByUser(r.Context(), u.ID)
		userMatch := q == "" || strings.Contains(strings.ToLower(u.Username), q)
		views := make([]devView, 0, len(ds))
		for _, d := range ds {
			if q != "" && !userMatch && !deviceMatchesQuery(d, q) {
				continue
			}
			effUp := computeEffectiveRateBPS(d.RateUploadBPS, rateCfg.SettingsUpBPS, rateCfg.TomlUpBPS, u.BandwidthUpBPS)
			effDown := computeEffectiveRateBPS(d.RateDownloadBPS, rateCfg.SettingsDownBPS, rateCfg.TomlDownBPS, u.BandwidthDownBPS)
			views = append(views, devView{
				Device:       d,
				EffUpHuman:   rateBytesHuman(effUp),
				EffDownHuman: rateBytesHuman(effDown),
			})
		}
		if q != "" && !userMatch && len(views) == 0 {
			continue
		}
		rows = append(rows, row{User: u, Devices: views})
	}
	s.renderPage(w, r, "devices_list.html", PageData{
		Title: tr(r, "page.devices.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:delete-device 等 redirect 写 flash
		Data: map[string]any{
			"Rows":             rows,
			"Query":            query,
			"ControlAvailable": rateCfgOK, // Q5:直接用 fetch 是否成功判定,不再绕 EffectiveBurst。
		},
		Nav: NavContext{Active: "devices"},
	})
}

// deviceMatchesQuery:设备维度搜索命中判定。q 已 lower-case。
func deviceMatchesQuery(d *store.Device, q string) bool {
	for _, f := range []string{d.DeviceName, d.Alias, d.DeviceUUID, d.Platform, d.FixedVIPv4, d.FixedVIPv6} {
		if f != "" && strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func (s *Server) handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	segs := pathSegments(r.URL.Path) // [devices, id, verb?]
	if len(segs) < 2 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.missingDeviceId"))
		return
	}
	id, err := strconv.ParseInt(segs[1], 10, 64)
	if err != nil || id <= 0 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.invalidDeviceId"))
		return
	}
	d, err := s.store.GetDevice(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, tr(r, "err.deviceNotFound"))
			return
		}
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryFailed")+err.Error())
		return
	}

	if len(segs) == 2 {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		lease, _ := s.store.GetLeaseByDevice(r.Context(), id)
		routes, _ := s.store.ListRoutesByDevice(r.Context(), id)
		// N25(2026-05-24):算「实际生效限速」给运维看,涵盖 device→settings→toml→user
		// 四层 cap。任一层不可达(server 没起 / GetUser 失败)按 0 降级,等价于「该层
		// 不约束」,与登录瞬时 server 端的行为一致。
		var settingsUp, settingsDown, tomlUp, tomlDown int64
		controlOK := false
		if s.control != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			if rc, err := s.control.RateConfig(ctx); err == nil {
				settingsUp, settingsDown = rc.SettingsUpBPS, rc.SettingsDownBPS
				tomlUp, tomlDown = rc.TomlUpBPS, rc.TomlDownBPS
				controlOK = true
			}
			cancel()
		}
		// M5(2026-05-24):d.UserID == 0 是匿名 device(客户端没上报合法 device_uuid
		// 或 UpsertDevice 时还没绑 user)。这种情况下走 GetUser 会拿到 ErrNotFound,
		// userUp/userDown 仍是 0,但 UI 模板用 hasUser=false 区分「user 不存在」vs
		// 「user 没设 bandwidth」,避免运维误以为数据丢了。
		var userUp, userDown int64
		hasUser := false
		if d.UserID > 0 {
			if u, err := s.store.GetUser(r.Context(), d.UserID); err == nil && u != nil {
				userUp, userDown = u.BandwidthUpBPS, u.BandwidthDownBPS
				hasUser = true
			}
		}
		effUp := computeEffectiveRateBPS(d.RateUploadBPS, settingsUp, tomlUp, userUp)
		effDown := computeEffectiveRateBPS(d.RateDownloadBPS, settingsDown, tomlDown, userDown)
		s.renderPage(w, r, "device_detail.html", PageData{
			Title: tr(r, "page.deviceDetail.title"),
			Flash: flashFromQuery(r), // 第九轮 P2:set-rate / set-fixed-vip POST redirect 写了 flash,本 GET 终于消费;mesh toggle 落到 device detail 时同样能看到横幅
			Data: map[string]any{
				"Device": d, "Lease": lease, "Routes": routes,
				// 0011:per-device 限速渲染辅助。Str = input value(空字符串 = 沿用默认);
				// Human = 只读小字展示「当前生效」,含 Mbps 折算。
				"DevRateUpStr":     rateBytesToMiBsString(d.RateUploadBPS),
				"DevRateDownStr":   rateBytesToMiBsString(d.RateDownloadBPS),
				"DevRateUpHuman":   rateBytesHuman(d.RateUploadBPS),
				"DevRateDownHuman": rateBytesHuman(d.RateDownloadBPS),
				// N25:四层 cap 后的实际生效值(per-platform toml cap 不在 UI 里预算)。
				"EffRateUpHuman":   rateBytesHuman(effUp),
				"EffRateDownHuman": rateBytesHuman(effDown),
				// 暴露各层值给模板,运维能看到「device 写 0 但 settings 在 cap 你」。
				"SettingsUpHuman":   rateBytesHuman(settingsUp),
				"SettingsDownHuman": rateBytesHuman(settingsDown),
				"TomlUpHuman":       rateBytesHuman(tomlUp),
				"TomlDownHuman":     rateBytesHuman(tomlDown),
				"UserUpHuman":       rateBytesHuman(userUp),
				"UserDownHuman":     rateBytesHuman(userDown),
				"HasUser":           hasUser,
				"ControlAvailable":  controlOK,
			},
			Nav: NavContext{Active: "devices"},
		})
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	verb := segs[2]
	switch verb {
	case "set-alias":
		// alias(0020, 2026-07-19):管理员别名,只影响展示/下发(exits-list、routes-list、
		// web 各页),不动客户端上报的 device_name,也不影响 MagicDNS。空串 = 清除。
		// 纯展示字段:不做唯一性约束,也不需要踢线/热更(出口列表下次重算自然带上)。
		alias := strings.TrimSpace(r.FormValue("alias"))
		if err := s.store.SetDeviceAlias(r.Context(), id, alias); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.deviceNotFound", "err.setFailed")
			return
		}
		s.audit.WriteFromRequest(r, "device_set_alias", FormatTarget("device", id),
			FormatDetail("uuid", d.DeviceUUID, "old", d.Alias, "new", alias))
		// 出口/子网列表的展示名变了:best-effort 让 server 重算并推送,客户端下拉即时换名。
		tryReloadExitsBackground(s.control)
		msg := tr(r, "flash.deviceAliasSet", alias)
		if alias == "" {
			msg = tr(r, "flash.deviceAliasCleared")
		}
		flashRedirect(w, r, fmt.Sprintf("/devices/%d", id), msg, "")
	case "delete":
		if err := s.store.DeleteDevice(r.Context(), id); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.deviceNotFound", "err.deleteFailed")
			return
		}
		s.audit.WriteFromRequest(r, "device_delete", FormatTarget("device", id),
			FormatDetail("uuid", d.DeviceUUID, "user_id", d.UserID))
		// 删设备级联清其出口/子网路由声明 + 4via6 siteID：通知 server 重建子网路由表并广播 routes-list，避免数据面
		// 快照 / 客户端可用列表陈旧（该设备网段在使用方侧黑洞、siteID→device 映射悬空）。best-effort，与 set-rate 的
		// control 推送同模式；未配 control socket 时内部 no-op。
		tryReloadRoutesBackground(s.control)
		flashRedirect(w, r, "/devices", tr(r, "flash.deviceDeleted"), "")
	case "set-rate":
		// 0011(2026-05-23):per-device 带宽限速。表单字段:rate_upload_mibs / rate_download_mibs
		// (浮点 MiB/s,空 / 0 = 沿用全局默认)。保存后异步调 control sock 推送给 active conn。
		upStr := strings.TrimSpace(r.FormValue("rate_upload_mibs"))
		downStr := strings.TrimSpace(r.FormValue("rate_download_mibs"))
		upBPS, err := parseRateMiBs(upStr)
		if err != nil {
			s.renderError(w, r, http.StatusBadRequest, tr(r, "err.rateUp")+trErr(r, err))
			return
		}
		downBPS, err := parseRateMiBs(downStr)
		if err != nil {
			s.renderError(w, r, http.StatusBadRequest, tr(r, "err.rateDown")+trErr(r, err))
			return
		}
		oldUp, oldDown := d.RateUploadBPS, d.RateDownloadBPS
		if err := s.store.SetDeviceRateLimit(r.Context(), id, upBPS, downBPS); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.deviceNotFound", "err.saveFailed")
			return
		}
		s.audit.WriteFromRequest(r, "device_rate_set",
			FormatTarget("device", id),
			FormatDetail(
				"uuid", d.DeviceUUID,
				"old_up_bps", oldUp, "new_up_bps", upBPS,
				"old_down_bps", oldDown, "new_down_bps", downBPS,
			))
		// 立刻让 server 把 active conn 的 limiter 热更过去,不需要客户端重连。
		tryRateRefreshBackground(s.control, id)
		flashRedirect(w, r, fmt.Sprintf("/devices/%d", id), tr(r, "flash.deviceRateUpdated"), "")
	case "set-fixed-vip":
		// 0008(2026-05-23):把固定 vIP 钉到具体 device 上。空串清除。
		// 表单字段:fixed_vip_v4 / fixed_vip_v6。
		//
		// 2026-05-23:去掉了曾经的 allow_collision 跳过预检选项 —— 它实际不能「允许」
		// 冲突(DB UNIQUE 仍兜底),只是把可读 409 变成 500,纯误导。要顶替别人占用,
		// 请去对方设备页先清掉它的 fixed-vip 或释放 lease。
		v4 := strings.TrimSpace(r.FormValue("fixed_vip_v4"))
		v6 := strings.TrimSpace(r.FormValue("fixed_vip_v6"))

		// 合法 IP + 地址族校验(空串例外 = 清除)。ParseAddr 两族都收,
		// 不查族的话 IPv6 字面量能存进 fixed_vip_v4(反之亦然),分配时静默失效。
		if v4 != "" {
			addr, perr := netip.ParseAddr(v4)
			if perr != nil || !addr.Unmap().Is4() {
				s.renderError(w, r, http.StatusBadRequest, tr(r, "devices.fixedVip4Invalid", v4))
				return
			}
		}
		if v6 != "" {
			addr, perr := netip.ParseAddr(v6)
			if perr != nil || !addr.Is6() || addr.Is4In6() {
				s.renderError(w, r, http.StatusBadRequest, tr(r, "devices.fixedVip6Invalid", v6))
				return
			}
		}

		// 冲突预检:跨 device 扫 fixed_vip + lease 已占用。允许「钉自己 device 已有 lease」。
		// 与 admin CLI 的 findFixedVIPConflict 相同语义,但简化版:只检查其它 device 的 fixed。
		// 真正的全局唯一性由 SQL UNIQUE 索引兜底;这里跑一遍是为了给出可读的冲突来源。
		if v4 != "" && v4 != d.FixedVIPv4 {
			conflict, derr := s.checkFixedVIPConflict(r.Context(), v4, d.ID)
			if derr != nil {
				s.renderError(w, r, http.StatusInternalServerError, derr.Error())
				return
			}
			if conflict != "" {
				s.renderError(w, r, http.StatusConflict,
					tr(r, "devices.fixedVip4Conflict", conflict))
				return
			}
		}
		if v6 != "" && v6 != d.FixedVIPv6 {
			conflict, derr := s.checkFixedVIPConflict(r.Context(), v6, d.ID)
			if derr != nil {
				s.renderError(w, r, http.StatusInternalServerError, derr.Error())
				return
			}
			if conflict != "" {
				s.renderError(w, r, http.StatusConflict,
					tr(r, "devices.fixedVip6Conflict", conflict))
				return
			}
		}

		if err := s.store.SetDeviceFixedVIP(r.Context(), id, v4, v6); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.deviceNotFound", "err.setFailed")
			return
		}
		s.audit.WriteFromRequest(r, "device_set_fixed_vip", FormatTarget("device", id),
			FormatDetail(
				"uuid", d.DeviceUUID,
				"old_v4", d.FixedVIPv4, "new_v4", v4,
				"old_v6", d.FixedVIPv6, "new_v6", v6,
			))

		// 2026-05-23 智能踢线决策(对应「绑定 IP == 当前 IP 就别踢」的语义):
		//   1) 设备无活跃会话 / 调 /status 失败 → 不踢("下次连接时生效");
		//   2) 清除 fixed(v4==v6=="") → 不踢(in-flight session 继续用当前 IP,
		//      lease 也不变,只是 manual 标记被刷掉,下次重连走自动池);
		//   3) 新 fixed 与活跃 session 现有 vIP 完全匹配 → 不踢("已一致,无需重连");
		//   4) 其余(IP 真变了) → kick by device,让客户端 ~8s 自动重连拿新 IP。
		//
		// 用 Kick(KickReq{Kind:"device"}) 而非 by-session:同 device 理论上 supersede 后
		// 只有 1 个 active conn,但 race 边缘可能有 2 个(supersede 老 conn cleanup 未完),
		// by-device 一锅端最稳。
		verb := tr(r, "flash.fixedVipUpdated")
		if v4 == "" && v6 == "" {
			verb = tr(r, "flash.fixedVipUnbound")
		}
		if v4 != "" || v6 != "" {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			sessions, derr := s.control.DeviceSessions(ctx, id)
			cancel()
			needKick := false
			switch {
			case derr != nil:
				// /status 拿不到 → 保守不踢(server 可能没运行;UI 上提示用户下次连接生效)
			case len(sessions) == 0:
				verb = tr(r, "flash.fixedVipUpdatedNextLogin")
			default:
				ipMatches := func(s DeviceSession) bool {
					var hasV4, hasV6 bool
					for _, ip := range s.VIPs {
						if v4 != "" && ip == v4 {
							hasV4 = true
						}
						if v6 != "" && ip == v6 {
							hasV6 = true
						}
					}
					// 任一方向被设置时,该方向必须命中(没设的方向不计)。
					return (v4 == "" || hasV4) && (v6 == "" || hasV6)
				}
				allMatch := true
				for _, s := range sessions {
					if !ipMatches(s) {
						allMatch = false
						break
					}
				}
				if allMatch {
					verb = tr(r, "flash.fixedVipUpdatedConsistent")
				} else {
					needKick = true
				}
			}
			if needKick {
				kickCtx, kickCancel := context.WithTimeout(r.Context(), 5*time.Second)
				_, kerr := s.control.Kick(kickCtx, KickReq{
					Kind:   "device",
					ID:     strconv.FormatInt(id, 10),
					Reason: "fixed_vip_changed",
				})
				kickCancel()
				if kerr != nil {
					s.audit.WriteFromRequest(r, "device_set_fixed_vip_kick_fail",
						FormatTarget("device", id), FormatDetail("err", kerr.Error()))
					verb = tr(r, "flash.fixedVipUpdatedKickFailed")
				} else {
					s.audit.WriteFromRequest(r, "device_set_fixed_vip_kick_ok",
						FormatTarget("device", id), "")
					verb = tr(r, "flash.fixedVipUpdatedKicked")
				}
			}
		}

		// return_to(2026-05-23):支持从「在线会话」等页面一键绑定 / 解绑后跳回原页面。
		// 第九轮深扫 P1:从弱白名单(只检 `/` 前缀 + `//` 排除)切换到统一的
		// `safeReturnToOrFallback` —— 还会拒 URL-encoded `\` / scheme / host 绕过。
		// 不安全 / 空 return_to 时回到 device detail,而不是首页。
		//
		// flashRedirect 内部 QueryEscape + 附签名(第三轮 L5);verb 含字面 `+` 也不会被 decode 成空格。
		deviceDetail := "/devices/" + segs[1]
		dest := safeReturnToOrFallback(r.FormValue("return_to"), "", deviceDetail)
		flashRedirect(w, r, dest, verb, "")
	default:
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.unknownActionVerb", verb))
	}
}

// checkFixedVIPConflict:扫所有 device,看 candidate 是否已被其它 device 用作 fixed_vip
// 或当前 lease。返回人类可读冲突描述(无冲突返回 "")。candidate 必须已校验过为合法 IP。
//
// 注意:DB 层有 UNIQUE 索引兜底,这里只是为了在 UI 上展示可读的冲突来源。
// (历史上有过 allow_collision=on 跳过本预检的开关,2026-05-23 去掉 —— 它名不副实,
//
//	跳过预检后撞 DB UNIQUE 仍然 fail,只是把 409 退化成 500。)
func (s *Server) checkFixedVIPConflict(ctx context.Context, candidate string, ownerDeviceID int64) (string, error) {
	if candidate == "" {
		return "", nil
	}
	devs, err := s.store.ListAllDevices(ctx)
	if err != nil {
		return "", fmt.Errorf("list devices: %w", err)
	}
	lang := langFromCtx(ctx)
	for _, d := range devs {
		if d.ID == ownerDeviceID {
			continue
		}
		if d.FixedVIPv4 == candidate {
			return translate(lang, "devices.conflictFixedV4", d.ID, d.UserID, d.DeviceName, candidate), nil
		}
		if d.FixedVIPv6 == candidate {
			return translate(lang, "devices.conflictFixedV6", d.ID, d.UserID, d.DeviceName, candidate), nil
		}
		lease, err := s.store.GetLeaseByDevice(ctx, d.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("get lease for device %d: %w", d.ID, err)
		}
		if lease.VIPv4 == candidate {
			return translate(lang, "devices.conflictLeaseV4", d.ID, d.UserID, candidate), nil
		}
		if lease.VIPv6 == candidate {
			return translate(lang, "devices.conflictLeaseV6", d.ID, d.UserID, candidate), nil
		}
	}
	return "", nil
}

func (s *Server) handleLeaseList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 没有 ListAllLeases;直接 SELECT 一把。
	// 2026-07-19 易用性:join 出 device_name / alias — 租约页设备列显示人话名称
	// 而不是裸 UUID(UUID 降级为悬停 tooltip)。
	type leaseRow struct {
		DeviceID   int64
		DeviceUUID string
		DeviceName string
		Alias      string
		UserID     int64
		Username   string
		VIPv4      string
		VIPv6      string
		Manual     bool
		AssignedAt int64
	}
	rows, err := s.store.DB().QueryContext(r.Context(), `
		SELECT l.device_id, COALESCE(l.vip_v4,''), COALESCE(l.vip_v6,''), l.manual, l.assigned_at,
		       d.device_uuid, COALESCE(d.device_name,''), COALESCE(d.alias,''), d.user_id, u.username
		  FROM leases l
		  JOIN devices d ON d.id = l.device_id
		  JOIN users   u ON u.id = d.user_id
		 ORDER BY l.assigned_at DESC`)
	if err != nil {
		s.renderInternalError(w, r, "leases:list", err)
		return
	}
	defer rows.Close()
	var out []leaseRow
	for rows.Next() {
		var x leaseRow
		var manual int64
		if err := rows.Scan(&x.DeviceID, &x.VIPv4, &x.VIPv6, &manual, &x.AssignedAt,
			&x.DeviceUUID, &x.DeviceName, &x.Alias, &x.UserID, &x.Username); err != nil {
			s.renderInternalError(w, r, "leases:scan", err)
			return
		}
		x.Manual = manual != 0
		out = append(out, x)
	}
	s.renderPage(w, r, "leases_list.html", PageData{
		Title: tr(r, "page.leases.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:release-lease redirect 写 flash
		Data:  map[string]any{"Leases": out},
		Nav:   NavContext{Active: "leases"},
	})
}

func (s *Server) handleLeaseAction(w http.ResponseWriter, r *http.Request) {
	segs := pathSegments(r.URL.Path) // [leases, device_id, verb?]
	if len(segs) < 3 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.missingLeaseAction"))
		return
	}
	deviceID, err := strconv.ParseInt(segs[1], 10, 64)
	if err != nil || deviceID <= 0 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.invalidDeviceId"))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	verb := segs[2]
	switch verb {
	case "release":
		if err := s.store.DeleteLease(r.Context(), deviceID); err != nil {
			// 双击「释放」/ 陈旧列表页重提交 → 干净 404,而不是 500 + 裸 store 错误。
			// CLI lease release 已是同口径(cmd_lease.go 映射 ErrNotFound 为友好提示)。
			if errors.Is(err, store.ErrNotFound) {
				s.renderError(w, r, http.StatusNotFound, tr(r, "err.leaseNotFound"))
				return
			}
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.releaseFailed")+err.Error())
			return
		}
		s.audit.WriteFromRequest(r, "lease_release", FormatTarget("device", deviceID), "")
		flashRedirect(w, r, "/leases", tr(r, "flash.leaseReleased"), "")
	default:
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.unknownActionVerb", verb))
	}
}
