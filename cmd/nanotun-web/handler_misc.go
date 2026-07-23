package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// suggestionHostnameBlacklist 是 `deriveServerDialHostSuggestion` 在语法通过后**额外**
// 拒掉的 hostname 集合(精确匹配,大小写不敏感)。这些 hostname 语法上合法
// (RFC1035 单 label 含字母),但实际 DNS 解析 100% 指向 loopback —
// `store.ProbeServerDialHost` 在保存时会通过 `CheckResolvedDialIPs` 拒掉,但**那是在
// admin 点了「确认使用候选」之后**才发现的失败,UX 噪音。
//
// 在 derive 阶段直接拒,banner 就不会展示「localhost」这类一定失败的候选 — 改走
// 「未配置 + 无候选」分支,显示标准警告引导 admin 到设置页手填真实 IP。
//
// 2026-05-27 第二十三轮 A4 引入,dev 场景(`https://localhost:7443` 调试)噪音治理。
var suggestionHostnameBlacklist = map[string]struct{}{
	"localhost":             {},
	"localhost.localdomain": {},
	"ip6-localhost":         {},
	"ip6-loopback":          {},
}

// deriveServerDialHostSuggestion 从当前 HTTP 请求的 Host header 派生
// `server_dial_host` 候选值,用于 settings 表单未配置时**预填**(value),
// 让 admin 一键确认即可生效,不必手动 retype 浏览器地址栏里的 IP。
//
// 规则:
//   - 去掉端口部分(`net.SplitHostPort` 失败说明 r.Host 本身就不含端口,直接用)
//   - 去掉 IPv6 字面 bracket(`[::1]` → `::1`,与 `store.ParseLiteralIP` 对齐)
//   - 跑 `store.ValidateServerDialHost` 校验语法(IPv4/IPv6/RFC1035 hostname)
//   - `suggestionHostnameBlacklist` 精确拒(`localhost` 等语法合法但 DNS 必定 loopback)
//   - 任意一步失败 → 返回 ""(降级,不预填,admin 仍按原来填入 placeholder 提示)
//
// **安全注记**:r.Host 是浏览器发的 Host header,**可被伪造**(虚假 Host 攻击),
// 因此这里**只**作为表单预填的 default value 显示给 admin 看 — 不直接入库。
// admin 看到候选值后必须点保存,保存路径仍走完整的 ValidateServerDialHost +
// ProbeServerDialHost(DNS + ICMP),validation 失败入不了库,无安全风险。
func deriveServerDialHostSuggestion(r *http.Request) string {
	raw := strings.TrimSpace(r.Host)
	if raw == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		host = raw
	}
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if host == "" {
		return ""
	}
	if err := store.ValidateServerDialHost(host); err != nil {
		return ""
	}
	if _, blocked := suggestionHostnameBlacklist[strings.ToLower(host)]; blocked {
		return ""
	}
	return host
}

// 杂项 handlers:audit / settings / runtime ops / healthz / metrics。

// =========================================================================
// audit
// =========================================================================
//
// GET /audit?since=&until=&limit=N&offset=N&actor=&action=&range=1h|24h|7d|30d
//
// 2026-07-19 易用性改版:
//   - since/until 从「裸 unix 秒输入框」改为 datetime-local 控件;handler 同时
//     兼容两种格式(纯数字 = unix 秒,老书签不坏);
//   - ?range= 快捷预设(近 1 小时 / 24 小时 / 7 天 / 30 天),优先级高于 since/until;
//   - ?offset= 分页:store 层无 OFFSET 参数,取 offset+limit+1 条后内存切片 ——
//     audit 场景 admin 极少翻到几十页深,fetch 放大可接受(上限 10000 与 store cap 一致)。
func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().Unix()
	q := r.URL.Query()
	since := parseAuditTimeParam(q.Get("since"))
	until := parseAuditTimeParam(q.Get("until"))
	rangeKey := strings.TrimSpace(q.Get("range"))
	if secs, ok := auditRangeSeconds(rangeKey); ok {
		since = now - secs
		until = 0
	} else {
		rangeKey = ""
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	actorFilter := strings.TrimSpace(q.Get("actor"))
	actionFilter := strings.TrimSpace(q.Get("action"))

	if since == 0 {
		since = now - 7*24*3600 // 默认 7 天
	}
	if until == 0 {
		until = now + 1
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	fetchN := offset + limit + 1 // +1 探测是否还有下一页
	if actorFilter != "" || actionFilter != "" {
		// actor/action 是取回后内存过滤:按原始行数取 offset+limit+1 条,命中率
		// 低时切片凑不满,「下一页」会**提前消失**(更老的匹配行明明还在)。
		// 过滤激活时直接取到 store 上限(10000,audit 行很小,admin 场景可接受),
		// 让过滤后的分页在该窗口内语义正确。
		fetchN = 10000
	}
	if fetchN > 10000 {
		fetchN = 10000
	}
	logs, err := s.store.QueryAudit(r.Context(), since, until, fetchN)
	if err != nil {
		s.renderInternalError(w, r, "audit:query", err)
		return
	}
	// 应用 actor / action 过滤(数据库层没专门索引,内存过滤就够)。
	if actorFilter != "" || actionFilter != "" {
		filtered := logs[:0]
		for _, l := range logs {
			if actorFilter != "" && !strings.Contains(l.Actor, actorFilter) {
				continue
			}
			if actionFilter != "" && !strings.Contains(l.Action, actionFilter) {
				continue
			}
			filtered = append(filtered, l)
		}
		logs = filtered
	}
	// 分页切片(过滤后)。
	hasNext := len(logs) > offset+limit
	switch {
	case offset >= len(logs):
		logs = nil
	default:
		end := offset + limit
		if end > len(logs) {
			end = len(logs)
		}
		logs = logs[offset:end]
	}
	// prev/next 链接:保留过滤条件,只改 offset;并把 since/until **冻结为显式
	// unix 值**(range 参数剥掉)—— 否则翻页瞬间新写入的审计行会推移窗口,
	// 第二页出现与第一页重复的行。冻结后翻页语义 = 对同一时间切片分页。
	pageURL := func(off int) string {
		v := url.Values{}
		for k, vals := range q {
			for _, x := range vals {
				v.Add(k, x)
			}
		}
		v.Del("range")
		v.Del("flash")
		v.Del("flash_kind")
		v.Set("since", strconv.FormatInt(since, 10))
		v.Set("until", strconv.FormatInt(until, 10))
		if off > 0 {
			v.Set("offset", strconv.Itoa(off))
		} else {
			v.Del("offset")
		}
		return "/audit?" + v.Encode()
	}
	prevURL, nextURL := "", ""
	if offset > 0 {
		p := offset - limit
		if p < 0 {
			p = 0
		}
		prevURL = pageURL(p)
	}
	if hasNext {
		nextURL = pageURL(offset + limit)
	}
	// 快捷预设链接的过滤条件由模板逐参数拼接(`&actor={{.Data.Actor}}` 字面 `&` +
	// 值走 html/template 的 query-component 转义)。**不能**在 handler 预拼整段
	// query string 塞给模板:href 的 query 位置上模板会把 `&`/`=` 一起百分号转义,
	// 整段变成 range 参数的一部分,过滤条件静默丢失。
	limitParam := ""
	if q.Get("limit") != "" {
		limitParam = strconv.Itoa(limit)
	}
	s.renderPage(w, r, "audit_list.html", PageData{
		Title: tr(r, "page.audit.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:audit 当前没有 POST 写 flash,但保留 hook
		Data: map[string]any{
			"Logs":       logs,
			"Since":      since,
			"Until":      until,
			"SinceStr":   fmtDatetimeLocal(since),
			"UntilStr":   fmtDatetimeLocal(until),
			"Limit":      limit,
			"Offset":     offset,
			"Actor":      actorFilter,
			"Action":     actionFilter,
			"Range":      rangeKey,
			"PrevURL":    prevURL,
			"NextURL":    nextURL,
			"LimitParam": limitParam,
			"ShownFrom":  offset + 1,
			"ShownTo":    offset + len(logs),
		},
		Nav: NavContext{Active: "audit"},
	})
}

// parseAuditTimeParam 兼容两种输入:纯数字 = unix 秒(老书签 / API 习惯);
// datetime-local 控件值("2006-01-02T15:04" 或带秒),按服务器本地时区解析。
// 解析失败 / 空 → 0(caller 落默认区间)。
func parseAuditTimeParam(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.Unix()
		}
	}
	return 0
}

// auditRangeSeconds:快捷预设 key → 秒数。
func auditRangeSeconds(key string) (int64, bool) {
	switch key {
	case "1h":
		return 3600, true
	case "24h":
		return 24 * 3600, true
	case "7d":
		return 7 * 24 * 3600, true
	case "30d":
		return 30 * 24 * 3600, true
	}
	return 0, false
}

// fmtDatetimeLocal:unix 秒 → datetime-local 控件 value 格式(服务器本地时区)。
func fmtDatetimeLocal(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).Local().Format("2006-01-02T15:04")
}

// =========================================================================
// settings (read-only 展示 app_settings;v1 不开放写)
// =========================================================================

func (s *Server) handleSettingsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, err := s.store.DB().QueryContext(r.Context(),
		`SELECT key, value FROM app_settings ORDER BY key ASC`)
	if err != nil {
		s.renderInternalError(w, r, "settings:list", err)
		return
	}
	defer rows.Close()
	type kv struct{ K, V string }
	var out []kv
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			out = append(out, kv{K: k, V: v})
		}
	}
	// 0011:把全局默认限速单独抽出来给模板用,渲染独立编辑表单(可读 + 可改)。
	// 0012:加 burst + toml fallback 一起展示 — 运维清 settings 后能看到「实际还有 toml 撑底」。
	defaults, _ := s.store.GetRateDefaults(r.Context())
	// advertised_host(2026-05-26;原 public_host,migration 0015 改名):
	// 为 /server-qr 面板服务,settings 页有专门的编辑表单。
	// 读失败时按空兜底 — settings 主表(rate / 全表 dump)仍能正常展示。
	advertisedHost, _ := s.store.GetAdvertisedHost(r.Context())
	// server_dial_host(2026-05-26 第六轮拆字段):客户端实际拨号目标,与 advertised_host
	// (展示 label)分离。strict IPv4/IPv6/RFC1035 hostname 校验。空 = /server-qr 暂不
	// 可用,settings 页会显示警告。
	serverDialHost, _ := s.store.GetServerDialHost(r.Context())
	// 2026-05-27 第二十一轮:空配置时根据 admin 访问网址的 Host header 派生候选,
	// 模板渲染时把候选作为 input value 预填,admin 不必手动 retype 浏览器地址栏。
	// 派生失败(语法不过)或已配置 → 候选为空,模板按原逻辑只用 placeholder/value 提示。
	var serverDialHostSuggestion string
	if serverDialHost == "" {
		serverDialHostSuggestion = deriveServerDialHostSuggestion(r)
	}
	// toml 默认与 effective burst 从 server /status 取(也只有 server 知道当前 toml 解析后的值);
	// server 没起 / 拉失败按零值降级,模板显示 "不可用"。
	var rateCfg RateConfigSnapshot
	if s.control != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		rateCfg, _ = s.control.RateConfig(ctx)
		cancel()
	}
	s.renderPage(w, r, "settings.html", PageData{
		Title: tr(r, "page.settings.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:rate 默认值更新 redirect 写 flash
		Data: map[string]any{
			"Settings":      out,
			"RateDefaults":  defaults,
			"RateUpStr":     rateBytesToMiBsString(defaults.UploadBPS),
			"RateDownStr":   rateBytesToMiBsString(defaults.DownloadBPS),
			"RateUpHuman":   rateBytesHuman(defaults.UploadBPS),
			"RateDownHuman": rateBytesHuman(defaults.DownloadBPS),
			// burst:UI 输入 KiB(更人性,大多数运维心算 64/128/256 比写 65536 自然),
			// 内部还是字节存储。空 = 沿用代码 default(64 KiB)。
			"BurstKiBStr": rateBytesToKiBString(defaults.BurstBytes),
			"BurstHuman":  rateBytesHuman(defaults.BurstBytes),
			// toml fallback / effective burst 让用户看到「清 settings 后到底回退到啥」。
			"TomlUpHuman":              rateBytesHuman(rateCfg.TomlUpBPS),
			"TomlDownHuman":            rateBytesHuman(rateCfg.TomlDownBPS),
			"EffectiveBurst":           rateCfg.EffectiveBurst,
			"EffectiveBurstHuman":      rateBurstHuman(int64(rateCfg.EffectiveBurst)),
			"ControlAvailable":         rateCfg.EffectiveBurst > 0,
			"AdvertisedHost":           advertisedHost,
			"ServerDialHost":           serverDialHost,
			"ServerDialHostSuggestion": serverDialHostSuggestion,
		},
		Nav: NavContext{Active: "settings"},
	})
}

// handleSettingsRateSet:POST /settings/rate
//
// 表单:rate_default_upload_mibs / rate_default_download_mibs(浮点 MiB/s,空 / 0 = 清除)。
// 写入 app_settings 后立刻广播 /rate/refresh(device_id=0 全量),让所有 active conn
// 把 limiter 热更过来。失败只 warn(DB 已落)。
func (s *Server) handleSettingsRateSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	upStr := strings.TrimSpace(r.FormValue("rate_default_upload_mibs"))
	downStr := strings.TrimSpace(r.FormValue("rate_default_download_mibs"))
	burstStr := strings.TrimSpace(r.FormValue("rate_burst_kib"))
	upBPS, err := parseRateMiBs(upStr)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.rateDefaultUp")+trErr(r, err))
		return
	}
	downBPS, err := parseRateMiBs(downStr)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.rateDefaultDown")+trErr(r, err))
		return
	}
	burstBytes, err := parseBurstKiB(burstStr)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "burst: "+trErr(r, err))
		return
	}
	// audit 补 old → new 让事后追溯能看到「从 X 改到 Y」。读失败按零值显示,不阻塞写入。
	old, _ := s.store.GetRateDefaults(r.Context())
	if err := s.store.SetRateDefaults(r.Context(),
		store.RateDefaults{UploadBPS: upBPS, DownloadBPS: downBPS, BurstBytes: burstBytes}); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.saveFailed")+err.Error())
		return
	}
	s.audit.WriteFromRequest(r, "settings_rate_default_set", "",
		FormatDetail(
			"old_up_bps", old.UploadBPS, "new_up_bps", upBPS,
			"old_down_bps", old.DownloadBPS, "new_down_bps", downBPS,
			"old_burst_bytes", old.BurstBytes, "new_burst_bytes", burstBytes,
		))
	tryRateRefreshBackground(s.control, 0)
	flashRedirect(w, r, "/settings", tr(r, "flash.rateDefaultsUpdated"), "")
}

// =========================================================================
// runtime ops
// =========================================================================
//
// POST /runtime/reload?what=acl  → 调 control socket
// POST /runtime/kick             → 调 control socket(form: kind=session|user, id=, reason=)

func (s *Server) handleRuntimeReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	n, err := s.control.ReloadACL(ctx)
	if err != nil {
		s.audit.WriteFromRequest(r, "runtime_reload_acl_fail", "", FormatDetail("err", err.Error()))
		s.renderError(w, r, http.StatusBadGateway, tr(r, "err.reloadFailed")+trErr(r, err))
		return
	}
	s.audit.WriteFromRequest(r, "runtime_reload_acl_ok", "", FormatDetail("rules", n))
	// 第三轮深扫 P2-8 拼字风格统一:原 `+` 表空格不规范且 raw 空格混在 raw query。
	// 2026-07-19 易用性:回跳发起页(ACL 页的「重载 ACL」按钮点完应回 ACL 页,
	// 不是甩去 dashboard)。return_to 表单字段优先,否则 Referer path-only,
	// 都不可用回 /(sanitizeReturnTo 统一防开放重定向)。
	dest := sanitizeReturnTo(r.FormValue("return_to"), r.Referer())
	flashRedirect(w, r, dest, tr(r, "flash.aclReloaded", n), "")
}

// handleRuntimeMeshToggle:POST /runtime/mesh-toggle
//
// 表单字段(可选):
//   - to=on / to=off    显式指定目标状态;不传 = 翻转当前值
//   - return_to=<path>  302 redirect 目标(默认走 Referer,Referer 也空就回 /)
//
// 流程:
//  1. 读当前 store.GetMeshEnabled
//  2. 计算 target(传 to 就直接用,否则取反)
//  3. store.SetMeshEnabled(target) 持久化
//  4. **同步** reload ACL snapshot(8s 超时)——2026-07-19 深扫瑕疵修复:此前异步 best-effort,
//     reload 失败只落一行 Warn 日志,侧栏按钮(读 DB)已显示新状态而数据面(读快照)仍按旧状态跑,
//     劈叉能一直持续到下次 reload/重启且无人知晓。组网是隔离总闸,必须当场确认生效;
//     失败时 flash 里显式告警(DB 已落,重试 toggle / systemctl reload 均可收敛),audit 记 reload_ok=false。
//  5. audit 写 mesh.toggle action(含 reload_ok)
//  6. Redirect 回 referer + flash
//
// 与 ACL reload 共享同一条 control 路径:server 那边 reloadACLSnapshotFromStore
// 已经把 mesh_enabled 凝固进 snapshot,reload 一次就 atomic.Pointer 替换,新流量立刻按
// 新规则裁决。**已建立的连接里 in-flight 包**理论上有几十微秒的窗口仍按旧 snapshot
// 走,运维场景下可接受;严格断流需要 admin 主动 kick 全部用户。
func (s *Server) handleRuntimeMeshToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	// 深扫第八轮 LOW:此前 `current, _ :=` 吞掉读错误。current 有两个用途:审计里的
	// from 字段,以及 to 缺省时用「取反」推出 target。读失败(DB 抖动)会让 current=false,
	// 若请求又没带显式 to,target 就被推成 true —— 一次读错误可能把 mesh 误**打开**。
	// 这里区分对待:先看请求有没有显式 to;没有显式 to 时才依赖 current,此时读错误即中止。
	current, cerr := s.store.GetMeshEnabled(r.Context())
	var target bool
	switch strings.ToLower(strings.TrimSpace(r.FormValue("to"))) {
	case "on", "true", "1", "yes":
		target = true
	case "off", "false", "0", "no":
		target = false
	default:
		// 无显式 to → 依赖 current 取反。读失败则不猜(防误开),直接报错让用户重试。
		if cerr != nil {
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryFailed")+cerr.Error())
			return
		}
		target = !current
	}
	if err := s.store.SetMeshEnabled(r.Context(), target); err != nil {
		s.audit.WriteFromRequest(r, "mesh_toggle_fail", "",
			FormatDetail("from", current, "to", target, "err", err.Error()))
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.saveMeshFailed")+err.Error())
		return
	}
	// 同步 reload:拉的是隔离总闸,必须当场确认数据面已切换;失败不回滚 DB(管理员意图已明确),
	// 但要在 flash 里把「数据面还没生效」喊出来,不能让 UI 状态与实际执行悄悄劈叉。
	reloadErr := func() error {
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		_, err := s.control.ReloadACL(ctx)
		return err
	}()
	if reloadErr != nil {
		logrus.WithError(reloadErr).Warn("[web] mesh toggle 已落库,但通知 server 重载失败——数据面仍按旧状态运行")
	}
	s.audit.WriteFromRequest(r, "mesh_toggle", "",
		FormatDetail("from", current, "to", target, "reload_ok", reloadErr == nil))

	verb := tr(r, "flash.meshDisabled")
	if target {
		verb = tr(r, "flash.meshEnabled")
	}
	if reloadErr != nil {
		verb += tr(r, "flash.meshReloadWarn")
	}
	// redirect 目标:优先 return_to(白名单要求是站内 path,/ 开头且非 //),
	// 否则 Referer 的 path-only(不接受跨域绝对 URL,防开放重定向),最后 "/"。
	//
	// 第八轮深扫 P1(旧账):原实现 Referer fallback 直接吃绝对 URL,登录 admin
	// 在 evil.example.com 被钓鱼后点 toggle 会跳回 evil.example.com,且带上
	// `?flash=已开启组网` 让攻击者拿到时序信号。对齐 devices `handler_devices.go`
	// 的 `!HasPrefix("//")` 双斜杠防御 + `url.Parse` 取 path-only。
	dest := sanitizeReturnTo(r.FormValue("return_to"), r.Referer())
	kind := ""
	if reloadErr != nil {
		// 2026-07-19:数据面未生效属于「需要 admin 后续动作」,横幅升级为 warn 色。
		kind = "warn"
	}
	// flashRedirect 内部 QueryEscape + 附签名(第三轮 L5)。
	flashRedirect(w, r, dest, verb, kind)
}

// safeReturnToOrFallback 是 [sanitizeReturnTo] 的「caller 自定义 fallback」版本:
// 当 returnTo / referer 都拒绝后,不回首页 `/`,而是用 caller 提供的 `fallback`
// (e.g. `/devices/<id>`,让用户**留在原详情页**而不是被推回 dashboard)。
// fallback 自身**不**再经过 sanitize —— 它是 caller 写死的字面 path,信任它。
//
// 第九轮深扫 P1 引入。`handler_devices.go::handleDeviceAction` 等 detail-action
// 处理用,失败兜底要回详情页而不是首页;mesh toggle 用 [sanitizeReturnTo] 兜底
// `/` 即可(没有「原页面」概念,header 全站可见)。
func safeReturnToOrFallback(returnTo, referer, fallback string) string {
	if dest := sanitizeReturnTo(returnTo, referer); dest != "/" {
		return dest
	}
	// 这里不强检 fallback —— caller 写死的字面值视为安全。但兜底 "/" 防 caller 漏传。
	if !strings.HasPrefix(fallback, "/") || strings.HasPrefix(fallback, "//") {
		return "/"
	}
	return fallback
}

// sanitizeReturnTo 把 `return_to` 与 `Referer` 收敛成「站内安全 path」,
// 防开放重定向 + 协议无关 URL(`//evil.com`)+ 反斜杠绕过(`/\\evil.com`)。
// 返回值保证:
//   - "/" 开头
//   - **不**以 "//" 开头(浏览器会解析成 `https://evil.com`)
//   - 不含 `\`(部分浏览器把 `/\\evil.com` 解析成 host)
//   - 仅保留 path + raw query,丢弃 scheme / host / fragment
//
// `return_to`(用户表单输入)policy:**仅站内 path**;绝对 URL / 协议无关 URL
// / 含反斜杠 / 含 host 全部拒绝 → fallback。这是「最严」语义,因为 return_to
// 是用户可控字段,攻击者只要把它塞成 `https://evil.com/x` 就能拿开放重定向。
//
// `Referer`(浏览器自动发送)policy:**path-only 复用**。Referer 可能来自跨域
// (admin 从 evil.example.com 被钓鱼后点 toggle),用 url.Parse 只取 Path/Query,
// 剥掉 scheme/host;跨域 Referer 自然被剥成自家同 path —— 最差跳到自家不存在的
// 页面触发 404,比开放重定向到攻击者控制的页面安全得多。
//
// 第八轮深扫 P1 引入。供 mesh toggle 等需要回跳的 handler 复用,避免每处各写
// 一份不同强度的白名单(devices 仅 `HasPrefix("/") && !HasPrefix("//")`,
// 这里加上反斜杠 / scheme / host 三层防御)。
// hasControlByte 判断字符串是否含 C0 控制字符(<0x20)或 DEL(0x7f)。用于 return-to 白名单兜底:
// 双重编码的 CRLF(如 %250d%250a)在浏览器/一次表单解码后成 %0d%0a,url.Parse 再解码即得真实 CR/LF 落进
// u.Path。虽然 Go 1.25+ 会把 Location 头里的 CR/LF 改写成空格(经典响应头注入已被消音),但白名单本就不该
// 放行含控制字符的路径 —— 与运行时版本无关地拒之(第四轮深扫 LOW,纵深防御)。
func hasControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func sanitizeReturnTo(returnTo, referer string) string {
	// strictPath 只接受站内 path(/ 开头, 不含 //, 不含 \, 无 host 无 scheme)。
	//
	// 第九轮深扫 P1:`%5C` URL-encoded 反斜杠绕过 —— 字面 `\` 在第一道
	// `strings.Contains(raw, "\\")` 被拦,但 `%5C` 是 url-encoded 形态,字符串
	// 检测看不到,`url.Parse` 后 `u.Path` 会解码出 `/\evil.com` 真实 `\`。修法:
	// Parse 后再用 `containsBackslash(u.Path)` 检一次 + 检 `u.Path` 是否仍以 `/`
	// 开头且非 `//`(以防 RawPath 与 Path 解码后语义不同的边缘情况)。
	strictPath := func(raw string) string {
		raw = strings.TrimSpace(raw)
		if raw == "" || !strings.HasPrefix(raw, "/") {
			return ""
		}
		if strings.HasPrefix(raw, "//") || strings.Contains(raw, `\`) {
			return ""
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host != "" || u.Scheme != "" {
			return ""
		}
		if strings.Contains(u.Path, `\`) {
			return "" // %5C 绕过:Parse 解码出真实 `\`
		}
		if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
			return "" // 解码后 Path 不再是站内安全 path
		}
		out := u.Path
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
		}
		if hasControlByte(out) {
			return "" // 双重编码 CRLF 等控制字符(见 hasControlByte),白名单一律拒
		}
		return out
	}
	// pathFromReferer 接受绝对 / 相对 URL,但只复用 path + query,丢 scheme/host。
	// 第九轮 P1 同款:Parse 后再检 Path 内反斜杠(`%5C` 绕过)。
	pathFromReferer := func(raw string) string {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "//") || strings.Contains(raw, `\`) {
			return ""
		}
		u, err := url.Parse(raw)
		if err != nil || u.Path == "" {
			return ""
		}
		if strings.Contains(u.Path, `\`) {
			return "" // %5C 绕过
		}
		out := u.Path
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
		}
		if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") {
			return ""
		}
		if hasControlByte(out) {
			return "" // 双重编码 CRLF 等控制字符,拒
		}
		return out
	}
	if dest := strictPath(returnTo); dest != "" {
		return dest
	}
	if dest := pathFromReferer(referer); dest != "" {
		return dest
	}
	return "/"
}

func (s *Server) handleRuntimeKick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	kind := strings.TrimSpace(r.FormValue("kind"))
	id := strings.TrimSpace(r.FormValue("id"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		reason = "kicked_via_web"
	}
	if kind == "" || id == "" {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.kickFieldsRequired"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	resp, err := s.control.Kick(ctx, KickReq{Kind: kind, ID: id, Reason: reason})
	if err != nil {
		s.audit.WriteFromRequest(r, "runtime_kick_fail",
			FormatTarget(kind, id), FormatDetail("err", err.Error()))
		s.renderError(w, r, http.StatusBadGateway, tr(r, "err.kickFailed")+trErr(r, err))
		return
	}
	s.audit.WriteFromRequest(r, "runtime_kick_ok",
		FormatTarget(kind, id),
		FormatDetail("kicked", resp.Kicked, "reason", reason))
	// 2026-07-19 易用性:回跳发起页 —— 会话页踢线回会话页、用户详情「踢下线」
	// 回该用户详情,不再一律甩回 dashboard 丢上下文。
	dest := sanitizeReturnTo(r.FormValue("return_to"), r.Referer())
	flashRedirect(w, r, dest, tr(r, "flash.sessionsKicked", resp.Kicked), "")
}

// =========================================================================
// healthz / metrics
// =========================================================================

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// 用 DB ping 简单判断。
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.DB().PingContext(ctx); err != nil {
		// /healthz 是**公开**路由(未鉴权)。裸 err.Error() 对 SQLite 可能含库文件路径 / 内部状态,
		// 不能回显给匿名访客(第三轮深扫 L2)。详情只进服务端日志,响应固定通用文案。
		logrus.WithError(err).WithField("ip", clientIP(r)).Warn("[web] healthz db ping failed")
		http.Error(w, "unhealthy\n", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

// metricsAccessAllowed 门禁 /metrics:此前完全无鉴权,任意访客可读 admin 账号数 / 请求 / 错误计数。
//   - 配了 MetricsToken:要求 `Authorization: Bearer <token>`(常量时间比较),供远程 Prometheus 抓取;
//   - 未配:仅放行**环回**对端(127.0.0.1 / ::1),远程一律拒。用 TCP 直连对端(RemoteAddr),
//     刻意不走 clientIP/XFF —— 门禁必须看真实对端,不能被伪造的 X-Forwarded-For 绕过。
func (s *Server) metricsAccessAllowed(r *http.Request) bool {
	if tok := strings.TrimSpace(s.cfg.MetricsToken); tok != "" {
		const pfx = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, pfx) {
			return false
		}
		got := strings.TrimSpace(strings.TrimPrefix(h, pfx))
		return subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.metricsAccessAllowed(r) {
		// 404(而非 403):不向未授权来源暴露该 endpoint 的存在。
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	uptime := time.Since(s.startedAt).Seconds()
	fmt.Fprintln(w, "# HELP nanotun-web_uptime_seconds Web admin process uptime")
	fmt.Fprintln(w, "# TYPE nanotun-web_uptime_seconds gauge")
	fmt.Fprintf(w, "nanotun-web_uptime_seconds %.0f\n", uptime)

	fmt.Fprintln(w, "# HELP nanotun-web_requests_total Total HTTP requests served")
	fmt.Fprintln(w, "# TYPE nanotun-web_requests_total counter")
	fmt.Fprintf(w, "nanotun-web_requests_total %d\n", totalRequests.Load())

	fmt.Fprintln(w, "# HELP nanotun-web_errors_total HTTP responses with status >= 400")
	fmt.Fprintln(w, "# TYPE nanotun-web_errors_total counter")
	fmt.Fprintf(w, "nanotun-web_errors_total{class=\"4xx\"} %d\n", totalErrors4xx.Load())
	fmt.Fprintf(w, "nanotun-web_errors_total{class=\"5xx\"} %d\n", totalErrors5xx.Load())

	if n, err := s.store.CountWebAdmins(r.Context()); err == nil {
		fmt.Fprintln(w, "# HELP nanotun-web_admins Total web admin accounts")
		fmt.Fprintln(w, "# TYPE nanotun-web_admins gauge")
		fmt.Fprintf(w, "nanotun-web_admins %d\n", n)
	}
}
