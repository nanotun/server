package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// handleDashboard 渲染管理后台首页:
//   - 顶部:服务运行时状态(uptime / conn_count / acl drop / lease GC)→ 从 control socket
//     拿;失败展示 "运行时数据不可用" 横幅,但页面其它部分(数据库统计)仍可看;
//   - 计数:user / device / lease / acl / route / audit 条目数;
//   - 最近 10 条 audit。
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// 2026-05-27 第二十四轮 P3-3:routes.go `case path == "/"` 把根路径分派到
	// dashboard,但原 handler 无 Method 限制,POST/PUT/DELETE 等也会渲染 HTML —
	// 虽然 CSRF middleware 在 POST 时已校验 token(`requireCSRFAndAuth`),非 GET
	// 仍渲染 dashboard 是无害但有"潜在 surface"。GET-only guard 把意图收紧。
	// HEAD 是 GET 的子集(只要 header),代理 / health check 常用,一并放行。
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	dbStats := s.collectDBStats(ctx)
	runtime, runtimeErr := s.collectRuntime(ctx)

	// 「在线会话」简表,Dashboard 上只展示前 5 条最新会话,详情和踢操作在 /sessions。
	// 失败(control sock 不可达)= 留空 + 顶部已有 RuntimeErr 横幅,不重复显示错误。
	//
	// Q3(2026-05-25):传 WithLimit(10) 让 server 端只返前 10 条 — 比 collect 全量
	// 再客户端切片省 99% 带宽(N=10K conn 时)。多取 5 条余量,留给将来 join 失败
	// 静默丢条目时仍有 5 条可渲染。
	// totalSessions 改用 runtime.sessions_total(server 给的 filter 后总数),不再
	// 用 len(sessions);否则分页拿 10 条就显示「共 10 条」误导。
	sessions, _ := s.collectSessionsForView(ctx, WithLimit(10))
	totalSessions := 0
	if runtime != nil {
		// sessions_total / conn_count 是 JSON 数字 → unmarshal 进 map[string]any 是 float64。
		if v, ok := runtime["sessions_total"].(float64); ok {
			totalSessions = int(v)
		} else if v, ok := runtime["conn_count"].(float64); ok {
			totalSessions = int(v) // 老 server 没有 sessions_total fallback。
		}
	}
	if len(sessions) > 5 {
		sessions = sessions[:5]
	}

	recentAudit, _ := s.store.QueryAudit(ctx, 0, time.Now().Unix()+1, 10)

	// 两个 host 字段同时取(2026-05-26 第六轮拆字段:server_dial_host=dial,
	// advertised_host=label),失败按空兜底 — dashboard 主体功能不应该因为读
	// setting 失败而 500。模板那边:
	//   - **ServerDialHost 是 QR 生成的阻断键**:空 → 顶部红 banner 警告 +
	//     「显示服务器 QR」按钮也禁用,避免 admin 点了才看到 412;
	//   - AdvertisedHost 是展示 label,空就算了,只影响客户端 UI 副标题口径。
	advertisedHost, _ := s.store.GetAdvertisedHost(ctx)
	serverDialHost, _ := s.store.GetServerDialHost(ctx)
	// 2026-05-27 第二十一轮:空 server_dial_host 时根据 admin 当前访问 URL 的 Host
	// 派生候选,dashboard 顶部红 banner 把候选嵌进引导文案,admin 看到「点修改 →
	// 进 settings 页直接 enter 即可」的明显路径。详见 `deriveServerDialHostSuggestion`
	// 安全注记 — 不直接入库,仅作显示用候选。
	var serverDialHostSuggestion string
	if serverDialHost == "" {
		serverDialHostSuggestion = deriveServerDialHostSuggestion(r)
	}
	// 第十三轮(2026-05-27):server_id 在 dashboard 展示给 admin。
	//
	// 为什么 ops 需要看到 server_id:
	//   - 灾备 / 跨机迁移时,admin 要知道当前实例的稳定指纹(类比 hostname 但永不变);
	//   - 客户端按 server_id 做 profile upsert,server_id 变了 = 客户端会当作"全新 server"
	//     重新创建本地 profile(用户体验:连接列表多一项);
	//   - 老 server(2026-05-26 之前)没 server_id,首次访问 dashboard 时 migration
	//     会自动 init 一个 v4 UUID 并写入 app_settings(`GetOrInitServerID`)。
	//     dashboard 用 `GetServerID`(只读)避免 metrics / 路由抓取顺手触发持久化写入 —
	//     init 路径只在 migration 阶段跑一次,handler 应当看到"已 init 完"的状态。
	serverID, _ := s.store.GetServerID(ctx)

	s.renderPage(w, r, "dashboard.html", PageData{
		Title: tr(r, "page.dashboard.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:统一到 helper
		Data: map[string]any{
			"DB":                       dbStats,
			"Runtime":                  runtime,
			"RuntimeErr":               runtimeErrToText(runtimeErr),
			"Sessions":                 sessions,
			"SessionsTotal":            totalSessions,
			"Audit":                    recentAudit,
			"AdvertisedHost":           advertisedHost,
			"ServerDialHost":           serverDialHost,
			"ServerDialHostSuggestion": serverDialHostSuggestion,
			"ServerID":                 serverID,
		},
		Nav: NavContext{Active: "dashboard"},
	})
}

// dbStatsSnapshot:从 SQLite 一把抓所有计数。每查一次 < 1ms。
type dbStatsSnapshot struct {
	Users   int
	Admins  int
	Devices int
	Leases  int
	ACLs    int
	Routes  int
	Audits  int64
	WebSess int
}

func (s *Server) collectDBStats(ctx context.Context) dbStatsSnapshot {
	var out dbStatsSnapshot

	// 这些 count 都是简单 SELECT COUNT,即便表大也走 idx。
	if u, err := s.store.ListUsers(ctx); err == nil {
		out.Users = len(u)
	}
	if n, err := s.store.CountWebAdmins(ctx); err == nil {
		out.Admins = int(n)
	}
	// device / lease / acl / route 没有专门的 Count* 函数,但 List 数量有上限就够展示。
	if d, err := s.store.ListAllRoutes(ctx); err == nil {
		out.Routes = len(d)
	}
	if a, err := s.store.ListACLPairs(ctx); err == nil {
		out.ACLs = len(a)
	}
	if n, err := s.store.CountAudit(ctx); err == nil {
		out.Audits = n
	}
	// devices / leases 没现成的 Count*;走 SQL 一行。
	var n int
	_ = s.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM devices`).Scan(&n)
	out.Devices = n
	n = 0
	_ = s.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM leases`).Scan(&n)
	out.Leases = n
	n = 0
	_ = s.store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM web_sessions`).Scan(&n)
	out.WebSess = n
	return out
}

// collectRuntime:从 nanotund control socket /status 拿。
// 失败时返回 nil + error,handler 渲染时降级。
func (s *Server) collectRuntime(ctx context.Context) (map[string]any, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := s.control.Status(cctx)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func runtimeErrToText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
