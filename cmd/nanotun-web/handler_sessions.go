package main

import (
	"net/http"
	"strings"
)

// 2026-05-23 新增:M2 在线会话/在线设备页面。
//
// GET /sessions
//
// 列出当前 nanotund 维持的所有活跃链路:每条 conn 一行,展示 user / device /
// vIPv4 / vIPv6 / 连接时长 / 出口开关 / 限速。每行可单击「踢」(POST /runtime/kick
// kind=session id=<conn_id>),复用现有 runtime/kick handler 的 audit/CSRF/角色校验,
// 不引入新写路径。
//
// 数据来源:nanotund control socket /status 的 sessions[];本 handler 不直接读
// DB(except join 出 username / device_name)。control sock 不可达时降级展示错
// 误横幅,DB join 走 collectSessionsForView 的 best-effort 路径(单条失败留空,
// 不阻断其它行)。
//
// 不做的事:
//   - 不分页:conn_count 通常 < 256,一页够。若未来明显爆量再分页。
//   - 不做实时 SSE 推送:Refresh 按钮 + 浏览器 F5 够用,简单可靠。
//   - 没有 filter:有需要先看 device list 再来这里找,filter 后置到 P3。
func (s *Server) handleSessionList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessions, err := s.collectSessionsForView(r.Context())
	// 2026-07-19 易用性:?autorefresh=1 开启 10s 自动刷新(模板底部内嵌一段
	// setInterval + document.hidden 守门的小脚本;无 JS 浏览器退化为手动刷新)。
	// 状态随 query 参数持续,书签/分享链接也能带上。
	autoRefresh := false
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("autorefresh"))) {
	case "1", "true", "yes", "on":
		autoRefresh = true
	}
	s.renderPage(w, r, "sessions_list.html", PageData{
		Title: tr(r, "page.sessions.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:统一到 helper,去重 dashboard / me / sessions 的手写解析
		Data: map[string]any{
			"Sessions":    sessions,
			"RuntimeErr":  runtimeErrToText(err),
			"AutoRefresh": autoRefresh,
		},
		Nav: NavContext{Active: "sessions"},
	})
}
