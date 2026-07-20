package main

import (
	"io/fs"
	"net/http"
	"strings"
)

// M2:路由表。
//
// 用 net/http 标准库 mux,够用且零依赖。每个 path 显式拆 GET / POST,
// 写操作前一律过 requireCSRFAndAuth(自带 session + csrf 校验)。
//
// 路径风格 RESTful but pragmatic:
//   GET  /users         list
//   GET  /users/new     表单
//   POST /users/new     创建
//   GET  /users/{id}    详情
//   POST /users/{id}/disable
//   POST /users/{id}/delete
//   POST /users/{id}/reset-psk
//
// 因为 net/http mux 不带路径参数解析,handler 自己 strings.Split 取 id。

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// 静态资源(CSS / 小图标)
	mux.Handle("/static/", staticFileServer())

	// 健康 / 监控
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/metrics", s.handleMetrics)

	// K4(2026-05-23):浏览器会自动 GET /favicon.ico;如果不显式 short-circuit,
	// 它会落到 mux "/" → requireCSRFAndAuth → 未登录 → 302 /login,然后浏览器
	// 又跟着 GET /login 拿响应。这次额外的 GET 会再发一个 csrf cookie 覆盖用户
	// 当前看到的登录表单里嵌的 token,POST 提交时直接 "CSRF: token 不匹配"。
	// 直接返回 204 既省事也避免触发其它副作用。
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusNoContent)
	})

	// 公开路由:setup + login + logout + login/totp(密码已过、TOTP 转场)
	mux.HandleFunc("/setup", s.handleSetup)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/login/totp", s.handleLoginTOTP)
	mux.HandleFunc("/logout", s.handleLogout)

	// 业务路由:全部要登录;按 path prefix 分发到 handler。
	authed := http.HandlerFunc(s.routeAuthed)
	mux.Handle("/", s.requireCSRFAndAuth(authed))

	// withLang 放在最内层(紧贴 mux),让语言判定结果在所有 handler(含 renderPage)
	// 里都可用;它可能对带 ?lang= 的 GET 请求做 302 剥参重定向。
	return withRecover(withCommonHeaders(withRequestLog(withLang(mux))))
}

// routeAuthed:已登录路径的二级 dispatcher。把 path 拆成段后路由到具体 handler。
func (s *Server) routeAuthed(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/":
		s.handleDashboard(w, r)

	// users
	case path == "/users":
		s.handleUserList(w, r)
	case path == "/users/new":
		s.handleUserNew(w, r)
	case strings.HasPrefix(path, "/users/"):
		s.handleUserAction(w, r)

	// devices
	case path == "/devices":
		s.handleDeviceList(w, r)
	case strings.HasPrefix(path, "/devices/"):
		s.handleDeviceAction(w, r)

	// leases
	case path == "/leases":
		s.handleLeaseList(w, r)
	case strings.HasPrefix(path, "/leases/"):
		s.handleLeaseAction(w, r)

	// acl
	case path == "/acl":
		s.handleACLList(w, r)
	case path == "/acl/new":
		s.handleACLNew(w, r)
	case strings.HasPrefix(path, "/acl/"):
		s.handleACLAction(w, r)

	// routes (subnet route advertise + 出口节点一键指定)
	case path == "/routes":
		s.handleRouteList(w, r)
	case strings.HasPrefix(path, "/routes/exit/"):
		// 必须先于通配的 /routes/,否则 "exit" 会被当 device_id 解析失败。
		s.handleExitAction(w, r)
	case strings.HasPrefix(path, "/routes/"):
		s.handleRouteAction(w, r)

	// port-forwards (FRP 式反向端口转发：公网端口 → mesh 节点自身/LAN 后设备)
	case path == "/port-forwards":
		s.handlePortForwardList(w, r)
	case path == "/port-forwards/new":
		s.handlePortForwardNew(w, r)
	case strings.HasPrefix(path, "/port-forwards/"):
		s.handlePortForwardAction(w, r)

	// sessions(在线会话/在线设备)
	case path == "/sessions":
		s.handleSessionList(w, r)

	// me(我的账号 + TOTP)
	case path == "/me":
		s.handleMe(w, r)
	case strings.HasPrefix(path, "/me/"):
		s.handleMeAction(w, r)

	// audit
	case path == "/audit":
		s.handleAuditList(w, r)

	// admins (web 后台账号管理)
	case path == "/admins":
		s.handleAdminList(w, r)
	case path == "/admins/new":
		s.handleAdminNew(w, r)
	case strings.HasPrefix(path, "/admins/"):
		s.handleAdminAction(w, r)

	// runtime ops (reload / kick / mesh-toggle)
	case path == "/runtime/reload":
		s.handleRuntimeReload(w, r)
	case path == "/runtime/kick":
		s.handleRuntimeKick(w, r)
	case path == "/runtime/mesh-toggle":
		s.handleRuntimeMeshToggle(w, r)

	// settings (app_settings)
	case path == "/settings":
		s.handleSettingsList(w, r)
	case path == "/settings/rate":
		s.handleSettingsRateSet(w, r)
	case path == "/settings/advertised-host":
		s.handleSettingsAdvertisedHostSet(w, r)
	case path == "/settings/server-dial-host":
		// 2026-05-26 第六轮拆字段:与 advertised-host 兄弟,客户端实际拨号目标,
		// strict IPv4/IPv6/RFC1035 hostname 校验。
		s.handleSettingsServerDialHostSet(w, r)

	// server-qr(2026-05-26):管理员看服务器 profile QR — 需 step-up 密码再验证。
	// GET 输密码,POST 验证 + 显示 QR。详见 handler_server_qr.go。
	case path == "/server-qr":
		s.handleServerQR(w, r)
	case path == "/server-qr/reveal":
		s.handleServerQRReveal(w, r)

	// sysmon (V1, 2026-05-26):系统监控 — CPU/mem/网卡 + VPN 业务流量。
	// HTML shell + 数据走 /sysmon/data 异步轮询(2s)。
	case path == "/sysmon":
		s.handleSysmon(w, r)
	case path == "/sysmon/data":
		s.handleSysmonData(w, r)

	default:
		s.renderError(w, r, http.StatusNotFound, tr(r, "err.pageNotFound", path))
	}
}

// pathSegments:把 /users/12/disable 拆成 ["users", "12", "disable"]。空段不计。
func pathSegments(p string) []string {
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, x := range parts {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// staticFileServer 从 //go:embed static/* 服务出 /static/...
//
// 用 fs.Sub 把 embed 的 "static" 子目录抠出来当 root,然后包成 http.FS 给
// 标准库 FileServer。这样 /static/style.css → static/style.css。
//
// 第十一轮性能:embed.FS 的文件 ModTime 是零值 → FileServer 发不出 Last-Modified,
// 浏览器无从条件请求(If-Modified-Since),每次导航都整包重拉 style.css(25KB)+
// appicon.png(23KB)。加 Cache-Control 一天;资源只随二进制升级变化,模板侧
// 引用带 ?v=<webVersion> 做 cache-busting,升级后 URL 变化自然击穿旧缓存。
func staticFileServer() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// embed.FS 永远存在 "static" 目录(由 go:embed 保证),这条路径
		// 实际上跑不到。退化:404 一切。
		return http.NotFoundHandler()
	}
	inner := http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		inner.ServeHTTP(w, r)
	})
}
