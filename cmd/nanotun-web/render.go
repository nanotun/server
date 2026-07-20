package main

import (
	"bytes"
	"encoding/base32"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// M2:模板渲染封装。
//
// 用 html/template 的"先 buffer 再写"模式:模板执行失败时不会把已经写出去的
// 半截 HTML 留给浏览器,而是直接 500 + 日志,不污染用户视野。

// PageData 是所有页面共享的 envelope。模板里用 .Admin / .Title / .Data 等。
type PageData struct {
	Title     string
	Admin     *store.WebAdmin
	CSRFToken string

	// 横幅:flash 消息(成功 / 警告 / 错误),典型场景是 POST→Redirect→GET 后展示。
	// 当前实现是「请求级 in-context」,跨请求需 cookie / session;先简单实现。
	Flash *Flash

	// 给具体页面用的 payload。
	Data any

	// 顶栏需要的运行时小信息(只在 layout 用到)。
	Nav NavContext

	// Lang 当前渲染语言(zh / en),供 header 渲染 <html lang> 与语言切换器高亮。
	// renderPage 从 request context 注入,handler 不用管。
	Lang string

	// LangSwitchURLs 语言切换链接:key=语言码,value=「保留当前 path + 其它 query
	// 参数、只把 lang 设成该语言」的相对 URL。renderPage 从 r.URL 计算 —— 避免切换器
	// 用裸 "?lang=xx" 覆盖掉 show_disabled / audit filter 等已有 query 参数。
	LangSwitchURLs map[string]string

	// Path 当前页面的站内相对 URL(path + query,已剥 flash/flash_kind)。
	// 2026-07-19 易用性改版:全站 Referrer-Policy 是 no-referrer,浏览器不发
	// Referer,依赖 Referer 的「操作后回原页」全部静默退化回 dashboard —— 侧栏
	// 组网开关等全局表单需要显式 return_to,模板从这里取。renderPage 自动填。
	Path string
}

// Flash 一条提示。Kind: "ok" / "warn" / "err"。
type Flash struct {
	Kind string
	Text string
}

// flashFromQuery 把 `?flash=<text>` 解析成 `*Flash{Kind:"ok"}`,空 query 返回 nil。
//
// 背景(第六轮深扫 P1#1):POST→Redirect→GET 模式的 list 页全都把成功消息塞进
// `?flash=`,但只有 dashboard / sessions / me 三个 GET 主动读了,users / admins /
// routes / acl / devices / settings / leases 都把 query 静默丢弃 —— admin 删一个
// 用户 / 改一条 ACL 后看不到「已删除」横幅。把读 flash 抽成单点工具,GET handler
// 一行调用即可消费,避免每个 list 各自手写五行 + 容易漏。
//
// 默认 `?flash=<text>` → `Kind="ok"`;2026-07-19 易用性改版起支持
// `&flash_kind=warn|err` 覆盖 —— ACL「已创建但重载失败」这类**操作成功但有
// 后续动作要做**的提示,用绿色成功横幅会误导 admin 以为万事大吉。
// kind 白名单收口(ok/warn/err),非法值静默回落 ok(kind 只影响横幅配色)。
func flashFromQuery(r *http.Request) *Flash {
	text := r.URL.Query().Get("flash")
	if text == "" {
		return nil
	}
	kind := "ok"
	switch r.URL.Query().Get("flash_kind") {
	case "warn":
		kind = "warn"
	case "err":
		kind = "err"
	}
	return &Flash{Kind: kind, Text: text}
}

// NavContext:顶栏上展示的当前页活跃 tab + 一些环境标识。
type NavContext struct {
	Active     string // dashboard | users | devices | leases | acl | routes | audit | admins | settings
	Version    string
	ServerHost string

	// MeshEnabled(2026-05-23):全网组网模式总开关。顶栏 partial 用它渲染
	// 「组网 ON / 组网 OFF」一键 toggle 按钮。renderPage 自动从 store 读填,
	// 失败则按 true 兜底(避免 DB 抖动让 UI 上误显示 OFF 让 admin 惊慌)。
	MeshEnabled bool
}

// renderPage 是统一渲染入口。layout.html 必须存在并里面用 {{template "content" .}}
// 把子模板嵌入。子模板必须 {{define "content"}} ... {{end}}。
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request,
	templateName string, data PageData) {

	if data.Admin == nil {
		data.Admin = adminFromCtx(r.Context())
	}
	if data.CSRFToken == "" {
		data.CSRFToken = csrfTokenFromCtx(r.Context())
	}
	if data.Nav.Version == "" {
		data.Nav.Version = webVersion
	}
	if data.Nav.ServerHost == "" {
		h, _ := osHostname()
		data.Nav.ServerHost = h
	}
	// MeshEnabled 总是从 store 读最新值(写路径会写库后立刻 reload server snapshot,
	// 但 UI 上能看见的 source of truth 是 setting 表)。失败按 true 兜底,以免
	// DB 临时不可读把 UI 上 "组网 ON" 误降为 "组网 OFF"。
	// 性能:每次渲染一次 SELECT KEY=,SQLite 在 WAL 模式下走 page cache 命中,
	// 微秒级开销可以接受 — 跟模板渲染本身比可以忽略。后续高并发可考虑给个
	// atomic.Bool 在写路径同步,这里先 KISS。
	meshOn, err := s.store.GetMeshEnabled(r.Context())
	if err != nil {
		logrus.WithError(err).Warn("[web] GetMeshEnabled 失败,顶栏按 ON 兜底渲染")
		meshOn = true
	}
	data.Nav.MeshEnabled = meshOn
	// 语言:从 request context 取(由 withLang 中间件判定),注入 PageData 供模板用。
	lang := langFromCtx(r.Context())
	if data.Lang == "" {
		data.Lang = lang
	}
	if data.LangSwitchURLs == nil {
		data.LangSwitchURLs = buildLangSwitchURLs(r)
	}
	if data.Path == "" {
		// 只有 GET/HEAD 的 URL 才能安全回跳 —— POST 场景(表单校验失败重渲染、
		// POST 触发的错误页)r.URL 是写路径(如 /users/5/delete),GET 它会 405。
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			q := r.URL.Query()
			q.Del("flash") // 一次性提示不该被 return_to 再带回来
			q.Del("flash_kind")
			u := *r.URL
			u.RawQuery = q.Encode()
			data.Path = u.RequestURI()
		} else {
			data.Path = "/"
		}
	}
	if data.Title == "" {
		data.Title = translate(data.Lang, "app.title")
	}

	// 第十一轮性能:优先用启动时按语言预 Clone 好的模板集(见 buildLangTemplates),
	// 请求路径不再逐次深拷贝 30+ 个 parse tree。html/template 并发 Execute 安全。
	clone := s.tmplByLang[data.Lang]
	if clone == nil {
		// 回落:老测试手工构造 Server 只填 tmpl,保持逐请求 Clone + 绑定语言 funcs。
		c, err := s.tmpl.Clone()
		if err != nil {
			logrus.WithError(err).Error("[web] clone templates 失败")
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		clone = c.Funcs(i18nFuncs(data.Lang))
	}
	// 子模板内部都已 {{define "content"}},Clone 后 ExecuteTemplate("layout.html") 能找到。
	// 但若子模板和 layout 是分离的 partials,我们用 ExecuteTemplate(子模板) 这种简化路径。
	// 这里走「子模板 = 完整页面,内联了 layout 引用」模式 → 直接 ExecuteTemplate(子模板名)。
	var buf bytes.Buffer
	if err := clone.ExecuteTemplate(&buf, templateName, data); err != nil {
		logrus.WithError(err).WithField("template", templateName).Error("[web] 渲染模板失败")
		http.Error(w, "internal: render "+templateName+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// renderError 渲染 error 页(或者退化为 plain text)。
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.renderErrorWithCTA(w, r, status, msg, "", "")
}

// renderStoreWriteErr 统一处理「先 Get 校验存在、再 store 写」路径上写操作的报错渲染。
//
// 深扫第八轮 LOW:这些 action handler(user/admin/device 的 disable/enable/delete/
// set-* 等)都先 Get 一次(命中 404),但随后的写若因 GET→写之间那条窄窗口内该行被删
// (TOCTOU)返回 store.ErrNotFound,此前一律被包成通用 500。route/lease/port-forward
// 这类「无前置 Get」的 handler 已正确映射 404,这里让前者对齐:ErrNotFound → 404
// (用调用方给的实体 notFoundKey),其余错误仍 500(failKey + 原始错误串)。
func (s *Server) renderStoreWriteErr(w http.ResponseWriter, r *http.Request, err error, notFoundKey, failKey string) {
	if errors.Is(err, store.ErrNotFound) {
		s.renderError(w, r, http.StatusNotFound, tr(r, notFoundKey))
		return
	}
	s.renderError(w, r, http.StatusInternalServerError, tr(r, failKey)+err.Error())
}

// renderErrorWithCTA 在 error.html 默认「返回首页」按钮**之外**额外渲染一个
// secondary action 按钮(链接形式,主样式 btn-primary 引导优先点)。caller 把
// 失败场景对应的「下一步推荐操作」写进 ctaURL/ctaLabel — admin 在 error 页
// 看到清晰的逃生路径,不必凭直觉摸索"现在该去哪修复"。
//
// 2026-05-27 第二十四轮 P3-2 引入。典型用法:
//   - 412 ICMP softfail:label="到设置页勾选「跳过 ICMP」重试", url="/settings"
//   - 400 server_dial_host 语法:label="到设置页手改", url="/settings"
//
// ctaURL=="" 则不渲染 secondary,与旧 renderError 行为完全等价。
func (s *Server) renderErrorWithCTA(w http.ResponseWriter, r *http.Request, status int, msg, ctaURL, ctaLabel string) {
	admin := adminFromCtx(r.Context())
	lang := langFromCtx(r.Context())
	data := PageData{
		Title: translate(lang, "error.title", status),
		Admin: admin,
		Data: map[string]any{
			"Status":   status,
			"Message":  msg,
			"CTAURL":   ctaURL,
			"CTALabel": ctaLabel,
		},
	}
	w.WriteHeader(status)
	// 退化:如果模板没定义 error.html,plain text(secondary CTA 也只在 plain
	// 文本里附一行,避免 admin 凉透完全无引导)。
	if s.tmpl.Lookup("error.html") == nil {
		body := fmt.Sprintf("[%d] %s\n", status, msg)
		if ctaURL != "" {
			body += fmt.Sprintf("%s: %s -> %s\n", translate(lang, "error.nextStep"), ctaLabel, ctaURL)
		}
		_, _ = w.Write([]byte(body))
		return
	}
	s.renderPage(w, r, "error.html", data)
}

// =========================================================================
// 模板函数
// =========================================================================

func templateFuncs() template.FuncMap {
	fm := template.FuncMap{
		"fmtTime":     fmtTime,
		"fmtDuration": fmtDurationSince,
		"fmtBool":     fmtBool,
		"fmtBytes":    fmtBytes,
		// rateBytes:0011 限速展示。byte/s → "12.0 MiB/s (96 Mbps)"。0/负 → "—"。
		"rateBytes": rateBytesHuman,
		"trim":      strings.TrimSpace,
		"upper":     strings.ToUpper,
		"lower":     strings.ToLower,
		"isEmpty":   isEmpty,
		"join":      strings.Join,
		"contains":  strings.Contains,
		"add":       func(a, b int) int { return a + b },
		"sub":       func(a, b int) int { return a - b },
		"int64":     func(v any) int64 { return toInt64(v) },
		"qrPayload": qrPayload,
	}
	// i18n:注册默认(zh)T/Th,保证模板能解析 {{T}}/{{Th}};renderPage 会按请求
	// 语言用 clone.Funcs 覆盖。
	for k, v := range defaultI18nFuncs() {
		fm[k] = v
	}
	return fm
}

func fmtTime(unix int64) string {
	if unix <= 0 {
		return "-"
	}
	return time.Unix(unix, 0).Local().Format("2006-01-02 15:04:05")
}

// fmtDurationSince 是解析期 / 默认语言(zh)入口。renderPage 会用 i18nFuncs(lang)
// 把模板里的 {{fmtDuration}} 覆盖成按请求语言翻译的 fmtDurationSinceLang。
func fmtDurationSince(unix int64) string {
	return fmtDurationSinceLang(LangDefault, unix)
}

// fmtDurationSinceLang 语言感知的「相对现在多久前」。后缀(前 / ago)走 i18n 目录,
// 让英文页显示 "5m ago" 而不是 "5m 前"。
func fmtDurationSinceLang(lang string, unix int64) string {
	if unix <= 0 {
		return "-"
	}
	d := time.Since(time.Unix(unix, 0))
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return translate(lang, "time.agoSeconds", int(d.Seconds()))
	case d < time.Hour:
		return translate(lang, "time.agoMinutes", int(d.Minutes()))
	case d < 24*time.Hour:
		return translate(lang, "time.agoHours", int(d.Hours()))
	default:
		return translate(lang, "time.agoDays", int(d.Hours()/24))
	}
}

func fmtBool(b bool) string {
	if b {
		return "✓"
	}
	return "✗"
}

func fmtBytes(n int64) string {
	const k = 1024
	if n < k {
		return fmt.Sprintf("%d B", n)
	}
	if n < k*k {
		return fmt.Sprintf("%.1f KiB", float64(n)/k)
	}
	if n < k*k*k {
		return fmt.Sprintf("%.1f MiB", float64(n)/(k*k))
	}
	return fmt.Sprintf("%.1f GiB", float64(n)/(k*k*k))
}

func isEmpty(s string) bool { return strings.TrimSpace(s) == "" }

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case int64:
		return x
	case uint:
		return int64(x)
	case uint32:
		return int64(x)
	case uint64:
		return int64(x)
	}
	return 0
}

// qrPayload:把 PSK / profile 信息编成可扫码字符串。
// 当前简单返回原文,后续可改成 client profile JSON 的 URL-safe base32。
func qrPayload(s string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(s))
}

// =========================================================================
// helpers
// =========================================================================

// osHostname:本机 hostname,只 cache 一次。
var cachedHostname string

func osHostname() (string, error) {
	if cachedHostname != "" {
		return cachedHostname, nil
	}
	// hostname 失败大概率是 /etc/hostname 没设;给一个推断兜底。
	h, err := netHostnameOrLocal()
	if err == nil {
		cachedHostname = h
	}
	return h, err
}

func netHostnameOrLocal() (string, error) {
	if h, err := netLookupSelf(); err == nil && h != "" {
		return h, nil
	}
	if h, err := osDirectHostname(); err == nil && h != "" {
		return h, nil
	}
	return "localhost", nil
}

func netLookupSelf() (string, error) {
	addrs, err := net.LookupAddr("127.0.0.1")
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		a = strings.TrimSuffix(a, ".")
		if a != "" && a != "localhost" {
			return a, nil
		}
	}
	return "", fmt.Errorf("no usable addr")
}

func osDirectHostname() (string, error) {
	return hostnameOS()
}
