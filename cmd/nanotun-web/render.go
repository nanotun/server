package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

	// Nonce 本次请求的 CSP script nonce(withCommonHeaders 生成并注入 ctx,renderPage
	// 从 ctx 填)。模板里所有内联 <script> 必须写 nonce="{{.Nonce}}" 才能在
	// script-src 'nonce-...' 下执行 —— 第十一轮深扫 LOW:去掉 'unsafe-inline' 的配套。
	Nonce string
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
	q := r.URL.Query()
	text := q.Get("flash")
	if text == "" {
		return nil
	}
	kind := normalizeFlashKind(q.Get("flash_kind"))
	// 第三轮深扫 L5:必须带**合法签名**才渲染。此前 flashFromQuery 反射任意 `?flash=<text>`(HTML 转义故
	// 非 XSS,但攻击者可给已登录 admin 发 `/users?flash=<伪装系统消息>&flash_kind=err` 造出以假乱真的
	// 「系统」横幅做站内钓鱼)。现在 flash 由服务端 flashRedirect/flashQuery 签发时附 HMAC 签名,校验不过
	// (缺失 / 伪造)一律静默丢弃 —— 攻击者不知进程随机的 flashHMACKey,无法为任意文本伪造签名。
	if sig := q.Get("flash_sig"); sig == "" || !hmac.Equal([]byte(sig), []byte(flashSig(text, kind))) {
		return nil
	}
	return &Flash{Kind: kind, Text: text}
}

// flashHMACKey 给 ?flash= 反射内容签名。进程随机:flash 在下一个 GET 即被消费,进程级 key 足够;
// 重启只会丢掉「在途」flash 横幅(可接受)。
var flashHMACKey = mustRandomKey(32)

func mustRandomKey(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("nanotun-web: 初始化 flash hmac key 失败: " + err.Error())
	}
	return b
}

// normalizeFlashKind 把 flash_kind 收口到白名单;非法/空一律 "ok"(kind 只影响横幅配色)。
func normalizeFlashKind(kind string) string {
	switch kind {
	case "warn", "err":
		return kind
	default:
		return "ok"
	}
}

// flashSig 对 (kind, text) 算 HMAC 签名(base64url)。kind 须已归一。
func flashSig(text, kind string) string {
	mac := hmac.New(sha256.New, flashHMACKey)
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(text))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// flashQuery 构造带签名的 flash query 片段(不含前导 ? / &):flash=..[&flash_kind=..]&flash_sig=..
// kind 空/非法视为 "ok"(不写 flash_kind)。所有写 ?flash= 的 redirect 都应经此(或 flashRedirect)。
func flashQuery(text, kind string) string {
	k := normalizeFlashKind(kind)
	qs := "flash=" + url.QueryEscape(text)
	if k != "ok" {
		qs += "&flash_kind=" + k
	}
	qs += "&flash_sig=" + flashSig(text, k)
	return qs
}

// flashRedirect 303(SeeOther)跳到 path 并附**签名** flash。path 可自带 query(自动选 ? / &)。
func flashRedirect(w http.ResponseWriter, r *http.Request, path, text, kind string) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	http.Redirect(w, r, path+sep+flashQuery(text, kind), http.StatusSeeOther)
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
	// CSP script nonce:从 withCommonHeaders 注入的 ctx 取,填进 PageData 供模板内联
	// <script nonce="{{.Nonce}}"> 用。空串(crypto/rand 失败的极端情形)时内联脚本会被
	// CSP 拦,但页面 HTML 仍正常渲染 —— 只有依赖内联 JS 的增强功能降级。
	if data.Nonce == "" {
		data.Nonce = cspNonceFromCtx(r.Context())
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
		// 详情(含模板名 / 数据形状 / 内部错误)只进服务端日志;响应回固定通用文案。renderPage 也服务
		// **未鉴权**页(login.html / setup.html),不能把 err.Error() 回显给匿名访客(第三轮深扫 L3)。
		logrus.WithError(err).WithField("template", templateName).Error("[web] 渲染模板失败")
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// renderError 渲染 error 页(或者退化为 plain text)。
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.renderErrorWithCTA(w, r, status, msg, "", "")
}

// renderInternalError 把内部错误详情记到**服务端日志**,只向用户回一条通用 500 文案。
//
// 用于 setup / login / TOTP 等 pre-auth 路径:此前这些路径直接把 err.Error()(可能含 DB 约束、文件
// 路径、内部状态)拼进错误页回显给(未认证的)访客,构成信息泄漏。改为详情只进日志、页面只显示通用
// 提示,既方便运维排查、又不向外暴露实现细节。logCtx 是简短定位串(如 "setup:count_admins")。
func (s *Server) renderInternalError(w http.ResponseWriter, r *http.Request, logCtx string, err error) {
	logrus.WithError(err).WithField("ctx", logCtx).WithField("ip", clientIP(r)).Error("[web] internal error")
	s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.internalGeneric"))
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
	// 详情(可能含 SQL 约束 / 库路径 / 内部状态)只进服务端日志,页面只显示通用 failKey 文案。
	// 此前把裸 err.Error() 拼进错误页 —— viewer 角色也能触达部分会走到这里的写失败路径,构成信息泄漏
	// (第三轮深扫 L4)。与 renderInternalError / L2 / L3 一致:详情进日志,不外泄。
	logrus.WithError(err).WithField("ctx", failKey).WithField("ip", clientIP(r)).Error("[web] store write error")
	s.renderError(w, r, http.StatusInternalServerError, tr(r, failKey))
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

// osHostname:本机 hostname,只 cache 一次。用 sync.Once 消除此前惰性读写 cachedHostname 的良性
// data race(go test -race 报警)。netHostnameOrLocal 始终有兜底返回("localhost"),故 Once 里必得值、
// 不会像随机 decoy 那样有「首次失败即永久退化」的隐患。
var (
	cachedHostname     string
	cachedHostnameOnce sync.Once
)

func osHostname() (string, error) {
	cachedHostnameOnce.Do(func() {
		// hostname 失败大概率是 /etc/hostname 没设;netHostnameOrLocal 会兜底成 "localhost",不返回 error。
		cachedHostname, _ = netHostnameOrLocal()
	})
	return cachedHostname, nil
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
