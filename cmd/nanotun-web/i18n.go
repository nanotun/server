package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// i18n:多语言(国际化)基础设施。
//
// 设计取舍:
//   - 采用「翻译 key」模式,模板里写 {{T "some.key"}},文案集中在 catZH / catEN
//     两张表(i18n_zh.go / i18n_en.go),而不是把 UI 文案硬编码在模板里 —— 这样
//     单一结构源(模板)+ 集中翻译表,后续加语言只需再补一张表。
//   - 默认语言 = 中文(zh),也是 fallback:某 key 在目标语言缺失时回落 zh,
//     再缺失回落 key 本身(便于开发期发现漏翻)。
//   - 语言判定优先级:?lang= 显式覆盖(并写 cookie 持久化) > lang cookie >
//     Accept-Language 头 > 默认 zh。判定结果挂在 request context 上,renderPage
//     从中取出,给模板注入请求级 T/Th 函数。
//
// 安全:T 返回 string,{{T}} 在模板里按所处上下文(HTML text / 属性 / JS)自动
// 转义,与硬编码文案等价安全。Th 返回 template.HTML(不转义),仅用于「我们自己
// 维护的、含少量 <code>/<a> 标记且不含用户可控数据」的静态片段。

// Lang 语言代码。
const (
	LangZH      = "zh"
	LangEN      = "en"
	LangDefault = LangZH
)

// langCookieName 持久化用户选择的语言。非 HttpOnly(纯 UI 偏好,前端无需读但也无妨),
// SameSite=Lax + Secure(本服务仅 TLS)。
const langCookieName = "lang"

// supportedLangs 当前支持的语言集合(有序,用于渲染切换器)。
var supportedLangs = []string{LangZH, LangEN}

// langDisplayName 语言在切换器里的展示名(用各自母语书写)。
var langDisplayName = map[string]string{
	LangZH: "中文",
	LangEN: "English",
}

// normalizeLang 把任意输入规整成受支持的语言码;不支持返回 ("", false)。
func normalizeLang(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case s == LangZH || strings.HasPrefix(s, "zh"):
		return LangZH, true
	case s == LangEN || strings.HasPrefix(s, "en"):
		return LangEN, true
	}
	return "", false
}

// langFromAcceptHeader 解析 Accept-Language,取第一个受支持语言;都不支持回落默认。
// 简化实现:不解析 q 权重,按出现顺序取首个能匹配的(对 zh/en 二选一足够)。
func langFromAcceptHeader(h string) string {
	for _, part := range strings.Split(h, ",") {
		tag := part
		if i := strings.IndexByte(tag, ';'); i >= 0 {
			tag = tag[:i]
		}
		if l, ok := normalizeLang(tag); ok {
			return l
		}
	}
	return LangDefault
}

// ctxKeyLang 见 middleware.go 的 ctxKey 常量块(那里集中定义,避免 iota 冲突)。

// langFromCtx 从 request context 取语言;缺失回落默认。
func langFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyLang).(string); ok && v != "" {
		return v
	}
	return LangDefault
}

// buildLangSwitchURLs 为每个受支持语言生成「切到该语言」的链接:保留当前 path +
// 其它 query 参数,只把 lang 设成目标语言。withLang 会在收到 ?lang= 的 GET 时写
// cookie 并 302 到剥掉 lang 的干净 URL,其它 query 参数(如 show_disabled / audit
// filter)原样保留,不再被裸 "?lang=xx" 覆盖丢失。
//
// 剔除 flash:切语言不该把上一条操作的成功横幅重新翻出来(flash 是一次性提示)。
func buildLangSwitchURLs(r *http.Request) map[string]string {
	out := make(map[string]string, len(supportedLangs))
	base := *r.URL // 拷贝,避免改到请求自身的 URL
	for _, l := range supportedLangs {
		q := r.URL.Query()
		q.Del("flash")
		q.Del("flash_kind")
		q.Set(langCookieName, l)
		base.RawQuery = q.Encode()
		out[l] = base.RequestURI()
	}
	return out
}

// tr 是 handler 层构造 Title / flash 横幅 / 内联表单错误文案时的便捷翻译封装:
// 按当前请求语言(withLang 判定,挂在 ctx 上)查目录。等价于
// translate(langFromCtx(r.Context()), key, args...)。
func tr(r *http.Request, key string, args ...any) string {
	return translate(langFromCtx(r.Context()), key, args...)
}

// localizedError 是「我们自己定义、且要给用户看」的错误的可本地化契约。
//
// 后端错误创建时拿不到请求语言(store / server / util 等深层包更是与 CLI、日志、
// 中文断言测试共用同一份 err.Error() 文案),所以本项目不把 lang 往下游穿透,而是:
//   - 错误值实现 LocaleKey() 暴露「翻译 key + 参数」;
//   - Error() 仍返回中文(供 CLI / 日志 / errors.Is 之外的落盘保持不变);
//   - web 层用 trErr(r, err) 在响应边界按当前请求语言翻译。
//
// 这样加多语言不改变任何 err.Error() 既有行为,CLI 与既有测试断言不受影响。
type localizedError interface {
	error
	LocaleKey() (key string, args []any)
}

// locErr 是 localizedError 的通用实现:Error() 走默认语言(zh)翻译,
// LocaleKey() 交给 web 层按请求语言翻译。
type locErr struct {
	key  string
	args []any
}

func (e *locErr) Error() string              { return translate(LangDefault, e.key, e.args...) }
func (e *locErr) LocaleKey() (string, []any) { return e.key, e.args }

// newLocErr 构造一个可本地化错误。key 需同时存在于 catZH / catEN(TestCatalogParity 兜底)。
func newLocErr(key string, args ...any) error { return &locErr{key: key, args: args} }

// trErr 把 err 翻成当前请求语言:
//   - err 链上携带 LocaleKey(我们自己定义的错误)→ 按 key + 请求语言翻译;
//   - 否则退回 err.Error()(后端 / 第三方错误保持原样,不强译)。
func trErr(r *http.Request, err error) string {
	if err == nil {
		return ""
	}
	var le localizedError
	if errors.As(err, &le) {
		k, a := le.LocaleKey()
		return tr(r, k, a...)
	}
	return err.Error()
}

// withLang 语言判定中间件。包在整个 mux 外层(见 routes.go),让所有 handler
// (含公开的 /login /setup)都能拿到语言。
//
// ?lang=xx:显式切换。写 cookie 持久化;若是 GET/HEAD,则 302 到「剥掉 lang 参数」
// 的干净 URL —— 既让地址栏不残留 ?lang=,也让后续导航沿用 cookie。非 GET 只写
// cookie 不重定向(避免打断 POST)。
func withLang(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := ""
		if q := r.URL.Query().Get(langCookieName); q != "" {
			if l, ok := normalizeLang(q); ok {
				lang = l
				http.SetCookie(w, &http.Cookie{
					Name:     langCookieName,
					Value:    lang,
					Path:     "/",
					MaxAge:   int((365 * 24 * time.Hour).Seconds()),
					HttpOnly: false,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				})
			}
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				q2 := r.URL.Query()
				q2.Del(langCookieName)
				r.URL.RawQuery = q2.Encode()
				http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
				return
			}
		}
		if lang == "" {
			if c, err := r.Cookie(langCookieName); err == nil {
				if l, ok := normalizeLang(c.Value); ok {
					lang = l
				}
			}
		}
		if lang == "" {
			lang = langFromAcceptHeader(r.Header.Get("Accept-Language"))
		}
		ctx := context.WithValue(r.Context(), ctxKeyLang, lang)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// catalogs 语言 → (key → 文案)。在 i18n_zh.go / i18n_en.go 里各自填充。
var catalogs = map[string]map[string]string{
	LangZH: catZH,
	LangEN: catEN,
}

// translate 查表翻译。缺 key(key 完全不存在)时回落:目标语言 → zh → key 本身。
// 传了 args 则按 fmt.Sprintf 格式化(文案里用 %s/%d 占位)。
//
// 注意:回落条件是「key 不存在(!ok)」而**不是**「值为空」。有些 key 的英文值
// 是**有意的空串**(如中文量词后缀 "共 N 条" 的 " 条",英文 "Total: N" 无后缀),
// 若把空串也当缺失回落,英文界面会漏出中文量词。key 缺失由 TestCatalogParity
// 在测试期兜底,不再依赖运行时空值回落。
func translate(lang, key string, args ...any) string {
	msg, ok := catalogs[lang][key]
	if !ok {
		if msg, ok = catalogs[LangDefault][key]; !ok {
			msg = key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, translateArgs(lang, args)...)
	}
	return msg
}

// translateArgs 递归翻译参数:若某个参数本身是可本地化错误(携带 LocaleKey,
// 典型如 store 层把内层诊断错误当 %s 透传的场景 —— server_dial_host 的 label
// 语法错误 / 特殊 IP reason / ping 明细),就按目标语言把它翻成字符串再交给
// fmt.Sprintf,避免英文界面里混出中文技术细节。非本地化参数原样透传。
func translateArgs(lang string, args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		if le, ok := a.(localizedError); ok {
			k, sub := le.LocaleKey()
			out[i] = translate(lang, k, sub...)
			continue
		}
		out[i] = a
	}
	return out
}

// i18nFuncs 返回绑定到指定语言的模板函数集,供 renderPage 每请求注入到 clone。
//   - T:转义文本(安全默认)。
//   - Th:受信 HTML 片段(不转义),仅用于我们自己维护、不含用户数据的静态标记。
func i18nFuncs(lang string) template.FuncMap {
	return template.FuncMap{
		"T": func(key string, args ...any) string {
			return translate(lang, key, args...)
		},
		"Th": func(key string, args ...any) template.HTML {
			return template.HTML(translate(lang, key, args...)) //nolint:gosec // 受信静态文案
		},
		// fmtDuration 语言感知覆盖:解析期 templateFuncs 注册的是默认(zh)版本,
		// renderPage 用本 map 覆盖成按请求语言翻译的版本,让英文页的相对时间后缀
		// 显示 "ago" 而非 "前"。
		"fmtDuration": func(unix int64) string {
			return fmtDurationSinceLang(lang, unix)
		},
	}
}

// defaultI18nFuncs 解析期占位 + 直接 ExecuteTemplate(未经 renderPage 绑定)时的
// 回退实现:按默认语言(zh)翻译。这样既保证模板能解析 {{T}}/{{Th}},又让不走
// renderPage 的老测试(直接 clone.ExecuteTemplate)仍拿到中文文案。
func defaultI18nFuncs() template.FuncMap {
	return i18nFuncs(LangDefault)
}
