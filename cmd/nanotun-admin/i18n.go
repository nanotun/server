package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nanotun/server/store"
)

// i18n:nanotun-admin(CLI)的多语言支持。
//
// 设计:
//   - 默认语言 = **英文**(langDefault = langEN)。CLI 面向运维/自动化,英文更通用;
//     显式 `--lang zh`(或 env NANOTUN_LANG=zh)切中文。
//   - 与 nanotun-web 各自独立一份 catalog —— 两者是不同的 main 包,不共享代码;
//     CLI 的文案(usage / 表格 / 提示 / 错误)与 web 也基本不重叠。
//   - store 层的 LocalizedError(host / probe 校验)经 opts.errText 用同名 key 翻译,
//     所以 CLI catalog 里也补了那几个 store.* key(值与 web 对齐)。
//   - 回落:目标语言缺 key → 英文(默认)→ key 本身。
//
// 用法:子命令里 `opts.T("key", args...)` 取文案;错误统一由顶层 opts.errText 翻译。

const (
	langEN      = "en"
	langZH      = "zh"
	langDefault = langEN // CLI 默认英文
)

// normalizeLang 把用户输入 / 环境变量归一化成 langEN / langZH。
func normalizeLang(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case s == "en" || s == "english" || strings.HasPrefix(s, "en-") || strings.HasPrefix(s, "en_"):
		return langEN, true
	case s == "zh" || s == "cn" || s == "chinese" ||
		strings.HasPrefix(s, "zh-") || strings.HasPrefix(s, "zh_"):
		return langZH, true
	}
	return "", false
}

// cliCatalogs 语言 → (key → 文案)。catEN / catZH 在 catalog_en.go / catalog_zh.go。
var cliCatalogs = map[string]map[string]string{
	langEN: catEN,
	langZH: catZH,
}

// translate 查表翻译。缺 key(完全不存在)时回落:目标语言 → 英文 → key 本身。
// 传了 args 则按 fmt.Sprintf 格式化。
func translate(lang, key string, args ...any) string {
	if lang == "" {
		lang = langDefault
	}
	msg, ok := cliCatalogs[lang][key]
	if !ok {
		if msg, ok = cliCatalogs[langDefault][key]; !ok {
			msg = key
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, translateArgs(lang, args)...)
	}
	return msg
}

// translateArgs 递归翻译参数:若某个参数本身携带 LocaleKey(典型如 store 层把
// 内层诊断错误当 %s 透传:server_dial_host 的 label 语法错误 / 特殊 IP reason /
// ping 明细),按目标语言翻成字符串再交给 fmt.Sprintf,避免英文输出里混出中文。
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

// T 是子命令构造输出文案的便捷封装,按 opts.lang 查表。
func (o *globalOpts) T(key string, args ...any) string {
	return translate(o.lang, key, args...)
}

// warnPSKOnArgv 在运维通过 --psk 在命令行明文传 PSK 时打一条 stderr 提示:命令行参数会进入 ps /
// /proc/<pid>/cmdline / shell history,含密 PSK 因而可能被同机其它本地用户或历史文件读到。这是提示而
// **非阻断**(脚本化 / 自动化仍需要 --psk);更安全的做法是省略 --psk 让系统随机生成、再从命令输出读取。
// 仅在 flag 值非空时调用。
func (o *globalOpts) warnPSKOnArgv() {
	fmt.Fprintln(o.stderr, o.T("psk.argvLeakWarning"))
}

// usage 拼装子命令的 usage 提示:前缀("usage: " / "用法: ")按语言切换,后面的
// 命令语法(子命令名 / flag / 占位符)是用户实际敲的字面量,不翻译。
func (o *globalOpts) usage(syntax string) string {
	return o.T("common.usagePrefix") + syntax
}

// usageErr 标记「用法 / 参数错误」——与运行期错误(DB / IO / 业务失败)区分,让顶层退出码映射
// 把它统一到 exit 2(与顶层 dispatch、restore、config lint、connection 的 usage 退出码一致),
// 而非 runWithStore / 直连 handler 默认的 exit 1。
//
// 第十一轮深扫 LOW(保留项):此前经 runWithStore 的子命令把 usage 错误当普通 error 返回 → 恒 exit 1,
// 与 CLI 其余「usage = exit 2」的约定不一致(如 `nanotun-admin user` 无 verb 曾 exit 1,而 `restore`
// 无参 exit 2)。用本 sentinel 把二者归一。errText 走 err.Error()(usageErr 无 LocaleKey),文案与
// 原 errors.New(opts.usage(...)) 完全一致。
type usageErr struct {
	msg   string
	inner error
}

func (e *usageErr) Error() string {
	if e.inner != nil {
		return e.msg + ": " + e.inner.Error()
	}
	return e.msg
}
func (e *usageErr) Unwrap() error { return e.inner }

// usageError 把一段已拼好的 usage 文本(通常来自 opts.usage(...))包成 *usageErr。
func usageError(msg string) error { return &usageErr{msg: msg} }

// usageErrorWrap 同 usageError,但额外携带内层错误(如 flag / 数字解析失败),
// Error() 拼成 "用法: ...: <inner>",与原 fmt.Errorf("%s: %w", opts.usage(...), err) 文案一致。
func usageErrorWrap(msg string, inner error) error { return &usageErr{msg: msg, inner: inner} }

// isUsageErr 报告 err 链中是否含 *usageErr(顶层据此把退出码判为 2)。
func isUsageErr(err error) bool {
	var u *usageErr
	return errors.As(err, &u)
}

// exitCodeForErr 把一次子命令返回的非 nil 错误映射为进程退出码:用法/参数错误 → 2,其余 → 1。
func exitCodeForErr(err error) int {
	if isUsageErr(err) {
		return 2
	}
	// 第十二轮深扫 MED:未知子命令(`user bogus` / `route bogus` …)属**用法错误**,应与顶层 dispatch、
	// `config` 未知子命令、restore 的 exit 2 对齐,而非经 runWithStore 默认吞成的 exit 1。这些错误由
	// newLocErr 携带 LocaleKey(cli.unknownSubcommand[Bare])而非 *usageErr,故在此按 key 归一。
	var le *locErr
	if errors.As(err, &le) {
		switch le.key {
		case "cli.unknownSubcommand", "cli.unknownSubcommandBare":
			return 2
		// 第十四轮深扫 LOW:未知 flag(如 `backup --bogus`)与多余参数同属**用法错误** → exit 2,与未知子命令 /
		// flag 解析错(usageErrorWrap)一致(此前经 runWithStore 恒 exit 1)。
		case "cli.unknownFlag", "cli.unexpectedArgs":
			return 2
		}
	}
	return 1
}

// localizedError 是「携带翻译 key」的错误契约(store.LocalizedError 等实现它)。
// 结构化(duck-typed)接口:任何带 LocaleKey() (string, []any) 方法的类型都匹配,
// 无需 import 具体类型。
type localizedError interface {
	LocaleKey() (key string, args []any)
}

// locErr 是 CLI 自产的可翻译错误 —— 用在拿不到 opts 的纯 helper(如 rate_fmt.go 的
// parseRateFlag)里。Error() 回落**英文**(默认语言),与「CLI 默认英文」一致;真正
// 展示时由顶层 opts.errText 按用户语言翻译。
type locErr struct {
	key  string
	args []any
}

func (e *locErr) Error() string              { return translate(langDefault, e.key, e.args...) }
func (e *locErr) LocaleKey() (string, []any) { return e.key, e.args }

func newLocErr(key string, args ...any) error { return &locErr{key: key, args: args} }

// errText 把 err 翻成当前语言:
//   - err **本身**携带 LocaleKey(如 store 的校验/探测错误直接冒泡)→ 按 key + 语言翻译;
//   - 否则退回 err.Error()(其余错误原样;CLI 自己包一层的错误应在构造处用 opts.T /
//     opts.errText 把内层翻好,故这里用直接类型断言而非 errors.As —— 避免穿透 CLI 的
//     包装前缀、只翻内层而丢掉外层语义)。
func (o *globalOpts) errText(err error) string {
	if err == nil {
		return ""
	}
	if le, ok := err.(localizedError); ok {
		k, a := le.LocaleKey()
		return o.T(k, a...)
	}
	return err.Error()
}

// notFoundErr 把 store.ErrNotFound 翻成本地化的「不存在」消息(带标识 ident);其它错误原样返回。
// 深扫第十一轮 LOW:route/acl/lease 各 verb 已本地化 ErrNotFound,而 user/device 的解析路径
// 仍裸抛英文 "store: not found"。用本 helper 在这些 verb 的解析点统一口径,消除不一致。
func (o *globalOpts) notFoundErr(err error, key string, ident any) error {
	if errors.Is(err, store.ErrNotFound) {
		return errors.New(o.T(key, ident))
	}
	return err
}
