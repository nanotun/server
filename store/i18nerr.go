package store

// LocalizedError 是「store 定义、且会经由 nanotun-web 展示给最终用户」的错误。
//
// 背景 / 约束:store 是 nanotun-web 与 nanotun-admin(CLI)共用的 DAL,错误创建
// 时既拿不到 HTTP 请求语言,又不能改动 Error() 的中文文案 —— CLI 直接把 err.Error()
// 打到终端、日志按中文记录、store 的一批测试用 strings.Contains(err.Error(), "中文")
// 断言。因此本类型采用「双载」:
//
//   - Error() 返回中文(默认语言,已格式化)—— CLI / 日志 / 测试行为完全不变;
//   - LocaleKey() 暴露「翻译 key + 参数」—— nanotun-web 的 trErr 通过 duck-typed
//     接口 { error; LocaleKey() (string, []any) } 用 errors.As 捕获,按请求语言查
//     它自己的 catalog 翻译。store 不需要知道 web 的 catalog,web 也不需要 import store
//     的具体类型(靠接口结构匹配)。
//   - Unwrap() 保留底层 error 链,让 errors.Is/As(如 %w 包裹的 ErrDuplicate)照常工作。
type LocalizedError struct {
	msg     string // 中文,已格式化;Error() 原样返回
	key     string // 翻译 key,须同时存在于 web 的 catZH / catEN
	args    []any  // 传给上层 catalog fmt.Sprintf 的参数
	wrapped error  // 可选:保留 errors.Is/As 链
}

func (e *LocalizedError) Error() string              { return e.msg }
func (e *LocalizedError) LocaleKey() (string, []any) { return e.key, e.args }
func (e *LocalizedError) Unwrap() error              { return e.wrapped }

// i18nErr 构造可本地化错误:zhMsg 给 Error()/CLI/测试(应与既有中文文案逐字节一致),
// key+args 给 web 按语言翻译。
func i18nErr(key, zhMsg string, args ...any) error {
	return &LocalizedError{msg: zhMsg, key: key, args: args}
}

// i18nErrWrap 同 i18nErr,但额外保留 wrapped 到 Unwrap 链(用于 %w 语义的场景,
// 如 public_port 冲突包裹 ErrDuplicate,调用方仍可 errors.Is(err, ErrDuplicate))。
func i18nErrWrap(key, zhMsg string, wrapped error, args ...any) error {
	return &LocalizedError{msg: zhMsg, key: key, args: args, wrapped: wrapped}
}
