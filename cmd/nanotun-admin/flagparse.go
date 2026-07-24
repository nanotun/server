package main

import "flag"

// parseInterspersed 跟标准库 flag.FlagSet.Parse 类似，但允许 flag 与 positional
// 交错出现：例如 `user create alice --admin` 也能识别。
//
// flag 的值如果用 `--key value` 写法，仍由 flag 包自己消费 value，不会被错误归到 pos。
// 错误一律向上抛，由调用方转换为「usage」提示。
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			// 第十四轮深扫 LOW:flag 解析错误(未知 flag 如 `backup --bogus`、非法取值、缺参、`-h`)属**用法错误**
			// → exit 2,与顶层 dispatch / restore / 其它 usageError 退出码一致(此前经 runWithStore 恒 exit 1)。
			// fs 已把详情 + usage 打到 stderr;这里包成 usageErr(携带 inner)让 exitCodeForErr 归 2。
			return nil, usageErrorWrap(err.Error(), err)
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		// 取第一个非 flag 参数，作为 positional；剩余继续解析。
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}
