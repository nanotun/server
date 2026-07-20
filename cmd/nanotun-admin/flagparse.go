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
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		// 取第一个非 flag 参数，作为 positional；剩余继续解析。
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}
