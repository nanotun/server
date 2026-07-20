package main

// J4(2026-05-22)config 子命令:
//
//   nanotun-admin config lint <path>
//     用 strict 模式校验 server config.toml,任何未知字段返回非 0 退出码,
//     便于 CI / 升级流程在重启 server 前先验证配置干净。
//
// 不需要 SQLite,直接读文件 + 调 config.StrictCheck。

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"

	"github.com/nanotun/server/config"
)

func cmdConfig(opts *globalOpts, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(opts.stderr, configUsage(opts))
		return 2
	}
	switch args[0] {
	case "lint":
		return cmdConfigLint(opts, args[1:])
	case "help", "-h", "--help":
		fmt.Fprintln(opts.stdout, configUsage(opts))
		return 0
	default:
		fmt.Fprintf(opts.stderr, "%s\n%s\n", opts.T("cli.unknownSubcommandBare", args[0]), configUsage(opts))
		return 2
	}
}

func configUsage(opts *globalOpts) string {
	return opts.T("config.usage")
}

func cmdConfigLint(opts *globalOpts, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(opts.stderr, opts.usage("nanotun-admin config lint <config.toml>"))
		return 2
	}
	path := args[0]
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(opts.stderr, "read %s: %v\n", path, err)
		return 1
	}
	// 先 lenient 解一遍:语法错 / 类型错在这里抓到。
	var cfg config.Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintln(opts.stderr, opts.T("config.tomlParseFail", err.Error()))
		return 4
	}
	// 再走 strict 检查未知字段。
	if err := config.StrictCheck(data); err != nil {
		fmt.Fprintln(opts.stderr, opts.T("config.strictFail", path, err.Error()))
		return 3
	}
	fmt.Fprintf(opts.stdout, "%s OK\n", path)
	return 0
}
