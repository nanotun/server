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
	// 第四轮深扫 LOW(e_config_lint):此前 lint 只查「语法 + 未知字段」,一份**语义**非法的配置
	// (负速率、非法 CIDR、越界 hy2 调优、REALITY dest 缺 port、exit_mode 拼错……)照样报 OK,却会
	// 在真正重启 server 时才 Fatal —— lint 的价值(重启前拦截)大打折扣。这里补齐启动期同款语义校验:
	// cfg.Validate() + hy2(凭证配套 & 调优区间) + REALITY(启用时) + exit_mode / exit_dns_redirect。
	// 不含 validateVPNListenAddr(那条依赖运行期环回可达性语义,且会 os.Exit,不适合 lint)。
	if lerr := lintSemantic(&cfg); lerr != nil {
		fmt.Fprintln(opts.stderr, opts.T("config.strictFail", path, lerr.Error()))
		return 3
	}
	fmt.Fprintf(opts.stdout, "%s OK\n", path)
	return 0
}

// lintSemantic 复用 config 包里与 server 启动期一致的语义校验,聚合首个失败返回。
// 顺序与 cmd/nanotund 启动路径对齐:通用 Validate → hy2 → REALITY → exit。
func lintSemantic(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	// hy2:凭证「全空或全配齐」+ 启用时的调优区间。两者都对未启用(全空)场景无害。
	if err := cfg.Hysteria.ValidateHysteriaCredentials(); err != nil {
		return err
	}
	if err := cfg.Hysteria.ValidateTuning(); err != nil {
		return err
	}
	// REALITY:仅在 listen_addr 非空(即启用)时做深校验;Validate 内部已对空 listen_addr 直接放行。
	if err := cfg.Reality.Validate(); err != nil {
		return fmt.Errorf("reality: %w", err)
	}
	if err := cfg.TUN.ValidateExitMode(); err != nil {
		return err
	}
	if err := cfg.TUN.ValidateExitDNSRedirect(); err != nil {
		return err
	}
	// 第十六轮深扫 MED:TUN 网段「两者皆空」与「族错配」——同为启动期 Fatal,理应在重启前被 lint 拦下。
	if err := cfg.TUN.ValidateTUNSubnets(); err != nil {
		return err
	}
	// 第七轮深扫 MED:补齐三处「启动期 Fatal(ExitConfigSemantic)但 lint 从前不查」的语义。
	// 这些方法是对应 invariant 的单一事实来源(见 config/validate_startup.go),cmd/nanotund
	// 启动路径按同一语义 fail-fast。任一非法都会让 server 拒绝启动,理应在重启前被 lint 拦下。
	if err := cfg.Server.Pow.Validate(); err != nil {
		return err
	}
	if err := cfg.Server.ValidateTLSPair(); err != nil {
		return err
	}
	if err := cfg.Server.ValidateJumpHostFirewall(); err != nil {
		return err
	}
	if err := cfg.Server.ValidateJumpHostProtectedPorts(); err != nil {
		return err
	}
	return nil
}
