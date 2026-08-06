package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 每个子命令都得认 `--help`。
//
// 从前只有 config 认,其余十几个一律答 unknown subcommand "--help" —— 而裸打子命令名
// 就会把同一段用法印出来。人当然是先敲 --help 的。
//
// 更要紧的是「问用法不该把事做了」:从前 `vacuum --help` 真的去独占锁库跑了一次 VACUUM,
// `restore --help` 真的开始尝试恢复,`reload --help` 把 --help 当成 reload 目标发给了 server。
//
// 顺带钉住两条前提:
//   - 退出码 0、文字走 stdout:明确问用法时,用法是答案而不是错误。
//   - 不碰数据库:这里指的库根本不存在,任何一个子命令若在拿到 usage 前就去开库,
//     测试会看见 "db not found" 而不是用法。装机之前也得能查用法。
func TestSubcommandHelp(t *testing.T) {
	subs := []string{
		"init", "user", "device", "lease", "acl", "setting", "profile",
		"credentials", "audit", "webadmin", "connection", "route", "exit",
		"config", "backup", "vacuum", "restore", "reload", "kick",
	}
	// 一个确定不存在的库路径:任何提前开库的行为都会在输出里露出马脚,
	// 而「库被凭空建出来」正好是干活的铁证 —— 查用法不该留下任何痕迹。
	dir := t.TempDir()
	missingDB := filepath.Join(dir, "definitely-absent.db")

	for _, sub := range subs {
		for _, tok := range []string{"--help", "-h", "help"} {
			t.Run(sub+" "+tok, func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				opts := &globalOpts{
					stdout: &stdout, stderr: &stderr,
					dbPath: missingDB, lang: langEN,
				}

				code := runRoot([]string{sub, tok}, opts)
				out := stdout.String() + stderr.String()

				if code != 0 {
					t.Errorf("exit %d(应为 0),输出=%q", code, out)
				}
				if !strings.Contains(out, sub) {
					t.Errorf("用法里应出现子命令名 %q, got %q", sub, out)
				}
				if strings.Contains(out, "db not found") || strings.Contains(out, "db not initialized") {
					t.Errorf("--help 不该需要数据库, got %q", out)
				}
				if strings.Contains(out, "unknown subcommand") {
					t.Errorf("不该报 unknown subcommand, got %q", out)
				}
				if _, err := os.Stat(missingDB); err == nil {
					t.Fatalf("%s --help 把数据库建出来了 —— 说明它真去干活了", sub)
				}
			})
		}
	}
}

// `--help` 夹在真实参数里时不算「问用法」,交回正常解析去报错,
// 免得 `user --help create` 这种误打被当成查文档而悄悄什么都不做。
func TestHelpTokenOnlyWhenAlone(t *testing.T) {
	for _, args := range [][]string{
		{"user", "--help", "create"},
		{"user", "create", "--help"},
		{"user", "-h", "-h"},
	} {
		if isHelpToken(args[1:]) {
			t.Errorf("%v 不该被当成单纯问用法", args)
		}
	}
	for _, tok := range []string{"help", "-h", "--help"} {
		if !isHelpToken([]string{tok}) {
			t.Errorf("%q 应被当成问用法", tok)
		}
	}
}
