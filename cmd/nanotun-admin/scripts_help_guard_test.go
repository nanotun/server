package main

// scripts_help_guard_test.go —— 装成命令的那几个脚本,`--help` 得真的能用。
//
// 装机时 install-self-hosted.sh 会把 scripts/ 里的四个脚本装进 /usr/local/bin,并且**改名**:
// setup.sh → nanotun-setup、preflight.sh → nanotun-preflight、uninstall.sh → nanotun-uninstall、
// set-magic-suffix.sh → nanotun-set-suffix。改名的理由恰恰是「一键安装的人当前目录里没有
// scripts/」—— 发布包解压在 /opt/nanotun/<版本>-<架构>/ 底下,用完基本不会再回去。
//
// 于是帮助文案有了一个没人盯着的失效方式:脚本自己写的还是 `./scripts/xxx.sh`,而人手里
// 只有 `nanotun-xxx`。照着敲的是一条不存在的路径,而这话偏偏出现在他最需要它的时候
// (想卸载、想改后缀)。
//
// 这不是假想,是已经发生过三次的同一件事:setup.sh 早就按 $0 改名了并写了注释说明缘由,
// 而同期装成命令的另外三个都没跟上 —— uninstall.sh 的用法一直写着 ./scripts/uninstall.sh;
// preflight.sh 的 -h 是 `sed -n '2,30p' "$0"`,注释长过 30 行之后既截断又把 `set -uo pipefail`
// 这行源码打了出来;set-magic-suffix.sh 干脆没有 --help,`--help` 被当成后缀,回一句
// 「FATAL: 后缀不合法」。三个都是「装成命令」这件事发生之后才出现的,而 shell 那侧没有单测,
// 从 Go 这边把它们按装好的名字跑一遍是唯一能把这条变成断言的办法。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 装机时会改名的脚本,以及它们装好之后的名字。新增一个装成命令的脚本时,这里也要加一行 ——
// 漏了不会有任何提示,而漏掉的那个正是下一个长歪的。
var installedAsCommand = []struct {
	script string // 相对仓库根
	name   string // 装进 /usr/local/bin 之后的名字
}{
	{"scripts/setup.sh", "nanotun-setup"},
	{"scripts/preflight.sh", "nanotun-preflight"},
	{"scripts/uninstall.sh", "nanotun-uninstall"},
	{"scripts/set-magic-suffix.sh", "nanotun-set-suffix"},
}

func TestInstalledScripts_HelpWorksUnderInstalledName(t *testing.T) {
	for _, tc := range installedAsCommand {
		t.Run(tc.name, func(t *testing.T) {
			src := filepath.Join("../..", tc.script)
			raw, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("读 %s: %v", tc.script, err)
			}
			// 按**装好之后的名字**跑。这一点是本测试的全部意义:这几个脚本的帮助都按 $0
			// 分岔,用原文件名跑等于走了另一条分支,恰好绕开要测的那条。
			bin := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(bin, raw, 0o755); err != nil {
				t.Fatal(err)
			}

			out, err := exec.Command("bash", bin, "--help").CombinedOutput()
			body := string(out)
			if err != nil {
				t.Fatalf("`%s --help` 退出码非 0(%v),输出:\n%s\n"+
					"  装成命令的脚本都该有 --help —— 想确认参数的人第一反应就是敲它", tc.name, err, body)
			}
			if strings.TrimSpace(body) == "" {
				t.Fatalf("`%s --help` 什么都没打", tc.name)
			}

			// 帮助里得出现它自己被调用的那个名字,否则等于没告诉人该敲什么。
			if !strings.Contains(body, tc.name) {
				t.Errorf("`%s --help` 的输出里没出现 %q —— 照着敲的人不知道该敲哪个命令:\n%s",
					tc.name, tc.name, body)
			}

			// 也不该再指 ./scripts/xxx.sh:一键安装的人手里没有那个目录。
			stale := "./scripts/" + filepath.Base(tc.script)
			if strings.Contains(body, stale) {
				t.Errorf("`%s --help` 里还写着 %q —— 一键安装的机器上没有 scripts/ 目录,"+
					"照着敲是一条不存在的路径。按 $0 判一下,装成命令时改写成 %s:\n%s",
					tc.name, stale, tc.name, body)
			}

			// 帮助里混进源码,说明它是按行号截的注释而不是按内容取的。
			// preflight.sh 的 `sed -n '2,30p'` 就是这么把 `set -uo pipefail` 打出来的 ——
			// 屏幕上看着像脚本自己出了错。
			for _, leak := range []string{"set -euo pipefail", "set -uo pipefail", "#!/usr/bin/env"} {
				if strings.Contains(body, leak) {
					t.Errorf("`%s --help` 里混进了源码 %q —— 多半是按写死的行号截注释,"+
						"注释一变长就既截断又漏出代码。按行内容判起止:\n%s", tc.name, leak, body)
				}
			}
		})
	}
}

// 除了 --help,别的以 - 开头的参数也不该被当成正常输入吞掉。
//
// set-magic-suffix.sh 此前就是这样:参数直接落进 SUFFIX,`--help` 被后缀合法性正则判死,
// 打出「后缀不合法（只允许小写字母/数字/连字符）：'--help'」—— 而人压根没在写后缀。
// 措辞把他支去检查一个他没输入过的东西。
//
// 只要求「退出码非 0 且提到 --help」,不规定具体措辞:这里要挡的是「被当成正常输入」,
// 不是统一文案。
func TestInstalledScripts_UnknownFlagPointsAtHelp(t *testing.T) {
	for _, tc := range installedAsCommand {
		t.Run(tc.name, func(t *testing.T) {
			src := filepath.Join("../..", tc.script)
			raw, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("读 %s: %v", tc.script, err)
			}
			bin := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(bin, raw, 0o755); err != nil {
				t.Fatal(err)
			}

			out, err := exec.Command("bash", bin, "--definitely-not-a-flag").CombinedOutput()
			body := string(out)
			if err == nil {
				t.Fatalf("`%s --definitely-not-a-flag` 居然成功了 —— 认不得的参数被当成正常输入吞了:\n%s",
					tc.name, body)
			}
			if !strings.Contains(body, "--help") {
				t.Errorf("`%s` 拒绝未知参数时没指向 --help,人只能猜自己错在哪:\n%s", tc.name, body)
			}
		})
	}
}
