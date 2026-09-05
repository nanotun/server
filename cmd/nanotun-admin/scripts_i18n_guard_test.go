package main

// scripts_i18n_guard_test.go —— 安装链上那几个脚本必须是双语的,而且默认英文。
//
// 起因:Go 这侧早就双语了(catalog_en.go / catalog_zh.go,418 个 key,默认英文,认
// --lang 与 NANOTUN_LANG),而 shell 那层一直只有中文。更糟的是它**主动把语言按回中文**:
// setup.sh 和 install-self-hosted.sh 里各有一句 `export NANOTUN_LANG="${NANOTUN_LANG:-zh}"`,
// 注释写着「nanotun-admin 默认输出英文,而这个向导从头到尾是中文」—— 为了不让英文夹在
// 中文里,把 admin 也拽成了中文。于是一个英文用户从第一屏到最后一屏全是看不懂的字,
// 而这恰恰是他对这个项目的全部第一印象。
//
// 现在反过来:脚本自己双语,默认英文,语言由 install.sh 问一次(只在有终端时)、经
// NANOTUN_LANG 一路传下去、并落盘到 /etc/nanotun/lang 供事后单独跑的 nanotun-* 命令沿用。
//
// 这个测试盯的是这套约定里**会静默失效**的那几处:
//
//   ① 新加一个脚本(或改一个)时忘了双语 —— 症状是英文用户在某一屏突然掉进中文,
//      而跑的人如果自己看得懂中文,压根不会注意到。
//   ② 有人又把 `${NANOTUN_LANG:-zh}` 加回来。这一句看着无害(「保持中文体验一致」),
//      实际是把整条链的默认语言从英文改回中文,而且是在**一个跟语言无关的改动里**顺手
//      加的那种。它出现过一次,所以钉住它。
//   ③ --lang 没真的进参数解析。这几个脚本对未知参数一律顶回(exit 2,有别的守卫盯着),
//      所以 --lang 少加一个地方,一键安装把它传下去时就会被自己的下游拒掉 —— 而报错
//      长得像「用户参数写错了」。
//   ④ 英文那份漏译。判据是「英文 --help 里不该出现任何中日韩字符」:漏译一句就会露馅,
//      而这条比逐句核对可靠得多(它不需要有人去维护一份 key 清单)。
//
// 为什么不像 Go 那侧一样做成 key → 文案的目录、再断言两份 key 对齐:shell 这层几乎每句
// 提示都在插值(${TMPDIR:-/tmp}、$DL $CURL_RC、$(df -h …)),搬进目录要把每处插值改写成
// %s 参数按序传回,那是这类改动里最容易出错的一环,错了还不会有任何东西红(文案照样
// 打得出来,只是数字串了位)。所以文案是两种语言并排写在调用处的,而这个测试从**行为**
// 上验双语,不去数 key。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// 安装链上所有会打字给用户看的脚本。新增一个就往这里加一行 —— 漏了不会有任何提示,
// 而漏掉的那个正是下一个掉回单语的。
var bilingualScripts = []string{
	"scripts/install.sh",
	"scripts/preflight.sh",
	"scripts/install-self-hosted.sh",
	"scripts/setup.sh",
	"scripts/uninstall.sh",
	"scripts/set-magic-suffix.sh",
}

func hasCJK(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// 只取非注释行:维护者注释一直是中文,而且应该一直是中文 —— 它们不是 UI。
func codeLines(body string) string {
	var b strings.Builder
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return b.String()
}

func TestScripts_HaveLanguageMechanism(t *testing.T) {
	for _, script := range bilingualScripts {
		t.Run(filepath.Base(script), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("../..", script))
			if err != nil {
				t.Fatalf("读 %s: %v", script, err)
			}
			body := string(raw)

			for _, c := range []struct{ needle, why string }{
				{"NT_LANG=en", "默认语言必须是英文,而且要写成一眼看得见的那种(NT_LANG=en)"},
				{"nt_lang_normalize", "得能把 zh_CN.UTF-8 这类完整 locale 名归一到 en/zh"},
				{"tsel()", "双语选择器缺了,说明这个脚本的文案没有并排两份"},
				{"/etc/nanotun/lang", "得读落盘的那份,否则事后单独跑时语言跟装机时选的不一致"},
				{"--lang", "--lang 没进这个脚本,一键安装把它传下来会被自己的下游拒掉"},
			} {
				if !strings.Contains(body, c.needle) {
					t.Errorf("%s 里找不到 %q —— %s", script, c.needle, c.why)
				}
			}

			// ② 那一条:别再把默认按回中文。
			for _, bad := range []string{
				`NANOTUN_LANG:-zh`,
				`NANOTUN_LANG="zh"`,
				`NANOTUN_LANG=zh`,
			} {
				if strings.Contains(codeLines(body), bad) {
					t.Errorf("%s 里又出现了 %q —— 这一句会把整条链的默认语言从英文改回中文。\n"+
						"  语言只该由 --lang / NANOTUN_LANG / /etc/nanotun/lang 决定,脚本自己不要钉死一种。",
						script, bad)
				}
			}
		})
	}
}

// helpCmd 跑「不带 --lang 的 --help」,也就是英文那一屏。
//
// 语言优先级是 --lang > NANOTUN_LANG > /etc/nanotun/lang > en(见各脚本开头),
// 所以「默认就是英文」这个前提只在前两级都不存在时成立。而 exec.Command 默认继承
// 父进程环境:开发机上只要 NANOTUN_LANG=zh(装机向导本来就会把它写进
// /etc/nanotun/web.env,维护者的 shell 里也常有),脚本会**正确地**打出中文,
// 这条断言随之报「有文案漏译了」—— 一个假警报,而且它指向的方向完全是错的。
// 所以这里把那个变量摘掉,让子进程真的走到缺省分支。
//
// 落盘的 /etc/nanotun/lang 是绝对路径,测试没法隔离;它存在且写着中文时直接跳过并
// 说明原因,不装作通过。
func helpCmd(t *testing.T, bin string) *exec.Cmd {
	t.Helper()
	if b, err := os.ReadFile("/etc/nanotun/lang"); err == nil &&
		strings.HasPrefix(strings.TrimSpace(string(b)), "zh") {
		t.Skip("本机 /etc/nanotun/lang 写着 zh,脚本的缺省语言就是中文,这条断言在此机器上无从判断")
	}
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "NANOTUN_LANG=") {
			env = append(env, kv)
		}
	}
	cmd := exec.Command("bash", bin, "--help")
	cmd.Env = env
	return cmd
}

// --help 得真的分语言。这条是「漏译」唯一一条不需要人去核对清单的判据。
func TestScripts_HelpIsBilingual(t *testing.T) {
	for _, script := range bilingualScripts {
		t.Run(filepath.Base(script), func(t *testing.T) {
			src := filepath.Join("../..", script)
			raw, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("读 %s: %v", script, err)
			}
			// 按装好之后的名字跑:这几个脚本的帮助都按 $0 分岔(见 scripts_help_guard_test.go),
			// 用原文件名跑会走另一条分支。这里只关心语言,但没理由绕开真实那条路。
			name := "nanotun-" + strings.TrimSuffix(filepath.Base(script), ".sh")
			if script == "scripts/install.sh" {
				name = "install.sh" // 它不装成命令,是网络入口
			}
			bin := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(bin, raw, 0o755); err != nil {
				t.Fatal(err)
			}

			en, err := helpCmd(t, bin).CombinedOutput()
			if err != nil {
				t.Fatalf("`%s --help` 退出码非 0(%v):\n%s", name, err, en)
			}
			if hasCJK(string(en)) {
				t.Errorf("`%s --help` 默认(英文)输出里有中文 —— 有文案漏译了。\n"+
					"  英文是默认语言,这一屏是英文用户看到的第一样东西:\n%s", name, en)
			}

			zh, err := exec.Command("bash", bin, "--lang", "zh", "--help").CombinedOutput()
			if err != nil {
				t.Fatalf("`%s --lang zh --help` 退出码非 0(%v):\n%s", name, err, zh)
			}
			if !hasCJK(string(zh)) {
				t.Errorf("`%s --lang zh --help` 打出来没有一个中文字 —— --lang zh 没生效,\n"+
					"  或者中文那份被英文覆盖掉了:\n%s", name, zh)
			}
		})
	}
}

// 认不得的语言要当场说,不能默默回落到英文 —— 那样 `--lang fr` 看着像生效了。
func TestScripts_RejectUnknownLang(t *testing.T) {
	for _, script := range bilingualScripts {
		t.Run(filepath.Base(script), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("../..", script))
			if err != nil {
				t.Fatalf("读 %s: %v", script, err)
			}
			bin := filepath.Join(t.TempDir(), filepath.Base(script))
			if err := os.WriteFile(bin, raw, 0o755); err != nil {
				t.Fatal(err)
			}

			out, err := exec.Command("bash", bin, "--lang", "fr").CombinedOutput()
			if err == nil {
				t.Errorf("`%s --lang fr` 居然成功了 —— 认不得的语言被默默当成英文,\n"+
					"  而敲的人会以为自己拿到了法语:\n%s", filepath.Base(script), out)
			}
			if !strings.Contains(string(out), "en") || !strings.Contains(string(out), "zh") {
				t.Errorf("`%s --lang fr` 的报错里没说清认哪几种(en / zh):\n%s",
					filepath.Base(script), out)
			}
		})
	}
}

// 没有终端时不许问语言。
//
// 问话这件事只有 install.sh 做,而它必须只在 stdin 真是终端时做:CI / cloud-init /
// `curl … | bash` 那些形态下问一句就是无限期挂住,而屏幕上只有一个等输入的冒号 ——
// 装机脚本卡在第一句话,人连「装到哪一步」都无从判断。
//
// 这条不是假想:本仓库为「向导在没有终端时问话」的同一类问题栽过两次(见 install.sh 里
// under_sudo_pty 那一大段)。所以宁可默认英文,也不能赌那个终端存在。
func TestInstall_DoesNotAskLanguageWithoutTTY(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/install.sh"))
	if err != nil {
		t.Fatalf("读 install.sh: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(bin, raw, 0o755); err != nil {
		t.Fatal(err)
	}

	// --check-only 走完环境自检就退,不动系统;stdin 给一个已经读到底的管道,
	// 正是 `curl … | bash` 那种形态。
	cmd := exec.Command("bash", bin, "--check-only")
	cmd.Stdin = strings.NewReader("")
	out, _ := cmd.CombinedOutput() // 自检在开发机上必然不过,退出码不看

	if strings.Contains(string(out), "Language / 语言") {
		t.Errorf("没有终端时 install.sh 还是问了语言 —— 这一问在 CI / cloud-init 里会挂住:\n%s", out)
	}
}
