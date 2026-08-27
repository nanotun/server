package main

// unit_guards_test.go —— systemd 单元里不能把「有 env 对应项」的 flag 显式写上。
//
// 起因是一个不出声的坑:ExecStart 原来把 -listen / -db / -control-socket / -cert-dir 四个
// 都写死了,而它们的值和 defaultConfig() 里的默认值逐字相同 —— 写不写运行结果都一样。
// 但 main.go 定的优先级是「显式 flag > env > 默认」(那段快照/回填的逻辑是为了防止 systemd
// 里的 NANOTUN_WEB_LISTEN 把运维手敲的 -listen=127.0.0.1 压回公网),于是这四个 flag 一旦
// 出现,同一个单元里 EnvironmentFile=-/etc/nanotun/web.env 声明的那四个 NANOTUN_WEB_* 就
// 全被压死了。
//
// 压死的方式偏偏是最难查的那种:实测往 web.env 写 NANOTUN_WEB_LISTEN=0.0.0.0:9443、重启,
// 服务照常起来、日志照打 listen="0.0.0.0:7443",没有一个字提到那行被忽略。而同一个文件里的
// NANOTUN_WEB_ALLOW_SETUP 是生效的(它不是 flag),装机脚本和向导还专门往这里写它 —— 一路在
// 教人「配置写这儿」,结果一半管用一半静默无效。
//
// 端口被占时这条尤其要紧:7443 在 config.toml 里没有任何对应的键,web.env 是唯一的入口。

import (
	"os"
	"strings"
	"testing"
)

// 有 env 对应项的 flag。applyEnvOverrides 里每多认一个 NANOTUN_WEB_*,这里就要多一行 ——
// 漏了不会有任何提示,而漏掉的那个正是下一个被静默压死的。
var envBackedFlags = []struct {
	flag string // ExecStart 里的 flag 名(不含前导 -)
	env  string // 对应的环境变量,压死时受害的就是它
}{
	{"listen", "NANOTUN_WEB_LISTEN"},
	{"db", "NANOTUN_WEB_DB"},
	{"control-socket", "NANOTUN_CONTROL_SOCKET"},
	{"cert-dir", "NANOTUN_WEB_CERT_DIR"},
}

func TestUnit_ExecStartDoesNotKillEnvOverrides(t *testing.T) {
	const unit = "nanotun-web.service"
	raw, err := os.ReadFile(unit)
	if err != nil {
		t.Fatalf("读 %s: %v", unit, err)
	}
	body := string(raw)

	// 单元得确实声明了 EnvironmentFile,否则下面这条约束就失去了前提 —— 而失去前提的
	// 断言会一直绿着,直到有人删掉那行、把 web.env 变成一个谁也不读的文件。
	if !strings.Contains(body, "EnvironmentFile=-/etc/nanotun/web.env") {
		t.Fatalf("%s 里没有 EnvironmentFile=-/etc/nanotun/web.env —— 装机脚本和向导都往那个文件"+
			"写 NANOTUN_WEB_ALLOW_SETUP,不读它的话那行就成了摆设", unit)
	}

	// 只看 ExecStart 那一段(可能带续行反斜杠),别把注释里提到的 flag 名当成真的传了。
	// 这里恰恰有一大段注释在讲「不要写这四个」,按整文件搜必然自己把自己判红。
	var exec []string
	inExec := false
	for _, ln := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "ExecStart=") {
			inExec = true
		}
		if !inExec {
			continue
		}
		exec = append(exec, trimmed)
		if !strings.HasSuffix(trimmed, "\\") {
			break
		}
	}
	if len(exec) == 0 {
		t.Fatalf("%s 里找不到 ExecStart=", unit)
	}
	execLine := strings.Join(exec, " ")

	for _, f := range envBackedFlags {
		if strings.Contains(execLine, "-"+f.flag) {
			t.Errorf("ExecStart 里显式写了 -%s,这会让 %s 静默失效 —— 优先级是"+
				"「显式 flag > env > 默认」,而这个 flag 的值和内置默认值本来就一样,写它不改变"+
				"任何行为,只是把 web.env 里那一项压死,且不打任何日志。\nExecStart: %s",
				f.flag, f.env, execLine)
		}
	}
}
