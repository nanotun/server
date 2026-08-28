package main

// scripts_ports_guard_test.go —— 对外端口只能从配置里读,不许写死。
//
// 起因是一次实测:把 [reality] 的 listen_addr 改到 9443(而这正是环境自检遇到端口冲突时
// 给出的建议)之后重跑安装,机器变成了客户端连不上的状态 ——
//
//   · ufw 放行的是 8443,那儿没有任何东西在听;真正要连的 9443 关着。
//   · 屏幕上打的却是「✓ ufw 放行：8443/tcp 443/udp 7443/tcp(web)」,一切看着都对。
//   · 状态自检去看 8443,报「! 没听上:8443/tcp(REALITY)」并跟一大段诊断,把人指向
//     「服务没起来」—— 而服务好好地在 9443 上跑着。
//   · 卸载收回的还是那三条写死的规则,自定义端口被永久留在防火墙里。
//
// 四个症状一个根:装机、自检、卸载三个脚本各自把 8443/443/7443 抄了一遍。修法是统一从
// scripts/nanotun-ports.sh 里读实际值。这个测试盯的是别再抄回去 —— 抄回去不会有任何报错,
// 只会让改过端口的人再次踩进同一个坑,而现场证据全指向错误的方向。
//
// 允许出现字面量的地方只有两处:nanotun-ports.sh 里的默认值定义,以及各脚本里
// `${NT_PORT_xxx:-8443}` 这种带回落的引用(读不到解析器时默认值本来就是对的)。

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 会因为写死端口而出错的脚本。新增脚本要碰这三个端口的话,也该走 nanotun-ports.sh。
var portSensitiveScripts = []string{
	"scripts/install-self-hosted.sh",
	"scripts/uninstall.sh",
	"scripts/preflight.sh",
	// 2026-08-28 补:开服向导也在说端口 —— 登录地址、以及「客户端连不上时先查防火墙:
	// REALITY x/tcp、hysteria2 y/udp」。它此前用的是写死的 7443 / 8443,于是改过端口的
	// 机器上向导打出的登录地址指向一个没人听的端口,而那句防火墙建议让人去查三条与自己
	// 无关的规则。它是这份清单最初漏掉的那一个,而漏掉的那个正是下一个长歪的。
	"scripts/setup.sh",
}

// 形如 8443/tcp、443/udp、7443/tcp 的字面量 —— 放行清单和自检标签都长这样。
// 443/tcp 也算:REALITY 的默认端口 2026-08-28 从 8443 改成 443,于是「写死 443/tcp」
// 成了同一个 bug 的新形态 —— 只盯 8443 的话,下一次退化会静静地通过。
var literalPortSpec = regexp.MustCompile(`\b(8443|7443|443)/tcp|\b443/udp`)

// 端口检查函数的裸参数:`chk_port tcp 8443` / `check_port udp 443`。
// 这一条是补上来的:最初只盯带 /tcp 后缀的写法,而把 chk_port 的端口改回字面量时守卫
// 一声不吭 —— 恰恰是本次 bug 里「状态自检看错端口」那一半,最该被拦住的就是它。
var literalPortArg = regexp.MustCompile(`\b(chk_port|check_port)\s+(tcp|udp)\s+\d+`)

// URL 形态的字面量:`https://<server>:7443/`。
//
// 这是本守卫最初的盲区,2026-08-28 扫出来的:上面那条只认「端口/协议」(防火墙清单和
// 自检标签的样子),而登录地址长的是 `:7443/` —— 于是 install-self-hosted.sh 在装机结尾
// 打给用户的登录地址写死了 7443,一路通过了守卫、CI 和三机门禁。而那句话恰恰是用户装完
// 看到的最后一行,Web 端口改成随机默认之后它给的是一个没人听的端口:照着点进去连不上,
// 而现场看起来像「后台没装起来」。
//
// 一条漏掉真问题的守卫比没有守卫更糟 —— 它给的是虚假的安心,所以这里把形态补齐。
var literalPortInURL = regexp.MustCompile(`:(8443|7443|443)(/|"|'|\s|$)`)

// 带回落的引用:${NT_PORT_REALITY:-8443}/tcp。这种是合法的,不该算进去。
var fallbackRef = regexp.MustCompile(`\$\{NT_PORT_[A-Z0-9_]+:-\d+\}`)

func TestScripts_PortsComeFromConfigNotLiterals(t *testing.T) {
	for _, rel := range portSensitiveScripts {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("../..", rel))
			if err != nil {
				t.Fatalf("读 %s: %v", rel, err)
			}
			for i, line := range strings.Split(string(raw), "\n") {
				trimmed := strings.TrimSpace(line)
				// 注释里可以随便举例 —— 上面那段病史就得把 8443 写出来才说得清。
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				// 历史规则的回收(8444/tcp、8080/tcp)和默认值的回收本来就该按字面量写,
				// 它们不是「这台机器听哪个端口」,而是「以前放行过什么,现在收掉」。
				if strings.Contains(line, "NT_DEFAULT_") || strings.Contains(line, "delete allow") ||
					strings.Contains(line, "remove-port") {
					continue
				}
				if fallbackRef.MatchString(line) {
					continue
				}
				// 出站目标不算。REALITY 的 dest(www.microsoft.com:443)是**要去连的别人家**
				// 的端口,它就该是 443 —— 那是 HTTPS,换一个反而不像正常流量了。本守卫管的是
				// 「这台机器听什么 / 放行什么 / 让用户连什么」,跟出站目标是两件事。
				if strings.Contains(line, "dest_check") {
					continue
				}
				m := literalPortSpec.FindString(line)
				if m == "" {
					m = literalPortArg.FindString(line)
				}
				if m == "" {
					m = literalPortInURL.FindString(line)
				}
				if m != "" {
					t.Errorf("%s:%d 把端口写死成 %s:\n    %s\n"+
						"  这三个端口要从 nanotun-ports.sh 读(nanotun_load_ports 之后用 $NT_PORT_*)——\n"+
						"  写死的话,改过端口的机器上防火墙会放行一个没人听的端口,而客户端要连的那个是关着的。",
						rel, i+1, m, trimmed)
				}
			}
		})
	}
}

// 解析器本身得被打进发布包并装成命令旁边的文件,否则卸载和自检 source 不到它,
// 又会静静地退回默认值 —— 那是这次要修的 bug 的另一种形态。
func TestPortsHelper_IsPackagedAndInstalled(t *testing.T) {
	for _, c := range []struct{ file, needle, why string }{
		{"scripts/build-release.sh", "scripts/nanotun-ports.sh", "没打进发布包,装机时的必需文件检查会直接 die"},
		{"scripts/install-self-hosted.sh", "/usr/local/bin/nanotun-ports.sh", "没装到 /usr/local/bin,卸载和自检 source 不到"},
		{"scripts/uninstall.sh", "/usr/local/bin/nanotun-ports.sh", "卸载没读实际端口,自定义端口会留在防火墙里"},
		{"scripts/preflight.sh", "/usr/local/bin/nanotun-ports.sh", "自检会去看默认端口,漏检真正在用的那个"},
		{"scripts/setup.sh", "/usr/local/bin/nanotun-ports.sh", "向导会打出登录地址和防火墙建议,读不到实际端口就会说错"},
	} {
		raw, err := os.ReadFile(filepath.Join("../..", c.file))
		if err != nil {
			t.Fatalf("读 %s: %v", c.file, err)
		}
		if !strings.Contains(string(raw), c.needle) {
			t.Errorf("%s 里找不到 %q —— %s", c.file, c.needle, c.why)
		}
	}
}

// 测试台容器内的 Web 端口必须和它的 -p 映射对得上。
//
// lab.sh 的模型是「宿主某端口 → 容器某固定端口」,而那条 -p 在 docker run 那一刻就定死
// 了 —— 那时候装机还没发生。装机默认会随机挑 Web 端口(见 install-self-hosted.sh),所以
// lab.sh 必须显式钉住容器内的值,否则映射指向空处。
//
// 之所以值得一条守卫:它坏掉的样子会撒谎。lab.sh status 会打「宿主连不上 —— Docker
// Desktop 端口转发的毛病,不是服务端」,于是人去查一个 Docker 的 bug,而真因是 Web 听在
// 某个随机端口(2026-08-28 实测:容器内 10678、映射 7443,browse / browse-2fa / drill
// 三条全断)。谁把那个钉子拔了,先在这儿红。
func TestLabPinsContainerWebPortToItsPortMapping(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "testlab", "lab.sh"))
	if err != nil {
		t.Fatalf("读不到 lab.sh:%v", err)
	}
	src := string(b)

	pin := regexp.MustCompile(`:\s*"\$\{NANOTUN_WEB_PORT:=(\d+)\}"`).FindStringSubmatch(src)
	if pin == nil {
		t.Fatal("lab.sh 没有钉住容器内的 Web 端口(找不到 : \"${NANOTUN_WEB_PORT:=<口>}\")。\n" +
			"不钉住的话装机会随机挑一个,而 -p 映射打向一个固定端口 —— 宿主就连不上了,\n" +
			"且报错会把人指向 Docker Desktop。")
	}
	mapping := regexp.MustCompile(`-p\s+"?127\.0\.0\.1:\$\{?WEB_PORT\}?:(\d+)`).FindStringSubmatch(src)
	if mapping == nil {
		t.Fatal("lab.sh 里找不到 -p 127.0.0.1:${WEB_PORT}:<容器端口> 这条映射;" +
			"若映射写法改了,请同步更新本守卫。")
	}
	if pin[1] != mapping[1] {
		t.Fatalf("lab.sh 自相矛盾:容器内 Web 端口钉在 %s,而 -p 映射打向容器 %s。\n"+
			"两者必须一致,否则宿主上的 https://127.0.0.1:<宿主口>/ 连不上,"+
			"而 browse / browse-2fa / drill 都走那个地址。", pin[1], mapping[1])
	}
}

// Web 端口挪走时,两个防火墙分支都必须收回**旧那个**端口的规则。
//
// 只收静态默认值(7443)是不够的:Web 端口改成随机默认之后,每台机器的旧值都是随机数,
// 于是「等于默认值」这个条件覆盖的恰好是一个不再发生的情况。漏掉的后果是每换一次端口
// 就在机器上留下一条对公网敞着、却没有任何东西在听的放行规则。
//
// 它不是「有洞」(没人听就进不去),而是让 ufw status / firewall-cmd --list-ports 高估
// 这台机器的暴露面 —— 对一个隐私工具来说,审计时看到的必须是真的。而且它无声:陈旧规则
// 不会让任何东西看起来坏掉,所以只能靠守卫盯着。
//
// 2026-08-28 实测过两边的差别:旧逻辑把 9000 挪到 8000 只发 `delete allow 7443/tcp`,
// 9000 就永久留着了;修好后同一步会同时发 `delete allow 8000/tcp`。
func TestInstallerReclaimsPreviousWebPortFirewallRule(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install-self-hosted.sh"))
	if err != nil {
		t.Fatalf("读不到 install-self-hosted.sh:%v", err)
	}
	src := string(b)

	// 旧值只能从写 web.env 之前读到的那个来 —— 这个变量必须还在,否则无从知道要收哪条。
	if !strings.Contains(src, "NT_WEB_PORT_PINNED=") {
		t.Fatal("找不到 NT_WEB_PORT_PINNED(写 web.env 前读到的旧 Web 端口)。" +
			"没有它就无法知道端口挪走后该收回哪条防火墙规则。")
	}

	for _, c := range []struct{ name, want string }{
		{"ufw", `ufw delete allow "${NT_WEB_PORT_PINNED}/tcp"`},
		{"firewalld", `firewall-cmd --permanent --remove-port="${NT_WEB_PORT_PINNED}/tcp"`},
	} {
		if !strings.Contains(src, c.want) {
			t.Errorf("%s 分支没有收回旧的 Web 端口规则,缺:%s\n"+
				"只收 $NT_DEFAULT_WEB 是不够的 —— 随机默认之后旧值几乎总是随机数,"+
				"漏掉就会每改一次端口留下一条敞着却没人听的规则。", c.name, c.want)
		}
	}
}

// tomlSectionPort 从 config.toml 的某个 section 里取 listen_addr 的端口。
// 端口并集(":443,5000-5100")取第一个 —— 那是实际绑定的主端口。
func tomlSectionPort(t *testing.T, src, section string) string {
	t.Helper()
	i := strings.Index(src, "\n["+section+"]")
	if i < 0 {
		t.Fatalf("config.toml 里找不到 [%s]", section)
	}
	rest := src[i+1:]
	// 到下一个 section 为止,别把别人的 listen_addr 读进来
	if j := regexp.MustCompile(`\n\[[a-z0-9_.]+\]`).FindStringIndex(rest); j != nil {
		rest = rest[:j[0]]
	}
	m := regexp.MustCompile(`(?m)^\s*listen_addr\s*=\s*"([^"]*)"`).FindStringSubmatch(rest)
	if m == nil {
		t.Fatalf("[%s] 里找不到 listen_addr", section)
	}
	p := m[1][strings.LastIndex(m[1], ":")+1:]
	if k := strings.IndexAny(p, ",-"); k >= 0 {
		p = p[:k]
	}
	return p
}

// 镜像的 EXPOSE 必须和 config.toml 模板里数据面实际听的端口一致。
//
// EXPOSE 不影响 network_mode: host(官方 compose 走的就是它),所以它漂了完全无声 ——
// 没有任何测试、日志或健康检查会提一句。但它是镜像元数据:docker inspect、registry 页面、
// 以及 docker run -P 都读它。漂了的后果是 -P 把一个没人听的端口发布出去,而客户端真正要
// 连的那个反倒没发布,偏偏 docker port 的输出看上去一切正常。
//
// 2026-08-28 实测到的就是这个:REALITY 从 8443 挪到 443,模板改了、entrypoint 改了、
// 文档改了,唯独 Dockerfile 的 EXPOSE 还写着 8443/tcp,而且它上面的注释还在说
// 「8443/tcp REALITY」—— 一条会被人当依据去开防火墙的错误说明。
func TestDockerfileExposeMatchesDataPlanePorts(t *testing.T) {
	cfgRaw, err := os.ReadFile(filepath.Join("..", "..", "cmd", "nanotund", "config.toml"))
	if err != nil {
		t.Fatalf("读 config.toml:%v", err)
	}
	dfRaw, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatalf("读 Dockerfile:%v", err)
	}
	cfg, df := string(cfgRaw), string(dfRaw)

	expose := regexp.MustCompile(`(?m)^EXPOSE\s+(.*)$`).FindStringSubmatch(df)
	if expose == nil {
		t.Fatal("Dockerfile 里找不到 EXPOSE 行")
	}
	line := expose[1]

	for _, c := range []struct{ section, proto string }{
		{"reality", "tcp"},
		{"hysteria", "udp"},
	} {
		want := tomlSectionPort(t, cfg, c.section) + "/" + c.proto
		if !strings.Contains(line, want) {
			t.Errorf("EXPOSE 少了 %s([%s] 在 config.toml 模板里听的就是它):\n  EXPOSE %s\n"+
				"  桥接模式下 docker run -P 会漏发布这个端口,而客户端要连的正是它。",
				want, c.section, line)
		}
	}
	// 挪走之后旧端口不能还留在 EXPOSE 里:-P 会把它发布出去,而那儿没有任何东西在听。
	if realityPort := tomlSectionPort(t, cfg, "reality"); realityPort != "8443" &&
		strings.Contains(line, "8443/tcp") {
		t.Errorf("EXPOSE 里还留着 8443/tcp,但 [reality] 现在听的是 %s:\n  EXPOSE %s\n"+
			"  -P 会发布一个没人听的端口,而 docker port 的输出看上去毫无异常。",
			realityPort, line)
	}
}

// 端口冲突的「改端口」建议:硬失败和软提醒两条分支都必须看配置文件在不在。
//
// 全新机器上 /etc/nanotun/config.toml 要装完才有,所以「去改它的 listen_addr」在装机前
// 是一条把人支到空地方的建议。preflight 里这句话写了两遍:FOR_INSTALL 那支(真装机,判死)
// 和 soft 那支(只体检,不拦)。
//
// 2026-08-28 实测:硬失败那支做了判断,软提醒那支没有 —— 而 install.sh --check-only
// (装机前最常走的那条路)恰恰走软提醒。同一个坑、同一个脚本、两条分支各写一遍,修了一条
// 另一条留着。REALITY 从 8443 挪到 443 之后这条更常被踩:8443 几乎没人占,443 上到处是
// nginx。这条守卫盯的就是它们别再分家。
func TestPreflightPortAdviceChecksConfigExistsInBothBranches(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "preflight.sh"))
	if err != nil {
		t.Fatalf("读不到 preflight.sh:%v", err)
	}
	src := string(b)

	// 只看 chk_port 这个函数体 —— 别的地方提到 config.toml 不算数。
	start := strings.Index(src, "chk_port() {")
	if start < 0 {
		t.Fatal("preflight.sh 里找不到 chk_port(),若改名请同步本守卫")
	}
	body := src[start:]
	if end := strings.Index(body, "\n  }\n"); end > 0 {
		body = body[:end]
	}

	if !strings.Contains(body, `[ "$FOR_INSTALL" = 1 ]`) {
		t.Fatal("chk_port() 里找不到 FOR_INSTALL 分支")
	}
	if !strings.Contains(body, "soft_t") {
		t.Fatal("chk_port() 里找不到 soft_t(只体检、不拦人的那支)")
	}

	// 两条分支各要判一次。数个数而不是切片定位:切片端点全是魔数,改动措辞就会
	// 悄悄失准 —— 一条盯着别人别写错的守卫,自己不能是这种写法。
	const exists = `[ -f /etc/nanotun/config.toml ]`
	if n := strings.Count(body, exists); n < 2 {
		t.Errorf("chk_port() 里只有 %d 处判断配置文件在不在,应当是 2 处(硬失败一处、软提醒一处):\n"+
			"  缺的那处会让人去改一个还不存在的文件 —— 全新机器上 config.toml 要装完才有,\n"+
			"  而 install.sh --check-only(装机前最常走的那条路)走的正是软提醒那支。", n)
	}
}

// install.sh 解析器认的每个 --*-port,两份 --help 里都得查得到。
//
// 起因是 --web-port:它的能力早就有了(环境变量 NANOTUN_WEB_PORT),后来补了同名参数,而
// --help 里一个字都没提 —— 于是「怎么固定 Web 端口」这件事只有读过源码的人知道。
// 一个查不到的参数等于不存在,而它偏偏又是端口撞了之后唯一的出路。
//
// 判据取自解析器本身而不是一张手写清单:新加一个 --xxx-port 忘了写文档,这里就会红。
func TestInstallHelpDocumentsEveryPortFlag(t *testing.T) {
	path := filepath.Join("..", "..", "scripts", "install.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到 install.sh:%v", err)
	}

	// 解析器里的分支长这样:    --web-port)  /  --reality-port=*)
	found := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+--([a-z0-9-]+-port)\)`).FindAllStringSubmatch(string(raw), -1) {
		found["--"+m[1]] = true
	}
	if len(found) == 0 {
		t.Fatal("install.sh 的参数解析里一个 --*-port 都没找到;若分支写法改了,请同步本守卫")
	}

	for _, c := range []struct {
		name string
		args []string
	}{
		{"英文", []string{path, "--help"}},
		{"中文", []string{path, "--lang", "zh", "--help"}},
	} {
		out, err := exec.Command("bash", c.args...).CombinedOutput()
		if err != nil {
			t.Fatalf("`install.sh %v` 退出码非 0(%v):\n%s", c.args[1:], err, out)
		}
		for flag := range found {
			if !strings.Contains(string(out), flag) {
				t.Errorf("%s --help 里查不到 %s,但解析器认它。\n"+
					"  查不到的参数等于不存在 —— 而端口类参数恰恰是端口撞了之后唯一的出路。",
					c.name, flag)
			}
		}
	}
}

// preflight 必须认装机进行中的端口覆盖 —— Web 和 REALITY 两个都要。
//
// 全新机器上 /usr/local/bin/nanotun-ports.sh 还不存在(装完才有),所以 nanotun_load_ports
// 整块被跳过,里面对环境变量的处理压根不会跑。漏一个的后果是检查去查**默认**端口:
// 显式指定的那个被占着也一路放行(装完 crash-loop),或者反过来,默认端口被别人占着却把
// 一次本该成功的安装挡下 —— 而报的那个端口正是用户已经绕开的那个。
func TestPreflightHonorsInstallTimePortOverrides(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "preflight.sh"))
	if err != nil {
		t.Fatalf("读不到 preflight.sh:%v", err)
	}
	src := string(b)
	for _, c := range []struct{ env, target string }{
		{"NANOTUN_WEB_PORT", "NT_PORT_WEB"},
		{"NANOTUN_REALITY_PORT", "NT_PORT_REALITY"},
	} {
		want := c.target + `="$` + c.env + `"`
		if !strings.Contains(src, want) {
			t.Errorf("preflight 没把 %s 应用到 %s(缺 %s):\n"+
				"  全新机器上 nanotun-ports.sh 还不存在,不在这儿认一遍就只能查到默认端口。",
				c.env, c.target, want)
		}
	}
}
