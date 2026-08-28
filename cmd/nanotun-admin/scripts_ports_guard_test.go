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
				m := literalPortSpec.FindString(line)
				if m == "" {
					m = literalPortArg.FindString(line)
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
