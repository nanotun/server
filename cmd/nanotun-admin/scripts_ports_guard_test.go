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
}

// 形如 8443/tcp、443/udp、7443/tcp 的字面量 —— 放行清单和自检标签都长这样。
var literalPortSpec = regexp.MustCompile(`\b(8443|7443)/tcp|\b443/udp`)

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
