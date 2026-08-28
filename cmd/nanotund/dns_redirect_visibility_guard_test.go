package main

// dns_redirect_visibility_guard_test.go —— 出口 DNS 接管也是启动时快照,同样要说清钉的是谁。
//
// exit_dns_redirect 默认 auto:启动那一刻读一次 /etc/resolv.conf,把系统解析器钉进
// nat PREROUTING 的 DNAT 规则。这和出口 SNAT 的源地址是同一个模子,而且触发得更勤 ——
// 解析器地址比主机 IP 更容易变(DHCP 续约换了 DNS 选项、systemd-resolved 重配、
// 机器换了网络)。变过之后,客户端的查询仍被转给那个旧地址:连得上、能拿到 IP、
// 域名却全解析不了。
//
// 实测:默认安装的机器上规则是 `--to-destination 192.168.65.7:53`;把 resolv.conf 改成
// 10.0.0.53 之后,规则纹丝不动。没有日志、没有自检提过这件事,而这个症状跟 SNAT 那个
// (连得上但出不了网)第一眼分不开,两个都得靠猜。
//
// 所以两头留话,跟 SNAT 那次一个做法:启动日志说清接管到哪、这个值怎么来的、怎么修;
// 环境自检主动比对一次(见 preflight.sh)。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDNSRedirectLog_NamesPinnedResolver(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(".", "network_setup_linux.go"))
	if err != nil {
		t.Fatalf("读 network_setup_linux.go: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "egress DNS taken over →") {
		t.Fatal("装完 DNS DNAT 之后没有日志说接管到了哪个解析器 —— " +
			"查「连得上但域名解析不了」的人第一件事就是 journalctl,那时最该看见的正是这个值")
	}
	for _, c := range []struct{ needle, why string }{
		{"auto: detected by reading /etc/resolv.conf at startup", "得说清这个值是探来的而不是配的 —— 否则人不会想到它会过期"},
		{"domain names do not resolve", "得把症状写出来,查的人是带着症状来的"},
		{"restart nanotun", "得给出解法:重启会重新探测"},
		{"egress DNS not taken over", "off / 探不到解析器时也要留一行 —— 否则「没接管」和「接管了但没打日志」分不开"},
	} {
		if !strings.Contains(body, c.needle) {
			t.Errorf("DNS 接管日志里没有 %q —— %s", c.needle, c.why)
		}
	}
}

func TestPreflight_ChecksDNSRedirectIsStillCurrent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/preflight.sh"))
	if err != nil {
		t.Fatalf("读 preflight.sh: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "出口 DNS 接管指向") {
		t.Error("环境自检没有比对 DNS 接管的目标 —— 解析器漂移之后客户端能连上却解析不了域名")
	}
	// 显式配了具体 IP 的人本来就是要钉住某个解析器,跟 resolv.conf 不一致是他的意图。
	// 不分模式就比,等于对着正确配置喊,而喊多了这条就没人看了。
	if !strings.Contains(body, `[ "$dns_mode" = auto ]`) {
		t.Error("没有区分 auto 与显式配置 —— 显式配了固定解析器的机器会被误报")
	}
	// 取值口径必须跟 detectSystemDNSv4 一致:两个文件依次找、跳过环回。
	// 少了 /run/systemd/resolve/resolv.conf 这一份,systemd-resolved 的机器上会取空;
	// 不跳 127. 的话会取到 stub(127.0.0.53),而 Go 那边跳过它 —— 两边口径一错就是误报。
	if !strings.Contains(body, "/run/systemd/resolve/resolv.conf") {
		t.Error("没有读 systemd-resolved 的上游文件 —— 口径与 detectSystemDNSv4 不一致")
	}
	if !strings.Contains(body, `$2 !~ /^127\./`) {
		t.Error("没有跳过环回解析器 —— systemd-resolved 的 127.0.0.53 stub 会被当成系统解析器,导致误报")
	}
}
