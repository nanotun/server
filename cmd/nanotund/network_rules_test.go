package main

import (
	"strings"
	"testing"

	"github.com/nanotun/server/config"
)

// TestExitModePolicy_MatchesConfigContract 用 config 里的常量而非字面量做断言:
// exitModePolicy 内部是拿字符串硬比的,一旦 config 那边改了取值(或加了第四档),
// 这里立刻红,而不是让 iptables 悄悄按 mesh 装规则 —— 那是 fail-open。
func TestExitModePolicy_MatchesConfigContract(t *testing.T) {
	cases := []struct {
		mode         string
		wantIsolate  bool
		wantAllowWAN bool
		what         string
	}{
		{config.TUNExitModeMesh, false, true, "mesh:互通且有出口"},
		{config.TUNExitModeIsolate, true, true, "isolate:禁止横向,但仍有出口"},
		{config.TUNExitModeOff, false, false, "off:纯组网,无出口"},
	}
	for _, c := range cases {
		gotIsolate, gotAllowWAN := exitModePolicy(c.mode)
		if gotIsolate != c.wantIsolate || gotAllowWAN != c.wantAllowWAN {
			t.Errorf("%s (exit_mode=%q): isolate=%v allowWAN=%v, 期望 isolate=%v allowWAN=%v",
				c.what, c.mode, gotIsolate, gotAllowWAN, c.wantIsolate, c.wantAllowWAN)
		}
	}
}

// TestExitModePolicy_UnknownFallsBackToMesh 未知取值的兜底方向必须是 mesh。
//
// 正常路径上 ValidateExitMode 会在启动期把 typo 拦掉,这里守的是「万一漏到这一层」:
// 兜底成 mesh(保持连通)是有意选择,兜底成 off 会让一个 typo 直接断掉整个出口。
func TestExitModePolicy_UnknownFallsBackToMesh(t *testing.T) {
	for _, mode := range []string{"", "lockdow", "OFF", "Isolate", "  off  "} {
		isolate, allowWAN := exitModePolicy(mode)
		if isolate || !allowWAN {
			t.Errorf("exit_mode=%q 应兜底成 mesh, 实际 isolate=%v allowWAN=%v", mode, isolate, allowWAN)
		}
	}
}

// ruleString 把规则参数拼成一行,便于断言与报错阅读。
func ruleString(rule []string) string { return strings.Join(rule, " ") }

func ruleSet(rules [][]string) map[string]bool {
	out := make(map[string]bool, len(rules))
	for _, r := range rules {
		out[ruleString(r)] = true
	}
	return out
}

// TestTunForwardPortDropRules 表驱动 forward_block_* 三个开关。
//
// 这三个开关此前完全没有测试:开关写了但规则没装、或者装错端口/错协议,
// 都只会表现为「配置看起来开了,滥用照旧」,运维无从察觉。
func TestTunForwardPortDropRules(t *testing.T) {
	const (
		btTCP   = "-p tcp --dport 6881:6889 -j DROP"
		btUDP   = "-p udp --dport 6881:6889 -j DROP"
		tracker = "-p tcp --dport 6969 -j DROP"
		smtp    = "-p tcp --dport 25 -j DROP"
	)
	cases := []struct {
		name                    string
		bt, tracker6969, smtp25 bool
		want                    []string
	}{
		{"全关不装任何规则", false, false, false, nil},
		{"仅 BT", true, false, false, []string{btTCP, btUDP}},
		{"仅 tracker", false, true, false, []string{tracker}},
		{"仅 SMTP", false, false, true, []string{smtp}},
		{"全开", true, true, true, []string{btTCP, btUDP, tracker, smtp}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := tunForwardPortDropRules(c.bt, c.tracker6969, c.smtp25)
			if len(got) != len(c.want) {
				t.Fatalf("规则条数 %d, 期望 %d\n实际: %v", len(got), len(c.want), got)
			}
			for i, want := range c.want {
				if g := ruleString(got[i]); g != want {
					t.Errorf("第 %d 条: %q, 期望 %q", i, g, want)
				}
			}
		})
	}
}

// TestTunForwardPortDropRules_BTCoversUDP 单拎出来:BT 只挡 tcp 是个典型的半拉子实现,
// uTP / DHT 走 udp 照样能把出口跑满,而规则列表看上去「已经挡了 BT」。
func TestTunForwardPortDropRules_BTCoversUDP(t *testing.T) {
	set := ruleSet(tunForwardPortDropRules(true, false, false))
	for _, proto := range []string{"tcp", "udp"} {
		want := "-p " + proto + " --dport 6881:6889 -j DROP"
		if !set[want] {
			t.Errorf("开启 forward_block_bt 后缺少 %q —— %s 方向没挡住", want, proto)
		}
	}
}

// TestTunForwardPortDropRules_AllRulesAreDrops 兜底:这批规则的动作只能是 DROP。
// 误写成 ACCEPT 会把「封禁」变成「显式放行」,比不装规则更糟。
func TestTunForwardPortDropRules_AllRulesAreDrops(t *testing.T) {
	rules := tunForwardPortDropRules(true, true, true)
	if len(rules) == 0 {
		t.Fatal("全开时不应为空")
	}
	for _, r := range rules {
		if len(r) < 2 || r[len(r)-2] != "-j" || r[len(r)-1] != "DROP" {
			t.Errorf("规则未以 -j DROP 结尾: %q", ruleString(r))
		}
	}
}
