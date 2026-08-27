package main

// snat_visibility_guard_test.go —— 出口用的是 SNAT,那就得说清源地址钉的是谁。
//
// 数据面出口装的是 `-j SNAT --to-source <wanIP>`,不是 MASQUERADE:源地址是**启动那一刻**
// 探到的,之后钉死在规则里。机器的 WAN 地址后来变了(DHCP 续约拿到新地址、云上重新分配、
// 双网卡切换),规则就把客户端流量改写成一个本机已经没有的地址 —— 包发不出去,而控制面
// 一切照常:客户端连得上、握手成功、就是上不了网。
//
// 实测过:把 eth0 的地址从 172.17.0.2 换成别的,规则仍然指着 172.17.0.2,而那个地址已经
// 不在本机任何网卡上。没有任何日志、没有任何自检提到这件事。
//
// 这类故障几乎没法从症状反推(「VPN 连上了但上不了网」能有二十种原因),所以两头都要留话:
// 启动日志说清当初钉的是谁(查的人第一件事就是 journalctl),环境自检主动比对一次
// (见 preflight.sh —— 那边是真去比,这里只负责让人看得见)。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSNATLog_NamesIfaceAndPinnedSource(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(".", "network_setup_linux.go"))
	if err != nil {
		t.Fatalf("读 network_setup_linux.go: %v", err)
	}
	body := string(raw)

	i := strings.Index(body, "已添加 NAT SNAT")
	if i < 0 {
		t.Fatal("找不到 SNAT 那条日志,这个测试的定位假设已经失效")
	}
	line := body[i:]
	if j := strings.Index(line, "\n\t\t}"); j > 0 {
		line = line[:j]
	}

	for _, c := range []struct{ needle, why string }{
		{"出口 %s", "得说出走的是哪张网卡 —— 多网卡机器上这是第一个要确认的事"},
		{"源地址钉为 %s", "得说出钉住的源地址,拿它跟 ip -4 addr 一比就能确认是不是这个原因"},
		{"客户端连得上但出不了网", "得把症状写出来 —— 查的人是带着这个症状来的,他要能对上号"},
		{"重启 nanotun", "得给出解法:重启会重新探测"},
	} {
		if !strings.Contains(line, c.needle) {
			t.Errorf("SNAT 日志里没有 %q —— %s\n当前那行:%s", c.needle, c.why, line)
		}
	}
}

func TestPreflight_ChecksSNATSourceIsStillLocal(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/preflight.sh"))
	if err != nil {
		t.Fatalf("读 preflight.sh: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "已经不在本机任何网卡上") {
		t.Error("环境自检没有比对 SNAT 源地址 —— " +
			"地址漂移之后客户端连得上却出不了网,而这在自检里只是一次字符串比对")
	}
	// 取的是 --to-source 后面那个值;写死字段序号会被 iptables 输出格式的变动咬到。
	if !strings.Contains(body, `$i == "--to-source"`) {
		t.Error("没有按 --to-source 定位源地址 —— 靠字段序号取值,iptables 输出一变就取错")
	}
	// 规则里可能是 a.b.c.d:1024-65535 的形态,不剥端口会永远比不上。
	if !strings.Contains(body, `snat_src="${snat_src%%:*}"`) {
		t.Error("没有剥掉 --to-source 上可能带的端口范围 —— 带着端口去比,正常机器也会被误报")
	}
}
