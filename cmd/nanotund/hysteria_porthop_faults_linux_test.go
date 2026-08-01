package main

import (
	"strings"
	"testing"
)

// Hy2 端口跳跃的 iptables 安装/回滚/清理路径,此前故障分支一条没跑过。
// 复用 network_setup_faults_linux_test.go 里的假工具(同包)。
//
// 这里最要紧的是**装到一半失败要回滚**。端口并集常有十几个口,装到第三个失败却把前两个
// 留在链上,结果是「一部分端口能跳、一部分不能」—— 客户端换端口时随机连不上,而
// `iptables -S` 里规则确实存在,看着一切正常。这种半残状态比整个功能不可用难查得多。

// TestSetupHy2PortHop_RollsBackOnPartialFailure 中途失败必须把已装的全撤掉。
func TestSetupHy2PortHop_RollsBackOnPartialFailure(t *testing.T) {
	f := newFakeNetTools(t)
	// 主端口 443,并集里另有 8443 与 9000-9100。让第二条(9000:9100)安装失败。
	f.failOn(t, "-A PREROUTING .*--dport 9000:9100")

	cleanup, err := setupHy2UDPPortHopRedirect(443, "443,8443,9000-9100", "")
	if err == nil {
		t.Fatal("安装失败却返回 nil;调用方会以为端口跳跃已生效")
	}
	if cleanup != nil {
		t.Error("失败时不该返回 cleanup 函数(调用方 defer 它会二次删除)")
	}
	// 已经装上的 8443 必须被撤掉,否则留下「只有部分端口能跳」的半残状态。
	if n := f.countMatching(t, "-t nat -D PREROUTING", "--dport 8443"); n == 0 {
		t.Error("失败后没有回滚已装的 8443 规则 —— 留下一半生效的端口跳跃")
	}
}

// TestSetupHy2PortHop_InstallsEveryNonPrimaryPort 正常路径:除主端口外每个口一条规则。
func TestSetupHy2PortHop_InstallsEveryNonPrimaryPort(t *testing.T) {
	f := newFakeNetTools(t)

	cleanup, err := setupHy2UDPPortHopRedirect(443, "443,8443,9000-9100", "")
	if err != nil {
		t.Fatalf("正常路径不该报错:%v", err)
	}
	if cleanup == nil {
		t.Fatal("成功时必须返回 cleanup 函数,否则退出时规则留在系统里")
	}
	for _, dport := range []string{"8443", "9000:9100"} {
		if n := f.countMatching(t, "-t nat -A PREROUTING", "--dport "+dport, "--to-ports 443"); n != 1 {
			t.Errorf("端口 %s 应装且只装一条 REDIRECT,实际 %d 条", dport, n)
		}
	}
	// 主端口自己不能被 REDIRECT 到自己。
	if n := f.countMatching(t, "-A PREROUTING", "--dport 443 "); n != 0 {
		t.Errorf("给主端口 443 也装了 REDIRECT(%d 条)—— 自己转自己", n)
	}

	cleanup()
	for _, dport := range []string{"8443", "9000:9100"} {
		if n := f.countMatching(t, "-t nat -D PREROUTING", "--dport "+dport); n == 0 {
			t.Errorf("cleanup 没有删除端口 %s 的规则 —— 退出后规则残留在系统里", dport)
		}
	}
}

// TestSetupHy2PortHop_ScopesToIfaceWhenGiven 指定了入接口就必须限定 -i。
//
// 不限定的话所有接口上的这些 UDP 端口都会被 REDIRECT,包括内网管理口 —— 配置项
// port_hop_iface 的全部意义就是收窄这个范围,静默失效等于配了个寂寞。
func TestSetupHy2PortHop_ScopesToIfaceWhenGiven(t *testing.T) {
	f := newFakeNetTools(t)
	if _, err := setupHy2UDPPortHopRedirect(443, "443,8443", "eth0"); err != nil {
		t.Fatal(err)
	}
	if n := f.countMatching(t, "-A PREROUTING", "-i eth0", "--dport 8443"); n != 1 {
		t.Errorf("指定 iface 时规则应带 -i eth0,实际匹配 %d 条", n)
	}

	f2 := newFakeNetTools(t)
	if _, err := setupHy2UDPPortHopRedirect(443, "443,8443", ""); err != nil {
		t.Fatal(err)
	}
	if n := f2.countMatching(t, "-A PREROUTING", "-i "); n != 0 {
		t.Errorf("未指定 iface 时不该出现 -i,实际 %d 条", n)
	}
}

// TestSetupHy2PortHop_RejectsInvalidPortUnion 并集解析不出来要报错,不能装个空规则集。
func TestSetupHy2PortHop_RejectsInvalidPortUnion(t *testing.T) {
	f := newFakeNetTools(t)
	if _, err := setupHy2UDPPortHopRedirect(443, "not-a-port-union", ""); err == nil {
		t.Fatal("非法端口并集却没报错")
	}
	if n := f.countMatching(t, "-A PREROUTING"); n != 0 {
		t.Errorf("解析失败后仍装了 %d 条规则", n)
	}
}

// TestSetupHy2PortHop_NoopWhenUnionIsOnlyPrimary 并集里只有主端口时无事可做。
func TestSetupHy2PortHop_NoopWhenUnionIsOnlyPrimary(t *testing.T) {
	f := newFakeNetTools(t)
	cleanup, err := setupHy2UDPPortHopRedirect(443, "443", "")
	if err != nil {
		t.Fatal(err)
	}
	if cleanup == nil {
		t.Fatal("应返回一个空的 cleanup 而不是 nil,免得调用方 defer 时空指针")
	}
	cleanup() // 不 panic 即通过
	if n := f.countMatching(t, "-A PREROUTING"); n != 0 {
		t.Errorf("并集里只有主端口,不该装规则,实际 %d 条", n)
	}
}

// TestSetupHy2PortHop_SkipsInsertWhenRuleAlreadyPresent -C 说已存在就不再 -A。
func TestSetupHy2PortHop_SkipsInsertWhenRuleAlreadyPresent(t *testing.T) {
	f := newFakeNetTools(t)
	f.ruleExists(t, "--dport 8443")

	if _, err := setupHy2UDPPortHopRedirect(443, "443,8443", ""); err != nil {
		t.Fatal(err)
	}
	if n := f.countMatching(t, "-A PREROUTING", "--dport 8443"); n != 0 {
		t.Errorf("规则已存在却仍追加了 %d 条 —— 同一 dport 多条 REDIRECT,匹配行为飘忽", n)
	}
}

// TestSweepHy2PortHop_OnlyDeletesOwnComment sweep 只清自己 comment 的规则。
//
// 与主规则集的 sweep 同理:这台机器的 nat PREROUTING 上还有 docker 的 DNAT。
// 匹配条件放宽一点,每次启动就会把 docker 的端口映射清掉。
func TestSweepHy2PortHop_OnlyDeletesOwnComment(t *testing.T) {
	f := newFakeNetTools(t)
	f.saveOutput(t, strings.Join([]string{
		"*nat",
		":PREROUTING ACCEPT [0:0]",
		"-A PREROUTING -p udp -m udp --dport 8443 -m comment --comment " + hy2PortHopIptComment + " -j REDIRECT --to-ports 443",
		"-A PREROUTING -p udp -m udp --dport 9000:9100 -m comment --comment " + hy2PortHopIptComment + " -j REDIRECT --to-ports 443",
		"-A PREROUTING -p tcp -m tcp --dport 80 -j DNAT --to-destination 172.17.0.2:80",
		"-A POSTROUTING -s 172.17.0.0/16 -j MASQUERADE",
		// 带**同样 comment**但在 POSTROUTING 上的规则。这一条是专门用来验证「链范围」
		// 这道检查的:少了它,fixture 里所有非 PREROUTING 行都不带 hy2 comment,于是
		// comment 检查会顺手把它们全挡住,链检查删掉也照样绿 —— 断言等于没写。
		// (2026-08-01 变异验证就是这么逃掉一条的。)
		"-A POSTROUTING -p udp -m udp --dport 8443 -m comment --comment " + hy2PortHopIptComment + " -j REDIRECT --to-ports 443",
		"COMMIT",
	}, "\n"))

	cleaned := sweepHy2UDPPortHopByComment()
	if cleaned != 2 {
		t.Errorf("应只清掉 PREROUTING 上自己的那 2 条,实得 %d", cleaned)
	}
	for _, foreign := range []string{"DNAT", "MASQUERADE"} {
		if n := f.countMatching(t, "-D", foreign); n != 0 {
			t.Errorf("删除了别人的 %s 规则 %d 次 —— 每次启动都会破坏 docker 的端口映射", foreign, n)
		}
	}
	// 这个 sweep 只负责 PREROUTING。POSTROUTING 上即便带着同样的 comment 也不归它管 ——
	// 越界删除会静默拆掉别处依赖这条 comment 的规则。
	if n := f.countMatching(t, "-D POSTROUTING"); n != 0 {
		t.Errorf("越界删除了 POSTROUTING 上的规则 %d 条 —— sweep 的链范围失守", n)
	}
}

// TestSweepHy2PortHop_ToleratesMissingIptablesSave iptables-save 挂了不能阻断启动。
func TestSweepHy2PortHop_ToleratesMissingIptablesSave(t *testing.T) {
	f := newFakeNetTools(t)
	f.saveOutput(t, "") // 空输出:nat 表为空的等价情形

	if n := sweepHy2UDPPortHopByComment(); n != 0 {
		t.Errorf("没有残留规则时应返回 0,实得 %d", n)
	}
	if n := f.countMatching(t, "iptables ", "-D"); n != 0 {
		t.Errorf("没有可清的规则却发了 %d 次删除", n)
	}
}
