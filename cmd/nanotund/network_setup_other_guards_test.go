//go:build !linux

package main

import (
	"net"
	"strings"
	"testing"
)

// 非 Linux 平台上这些网络配置函数全是桩。它们唯一的正确行为是**明确报错**:
// 数据面的转发、NAT、连接数限制、端口放行全靠 iptables/ip6tables,而这些桩什么都没做。
// 桩若返回 nil,启动路径会认为「防火墙已就绪」并继续把 server 拉起来 —— 开发机上跑出来的是
// 一台没有任何规则的 server:转发不通(或更糟:没有任何限制地转发)、mesh 之间毫无隔离,
// 而日志里一行错误都没有。所以这里钉的是「桩必须 fail-closed 且说清原因」。
func TestNonLinuxNetworkStubs_FailClosedWithAReasonInTheMessage(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"EnableIPForward", EnableIPForward()},
		{"EnableIPv6Forward", EnableIPv6Forward()},
		{"SetupIptables", SetupIptables("nanotun0", "eth0", "203.0.113.9",
			[]string{"10.202.0.0/16"}, 100, 100, false, false, false, "", "", "", "", 0)},
		{"SetupIp6tables", SetupIp6tables("nanotun0", "eth0", "2001:db8::1",
			[]string{"fd00:202::/64"}, 100, 100, false, false, false, "", "", "")},
	}
	for _, c := range cases {
		if c.err == nil {
			t.Errorf("%s 在非 Linux 上返回了 nil —— 启动路径会当成「防火墙已就绪」继续拉起 server,"+
				"跑出来的是一台没有任何规则的机器,而日志里一行错误都没有", c.name)
			continue
		}
		if !strings.Contains(c.err.Error(), "Linux") {
			t.Errorf("%s 的报错没说清是平台限制: %v", c.name, c.err)
		}
	}

	// WAN 探测同理:返回空串加 nil 会让启动路径拿着空网卡名去装规则。
	if _, _, err := GetWAN(); err == nil {
		t.Error("GetWAN 在非 Linux 上返回了 nil —— 启动路径会拿着空网卡名继续走")
	}
	if _, _, err := GetWANv6(); err == nil {
		t.Error("GetWANv6 在非 Linux 上返回了 nil")
	}

	// 这几个是查询/清理类,返回空即可,但不许 panic:启动路径无条件调用它们。
	if nets, err := GetLocalSubnets(); err != nil || len(nets) != 0 {
		t.Errorf("GetLocalSubnets 应返回空且无错, got %v / %v", nets, err)
	}
	if nets, err := GetLocalSubnetsV6(); err != nil || len(nets) != 0 {
		t.Errorf("GetLocalSubnetsV6 应返回空且无错, got %v / %v", nets, err)
	}
	_, a, _ := net.ParseCIDR("10.202.0.0/16")
	_, b, _ := net.ParseCIDR("10.202.0.0/24")
	if SubnetOverlaps(a, b) {
		t.Error("非 Linux 桩的 SubnetOverlaps 应恒为 false(它没有真实实现,不能拿来做判断)")
	}
	DeleteExistingTUNs("nanotun", 4)
	DeleteExistingTUN("nanotun0")
}

// TestNonLinuxIptablesSweepStubs_NoopButKeepTheShape:主链规则清扫在非 Linux 上是 noop。
// 与上面那组相反,这里**不能**报错:启动早期无条件调用它们清理上次崩溃的残留规则,
// 桩若报错开发机根本起不来。要钉的是「形状不变」——加注释的参数原样返回(不能吞掉参数,
// 否则 Linux 版换回来时调用方传的规则会静默丢失)、清扫报告清掉 0 条、拆除不 panic。
func TestNonLinuxIptablesSweepStubs_NoopButKeepTheShape(t *testing.T) {
	args := []string{"-A", "FORWARD", "-i", "nanotun0", "-j", "DROP"}
	got := withMainComment(args)
	if len(got) != len(args) {
		t.Fatalf("非 Linux 桩不该增删参数,want %d 个,got %v", len(args), got)
	}
	for i := range args {
		if got[i] != args[i] {
			t.Fatalf("参数被改写了:第 %d 个 want %q got %q", i, args[i], got[i])
		}
	}
	if n := sweepMainIptablesRules("iptables"); n != 0 {
		t.Errorf("非 Linux 上没有规则可清,应报 0 条,got %d", n)
	}
	teardownMainIptablesRules() // 不许 panic
}
