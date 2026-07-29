package main

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// 端口转发管理器的启动这一步做了三件互不相干的事,而它们的失效方式都不报错。
//
// 一是把 mesh 网段解析出来 —— 这是「target_ip 是本 mesh 里的 vIP,还是节点 LAN 后的设备」唯一
// 判据。解析不出来时全部目标都被当成 LAN,于是给一个 mesh vIP 也装一条 /32 主机路由:那条路由
// 与 mesh 网段路由指向同一设备,看不出毛病,但 v6 那段漏解析的后果是 v6 vIP 目标进了 LAN 精确
// 路由表,数据面的源反欺骗放行表跟着跑偏。
//
// 二是清掉上次进程崩溃残留的放行规则。不清,那些端口就一直对公网开着 —— 映射早就删了,管理员在
// web 上看不到任何在开的端口,而机器上的 INPUT 里还留着 ACCEPT。
//
// 三是把自己发布成全局单例并做一次 reload。没发布,后续 control-socket 的 reload 一律 no-op,
// 表现为「改了映射不生效,重启才生效」。

// TestStartPortForwardManager_ParsesMeshPrefixesAndSweepsStaleRules 启动这一步的三件事。
func TestStartPortForwardManager_ParsesMeshPrefixesAndSweepsStaleRules(t *testing.T) {
	env := newPFEnv(t)
	// 上一次进程崩溃残留:两条带本特性 comment 的放行规则,而库里现在一条映射都没有。
	env.fake.dump["iptables"] = "-P INPUT ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 8443 -m comment --comment nanotun_pf -j ACCEPT\n" +
		"-A INPUT -p tcp -m tcp --dport 9000 -m comment --comment \"nanotun_pf\" -j ACCEPT\n"

	prevV4, prevV6 := sharedTUNGateway, sharedTUNGatewayV6
	sharedTUNGateway, sharedTUNGatewayV6 = "10.90.0.1/16", "fd00:90::1/64"
	t.Cleanup(func() { sharedTUNGateway, sharedTUNGatewayV6 = prevV4, prevV6 })

	prevMgr := portForwardMgr.Load()
	t.Cleanup(func() { portForwardMgr.Store(prevMgr) })

	stop := startPortForwardManager(env.gw, "nanotun9")
	t.Cleanup(stop)

	m := portForwardMgr.Load()
	if m == nil {
		t.Fatal("管理器没有发布成全局单例 —— 之后所有 reload 都是 no-op,改了映射要重启才生效")
	}
	if m.tunDev != "nanotun9" {
		t.Errorf("tunDev = %q, want nanotun9(主机路由会装到别的设备上)", m.tunDev)
	}
	// 两族网段都要解析出来,且按网段归一(给的是网关地址,不是网络地址)。
	if want := netip.MustParsePrefix("10.90.0.0/16"); m.meshV4 != want {
		t.Errorf("meshV4 = %v, want %v", m.meshV4, want)
	}
	if want := netip.MustParsePrefix("fd00:90::/64"); m.meshV6 != want {
		t.Errorf("meshV6 = %v, want %v —— v6 网段没解析出来,v6 vIP 目标会被当成 LAN", m.meshV6, want)
	}
	// 判据真的生效:mesh 内的 vIP 不是 LAN 目标,mesh 外的才是。
	if m.isLANTarget(netip.MustParseAddr("10.90.0.7")) {
		t.Error("mesh v4 vIP 被判成 LAN 目标 —— 会给它多装一条 /32 主机路由")
	}
	if m.isLANTarget(netip.MustParseAddr("fd00:90::7")) {
		t.Error("mesh v6 vIP 被判成 LAN 目标")
	}
	if !m.isLANTarget(netip.MustParseAddr("192.168.7.7")) {
		t.Error("真正的 LAN 目标被判成 mesh vIP —— 不装主机路由就到不了")
	}

	// 残留的两个端口都要被收掉(两种 comment 渲染都得认)。
	calls := env.fake.got()
	for _, port := range []string{"8443", "9000"} {
		found := false
		for _, c := range calls {
			if containsAll(c, "iptables -D INPUT", "--dport "+port) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("崩溃残留的 :%s 放行规则没被收掉 —— 这个端口会一直对公网开着，而 web 上看不到任何映射", port)
		}
	}
}

// TestStartPortForwardManager_NoStoreIsANoop 没有 store 时必须是干净的 no-op。
//
// 这条路给的是测试与「DB 尚未就绪」的启动早期。它若照常往下走,就会在 store 为 nil 上取值;
// 返回的 cleanup 若是 nil,调用方 defer 它直接 panic。
func TestStartPortForwardManager_NoStoreIsANoop(t *testing.T) {
	env := newPFEnv(t)
	before := len(env.fake.got())

	for name, gw := range map[string]*gatewayState{
		"gw 为 nil":    nil,
		"store 为 nil": {},
	} {
		t.Run(name, func(t *testing.T) {
			stop := startPortForwardManager(gw, "nanotun0")
			if stop == nil {
				t.Fatal("返回了 nil cleanup —— 调用方 defer 它就是 panic")
			}
			stop()
		})
	}
	if len(env.fake.got()) != before {
		t.Error("no-op 路径动了系统规则")
	}
}

// TestPortForwardFirewall_KeepsGoingWhenTheSystemSaysNo 系统命令失败时不许连带停掉监听。
//
// iptables 可能整个不可用(容器里没 CAP_NET_ADMIN、或机器没 ip6tables),而端口转发本身与放行是
// 两件事:放行失败只意味着「外部可能连不上,要管理员手动放行」,监听照旧要起。把它当致命错误的
// 后果是 v4 一切正常的机器因为缺 ip6tables 而整个特性起不来。
func TestPortForwardFirewall_KeepsGoingWhenTheSystemSaysNo(t *testing.T) {
	env := newPFEnv(t)
	env.fake.failOn("ip6tables", "ip6tables: command not found", errors.New("exit 127"))
	env.fake.failOn("iptables -I", "iptables: permission denied", errors.New("exit 1"))

	openFirewallPort(18443) // 不许 panic,也不许因为 v6 缺失就跳过 v4
	closeFirewallPort(18443)

	var sawV4Insert, sawV6 bool
	for _, c := range env.fake.got() {
		if containsAll(c, "iptables -I INPUT", "--dport 18443") {
			sawV4Insert = true
		}
		if containsAll(c, "ip6tables", "18443") {
			sawV6 = true
		}
	}
	if !sawV4Insert {
		t.Error("v4 放行都没试 —— 外部连不上")
	}
	if !sawV6 {
		t.Error("v6 那侧被整个跳过了")
	}

	// `-S INPUT` 读不出来时(表不存在 / 无权限)只能跳过这一族,不能拿空输出当「没有残留」之后
	// 还去解析。这里 dump 没设,fake 会返回错误。
	flushStalePortForwardFirewallRules()
}

// TestPortForwardDelRoute_RefcountsBeforeRemoving 同一 LAN IP 上的多条映射共享一条主机路由。
//
// 两条映射指到同一台 LAN 设备的不同端口(比如 80 和 443)是常见配置,它们共用一条 /32 主机路由。
// 删其中一条映射时若不看引用计数就把路由删了,另一条映射当场断 —— 而它自己什么都没改。
func TestPortForwardDelRoute_RefcountsBeforeRemoving(t *testing.T) {
	env := newPFEnv(t)
	ip := netip.MustParseAddr("192.168.50.7")

	env.m.addRoute(ip)
	env.m.addRoute(ip)
	base := len(env.fake.got())

	env.m.delRoute(ip) // 还有一条映射在用
	for _, c := range env.fake.got()[base:] {
		if containsAll(c, "route del") {
			t.Fatal("还有映射在用就把主机路由删了 —— 另一条映射当场断,而它自己什么都没改")
		}
	}

	env.m.delRoute(ip) // 最后一条
	sawDel := false
	for _, c := range env.fake.got()[base:] {
		if containsAll(c, "route del", ip.String()) {
			sawDel = true
		}
	}
	if !sawDel {
		t.Error("最后一条映射也删了却没收回主机路由 —— 路由残留会一直把该 IP 的流量往 TUN 灌")
	}

	// 删路由的系统命令失败只是 Debug(路由可能本就不存在),不该冒出去。
	env.fake.failOn("ip route del", "RTNETLINK answers: No such process", errors.New("exit 2"))
	env.m.addRoute(ip)
	env.m.delRoute(ip)

	env.m.stopEntry(nil) // nil 条目要安全跳过:停一条已经被别处摘除的监听是正常竞态
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
