package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// 端口转发要往系统里装两类东西:LAN 目标的 /32 主机路由,和公网端口的 INPUT 放行规则。
// 这两类命令拼错时**不会报错**——`ip route add` 参数少一个 -6 只是装到了 v4 表里,
// `iptables -I INPUT` 少了位置参数只是插到了末尾(排在 ufw 的 DROP 后面 = 等于没放行)。
// 这类错误只有到生产机上敲 `iptables -S` 才看得见,所以规则的形状本身必须钉住。

// fakePF 记录所有经由命令接缝发出的调用,并可以按前缀注入失败。
type fakePF struct {
	mu    sync.Mutex
	calls []string
	// fail:命令前缀 → 返回的错误(按顺序首个匹配生效)。
	fail []struct {
		prefix string
		err    error
		out    string
	}
	// dump:`iptables -S INPUT` 的输出。
	dump map[string]string
}

func newFakePF(t *testing.T) *fakePF {
	t.Helper()
	f := &fakePF{dump: map[string]string{}}
	orig := pfExec
	pfExec = f.run
	t.Cleanup(func() { pfExec = orig })
	return f
}

func (f *fakePF) run(name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.calls = append(f.calls, line)
	f.mu.Unlock()

	if len(args) >= 2 && args[0] == "-S" && args[1] == "INPUT" {
		if d, ok := f.dump[name]; ok {
			return []byte(d), nil
		}
		return nil, errors.New("no such table")
	}
	for _, fl := range f.fail {
		if strings.HasPrefix(line, fl.prefix) {
			return []byte(fl.out), fl.err
		}
	}
	return nil, nil
}

func (f *fakePF) failOn(prefix, out string, err error) {
	f.fail = append(f.fail, struct {
		prefix string
		err    error
		out    string
	}{prefix, err, out})
}

func (f *fakePF) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakePF) countWith(sub string) int {
	n := 0
	for _, c := range f.got() {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func TestHostRouteCmd_BuildsTheRightPrefixForEachFamily(t *testing.T) {
	cases := []struct {
		name    string
		op      string
		ip      string
		dev     string
		want    string
		because string
	}{
		{"IPv4 装 /32", "add", "192.168.1.50", "nanotun0",
			"ip route add 192.168.1.50/32 dev nanotun0", ""},
		{"IPv4 删", "del", "192.168.1.50", "nanotun0",
			"ip route del 192.168.1.50/32 dev nanotun0", ""},
		{"IPv6 要带 -6 且装 /128", "add", "fd00:1::50", "nanotun0",
			"ip -6 route add fd00:1::50/128 dev nanotun0",
			"漏了 -6 会装进 v4 路由表,命令成功但那台 LAN 设备永远不通"},
		{"v4-mapped 归一成裸 v4", "add", "::ffff:192.168.1.50", "nanotun0",
			"ip route add 192.168.1.50/32 dev nanotun0",
			"不归一的话会拼出 ::ffff:192.168.1.50/32 这种 ip 命令不认的写法"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakePF(t)
			addr := netip.MustParseAddr(tc.ip)
			if err := hostRouteCmd(tc.op, addr, tc.dev); err != nil {
				t.Fatalf("hostRouteCmd: %v", err)
			}
			got := f.got()
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("发出的命令是 %v\n应为 %q(%s)", got, tc.want, tc.because)
			}
		})
	}

	t.Run("没有 TUN 设备名时直接报错", func(t *testing.T) {
		f := newFakePF(t)
		if err := hostRouteCmd("add", netip.MustParseAddr("10.0.0.1"), ""); err == nil {
			t.Fatal("空设备名应报错 —— 不带 dev 的 route add 会装到默认网卡上去")
		}
		if len(f.got()) != 0 {
			t.Fatalf("不该发出任何命令,got %v", f.got())
		}
	})

	t.Run("命令失败时把输出带回来", func(t *testing.T) {
		f := newFakePF(t)
		f.failOn("ip route add", "RTNETLINK answers: File exists", errors.New("exit status 2"))
		err := hostRouteCmd("add", netip.MustParseAddr("10.0.0.1"), "nanotun0")
		if err == nil {
			t.Fatal("应报错")
		}
		if !strings.Contains(err.Error(), "File exists") {
			t.Fatalf("错误里应带上命令输出(排查时全靠它),got %v", err)
		}
	})
}

func TestFirewallRuleArgs_InsertsAtTheTopAndCarriesTheMarker(t *testing.T) {
	ins := strings.Join(firewallRuleArgs("-I", 8443), " ")
	if !strings.HasPrefix(ins, "-I INPUT 1 ") {
		t.Fatalf("放行规则必须插到 INPUT 首位,got %q —— 插在末尾会排在 ufw 的 DROP 后面,等于没放行", ins)
	}
	for _, must := range []string{"-p tcp", "--dport 8443", "--comment " + portForwardFirewallComment, "-j ACCEPT"} {
		if !strings.Contains(ins, must) {
			t.Fatalf("规则里缺 %q: %q", must, ins)
		}
	}

	del := strings.Join(firewallRuleArgs("-D", 8443), " ")
	if strings.HasPrefix(del, "-D INPUT 1 ") {
		t.Fatalf("删除不该带位置参数,got %q —— `-D INPUT 1` 删的是第一条规则,不管它是不是我们装的", del)
	}
	if !strings.HasPrefix(del, "-D INPUT -p tcp") {
		t.Fatalf("删除规则形状不对: %q", del)
	}
	// 删除用的参数必须和插入时一模一样(除了位置),否则匹配不上、删不掉。
	insBody := strings.TrimPrefix(ins, "-I INPUT 1 ")
	delBody := strings.TrimPrefix(del, "-D INPUT ")
	if insBody != delBody {
		t.Fatalf("插入与删除的规则体不一致,-D 会匹配不上:\n  插入 %q\n  删除 %q", insBody, delBody)
	}
}

func TestDelFirewallRuleAll_StopsAtFirstMissAndIsBounded(t *testing.T) {
	t.Run("一条都没有时只试一次", func(t *testing.T) {
		f := newFakePF(t)
		f.failOn("iptables -D", "", errors.New("No chain/target/match by that name"))
		delFirewallRuleAll("iptables", 8443)
		if n := len(f.got()); n != 1 {
			t.Fatalf("第一次就没匹配上就该停,却试了 %d 次", n)
		}
	})

	t.Run("有重复规则时反复删但有上限", func(t *testing.T) {
		f := newFakePF(t)
		// 永远删得掉 = 模拟一条删不完的规则,验证循环不会无限转。
		delFirewallRuleAll("iptables", 8443)
		if n := len(f.got()); n != 8 {
			t.Fatalf("应最多试 8 次就收手,实际 %d 次 —— 没有上限的话一条删不掉的规则会让启动卡死", n)
		}
	})
}

func TestOpenAndCloseFirewallPort_CoverBothFamiliesAndAreIdempotent(t *testing.T) {
	f := newFakePF(t)
	f.failOn("iptables -D", "", errors.New("no match"))
	f.failOn("ip6tables -D", "", errors.New("no match"))

	openFirewallPort(8443)
	got := f.got()

	// v4 和 v6 都要放行:只放 v4 的话,从 IPv6 过来的连接会被默认策略挡掉,
	// 而运维在 iptables -S 里看得到规则,很难想到是 ip6tables 那边缺了一条。
	if f.countWith("iptables -I INPUT 1") != 1 {
		t.Fatalf("v4 放行规则应恰好插一条,got %v", got)
	}
	if f.countWith("ip6tables -I INPUT 1") != 1 {
		t.Fatalf("v6 也必须放行,got %v", got)
	}
	// 先删净再插:否则反复 reload 会把同一条规则越堆越多。
	var idxDel, idxIns = -1, -1
	for i, c := range got {
		if strings.HasPrefix(c, "iptables -D") && idxDel < 0 {
			idxDel = i
		}
		if strings.HasPrefix(c, "iptables -I") {
			idxIns = i
		}
	}
	if idxDel < 0 || idxIns < 0 || idxDel > idxIns {
		t.Fatalf("应先删净再插入(幂等),实际顺序 %v", got)
	}

	f2 := newFakePF(t)
	f2.failOn("iptables -D", "", errors.New("no match"))
	f2.failOn("ip6tables -D", "", errors.New("no match"))
	closeFirewallPort(8443)
	if f2.countWith("-I INPUT") != 0 {
		t.Fatalf("收回放行时不该插规则,got %v", f2.got())
	}
	if f2.countWith("iptables -D") != 1 || f2.countWith("ip6tables -D") != 1 {
		t.Fatalf("两个族都要收,got %v", f2.got())
	}
}

// 进程被 kill -9 之后,上次装的放行规则会留在 iptables 里。下次启动如果不清,
// 那些端口就在没有任何映射对应的情况下一直对公网开着。
func TestFlushStalePortForwardFirewallRules_RemovesOnlyOurLeftovers(t *testing.T) {
	f := newFakePF(t)
	f.dump["iptables"] = strings.Join([]string{
		"-P INPUT DROP",
		"-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
		`-A INPUT -p tcp -m tcp --dport 8443 -m comment --comment nanotun_pf -j ACCEPT`,
		`-A INPUT -p tcp -m tcp --dport 9000 -m comment --comment "nanotun_pf" -j ACCEPT`,
		`-A INPUT -p tcp -m tcp --dport 3306 -m comment --comment other_tool -j ACCEPT`,
	}, "\n")
	f.dump["ip6tables"] = "-P INPUT ACCEPT"
	f.failOn("iptables -D", "", errors.New("no match"))
	f.failOn("ip6tables -D", "", errors.New("no match"))

	flushStalePortForwardFirewallRules()

	if f.countWith("--dport 8443") == 0 {
		t.Fatal("不带引号渲染的残留规则没被清掉")
	}
	if f.countWith("--dport 9000") == 0 {
		t.Fatal("带引号渲染的残留规则没被清掉 —— 不同 iptables 版本的 -S 输出不一样,两种都得认")
	}
	if f.countWith("--dport 22") != 0 {
		t.Fatal("清掉了别人的 SSH 放行规则 —— 只该动带我们自己 comment 的那些")
	}
	if f.countWith("--dport 3306") != 0 {
		t.Fatal("清掉了别的工具装的规则")
	}
	// v6 侧的 -S 成功但没有我们的规则,不该有任何删除。
	if f.countWith("ip6tables -D") != 0 {
		t.Fatalf("v6 侧没有残留却发了删除命令: %v", f.got())
	}
}

func TestParseStalePortForwardPorts_ReadsRealIptablesOutput(t *testing.T) {
	cases := []struct {
		name string
		dump string
		want []int
	}{
		{"空输出", "", nil},
		{"只有策略行", "-P INPUT DROP\n-P FORWARD DROP", nil},
		{"不带引号", `-A INPUT -p tcp --dport 8443 -m comment --comment nanotun_pf -j ACCEPT`, []int{8443}},
		{"带引号", `-A INPUT -p tcp --dport 8443 -m comment --comment "nanotun_pf" -j ACCEPT`, []int{8443}},
		{"comment 在行尾", `-A INPUT -p tcp --dport 8443 -m comment --comment nanotun_pf`, []int{8443}},
		{"没有我们的 comment", `-A INPUT -p tcp --dport 8443 -j ACCEPT`, nil},
		{"别人的 comment", `-A INPUT -p tcp --dport 8443 -m comment --comment nanotun_pf_other -j ACCEPT`, nil},
		{"不是 -A 行", `-N INPUT -p tcp --dport 8443 -m comment --comment nanotun_pf -j ACCEPT`, nil},
		{"缺 dport", `-A INPUT -p tcp -m comment --comment nanotun_pf -j ACCEPT`, nil},
		{"dport 非法", `-A INPUT -p tcp --dport 99999 -m comment --comment nanotun_pf -j ACCEPT`, nil},
		{"dport 为 0", `-A INPUT -p tcp --dport 0 -m comment --comment nanotun_pf -j ACCEPT`, nil},
		{"重复端口只算一次", strings.Join([]string{
			`-A INPUT -p tcp --dport 8443 -m comment --comment nanotun_pf -j ACCEPT`,
			`-A INPUT -p tcp --dport 8443 -m comment --comment nanotun_pf -j ACCEPT`,
		}, "\n"), []int{8443}},
		{"多个端口按出现顺序", strings.Join([]string{
			`-A INPUT -p tcp --dport 9000 -m comment --comment nanotun_pf -j ACCEPT`,
			`-A INPUT -p tcp --dport 8443 -m comment --comment nanotun_pf -j ACCEPT`,
		}, "\n"), []int{9000, 8443}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseStalePortForwardPorts(tc.dump)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("got %v,want %v", got, tc.want)
			}
		})
	}
}

// 两条映射指向同一台 LAN 设备时,主机路由只该装一次,也只该在最后一条停掉时才删。
// 引用计数错了的后果是:停掉其中一条,另一条的 LAN 目标突然不通了。
func TestAddDelRoute_RefCountsSoOneStopDoesNotBreakTheOther(t *testing.T) {
	f := newFakePF(t)
	m := &portForwardManager{tunDev: "nanotun0", routeRef: map[string]int{}}
	ip := netip.MustParseAddr("192.168.1.50")

	if !m.addRoute(ip) {
		t.Fatal("首次装路由应成功")
	}
	if !m.addRoute(ip) {
		t.Fatal("第二条映射复用同一路由应视为已就位")
	}
	if n := f.countWith("route add"); n != 1 {
		t.Fatalf("同一 IP 只该真装一次,实际 %d 次", n)
	}

	m.delRoute(ip)
	if n := f.countWith("route del"); n != 0 {
		t.Fatal("还有一条映射在用,不该删路由 —— 删了的话另一条的 LAN 目标立刻不通")
	}
	m.delRoute(ip)
	if n := f.countWith("route del"); n != 1 {
		t.Fatalf("最后一个引用释放后应删一次,实际 %d 次", n)
	}
	if len(m.routeRef) != 0 {
		t.Fatalf("引用计数表该清空,got %v", m.routeRef)
	}

	// 多删一次不该爆,也不该重复发命令。
	m.delRoute(ip)
	if n := f.countWith("route del"); n != 2 {
		t.Fatalf("对已删的 IP 再删一次会发一条无害的 del(幂等),实际发了 %d 条", n)
	}
}

func TestAddRoute_ExistingRouteCountsAsSuccess(t *testing.T) {
	t.Run("File exists 视为已就位", func(t *testing.T) {
		f := newFakePF(t)
		f.failOn("ip route add", "RTNETLINK answers: File exists", errors.New("exit status 2"))
		m := &portForwardManager{tunDev: "nanotun0", routeRef: map[string]int{}}
		if !m.addRoute(netip.MustParseAddr("192.168.1.50")) {
			t.Fatal("路由本来就在(进程重启 / 手工装过)不算失败 —— 判成失败会让映射平白标成降级态")
		}
	})

	t.Run("真失败要如实报告", func(t *testing.T) {
		f := newFakePF(t)
		f.failOn("ip route add", "Cannot find device \"nanotun0\"", errors.New("exit status 1"))
		m := &portForwardManager{tunDev: "nanotun0", routeRef: map[string]int{}}
		if m.addRoute(netip.MustParseAddr("192.168.1.50")) {
			t.Fatal("设备不存在这种真失败必须报出来,否则运行态会显示一切正常而 LAN 目标其实不可达")
		}
		// 失败也要记引用计数,停的时候才能对称清理。
		if m.routeRef["192.168.1.50"] != 1 {
			t.Fatalf("失败也该记引用,否则 stop 时不会尝试清理,got %v", m.routeRef)
		}
	})
}

func TestIsLANTarget_MeshVIPsDoNotNeedAHostRoute(t *testing.T) {
	m := &portForwardManager{
		meshV4: netip.MustParsePrefix("10.80.0.0/16"),
		meshV6: netip.MustParsePrefix("fd00:80::/64"),
	}
	cases := []struct {
		ip      string
		wantLAN bool
		because string
	}{
		{"10.80.0.5", false, "mesh 内的 vIP,demux 直接投递,不需要主机路由"},
		{"10.80.255.255", false, "还在网段内"},
		{"10.81.0.1", true, "出了 mesh 网段就是节点 LAN 后的设备"},
		{"192.168.1.50", true, "典型的家用 LAN 地址"},
		{"::ffff:10.80.0.5", false, "v4-mapped 要先归一再比,否则会被当成 v6 走错分支"},
		{"fd00:80::1", false, "mesh v6 内"},
		{"fd00:81::1", true, "mesh v6 之外"},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			if got := m.isLANTarget(netip.MustParseAddr(tc.ip)); got != tc.wantLAN {
				t.Fatalf("isLANTarget(%s)=%v,want %v(%s)", tc.ip, got, tc.wantLAN, tc.because)
			}
		})
	}

	// mesh 网段没配置时一律当 LAN:多装一条 /32 主机路由是安全的,
	// 把 LAN 目标误判成 mesh vIP 则会让它彻底不通。
	empty := &portForwardManager{}
	for _, ip := range []string{"10.80.0.5", "fd00:80::1"} {
		if !empty.isLANTarget(netip.MustParseAddr(ip)) {
			t.Fatalf("mesh 网段未配置时 %s 应保守当作 LAN", ip)
		}
	}
}
