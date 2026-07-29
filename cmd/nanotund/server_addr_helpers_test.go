package main

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
)

// server.go 里这几个地址/网段辅助函数此前零覆盖。它们全是启动期的配置判定:
// 判错的后果不是崩溃,而是「端口起来了、数据面是黑洞」——最难排查的那种故障。

// classifyVPNListenAddr 决定 hy2/REALITY 的环回桥接(固定拨 127.0.0.1)能不能打进 listener。
// 放宽一点点就是数据面静默全断,所以这里把每一类写法都钉住。
func TestClassifyVPNListenAddr_OnlyAcceptsWhatLoopbackDialCanReach(t *testing.T) {
	cases := []struct {
		addr    string
		want    vpnListenVerdict
		because string
	}{
		{":8443", vpnListenReachable, "无 host 简写 = 绑所有网卡,含 127.0.0.1"},
		{"0.0.0.0:8443", vpnListenReachable, "IPv4 通配"},
		{"[::]:8443", vpnListenReachable, "IPv6 通配,dual-stack 下也收 IPv4-mapped"},
		{"127.0.0.1:8443", vpnListenReachable, "精确匹配环回桥接的目标"},
		{"  127.0.0.1:8443  ", vpnListenReachable, "两侧空白要先 trim"},
		{"127.0.0.2:8443", vpnListenOtherLoopback, "是回环但收不到 127.0.0.1 的拨号"},
		{"[::1]:8443", vpnListenOtherLoopback, "IPv6 回环同理,收不到 IPv4 环回拨号"},
		{"10.0.0.5:8443", vpnListenSpecificIP, "绑具体网卡 IP,环回拨号会被拒"},
		{"example.com:8443", vpnListenHostNotIP, "host 必须是 IP,域名解析结果不可控"},
		{"localhost:8443", vpnListenHostNotIP, "localhost 应由 normalizeLoopbackHost 先归一,漏了就得报错"},
		{"没有端口", vpnListenUnparsable, "拆不出 host:port"},
		// 冒号过多的畸形值:曾被「以冒号开头就放行」的兜底当成通配放过去,而它连 net.Listen
		// 都绑不上 —— 结果是启动期沉默、运行期数据面黑洞。必须在这里就拦下。
		{"::", vpnListenUnparsable, "缺端口的 IPv6 通配写法,绑不上"},
		{":8443:9000", vpnListenUnparsable, "冒号过多,不是合法监听地址"},
	}
	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			got, _ := classifyVPNListenAddr(c.addr)
			if got != c.want {
				t.Fatalf("classify(%q) = %v, want %v —— %s", c.addr, got, c.want, c.because)
			}
		})
	}
}

// normalizeLoopbackHost 把 localhost 归一成 127.0.0.1:某些环境把 ::1 排在前面,
// listener 只绑 IPv6 回环 → 环回桥接打不进来。
func TestNormalizeLoopbackHost(t *testing.T) {
	cases := map[string]string{
		"localhost:8443":    "127.0.0.1:8443",
		"LocalHost:8443":    "127.0.0.1:8443", // 大小写不敏感
		"  localhost:1 ":    "127.0.0.1:1",    // 先 trim 再比
		"127.0.0.1:8443":    "127.0.0.1:8443", // 已经是目标形态,原样
		"0.0.0.0:8443":      "0.0.0.0:8443",
		":8443":             ":8443",             // 无 host,不动
		"localhost-no-port": "localhost-no-port", // 拆不开就原样交给 validate 去报错
	}
	for in, want := range cases {
		if got := normalizeLoopbackHost(in); got != want {
			t.Errorf("normalizeLoopbackHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseListenPortValue(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		deflt   string
		want    int
		wantErr bool
	}{
		{"host:port", "127.0.0.1:8443", ":443", 8443, false},
		{"无 host 简写", ":8443", ":443", 8443, false},
		{"IPv6 带方括号", "[::1]:9000", ":443", 9000, false},
		{"空串回落默认值", "", "127.0.0.1:7443", 7443, false},
		{"空白串也回落", "   ", ":6443", 6443, false},
		{"端口 0 非法", "127.0.0.1:0", ":443", 0, true},
		{"端口越界", "127.0.0.1:65536", ":443", 0, true},
		{"端口不是数字", "127.0.0.1:http", ":443", 0, true},
		{"根本没有端口", "127.0.0.1", ":443", 0, true},
		{"只有冒号", ":", ":443", 0, true},
		{"简写但端口越界", ":70000", ":443", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseListenPortValue(c.addr, c.deflt)
			if (err != nil) != c.wantErr {
				t.Fatalf("parseListenPortValue(%q,%q) err = %v, wantErr = %v", c.addr, c.deflt, err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Fatalf("port = %d, want %d", got, c.want)
			}
		})
	}
}

// gatewayCIDRFromSubnet 必须先对齐到网络地址再 +1 —— 运维把网段写成 10.0.0.7/24
// 这种主机形式时,不能算出 10.0.0.8/24 那种错网关。
func TestGatewayCIDRFromSubnet(t *testing.T) {
	cases := []struct {
		subnet  string
		want    string
		wantErr bool
	}{
		{"10.0.0.0/24", "10.0.0.1/24", false},
		{"10.0.0.7/24", "10.0.0.1/24", false}, // 主机形式:先 Masked 再 +1
		{"10.201.0.0/16", "10.201.0.1/16", false},
		{"fd00::/64", "fd00::1/64", false},
		{"fd00::abcd/64", "fd00::1/64", false},
		{"192.168.1.0/31", "192.168.1.1/31", false},
		{"不是网段", "", true},
		{"10.0.0.0/33", "", true},
		{"", "", true},
		// 全一前缀:网络地址 +1 溢出,算不出网关。回一个空串而不是错误的话,下游会拿 ""
		// 去装 TUN 地址 —— 那时报的错离配置很远,查起来先怀疑的是网卡。
		{"255.255.255.255/32", "", true},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "", true},
	}
	for _, c := range cases {
		t.Run(c.subnet, func(t *testing.T) {
			got, err := gatewayCIDRFromSubnet(c.subnet)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Fatalf("gateway = %q, want %q", got, c.want)
			}
		})
	}
}

// maskFromGatewayCIDR:IPv4 要给点分十进制(客户端按老式掩码配网卡),IPv6 给前缀长度。
func TestMaskFromGatewayCIDR(t *testing.T) {
	cases := map[string]string{
		"10.0.0.1/24":   "255.255.255.0",
		"10.201.0.1/16": "255.255.0.0",
		"10.0.0.1/32":   "255.255.255.255",
		"10.0.0.1/8":    "255.0.0.0",
		"fd00::1/64":    "64",
		"fd00::1/128":   "128",
		"不是 CIDR":       "",
		"":              "",
		"10.0.0.1":      "", // 缺前缀长度
	}
	for in, want := range cases {
		if got := maskFromGatewayCIDR(in); got != want {
			t.Errorf("maskFromGatewayCIDR(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMaskFromGatewayCIDR_FallsBackToTheOldParserForNonCanonicalForms 新解析器挑剔的写法,老解析器兜住。
//
// netip.ParsePrefix 只认规范写法,net.ParseCIDR 宽松得多 —— "10.201.0.1/016"(前缀长度带前导零)是
// 后者收、前者拒的典型。这个掩码是**下发给客户端配网卡**的:兜不住就下发空串,客户端把网卡配成
// 无掩码 / 默认掩码,整条 VPN 路由随之错位,而服务端日志一切正常。
func TestMaskFromGatewayCIDR_FallsBackToTheOldParserForNonCanonicalForms(t *testing.T) {
	if got := maskFromGatewayCIDR("10.201.0.1/016"); got != "255.255.0.0" {
		t.Errorf("maskFromGatewayCIDR(%q) = %q,期望 255.255.0.0 —— 老式写法没兜住,客户端会拿到空掩码",
			"10.201.0.1/016", got)
	}
	// 兜底只对「老解析器认、且是 v4」的输入生效;真正的垃圾仍要返回空串,而不是编一个掩码出来。
	for _, bad := range []string{"fe80::1%eth0/64", "010.0.0.1/24", "10.0.0.1/33"} {
		if got := maskFromGatewayCIDR(bad); got != "" {
			t.Errorf("maskFromGatewayCIDR(%q) = %q,非法输入应返回空串", bad, got)
		}
	}
}

func TestParseCIDR_ReturnsNetworkOrError(t *testing.T) {
	n, err := parseCIDR("10.0.0.7/24")
	if err != nil {
		t.Fatalf("合法 CIDR 不该报错: %v", err)
	}
	if n.String() != "10.0.0.0/24" {
		t.Fatalf("应返回对齐后的网络地址,got %s", n.String())
	}
	if _, err := parseCIDR("10.0.0.0"); err == nil {
		t.Fatal("缺前缀长度应报错")
	}
}

func TestIPToKey_UnmapsV4MappedV6(t *testing.T) {
	if got := ipToKey("::ffff:10.0.0.5"); got != netip.MustParseAddr("10.0.0.5") {
		t.Fatalf("v4-mapped 必须归一成 v4,否则 demux 查表会漏,got %v", got)
	}
	if got := ipToKey("fd00::1"); got != netip.MustParseAddr("fd00::1") {
		t.Fatalf("纯 v6 应原样保留,got %v", got)
	}
	if got := ipToKey("不是地址"); got.IsValid() {
		t.Fatalf("解析失败应返回零值 Addr,got %v", got)
	}
}

// probeLoopbackVPNReachable 的成功路径:listener 在 127.0.0.1 上时应当一拨即通、直接返回。
// (失败路径会 FatalExit 退进程,不在单测里走。)
func TestProbeLoopbackVPNReachable_ReturnsWhenLoopbackAccepts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	probeLoopbackVPNReachable(ln.Addr().String(), port) // 拨不通会 FatalExit,能返回即通过
}
