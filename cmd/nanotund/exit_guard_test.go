package main

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/nanotun/server/config"
)

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("测试数据 %q 不是合法前缀: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

// 云元数据地址必须无条件被拦 —— 这是本闸门的第一动因:VPN 用户经隧道读 169.254.169.254
// 就等于拿到服务器的云身份(AWS IMDSv1 的 IAM 临时凭证 / GCP·Azure 的服务账号 token)。
// 2026-07-25 双机实测:未拦时客户端拿到的 instance-v2-id 与服务器本机完全一致。
func TestComputeExitDenyPrefixes_AlwaysBlocksLinkLocal(t *testing.T) {
	for _, mode := range []string{config.TUNExitDenyPrivateAuto, config.TUNExitDenyPrivateLinkLocal} {
		got := computeExitDenyPrefixes(mode, nil, nil, false)
		if !reflect.DeepEqual(got, []string{"169.254.0.0/16"}) {
			t.Fatalf("mode=%s: got %v, want [169.254.0.0/16]", mode, got)
		}
		gotV6 := computeExitDenyPrefixes(mode, nil, nil, true)
		if !reflect.DeepEqual(gotV6, []string{"fe80::/10"}) {
			t.Fatalf("mode=%s(v6): got %v, want [fe80::/10]", mode, gotV6)
		}
	}
}

func TestComputeExitDenyPrefixes_Off(t *testing.T) {
	// off 是「修复前的行为」,必须一条都不装 —— 给「服务器兼作局域网网关」的部署留的门。
	if got := computeExitDenyPrefixes(config.TUNExitDenyPrivateOff,
		prefixes(t, "10.5.0.0/24"), nil, false); got != nil {
		t.Fatalf("off 档不该装任何规则,得到 %v", got)
	}
}

// auto 档:探到的私网段一并拦(云上单网卡 VPC 的常见形态),公网地址不动。
func TestComputeExitDenyPrefixes_AutoPicksPrivateOnly(t *testing.T) {
	cands := prefixes(t,
		"10.5.0.0/24",     // VPC 子网(单网卡形态下与出网共用一块卡)
		"172.20.0.0/16",   // 另一段内网
		"100.64.0.0/10",   // CGNAT:云上也用来放内部服务
		"45.32.249.36/32", // 公网自身地址:绝不能拦,拦了等于关掉出口
		"203.0.113.0/24",  // 公网邻段
		"0.0.0.0/0",       // 默认路由:必须排除
		"192.168.1.7/32",  // 裸地址型路由(ip route 里常见)
	)
	got := computeExitDenyPrefixes(config.TUNExitDenyPrivateAuto, cands, nil, false)
	want := []string{"10.5.0.0/24", "100.64.0.0/10", "169.254.0.0/16", "172.20.0.0/16", "192.168.1.7/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

// 与 VPN 网段重叠的候选必须放过:mesh 互访、网关自身(MagicDNS)、已批准子网路由都可能落在里面。
// 拦了就是把自家数据面打断 —— 这是本改动最危险的失败模式,故单列一条。
func TestComputeExitDenyPrefixes_NeverTouchesMesh(t *testing.T) {
	mesh := prefixes(t, "10.201.0.0/16")
	cands := prefixes(t, "10.201.0.0/16", "10.201.5.0/24", "10.5.0.0/24")
	got := computeExitDenyPrefixes(config.TUNExitDenyPrivateAuto, cands, mesh, false)
	want := []string{"10.5.0.0/24", "169.254.0.0/16"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mesh 网段被拦会打断互访/MagicDNS: got %v want %v", got, want)
	}

	meshV6 := prefixes(t, "fd00:200::/64")
	candsV6 := prefixes(t, "fd00:200::/64", "fd00:999::/64", "2001:db8::/32")
	gotV6 := computeExitDenyPrefixes(config.TUNExitDenyPrivateAuto, candsV6, meshV6, true)
	wantV6 := []string{"fd00:999::/64", "fe80::/10"}
	if !reflect.DeepEqual(gotV6, wantV6) {
		t.Fatalf("v6: got %v want %v", gotV6, wantV6)
	}
}

// 被更短前缀包含的候选是冗余的:探到 10.0.0.0/8 就不必再单独装 10.5.0.0/24。
func TestComputeExitDenyPrefixes_DropsSubsumed(t *testing.T) {
	cands := prefixes(t, "10.0.0.0/8", "10.5.0.0/24", "10.5.0.7/32", "172.16.0.0/12")
	got := computeExitDenyPrefixes(config.TUNExitDenyPrivateAuto, cands, nil, false)
	want := []string{"10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// v6 候选不能混进 v4 结果(反之亦然)—— 两族各自装表,串了会插出无效规则。
func TestComputeExitDenyPrefixes_FamilyIsolation(t *testing.T) {
	mixed := prefixes(t, "10.5.0.0/24", "fd00:abcd::/64")
	if got := computeExitDenyPrefixes(config.TUNExitDenyPrivateAuto, mixed, nil, false); !reflect.DeepEqual(
		got, []string{"10.5.0.0/24", "169.254.0.0/16"}) {
		t.Fatalf("v4 结果混入 v6: %v", got)
	}
	if got := computeExitDenyPrefixes(config.TUNExitDenyPrivateAuto, mixed, nil, true); !reflect.DeepEqual(
		got, []string{"fd00:abcd::/64", "fe80::/10"}) {
		t.Fatalf("v6 结果混入 v4: %v", got)
	}
}

// link-local 档只拦链路本地,私网段照旧放行(明知云上仍暴露,是运维的显式选择)。
func TestComputeExitDenyPrefixes_LinkLocalModeIgnoresCandidates(t *testing.T) {
	got := computeExitDenyPrefixes(config.TUNExitDenyPrivateLinkLocal,
		prefixes(t, "10.5.0.0/24", "192.168.0.0/16"), nil, false)
	if !reflect.DeepEqual(got, []string{"169.254.0.0/16"}) {
		t.Fatalf("link-local 档不该拦私网段,得到 %v", got)
	}
}

func TestParseIPRouteDests(t *testing.T) {
	// 取自真实 `ip route show dev eth0` / `ip -6 route show dev eth0` 的形态。
	out := `default via 45.32.248.1 proto dhcp src 45.32.249.36 metric 100
10.5.0.0/24 proto kernel scope link src 10.5.0.7
169.254.169.254 via 45.32.248.1 proto dhcp src 45.32.249.36 metric 100
45.32.248.0/23 proto kernel scope link src 45.32.249.36
blackhole 192.0.2.0/24
garbage line without a destination? 
`
	got := parseIPRouteDests(out)
	want := prefixes(t, "10.5.0.0/24", "169.254.169.254/32", "45.32.248.0/23")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseIPRouteDests_TolerantOfJunk(t *testing.T) {
	// 探测失败只能少拦一段,绝不能 panic 或阻断启动。
	for _, in := range []string{"", "\n\n", "Error: any valid prefix is expected rather than \"x\"."} {
		if got := parseIPRouteDests(in); len(got) != 0 {
			t.Fatalf("输入 %q 应解析不出目的地,得到 %v", in, got)
		}
	}
}
