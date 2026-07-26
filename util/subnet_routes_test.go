package util

import (
	"net/netip"
	"testing"
)

func TestNormalizeAdvertisedCIDR(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"192.168.1.0/24", "192.168.1.0/24", false},
		{"192.168.1.5/24", "192.168.1.0/24", false}, // mask 化
		{"10.0.0.0/8", "10.0.0.0/8", false},
		{"  10.0.0.0/8  ", "10.0.0.0/8", false},
		{"172.20.0.0/16", "172.20.0.0/16", false},   // RFC1918 172.16/12 内
		{"100.64.0.0/10", "100.64.0.0/10", false},   // CGNAT
		{"fc00::/7", "fc00::/7", false},             // ULA
		{"fd12:3456::/32", "fd12:3456::/32", false}, // ULA 更具体
		{"0.0.0.0/0", "", true},                     // 不允许 /0
		{"::/0", "", true},
		// 第八轮深扫 MED:公网 / 全网覆盖宽段一律拒(子网路由须私有/保留段)。
		{"0.0.0.0/1", "", true},      // 半个 IPv4,绕 /0 守卫的经典手法
		{"128.0.0.0/1", "", true},    // 另半个 IPv4
		{"8.8.8.0/24", "", true},     // 公网具体段
		{"203.0.113.0/24", "", true}, // 公网(文档用)段
		{"172.32.0.0/16", "", true},  // 紧邻 172.16/12 之外的公网段
		{"2001:db8::/32", "", true},  // 公网 IPv6 文档段
		{"not-a-cidr", "", true},
		{"192.168.1.0", "", true}, // 没 mask
		{"", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeAdvertisedCIDR(c.in)
		if c.wantErr {
			if err == nil {
				t.Fatalf("NormalizeAdvertisedCIDR(%q) want err, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeAdvertisedCIDR(%q) err = %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("NormalizeAdvertisedCIDR(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRouteAdvertise_RoundTrip(t *testing.T) {
	in := []string{"192.168.1.0/24", "10.0.0.0/24"}
	body, err := MarshalRouteAdvertise(in)
	if err != nil {
		t.Fatal(err)
	}
	ra, err := ParseRouteAdvertise(body)
	if err != nil {
		t.Fatal(err)
	}
	if ra.Schema != RouteSchemaCurrent {
		t.Fatalf("schema = %d, want %d", ra.Schema, RouteSchemaCurrent)
	}
	if len(ra.Routes) != 2 {
		t.Fatalf("routes len = %d, want 2", len(ra.Routes))
	}
}

func TestRouteApproveStatus_RoundTrip(t *testing.T) {
	in := []RouteStatusEntry{
		{CIDR: "192.168.1.0/24", Status: RouteStatusApproved, At: 1000},
		{CIDR: "10.0.0.0/24", Status: RouteStatusRejected, Reason: "conflict", At: 2000},
	}
	body, err := MarshalRouteApproveStatus(in)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ParseRouteApproveStatus(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Updated) != 2 {
		t.Fatalf("updated len = %d", len(rs.Updated))
	}
	if rs.Updated[1].Reason != "conflict" {
		t.Fatalf("reason = %q", rs.Updated[1].Reason)
	}
}

func TestParseRouteAdvertise_SchemaMismatch(t *testing.T) {
	if _, err := ParseRouteAdvertise([]byte(`{"schema":999,"routes":[]}`)); err == nil {
		t.Fatal("schema 不匹配应报错")
	}
}

// TestNormalizeAdvertisedCIDR_RejectsLinkLocal:链路本地不得作为子网路由宣告。
//
// 三机实测(2026-07-26)复现的跨用户云元数据冒充:A(user testcli)宣告 169.254.169.254/32(旧白名单放行,
// 因 32 >= 16)、admin 批准后,C(user u4,--accept-routes)装上 `169.254.169.254 dev nanotun0`(metric 0,
// 压过 DHCP 那条 metric 100)→ C 请求 http://169.254.169.254/v1.json 拿到的是 A 身后主机伪造的内容,
// C 自己真实的云元数据反而不可达。与 exit_guard 把 169.254/16「无条件拦」的口径直接矛盾,故移出白名单。
func TestNormalizeAdvertisedCIDR_RejectsLinkLocal(t *testing.T) {
	for _, cidr := range []string{
		"169.254.0.0/16",
		"169.254.169.254/32", // 精确到云元数据地址:实测中真正被利用的形态
		"169.254.1.0/24",
		"fe80::/10",
		"fe80::1/128",
	} {
		if got, err := NormalizeAdvertisedCIDR(cidr); err == nil {
			t.Errorf("NormalizeAdvertisedCIDR(%q) 应拒绝(链路本地不可宣告),却返回 %q", cidr, got)
		}
		// 出口语境同样不放宽:唯一放宽处只有 0/0 与 ::/0。
		if got, err := NormalizeExitAdvertisedCIDR(cidr); err == nil {
			t.Errorf("NormalizeExitAdvertisedCIDR(%q) 应拒绝,却返回 %q", cidr, got)
		}
		// 载入端同门槛:存量已批准的链路本地条目自动被挡在转发表外(不删库)。
		if p, perr := netip.ParsePrefix(cidr); perr == nil && PrefixWithinAdvertisable(p.Masked()) {
			t.Errorf("PrefixWithinAdvertisable(%q) 应为 false,使存量条目载入时被挡下", cidr)
		}
	}
	// 对照:合法的私有段仍必须放行。
	for _, cidr := range []string{"10.0.0.0/8", "172.20.10.0/24", "192.168.88.0/24", "100.64.0.0/10", "fd12::/64"} {
		if _, err := NormalizeAdvertisedCIDR(cidr); err != nil {
			t.Errorf("NormalizeAdvertisedCIDR(%q) 不该被拒: %v", cidr, err)
		}
	}
}
