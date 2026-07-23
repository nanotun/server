package util

import "testing"

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
		{"0.0.0.0/1", "", true},       // 半个 IPv4,绕 /0 守卫的经典手法
		{"128.0.0.0/1", "", true},     // 另半个 IPv4
		{"8.8.8.0/24", "", true},      // 公网具体段
		{"203.0.113.0/24", "", true},  // 公网(文档用)段
		{"172.32.0.0/16", "", true},   // 紧邻 172.16/12 之外的公网段
		{"2001:db8::/32", "", true},   // 公网 IPv6 文档段
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
