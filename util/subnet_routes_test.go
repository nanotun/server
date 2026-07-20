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
		{"0.0.0.0/0", "", true}, // 不允许 /0
		{"::/0", "", true},
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
