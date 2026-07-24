package util

import "testing"

// TestCIDROverlapsAny 覆盖批准期 mesh 交叠判定的各分支:被包含 / 包含 / 相等 / 不相交 / 跨族 / 非法输入。
func TestCIDROverlapsAny(t *testing.T) {
	mesh := []string{"10.201.0.1/16", "fd00::1/64"} // 网关形态(带 host 位),CIDROverlapsAny 内部 Masked。

	cases := []struct {
		name string
		cidr string
		mesh []string
		want bool
	}{
		{"v4 subnet within mesh", "10.201.5.0/24", mesh, true},
		{"v4 mesh within wider route", "10.0.0.0/8", mesh, true},
		{"v4 exact mesh net", "10.201.0.0/16", mesh, true},
		{"v4 disjoint", "192.168.1.0/24", mesh, false},
		{"v6 within mesh", "fd00::/96", mesh, true},
		{"v6 disjoint", "fd99::/64", mesh, false},
		{"v4 route vs v6 mesh only", "10.201.5.0/24", []string{"fd00::1/64"}, false},
		{"v6 route vs v4 mesh only", "fd00::/96", []string{"10.201.0.1/16"}, false},
		{"empty mesh list", "10.201.5.0/24", nil, false},
		{"invalid cidr", "not-a-cidr", mesh, false},
		{"invalid mesh entry skipped", "192.168.1.0/24", []string{"garbage", "192.168.0.0/16"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CIDROverlapsAny(tc.cidr, tc.mesh); got != tc.want {
				t.Fatalf("CIDROverlapsAny(%q, %v) = %v, want %v", tc.cidr, tc.mesh, got, tc.want)
			}
		})
	}
}
