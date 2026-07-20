package util

import "testing"

func TestIsValidUUIDv4_Accept(t *testing.T) {
	good := []string{
		"11111111-2222-4333-8444-555555555555",
		"aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee",
		"00000000-0000-4000-8000-000000000000",
		"AAAAAAAA-BBBB-4CCC-9DDD-EEEEEEEEEEEE", // 大小写都允许
	}
	for _, s := range good {
		if !IsValidUUIDv4(s) {
			t.Fatalf("应通过: %q", s)
		}
	}
}

func TestIsValidUUIDv4_Reject(t *testing.T) {
	bad := []string{
		"",
		"not-a-uuid",
		"11111111-2222-1333-8444-555555555555",  // version=1
		"11111111-2222-4333-7444-555555555555",  // variant=7
		"11111111-2222-4333-c444-555555555555",  // variant=c
		"00000000-0000-0000-0000-000000000000",  // version=0
		"11111111-2222-4333-8444-55555555555",   // 长度 35
		"11111111-2222-4333-8444-5555555555555", // 长度 37
		"1111111122224333844455555555555555",    // 没分隔
		"11111111X2222-4333-8444-555555555555",  // 分隔错位
		"11111111-2222-4333-8444-55555555555g",  // 非 hex 字符
	}
	for _, s := range bad {
		if IsValidUUIDv4(s) {
			t.Fatalf("应拒绝: %q", s)
		}
	}
}

func TestNormalizeDeviceUUID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"AAAAAAAA-BBBB-4CCC-9DDD-EEEEEEEEEEEE", "aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee"},
		{"  AaBb  ", "aabb"},
	}
	for _, c := range cases {
		got := NormalizeDeviceUUID(c.in)
		if got != c.want {
			t.Fatalf("NormalizeDeviceUUID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
