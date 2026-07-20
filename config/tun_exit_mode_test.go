package config

import "testing"

func TestTUNConfig_ResolveExitMode(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		legacy   bool
		expected string
	}{
		{"empty + legacy false → mesh", "", false, "mesh"},
		{"empty + legacy true → isolate(向后兼容)", "", true, "isolate"},
		{"显式 mesh", "mesh", true /*legacy 应被无视*/, "mesh"},
		{"显式 isolate", "isolate", false, "isolate"},
		{"显式 off", "off", false, "off"},
		{"大小写不敏感 + trim", " ISOLATE ", false, "isolate"},
		{"未知字符串走兼容路径(legacy=true)", "lockdown", true, "isolate"},
		{"未知字符串走兼容路径(legacy=false)", "lockdown", false, "mesh"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := TUNConfig{ExitMode: c.mode, ClientIsolate: c.legacy}
			if got := tc.ResolveExitMode(); got != c.expected {
				t.Errorf("ResolveExitMode(%q, legacy=%v) = %q, want %q",
					c.mode, c.legacy, got, c.expected)
			}
		})
	}
}
