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
		// ResolveExitMode 的 default 兜底仍保留(万一 Validate 被绕过不 panic),
		// 但生产路径由 ValidateExitMode 提前拦截未知值(见下方 TestTUNConfig_ValidateExitMode)。
		{"未知字符串兜底(legacy=true)", "lockdown", true, "isolate"},
		{"未知字符串兜底(legacy=false)", "lockdown", false, "mesh"},
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

func TestTUNConfig_ValidateExitMode(t *testing.T) {
	valid := []string{"", "mesh", "isolate", "off", " ISOLATE ", "OFF"}
	for _, m := range valid {
		if err := (&TUNConfig{ExitMode: m}).ValidateExitMode(); err != nil {
			t.Errorf("ValidateExitMode(%q) 应通过, got err=%v", m, err)
		}
	}
	invalid := []string{"lockdown", "meshh", "none", "true", "0"}
	for _, m := range invalid {
		if err := (&TUNConfig{ExitMode: m}).ValidateExitMode(); err == nil {
			t.Errorf("ValidateExitMode(%q) 应拒绝(fail-fast), got nil", m)
		}
	}
}
