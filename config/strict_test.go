package config

import (
	"os"
	"strings"
	"testing"
)

func TestStrictCheck_AcceptsKnownFields(t *testing.T) {
	const ok = `
[log]
level = "debug"

[server]
listen_addr = ":443"
`
	if err := StrictCheck([]byte(ok)); err != nil {
		t.Fatalf("已知字段不应报错: %v", err)
	}
}

func TestStrictCheck_RejectsUnknownField(t *testing.T) {
	const bad = `
[server]
listen_addr = ":443"
lease_gc_idle_day = 30
`
	err := StrictCheck([]byte(bad))
	if err == nil {
		t.Fatal("拼错字段应报错")
	}
	if !strings.Contains(err.Error(), "lease_gc_idle_day") {
		t.Errorf("err 应点名未知字段, got %v", err)
	}
}

func TestStrictModeEnabled_EnvVariants(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"1", true},
		{"true", true},
		{"YES", true},
		{" true ", true},
		{"random", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			t.Setenv(StrictEnvVar, c.in)
			if got := StrictModeEnabled(); got != c.want {
				t.Fatalf("env=%q: want %v got %v", c.in, c.want, got)
			}
		})
	}
}

// 确保我们没有把 StrictEnvVar 写错(常见 typo).
func TestStrictEnvVar_ConstName(t *testing.T) {
	if StrictEnvVar != "NANOTUN_CONFIG_STRICT" {
		t.Fatalf("StrictEnvVar = %q,与文档/外部脚本不一致", StrictEnvVar)
	}
	// 同步清掉测试残留。
	_ = os.Unsetenv(StrictEnvVar)
}
