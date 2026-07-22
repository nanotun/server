package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	good := defaultConfig()
	if err := good.Validate(); err != nil {
		t.Fatalf("default config should pass: %v", err)
	}

	bad := defaultConfig()
	bad.ListenAddr = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("empty listen should fail")
	}

	bad = defaultConfig()
	bad.ListenAddr = "no-port-here"
	if err := bad.Validate(); err == nil {
		t.Fatal("listen without port should fail")
	}

	bad = defaultConfig()
	bad.DBPath = "relative/path"
	if err := bad.Validate(); err == nil {
		t.Fatal("relative db path should fail")
	}

	bad = defaultConfig()
	bad.SessionTTLSec = 30
	if err := bad.Validate(); err == nil {
		t.Fatal("tiny session ttl should fail")
	}

	// max_login_failures=0 会彻底关闭暴力破解锁定,必须拒。
	bad = defaultConfig()
	bad.MaxLoginFailures = 0
	if err := bad.Validate(); err == nil {
		t.Fatal("max_login_failures=0 should fail (would disable lockout)")
	}
	bad = defaultConfig()
	bad.MaxLoginFailures = -1
	if err := bad.Validate(); err == nil {
		t.Fatal("negative max_login_failures should fail")
	}
}

func TestMetricsTokenEnvOverride(t *testing.T) {
	t.Setenv("NANOTUN_WEB_METRICS_TOKEN", "  supersecret  ")
	c := defaultConfig()
	c.applyEnvOverrides()
	if c.MetricsToken != "supersecret" {
		t.Fatalf("MetricsToken = %q, want trimmed 'supersecret'", c.MetricsToken)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("NANOTUN_WEB_LISTEN", "1.2.3.4:9999")
	t.Setenv("NANOTUN_WEB_DB", "/tmp/abc.db")
	t.Setenv("NANOTUN_WEB_EXTRA_SANS", "a.com, b.com , 10.0.0.1")
	t.Setenv("NANOTUN_WEB_DISABLE_AUTORELOAD", "1")

	c := defaultConfig()
	c.applyEnvOverrides()

	if c.ListenAddr != "1.2.3.4:9999" {
		t.Errorf("ListenAddr = %s", c.ListenAddr)
	}
	if c.DBPath != "/tmp/abc.db" {
		t.Errorf("DBPath = %s", c.DBPath)
	}
	if len(c.ExtraSANs) != 3 {
		t.Errorf("ExtraSANs = %v", c.ExtraSANs)
	}
	if c.AutoReloadOnACLChange {
		t.Errorf("AutoReloadOnACLChange should be false")
	}
	_ = strings.Split // unused-import shim if needed
	_ = os.Getenv
}

// TestMetricsAccessGate 覆盖 /metrics 门禁:无 token 时仅环回放行;配了 token 时凭 Bearer 放行。
func TestMetricsAccessGate(t *testing.T) {
	// 未配 token:环回放行,非环回拒。
	s := &Server{}
	loop := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	loop.RemoteAddr = "127.0.0.1:5555"
	if !s.metricsAccessAllowed(loop) {
		t.Fatal("loopback peer should be allowed when no token configured")
	}
	remote := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	remote.RemoteAddr = "203.0.113.7:5555"
	if s.metricsAccessAllowed(remote) {
		t.Fatal("non-loopback peer must be denied when no token configured")
	}

	// 配了 token:凭正确 Bearer 从任意来源放行,错误 / 缺失拒。
	s2 := &Server{cfg: Config{MetricsToken: "sekret"}}
	ok := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	ok.RemoteAddr = "203.0.113.7:5555"
	ok.Header.Set("Authorization", "Bearer sekret")
	if !s2.metricsAccessAllowed(ok) {
		t.Fatal("correct bearer token should be allowed from any source")
	}
	badTok := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	badTok.Header.Set("Authorization", "Bearer wrong")
	if s2.metricsAccessAllowed(badTok) {
		t.Fatal("wrong bearer token must be denied")
	}
	noTok := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	noTok.RemoteAddr = "127.0.0.1:5555" // 环回也不行:配了 token 后一律要 token
	if s2.metricsAccessAllowed(noTok) {
		t.Fatal("missing bearer token must be denied even from loopback when token configured")
	}
}

func TestParseBoolEnv(t *testing.T) {
	cases := []struct {
		in  string
		def bool
		out bool
	}{
		{"1", false, true},
		{"true", false, true},
		{"YES", false, true},
		{"on", false, true},
		{"0", true, false},
		{"false", true, false},
		{"no", true, false},
		{"", false, false},
		{"", true, true},
		{"garbage", true, true},
	}
	for _, c := range cases {
		if got := parseBoolEnv(c.in, c.def); got != c.out {
			t.Errorf("parseBoolEnv(%q, %v) = %v, want %v", c.in, c.def, got, c.out)
		}
	}
}
