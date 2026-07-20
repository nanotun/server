package main

import (
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
