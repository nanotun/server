package main

import (
	"fmt"
	"testing"
)

func TestAllocClientIP_FirstInSubnet(t *testing.T) {
	used := map[string]bool{}
	cfg, err := AllocClientIP("10.0.0.1/24", used, nil)
	if err != nil {
		t.Fatalf("AllocClientIP(10.0.0.1/24, used): %v", err)
	}
	if cfg.ClientIP != "10.0.0.2" {
		t.Errorf("ClientIP = %q, want 10.0.0.2", cfg.ClientIP)
	}
	if cfg.Mask != "255.255.255.0" {
		t.Errorf("Mask = %q, want 255.255.255.0", cfg.Mask)
	}
	if cfg.Gateway != "10.0.0.1" {
		t.Errorf("Gateway = %q, want 10.0.0.1", cfg.Gateway)
	}
}

func TestAllocClientIP_DifferentCIDRs(t *testing.T) {
	used := map[string]bool{}
	cases := []struct {
		cidr        string
		wantClient  string
		wantGateway string
	}{
		{"10.0.0.1/24", "10.0.0.2", "10.0.0.1"},
		{"10.0.1.1/24", "10.0.1.2", "10.0.1.1"},
		{"10.0.4.1/24", "10.0.4.2", "10.0.4.1"},
		{"192.168.100.1/24", "192.168.100.2", "192.168.100.1"},
		{"192.168.104.1/24", "192.168.104.2", "192.168.104.1"},
		{"172.16.0.1/24", "172.16.0.2", "172.16.0.1"},
		{"172.20.0.1/24", "172.20.0.2", "172.20.0.1"},
	}
	for _, c := range cases {
		cfg, err := AllocClientIP(c.cidr, used, nil)
		if err != nil {
			t.Fatalf("AllocClientIP(%q): %v", c.cidr, err)
		}
		if cfg.ClientIP != c.wantClient || cfg.Gateway != c.wantGateway {
			t.Errorf("cidr %q: got ClientIP=%q Gateway=%q, want ClientIP=%q Gateway=%q",
				c.cidr, cfg.ClientIP, cfg.Gateway, c.wantClient, c.wantGateway)
		}
		if cfg.Mask != "255.255.255.0" {
			t.Errorf("cidr %q: Mask = %q", c.cidr, cfg.Mask)
		}
	}
}

func TestAllocClientIP_UsedIncrements(t *testing.T) {
	used := map[string]bool{}
	for _, wantIP := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"} {
		cfg, err := AllocClientIP("10.0.0.1/24", used, nil)
		if err != nil {
			t.Fatalf("AllocClientIP: %v", err)
		}
		if cfg.ClientIP != wantIP {
			t.Errorf("got %q, want %q", cfg.ClientIP, wantIP)
		}
		used[cfg.ClientIP] = true
	}
}

func TestAllocClientIP_SubnetFull(t *testing.T) {
	used := map[string]bool{}
	for i := 2; i <= 254; i++ {
		used[fmt.Sprintf("10.0.0.%d", i)] = true
	}
	_, err := AllocClientIP("10.0.0.1/24", used, nil)
	if err == nil {
		t.Error("expected error when subnet full")
	}
}

func TestAllocClientIP_InvalidCIDR(t *testing.T) {
	_, err := AllocClientIP("not-a-cidr", nil, nil)
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
	_, err = AllocClientIP("", nil, nil)
	if err == nil {
		t.Error("expected error for empty CIDR")
	}
}
