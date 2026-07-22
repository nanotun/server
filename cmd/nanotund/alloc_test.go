package main

import (
	"fmt"
	"testing"
)

func TestPreferredVIPUsable(t *testing.T) {
	const gw4 = "10.0.0.1/24"
	const gw6 = "fd00::1/64"
	cases := []struct {
		name string
		cidr string
		vip  string
		used map[string]bool
		want bool
	}{
		{"ok-v4", gw4, "10.0.0.7", nil, true},
		{"empty", gw4, "", nil, false},
		{"used", gw4, "10.0.0.7", map[string]bool{"10.0.0.7": true}, false},
		{"out-of-subnet", gw4, "10.0.1.7", nil, false},
		{"is-gateway", gw4, "10.0.0.1", nil, false},
		{"is-network", gw4, "10.0.0.0", nil, false},
		{"garbage", gw4, "not-an-ip", nil, false},
		{"ok-v6", gw6, "fd00::7", nil, true},
		{"is-gateway-v6", gw6, "fd00::1", nil, false},
		{"is-network-v6", gw6, "fd00::", nil, false},
	}
	for _, tc := range cases {
		if got := preferredVIPUsable(tc.cidr, tc.vip, tc.used); got != tc.want {
			t.Errorf("%s: preferredVIPUsable(%q,%q) = %v, want %v", tc.name, tc.cidr, tc.vip, got, tc.want)
		}
	}
}

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
