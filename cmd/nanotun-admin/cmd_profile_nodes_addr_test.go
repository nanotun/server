package main

// cmd_profile_nodes_addr_test.go - 入口节点地址拼装(第五轮深扫 HIGH,IPv6 必须加方括号)。

import "testing"

func TestAttachEntryAddresses_IPv6Bracketed(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		realPort uint16
		hy2Port  uint16
		hy2Ports string
		wantReal string
		wantHy2  string
	}{
		{"ipv4_single", "1.2.3.4", 8443, 443, "", "1.2.3.4:8443", "1.2.3.4:443"},
		{"ipv6_single", "2001:db8::1", 8443, 443, "", "[2001:db8::1]:8443", "[2001:db8::1]:443"},
		{"domain_single", "hk.example.com", 8443, 443, "", "hk.example.com:8443", "hk.example.com:443"},
		{"ipv6_default_ports", "2001:db8::1", 0, 0, "", "[2001:db8::1]:8443", "[2001:db8::1]:443"},
		{"ipv6_hy2_porthop", "2001:db8::1", 8443, 0, "443,8443", "[2001:db8::1]:8443", "[2001:db8::1]:443,8443"},
		{"ipv4_hy2_porthop", "1.2.3.4", 8443, 0, "443,8443", "1.2.3.4:8443", "1.2.3.4:443,8443"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &profileSchemaReality{Port: c.realPort}
			h := &profileSchemaHy2{UDPPort: c.hy2Port, UDPPorts: c.hy2Ports}
			attachEntryAddresses(c.host, r, h)
			if r.Address != c.wantReal {
				t.Errorf("reality address = %q, want %q", r.Address, c.wantReal)
			}
			if h.Address != c.wantHy2 {
				t.Errorf("hy2 address = %q, want %q", h.Address, c.wantHy2)
			}
			// 拼进 address 后端口字段必须清零,避免与 address 重复。
			if r.Port != 0 || h.UDPPort != 0 || h.UDPPorts != "" {
				t.Errorf("port fields not cleared: reality.Port=%d hy2.UDPPort=%d hy2.UDPPorts=%q",
					r.Port, h.UDPPort, h.UDPPorts)
			}
		})
	}
}
