package main

import (
	"net/netip"
	"testing"
)

// 编码→解码往返：任意 (siteID, IPv4) 编码成 4via6 再解回，必须完全一致，且能被 is4via6 识别。
func TestVia6RoundTrip(t *testing.T) {
	cases := []struct {
		site uint16
		v4   string
	}{
		{1, "192.168.1.5"},
		{2, "192.168.1.5"}, // 同一 v4、不同站点 → 必得不同 4via6（消歧的核心）
		{0, "10.0.5.10"},
		{65535, "172.16.0.1"},
		{1234, "0.0.0.0"},
		{7, "255.255.255.255"},
	}
	var seen = map[netip.Addr]bool{}
	for _, c := range cases {
		v4 := netip.MustParseAddr(c.v4)
		addr, ok := encode4via6(c.site, v4)
		if !ok {
			t.Fatalf("encode(%d,%s) 失败", c.site, c.v4)
		}
		if !is4via6(addr) {
			t.Fatalf("encode 出的 %s 未被 is4via6 识别", addr)
		}
		site2, v42, ok := decode4via6(addr)
		if !ok {
			t.Fatalf("decode(%s) 失败", addr)
		}
		if site2 != c.site || v42 != v4 {
			t.Fatalf("往返不符: 期望(%d,%s) 得到(%d,%s) via %s", c.site, v4, site2, v42, addr)
		}
		seen[addr] = true
	}
	// (site=1,.5) 与 (site=2,.5) 必须是两个不同地址
	a1, _ := encode4via6(1, netip.MustParseAddr("192.168.1.5"))
	a2, _ := encode4via6(2, netip.MustParseAddr("192.168.1.5"))
	if a1 == a2 {
		t.Fatalf("同 v4 不同站点得到相同 4via6，消歧失败: %s", a1)
	}
}

// 已知向量：siteID=1, 192.168.1.5 → fdbc:4a60:0:0:0:1:c0a8:0105。
func TestVia6KnownVector(t *testing.T) {
	addr, ok := encode4via6(1, netip.MustParseAddr("192.168.1.5"))
	if !ok {
		t.Fatal("encode 失败")
	}
	want := netip.MustParseAddr("fdbc:4a60:0:0:0:1:c0a8:0105")
	if addr != want {
		t.Fatalf("已知向量不符: 期望 %s 得到 %s", want, addr)
	}
}

// 非 4via6 地址（mesh vIP v6 / 公网 v6 / loopback / 相邻但不同前缀）均不应被识别或解码。
func TestVia6RejectNonVia6(t *testing.T) {
	for _, s := range []string{
		"fd00:200::1",    // mesh vIP v6 段
		"2001:db8::1",    // 公网 v6
		"::1",            // loopback
		"fdbc:4a61::1",   // 相邻但前缀不同（/64 边界）
		"fdbc:4a60:1::1", // 前缀 /64 之外（第 4 组非 0）
	} {
		a := netip.MustParseAddr(s)
		if is4via6(a) {
			t.Fatalf("%s 不应被识别为 4via6", s)
		}
		if _, _, ok := decode4via6(a); ok {
			t.Fatalf("%s 不应能 decode", s)
		}
	}
}

// encode 只接受 IPv4 输入；IPv6 输入必须拒绝。
func TestVia6EncodeRejectsV6Input(t *testing.T) {
	if _, ok := encode4via6(1, netip.MustParseAddr("::1")); ok {
		t.Fatal("encode 不应接受 IPv6 输入")
	}
	if _, ok := encode4via6(1, netip.MustParseAddr("2001:db8::1")); ok {
		t.Fatal("encode 不应接受 IPv6 输入")
	}
}
