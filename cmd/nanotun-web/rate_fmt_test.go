package main

import "testing"

func TestParseRateMiBs(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"  ", 0, false},
		{"0", 0, false},
		{"1", 1024 * 1024, false},
		{"1.5", int64(1.5 * 1024 * 1024), false},
		{"20", 20 * 1024 * 1024, false},
		{"-1", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := parseRateMiBs(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: want error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected err %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("%q: want %d got %d", c.in, c.want, got)
		}
	}
}

func TestRateBytesToMiBsString_Roundtrip(t *testing.T) {
	// 0012:Go 1.21+ 禁止 const float→int64 直接 truncate(精度风险),
	// 把 2.7 / 1.5 这种用 var 中转。
	const oneMiB = 1024 * 1024
	v15 := int64(1.5 * oneMiB)
	v27Float := 2.7
	v27 := int64(v27Float * oneMiB)

	cases := []struct {
		bps  int64
		want string
	}{
		{0, ""},
		{-1, ""},
		{oneMiB, "1"},
		{v15, "1.5"},
		{10 * oneMiB, "10"},
		// 用户输 2.7 → 落库 ~2831155 byte → 回显应该被 round 成短字符串,
		// 不再回显成 "2.7000007629394531" 这种巨丑值。
		{v27, "2.7"},
		// 100 MiB/s 整数走 %g 不带小数。
		{100 * oneMiB, "100"},
	}
	for _, c := range cases {
		got := rateBytesToMiBsString(c.bps)
		if got != c.want {
			t.Errorf("%d: want %q got %q", c.bps, c.want, got)
		}
	}
}

// TestParseBurstKiB_Roundtrip:0012 burst KiB 解析 + 反向格式化。
func TestParseBurstKiB_Roundtrip(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"64", 64 * 1024, false},
		{"256", 256 * 1024, false},
		{"-1", 0, true},
		{"abc", 0, true},
		// N11(2026-05-24):上界 16 MiB(16384 KiB)。
		{"16384", 16 * 1024 * 1024, false}, // 边界值放行
		{"16385", 0, true},                 // 超 1 KiB 报错
		{"1048576", 0, true},               // 1 GiB 直接拒
	}
	for _, c := range cases {
		got, err := parseBurstKiB(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: want error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected err %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("%q: want %d got %d", c.in, c.want, got)
		}
	}

	if got := rateBytesToKiBString(64 * 1024); got != "64" {
		t.Errorf("64 KiB roundtrip: want \"64\" got %q", got)
	}
	if got := rateBytesToKiBString(0); got != "" {
		t.Errorf("0 should empty: got %q", got)
	}
	if got := rateBurstHuman(0); got != "—" {
		t.Errorf("rateBurstHuman(0) want — got %q", got)
	}
	if got := rateBurstHuman(64 * 1024); got != "64 KiB" {
		t.Errorf("rateBurstHuman(64KiB) want \"64 KiB\" got %q", got)
	}
}

func TestRateBytesHuman(t *testing.T) {
	if got := rateBytesHuman(0); got != "—" {
		t.Errorf("0: want '—' got %q", got)
	}
	got := rateBytesHuman(20 * 1024 * 1024)
	want := "20.00 MiB/s (167.8 Mbps)"
	if got != want {
		t.Errorf("20 MiB/s: want %q got %q", want, got)
	}
}
