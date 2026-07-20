package main

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRateFlag_Variants(t *testing.T) {
	cases := []struct {
		name      string
		mibs, bps string
		want      int64
		wantErr   string // 子串匹配
	}{
		{"mibs only", "1.5", "", int64(1.5 * 1024 * 1024), ""},
		{"bps only", "", "1572864", 1572864, ""},
		{"zero mibs", "0", "", 0, ""},
		{"zero bps", "", "0", 0, ""},
		{"both set", "1", "1024", 0, "mutually exclusive"},
		{"negative mibs", "-1", "", 0, "must not be negative"},
		{"negative bps", "", "-100", 0, "must not be negative"},
		{"bad mibs", "abc", "", 0, "parse failed"},
		{"bad bps", "", "1.5", 0, "parse failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRateFlag(tc.mibs, tc.bps)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err=%v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Errorf("want %d got %d", tc.want, got)
			}
		})
	}
}

func TestParseRateFlag_Unset(t *testing.T) {
	_, err := parseRateFlag("", "")
	if !errors.Is(err, errRateUnset) {
		t.Errorf("want errRateUnset, got %v", err)
	}
}

// TestParseBurstFlagKiB(0012 + N11 上界 2026-05-24):空 → errRateUnset,
// 负 / 非数字 / 超 16 MiB 报错,合法值返回字节数。
func TestParseBurstFlagKiB(t *testing.T) {
	if _, err := parseBurstFlagKiB(""); !errors.Is(err, errRateUnset) {
		t.Errorf("empty: want errRateUnset, got %v", err)
	}
	cases := []struct {
		in      string
		want    int64
		wantErr string
	}{
		{"0", 0, ""},
		{"64", 64 * 1024, ""},
		{"16384", 16 * 1024 * 1024, ""},
		{"-1", 0, "must not be negative"},
		{"abc", 0, "parse failed"},
		{"16385", 0, "exceed"},
		{"1048576", 0, "exceed"},
	}
	for _, tc := range cases {
		got, err := parseBurstFlagKiB(tc.in)
		if tc.wantErr != "" {
			if err == nil {
				t.Errorf("%q: want error %q, got nil", tc.in, tc.wantErr)
				continue
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: err=%v, want substring %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected err: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q: want %d got %d", tc.in, tc.want, got)
		}
	}
}

func TestBytesPerSecondHuman(t *testing.T) {
	cases := []struct {
		bps  int64
		want string
	}{
		{0, "-"},
		{-1, "-"},
		// 1 MiB/s = 1048576 byte/s,转 Mbps = 1048576*8/1e6 = 8.388608
		{1024 * 1024, "1.00 MiB/s (8.4 Mbps)"},
		{20 * 1024 * 1024, "20.00 MiB/s (167.8 Mbps)"},
	}
	for _, tc := range cases {
		got := bytesPerSecondHuman(tc.bps)
		if got != tc.want {
			t.Errorf("bps=%d: want %q got %q", tc.bps, tc.want, got)
		}
	}
}
