package main

import (
	"testing"

	"github.com/nanotun/server/config"
	"golang.org/x/time/rate"
)

func TestLinkRatesForPlatform_GlobalAndKCPFallback(t *testing.T) {
	gw := &gatewayState{cfg: &config.Config{
		Server: config.ServerConfig{UploadRate: 100, DownloadRate: 200},
		KCP:    config.KCPConfig{UploadRate: 10, DownloadRate: 20},
	}}
	u, d := linkRatesForPlatform(gw, "")
	if u != 100 || d != 200 {
		t.Fatalf("want 100,200 got %d,%d", u, d)
	}

	gw2 := &gatewayState{cfg: &config.Config{
		Server: config.ServerConfig{},
		KCP:    config.KCPConfig{UploadRate: 11, DownloadRate: 22},
	}}
	u, d = linkRatesForPlatform(gw2, "linux")
	if u != 11 || d != 22 {
		t.Fatalf("kcp fallback want 11,22 got %d,%d", u, d)
	}
}

func TestLinkRatesForPlatform_OverrideByPlatform(t *testing.T) {
	gw := &gatewayState{cfg: &config.Config{
		Server: config.ServerConfig{
			UploadRate:   1000,
			DownloadRate: 2000,
			RateLimitByPlatform: map[string]config.LinkRateLimitPlatform{
				"linux":   {UploadRate: 100, DownloadRate: 0},
				"android": {UploadRate: 0, DownloadRate: 300},
			},
		},
		KCP: config.KCPConfig{},
	}}
	u, d := linkRatesForPlatform(gw, "Linux")
	if u != 100 || d != 2000 {
		t.Fatalf("linux: want upload=100 download=2000 (0=no override) got %d,%d", u, d)
	}
	u, d = linkRatesForPlatform(gw, "android")
	if u != 1000 || d != 300 {
		t.Fatalf("android: want 1000,300 got %d,%d", u, d)
	}
	u, d = linkRatesForPlatform(gw, "windows")
	if u != 1000 || d != 2000 {
		t.Fatalf("unknown platform: want 1000,2000 got %d,%d", u, d)
	}
}

// TestEffectiveLinkRates_FourLayer:0011 四级回退取 min。
//
// 输入:toml=1000/2000 + linux 平台 override 100/none(沿用) + settings=50/0 + device=30/0
//
// 预期 eff_up = min(1000, 100[linux override], 50[settings], 30[device]) = 30
//
//	eff_down = min(2000[toml] = no override no settings = 2000, 0=不限device) = 2000
//
// 这个用例同时覆盖「某一层 0 表示不在该层强制」的语义,以及「device > settings > toml」
// 层级排序在 min 语义下其实只算「都参与 min」。
func TestEffectiveLinkRates_FourLayer(t *testing.T) {
	gw := &gatewayState{cfg: &config.Config{
		Server: config.ServerConfig{
			UploadRate:   1000,
			DownloadRate: 2000,
			RateLimitByPlatform: map[string]config.LinkRateLimitPlatform{
				"linux": {UploadRate: 100, DownloadRate: 0},
			},
		},
	}}
	defaults := storeRateDefaultsView{UploadBPS: 50, DownloadBPS: 0}
	up, down := effectiveLinkRates(gw, "linux", 30, 0, defaults)
	if up != 30 {
		t.Errorf("up: want 30 (min of 1000,100,50,30), got %d", up)
	}
	if down != 2000 {
		t.Errorf("down: want 2000 (toml only, settings=0, device=0), got %d", down)
	}
}

// TestEffectiveLinkRates_NoOverrides:全部 0 时只走 toml,与 linkRatesForPlatform 等价。
func TestEffectiveLinkRates_NoOverrides(t *testing.T) {
	gw := &gatewayState{cfg: &config.Config{
		Server: config.ServerConfig{UploadRate: 1000, DownloadRate: 2000},
	}}
	up, down := effectiveLinkRates(gw, "", 0, 0, storeRateDefaultsView{})
	if up != 1000 || down != 2000 {
		t.Errorf("no overrides: want 1000/2000 got %d/%d", up, down)
	}
}

// TestEffectiveLinkRates_DeviceCanLooserDoesNotHelp:device 设了 5000(比 toml 大),
// effective 仍是 toml 1000 —— 「device 设得更宽」绝不能放宽更严的层。
func TestEffectiveLinkRates_DeviceCanNotRelax(t *testing.T) {
	gw := &gatewayState{cfg: &config.Config{
		Server: config.ServerConfig{UploadRate: 1000, DownloadRate: 2000},
	}}
	up, down := effectiveLinkRates(gw, "", 5000, 5000, storeRateDefaultsView{})
	if up != 1000 || down != 2000 {
		t.Errorf("device wider than toml: want toml win (1000/2000), got %d/%d", up, down)
	}
}

// TestEffectiveLinkRates_SettingsCoversTomlMissing:toml 全 0,settings = 8000/0,
// device = 0/4000 → 上行走 settings(8000),下行走 device(4000)。覆盖「toml 真不限时
// settings/device 能落地」分支。
func TestEffectiveLinkRates_SettingsCoversTomlMissing(t *testing.T) {
	gw := &gatewayState{cfg: &config.Config{}}
	up, down := effectiveLinkRates(gw, "", 0, 4000, storeRateDefaultsView{UploadBPS: 8000})
	if up != 8000 || down != 4000 {
		t.Errorf("toml empty: want settings.up=8000 device.down=4000, got %d/%d", up, down)
	}
}

// TestRateLimitedConn_SetLimits_HotSwap:rateLimitedConn 在 nil ↔ limiter ↔ 改 limit
// 之间能热切换,且不会因为 nil 写穿。
// 0012:burst 也跟着热改,验证 SetBurst 路径复用 limiter。
func TestRateLimitedConn_SetLimits_HotSwap(t *testing.T) {
	rwc := newRateLimitedConn(nopReadWriteCloser{}, nil, nil, nil)
	if u, d, _, _ := rwc.snapshotLimits(); u != 0 || d != 0 {
		t.Fatalf("init: want 0/0, got %d/%d", u, d)
	}

	// nil → 100 字节/秒 burst=64K
	rwc.SetUploadLimit(100, 64*1024)
	if u, _, ub, _ := rwc.snapshotLimits(); u != 100 || ub != 64*1024 {
		t.Errorf("after set up=100/64K: got %d/%d", u, ub)
	}

	// 100 → 500(SetLimit 路径,复用 limiter),burst 同时改 128K
	prev := rwc.uploadLimiter
	rwc.SetUploadLimit(500, 128*1024)
	if rwc.uploadLimiter != prev {
		t.Errorf("expect limiter object reused, was replaced")
	}
	if u, _, ub, _ := rwc.snapshotLimits(); u != 500 || ub != 128*1024 {
		t.Errorf("after set up=500/128K: got %d/%d", u, ub)
	}

	// 清回 nil(限速解除)
	rwc.SetUploadLimit(0, 64*1024)
	if u, _, _, _ := rwc.snapshotLimits(); u != 0 {
		t.Errorf("after clear up: got %d", u)
	}

	// 同时改下行,interleave 验证两方向独立
	rwc.SetDownloadLimit(1000, 64*1024)
	rwc.SetUploadLimit(200, 64*1024)
	if u, d, _, _ := rwc.snapshotLimits(); u != 200 || d != 1000 {
		t.Errorf("interleave: want 200/1000, got %d/%d", u, d)
	}

	// 防御:burst=0 应该 fallback 到代码 default,不至于 NewLimiter panic
	rwc2 := newRateLimitedConn(nopReadWriteCloser{}, nil, nil, nil)
	rwc2.SetUploadLimit(50, 0)
	if u, _, ub, _ := rwc2.snapshotLimits(); u != 50 || ub == 0 {
		t.Errorf("burst=0 should fallback to non-zero default, got rate=%d burst=%d", u, ub)
	}
}

// TestEffectiveBurst 覆盖 0012 burst 选择逻辑 + N11 上界 clamp:
//
//	0/负 → default、<4K → clamp 上、>16MiB → clamp 下、[4K,16M] → 原值。
func TestEffectiveBurst(t *testing.T) {
	cases := []struct {
		name string
		in   int64
		want int
	}{
		{"zero falls back to default", 0, defaultRateBurstBytes},
		{"negative falls back to default", -1, defaultRateBurstBytes},
		{"too small is clamped up", 1024, minRateBurstBytes},
		{"min boundary unchanged", int64(minRateBurstBytes), minRateBurstBytes},
		{"normal value passes through", 256 * 1024, 256 * 1024},
		// N11:上界保护。
		{"max boundary unchanged", int64(maxRateBurstBytes), maxRateBurstBytes},
		{"just over max clamped down", int64(maxRateBurstBytes) + 1, maxRateBurstBytes},
		{"1 GiB clamped to max", 1 << 30, maxRateBurstBytes},
		{"int64 max clamped to max", 1 << 62, maxRateBurstBytes},
	}
	for _, c := range cases {
		if got := effectiveBurst(c.in); got != c.want {
			t.Errorf("%s: effectiveBurst(%d) = %d, want %d", c.name, c.in, got, c.want)
		}
	}
}

// nopReadWriteCloser:仅给 rateLimitedConn 单测做 raw 占位,不实际 IO。
type nopReadWriteCloser struct{}

func (nopReadWriteCloser) Read(p []byte) (int, error)  { return 0, nil }
func (nopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWriteCloser) Close() error                { return nil }

// _ 让编译器闭嘴:rate 包仅在 rateLimitedConn 内部使用,但这里我们 inspect 字段,
// 需要导入 rate 才能引用 rate.Limit 在断言里。当前不直接用,占位。
var _ = rate.Limit(0)
