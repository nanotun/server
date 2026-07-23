package main

// pow_config_test.go - NewPoWService 的配置守卫(e_pow_cfg)。
//
// 契约:
//   - 零值 / 未配置 → 用推荐默认(8/14/2/22/300),不报错;
//   - 显式越界 / 负值 / 顺序倒置 → fail-fast 返回 error(不再静默夹断)。

import (
	"strings"
	"testing"
)

func TestNewPoWService_DefaultsFromZero(t *testing.T) {
	// 全零 = 未配置,应落到默认且不报错。
	svc, err := NewPoWService(nil, nil, 0, 0, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("零值配置应走默认不报错, got %v", err)
	}
	if svc.baseDifficulty != 8 || svc.rampDifficulty != 14 || svc.stepPerFailure != 2 ||
		svc.adaptiveCeiling != 22 || svc.ttlSec != 300 {
		t.Fatalf("默认值不符: base=%d ramp=%d step=%d ceil=%d ttl=%d",
			svc.baseDifficulty, svc.rampDifficulty, svc.stepPerFailure, svc.adaptiveCeiling, svc.ttlSec)
	}
}

func TestNewPoWService_ValidExplicit(t *testing.T) {
	svc, err := NewPoWService(nil, nil, 3, 8, 14, 2, 22, 300)
	if err != nil {
		t.Fatalf("合法显式配置不应报错, got %v", err)
	}
	if svc.baseDifficulty != 8 || svc.rampDifficulty != 14 || svc.adaptiveCeiling != 22 {
		t.Fatalf("显式合法值被改写: base=%d ramp=%d ceil=%d",
			svc.baseDifficulty, svc.rampDifficulty, svc.adaptiveCeiling)
	}
}

func TestNewPoWService_OutOfRangeFailFast(t *testing.T) {
	cases := []struct {
		name                       string
		fe, base, ramp, step, ceil int
		ttl                        int64
		wantSub                    string
	}{
		{"base_too_high", 0, 40, 14, 2, 22, 300, "base_difficulty"},
		{"base_below_min", 0, 3, 14, 2, 22, 300, "base_difficulty"},
		{"ramp_too_high", 0, 8, 99, 2, 22, 300, "ramp_difficulty"},
		{"ceiling_too_high", 0, 8, 14, 2, 27, 300, "adaptive_ceiling"},
		{"negative_failures_enable", -1, 8, 14, 2, 22, 300, "failures_enable"},
		{"negative_step", 0, 8, 14, -1, 22, 300, "step_per_failure"},
		{"negative_ttl", 0, 8, 14, 2, 22, -5, "ttl_sec"},
		{"ramp_below_base", 0, 20, 10, 2, 22, 300, "ramp_difficulty"},
		{"ceiling_below_ramp", 0, 8, 20, 2, 10, 300, "adaptive_ceiling"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPoWService(nil, nil, c.fe, c.base, c.ramp, c.step, c.ceil, c.ttl)
			if err == nil {
				t.Fatalf("越界配置应 fail-fast, got nil")
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("错误信息应点名 %q, got %q", c.wantSub, err.Error())
			}
		})
	}
}
