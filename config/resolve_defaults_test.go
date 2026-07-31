package config

import "testing"

// 这一族 Resolve* 是「0 = 未配 → 用默认」的**单一事实来源**:启动时构建服务用它,
// SIGHUP 判断「改动是否真的改变了生效值」也用它。
//
// 它们此前在本包内 0% 覆盖 —— 只被 cmd/nanotund 的测试间接调到。而这恰恰是最不该松的地方:
// 2026-07-31 那个 PoW 缺陷(failures_enable 漏了零值默认,导致 base_difficulty 永不可达、
// 每次正常登录白付 64 倍哈希)的根因就是**默认值离字段声明太远、没人核对**。默认值搬到本包
// 之后,守住它们的断言也该在本包。
//
// 两侧都要钉:
//   - 0 → 默认(漏了就是上面那个缺陷的形状:某个旋钮悄悄变成死配置);
//   - 非 0 → 原样返回(错了就是「运维写的值被静默改写」,比报错更危险 —— NewPoWService
//     顶部那段注释专门讲过这条:安全参数被悄悄夹断过一次,此后改成非法即报错)。

func TestPoWConfig_ResolveUsesDefaultsOnlyForZero(t *testing.T) {
	var unset PoWConfig
	for _, tc := range []struct {
		name       string
		got, want  int
		explicit   func() int
		wantExplic int
	}{
		{"failures_enable", unset.ResolveFailuresEnable(), PoWDefaultFailuresEnable,
			func() int { return PoWConfig{FailuresEnable: 5}.ResolveFailuresEnable() }, 5},
		{"base_difficulty", unset.ResolveBaseDifficulty(), PoWDefaultBaseDifficulty,
			func() int { return PoWConfig{BaseDifficulty: 6}.ResolveBaseDifficulty() }, 6},
		{"ramp_difficulty", unset.ResolveRampDifficulty(), PoWDefaultRampDifficulty,
			func() int { return PoWConfig{RampDifficulty: 12}.ResolveRampDifficulty() }, 12},
		{"step_per_failure", unset.ResolveStepPerFailure(), PoWDefaultStepPerFailure,
			func() int { return PoWConfig{StepPerFailure: 3}.ResolveStepPerFailure() }, 3},
		{"adaptive_ceiling", unset.ResolveAdaptiveCeiling(), PoWDefaultAdaptiveCeiling,
			func() int { return PoWConfig{AdaptiveCeiling: 17}.ResolveAdaptiveCeiling() }, 17},
	} {
		if tc.got != tc.want {
			t.Errorf("%s 未配时应取默认 %d,得到 %d —— 漏了零值默认就会让这个旋钮变成死配置",
				tc.name, tc.want, tc.got)
		}
		if got := tc.explicit(); got != tc.wantExplic {
			t.Errorf("%s 显式配 %d 却返回 %d —— 运维写的值被静默改写",
				tc.name, tc.wantExplic, got)
		}
	}

	// ttl_sec 是 int64,单独走一遍。
	if got := unset.ResolveTTLSec(); got != PoWDefaultTTLSec {
		t.Errorf("ttl_sec 未配时应取默认 %d,得到 %d", PoWDefaultTTLSec, got)
	}
	if got := (PoWConfig{TTLSec: 60}).ResolveTTLSec(); got != 60 {
		t.Errorf("ttl_sec 显式配 60 却返回 %d", got)
	}
}

// TestPoWConfig_ResolveKeepsNegativesAsWritten 负值原样返回,由 NewPoWService fail-fast。
//
// Resolve 只做「零值 → 默认」,**不**替调用方纠正非法值:悄悄把负数当成默认会让一份非法配置
// 静默跑起来,而现在的约定是启动期拒绝(见 NewPoWService)。这条钉的就是「别顺手多做一步」。
func TestPoWConfig_ResolveKeepsNegativesAsWritten(t *testing.T) {
	if got := (PoWConfig{FailuresEnable: -1}).ResolveFailuresEnable(); got != -1 {
		t.Errorf("负值应原样返回好让 NewPoWService 拒绝启动,得到 %d", got)
	}
	if got := (PoWConfig{TTLSec: -5}).ResolveTTLSec(); got != -5 {
		t.Errorf("负值应原样返回,得到 %d", got)
	}
}

// TestTUNConfig_ResolveConnlimitPerIP 每虚拟 IP 并发上限的生效值。
//
// 这里 ≤0(不只是 ==0)都取默认:和 PoW 那族不同,负数在这一族没有「留给启动期拒绝」的语义,
// iptables 侧也没法表达负的连接数。
func TestTUNConfig_ResolveConnlimitPerIP(t *testing.T) {
	var unset TUNConfig
	if got := unset.ResolveTCPConnlimitPerIP(); got != DefaultConnlimitPerIP {
		t.Errorf("tcp 未配时应取默认 %d,得到 %d", DefaultConnlimitPerIP, got)
	}
	if got := unset.ResolveUDPConnlimitPerIP(); got != DefaultConnlimitPerIP {
		t.Errorf("udp 未配时应取默认 %d,得到 %d", DefaultConnlimitPerIP, got)
	}

	explicit := TUNConfig{TCPConnlimitPerIP: 5, UDPConnlimitPerIP: 7}
	if got := explicit.ResolveTCPConnlimitPerIP(); got != 5 {
		t.Errorf("tcp 显式配 5 却返回 %d", got)
	}
	if got := explicit.ResolveUDPConnlimitPerIP(); got != 7 {
		t.Errorf("udp 显式配 7 却返回 %d", got)
	}

	// 负数与 0 同义:都回默认(而不是「关闭上限」——那会是个静默去掉防护的语义)。
	neg := TUNConfig{TCPConnlimitPerIP: -1, UDPConnlimitPerIP: -9}
	if got := neg.ResolveTCPConnlimitPerIP(); got != DefaultConnlimitPerIP {
		t.Errorf("tcp 配负数应回默认 %d,得到 %d —— 不能理解成「不限制」", DefaultConnlimitPerIP, got)
	}
	if got := neg.ResolveUDPConnlimitPerIP(); got != DefaultConnlimitPerIP {
		t.Errorf("udp 配负数应回默认 %d,得到 %d", DefaultConnlimitPerIP, got)
	}
}
