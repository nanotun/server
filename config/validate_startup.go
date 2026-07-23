package config

// validate_startup.go — 把 cmd/nanotund 启动期若干 fail-fast 语义校验抽成 config
// 包方法,让 `nanotun-admin config lint` 能在**重启前**预演这些"会让 server 拒绝
// 启动"的配置错误。
//
// 背景(第七轮深扫 MED):`config lint` 的 lintSemantic 此前已覆盖 Validate / hy2 /
// REALITY / exit,但漏了三处同为启动期 Fatal(util.ExitConfigSemantic)的检查:
//   - [server.pow] 各难度字段区间 + base ≤ ramp ≤ ceiling 顺序(见 pow.go NewPoWService);
//   - [server] tls_cert_file / tls_key_file 半配(见 server.go);
//   - [server] jump_host_firewall=true 却空 jump_host_allowed_ips(见 server.go)。
// 漏掉的后果:一份能过 lint 的配置照样在真正重启时 Fatal,lint「重启前拦截」的价值缩水。
//
// 这三个方法是这些 invariant 的**单一事实来源**:PoW 难度边界(PoWMinDifficulty /
// PoWMaxDifficulty)由 pow.go 别名引用,tls/jump_host 的语义与 server.go 同步(见各自注释)。

import (
	"fmt"
	"strings"
)

// PoW 难度边界 —— PoW 难度取值的单一事实来源(single source of truth)。
//
// cmd/nanotund/pow.go 的 powMinDifficulty / powMaxDifficulty 别名到这里,
// PoWConfig.Validate(供 `config lint`)也据此在重启前预演 NewPoWService 的 fail-fast,
// 三处永不漂移。数值语义详见 pow.go 常量注释:4=与旧集中式后端/客户端一致的下界;
// 22-bit≈M1 10s / iPhone 15s 封顶。
const (
	PoWMinDifficulty = 4
	PoWMaxDifficulty = 22
)

// Validate 预演 cmd/nanotund NewPoWService 的启动期 fail-fast:各难度字段的取值区间
// + base ≤ ramp ≤ ceiling 顺序约束。零值一律视作「未配 → 用默认」(8/14/2/22/300),
// 与运行期语义一致,因此一份「全缺省」的 [server.pow] 永远通过。
//
// 与 NewPoWService 的差异:本方法**不**构造服务、不生成 HMAC key,纯做参数校验,供
// `config lint` 在重启前拦截「会让 server 拒绝启动」的 PoW 配置。校验步骤必须与
// NewPoWService 同步:先查区间(任一越界即返回,避免用被污染的值做二次误导的顺序校验),
// 干净后再在「零值→默认」解析出的值上查顺序。
func (p PoWConfig) Validate() error {
	var errs []string
	if p.FailuresEnable < 0 {
		errs = append(errs, fmt.Sprintf("[server.pow].failures_enable=%d 不能为负(0=从第 1 次失败即 ramp)", p.FailuresEnable))
	}
	// 各难度字段:==0 视作未配(用默认);其余(含负数)必须落在 [PoWMinDifficulty, PoWMaxDifficulty]。
	checkRange := func(name string, v, def int) {
		if v != 0 && (v < PoWMinDifficulty || v > PoWMaxDifficulty) {
			errs = append(errs, fmt.Sprintf("[server.pow].%s=%d 越界(须 %d..%d;0=用默认 %d)",
				name, v, PoWMinDifficulty, PoWMaxDifficulty, def))
		}
	}
	checkRange("base_difficulty", p.BaseDifficulty, 8)
	checkRange("ramp_difficulty", p.RampDifficulty, 14)
	checkRange("adaptive_ceiling", p.AdaptiveCeiling, 22)
	if p.StepPerFailure < 0 {
		errs = append(errs, fmt.Sprintf("[server.pow].step_per_failure=%d 不能为负(0=用默认 2)", p.StepPerFailure))
	}
	if p.TTLSec < 0 {
		errs = append(errs, fmt.Sprintf("[server.pow].ttl_sec=%d 不能为负(0=用默认 300)", p.TTLSec))
	}
	if len(errs) > 0 {
		return fmt.Errorf("[server.pow] 配置非法:\n  - %s", strings.Join(errs, "\n  - "))
	}
	// 顺序约束在「零值→默认」解析后的值上做(与 NewPoWService 一致):倒置意味着
	// 「失败后难度反而更低」,让自适应升级失效。
	base := powValOrDefault(p.BaseDifficulty, 8)
	ramp := powValOrDefault(p.RampDifficulty, 14)
	ceil := powValOrDefault(p.AdaptiveCeiling, 22)
	if ramp < base {
		errs = append(errs, fmt.Sprintf("[server.pow].ramp_difficulty(%d) 必须 ≥ base_difficulty(%d)", ramp, base))
	}
	if ceil < ramp {
		errs = append(errs, fmt.Sprintf("[server.pow].adaptive_ceiling(%d) 必须 ≥ ramp_difficulty(%d)", ceil, ramp))
	}
	if len(errs) > 0 {
		return fmt.Errorf("[server.pow] 配置非法:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func powValOrDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// ValidateTLSPair 预演 cmd/nanotund 启动期「[server] tls_cert_file 与 tls_key_file
// 须同时配置或同时留空」的 fail-fast:两者同为对外 HTTPS/WSS 的开关,半配(只填一个)
// 会让 TLS 监听起不来,是明确的配置错误。语义与 server.go 一致(TrimSpace 后异或判空)。
//
// 注意:本方法只管 [server] 的一对;[hysteria] 另有自己的 tls_cert_file/tls_key_file,
// 由 ValidateHysteriaCredentials 覆盖。
func (s ServerConfig) ValidateTLSPair() error {
	cert := strings.TrimSpace(s.TLSCertFile)
	key := strings.TrimSpace(s.TLSKeyFile)
	if (cert != "") != (key != "") {
		return fmt.Errorf("[server] tls_cert_file 与 tls_key_file 须同时配置或同时留空")
	}
	return nil
}

// ValidateJumpHostFirewall 预演 cmd/nanotund 启动期「启用 jump_host_firewall 必须提供
// jump_host_allowed_ips 名单」的 fail-fast:名单空 + 开 firewall = 「以为开了限制、实际
// 全网开放」陷阱。语义与 server.go 一致(仅在 firewall 开启时校验 len==0)。
func (s ServerConfig) ValidateJumpHostFirewall() error {
	if !s.JumpHostFirewall {
		return nil
	}
	if len(s.JumpHostAllowedIPs) == 0 {
		return fmt.Errorf("[server] 启用 jump_host_firewall 必须在 [server].jump_host_allowed_ips 提供跳板机 IPv4 名单(留空等于全网开放,这通常不是你想要的)。要么填名单,要么把 jump_host_firewall 设为 false。")
	}
	return nil
}
