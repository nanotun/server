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
	"net"
	"strconv"
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
		errs = append(errs, fmt.Sprintf("[server.pow].failures_enable=%d must not be negative (0 = ramp starting from the 1st failure)", p.FailuresEnable))
	}
	// 各难度字段:==0 视作未配(用默认);其余(含负数)必须落在 [PoWMinDifficulty, PoWMaxDifficulty]。
	checkRange := func(name string, v, def int) {
		if v != 0 && (v < PoWMinDifficulty || v > PoWMaxDifficulty) {
			errs = append(errs, fmt.Sprintf("[server.pow].%s=%d out of range (must be %d..%d; 0 = use the default %d)",
				name, v, PoWMinDifficulty, PoWMaxDifficulty, def))
		}
	}
	checkRange("base_difficulty", p.BaseDifficulty, 8)
	checkRange("ramp_difficulty", p.RampDifficulty, 14)
	checkRange("adaptive_ceiling", p.AdaptiveCeiling, 22)
	if p.StepPerFailure < 0 {
		errs = append(errs, fmt.Sprintf("[server.pow].step_per_failure=%d must not be negative (0 = use the default 2)", p.StepPerFailure))
	}
	if p.TTLSec < 0 {
		errs = append(errs, fmt.Sprintf("[server.pow].ttl_sec=%d must not be negative (0 = use the default 300)", p.TTLSec))
	}
	if len(errs) > 0 {
		return fmt.Errorf("[server.pow] invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	// 顺序约束在「零值→默认」解析后的值上做(与 NewPoWService 一致):倒置意味着
	// 「失败后难度反而更低」,让自适应升级失效。
	base := powValOrDefault(p.BaseDifficulty, 8)
	ramp := powValOrDefault(p.RampDifficulty, 14)
	ceil := powValOrDefault(p.AdaptiveCeiling, 22)
	if ramp < base {
		errs = append(errs, fmt.Sprintf("[server.pow].ramp_difficulty(%d) must be >= base_difficulty(%d)", ramp, base))
	}
	if ceil < ramp {
		errs = append(errs, fmt.Sprintf("[server.pow].adaptive_ceiling(%d) must be >= ramp_difficulty(%d)", ceil, ramp))
	}
	if len(errs) > 0 {
		return fmt.Errorf("[server.pow] invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
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
		return fmt.Errorf("[server] tls_cert_file and tls_key_file must both be set or both be left empty")
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
		return fmt.Errorf("[server] enabling jump_host_firewall requires a jump host IPv4 allowlist in [server].jump_host_allowed_ips (leaving it empty is the same as opening up to the whole internet, which is usually not what you want). Either fill in the allowlist, or set jump_host_firewall to false.")
	}
	// 第十二轮深扫 MED:逐条校验必须是可解析的 **IPv4 地址**(runtime sanitizeJumpHostIPv4s 只认 net.ParseIP
	// 的 IPv4:CIDR / 主机名 / IPv6 一律静默丢弃)。此前只查 len==0 → 配 ["not-an-ip"] 能过 lint 与启动,运行期
	// 全被丢 → ensureLoopbackIPv4Allowlist 退化为仅 127.0.0.1 → 预期跳板机被静默挡死(自锁)。任一非法即报错,
	// 且要求至少留下一个有效 IPv4。空白项容忍(与 runtime skip 空串一致)。
	var errs []string
	valid := 0
	for _, raw := range s.JumpHostAllowedIPs {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if ip := net.ParseIP(e); ip == nil || ip.To4() == nil {
			errs = append(errs, fmt.Sprintf("%q is not a valid IPv4 address (CIDR / hostname / IPv6 are not accepted)", raw))
			continue
		}
		valid++
	}
	if len(errs) > 0 {
		return fmt.Errorf("[server].jump_host_allowed_ips has invalid entries (the runtime silently drops them, so the jump host you meant to allow ends up locked out; fix them to valid IPv4 or remove them):\n  - %s",
			strings.Join(errs, "\n  - "))
	}
	if valid == 0 {
		return fmt.Errorf("[server].jump_host_allowed_ips holds nothing but blank entries, which with jump_host_firewall enabled allows 127.0.0.1 only (the jump host you meant to allow ends up locked out). Add at least one valid IPv4, or set jump_host_firewall to false.")
	}
	return nil
}

// ValidateJumpHostProtectedPorts 严格校验 [server].jump_host_protected_ports 语法(仅在
// jump_host_firewall 启用时有意义 —— 关闭时该字段被完全忽略,不校验)。
//
// 第七轮深扫 MED:runtime parseJumpHostProtectedPorts 对非法条目「Warn 后跳过」;若条目**全**非法
// 会退化为只保护 listen_addr TCP,hy2 UDP / REALITY 端口裸奔而运维以为已被跳板机围栏覆盖;**部分**
// 非法则只有部分端口被保护。这是与已修的 exit_dns_redirect 拼错同类的静默 fail-open。这里改成:启用
// firewall 且列表非空时,任一条目语法非法即报错 —— 启动路径 FatalExit(ExitConfigSemantic)、lint 退非零,
// 逼运维改对或清空(清空 = 沿用历史默认:只保护 listen_addr TCP)。语法与 parseJumpHostProtectedPorts
// 对齐:proto/port 或 proto/start-end 或 proto/start:end,proto ∈ {tcp,udp},端口 1..65535。空白项容忍
// (与 runtime skip 空串一致,不算错)。
func (s ServerConfig) ValidateJumpHostProtectedPorts() error {
	if !s.JumpHostFirewall {
		return nil
	}
	var errs []string
	for _, raw := range s.JumpHostProtectedPorts {
		e := strings.TrimSpace(strings.ToLower(raw))
		if e == "" {
			continue
		}
		if msg := jumpHostPortSpecError(e); msg != "" {
			errs = append(errs, fmt.Sprintf("%q: %s", raw, msg))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("[server].jump_host_protected_ports has invalid entries (with jump_host_firewall enabled they must not be silently skipped, otherwise the hy2/REALITY ports are left unprotected; either fix them, or clear the list to keep the default of protecting only listen_addr TCP):\n  - %s",
			strings.Join(errs, "\n  - "))
	}
	return nil
}

// ValidateTUNSubnets 预演 cmd/nanotund 启动期两处 TUN 网段 fail-fast:
//   - [tun].subnets 与 subnets_v6 **同时为空**(去空白后)→ server.go 直接 FatalExit「至少配置一项」;
//   - **族错配**:IPv6 CIDR 落进 [tun].subnets、或 IPv4 CIDR 落进 [tun].subnets_v6。runtime 按列表分别喂给
//     v4 / v6 地址池:放错族的条目要么解析进错误池、要么被跳过 → 该族「无可用网段」,最终撞上 server.go 的
//     「IPv4 和 IPv6 均无可用网段」FatalExit。此前 Config.Validate 的 checkCIDRs 只校验「是不是合法 CIDR」,
//     不看族,故一份把 v4/v6 写反的配置能过 lint 却开机 Fatal。
//
// CIDR 语法本身仍由 Config.Validate 的 checkCIDRs 负责;这里解析失败就跳过(交给它报),只补「族」这一维。
func (t TUNConfig) ValidateTUNSubnets() error {
	countNonBlank := func(list []string) int {
		n := 0
		for _, s := range list {
			if strings.TrimSpace(s) != "" {
				n++
			}
		}
		return n
	}
	if countNonBlank(t.Subnets) == 0 && countNonBlank(t.SubnetsV6) == 0 {
		return fmt.Errorf("[tun] at least one of subnets and subnets_v6 must be set (with both empty the data plane has no address pool and the server goes Fatal on startup)")
	}
	var errs []string
	for i, s := range t.Subnets {
		e := strings.TrimSpace(s)
		if e == "" {
			continue
		}
		ip, _, err := net.ParseCIDR(e)
		if err != nil {
			continue // CIDR 语法错交给 Config.Validate.checkCIDRs
		}
		if ip.To4() == nil {
			errs = append(errs, fmt.Sprintf("[tun].subnets[%d]=%q is an IPv6 CIDR and belongs in [tun].subnets_v6", i, s))
			continue
		}
		// v4-mapped 写法(`::ffff:10.0.0.1/24`):地址解析出来是 v4,但前缀长度是在 **128 位**空间里算的。
		// 于是 /24 覆盖的是 v6 空间的一大片而不是 256 个 v4 地址:掩码下发成 0.0.0.0,地址池一个都分不出来。
		// 这条以前能过校验(To4() 非空 → 当成合法 v4 网段),要到第一个客户端登录才发作。
		if strings.Contains(e, ":") {
			errs = append(errs, fmt.Sprintf(
				"[tun].subnets[%d]=%q uses the IPv4-mapped form, so the prefix length is interpreted in 128-bit space (the netmask goes out as 0.0.0.0 and the address pool cannot hand out a single address); write plain dotted decimal instead, such as %q",
				i, s, ip.String()+"/24"))
		}
	}
	for i, s := range t.SubnetsV6 {
		e := strings.TrimSpace(s)
		if e == "" {
			continue
		}
		ip, _, err := net.ParseCIDR(e)
		if err != nil {
			continue
		}
		if ip.To4() != nil {
			errs = append(errs, fmt.Sprintf("[tun].subnets_v6[%d]=%q is an IPv4 CIDR and belongs in [tun].subnets", i, s))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("[tun] subnet address family mismatch (the runtime feeds them to the wrong address pool, that family is left with no usable subnet, and startup goes Fatal):\n  - %s",
			strings.Join(errs, "\n  - "))
	}
	return nil
}

// jumpHostPortSpecError 返回单条 protected-port 规格的语法错误描述(合法则空串)。语法与
// cmd/nanotund parseJumpHostProtectedPorts 的接受集精确对齐:非法条目正是 runtime 会静默跳过的那些。
func jumpHostPortSpecError(s string) string {
	idx := strings.Index(s, "/")
	if idx <= 0 || idx == len(s)-1 {
		return "format must be proto/port or proto/start-end"
	}
	proto := s[:idx]
	portPart := s[idx+1:]
	if proto != "tcp" && proto != "udp" {
		return "proto must be tcp or udp"
	}
	startStr, endStr := portPart, ""
	if strings.ContainsAny(portPart, "-:") {
		sep := "-"
		if strings.Contains(portPart, ":") {
			sep = ":"
		}
		parts := strings.SplitN(portPart, sep, 2)
		startStr, endStr = parts[0], parts[1]
	}
	if n, err := strconv.Atoi(startStr); err != nil || n < 1 || n > 65535 {
		return "invalid start port (must be 1..65535)"
	}
	if endStr != "" {
		if n, err := strconv.Atoi(endStr); err != nil || n < 1 || n > 65535 {
			return "invalid end port (must be 1..65535)"
		}
	}
	return ""
}
