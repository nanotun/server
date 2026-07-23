package config

import (
	"fmt"
	"strings"
)

// HysteriaPasswordMinLen 是 hy2 password 的最小可接受长度(字节)。
//
// 16 字节 ≈ 96 bit 熵的随机口令,对 hy2 单密码认证已经远超暴力下限。运维想用更短
// 也行,但应当显式覆盖到 0 表示「我知道我在干啥」—— 目前我们不提供这个开关,
// 强制 16,避免出现 `password = "123"` 也能起服务的低级失误。
//
// 注:此长度只在 server 端启用 hy2 时校验。客户端不参与,密码字节长度对客户端只是
// 「拷过去就行」,无需做匹配。
const HysteriaPasswordMinLen = 16

// ValidateHysteriaCredentials 检查 hy2 凭证是否「全空或全配齐」。仅配一部分时返回错误。
//
// 启用 hy2 时还会校验:
//   - password 最小长度 >= HysteriaPasswordMinLen 字节(防止 "123" 上线);
//   - obfs_salamander_password 已有的最小 4 字节(库要求)。
func (h *HysteriaConfig) ValidateHysteriaCredentials() error {
	p := strings.TrimSpace(h.Password)
	c := strings.TrimSpace(h.TLSCertFile)
	k := strings.TrimSpace(h.TLSKeyFile)
	n := 0
	if p != "" {
		n++
	}
	if c != "" {
		n++
	}
	if k != "" {
		n++
	}
	if n != 0 && n != 3 {
		return fmt.Errorf("hysteria: password、tls_cert_file、tls_key_file 须同时配置或同时留空")
	}
	if n == 3 && len(p) < HysteriaPasswordMinLen {
		return fmt.Errorf("hysteria: password 至少 %d 字节(当前 %d);弱口令容易被刷",
			HysteriaPasswordMinLen, len(p))
	}
	obfsPW := strings.TrimSpace(h.ObfsSalamanderPassword)
	if obfsPW != "" {
		if n != 3 {
			return fmt.Errorf("hysteria: 启用 obfs_salamander_password 须先配齐 password、tls_cert_file、tls_key_file")
		}
		if len(obfsPW) < 4 {
			return fmt.Errorf("hysteria: obfs_salamander_password 须至少 4 字节")
		}
	}
	return nil
}

// HysteriaActive 三项均非空时启用进程内 hy2 与 node_login.hysteria 上报。
func (h *HysteriaConfig) HysteriaActive() bool {
	return strings.TrimSpace(h.Password) != "" &&
		strings.TrimSpace(h.TLSCertFile) != "" &&
		strings.TrimSpace(h.TLSKeyFile) != ""
}

// ValidateTuning 校验 hy2 的 QUIC / 带宽 / UDP / MTU 调优字段是否落在合法区间。
//
// 第四轮深扫 LOW(e_config_lint):此逻辑原先只存在于 cmd/nanotund(启动期 buildHysteriaServerConfig
// 才调),`nanotun-admin config lint` 完全不碰这些字段 —— 一个越界的 quic_max_idle_timeout_sec /
// bandwidth_max_tx_bps 能过 lint 却在真正重启 server 时 Fatal。上移到 config 包,让启动期与 lint
// 共用同一套约束。约束值与 apernet/hysteria core 对齐;0 一律表示"用库默认",跳过校验。
func (h *HysteriaConfig) ValidateTuning() error {
	const minWindow = 16384
	if h.QUICInitialStreamRecvWindow != 0 && h.QUICInitialStreamRecvWindow < minWindow {
		return fmt.Errorf("hysteria: quic_initial_stream_recv_window 须为 0 或 ≥ %d", minWindow)
	}
	if h.QUICMaxStreamRecvWindow != 0 && h.QUICMaxStreamRecvWindow < minWindow {
		return fmt.Errorf("hysteria: quic_max_stream_recv_window 须为 0 或 ≥ %d", minWindow)
	}
	if h.QUICInitialConnRecvWindow != 0 && h.QUICInitialConnRecvWindow < minWindow {
		return fmt.Errorf("hysteria: quic_initial_conn_recv_window 须为 0 或 ≥ %d", minWindow)
	}
	if h.QUICMaxConnRecvWindow != 0 && h.QUICMaxConnRecvWindow < minWindow {
		return fmt.Errorf("hysteria: quic_max_conn_recv_window 须为 0 或 ≥ %d", minWindow)
	}
	if h.QUICMaxIdleTimeoutSec != 0 {
		if h.QUICMaxIdleTimeoutSec < 4 || h.QUICMaxIdleTimeoutSec > 120 {
			return fmt.Errorf("hysteria: quic_max_idle_timeout_sec 须为 0 或 4～120")
		}
	}
	if h.QUICMaxIncomingStreams != 0 && h.QUICMaxIncomingStreams < 8 {
		return fmt.Errorf("hysteria: quic_max_incoming_streams 须为 0 或 ≥ 8")
	}
	const minBps = 65536
	if h.BandwidthMaxTxBps != 0 && h.BandwidthMaxTxBps < minBps {
		return fmt.Errorf("hysteria: bandwidth_max_tx_bps 须为 0 或 ≥ %d", minBps)
	}
	if h.BandwidthMaxRxBps != 0 && h.BandwidthMaxRxBps < minBps {
		return fmt.Errorf("hysteria: bandwidth_max_rx_bps 须为 0 或 ≥ %d", minBps)
	}
	if h.UDPRelayEnabled && h.UDPIdleTimeoutSec != 0 {
		if h.UDPIdleTimeoutSec < 2 || h.UDPIdleTimeoutSec > 600 {
			return fmt.Errorf("hysteria: udp_idle_timeout_sec 须为 0 或 2～600")
		}
	}
	if h.MTU != 0 && (h.MTU < 1200 || h.MTU > 9216) {
		return fmt.Errorf("hysteria: mtu 须为 0 或 1200～9216")
	}
	return nil
}
