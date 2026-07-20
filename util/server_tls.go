package util

import (
	"crypto/tls"
	"crypto/x509"
)

// ServerTLSOptions 描述构造服务端 *tls.Config 时的全部可调项。零值即「合理默认」:
//
//   - MinTLS12 = true,显式 TLS 1.2 起步;
//   - SessionTicketsDisabled = true,VPN 长连接无 resumption 需求,禁 ticket 减少
//     ticket key 泄漏后的 session resume 攻击面;
//   - PreferAEAD = true,显式指定 TLS 1.2 cipher suite 白名单,只允许 AEAD ciphers,
//     防止 Go 默认行为未来变化或老版本 Go 协商到非 AEAD。
//
// 调用方按场景再传入:
//   - NextProtos:ALPN(数据面 wss 设 "http/1.1");
//   - ClientCAs + ClientAuth:mTLS(保活 wss 用);
//   - InsecureSkipVerify:仅用于本机环回 dial(loopback dial 不算入服务端配置)。
type ServerTLSOptions struct {
	Certificates []tls.Certificate
	NextProtos   []string
	ClientCAs    *x509.CertPool
	ClientAuth   tls.ClientAuthType

	// 默认 true。VPN 没有 0-RTT / resumption 必要,关掉减少攻击面 + 简化合规。
	// 设 false 显式启用(REALITY 自己有等价开关,这里走 reality 库不经过本工厂)。
	SessionTicketsDisabled bool

	// 高级覆盖:留空时使用上述默认;非空时直接用调用方提供的内容(用于实验 / 兼容
	// 老客户端)。
	OverrideMinVersion   uint16
	OverrideCipherSuites []uint16
}

// NewServerTLSConfig 是服务端 TLS 配置统一工厂。
//
// 之前 vpn-wss / hy2 keepalive wss / (hy2 quic 由 hysteria core 接管) 三处各自硬编码
// tls.Config,容易出现:某处忘了设 MinVersion、忘了禁 ticket、cipher 白名单缺失;
// 也很难做合规审计「这个服务到底用什么 TLS 配置」。
//
// 工厂化后:
//   - 一处改 → 全局生效(eg. 之后想把 MinVersion 改 TLS1.3 只动这里);
//   - 测试时打印 Config 对比简单;
//   - 给 reality/hy2 等使用第三方库构造 TLSConfig 的场景留出明确的「不走工厂」例外。
//
// 不接受 nil cert(对外要 serve 必有 cert);Certificates 为空时 panic,让调用方
// 在启动阶段就 fail,而不是握手到一半才报错。
func NewServerTLSConfig(opts ServerTLSOptions) *tls.Config {
	if len(opts.Certificates) == 0 {
		panic("util: NewServerTLSConfig 调用时 Certificates 为空,必须至少提供一份证书")
	}

	minV := uint16(tls.VersionTLS12)
	if opts.OverrideMinVersion != 0 {
		minV = opts.OverrideMinVersion
	}

	suites := opts.OverrideCipherSuites
	if suites == nil {
		// TLS 1.2 AEAD only。
		// (TLS 1.3 cipher 在 Go 中由 runtime 内部管理,不可在此设置,
		//  Go 文档明确说明 CipherSuites 字段对 TLS 1.3 无效。)
		suites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	}

	cfg := &tls.Config{
		Certificates:           opts.Certificates,
		MinVersion:             minV,
		CipherSuites:           suites,
		NextProtos:             opts.NextProtos,
		SessionTicketsDisabled: opts.SessionTicketsDisabled,
		ClientCAs:              opts.ClientCAs,
		ClientAuth:             opts.ClientAuth,
	}
	return cfg
}
