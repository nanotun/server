package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// RealityConfig REALITY 入站（对齐 Xray realitySettings + github.com/xtls/reality）。
// ListenAddr 非空时启用；私钥与 shortId 格式与 `xray x25519` / 面板一致。
type RealityConfig struct {
	ListenAddr string `toml:"listen_addr"` // 如 :443；空表示不启用 REALITY 监听

	Dest string `toml:"dest"` // 回落目标，如 www.microsoft.com:443
	Type string `toml:"type"` // 默认 tcp
	Xver int    `toml:"xver"` // PROXY protocol：0 关闭，1 v1，2 v2

	PrivateKey  string   `toml:"private_key"` // X25519 私钥，Base64（RawURL / URL / Std 均可），解码后须 32 字节
	ServerNames []string `toml:"server_names"`
	ShortIds    []string `toml:"short_ids"` // 十六进制，偶数位，至多 16 字符（8 字节）；"" 表示全 0 shortId

	Show bool `toml:"show"` // 对应 Xray realitySettings.show

	// MaxTimeDiffMs 允许客户端时间戳与本地相差（毫秒）；0 表示不校验（与 Xray maxTimeDiff: 0 一致）
	MaxTimeDiffMs int64 `toml:"max_time_diff_ms"`

	// Mldsa65SeedBase64 可选，32 字节 seed 的 Base64；非空时启用 ML-DSA-65 叶证书扩展（与 Xray mldsa65Seed 一致）
	Mldsa65SeedBase64 string `toml:"mldsa65_seed_base64"`

	// ClientAddr 可选，写入日志/文档用：对外展示的「客户端应连」地址（不参与协议）
	ClientAddr string `toml:"client_addr"`
}

// Validate 在已决定启用 REALITY（ListenAddr 非空）时调用。
func (r *RealityConfig) Validate() error {
	if strings.TrimSpace(r.ListenAddr) == "" {
		return nil
	}
	if err := validateRealityDest(r.Dest); err != nil {
		return fmt.Errorf("dest: %w", err)
	}
	// 深扫第十轮 LOW:xver 只有 0/1/2 三个合法值(PROXY protocol 关闭 / v1 / v2)。
	// 此前 Validate 不查、listener 又把它 byte(r.Xver) 直传底层 —— 写成 3 会静默让 PROXY
	// 头行为未定义(既非关闭也非合法版本)。这里启动期 fail-fast。
	if r.Xver < 0 || r.Xver > 2 {
		return fmt.Errorf("xver 须为 0(关闭)/1(PROXY v1)/2(PROXY v2),得 %d", r.Xver)
	}
	if _, err := DecodeRealityPrivateKey(r.PrivateKey); err != nil {
		return fmt.Errorf("private_key: %w", err)
	}
	// 深扫第十轮 LOW:mldsa65 seed 非空时应能解码成 32 字节,提前到启动期校验,
	// 而不是等 listener 起来时才失败(此前 config 校验完全不碰这个字段)。
	if strings.TrimSpace(r.Mldsa65SeedBase64) != "" {
		if _, err := DecodeRealityMldsa65Seed(r.Mldsa65SeedBase64); err != nil {
			return fmt.Errorf("mldsa65_seed_base64: %w", err)
		}
	}
	if len(r.ServerNames) == 0 {
		return fmt.Errorf("server_names 至少一项")
	}
	if len(r.ShortIds) == 0 {
		return fmt.Errorf("short_ids 至少一项（可含空字符串表示允许全 0 shortId）")
	}
	for _, sn := range r.ServerNames {
		if strings.TrimSpace(sn) == "" {
			return fmt.Errorf("server_names 含空项")
		}
	}
	for i, sid := range r.ShortIds {
		if _, err := ParseRealityShortID(sid); err != nil {
			return fmt.Errorf("short_ids[%d]: %w", i, err)
		}
	}
	return nil
}

// validateRealityDest 校验 dest 形如 host:port 或 ip:port,且 port 在 1..65535。
//
// REALITY 在握手后会**直接**把 raw TCP 转发到 dest;dest 错误意味着 fallback 失败,
// 攻击者的非合法客户端会得到一个奇怪的 TCP 错误(可能暴露指纹)。之前 Validate 只
// 检查空字符串,容易漏掉:
//   - 只填了 host 没填 port:"www.microsoft.com"  → net.Dial 直接报「missing port」;
//   - 填了纯 port:":443" → fallback 到本机,造成回环;
//   - 错误 port:"www.microsoft.com:0" → Dial 报「unknown port 0」。
//
// 这里严格校验,把这些问题在启动期直接 Fatal。
func validateRealityDest(dest string) error {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return fmt.Errorf("不能为空")
	}
	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		return fmt.Errorf("须为 host:port 形式,例如 www.microsoft.com:443: %w", err)
	}
	if host == "" {
		return fmt.Errorf("host 段为空(fallback 到本机会引发回环)")
	}
	pn, err := net.LookupPort("tcp", port)
	if err != nil {
		return fmt.Errorf("port 段非法: %w", err)
	}
	if pn <= 0 || pn > 65535 {
		return fmt.Errorf("port 越界: %d", pn)
	}
	return nil
}

// ParseRealityShortID 将配置中的 shortId 转为 8 字节（与 Xray shortIds 一致）。
//
// 对齐方向必须与 Xray/xtls-reality 线上格式一致：客户端把 shortId 解码后从
// sessionId[8] 起**左对齐**写入，服务端 tls.go 亦以 copy(ClientShortId[:], plainText[8:])
// 左对齐读取。因此这里必须左对齐（copy(out[:], dec)）——若右对齐，任何短于 16 个
// 十六进制字符的 shortId（面板默认常见 8 位）都会与客户端发来的 key 不相等，
// REALITY 握手静默匹配失败并回落到 dest。
func ParseRealityShortID(s string) ([8]byte, error) {
	var out [8]byte
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return out, nil
	}
	if len(s)%2 != 0 {
		return out, fmt.Errorf("十六进制长度须为偶数")
	}
	if len(s) > 16 {
		return out, fmt.Errorf("至多 8 字节（16 个十六进制字符）")
	}
	dec, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	copy(out[:], dec)
	return out, nil
}

// DecodeRealityPrivateKey 解码 Xray 格式的 REALITY X25519 私钥（32 字节）。
func DecodeRealityPrivateKey(s string) ([]byte, error) {
	return decodeRealityPrivateKey(s)
}

// DecodeRealityMldsa65Seed 解码 mldsa65_seed_base64 为 32 字节 seed,接受
// RawURL / URL / RawStd / Std 四种 Base64(与 reality listener 侧同口径)。
// 单一实现供 config.Validate(启动期校验)与 listener(实际取 key)共用。
func DecodeRealityMldsa65Seed(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("不能为空")
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("须解码为 32 字节")
}

func decodeRealityPrivateKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("不能为空")
	}
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, enc := range encodings {
		b, err := enc.DecodeString(s)
		if err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, fmt.Errorf("须为解码后 32 字节的 Base64 私钥")
}
