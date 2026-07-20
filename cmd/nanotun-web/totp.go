package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

// M2 + 0009:Web 后台管理员的 TOTP(RFC 6238)实现。
//
// 故意选择"自己实现 ~ 50 行"而不是 import 第三方库,原因:
//   1) RFC 6238 + RFC 4226 算法极其简单(HMAC-SHA1 + 4 字节截断 + mod 10^N),
//      可读性远好于把 pquerna/otp 的多层抽象拉进来;
//   2) Google Authenticator / Microsoft Authenticator / Authy / 1Password 等所有
//      主流客户端都默认 SHA1 + 30s + 6 位,我们不开放参数;
//   3) 减少依赖面 → 减少 supply-chain 风险面。QR 用现成的 skip2/go-qrcode 渲染。
//
// 兼容性已经在 RFC 6238 附录 B 的 SHA1 参考向量上验证(见 totp_test.go),与上述
// 所有 app 一致。

const (
	// totpSecretLen:RFC 4226 建议 ≥ 128 bit;Google Authenticator 文档要求 base32
	// 长度是 8 的倍数(无 padding 也行,但 Microsoft 旧版本对 padding 敏感),16/20 字
	// 节都行,这里取 20(= 160 bit)与 Google 默认一致,base32 后是 32 字符。
	totpSecretLen = 20

	// totpDigits:6 位码,业界事实标准。
	totpDigits = 6

	// totpPeriodSec:30 秒一个时间步,RFC 6238 推荐 + Google 默认。
	totpPeriodSec = 30

	// totpAllowedSkew:允许 ±1 个时间步的时钟漂移(总计 ~90 秒窗口)。
	// 太大就增加 brute force 风险(每窗口可猜 10^6 个码),所以保守 1。
	totpAllowedSkew = 1

	// recoveryCodeCount / recoveryCodeRawBytes:每次启用 / 重置 TOTP 时发 10 条
	// 一次性恢复码;每条原始 5 字节(40 bit) → base32 编码 8 字符 + 中间一个 '-'
	// 分组成 "XXXX-XXXX",方便手抄 / 防止 1/I、0/O 混淆。
	recoveryCodeCount    = 10
	recoveryCodeRawBytes = 5

	// totpIssuer:出现在 Google Authenticator 列表里"nanotun (admin@host)" 的
	// 前一部分,用于一眼区分这个码是给哪个服务的。
	totpIssuer = "nanotun"
)

// =========================================================================
// secret 生成 / otpauth URI
// =========================================================================

// GenerateTOTPSecret 用 crypto/rand 生成 20 字节,返回 base32 编码(无 padding)。
//
// 失败仅在 OS RNG 不可用时发生,几乎不会出现;调用方应当把 error 上报让用户
// 重试,不要兜底用伪随机 — TOTP secret 一旦弱随机,就被时间空间内全部 6 位码暴力。
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("totp: rand: %w", err)
	}
	// NoPadding 是 RFC 6238 + Google Authenticator 都接受的格式;但有些老 app
	// 对小写敏感,统一用大写更保险。
	return strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)), nil
}

// BuildOtpauthURI 拼 otpauth://totp/<issuer>:<account>?secret=...&issuer=...
//
// 这是 Google Authenticator 通用的扫码 URI 格式(Key URI Format),所有主流
// app 都支持。我们显式带上 algorithm/digits/period,即使是默认值,避免少数
// 旧 app 默认值不一致时算出错码。
//
// account 一般用 username@hostname,方便用户在 Authenticator app 里区分多个账号。
func BuildOtpauthURI(secretBase32, account string) string {
	label := url.PathEscape(totpIssuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secretBase32)
	q.Set("issuer", totpIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(totpDigits))
	q.Set("period", strconv.Itoa(totpPeriodSec))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// RenderTOTPQRCodePNG 把 otpauth URI 渲染成 PNG 二进制(默认 256x256)。
// 输出可以直接 base64 写进 HTML 的 <img src="data:image/png;base64,..."/>。
// 256x256 折中:< 200 时手机摄像头偶尔扫不出,> 384 时 dataURL 体积变大(~ 4KB 起)。
func RenderTOTPQRCodePNG(otpauthURI string) ([]byte, error) {
	png, err := qrcode.Encode(otpauthURI, qrcode.Medium, 256)
	if err != nil {
		return nil, fmt.Errorf("totp: encode qr: %w", err)
	}
	return png, nil
}

// =========================================================================
// 验证(RFC 6238)
// =========================================================================

// VerifyTOTP 用给定 base32 secret 验证 code 是否匹配当前 unix 时间(允许 ±skew 步)。
//
// 步骤(对照 RFC 6238 §4 + RFC 4226 §5.3):
//
//	T = (now - T0) / period;以 8 字节大端写入 buffer;
//	HMAC-SHA1(secret, buffer)        → 20 字节 mac;
//	offset = mac[19] & 0x0f          → 0..15;
//	bin = mac[off..off+4] & 0x7fffffff(去最高位)
//	code = bin mod 10^digits;
//	字符串比对常量时间。
//
// 失败原因:
//   - secret 解码失败 → 配置错乱(不大可能,因为是我们自己生成的)
//   - code 长度 ≠ totpDigits → ErrTOTPBadFormat
//   - 不匹配 → ErrTOTPMismatch
//
// 注意:这里不做 replay 防护(连续两次正确码不会被拒)。这对运维管理后台够用 —
// 真要严防 replay 可以加一个 last_used_step 字段,但代价是 admin 偶尔会"刚输完就
// 重输被拒"。
func VerifyTOTP(secretBase32, code string) error {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return ErrTOTPBadFormat
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return ErrTOTPBadFormat
		}
	}
	key, err := decodeTOTPSecret(secretBase32)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	for skew := -int64(totpAllowedSkew); skew <= int64(totpAllowedSkew); skew++ {
		t := now/int64(totpPeriodSec) + skew
		got := truncatedHOTP(key, uint64(t))
		expected := fmt.Sprintf("%0*d", totpDigits, got)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return nil
		}
	}
	return ErrTOTPMismatch
}

// truncatedHOTP 算一次 HOTP(RFC 4226 §5.3)截断后的整数(0..10^digits-1)。
// 抽出来便于单测覆盖参考向量。
func truncatedHOTP(key []byte, counter uint64) uint32 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := int(sum[len(sum)-1] & 0x0f)
	bin := (uint32(sum[off]) & 0x7f) << 24
	bin |= uint32(sum[off+1]) << 16
	bin |= uint32(sum[off+2]) << 8
	bin |= uint32(sum[off+3])
	return bin % uint32(pow10(totpDigits))
}

// pow10 简单算 10^n;n 受 totpDigits 限制,运行时只可能拿到 6。
func pow10(n int) uint64 {
	out := uint64(1)
	for i := 0; i < n; i++ {
		out *= 10
	}
	return out
}

// decodeTOTPSecret 把存库的 base32 字符串(可能带 padding 也可能不带,可能大小
// 写混)解回原始 bytes。统一 ToUpper + 去 padding 再加回去,容错所有常见格式。
func decodeTOTPSecret(secretBase32 string) ([]byte, error) {
	s := strings.ToUpper(strings.TrimSpace(secretBase32))
	s = strings.TrimRight(s, "=")
	// base32 NoPadding 不依赖填充等号,直接 decode。
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("totp: bad secret: %w", err)
	}
	if len(raw) < 10 {
		// < 80 bit 太弱;RFC 4226 强制最小 128 bit,我们写库时就是 160 bit,真到这
		// 里说明 schema / 手工导入数据被破坏过 → 拒绝。
		return nil, errors.New("totp: secret too short (need >= 80 bit)")
	}
	return raw, nil
}

// 错误集合。
var (
	// 这几个是「我们自己定义、且会展示给用户」的错误:用 newLocErr 让 Error()
	// 返回默认语言(zh,供 CLI/日志/errors.Is 之外的场景与旧行为一致),web 层
	// 通过 trErr(r, err) 按请求语言翻译。仍是 sentinel:调用方 `errors.Is` /
	// `err == ErrTOTPBadFormat`(见 totp_test.go)比较的是同一个变量,不受影响。
	ErrTOTPBadFormat   = newLocErr("totp.badFormat")
	ErrTOTPMismatch    = newLocErr("totp.mismatch")
	ErrTOTPNotEnabled  = newLocErr("totp.notEnabled")
	ErrTOTPAlreadyDone = newLocErr("totp.alreadyEnabled")
)

// =========================================================================
// 恢复码
// =========================================================================

// GenerateRecoveryCodes 生成 N 条一次性恢复码;每条 10 字符 base32 加横线分组。
//
// 返回:plain[] 是直接显示给用户的格式("XXXX-XXXX"),hash[] 是要存数据库的
// argon2id PHC;两者按下标一一对应。函数内部 ToUpper 保证字母统一,展示时不会有
// 大小写歧义。
//
// 失败:OS RNG 不可用 / argon2 hash 失败 → 返回 error。
func GenerateRecoveryCodes() (plain []string, hashes []string, err error) {
	plain = make([]string, 0, recoveryCodeCount)
	hashes = make([]string, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		raw := make([]byte, recoveryCodeRawBytes)
		if _, err := rand.Read(raw); err != nil {
			return nil, nil, fmt.Errorf("totp: recovery rand: %w", err)
		}
		// base32 5 bytes = 8 字符(无 padding);切成 4-4 用 '-' 分组方便手抄。
		s := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
		if len(s) != 8 {
			// base32 5 → 8 字符是 RFC 4648 固定结果,真到这里说明库版本异常。
			return nil, nil, fmt.Errorf("totp: unexpected recovery len %d", len(s))
		}
		formatted := s[:4] + "-" + s[4:]
		plain = append(plain, formatted)
		h, err := HashWebPassword(formatted)
		if err != nil {
			return nil, nil, fmt.Errorf("totp: hash recovery: %w", err)
		}
		hashes = append(hashes, h)
	}
	return plain, hashes, nil
}

// NormalizeRecoveryCode 把用户输入的恢复码归一化(去空格 / 大写 / 加横线)。
// 用户拷贝时可能粘进多余空格 / 全小写 / 没横线,统一变成 "XXXX-XXXX"。
// 失败(长度不对、含非 base32 字符)返回 "" + error。
func NormalizeRecoveryCode(in string) (string, error) {
	s := strings.ToUpper(in)
	// 移除一切非字母数字字符(空格、横线、tab、换行)。
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7') {
			b.WriteRune(r)
		}
	}
	stripped := b.String()
	if len(stripped) != 8 {
		return "", newLocErr("totp.recoveryBadFormat", len(stripped))
	}
	return stripped[:4] + "-" + stripped[4:], nil
}
