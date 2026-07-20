package main

import (
	"encoding/base32"
	"encoding/hex"
	"strings"
	"testing"
)

// totp_test.go:覆盖 RFC 6238 参考向量 + secret/recovery code/normalize 等关键路径。
//
// RFC 6238 附录 B 给出了 SHA-1 的标准测试向量,key = ASCII "12345678901234567890"
// (20 字节)。我们用 truncatedHOTP(key, T) 直接验,跳过 ToHexCounter/decode 包装层。

func TestTruncatedHOTP_RFC6238_SHA1(t *testing.T) {
	key := []byte("12345678901234567890")
	cases := []struct {
		name     string
		counterT uint64
		want     uint32
	}{
		// RFC 6238 Appendix B: time -> T (counter = floor(time / 30)) -> 8-digit code
		// 我们 totpDigits=6, 所以取下面 want 的后 6 位即可。
		{"1970-01-01 00:00:59", 59 / 30, 287082},         // RFC: 94287082
		{"2005-03-18 01:58:29", 1111111109 / 30, 81804},  // RFC: 07081804 -> 6 位 081804
		{"2005-03-18 01:58:31", 1111111111 / 30, 50471},  // RFC: 14050471 -> 6 位 050471
		{"2009-02-13 23:31:30", 1234567890 / 30, 5924},   // RFC: 89005924 -> 6 位 005924
		{"2033-05-18 03:33:20", 2000000000 / 30, 279037}, // RFC: 69279037 -> 6 位 279037
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncatedHOTP(key, tc.counterT)
			if got != tc.want {
				t.Fatalf("counter %d: got %06d, want %06d", tc.counterT, got, tc.want)
			}
		})
	}
}

func TestGenerateTOTPSecret_FormatAndUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		s, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret: %v", err)
		}
		// 20 bytes base32 NoPadding = 32 字符。
		if len(s) != 32 {
			t.Fatalf("len = %d, want 32; got %q", len(s), s)
		}
		// 大写 + base32 字符集。
		if s != strings.ToUpper(s) {
			t.Fatalf("secret 应该全大写: %q", s)
		}
		if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s); err != nil {
			t.Fatalf("base32 decode 失败: %v (%q)", err, s)
		}
		if seen[s] {
			t.Fatalf("生成了重复 secret: %q", s)
		}
		seen[s] = true
	}
}

func TestVerifyTOTP_RoundTrip(t *testing.T) {
	// 用 RFC 向量做"用我们的 VerifyTOTP 模拟一个码 → 自己校验自己"逻辑不直接,因为
	// VerifyTOTP 依赖 time.Now()。改用:生成 secret, 手动算当前应当返回的码,
	// 然后调用 VerifyTOTP 验证它接受这个码。
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 当前应当的码
	now := nowUnix()
	currentCode := truncatedHOTP(key, uint64(now/int64(totpPeriodSec)))
	codeStr := paddedDigits(currentCode, totpDigits)
	if err := VerifyTOTP(secret, codeStr); err != nil {
		t.Fatalf("VerifyTOTP(current) 应当通过: %v", err)
	}
	// 前一个步长的码也应该通过(±1 容忍)
	prevCode := truncatedHOTP(key, uint64(now/int64(totpPeriodSec))-1)
	if err := VerifyTOTP(secret, paddedDigits(prevCode, totpDigits)); err != nil {
		t.Fatalf("VerifyTOTP(prev step) 应当通过(±1 skew): %v", err)
	}
	// 远超 skew(+10 步 = 300s)应该拒绝。极端罕见碰撞:不同 counter 算出同一码
	// 的概率 ~ 1e-6,我们循环找一个肯定不同的。
	for delta := int64(10); delta < 100; delta++ {
		far := truncatedHOTP(key, uint64(now/int64(totpPeriodSec))+uint64(delta))
		if far != currentCode && far != prevCode {
			if err := VerifyTOTP(secret, paddedDigits(far, totpDigits)); err == nil {
				t.Fatalf("VerifyTOTP(future +%d steps) 不该通过", delta)
			}
			return
		}
	}
	t.Fatal("没找到与当前不同的远期码 - 极端不可能,检查 truncatedHOTP")
}

func TestVerifyTOTP_BadInput(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrTOTPBadFormat},
		{"too short", "12345", ErrTOTPBadFormat},
		{"too long", "1234567", ErrTOTPBadFormat},
		{"non digit", "abcdef", ErrTOTPBadFormat},
		{"spaces", "12 345", ErrTOTPBadFormat},           // 长度 6 但含空格 → 非数字 → ErrTOTPBadFormat
		{"all zero unlikely", "000000", ErrTOTPMismatch}, // 概率 1e-6 不通过
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyTOTP(secret, tc.in)
			if err == nil {
				t.Fatalf("应当报错(可能极偶然 000000 通过 — 重跑即可),got nil")
			}
			if tc.want == ErrTOTPBadFormat && err != ErrTOTPBadFormat {
				t.Fatalf("want ErrTOTPBadFormat, got %v", err)
			}
		})
	}
}

func TestBuildOtpauthURI(t *testing.T) {
	uri := BuildOtpauthURI("ABCDEFGHIJ234567", "alice@host")
	for _, must := range []string{
		"otpauth://totp/",
		"nanotun", // issuer
		"secret=ABCDEFGHIJ234567",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, must) {
			t.Fatalf("uri 缺 %q: %s", must, uri)
		}
	}
}

func TestGenerateRecoveryCodes_ShapeAndUnique(t *testing.T) {
	plain, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if len(plain) != recoveryCodeCount || len(hashes) != recoveryCodeCount {
		t.Fatalf("count = %d/%d, want %d", len(plain), len(hashes), recoveryCodeCount)
	}
	seen := make(map[string]bool)
	for i, p := range plain {
		if !strings.Contains(p, "-") || len(p) != 9 {
			t.Fatalf("plain[%d] = %q 格式应当 XXXX-XXXX (9 chars)", i, p)
		}
		if seen[p] {
			t.Fatalf("重复恢复码: %q", p)
		}
		seen[p] = true
		// hash 应当是 argon2id PHC
		if !strings.HasPrefix(hashes[i], "argon2id$") {
			t.Fatalf("hash[%d] 不是 argon2id PHC: %q", i, hashes[i])
		}
		// 用对应 hash 验明文应当通过
		ok, err := VerifyWebPassword(p, hashes[i])
		if err != nil || !ok {
			t.Fatalf("hash[%d] verify 失败: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"ABCD-EFGH", "ABCD-EFGH", true},
		{"abcd-efgh", "ABCD-EFGH", true},
		{"abcdefgh", "ABCD-EFGH", true},
		{"  abcd efgh ", "ABCD-EFGH", true},
		{"ABCD-EFG", "", false},   // 7 字符
		{"ABCD-EFGHI", "", false}, // 9 字符
		{"!@#$%^&*", "", false},   // 全非法
	}
	for _, tc := range cases {
		got, err := NormalizeRecoveryCode(tc.in)
		if tc.ok {
			if err != nil {
				t.Errorf("Normalize(%q) want ok, got err %v", tc.in, err)
				continue
			}
			if got != tc.want {
				t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		} else {
			if err == nil {
				t.Errorf("Normalize(%q) 应该报错,得到 %q", tc.in, got)
			}
		}
	}
}

func TestDecodeTOTPSecret_Tolerance(t *testing.T) {
	raw := []byte("12345678901234567890") // 20 bytes
	canonical := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	cases := []string{
		canonical,                  // 大写
		strings.ToLower(canonical), // 小写
		"  " + canonical + "\n",    // 空白
		canonical + "==",           // 加 padding(虽然 NoPadding,但 TrimRight = 兼容)
	}
	for _, s := range cases {
		decoded, err := decodeTOTPSecret(s)
		if err != nil {
			t.Fatalf("decode %q: %v", s, err)
		}
		if hex.EncodeToString(decoded) != hex.EncodeToString(raw) {
			t.Fatalf("decode %q = %x, want %x", s, decoded, raw)
		}
	}
}

// paddedDigits 是测试辅助,与 totp.go 内部 fmt.Sprintf("%0*d") 等价。
func paddedDigits(v uint32, n int) string {
	out := []byte("000000")[:n]
	for i := n - 1; i >= 0; i-- {
		out[i] = byte('0' + v%10)
		v /= 10
	}
	return string(out)
}
