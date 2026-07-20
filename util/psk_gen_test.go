package util

import (
	"encoding/base32"
	"strings"
	"testing"
)

// TestGeneratePSK_FormatAndEntropy 锁定 GeneratePSK 的两个不变量:
//   - 256 bit 熵(下限 50 字符,留 buffer 也挡住"无声退化回 160 bit / 20 字节")
//   - 分隔符存在(切 5 字符 + "-" 拼接的格式)
//
// 不直接断言"等于 62 字符"是为了给未来如果再加长留余地;只要不退化即可。
//
// 100 次抽样无重复 ≈ 强随机性 smoke test(理论碰撞概率在 256 bit 下 100^2 / 2^257
// 完全可忽略,任何实际碰撞都意味着 rand.Read 退化到非密码学 PRNG)。
func TestGeneratePSK_FormatAndEntropy(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		p, err := GeneratePSK()
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if _, dup := seen[p]; dup {
			t.Fatalf("collision after %d iterations: %q", i, p)
		}
		seen[p] = struct{}{}
		if len(p) < 50 {
			t.Fatalf("psk too short (expected ~62 chars for 256 bit): %q (len=%d)", p, len(p))
		}
		if !strings.Contains(p, "-") {
			t.Fatalf("psk missing separators: %q", p)
		}
	}
}

// TestGeneratePSK_DecodableToExpectedBytes 验证去掉分隔符后是合法的 base32(NoPadding)
// 且解码后字节数恰好等于 PSKRandomBytes。捕捉两类回归:
//   - 编码方式被改成 base64 / hex(decode 失败)
//   - PSKRandomBytes 改了但分段逻辑没跟着改(decode 字节数不一致)
func TestGeneratePSK_DecodableToExpectedBytes(t *testing.T) {
	p, err := GeneratePSK()
	if err != nil {
		t.Fatal(err)
	}
	flat := strings.ReplaceAll(p, "-", "")
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(flat)
	if err != nil {
		t.Fatalf("base32 decode failed for %q: %v", flat, err)
	}
	if len(decoded) != PSKRandomBytes {
		t.Fatalf("decoded length = %d, want PSKRandomBytes = %d", len(decoded), PSKRandomBytes)
	}
}
