package util

// psk_gen.go(2026-05-26):全仓 PSK 自动生成入口,由 `nanotun-admin`(CLI 创建 / 重置
// 用户 / 凭证)与 `nanotun-web`(Web 管理后台创建用户 / 重置 PSK)共同使用。
//
// 背景:本函数原先在两个 binary 各自有一份(`nanotun-admin/psk.go` /
// `nanotun-web/psk.go`),admin 那份在 server_id 改造期把 raw 字节从 20 升到 32
// (160 bit → 256 bit),web 那份**漏升**——结果同一个系统两个入口生成不同强度的
// PSK,运维体感不一致。本文件把两份合并到 `util` 包(已是两 binary 共享 wire 工具
// 的归口,例如 `credentials_url.go`),Single Source of Truth,日后不会再分叉。
//
// 设计要点:
//   - 32 字节原始熵 = 256 bit。向 AES-256 / X25519 等现代算法对齐,Grover 量子搜索
//     后仍留 128 bit headroom。
//   - PSK 走 QR 扫码进 client Keychain,几乎不再手输 —— 长度从 160 bit 升到 256 bit
//     UX 完全无感。
//   - argon2id verify 对明文长度近似线性但常量极小(20B → 32B 实测 ~50ms → ~52ms),
//     hash 端不会因长度增加感到压力。
//   - 格式 = base32(NoPadding) 后每 5 字符一段用 "-" 拼,在终端 / 二维码 / 口述场景
//     都比较稳;Keychain 落盘对长度不敏感。32 字节 raw → 52 字符 base32 → 10 段 +
//     2 字符尾巴,带 "-" 总长 ~62 字符。
//
// 用户也可以手动 `--psk` / 表单填入自带口令(任意长度),服务端只看 argon2id 哈希,
// 不强制本函数生成的格式。

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
)

// PSKRandomBytes 是 GeneratePSK 原始熵字节数。导出为常量便于测试 / 文档引用。
// 32 字节 = 256 bit。改这个常量请同步更新 `util/psk_gen_test.go::TestGeneratePSK_FormatAndEntropy`
// 里的下限断言,避免无声退化。
const PSKRandomBytes = 32

// GeneratePSK 返回一个 256 bit 随机 PSK 的人类可读形式:
//
//	ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-ABCDE-FGHIJ-KLMNO-PQRST-UVWXY-AB
//
// 失败仅源于 `crypto/rand.Read` 异常(理论上不会,操作系统熵不足才出错)。
//
// **不要**自行 strings.ReplaceAll(_, "-", "") 后比对:服务端只看 argon2id 哈希,
// 客户端 Keychain 也按原字符串存,中间任何形态转换都会导致 PSK 不匹配。
func GeneratePSK() (string, error) {
	raw := make([]byte, PSKRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	segs := make([]string, 0, len(enc)/5+1)
	for i := 0; i < len(enc); i += 5 {
		end := i + 5
		if end > len(enc) {
			end = len(enc)
		}
		segs = append(segs, enc[i:end])
	}
	return strings.Join(segs, "-"), nil
}
