package util

import "strings"

// IsValidUUIDv4 严格校验 RFC 4122 v4 UUID 文本：
// 36 字符、按 8-4-4-4-12 分段、版本字段为 4、variant 高 2 位 `10`（即第 19 个字符是 8|9|a|b，大小写不敏感）。
//
// 跟 rust_vpn_client_lib::device_id::is_valid_uuid_v4 保持完全一致语义，是客户端 / 服务端共享的
// 「认这是同一个 UUID」契约：
//   - 客户端 (Swift / Rust) 写入前 / 读出时校验
//   - 服务端 authenticatePSK 收到 LoginReq.DeviceUUID 时校验，不合规一律按「未提供」降级
//
// 不合规的输入（含老版本误写的 garbage、用户手工录入的非 v4 串）让服务端不会创建脏 device 行，
// 也避免恶意客户端构造大量随意串撑爆 devices 表 / 占满 vIP 池。
func IsValidUUIDv4(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		b := s[i]
		switch i {
		case 8, 13, 18, 23:
			if b != '-' {
				return false
			}
		default:
			if !isHexLower(b) && !isHexUpper(b) && !(b >= '0' && b <= '9') {
				return false
			}
		}
	}
	// version 4：第 14 个字符（index 14）必须是 '4'
	if s[14] != '4' {
		return false
	}
	// variant：第 19 个字符（index 19）必须是 8/9/a/A/b/B
	switch s[19] {
	case '8', '9', 'a', 'b', 'A', 'B':
		return true
	default:
		return false
	}
}

// NormalizeDeviceUUID 把客户端送来的 UUID 文本归一：
//   - 先 trim 两端空白；
//   - 再 ToLower —— Swift / Rust 客户端都已 lowercase，但万一某客户端没归一，
//     这里兜底，让同一台设备永远落到同一行 (user_id, device_uuid)。
//
// 空串返回空串，让上层走「未提供」降级路径。
func NormalizeDeviceUUID(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func isHexLower(b byte) bool { return b >= 'a' && b <= 'f' }
func isHexUpper(b byte) bool { return b >= 'A' && b <= 'F' }
