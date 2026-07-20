package util

import "strings"

// NormalizeMagicHost 把设备名/主机名归一成 magic 子域风格:小写 + 非 [a-z0-9-] 一律换连字符,
// 首尾连字符 trim、连续连字符折叠。
//
// MagicDNS 主机名解析(server)与「每用户设备名唯一」去重(store)都用它做同口径比较,集中在此
// 避免两处逻辑漂移。归一后同名(如 "home pi" / "home-pi" / "home_pi" 都 → "home-pi")在 DNS 名
// 层面本就不可区分,故去重也应按归一形判定。
func NormalizeMagicHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-':
			b = append(b, c)
		default:
			b = append(b, '-')
		}
	}
	out := strings.Trim(string(b), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return out
}
