package main

import (
	"fmt"
	"strconv"
	"strings"
)

// 0011(2026-05-23):带宽限速 UI 输入/展示 helper。
// 与 nanotun-admin/rate_fmt.go 同语义,因为两个 main package 不共享代码,这里独立一份。
//
// UI 约定:
//   - 输入用 MiB/s(浮点),旁边小字显示对应 Mbps;
//   - 内部存字节/秒(byte/s, int64);
//   - 0 / 空 = 「该方向不在该层强制」(回退上一层)。

// maxRateMiBsInput(第八轮深扫 LOW):限速输入上界 ≈ 1 TiB/s(8.8 Tbps),远超任何真实链路。
// 作用是**防 int64 转换溢出**:此前 parseRateMiBs 对 int64(f*1024*1024) 不设上限,一个超大浮点(admin
// 输入)会溢出成负/垃圾值并被 audit 原样记录(与 parseBurstKiB 的 maxBurstKiBInput 不对称)。server 下游
// 虽会 clamp,但先在入口拒掉越界值,UI 立即反馈、audit 不留垃圾。
const maxRateMiBsInput = 1024 * 1024 // MiB/s

// parseRateMiBs 把表单字段 "1.5" 解析成 byte/s。空 / 0 / 0.0 都视为 0。
// 错误情况:负数 / 非数字 / 超过 maxRateMiBsInput。
func parseRateMiBs(raw string) (int64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, newLocErr("rate.notANumber", s)
	}
	if f < 0 {
		return 0, newLocErr("rate.negative")
	}
	if f > maxRateMiBsInput {
		return 0, newLocErr("rate.tooLarge", int64(maxRateMiBsInput))
	}
	return int64(f * 1024 * 1024), nil
}

// rateBytesToMiBsString:1572864 → "1.5"(浮点字符串,给 input value 用)。0 → ""。
//
// 选择空串而非 "0":form 上「未填」与「显式 0」语义一致(都 = 沿用上层),空串
// 让 placeholder 能正确显示提示语,UI 更干净。
//
// 精度策略(0012):用 %.6g 而非 -1 ——
//   - -1 精度(strconv 的 "ryū" 算法)会选「能精确还原 float64 的最短字符串」,
//     但用户输入 2.7 MiB/s → byte = int64(2.7 * 1048576) = 2831155 → float64(2831155)/1048576
//     = 2.7000007629... 这是真实的精度损失,-1 会忠实回显成 "2.7000007629394531",
//     UI 上极丑;
//   - %.6g 给 6 位有效数字,小数末尾零自动 strip("10" 不会变 "10.0000"),
//     2.7 精度损失被 round 掉显示成 "2.7",日常输入范围内不会让用户困惑;
//   - 极端值(如 1234.5678 MiB/s)会丢一两位,但 admin 输入这种值的概率几乎为 0,
//     真要精确请用 CLI --up-bps。
func rateBytesToMiBsString(bps int64) string {
	if bps <= 0 {
		return ""
	}
	v := float64(bps) / (1024 * 1024)
	return strconv.FormatFloat(v, 'g', 6, 64)
}

// rateBytesHuman:给只读展示用,格式 "12.0 MiB/s (96 Mbps)"。0 → "—"(不限)。
func rateBytesHuman(bps int64) string {
	if bps <= 0 {
		return "—"
	}
	mibs := float64(bps) / (1024 * 1024)
	mbps := float64(bps) * 8 / 1e6
	return fmt.Sprintf("%.2f MiB/s (%.1f Mbps)", mibs, mbps)
}

// rateBytesToKiBString(0012):burst 字节 → KiB 字符串,0 → ""(沿用 default)。
// burst 用 KiB 输入比 MiB 自然 — 实际范围 4–256 KiB,MiB 会都是小数。
func rateBytesToKiBString(b int64) string {
	if b <= 0 {
		return ""
	}
	v := float64(b) / 1024
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// parseBurstKiB(0012):表单 "64" / "256" / 空 / "0" → 字节。空 / 0 = 沿用 default。
// server 端会兜底夹到 [4 KiB, 16 MiB]。
//
// N11(2026-05-24):前端**也**显式拒绝超过 16 MiB(16384 KiB)的输入,UI 立刻报错,
// 避免运维输完保存看不到反馈(server 端虽然会 clamp,但 audit 写的是原值,
// 阅读时容易误以为真生效了一个 1 GiB 的桶)。
const maxBurstKiBInput = 16 * 1024 // 16 MiB,与 server.maxRateBurstBytes 对齐

func parseBurstKiB(raw string) (int64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, newLocErr("rate.notANumber", s)
	}
	if f < 0 {
		return 0, newLocErr("rate.negative")
	}
	if f > maxBurstKiBInput {
		return 0, newLocErr("rate.burstTooLarge", maxBurstKiBInput)
	}
	return int64(f * 1024), nil
}

// minPositiveBPS:两层 cap 取严的那一层。0 / 负数表示「该层不强制」(+∞),
// 所以遇到 0 就返回另一边;两边都 >0 取小;两边都 ≤0 返回 0(完全不限)。
//
// 与 cmd/nanotund/server.go 同名函数对齐;web 这边复刻是为了 device_detail 页面算
// effective rate(N25),不想搞 cross-process RPC 拿这个简单算式。
func minPositiveBPS(a, b int64) int64 {
	if a <= 0 {
		if b <= 0 {
			return 0
		}
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// computeEffectiveRateBPS(N25, 2026-05-24):按 server 端 effectiveLinkRates 的语义
// 模拟一遍 device → settings → toml → user 的多层 cap min。给 web UI 在 device_detail
// 页直接展示「实际生效限速」,运维设了 device.rate=0 也能看到「其实 settings/toml/user
// 还在 cap 你」。
//
// 参数都是同方向(全 up 或全 down)的字节速率;0 / 负 = 该层不强制。
// 返回值 0 表示完全不限;>0 即为实际生效字节速率。
//
// 注意:本函数不包括 per-platform toml cap —— 那只在登录瞬时按客户端 platform 取,
// 离线视角没法预算,UI 上单独标注「per-platform 配置另行生效」即可。
func computeEffectiveRateBPS(deviceBPS, settingsBPS, tomlBPS, userBPS int64) int64 {
	out := deviceBPS
	out = minPositiveBPS(out, settingsBPS)
	out = minPositiveBPS(out, tomlBPS)
	out = minPositiveBPS(out, userBPS)
	return out
}

// rateBurstHuman(0012):burst 字节 → "64 KiB" / "1.5 MiB" / "—"。
// burst 不带 /s,纯容量单位,跟 rateBytesHuman 区分。
func rateBurstHuman(b int64) string {
	if b <= 0 {
		return "—"
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.0f KiB", float64(b)/1024)
	}
	return fmt.Sprintf("%.2f MiB", float64(b)/(1024*1024))
}
