package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// 0011 带宽限速 CLI 输入/输出帮助:
//   - 内部统一存字节/秒(byte/s, int64),与 SQLite 列对齐;
//   - CLI 默认接受 --up-mibs / --down-mibs(浮点 MiB/s,1 MiB = 1024*1024 byte);
//   - 也接受 --up-bps / --down-bps(int64 byte/s,精确),互斥;
//   - 0 / 空 = 「该方向不强制」(回退上一层),负数报错。
//
// 输出展示:bytesPerSecondHuman(2 MiB/s ≈ 16.0 Mbps) — 同时给字节口径(下载速度)和比特口径
// (运营商带宽)。

// parseRateFlag 把 `--*-mibs` 和 `--*-bps` 合并解析。返回字节/秒。
//
// 调用约束:mibsRaw / bpsRaw 至多一个非空字符串;两个都非空时报错(语义冲突)。
// 两个都空时返回 (0, ErrRateUnset),由 caller 决定「保持不变」还是「视为 0 清除」。
//
// 单位:
//   - mibs:浮点 MiB/s,例 "1.5" → 1572864 byte/s
//   - bps :int64 byte/s,例 "1572864"
//
// 这里故意不接 KB/s / Mbps 等口径,避免用户在「比特 vs 字节」上犯错;CLI 输出会
// 同时打两种,够看清楚。
func parseRateFlag(mibsRaw, bpsRaw string) (int64, error) {
	mibsRaw = strings.TrimSpace(mibsRaw)
	bpsRaw = strings.TrimSpace(bpsRaw)
	if mibsRaw != "" && bpsRaw != "" {
		return 0, newLocErr("rate.mutuallyExclusive")
	}
	if mibsRaw == "" && bpsRaw == "" {
		return 0, errRateUnset
	}
	if bpsRaw != "" {
		v, err := strconv.ParseInt(bpsRaw, 10, 64)
		if err != nil {
			return 0, newLocErr("rate.bpsParseFail", bpsRaw, err.Error())
		}
		if v < 0 {
			return 0, newLocErr("rate.bpsNegative", v)
		}
		return v, nil
	}
	f, err := strconv.ParseFloat(mibsRaw, 64)
	if err != nil {
		return 0, newLocErr("rate.mibsParseFail", mibsRaw, err.Error())
	}
	if f < 0 {
		return 0, newLocErr("rate.mibsNegative", f)
	}
	return int64(f * 1024 * 1024), nil
}

// errRateUnset:parseRateFlag 用,表示「这次调用没提供该方向的值」。
// caller(cmdDeviceSetRate / cmdSettingRate)用 errors.Is 判别,决定「沿用旧值」or「设为 0」。
var errRateUnset = errors.New("rate flag not set")

// bytesPerSecondHuman:把 byte/s 渲染成 "12.0 MiB/s (96.0 Mbps)";0 显示 "-(不限)"。
// CLI 表格列宽:大约 22 字符内。Mbps = byte/s × 8 / 1e6(运营商十进制口径)。
func bytesPerSecondHuman(bps int64) string {
	if bps <= 0 {
		return "-"
	}
	mibs := float64(bps) / (1024 * 1024)
	mbps := float64(bps) * 8 / 1e6
	return fmt.Sprintf("%.2f MiB/s (%.1f Mbps)", mibs, mbps)
}

// parseBurstFlagKiB(0012):--burst-kib 解析。空 = errRateUnset(caller 决定怎么处理),
// "0" = 显式清(回退 default)。负数报错。返回字节数(int64)。
//
// N11(2026-05-24):上界 16 MiB(16384 KiB),与 server.maxRateBurstBytes 对齐;
// 超过即拒,避免 audit 写入大值但实际被 clamp 引发认知错乱。
const maxBurstKiBFlag = 16 * 1024

func parseBurstFlagKiB(raw string) (int64, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errRateUnset
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, newLocErr("rate.burstParseFail", s, err.Error())
	}
	if f < 0 {
		return 0, newLocErr("rate.burstNegative", f)
	}
	if f > maxBurstKiBFlag {
		return 0, newLocErr("rate.burstTooLarge", maxBurstKiBFlag)
	}
	return int64(f * 1024), nil
}

// burstBytesHuman(0012):burst 字节 → "64 KiB" / "—"。CLI dry-run 用。
func burstBytesHuman(opts *globalOpts, b int64) string {
	if b <= 0 {
		return opts.T("rate.burstDefault")
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.0f KiB", float64(b)/1024)
	}
	return fmt.Sprintf("%.2f MiB", float64(b)/(1024*1024))
}
