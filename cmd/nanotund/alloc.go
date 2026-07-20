package main

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/sirupsen/logrus"
)

// ClientNetConfig 表示分配给客户端的网络三件套：客户端 IP、子网掩码/前缀长度、网关
type ClientNetConfig struct {
	ClientIP string // 客户端 IP，如 "10.0.0.2" 或 "fd00::2"
	Mask     string // IPv4 子网掩码（如 "255.255.255.0"）或 IPv6 前缀长度（如 "64"）
	Gateway  string // 网关，如 "10.0.0.1" 或 "fd00::1"
}

// AllocClientIP 根据网关 CIDR（如 "10.0.0.1/24" 或 "fd00::1/64"）和已分配集合，
// 分配一个未占用的客户端 IP。同时支持 IPv4 和 IPv6。
// exclude 为需要排除的 IP，保证虚拟 IP 与本地 IP 不会相同；可为 nil。
func AllocClientIP(gatewayCIDR string, used map[string]bool, exclude map[string]bool) (ClientNetConfig, error) {
	prefix, err := netip.ParsePrefix(gatewayCIDR)
	if err != nil {
		return ClientNetConfig{}, fmt.Errorf("parse gateway cidr: %w", err)
	}
	gatewayAddr := prefix.Addr().Unmap()
	gatewayStr := gatewayAddr.String()

	var maskStr string
	if gatewayAddr.Is4() {
		_, network, errOld := net.ParseCIDR(gatewayCIDR)
		if errOld != nil {
			return ClientNetConfig{}, fmt.Errorf("parse mask: %w", errOld)
		}
		m := network.Mask
		if len(m) == 4 {
			maskStr = fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
		} else if len(m) >= 16 {
			maskStr = fmt.Sprintf("%d.%d.%d.%d", m[12], m[13], m[14], m[15])
		}
	} else {
		maskStr = fmt.Sprintf("%d", prefix.Bits())
	}

	// 扫描范围根据前缀长度计算：IPv4 /24→254, /16→65534; IPv6 统一 65534
	var maxIter int
	if gatewayAddr.Is4() {
		hostBits := 32 - prefix.Bits()
		if hostBits > 16 {
			hostBits = 16
		}
		maxIter = (1 << hostBits) - 2
		if maxIter < 1 {
			maxIter = 1
		}
	} else {
		maxIter = 65534
	}

	networkAddr := prefix.Masked().Addr()

	for i := 2; i <= maxIter; i++ {
		var cand netip.Addr
		if gatewayAddr.Is4() {
			raw := networkAddr.As4()
			sum := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
			sum += uint32(i)
			raw[0] = byte(sum >> 24)
			raw[1] = byte(sum >> 16)
			raw[2] = byte(sum >> 8)
			raw[3] = byte(sum)
			cand = netip.AddrFrom4(raw)
		} else {
			raw := networkAddr.As16()
			raw[14] = byte(i >> 8)
			raw[15] = byte(i & 0xFF)
			cand = netip.AddrFrom16(raw)
		}
		candStr := cand.String()
		if candStr == gatewayStr {
			continue
		}
		if !used[candStr] && (exclude == nil || !exclude[candStr]) {
			// G7(P2-7): 在 alloc 成功路径上做容量监控。used + exclude 之和接近 maxIter
			// (即「90% 使用率」)时发出 warn,运维需扩容(改 config.toml 中的 [tun].subnets /
			// subnets_v6)或跑 `nanotun-admin lease gc --idle 30d` 回收僵死 lease。
			// P3-c:历史 default_cidr_v4/v6 app_setting 已在 0005 migration 删除,
			// 现在网段唯一真源是 config.toml。
			//
			// 用 90% 阈值有两点考虑:
			//   - 太低会有大量噪音(假阳性);
			//   - 太高(95%)留给运维处理时间不足,可能下一批客户端登录就 OOPS。
			//
			// 实际 used 数 = len(used) + len(exclude)(粗略,两 set 可能有重叠);
			// 在「将爆未爆」阶段一般是显著高,误差 < 5% 可接受。
			usedAfter := len(used) + 1
			if exclude != nil {
				usedAfter += len(exclude)
			}
			if maxIter > 0 && float64(usedAfter)/float64(maxIter) >= 0.9 {
				// 直接打 logrus.Warn:每次 alloc 都打可能噪音大,但「池子已 90% 满」
				// 这件事确实每次 alloc 都该提醒一次,运维收到后会处理。
				logrusWarnPoolFull(gatewayCIDR, usedAfter, maxIter)
			}
			return ClientNetConfig{
				ClientIP: candStr,
				Mask:     maskStr,
				Gateway:  gatewayStr,
			}, nil
		}
	}
	return ClientNetConfig{}, fmt.Errorf("no free IP in subnet %s (subnet full)", gatewayCIDR)
}

// logrusWarnPoolFull 单独拎出来避免在 alloc 主路径里直接拉 logrus 依赖(util/alloc
// 包想保持轻),由 alloc.go 内部直接 import logrus 也行,这里就纯粹是 readability。
func logrusWarnPoolFull(cidr string, used, total int) {
	logrus.WithFields(logrus.Fields{
		"cidr":  cidr,
		"used":  used,
		"total": total,
		"pct":   float64(used) / float64(total),
	}).Warn("[ip-pool] vIP 池容量 ≥ 90%,建议扩容网段或跑 `nanotun-admin lease gc --idle 30d` 回收孤儿 lease")
}
