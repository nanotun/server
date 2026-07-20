package main

// 4via6 —— 子网路由的「同网段消歧」地址编码（SR-VIA6，仿 Tailscale 4via6）。
//
// 问题：多个子网路由器可能宣告**同一个** RFC1918 网段（如都是 192.168.1.0/24，家用路由器出厂默认），
// 使用方本地 LAN 也常是同段 → 纯 IPv4 无法区分「本地的 .5」和「远端某站点的 .5」，路由表二选一。
//
// 方案：给每个宣告方（= 一个「站点 / site」）分配一个 16 位 siteID，把 (siteID, 原始 IPv4) 一起编码进一个
// **唯一的 IPv6 地址**。使用方访问该 v6（本地 v4 照走 v4，两套地址空间不重叠 → 可同时访问）；服务器按 siteID
// 无状态路由到对应宣告方；宣告方（用户态 netstack，socket relay）解出低 32 位 v4、直接 connect 进本机 LAN。
//
// 地址布局（128 位）：
//
//	[   prefix 64 位   ][ reserved 16 = 0 ][ siteID 16 ][   IPv4 32   ]
//	  fdbc:4a60:0:0    :       0          :   <site>   : <v4 高16>:<低16>
//
// 例：siteID=1, v4=192.168.1.5 → fdbc:4a60:0:0:0:1:c0a8:0105。
// 前缀刻意用 fdbc:（≈旧后端）开头，与 mesh vIP 的 fd00: 段前 16 位即不同，绝不冲突；使用方装一条
// fdbc:4a60::/64 路由即覆盖全部站点。

import (
	"net/netip"
)

// via6Prefix：4via6 的 /64 前缀。ULA fd00::/8 内的产品专属段，避开 mesh vIP 的 fd00: 段。
var via6Prefix = netip.MustParsePrefix("fdbc:4a60::/64")

// Via6Prefix 返回 4via6 的 /64 前缀（供 routes-list 下发 / 使用方装路由 / 测试引用）。
func Via6Prefix() netip.Prefix { return via6Prefix }

// encode4via6 把 (siteID, IPv4) 编码成唯一的 4via6 IPv6 地址。v4 必须是 IPv4 地址；否则 ok=false。
func encode4via6(siteID uint16, v4 netip.Addr) (netip.Addr, bool) {
	if !v4.Is4() {
		return netip.Addr{}, false
	}
	var b [16]byte
	p := via6Prefix.Addr().As16()
	copy(b[0:8], p[0:8]) // 前 64 位 = 前缀
	// b[8], b[9] = reserved（保持 0）
	b[10] = byte(siteID >> 8)
	b[11] = byte(siteID)
	v4b := v4.As4()
	copy(b[12:16], v4b[:]) // 低 32 位 = 原始 IPv4
	return netip.AddrFrom16(b), true
}

// decode4via6 从 4via6 地址解出 (siteID, 原始 IPv4)。地址不在 4via6 前缀内 → ok=false。
func decode4via6(addr netip.Addr) (siteID uint16, v4 netip.Addr, ok bool) {
	if !is4via6(addr) {
		return 0, netip.Addr{}, false
	}
	b := addr.As16()
	siteID = uint16(b[10])<<8 | uint16(b[11])
	v4 = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	return siteID, v4, true
}

// is4via6 报告地址是否为 4via6 地址（IPv6 且落在 via6Prefix /64 内）。
func is4via6(addr netip.Addr) bool {
	return addr.Is6() && !addr.Is4In6() && via6Prefix.Contains(addr)
}
