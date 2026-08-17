package main

// via4 的 SIIT 翻译（RFC 7915 精简版，只服务 via4 一条路径，见 via4.go 顶部设计注释）。
//
// 支持 TCP / UDP / ICMP-echo；不支持分片、IPv6 扩展头、其它 ICMP 类型（全部丢弃计数，
// 由调用方 via4DataPlane 统一记 via4DropUntranslate / via4DropReturnUnknown）。
// 地址族变化 ⇒ L4 伪头变化 ⇒ TCP/UDP/ICMPv6 校验和必须重算——一律全量重算（不做增量），
// 顺带把 v4 侧 UDP checksum=0（v4 合法、v6 非法）的包补上真校验和。
//
// TTL/HopLimit 语义：翻译器是一跳路由器，转发时 -1；入包 TTL≤1 本应回 Time Exceeded，
// 简化为丢弃（via 流量两端都在 mesh 内，正常 TTL 远大于路径跳数，触发即异常包）。

import (
	"encoding/binary"
	"net/netip"
)

// ---- 出向：发起方 v4（dst=池地址） → 4via6 v6 ----

// translateVia4ToV6 把「发起方 → 池地址」的 v4 包改写为「返程标记 src → 4via6 dst」的 v6 包。
// pkt 已被 TrimIPPacketToTotalLen 截齐。失败返回 (nil,false)，调用方计数丢弃。
func translateVia4ToV6(pkt []byte, key via4Key, clientSrcV4 netip.Addr) ([]byte, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	totLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if ihl < 20 || totLen < ihl || totLen > len(pkt) || totLen > via4MaxV4Len {
		return nil, false
	}
	// 分片（offset≠0 或 MF=1）不翻译：v6 侧无对应的路由器分片语义，TCP 有 MSS 钳制兜底。
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return nil, false
	}
	ttl := pkt[8]
	if ttl <= 1 {
		return nil, false
	}
	proto := pkt[9]
	src6, ok := encodeVia4Return(clientSrcV4)
	if !ok {
		return nil, false
	}
	dst6, ok := encode4via6(key.siteID, key.v4)
	if !ok {
		return nil, false
	}
	l4 := make([]byte, totLen-ihl)
	copy(l4, pkt[ihl:totLen])

	var nextHdr byte
	switch proto {
	case 6: // TCP：SYN 段钳 MSS（钳完再统一重算校验和）
		if len(l4) < 20 {
			return nil, false
		}
		clampTCPMSS(l4, via4MSSCeiling)
		nextHdr = 6
	case 17: // UDP
		if len(l4) < 8 {
			return nil, false
		}
		nextHdr = 17
	case 1: // ICMPv4 → ICMPv6，只翻 echo
		if len(l4) < 8 {
			return nil, false
		}
		switch l4[0] {
		case 8:
			l4[0] = 128 // echo request
		case 0:
			l4[0] = 129 // echo reply
		default:
			return nil, false
		}
		nextHdr = 58
	default:
		return nil, false
	}

	s16, d16 := src6.As16(), dst6.As16()
	writeL4ChecksumV6(l4, nextHdr, s16, d16)

	out := make([]byte, 40+len(l4))
	tc := pkt[1] // DSCP/ECN 原样带过去
	out[0] = 0x60 | (tc >> 4)
	out[1] = (tc << 4) & 0xf0
	// flow label 0（out[1] 低 4 位与 out[2:4] 保持 0）
	binary.BigEndian.PutUint16(out[4:6], uint16(len(l4)))
	out[6] = nextHdr
	out[7] = ttl - 1
	copy(out[8:24], s16[:])
	copy(out[24:40], d16[:])
	copy(out[40:], l4)
	return out, true
}

// ---- 返程：宣告方 v6（src=4via6，dst=返程标记） → 发起方 v4 ----

// translateVia4ToV4 把「4via6 src → 返程标记 dst」的 v6 包改写为「池地址 src → 发起方 vIP dst」的 v4 包。
// clientV4 由调用方从返程标记解出。src 必须是真 4via6（reserved==0）且映射仍在，否则 (nil,false)。
func translateVia4ToV4(pkt []byte, t *via4Table, clientV4 netip.Addr) ([]byte, bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return nil, false
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if 40+payloadLen > len(pkt) {
		return nil, false
	}
	nextHdr := pkt[6]
	hop := pkt[7]
	if hop <= 1 {
		return nil, false
	}
	src6, ok := netip.AddrFromSlice(pkt[8:24])
	if !ok {
		return nil, false
	}
	// src 必须是真 4via6（b[8:10]==0，排除返程标记等特殊布局被当站点地址反查）。
	sb := src6.As16()
	if sb[8] != 0 || sb[9] != 0 {
		return nil, false
	}
	siteID, targetV4, ok := decode4via6(src6)
	if !ok {
		return nil, false
	}
	poolAddr, ok := t.via4KeyToPool(via4Key{siteID: siteID, v4: targetV4})
	if !ok {
		return nil, false // 映射被驱逐：陈旧连接，丢弃（客户端重查 DNS 自愈）
	}

	l4 := make([]byte, payloadLen)
	copy(l4, pkt[40:40+payloadLen])

	var proto byte
	switch nextHdr {
	case 6:
		if len(l4) < 20 {
			return nil, false
		}
		clampTCPMSS(l4, via4MSSCeiling) // LAN 侧常给 mss=1460，SYN-ACK 也要钳
		proto = 6
	case 17:
		if len(l4) < 8 {
			return nil, false
		}
		proto = 17
	case 58: // ICMPv6 → ICMPv4，只翻 echo
		if len(l4) < 8 {
			return nil, false
		}
		switch l4[0] {
		case 129:
			l4[0] = 0 // echo reply
		case 128:
			l4[0] = 8 // echo request（LAN 侧主动 ping 发起方的对称路径）
		default:
			return nil, false
		}
		proto = 1
	default:
		return nil, false // 带扩展头 / 其它协议不支持
	}

	p4, c4 := poolAddr.As4(), clientV4.As4()
	writeL4ChecksumV4(l4, proto, p4, c4)

	out := make([]byte, 20+len(l4))
	out[0] = 0x45
	out[1] = (pkt[0]&0x0f)<<4 | (pkt[1] >> 4) // Traffic Class → TOS
	binary.BigEndian.PutUint16(out[2:4], uint16(20+len(l4)))
	// id=0 + DF：翻译产物不参与 v4 分片（RFC 7915 §5.1 非分片路径）
	binary.BigEndian.PutUint16(out[6:8], 0x4000)
	out[8] = hop - 1
	out[9] = proto
	copy(out[12:16], p4[:])
	copy(out[16:20], c4[:])
	binary.BigEndian.PutUint16(out[10:12], ipv4HeaderChecksum(out[:20]))
	copy(out[20:], l4)
	return out, true
}

// ---- 校验和 / MSS 工具 ----

// onesSum 累加 16 位反码和（不折叠）。
func onesSum(b []byte) uint32 {
	var s uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if n%2 == 1 {
		s += uint32(b[n-1]) << 8
	}
	return s
}

// foldChecksum 折叠为最终 16 位反码校验和。
func foldChecksum(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xffff) + s>>16
	}
	return ^uint16(s)
}

// l4ChecksumOffset 返回该 L4 协议校验和字段在段内的偏移。
func l4ChecksumOffset(proto byte) int {
	switch proto {
	case 6:
		return 16 // TCP
	case 17:
		return 6 // UDP
	case 1, 58:
		return 2 // ICMPv4 / ICMPv6
	}
	return -1
}

// writeL4ChecksumV6 就地写入 v6 伪头语义下的 L4 校验和（TCP/UDP/ICMPv6 都含伪头）。
func writeL4ChecksumV6(l4 []byte, proto byte, src, dst [16]byte) {
	off := l4ChecksumOffset(proto)
	if off < 0 || len(l4) < off+2 {
		return
	}
	l4[off], l4[off+1] = 0, 0
	var pseudo [40]byte
	copy(pseudo[0:16], src[:])
	copy(pseudo[16:32], dst[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(l4)))
	pseudo[39] = proto
	ck := foldChecksum(onesSum(pseudo[:]) + onesSum(l4))
	if proto == 17 && ck == 0 {
		ck = 0xffff // UDP：0 保留作「无校验和」，v6 下非法 → 用等价的全 1
	}
	binary.BigEndian.PutUint16(l4[off:off+2], ck)
}

// writeL4ChecksumV4 就地写入 v4 语义下的 L4 校验和（TCP/UDP 含 v4 伪头；ICMPv4 不含伪头）。
func writeL4ChecksumV4(l4 []byte, proto byte, src, dst [4]byte) {
	off := l4ChecksumOffset(proto)
	if off < 0 || len(l4) < off+2 {
		return
	}
	l4[off], l4[off+1] = 0, 0
	var sum uint32
	if proto == 6 || proto == 17 {
		var pseudo [12]byte
		copy(pseudo[0:4], src[:])
		copy(pseudo[4:8], dst[:])
		pseudo[9] = proto
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(l4)))
		sum = onesSum(pseudo[:])
	}
	ck := foldChecksum(sum + onesSum(l4))
	if proto == 17 && ck == 0 {
		ck = 0xffff
	}
	binary.BigEndian.PutUint16(l4[off:off+2], ck)
}

// ipv4HeaderChecksum 计算 v4 头校验和（调用前须保证 h[10:12] 为 0）。
func ipv4HeaderChecksum(h []byte) uint16 {
	return foldChecksum(onesSum(h))
}

// clampTCPMSS 把 SYN 段的 MSS 选项钳到 ceiling（就地改；校验和由调用方随后统一重算）。
// 非 SYN / 无 MSS 选项 / 选项区越界均为 no-op。
func clampTCPMSS(l4 []byte, ceiling uint16) {
	if len(l4) < 20 || l4[13]&0x02 == 0 { // 非 SYN
		return
	}
	dataOff := int(l4[12]>>4) * 4
	if dataOff < 20 || dataOff > len(l4) {
		return
	}
	for i := 20; i < dataOff; {
		kind := l4[i]
		switch kind {
		case 0: // End of options
			return
		case 1: // NOP
			i++
		default:
			if i+1 >= dataOff {
				return
			}
			optLen := int(l4[i+1])
			if optLen < 2 || i+optLen > dataOff {
				return
			}
			if kind == 2 && optLen == 4 {
				if mss := binary.BigEndian.Uint16(l4[i+2 : i+4]); mss > ceiling {
					binary.BigEndian.PutUint16(l4[i+2:i+4], ceiling)
				}
			}
			i += optLen
		}
	}
}
