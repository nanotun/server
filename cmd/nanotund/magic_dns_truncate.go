package main

// UDP/53 侧的应答长度约束与截断（RFC 1035 §4.2.1 / RFC 6891 §6.2.3）。
//
// 要解决的是「静默黑洞」：应答字节数超过使用方声明的接收缓冲区时，若照原样 sendto，
//   - 报文在路径上被丢（IP 分片被中间设备丢，或对端 recvfrom 缓冲区装不下被内核截掉），
//   - 使用方看到的是**超时**，而不是「答案太大、请改用 TCP」，
// 于是它只会原样重试 UDP，一直失败。正确处置是回一帧**合法的空应答 + TC=1**：使用方据此立刻改走
// TCP/53 重查（magic_dns_tcp.go），一个来回就拿到完整答案。
//
// 实现刻意集中在这一个写入器里：runMagicDNSLoop 每包把 *net.UDPConn 包一层 udpDNSReplyConn，
// 于是**所有** UDP 应答路径（magic 名 / 出口中继 / 上游转发 / 缓存命中 / 各类错误码）自动获得同一套
// 长度约束，无需在几十处 WriteToUDP 调用点各自判断。TCP 侧用的是 tcpDNSReplyConn，天然不经过这里
// —— TCP 无长度上限，也就不该置 TC。

import (
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// magicDNSUDPFloor 是无 EDNS 时的应答上限（RFC 1035 §4.2.1 的 512 字节）。查询没带 OPT 伪 RR
	// 就意味着使用方只保证收得下 512。
	magicDNSUDPFloor = 512
	// magicDNSUDPCeiling 给使用方声明的缓冲区**再加一道封顶**。使用方常见地声明 65535（"我能收多大都行"），
	// 但那只是它的 recvfrom 缓冲区，路径 MTU 管不着：真发出 20KB 会被 IP 分片，而分片在公网/隧道上丢失率显著
	// 更高，表现又回到「静默超时」。4096 是 EDNS 部署里的常见上限，超出即宁可让对方走 TCP。
	magicDNSUDPCeiling = 4096
)

// udpDNSReplyConn 是 UDP/53 的应答写入器：超过本次查询可接受的长度就换成「空应答 + TC=1」。
//
// limit 惰性求值：只有当应答真的超过 512 字节时才去解析查询里的 EDNS 缓冲区声明。绝大多数应答远小于
// 512，这样每包省掉一次完整的 DNS 报文 Unpack（那是本路径上最贵的一步）。
type udpDNSReplyConn struct {
	conn  *net.UDPConn
	query []byte
	limit int // 0 = 还没算过
}

func (w *udpDNSReplyConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if len(b) > magicDNSUDPFloor {
		if w.limit == 0 {
			w.limit = udpDNSReplyLimit(w.query)
		}
		if len(b) > w.limit {
			if tc := buildTruncatedDNSReply(b, w.limit); tc != nil {
				b = tc
			}
			// tc == nil（应答连解都解不开）→ 原样发出。这只可能来自上游的坏包：与其静默吞掉，
			// 不如让使用方自己判断（它可能比我们更宽容）。
		}
	}
	return w.conn.WriteToUDP(b, addr)
}

// udpDNSReplyLimit 返回本次查询可接受的最大 UDP 应答字节数：使用方 EDNS 声明的缓冲区，夹在
// [magicDNSUDPFloor, magicDNSUDPCeiling]。查询无 OPT / 解不开 → 512。
//
// 夹下界的原因：有实现把 OPT.Class 填成 0 或 512 以下的小值，照做会让几乎所有应答都被截断置 TC，
// 把本可一次 UDP 完成的解析全推去 TCP。512 是协议保底值，任何 DNS 使用方都必须收得下。
func udpDNSReplyLimit(query []byte) int {
	ednsBuf, _, _, ok := parseUpstreamCacheEDNS(query)
	if !ok || int(ednsBuf) < magicDNSUDPFloor {
		return magicDNSUDPFloor
	}
	if int(ednsBuf) > magicDNSUDPCeiling {
		return magicDNSUDPCeiling
	}
	return int(ednsBuf)
}

// buildTruncatedDNSReply 把一帧过长的应答换成**合法的**截断应答：保留 qid / rcode / question，
// 丢掉 answer / authority，置 TC=1。返回 nil = resp 解不开（调用方原样发出）。
//
// 绝不能直接把字节切短：那会得到一帧 header 声称有 N 条记录、实际数据被砍掉一半的报文，使用方一律按
// FORMERR 丢弃，等于又回到静默失败。必须重新打包。
//
// 逐级降级（每级都要重新 Pack 并校验长度，因为 question 段本身也可能很长）：
//  1. question + OPT：保留 OPT 让使用方知道我们支持 EDNS（RFC 6891 §6.2.3 要求 TC 应答也带 OPT）；
//  2. 只留 question：极长域名 + OPT 挤不进 512 时；
//  3. 只留 header：连 question 都装不下（qname 接近 255 字节上限而使用方缓冲区又被夹到 512）。
//     此时无法回显 question，部分使用方会因此丢弃 —— 但它至少能立刻看到 TC 并改走 TCP，仍好过超时。
func buildTruncatedDNSReply(resp []byte, limit int) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return nil
	}
	m.Header.Response = true
	m.Header.Truncated = true
	m.Answers = nil
	m.Authorities = nil
	// 只留 OPT 伪 RR（它携带 EDNS 能力声明），其余 additional 一并丢弃。
	opt := m.Additionals[:0]
	for i := range m.Additionals {
		if m.Additionals[i].Header.Type == dnsmessage.TypeOPT {
			opt = append(opt, m.Additionals[i])
			break
		}
	}
	m.Additionals = opt

	for _, degrade := range []func(){
		func() {},                    // question + OPT
		func() { m.Additionals = nil }, // 只留 question
		func() { m.Questions = nil },   // 只留 header
	} {
		degrade()
		if raw, err := m.Pack(); err == nil && len(raw) <= limit {
			return raw
		}
	}
	return nil
}
