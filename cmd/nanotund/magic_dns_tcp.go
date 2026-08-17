package main

// magic DNS 的 TCP/53 传输（RFC 1035 §4.2.2 长度前缀 + RFC 7766 的连接复用/超时要求）。
//
// 为什么必须有：
//  1. RFC 7766 把「同时支持 UDP 与 TCP」定为 DNS 实现的**必需项**——只听 UDP 的解析器不合规。
//  2. 更要紧的实际后果：应答被截断（TC=1）时使用方唯一的补救手段就是改用 TCP 重查。此前 magic DNS
//     的 TCP/53 直接 connection refused，于是「大应答」在这条链路上无路可走。
//  3. Windows 全隧道客户端此前会按 RTT 择优绕开 magic DNS（见 blackhorse-windows 的 NRPT catch-all
//     修复）；把全部公网域名压回 magic DNS 之后，TCP 缺失从「边角不合规」变成了会真实伤到用户的缺口。
//
// 与 UDP 侧共用同一套解析 / 策略 / 缓存逻辑：见 magicDNSReplyConn 的说明。

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// magicDNSTCPMaxConns 是**全服务器** magic DNS TCP 并发连接上限。TCP 每连接占一个 goroutine + 读缓冲，
// 必须封顶，否则「大量半开连接」就是一条廉价的资源耗尽路径。DNS over TCP 的正常用量极低（只在 UDP 被
// 截断或使用方偏好 TCP 时才用），512 已远超实际需要。
//
// 是 var 而非 const 仅为让测试能压到 1 来验证「超限即关」这条路径 —— 真按 512 造连接的测试又慢又脆。
// 生产代码不改它。
var magicDNSTCPMaxConns int64 = 512

const (
	// magicDNSTCPIdleTimeout 是连接空闲超时。RFC 7766 §6.2.3 要求实现主动回收空闲连接、并允许在同一连接上
	// 复用多次查询；10s 兼顾「使用方连续几条查询复用同一连接」与「不给空闲连接白占坑」。
	magicDNSTCPIdleTimeout = 10 * time.Second
	// magicDNSTCPWriteTimeout 是单次应答的写超时，防慢速读取方（拿到连接却不读）长期占坑。
	magicDNSTCPWriteTimeout = 5 * time.Second
	// magicDNSTCPMaxQuerySize 是单条 TCP 查询的长度上限。协议上长度前缀最大 65535，但 DNS **查询**再大也
	// 用不了几百字节；压到 4KB 既容得下带 EDNS/ECS 的查询，又不让对端用「声明 64KB 然后慢慢喂」占内存。
	magicDNSTCPMaxQuerySize = 4096
)

// magicDNSTCPConnCount 是当前在处理的 TCP 连接数（受 magicDNSTCPMaxConns 约束）。
var magicDNSTCPConnCount atomic.Int64

// magicDNSTCPAcceptedCount / magicDNSTCPRejectedCount:累计接受 / 因超上限被立即关闭的 TCP 连接数，供 /status 观测。
var (
	magicDNSTCPAcceptedCount atomic.Uint64
	magicDNSTCPRejectedCount atomic.Uint64
)

// errDNSReplyTooLongForTCP:应答超过 TCP 长度前缀能表达的 65535 字节。上游不可能给出这么大的 DNS 应答，
// 出现即说明上游/中继链路异常，宁可不回也不能写一个长度字段与实际不符的帧（会让对端连接彻底错位）。
var errDNSReplyTooLongForTCP = errors.New("dns reply too long for tcp framing")

// magicDNSReplyConn 抽掉「应答怎么送回使用方」，让 UDP/53 与 TCP/53 共用同一套解析、ACL、出口中继、缓存逻辑。
//
// 方法签名刻意与 `*net.UDPConn.WriteToUDP` 完全一致 —— 于是 `*net.UDPConn` **天然满足**本接口，几十处
// 既有调用点（绝大多数在测试里）无需任何改动即可接入，改造风险被压到最低。代价是名字带着 UDP 味，实际有
// 三种实现：裸 `*net.UDPConn`（测试直接传）、udpDNSReplyConn（生产 UDP 路径，多一层长度约束/TC 截断）、
// tcpDNSReplyConn（TCP 路径，忽略 addr —— TCP 有独立流、无需逐包指定对端 —— 并按 RFC 1035 §4.2.2 前置
// 2 字节长度）。「按传输方式分叉」的行为差异全部收在各实现内部，调用方不该、也不需要判断自己在哪种传输上。
type magicDNSReplyConn interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
}

// tcpDNSReplyConn 把一条 TCP 连接包成 magicDNSReplyConn。每次 writeReply 一次性写出「2 字节长度 + 载荷」，
// 绝不分两次 Write：分开写在对端看来仍是同一字节流，但一旦中间写失败就会留下「长度已宣告、载荷缺失」的
// 半帧，后续所有查询在这条连接上全部错位。
type tcpDNSReplyConn struct{ conn net.Conn }

func (w *tcpDNSReplyConn) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	if len(b) > 0xffff {
		return 0, errDNSReplyTooLongForTCP
	}
	frame := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(b)))
	copy(frame[2:], b)
	_ = w.conn.SetWriteDeadline(time.Now().Add(magicDNSTCPWriteTimeout))
	n, err := w.conn.Write(frame)
	if n > 2 {
		n -= 2 // 对调用方报「DNS 载荷写了多少」，不含长度前缀
	} else {
		n = 0
	}
	return n, err
}

// startMagicDNSTCP 在 listenAddr:port 上起 TCP/53，与 startMagicDNS（UDP）成对。返回 cleanup 关监听器；
// 任何一步失败都只记日志并返回 no-op cleanup —— TCP 是 UDP 的补充，它起不来不该拖垮已经可用的 UDP 解析。
func startMagicDNSTCP(gw *gatewayState, listenAddr string) func() {
	if gw == nil || gw.store == nil || gw.cfg == nil {
		return func() {}
	}
	if !gw.cfg.Server.MagicDNS.Enabled {
		return func() {}
	}
	if listenAddr == "" {
		return func() {}
	}
	resolved := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	ip := net.ParseIP(listenAddr)
	if ip == nil {
		logrus.WithField("listen_addr", listenAddr).Error("[magic-dns] TCP listen_addr 不是合法 IP,跳过")
		return func() {}
	}
	addr := net.TCPAddr{IP: ip, Port: int(resolved.port)}
	ln, err := net.ListenTCP("tcp", &addr)
	if err != nil {
		logrus.WithError(err).WithField("addr", addr.String()).Error("[magic-dns] 启动 TCP DNS server 失败(UDP 不受影响)")
		return func() {}
	}
	logrus.WithField("addr", addr.String()).Info("[magic-dns] TCP/53 已启动(RFC 7766;截断应答的回落路径)")

	go safeGlobalGoroutine("magicDNSTCP", globalContextCancel, func() {
		runMagicDNSTCPAcceptLoop(globalContext, gw, ln, resolved)
	})
	return func() { _ = ln.Close() }
}

// runMagicDNSTCPAcceptLoop accept 循环：每条连接一个 goroutine，受 magicDNSTCPMaxConns 封顶。
// 超上限时**立即关掉新连接**而不是排队等待——排队会让 accept 队列堆积、把压力藏起来；直接关闭则让使用方
// 立刻知道并回退 UDP 或重试。
func runMagicDNSTCPAcceptLoop(ctx context.Context, gw *gatewayState, ln *net.TCPListener, r magicDNSResolved) {
	for {
		if ctx.Err() != nil {
			return
		}
		_ = ln.SetDeadline(time.Now().Add(2 * time.Second)) // 借此 tick 检查 ctx.Done
		c, err := ln.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			logrus.WithError(err).Debug("[magic-dns] TCP Accept 错误")
			continue
		}
		if magicDNSTCPConnCount.Add(1) > magicDNSTCPMaxConns {
			magicDNSTCPConnCount.Add(-1)
			magicDNSTCPRejectedCount.Add(1)
			_ = c.Close()
			continue
		}
		magicDNSTCPAcceptedCount.Add(1)
		go safeGoroutine("magic_dns_tcp_conn", func() {
			defer magicDNSTCPConnCount.Add(-1)
			defer c.Close()
			serveMagicDNSTCPConn(ctx, gw, c, r)
		})
	}
}

// serveMagicDNSTCPConn 在一条 TCP 连接上循环处理查询（RFC 7766 允许在同一连接上连发多条）。
// 空闲超过 magicDNSTCPIdleTimeout 即关闭。任何读错误 / 非法长度都直接结束该连接（不试图重新对齐字节流——
// 一旦错位就无法可靠恢复，关掉让使用方重连才是正确处置）。
func serveMagicDNSTCPConn(ctx context.Context, gw *gatewayState, c net.Conn, r magicDNSResolved) {
	w := &tcpDNSReplyConn{conn: c}
	// 把 TCP 对端合成成等价的 *net.UDPAddr：既有的 ACL / 组网隔离 / 限流 / ECS 会话查找全按「使用方 vIP」
	// 判断，合成后这些逻辑完全无需感知传输层。
	peer := magicDNSPeerFromTCP(c.RemoteAddr())
	if peer == nil {
		return
	}
	var lenBuf [2]byte
	for {
		if ctx.Err() != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(magicDNSTCPIdleTimeout))
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return // EOF / 空闲超时 / 对端半关：正常收摊
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n == 0 || n > magicDNSTCPMaxQuerySize {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		// 与 UDP 侧同款在途限流:TCP 不能成为绕过全局池 / 单客户端配额的后门。占不到坑就直接结束连接
		// (不回 SERVFAIL —— 与 UDP 的 drop 语义一致,使用方自然重试)。
		clientKey, haveKey := netipAddrFromUDP(peer)
		release, ok := tryAcquireMagicDNSSlot(clientKey, haveKey)
		if !ok {
			return
		}
		// 同一连接上串行处理:TCP 是有序流,逐条处理天然保序,也让 release 的生命周期简单可证。
		func() {
			defer release()
			handleMagicDNSPacket(ctx, gw, w, peer, query, r)
		}()
	}
}

// magicDNSUpstreamTCPTimeout 是「上游回 TC=1 → 改用 TCP 重查」的整体超时。比 UDP 的 800ms 宽一些：TCP 多一次
// 握手 RTT，而这条路径本就罕见（只在上游装不下应答时），宁可多等 700ms 也别把完整答案丢掉。
const magicDNSUpstreamTCPTimeout = 1500 * time.Millisecond

// magicDNSUpstreamTCPRetryCount:因上游回 TC=1 而改走 TCP 重查的次数,供 /status 观测。
var magicDNSUpstreamTCPRetryCount atomic.Uint64

// dialAndQueryTCP 用 TCP 向 addr 发一条 DNS 查询并读回应答（长度前缀成帧）。
//
// 校验与 UDP 路径同口径（dnsReplyMatches：Response 位 + TXID + question 相符）：TCP 三次握手已排除盲注，但
// 「上游把别人的应答串给我们」这类实现缺陷仍存在，且这份答案会进缓存喂给后续所有使用方，代价太大 ——
// 多一次校验换一份确定性。
func dialAndQueryTCP(ctx context.Context, addr string, query []byte, timeout time.Duration) ([]byte, error) {
	if len(query) > 0xffff {
		return nil, errDNSReplyTooLongForTCP
	}
	wantID, wantQ, haveKey := parseDNSQueryKey(query)

	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := c.Write(frame); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 {
		return nil, errors.New("upstream tcp dns returned an empty frame")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	// haveKey=false:查询本身解析不出 key(异常报文)→ 与 UDP 路径同样退回「收到即用」,不改变可用性。
	if haveKey && !dnsReplyMatches(resp, wantID, wantQ) {
		return nil, errors.New("upstream tcp dns reply does not match the query")
	}
	return resp, nil
}

// magicDNSPeerFromTCP 把 TCP 对端地址转成等价的 *net.UDPAddr（IP + Port 原样搬运）。
// 非 *net.TCPAddr（不该发生）→ nil，调用方放弃该连接。
func magicDNSPeerFromTCP(a net.Addr) *net.UDPAddr {
	ta, ok := a.(*net.TCPAddr)
	if !ok || ta == nil || ta.IP == nil {
		return nil
	}
	return &net.UDPAddr{IP: ta.IP, Port: ta.Port, Zone: ta.Zone}
}
