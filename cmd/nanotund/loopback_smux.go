package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/util"
)

// loopbackSmuxMagic 写在环回 smux 承载 TCP 的最前面，便于与直连明文链路帧区分。
var loopbackSmuxMagic = []byte("VPN1")

func buildSmuxConfigFrom(c *config.SmuxConfig) *smux.Config {
	if c == nil {
		return smux.DefaultConfig()
	}
	dc := smux.DefaultConfig()
	out := &smux.Config{
		Version:           dc.Version,
		KeepAliveDisabled: dc.KeepAliveDisabled,
		KeepAliveInterval: dc.KeepAliveInterval,
		KeepAliveTimeout:  dc.KeepAliveTimeout,
		MaxFrameSize:      dc.MaxFrameSize,
		MaxReceiveBuffer:  dc.MaxReceiveBuffer,
		MaxStreamBuffer:   dc.MaxStreamBuffer,
	}
	if c.Version == 1 || c.Version == 2 {
		out.Version = c.Version
	}
	if c.KeepAliveDisabled {
		out.KeepAliveDisabled = true
	}
	if c.KeepAliveIntervalSec > 0 {
		out.KeepAliveInterval = time.Duration(c.KeepAliveIntervalSec) * time.Second
	}
	if c.KeepAliveTimeoutSec > 0 {
		out.KeepAliveTimeout = time.Duration(c.KeepAliveTimeoutSec) * time.Second
	}
	if c.MaxFrameSize > 0 {
		out.MaxFrameSize = c.MaxFrameSize
	}
	if c.MaxReceiveBuffer > 0 {
		out.MaxReceiveBuffer = c.MaxReceiveBuffer
	}
	if c.MaxStreamBuffer > 0 {
		out.MaxStreamBuffer = c.MaxStreamBuffer
	}
	// 纵深防御:config.Validate 已在启动期校验用户显式值,但「用户值 + 默认值」的混合组合仍可能触发
	// smux 的跨字段约束(如用户只设 max_stream_buffer 且 > 默认 max_receive_buffer)。若最终 config 非法,
	// 回退全默认并告警 —— 远好过让每条连接静默 VerifyConfig 失败、数据面整体不可用。
	if err := smux.VerifyConfig(out); err != nil {
		logrus.WithError(err).Warn("[smux] the synthesized config failed VerifyConfig, falling back to the smux defaults")
		return smux.DefaultConfig()
	}
	return out
}

func loopbackSmuxMultiplexEnabled(cfg *config.Config) bool {
	if cfg == nil || cfg.Smux == nil {
		return false
	}
	if cfg.Hysteria.HysteriaActive() {
		return true
	}
	return strings.TrimSpace(cfg.Reality.ListenAddr) != ""
}

// connBufCloser 将已 Peek 的数据通过 bufio 交给后续 Read。
type connBufCloser struct {
	net.Conn
	r *bufio.Reader
}

func (c *connBufCloser) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// loopbackSmuxPool 本机 hy2 / REALITY 共用的单条 WebSocket + smux；每逻辑 VPN 一条 stream。
type loopbackSmuxPool struct {
	wsURL   string
	smuxCfg *smux.Config
	tlsDial *tls.Config // wss 环回时非 nil（通常为 InsecureSkipVerify）

	mu   sync.Mutex
	sess *smux.Session
	// dialing 非 nil = 已有一名调用者正在重建会话(拨号在**锁外**进行)。其余调用者等它关闭后重取 sess,
	// 而不是各自再拨一次 —— 见 OpenStream。
	dialing chan struct{}
}

func newLoopbackSmuxPool(wsURL string, smuxCfg *smux.Config, tlsDial *tls.Config) *loopbackSmuxPool {
	return &loopbackSmuxPool{wsURL: wsURL, smuxCfg: smuxCfg, tlsDial: tlsDial}
}

// loopbackSmuxDialTimeout 是环回 WSS 握手的上限。它同时是 OpenStream 慢路径的最长等待。
const loopbackSmuxDialTimeout = 15 * time.Second

// OpenStream 取一条复用 stream;会话不存在 / 已关闭时按需重建。
//
// 第二十三轮深扫 MED:重建的**拨号必须在锁外**。此前 OpenStream 全程持 p.mu 并在锁内调
// DialVPNWebSocket(15s 上限),于是环回 WSS 变慢或不可达时:① 每个等锁的调用者依次各拨一次,N 个并发调用
// 被放大成 N×15s 的串行阻塞;② 期间任何 hy2 / REALITY 新流都卡在这把锁上 —— 一次慢握手把整个节点的新连接
// 全部串行化。现在改为 singleflight:同一时刻只有一名调用者拨号(锁外),其余等它的结果;失败也只失败一次。
func (p *loopbackSmuxPool) OpenStream() (net.Conn, error) {
	// 最多三轮,每轮至多推进一步,不无限重试:① 等别人在飞的那次重建;② 复用的会话开流失败、摘掉尸体;
	// ③ 自己拨一次。
	for attempt := 0; attempt < 3; attempt++ {
		p.mu.Lock()
		if sess := p.sess; sess != nil && !sess.IsClosed() {
			p.mu.Unlock()
			st, err := sess.OpenStream()
			if err == nil {
				return &poolStream{Stream: st, pool: p, sess: sess}, nil
			}
			// 第二十五轮深扫 MED:会话对象自称还活着,开流却失败 —— 承载已断,而 smux 要等 keepalive
			// 超时(DefaultConfig 30s)才把会话标记为死。期间 IsClosed() 恒 false,clearOnClose 也还没
			// 醒,于是池子会一直往这具尸体上开流:每条新 hy2 / REALITY 流都以 broken pipe 失败,长达半分钟,
			// 而重拨一条环回只要几毫秒。这里立刻摘掉它,本轮之后重建。
			p.dropSession(sess)
			continue
		}
		if ch := p.dialing; ch != nil {
			p.mu.Unlock()
			<-ch // 等在飞的那次重建落地,不再各自拨一次
			continue
		}
		ch := make(chan struct{})
		p.dialing = ch
		p.mu.Unlock()

		sess, err := p.dialNewSession()
		p.mu.Lock()
		if err == nil {
			p.sess = sess
		}
		p.dialing = nil
		p.mu.Unlock()
		close(ch) // 唤醒等待者(无论成败:失败时它们会自己再试一轮)
		if err != nil {
			return nil, err
		}
		st, err := sess.OpenStream()
		if err != nil {
			return nil, err
		}
		return &poolStream{Stream: st, pool: p, sess: sess}, nil
	}
	return nil, errors.New("loopback smux: the rebuilt session never became ready")
}

// poolStream 包住一条复用 stream,把「承载已断」的信号回传给池。
//
// 为什么必须从流上回传:承载断掉的那一刻 OpenStream 往往仍然成功(SYN 由 shaper 异步写出),错误要到
// 第一次 Read/Write 才浮出来;而 smux 只在 keepalive 超时(DefaultConfig 30s)后才把会话标记为死。
// 两者叠加的结果是:池子在这半分钟里把每条新 hy2 / REALITY 流都开在同一具尸体上,全部失败。回传之后,
// 代价收敛成「正好撞上断线的那一条流失败」,下一条流就落在新承载上。
type poolStream struct {
	*smux.Stream
	pool *loopbackSmuxPool
	sess *smux.Session
}

func (s *poolStream) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	s.noteIOError(err)
	return n, err
}

func (s *poolStream) Write(b []byte) (int, error) {
	n, err := s.Stream.Write(b)
	s.noteIOError(err)
	return n, err
}

// noteIOError 两侧共用:承载断了的时候,先撞上的可能是读也可能是写(取决于这条流当时在干什么),
// 所以两边都得回报,判据也必须是同一套。
func (s *poolStream) noteIOError(err error) {
	if carrierIsBroken(err) {
		s.pool.retireSession(s.sess)
	}
}

// carrierIsBroken 判断一次 stream I/O 错误是否说明**承载**出了问题(而不只是这条 stream 结束了)。
//
// 下面这几个是 stream 自身的生命周期 / 调用方 deadline,与承载无关:据此拆共享承载的话,每条正常
// 结束的连接都会把别人的流一起带走。其余的(承载 socket 的读写错误、smux 协议错误、stream id 用尽)
// 都意味着这条会话不该再接新流。
func carrierIsBroken(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, smux.ErrTimeout) {
		return false
	}
	return true
}

// dialNewSession 建一条新的环回 WSS + smux 客户端会话。**不持 p.mu**(见 OpenStream)。
func (p *loopbackSmuxPool) dialNewSession() (*smux.Session, error) {
	conn, err := util.DialVPNWebSocket(p.wsURL, loopbackSmuxDialTimeout, p.tlsDial)
	if err != nil {
		return nil, err
	}
	enableTCPKeepAlive(conn)
	if _, err := conn.Write(loopbackSmuxMagic); err != nil {
		_ = conn.Close()
		return nil, err
	}
	sess, err := smux.Client(conn, p.smuxCfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	// 第十四轮深扫 MED:包 safeGoroutine —— clearOnClose 阻塞在 sess.CloseChan() 等会话关闭,panic 只应 log、
	// 不拖垮整进程(与全站「无裸 go」不变量一致)。
	go safeGoroutine("loopbackSmux/clearOnClose", func() { p.clearOnClose(conn, sess) })
	return sess, nil
}

// retireSession 把一具疑似失效的会话从池里摘掉(仅当它仍是当前会话,避免误伤别人刚建好的新会话),
// 于是下一次 OpenStream 会重建。
//
// 故意**不** Close:承载真断了的话,smux 会在 keepalive 超时后自己收尸、clearOnClose 随后关掉那条 WSS;
// 而万一是误判,已经跑在这条会话上的流不会被连带掐断 —— 最坏结果只是多出一条承载,不会丢连接。
func (p *loopbackSmuxPool) retireSession(dead *smux.Session) {
	p.mu.Lock()
	if p.sess == dead {
		p.sess = nil
	}
	p.mu.Unlock()
}

// dropSession 用于「会话已确定不可用」(OpenStream 直接报错:socket 错误 / 协议错误 / stream id 用尽)。
// 除摘掉之外还要 Close —— 那才会唤醒 clearOnClose 去收底下那条环回 WSS,不必等 keepalive 超时。
func (p *loopbackSmuxPool) dropSession(dead *smux.Session) {
	p.retireSession(dead)
	_ = dead.Close()
}

func (p *loopbackSmuxPool) clearOnClose(conn net.Conn, sess *smux.Session) {
	<-sess.CloseChan()
	p.mu.Lock()
	if p.sess == sess {
		p.sess = nil
	}
	p.mu.Unlock()
	_ = conn.Close()
}

// loopbackDispatchPeekTimeout 是「识别这条连接是什么」的上限。
//
// 未认证的对端在这一步只要一个字节;一直不发就把 goroutine 和这块读缓冲白占着,是笔便宜的 DoS。
// 与 handleVPNLink 的 pre-login idle deadline 同量级,识别成功后立即撤销。
//
// var 而非 const:测试里调小到几百毫秒才能在秒级内验证「不发就踢」以及「识别完确实撤了 deadline」。
var loopbackDispatchPeekTimeout = 30 * time.Second

func setPeekDeadline(c net.Conn) error {
	return c.SetReadDeadline(time.Now().Add(loopbackDispatchPeekTimeout))
}

// dispatchVPNIncoming 区分直连链路帧与环回 smux 承载（魔法前缀 VPN1）。
func dispatchVPNIncoming(c net.Conn, gw *gatewayState, muxEnabled bool, smuxCfg *smux.Config) {
	if muxEnabled {
		br := bufio.NewReaderSize(c, 256)
		// 第二十五轮深扫 HIGH:这里只许**先看一个字节**。
		//
		// 直连原生客户端的首帧是 PoWChallengeReq,协议规定 body 必须为空 —— 线上恒为 3 字节
		// (2 长度 + 1 类型)。此前这里直接 Peek(4),于是启用 [smux] + hy2/REALITY 时:服务端等
		// 第 4 个字节,客户端等 PoWChallenge 回复,双方互相干等到超时,**所有直连客户端都登不进来**。
		// (三机 e2e 从未配 hy2/REALITY,这个组合一直没被跑到。)
		//
		// 环回桥接是把 4 字节魔法一次写出的,首字节必为 'V';链路帧的首字节是长度高位,只有在帧长
		// ≥0x5600 时才可能撞上 'V',而那时后续字节早已到齐,Peek(4) 不会等。所以「首字节匹配才要求
		// 看满 4 字节」既不会误判,也不会在直连路径上多等一个字节。
		if err := setPeekDeadline(c); err != nil {
			logrus.WithError(err).Debug("failed to set the read deadline for the data-plane connection detection phase")
		}
		head, err := br.Peek(1)
		if err == nil && head[0] == loopbackSmuxMagic[0] {
			head, err = br.Peek(4)
		}
		if err != nil {
			logrus.WithError(err).Debug("[dataplane] connection Peek failed")
			_ = c.Close()
			return
		}
		// 识别完就把 deadline 撤掉,后续握手期由 handleVPNLink 自己的 pre-login idle deadline 接管。
		_ = c.SetReadDeadline(time.Time{})
		if len(head) >= 4 && bytes.Equal(head[:4], loopbackSmuxMagic) {
			// M1 安全边界:VPN1/smux 承载(其上每条 stream 带可覆盖源地址的 PROXY v2 头)只应来自本机
			// 环回桥接(hy2/REALITY 恒 dial 127.0.0.1)。从**非环回**对端收到 VPN1 = 公网客户端在伪造
			// smux + PROXY 头冒充任意源 IP、绕过按 IP 的反滥用归因(登录限流 / IP 失败锁定 / 嫁祸受害 IP)。
			// 直接拒绝。直连 native 客户端不发 VPN1、走下方普通链路帧路径,其真实 IP 本就在 conn 上,不受影响。
			if !isLoopbackConnPeer(c) {
				loopbackSmuxForeignRejectCount.Add(1)
				logrus.WithField("remote", c.RemoteAddr().String()).
					Warn("rejecting a VPN1/smux carrier from a non-loopback source (likely a forged PROXY source address trying to bypass per-IP abuse controls)")
				_ = c.Close()
				return
			}
			if _, err := br.Discard(4); err != nil {
				_ = c.Close()
				return
			}
			wrapped := &connBufCloser{Conn: c, r: br}
			enableTCPKeepAlive(c)
			runLoopbackSmuxServerSide(wrapped, gw, smuxCfg)
			return
		}
		wrapped := &connBufCloser{Conn: c, r: br}
		enableTCPKeepAlive(c)
		handleVPNLink(wrapped, gw)
		return
	}
	enableTCPKeepAlive(c)
	handleVPNLink(c, gw)
}

func runLoopbackSmuxServerSide(rw io.ReadWriteCloser, gw *gatewayState, smuxCfg *smux.Config) {
	sess, err := smux.Server(rw, smuxCfg)
	if err != nil {
		logrus.WithError(err).Warn("loopback smux.Server failed")
		_ = rw.Close()
		return
	}
	defer func() { _ = sess.Close() }()
	logrus.Info("[dataplane] loopback smux carrier established, hy2/REALITY will multiplex onto this session")
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			logrus.WithError(err).Debug("smux AcceptStream ended")
			return
		}
		// per-stream goroutine:smux 单 stream panic 不应该拖死同 sess 上的其它复用 stream
		// (一条 hy2/REALITY 多路复用承载着所有进入这个节点的连接,挂掉就是全节点断)。
		// st.Close 在 safeGoroutine recover 后由 handleVPNLink 内的 defer raw.Close 兜底。
		// M1:每条 loopback smux stream 开头都带一个 PROXY v2 头,readLoopbackClientAddr 先读出
		// 真实客户端源地址并包装 conn,使 handleVPNLink 的 PoW/限流/审计看到真实 IP 而非环回地址。
		go safeGoroutine("handleVPNLink-smux", func() { handleVPNLink(readLoopbackClientAddr(st), gw) })
	}
}
