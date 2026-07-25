package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
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
		logrus.WithError(err).Warn("[smux] 合成配置未通过 VerifyConfig,回退 smux 默认配置")
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
	// 最多两轮:第一轮可能是「等别人重建」,若那次失败则本轮自己成为拨号者。再失败即返回,不无限重试。
	for attempt := 0; attempt < 2; attempt++ {
		p.mu.Lock()
		if sess := p.sess; sess != nil && !sess.IsClosed() {
			p.mu.Unlock()
			return sess.OpenStream()
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
		return sess.OpenStream()
	}
	return nil, errors.New("loopback smux: 会话重建未能就绪")
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

func (p *loopbackSmuxPool) clearOnClose(conn net.Conn, sess *smux.Session) {
	<-sess.CloseChan()
	p.mu.Lock()
	if p.sess == sess {
		p.sess = nil
	}
	p.mu.Unlock()
	_ = conn.Close()
}

// dispatchVPNIncoming 区分直连链路帧与环回 smux 承载（魔法前缀 VPN1）。
func dispatchVPNIncoming(c net.Conn, gw *gatewayState, muxEnabled bool, smuxCfg *smux.Config) {
	if muxEnabled {
		br := bufio.NewReaderSize(c, 256)
		head, err := br.Peek(4)
		if err != nil {
			logrus.WithError(err).Debug("VPN 连接 Peek 失败")
			_ = c.Close()
			return
		}
		if len(head) >= 4 && bytes.Equal(head[:4], loopbackSmuxMagic) {
			// M1 安全边界:VPN1/smux 承载(其上每条 stream 带可覆盖源地址的 PROXY v2 头)只应来自本机
			// 环回桥接(hy2/REALITY 恒 dial 127.0.0.1)。从**非环回**对端收到 VPN1 = 公网客户端在伪造
			// smux + PROXY 头冒充任意源 IP、绕过按 IP 的反滥用归因(登录限流 / IP 失败锁定 / 嫁祸受害 IP)。
			// 直接拒绝。直连 native 客户端不发 VPN1、走下方普通链路帧路径,其真实 IP 本就在 conn 上,不受影响。
			if !isLoopbackConnPeer(c) {
				loopbackSmuxForeignRejectCount.Add(1)
				logrus.WithField("remote", c.RemoteAddr().String()).
					Warn("拒绝非环回来源的 VPN1/smux 承载(疑似伪造 PROXY 源地址绕过按 IP 反滥用)")
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
		logrus.WithError(err).Warn("环回 smux.Server 失败")
		_ = rw.Close()
		return
	}
	defer func() { _ = sess.Close() }()
	logrus.Info("环回 VPN：smux 承载已建立，hy2/REALITY 将多路复用至本会话")
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			logrus.WithError(err).Debug("smux AcceptStream 结束")
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
