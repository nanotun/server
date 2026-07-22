package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
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
}

func newLoopbackSmuxPool(wsURL string, smuxCfg *smux.Config, tlsDial *tls.Config) *loopbackSmuxPool {
	return &loopbackSmuxPool{wsURL: wsURL, smuxCfg: smuxCfg, tlsDial: tlsDial}
}

func (p *loopbackSmuxPool) OpenStream() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureSessionLocked(); err != nil {
		return nil, err
	}
	return p.sess.OpenStream()
}

func (p *loopbackSmuxPool) ensureSessionLocked() error {
	if p.sess != nil && !p.sess.IsClosed() {
		return nil
	}
	p.sess = nil
	conn, err := util.DialVPNWebSocket(p.wsURL, 15*time.Second, p.tlsDial)
	if err != nil {
		return err
	}
	enableTCPKeepAlive(conn)
	if _, err := conn.Write(loopbackSmuxMagic); err != nil {
		_ = conn.Close()
		return err
	}
	sess, err := smux.Client(conn, p.smuxCfg)
	if err != nil {
		_ = conn.Close()
		return err
	}
	p.sess = sess
	go p.clearOnClose(conn, sess)
	return nil
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
