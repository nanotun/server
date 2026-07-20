package util

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSStreamConn 将 WebSocket Binary 消息序列视为连续字节流：每次 Write 发出一条 Binary；
// Read 按顺序消费各条 Binary 中的字节（与 TCP 流语义一致，供 smux 与链路帧 ReadFull 使用）。
type WSStreamConn struct {
	c       *websocket.Conn
	readBuf []byte
	writeMu sync.Mutex
}

// WSReadLimitBytes 单条 WebSocket Binary 消息可接受的最大字节数。
//
// 上层链路帧 L 是 uint16，因此一条 link frame 最多 2 + MaxLinkFrameBody = 65537 字节；
// 此外 smux 帧（默认 MaxFrameSize 32KB，上限 65535）也复用本 conn。
// 取 80 KiB 作为统一上限：足以覆盖 link / smux 任一帧 + 少量握手字节，
// 又能让 gorilla websocket 在恶意客户端发超大单帧时立即报错（NextReader 触发
// websocket.ErrReadLimit），避免一次 make([]byte, N) 触发巨量 alloc。
//
// 注：gorilla 默认 ReadLimit = 0（不限），所以不显式 SetReadLimit 就有 DoS 面。
const WSReadLimitBytes int64 = 80 * 1024

// NewWSStreamConn 包装已 Upgrade 的 WebSocket 连接。
//
// 调用方完成 Upgrade 后传入即可；本函数会对 c 设置 ReadLimit，避免恶意端 peer
// 发送超大单 WS 帧让进程一次性 alloc 巨量 buffer（gorilla 默认无 limit）。
func NewWSStreamConn(c *websocket.Conn) net.Conn {
	c.SetReadLimit(WSReadLimitBytes)
	return &WSStreamConn{c: c}
}

// DialVPNWebSocket 建立 VPN 数据面 WebSocket（ws/wss），超时用于握手阶段。
// tlsClient 非 nil 时用于 wss 客户端 TLS（如环回自签：InsecureSkipVerify）；ws URL 或未使用 wss 时可传 nil。
func DialVPNWebSocket(wsURL string, handshakeTimeout time.Duration, tlsClient *tls.Config) (net.Conn, error) {
	d := websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
		TLSClientConfig:  tlsClient,
	}
	c, _, err := d.Dial(wsURL, nil)
	if err != nil {
		return nil, err
	}
	return NewWSStreamConn(c), nil
}

func (s *WSStreamConn) Read(p []byte) (int, error) {
	if len(s.readBuf) == 0 {
		mt, data, err := s.c.ReadMessage()
		if err != nil {
			return 0, err
		}
		if mt != websocket.BinaryMessage {
			return 0, io.ErrUnexpectedEOF
		}
		s.readBuf = data
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *WSStreamConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *WSStreamConn) Close() error {
	return s.c.Close()
}

// UnderlyingConn 供开启 TCP keepalive 等；与 gorilla/websocket.Conn 行为一致。
func (s *WSStreamConn) UnderlyingConn() net.Conn {
	return s.c.UnderlyingConn()
}

func (s *WSStreamConn) LocalAddr() net.Addr {
	return s.c.LocalAddr()
}

func (s *WSStreamConn) RemoteAddr() net.Addr {
	return s.c.RemoteAddr()
}

func (s *WSStreamConn) SetDeadline(t time.Time) error {
	_ = s.c.SetReadDeadline(t)
	return s.c.SetWriteDeadline(t)
}

func (s *WSStreamConn) SetReadDeadline(t time.Time) error {
	return s.c.SetReadDeadline(t)
}

func (s *WSStreamConn) SetWriteDeadline(t time.Time) error {
	return s.c.SetWriteDeadline(t)
}
