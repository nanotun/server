package main

import (
	"bufio"
	"net"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/sirupsen/logrus"
)

// M1(真实客户端 IP 透传):hy2 / REALITY 握手完成后经**环回 smux**多路复用回本机 VPN 数据面。
// 服务端此前只能看到环回对端 127.0.0.1,导致按 IP 的 PoW / 登录限流 / IP 失败计数 / 审计全部塌到
// 环回地址(所有 hy2/REALITY 客户端被当成同一个来源,单个滥用者无法被隔离,anti-abuse 形同虚设)。
//
// 修法:在**每条** loopback smux stream 的最前面写一行 PROXY protocol v2 头,把真实源地址透传给
// 服务端解析。约定:每条 loopback smux stream 开头有且仅有一个 PROXY v2 头 ——
//   - REALITY:桥接 goroutine 持有 realityConn,写真实源(RemoteAddr)+ 入口(LocalAddr);
//   - hy2    :共享 smux 池无法把某条 stream 关联回具体客户端(hysteria Outbound 接口不透出
//              客户端地址),写 LOCAL(无源)头 —— 服务端据此回退环回地址(与既有行为一致),
//              但读头路径对每条 stream 统一,无需区分来源协议。
//
// 服务端 runLoopbackSmuxServerSide 对每条 accept 到的 stream 先经 readLoopbackClientAddr 读该头,
// 再进入 handleVPNLink;handleVPNLink 全程用 raw.RemoteAddr(),故包装后 PoW/限流/审计自动看真实 IP。
//
// 注意:该头**仅**用于环回 smux 承载。直连 native 客户端(ws/wss)不经此路径、不写不读该头,
// 其真实 IP 本就在 WebSocket 的 r.RemoteAddr 里,行为不变。

// loopbackProxyHeaderReadTimeout 服务端读单条 stream 开头 PROXY 头的上限。头由本进程另一侧即时写出,
// 正常远小于此;设超时只为个别异常 stream 不至于卡死其 goroutine。
const loopbackProxyHeaderReadTimeout = 10 * time.Second

// writeLoopbackProxyHeader 向环回 smux stream 写一行 PROXY v2 头。src/dst 任一非 *net.TCPAddr 时
// go-proxyproto 退化为 LOCAL(无源)头。REALITY 传 realityConn.RemoteAddr()/LocalAddr()。
func writeLoopbackProxyHeader(w net.Conn, src, dst net.Addr) error {
	_, err := proxyproto.HeaderProxyFromAddrs(2, src, dst).WriteTo(w)
	return err
}

// writeLoopbackProxyHeaderLocal 写一个 LOCAL(无源)PROXY v2 头,用于 hy2 这类拿不到客户端地址的场景,
// 保证服务端「每条 stream 都先读一个头」的约定成立。
func writeLoopbackProxyHeaderLocal(w net.Conn) error {
	_, err := proxyproto.HeaderProxyFromAddrs(2, nil, nil).WriteTo(w)
	return err
}

// proxyAddrConn 包一层 loopback smux stream:RemoteAddr() 返回 PROXY 头解析出的真实客户端地址,
// 其余读写 / SetDeadline / Close 委托底层 stream。已被 bufio 预读的残留字节经 br 透出,不丢帧。
type proxyAddrConn struct {
	net.Conn
	br         *bufio.Reader
	realRemote net.Addr // nil = 回退底层(环回)地址
}

func (c *proxyAddrConn) Read(b []byte) (int, error) { return c.br.Read(b) }

func (c *proxyAddrConn) RemoteAddr() net.Addr {
	if c.realRemote != nil {
		return c.realRemote
	}
	return c.Conn.RemoteAddr()
}

// readLoopbackClientAddr 从 loopback smux stream 读开头的 PROXY v2 头,返回一个 RemoteAddr() 反映
// 真实客户端地址的包装 conn。读失败 / LOCAL 头(无源)时 realRemote=nil(回退环回地址),但仍用同一个
// bufio.Reader 包装以免丢弃已读入缓冲的后续帧字节。带读超时,避免个别 stream 卡在读头拖住其 goroutine。
func readLoopbackClientAddr(st net.Conn) net.Conn {
	br := bufio.NewReaderSize(st, 256)
	_ = st.SetReadDeadline(time.Now().Add(loopbackProxyHeaderReadTimeout))
	hdr, err := proxyproto.Read(br)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		// 本进程另一侧应当总会写一个头;读失败多为 stream 早断。回退环回地址,交由 handleVPNLink 处理后续。
		logrus.WithError(err).Debug("环回 smux stream 读取 PROXY 头失败,回退环回源地址")
		return &proxyAddrConn{Conn: st, br: br}
	}
	if src, _, ok := hdr.TCPAddrs(); ok && src != nil {
		return &proxyAddrConn{Conn: st, br: br, realRemote: src}
	}
	// LOCAL 头(hy2)或非 TCP:回退环回地址。
	return &proxyAddrConn{Conn: st, br: br}
}
