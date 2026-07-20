package main

import (
	"net"
	"net/http"
	"time"
)

// handshakeDeadlineListener 在 Accept 返回 net.Conn 之前给它套一个握手截止时间。
// 用于在 TLS / WS Upgrade 之前防御 Slow-loris / 半开连接攻击 —— 攻击者大量发起
// TCP 连接但不完成 TLS ClientHello / HTTP 头读取,占满 accept queue 与握手 goroutine。
//
// 关键不变量:
//   - Accept 返回的 net.Conn 已带 deadline,业务方完成握手后**必须**调用
//     `conn.SetDeadline(time.Time{})` 清掉,否则后续长连接业务会被错误地终止。
//   - 数据面 wss 路径在 vpn_listen.go 的 mux.HandleFunc 里 Upgrade 成功后,
//     util.NewWSStreamConn 包装的 net.Conn 透传到 dispatchVPNIncoming;那个路径
//     现在需要手动清掉 deadline(见 vpn_listen.go 的修改)。
//   - 保活 wss 同上,Upgrade 成功后 runHysteriaKeepaliveWSConn 入口清掉。
//
// 与 reality_listen.go 的 realityAcceptDeadlineListener 实现等价,但 reality 用的
// 是 net.Listener 的子集 + 单独的常量(REALITY 端口对公网,握手限并发 1024),所以
// 两个文件保留独立类型避免耦合,共用太多反而难维护。
type handshakeDeadlineListener struct {
	net.Listener
	timeout time.Duration
}

func newHandshakeDeadlineListener(ln net.Listener, timeout time.Duration) net.Listener {
	if timeout <= 0 {
		return ln
	}
	return &handshakeDeadlineListener{Listener: ln, timeout: timeout}
}

func (l *handshakeDeadlineListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(l.timeout))
	return c, nil
}

// wssHandshakeTimeout 数据面 / 保活 wss 入口握手超时。15s 给慢速移动网络 + 大握手
// 留充裕余量,同时把 Slow-loris 攻击者拖死(超时即断)。
const wssHandshakeTimeout = 15 * time.Second

// strictWSCheckOrigin 实现 gorilla/websocket Upgrader.CheckOrigin 的严格版:
//   - Origin header 为空 → 通过(native 客户端正常不带);
//   - Origin header 非空 → 拒绝(浏览器才会自动加,VPN 客户端不应该有)。
//
// 这样无需维护白名单,直接挡住所有「浏览器恶意 WS CSRF」尝试。代价是不能在浏览器
// 调试本地 wss(临时改 true 即可);考虑到 VPN 协议体复杂,生产中没人在浏览器里
// 直接调试数据面 WS,这个代价可以忽略。
//
// 注:此处 *http.Request 必非 nil(gorilla 调用方保证),不再加 nil 防御。
func strictWSCheckOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin == ""
}
