package main

import (
	"bufio"
	"net"
	"testing"

	proxyproto "github.com/pires/go-proxyproto"
)

// 环回 smux 承载上的「真实客户端 IP 透传」。
//
// hy2 / REALITY 握手完成后经本机环回 smux 回到 VPN 数据面,服务端看到的对端是 127.0.0.1。
// 按 IP 的 PoW / 登录限流 / IP 失败锁定 / 审计因此全部塌到环回地址 —— 所有 hy2 客户端被当成
// 同一个来源,单个滥用者无法隔离,anti-abuse 形同虚设。修法是每条 stream 开头写一个 PROXY v2 头
// 把真实源带过去。
//
// 这里钉两处。一是地址归一:go-proxyproto 要求 src 与 dst **同类型**,否则整个头**静默**退化成
// LOCAL(无源)。环回 smux 的 dst 恒是 TCP,而 hy2 的客户端地址来自 QUIC —— *net.UDPAddr。
// 不归一就退化,而退化不报错(2026-07-25 双机实测:hy2 会话的审计 actor 仍是 127.0.0.1)。
// 二是承载入口的对端校验:这条路径允许用 PROXY 头覆盖源地址,所以**只能**接受来自环回的对端,
// 否则任何公网客户端都能自己发 VPN1 魔法 + 伪造头冒充任意 IP,绕过按 IP 的限流或嫁祸某受害 IP。

// addrOnlyConn 是只提供 RemoteAddr 的 net.Conn —— isLoopbackConnPeer 只看那一项。
type addrOnlyConn struct {
	net.Conn
	remote net.Addr
}

func (c *addrOnlyConn) RemoteAddr() net.Addr { return c.remote }

// fakeAddr 是一个既不是 TCPAddr 也不是 UDPAddr 的 net.Addr(模拟自定义包装)。
type fakeAddr struct{ s string }

func (f fakeAddr) Network() string { return "fake" }
func (f fakeAddr) String() string  { return f.s }

// TestNormalizeProxyAddr_TurnsQUICAddressesIntoSomethingTheHeaderAccepts hy2 那条路必须归一。
func TestNormalizeProxyAddr_TurnsQUICAddressesIntoSomethingTheHeaderAccepts(t *testing.T) {
	t.Run("UDP 地址归一成 TCP", func(t *testing.T) {
		got := normalizeProxyAddr(&net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 41234})
		if got == nil {
			t.Fatal("hy2 的 QUIC 地址被丢掉了 —— 头会退化成 LOCAL,真实 IP 透传形同未做")
		}
		if got.IP.String() != "203.0.113.7" || got.Port != 41234 {
			t.Errorf("归一成 %v,期望 203.0.113.7:41234", got)
		}
	})

	t.Run("TCP 地址原样返回", func(t *testing.T) {
		in := &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 443}
		if got := normalizeProxyAddr(in); got != in {
			t.Errorf("TCP 地址不该被改写: %v", got)
		}
	})

	t.Run("IPv6 带 zone 也要保住", func(t *testing.T) {
		got := normalizeProxyAddr(&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 5000, Zone: "eth0"})
		if got == nil || got.Zone != "eth0" {
			t.Errorf("zone 丢了: %+v —— link-local 地址少了 zone 就不完整", got)
		}
	})

	t.Run("其它 net.Addr 按字符串解析", func(t *testing.T) {
		got := normalizeProxyAddr(fakeAddr{s: "192.0.2.5:8080"})
		if got == nil || got.IP.String() != "192.0.2.5" || got.Port != 8080 {
			t.Errorf("自定义 Addr 解析成 %v,期望 192.0.2.5:8080", got)
		}
		if got := normalizeProxyAddr(fakeAddr{s: "[2001:db8::1]:8080"}); got == nil || got.Port != 8080 {
			t.Errorf("带方括号的 v6 形态没解析出来: %v", got)
		}
	})

	t.Run("拿不到 IP:port 一律返回 nil", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			in   net.Addr
		}{
			{"nil 接口", nil},
			{"空 IP 的 TCPAddr", &net.TCPAddr{Port: 443}},
			{"空 IP 的 UDPAddr", &net.UDPAddr{Port: 443}},
			{"拆不出 host:port", fakeAddr{s: "not-an-address"}},
			{"host 不是 IP", fakeAddr{s: "example.com:443"}},
			{"端口不是数字也不是服务名", fakeAddr{s: "192.0.2.5:nosuchservice"}},
		} {
			if got := normalizeProxyAddr(tc.in); got != nil {
				t.Errorf("%s 归一出了 %v,期望 nil —— 宁可写 LOCAL 头,也不能给对端一个残缺的源地址",
					tc.name, got)
			}
		}
	})
}

// TestWriteLoopbackProxyHeader_CarriesTheRealClientIPForQUICPeers 端到端:写头 → 读回来。
//
// 单看归一函数还不够 —— 真正出过事的是「src 是 UDPAddr、dst 是 TCPAddr」这个组合让整个头静默
// 退化。这里就按那个组合写一次头,再解回来确认源地址真的在里面。
func TestWriteLoopbackProxyHeader_CarriesTheRealClientIPForQUICPeers(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.77"), Port: 51000} // hy2:QUIC 对端
	dst := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}     // 环回 smux 入口

	errCh := make(chan error, 1)
	go func() { errCh <- writeLoopbackProxyHeader(client, src, dst) }()

	hdr, err := proxyproto.Read(bufio.NewReader(server))
	if err != nil {
		t.Fatalf("读 PROXY 头: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("写 PROXY 头: %v", err)
	}
	if hdr.Command != proxyproto.PROXY {
		t.Fatalf("头退化成 %v(应为 PROXY) —— 这正是 hy2 会话审计 actor 仍是 127.0.0.1 的原因", hdr.Command)
	}
	got, _ := hdr.SourceAddr.(*net.TCPAddr)
	if got == nil || got.IP.String() != "203.0.113.77" || got.Port != 51000 {
		t.Errorf("头里的源地址是 %v,期望 203.0.113.77:51000", hdr.SourceAddr)
	}
}

// TestIsLoopbackConnPeer_OnlyTrustsTheLoopbackBridge 承载入口只信环回对端。
//
// 这条路径允许用 PROXY 头覆盖源地址,所以它就是一道边界:放开非环回对端,等于让任何公网客户端
// 自己发 VPN1 魔法 + 伪造头冒充任意源 IP —— 既能绕过按 IP 的登录限流 / 失败锁定,也能把封禁
// 嫁祸给某个受害 IP。
func TestIsLoopbackConnPeer_OnlyTrustsTheLoopbackBridge(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr net.Addr
		want bool
	}{
		{"127.0.0.1", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}, true},
		{"127.0.0.0/8 里的别的地址", &net.TCPAddr{IP: net.ParseIP("127.5.6.7"), Port: 1}, true},
		{"::1", &net.TCPAddr{IP: net.ParseIP("::1"), Port: 1}, true},
		{"公网地址", &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 1}, false},
		{"内网地址", &net.TCPAddr{IP: net.ParseIP("192.168.1.5"), Port: 1}, false},
		{"解析不出 IP 的对端", fakeAddr{s: "some-pipe"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLoopbackConnPeer(&addrOnlyConn{remote: tc.addr}); got != tc.want {
				t.Errorf("判定 %v,期望 %v —— 放开非环回对端就等于让公网客户端伪造 PROXY 头冒充任意源 IP",
					got, tc.want)
			}
		})
	}

	t.Run("入口守卫", func(t *testing.T) {
		if isLoopbackConnPeer(nil) {
			t.Error("nil 连接被当成环回 —— 该路径会接受伪造的源地址")
		}
		if isLoopbackConnPeer(&addrOnlyConn{remote: nil}) {
			t.Error("拿不到对端地址却当成环回")
		}
	})
}
