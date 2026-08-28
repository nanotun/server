package main

// hy2 出口的成功路径。
//
// 已有测试把失败面钉得挺全(pool 为 nil、拨号超时、调优参数越界、端口被占……),缺的是
// **真的跑通一条**。而这条路上有两个只在成功时才成立、错了又完全不报错的性质:
//
//  1. reqAddr 绝不能当 dial 目标。hy2 出口恒环回本机 VPN 数据面 —— 一旦拿它去拨,
//     nanotun 就变成一台任意 TCP 开放代理,任何持密码的客户端都能借它连内网。
//  2. 每条 stream 开头的 PROXY v2 头必须带**真实**客户端地址。带不上不会报错,
//     只是所有 hy2 客户端塌进 127.0.0.1 这一个桶:loginIPLimiter / powIPLimiter 都按
//     remoteAddr 的 host 分桶,于是单个滥用者就能把全部 hy2 用户一起限死。而客户端
//     transport=auto 优先选的正是 hy2。

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// hy2RelayHandoff 照 hysteria v2.9.2 handleTCPRequest 的真实顺序走一遍:
// RequestHook.TCP 埋 token → EventLogger.TCPRequest 记真实地址 → 把同一个 reqAddr 交给 Outbound。
// 顺序错了(比如先 Take 再 put)真实地址就取不到,所以这里必须照抄那三行的次序。
func hy2RelayHandoff(t *testing.T, relay *hy2ClientAddrRelay, clientAddr net.Addr) string {
	t.Helper()
	reqAddr := "example.com:443" // 客户端请求的目标,会被 hook 无条件覆盖成 token
	if _, err := relay.TCP(nil, &reqAddr); err != nil {
		t.Fatalf("RequestHook.TCP: %v", err)
	}
	if !strings.HasPrefix(reqAddr, hy2AddrTokenPrefix) {
		t.Fatalf("hook 应把 reqAddr 覆盖成 token, got %q", reqAddr)
	}
	relay.TCPRequest(clientAddr, "auth-id", reqAddr)
	return reqAddr
}

// TestVpnSmuxStreamOutbound_CarriesTheRealClientAddrToTheLoopback
// smux 出口的成功路径:落到环回、且服务端看到的是**客户端**的地址。
//
// 这是 hy2 侧「按真实 IP 归因」的唯一实现路径(REALITY 那边桥接 goroutine 自己持有 conn,
// hy2 拿不到,只能靠 relay 传一手)。传不到不会报错,表现是所有 hy2 客户端共用一个限流桶。
func TestVpnSmuxStreamOutbound_CarriesTheRealClientAddrToTheLoopback(t *testing.T) {
	echo := startLoopbackWSEcho(t, true)
	listenAddr, wsPath, seen := echo.listenAddr, echo.wsPath, echo.seen
	pool := newLoopbackSmuxPool(loopbackVPNWebSocketURL(listenAddr, wsPath, false), smux.DefaultConfig(), nil)
	relay := newHy2ClientAddrRelay()
	out := &vpnSmuxStreamOutbound{pool: pool, relay: relay}

	client := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 5555} // hy2 是 QUIC,来的是 UDPAddr
	reqAddr := hy2RelayHandoff(t, relay, client)

	st, err := out.TCP(reqAddr)
	if err != nil {
		t.Fatalf("TCP: %v", err)
	}
	defer func() { _ = st.Close() }()

	select {
	case got := <-seen:
		// 期望 203.0.113.7:5555:归一成 TCPAddr 只是 PROXY 头的格式要求(见 normalizeProxyAddr),
		// IP:port 必须原样带过来。
		if got != "203.0.113.7:5555" {
			t.Errorf("服务端看到的客户端地址是 %s,应为 203.0.113.7:5555 —— "+
				"塌回环回地址会让所有 hy2 客户端共用一个限流桶,单个滥用者即可把其余人一起限死", got)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("环回那侧没收到 stream")
	}

	// token 用完必须销掉:每条 stream 漏一个,长跑就是内存泄漏。
	if n := relay.pendingLenForTest(); n != 0 {
		t.Errorf("取用之后 relay 里还留着 %d 个 token", n)
	}

	// stream 真能跑数据(只写对了头但流不通,现象是 hy2 连上就卡住)。
	payload := []byte("hy2-smux-roundtrip")
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("写: %v", err)
	}
	_ = st.SetReadDeadline(time.Now().Add(10 * time.Second))
	back := make([]byte, len(payload))
	if _, err := io.ReadFull(st, back); err != nil {
		t.Fatalf("读回显: %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("回显不匹配: %q", back)
	}
}

// TestVpnSmuxStreamOutbound_IgnoresRequestedTargetEvenWhenItIsDialable
// reqAddr 里给一个**真能连上**的地址,出口也必须落到环回。
//
// 已有的用例只验了「pool 为 nil 时报错」,那条路上 reqAddr 压根没机会被使用。这里放一个
// 活着的监听在那儿:一旦实现拿 reqAddr 去拨,它就会收到连接 —— 而那意味着 nanotun 成了
// 一台任意 TCP 开放代理(hy2 密码持有者能借它访问内网任意端口)。
func TestVpnSmuxStreamOutbound_IgnoresRequestedTargetEvenWhenItIsDialable(t *testing.T) {
	bait, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起诱饵 listener: %v", err)
	}
	defer func() { _ = bait.Close() }()
	baited := make(chan struct{}, 1)
	go func() {
		if c, err := bait.Accept(); err == nil {
			baited <- struct{}{}
			_ = c.Close()
		}
	}()

	echo := startLoopbackWSEcho(t, true)
	listenAddr, wsPath, seen := echo.listenAddr, echo.wsPath, echo.seen
	pool := newLoopbackSmuxPool(loopbackVPNWebSocketURL(listenAddr, wsPath, false), smux.DefaultConfig(), nil)
	out := &vpnSmuxStreamOutbound{pool: pool} // 不挂 relay:走 LOCAL 头那条分支

	// 直接把诱饵地址当 reqAddr 递进去(没有 token 前缀,Take 也取不到东西)。
	st, err := out.TCP(bait.Addr().String())
	if err != nil {
		t.Fatalf("TCP: %v", err)
	}
	defer func() { _ = st.Close() }()

	select {
	case got := <-seen:
		// 没有真实地址可用时回退 LOCAL 头,服务端按环回归因 —— 这是可接受的降级,
		// 但**必须**仍然落在环回上。
		if !strings.HasPrefix(got, "127.0.0.1:") {
			t.Errorf("服务端看到的源地址是 %s,期望环回 —— 取不到真实地址时应回退 LOCAL 头", got)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("环回那侧没收到 stream —— 出口没落到本机 VPN 数据面")
	}

	select {
	case <-baited:
		t.Fatal("出口把 reqAddr 当成了 dial 目标 —— nanotun 变成任意 TCP 开放代理," +
			"任何持 hy2 密码的客户端都能借它连内网任意端口")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestVpnSmuxStreamOutbound_ReportsFailureWhenTheLoopbackIsDown 环回那侧不可达时必须报错。
// 返回一条「建好了但其实不通」的 stream,hysteria 会以为出口就绪并回客户端一个成功的
// TCP response(fast-open),客户端于是发出 VPN1 握手后一直等不到回应 —— 表现成连上就卡住。
func TestVpnSmuxStreamOutbound_ReportsFailureWhenTheLoopbackIsDown(t *testing.T) {
	dead := freeTCPPort(t) // 探完即释放:这个端口上没人听
	pool := newLoopbackSmuxPool(fmt.Sprintf("ws://127.0.0.1:%d/vpn", dead), smux.DefaultConfig(), nil)
	out := &vpnSmuxStreamOutbound{pool: pool, relay: newHy2ClientAddrRelay()}

	c, err := out.TCP("example.com:443")
	if err == nil {
		_ = c.Close()
		t.Fatal("环回不可达却返回了一条 stream —— hy2 会回客户端成功再让它干等")
	}
}

// TestVpnLocalOutbound_DialsTheLoopbackAndIgnoresTheRequestedTarget
// 每流直拨那条路径(没配 [smux] 时)的成功面。同样的开放代理约束在这条路上也要成立。
func TestVpnLocalOutbound_DialsTheLoopbackAndIgnoresTheRequestedTarget(t *testing.T) {
	echo := startLoopbackWSEcho(t, false)
	listenAddr, wsPath, seen := echo.listenAddr, echo.wsPath, echo.seen
	out := &vpnLocalOutbound{
		wsURL:   loopbackVPNWebSocketURL(listenAddr, wsPath, false),
		timeout: 10 * time.Second,
	}

	c, err := out.TCP("10.0.0.1:22") // 内网 SSH:实现若拿它去拨就是开放代理
	if err != nil {
		t.Fatalf("TCP: %v", err)
	}
	defer func() { _ = c.Close() }()

	select {
	case <-seen:
	case <-time.After(15 * time.Second):
		t.Fatal("环回 WebSocket 没收到连接")
	}
	if !strings.HasPrefix(c.RemoteAddr().String(), "127.0.0.1:") {
		t.Errorf("连出去的对端是 %s,应当恒为本机环回", c.RemoteAddr())
	}

	payload := []byte("hy2-plain-roundtrip")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("写: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	back := make([]byte, len(payload))
	if _, err := io.ReadFull(c, back); err != nil {
		t.Fatalf("读回显: %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("回显不匹配: %q", back)
	}
}

// TestHysteriaUDPProxyConn_ReportsEmptyAddrWhenThereIsNone 读失败时没有来源地址,
// 必须返回空串。返回 addr.String() 会在 addr 为 nil 时直接 panic —— 而 panic 发生在
// hysteria 的 UDP 搬运 goroutine 里,拖垮的是整个进程。
func TestHysteriaUDPProxyConn_ReportsEmptyAddrWhenThereIsNone(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	c := &hysteriaUDPProxyConn{UDPConn: pc}
	_ = pc.Close() // 关掉之后 ReadFrom 必定失败,且 addr 为 nil

	n, addr, err := c.ReadFrom(make([]byte, 16))
	if err == nil {
		t.Fatal("已关闭的 socket 上读取却成功了")
	}
	if addr != "" {
		t.Errorf("没有来源地址时应返回空串, got %q", addr)
	}
	if n != 0 {
		t.Errorf("读失败时字节数应为 0, got %d", n)
	}
}

// TestUdpPortFromPacketConn_RejectsOutOfRangePort 端口越界要报错。
// 这个值会经 node_login 上报给控制面、客户端照它连,上报 0 的现象是「服务正常但整个节点不可达」。
func TestUdpPortFromPacketConn_RejectsOutOfRangePort(t *testing.T) {
	if _, err := udpPortFromPacketConn(zeroPortPacketConn{}); err == nil {
		t.Fatal("端口 0 必须报错,不能上报给控制面")
	} else if !strings.Contains(err.Error(), "port") {
		t.Errorf("错误里该说明是端口的问题: %v", err)
	}
}

type zeroPortPacketConn struct{ net.PacketConn }

func (zeroPortPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// TestStartEmbeddedHysteria_DefaultsTo443WhenListenAddrIsEmpty listen_addr 留空要回落 :443。
// 回落成 :0 之类的话,内核随便给一个端口,客户端按 443 连过去就是「服务起着但没人连得上」。
func TestStartEmbeddedHysteria_DefaultsTo443WhenListenAddrIsEmpty(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	cfg := testHysteriaConfig(t, "", "0123456789abcdef", certFile, keyFile)

	srv, port, cleanup, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
	if err != nil {
		// 非 root 绑不上 443,错误里必须能看出它就是去绑 443 了。
		if !strings.Contains(err.Error(), "443") {
			t.Fatalf("listen_addr 留空时应回落 :443,错误里却看不到 443: %v", err)
		}
		if os.Geteuid() == 0 {
			t.Fatalf("以 root 运行却绑不上 443: %v", err)
		}
		return
	}
	t.Cleanup(func() {
		_ = srv.Close()
		if cleanup != nil {
			cleanup()
		}
	})
	if port != 443 {
		t.Errorf("listen_addr 留空应监听 443, got %d", port)
	}
}

// TestStartEmbeddedHysteria_ReleasesThePortWhenLaterStepsFail 启动的后半段失败时,
// 前面已经绑上的 UDP 端口必须还回去。
//
// 漏关的后果不是「起不来」那么简单:main 在这里 Fatal 之前,那个 socket 还攥在手里;
// 而 hy2 的端口常与端口跳跃的 iptables 规则配套,残留监听会让后续重试/回滚看到一个
// 「端口已被占用」的假象,排查方向直接被带偏。
func TestStartEmbeddedHysteria_ReleasesThePortWhenLaterStepsFail(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	port := pickFreeUDPPort(t)

	cfg := testHysteriaConfig(t, fmt.Sprintf("127.0.0.1:%d", port), "0123456789abcdef", certFile, keyFile)
	// 让**绑定之后**的那一步失败:CA 文件存在但不是 PEM → buildHysteriaServerConfig 报错。
	badCA := dir + "/not-a-pem.crt"
	if err := os.WriteFile(badCA, []byte("这不是 PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Hysteria.TLSClientCAFile = badCA

	srv, gotPort, cleanup, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
	if err == nil {
		if srv != nil {
			_ = srv.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("CA 文件不是 PEM 却启动成功了")
	}
	if srv != nil || gotPort != 0 || cleanup != nil {
		t.Errorf("失败时不能返回半成品(srv=%v port=%d cleanup==nil:%v)", srv, gotPort, cleanup == nil)
	}

	probe, perr := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if perr != nil {
		t.Fatalf("失败路径没有关掉已绑的 UDP 端口 %d: %v —— "+
			"残留监听会让后续重试看到「端口已被占用」的假象", port, perr)
	}
	_ = probe.Close()
}

// TestBuildHy2TCPOutbound_PicksTheStreamOutboundWheneverSmuxIsConfigured
// 出口的选择。配了 [smux] 却仍用每流直拨,不会报任何错 —— 只是「stream 开头一个 PROXY 头」
// 的约定没人来写,真实客户端地址无处安放,全部 hy2 客户端又塌回 127.0.0.1 那一个限流桶。
func TestBuildHy2TCPOutbound_PicksTheStreamOutboundWheneverSmuxIsConfigured(t *testing.T) {
	pool := newLoopbackSmuxPool("ws://127.0.0.1:8080/vpn", smux.DefaultConfig(), nil)

	ob, relay := buildHy2TCPOutbound(pool, "ws://127.0.0.1:8080/vpn", 7*time.Second, nil)
	sm, ok := ob.(*vpnSmuxStreamOutbound)
	if !ok {
		t.Fatalf("配了 [smux] 就必须走共享会话的出口, got %T —— 每流直拨那条路没法带真实客户端地址", ob)
	}
	if sm.pool != pool {
		t.Error("出口拿到的不是传进来的那个 pool —— 会另开一条环回会话,复用形同未做")
	}
	if relay == nil {
		t.Fatal("smux 路必须建地址中转,否则真实客户端地址传不到出口")
	}
	// 必须是**同一个**实例:两个不同的 relay 会让出口去一张没人写的表里查 token,
	// 恒取不到 → 悄悄退回 LOCAL 头,与压根没做这件事等价。
	if sm.relay != relay {
		t.Error("出口用的 relay 与返回给调用方的不是同一个 —— 出口会永远取不到地址,静默退回环回归因")
	}

	// 没配 [smux]:退回每流直拨,且不该建 relay(建了也没地方写头,只会误导)。
	obPlain, relayPlain := buildHy2TCPOutbound(nil, "ws://127.0.0.1:9999/feed", 7*time.Second, nil)
	local, ok := obPlain.(*vpnLocalOutbound)
	if !ok {
		t.Fatalf("没配 [smux] 应走每流直拨, got %T", obPlain)
	}
	if local.wsURL != "ws://127.0.0.1:9999/feed" || local.timeout != 7*time.Second {
		t.Errorf("环回 URL / 超时没透传: %+v", local)
	}
	if relayPlain != nil {
		t.Error("直拨路径不该建 relay —— 那条路上没有写 PROXY 头的约定")
	}
}

// TestStartEmbeddedHysteria_SmuxPathWiresTheStreamOutbound 配了 [smux] 时能正常起来。
// 顺带覆盖开/不开 Salamander 混淆两条启动日志分支。出口选得对不对由上面那条直接钉
// (startEmbeddedHysteria 只返回 hyserver.Server,从返回值看不见挂的是哪个 outbound)。
func TestStartEmbeddedHysteria_SmuxPathWiresTheStreamOutbound(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)

	for _, obfs := range []string{"", "salamander-pw"} {
		name := "不带混淆"
		if obfs != "" {
			name = "带 Salamander 混淆"
		}
		t.Run(name, func(t *testing.T) {
			cfg := testHysteriaConfig(t, "127.0.0.1:0", "0123456789abcdef", certFile, keyFile)
			cfg.Hysteria.ObfsSalamanderPassword = obfs
			pool := newLoopbackSmuxPool("ws://127.0.0.1:8080/vpn", smux.DefaultConfig(), nil)

			srv, port, cleanup, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", pool, nil)
			if err != nil {
				t.Fatalf("启动失败: %v", err)
			}
			t.Cleanup(func() {
				_ = srv.Close()
				if cleanup != nil {
					cleanup()
				}
			})
			if srv == nil || port < 1 {
				t.Fatalf("配齐了就该起来(srv=%v port=%d)", srv, port)
			}
			if cleanup != nil {
				t.Error("没配端口跳跃时不该返回 iptables 清理函数")
			}
		})
	}
}
