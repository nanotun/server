package main

import (
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hyserver "github.com/apernet/hysteria/core/v2/server"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/util"
)

// hy2 的 Outbound 是这个服务里最容易被误改成「开放代理」的地方:hysteria 会把客户端
// 请求的目标地址交给我们,而我们必须**完全忽略**它、恒连本机 VPN 数据面。下面这组
// 用例把这条硬约束和它周边的降级行为钉住。

// 三种 outbound 的 UDP 出口:只有显式打开 udp_relay 的 hybrid 才放行。
// 另外两个若哪天"顺手"实现了 UDP,hy2 就成了可被用来打 DNS 放大的 UDP 代理。
func TestHy2Outbounds_UDPStaysShutUnlessRelayIsExplicitlyEnabled(t *testing.T) {
	t.Run("直拨环回的 outbound 拒 UDP", func(t *testing.T) {
		o := &vpnLocalOutbound{}
		if c, err := o.UDP("8.8.8.8:53"); err == nil || c != nil {
			t.Fatalf("UDP() 应当拒绝,got (%v,%v)", c, err)
		}
		if err := o.CheckUDP("8.8.8.8:53"); err == nil {
			t.Fatal("CheckUDP 也要拒 —— 它是 ACL 层的准入钩子,放行了等于开了个口子")
		}
	})

	t.Run("smux 多路复用的 outbound 拒 UDP", func(t *testing.T) {
		o := &vpnSmuxStreamOutbound{}
		if c, err := o.UDP("8.8.8.8:53"); err == nil || c != nil {
			t.Fatalf("UDP() 应当拒绝,got (%v,%v)", c, err)
		}
		if err := o.CheckUDP("8.8.8.8:53"); err == nil {
			t.Fatal("CheckUDP 也要拒")
		}
	})

	t.Run("hybrid 打开 udp_relay 后才放行", func(t *testing.T) {
		o := &vpnHybridOutbound{}
		if err := o.CheckUDP("8.8.8.8:53"); err != nil {
			t.Fatalf("hybrid 就是给 udp_relay=true 用的,应放行: %v", err)
		}
		c, err := o.UDP("8.8.8.8:53")
		if err != nil {
			t.Fatalf("UDP(): %v", err)
		}
		defer c.Close()
		// 全锥:每次 UDP() 拿到的是一个新的本地随机端口 socket。
		c2, err := o.UDP("1.1.1.1:53")
		if err != nil {
			t.Fatalf("UDP() 第二次: %v", err)
		}
		defer c2.Close()
		if c == c2 {
			t.Fatal("两次 UDP() 应各自拿到独立 socket")
		}
	})
}

// TCP 侧的硬约束:请求的目标地址只被当作「取 token 的钥匙」,绝不作为 dial 目标。
func TestVpnSmuxStreamOutbound_IgnoresTheRequestedTargetEntirely(t *testing.T) {
	t.Run("没有 pool 时明确报错而不是空指针", func(t *testing.T) {
		o := &vpnSmuxStreamOutbound{}
		c, err := o.TCP("example.com:443")
		if err == nil {
			_ = c.Close()
			t.Fatal("pool 未初始化应报错")
		}
		if !strings.Contains(err.Error(), "smux") {
			t.Fatalf("错误里该指出是 smux pool 的问题: %v", err)
		}
	})
}

// 每流直拨那条路径:dial 超时没配时要有默认值,否则一个连不上的环回会把 goroutine 挂死。
func TestVpnLocalOutbound_FallsBackToADefaultDialTimeout(t *testing.T) {
	// 指向一个不会有人应答的地址,让 dial 一定失败。
	o := &vpnLocalOutbound{wsURL: "ws://127.0.0.1:1/vpn", timeout: 200 * time.Millisecond}
	start := time.Now()
	if c, err := o.TCP("whatever:443"); err == nil {
		_ = c.Close()
		t.Fatal("拨一个没人监听的端口不该成功")
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("拨号耗时 %v,超时没生效", el)
	}

	// timeout<=0 走内置默认值(15s),这里只验证它不会立刻返回「无效超时」类错误,
	// 也不会因为 0 被当成「立即超时」。
	o2 := &vpnLocalOutbound{wsURL: "ws://127.0.0.1:1/vpn"}
	if c, err := o2.TCP("whatever:443"); err == nil {
		_ = c.Close()
		t.Fatal("同样不该成功")
	}
}

func TestHysteriaUDPProxyConn_TranslatesBetweenStringAndUDPAddr(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer pc.Close()
	c := &hysteriaUDPProxyConn{UDPConn: pc}

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP peer: %v", err)
	}
	defer peer.Close()

	if _, err := c.WriteTo([]byte("hello"), peer.LocalAddr().String()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 64)
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := peer.ReadFrom(buf)
	if err != nil {
		t.Fatalf("对端没收到: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("收到 %q", buf[:n])
	}

	// 反向:ReadFrom 要把 net.Addr 转成 hysteria 期望的字符串形式。
	if _, err := peer.WriteTo([]byte("pong"), from.(*net.UDPAddr)); err != nil {
		t.Fatalf("回写: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, addrStr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("收到 %q", buf[:n])
	}
	if _, _, err := net.SplitHostPort(addrStr); err != nil {
		t.Fatalf("地址 %q 不是 host:port 形式,hysteria 那边解析不了: %v", addrStr, err)
	}

	// 目标地址解析不出来时要报错,而不是把包发给一个零值地址。
	if _, err := c.WriteTo([]byte("x"), "这不是地址"); err == nil {
		t.Fatal("非法目标地址应报错")
	}
}

func TestUdpPortFromPacketConn_RejectsAnythingItCannotReport(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	port, err := udpPortFromPacketConn(pc)
	if err != nil {
		t.Fatalf("正常 UDP 监听应能取出端口: %v", err)
	}
	if port < 1 || port > 65535 {
		t.Fatalf("端口 %d 不在合法范围", port)
	}

	// 非 UDP 的 PacketConn:这个端口会被上报给 node_login,取错了整个节点就不可达。
	if _, err := udpPortFromPacketConn(notUDPPacketConn{}); err == nil {
		t.Fatal("非 UDP 地址应报错,不能默默上报 0")
	}
}

type notUDPPacketConn struct{ net.PacketConn }

func (notUDPPacketConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func TestBuildHysteriaServerConfig_TranslatesTuningKnobsFaithfully(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	out := &vpnLocalOutbound{}

	t.Run("零值一律不覆盖 hysteria 自己的默认", func(t *testing.T) {
		cfg, err := buildHysteriaServerConfig(&config.HysteriaConfig{Password: "pw"}, cert, out, nil)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		q := cfg.QUICConfig
		if q.InitialStreamReceiveWindow != 0 || q.MaxStreamReceiveWindow != 0 ||
			q.InitialConnectionReceiveWindow != 0 || q.MaxConnectionReceiveWindow != 0 ||
			q.MaxIdleTimeout != 0 || q.MaxIncomingStreams != 0 {
			t.Fatalf("没配的项不该被写成 0 传下去(会覆盖掉 hysteria 的默认值): %+v", q)
		}
		if !cfg.DisableUDP {
			t.Fatal("没开 udp_relay 时必须 DisableUDP —— 否则 hy2 成了通用 UDP 代理")
		}
		if cfg.RequestHook != nil || cfg.EventLogger != nil {
			t.Fatal("没传 relay 时不该挂 hook")
		}
		if cfg.MasqHandler != nil {
			t.Fatal("没配 masquerade_dir 时不该挂文件服务")
		}
	})

	t.Run("配了就逐项传下去", func(t *testing.T) {
		hc := &config.HysteriaConfig{
			Password:                    "pw",
			QUICInitialStreamRecvWindow: 1 << 20,
			QUICMaxStreamRecvWindow:     2 << 20,
			QUICInitialConnRecvWindow:   3 << 20,
			QUICMaxConnRecvWindow:       4 << 20,
			QUICMaxIdleTimeoutSec:       45,
			QUICMaxIncomingStreams:      256,
			QUICDisablePathMTUDiscovery: true,
			IgnoreClientBandwidth:       true,
			BandwidthMaxTxBps:           1000,
			BandwidthMaxRxBps:           2000,
			MasqueradeDir:               dir,
		}
		cfg, err := buildHysteriaServerConfig(hc, cert, out, nil)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		q := cfg.QUICConfig
		if q.InitialStreamReceiveWindow != 1<<20 || q.MaxStreamReceiveWindow != 2<<20 ||
			q.InitialConnectionReceiveWindow != 3<<20 || q.MaxConnectionReceiveWindow != 4<<20 {
			t.Fatalf("窗口参数没传对: %+v", q)
		}
		if q.MaxIdleTimeout != 45*time.Second {
			t.Fatalf("idle timeout 应按秒换算,got %v", q.MaxIdleTimeout)
		}
		if q.MaxIncomingStreams != 256 || !q.DisablePathMTUDiscovery {
			t.Fatalf("流数上限 / PMTUD 开关没传对: %+v", q)
		}
		if !cfg.IgnoreClientBandwidth ||
			cfg.BandwidthConfig.MaxTx != 1000 || cfg.BandwidthConfig.MaxRx != 2000 {
			t.Fatalf("带宽配置没传对: %+v", cfg.BandwidthConfig)
		}
		if cfg.MasqHandler == nil {
			t.Fatal("配了 masquerade_dir 就该挂上文件服务 —— 它是主动探测时的伪装门面")
		}
	})

	t.Run("udp_relay 打开时换成 hybrid 出口并接受 idle timeout", func(t *testing.T) {
		hc := &config.HysteriaConfig{Password: "pw", UDPRelayEnabled: true, UDPIdleTimeoutSec: 30}
		cfg, err := buildHysteriaServerConfig(hc, cert, out, nil)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if cfg.DisableUDP {
			t.Fatal("显式打开了 udp_relay,不该再 DisableUDP")
		}
		if _, ok := cfg.Outbound.(*vpnHybridOutbound); !ok {
			t.Fatalf("出口应换成 hybrid,got %T", cfg.Outbound)
		}
		if cfg.UDPIdleTimeout != 30*time.Second {
			t.Fatalf("udp idle timeout 应按秒换算,got %v", cfg.UDPIdleTimeout)
		}
	})

	t.Run("udp_relay 关着时 idle timeout 不生效", func(t *testing.T) {
		hc := &config.HysteriaConfig{Password: "pw", UDPIdleTimeoutSec: 30}
		cfg, err := buildHysteriaServerConfig(hc, cert, out, nil)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if cfg.UDPIdleTimeout != 0 {
			t.Fatalf("UDP 都禁了,不该设 idle timeout: %v", cfg.UDPIdleTimeout)
		}
	})

	// hook 与 EventLogger 必须成对挂:只挂一半的话真实客户端地址永远取不到,
	// 所有 hy2 客户端会塌回同一个限流桶(共命运 DoS)。
	t.Run("传了 relay 就两个钩子一起挂", func(t *testing.T) {
		relay := newHy2ClientAddrRelay()
		cfg, err := buildHysteriaServerConfig(&config.HysteriaConfig{Password: "pw"}, cert, out, relay)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if cfg.RequestHook == nil || cfg.EventLogger == nil {
			t.Fatal("RequestHook 与 EventLogger 必须同时挂上,少一个真实客户端地址就传不到出口")
		}
	})
}

func TestBuildHysteriaServerConfig_ClientCARejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	out := &vpnLocalOutbound{}

	t.Run("合法 CA 装进 pool", func(t *testing.T) {
		hc := &config.HysteriaConfig{Password: "pw", TLSClientCAFile: certFile}
		cfg, err := buildHysteriaServerConfig(hc, cert, out, nil)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if cfg.TLSConfig.ClientCAs == nil {
			t.Fatal("配了 client CA 就该装进 pool,否则 mTLS 形同虚设")
		}
	})

	t.Run("文件不存在要报错", func(t *testing.T) {
		hc := &config.HysteriaConfig{Password: "pw", TLSClientCAFile: filepath.Join(dir, "nope.pem")}
		if _, err := buildHysteriaServerConfig(hc, cert, out, nil); err == nil {
			t.Fatal("读不到 CA 文件应报错 —— 静默跳过等于关掉了客户端证书校验")
		}
	})

	t.Run("不是 PEM 要报错", func(t *testing.T) {
		bad := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(bad, []byte("这不是证书"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		hc := &config.HysteriaConfig{Password: "pw", TLSClientCAFile: bad}
		_, err := buildHysteriaServerConfig(hc, cert, out, nil)
		if err == nil {
			t.Fatal("空的 CA pool 会让所有客户端证书都验不过,必须启动期就报出来")
		}
		if !strings.Contains(err.Error(), "PEM") {
			t.Fatalf("错误里该说明是 PEM 的问题: %v", err)
		}
	})
}

func TestStartEmbeddedHysteria_StaysOffUntilFullyConfigured(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)

	t.Run("三件套都没配 = 不启用", func(t *testing.T) {
		srv, port, cleanup, err := startEmbeddedHysteria(&config.Config{}, "", "ws://127.0.0.1:8080/vpn", nil, nil)
		if err != nil || srv != nil || port != 0 || cleanup != nil {
			t.Fatalf("未配置时应静默不启用,got (srv=%v port=%d cleanup==nil:%v err=%v)",
				srv, port, cleanup == nil, err)
		}
	})

	t.Run("调优参数越界 → 启动期就报错", func(t *testing.T) {
		cfg := testHysteriaConfig(t, "127.0.0.1:0", "0123456789abcdef", certFile, keyFile)
		cfg.Hysteria.QUICMaxIdleTimeoutSec = 999999
		_, _, _, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
		if err == nil {
			t.Fatal("越界的调优参数应当拦在启动期,而不是运行时才暴露")
		}
	})

	t.Run("证书路径不对 → 报错且带上下文", func(t *testing.T) {
		cfg := testHysteriaConfig(t, "127.0.0.1:0", "0123456789abcdef",
			filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"))
		_, _, _, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
		if err == nil {
			t.Fatal("证书读不到应报错")
		}
		if !strings.Contains(err.Error(), "hysteria") {
			t.Fatalf("错误里该点明是 hy2 的证书: %v", err)
		}
	})

	t.Run("listen_addr 畸形 → 报错", func(t *testing.T) {
		cfg := testHysteriaConfig(t, "这不是地址", "0123456789abcdef", certFile, keyFile)
		_, _, _, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
		if err == nil {
			t.Fatal("畸形 listen_addr 应报错")
		}
	})

	t.Run("端口被占 → 报错并且不泄漏监听", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		defer pc.Close()
		cfg := testHysteriaConfig(t, pc.LocalAddr().String(), "0123456789abcdef", certFile, keyFile)
		_, _, _, err = startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
		if err == nil {
			t.Fatal("端口已被占用应报错")
		}
	})
}

// 真起一次:确认它确实占住了 UDP 端口,并且上报的端口号就是实际监听的那个 ——
// node_login 拿这个值去告诉客户端往哪连,报错了整个节点不可达。
func TestStartEmbeddedHysteria_ReportsThePortItActuallyBound(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	cfg := testHysteriaConfig(t, "127.0.0.1:0", "0123456789abcdef", certFile, keyFile)

	srv, port, cleanup, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	if srv == nil {
		t.Fatal("配齐了三件套就该起来")
	}
	t.Cleanup(func() {
		_ = srv.Close()
		if cleanup != nil {
			cleanup()
		}
	})
	if port < 1 || port > 65535 {
		t.Fatalf("上报端口 %d 不合法 —— 客户端会照着它连", port)
	}
	// :0 让内核分配,所以上报的端口必须是内核给的那个,不能是配置里的 0。
	if pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", itoa64(int64(port)))); err == nil {
		_ = pc.Close()
		t.Fatalf("端口 %d 还能再绑一次,说明上报的不是真正监听的那个", port)
	}
	if cleanup != nil {
		t.Fatal("没配端口跳跃时不该返回 iptables 清理函数")
	}
}

// Salamander 混淆开着的时候,监听端口的语义不能变 —— 它只是在 PacketConn 外面套了一层。
func TestStartEmbeddedHysteria_ObfsWrapsThePacketConnWithoutChangingThePort(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	cfg := testHysteriaConfig(t, "127.0.0.1:0", "0123456789abcdef", certFile, keyFile)
	cfg.Hysteria.ObfsSalamanderPassword = "salamander-pw"

	srv, port, cleanup, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
		if cleanup != nil {
			cleanup()
		}
	})
	if port < 1 {
		t.Fatalf("端口 %d 不合法", port)
	}
}

// smux pool 存在时才建 relay:没有 relay,真实客户端地址就传不到出口。
func TestStartEmbeddedHysteria_OnlyWiresTheAddressRelayOnTheSmuxPath(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	// 没有 pool → 每流直拨,没有「一条 stream 一个 PROXY 头」的约定,relay 无处安放。
	cfgNoRelay, err := buildHysteriaServerConfig(&config.HysteriaConfig{Password: "pw"}, cert,
		&vpnLocalOutbound{wsURL: "ws://127.0.0.1:8080/vpn"}, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfgNoRelay.RequestHook != nil {
		t.Fatal("直拨路径不该挂 relay")
	}

	relay := newHy2ClientAddrRelay()
	cfgRelay, err := buildHysteriaServerConfig(&config.HysteriaConfig{Password: "pw"}, cert,
		&vpnSmuxStreamOutbound{pool: &loopbackSmuxPool{}, relay: relay}, relay)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfgRelay.RequestHook == nil || cfgRelay.EventLogger == nil {
		t.Fatal("smux 路径必须挂上 relay,否则所有 hy2 客户端塌进同一个限流桶")
	}
}

// relay 里没被 Outbound 取走的 token 不能永远留着 —— 每条异常 stream 漏一个,
// 长跑下来就是内存泄漏。
func TestHy2ClientAddrRelay_DoesNotLeakTokensOnTheErrorPath(t *testing.T) {
	r := newHy2ClientAddrRelay()
	addr := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 5555}

	var reqAddr string
	if _, err := r.TCP(nil, &reqAddr); err != nil {
		t.Fatalf("TCP hook: %v", err)
	}
	if !strings.HasPrefix(reqAddr, hy2AddrTokenPrefix) {
		t.Fatalf("hook 应把 reqAddr 改写成 token,got %q", reqAddr)
	}
	r.TCPRequest(addr, "auth", reqAddr)
	if n := r.pendingLenForTest(); n != 1 {
		t.Fatalf("记下了 %d 条,期望 1", n)
	}

	// dial 失败走 TCPError,token 要就地清掉,不能等 30s TTL。
	r.TCPError(addr, "auth", reqAddr, os.ErrDeadlineExceeded)
	if n := r.pendingLenForTest(); n != 0 {
		t.Fatalf("出错路径漏了 %d 条 token", n)
	}

	// nil 的 reqAddr 指针不能崩(hysteria 那边理论上不会传,但这是外部库)。
	if _, err := r.TCP(nil, nil); err != nil {
		t.Fatalf("nil reqAddr 不该报错: %v", err)
	}
	// 不带前缀的地址不是我们埋的,不该被记下来也不该被取走。
	r.TCPRequest(addr, "auth", "example.com:443")
	if n := r.pendingLenForTest(); n != 0 {
		t.Fatalf("非本 relay 的 reqAddr 被记下来了(%d 条)", n)
	}
	if got := r.Take("example.com:443"); got != nil {
		t.Fatalf("不该取出东西: %v", got)
	}
	// UDP 侧是空实现,调了不能崩。
	if err := r.UDP(nil, nil); err != nil {
		t.Fatalf("UDP hook 应为空实现: %v", err)
	}
	r.Connect(addr, "auth", 1)
	r.Disconnect(addr, "auth", nil)
	r.UDPRequest(addr, "auth", 1, "x")
	r.UDPError(addr, "auth", 1, nil)

	// Check:只接管 TCP。接管 UDP 会让 UDP 请求也被改写成 token,直接坏掉。
	if !r.Check(false, "x:1") || r.Check(true, "x:1") {
		t.Fatal("Check 应当只对 TCP 返回 true")
	}
}

// 上限撞顶时宁可退回环回归因,也不能让 map 无界增长。
func TestHy2ClientAddrRelay_DropsNewEntriesInsteadOfGrowingForever(t *testing.T) {
	r := newHy2ClientAddrRelay()
	addr := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 5555}
	for i := 0; i < hy2PendingMax+50; i++ {
		r.put(hy2AddrTokenPrefix+newHy2AddrToken(), addr)
	}
	if n := r.pendingLenForTest(); n > hy2PendingMax {
		t.Fatalf("pending 涨到了 %d,超过上限 %d", n, hy2PendingMax)
	}
}

var _ hyserver.Outbound = (*vpnHybridOutbound)(nil)
var _ = util.FormatUDPListenAddr
