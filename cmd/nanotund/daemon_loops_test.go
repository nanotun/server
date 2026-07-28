package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	hyserver "github.com/apernet/hysteria/core/v2/server"
	"github.com/xtaci/smux"
	"golang.org/x/net/dns/dnsmessage"
)

// 这些常驻 goroutine 都由 main 拉起、由 ctx / stop / listener 关闭来收尾。
// 收不干净的代价是进程停不下来:systemd 等到超时再 SIGKILL,期间 iptables 规则
// 不撤、WAL 不 checkpoint。

// withTestGlobalContext 把包级 globalContext 换成测试自己的,用完还原。
// 后台 goroutine 的启动器都从这个全局变量取 ctx。
func withTestGlobalContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	prevCtx, prevCancel := globalContext, globalContextCancel
	ctx, cancel := context.WithCancel(context.Background())
	globalContext, globalContextCancel = ctx, cancel
	t.Cleanup(func() {
		cancel()
		globalContext, globalContextCancel = prevCtx, prevCancel
	})
	return ctx, cancel
}

func awaitClosed(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s 没有退出", what)
	}
}

func TestRunMagicDNSLoop_ServesQueriesAndStopsCleanly(t *testing.T) {
	gw := newMagicDNSGateway(t)
	r := magicDNSResolved{suffix: "lan", port: 5353}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() { defer close(done); runMagicDNSLoop(ctx, gw, conn, r) }()

	// 发一条查不到的名字:内容不重要,重点是循环收得到、答得回、不卡死。
	client, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer client.Close()
	if _, err := client.Write(buildDNSQuery(t, "nobody.lan", dnsmessage.TypeA)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 512)); err != nil {
		t.Fatalf("循环没有回应答: %v", err)
	}

	// 畸形报文不能把循环打断 —— 公网可达的 UDP 端口上这是常态输入。
	if _, err := client.Write([]byte{0x00}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := client.Write(buildDNSQuery(t, "nobody2.lan", dnsmessage.TypeA)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Read(make([]byte, 512)); err != nil {
		t.Fatalf("一条畸形报文之后循环就不干活了: %v", err)
	}

	// 关 socket 是 startMagicDNS 返回的 cleanup 干的事,循环必须据此退出。
	_ = conn.Close()
	awaitClosed(t, done, "runMagicDNSLoop(socket 关闭后)")
}

func TestRunMagicDNSLoop_ExitsOnContextCancelEvenWithNoTraffic(t *testing.T) {
	gw := newMagicDNSGateway(t)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMagicDNSLoop(ctx, gw, conn, magicDNSResolved{suffix: "lan", port: 5353})
	}()

	cancel()
	// 循环靠 2s 读超时来查 ctx,所以给足余量。
	awaitClosed(t, done, "runMagicDNSLoop(ctx 取消后)")
}

func TestRunUserInvalidationLoop_ScansOnEntryAndExitsOnCancel(t *testing.T) {
	st := newDaemonTestStore(t)
	gw := &gatewayState{store: st}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); runUserInvalidationLoop(ctx, gw, 20*time.Millisecond) }()

	// 进入就先扫一次(不等第一个 tick),否则被禁用的用户最多能多活一个周期。
	time.Sleep(100 * time.Millisecond)
	cancel()
	awaitClosed(t, done, "runUserInvalidationLoop")
}

func TestStartUserInvalidationLoop_NonPositiveIntervalFallsBackToTheDefault(t *testing.T) {
	withTestGlobalContext(t)
	st := newDaemonTestStore(t)
	gw := &gatewayState{store: st}

	// interval<=0 必须回落到默认值:传 0 给 time.NewTicker 会直接 panic。
	stop := startUserInvalidationLoop(gw, 0)
	if stop == nil {
		t.Fatal("应返回可调用的 stop")
	}
	stop()
	time.Sleep(50 * time.Millisecond)
}

func TestRunLoopbackSmuxServerSide_ServesStreamsAndUnwindsWithTheSession(t *testing.T) {
	st := newDaemonTestStore(t)
	gw := &gatewayState{store: st}
	cfg := smux.DefaultConfig()

	serverSide, clientSide := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); runLoopbackSmuxServerSide(serverSide, gw, cfg) }()

	sess, err := smux.Client(clientSide, cfg)
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// 每条 loopback stream 开头要有一个 PROXY v2 头,服务端先读它才知道真实客户端 IP。
	if err := writeLoopbackProxyHeaderLocal(stream); err != nil {
		t.Fatalf("写 PROXY 头: %v", err)
	}
	// 后面发什么无所谓 —— 这里验的是「一条坏 stream 不会掀翻整个会话」。
	_, _ = stream.Write([]byte("垃圾数据"))
	_ = stream.Close()

	// 会话还活着:能再开一条。
	stream2, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("一条 stream 出问题之后开不出新的了: %v", err)
	}
	_ = stream2.Close()

	// 承载连接一断,accept 循环必须退出,不能留着 goroutine。
	_ = sess.Close()
	_ = clientSide.Close()
	awaitClosed(t, done, "runLoopbackSmuxServerSide")
}

func TestRunLoopbackSmuxServerSide_ClosesTheCarrierWhenTheSessionCannotStart(t *testing.T) {
	c := &closeTrackingRWC{}
	// smux.Server 对非法配置会失败;失败时必须把承载连接关掉,否则它永远挂着。
	bad := smux.DefaultConfig()
	bad.MaxFrameSize = 0

	runLoopbackSmuxServerSide(c, &gatewayState{}, bad)

	if !c.closed() {
		t.Fatal("smux 会话建不起来时必须关掉承载连接")
	}
}

type closeTrackingRWC struct {
	mu   sync.Mutex
	shut bool
}

func (c *closeTrackingRWC) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *closeTrackingRWC) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeTrackingRWC) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shut = true
	return nil
}
func (c *closeTrackingRWC) closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.shut
}

func TestStartVPNHTTPServer_ServesTheWSPathAndShutsDownOnCleanup(t *testing.T) {
	withTestGlobalContext(t)
	st := newDaemonTestStore(t)
	gw := &gatewayState{store: st}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	errCh := make(chan error, 1)
	cleanup := startVPNHTTPServer(ln, "/vpn", gw, false, nil, errCh)

	base := "http://" + ln.Addr().String()
	client := &http.Client{Timeout: 3 * time.Second}

	// 普通 GET(没有 Upgrade 头)不该被当成数据面连接接进来。
	resp, err := client.Get(base + "/vpn")
	if err != nil {
		t.Fatalf("GET /vpn: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("没有 Upgrade 头也升级成 WebSocket 了")
	}

	// 别的路径不该存在 —— 数据面端口上多一个可探测的 endpoint 就多一分指纹。
	resp2, err := client.Get(base + "/别的路径")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode == http.StatusSwitchingProtocols {
		t.Fatalf("非数据面路径不该升级")
	}

	cleanup()
	_ = ln.Close()

	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			// 正常收尾。
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve 没有把结束原因报回 errCh —— main 会一直等在那里")
	}
}

// hybrid 出口的 TCP 侧必须原样委托给 VPN 环回出口,不能自己去 dial 客户端给的目标 ——
// 那一步做错,hy2 立刻变成任意 TCP 开放代理。
func TestVpnHybridOutbound_DelegatesTCPToTheLoopbackOutbound(t *testing.T) {
	inner := &recordingOutbound{}
	o := &vpnHybridOutbound{tcp: inner}

	if _, err := o.TCP("example.com:443"); err == nil {
		t.Fatal("内层返回了错误,应当透传")
	}
	if inner.lastReq != "example.com:443" {
		t.Fatalf("请求没原样交给内层出口: %q", inner.lastReq)
	}
	if inner.calls != 1 {
		t.Fatalf("内层被调了 %d 次,期望 1", inner.calls)
	}
}

type recordingOutbound struct {
	lastReq string
	calls   int
}

func (o *recordingOutbound) TCP(req string) (net.Conn, error) {
	o.lastReq = req
	o.calls++
	return nil, errors.New("不实际拨号")
}
func (o *recordingOutbound) UDP(string) (hyserver.UDPConn, error) { return nil, errors.New("disabled") }
func (o *recordingOutbound) CheckUDP(string) error                { return errors.New("disabled") }

// ---- server 自身的 v6 出网探测 ----
//
// 探测结果决定数据面要不要给客户端的公网 v6 直接回 ICMPv6 unreachable。判反了要么
// 把能用的 v6 掐掉,要么把流量往黑洞里送。

func TestIsUsableV6EgressSrc_RejectsTheFakeGlobalAddressesHomeRoutersHandOut(t *testing.T) {
	cases := []struct {
		addr string
		want bool
		why  string
	}{
		{"2400:cb00::1", true, "真·全局单播"},
		{"2001:db8:1::5", false, "RFC3849 文档段:家用路由器 RA 误发的假 v6 实测就落这里"},
		{"fd00::1", false, "ULA 不是出网源"},
		{"fe80::1", false, "链路本地"},
		{"::1", false, "环回"},
		{"::ffff:203.0.113.1", false, "v4-mapped 不算 v6 出网"},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			got := isUsableV6EgressSrc(netip.MustParseAddr(tc.addr).Unmap())
			if got != tc.want {
				t.Fatalf("got %v want %v(%s)", got, tc.want, tc.why)
			}
		})
	}
}

func TestV6ProbeDNSRoundTrip_NeedsAnActualReplyNotJustAWritableSocket(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("本机没有 IPv6 回环,跳过")
	}

	t.Run("对端有回包 = 通", func(t *testing.T) {
		pc, err := net.ListenPacket("udp6", "[::1]:0")
		if err != nil {
			t.Skipf("起不了 udp6 监听: %v", err)
		}
		defer pc.Close()
		go func() {
			buf := make([]byte, 512)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}()

		_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
		if !v6ProbeDNSRoundTripTo(t, "::1", port) {
			t.Fatal("对端确实回包了,探测却判不通")
		}
	})

	t.Run("端口上没人 = 不通", func(t *testing.T) {
		// 没人监听时 udp6 write 依然"成功",只有等不到回包才能判定不通 ——
		// 这正是这个探测存在的意义:光有地址和路由不算有出网。
		if v6ProbeDNSRoundTrip("::1", 300*time.Millisecond) {
			t.Skip("本机 ::1:53 上真有 DNS 在跑,这条断言无意义")
		}
	})
}

// v6ProbeDNSRoundTripTo 是给测试用的变体:生产函数固定打 :53,这里换成临时端口。
func v6ProbeDNSRoundTripTo(t *testing.T, host, port string) bool {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x7636, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("www.google.com."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	query, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	conn, err := net.DialTimeout("udp6", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return false
	}
	n, err := conn.Read(make([]byte, 512))
	return err == nil && n > 0
}

func hasIPv6Loopback() bool {
	c, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// 路由查得通不代表真能出网 —— 这个短路顺序就是修掉"假 v6"黑洞的关键。
func TestProbeServerIPv6Egress_RouteCheckGatesTheRoundTripCheck(t *testing.T) {
	hasRoute := probeServerIPv6Route()
	got := probeServerIPv6Egress()
	if !hasRoute && got {
		t.Fatal("路由级都没过,整体不该判成有 v6 出网")
	}
	if got && !verifyServerIPv6RoundTrip() {
		t.Fatal("判成有出网,但端到端往返验不过 —— 这正是会把流量送进黑洞的组合")
	}
}

func TestStartServerV6EgressProbe_StopsOnSignal(t *testing.T) {
	withTestGlobalContext(t)

	prevHas := serverV6EgressHas.Load()
	prevKnown := serverV6EgressKnown.Load()
	t.Cleanup(func() {
		serverV6EgressHas.Store(prevHas)
		serverV6EgressKnown.Store(prevKnown)
	})

	stop := make(chan struct{})
	startServerV6EgressProbe(stop)
	// 探测一轮最坏几秒(拨测超时),给足时间让它至少跑完首轮并写下结果。
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && !serverV6EgressKnown.Load() {
		time.Sleep(100 * time.Millisecond)
	}
	if !serverV6EgressKnown.Load() {
		t.Fatal("首轮探测没有写下结果 —— 数据面会一直按「未知」处理")
	}
	close(stop)
}

// NAT66 补装钩子:探到有 v6 才补装,装成功就撤钩,只补一次。
func TestV6SetupRetryHook_RunsOnceAndDisarmsOnSuccess(t *testing.T) {
	v6SetupRetryMu.Lock()
	prev := v6SetupRetryFn
	v6SetupRetryMu.Unlock()
	t.Cleanup(func() { armV6SetupRetry(prev) })

	// 没注册时调用是安全的空操作。
	armV6SetupRetry(nil)
	runV6SetupRetryIfArmed()

	var calls int
	armV6SetupRetry(func() bool { calls++; return false })
	runV6SetupRetryIfArmed()
	runV6SetupRetryIfArmed()
	if calls != 2 {
		t.Fatalf("装失败时钩子应保留供下轮再试,调用次数 %d", calls)
	}

	calls = 0
	armV6SetupRetry(func() bool { calls++; return true })
	runV6SetupRetryIfArmed()
	runV6SetupRetryIfArmed()
	if calls != 1 {
		t.Fatalf("装成功后应撤钩,只该调一次,got %d —— 反复补装会和关停时的清理打架", calls)
	}
}
