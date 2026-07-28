package main

// REALITY 入口的启动、accept 循环与环回桥接。
//
// 这三处的共同点是**故障不表现为报错**:
//
//   - 启动:上报的 tcp_port 与真正在听的端口不一致,客户端全都连不上,而日志一切正常;
//   - accept:把 fd 耗尽这类可恢复错误当成致命,整个 REALITY 入口对所有人永久消失
//     (进程还活着,别的入口还在服务,所以监控也不一定报);
//   - 桥接:环回不可用时不关外部连接,客户端挂在那儿等到超时;或者握手 deadline 忘了清,
//     长连接每 15 秒被砍一次。
//
// 另外 REALITY 端口常年 :443 对公网、且不受 jump_host_firewall 保护(见其顶部 doc),
// 所以「失败之后还能不能继续服务」在这里比别处更要紧。

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/util"
)

// ── 脚手架 ──────────────────────────────────────────────────────────────────

// realityFixture 一份能通过 Validate 的最小 REALITY 配置。私钥是 32 字节任意值
// (X25519 对私钥没有额外结构要求),够 buildRealityTLSConfig 与 reality.NewListener 用。
func realityFixture(t *testing.T) *config.Config {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cfg := &config.Config{}
	cfg.Reality.ListenAddr = "127.0.0.1:0"
	cfg.Reality.Dest = "127.0.0.1:443"
	cfg.Reality.PrivateKey = base64.RawURLEncoding.EncodeToString(key)
	cfg.Reality.ServerNames = []string{"www.example.com"}
	cfg.Reality.ShortIds = []string{"0123456789abcdef"}
	cfg.Reality.ClientAddr = "vpn.example.com:443" // 只进日志,顺带覆盖那条分支
	// 必须是**具体端口**:启动日志里会拼环回 URL,而 parseListenPort 遇到 ":0" 会当配置错误
	// 直接结束进程(config 校验保证生产里到不了这儿,但测试直接调 listener 就绕过了校验)。
	cfg.Server.ListenAddr = "127.0.0.1:8080"
	return cfg
}

// scriptedListener 按剧本逐次返回 Accept 结果。accept 循环的错误分类只能这样验 ——
// 真 listener 造不出 EMFILE。
type scriptedListener struct {
	ch        chan scriptedAccept
	closeCnt  atomic.Int32
	acceptCnt atomic.Int32

	mu     sync.Mutex
	stamps []time.Time // 每次 Accept 被调用的时刻,用来量退避实际睡了多久
}

type scriptedAccept struct {
	c   net.Conn
	err error
}

func newScriptedListener(steps ...scriptedAccept) *scriptedListener {
	l := &scriptedListener{ch: make(chan scriptedAccept, len(steps)+1)}
	for _, s := range steps {
		l.ch <- s
	}
	return l
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.acceptCnt.Add(1)
	l.mu.Lock()
	l.stamps = append(l.stamps, time.Now())
	l.mu.Unlock()
	a := <-l.ch
	return a.c, a.err
}

// gapBetweenAccepts 第 i 次与第 i+1 次 Accept 之间隔了多久(1 起数)= 第 i 次之后睡的退避。
func (l *scriptedListener) gapBetweenAccepts(t *testing.T, i int) time.Duration {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.stamps) < i+1 {
		t.Fatalf("只记到 %d 次 Accept,取不到第 %d 与第 %d 次之间的间隔", len(l.stamps), i, i+1)
	}
	return l.stamps[i].Sub(l.stamps[i-1])
}
func (l *scriptedListener) Close() error { l.closeCnt.Add(1); return nil }
func (l *scriptedListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}

// freeTCPPort 拿一个当下空闲的本地端口(拿完即释放)。用来验「端口冲突」与「关掉之后端口真的还了」。
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("探测空闲端口: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// startLoopbackWSEcho 起一个环回 WebSocket 服务端,模拟 [server] 那一侧。
//
// smuxMode=true 时按环回承载的真实约定收:先读 4 字节 VPN1 魔法、再 smux.Server,
// 每条 stream 先经 readLoopbackClientAddr 读 PROXY 头 —— 于是 bridge 写的头能被
// 真实解析,「真实客户端 IP 有没有透传过来」才是可断言的。
//
// 返回 listenAddr / wsPath 供 bridgeRealityToPlainVPN 自己拼 URL(拼错也是一种静默故障,
// 让它自己拼才测得到),以及一个收「服务端观察到的客户端地址」的 channel。
func startLoopbackWSEcho(t *testing.T, smuxMode bool) (listenAddr, wsPath string, seenRemote <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起环回 WS listener: %v", err)
	}
	seen := make(chan string, 4)
	path := "/reality-guard-test/v1/feed"
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		ws, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		nc := util.NewWSStreamConn(ws)
		defer func() { _ = nc.Close() }()
		if !smuxMode {
			seen <- nc.RemoteAddr().String()
			_, _ = io.Copy(nc, nc)
			return
		}
		br := bufio.NewReaderSize(nc, 256)
		head, err := br.Peek(4)
		if err != nil || !bytes.Equal(head[:4], loopbackSmuxMagic) {
			return
		}
		_, _ = br.Discard(4)
		sess, err := smux.Server(&connBufCloser{Conn: nc, r: br}, smux.DefaultConfig())
		if err != nil {
			return
		}
		defer func() { _ = sess.Close() }()
		for {
			st, err := sess.AcceptStream()
			if err != nil {
				return
			}
			go func(s *smux.Stream) {
				defer func() { _ = s.Close() }()
				wrapped := readLoopbackClientAddr(s)
				seen <- wrapped.RemoteAddr().String()
				_, _ = io.Copy(wrapped, wrapped)
			}(st)
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), path, seen
}

// dialLoopbackTCP 造一条**真** TCP 连接对,用它当 realityConn。
//
// 不能图省事用 net.Pipe:pipe 的 RemoteAddr 是 "pipe",normalizeProxyAddr 认不出来,
// PROXY 头会退化成 LOCAL(无源)—— 那样「真实客户端地址透传」这条断言就永远是假通过。
func dialLoopbackTCP(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起 listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	type res struct {
		c   net.Conn
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- res{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	r := <-accepted
	if r.err != nil {
		t.Fatalf("Accept: %v", r.err)
	}
	t.Cleanup(func() {
		_ = r.c.Close()
		_ = client.Close()
	})
	return r.c, client
}

// ── buildRealityTLSConfig ───────────────────────────────────────────────────
//
// 主体归一与三个解码失败已由 daemon_helpers_test.go 那份钉住。这里只补两处它没覆盖、
// 而错了会**静默**让整批客户端连不上的:shortId 的字节摆放,以及 seed→key 的确定性。

// TestBuildRealityTLSConfig_ShortIDsMustMatchWhatClientsPutOnTheWire
// shortId 在线上是**左对齐**的:客户端把它解码后从 sessionId[8] 起左对齐写入,服务端
// 也按 copy(dst[:], plainText[8:]) 左对齐读。右对齐的实现会让任何短于 16 个十六进制字符
// 的 shortId(面板默认的 8 位就是)对不上 —— 握手静默失败、回落 dest,客户端看到的是
// 一个正常的第三方网站,不是错误。这种故障从现象上根本认不出来。
func TestBuildRealityTLSConfig_ShortIDsMustMatchWhatClientsPutOnTheWire(t *testing.T) {
	cfg := realityFixture(t)
	r := &cfg.Reality
	r.ServerNames = []string{"  a.example.com  ", "", "   ", "b.example.com"}
	r.ShortIds = []string{"", "abcd", "0123456789abcdef"}

	rc, err := buildRealityTLSConfig(r)
	if err != nil {
		t.Fatalf("buildRealityTLSConfig: %v", err)
	}

	if len(rc.ShortIds) != 3 {
		t.Fatalf("三项 short_id 都该收下(含空串), got %v", rc.ShortIds)
	}
	if !rc.ShortIds[[8]byte{}] {
		t.Error("空 short_id 应映射成全 0 —— 面板默认就是它,漏了这批客户端会全部静默回落 dest")
	}
	if !rc.ShortIds[[8]byte{0xab, 0xcd}] {
		t.Errorf("短 short_id 必须左对齐存放(高位在前、低位补 0), got %v —— "+
			"右对齐会让 8 位 shortId 的客户端全部静默握手失败", rc.ShortIds)
	}
	if !rc.ShortIds[[8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}] {
		t.Errorf("满 8 字节 short_id 摆放不对: %v", rc.ShortIds)
	}

	// server_names 的**首尾空白**也要去掉:SNI 精确匹配,带空格等于这个域名没配上。
	if len(rc.ServerNames) != 2 || !rc.ServerNames["a.example.com"] || !rc.ServerNames["b.example.com"] {
		t.Errorf("server_names 应去首尾空白并跳过空项, got %v", rc.ServerNames)
	}
}

// TestBuildRealityTLSConfig_Mldsa65KeyDerivedFromSeed 同一个 seed 必须恒等推出同一把 key。
// 每次重启换一把的话,客户端里固定的那份公钥就对不上了 —— 而这依然表现为静默回落。
func TestBuildRealityTLSConfig_Mldsa65KeyDerivedFromSeed(t *testing.T) {
	cfg := realityFixture(t)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	cfg.Reality.Mldsa65SeedBase64 = base64.RawURLEncoding.EncodeToString(seed)
	first, err := buildRealityTLSConfig(&cfg.Reality)
	if err != nil {
		t.Fatalf("带 seed: %v", err)
	}
	if len(first.Mldsa65Key) == 0 {
		t.Fatal("配了 seed 却没推出 key")
	}
	second, err := buildRealityTLSConfig(&cfg.Reality)
	if err != nil {
		t.Fatalf("再来一次: %v", err)
	}
	if !bytes.Equal(first.Mldsa65Key, second.Mldsa65Key) {
		t.Error("同一个 seed 两次推出的 key 不同 —— 每次重启都换公钥,客户端固定的那份就废了")
	}

	// 换 seed 必须换 key,否则「配了 seed」等于没生效。
	seed[0] ^= 0xff
	cfg.Reality.Mldsa65SeedBase64 = base64.RawURLEncoding.EncodeToString(seed)
	other, err := buildRealityTLSConfig(&cfg.Reality)
	if err != nil {
		t.Fatalf("换 seed: %v", err)
	}
	if bytes.Equal(first.Mldsa65Key, other.Mldsa65Key) {
		t.Error("换了 seed 推出的 key 却没变 —— seed 根本没参与推导")
	}
}

// ── 启动 ────────────────────────────────────────────────────────────────────

// TestStartRealityVPNListener_BindsReportsRealPortAndReleasesOnClose 三件事:真的绑上了、
// 上报的端口就是在听的那个、close 之后端口真的还了。
//
// 中间那条最值钱:tcpPort 会经 node_login 上报给控制面,客户端照它连。上报成 0 或别的值,
// 现象是「服务一切正常但没人连得上」,而服务端日志里什么错都没有。
func TestStartRealityVPNListener_BindsReportsRealPortAndReleasesOnClose(t *testing.T) {
	withTestGlobalContext(t)
	cfg := realityFixture(t)

	closeFn, startAccept, port, err := startRealityVPNListener(cfg, nil, nil)
	if err != nil {
		t.Fatalf("启动 REALITY 监听: %v", err)
	}
	if closeFn == nil || startAccept == nil {
		t.Fatal("启用时必须同时返回 closeFn 与 startAccept(main 的关机路径 defer 调 closeFn)")
	}
	if port <= 0 {
		t.Fatalf("listen_addr 用 :0 时应上报内核分配的真实端口, got %d —— 上报错了客户端一个都连不上", port)
	}

	// 上报的端口必须**正在被占用**:占不上才说明它就是真在听的那个。
	if probe, perr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); perr == nil {
		_ = probe.Close()
		closeFn()
		t.Fatalf("上报 tcp_port=%d 却能被别人绑上 —— 上报的不是真正在听的端口", port)
	}

	startAccept() // 只验不 panic;真 REALITY 握手要密钥协商,进程内造不出

	closeFn()
	closeFn() // 幂等:关机路径上重复调不该炸

	// 关掉之后端口必须归还,否则同端口重启会因 address in use 起不来。
	deadline := time.Now().Add(3 * time.Second)
	for {
		probe, perr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if perr == nil {
			_ = probe.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("closeFn 之后端口 %d 仍被占着: %v —— 同端口重启会 address in use", port, perr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestStartRealityVPNListener_PortConflictFailsFastWithoutHalfListener 端口被占时必须报错,
// 且**什么都不返回**。返回一个非 nil 的 closeFn 会让调用方以为起来了 —— 那是「以为 REALITY
// 开着、其实没开」的经典形状,而 :443 这种端口被别的进程占住并不罕见。
func TestStartRealityVPNListener_PortConflictFailsFastWithoutHalfListener(t *testing.T) {
	port := freeTCPPort(t)
	occupied, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("占位 listener: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	cfg := realityFixture(t)
	cfg.Reality.ListenAddr = fmt.Sprintf("127.0.0.1:%d", port)

	closeFn, startAccept, gotPort, err := startRealityVPNListener(cfg, nil, nil)
	if err == nil {
		if closeFn != nil {
			closeFn()
		}
		t.Fatal("端口已被占用却启动成功了")
	}
	if closeFn != nil || startAccept != nil || gotPort != 0 {
		t.Errorf("绑定失败时不能返回半成品(closeFn=%v startAccept=%v port=%d)",
			closeFn != nil, startAccept != nil, gotPort)
	}
}

// ── accept 循环 ─────────────────────────────────────────────────────────────

// TestRunRealityAcceptLoop_TransientErrorsDoNotKillTheListener 这是这个文件里最要紧的一条。
//
// fd 耗尽(EMFILE)、客户端在 backlog 里就 RST(ECONNABORTED)都是**可恢复**的:listen 本身
// 还好着,过几秒就能继续服务。把它们当致命而退出循环,后果是整个 REALITY 入口对所有客户端
// 永久消失 —— 进程还活着、别的入口还在服务,所以监控大概也不会响。
func TestRunRealityAcceptLoop_TransientErrorsDoNotKillTheListener(t *testing.T) {
	withTestGlobalContext(t)

	server, _ := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	ln := newScriptedListener(
		scriptedAccept{err: syscall.EMFILE},       // fd 用尽
		scriptedAccept{err: syscall.ECONNABORTED}, // backlog 里被 RST
		scriptedAccept{err: errors.New("boom")},   // 不认识的错误也不该致命
		scriptedAccept{c: server},                 // 恢复:这条必须被处理
		scriptedAccept{err: net.ErrClosed},        // 正常关机
	)

	handled := make(chan net.Conn, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runRealityAcceptLoop(ln, func(c net.Conn) { handled <- c })
	}()

	select {
	case got := <-handled:
		if got != server {
			t.Fatal("交给 handle 的不是 Accept 出来的那条连接")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("三个 transient 错误之后循环就没再 Accept 了 —— REALITY 入口会因一次 fd 耗尽永久停止服务")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("net.ErrClosed 之后循环没退出 —— 关机会卡住,systemd 只能 SIGKILL")
	}
	if n := ln.acceptCnt.Load(); n != 5 {
		t.Errorf("应当把剧本走完(5 次 Accept), got %d", n)
	}
}

// TestRunRealityAcceptLoop_ResetsBackoffAfterASuccessfulAccept 成功一次之后退避必须归零。
//
// 不归零的话,一段偶发错误把退避顶到 1s 封顶之后,**此后每一次**错误都要等满 1s ——
// 高峰期客户端的接入延迟被一段早已过去的抖动长期拖住,而这时监听器一切正常。
// 断言方式是量「出错到下次 Accept」的实际间隔:重置了是 5ms 起,没重置是几百毫秒。
func TestRunRealityAcceptLoop_ResetsBackoffAfterASuccessfulAccept(t *testing.T) {
	withTestGlobalContext(t)

	server, _ := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })

	// 先用 6 个错误把退避顶到 160ms(5→10→20→40→80→160),再成功一次,再错一次。
	// 重置了的话最后那次错误后只睡 5ms;没重置则要睡 320ms。
	steps := []scriptedAccept{}
	for i := 0; i < 6; i++ {
		steps = append(steps, scriptedAccept{err: syscall.ECONNABORTED})
	}
	steps = append(steps,
		scriptedAccept{c: server},                 // 第 7 次:成功
		scriptedAccept{err: syscall.ECONNABORTED}, // 第 8 次:再错
		scriptedAccept{err: net.ErrClosed},        // 第 9 次:收工
	)
	ln := newScriptedListener(steps...)

	done := make(chan struct{})
	go func() {
		defer close(done)
		runRealityAcceptLoop(ln, func(net.Conn) {})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("循环没退出")
	}

	if gap := ln.gapBetweenAccepts(t, 8); gap > 100*time.Millisecond {
		t.Errorf("成功一次之后再出错,等了 %v 才重试 —— 退避没归零,"+
			"一段早已过去的抖动会长期给每次接入加上封顶延迟", gap)
	}
}

// TestRunRealityAcceptLoop_ErrClosedExitsImmediately 主动 Close 是唯一的致命错误,且必须
// **立刻**退出:在这条路径上多睡一个 backoff 就是给关机时间凭空加延迟。
func TestRunRealityAcceptLoop_ErrClosedExitsImmediately(t *testing.T) {
	withTestGlobalContext(t)

	ln := newScriptedListener(scriptedAccept{err: net.ErrClosed})
	handled := make(chan net.Conn, 1)
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		runRealityAcceptLoop(ln, func(c net.Conn) { handled <- c })
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ErrClosed 之后没退出")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("退出花了 %v —— ErrClosed 走的是 backoff 分支,关机被无谓拖慢", elapsed)
	}
	if len(handled) != 0 {
		t.Error("出错时不该调 handle")
	}
	if n := ln.acceptCnt.Load(); n != 1 {
		t.Errorf("ErrClosed 之后不该再 Accept, got %d 次", n)
	}
}

// TestRunRealityAcceptLoop_StopsWhenGlobalContextCancelledDuringBackoff 退避期间收到关机信号
// 必须立刻走。少了这条 select 分支,一个持续报错的 listener 会把关机拖到 backoff 结束
// (封顶 1s,但每轮都要等)—— 而 fd 耗尽时错误恰恰是持续的。
func TestRunRealityAcceptLoop_StopsWhenGlobalContextCancelledDuringBackoff(t *testing.T) {
	_, cancel := withTestGlobalContext(t)

	ln := &scriptedListener{ch: make(chan scriptedAccept)}
	feeding := make(chan struct{})
	go func() { // 一直报同一个可恢复错误,逼循环停在退避里
		defer close(feeding)
		for {
			select {
			case ln.ch <- scriptedAccept{err: syscall.EMFILE}:
			case <-time.After(3 * time.Second):
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runRealityAcceptLoop(ln, func(net.Conn) { t.Error("不该有连接被处理") })
	}()

	// 等它确实进了退避(至少报过一次错)再取消。
	deadline := time.Now().Add(2 * time.Second)
	for ln.acceptCnt.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("关机信号来了却还在退避里睡 —— 一个持续报错的 listener 会把关机拖住")
	}
}

// TestNextRealityAcceptBackoff_GrowsThenCapsAndNeverZero 退避序列本身。
// 返回 0 会让持续报错变成 hot-spin 把 CPU 吃满;封顶太大则 fd 回收之后监听还在睡。
func TestNextRealityAcceptBackoff_GrowsThenCapsAndNeverZero(t *testing.T) {
	if got := nextRealityAcceptBackoff(0); got != 5*time.Millisecond {
		t.Errorf("首次退避应为 5ms, got %v", got)
	}
	if got := nextRealityAcceptBackoff(-time.Second); got != 5*time.Millisecond {
		t.Errorf("负值(不该出现)也应回到首次退避, got %v", got)
	}
	if got := nextRealityAcceptBackoff(5 * time.Millisecond); got != 10*time.Millisecond {
		t.Errorf("应当翻倍, got %v", got)
	}

	d := time.Duration(0)
	for i := 0; i < 40; i++ {
		d = nextRealityAcceptBackoff(d)
		if d <= 0 {
			t.Fatalf("第 %d 次退避得到 %v —— 0 会让持续报错变成 hot-spin 吃满 CPU", i+1, d)
		}
		if d > time.Second {
			t.Fatalf("第 %d 次退避 %v 超过 1s 封顶 —— fd 早回收了监听还在睡", i+1, d)
		}
	}
	if d != time.Second {
		t.Errorf("反复退避应稳定在 1s 封顶, got %v", d)
	}
}

// ── 两层抗 DoS 包装的错误路径 ───────────────────────────────────────────────

// TestRealityAcceptDeadlineListener_PropagatesAcceptError Accept 失败必须原样冒上去,
// 且不把连接交上去。
//
// 剧本刻意**同时**给出 conn 和错误(真 listener 不会这样,但这一层不该指望底层守规矩):
// 只给错误的话「返回 c」与「返回 nil」结果一样,这条断言就是假通过。语义上这也正是
// net.Listener 的约定 —— 出错即无连接,上层照约定只看 err、可以放心不判 c。
func TestRealityAcceptDeadlineListener_PropagatesAcceptError(t *testing.T) {
	want := syscall.EMFILE
	stray, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = stray.Close() })

	base := newScriptedListener(scriptedAccept{c: stray, err: want})
	ln := &realityAcceptDeadlineListener{Listener: base, handshakeTimeout: time.Second}

	c, err := ln.Accept()
	if !errors.Is(err, want) {
		t.Errorf("错误应原样冒上去, got %v", err)
	}
	if c != nil {
		t.Error("出错时必须返回 nil conn —— 按 net.Listener 的约定「有错即无连接」," +
			"给上层一条半成品连接会让它以为握手 deadline 已经盖上了")
	}
}

// TestRealityConcLimitListener_ReleasesSlotOnAcceptError 这条和上面那个「transient 不致命」
// 是一对:循环正确地重试了,但如果每次失败都漏还一个信号量槽位,那么一次 fd 耗尽风暴之后
// 监听器照样永久卡死在 `sem <-` 上 —— 两处都对才真的扛得住。
func TestRealityConcLimitListener_ReleasesSlotOnAcceptError(t *testing.T) {
	const capacity = 2
	base := &scriptedListener{ch: make(chan scriptedAccept, 1)}
	ln := &realityConcLimitListener{Listener: base, sem: make(chan struct{}, capacity)}

	// 失败次数远超容量。漏还的话第 capacity+1 次就永久卡在信号量上。
	for i := 0; i < capacity*5; i++ {
		base.ch <- scriptedAccept{err: syscall.ECONNABORTED}
		errCh := make(chan error, 1)
		go func() {
			_, err := ln.Accept()
			errCh <- err
		}()
		select {
		case err := <-errCh:
			if err == nil {
				t.Fatal("剧本给的是错误")
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("第 %d 次 Accept 卡住(容量 %d)—— 失败路径漏还信号量槽位,"+
				"一次 fd 耗尽风暴过后监听器就永久停止服务了", i+1, capacity)
		}
		if n := len(ln.sem); n != 0 {
			t.Fatalf("第 %d 次失败后信号量里还剩 %d 个占用", i+1, n)
		}
	}
}

// TestRealityConcLimitConn_CloseWriteFallsBackToCloseForNonTCP 底层不支持半关时降级为 Close。
// 直接返回 error 会让 reality 库在握手前的 CloseWrite 报错路径上放弃连接;什么都不做则更糟 ——
// 对端一直等我们的 FIN。
func TestRealityConcLimitConn_CloseWriteFallsBackToCloseForNonTCP(t *testing.T) {
	server, client := net.Pipe() // net.Pipe 不实现 CloseWrite
	t.Cleanup(func() { _ = client.Close() })

	released := make(chan struct{}, 1)
	c := &realityConcLimitListenerConn{Conn: server, release: func() { released <- struct{}{} }}

	if _, ok := any(server).(interface{ CloseWrite() error }); ok {
		t.Skip("前置条件不成立:net.Pipe 竟然实现了 CloseWrite,这条降级路径测不到")
	}
	if err := c.CloseWrite(); err != nil {
		t.Errorf("降级为 Close 不该报错: %v", err)
	}
	// 真的关掉了才算降级成功:对端读应当立刻结束,而不是一直等 FIN。
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("CloseWrite 降级之后对端仍能读 —— 连接没被关,对端会一直等")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("CloseWrite 降级什么都没做 —— 对端读一直挂着直到超时")
	}
}

// ── 环回桥接 ────────────────────────────────────────────────────────────────

// 两条**失败**路径(环回拨不通 / OpenStream 失败都必须关掉外部连接)已由
// daemon_helpers_test.go 的 TestBridgeRealityToPlainVPN_ClosingOneSideTearsDownTheOther 钉住。
// 这里补的是成功路径 —— 那才是真正跑数据的那条,此前一条断言都没有。

// TestBridgeRealityToPlainVPN_SmuxPathCarriesRealClientAddrAndBridgesBothWays
// smux 这条路的三件事,每件都对应一类静默故障:
//
//  1. 每条 stream 开头必须写 PROXY v2 头,且带**真实**客户端地址。缺了它,服务端对这条
//     连接的 PoW / 登录限流 / IP 失败锁定 / 审计全都记在 127.0.0.1 上 —— 按 IP 的反滥用
//     整体失效,还会连坐所有走同一环回的用户。
//  2. 握手 deadline 必须清掉。realityAcceptDeadlineListener 给每条 conn 套了 15s,不清的话
//     业务数据一旦有 15s 空闲就被砍断 —— 表现成「连上能用一会儿然后莫名断线」。
//  3. 双向都要通。只通一向的现象是「能发不能收」。
func TestBridgeRealityToPlainVPN_SmuxPathCarriesRealClientAddrAndBridgesBothWays(t *testing.T) {
	listenAddr, wsPath, seen := startLoopbackWSEcho(t, true)
	pool := newLoopbackSmuxPool(loopbackVPNWebSocketURL(listenAddr, wsPath, false), smux.DefaultConfig(), nil)

	server, client := dialLoopbackTCP(t)
	clientLocal := client.LocalAddr().String() // 这就是「真实客户端地址」

	// 学 realityAcceptDeadlineListener:进 bridge 之前先套一个很短的握手 deadline。
	// bridge 不清掉它的话,下面那次读写会被它打断。
	if err := server.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("设握手 deadline: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		bridgeRealityToPlainVPN(server, listenAddr, wsPath, pool, nil)
	}()

	select {
	case got := <-seen:
		if got != clientLocal {
			t.Errorf("服务端看到的客户端地址是 %s,应为 %s —— PoW/限流/审计会全记在环回地址上,"+
				"按 IP 的反滥用失效并连坐同一环回的所有用户", got, clientLocal)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("服务端没收到 stream(PROXY 头没写出去?)")
	}

	// 故意等过刚才那个 300ms 的握手 deadline 再收发:清干净了才通。
	time.Sleep(500 * time.Millisecond)

	payload := []byte("reality-bridge-roundtrip")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("客户端写: %v —— 握手 deadline 没被清掉的话这里就会超时", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	back := make([]byte, len(payload))
	if _, err := io.ReadFull(client, back); err != nil {
		t.Fatalf("客户端读回显: %v —— 握手 deadline 残留会让连接用一会儿就莫名断线", err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("回显不匹配: %q", back)
	}

	// 客户端断开 → bridge 两侧都要关,否则另一侧的 io.Copy 永远挂在 Read 上
	// (环回连接长期 ESTABLISHED,是斗篷/REALITY 的经典泄漏)。
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("客户端已断,bridge 没有收尾 —— 环回那侧会长期 ESTABLISHED 泄漏")
	}
}

// TestBridgeRealityToPlainVPN_PlainWebSocketPathBridgesBothWays 没开 smux 复用时走每连接
// 一次 WebSocket 直连。这条路自己拼环回 URL,拼错(端口/路径/scheme)就整条入口不通,
// 所以让 bridge 自己拼、只喂它 [server] 的 listen_addr。
func TestBridgeRealityToPlainVPN_PlainWebSocketPathBridgesBothWays(t *testing.T) {
	listenAddr, wsPath, seen := startLoopbackWSEcho(t, false)

	server, client := dialLoopbackTCP(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		bridgeRealityToPlainVPN(server, listenAddr, wsPath, nil, nil)
	}()

	select {
	case <-seen:
	case <-time.After(15 * time.Second):
		t.Fatal("环回 WebSocket 没收到连接 —— URL 拼错了整条 REALITY 入口都不通")
	}

	payload := []byte("plain-ws-roundtrip")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("客户端写: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	back := make([]byte, len(payload))
	if _, err := io.ReadFull(client, back); err != nil {
		t.Fatalf("客户端读回显: %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("回显不匹配: %q", back)
	}

	_ = client.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("客户端已断,bridge 没收尾")
	}
}
