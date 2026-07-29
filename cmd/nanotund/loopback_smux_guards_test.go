package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"

	"github.com/nanotun/server/util"
)

// 本文件钉住环回承载(hy2 / REALITY 共用的那条数据面)的两处静默故障:
//
//   - 池退化成「每条流一条 WSS」:功能上照样通,但复用形同未做,每条流都要重做一次环回握手,
//     并发一上来端口 / 握手开销全回来了。只有数「建了几条承载」才看得见。
//   - dispatchVPNIncoming 路由走错:VPN1 该当承载、非 VPN1 该当直连链路帧。走错时连接一样会断,
//     错误日志也一样,所以断言必须落在「这条连接到底是被当成 smux 会话还是被当成链路帧」上。

// smuxPoolForEcho 建一个指向回声服务端的池。
func smuxPoolForEcho(es *loopbackEchoServer, cfg *smux.Config) *loopbackSmuxPool {
	return newLoopbackSmuxPool(es.wsURL(), cfg, nil)
}

// tryEcho 在一条 stream 上跑一次回声,确认它真能通(不只是 OpenStream 返回了对象)。
func tryEcho(c net.Conn, payload string) error {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(payload)); err != nil {
		return fmt.Errorf("写 stream: %w", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		return fmt.Errorf("读回声: %w", err)
	}
	if string(buf) != payload {
		return fmt.Errorf("回声不一致: want %q got %q", payload, buf)
	}
	return nil
}

func echoRoundTrip(t *testing.T, c net.Conn, payload string) {
	t.Helper()
	if err := tryEcho(c, payload); err != nil {
		t.Fatal(err)
	}
}

// 多条流必须挤在同一条承载上 —— 这是池存在的唯一理由。
func TestLoopbackSmuxPool_ManyStreamsShareOneCarrier(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	pool := smuxPoolForEcho(es, smux.DefaultConfig())

	for i := 0; i < 5; i++ {
		st, err := pool.OpenStream()
		if err != nil {
			t.Fatalf("第 %d 条 OpenStream: %v", i, err)
		}
		echoRoundTrip(t, st, "ping")
		_ = st.Close()
	}
	if got := es.upgrades.Load(); got != 1 {
		t.Fatalf("5 条流应复用 1 条承载,实际建了 %d 条(复用没生效)", got)
	}
}

// 并发首次 OpenStream 只许拨一次:singleflight。
//
// 退化成「各自拨一次」时功能仍正常(每人拿到自己的会话),只有承载条数能揭发它;而环回一旦变慢,
// 这就是 N×15s 的串行放大。
func TestLoopbackSmuxPool_ConcurrentFirstOpenDialsOnlyOnce(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	pool := smuxPoolForEcho(es, smux.DefaultConfig())

	const n = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			st, err := pool.OpenStream()
			if err != nil {
				errs <- err
				return
			}
			_ = st.Close()
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发 OpenStream 失败: %v", err)
	}
	if got := es.upgrades.Load(); got != 1 {
		t.Fatalf("%d 个并发调用应只拨 1 次,实际拨了 %d 次(singleflight 失效)", n, got)
	}
}

// 承载被掐断后,最多只许赔上**一条**流。
//
// 第二十五轮深扫 MED 的回归测试。两个事实叠在一起:① 断线那一刻 OpenStream 往往仍然成功
// (SYN 由 shaper 异步写出,开流时还看不出承载已断),错误要到第一次读写才浮出来;② smux 要等
// keepalive 超时(DefaultConfig 30s)才把会话标记为死。此前池子只看 IsClosed(),于是在这半分钟里
// 把每条新 hy2 / REALITY 流都开在同一具尸体上,全部失败。现在第一条失败就摘掉会话,代价收敛成一条流。
// 不给任何等待时间:自愈必须发生在下一次调用,而不是等 keepalive。
func TestLoopbackSmuxPool_LosesAtMostOneStreamWhenTheCarrierDies(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	pool := smuxPoolForEcho(es, smux.DefaultConfig())

	st, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("首次 OpenStream: %v", err)
	}
	echoRoundTrip(t, st, "one")
	_ = st.Close()

	es.killCarriers()

	failed := 0
	var healed net.Conn
	for i := 0; i < 3 && healed == nil; i++ {
		st2, err := pool.OpenStream()
		if err != nil {
			failed++
			continue
		}
		if err := tryEcho(st2, "two"); err != nil {
			failed++
			_ = st2.Close()
			continue
		}
		healed = st2
	}
	if healed == nil {
		t.Fatal("承载断后连开三条流都不通:池子没有自愈,一直在往尸体上开流")
	}
	_ = healed.Close()
	if failed > 1 {
		t.Fatalf("承载断后有 %d 条流失败;应在第一条失败时就摘掉会话,把代价限制在一条内", failed)
	}
	if got := es.upgrades.Load(); got != 2 {
		t.Fatalf("应只重建 1 条承载(共 2),实际 %d 条", got)
	}
}

// 一条流正常收尾(对端关流 → EOF / 本端写已关闭的流)绝不能把共用承载带走。
//
// 上面那条自愈是靠「流上的 I/O 错误」触发的,所以这里是它的反面约束:承载是所有 hy2 / REALITY
// 连接共用的,把 EOF 之类的正常结束当成承载故障,等于每条连接断开都顺手掐断其他人的隧道。
func TestLoopbackSmuxPool_AStreamEndingNormallyKeepsTheSharedCarrier(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	pool := smuxPoolForEcho(es, smux.DefaultConfig())

	long, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream(长命流): %v", err)
	}
	defer func() { _ = long.Close() }()
	echoRoundTrip(t, long, "keep")

	// 短命流:自己关掉,再在上面读写各一次,把 io.EOF / io.ErrClosedPipe 都走一遍。
	short, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream(短命流): %v", err)
	}
	echoRoundTrip(t, short, "bye")
	_ = short.Close()
	_, _ = short.Read(make([]byte, 1))
	_, _ = short.Write([]byte("x"))

	// 长命流必须毫发无伤,而且不许悄悄换了承载。
	echoRoundTrip(t, long, "still")
	third, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("短命流结束后 OpenStream 失败(承载被误判故障摘掉了?): %v", err)
	}
	echoRoundTrip(t, third, "more")
	_ = third.Close()
	if got := es.upgrades.Load(); got != 1 {
		t.Fatalf("正常关流不该导致重建承载,实际共 %d 条", got)
	}
}

// brokenCarrierConn 一条可以按开关变坏的承载连接:Read / deadline 走真管道,Write 在开关打开后
// 返回承载级错误。用来把「smux 还没察觉承载已断」那个时间窗做成确定的。
type brokenCarrierConn struct {
	net.Conn
	failWrites atomic.Bool
}

func (c *brokenCarrierConn) Write(b []byte) (int, error) {
	if c.failWrites.Load() {
		return 0, &net.OpError{Op: "write", Net: "tcp", Err: errors.New("broken pipe")}
	}
	return c.Conn.Write(b)
}

// 流上撞到承载级错误时,必须当场把会话摘掉,不能等 smux 的 keepalive。
//
// 这是那条自愈的**第二道**:OpenStream 自己会检查 smux 记下的 socket 错误,但承载刚断的那一瞬间
// smux 往往还没察觉(SYN 由 shaper 异步写出),于是流开出来了、错误落在第一次读写上。这一道不补,
// 那个窗口里的每条流都白白失败。
func TestPoolStream_ACarrierLevelIOErrorRetiresTheSessionAtOnce(t *testing.T) {
	drained, raw := net.Pipe()
	t.Cleanup(func() { _ = drained.Close(); _ = raw.Close() })
	go func() { _, _ = io.Copy(io.Discard, drained) }()

	carrier := &brokenCarrierConn{Conn: raw}
	sess, err := smux.Client(carrier, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	st, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	pool := newLoopbackSmuxPool("ws://127.0.0.1:1/never", smux.DefaultConfig(), nil)
	pool.mu.Lock()
	pool.sess = sess
	pool.mu.Unlock()
	ps := &poolStream{Stream: st, pool: pool, sess: sess}

	carrier.failWrites.Store(true) // 承载断了,但 smux 此刻还不知道
	_ = ps.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := ps.Write([]byte("payload")); err == nil {
		t.Fatal("承载已坏,写应报错")
	}
	if poolCurrentSession(pool) != nil {
		t.Fatal("流上的承载级错误没有回传给池:后续每条流都还会开在这具尸体上")
	}
}

func poolCurrentSession(p *loopbackSmuxPool) *smux.Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sess
}

// 摘掉一具疑似失效的会话时,不许连带掐断已经跑在上面的流。
//
// 「疑似」是关键:判据是流上的一次 I/O 错误,可能误判。误判的代价必须是「多出一条承载」,
// 而不是「把别人正在用的隧道一起关掉」—— 所以 retireSession 只摘不关。
func TestLoopbackSmuxPool_RetiringASessionLeavesRunningStreamsAlone(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	pool := smuxPoolForEcho(es, smux.DefaultConfig())

	live, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer func() { _ = live.Close() }()
	echoRoundTrip(t, live, "before")

	sess := poolCurrentSession(pool)
	pool.retireSession(sess)

	if poolCurrentSession(pool) != nil {
		t.Fatal("retireSession 应把会话从池里摘掉")
	}
	echoRoundTrip(t, live, "after") // 被 Close 的话这里就断了
	next, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("摘掉后应能重建: %v", err)
	}
	echoRoundTrip(t, next, "fresh")
	_ = next.Close()
	if got := es.upgrades.Load(); got != 2 {
		t.Fatalf("应新建 1 条承载(共 2),实际 %d 条", got)
	}
}

// 迟到的旧会话故障信号不许动别人刚建好的新承载。
//
// 一条流可能在承载已被换掉之后才报错(比如它自己的读写慢一步)。若不认「是不是当前会话」就清,
// 新承载会被一次接一次的旧信号反复摘掉,退化成每条流一条承载。
func TestLoopbackSmuxPool_RetiringAStaleSessionDoesNotTouchTheCurrentOne(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	pool := smuxPoolForEcho(es, smux.DefaultConfig())

	if _, err := pool.OpenStream(); err != nil {
		t.Fatalf("OpenStream(会话 A): %v", err)
	}
	sessA := poolCurrentSession(pool)
	pool.retireSession(sessA)

	stB, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream(会话 B): %v", err)
	}
	sessB := poolCurrentSession(pool)
	if sessB == nil || sessB == sessA {
		t.Fatal("应已建起一条新会话 B")
	}

	pool.retireSession(sessA) // 迟到的旧信号

	if got := poolCurrentSession(pool); got != sessB {
		t.Fatal("旧会话的故障信号把当前承载也摘掉了")
	}
	echoRoundTrip(t, stB, "still-b")
	_ = stB.Close()
	if got := es.upgrades.Load(); got != 2 {
		t.Fatalf("不该因迟到信号再建承载,实际共 %d 条", got)
	}
}

// 会话自己死掉(keepalive 超时那条路)时,池子必须收尸:摘掉会话、关掉底下那条 WSS,并能重建。
//
// 不收尸的两种后果都不出声:① 池子一直握着死会话,新流全开在上面;② 环回 WSS 一直挂在服务端那侧,
// 每次断线泄漏一条。
func TestLoopbackSmuxPool_CollectsASessionThatDiesOnItsOwn(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	pool := smuxPoolForEcho(es, smux.DefaultConfig())

	st, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	echoRoundTrip(t, st, "one")
	sess := poolCurrentSession(pool)

	_ = sess.Close() // smux 判定会话死亡(等效于 keepalive 超时)

	deadline := time.Now().Add(5 * time.Second)
	for poolCurrentSession(pool) != nil {
		if time.Now().After(deadline) {
			t.Fatal("会话已死,池子仍握着它(后续每条流都会开在上面)")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-es.carrierGone:
	case <-time.After(5 * time.Second):
		t.Fatal("会话死了但底下那条环回 WSS 没被关掉(每次断线泄漏一条)")
	}

	next, err := pool.OpenStream()
	if err != nil {
		t.Fatalf("收尸后应能重建: %v", err)
	}
	echoRoundTrip(t, next, "two")
	_ = next.Close()
	if got := es.upgrades.Load(); got != 2 {
		t.Fatalf("应重建 1 条承载(共 2),实际 %d 条", got)
	}
}

// dropSession 用在「会话已确定不可用」上:除摘掉还要 Close,好让底下那条 WSS 当场被收走。
func TestLoopbackSmuxPool_DropSessionAlsoCollectsTheCarrier(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	pool := smuxPoolForEcho(es, smux.DefaultConfig())

	if _, err := pool.OpenStream(); err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	sess := poolCurrentSession(pool)

	pool.dropSession(sess)

	if poolCurrentSession(pool) != nil {
		t.Fatal("dropSession 应把会话从池里摘掉")
	}
	if !sess.IsClosed() {
		t.Fatal("dropSession 应把会话关掉(否则要等 keepalive 超时才收 WSS)")
	}
	select {
	case <-es.carrierGone:
	case <-time.After(5 * time.Second):
		t.Fatal("dropSession 后环回 WSS 未被收走")
	}
}

// 环回拨不通时要如实报错,且不许在池里留下任何东西 —— 留下就等于把失败缓存给后续所有流。
func TestLoopbackSmuxPool_ReportsDialFailureAndCachesNothing(t *testing.T) {
	// 127.0.0.1:1 上不会有监听者。
	pool := newLoopbackSmuxPool("ws://127.0.0.1:1/nope", smux.DefaultConfig(), nil)

	if _, err := pool.OpenStream(); err == nil {
		t.Fatal("环回拨不通时 OpenStream 应报错")
	}
	if poolCurrentSession(pool) != nil {
		t.Fatal("拨号失败后池里不该留下会话")
	}
	// 第二次仍应如实报错(而不是永远返回同一个缓存失败,或反过来假装成功)。
	if _, err := pool.OpenStream(); err == nil {
		t.Fatal("第二次 OpenStream 也应报错")
	}
}

// smux 客户端建不起来时,底下那条 WSS 必须一起关掉,不能留着挂在服务端。
func TestLoopbackSmuxPool_ClosesTheCarrierWhenTheSmuxClientCannotStart(t *testing.T) {
	es := startLoopbackWSEcho(t, true)
	bad := smux.DefaultConfig()
	bad.MaxFrameSize = 0 // smux.Client 在写任何帧之前就会拒掉这个配置
	pool := smuxPoolForEcho(es, bad)

	if _, err := pool.OpenStream(); err == nil {
		t.Fatal("非法 smux 配置下 OpenStream 应报错")
	}
	if got := es.upgrades.Load(); got != 1 {
		t.Fatalf("应已建起 1 条 WSS 再失败,实际 %d 条", got)
	}
	// 连接泄漏的话,服务端 handler 会一直挂在 AcceptStream 上,永远收不到这个信号。
	select {
	case <-es.carrierGone:
	case <-time.After(5 * time.Second):
		t.Fatal("smux.Client 失败后未关闭环回连接(服务端 handler 仍挂着)")
	}
	// 失败不该在池里留下半成品会话。
	pool.mu.Lock()
	leftover := pool.sess != nil
	pool.mu.Unlock()
	if leftover {
		t.Fatal("dialNewSession 失败后 p.sess 不应被写入")
	}
}

// dispatchVPNIncoming 的路由判据:同一份 PoWChallengeReq 帧,回复落在**裸连接上**还是**stream 里**。
//
// 走错路时连接一样会断、日志也差不多,所以只有「谁回了这一帧」能区分两条路由。顺带钉住 Peek 过的
// 前 4 字节必须原样交下去 —— 吞掉的话每个直连原生客户端的首帧都会解析失败。

// startDispatch 起一条真环回 TCP(isLoopbackConnPeer 要求对端是环回地址)并交给 dispatch。
func startDispatch(t *testing.T, muxEnabled bool) (client net.Conn, gw *gatewayState) {
	t.Helper()
	env := newLoginGateEnv(t)
	server, client := dialLoopbackTCP(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		dispatchVPNIncoming(server, env.gw, muxEnabled, smux.DefaultConfig())
	}()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		<-done
	})
	return client, env.gw
}

// 环回来源的 VPN1:整条连接当承载,链路帧在 stream 里跑(每条 stream 先读 PROXY 头)。
func TestDispatchVPNIncoming_VPN1FromLoopbackCarriesLinkFramesInsideStreams(t *testing.T) {
	client, _ := startDispatch(t, true)

	if _, err := client.Write(loopbackSmuxMagic); err != nil {
		t.Fatalf("写魔法前缀: %v", err)
	}
	sess, err := smux.Client(client, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	defer func() { _ = sess.Close() }()
	st, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if err := writeLoopbackProxyHeader(st,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4321},
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}); err != nil {
		t.Fatalf("写 PROXY 头: %v", err)
	}
	if err := writeLinkFrameWithDeadline(st, util.LinkTypePoWChallengeReq, nil, 5*time.Second); err != nil {
		t.Fatalf("写 PoWChallengeReq: %v", err)
	}
	typ, _, err := readLinkFrameWithDeadline(st, 5*time.Second)
	if err != nil {
		t.Fatalf("stream 内没读到服务端回应(VPN1 没被当成承载?): %v", err)
	}
	if typ != util.LinkTypePoWChallenge {
		t.Fatalf("stream 内首帧 typ=%d,期望 PoWChallenge(%d)", typ, util.LinkTypePoWChallenge)
	}
}

// 不带魔法前缀:必须直接交给 handleVPNLink,且 Peek 走的字节要原样还给它。
//
// 第二十五轮深扫 HIGH 的回归测试:首帧 PoWChallengeReq 协议规定 body 为空,线上恒为 3 字节。
// 此前 dispatch 在识别阶段死等 4 个字节,于是启用 [smux] + hy2/REALITY 时服务端等第 4 字节、
// 客户端等 PoWChallenge,所有直连客户端都登不进来。下面先钉住「首帧真的只有 3 字节」这个前提,
// 否则协议一改,这条用例会悄悄不再覆盖那个 bug。
func TestDispatchVPNIncoming_NonMagicPrefixGoesStraightToTheLinkHandler(t *testing.T) {
	var wire bytes.Buffer
	if err := util.WriteLinkFrame(&wire, util.LinkTypePoWChallengeReq, nil); err != nil {
		t.Fatalf("WriteLinkFrame: %v", err)
	}
	if wire.Len() >= 4 {
		t.Fatalf("首帧已不止 3 字节(%d),本用例的前提失效,请改用一个短于 4 字节的首帧", wire.Len())
	}

	client, _ := startDispatch(t, true)

	if err := writeLinkFrameWithDeadline(client, util.LinkTypePoWChallengeReq, nil, 5*time.Second); err != nil {
		t.Fatalf("写 PoWChallengeReq: %v", err)
	}
	typ, _, err := readLinkFrameWithDeadline(client, 5*time.Second)
	if err != nil {
		t.Fatalf("裸连接上没读到服务端回应(帧被当成 smux 承载或前 4 字节被吞了?): %v", err)
	}
	if typ != util.LinkTypePoWChallenge {
		t.Fatalf("首帧 typ=%d,期望 PoWChallenge(%d)", typ, util.LinkTypePoWChallenge)
	}
}

// 未启用 [smux] 时:任何形状都直连,连一个字节都不许当承载读。
func TestDispatchVPNIncoming_WithoutMuxEveryConnIsADirectLink(t *testing.T) {
	client, _ := startDispatch(t, false)

	if err := writeLinkFrameWithDeadline(client, util.LinkTypePoWChallengeReq, nil, 5*time.Second); err != nil {
		t.Fatalf("写 PoWChallengeReq: %v", err)
	}
	typ, _, err := readLinkFrameWithDeadline(client, 5*time.Second)
	if err != nil {
		t.Fatalf("[smux] 未启用时应直连,却没读到回应: %v", err)
	}
	if typ != util.LinkTypePoWChallenge {
		t.Fatalf("首帧 typ=%d,期望 PoWChallenge(%d)", typ, util.LinkTypePoWChallenge)
	}
}

// 未启用 [smux] 时,客户端自称 VPN1 也不能把自己升级成承载。
func TestDispatchVPNIncoming_VPN1CannotSelfUpgradeWhenMuxDisabled(t *testing.T) {
	client, _ := startDispatch(t, false)

	if _, err := client.Write(loopbackSmuxMagic); err != nil {
		t.Fatalf("写魔法前缀: %v", err)
	}
	sess, err := smux.Client(client, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	defer func() { _ = sess.Close() }()
	st, err := sess.OpenStream()
	if err != nil {
		return // 承载没建起来,本就符合预期
	}
	_ = writeLoopbackProxyHeader(st,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4321},
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
	if err := writeLinkFrameWithDeadline(st, util.LinkTypePoWChallengeReq, nil, 2*time.Second); err != nil {
		return
	}
	if typ, _, err := readLinkFrameWithDeadline(st, 2*time.Second); err == nil {
		t.Fatalf("[smux] 未启用时 VPN1 仍被当成承载,stream 内收到了 typ=%d", typ)
	}
}

func withShortIdentifyTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := loopbackDispatchPeekTimeout
	loopbackDispatchPeekTimeout = d
	t.Cleanup(func() { loopbackDispatchPeekTimeout = prev })
}

// 连上就装死的对端必须被踢掉:未认证连接白占一个 goroutine 和一块读缓冲是笔便宜的 DoS。
func TestDispatchVPNIncoming_KicksAPeerThatNeverIdentifiesItself(t *testing.T) {
	withShortIdentifyTimeout(t, 200*time.Millisecond)
	env := newLoginGateEnv(t)

	server, client := dialLoopbackTCP(t)
	defer func() { _ = client.Close() }()
	done := make(chan struct{})
	go func() {
		defer close(done)
		dispatchVPNIncoming(server, env.gw, true, smux.DefaultConfig())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("对端一个字节都不发,识别阶段却一直等下去(goroutine 被白占)")
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("识别超时后连接未被关闭")
	}
}

// 识别完必须把那道 deadline 撤掉,否则承载会在识别超时那一刻被硬生生截断。
//
// 承载是长命的(所有 hy2 / REALITY 流都跑在上面),而识别期的 deadline 是给未认证连接设的;
// 忘了撤 = 每条承载最多活 30s,之后所有多路复用连接一起断。
func TestDispatchVPNIncoming_ClearsTheIdentifyDeadlineOnTheCarrier(t *testing.T) {
	withShortIdentifyTimeout(t, 200*time.Millisecond)
	client, _ := startDispatch(t, true)

	if _, err := client.Write(loopbackSmuxMagic); err != nil {
		t.Fatalf("写魔法前缀: %v", err)
	}
	sess, err := smux.Client(client, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	defer func() { _ = sess.Close() }()

	time.Sleep(600 * time.Millisecond) // 远超识别超时:deadline 没撤的话承载此刻已死

	st, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("识别超时之后 OpenStream 失败(承载被那道 deadline 截断了?): %v", err)
	}
	if err := writeLoopbackProxyHeader(st,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4321},
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}); err != nil {
		t.Fatalf("写 PROXY 头: %v", err)
	}
	if err := writeLinkFrameWithDeadline(st, util.LinkTypePoWChallengeReq, nil, 5*time.Second); err != nil {
		t.Fatalf("写 PoWChallengeReq: %v", err)
	}
	typ, _, err := readLinkFrameWithDeadline(st, 5*time.Second)
	if err != nil {
		t.Fatalf("承载在识别超时之后不再可用(那道 deadline 没撤): %v", err)
	}
	if typ != util.LinkTypePoWChallenge {
		t.Fatalf("stream 内首帧 typ=%d,期望 PoWChallenge(%d)", typ, util.LinkTypePoWChallenge)
	}
}

// 对端连上就跑:Peek 失败必须关连接并返回,不能挂着。
func TestDispatchVPNIncoming_ClosesTheConnWhenPeekFails(t *testing.T) {
	_, cancel := withTestGlobalContext(t)
	defer cancel()

	server, client := dialLoopbackTCP(t)
	_ = client.Close() // 一个字节都不发就走

	done := make(chan struct{})
	go func() {
		defer close(done)
		dispatchVPNIncoming(server, &gatewayState{}, true, smux.DefaultConfig())
	}()
	awaitClosed(t, done, "dispatchVPNIncoming(Peek 失败)")
	_ = server.Close()
}
