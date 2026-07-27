package main

// REALITY 入站监听器的外壳测试。
//
// REALITY 握手本身没法在进程内造(要真实密钥协商与回落目标),但它外面套的**两层
// 抗 DoS 包装**是纯 net.Listener 逻辑,可以直接测 —— 而这两层恰恰是 REALITY 端口
// (常年 :443 对公网、且不受 jump_host_firewall 保护)唯一的防线。
//
// 其中并发限制那层还背着一次真实事故:早先直接用 netutil.LimitListener,它返回的
// conn 只嵌入 net.Conn 接口、不暴露 CloseWrite(),而 reality 库握手前会做
// raw.(CloseWriteConn) 强类型断言 —— 断言 panic 被库内的 recover 静默吞掉,
// 连接永不关闭、信号量槽位永不释放,攒够 1024 个之后整个监听器彻底死掉。
// 这类「已经踩过一次」的坑最值得钉死。

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/config"
)

// closeWriteConn 是 xtls/reality 在握手前强制断言的接口(net.Conn + CloseWrite)。
// 这里照抄一份,免得为了测试去依赖 reality 库的内部类型。
type closeWriteConn interface {
	net.Conn
	CloseWrite() error
}

// TestRealityConcLimitConn_SatisfiesCloseWriteConn 是那次事故的定点回归。
//
// 包装后的 conn 必须仍然满足 CloseWriteConn。不满足的话,reality 库在握手前的
// 类型断言会 panic,而它自己的 recover 会把 panic 静默吃掉 —— 现场表现是客户端
// 连上后 15 秒收不到任何应用层响应、90 秒后被 keepalive RST,累计约 1024 次之后
// 监听器完全卡死。全程没有一行错误日志。
func TestRealityConcLimitConn_SatisfiesCloseWriteConn(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起测试 listener: %v", err)
	}
	defer func() { _ = base.Close() }()

	ln := &realityConcLimitListener{Listener: base, sem: make(chan struct{}, 4)}

	go func() {
		c, err := net.Dial("tcp", base.Addr().String())
		if err == nil {
			time.Sleep(200 * time.Millisecond)
			_ = c.Close()
		}
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cw, ok := conn.(closeWriteConn)
	if !ok {
		t.Fatal("并发限制包装之后的 conn 不再满足 CloseWriteConn —— reality 握手前的类型断言会 panic," +
			"且被库内 recover 静默吞掉:连接不关、信号量不释放,约 1024 次之后监听器彻底卡死,全程无日志")
	}
	// 真调一次,确认不是只有方法签名、实际会 panic 或永远报错。
	if err := cw.CloseWrite(); err != nil {
		t.Errorf("CloseWrite() 返回错误: %v", err)
	}
}

// TestRealityConcLimitListener_ReleasesSlotOnClose 槽位必须在 Close 时归还。
//
// 不归还的话,监听器会在累计接受 realityMaxConcurrent 条连接之后**永久**卡在
// Accept 上,哪怕当时一条连接都没有 —— 是一条只需时间就能触发的拒绝服务路径。
func TestRealityConcLimitListener_ReleasesSlotOnClose(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起测试 listener: %v", err)
	}
	defer func() { _ = base.Close() }()

	const cap = 2
	ln := &realityConcLimitListener{Listener: base, sem: make(chan struct{}, cap)}

	// 反复「连上 → 接受 → 关闭」远超容量的次数。槽位若不归还,会在第 cap+1 次卡死。
	for i := 0; i < cap*5; i++ {
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, err := net.Dial("tcp", base.Addr().String())
			if err == nil {
				_ = c.Close()
			}
		}()

		accepted := make(chan net.Conn, 1)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				accepted <- c
			}
		}()

		select {
		case c := <-accepted:
			_ = c.Close() // 归还槽位
		case <-time.After(5 * time.Second):
			t.Fatalf("第 %d 次 Accept 卡住(容量 %d)—— 关闭连接没有归还信号量槽位,"+
				"监听器会在累计接受 %d 条连接后永久停止服务", i+1, cap, realityMaxConcurrent)
		}
		<-done
	}
}

// TestRealityConcLimitConn_DoubleCloseReleasesOnce 重复 Close 只能归还一次槽位。
//
// 归还多次会把容量凭空放大,并发上限形同虚设;而 bridge 的清理路径上确实存在
// 同一条 conn 被关两次的可能(defer 链 + 错误分支各关一次)。
func TestRealityConcLimitConn_DoubleCloseReleasesOnce(t *testing.T) {
	sem := make(chan struct{}, 2)
	sem <- struct{}{} // 占一个槽位,模拟 Accept 拿到的那条

	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	c := &realityConcLimitListenerConn{
		Conn:    server,
		release: func() { <-sem },
	}

	_ = c.Close()
	_ = c.Close() // 第二次不该再归还

	if len(sem) != 0 {
		t.Fatalf("两次 Close 之后信号量里还剩 %d,状态异常", len(sem))
	}
	// 容量是 2、占用过 1 个又归还了 1 个,现在应当能放进 2 个而不阻塞。
	for i := 0; i < 2; i++ {
		select {
		case sem <- struct{}{}:
		default:
			t.Fatalf("重复 Close 少归还了槽位(第 %d 个放不进去)", i+1)
		}
	}
	// 第 3 个必须放不进去 —— 放得进说明重复 Close 把容量放大了。
	select {
	case sem <- struct{}{}:
		t.Error("重复 Close 归还了两次槽位,并发上限被放大 —— 抗 DoS 的封顶失效")
	default:
	}
}

// TestRealityAcceptDeadline_SetsHandshakeDeadline Accept 出来的连接必须自带截止时间。
//
// 少了它,攻击者只要建 TCP 连接却不发 ClientHello,握手 goroutine 就会一直挂着,
// 配合上面的并发上限反而更快把监听器占满。
func TestRealityAcceptDeadline_SetsHandshakeDeadline(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起测试 listener: %v", err)
	}
	defer func() { _ = base.Close() }()

	ln := &realityAcceptDeadlineListener{Listener: base, handshakeTimeout: 150 * time.Millisecond}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		time.Sleep(2 * time.Second) // 学攻击者:连上就不说话
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 对端一言不发,读操作应当被截止时间打断,而不是一直挂着。
	buf := make([]byte, 1)
	start := time.Now()
	_, rerr := conn.Read(buf)
	elapsed := time.Since(start)

	if rerr == nil {
		t.Fatal("对端什么都没发,Read 却成功返回了")
	}
	ne, ok := rerr.(net.Error)
	if !ok || !ne.Timeout() {
		t.Fatalf("Read 的错误是 %v,期望超时错误 —— 说明 Accept 没给连接设握手截止时间,"+
			"只连不说话的连接会一直占着握手槽位", rerr)
	}
	if elapsed > time.Second {
		t.Errorf("Read 过了 %v 才超时,远超设定的 150ms", elapsed)
	}
	wg.Wait()
}

// TestRealityAcceptDeadline_ZeroTimeoutMeansNoDeadline 超时设为 0 时不该设截止时间。
// 这是「关掉这层防护」的语义,别让它意外变成「立刻超时」。
func TestRealityAcceptDeadline_ZeroTimeoutMeansNoDeadline(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起测试 listener: %v", err)
	}
	defer func() { _ = base.Close() }()

	ln := &realityAcceptDeadlineListener{Listener: base, handshakeTimeout: 0}

	go func() {
		c, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			return
		}
		time.Sleep(300 * time.Millisecond)
		_, _ = c.Write([]byte("x"))
		time.Sleep(100 * time.Millisecond)
		_ = c.Close()
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Errorf("超时设为 0(即不限)时读取却失败了: %v", err)
	}
}

// ── 启动路径 ────────────────────────────────────────────────────────────────

// TestStartRealityVPNListener_DisabledWhenAddrEmpty 没配监听地址时应当安静地不启用,
// 而不是报错阻断整个服务启动。
func TestStartRealityVPNListener_DisabledWhenAddrEmpty(t *testing.T) {
	cfg := &config.Config{}
	cfg.Reality.ListenAddr = "   " // 只有空白

	closeFn, startAccept, port, err := startRealityVPNListener(cfg, nil, nil)
	if err != nil {
		t.Fatalf("未配置 REALITY 时不该报错,却得到: %v", err)
	}
	if closeFn != nil || startAccept != nil || port != 0 {
		t.Errorf("未配置 REALITY 时不该返回可用的监听器(closeFn=%v startAccept=%v port=%d)",
			closeFn != nil, startAccept != nil, port)
	}
}

// TestStartRealityVPNListener_RejectsInvalidConfig 配了监听地址但配置不合法时必须**报错**,
// 不能悄悄跳过 —— 否则运维以为 REALITY 开着,实际上客户端一个也连不上。
func TestStartRealityVPNListener_RejectsInvalidConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Reality.ListenAddr = "127.0.0.1:0"
	// 故意不填 dest / private_key / server_names,Validate 应当拒绝。

	closeFn, _, _, err := startRealityVPNListener(cfg, nil, nil)
	if closeFn != nil {
		closeFn()
	}
	if err == nil {
		t.Error("REALITY 配置不完整却启动成功了 —— 运维会以为它在工作,实际客户端全都连不上")
	}
}
