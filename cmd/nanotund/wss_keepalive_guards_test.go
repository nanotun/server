package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// keepalive 这条 goroutine 有两处只在配置写错 / 链路断掉时才走到的分支。
//
// 一是**次毫秒间隔的夹取**。`data_plane_ping_interval = "500us"` 是能通过配置解析的(单位合法),
// 但它意味着每秒两千次写帧,每次都要抢 linkWrMu —— 数据面的写会被这条保活挤住,CPU 也在刷屏。
// 夹到 1ms 只是兜底,真正的现象是「改完一行配置整机负载起飞」,而日志里没有任何错误。
//
// 二是**写失败后退出而不是接着刷**。链路已经断了,保活写只会一次次失败;不退出的话这条 goroutine
// 会以 interval 的频率永远重试下去,而每次重试都要拿 linkWrMu —— 连接清理正好也要这把锁。
// 一条断掉的连接因此变成一个持续占锁的僵尸。

// failingWriter 第一次写就报错,并记录被写了几次。
type failingWriter struct {
	mu     sync.Mutex
	writes int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	f.writes++
	f.mu.Unlock()
	return 0, errors.New("链路已断")
}

func (f *failingWriter) Read([]byte) (int, error) { return 0, errors.New("closed") }
func (f *failingWriter) Close() error             { return nil }

func (f *failingWriter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// TestStartWSSDataPlaneKeepalive_ClampsSubMillisecondIntervals 次毫秒间隔必须被夹住。
func TestStartWSSDataPlaneKeepalive_ClampsSubMillisecondIntervals(t *testing.T) {
	rec := newRWCRecorder()
	c := &Connection{linkConn: rec}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 1ns:漏写单位("data_plane_ping_interval = 1")就是这个值。按字面执行等于 ticker 满速自旋
		// (实测 100ms 里约 75 万拍),每一拍都要抢一次 linkWrMu —— 数据面的写和 CPU 一起被挤住。
		//
		// missThreshold 特意开得极大:判活窗口是 missThreshold × interval,间隔取 ns 级时这个窗口也是
		// ns 级,于是连接会在第 4 个 Ping 就被判成僵尸并 Close —— Ping 数就此与「间隔有没有被夹住」无关,
		// 断言变成空过。把宽限期拉长到本用例内不可能走完,间隔才是唯一变量。
		startWSSDataPlaneKeepalive(ctx, c, rec, "test", time.Nanosecond, 1<<20)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// 夹到 1ms 之后 100ms 内约 100 帧;不夹是几十万帧。门槛取 1000,足够把两者分开又不赌调度精度。
	if n := rec.frameCount(util.LinkTypePing); n > 1000 {
		t.Fatalf("100ms 内发了 %d 个 Ping —— 间隔没被夹到 1ms,次毫秒自旋会把数据面的写和 CPU 一起挤住", n)
	}
}

// TestStartWSSDataPlaneKeepalive_StopsAfterAWriteFails 写失败即退出,不再反复抢锁重试。
func TestStartWSSDataPlaneKeepalive_StopsAfterAWriteFails(t *testing.T) {
	w := &failingWriter{}
	c := &Connection{linkConn: w}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		startWSSDataPlaneKeepalive(ctx, c, w, "test", 10*time.Millisecond, 3)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("写失败之后 keepalive 没退出 —— 它会一直以 interval 的频率重试并抢 linkWrMu,把连接清理堵住")
	}
	if n := w.count(); n != 1 {
		t.Errorf("失败后又写了 %d 次(应只有 1 次)", n)
	}
}

// TestStartWSSDataPlaneKeepalive_GivesTheClientAGraceBeforeDeclaringItDead 起步阶段不许判死。
//
// lastPongAt 初值是 0(从未收到 Pong),而刚启动时本来就还没有 Pong。不给宽限期的话,第一个
// Ping 间隔一到就把一条**完全正常**的新连接判成僵尸并 Close —— 客户端刚连上就被踢,然后重连、
// 再被踢,变成谁也说不清的循环掉线。
func TestStartWSSDataPlaneKeepalive_GivesTheClientAGraceBeforeDeclaringItDead(t *testing.T) {
	rec := newRWCRecorder()
	c := &Connection{linkConn: rec}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go startWSSDataPlaneKeepalive(ctx, c, rec, "test", 20*time.Millisecond, 3)

	// 宽限期是 missThreshold 个 Ping。取两个间隔:此时已发过 Ping,但还不该判死。
	time.Sleep(50 * time.Millisecond)
	if rec.closed.Load() {
		t.Fatal("宽限期内就把连接判成僵尸关掉了 —— 新连接刚连上即被踢,客户端会陷入重连即掉线的循环")
	}
	if rec.frameCount(util.LinkTypePing) == 0 {
		t.Fatal("宽限期内一个 Ping 都没发 —— 保活根本没在跑")
	}
}
