package main

import (
	"context"
	"io"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// rateLimitedConn 是**每一个**字节的必经之路:登录、接管、TunChan demux、shutdown drain 全走它。
// 因此这里有两类容易静默出错的东西。
//
// 一是流量计数。它是「客户端上传/下载」的唯一读数,admin 用它对账、排查限速是否生效。
// io 协议允许 Read 返回 (n>0, err)(关闭那一帧通常是 (n>0, io.EOF)),漏掉这一帧的现象是
// 统计悄悄少算 —— 单连接看不出来,高频短连接(smux 子流、PoW、keepalive)累积起来就把读数拉歪了,
// 而没人会怀疑一个「一直在涨」的计数器。
//
// 二是限速等待的取消。WaitN 是在持有 linkWrMu 的情况下阻塞的,取消源必须是 per-tunnel 的 ctx,
// 否则 kick / 接管 / supersede 想逼停一条被限速卡住的连接时会拿不到锁,teardown 卡在那儿直到
// token 攒够 —— 低速限制下这可能是几十秒。

// scriptedRWC 按脚本返回 Read 结果,并记录 Write 的调用。
type scriptedRWC struct {
	reads []struct {
		data []byte
		err  error
	}
	writeN   int
	writeErr error
}

func (s *scriptedRWC) Read(p []byte) (int, error) {
	if len(s.reads) == 0 {
		return 0, io.EOF
	}
	r := s.reads[0]
	s.reads = s.reads[1:]
	n := copy(p, r.data)
	return n, r.err
}

func (s *scriptedRWC) Write(p []byte) (int, error) {
	if s.writeN > 0 || s.writeErr != nil {
		return s.writeN, s.writeErr
	}
	return len(p), nil
}

func (s *scriptedRWC) Close() error { return nil }

// TestRateLimitedConnRead_CountsTheBytesEvenOnTheClosingFrame 带 err 的那一帧字节也要计入。
func TestRateLimitedConnRead_CountsTheBytesEvenOnTheClosingFrame(t *testing.T) {
	inner := &scriptedRWC{reads: []struct {
		data []byte
		err  error
	}{
		{data: make([]byte, 700), err: io.EOF}, // 关闭那一帧:已读 700 字节 + EOF
		{data: nil, err: io.EOF},               // 纯 EOF:一个字节都没有
	}}
	c := newRateLimitedConn(inner, nil, nil, context.Background())

	before := vpnBytesUp.Load()
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if n != 700 || err != io.EOF {
		t.Fatalf("Read = (%d, %v),want (700, EOF)", n, err)
	}
	if got := vpnBytesUp.Load() - before; got != 700 {
		t.Fatalf("上行计数只加了 %d 字节 —— 连接关闭那一帧的流量被漏掉了,高频短连接场景累计会把读数拉歪", got)
	}

	// 纯 EOF(n==0)不该动计数。
	mid := vpnBytesUp.Load()
	if n, _ := c.Read(buf); n != 0 {
		t.Fatalf("第二次 Read 返回了 %d 字节", n)
	}
	if vpnBytesUp.Load() != mid {
		t.Error("n==0 的那一帧也加了计数 —— 空读会把读数虚高")
	}
}

// TestRateLimitedConnWrite_CountsPartialWrites 部分写的字节确实已经发出去了,必须计入。
func TestRateLimitedConnWrite_CountsPartialWrites(t *testing.T) {
	inner := &scriptedRWC{writeN: 300, writeErr: io.ErrShortWrite}
	c := newRateLimitedConn(inner, nil, nil, context.Background())

	before := vpnBytesDown.Load()
	n, err := c.Write(make([]byte, 1000))
	if n != 300 || err == nil {
		t.Fatalf("Write = (%d, %v),want (300, err)", n, err)
	}
	if got := vpnBytesDown.Load() - before; got != 300 {
		t.Fatalf("下行计数加了 %d,want 300 —— 部分写的真实出流量被漏掉", got)
	}
}

// TestRateLimitedConn_NilCtxDoesNotPanic 桩连接可能不带 ctx,限速等待不能因此掀翻数据面。
func TestRateLimitedConn_NilCtxDoesNotPanic(t *testing.T) {
	c := newRateLimitedConn(&scriptedRWC{
		reads: []struct {
			data []byte
			err  error
		}{{data: make([]byte, 16)}},
	}, rate.NewLimiter(rate.Inf, 1024), rate.NewLimiter(rate.Inf, 1024), nil)

	if _, err := c.Read(make([]byte, 64)); err != nil {
		t.Fatalf("nil ctx 下 Read 出错: %v", err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("nil ctx 下 Write 出错: %v", err)
	}
}

// TestRateLimitedConnRead_SkipsTheTokenWaitOnTheClosingFrame 关闭那一帧不该再去等令牌。
//
// 这一帧之后不会再有 Read,等 token 纯属浪费 —— 而在低速限制下它会让连接清理白白多挂几秒,
// 期间 linkWrMu 仍被攥着。字节要算(上一条用例钉住),但 token 不该等。
func TestRateLimitedConnRead_SkipsTheTokenWaitOnTheClosingFrame(t *testing.T) {
	// 1 B/s、桶容量 2048:桶初始是满的,所以第一帧不用等;它把桶抽干之后,第二帧若真去等就要等几百秒。
	// (桶容量必须 ≥ 单帧字节数 —— 否则 WaitN 会以「超过 burst」立即报错,等待根本不会发生,
	// 这条断言也就观测不到任何东西。)
	slow := rate.NewLimiter(1, 2048)
	inner := &scriptedRWC{reads: []struct {
		data []byte
		err  error
	}{
		{data: make([]byte, 1500)},             // 正常帧:抽干桶
		{data: make([]byte, 900), err: io.EOF}, // 关闭帧:不该再等
	}}
	c := newRateLimitedConn(inner, slow, nil, context.Background())

	if _, err := c.Read(make([]byte, 1500)); err != nil {
		t.Fatalf("第一帧出错: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Read(make([]byte, 1500))
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("带 EOF 的那一帧仍去等限速令牌 —— 连接清理会被限速拖住,期间 linkWrMu 一直被占")
	}
}
