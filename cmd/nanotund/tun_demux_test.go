package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// blockingDeadlinerWriter 是给 tunDemuxToLink 单测的 io.Writer:
//   - 每次 Write 阻塞在 released 信号上(模拟慢客户端 / 阻塞 socket)
//   - SetWriteDeadline 被设到「过去时间」时**立即**唤醒 in-flight Write 返回 timeout 错(模拟内核 EAGAIN)
//   - 满足 deadliner 接口,触发 tunDemuxToLink 走 deadline 分支
//
// 设计要点:用 abortCh(每次 Write 重新拿一个)让 SetWriteDeadline 可以异步唤醒;
// 闭包式 channel 而非 sync.Cond 让测试代码足够直观。
type blockingDeadlinerWriter struct {
	mu          sync.Mutex
	deadlineSet []time.Time
	writes      int
	released    chan struct{}
	abortCh     chan struct{}
}

func newBlockingDeadlinerWriter() *blockingDeadlinerWriter {
	return &blockingDeadlinerWriter{
		released: make(chan struct{}),
		abortCh:  make(chan struct{}),
	}
}

func (w *blockingDeadlinerWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.writes++
	abortCh := w.abortCh
	w.mu.Unlock()
	select {
	case <-w.released:
		return len(p), nil
	case <-abortCh:
		return 0, errors.New("blockingDeadlinerWriter: i/o timeout (deadline)")
	case <-time.After(2 * time.Second):
		return 0, errors.New("blockingDeadlinerWriter: test timeout (released never fired)")
	}
}

func (w *blockingDeadlinerWriter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.deadlineSet = append(w.deadlineSet, t)
	// 过去时间 + non-zero → 模拟内核「deadline 已过」语义,唤醒任何 in-flight Write。
	// 设置成新的 channel(让下次 Write 重新拿一个未关闭的),与 net.Conn.SetWriteDeadline
	// 「立即生效到 in-flight + 后续 write 默认无超时」的行为对齐。
	if !t.IsZero() && t.Before(time.Now()) {
		close(w.abortCh)
		w.abortCh = make(chan struct{})
	}
	w.mu.Unlock()
	return nil
}

func (w *blockingDeadlinerWriter) deadlineCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.deadlineSet)
}

// C3 单测 a:正常路径 — tunDemuxToLink 每次 WriteLinkFrame 前后都设置 SetWriteDeadline。
//
// 验证手段:发一个包,等 demux goroutine 调 Write 阻塞;立刻 release;验证至少 2 次
// SetWriteDeadline 调用(set future + clear to zero)且参数模式正确。
func TestTunDemuxToLink_SetsDeadlinePerWrite(t *testing.T) {
	w := newBlockingDeadlinerWriter()
	ch := make(chan *util.TunPacket, 1)
	mu := &sync.Mutex{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		tunDemuxToLink(ch, w, mu, ctx)
	}()

	pkt := &util.TunPacket{Buf: []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}, N: 20}
	ch <- pkt
	time.Sleep(50 * time.Millisecond)
	close(w.released)

	close(ch)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("tunDemuxToLink 未退出")
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writes < 1 {
		t.Fatalf("Write 未被调用")
	}
	if len(w.deadlineSet) < 2 {
		t.Fatalf("SetWriteDeadline 至少调用 2 次(set future + clear),got %d", len(w.deadlineSet))
	}
	if w.deadlineSet[0].IsZero() {
		t.Errorf("第一次 SetWriteDeadline 应为 future 时间,got zero")
	}
	cleared := false
	for _, d := range w.deadlineSet[1:] {
		if d.IsZero() {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Errorf("没有看到清零 SetWriteDeadline(time.Time{}) 的调用,deadlineSet=%v", w.deadlineSet)
	}
}

// C3 单测 b:ctx 中断 — tunDemuxToLink 卡在 Write 内时,cancel(ctx) 应该立刻让
// watchdog 把 deadline 推到过去 → 写返回 timeout → goroutine 退出。
//
// 通过测试:取消后 1 秒内 demux goroutine 退出。tunDemuxWriteDeadline=5s,所以若 watchdog
// 不生效,这个测试会 1 秒超时失败。
func TestTunDemuxToLink_CtxCancelInterruptsStuckWrite(t *testing.T) {
	w := newBlockingDeadlinerWriter()
	ch := make(chan *util.TunPacket, 1)
	mu := &sync.Mutex{}
	ctx, cancel := context.WithCancel(context.Background())

	exited := atomic.Int32{}
	go func() {
		tunDemuxToLink(ch, w, mu, ctx)
		exited.Store(1)
	}()

	pkt := &util.TunPacket{Buf: []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}, N: 20}
	ch <- pkt
	time.Sleep(50 * time.Millisecond)

	cancel()

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if exited.Load() == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("tunDemuxToLink 在 1s 内未退出(watchdog 没把 in-flight write 拍醒),deadlineSet=%d", w.deadlineCount())
}

// C3 单测 c:不支持 SetWriteDeadline 的 writer(向后兼容) — 不应 panic,
// 且 ctx.Done 仍然能让 demux 退出(只是 in-flight write 没法被打断,要等自然返回)。
type plainBlockingWriter struct {
	released chan struct{}
}

func (p *plainBlockingWriter) Write(b []byte) (int, error) {
	select {
	case <-p.released:
		return len(b), nil
	case <-time.After(2 * time.Second):
		return 0, errors.New("test timeout")
	}
}

func TestTunDemuxToLink_NoDeadlineSupport_StillExitsOnCtx(t *testing.T) {
	w := &plainBlockingWriter{released: make(chan struct{})}
	ch := make(chan *util.TunPacket, 1)
	mu := &sync.Mutex{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		tunDemuxToLink(ch, w, mu, ctx)
	}()

	cancel()
	close(w.released)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("plainBlockingWriter 路径下 tunDemuxToLink 未退出")
	}
}

// C3 单测 d:rateLimitedConn.SetWriteDeadline 应透传到 inner;
// inner 不实现时静默返回 nil(不报错,让上层 type assertion 仍可成功)。
type recordingDeadlinerInner struct {
	deadlines []time.Time
}

func (r *recordingDeadlinerInner) Read(p []byte) (int, error)  { return 0, nil }
func (r *recordingDeadlinerInner) Write(p []byte) (int, error) { return len(p), nil }
func (r *recordingDeadlinerInner) Close() error                { return nil }
func (r *recordingDeadlinerInner) SetWriteDeadline(t time.Time) error {
	r.deadlines = append(r.deadlines, t)
	return nil
}

type plainInner struct{}

func (p *plainInner) Read(b []byte) (int, error)  { return 0, nil }
func (p *plainInner) Write(b []byte) (int, error) { return len(b), nil }
func (p *plainInner) Close() error                { return nil }

func TestRateLimitedConn_SetWriteDeadline_Delegation(t *testing.T) {
	rec := &recordingDeadlinerInner{}
	c := newRateLimitedConn(rec, nil, nil, context.Background())
	d := time.Now().Add(time.Second)
	if err := c.SetWriteDeadline(d); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if len(rec.deadlines) != 1 || !rec.deadlines[0].Equal(d) {
		t.Fatalf("inner 未透传 deadline,got %v", rec.deadlines)
	}

	c2 := newRateLimitedConn(&plainInner{}, nil, nil, context.Background())
	if err := c2.SetWriteDeadline(d); err != nil {
		t.Fatalf("plainInner 路径不应报错,got %v", err)
	}
}
