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

// readWriteCloseRecorder 是 startWSSDataPlaneKeepalive 测试用的写收集器:
//   - 实现 io.Writer + io.Closer + deadliner;
//   - Write 把 frame 解析(LinkType + payload)写入 frames 列表;
//   - Close() 通过 closeNotify 通道告知测试主线程「服务端调用 Close → 判定僵尸连接」。
type readWriteCloseRecorder struct {
	mu          sync.Mutex
	frames      []recordedFrame
	closed      atomic.Bool
	closeNotify chan struct{}
	deadlines   []time.Time
}

type recordedFrame struct {
	typ uint8
	buf []byte
}

func newRWCRecorder() *readWriteCloseRecorder {
	return &readWriteCloseRecorder{closeNotify: make(chan struct{}, 1)}
}

func (r *readWriteCloseRecorder) Read(p []byte) (int, error) {
	// 阻塞直到 Close;keepalive sender 不会用 Read,只是接口要求。
	<-r.closeNotify
	return 0, errors.New("rwcRecorder Read: closed")
}

func (r *readWriteCloseRecorder) Write(p []byte) (int, error) {
	// 与 util.WriteLinkFrame 拼帧格式对齐:2B 大端长度 + 1B type + payload
	if len(p) < 3 {
		return 0, errors.New("frame too short")
	}
	typ := p[2]
	body := append([]byte(nil), p[3:]...)
	r.mu.Lock()
	r.frames = append(r.frames, recordedFrame{typ: typ, buf: body})
	r.mu.Unlock()
	return len(p), nil
}

func (r *readWriteCloseRecorder) Close() error {
	if r.closed.CompareAndSwap(false, true) {
		select {
		case r.closeNotify <- struct{}{}:
		default:
		}
	}
	return nil
}

func (r *readWriteCloseRecorder) SetWriteDeadline(t time.Time) error {
	r.mu.Lock()
	r.deadlines = append(r.deadlines, t)
	r.mu.Unlock()
	return nil
}

func (r *readWriteCloseRecorder) frameCount(typ uint8) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, f := range r.frames {
		if f.typ == typ {
			n++
		}
	}
	return n
}

// G_wss_ping 单测 a:interval=0 时立即返回,不发任何 Ping。
func TestStartWSSDataPlaneKeepalive_Disabled(t *testing.T) {
	rec := newRWCRecorder()
	c := &Connection{linkConn: rec}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		startWSSDataPlaneKeepalive(ctx, c, rec, "test", 0, 3)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("interval=0 应立即返回")
	}
	if rec.frameCount(util.LinkTypePing) != 0 {
		t.Fatalf("不应发 Ping,got %d", rec.frameCount(util.LinkTypePing))
	}
}

// G_wss_ping 单测 b:启用后周期性发 Ping,客户端及时回 Pong → 不 Close。
// 测试中用一个 50ms interval + 模拟「实时 Pong」:每 frame 写入 frames 后立刻
// 在 lastPongAtNano 上 store now,模拟客户端及时响应。
func TestStartWSSDataPlaneKeepalive_HealthyLink_NoClose(t *testing.T) {
	rec := newRWCRecorder()
	c := &Connection{linkConn: rec}
	ctx, cancel := context.WithCancel(context.Background())

	// 持续在后台 store lastPongAtNano,模拟客户端不停回 Pong
	stopPongSim := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				c.lastPongAtNano.Store(time.Now().UnixNano())
			case <-stopPongSim:
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		startWSSDataPlaneKeepalive(ctx, c, rec, "test", 50*time.Millisecond, 3)
		close(done)
	}()

	time.Sleep(400 * time.Millisecond)
	cancel()
	<-done
	close(stopPongSim)

	if rec.closed.Load() {
		t.Fatalf("及时 Pong 不应触发 Close")
	}
	if pingCount := rec.frameCount(util.LinkTypePing); pingCount < 4 {
		t.Fatalf("400ms / 50ms interval 应至少发 4 个 Ping,got %d", pingCount)
	}
}

// G_wss_ping 单测 c:启用后客户端从不回 Pong → grace 内不 Close,grace 后 Close 触发。
// grace = missThreshold * interval = 3 * 30ms = 90ms;500ms 内必然触发 Close。
func TestStartWSSDataPlaneKeepalive_NoPong_ClosesLink(t *testing.T) {
	rec := newRWCRecorder()
	c := &Connection{linkConn: rec}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		startWSSDataPlaneKeepalive(ctx, c, rec, "test", 30*time.Millisecond, 3)
		close(done)
	}()

	select {
	case <-rec.closeNotify:
	case <-time.After(1 * time.Second):
		cancel()
		<-done
		t.Fatalf("1s 内未触发 Close;ping 次数 %d", rec.frameCount(util.LinkTypePing))
	}
	cancel()
	<-done
}

// G_wss_ping 单测 d:客户端启动后短暂回过 Pong,然后停止回 → 也会 Close。
// 检验「曾经 Pong 过但又停了」分支(now - lastPongAt > missWindow)。
func TestStartWSSDataPlaneKeepalive_PongThenStops_ClosesLink(t *testing.T) {
	rec := newRWCRecorder()
	c := &Connection{linkConn: rec}
	c.lastPongAtNano.Store(time.Now().UnixNano()) // 起点先盖一个 fresh Pong

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		startWSSDataPlaneKeepalive(ctx, c, rec, "test", 30*time.Millisecond, 3)
		close(done)
	}()

	select {
	case <-rec.closeNotify:
	case <-time.After(1 * time.Second):
		cancel()
		<-done
		t.Fatalf("Pong 停止后 1s 内未触发 Close;ping=%d", rec.frameCount(util.LinkTypePing))
	}
	cancel()
	<-done
}
