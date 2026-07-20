package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// shutdownTestConn 是只支持 Write 的最小 io.ReadWriteCloser,
// 用于断言 broadcastShutdownClose 写出的字节流是不是预期 LinkTypeClose 帧。
//
// 不直接走 net.Pipe / WSS:那两条都得起 goroutine 读,反过来又要做 race 同步,
// 让单测复杂度起来,失去「快速覆盖广播路径」的初衷。
type shutdownTestConn struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed atomic.Bool
	// writeBlock 如果 > 0,Write 会先 sleep 这么久,模拟「慢客户端」,
	// 用于验证 SetWriteDeadline / 并发广播分支。
	writeBlock time.Duration
	// failWith 如果非 nil,Write 立刻返回此错误,验证 fail 计数。
	failWith error
}

func (c *shutdownTestConn) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (c *shutdownTestConn) Write(p []byte) (int, error) {
	if c.failWith != nil {
		return 0, c.failWith
	}
	if c.writeBlock > 0 {
		time.Sleep(c.writeBlock)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *shutdownTestConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *shutdownTestConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, c.buf.Len())
	copy(out, c.buf.Bytes())
	return out
}

// withConnIDMap 在测试持续期间替换全局 connIDMap,测试结束自动还原。
// 必要的隔离手段:本包的 broadcastShutdownClose 直接读全局表,
// 单测必须独占,否则并行 go test -count=n 会污染状态。
func withConnIDMap(t *testing.T, conns map[string]*Connection) {
	t.Helper()
	connIDMapMu.Lock()
	saved := connIDMap
	connIDMap = conns
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		connIDMap = saved
		connIDMapMu.Unlock()
	})
}

func makeShutdownTestConn(id string, conn io.ReadWriteCloser) *Connection {
	return &Connection{
		connIDStr: id,
		linkConn:  conn,
	}
}

func TestBroadcastShutdownClose_NoConns(t *testing.T) {
	withConnIDMap(t, map[string]*Connection{})
	start := time.Now()
	broadcastShutdownClose(0)
	if dt := time.Since(start); dt > 200*time.Millisecond {
		t.Fatalf("无 conn 时早退,但耗时 %v 过长(疑似进了 drain sleep)", dt)
	}
}

func TestBroadcastShutdownClose_NilLinkConnSkipped(t *testing.T) {
	c := &Connection{connIDStr: "nil-link"}
	withConnIDMap(t, map[string]*Connection{c.connIDStr: c})
	broadcastShutdownClose(0)
}

func TestBroadcastShutdownClose_WritesCloseFrame(t *testing.T) {
	tc := &shutdownTestConn{}
	c := makeShutdownTestConn("c-1", tc)
	withConnIDMap(t, map[string]*Connection{c.connIDStr: c})

	broadcastShutdownClose(0)

	data := tc.Bytes()
	if len(data) == 0 {
		t.Fatal("期望写出 LinkTypeClose 帧,实际空")
	}
	typ, payload, err := util.ReadLinkFrame(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("解析帧失败: %v", err)
	}
	if typ != util.LinkTypeClose {
		t.Fatalf("帧类型 = %d, 期望 LinkTypeClose(%d)", typ, util.LinkTypeClose)
	}
	msg, err := util.ParseCloseLinkPayload(payload)
	if err != nil {
		t.Fatalf("解析 CloseMsg 失败: %v", err)
	}
	if msg.Code != CloseCodeShutdown {
		t.Fatalf("CloseMsg.Code = %d, 期望 %d", msg.Code, CloseCodeShutdown)
	}
	if msg.Reason != ShutdownReason {
		t.Fatalf("CloseMsg.Reason = %q, 期望 %q", msg.Reason, ShutdownReason)
	}
}

func TestBroadcastShutdownClose_ConcurrentMany(t *testing.T) {
	// 50 个 conn 并发广播,断言总耗时远小于「单条 writeBlock × 50」
	// (验证 `go safeGoroutine` 真的拿到了并发,而不是顺序跑)。
	const n = 50
	const perWriteBlock = 30 * time.Millisecond
	conns := make(map[string]*Connection, n)
	tcs := make([]*shutdownTestConn, 0, n)
	for i := 0; i < n; i++ {
		tc := &shutdownTestConn{writeBlock: perWriteBlock}
		tcs = append(tcs, tc)
		id := "c-" + strconv.Itoa(i)
		conns[id] = makeShutdownTestConn(id, tc)
	}
	withConnIDMap(t, conns)

	start := time.Now()
	broadcastShutdownClose(0)
	elapsed := time.Since(start)

	for i, tc := range tcs {
		if len(tc.Bytes()) == 0 {
			t.Fatalf("conn[%d] 没收到 Close 帧", i)
		}
	}
	// 串行下界 ~ n * perWriteBlock = 1.5s;并发下应 < 500ms(本机 CPU + go scheduler 抖动留余量)
	if elapsed >= time.Duration(n)*perWriteBlock/2 {
		t.Fatalf("broadcastShutdownClose 看起来没并发(耗时 %v,期望 < %v),检查 `go safeGoroutine` 关键字",
			elapsed, time.Duration(n)*perWriteBlock/2)
	}
}

func TestBroadcastShutdownClose_DrainTimeoutSleeps(t *testing.T) {
	tc := &shutdownTestConn{}
	c := makeShutdownTestConn("c-1", tc)
	withConnIDMap(t, map[string]*Connection{c.connIDStr: c})

	const drain = 150 * time.Millisecond
	start := time.Now()
	broadcastShutdownClose(drain)
	elapsed := time.Since(start)
	if elapsed < drain {
		t.Fatalf("drainTimeout=%v 时实际仅等 %v(疑似 Sleep 被跳过)", drain, elapsed)
	}
}

func TestBroadcastShutdownClose_WriteErrorCounted(t *testing.T) {
	// failWith 触发 Write 立刻 fail,验证不 panic、不阻塞、广播能继续跑完
	tc := &shutdownTestConn{failWith: errors.New("simulated write error")}
	c := makeShutdownTestConn("c-fail", tc)
	withConnIDMap(t, map[string]*Connection{c.connIDStr: c})

	done := make(chan struct{})
	go func() {
		broadcastShutdownClose(0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("写 Close 帧失败时广播被卡住")
	}
}

// 验证持 linkWrMu 时与并发 kick 路径互斥,不会出现两条 goroutine 同时写同一 linkConn。
// 这条用真实 net.Pipe + ReadLinkFrame 反向校验帧完整性。
func TestBroadcastShutdownClose_LinkWrMuSerialized(t *testing.T) {
	srv, cli := net.Pipe()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = cli.Close()
	})

	c := &Connection{
		connIDStr: "c-pipe",
		linkConn:  srv,
	}
	withConnIDMap(t, map[string]*Connection{c.connIDStr: c})

	// 客户端读侧:必须有 reader 否则 net.Pipe 是 synchronous 的,写会永远阻塞。
	frameTyp := make(chan byte, 1)
	go func() {
		typ, _, err := util.ReadLinkFrame(cli)
		if err != nil {
			frameTyp <- 0
			return
		}
		frameTyp <- typ
	}()

	// 同时启动一个 mock kick(也持 linkWrMu),验证两者串行化无 panic / 无 race。
	var wg sync.WaitGroup
	wg.Add(1)
	go safeGoroutine("mockKick", func() {
		defer wg.Done()
		c.linkWrMu.Lock()
		defer c.linkWrMu.Unlock()
		time.Sleep(20 * time.Millisecond) // 模拟 kick 写帧的耗时
	})

	broadcastShutdownClose(0)
	wg.Wait()

	select {
	case typ := <-frameTyp:
		if typ != util.LinkTypeClose {
			t.Fatalf("客户端读到帧类型 = %d, 期望 LinkTypeClose", typ)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("客户端未读到 Close 帧(可能被 mockKick 锁卡死)")
	}
}
