package main

import (
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// Upgrade 成功之后这个 handler 还要做一件容易被忽略的事:把 accept 时设的**握手超时**撤掉。
//
// 那个 deadline 是给「连上来却迟迟不发握手」的慢连接用的(handshakeDeadlineListener)。可它是设在
// 底层 conn 上的绝对时间,Upgrade 之后并不会自动消失 —— 不撤的话,一条完全正常的数据面长连接会在
// 握手超时那一刻(默认十几秒)突然读失败断开。客户端看到的是「连上就用,十几秒后必掉线」,而服务端
// 日志里只有一条普通的读错误;更难的是它跟流量无关,复现起来像是网络问题。
//
// 这里用一个记录 deadline 的假 listener 观察:Upgrade 完成后必须出现一次「清零」的 SetDeadline。

// deadlineRecordingListener 把 Accept 出来的连接包一层,记录所有 SetDeadline 调用。
type deadlineRecordingListener struct {
	net.Listener
	mu      sync.Mutex
	set     []time.Time
	initial time.Duration
}

func (l *deadlineRecordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// 模拟 handshakeDeadlineListener:accept 即给一个握手期截止时间。
	_ = c.SetDeadline(time.Now().Add(l.initial))
	return &handshakeDeadlineProbeConn{Conn: c, owner: l}, nil
}

func (l *deadlineRecordingListener) record(t time.Time) {
	l.mu.Lock()
	l.set = append(l.set, t)
	l.mu.Unlock()
}

// sawCleared 有没有出现过「无截止时间」。
//
// 单看这一条不足以钉住 handler 那行:net/http 的 connReader 与 gorilla 的 Upgrade 各自也会清一次。
// 所以配一条 noLongLivedDeadline 一起用 —— 两条合起来才是那行代码的效果:清掉,而且不是换成一个
// 长效的绝对时间。也不能改成看「最后一次是不是零」:Upgrade 之后 dispatchVPNIncoming 立刻会为登录
// 握手设自己的短超时,谁最后落笔取决于调度。
func (l *deadlineRecordingListener) sawCleared() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, t := range l.set {
		if t.IsZero() {
			return true
		}
	}
	return false
}

// noLongLivedDeadline 确认没人给这条连接留下长效的绝对截止时间。
//
// 数据面之后的所有截止时间都是「握手/读写级」的秒量级;留下一个几十分钟后到期的绝对时间,
// 表面上一切正常,直到那一刻整条连接突然读失败 —— 而那时早已看不出跟握手期有任何关系。
func (l *deadlineRecordingListener) noLongLivedDeadline() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, t := range l.set {
		if !t.IsZero() && time.Until(t) > time.Minute {
			return t, false
		}
	}
	return time.Time{}, true
}

type handshakeDeadlineProbeConn struct {
	net.Conn
	owner *deadlineRecordingListener
}

// 只观察逐向的 SetReadDeadline。合并的 SetDeadline 不算:net/http 在 Hijack 时、gorilla 在 Upgrade
// 收尾时都会各自用它清一次,把那两次算进来的话,handler 里撤不撤都是绿的。写侧也不算:gorilla 把写
// 截止时间存在自己手里,要等真正下行写的时候才落到 conn 上,而这条用例里服务端还在等登录帧。
func (c *handshakeDeadlineProbeConn) SetReadDeadline(t time.Time) error {
	c.owner.record(t)
	return c.Conn.SetReadDeadline(t)
}

// TestVPNWSHandler_ClearsTheHandshakeDeadlineAfterUpgrade Upgrade 之后握手超时必须被撤掉。
func TestVPNWSHandler_ClearsTheHandshakeDeadlineAfterUpgrade(t *testing.T) {
	resetServerGlobals(t)
	withTestGlobalContext(t)

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &deadlineRecordingListener{Listener: base, initial: 15 * time.Second}

	errCh := make(chan error, 1)
	cleanup := startVPNHTTPServer(ln, "/tunnel", newMagicDNSGateway(t), false, nil, errCh)
	defer cleanup()

	wsURL := "ws://" + base.Addr().String() + "/tunnel"
	conn, err := util.DialVPNWebSocket(wsURL, 3*time.Second, nil)
	if err != nil {
		t.Fatalf("拨 WSS: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	cleared := false
	for time.Now().Before(deadline) && !cleared {
		cleared = ln.sawCleared()
		if !cleared {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !cleared {
		t.Fatal("Upgrade 之后没把握手超时清零 —— 一条正常的数据面长连接会在十几秒后突然读失败断开," +
			"客户端表现为「连上就用、十几秒必掉线」,而服务端日志里只有一条普通读错误")
	}
	if bad, ok := ln.noLongLivedDeadline(); !ok {
		t.Fatalf("这条连接被留下了一个 %v 之后到期的绝对截止时间 —— 到那一刻整条隧道会突然读失败,"+
			"而现场已经看不出跟握手期有任何关系", time.Until(bad).Round(time.Second))
	}
}

// TestVPNWSHandler_RefusesPlainHTTPWithoutSpendingAConnectionSlot 非 Upgrade 请求直接 426。
//
// 这条路径每天都被扫描器走到。回错状态码不是体面问题:426 让对端立刻走,而任何「先当成 WS 处理再失败」
// 的写法都会白占一个 per-connection goroutine 与一次 accept 槽位。
func TestVPNWSHandler_RefusesPlainHTTPWithoutSpendingAConnectionSlot(t *testing.T) {
	srv := httptest.NewServer(buildVPNHTTPServeMux("/tunnel", nil, false, nil))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/tunnel")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 426 {
		t.Fatalf("普通 GET 得到 %d,want 426 Upgrade Required", resp.StatusCode)
	}

	// 其它路径一律 404:数据面 listener 上不该出现任何可探测的端点(/health 已挪到独立 listener)。
	for _, p := range []string{"/", "/health", "/tunnel/x"} {
		r, err := srv.Client().Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != 404 {
			t.Errorf("%s 返回 %d,want 404 —— 数据面 listener 上多一个可探测端点就多一份指纹", p, r.StatusCode)
		}
	}
}

// TestStartVPNHTTPServer_CleanupIsIdempotentAndReportsServeExit cleanup 可重复调用,Serve 退出要上报。
//
// Serve 的返回值经 errCh 交给 main 决定是否整机退出。吞掉它的后果是 listener 已经死了(端口被抢、
// fd 耗尽)而进程照常活着 —— 监控看到进程在跑,客户端却一个都连不上。
func TestStartVPNHTTPServer_CleanupIsIdempotentAndReportsServeExit(t *testing.T) {
	resetServerGlobals(t)
	withTestGlobalContext(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	cleanup := startVPNHTTPServer(ln, "/tunnel", nil, false, nil, errCh)

	cleanup()
	cleanup() // 重复调用必须安全:shutdown 路径上它可能被 defer 与显式调用各走一次

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "closed") {
			t.Logf("Serve 退出原因: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve 退出后没往 errCh 上报 —— listener 已死而进程照常活着,客户端一个都连不上而监控显示正常")
	}
}
