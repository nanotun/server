package main

// 三处边界:DNS 错误帧的成帧、承载识别期超时设置失败、关机窗口里的 NAT66 补装。

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/util"
)

// TestWriteMagicDNSStatus_NeverWritesAMalformedFrame
// 错误帧要么是一份能解开的应答,要么压根不写 —— 不能给出半截字节。
//
// 客户端收到一帧解不开的 DNS 应答,stub resolver 的处理是等到超时再重试:同一个名字每次都要多等
// 一整个超时窗口,而 server 侧看不到任何异常;而压根不写会让客户端立刻转下一个 DNS。
//
// 钉的是**结果**不是分支:实测拿 Length 撒谎的 Name 也能拼出合法应答(builder 自己兜住了),所以
// buildMagicDNSStatusBytes 里那条 `raw == nil` 的兜底目前进程内无从触发 —— 那两条语句留在缺口表里,
// 原因就是这个,不是没人写用例。
func TestWriteMagicDNSStatus_NeverWritesAMalformedFrame(t *testing.T) {
	bad := dnsmessage.Question{
		Name:  dnsmessage.Name{Length: 200},
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	if raw := buildMagicDNSStatusBytes(0x1234, dnsmessage.RCodeNameError, bad); raw != nil {
		// 拼得出来也可以 —— 但拼出来的东西必须是能解开的合法应答。
		var m dnsmessage.Message
		if err := m.Unpack(raw); err != nil {
			t.Errorf("给出了一帧解不开的应答(%d 字节): %v —— 客户端只能等到超时再重试", len(raw), err)
		}
		return
	}
	// 构不出来时,写函数必须把失败往上报,而不是静默当作已作答。
	if err := writeMagicDNSStatus(nil, nil, 0x1234, dnsmessage.RCodeNameError, nil, bad); err == nil {
		t.Error("构不出错误帧却报告成功 —— 调用方会以为已经答复,客户端那侧只能干等超时")
	}
}

// noDeadlineConn 的 SetReadDeadline 恒失败,模拟不支持 deadline 的底层 conn
// (自定义 net.Conn 实现、某些代理/包装层)。其余行为透传。
type noDeadlineConn struct {
	net.Conn
}

func (noDeadlineConn) SetReadDeadline(time.Time) error {
	return errors.New("该 conn 不支持 read deadline")
}

// TestDispatchVPNIncoming_KeepsGoingWhenThePeekDeadlineCannotBeSet
// 识别期读超时设不上时只能记一笔然后继续,不能因此拒掉连接。
//
// 那道 deadline 是防「连上不发字节白占 goroutine」的,属于加固;而底层 conn 不支持 deadline
// 是它自己的事。因为设不上就断开的话,这类客户端一个都连不进来,而日志里只有一条 Debug ——
// 排查会从协议开始怀疑,离真正的原因很远。
func TestDispatchVPNIncoming_KeepsGoingWhenThePeekDeadlineCannotBeSet(t *testing.T) {
	env := newLoginGateEnv(t)
	server, client := dialLoopbackTCP(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		dispatchVPNIncoming(noDeadlineConn{Conn: server}, env.gw, true, smux.DefaultConfig())
	}()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		<-done
	})

	if err := writeLinkFrameWithDeadline(client, util.LinkTypePoWChallengeReq, nil, 5*time.Second); err != nil {
		t.Fatalf("写 PoWChallengeReq: %v", err)
	}
	typ, _, err := readLinkFrameWithDeadline(client, 10*time.Second)
	if err != nil {
		t.Fatalf("设不上识别期 deadline 就把连接断了: %v —— 不支持 deadline 的底层 conn 会全体登不进来", err)
	}
	if typ != util.LinkTypePoWChallenge {
		t.Fatalf("首帧 typ=%d,期望 PoWChallenge(%d)", typ, util.LinkTypePoWChallenge)
	}
}

// TestStartServerV6EgressProbe_DoesNotInstallNAT66WhileShuttingDown
// 关机进行中即便探明有 v6 也不许再补装 NAT66。
//
// 补装与优雅关停里的 teardown sweep 是两个方向:sweep 已经在清规则了,补装再把 MASQUERADE 加回去,
// 进程一走规则就留在机器上 —— 下次启动前那段 v6 出网一直被一条指向不存在实例的 NAT 规则接管。
// (在途的安装打断不了,所以这道闸只能设在「开始装之前」。)
func TestStartServerV6EgressProbe_DoesNotInstallNAT66WhileShuttingDown(t *testing.T) {
	var installs atomic.Int32
	t.Cleanup(func() { armV6SetupRetry(nil) })
	armV6SetupRetry(func() bool { installs.Add(1); return true })

	stop := make(chan struct{})
	probed := make(chan struct{})
	oldFn, oldGW, oldInterval := probeServerIPv6EgressFn, sharedTUNGatewayV6, serverV6EgressProbeInterval
	serverV6EgressProbeInterval = 20 * time.Millisecond
	sharedTUNGatewayV6 = ""
	serverV6EgressKnown.Store(false)
	serverV6EgressHas.Store(false)
	// 探到「有 v6」的同一刻关机信号已经拉起 —— 这正是要钉的那个窗口。
	var once sync.Once
	probeServerIPv6EgressFn = func() bool {
		once.Do(func() { close(stop); close(probed) })
		return true
	}
	t.Cleanup(func() {
		time.Sleep(200 * time.Millisecond) // 留出退出窗口,再还原全局(见 v6ProbeHarness 注释)
		probeServerIPv6EgressFn, sharedTUNGatewayV6, serverV6EgressProbeInterval = oldFn, oldGW, oldInterval
		serverV6EgressKnown.Store(false)
		serverV6EgressHas.Store(false)
	})

	startServerV6EgressProbe(stop)

	select {
	case <-probed:
	case <-time.After(3 * time.Second):
		t.Fatal("探测一轮都没跑")
	}
	// 探测结果本身仍要落地(数据面读的是它),只是不许再动 iptables。
	deadline := time.Now().Add(2 * time.Second)
	for !serverV6EgressKnown.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !serverV6EgressHas.Load() {
		t.Error("探到有 v6,结果却没记下来")
	}
	time.Sleep(200 * time.Millisecond)
	if n := installs.Load(); n != 0 {
		t.Errorf("关机中还补装了 %d 次 NAT66 —— 与 teardown sweep 反向打架,规则会留在机器上过夜", n)
	}
}
