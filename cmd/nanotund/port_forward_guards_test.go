package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 端口转发管理器剩下的几条失败路径。
//
// 这一组盯的都是「不改现状」与「不假装成功」:reload 读不到 DB 时保留现有监听(清空等于把所有
// 公网入口一次性关掉,而原因只是一次库抖动);Accept 出瞬时错误时退避重试而不是退出循环(退出
// 就是那个公网端口从此不再接客,而运行态显示一切正常);解析不出目标时关连接而不是盲拨。

// TestPortForwardReload_KeepsListenersWhenTheDBIsUnreadable 读不到映射表时保留现有监听。
func TestPortForwardReload_KeepsListenersWhenTheDBIsUnreadable(t *testing.T) {
	e := newPFEnv(t)
	port := freePort(t)
	e.mkPF(port, pfTestUUID, "10.80.0.9", 8080)
	e.m.reload(e.ctx)
	if got := len(e.m.active); got != 1 {
		t.Fatalf("前置条件:应有 1 个活跃监听,got %d", got)
	}

	// 把映射表藏起来 → ListEnabledPortForwards 出错。
	if _, err := e.st.DB().ExecContext(e.ctx,
		`ALTER TABLE port_forwards RENAME TO port_forwards_gone`); err != nil {
		t.Fatalf("藏表: %v", err)
	}
	e.m.reload(e.ctx)

	if got := len(e.m.active); got != 1 {
		t.Fatalf("读不到映射表时监听被拆掉了(active=%d)—— 一次库抖动会把所有公网入口同时关闭", got)
	}
	// 端口确实还被我们自己占着(socket 没关)。这里故意不去拨它:拨一下会催生一个连接
	// goroutine 去拨那个不可达的目标,挂满 10s 拨号超时,活得比本用例还久 —— 而它一路读的
	// globalContext 会在 pfEnv 收尾时被还原,于是变成一次测试自造的数据竞争。
	if ln, err := net.Listen("tcp", ":"+strconv.Itoa(port)); err == nil {
		_ = ln.Close()
		t.Fatal("端口已能重新绑定,说明原监听被关掉了 —— 公网入口断了")
	}
}

// TestPortForwardReload_DropsRuntimeStateForPortsNobodyWantsAnymore 映射删掉后运行态也要清掉。
//
// 留着的后果是 web 后台一直显示一条早已不存在的映射(还可能带着 bind_failed 的红字),
// 运维照着它去排查一个不存在的问题。
func TestPortForwardReload_DropsRuntimeStateForPortsNobodyWantsAnymore(t *testing.T) {
	t.Run("在跑的映射被删:监听与运行态一起消失", func(t *testing.T) {
		e := newPFEnv(t)
		port := freePort(t)
		pf := e.mkPF(port, pfTestUUID, "10.80.0.9", 8080)
		e.m.reload(e.ctx)
		if _, ok := e.m.status[port]; !ok {
			t.Fatal("前置条件:应有该端口的运行态")
		}

		if err := e.st.DeletePortForward(e.ctx, pf.ID); err != nil {
			t.Fatalf("DeletePortForward: %v", err)
		}
		e.m.reload(e.ctx)

		if _, ok := e.m.status[port]; ok {
			t.Error("映射已删,运行态还留着 —— web 后台会显示一条不存在的映射")
		}
		if _, ok := e.m.active[port]; ok {
			t.Error("映射已删,监听还在 —— 公网端口仍然开着")
		}
	})

	// 真正需要第 ③ 段清理的是这种:压根没进 active 的失败态。停监听那条路顺手就把 active
	// 里的清了,而 bind_failed 只活在 status 里 —— 不专门扫一遍,它会永远挂在后台页面上,
	// 带着红字报一个早已不存在的映射的错。
	t.Run("绑失败过的端口被删:失败态也要清掉", func(t *testing.T) {
		e := newPFEnv(t)
		port := freePort(t)
		blocker, err := net.Listen("tcp", ":"+strconv.Itoa(port))
		if err != nil {
			t.Skipf("拿不到端口做冲突: %v", err)
		}
		defer blocker.Close()

		pf := e.mkPF(port, pfTestUUID, "192.168.80.60", 22)
		e.m.reload(e.ctx)
		if _, ok := e.m.active[port]; ok {
			t.Fatal("前置条件:端口被占,不该进 active")
		}
		if e.statusOf(port).State != pfStateBindFailed {
			t.Fatalf("前置条件:应是 bind_failed,got %q", e.statusOf(port).State)
		}

		if err := e.st.DeletePortForward(e.ctx, pf.ID); err != nil {
			t.Fatalf("DeletePortForward: %v", err)
		}
		e.m.reload(e.ctx)

		if _, ok := e.m.status[port]; ok {
			t.Error("映射已删,bind_failed 的运行态还留着 —— 后台会一直红字报一个不存在的映射")
		}
	})
}

// TestResolveDeviceID_RefusesToGuess UUID 解析不出设备时必须说「不知道」。
//
// 它的返回值决定精确路由表里那条 LAN 目标指向谁。猜一个 deviceID 出来,就是把公网端口上的
// 流量投给一台没被指定的设备 —— 投进了别人的 LAN。
func TestResolveDeviceID_RefusesToGuess(t *testing.T) {
	e := newPFEnv(t)
	dev := e.mkDevice("pfuser", "aaaaaaaa-1111-4111-8111-111111111111", "10.80.0.9", "")

	for _, tc := range []struct {
		name string
		uuid string
		m    *portForwardManager
	}{
		{"空 UUID", "", e.m},
		{"只有空白的 UUID", "   ", e.m},
		{"没有 gateway", dev.DeviceUUID, &portForwardManager{}},
		{"没有 store", dev.DeviceUUID, &portForwardManager{gw: &gatewayState{}}},
		{"库里没有这台设备", "bbbbbbbb-2222-4222-8222-222222222222", e.m},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if id, ok := tc.m.resolveDeviceID(e.ctx, tc.uuid); ok {
				t.Errorf("解析不出设备时必须回 (0,false),got (%d,true) —— "+
					"猜一个 deviceID 就是把公网流量投进别人的 LAN", id)
			}
		})
	}

	// 反面:正常 UUID 要解析得出来(大小写不敏感),否则上面全可由「永远失败」满足。
	if id, ok := e.m.resolveDeviceID(e.ctx, "AAAAAAAA-1111-4111-8111-111111111111"); !ok || id != dev.ID {
		t.Errorf("大小写不同的合法 UUID 应解析到 device %d,got (%d,%v)", dev.ID, id, ok)
	}
}

// TestFRPLANReplyFromDevice_RefusesWhatItCannotConfirm LAN 回程的确认表。
//
// 这张表回答「这个 LAN 源地址+端口的回包,是不是来自我指定的那台宣告方」。答错方向:
// 表没建好时放行 = 任何宣告方都能伪造别人 LAN 主机的回包;匿名会话放行 = 无从确认是谁。
func TestFRPLANReplyFromDevice_RefusesWhatItCannotConfirm(t *testing.T) {
	src := netip.MustParseAddr("192.168.80.9")
	tup := pktTuple{hasL4Ports: true, srcPort: 8080, proto: "tcp"}

	prev := frpLANReplyTable.Load()
	t.Cleanup(func() { frpLANReplyTable.Store(prev) })

	t.Run("表未建时一律不认", func(t *testing.T) {
		frpLANReplyTable.Store(nil)
		if frpLANReplyFromDevice(5, src, tup) {
			t.Error("表未建时不该认下任何回包")
		}
	})

	t.Run("匿名会话与无端口的包一律不认", func(t *testing.T) {
		tbl := map[frpLANReplyKey]frpLANReplyVal{
			{addr: src, port: 8080}: {deviceID: 5, proto: "tcp"},
			// 故意放一条 deviceID=0 的表项:入口那道 deviceID<=0 的闸若被去掉,匿名会话就会
			// 从这里过关。正常构表不会产出它,但这个判据收的是任意一张表 ——「无从确认是谁」
			// 撞上「一条没有主人的表项」正是它要挡的形状。
			{addr: netip.MustParseAddr("192.168.80.10"), port: 9090}: {deviceID: 0, proto: "tcp"},
		}
		frpLANReplyTable.Store(&tbl)
		if frpLANReplyFromDevice(0, netip.MustParseAddr("192.168.80.10"),
			pktTuple{hasL4Ports: true, srcPort: 9090, proto: "tcp"}) {
			t.Error("deviceID=0(匿名)无从确认是被指定的宣告方,不该认 —— " +
				"哪怕表里真有一条没有主人的表项")
		}
		if frpLANReplyFromDevice(0, src, tup) {
			t.Error("deviceID=0(匿名)不该认下别人的表项")
		}
		if frpLANReplyFromDevice(-1, src, tup) {
			t.Error("负 deviceID 不该认")
		}
		if frpLANReplyFromDevice(5, src, pktTuple{hasL4Ports: false, proto: "tcp"}) {
			t.Error("没有四层端口的包不该认")
		}
		if frpLANReplyFromDevice(5, src, pktTuple{hasL4Ports: true, srcPort: 0, proto: "tcp"}) {
			t.Error("源端口为 0 的包不该认")
		}
		// 正主要认下来,同时别的设备 / 别的协议不认。
		if !frpLANReplyFromDevice(5, src, tup) {
			t.Error("被指定的宣告方发来的回包必须认")
		}
		if frpLANReplyFromDevice(6, src, tup) {
			t.Error("别的设备不该借这条表项过关")
		}
		if frpLANReplyFromDevice(5, src, pktTuple{hasL4Ports: true, srcPort: 8080, proto: "udp"}) {
			t.Error("协议不同不该过关")
		}
	})
}

// TestAcceptPortForward_BacksOffOnTransientErrorsAndStopsOnFatalOnes Accept 循环的错误分档。
//
// 分错的两种坏法:把瞬时错误(fd 暂时耗尽)当致命 → 那个公网端口从此不再接客,而 active/status
// 里它仍是「running」,只有用户会发现连不上;把致命错误当瞬时 → 忙循环烧 CPU。
func TestAcceptPortForward_BacksOffOnTransientErrorsAndStopsOnFatalOnes(t *testing.T) {
	e := newPFEnv(t)
	pf := store.PortForward{PublicPort: 1, Proto: "tcp", TargetIP: "10.80.0.9", TargetPort: 8080}

	t.Run("瞬时错误退避后继续接客,遇永久错误才退出", func(t *testing.T) {
		// 两次瞬时错误 → 应各退避一次并继续;第三次永久错误 → 退出循环。
		ln := newScriptedListener(
			scriptedAccept{err: transientNetErr{}},
			scriptedAccept{err: transientNetErr{}},
			scriptedAccept{err: errors.New("listener closed for good")},
		)
		done := make(chan struct{})
		go func() {
			defer close(done)
			acceptPortForward(e.ctx, ln, e.m, pf, make(chan struct{}, 4))
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("永久错误后 Accept 循环应退出,却还在转")
		}
		if got := ln.acceptCnt.Load(); got != 3 {
			t.Fatalf("应当把三步都走完(两次退避重试 + 一次致命),实际只 Accept 了 %d 次 —— "+
				"提前退出意味着那个公网端口从此不再接客,而运行态里它仍是 running", got)
		}
		// 退避是真的睡了:第一次瞬时错误后至少 5ms,第二次翻倍。
		if gap := ln.gapBetweenAccepts(t, 1); gap < 4*time.Millisecond {
			t.Errorf("第一次瞬时错误后几乎没退避(%v)—— fd 耗尽时会变成忙循环烧 CPU", gap)
		}
		if gap := ln.gapBetweenAccepts(t, 2); gap < 9*time.Millisecond {
			t.Errorf("第二次退避没有翻倍(%v)", gap)
		}
	})

	t.Run("ctx 取消时干净退出,不当成错误刷日志", func(t *testing.T) {
		ctx, cancel := context.WithCancel(e.ctx)
		// 不排任何脚本:Accept 会一直阻塞在 channel 上,直到 watcher 因 ctx 取消关掉它。
		ln := newScriptedListener()
		done := make(chan struct{})
		go func() {
			defer close(done)
			acceptPortForward(ctx, ln, e.m, pf, make(chan struct{}, 4))
		}()
		// 让 Accept 先进去阻塞,再取消:watcher 关 listener → 我们喂一个错误模拟 Accept 返回。
		time.Sleep(50 * time.Millisecond)
		cancel()
		ln.ch <- scriptedAccept{err: errors.New("use of closed network connection")}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("ctx 取消后 Accept 循环应退出")
		}
		// 关 listener 由 watcher goroutine 做,与 accept 循环退出是并发的,轮询等它。
		deadline := time.Now().Add(2 * time.Second)
		for ln.closeCnt.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if ln.closeCnt.Load() == 0 {
			t.Error("ctx 取消时 watcher 应关掉 listener,否则那个公网端口一直被占着")
		}
	})
}

// transientNetErr 一个自称「可重试」的网络错误(fd 暂时耗尽就是这个形状)。
type transientNetErr struct{}

func (transientNetErr) Error() string   { return "临时错误" }
func (transientNetErr) Timeout() bool   { return false }
func (transientNetErr) Temporary() bool { return true }
