package main

import (
	"context"
	"testing"
	"time"
)

// 接管时「老链路的 demux 还在消费共享 TunChan」这段等待。
//
// 接管不换 vIP,新老两条连接共用同一组 TunChan。老链路的 demux 若还没退出就启动新 demux,两个 demux
// 会并发从同一条下行队列取包 —— 取到的那一半被写进已经关掉的老链路,**直接丢**。表现是接管后下行
// 断续丢包几十秒(smux keepalive 级别),客户端不报错、日志也不报错,只是网页转圈。
//
// 所以 handler 会先等老链路退出;等不到就主动 cancel 它的 tunnel ctx 逼停(demux 可能正卡在限速器
// WaitN 上,那个既不看 deadline 也不看链路已关);再等不到才作为最后手段继续。这三段逻辑此前一行没跑过。

// withShortTakeoverGrace 把两段等待压到测试量级,收尾还原。
func withShortTakeoverGrace(t *testing.T, grace, cancelGrace time.Duration) {
	t.Helper()
	prevG, prevC := takeoverOldTunnelGrace, takeoverOldTunnelCancelGrace
	takeoverOldTunnelGrace, takeoverOldTunnelCancelGrace = grace, cancelGrace
	t.Cleanup(func() {
		takeoverOldTunnelGrace, takeoverOldTunnelCancelGrace = prevG, prevC
	})
}

// armOldTunnelCtx 给老连接装上一个真实的 tunnel ctx(生产里由 runLinkTunnel 装),
// 返回的 ctx 用来观察它有没有被主动取消。
func armOldTunnelCtx(t *testing.T, c *Connection) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cf := context.CancelFunc(cancel)
	c.tunnelCancel.Store(&cf)
	return ctx
}

// TestTakeover_ForcesTheOldTunnelDownWhenItOverstays 接管过程中老链路的 tunnel ctx 必须被主动 cancel。
//
// 只「关掉链路然后等」是不够的:老 demux 卡住的典型原因就是限速器 WaitN(低带宽配置下一次等待可以到
// 数秒,且不受 SetWriteDeadline 与链路 Close 影响),干等不会让它松手,cancel 才会。
//
// 这道闸有两层:抢老链路写锁之前先 cancel 一次,等不到退出时在 grace 超时里再 cancel 一次。任何一层单独
// 拆掉,另一层都会补上 —— 所以对应的变异必须两层同拆(见 mutations-round45.json),单拆的结果是「看着没测」。
func TestTakeover_ForcesTheOldTunnelDownWhenItOverstays(t *testing.T) {
	fx := newTakeoverFixture(t)
	withShortTakeoverGrace(t, 150*time.Millisecond, 3*time.Second)
	oldCtx := armOldTunnelCtx(t, fx.oldConn)

	// 老 demux 的真实反应:被 cancel 之后收工,close(tunnelDone)。
	go func() {
		<-oldCtx.Done()
		close(fx.oldConn.tunnelDone)
	}()

	resp, _ := startTakeoverOK(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("合法接管应成功: %+v", resp)
	}

	select {
	case <-oldCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("老链路赖着不退出,接管却没去 cancel 它的 tunnel ctx —— 新老两个 demux 会并抢同一条下行队列,接管后下行开始随机丢包")
	}
	// cancel 之后老链路确实退出了,接管应当立刻继续(而不是把第二段 grace 也睡满)。
	if cur := currentConnForSID(t, fx.sid, fx.oldConn); cur == nil {
		t.Fatal("接管没落地")
	}
}

// TestTakeover_StillHandsOverWhenTheOldTunnelIgnoresTheCancel cancel 也叫不动时,接管仍要落地。
//
// 反向的坏法同样真实:为了「绝对不丢包」而无限等下去的话,一个卡死的老 demux 就能让这条会话**永远
// 接管不了** —— 客户端每次热切换都超时重连,而重连还是撞上同一条卡死的老连接。宁可短暂丢几个下行包,
// 也要让会话恢复。
func TestTakeover_StillHandsOverWhenTheOldTunnelIgnoresTheCancel(t *testing.T) {
	fx := newTakeoverFixture(t)
	// 两段都压短:这条用例里 tunnelDone 从头到尾不会关,两段等待都会走满。
	withShortTakeoverGrace(t, 150*time.Millisecond, 150*time.Millisecond)
	oldCtx := armOldTunnelCtx(t, fx.oldConn)

	resp, _ := startTakeoverOK(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("老链路不退出不该让接管失败: %+v", resp)
	}
	// 两段等待都会走满(tunnelDone 从头到尾不关),但它们必须**有上限** —— 接管最终要落地。
	newConn := currentConnForSID(t, fx.sid, fx.oldConn)
	if newConn == nil {
		t.Fatal("老链路不退出,接管就再也落不了地 —— 这条会话被一个卡死的 demux 永久锁死了")
	}
	select {
	case <-oldCtx.Done():
	case <-time.After(5 * time.Second):
		t.Error("最后放行前没有 cancel 老 tunnel ctx —— 它会带着共享 TunChan 继续跑下去")
	}
}
