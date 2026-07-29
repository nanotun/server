package main

// server.go 上几个「一条语句、错了不报错」的小分支。
//
// 它们各自很小,但都在别处被反复调用,错了都是静默的:
//
//   - 会话下线后不刷路由列表 → 请求方 UI 上那条网段一直显示「可用」,包却已经没人转;
//   - 限速取 min 时把 0 当成「0 bps」而不是「不限」→ 任一层没配就把链路掐成 0;
//   - 关机中还在等 demux 回执 → 清理协程挂死,进程等到 systemd 的 SIGKILL 才走。

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

// TestCleanupConnection_AdvertiserGoingOfflineRefreshesTheRoutesList
// 已批准的子网路由宣告方下线 → 必须重播一次路由列表。
//
// Online 位只在「客户端连入 / admin 改路由」时重算。宣告方自己下线不重算的话,已经连着的请求方
// 手里停在旧的 online=true:UI 说这条网段能走,数据面(判据是当前宣告集)照旧丢包。两侧都"正常",
// 属于最难从现象倒推的一类。
func TestCleanupConnection_AdvertiserGoingOfflineRefreshesTheRoutesList(t *testing.T) {
	resetConnByDeviceForTest(t)
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.61.0/24", 61)})
	prevGW := gatewayInstance
	gatewayInstance = &gatewayState{}
	t.Cleanup(func() { gatewayInstance = prevGW })

	// 请求方:一直在线,靠它观察有没有收到重播。
	//
	// 这里不能用 fakeLinkConn:它的 writeBuf 是裸切片,而这条重播是**在别的 goroutine 里**写的
	// (cleanupConnection 有意不阻塞在广播上),边写边读就是 -race 抓的那种竞态 —— 是测试自己造的。
	watcher := newFrameWatchConn()
	requester := &Connection{connIDStr: "routes-watcher", userID: "1", linkConn: watcher, tunnelDone: make(chan struct{}), createdAt: time.Now()}

	install := func(c *Connection) {
		connIDMapMu.Lock()
		connIDMap[c.connIDStr] = c
		connIDMapMu.Unlock()
		t.Cleanup(func() {
			connIDMapMu.Lock()
			delete(connIDMap, c.connIDStr)
			connIDMapMu.Unlock()
		})
	}
	install(requester)

	// 先让一台**与批准表无关**的设备下线:不该触发重播(否则每个普通客户端断线都要全站重播一次)。
	plain := &Connection{connIDStr: "plain-leaver", userID: "2", deviceID: 999, tunnelDone: make(chan struct{}), createdAt: time.Now()}
	install(plain)
	cleanupConnection(plain)
	if n := watcher.waitBytes(200 * time.Millisecond); n != 0 {
		t.Fatalf("普通客户端下线也触发了路由列表重播(收到 %d 字节)—— 每次断线全站重播,几百个会话时是自伤", n)
	}

	// 现在是宣告方下线。
	advertiser := &Connection{connIDStr: "adv-leaver", userID: "1", deviceID: 61, tunnelDone: make(chan struct{}), createdAt: time.Now()}
	install(advertiser)
	cleanupConnection(advertiser)

	if watcher.waitBytes(5*time.Second) == 0 {
		t.Fatal("已批准宣告方下线后没有重播路由列表 —— 请求方 UI 会一直停在 online=true,而包已经没人转")
	}
}

// frameWatchConn 是个只记「收了多少字节」的链路对端,读写都过锁 —— 供断言与后台广播 goroutine 并发使用。
type frameWatchConn struct {
	mu     sync.Mutex
	n      int
	closed chan struct{}
}

func newFrameWatchConn() *frameWatchConn {
	return &frameWatchConn{closed: make(chan struct{})}
}

func (c *frameWatchConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *frameWatchConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.n += len(p)
	c.mu.Unlock()
	return len(p), nil
}

func (c *frameWatchConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *frameWatchConn) SetWriteDeadline(time.Time) error { return nil }

func (c *frameWatchConn) bytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// waitBytes 最多等 d,一收到字节就返回;超时返回 0。
func (c *frameWatchConn) waitBytes(d time.Duration) int {
	deadline := time.Now().Add(d)
	for {
		if n := c.bytes(); n != 0 {
			return n
		}
		if time.Now().After(deadline) {
			return 0
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMinPositiveInt_TreatsZeroAsUnlimited
// 0 / 负数在限速语义里是「不限」,不是「0」。取成 0 的后果是链路被掐死(客户端连上就一个字节都跑不动),
// 而配置文件里那一层根本没打算限速。
func TestMinPositiveInt_TreatsZeroAsUnlimited(t *testing.T) {
	cases := []struct{ a, b, want int }{
		{0, 500, 500},   // platform 没配 → 听 user 的
		{500, 0, 500},   // user 没配 → 听 platform 的
		{-1, 500, 500},  // 负数同 0
		{0, 0, 0},       // 都没配 → 不限
		{300, 500, 300}, // 都配了 → 取更严的
		{500, 300, 300},
	}
	for _, c := range cases {
		if got := minPositiveInt(c.a, c.b); got != c.want {
			t.Errorf("minPositiveInt(%d, %d) = %d, want %d —— 把「没配」当成 0 会把链路掐成 0",
				c.a, c.b, got, c.want)
		}
	}
}

// TestEvictOldestSessionsLocked_NeedsAnIdentifiedUserToCountAgainst
// 匿名 / 空会话不参与「同用户最多几条会话」的淘汰。
//
// 按 userID 分桶数数的逻辑,遇到空 userID 会把**所有**匿名会话并成同一个用户:一台机器登录
// 就可能把别人的会话挤下线。所以这里必须一条都不淘汰。
func TestEvictOldestSessionsLocked_NeedsAnIdentifiedUserToCountAgainst(t *testing.T) {
	gw := &gatewayState{}
	if victims := evictOldestSessionsLocked(gw, nil); len(victims) != 0 {
		t.Errorf("nil 会话不该淘汰任何人,got %d 个", len(victims))
	}

	// 让「按空 userID 分桶」这件事真的有东西可数:桶里先放一条别人的匿名会话,新来的又把上限定成 1。
	// 少了这一步,不管有没有那道闸都数到 0 条、都不淘汰,断言等于没验。
	victim := &Connection{connIDStr: "anon-victim", createdAt: time.Now().Add(-time.Hour)}
	connIDMapMu.Lock()
	if connByUser[""] == nil {
		connByUser[""] = map[string]*Connection{}
	}
	connByUser[""][victim.connIDStr] = victim
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connByUser, "")
		connIDMapMu.Unlock()
	})

	newcomer := &Connection{connIDStr: "anon-newcomer", maxSessionsAtLogin: 1, createdAt: time.Now()}
	if victims := evictOldestSessionsLocked(gw, newcomer); len(victims) != 0 {
		t.Errorf("空 userID 的会话淘汰了 %d 个人 —— 所有匿名会话被并成同一个用户,一台机器登录就能把别人挤下线",
			len(victims))
	}
}

// TestSendRegisterActionAwait_GivesUpWhenTheProcessIsShuttingDown
// 关机中不许再等 demux 的回执。
//
// 这个函数是「投递 + 等确认」两段,而 demux 在关机时先退。不看 globalContext 的话,清理路径会永远
// 停在等确认那一步:优雅关停里所有 defer(iptables 清理 / TUN 关闭 / WAL checkpoint)都跑不到,
// 最后靠 systemd 的 SIGKILL 收场 —— 现象是每次重启都留下一批残留规则。
func TestSendRegisterActionAwait_GivesUpWhenTheProcessIsShuttingDown(t *testing.T) {
	prevCtx, prevCancel := globalContext, globalContextCancel
	ctx, cancel := context.WithCancel(context.Background())
	globalContext, globalContextCancel = ctx, cancel
	t.Cleanup(func() { globalContext, globalContextCancel = prevCtx, prevCancel })

	// 关键是让它**卡在等回执那一段**:先让投递成功(一个只收不答的消费者,正是关机路上的 demux),
	// 之后才拉关机信号。若一开始就把 ctx 取消,投递那段的 ctx 分支会先短路 —— 等回执那道闸压根不会被跑到,
	// 断言看着绿,实际什么都没验(这条用例第一版就是这么假绿的)。
	taken := make(chan struct{})
	go func() {
		<-registerTunReadChan
		close(taken)
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sendRegisterActionAwait(registerTunReadChanAction{action: 1, success: make(chan struct{}, 1)})
	}()

	select {
	case <-taken:
	case <-time.After(3 * time.Second):
		t.Fatal("投递都没成功,本用例没进到「等回执」那一段")
	}
	cancel() // 关机开始,demux 不会再答复了

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("关机中仍在死等 demux 回执 —— 清理协程就挂在这里,优雅关停的 defer 一个都跑不到")
	}
}

// TestSendRegisterActionAwait_GivesUpWhenTheQueueIsFullAndWeAreShuttingDown
// 关机中投递不进去也不许干等。
//
// 上面那条钉的是「等回执」那一段,这条钉前一段:投递队列满。关机瞬间正是它最容易满的时候
// —— 所有会话同时清理,每条都要投一次 unregister,而 demux 已经先退、没人再取。不看
// globalContext 的话,清理协程堵在投递上,后果与上面同款:优雅关停退化成 SIGKILL。
func TestSendRegisterActionAwait_GivesUpWhenTheQueueIsFullAndWeAreShuttingDown(t *testing.T) {
	prevCtx, prevCancel := globalContext, globalContextCancel
	ctx, cancel := context.WithCancel(context.Background())
	globalContext, globalContextCancel = ctx, cancel
	cancel() // 关机已经开始

	// 换成一条无人接收的零容量队列 = 「队列满」。生产里是 800 条积压,行为一致而不必真灌 800 条。
	prevChan := registerTunReadChan
	registerTunReadChan = make(chan registerTunReadChanAction)
	t.Cleanup(func() {
		registerTunReadChan = prevChan
		globalContext, globalContextCancel = prevCtx, prevCancel
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		sendRegisterActionAwait(registerTunReadChanAction{action: 1, success: make(chan struct{}, 1)})
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("关机中投递不进去还在死等 —— 清理协程挂在投递上,优雅关停的 defer 一个都跑不到")
	}
}
