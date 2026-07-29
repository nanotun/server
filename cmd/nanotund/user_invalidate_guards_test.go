package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 这条扫描循环手里握着「把在线会话踢下线」的权力,所以它的每个不确定分支都必须收敛到**不踢**。
//
// 踢错的代价是不对称的:漏踢一轮,下一 tick(默认几十秒)会补上;误踢一轮,用户当场断线,而且
// 若判据本身是错的,他重连后还会再被踢 —— 变成一个谁也说不清的掉线循环。

// TestScanAndKickInvalidUsers_ADBHiccupNeverKicksAnyone 查不到 user 状态时本轮什么都不做。
//
// GetUser 报错分两种:ErrNotFound 说明账号真被删了(该踢),其它错误(库锁住、磁盘满、ctx 超时)
// 只说明「这一轮问不出来」。把后者当成「账号无效」就会在一次 DB 抖动里把全站会话踢干净。
func TestScanAndKickInvalidUsers_ADBHiccupNeverKicksAnyone(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	ctx := t.Context()
	user, err := gw.store.CreateUser(ctx, store.NewUser{Username: "dbhiccup", PSKHash: "psk-x"})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeLinkConn()
	c := &Connection{
		connIDStr:      "conn-dbhiccup",
		userID:         userIDFromStoreID(user.ID),
		linkConn:       fake,
		pskHashAtLogin: "psk-x",
		tunnelDone:     make(chan struct{}),
		createdAt:      time.Now(),
	}
	installConn(t, c)

	// 关掉库:GetUser 会失败,而且不是 ErrNotFound。
	_ = gw.store.Close()

	scanAndKickInvalidUsers(ctx, gw)
	select {
	case <-fake.closed:
		t.Fatal("一次 DB 故障就把在线会话踢了 —— 库抖一下等于全站掉线")
	default:
	}
	if c.superseded.Load() {
		t.Error("会话被标成 superseded —— 它会立刻从出口 / 子网转发目标里消失,等于半踢")
	}
}

// TestScanAndKickInvalidUsers_IgnoresSessionsWithoutARealUser 没有真实 user 的表项要跳过。
//
// by-user 索引的键是登录时写进去的 userID 字符串。预登录 / 异常路径可能留下解析不出数字的键,
// 对它们查 DB 只会拿到 ErrNotFound —— 而 ErrNotFound 的处置是「账号已删,全员踢」。若不先跳过,
// 这些会话会被一条不存在的账号判死。
func TestScanAndKickInvalidUsers_IgnoresSessionsWithoutARealUser(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	fake := newFakeLinkConn()
	c := &Connection{
		connIDStr:  "conn-no-user",
		userID:     "", // 尚未认证
		linkConn:   fake,
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	}
	installConn(t, c)

	scanAndKickInvalidUsers(t.Context(), gw)
	select {
	case <-fake.closed:
		t.Fatal("没有真实 user 的会话被当成「账号已删」踢掉了")
	default:
	}
}

// TestScanAndKickInvalidUsers_NoStoreIsANoop 没有 store 时安全返回。
func TestScanAndKickInvalidUsers_NoStoreIsANoop(t *testing.T) {
	scanAndKickInvalidUsers(t.Context(), nil)
	scanAndKickInvalidUsers(t.Context(), &gatewayState{})
}

// TestKickConnForUserInvalidate_GivesUpInsteadOfChasingForever 接管链回溯有跳数上限。
//
// 踢一条已被接管的会话时,要沿 sid 追到当前真正在跑的那条(否则踢的是个已作废的对象,而
// control-socket 还会把它计成「已踢除」回报给管理员)。但这个回溯必须有上限:一条持续重连的
// 会话可以让每次回溯都看到「又被接管了」,没有上限就是一个持着 RLock 反复读表的死循环 ——
// 那会把整条扫描 goroutine 卡住,连带所有账号级失效判定全部停摆。
func TestKickConnForUserInvalidate_GivesUpInsteadOfChasingForever(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	ctx := t.Context()
	user, err := gw.store.CreateUser(ctx, store.NewUser{Username: "hops", PSKHash: "psk-h"})
	if err != nil {
		t.Fatal(err)
	}
	uid := userIDFromStoreID(user.ID)

	// 造一条比上限更长的接管链:每一跳追到的会话本身又已经被接管。
	mk := func(sid string) *Connection {
		c := &Connection{connIDStr: sid, userID: uid, linkConn: newFakeLinkConn(), tunnelDone: make(chan struct{}), createdAt: time.Now()}
		c.takenOver.Store(true)
		return c
	}
	chain := make([]*Connection, maxKickTakeoverHops+2)
	for i := range chain {
		chain[i] = mk(fmt.Sprintf("conn-hop-%d", i))
	}
	connIDMapMu.Lock()
	for i := 0; i < len(chain)-1; i++ {
		connIDMap[chain[i].connIDStr] = chain[i+1]
	}
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		for _, c := range chain {
			delete(connIDMap, c.connIDStr)
		}
		connIDMapMu.Unlock()
	})

	done := make(chan bool, 1)
	go func() {
		done <- kickConnForUserInvalidate(ctx, gw, chain[0], user.ID, "user_deleted", kickFollowTakeover)
	}()
	select {
	case ok := <-done:
		if ok {
			t.Error("回溯超上限还报告踢成功 —— 管理员会拿到一个虚假的『已踢除』计数")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("回溯没有跳数上限,扫描 goroutine 卡在里面出不来了")
	}
	// 链上任何一条都不该被真的关掉:回溯没追到活会话,就什么都不做。
	for i, c := range chain {
		if c.superseded.Load() {
			t.Errorf("第 %d 跳的会话被标成 superseded —— 回溯放弃了却留下了半踢状态", i)
		}
	}
}

// TestKickConnForUserInvalidate_NilConnIsNotASuccess nil 会话不是「踢成功」。
func TestKickConnForUserInvalidate_NilConnIsNotASuccess(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	if kickConnForUserInvalidate(t.Context(), gw, nil, 1, "user_deleted", kickFollowTakeover) {
		t.Error("对 nil 会话报告踢成功 —— 计数会虚高,管理员以为清干净了")
	}
}
