package main

import (
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/util"
)

// deadlineRecordingLink 记录链路上的写与写超时设置 —— 出口列表推送必须带写超时并在写完撤掉。
type deadlineRecordingLink struct {
	mu        sync.Mutex
	buf       []byte
	deadlines []time.Time
	closed    chan struct{}
}

func newDeadlineRecordingLink() *deadlineRecordingLink {
	return &deadlineRecordingLink{closed: make(chan struct{})}
}

func (c *deadlineRecordingLink) Read(p []byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *deadlineRecordingLink) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *deadlineRecordingLink) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *deadlineRecordingLink) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines = append(c.deadlines, t)
	return nil
}

func (c *deadlineRecordingLink) written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...)
}

func (c *deadlineRecordingLink) deadlineCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, d := range c.deadlines {
		if !d.IsZero() {
			n++
		}
	}
	return n
}

func (c *deadlineRecordingLink) deadlineWasCleared() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.deadlines) > 0 && c.deadlines[len(c.deadlines)-1].IsZero()
}

// supersede 存在的全部意义是「同一台设备重登,vIP 不变」。为此新连接要等老连接**彻底**清理完
// (vIP 占用位释放)才去分配地址。这里钉住那段等待的三条边界:
//
//   - victim 列表里的 nil / 重复项。重复项会让同一条连接被 close 两次、被等两次;nil 项则在
//     解引用时直接 panic —— 而这段代码跑在登录路径上,panic 掉的是正在登录的那个用户。
//   - 老连接卡住时的总等待必须硬顶在 supersedeWaitTimeout 内。这里曾是「逐条各等 5s」:
//     多条 victim 同时卡在 takeoverMu 时退化成 5s×N,新连接的握手响应被拖到客户端超时 ——
//     用户看到的是「重连要等半分钟甚至失败」,而服务端一切正常。
//   - 到点仍未清完就继续登录(退化成无 supersede:可能换一个 vIP),而不是拒登。拒登比换地址更糟:
//     设备再也连不上,得等那条卡住的老连接自己超时。

// TestDedupVictims_NilAndDuplicateEntriesAreDropped nil 跳过、重复只留一份、顺序稳定。
func TestDedupVictims_NilAndDuplicateEntriesAreDropped(t *testing.T) {
	a := &Connection{connIDStr: "a"}
	b := &Connection{connIDStr: "b"}
	c := &Connection{connIDStr: "c"}

	if got := dedupVictims(nil, nil); got != nil {
		t.Fatalf("两边都空时返回了 %v,want nil", got)
	}

	got := dedupVictims(
		[]*Connection{a, nil, a, b},
		[]*Connection{b, nil, c, c},
	)
	if len(got) != 3 {
		t.Fatalf("去重后 %d 条,want 3(a/b/c 各一条)—— 重复项会让同一条连接被 close 两次、被等两次", len(got))
	}
	// 顺序:先 supersede 再 evict,便于日志阅读。
	if got[0] != a || got[1] != b || got[2] != c {
		t.Fatalf("顺序错了: %q/%q/%q,want a/b/c(先 supersede 后 evict)",
			got[0].connIDStr, got[1].connIDStr, got[2].connIDStr)
	}
	for i, v := range got {
		if v == nil {
			t.Fatalf("第 %d 条是 nil —— 后面 close / 等 cleanupDone 时会当场 panic,而这段跑在登录路径上", i)
		}
	}
}

// TestWaitConnsCleanup_ReturnsAsSoonAsEveryoneIsDone 全部清完就立刻返回,不空等。
func TestWaitConnsCleanup_ReturnsAsSoonAsEveryoneIsDone(t *testing.T) {
	mk := func(id string) *Connection {
		c := &Connection{connIDStr: id, cleanupDone: make(chan struct{})}
		close(c.cleanupDone)
		return c
	}
	// nil 项与没有 cleanupDone 通道的项都必须跳过(后者是尚未进入清理流程的连接:
	// 等一个永不关闭的 nil 通道会一直等到超时,把每次重登都拖满 5s)。
	victims := []*Connection{mk("x"), nil, {connIDStr: "no-chan"}, mk("y")}

	start := time.Now()
	done := make(chan struct{})
	go func() { waitConnsCleanup(victims); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("victim 全部清理完毕却没有立刻返回 —— 每次重登都要白等,nil / 无通道的项被当成「还没清完」")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("等了 %v —— 应当立刻返回", el)
	}

	// 空列表是最常见的情形(首次登录),必须零成本返回。
	waitConnsCleanup(nil)
}

// TestWaitConnsCleanup_TotalWaitIsCappedNotPerVictim 多条卡住的 victim 共享一个总超时。
func TestWaitConnsCleanup_TotalWaitIsCappedNotPerVictim(t *testing.T) {
	oldTimeout := supersedeWaitTimeout
	t.Cleanup(func() { supersedeWaitTimeout = oldTimeout })
	supersedeWaitTimeout = 300 * time.Millisecond

	hook := &countingLogHook{levels: []logrus.Level{logrus.WarnLevel}}
	logrus.AddHook(hook)
	t.Cleanup(func() { hook.mu.Lock(); hook.levels = []logrus.Level{logrus.PanicLevel}; hook.mu.Unlock() })

	// 五条 victim 全部卡住(生产里对应它们都阻塞在 takeoverMu:并发 takeover 正持锁跑 argon2)。
	stuck := make([]*Connection, 5)
	for i := range stuck {
		stuck[i] = &Connection{
			connIDStr:   "stuck-" + string(rune('a'+i)),
			deviceUUID:  "22222222-2222-4222-8222-22222222222" + string(rune('0'+i)),
			cleanupDone: make(chan struct{}), // 永不关闭
		}
	}

	start := time.Now()
	waitConnsCleanup(stuck)
	el := time.Since(start)

	// 逐条各等一遍会是 5×300ms;共享 deadline 应当在一个超时窗口内就全部走完。
	if el > 900*time.Millisecond {
		t.Fatalf("五条卡住的 victim 等了 %v —— 退化成「逐条各等一遍」,新连接的握手响应会被拖到客户端超时,"+
			"用户看到的是「重连要等半分钟甚至失败」而服务端一切正常", el)
	}
	if el < 200*time.Millisecond {
		t.Fatalf("只等了 %v 就返回 —— 完全没等 cleanup,新连接会在 vIP 尚未释放时去分配,拿到不同的地址,"+
			"supersede 存在的意义就没了", el)
	}
	if hook.count() == 0 {
		t.Error("等 cleanup 超时没有任何 WARN —— 「这次重登为什么换了 IP」在日志里将无迹可寻")
	}
	hook.mu.Lock()
	msg := strings.Join(hook.msgs, "\n")
	hook.mu.Unlock()
	if !strings.Contains(msg, "supersede") {
		t.Errorf("超时告警里没标出是 supersede 路径: %q", msg)
	}
}

// TestSendExitsListTo_SkipsSessionsThatCannotReceive 不能收的会话一律跳过,能收的要带写超时。
//
// 这条链路写在持 exitsBroadcastMu 期间:一个 TCP 窗口写满的客户端如果没有写超时,会一直占着这把锁,
// 拖住**所有**出口列表广播与初始推送 —— 现象是别人的出口下拉长时间不更新。
func TestSendExitsListTo_SkipsSessionsThatCannotReceive(t *testing.T) {
	exits := []util.ExitInfo{{DeviceUUID: "33333333-3333-4333-8333-333333333333", DeviceName: "exit-a", Online: true}}

	// nil / 还没有链路的会话:一律安静跳过,不能 panic。
	sendExitsListTo(nil, exits)
	sendExitsListTo(&Connection{}, exits)
	sendExitsListTo(&Connection{exitAllowed: true}, exits)

	// 有链路但没有出口权限:一个字节都不许写。出口列表本身就是情报 —— 它告诉对方这个 mesh 里
	// 有哪些设备可以当出口、此刻谁在线,而这个用户按策略根本不该看到这些。
	noPerm := newDeadlineRecordingLink()
	denied := &Connection{connIDStr: "no-exit-perm"}
	denied.linkConn = noPerm
	sendExitsListTo(denied, exits)
	if len(noPerm.written()) != 0 {
		t.Fatalf("给无出口权限的会话推了 %d 字节出口列表 —— 等于把「谁能当出口、此刻谁在线」"+
			"这份情报发给按策略不该看到它的用户", len(noPerm.written()))
	}

	link := newDeadlineRecordingLink()
	c := &Connection{connIDStr: "exit-watcher", exitAllowed: true}
	c.linkConn = link
	sendExitsListTo(c, exits)

	if len(link.written()) == 0 {
		t.Fatal("exit_allowed 会话没收到出口列表 —— 客户端的出口下拉会一直是空的")
	}
	if link.deadlineCount() == 0 {
		t.Error("推送没有加写超时 —— 一个 TCP 窗口写满的客户端会一直占着 exitsBroadcastMu,拖住所有人的出口列表广播")
	}
	if !link.deadlineWasCleared() {
		t.Error("写完没有清掉写超时 —— 这个绝对时间会留在链路上,之后数据面的下行写到点就开始失败")
	}
}
