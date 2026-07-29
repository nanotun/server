package main

import (
	"errors"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/nanotun/server/util"
	"github.com/sirupsen/logrus"
)

// TUN 那两条批量读写循环。它们是**整台服务器所有客户端**共用的两个 goroutine:上行的每个包都从
// tunReadLoop 出来,下行的每个包都从 tunWriteLoop 进内核。它们悄悄退出一次,数据面就整体停摆 ——
// 而链路、会话、心跳全都还活着,后台看着一切正常,只有用户发现「连上了但什么都打不开」。
//
// 这两个函数此前一行未跑过(单测侧),下面用一个可编排的假 TUN 把它们的每条出口都走一遍。

// scriptedTUN 是一个可编排的 tun.Device:读什么、什么时候报错、写是否失败,全部可控。
type scriptedTUN struct {
	batchSize int

	mu      sync.Mutex
	reads   [][][]byte // 每一项是一「批」包
	readErr error      // reads 耗尽后返回它(nil 则阻塞到 Close)
	writes  [][]byte   // 记录每次 Write 收到的包(已剥掉 offset、内容已拷贝)
	writeN  int        // Write 被调用的次数(批量合并的证据)
	writeEr error

	closeOnce sync.Once
	closed    chan struct{}
	events    chan tun.Event
}

func newScriptedTUN(batchSize int) *scriptedTUN {
	return &scriptedTUN{
		batchSize: batchSize,
		closed:    make(chan struct{}),
		events:    make(chan tun.Event),
	}
}

func (d *scriptedTUN) pushRead(batch ...[]byte) {
	d.mu.Lock()
	d.reads = append(d.reads, batch)
	d.mu.Unlock()
}

func (d *scriptedTUN) failReadsWith(err error) {
	d.mu.Lock()
	d.readErr = err
	d.mu.Unlock()
}

func (d *scriptedTUN) failWritesWith(err error) {
	d.mu.Lock()
	d.writeEr = err
	d.mu.Unlock()
}

func (d *scriptedTUN) writtenPackets() ([][]byte, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.writes))
	copy(out, d.writes)
	return out, d.writeN
}

func (d *scriptedTUN) File() *os.File { return nil }

func (d *scriptedTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		d.mu.Lock()
		if len(d.reads) > 0 {
			batch := d.reads[0]
			d.reads = d.reads[1:]
			err := d.readErr
			d.mu.Unlock()
			n := 0
			for i, p := range batch {
				if i >= len(bufs) || i >= len(sizes) {
					break // 超出调用方给的批容量:多的丢掉,由用例自己保证不越界
				}
				n = copy(bufs[i][offset:], p)
				sizes[i] = n
				n = i + 1
			}
			_ = err
			return n, nil
		}
		if d.readErr != nil {
			err := d.readErr
			d.mu.Unlock()
			return 0, err
		}
		d.mu.Unlock()
		// 没有编排好的读了 —— 挂到 Close(模拟真实 TUN 上「暂时没包」)。
		select {
		case <-d.closed:
			return 0, net.ErrClosed
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func (d *scriptedTUN) Write(bufs [][]byte, offset int) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.writeN++
	if d.writeEr != nil {
		return 0, d.writeEr
	}
	for _, b := range bufs {
		if len(b) < offset {
			continue
		}
		cp := make([]byte, len(b)-offset)
		copy(cp, b[offset:])
		d.writes = append(d.writes, cp)
	}
	return len(bufs), nil
}

func (d *scriptedTUN) MTU() (int, error)        { return 1420, nil }
func (d *scriptedTUN) Name() (string, error)    { return "scripted0", nil }
func (d *scriptedTUN) Events() <-chan tun.Event { return d.events }
func (d *scriptedTUN) BatchSize() int           { return d.batchSize }
func (d *scriptedTUN) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

// withTestTunChans 把两条包级全局队列换成本用例专属的,收尾时还原并抽干,避免串台。
func withTestTunChans(t *testing.T, readCap, writeCap int) (chan *util.TunPacket, chan []byte) {
	t.Helper()
	prevRead, prevWrite := tunReadChan, tunWriteChan
	rc := make(chan *util.TunPacket, readCap)
	wc := make(chan []byte, writeCap)
	tunReadChan, tunWriteChan = rc, wc
	t.Cleanup(func() {
		tunReadChan, tunWriteChan = prevRead, prevWrite
		// 有界抽干:队列可能已被用例关掉,那时 `<-ch` 会永远立即就绪 —— 无界的 select 会空转到死。
	drainRead:
		for i := 0; i <= readCap; i++ {
			select {
			case pkt, ok := <-rc:
				if !ok {
					break drainRead
				}
				if pkt != nil {
					tunReadBufPool.Put(pkt.Buf)
					tunPacketPool.Put(pkt)
				}
			default:
				break drainRead
			}
		}
	drainWrite:
		for i := 0; i <= writeCap; i++ {
			select {
			case _, ok := <-wc:
				if !ok {
					break drainWrite
				}
			default:
				break drainWrite
			}
		}
	})
	return rc, wc
}

// startLoop 起一个循环并保证它在用例结束前退出 —— 挂着的循环会读全局量,跟后面的用例打架。
func startLoop(t *testing.T, name string, fn func()) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("%s 没有退出", name)
		}
	})
	return done
}

// TestTunReadLoop_DeliversEveryPacketInABatch 一批读到多个包时,每一个都要投递出去。
// 只投第一个是最隐蔽的坏法:批量读在低负载时每批就一个包,一切正常;负载一上来批量生效,
// 于是「越忙丢包越多」。
func TestTunReadLoop_DeliversEveryPacketInABatch(t *testing.T) {
	withTestGlobalContext(t)
	rc, _ := withTestTunChans(t, 16, 16)

	dev := newScriptedTUN(4)
	dev.pushRead([]byte{0x45, 1, 1, 1}, []byte{0x45, 2, 2}, []byte{0x45, 3})
	done := startLoop(t, "tunReadLoop", func() { tunReadLoop(dev) })

	got := make([][]byte, 0, 3)
	for len(got) < 3 {
		select {
		case pkt := <-rc:
			cp := make([]byte, pkt.N)
			copy(cp, pkt.Buf[:pkt.N])
			got = append(got, cp)
			tunReadBufPool.Put(pkt.Buf)
			tunPacketPool.Put(pkt)
		case <-time.After(5 * time.Second):
			t.Fatalf("只收到 %d 个包,期望 3 个 —— 一批里的包被吞了", len(got))
		}
	}
	for i, want := range [][]byte{{0x45, 1, 1, 1}, {0x45, 2, 2}, {0x45, 3}} {
		if string(got[i]) != string(want) {
			t.Errorf("第 %d 个包 = %v,期望 %v(长度也必须对,否则收到的是截断包)", i+1, got[i], want)
		}
	}
	dev.Close()
	awaitClosed(t, done, "tunReadLoop")
}

// TestTunReadLoop_ClampsAZeroBatchSize 驱动报 batchSize 0 时不能算出零长切片 —— 那样一个包都读不到,
// 上行彻底不通,而循环本身跑得很欢。
func TestTunReadLoop_ClampsAZeroBatchSize(t *testing.T) {
	withTestGlobalContext(t)
	rc, _ := withTestTunChans(t, 8, 8)

	dev := newScriptedTUN(0)
	dev.pushRead([]byte{0x45, 9})
	done := startLoop(t, "tunReadLoop", func() { tunReadLoop(dev) })

	select {
	case pkt := <-rc:
		if pkt.N != 2 {
			t.Errorf("N = %d,期望 2", pkt.N)
		}
		tunReadBufPool.Put(pkt.Buf)
		tunPacketPool.Put(pkt)
	case <-time.After(5 * time.Second):
		t.Fatal("batchSize=0 时应夹取成 1 并照常读包,现在一个包都没来 —— 上行彻底不通")
	}
	dev.Close()
	awaitClosed(t, done, "tunReadLoop")
}

// poolWatch 换掉两个包级 pool,数「新建了多少个对象」。
//
// 归还与否本身看不见(sync.Pool 不提供计数),但可以从**新建次数**侧面观测:归还了的话紧接着的
// Get 会拿回刚放进去的那个,New 几乎不被调用;没归还就是每次都新建。这是唯一能把「池化泄漏」
// 变成断言的办法 —— 而这种泄漏在生产里只表现为内存一路涨到 OOM,现场看起来只是「丢过一些包」。
type poolWatch struct {
	newBufs atomic.Int64
	newPkts atomic.Int64
}

// quietLogs 把日志压到 Error 级。这不是为了输出干净:丢包路径每次都打 Warn,几百条日志的
// 分配会反复触发 GC,而 GC 每轮都清空 sync.Pool —— 计数就从「归还与否」变成了「GC 跑了几次」。
func quietLogs(t *testing.T) {
	t.Helper()
	prev := logrus.GetLevel()
	logrus.SetLevel(logrus.ErrorLevel)
	t.Cleanup(func() { logrus.SetLevel(prev) })
}

func withCountingTunPools(t *testing.T) *poolWatch {
	t.Helper()
	w := &poolWatch{}
	tunReadBufPool = sync.Pool{New: func() interface{} {
		w.newBufs.Add(1)
		return make([]byte, tunBufSize)
	}}
	tunPacketPool = sync.Pool{New: func() interface{} {
		w.newPkts.Add(1)
		return &util.TunPacket{}
	}}
	// sync.Pool 含 noCopy,存不下旧值,所以收尾时按生产的样子重建一对干净的(与 server.go 的
	// 初始化保持一致);池子本来就是可丢弃的缓存,重建不影响任何语义。
	t.Cleanup(func() {
		tunReadBufPool = sync.Pool{New: func() interface{} { return make([]byte, tunBufSize) }}
		tunPacketPool = sync.Pool{New: func() interface{} { return &util.TunPacket{} }}
	})
	return w
}

// TestTunReadLoop_DropsWithoutLeakingWhenTheChannelIsFull 队列满时丢包,但必须把 buffer 还回池子。
//
// 不还池的后果是慢性的:每丢一个包漏一个 2KB buffer,一次拥塞就是几万个 —— 内存一路涨到 OOM,
// 而现场看起来只是「丢过一些包」。丢包本身是有意的(宁可丢也不阻塞整条上行)。
func TestTunReadLoop_DropsWithoutLeakingWhenTheChannelIsFull(t *testing.T) {
	// 计数前先把三处噪声压掉,否则数到的 New 反映的不是「有没有还回池子」:
	//   - sync.Pool 的复用是 per-P 的:Put 进 A 核私有槽而 Get 发生在 B 核就会新建;
	//   - GC 每跑一轮就清空 Pool,而丢包路径每次都打一条 Warn,几百条日志的分配足以
	//     反复触发 GC —— 那时 New 计数几乎等于 GC 次数;
	//   - 剩下一处压不掉:-race 下 sync.Pool.Put 会**故意随机丢掉四分之一**的对象
	//     (race detector 借此暴露 put 之后仍在用的 bug),所以基线本身就有约 25% 的
	//     New。门槛因此定在总包数的一半:容得下这 25%,又与「一个都不还」的 100% 分得开。
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	quietLogs(t)
	withTestGlobalContext(t)
	rc, _ := withTestTunChans(t, 1, 8) // 容量 1:第二个包必然被丢
	watch := withCountingTunPools(t)

	const reads = 200
	const totalPkts = reads * 2 // scriptedTUN 每次读回 2 个包
	dev := newScriptedTUN(2)
	for i := 0; i < reads; i++ {
		dev.pushRead([]byte{0x45, byte(i)}, []byte{0x45, byte(i), 2})
	}
	done := startLoop(t, "tunReadLoop", func() { tunReadLoop(dev) })

	// 拿到第一个包就够了:关键是循环没有卡死、还在继续读(下面 Close 能让它干净退出)。
	select {
	case pkt := <-rc:
		tunReadBufPool.Put(pkt.Buf)
		tunPacketPool.Put(pkt)
	case <-time.After(5 * time.Second):
		t.Fatal("队列满不该让整条上行卡住")
	}
	// 等它把编排的读都消费完(绝大多数都会因为队列满而被丢)。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		dev.mu.Lock()
		left := len(dev.reads)
		dev.mu.Unlock()
		if left == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	dev.Close()
	awaitClosed(t, done, "tunReadLoop")

	// 丢了几百个包,新建的对象数必须远少于包数 —— 丢包路径把 buffer 与包结构都还回去了。
	const limit = totalPkts / 2
	if n := watch.newBufs.Load(); n > limit {
		t.Errorf("丢了约 %d 个包却新建了 %d 个 buffer(上限 %d) —— 丢包路径没把 buffer 还回池子,"+
			"一次拥塞漏几万个 2KB,内存一路涨到 OOM 而现场只看得到「丢过一些包」", totalPkts, n, limit)
	}
	if n := watch.newPkts.Load(); n > limit {
		t.Errorf("新建了 %d 个包结构(上限 %d) —— 丢包路径没把它还回池子", n, limit)
	}
}

// TestTunReadLoop_ExitsOnReadError 读错误是主退出路径(shutdown 时 main 关 dev 让 Read 立刻报错)。
func TestTunReadLoop_ExitsOnReadError(t *testing.T) {
	withTestGlobalContext(t)
	withTestTunChans(t, 8, 8)

	dev := newScriptedTUN(2)
	dev.failReadsWith(errors.New("tun 读崩了"))
	done := startLoop(t, "tunReadLoop", func() { tunReadLoop(dev) })
	awaitClosed(t, done, "tunReadLoop")
}

// TestTunReadLoop_CtxCancelClosesTheDeviceAndUnblocksTheRead 兜底退出路径:ctx 取消时看门狗主动
// 关 dev,让挂在 Read 上的循环立刻返回。没有这条,shutdown 会被一个阻塞的 Read 拖住数秒。
func TestTunReadLoop_CtxCancelClosesTheDeviceAndUnblocksTheRead(t *testing.T) {
	_, cancel := withTestGlobalContext(t)
	withTestTunChans(t, 8, 8)

	dev := newScriptedTUN(2) // 没有编排任何读 → 挂着
	done := startLoop(t, "tunReadLoop", func() { tunReadLoop(dev) })

	cancel()
	awaitClosed(t, done, "tunReadLoop")
	select {
	case <-dev.closed:
	default:
		t.Error("ctx 取消后看门狗应主动关掉设备 —— 否则 shutdown 要等 Read 自己醒")
	}
}

// TestTunWriteLoop_CoalescesQueuedPacketsIntoOneWrite 批量写的意义就在合并 syscall。
// 每包一次 Write 功能上也对,但那是几倍的系统调用开销 —— 高并发下这就是吞吐差距。
func TestTunWriteLoop_CoalescesQueuedPacketsIntoOneWrite(t *testing.T) {
	withTestGlobalContext(t)
	_, wc := withTestTunChans(t, 8, 16)

	dev := newScriptedTUN(4)
	// 先把包排进队列,再起循环 —— 保证它一进来就能看到多个待写包。
	for _, p := range [][]byte{{0x45, 1}, {0x45, 2}, {0x45, 3}} {
		buf := tunPktBufPool.Get().([]byte)
		n := copy(buf, p)
		wc <- buf[:n]
	}
	done := startLoop(t, "tunWriteLoop", func() { tunWriteLoop(dev) })

	deadline := time.Now().Add(5 * time.Second)
	var pkts [][]byte
	var calls int
	for time.Now().Before(deadline) {
		pkts, calls = dev.writtenPackets()
		if len(pkts) >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(pkts) < 3 {
		t.Fatalf("只写下去 %d 个包,期望 3 个 —— 下行丢包", len(pkts))
	}
	for i, want := range [][]byte{{0x45, 1}, {0x45, 2}, {0x45, 3}} {
		if string(pkts[i]) != string(want) {
			t.Errorf("第 %d 个写下去的包 = %v,期望 %v", i+1, pkts[i], want)
		}
	}
	if calls > 2 {
		t.Errorf("3 个已在队列里的包用了 %d 次 Write —— 批量合并没生效,syscall 开销白付", calls)
	}
	tunWriteLoopStop(t, done)
}

// TestTunWriteLoop_KeepsGoingAfterAWriteError 单次写失败不许带走整条下行。
//
// TUN 写失败是常态(队列满、MTU 抖动),错一次就 return 的后果是:这台服务器**所有**客户端从此
// 收不到任何下行包,而链路与心跳照常 —— 会话全部显示在线。
func TestTunWriteLoop_KeepsGoingAfterAWriteError(t *testing.T) {
	withTestGlobalContext(t)
	_, wc := withTestTunChans(t, 8, 16)

	dev := newScriptedTUN(1)
	dev.failWritesWith(errors.New("写 tun 失败"))
	done := startLoop(t, "tunWriteLoop", func() { tunWriteLoop(dev) })

	buf := tunPktBufPool.Get().([]byte)
	wc <- buf[:copy(buf, []byte{0x45, 1})]

	// 等第一次写失败发生。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, calls := dev.writtenPackets(); calls >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 恢复写,再喂一个包:必须还能写下去,说明循环没被一次失败带走。
	dev.failWritesWith(nil)
	buf2 := tunPktBufPool.Get().([]byte)
	wc <- buf2[:copy(buf2, []byte{0x45, 2})]

	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if pkts, _ := dev.writtenPackets(); len(pkts) > 0 {
			if string(pkts[len(pkts)-1]) == string([]byte{0x45, 2}) {
				tunWriteLoopStop(t, done)
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("一次写失败之后就再也写不进去了 —— 全服下行静默变黑洞,而会话全都显示在线")
}

// TestTunWriteLoop_ReservesTheVirtioHeader Linux 的 IFF_VNET_HDR 要求写时前留 virtio 头。
// 少留这几个字节,内核会把包头当成 virtio 头解析 —— 每个下行包都被丢弃或解析错。
func TestTunWriteLoop_ReservesTheVirtioHeader(t *testing.T) {
	withTestGlobalContext(t)
	_, wc := withTestTunChans(t, 8, 16)

	dev := newScriptedTUN(1)
	done := startLoop(t, "tunWriteLoop", func() { tunWriteLoop(dev) })

	payload := []byte{0x45, 0xaa, 0xbb, 0xcc}
	buf := tunPktBufPool.Get().([]byte)
	wc <- buf[:copy(buf, payload)]

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		// 假设 Write 收到的 offset 就是 virtioNetHdrLen:writtenPackets 已按 offset 剥掉头部,
		// 剥完必须恰好等于原始载荷 —— 多剥少剥都会在这里露出来。
		if pkts, _ := dev.writtenPackets(); len(pkts) > 0 {
			if string(pkts[0]) != string(payload) {
				t.Fatalf("按 virtio 头长度剥掉后得到 %v,期望 %v —— 预留的头部长度不对,内核会把包头当 virtio 头解析",
					pkts[0], payload)
			}
			tunWriteLoopStop(t, done)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("包没写下去")
}

// TestTunWriteLoop_ExitsWhenTheChannelClosesOrCtxIsDone 两条退出路径都要能走通,否则 shutdown 挂住。
func TestTunWriteLoop_ExitsWhenTheChannelClosesOrCtxIsDone(t *testing.T) {
	t.Run("队列关闭", func(t *testing.T) {
		withTestGlobalContext(t)
		_, wc := withTestTunChans(t, 8, 16)
		dev := newScriptedTUN(2)
		done := startLoop(t, "tunWriteLoop", func() { tunWriteLoop(dev) })
		close(wc)
		awaitClosed(t, done, "tunWriteLoop")
	})

	t.Run("ctx 取消", func(t *testing.T) {
		_, cancel := withTestGlobalContext(t)
		withTestTunChans(t, 8, 16)
		dev := newScriptedTUN(2)
		done := startLoop(t, "tunWriteLoop", func() { tunWriteLoop(dev) })
		cancel()
		awaitClosed(t, done, "tunWriteLoop")
	})
}

// tunWriteLoopStop 用 ctx 取消把写循环停下(它不看设备关闭,只看 ctx 与队列)。
func tunWriteLoopStop(t *testing.T, done <-chan struct{}) {
	t.Helper()
	if globalContextCancel != nil {
		globalContextCancel()
	}
	awaitClosed(t, done, "tunWriteLoop")
}

// TestDrainAndCloseTunChan_ReturnsEverythingToThePool 关队列时要把在途的包全部归还池子。
// 不归还就是每次 shutdown / 重建队列漏掉队列里那一千多个 2KB buffer。
func TestDrainAndCloseTunChan_ReturnsEverythingToThePool(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1)) // 压掉 per-P 复用噪声,见丢包那条的说明
	watch := withCountingTunPools(t)

	const inflight = 64
	ch := make(chan *util.TunPacket, inflight+2)
	for i := 0; i < inflight; i++ {
		pkt := tunPacketPool.Get().(*util.TunPacket)
		pkt.Buf = tunReadBufPool.Get().([]byte)
		pkt.N = 1
		ch <- pkt
	}
	ch <- nil // 容忍 nil 项:排空时对它做解引用会 panic 在 shutdown 路径上
	createdBefore := watch.newBufs.Load()

	drainAndCloseTunChan(ch)

	if _, ok := <-ch; ok {
		t.Error("排空后队列里还有东西")
	}

	// 排空归还之后再取同样多的对象:该基本全从池子里来,新建次数不该再明显增长。
	reused := make([][]byte, 0, inflight)
	for i := 0; i < inflight; i++ {
		reused = append(reused, tunReadBufPool.Get().([]byte))
	}
	// 上限取一半而不是「个位数」:-race 下 sync.Pool.Put 会故意随机丢掉四分之一的对象,
	// 基线本身就有约 25% 的新建(详见丢包那条的说明)。一半仍与「全不归还」的 100% 分得开。
	if grew := watch.newBufs.Load() - createdBefore; grew > inflight/2 {
		t.Errorf("排空 %d 个在途包后再取同样多,却新建了 %d 个 buffer(上限 %d) —— 排空路径没归还,"+
			"每次 shutdown / 重建队列都漏掉队列里那上千个 2KB", inflight, grew, inflight/2)
	}
	for _, b := range reused {
		tunReadBufPool.Put(b)
	}
}
