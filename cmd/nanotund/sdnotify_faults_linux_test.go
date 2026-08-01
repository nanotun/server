package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// sd_notify 这一侧此前一条语句都没跑过 —— 单测在 macOS 上不编译这个文件,e2e 又只
// 覆盖「systemd 正常」的happy path。
//
// 它值得被钉住,因为失效方式是**静默**的:
//   - READY=1 发不出去 → systemd 卡在 activating,超时后判定启动失败并重启,循环;
//   - 心跳该发不发 → systemd WatchdogSec 到点 SIGTERM,服务被莫名重启;
//   - 心跳**不该发却发了** → 这是最坏的一种。看门狗的全部意义是「进程卡死时自愈」,
//     若某个继承了 socket 的进程替真正的主进程发心跳,systemd 会一直认为一切正常,
//     而主进程其实已经死锁 —— 保护机制在场,但不起作用,且没有任何告警。
//     WATCHDOG_PID 检查就是拦这个的,本文件里那条用例是这批里最要紧的。
//
// 这些全靠环境变量驱动,`t.Setenv` + 一个真的 unixgram socket 就够,不需要改生产代码。

// resetNotifyState 清掉包级的一次性初始化状态。
//
// initNotify 用 sync.Once 缓存连接(生产上进程内只需一条),于是同一个测试二进制里
// 第一个用例的 NOTIFY_SOCKET 会把后面所有用例都锁死。同包白盒测试直接把它复位。
func resetNotifyState(t *testing.T) {
	t.Helper()
	reset := func() {
		if notifyConn != nil {
			_ = notifyConn.Close()
		}
		notifyOnce = sync.Once{}
		notifyConn = nil
		notifyAddr = nil
		notifyErr = nil
	}
	reset()
	t.Cleanup(reset)
}

// notifySink 起一个真的 unixgram 服务端,把收到的报文送进 channel。
type notifySink struct {
	addr string
	msgs chan string
}

func newNotifySink(t *testing.T, abstract bool) *notifySink {
	t.Helper()

	var ua *net.UnixAddr
	var shown string
	if abstract {
		// abstract socket 不占文件系统,名字前缀是 NUL;NOTIFY_SOCKET 里用 '@' 表示。
		name := fmt.Sprintf("nanotun-test-%d-%s", os.Getpid(), t.Name())
		name = strings.NewReplacer("/", "_", " ", "_").Replace(name)
		ua = &net.UnixAddr{Net: "unixgram", Name: "\x00" + name}
		shown = "@" + name
	} else {
		// unix 路径有 ~108 字节上限,t.TempDir() 在部分环境下会超,自己挑短路径。
		dir, err := os.MkdirTemp("", "sdn")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		p := filepath.Join(dir, "n.sock")
		ua = &net.UnixAddr{Net: "unixgram", Name: p}
		shown = p
	}

	conn, err := net.ListenUnixgram("unixgram", ua)
	if err != nil {
		t.Skipf("本环境起不了 unixgram socket(%v),跳过 sd_notify 用例", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	s := &notifySink{addr: shown, msgs: make(chan string, 256)}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			select {
			case s.msgs <- string(buf[:n]):
			default: // 满了就丢,用例只关心前几条
			}
		}
	}()
	return s
}

// waitFor 等一条含 want 的报文。
func (s *notifySink) waitFor(t *testing.T, want string, d time.Duration) bool {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case m := <-s.msgs:
			if strings.Contains(m, want) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func (s *notifySink) countWithin(d time.Duration) int {
	n := 0
	deadline := time.After(d)
	for {
		select {
		case <-s.msgs:
			n++
		case <-deadline:
			return n
		}
	}
}

// TestSDNotify_NoSocketMeansDisabled 没跑在 systemd 下时必须安静地什么都不做。
//
// 手动跑二进制、容器里跑、e2e 里跑 —— 都没有 NOTIFY_SOCKET。这条路径 panic 或阻塞
// 的话,影响的是所有非 systemd 部署。
func TestSDNotify_NoSocketMeansDisabled(t *testing.T) {
	resetNotifyState(t)
	t.Setenv("NOTIFY_SOCKET", "")
	t.Setenv("WATCHDOG_USEC", "1000000")

	sdNotifyReady()    // 不 panic 即通过
	sdNotifyStopping() // 同上
	if startSDWatchdog(context.Background()) {
		t.Error("没有 NOTIFY_SOCKET 却报告看门狗已启用 —— 会让人以为有自愈保护")
	}
}

// TestSDNotify_ReadyAndStoppingReachSystemd READY / STOPPING 要真的送达。
func TestSDNotify_ReadyAndStoppingReachSystemd(t *testing.T) {
	resetNotifyState(t)
	sink := newNotifySink(t, false)
	t.Setenv("NOTIFY_SOCKET", sink.addr)

	sdNotifyReady()
	if !sink.waitFor(t, "READY=1", 3*time.Second) {
		t.Fatal("systemd 没收到 READY=1 —— Type=notify 下服务会卡在 activating 直到超时重启")
	}
	sdNotifyStopping()
	if !sink.waitFor(t, "STOPPING=1", 3*time.Second) {
		t.Error("没收到 STOPPING=1 —— systemctl status 在停服期间显示不出 deactivating")
	}
}

// TestSDNotify_AbstractSocketAddressIsTranslated '@' 前缀要翻成 NUL 开头的抽象地址。
//
// systemd 现在默认给的就是抽象地址。把 '@' 当普通路径用的话,会去文件系统里找一个
// 叫 "@xxx" 的文件,必然失败 —— 于是所有 notify 静默失效,而日志只有一行 Debug。
func TestSDNotify_AbstractSocketAddressIsTranslated(t *testing.T) {
	resetNotifyState(t)
	sink := newNotifySink(t, true)
	t.Setenv("NOTIFY_SOCKET", sink.addr)

	sdNotifyReady()
	if notifyErr != nil {
		t.Fatalf("抽象地址 %q 连不上:%v", sink.addr, notifyErr)
	}
	if notifyAddr == nil || !strings.HasPrefix(notifyAddr.Name, "\x00") {
		t.Fatalf("抽象地址应翻成 NUL 前缀,实得 %q", func() string {
			if notifyAddr == nil {
				return "<nil>"
			}
			return notifyAddr.Name
		}())
	}
	if !sink.waitFor(t, "READY=1", 3*time.Second) {
		t.Error("抽象地址上没收到 READY=1")
	}
}

// TestSDNotify_UnreachableSocketIsNotFatal socket 存在但没人收时不能崩。
func TestSDNotify_UnreachableSocketIsNotFatal(t *testing.T) {
	resetNotifyState(t)
	dir, err := os.MkdirTemp("", "sdn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("NOTIFY_SOCKET", filepath.Join(dir, "nobody-listening.sock"))

	sdNotifyReady()
	sdNotifyStopping()
	if startSDWatchdog(context.Background()) {
		t.Error("连不上 socket 却报告看门狗已启用")
	}
}

// TestSDWatchdog_RefusesWhenWatchdogPidIsNotUs 这条是本文件里最要紧的。
//
// WATCHDOG_PID 是 systemd 指定的「该发心跳的进程」。若本进程不是它却照发,
// systemd 就会一直认为被监护的进程还活着 —— 看门狗形同虚设,而且是静默的:
// 真正的主进程死锁时不会有任何人发现,因为心跳一直在。
func TestSDWatchdog_RefusesWhenWatchdogPidIsNotUs(t *testing.T) {
	resetNotifyState(t)
	sink := newNotifySink(t, false)
	t.Setenv("NOTIFY_SOCKET", sink.addr)
	t.Setenv("WATCHDOG_USEC", "200000") // 0.2s
	t.Setenv("WATCHDOG_PID", fmt.Sprintf("%d", os.Getpid()+1))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if startSDWatchdog(ctx) {
		t.Fatal("WATCHDOG_PID 指的不是本进程,却启用了心跳 —— 看门狗会被这个进程「代打卡」而失效")
	}
	if n := sink.countWithin(600 * time.Millisecond); n != 0 {
		t.Errorf("不该发心跳却发了 %d 条", n)
	}
}

// TestSDWatchdog_RunsWhenPidMatches 反面锚点:PID 对得上时心跳必须真的发出去。
//
// 没有这条,一个「永远 return false」的实现能让上面几条全绿,而看门狗从此不工作。
func TestSDWatchdog_RunsWhenPidMatches(t *testing.T) {
	resetNotifyState(t)
	sink := newNotifySink(t, false)
	t.Setenv("NOTIFY_SOCKET", sink.addr)
	t.Setenv("WATCHDOG_USEC", "2000000") // 2s → 间隔 1s
	t.Setenv("WATCHDOG_PID", fmt.Sprintf("%d", os.Getpid()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !startSDWatchdog(ctx) {
		t.Fatal("PID 匹配且 USEC 合法,看门狗却没启用")
	}
	if !sink.waitFor(t, "WATCHDOG=1", 4*time.Second) {
		t.Fatal("没收到心跳 —— systemd 会在 WatchdogSec 到点时 SIGTERM 重启本服务")
	}
}

// TestSDWatchdog_StopsOnContextCancel ctx 取消后心跳必须停。
//
// 停不下来的话,graceful shutdown 期间进程还在给 systemd 报「我很好」。
func TestSDWatchdog_StopsOnContextCancel(t *testing.T) {
	resetNotifyState(t)
	sink := newNotifySink(t, false)
	t.Setenv("NOTIFY_SOCKET", sink.addr)
	t.Setenv("WATCHDOG_USEC", "2000000")
	t.Setenv("WATCHDOG_PID", fmt.Sprintf("%d", os.Getpid()))

	ctx, cancel := context.WithCancel(context.Background())
	if !startSDWatchdog(ctx) {
		t.Fatal("看门狗没启用")
	}
	if !sink.waitFor(t, "WATCHDOG=1", 4*time.Second) {
		t.Fatal("启用后没收到心跳")
	}
	cancel()
	time.Sleep(200 * time.Millisecond)
	_ = sink.countWithin(50 * time.Millisecond) // 排空取消前在途的那条
	if n := sink.countWithin(2500 * time.Millisecond); n != 0 {
		t.Errorf("ctx 取消后仍发了 %d 条心跳 —— 停服过程中还在向 systemd 报平安", n)
	}
}

// TestSDWatchdog_RejectsUnusableWatchdogUsec USEC 缺失 / 非数字 / 非正数一律不启用。
//
// 关键是「不启用」而不是「按某个默认值启用」:猜一个间隔的话,猜大了 systemd 先超时
// 重启,猜小了白烧 CPU,两种都比明确不启用差。
func TestSDWatchdog_RejectsUnusableWatchdogUsec(t *testing.T) {
	for _, tc := range []struct{ desc, usec string }{
		{"未设置", ""},
		{"非数字", "abc"},
		{"零", "0"},
		{"负数", "-1000000"},
		{"溢出 int64", "99999999999999999999"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			resetNotifyState(t)
			sink := newNotifySink(t, false)
			t.Setenv("NOTIFY_SOCKET", sink.addr)
			t.Setenv("WATCHDOG_USEC", tc.usec)
			t.Setenv("WATCHDOG_PID", "")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if startSDWatchdog(ctx) {
				t.Errorf("WATCHDOG_USEC=%q 不可用,却启用了看门狗", tc.usec)
			}
		})
	}
}

// TestSDWatchdog_IntervalHasOneSecondFloor 极小的 WatchdogSec 也不能把心跳打成风暴。
//
// USEC=1000(1ms)时若不设下限,间隔就是 0.5ms —— 每秒两千次 socket 写入,纯烧 CPU。
// 这里用「1.5 秒内不超过 10 条」判断:有下限时约 1~2 条,没下限时是三千条量级,
// 边界拉得很开,不会因为调度抖动误报。
func TestSDWatchdog_IntervalHasOneSecondFloor(t *testing.T) {
	resetNotifyState(t)
	sink := newNotifySink(t, false)
	t.Setenv("NOTIFY_SOCKET", sink.addr)
	t.Setenv("WATCHDOG_USEC", "1000") // 1ms
	t.Setenv("WATCHDOG_PID", fmt.Sprintf("%d", os.Getpid()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !startSDWatchdog(ctx) {
		t.Fatal("看门狗没启用")
	}
	if n := sink.countWithin(1500 * time.Millisecond); n > 10 {
		t.Errorf("1.5 秒内发了 %d 条心跳,间隔下限(1s)没生效", n)
	}
}
