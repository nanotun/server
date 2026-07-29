package main

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// panic 兜底这一层是「一条连接挂掉」与「整机瞬断」之间唯一的隔离。它有两个方向都不能错:
//
//   - per-connection 的 panic 不许升级成进程退出。Go 的默认行为是任何 goroutine panic 直接
//     终止进程 —— 一个畸形包打崩一条连接的处理 goroutine,全部在线用户同时掉线,而且
//     cleanupConnection 也不会跑:vIP 占用位、connIDMap、TunChan 全留在内存里陪着进程一起死。
//   - 关键全局 goroutine(TUN 读写、demux、保活)的 panic 反过来**必须**升级成 graceful shutdown。
//     只 recover 不做别的更糟:进程还活着、监控绿着、systemd 不会拉起新实例,而数据面已经停了 ——
//     客户端连得上、包不通,没有任何一条日志说破。

// TestSafeGoroutine_APanicStaysInsideOneConnection per-connection panic 只记日志,不外溢。
func TestSafeGoroutine_APanicStaysInsideOneConnection(t *testing.T) {
	hook := &countingLogHook{levels: []logrus.Level{logrus.ErrorLevel}}
	logrus.AddHook(hook)
	t.Cleanup(func() { hook.mu.Lock(); hook.levels = []logrus.Level{logrus.PanicLevel}; hook.mu.Unlock() })

	var done sync.WaitGroup
	done.Add(1)
	go safeGoroutine("test/one-connection", func() {
		defer done.Done()
		panic("畸形包打崩了这条连接")
	})
	done.Wait()

	// 走到这里就说明 panic 没有掀翻测试进程 —— 这正是生产里「一条连接挂 ≠ 全站掉线」。
	// 注意 fn 里的 defer 先跑,recover 与那条日志在它之后,所以要等一下再数。
	deadline := time.Now().Add(2 * time.Second)
	for hook.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := hook.count(); got != 1 {
		t.Fatalf("捕获 panic 后记了 %d 条 Error,want 1 —— 静默 recover 等于这条连接凭空消失,没人知道为什么", got)
	}
	// 日志里必须带 goroutine 名字与堆栈:少了名字就不知道是哪条路径挂的,
	// 少了堆栈只能看到「有东西 panic 过」,而 panic 一般不可复现。
	hook.mu.Lock()
	msg := strings.Join(hook.msgs, "\n")
	hook.mu.Unlock()
	if !strings.Contains(msg, "panic") {
		t.Errorf("日志里没写清是 panic: %q", msg)
	}

	// 正常返回的 fn 不该留下任何 Error。
	safeGoroutine("test/clean", func() {})
	time.Sleep(20 * time.Millisecond)
	if got := hook.count(); got != 1 {
		t.Errorf("正常返回也记了 Error(累计 %d 条)", got)
	}
}

// TestSafeGlobalGoroutine_APanicTriggersGracefulShutdown 关键 goroutine panic 必须触发收尾。
func TestSafeGlobalGoroutine_APanicTriggersGracefulShutdown(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	var done sync.WaitGroup
	done.Add(1)
	go safeGlobalGoroutine("test/tun-read", func() { cancelled <- struct{}{} }, func() {
		defer done.Done()
		panic("TUN 读循环挂了")
	})
	done.Wait()

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("关键 goroutine panic 后没有触发 graceful shutdown —— 进程还活着、监控绿着、" +
			"systemd 不会换新实例,而数据面已经停了:客户端连得上、包不通")
	}

	// cancel 为 nil 时不许再 panic 一次(那会绕过 recover 直接带走进程)。
	var second sync.WaitGroup
	second.Add(1)
	go safeGlobalGoroutine("test/no-cancel", nil, func() {
		defer second.Done()
		panic("没有注入 cancel")
	})
	second.Wait()

	// 正常返回不该触发关机 —— 否则每个正常退出的后台循环都会顺手把整机拉下来。
	var third sync.WaitGroup
	third.Add(1)
	go safeGlobalGoroutine("test/normal-exit", func() { cancelled <- struct{}{} }, func() {
		defer third.Done()
	})
	third.Wait()
	select {
	case <-cancelled:
		t.Fatal("正常返回也触发了 graceful shutdown —— 任何后台循环收尾都会把整机带下来")
	case <-time.After(100 * time.Millisecond):
	}
}
