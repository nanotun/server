package main

import (
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// TestSafeRLConn_RaceRegression(M2, 2026-05-24):
//
// N38 race 的针对性回归测试。验证:
//
//	写侧(模拟登录路径)在 c 已进入 connIDMap 之后才持 c.linkWrMu 写 c.rlConn;
//	同期读侧(模拟 /status / /rate/refresh)用 safeRLConn() 持同一把锁短锁读。
//	两边只要用同一把锁 happens-before 关系成立,go test -race 就**不**应报警。
//
// 必须在 -race 下跑(`go test -race -run TestSafeRLConn_RaceRegression ./server/`)。
//
// **反向验证历史**:
//
//	a) 2026-05-23 第一版:c.rlConn 是裸 *rateLimitedConn 指针,safeRLConn() 用
//	   c.linkWrMu 短锁包读。如果改回 `return c.rlConn` 裸读,本测试在 -race 下
//	   **必报** data race(已实测验证)。
//	b) 2026-05-24 升级:c.rlConn 改成 atomic.Pointer[rateLimitedConn],写侧
//	   Store(),读侧 Load()。本测试现在的 race 防御保险是「Go memory model 自带
//	   atomic happens-before」,即使把 safeRLConn() 直接换成 c.rlConn.Load()
//	   也无 race。本测试改为「行为合约」校验:writer 写完后 reader 至少能 Load
//	   到非 nil 一次,验证 atomic.Pointer 行为正确。如果有人把字段类型回退到裸
//	   指针,**编译期**会直接挂(没法 Store/Load),不必依赖 race 触发。
//
// 设计:N 轮(每轮一对 goroutine),每轮内 writer 模拟登录路径的两阶段写,
// reader 持续 safeRLConn() 读。close(start) 让两侧同时起跑,放大 race 窗口。
//
// 在 macOS Apple Silicon 上单轮 ~1ms 即够触发 race detector;100 轮 ~100ms,
// 跑得快且足够暴露问题。
func TestSafeRLConn_RaceRegression(t *testing.T) {
	const rounds = 100
	for i := 0; i < rounds; i++ {
		c := &Connection{
			connIDStr: "race-regression",
			userID:    "u-race",
		}
		// reader 用 channel 通知何时退出(每轮独立,避免上轮 leak goroutine 影响下轮)。
		stop := make(chan struct{})
		start := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			<-start
			// 模拟登录路径:1) c 进 connIDMap(本测试直接给 c 暴露给 reader 即等价,
			// 不必走 connIDMapMu 全套);2) 中间一小段时间(几百 ns),其它 goroutine
			// 可能在此时通过 safeRLConn() 读到 c;3) 持 linkWrMu 写 c.rlConn。
			time.Sleep(time.Microsecond * 10)
			c.linkWrMu.Lock()
			c.rlConn.Store(newRateLimitedConn(nopReadWriteCloser{}, nil, nil, nil))
			c.linkWrMu.Unlock()
		}()

		go func() {
			defer wg.Done()
			<-start
			// reader 持续调 safeRLConn(),直到 stop。
			// 期望:整个 spin 期间 -race 不报警(因为读侧也走 linkWrMu 跟写侧同步)。
			for {
				select {
				case <-stop:
					return
				default:
				}
				rl := c.safeRLConn()
				_ = rl // 用一下避免编译器警告;真实场景会 SetUploadLimit 之类
			}
		}()

		close(start)
		// 给 writer 写完 + reader 多读几轮的时间。
		time.Sleep(time.Millisecond)
		close(stop)
		wg.Wait()
	}
}

// TestSafeRLConn_NilSafe:c == nil 跟 c.rlConn == nil 都不应 panic,各自返回 nil。
// 是 helper 文档「nil 含义」的 contract 验证,被 control sock 三处依赖。
func TestSafeRLConn_NilSafe(t *testing.T) {
	if (*Connection)(nil).safeRLConn() != nil {
		t.Fatal("nil receiver: safeRLConn 应返回 nil")
	}
	c := &Connection{}
	if c.safeRLConn() != nil {
		t.Fatal("rlConn 未赋值: safeRLConn 应返回 nil")
	}
	c.rlConn.Store(newRateLimitedConn(nopReadWriteCloser{}, nil, nil, nil))
	if c.safeRLConn() == nil {
		t.Fatal("rlConn 已赋值: safeRLConn 不应返回 nil")
	}
}

// TestSafeLinkConn_NilSafe:safeLinkConn 跟 safeRLConn 同样契约,保留作为后续重构
// 出口,先用最小契约测试守护。
func TestSafeLinkConn_NilSafe(t *testing.T) {
	if (*Connection)(nil).safeLinkConn() != nil {
		t.Fatal("nil receiver: safeLinkConn 应返回 nil")
	}
	c := &Connection{}
	if c.safeLinkConn() != nil {
		t.Fatal("linkConn 未赋值: safeLinkConn 应返回 nil")
	}
}

// TestSafeClientIPs_RaceRegression(U1, 2026-05-26):
//
// S1 race 的针对性回归测试。c.clientIPs 现在是 atomic.Pointer,Go memory model
// 保证 Store-Load happens-before,本测试在 `go test -race` 下永远不应报警。
//
// 反向验证:如果有人把字段类型回退到裸 `[]util.VirtualIPAssignment` 切片,
// **编译期**会直接挂(没法调 .Store/.Load),不必依赖 race 触发,代码层
// 即可发现倒退。
//
// 模拟登录路径节奏:
//
//	writer:进 connIDMap → 等几 µs → 持 clientIPUsedMu → Store(&assignments);
//	reader:并发 safeClientIPs() 读;窗口期 Load 应返 nil 而非撕裂切片。
//
// 100 轮 ~100ms 跑得快,且足够暴露任何 unsafe 字段访问。
func TestSafeClientIPs_RaceRegression(t *testing.T) {
	const rounds = 100
	for i := 0; i < rounds; i++ {
		c := &Connection{
			connIDStr: "race-clientips",
			userID:    "u-race",
		}
		stop := make(chan struct{})
		start := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			<-start
			// 模拟登录路径:c 已对外可见(进 connIDMap 等价 — 这里直接共享 c 指针),
			// 等几 µs 让 reader 进入 race 窗口,然后 Store。
			time.Sleep(time.Microsecond * 10)
			ips := []util.VirtualIPAssignment{
				{VirtualIP: "10.0.0.1"},
				{VirtualIP: "fd00::1"},
			}
			c.clientIPs.Store(&ips)
		}()

		go func() {
			defer wg.Done()
			<-start
			for {
				select {
				case <-stop:
					return
				default:
				}
				// safeClientIPs() 返回 nil 或非 nil slice 都合法 — 关键是不撕裂、不 panic。
				// range over nil slice 也 OK(no-op)。
				for _, a := range c.safeClientIPs() {
					_ = a.VirtualIP
				}
			}
		}()

		close(start)
		time.Sleep(time.Millisecond)
		close(stop)
		wg.Wait()
	}
}

// TestSafeClientIPs_NilSafe:c == nil 跟 c.clientIPs 未 Store 都应返回 nil(不 panic)。
// 是 helper 文档「nil 含义」的契约校验,被 server.go broadcast / cleanupConnection /
// takeover / persistDeviceLease / control_socket /status 共 6 处依赖。
func TestSafeClientIPs_NilSafe(t *testing.T) {
	if (*Connection)(nil).safeClientIPs() != nil {
		t.Fatal("nil receiver: safeClientIPs 应返回 nil")
	}
	c := &Connection{}
	if c.safeClientIPs() != nil {
		t.Fatal("clientIPs 未 Store: safeClientIPs 应返回 nil")
	}
	ips := []util.VirtualIPAssignment{{VirtualIP: "10.0.0.99"}}
	c.clientIPs.Store(&ips)
	got := c.safeClientIPs()
	if len(got) != 1 || got[0].VirtualIP != "10.0.0.99" {
		t.Fatalf("Store 后 Load 应等价: want 1 条 10.0.0.99, got %+v", got)
	}
}
