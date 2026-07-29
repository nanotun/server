package main

import (
	"net"
	"testing"
	"time"
)

// /health 反射的是 TUN / store 的就绪状态。这个信息对扫描器很有用:它标出了这台机器什么时候处在
// 故障窗口里(故障期的服务更容易被撞开),也直接暴露「这是一台 nanotun server」这一指纹。
// 所以非环回地址默认拒启,只留一个显式环境变量作为逃生口 —— 有运维真的把它误配成 0.0.0.0 过。
//
// 三种输入必须各自成立:空地址 = 不启用(不是「用默认端口启动」);解析不出的地址 = 不启动但也
// 不能让整个 server 起不来(健康检查丢了不该阻塞业务);非环回 = 拒启,除非显式放行。
// 每种情况都要返回一个可调用的 cleanup —— main 里那条 defer 链拿到 nil 会直接 panic。

// TestStartHealthHTTPServer_RefusesToExposeReadinessToTheWorld 非环回默认拒启,显式放行才开。
func TestStartHealthHTTPServer_RefusesToExposeReadinessToTheWorld(t *testing.T) {
	gw := &gatewayState{}

	t.Run("非环回:默认拒启", func(t *testing.T) {
		t.Setenv(healthAllowPublicEnv, "")
		port := freeLoopbackPort(t)
		cleanup := startHealthHTTPServer("0.0.0.0:"+port, gw)
		if cleanup == nil {
			t.Fatal("返回了 nil cleanup —— main 里那条 defer 链会当场 panic")
		}
		defer cleanup()

		// 拒启就该没有人在听这个端口。
		if listening(t, "127.0.0.1:"+port) {
			t.Fatal("非环回地址上真把 /health 起来了 —— TUN/store 就绪状态被反射到公网,扫描器据此做指纹与故障窗口识别")
		}
	})

	t.Run("非环回:显式放行后才启动", func(t *testing.T) {
		t.Setenv(healthAllowPublicEnv, "1")
		port := freeLoopbackPort(t)
		cleanup := startHealthHTTPServer("0.0.0.0:"+port, gw)
		defer cleanup()
		waitListening(t, "127.0.0.1:"+port)
	})
}

// TestStartHealthHTTPServer_BadInputIsANoopNotAFailure 空地址与畸形地址都只是不启用。
func TestStartHealthHTTPServer_BadInputIsANoopNotAFailure(t *testing.T) {
	gw := &gatewayState{}
	for name, addr := range map[string]string{
		"没有端口":  "127.0.0.1",
		"解析不出来": "[::1:8081",
	} {
		t.Run(name, func(t *testing.T) {
			cleanup := startHealthHTTPServer(addr, gw)
			if cleanup == nil {
				t.Fatal("返回了 nil cleanup —— main 的 defer 链会 panic,一个可选的探活端点把整台 server 带下去")
			}
			cleanup() // 重复调用也必须安全
			cleanup()
		})
	}

	// 空地址是「运维明确关掉」,不是「用默认端口启动」。区别只在这一处能看出来:
	// 调用之后默认端口必须仍然空着 —— 否则一个被关掉的端点自己开了起来,而日志里写的是「未启用」。
	t.Run("空地址:默认端口仍空着", func(t *testing.T) {
		const defaultHealthAddr = "127.0.0.1:8081"
		probe, err := net.Listen("tcp", defaultHealthAddr)
		if err != nil {
			t.Skipf("默认端口已被别的进程占用,这条断言无从判断: %v", err)
		}
		_ = probe.Close()

		cleanup := startHealthHTTPServer("   ", gw)
		if cleanup == nil {
			t.Fatal("返回了 nil cleanup —— main 的 defer 链会 panic")
		}
		defer cleanup()

		// 真起服务是在一条 goroutine 里 bind 的,立刻探一次可能早于它 —— 轮询一小会儿。
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) {
			again, err := net.Listen("tcp", defaultHealthAddr)
			if err != nil {
				t.Fatalf("空地址下默认端口被占上了(%v)—— 运维明确关掉的探活端点自己开了起来,而日志说的是「未启用」", err)
			}
			_ = again.Close()
			time.Sleep(20 * time.Millisecond)
		}
	})
}

// TestStartHealthHTTPServer_CleanupStopsServing cleanup 之后端口必须真的放开。
//
// 不放开的表现是重启时 bind 失败:上一个进程的 listener 还挂着,新进程的 /health 起不来,
// 而这条失败只是一行 Warn —— 探活端点从此静默缺失,监控侧看到的是「一直没数据」。
func TestStartHealthHTTPServer_CleanupStopsServing(t *testing.T) {
	gw := &gatewayState{}
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port

	cleanup := startHealthHTTPServer(addr, gw)
	waitListening(t, addr)
	cleanup()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !listening(t, addr) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cleanup 之后端口还被占着 —— 下次启动 bind 失败,而那只是一行 Warn,探活端点从此静默缺失")
}

// freeLoopbackPort 借一个空闲端口号(立刻还掉,只取号)。
func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	return port
}

func listening(t *testing.T, addr string) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if listening(t, addr) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s 上没人在听 —— /health 没起来", addr)
}
