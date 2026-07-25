package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

// callHysteriaOrder 按 hysteria v2.9.2 server.handleTCPRequest 的真实顺序驱动 relay:
//
//	RequestHook.TCP(stream, &reqAddr) → EventLogger.TCPRequest(addr, id, reqAddr) → Outbound 取用
//
// 关联的正确性完全依赖这个顺序,所以测试必须照抄它,而不是直接调 put/Take。
func callHysteriaOrder(t *testing.T, r *hy2ClientAddrRelay, clientAddr net.Addr, origReq string) net.Addr {
	t.Helper()
	reqAddr := origReq
	if !r.Check(false, reqAddr) {
		t.Fatalf("Check 应接管 TCP 请求")
	}
	putback, err := r.TCP(nil, &reqAddr)
	if err != nil {
		t.Fatalf("RequestHook.TCP: %v", err)
	}
	if putback != nil {
		t.Fatalf("不应窥探客户端首包(putback 必须为 nil),得到 %d 字节", len(putback))
	}
	if reqAddr == origReq {
		t.Fatalf("reqAddr 未被改写:%q", reqAddr)
	}
	r.TCPRequest(clientAddr, "user", reqAddr)
	return r.Take(reqAddr)
}

func TestHy2ClientAddrRelay_PropagatesRealAddr(t *testing.T) {
	r := newHy2ClientAddrRelay()
	want := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51234}

	got := callHysteriaOrder(t, r, want, "example.com:443")
	if got == nil {
		t.Fatal("未取到真实客户端地址(会退回 LOCAL 头 → 全部 hy2 客户端塌到 127.0.0.1)")
	}
	if got.String() != want.String() {
		t.Fatalf("地址不符: got %s want %s", got, want)
	}
	// 取用即消费:不留悬挂条目。
	if n := r.pendingLenForTest(); n != 0 {
		t.Fatalf("token 泄漏,pending=%d", n)
	}
}

// 并发多客户端不能串味 —— 这是「不用 goroutine-local、靠一次性 token 关联」的核心正确性主张。
func TestHy2ClientAddrRelay_ConcurrentClientsDoNotCrossTalk(t *testing.T) {
	r := newHy2ClientAddrRelay()
	const n = 200

	var wg sync.WaitGroup
	errCh := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 每个「客户端」一个独立 IP,断言取回的正是自己的。
			want := &net.TCPAddr{IP: net.IPv4(198, 51, 100, byte(i%256)), Port: 40000 + i}
			reqAddr := fmt.Sprintf("host-%d:443", i)
			if !r.Check(false, reqAddr) {
				errCh <- "Check 未接管"
				return
			}
			if _, err := r.TCP(nil, &reqAddr); err != nil {
				errCh <- "hook: " + err.Error()
				return
			}
			r.TCPRequest(want, "user", reqAddr)
			got := r.Take(reqAddr)
			if got == nil || got.String() != want.String() {
				errCh <- fmt.Sprintf("串味: got %v want %v", got, want)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Fatal(msg)
	}
	if got := r.pendingLenForTest(); got != 0 {
		t.Fatalf("并发后仍有残留 token: %d", got)
	}
}

// 每条 stream 的 token 必须唯一,否则并发客户端会互相覆盖地址。
func TestHy2ClientAddrRelay_TokensAreUnique(t *testing.T) {
	r := newHy2ClientAddrRelay()
	seen := make(map[string]bool, 512)
	for i := 0; i < 512; i++ {
		reqAddr := "same-target:443"
		if _, err := r.TCP(nil, &reqAddr); err != nil {
			t.Fatalf("hook: %v", err)
		}
		if seen[reqAddr] {
			t.Fatalf("token 重复: %s", reqAddr)
		}
		seen[reqAddr] = true
	}
}

// dial 失败路径(hysteria 会调 TCPError)必须把 token 清掉,不能等 TTL 才回收。
func TestHy2ClientAddrRelay_TCPErrorReleasesToken(t *testing.T) {
	r := newHy2ClientAddrRelay()
	reqAddr := "example.com:443"
	if _, err := r.TCP(nil, &reqAddr); err != nil {
		t.Fatalf("hook: %v", err)
	}
	r.TCPRequest(&net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1234}, "user", reqAddr)
	if r.pendingLenForTest() != 1 {
		t.Fatalf("应已记录 1 条,得到 %d", r.pendingLenForTest())
	}
	r.TCPError(nil, "user", reqAddr, fmt.Errorf("dial failed"))
	if n := r.pendingLenForTest(); n != 0 {
		t.Fatalf("TCPError 未释放 token,pending=%d", n)
	}
}

// 取不到地址时必须回退 nil(调用方据此写 LOCAL 头),而不是返回垃圾地址把别人的 IP 记进审计。
func TestHy2ClientAddrRelay_UnknownTokenFallsBack(t *testing.T) {
	r := newHy2ClientAddrRelay()
	if got := r.Take(hy2AddrTokenPrefix + "deadbeef"); got != nil {
		t.Fatalf("未知 token 应回退 nil,得到 %v", got)
	}
	// 非本 relay 埋的 reqAddr(例如 hook 未生效时的原始目标)也必须回退,绝不能误当 token。
	if got := r.Take("example.com:443"); got != nil {
		t.Fatalf("非 token reqAddr 应回退 nil,得到 %v", got)
	}
	// EventLogger 收到非 token reqAddr 时不应记录任何东西(否则真实目标地址会污染表)。
	r.TCPRequest(&net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 1}, "user", "example.com:443")
	if n := r.pendingLenForTest(); n != 0 {
		t.Fatalf("非 token reqAddr 被误记录,pending=%d", n)
	}
}

// pending 表撞顶时只能放弃记录(退回环回归因),不能无界增长。
func TestHy2ClientAddrRelay_PendingIsBounded(t *testing.T) {
	r := newHy2ClientAddrRelay()
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 1}
	for i := 0; i < hy2PendingMax+500; i++ {
		reqAddr := "t:443"
		if _, err := r.TCP(nil, &reqAddr); err != nil {
			t.Fatalf("hook: %v", err)
		}
		r.TCPRequest(addr, "user", reqAddr) // 故意不 Take,模拟异常路径堆积
	}
	if n := r.pendingLenForTest(); n > hy2PendingMax {
		t.Fatalf("pending 超出上限: %d > %d", n, hy2PendingMax)
	}
}

// UDP 不接管:Check(isUDP=true) 必须返回 false,否则会插进 hysteria 的 UDP 路径。
func TestHy2ClientAddrRelay_DoesNotHookUDP(t *testing.T) {
	r := newHy2ClientAddrRelay()
	if r.Check(true, "example.com:53") {
		t.Fatal("不应接管 UDP 请求")
	}
}
