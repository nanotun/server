package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

// hy2 的真实客户端地址中转表:hook 埋 token → EventLogger 记真实地址 → Outbound 取出。
// 这一组钉的是「取不到时必须明确说取不到」以及「表不会无界增长」。
//
// 为什么取不到比取错好:取出来的地址会写进环回 smux 上的 PROXY v2 头,server 侧的登录限流 /
// IP 失败锁定 / 审计全按它归因。一条**过期**条目意味着 token 是很早以前埋的 —— 那时的真实地址
// 和现在这条 stream 未必是同一个客户端(极端情况下是「把限流账记到无辜 IP 上」)。宁可回 nil 让
// 调用方退回按环回归因(全部 hy2 塌到 127.0.0.1,是修复前的行为,难看但不冤枉人)。

func testHy2Addr(t *testing.T, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		t.Fatalf("resolve %s: %v", s, err)
	}
	return a
}

// TestHy2ClientAddrRelay_ExpiredTokenIsNotAnAddress:超过 TTL 的条目必须被当成「取不到」,
// 而且要顺手从表里摘掉(取一次就消失,不留悬挂条目)。
func TestHy2ClientAddrRelay_ExpiredTokenIsNotAnAddress(t *testing.T) {
	r := newHy2ClientAddrRelay()
	const token = hy2AddrTokenPrefix + "deadbeef"
	real := testHy2Addr(t, "203.0.113.7:44321")

	// 直接按「很久以前埋的」形状写入:正常路径是微秒级,这里要的是异常路径。
	r.mu.Lock()
	r.pending[token] = hy2PendingAddr{addr: real, at: time.Now().Add(-2 * hy2AddrTokenTTL)}
	r.mu.Unlock()

	if got := r.Take(token); got != nil {
		t.Errorf("过期 token 不该给出地址(会把限流/审计记到早已换人的 IP 上),got %v", got)
	}
	if n := r.pendingLenForTest(); n != 0 {
		t.Errorf("过期条目取过之后应已摘掉,表里还剩 %d 条", n)
	}

	// 新鲜条目照常取到,且同样只能取一次。
	r.TCPRequest(real, "", token)
	if got := r.Take(token); got == nil || got.String() != real.String() {
		t.Fatalf("新鲜 token 应取出真实地址 %v,got %v", real, got)
	}
	if got := r.Take(token); got != nil {
		t.Errorf("token 是一次性的,第二次应取不到,got %v", got)
	}
	// 不带前缀的 reqAddr 是「真实目标地址」,不该被当成 token 去查表。
	if got := r.Take("example.com:443"); got != nil {
		t.Errorf("非 token 的 reqAddr 不该命中,got %v", got)
	}
}

// TestHy2ClientAddrRelay_TableStaysBoundedByDroppingRatherThanGrowing:表撞顶时先清过期项;
// 清完还满就放弃记录这一条(退回环回归因),绝不无界增长 —— 这条表由客户端行为驱动,无界即可被打爆。
func TestHy2ClientAddrRelay_TableStaysBoundedByDroppingRatherThanGrowing(t *testing.T) {
	r := newHy2ClientAddrRelay()
	real := testHy2Addr(t, "198.51.100.9:1234")

	// 填满,其中前一半是过期项(模拟「埋了没取用」的残留)。
	stale := time.Now().Add(-2 * hy2AddrTokenTTL)
	fresh := time.Now()
	r.mu.Lock()
	for i := 0; i < hy2PendingMax; i++ {
		at := fresh
		if i%2 == 0 {
			at = stale
		}
		r.pending[hy2AddrTokenPrefix+"fill-"+strconvItoaHy2(i)] = hy2PendingAddr{addr: real, at: at}
	}
	r.mu.Unlock()

	const token = hy2AddrTokenPrefix + "newcomer"
	r.TCPRequest(real, "", token)

	// 过期项被清掉之后有位置,新条目应记下来。
	if got := r.Take(token); got == nil {
		t.Error("表里半数是过期项,清理后应有位置记新条目(不该直接放弃)")
	}
	if n := r.pendingLenForTest(); n > hy2PendingMax {
		t.Errorf("表长 %d 超过硬上限 %d", n, hy2PendingMax)
	}

	// 全是新鲜条目时撞顶:放弃记录,但表不能再长。
	r2 := newHy2ClientAddrRelay()
	r2.mu.Lock()
	for i := 0; i < hy2PendingMax; i++ {
		r2.pending[hy2AddrTokenPrefix+"hot-"+strconvItoaHy2(i)] = hy2PendingAddr{addr: real, at: fresh}
	}
	r2.mu.Unlock()

	const dropped = hy2AddrTokenPrefix + "no-room"
	r2.TCPRequest(real, "", dropped)
	if got := r2.Take(dropped); got != nil {
		t.Error("表满且无可清项时应放弃记录(退回环回归因),不该塞进去")
	}
	if n := r2.pendingLenForTest(); n != hy2PendingMax {
		t.Errorf("放弃记录后表长应仍为 %d,got %d", hy2PendingMax, n)
	}
}

// TestNewHy2AddrToken_StaysUniqueWhenEntropyIsGone:熵源故障时 token 退化成时间戳。这条降级
// 分支的唯一要求是**仍然唯一** —— token 是并发 stream 之间的关联键,撞一次就意味着两个客户端
// 的真实地址互串(A 的流量按 B 的 IP 归因)。它不承担安全语义(客户端注入不进来,reqAddr 恒被覆盖),
// 所以退化成时间戳是可以的,但不能退化成常量。
func TestNewHy2AddrToken_StaysUniqueWhenEntropyIsGone(t *testing.T) {
	prev := hy2TokenRandRead
	hy2TokenRandRead = func([]byte) (int, error) { return 0, errors.New("熵源故障") }
	t.Cleanup(func() { hy2TokenRandRead = prev })

	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		tok := newHy2AddrToken()
		if tok == "" {
			t.Fatal("熵源故障时也必须给出一个 token(空串会让整条 stream 关联失败)")
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("第 %d 个降级 token 撞号(%q)—— 两个客户端的真实地址会互串", i, tok)
		}
		seen[tok] = struct{}{}
	}
}

func strconvItoaHy2(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
