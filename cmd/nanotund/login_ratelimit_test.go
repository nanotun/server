package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// newTestLimiter 构造一份隔离的 loginIPLimiter,避免污染 globalLoginIPLimiter
// (其它测试可能依赖它的初始状态)。
//
// 注意:limiter 现在默认 ratePerMin=0(不限制),因此显式按旧固定速率
// (loginRLRate=5/60s → 5 次/分钟)开启限速,让下面的限速行为测试沿用旧语义。
func newTestLimiter() *loginIPLimiter {
	l := &loginIPLimiter{limits: make(map[string]*loginIPEntry)}
	l.SetRatePerMin(int(loginRLRate * 60))
	return l
}

// TestAllowLogin_ZeroRateMeansUnlimited 锁定关键需求:
// login_rate_limit_per_min=0(默认零值)= 完全不限制,且不在 map 里建 entry。
func TestAllowLogin_ZeroRateMeansUnlimited(t *testing.T) {
	l := &loginIPLimiter{limits: make(map[string]*loginIPEntry)} // ratePerMin 零值 = 0
	for i := 0; i < loginRLBurst*100; i++ {
		ok, host := l.AllowLogin("9.9.9.9:1000")
		if !ok {
			t.Fatalf("第 %d 次:0=不限制时必须放行", i)
		}
		if host != "9.9.9.9" {
			t.Fatalf("host 解析错: got=%q", host)
		}
	}
	// 不限制路径走无锁短路,不应建任何 per-IP entry。
	if got := len(l.limits); got != 0 {
		t.Fatalf("不限制时不应建 entry,map size = %d", got)
	}
}

// TestSetRatePerMin_ToggleOffUnlimits 验证从限速切到 0 后立即放行。
func TestSetRatePerMin_ToggleOffUnlimits(t *testing.T) {
	l := newTestLimiter() // 5/min, burst 3
	for i := 0; i < loginRLBurst; i++ {
		if ok, _ := l.AllowLogin("7.7.7.7:1"); !ok {
			t.Fatalf("burst %d 应允许", i)
		}
	}
	if ok, _ := l.AllowLogin("7.7.7.7:2"); ok {
		t.Fatal("burst 用完应被拒")
	}
	// 切到 0 = 不限制:同一 IP 立即恢复放行(无锁短路,不看旧 entry 的令牌)。
	l.SetRatePerMin(0)
	for i := 0; i < 50; i++ {
		if ok, _ := l.AllowLogin("7.7.7.7:3"); !ok {
			t.Fatalf("切到 0 后第 %d 次应放行", i)
		}
	}
}

func TestAllowLogin_BurstThenRateLimited(t *testing.T) {
	l := newTestLimiter()
	for i := 0; i < loginRLBurst; i++ {
		ok, _ := l.AllowLogin("1.2.3.4:5000")
		if !ok {
			t.Fatalf("burst %d: 应允许", i)
		}
	}
	// burst 用完后立即再来一次应该被拒。
	ok, _ := l.AllowLogin("1.2.3.4:5001")
	if ok {
		t.Fatal("burst 用完应被拒")
	}
}

func TestAllowLogin_DifferentIPsIndependent(t *testing.T) {
	l := newTestLimiter()
	ok1, _ := l.AllowLogin("10.0.0.1:1")
	ok2, _ := l.AllowLogin("10.0.0.2:1")
	if !ok1 || !ok2 {
		t.Fatal("两个不同 IP 各自第一次都应允许")
	}
}

// H1 regression:cap 满之后新 IP 进来必须被拒,且 capExceeded 计数增长。
// 旧 IP(已经在 map 里)的快路径不受影响。
func TestAllowLogin_CapEnforced_NewIPRejected(t *testing.T) {
	l := newTestLimiter()
	// 直接把 map 灌到 cap(用伪造 entry 模拟攻击灌包后的稳态)。
	// lastSeen = 现在,确保 forceGC 删不掉。
	now := time.Now()
	for i := 0; i < loginRLMaxEntries; i++ {
		l.limits[fmt.Sprintf("attacker-%d", i)] = &loginIPEntry{
			lim:      rate.NewLimiter(loginRLRate, loginRLBurst),
			lastSeen: now,
		}
	}
	if got := len(l.limits); got != loginRLMaxEntries {
		t.Fatalf("setup map size = %d, want %d", got, loginRLMaxEntries)
	}

	// 新 IP 应该被 cap-protect 拒绝。
	ok, host := l.AllowLogin("203.0.113.1:1234")
	if ok {
		t.Fatal("cap 满时新 IP 应被拒")
	}
	if host != "203.0.113.1" {
		t.Fatalf("host 解析错: got=%q", host)
	}
	if l.capExceeded != 1 {
		t.Fatalf("capExceeded = %d, want 1", l.capExceeded)
	}
	// map 不应增长,继续灌新 IP 应该持续 deny + 计数增长,而不是吃内存。
	for i := 0; i < 50; i++ {
		_, _ = l.AllowLogin(fmt.Sprintf("198.51.100.%d:80", i))
	}
	if l.capExceeded != 51 {
		t.Fatalf("capExceeded = %d, want 51", l.capExceeded)
	}
	if got := len(l.limits); got != loginRLMaxEntries {
		t.Fatalf("攻击下 map size = %d,不应增长(cap=%d)", got, loginRLMaxEntries)
	}
}

// H1 regression:cap 满但有过期 entry 时,forceGC 应能腾出空间让新 IP 进入。
func TestAllowLogin_CapWithStaleEntries_GCFreesSlots(t *testing.T) {
	l := newTestLimiter()
	stale := time.Now().Add(-loginRLGCTTL - time.Minute) // 过期
	for i := 0; i < loginRLMaxEntries; i++ {
		l.limits[fmt.Sprintf("stale-%d", i)] = &loginIPEntry{
			lim:      rate.NewLimiter(loginRLRate, loginRLBurst),
			lastSeen: stale,
		}
	}
	// 新 IP 进来:forceGC 把全部过期项删光,腾出空间,本次允许。
	ok, _ := l.AllowLogin("203.0.113.7:80")
	if !ok {
		t.Fatal("过期 entry 被 GC 后,新 IP 应允许")
	}
	if l.capExceeded != 0 {
		t.Fatalf("不应触发 capExceeded,实际 = %d", l.capExceeded)
	}
	if got := len(l.limits); got >= loginRLMaxEntries {
		t.Fatalf("GC 后 map size = %d,应远小于 cap", got)
	}
}

// H1 regression:已 active 的 IP 走 fast path,即便 map 接近 cap 也不会被拒。
// 这条最重要 —— 正常用户来自常驻 IP,不应该被攻击者灌包"挤掉"。
func TestAllowLogin_ActiveIPNotEvictedByFlood(t *testing.T) {
	l := newTestLimiter()
	// 先让常驻 IP 拿到 entry。
	if ok, _ := l.AllowLogin("alice:0"); !ok {
		t.Fatal("alice 首次应允许")
	}
	// 用攻击者灌满剩余 slot。
	now := time.Now()
	for i := 0; i < loginRLMaxEntries-1; i++ {
		l.limits[fmt.Sprintf("attacker-%d", i)] = &loginIPEntry{
			lim:      rate.NewLimiter(loginRLRate, loginRLBurst),
			lastSeen: now,
		}
	}
	// 攻击者继续灌新 IP,应被拒 + 不影响 alice fast path。
	for i := 0; i < 20; i++ {
		_, _ = l.AllowLogin(fmt.Sprintf("evil-%d:0", i))
	}
	// alice 第二次 / 第三次仍在 burst 内,应允许。
	if ok, _ := l.AllowLogin("alice:1"); !ok {
		t.Fatal("常驻 IP alice 不应被挤掉")
	}
}

// H1 regression:GC 是摊销的 —— 普通 call 不应该 O(N) 扫 map。
// 这条用「填充大量过期 entry,持续 call 99 次不触发 GC,第 100 次才扫」来验证。
func TestAllowLogin_GCIsAmortized(t *testing.T) {
	l := newTestLimiter()
	stale := time.Now().Add(-loginRLGCTTL - time.Minute)
	const filler = 200
	for i := 0; i < filler; i++ {
		l.limits[fmt.Sprintf("stale-%d", i)] = &loginIPEntry{
			lim:      rate.NewLimiter(loginRLRate, loginRLBurst),
			lastSeen: stale,
		}
	}
	beforeSize := len(l.limits)
	// 触发 loginRLGCEveryNCall-1 次 call,每次都是不同 IP(防止挂在 fast path 上)。
	// 但本测试目的是「99 次不触发全扫」,所以这里 callsSeq 在前 99 次只做 hashmap insert + GC 不触发。
	// 注意:callsSeq 是 uint64,从 0 开始;第一次 call 后 = 1,直到 = 100 才触发(100%100==0)。
	for i := 0; i < loginRLGCEveryNCall-1; i++ {
		_, _ = l.AllowLogin(fmt.Sprintf("warm-%d:0", i))
	}
	// 99 次都没触发 GC,过期 entry 仍在(+ 99 个新 warm IP)。
	wantMin := beforeSize + 50 // 至少有 stale + 大部分 warm
	if got := len(l.limits); got < wantMin {
		t.Fatalf("摊销 GC 不应在前 99 次清掉 stale,size=%d wantMin=%d", got, wantMin)
	}
	// 第 100 次 call 触发 GC,应清掉 stale entry。
	_, _ = l.AllowLogin("trigger:0")
	for k, v := range l.limits {
		if v.lastSeen.Equal(stale) {
			t.Fatalf("第 100 次 call 应触发 GC,但 stale entry %q 仍在", k)
		}
	}
}

// I1 regression:per-IP deny 的 WARN 日志必须节流。
// 直接灌 deny,然后检查 e.denySinceWarn 累积而非每次重置。
func TestAllowLogin_PerIPDenyLogThrottled(t *testing.T) {
	l := newTestLimiter()
	// 用尽 burst 让后续全部 deny。
	for i := 0; i < loginRLBurst; i++ {
		_, _ = l.AllowLogin("flooder:1")
	}
	// 紧接着灌 50 次 deny;第一次会触发 WARN(lastWarnAt 从零更新),
	// 之后 49 次都不应再触发 WARN —— denySinceWarn 应累积到 49。
	for i := 0; i < 50; i++ {
		ok, _ := l.AllowLogin("flooder:1")
		if ok {
			t.Fatalf("第 %d 次:burst 用完后必须 deny", i)
		}
	}
	l.mu.Lock()
	e := l.limits["flooder"]
	if e == nil {
		t.Fatal("flooder entry 应存在")
	}
	// 第一次 deny 触发 WARN 时 denySinceWarn 被 Swap 到 0,后续 49 次累积到 49。
	if e.denySinceWarn != 49 {
		t.Fatalf("denySinceWarn = %d, want 49(节流期内累积)", e.denySinceWarn)
	}
	if e.lastWarnAt.IsZero() {
		t.Fatal("第一次 deny 应当更新 lastWarnAt")
	}
	l.mu.Unlock()
}

// I1 regression:cap-exceeded 的 WARN 也必须节流(攻击者灌 1k 新 IP/s 时)。
func TestAllowLogin_CapExceededLogThrottled(t *testing.T) {
	l := newTestLimiter()
	now := time.Now()
	for i := 0; i < loginRLMaxEntries; i++ {
		l.limits[fmt.Sprintf("attacker-%d", i)] = &loginIPEntry{
			lim:      rate.NewLimiter(loginRLRate, loginRLBurst),
			lastSeen: now,
		}
	}
	// 灌 100 个不同新 IP,只第一次能触发 WARN,后续 99 次走累积。
	for i := 0; i < 100; i++ {
		_, _ = l.AllowLogin(fmt.Sprintf("evil-%d:0", i))
	}
	// capExceeded 总计应等于 100(全部被拒)。
	if l.capExceeded != 100 {
		t.Fatalf("capExceeded = %d, want 100", l.capExceeded)
	}
	// 第一次拒绝触发 WARN 时 Swap 走 1(包含本次),剩余 99 次累积到 99。
	got := l.capExceededSinceWarn.Load()
	if got != 99 {
		t.Fatalf("capExceededSinceWarn = %d, want 99(节流期内累积)", got)
	}
	if l.capExceededWarnAt.Load() == 0 {
		t.Fatal("第一次 cap-exceeded 应更新 capExceededWarnAt")
	}
}

// 简单的并发安全 sanity test(配合 go test -race)。
func TestAllowLogin_ConcurrentSafe(t *testing.T) {
	l := newTestLimiter()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ip := fmt.Sprintf("10.%d.%d.%d:0", w, i/256, i%256)
				_, host := l.AllowLogin(ip)
				if !strings.HasPrefix(host, "10.") {
					t.Errorf("host 异常: %q", host)
					return
				}
			}
		}()
	}
	wg.Wait()
}
