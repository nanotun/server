package main

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// server 自身有没有 v6 公网出网,决定数据面对使用方的公网 v6 流量是「转发」还是「回 ICMPv6
// unreachable 让客户端秒回落 v4」。判错的两个方向都不报错:
//
//   - 误判为「有」:公网 v6 包照转,但源地址是 ULA(或 NAT66 没装),上游直接丢 —— 客户端的 v6
//     连接全部卡到自己超时,而 v4 好着,现象是「某些网站时快时慢/打不开」。
//   - 误判为「无」:白白把所有 v6 降级成 v4。
//
// 真探测要拨公网 v6,在 CI / 无 v6 的机器上恒为 false,所以「探明有 v6 之后做什么」这半边只能靠
// probeServerIPv6EgressFn 这个接缝注入。

// v6ProbeHarness 管着探测接缝与探测 goroutine 的生命周期。
//
// 两个坑都在这里收敛:① 接缝是包级函数变量,探测 goroutine 会读它 —— 所以只装一次,阶段切换改 atomic
// 而不是改函数指针;② `close(stop)` 只是让循环在**下一次** select 时退出,本轮循环体还可能正在读
// sharedTUNGatewayV6,所以还原全局之前要留出退出窗口,否则 -race 会抓到测试自己造的竞态。
type v6ProbeHarness struct {
	has   atomic.Bool
	calls atomic.Int32
	stop  chan struct{}
}

func newV6ProbeHarness(t *testing.T, v6GatewayCIDR string) *v6ProbeHarness {
	t.Helper()
	h := &v6ProbeHarness{stop: make(chan struct{})}

	oldFn := probeServerIPv6EgressFn
	oldGW := sharedTUNGatewayV6
	oldInterval := serverV6EgressProbeInterval
	serverV6EgressProbeInterval = 20 * time.Millisecond
	probeServerIPv6EgressFn = func() bool {
		h.calls.Add(1)
		return h.has.Load()
	}
	sharedTUNGatewayV6 = v6GatewayCIDR
	serverV6EgressKnown.Store(false)
	serverV6EgressHas.Store(false)

	t.Cleanup(func() {
		close(h.stop)
		// 给循环体跑完当前一轮的时间:它没有阻塞调用(探测被换成了内存里的 atomic 读),
		// 所以这点时间足够它走到 select 并退出。之后还原全局才是安全的。
		time.Sleep(200 * time.Millisecond)
		probeServerIPv6EgressFn = oldFn
		sharedTUNGatewayV6 = oldGW
		serverV6EgressProbeInterval = oldInterval
		serverV6EgressKnown.Store(false)
		serverV6EgressHas.Store(false)
	})

	startServerV6EgressProbe(h.stop)
	return h
}

// waitCalls 等探测至少被调用 n 次(即循环已经跑过 n 轮)。
func (h *v6ProbeHarness) waitCalls(t *testing.T, n int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for h.calls.Load() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := h.calls.Load(); got < n {
		t.Fatalf("探测只跑了 %d 轮,期望至少 %d 轮", got, n)
	}
}

// TestStartServerV6EgressProbe_WarnsWhenV6SubnetsAreConfiguredButUnreachable 配了 v6 网段却探不到出网 → 必须告警。
func TestStartServerV6EgressProbe_WarnsWhenV6SubnetsAreConfiguredButUnreachable(t *testing.T) {
	hook := &countingLogHook{levels: []logrus.Level{logrus.WarnLevel}}
	logrus.AddHook(hook)
	t.Cleanup(func() { hook.mu.Lock(); hook.levels = []logrus.Level{logrus.PanicLevel}; hook.mu.Unlock() })

	h := newV6ProbeHarness(t, "fd00:202::1/64") // 配了 v6 网段
	h.has.Store(false)                          // 但本机探不到 v6 出网

	deadline := time.Now().Add(3 * time.Second)
	for hook.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hook.count() == 0 {
		t.Fatal("配了 [tun].subnets_v6 但本机探不到 v6 出网时没有任何告警 —— 客户端照样分到 v6 vIP," +
			"运维要等到用户报「有些站点打不开」才会知道配置与能力脱节")
	}
	hook.mu.Lock()
	msg := strings.Join(hook.msgs, "\n")
	hook.mu.Unlock()
	if !strings.Contains(msg, "subnets_v6") {
		t.Errorf("告警没点出是 subnets_v6 与实测能力脱节: %q", msg)
	}
	if !serverV6EgressKnown.Load() {
		t.Error("探测跑完了却没把「已知」置位 —— 数据面会一直按「未知」保守处理")
	}
	if serverV6EgressHas.Load() {
		t.Error("探测返回无 v6,结果却记成有 —— 数据面会照转公网 v6,包在上游被丢,客户端只看到超时")
	}
}

// TestStartServerV6EgressProbe_RetriesNAT66OnlyAfterV6IsProven 只有探明有 v6 才补装 NAT66。
//
// 启动时 server 的 v6 常常还没由 RA/DHCPv6 下发,ip6tables/NAT66 会装失败并注册补装钩子。
// 补装的时机很讲究:探明有 v6 之前就装,等于在没有 v6 的机器上凭空加规则;而探明之后不装,就会出现
// 「探测说有 v6、数据面照转,但 MASQUERADE 没装 → 公网 v6 以 ULA 源出网被上游丢」的脱节黑洞。
func TestStartServerV6EgressProbe_RetriesNAT66OnlyAfterV6IsProven(t *testing.T) {
	var installs atomic.Int32
	t.Cleanup(func() { armV6SetupRetry(nil) })
	armV6SetupRetry(func() bool { installs.Add(1); return true })

	h := newV6ProbeHarness(t, "") // 没配 v6 网段:本用例只看补装时机,不看那条告警
	h.has.Store(false)

	// ① 探不到 v6:钩子在册也绝不该被调用。
	h.waitCalls(t, 2)
	if got := installs.Load(); got != 0 {
		t.Fatalf("探不到 v6 却补装了 %d 次 NAT66 —— 在没有 v6 的机器上凭空加规则", got)
	}

	// ② 探到 v6:钩子必须被调用,结果也必须落到 atomic 上(数据面只读它)。
	h.has.Store(true)
	deadline := time.Now().Add(3 * time.Second)
	for installs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if installs.Load() == 0 {
		t.Fatal("探明有 v6 之后没有补装 NAT66 —— 数据面照转公网 v6,而 MASQUERADE 没装:" +
			"包以 ULA 源出网被上游丢弃,客户端只看到 v6 超时")
	}
	if !serverV6EgressHas.Load() {
		t.Error("探到有 v6,结果却没写进 atomic —— 数据面照旧按无 v6 处理,公网 v6 全站被降级成 v4")
	}

	// 补装成功之后钩子必须撤掉:否则每轮探测都会重装一遍同样的规则。
	v6SetupRetryMu.Lock()
	stillArmed := v6SetupRetryFn != nil
	v6SetupRetryMu.Unlock()
	if stillArmed {
		t.Error("补装成功后钩子没撤 —— 之后每轮探测都会重装一次同样的规则")
	}
}

// TestRunV6SetupRetryIfArmed_KeepsTheHookAfterAFailedInstall 装失败要保留钩子,下轮再试。
func TestRunV6SetupRetryIfArmed_KeepsTheHookAfterAFailedInstall(t *testing.T) {
	t.Cleanup(func() { armV6SetupRetry(nil) })

	// 没有钩子时是安静的 no-op(每轮探测都会调它)。
	armV6SetupRetry(nil)
	runV6SetupRetryIfArmed()

	var mu sync.Mutex
	var tries int
	armV6SetupRetry(func() bool {
		mu.Lock()
		defer mu.Unlock()
		tries++
		return tries >= 3 // 前两次失败(v6 还没下发),第三次成功
	})

	runV6SetupRetryIfArmed()
	runV6SetupRetryIfArmed()
	v6SetupRetryMu.Lock()
	armed := v6SetupRetryFn != nil
	v6SetupRetryMu.Unlock()
	if !armed {
		t.Fatal("补装失败后钩子被撤了 —— v6 由 RA 晚下发的机器就此永远补不上 NAT66,公网 v6 一直黑洞")
	}

	runV6SetupRetryIfArmed()
	v6SetupRetryMu.Lock()
	armed = v6SetupRetryFn != nil
	v6SetupRetryMu.Unlock()
	if armed {
		t.Error("补装成功后钩子仍在册 —— 每轮探测都会重复装同样的规则")
	}
	mu.Lock()
	got := tries
	mu.Unlock()
	if got != 3 {
		t.Errorf("钩子被调用 %d 次,want 3", got)
	}
}
