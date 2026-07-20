package main

// pow_limiter.go - PoW 出题速率防护,跟 login_ratelimit.go 是相互独立的两层:
//
//   loginIPLimiter:   per-IP 登录尝试 (token bucket 5/分钟,burst 3)
//                     调用点:PSK verify 之前,挡暴力破解
//   powIPLimiter:     per-IP 出题请求 (token bucket 60/分钟,burst 10)
//                     调用点:client 发 LinkTypePoWChallengeReq 进入 server 时,挡 challenge bombing
//   globalPoWIssueLimiter: 全局出题 (1000/秒,burst 100)
//                     调用点:powIPLimiter 之后,挡跨 IP 灌包 DoS
//
// 为什么 PoW 出题也要限速?
//   - 出题本身 ~5µs (生成 cid + salt + HMAC),非常便宜,attacker 拿百万 IP 灌不动 server;
//   - 但 sync.Map 跨 IP 写入 contention 会拖慢正常用户的 LoadOrStore;
//   - 60/分钟/IP 给 NAT 后多设备同时登录留足空间(预估 SOHO/小宿舍 ≤ 10 客户端 / IP);
//   - 全局 1000/秒 给 ~500 RPS 高并发服务留 2× 余量。
//
// 触发限速后的行为:
//   - powIPLimiter 拒:server 直接发 CloseMsg{Code: CodePowFailed, Reason: "rate limit"} + close socket。
//     仅 connect_close 阶段 attacker 重连重 WS 握手代价 ≪ 出题代价,所以不会真挡 DoS,
//     但能减少 ip_failures 列表无意义膨胀(那个比这个贵)。
//   - globalPoWIssueLimiter 拒:server 同上 close,但记 metric "pow_global_limited"
//     (这是 dashboard 监控指标:平时应为 0,>0 说明遭遇跨 IP 攻击)。

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// =============================================================================
// 常量
// =============================================================================

const (
	powIPRLBurst        = 10
	powIPRLRate         = rate.Limit(60.0 / 60.0) // 60 / 60s = 1/s 平均
	powIPRLGCTTL        = 30 * time.Minute
	powIPRLMaxEntries   = 4096
	powIPRLGCEveryNCall = 100

	// 与 login_ratelimit 一致:cap-exceeded WARN 节流间隔。
	powIPRLWarnThrottle = 60 * time.Second

	// 全局每秒 1000,burst 100。NAT 大入口最坏情况下也够用 ——
	// 1000 RPS 出题 ~5ms HMAC + sync.Map = 5s CPU/s,无压力。
	powGlobalRLRate  = rate.Limit(1000)
	powGlobalRLBurst = 100
)

// =============================================================================
// powIPLimiter - per-IP token bucket(直接复用 login_ratelimit.go 的结构思路)
// =============================================================================

type powIPLimiter struct {
	mu          sync.Mutex
	limits      map[string]*powIPEntry
	callsSeq    uint64
	capExceeded uint64

	capExceededWarnAt    atomic.Int64
	capExceededSinceWarn atomic.Uint64
}

type powIPEntry struct {
	lim           *rate.Limiter
	lastSeen      time.Time
	lastWarnAt    time.Time
	denySinceWarn uint64
}

var globalPoWIPLimiter = &powIPLimiter{limits: make(map[string]*powIPEntry)}

// AllowChallenge 给 IP 申请一个出题机会。返回 (allowed, host)。
// allowed=false 时调用方应当直接拒绝出题(回 close + Code=412)。
func (l *powIPLimiter) AllowChallenge(remoteAddr string) (bool, string) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.callsSeq++

	if l.callsSeq%powIPRLGCEveryNCall == 0 {
		for k, v := range l.limits {
			if now.Sub(v.lastSeen) > powIPRLGCTTL {
				delete(l.limits, k)
			}
		}
	}

	e, ok := l.limits[host]
	if !ok {
		if len(l.limits) >= powIPRLMaxEntries {
			l.forceGCLocked(now)
			if len(l.limits) >= powIPRLMaxEntries {
				l.capExceeded++
				l.capExceededSinceWarn.Add(1)
				nowNS := now.UnixNano()
				lastNS := l.capExceededWarnAt.Load()
				if nowNS-lastNS >= int64(powIPRLWarnThrottle) &&
					l.capExceededWarnAt.CompareAndSwap(lastNS, nowNS) {
					acc := l.capExceededSinceWarn.Swap(0)
					logrus.WithFields(logrus.Fields{
						"ip":                  host,
						"cap":                 powIPRLMaxEntries,
						"cap_exceeded_total":  l.capExceeded,
						"deny_in_last_window": acc,
						"window":              powIPRLWarnThrottle.String(),
					}).Warn("[pow-ratelimit] per-IP 出题状态表已满,拒绝新 IP 出题")
				}
				return false, host
			}
		}
		e = &powIPEntry{lim: rate.NewLimiter(powIPRLRate, powIPRLBurst)}
		l.limits[host] = e
	}
	e.lastSeen = now
	if !e.lim.Allow() {
		e.denySinceWarn++
		if now.Sub(e.lastWarnAt) >= powIPRLWarnThrottle {
			acc := e.denySinceWarn
			e.denySinceWarn = 0
			e.lastWarnAt = now
			logrus.WithFields(logrus.Fields{
				"ip":                  host,
				"burst":               powIPRLBurst,
				"rate_per_60s":        int(60 * float64(powIPRLRate)),
				"deny_in_last_window": acc,
				"window":              powIPRLWarnThrottle.String(),
			}).Warn("[pow-ratelimit] per-IP 出题尝试超频,拒绝")
		}
		return false, host
	}
	return true, host
}

func (l *powIPLimiter) forceGCLocked(now time.Time) {
	for k, v := range l.limits {
		if now.Sub(v.lastSeen) > powIPRLGCTTL {
			delete(l.limits, k)
		}
	}
}

// CountForTest 仅测试用。
func (l *powIPLimiter) CountForTest() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.limits)
}

// ResetForTest 测试间清空 per-IP 表。生产路径不应该调。
//
// 背景:net.Pipe 的 LocalAddr/RemoteAddr 都返回 "pipe",所有 net.Pipe 测试共享
// 同一个 powIPEntry。burst=10 → 大约第 11 个 PoW 测试就会被限速 false-positive。
// 测试初始化时调一次,把状态清空。
func (l *powIPLimiter) ResetForTest() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limits = make(map[string]*powIPEntry)
	l.callsSeq = 0
	l.capExceeded = 0
	l.capExceededWarnAt.Store(0)
	l.capExceededSinceWarn.Store(0)
}

// =============================================================================
// globalPoWIssueLimiter - 全局出题速率
// =============================================================================

var globalPoWIssueLimiter = rate.NewLimiter(powGlobalRLRate, powGlobalRLBurst)

// globalPoWGlobalLimitedTotal 全局出题被限速拒绝的累计次数。
// 暴露到 Prometheus(nanotun_pow_global_limited_total),平时应保持 0,
// > 0 说明跨 IP 灌包级别的 DoS。
var globalPoWGlobalLimitedTotal atomic.Uint64

// AllowGlobalIssue 当前能否再出一道题(全局 1000/s 限速)。
func AllowGlobalIssue() bool {
	ok := globalPoWIssueLimiter.Allow()
	if !ok {
		globalPoWGlobalLimitedTotal.Add(1)
	}
	return ok
}

// ResetGlobalPoWIssueLimiterForTest 重新构造全局出题限速器(burst 重置 100)。
// 仅测试用,生产路径不应该调。测试串行执行,无 race。
func ResetGlobalPoWIssueLimiterForTest() {
	globalPoWIssueLimiter = rate.NewLimiter(powGlobalRLRate, powGlobalRLBurst)
	globalPoWGlobalLimitedTotal.Store(0)
}
