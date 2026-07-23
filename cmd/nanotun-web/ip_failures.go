package main

// ip_failures.go - 登录失败的「按 IP 滑动窗口计数」,用来驱动自适应 PoW 难度。
//
// 设计要点
// --------
// 1) **不进 SQLite**:登录是高频公开页路径(扫描器一上来就打),写库会让
//    每次失败都走一次磁盘 fsync;纯进程内 sync.Map 同尺度成本可以低 1000 倍。
//    重启清空也能接受 — admin 登录低频,真攻击场景下重启后 attacker 还会
//    重新打,counters 一会就升起来。
//
// 2) **滑动窗口而不是「固定时间窗 + reset」**:
//    经典的"5min 内失败 N 次"用窗口起点 reset 的方式实现简单但有缺陷:
//    attacker 在窗口边缘连打 N 次能拿满 2 倍配额。这里 *简化版* 用
//    "最后失败时间 + lastFailureCount":距离 lastFailure 超过 windowSec
//    就把 counter 归零重新算;在窗口内的失败都累加。
//
//    更严格的 "每事件时间戳 list + 距 now < windowSec 才计数" 适合做精确
//    限流,但对自适应 PoW 来说 *差不多* 就行 — 真要更准换 token bucket 也是
//    几十行的事,不在 P3 范围内。
//
// 3) **IP 取自 clientIP(r)**(session.go):默认用 TCP 直连对端,不信任 XFF。
//    仅当运维配置了 trusted_proxies(反代 IP/CIDR)且直连对端落在其中时,clientIP
//    才解析 X-Forwarded-For 还原真实客户端 —— 否则按 IP 限流会被伪造 XFF 绕过 / 变成
//    跨账号 DoS(见 session.go: clientIP 与 config.go: TrustedProxies)。
//
// 4) **手动 prune**:GC 跟 PoW 共用一个 ticker(runPoWGC 里调一下),减少
//    后台 goroutine 数。

import (
	"sync"
	"sync/atomic"
	"time"
)

// 默认窗口:5 分钟。
// 失败到达 powFailuresEnable=3 就开始下发 PoW;
// 每多 1 次失败,难度 +2 bit。
const ipFailureWindowSec = int64(5 * 60)

// 全局 IP map 上限(第三轮深扫 L7,对齐 nanotund ip_failures.go 的 maxTrackedIPs=16384)。
// 此前本 tracker 用无上限 sync.Map,attacker 用大量不同源 IP(或反代配错时伪造 XFF)持续 fail,
// 能把 map 撑到「~2×window 的存活 IP 数」。加软上限:超限时先强制 Prune 回收陈旧项,仍满则丢弃
// 本次新 IP 记录(失败计数偏少,仅跨 IP 洪泛才触发,正常用户无感)。每条 ~80B,16384 ≈ 1.3MB。
const maxTrackedIPs = 16384

// ipFailureRecord 是单条 IP 的滑动窗口状态。
// 复用 sync.Mutex 而不是用 atomic 拆分 — 操作频率低(只在 GET/POST /login
// 上写),用普通 mutex 代码更清晰。
type ipFailureRecord struct {
	mu       sync.Mutex
	count    int
	lastFail int64 // Unix 秒;距 now > windowSec 时 reset 整个 count
}

// IPFailureTracker 跟踪每个 IP 的近期登录失败计数。
// 用 sync.Map 装 *ipFailureRecord,每个 record 自带 mutex,
// 写不冲突的 IP 之间完全无锁。
type IPFailureTracker struct {
	m sync.Map // map[string]*ipFailureRecord

	// size 近似跟踪 m 里的 entry 数(sync.Map 无 Len)。仅在**新增** entry 时 +1、Prune 删除时 -1,
	// 用于 maxTrackedIPs 软上限。并发下可能短暂偏差(可接受:软上限)。
	size atomic.Int64
}

// NewIPFailureTracker 构造一个新跟踪器。
func NewIPFailureTracker() *IPFailureTracker {
	return &IPFailureTracker{}
}

// Recent 返回该 IP 当前的"有效失败次数"。
// 距 lastFail > 窗口的算回 0(惰性归零,不需要扫描)。
//
// 该函数只读 — handler_auth 在 GET /login 用它决定下发难度时调用。
func (t *IPFailureTracker) Recent(ip string) int {
	if ip == "" {
		return 0
	}
	v, ok := t.m.Load(ip)
	if !ok {
		return 0
	}
	rec := v.(*ipFailureRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if t.shouldReset(rec) {
		rec.count = 0
		return 0
	}
	return rec.count
}

// Inc 失败 +1。POST /login 任何一种失败都应当调用(密码错 / captcha 错 /
// PoW 错都计入)。返回更新后的失败次数,让 handler 立刻拿去算下次的难度
// (虽然 retry 重渲页面会再次走 Recent,这里直接拿可减少一次锁)。
func (t *IPFailureTracker) Inc(ip string) int {
	if ip == "" {
		return 0
	}
	// 快路径:已存在的 IP 直接更新,不动 size、不受上限影响(合法用户重试也走这里)。
	if v, ok := t.m.Load(ip); ok {
		return t.bump(v.(*ipFailureRecord))
	}
	// 慢路径:新 IP。受 maxTrackedIPs 软上限保护 —— 超限先 Prune 回收陈旧项;仍满则**驱逐任意一个**旧条目
	// 腾位,而**不是**放弃追踪返回 0。
	//
	// 第四轮深扫 MED(修 L7 引入的 fail-open):此前满了直接 return 0 → 新 IP 不进表 → Recent()=0 →
	// ComputeDifficulty=0 → PoW 被跳过。攻击者只要先用一万多个不同源 IP 把 map 灌满,之后用**真实攻击 IP**
	// 就能永久免 PoW(把本该驱动自适应难度的失败信号一起关掉了)。改为 fail-closed:超限时驱逐一个旧条目
	// 让新 IP 仍被追踪,PoW 信号不丢;map 规模仍被 evict-on-insert 钉在 ~maxTrackedIPs,内存有界。
	if t.size.Load() >= maxTrackedIPs {
		t.Prune()
		if t.size.Load() >= maxTrackedIPs {
			t.evictOne()
		}
	}
	v, loaded := t.m.LoadOrStore(ip, &ipFailureRecord{})
	if !loaded {
		t.size.Add(1)
	}
	return t.bump(v.(*ipFailureRecord))
}

// evictOne 删掉 map 里**任意一个** entry(sync.Map 无序,取 Range 首个即可)给新 IP 腾位。
// 只在触顶时调用;用 LoadAndDelete 确保仅在确实删除时才 size--(并发下不双减)。
func (t *IPFailureTracker) evictOne() {
	t.m.Range(func(k, _ any) bool {
		if _, loaded := t.m.LoadAndDelete(k); loaded {
			t.size.Add(-1)
		}
		return false // 只删一个即停
	})
}

// bump 在持 record 锁下做「窗口过期归零 + 计数 +1 + 刷新 lastFail」,返回新计数。
func (t *IPFailureTracker) bump(rec *ipFailureRecord) int {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if t.shouldReset(rec) {
		rec.count = 0
	}
	rec.count++
	rec.lastFail = nowUnix()
	return rec.count
}

// Reset 清零某 IP 的失败计数 — 登录成功时调用。
func (t *IPFailureTracker) Reset(ip string) {
	if ip == "" {
		return
	}
	if v, ok := t.m.Load(ip); ok {
		rec := v.(*ipFailureRecord)
		rec.mu.Lock()
		rec.count = 0
		rec.lastFail = 0
		rec.mu.Unlock()
	}
}

// Prune 把所有 lastFail 距今超过 2 * window 的 IP record 整条删除。
// 用 2x 是为了避免边界处的反复创建/删除抖动。建议每分钟跑一次。
func (t *IPFailureTracker) Prune() {
	now := nowUnix()
	cutoff := now - 2*ipFailureWindowSec
	t.m.Range(func(k, v any) bool {
		rec := v.(*ipFailureRecord)
		rec.mu.Lock()
		stale := rec.lastFail > 0 && rec.lastFail < cutoff
		rec.mu.Unlock()
		if stale {
			t.m.Delete(k)
			t.size.Add(-1)
		}
		return true
	})
}

// snapshot 仅测试用 — 返回当前所有 IP 的快照,**不安全**用在生产路径。
func (t *IPFailureTracker) snapshot() map[string]int {
	out := map[string]int{}
	t.m.Range(func(k, v any) bool {
		rec := v.(*ipFailureRecord)
		rec.mu.Lock()
		if !t.shouldReset(rec) {
			out[k.(string)] = rec.count
		}
		rec.mu.Unlock()
		return true
	})
	return out
}

func (t *IPFailureTracker) shouldReset(rec *ipFailureRecord) bool {
	if rec.lastFail == 0 {
		return false
	}
	return nowUnix()-rec.lastFail > ipFailureWindowSec
}

// =============================================================================
// 时间封装 — 方便单测注入
// =============================================================================
//
// 全局复用 session.go 里的 nowUnix()(time.Now().Unix())。如果以后想做
// 时间注入,把 nowUnix 改成接口或函数 var 就行;现在没必要。

// 编译期断言:确保 time 包仍被引用(防 import 漂移)。
var _ time.Duration = 0
