package main

// ip_failures.go - PoW 自适应难度配套:per-IP 登录失败次数滑动窗口。
//
// 用途:
//   PoWService.ComputeDifficulty(failures) 根据 IP 当前失败次数动态调难度 ——
//   失败少时下发低难度(~5ms 客户端无感),失败多了跳到 14-bit+(~50ms 起步),
//   ramp 系数 + 失败次数线性加,直到 22-bit 封顶,让 attacker 的算力代价随
//   错误尝试数指数级增加。
//
// 滑动窗口设计:
//   - 每个 IP 维护一个 ring buffer 形式的 timestamp 列表(只追加,不删中间);
//   - 计数时跳过窗口外的 timestamp(惰性 GC,不在 Mark 时整理列表);
//   - 列表长度超 maxFailuresPerIP 时丢弃最老的一个,防止单 IP 内存膨胀;
//   - 全局 GC(Prune):每 60s 扫一遍 map,把窗口内已无任何 timestamp 的 IP 删掉,
//     防止 attacker 灌 IP 把 map 撑到无限大。
//
// 跟 globalLoginIPLimiter / powIPLimiter 区别:
//   - globalLoginIPLimiter:登录 token bucket(进 argon2 之前 5/分钟),针对暴力破解;
//   - powIPLimiter:出题频率上限(60/分钟/IP),针对 challenge bombing;
//   - IPFailureTracker:**失败计数**(用来调难度),只在 LoginResp.Code != 200 时
//     调 MarkFailure;成功登录后调 MarkSuccess 清零。
//
// 为什么不复用 globalLoginIPLimiter 的 callsSeq?
//   - 它统计「尝试次数」(无论成败),包含正常用户重输密码;
//   - PoW 难度只该跟「失败次数」挂钩,正常用户切设备登录不该被升难度。
//
// 失败被定义为:LoginResp 下发非 0 code 之前的任一 fail path
//   (PSK verify 失败 / token 失效 / VIP 过期 / IP rate limit / PoW 校验失败本身)。
// 但 **PoW 校验失败** 也算失败(MarkFailure)→ 滥用 challenge 也会升难度。

import (
	"sync"
	"time"
)

// =============================================================================
// 常量
// =============================================================================

const (
	// 失败计数滑动窗口长度。10 分钟内的失败计数 → 长期不会无限累积。
	// 跟 globalLoginIPLimiter 的 5 token/分钟 配套:即使 attacker 持续打满,
	// 10 分钟内最多累 50 个失败 → 16-bit + 5 × 2 = 26-bit → 早就被封顶在
	// 22-bit,实际工程意义到此即可。
	ipFailureWindow = 10 * time.Minute

	// 单 IP 失败记录上限。超过后丢最老的,防止 attacker 持续 fail 把内存撑爆。
	// 32 充裕:即使每 8 秒 fail 一次,窗口内 75 次,32 已经远超难度封顶
	// 所需(failure>=7 即封顶 22-bit)。
	maxFailuresPerIP = 32

	// 全局 IP map 上限。tracker 自己不强制,而是让 Prune 跑得勤一点;实测内存
	// 占用极低(每条 ~80B,1 万 entry = 800KB),不像 loginIPLimiter 那么需要硬上限。
	// 但仍设 maxTrackedIPs 上限作为安全网。
	maxTrackedIPs = 16384
)

// =============================================================================
// IPFailureTracker
// =============================================================================

// IPFailureTracker 进程级单例,Server 启动时建一份。
type IPFailureTracker struct {
	mu      sync.Mutex
	entries map[string][]time.Time
}

func NewIPFailureTracker() *IPFailureTracker {
	return &IPFailureTracker{entries: make(map[string][]time.Time)}
}

// MarkFailure 给 IP 计一次失败。
// 调用点:PSK verify 失败 / PoW 校验失败 / IP rate limited (拒绝前已经 ack 的部分场景)。
// 同步操作,持锁时间是 O(失败列表长度),≤ maxFailuresPerIP。
func (t *IPFailureTracker) MarkFailure(ip string) {
	if ip == "" {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	// 第十九轮深扫 MED(fail-closed,对齐 nanotun-web 的 evictOne):map 上限只约束**新** IP —— 已在表内的 IP
	// 直接累加(合法用户重试 / 真实攻击 IP 一旦进表就不受灌表影响)。新 IP 触顶时先 prune 陈旧项,仍满则**驱逐
	// 任意一个**旧 entry 腾位,而**不是**静默丢弃本条失败。
	//
	// 旧实现「满了直接 return」是 fail-open:攻击者先用上万个不同源 IP 把 map 灌满,之后真实攻击 IP 的失败会
	// 连同一起被丢 → Count 冻结在 0 → ComputeDifficulty 停在 base(~8bit),自适应 PoW 失效。默认
	// login_rate_limit_per_min=0 时自适应 PoW 是主要的 per-IP 代价升级器,故这是实打实的暴破成本削减。
	// nanotun-web 的孪生已用 evictOne 修成 fail-closed(cmd/nanotun-web/ip_failures.go),此处补齐 nanotund 侧。
	if _, exists := t.entries[ip]; !exists && len(t.entries) >= maxTrackedIPs {
		t.pruneLocked(now)
		if len(t.entries) >= maxTrackedIPs {
			t.evictOneLocked()
		}
	}

	list := t.entries[ip]
	list = append(list, now)
	// 单 IP 超长截断:抛掉最老的(线性 copy,但 maxFailuresPerIP=32 实际开销可忽略)。
	if len(list) > maxFailuresPerIP {
		list = list[len(list)-maxFailuresPerIP:]
	}
	t.entries[ip] = list
}

// evictOneLocked 删掉 map 里**任意一个** entry(Go map 迭代无序,取首个即可)给新 IP 腾位。
// 仅在 map 触顶且 prune 无效时由 MarkFailure 调用(fail-closed:保证新失败仍被记录,而非静默丢弃)。
// 调用方须已持 t.mu。
func (t *IPFailureTracker) evictOneLocked() {
	for k := range t.entries {
		delete(t.entries, k)
		return
	}
}

// MarkSuccess 该 IP 登录成功 → 把失败列表减半(不再直接清空)。
//
// 设计变更(P2-4 NAT 边界):原实现直接 delete(t.entries, ip),NAT 出口 IP 后
// 合法用户和 attacker 共享同一个 entry → 合法用户每次成功登录都会让 attacker
// 的 PoW 难度从 ramp 回到 base,放纵暴破。
//
// 折中:减半而非清零 ——
//   - 合法用户多次成功登录后失败计数按 1/2^n 衰减,几次后归零,正常体验恢复 base;
//   - attacker 在 NAT 后即使合法用户连续登录,自己积累的失败仍有一半保留,难度仍升;
//   - tradeoff:正常用户切设备/客户端重启第二次登录,如果上一次走过 fail 路径
//     (如 token 输错一次),首次会感受到 base+1 难度,仍在 ~5-10ms 区间,可接受;
//   - 配合 globalLoginIPLimiter 5/min 兜底,NAT 后暴破速率被双层限制。
//
// 调用时机:LoginResp.code=0(真成功)之后。中间过程(PoW 通过但 PSK 还没 verify)
// 不算。
func (t *IPFailureTracker) MarkSuccess(ip string) {
	if ip == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	list := t.entries[ip]
	if len(list) <= 1 {
		// 0 或 1 条:直接清掉,省 map entry。
		delete(t.entries, ip)
		return
	}
	// 留较新的一半(列表 append-only,后半段时间戳更新)。
	keep := len(list) / 2
	newList := make([]time.Time, keep)
	copy(newList, list[len(list)-keep:])
	t.entries[ip] = newList
}

// Count 返回 IP 在过去 ipFailureWindow 内的失败次数。
// 不做整理:只跳过窗口外的元素,真正的清理交给 Prune。
//
// 性能:即使列表 ≤ maxFailuresPerIP=32,持锁 + 线性扫描 ~32 元素也是 ns 级,
// 比 SHA-256 哈希便宜得多,不需要进一步优化。
func (t *IPFailureTracker) Count(ip string) int {
	if ip == "" {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	list := t.entries[ip]
	if len(list) == 0 {
		return 0
	}
	cutoff := time.Now().Add(-ipFailureWindow)
	cnt := 0
	for _, ts := range list {
		if ts.After(cutoff) {
			cnt++
		}
	}
	return cnt
}

// Prune 是 PoWService.RunGC 每 60s 调一次。
// 扫一遍 entries,把窗口内已无任何 timestamp 的 IP 整条 delete;有 timestamp 的
// 顺手做一次截断(只保留窗口内的),避免列表越攒越长。
func (t *IPFailureTracker) Prune() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(time.Now())
}

func (t *IPFailureTracker) pruneLocked(now time.Time) {
	cutoff := now.Add(-ipFailureWindow)
	for ip, list := range t.entries {
		// 找到首个窗口内 timestamp 的下标 → 截掉前缀。
		// 列表是 append-only,timestamp 单调递增,直接二分也行,但 maxFailuresPerIP=32
		// 线性扫更简单也更快(分支预测友好,无随机访问)。
		first := -1
		for i, ts := range list {
			if ts.After(cutoff) {
				first = i
				break
			}
		}
		if first == -1 {
			delete(t.entries, ip)
			continue
		}
		if first > 0 {
			// copy 截断,缩短切片;避免 underlying array 仍引用旧元素让 GC 抓不到。
			newList := make([]time.Time, len(list)-first)
			copy(newList, list[first:])
			t.entries[ip] = newList
		}
	}
}

// Size 返回当前 map 大小。
// 生产用法:metrics.go 暴露 nanotun_pow_ip_failures_tracked gauge,
// 运维监控当前跟踪了多少个失败 IP(DDoS 时会突涨)。
// 测试用法:验证 prune / cap 行为。
func (t *IPFailureTracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}
