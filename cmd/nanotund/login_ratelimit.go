package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// 登录频率防护(P0-2 配套 / E1):auth/psk.go 的 argon2Sema 限制**总并发**算力,
// 但单个攻击者仍能持续地发同一 IP 的登录尝试,占满 verify 槽位让正常用户排队。
// 这里再加一层 per-IP token bucket,把单 IP 在短窗口内的尝试次数限死。
//
// 速率可配置([server].login_rate_limit_per_min,见 loginIPLimiter.ratePerMin):
//
//   - 0 / 缺省 = **不限制**(默认):AllowLogin 无锁短路放行,本文件其余限速逻辑不触发;
//   - N > 0    = 每 IP 每分钟最多 N 次,突发固定 loginRLBurst(=3)。
//
// 默认放开的理由见 config.ServerConfig.LoginRateLimitPerMin:移动端弱网频繁重连 /
// AUTO 协议回退重试很容易把固定 5/min 打满误伤正常用户,而 PoW(始终启用,失败 ramp)
// 与 argon2id 全局 semaphore 已是防暴破主力,本限速仅作可选兜底。
//
// 启用(N>0)后,命中限速时直接拒绝(写一条登录失败响应),**不**进入 argon2 verify,因此:
//   - 攻击者无法用一台机器塞满全局 semaphore;
//   - 正常用户偶尔多按几次登录(突发 3)也不会被卡;
//   - 持续高频敲击 5 分钟以上的 IP 会有持续拒登的日志,便于运维介入封 IP。
//
// 实现细节:
//   - per-IP limiter 用 map[string]*rate.Limiter,key 是 host(不带端口),
//     这样 NAT 后多端口算同一 IP。
//   - 30 分钟没出现的 IP 自动 GC,避免内存增长。
//   - **硬上限 loginRLMaxEntries**(H1, 2026-05-22):防止 IPv6 botnet 灌不同源 IP
//     做 memory amplification + lock contention DoS。
//
// 取值理由:
//   - 5 次/分钟:正常用户重输密码 / 切设备登录场景充裕;
//   - 突发 3:首次连接 / 切换网络偶尔重试不被拒;
//   - 暴力破解 argon2id(64MB / 2 iter,~10ms/次):5 次/分钟 = 60 token/小时,
//     单 IP 一年只能试 ~50 万次,与 PSK 熵足够强(≥16 字节随机)结合,完全防御。
//
// H1(2026-05-22)硬上限设计:
//
// 原始 GC 策略每次 AllowLogin 都 O(N) 全遍历 map,生产中 N 通常远小于 1000 没事;
// 但 IPv6 攻击者从 N 个不同源 IP 灌登录请求(每 IP 29 分钟续命一次即可永久占位):
//
//  1. 内存放大:30M IPv6 源地址 × ~300B/entry ≈ 9GB(每分钟从 1M 新 IP 各打 1 包)
//  2. lock contention DoS:map 一旦到 30k entries,每次 AllowLogin 持 mu 锁
//     O(N) 扫描 → 毫秒级 → 所有正常登录被序列化卡死,**这本身就是攻击通道**。
//
// 修复:
//   - 硬上限 loginRLMaxEntries:超出 cap 拒绝新增 entry 但仍走限速判定,
//     攻击者灌再多新 IP 也只让 map 停在 cap,不会增长;
//   - GC 改为「累计 N 次 call 才扫一次」:正常路径上不持锁全扫;
//   - cap 满时一次 forceGC:扫一遍最老的 lastSeen,腾不出空间就拒绝新 IP 登录
//     (并写 WARN 让运维察觉攻击发生)。
const (
	loginRLBurst = 3
	// loginRLRate 是旧的固定速率(5 次/60s),现已被 [server].login_rate_limit_per_min
	// 取代为运行时可配置(见 loginIPLimiter.ratePerMin)。保留它作为「历史默认 / 建议起步值」
	// 与单测使用的参考速率(测试通过 SetRatePerMin(int(loginRLRate*60)) 复现旧行为)。
	loginRLRate         = rate.Limit(5.0 / 60.0) // 5 / 60s
	loginRLGCTTL        = 30 * time.Minute
	loginRLMaxEntries   = 4096
	loginRLGCEveryNCall = 100

	// I1(2026-05-22)log 节流间隔。
	//
	// 不加节流时,攻击者 100 req/s × per-IP deny → 100 WARN/s;
	// 同步 fsync 写盘 + logrus 锁竞争能把 server 自己卡住。
	// 节流策略:同一事件 60s 内只打一行 WARN,把这段时间内累积的次数一并写出来。
	loginRLWarnThrottle = 60 * time.Second
)

type loginIPLimiter struct {
	mu       sync.Mutex
	limits   map[string]*loginIPEntry
	callsSeq uint64 // 累计 AllowLogin 调用次数,触发摊销 GC
	// H1:capExceeded 计数 — cap 满 + forceGC 也腾不出空间时拒绝新 IP 次数。
	// 暴露给 /status,运维看到这个 > 0 就知道有大规模灌包攻击。
	capExceeded uint64
	// I1:cap-exceeded WARN 全局节流。原子读写,避免 hot path 加锁。
	capExceededWarnAt    atomic.Int64  // 上次 WARN 的 unix nano,0 = 从未
	capExceededSinceWarn atomic.Uint64 // 自上次 WARN 后累积的拒绝次数

	// ratePerMin 是「每 IP 每分钟最多登录次数」配置值([server].login_rate_limit_per_min)。
	// 用 atomic 持有,便于 SIGHUP 热更与无锁短路:
	//   - <=0 → **不限制**(默认零值):AllowLogin 直接放行,不建 entry、不占内存;
	//   - >0  → 新建 per-IP entry 用 rate.Limit(ratePerMin/60),突发固定 loginRLBurst。
	// 改值只影响**新建** entry;已存在的 entry 维持创建时速率,30min 内 GC 后按新值重建
	//(与本仓库其它限速「reload 仅对未来登录生效」语义一致)。
	ratePerMin atomic.Int64
}

type loginIPEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
	// I1:per-IP deny WARN 节流。lastWarnAt 是该 IP 上次打 WARN 的时间;
	// denySinceWarn 是自此之后累积的 deny 次数(下次 WARN 时附带打出)。
	lastWarnAt    time.Time
	denySinceWarn uint64
}

var globalLoginIPLimiter = &loginIPLimiter{limits: make(map[string]*loginIPEntry)}

// SetRatePerMin 配置每 IP 每分钟登录尝试上限(0 = 不限制)。
//
// main 启动时按 [server].login_rate_limit_per_min 调一次;SIGHUP 热更时再调。
// 原子写,立即对后续 AllowLogin 生效:切到 0 立刻全量放行;切到 N>0 后**新建**的
// per-IP entry 按新速率,已存在 entry 维持旧速率直到 GC(30min)后重建。负值按 0 处理。
func (l *loginIPLimiter) SetRatePerMin(n int) {
	if n < 0 {
		n = 0
	}
	l.ratePerMin.Store(int64(n))
}

// AllowLogin 返回 (allowed, host)。allowed=false 时调用方应当直接拒绝登录,不要继续做
// argon2 verify;否则一台机器单 IP 高频尝试就能把全局 argon2Sema 占满让正常用户饿死。
func (l *loginIPLimiter) AllowLogin(remoteAddr string) (bool, string) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // fallback,某些 conn type 没有 port,整体当 key
	}

	// 0 = 不限制(默认):无锁短路放行,不建 entry、不做 GC,零开销。
	// 这是 [server].login_rate_limit_per_min 的默认语义,运维显式配 >0 才启用限速。
	rpm := l.ratePerMin.Load()
	if rpm <= 0 {
		return true, host
	}
	limitPerSec := rate.Limit(float64(rpm) / 60.0)

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.callsSeq++

	// 摊销 GC:每 N 次 call 才走一遍全扫;正常路径只做 hashmap 查询。
	// 这样 map 大小恒定时,平均每次 AllowLogin 是 O(1)。
	if l.callsSeq%loginRLGCEveryNCall == 0 {
		for k, v := range l.limits {
			if now.Sub(v.lastSeen) > loginRLGCTTL {
				delete(l.limits, k)
			}
		}
	}

	e, ok := l.limits[host]
	if !ok {
		// H1:cap-aware insert。已有 entry 走快路径,新 IP 才需要 cap 检查。
		if len(l.limits) >= loginRLMaxEntries {
			// 全扫一次找最老,试图腾空间。如果最老的也还没过 TTL,
			// 说明攻击者灌的全是新鲜流量 → 拒绝新增,直接 deny。
			l.forceGCLocked(now)
			if len(l.limits) >= loginRLMaxEntries {
				l.capExceeded++
				// 不创建 entry(攻击者灌再多 IP 也不会让 map 膨胀)。
				// 直接 deny 本次登录:这是合理的「过载保护」语义 ——
				// 高峰期来自陌生 IP 的登录会被偶发拒一次,客户端重试即可
				// 拿到新一轮 cap budget;正常用户来自常驻 IP,entry 已经
				// 在 map 里,走 fast path 不受影响。
				//
				// I1 log 节流:cap-exceeded 是攻击信号,但攻击者灌 1k 新 IP/s
				// 不能让 server 1k WARN/s,把 fsync 自己卡死。每 60s 最多打一次,
				// 累积次数一并写出。判定 + Add 用原子,避免持锁段拉长。
				l.capExceededSinceWarn.Add(1)
				nowNS := now.UnixNano()
				lastNS := l.capExceededWarnAt.Load()
				if nowNS-lastNS >= int64(loginRLWarnThrottle) &&
					l.capExceededWarnAt.CompareAndSwap(lastNS, nowNS) {
					acc := l.capExceededSinceWarn.Swap(0)
					logrus.WithFields(logrus.Fields{
						"ip":                  host,
						"cap":                 loginRLMaxEntries,
						"cap_exceeded_total":  l.capExceeded,
						"deny_in_last_window": acc,
						"window":              loginRLWarnThrottle.String(),
					}).Warn("[login-ratelimit] per-IP 状态表已满,拒绝新 IP 登录(可能遭遇 IPv6 灌包)")
				}
				return false, host
			}
		}
		e = &loginIPEntry{lim: rate.NewLimiter(limitPerSec, loginRLBurst)}
		l.limits[host] = e
	}
	e.lastSeen = now
	if !e.lim.Allow() {
		// I1 log 节流:同一 IP 的 deny 每 60s 最多打一次,期间累计次数随下次 WARN
		// 一起写出。这里持 l.mu,e.lastWarnAt / e.denySinceWarn 直接走非原子。
		e.denySinceWarn++
		if now.Sub(e.lastWarnAt) >= loginRLWarnThrottle {
			acc := e.denySinceWarn
			e.denySinceWarn = 0
			e.lastWarnAt = now
			logrus.WithFields(logrus.Fields{
				"ip":                  host,
				"burst":               loginRLBurst,
				"rate_per_min":        rpm,
				"deny_in_last_window": acc,
				"window":              loginRLWarnThrottle.String(),
			}).Warn("[login-ratelimit] per-IP 登录尝试超频,拒绝")
		}
		return false, host
	}
	return true, host
}

// forceGCLocked 在 cap 满时调用:扫一遍 map,删所有超过 TTL 的 entry。
// 调用方必须持有 l.mu。
func (l *loginIPLimiter) forceGCLocked(now time.Time) {
	for k, v := range l.limits {
		if now.Sub(v.lastSeen) > loginRLGCTTL {
			delete(l.limits, k)
		}
	}
}
