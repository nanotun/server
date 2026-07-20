package main

import (
	"io"
	"sync/atomic"

	"github.com/nanotun/server/util"
)

// safeRLConnNilCount(可观测, 2026-05-24 → 2026-05-25 Q8 文档强化):
// safeRLConn() 返回 nil 的累计次数,Prometheus 抓为 race_window_total。
//
// 生产语义(纯净):
//
//	atomic.Pointer.Store 是 monotonic write — 一旦 c.rlConn.Store(rwc) 跑过,
//	后续 Load 永远返非 nil 直到 GC。cleanupConnection 也只 delete map 不会 Store(nil)。
//	所以 counter 真实只反映「c 已进 connIDMap 但 c.rlConn.Store(rwc) 还没跑」
//	这个 N38 race window 在生产被撞到的次数,**生产预期严格 0**。
//
// 测试噪声警告:
//
//	大量单测 fake conn(user_invalidate_test / shutdown_drain_test / route_advertise_test
//	等)构造 Connection 时根本不 Store rlConn,如果这些 fake conn 进过 connIDMap
//	并被 /status 等路径扫到,counter 会被推高。导入 Prometheus 时记得给「真生产
//	环境」打 host label,跟 CI 测试 host 区分,不然 dashboard 会被噪声淹掉。
//
// 与 cleanupConnection 的关系:cleanupConnection 走的是 delete(connIDMap, ...) +
// close(rwc),不动 c.rlConn 字段;所以「conn 被 close 但还没从 map 移除的瞬间」
// safeRLConn() 仍返回非 nil(指向已 close 的 rateLimitedConn),不计入 counter。
// 调用方调 SetUploadLimit on closed rwc 是 no-op,不会 panic — 这部分由
// rateLimitedConn 内部 ctx 控制。
var safeRLConnNilCount atomic.Uint64

// 本文件:Connection 字段的并发安全读 helper。
//
// 背景(2026-05-23 N38 race fix → 2026-05-24 atomic.Pointer 升级):
//
// 登录路径 handleVPNLink / handleTakeoverLogin 是这么一段:
//
//   1) connIDMapMu.Lock()            ──┐
//      connIDMap[connIDStr] = c       │  ← 此时 c 已对外可见
//      connByUserAddLocked(c)         │
//      ... supersede / evict ...     │
//      connIDMapMu.Unlock()           ──┘
//
//   2) 几百行后:vIP 分配、写 login resp、构造 rate.Limiter ...
//
//   3) c.linkWrMu.Lock()
//      c.linkConn = rwc               ← 真正赋值(interface 走 linkWrMu)
//      c.rlConn.Store(rwc)            ← atomic.Pointer 写
//      c.linkWrMu.Unlock()
//
// 中间 1)→3) 的窗口期(亚毫秒级),c 已经在 connIDMap 里被外部 goroutine
// 看到,但 c.linkConn / c.rlConn 还是 nil。
//
// 老路径(user_invalidate / route_advertise / wss_keepalive / shutdown_drain)
// 读 c.linkConn 时已经走 c.linkWrMu.Lock() 同步;0011/0012 新加的 control socket
// 三处(/status、/rate/refresh、/users/rate/refresh)曾裸读 c.rlConn,跟 3) 的
// 写形成 data race。
//
// 修法演进:
//   - 2026-05-23 第一版用 c.linkWrMu 短锁包读(safeRLConn 内部 Lock/Unlock)。
//     一致但读侧抢锁会等到 linkWrMu 写帧释放(几 ms 慢链路也跟着卡)。
//   - 2026-05-24 升级 atomic.Pointer[rateLimitedConn]:写侧 Store(),读侧 Load(),
//     纳秒级,零锁,Go memory model 保证 Store→Load happens-before。
//     c.linkConn 仍是 interface 无法简单 atomic,保留 linkWrMu 老路径。
//
// safeRLConn() 保留作为公共入口(三个 control 路径都走这条),哪天再升级实现
// 也只动这一处,调用方无需感知。

// safeRLConn 返回 c.rlConn 当前快照,无锁原子读。
//
// 返回 nil 含义:数据面未建立(登录路径还没走到 c.rlConn.Store(rwc)),或者
// cleanupConnection 已经 close。调用方应判 nil 后跳过(对死 conn 调
// SetUploadLimit 也无害,但跳过省一次方法调用)。
//
// 可观测性:nil 路径累加 safeRLConnNilCount 计数器,/status 暴露 race_window_total,
// 方便事后看「过去 24h N38 窗口期撞到几次」。
func (c *Connection) safeRLConn() *rateLimitedConn {
	if c == nil {
		return nil
	}
	rl := c.rlConn.Load()
	if rl == nil {
		safeRLConnNilCount.Add(1)
	}
	return rl
}

// safeLinkConn 返回 c.linkConn 当前快照,语义同 safeRLConn。
// 暂时未被新代码用(老路径都已经各自持 linkWrMu 操作),保留作为后续重构出口。
func (c *Connection) safeLinkConn() io.ReadWriteCloser {
	if c == nil {
		return nil
	}
	c.linkWrMu.Lock()
	lc := c.linkConn
	c.linkWrMu.Unlock()
	return lc
}

// safeClientIPs(S1, 2026-05-26):返回 c.clientIPs 的当前快照,无锁原子读。
//
// 返回值:
//   - nil:c == nil,或登录路径还没跑到 c.clientIPs.Store(...);
//   - 非 nil 切片:登录路径已经分配好 vIP(可能空 — 没分到 vIP 的会话也合法,
//     比如所有 vIP 池都满)。
//
// 调用方应当 range 返回值,不要直接 deref atomic 字段。
//
// 安全性:atomic.Pointer.Load 是 sequentially consistent,跟 Store 之间有
// happens-before;调用方在锁外 range 也不会读到撕裂的 slice header。slice
// underlying array 由 GC 保证生存(只要调用方持有引用)。
func (c *Connection) safeClientIPs() []util.VirtualIPAssignment {
	if c == nil {
		return nil
	}
	p := c.clientIPs.Load()
	if p == nil {
		return nil
	}
	return *p
}
