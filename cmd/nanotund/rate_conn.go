package main

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// V1(2026-05-26):VPN 数据面进/出字节累计计数器。
//
// 埋在 rateLimitedConn Read/Write 出口,**所有** link 上的字节最终都过这两个方法
// (登录路径 / takeover 路径 / TunChan demux / shutdown drain 全部走 c.linkConn,
// 而 c.linkConn 永远是 *rateLimitedConn 包装),因此这两个 counter 就是 VPN 业务流量
// 的真实读数,跟宿主机网卡(eth0)统计可对照看出加密 overhead / smux 多路复用效率。
//
// 命名:
//
//	vpnBytesUp   = 客户端上传 = server 从 link 读出的字节(Read 累加)
//	vpnBytesDown = 客户端下载 = server 向 link 写入的字节(Write 累加)
//
// 与 settings.rate_up_* / rate_down_* 方向语义对齐,排查"上行被限速没生效"等
// 问题时 admin 一眼能对上。
//
// 性能:每帧 1 次 atomic.Add(uint64) — x86_64 single instruction,纳秒级开销,
// 跟当前 mu 短锁(看 limiter 指针)比可以忽略。无锁意味着不会因 counter 访问而
// 拖慢数据面热路径或与控制面 /rate/refresh 互锁。
//
// 单调累加,server 重启清零(跟 Prometheus counter 约定一致;若需"跨重启历史"应
// 上 prometheus / VictoriaMetrics scrape)。
var (
	vpnBytesUp   atomic.Uint64
	vpnBytesDown atomic.Uint64
)

// rateLimitedConn 封装底层连接，对 Read 应用上行限速、对 Write 应用下行限速
//
// 2026-05-23(0011 per-device rate limit):
//   - 加 mu(读写 limiter 指针的轻量互斥),让控制面 /rate/refresh 能在 active conn
//     运行时安全地热更 limiter — 不踢线、不重连。
//   - SetUploadLimit / SetDownloadLimit 允许把 nil → *Limiter(从「不限」切到「限速」)
//     和反方向(*Limiter → nil,从「限速」切回「不限」),覆盖全场景。
//   - 命中已有的 *Limiter 时优先调它的 SetLimit/SetBurst(线程安全,无 alloc),只有
//     nil→非 nil 才 new。原因:rate.NewLimiter 内部用 Mutex,频繁 new 反而会触发 token
//     bucket 重置(已积累的 burst 全清零),热更场景下应尽量保留 limiter 状态。
type rateLimitedConn struct {
	inner io.ReadWriteCloser

	// mu 保护 uploadLimiter / downloadLimiter 字段本身的读写;limiter 内部 token
	// bucket 已自带锁,所以这里只锁「换/读 *Limiter 指针」的窗口,持锁极短。
	mu              sync.Mutex
	uploadLimiter   *rate.Limiter
	downloadLimiter *rate.Limiter

	ctx context.Context
}

func newRateLimitedConn(inner io.ReadWriteCloser, uploadLimiter, downloadLimiter *rate.Limiter, ctx context.Context) *rateLimitedConn {
	return &rateLimitedConn{
		inner:           inner,
		uploadLimiter:   uploadLimiter,
		downloadLimiter: downloadLimiter,
		ctx:             ctx,
	}
}

// SetUploadLimit / SetDownloadLimit:运行时改本 conn 的限速(字节/秒)+ burst 容量。
//   - bps <= 0  → 该方向「不限速」(limiter 字段清空,burst 入参忽略);
//   - bps > 0   → 该方向硬 cap。已有 limiter 优先 SetLimit/SetBurst 复用(保留 token 状态);
//     之前是 nil 才新建。
//
// 调用方:control socket /rate/refresh 端点(改 device 或 settings.default / burst 后)。
// 0012:burst 不再是 const,而是 caller 算出 effective burst 后传进来 ——
// 这样 settings.rate_burst_bytes 热改 + 登录路径 + 接管路径完全共用同一 effective 值,
// 不会出现 "登录走 64 KiB / hot-swap 走 96 KiB" 的不一致。
func (c *rateLimitedConn) SetUploadLimit(bps int64, burst int) {
	c.setOneLimit(&c.uploadLimiter, bps, burst)
}
func (c *rateLimitedConn) SetDownloadLimit(bps int64, burst int) {
	c.setOneLimit(&c.downloadLimiter, bps, burst)
}

func (c *rateLimitedConn) setOneLimit(field **rate.Limiter, bps int64, burst int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if bps <= 0 {
		*field = nil
		return
	}
	if burst <= 0 {
		// 防御:caller 没算 effective burst 直接传 0,fallback 到代码 default
		// (与 effectiveBurst 同一常量,但本文件不引 server.go 那个常量,避免循环依赖)。
		burst = 64 * 1024
	}
	if *field != nil {
		(*field).SetLimit(rate.Limit(bps))
		(*field).SetBurst(burst)
		return
	}
	*field = rate.NewLimiter(rate.Limit(bps), burst)
}

// snapshotLimits 返回当前生效的 (up_bps, down_bps, up_burst, down_burst);nil limiter 报 0(= 不限)。
// 给 control socket /status / /rate/refresh 响应、admin debug 用,不在 hot path。
// 0012:同时回 burst,让 /status 也能展示桶容量,方便排查"突发不够大"等问题。
func (c *rateLimitedConn) snapshotLimits() (upBPS, downBPS int64, upBurst, downBurst int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.uploadLimiter != nil {
		upBPS = int64(c.uploadLimiter.Limit())
		upBurst = c.uploadLimiter.Burst()
	}
	if c.downloadLimiter != nil {
		downBPS = int64(c.downloadLimiter.Limit())
		downBurst = c.downloadLimiter.Burst()
	}
	return
}

// Read / Write 数据路径上**热**:每包都跑。这里的 limiter 字段读取走 mu,
// 但 limiter 自己的 WaitN 没在临界区内,避免「等 token」时把 mu 攥着导致
// 控制面 /rate/refresh 排在后面 etag 这种事故。
//
// 用法:用 mu 拿到 limiter 指针快照后立即解锁,再用快照做 WaitN(若快照非 nil)。
// 切换 limiter 时 c.uploadLimiter 指针被改,但已经被持有的快照仍是合法对象;
// 这一拍的 WaitN 走老 limiter,下一拍就走新的,对客户端来说就是「秒级生效」,
// 完全够用。
func (c *rateLimitedConn) Read(p []byte) (n int, err error) {
	n, err = c.inner.Read(p)
	// N15(2026-05-26):跟 Write 对称 — 只看 n > 0 累加 counter,不再附加 err == nil
	// 守门。io 协议明确允许 Read 返 (n>0, err)(尤其 err == io.EOF):n 字节是有效
	// 已读,流量"事实发生",计数器必须算上。之前 err==nil 才累加在连接关闭那一帧
	// 会少算几 KB(最后一次 Read 通常带 EOF)— 单连接微不足道,但高频短连接
	// 场景(PoW / keepalive 攻击 / smux 子流释放)累计会拉低统计精度。
	//
	// 重复读风险:io 协议下不会 "(n>0, err) 后底层再返同 n 字节"。net.Conn /
	// tls.Conn / smux.Stream 都遵守这条 — 已返回的字节不会重发。
	if n > 0 {
		vpnBytesUp.Add(uint64(n))
	}
	// N15.2(2026-05-26):limiter.WaitN 只在 err == nil && n > 0 时调 — 跟之前
	// 行为对齐,语义干净:
	//   - err == nil 时连接还活着,WaitN 限速有意义;
	//   - err != nil 时连接通常即将 close(EOF / reset / timeout),即便 ctx 还
	//     没 cancel,等 rate limit token 没意义 — 这一帧之后不会再 Read,token
	//     消耗了也是浪费(虽然 ctx cancel 时 rate.Limiter 会 release reservation,
	//     不至于"漏 token",但语义上这一拍多余;省下进 limiter 内部 mu 的开销)。
	if err == nil && n > 0 {
		c.mu.Lock()
		lim := c.uploadLimiter
		c.mu.Unlock()
		if lim != nil {
			_ = lim.WaitN(c.ctx, n)
		}
	}
	return n, err
}

func (c *rateLimitedConn) Write(p []byte) (n int, err error) {
	if len(p) > 0 {
		c.mu.Lock()
		lim := c.downloadLimiter
		c.mu.Unlock()
		if lim != nil {
			_ = lim.WaitN(c.ctx, len(p))
		}
	}
	n, err = c.inner.Write(p)
	// V1:出字节累加。Write 的 n 在 err != nil 时也可能 > 0(部分写),仍要计入 ——
	// 这些字节已经发出去了。这跟 Read 不同:Read 错误 n>0 多数语义是"已读 n 但
	// 后续出错",虽然 n 也算"事实读取",此处稳健起见 Read 路径只在 err==nil 累加;
	// Write 反过来要总是累加非负 n,否则会少算"部分写"的真实出流量。
	if n > 0 {
		vpnBytesDown.Add(uint64(n))
	}
	return n, err
}

func (c *rateLimitedConn) Close() error {
	return c.inner.Close()
}

// SetWriteDeadline 把写截止时间下推到底层 conn。
//
// C3(2026-05-22):底层 raw 通常实现 net.Conn(TCP / TLS / smux Stream 都有),
// 但 rateLimitedConn 之前只暴露 Read/Write/Close,导致上层 type assertion
// `c.linkConn.(interface{ SetWriteDeadline(time.Time) error })` 永远失败 ——
// shutdown_drain.go 里的「广播 Close 帧前 set 1s 写超时」实际上是 no-op。
// 这里把 SetWriteDeadline 透传到 inner(若 inner 不支持则按 no-op 但不报错,
// 保持上层 type assertion ok=true 的语义)。
//
// 同时也是 tunDemuxToLink 写超时 + ctx 中断的下层支撑:per-write deadline
// 由上层在调用 WriteLinkFrame 前后 set / clear。
func (c *rateLimitedConn) SetWriteDeadline(t time.Time) error {
	if d, ok := c.inner.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

// SetReadDeadline 与 SetWriteDeadline 对称,某些路径(如 takeover / handshake
// timeout)会在登录后想给整链 read 也加上 deadline。当前没有调用方,但加上对
// 称避免下次还得二次改 + 与 net.Conn 接口对齐。
func (c *rateLimitedConn) SetReadDeadline(t time.Time) error {
	if d, ok := c.inner.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}
