package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// P1#9: server 内置 lease_gc 定时任务
//
// 背景:`store.GcOrphanLeases` 当前只在 admin CLI `nanotun-admin lease gc` 里被调用,
// 运维必须自己加 cron 才会跑;漏跑就让 leases 表里堆满「设备半年没上线」的 vIP 占位,
// 后续新设备拿不到 vIP(尤其 /28 的 IPv4 私网池场景)。
//
// 设计与 audit_gc 对齐:
//   - 启动跑一次(防错过 tick);
//   - 默认每天一次(24h ticker);
//   - 默认 idle 阈值 30 天 —— 比短(7 天)激进,避免周末 / 春节没上线的设备误回收;
//   - 比长(90 天)保守,避免长期残留;
//   - per-iteration 30s opCtx,确保 SIGTERM 时不会拖死 shutdown。
//
// 配置:
//   - [server].lease_gc_idle_days       不写 / 写 0 都是默认 30;**要关闭得写负数**(如 -1),
//     关闭后回归手动 cron 模型。理由见 config.LeaseGCIdleDays 的注释 —— int 零值分不出
//     「没配」与「显式 0」,把 0 当关闭会让没配过它的部署统统静默停掉回收。
//   - [server].lease_gc_interval_hours  默认 24
//
// 关闭后 admin CLI 的 lease gc 子命令仍可工作,不受影响。

const (
	defaultLeaseGCIdleDays      = 30
	defaultLeaseGCIntervalHours = 24
	// defaultLeaseGCStartupGraceSec:首轮回收在启动后延后多久再跑。
	//
	// 为什么必须延后(2026-07-30):doOnce 里那段 E1 防误伤 —— 回收前把**在线**会话持有的
	// device 的 last_seen_at 顶到 now —— 依赖 activeDeviceIDsSnapshot()。而启动那一瞬间
	// 一条会话都还没重连上来,快照必然是空的,这道防御在首轮完全空转。后果:一台
	// 「连续在线超过 idle 天数、期间没重新登录」的设备(last_seen_at 只在登录时刷),
	// 每次重启都会被收掉粘性租约 —— 重连后换 IP,按 vIP 钉的 ACL / 端口转发一起落空。
	// 延后到客户端重连之后再跑,E1 那道防御在首轮才真正生效。
	//
	// 120s 的取法:客户端断线重连是指数退避、上限 30s,两倍余量。首轮延后对这个功能
	// 本身没有代价 —— 它是天级的清扫任务,晚两分钟跑没有任何区别。
	defaultLeaseGCStartupGraceSec = 120
)

// leaseGCCount 累计已回收的 lease 总数,/metrics + 日志摘要消费。
var leaseGCCount atomic.Uint64

// startLeaseGCLoop 在后台开一条 goroutine 周期性回收 idle lease。
// gw/store 为 nil 或 idleDays<=0 时 no-op。
// startupGrace 为首轮回收的延后时长(见 defaultLeaseGCStartupGraceSec);<0 表示不延后。
func startLeaseGCLoop(gw *gatewayState, idleDays, intervalHours int, startupGrace time.Duration) func() {
	if gw == nil || gw.store == nil {
		return func() {}
	}
	if idleDays <= 0 {
		// 显式关闭。打一条 INFO 留痕,运维事后查日志能确认。
		logrus.Info("[lease-gc] 已通过 [server].lease_gc_idle_days 负值显式关闭定时回收,如需启用请设为正数天数")
		return func() {}
	}
	if intervalHours <= 0 {
		intervalHours = defaultLeaseGCIntervalHours
	}
	idle := time.Duration(idleDays) * 24 * time.Hour
	interval := time.Duration(intervalHours) * time.Hour
	// 启用也要留痕,与上面关闭那条对称:这套机制会**删库里的行**(vIP 占位),而在此之前
	// 启用侧一个字都不打 —— 只有真删到东西时才有 INFO。于是「按 30 天在回收」这件事在
	// 日志里不可见,运维照文档写了 0 以为关掉了也无从发现(2026-07-30 那处文档与代码矛盾
	// 之所以能一直活着,缺的就是这条)。
	if startupGrace < 0 {
		startupGrace = 0
	}
	logrus.WithFields(logrus.Fields{
		"idle":          idle.String(),
		"interval":      interval.String(),
		"startup_grace": startupGrace.String(),
	}).Info("[lease-gc] 定时回收已启用")
	go safeGlobalGoroutine("leaseGC", globalContextCancel, func() {
		runLeaseGCLoop(globalContext, gw.store, idle, interval, startupGrace)
	})
	return func() {}
}

// runLeaseGCLoop 抽出来便于 unit test 注入更短的 idle/interval/startupGrace。
func runLeaseGCLoop(ctx context.Context, st *store.Store, idle, interval, startupGrace time.Duration) {
	if ctx == nil {
		ctx = context.Background()
	}
	doOnce := func() {
		opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		// E1(2026-05-22):跑 GcOrphanLeases 之前,把所有 active session 持有的
		// device 的 last_seen_at 顶到 now。否则长在线客户端(>idle 天数)的 vIP
		// 会被误回收 —— 因为 GcOrphanLeases 看 devices.last_seen_at,而老路径
		// last_seen_at 只在登录时刷,长会话期间一直不变。
		// 失败不致命,只是这一轮可能会误回收,下一轮自然恢复。
		if active := activeDeviceIDsSnapshot(); len(active) > 0 {
			if err := st.BatchTouchDevices(opCtx, active); err != nil {
				logrus.WithError(err).WithField("count", len(active)).Warn("[lease-gc] 刷新 active device last_seen_at 失败,本轮回收可能误伤")
			}
		}
		n, err := st.GcOrphanLeases(opCtx, int64(idle.Seconds()))
		if err != nil {
			logrus.WithError(err).WithField("idle", idle.String()).Warn("[lease-gc] 回收 lease 失败,下次再试")
			return
		}
		if n > 0 {
			leaseGCCount.Add(uint64(n))
			logrus.WithFields(logrus.Fields{
				"reclaimed":    n,
				"idle":         idle.String(),
				"total_so_far": leaseGCCount.Load(),
			}).Info("[lease-gc] 回收完成")
		} else {
			logrus.WithField("idle", idle.String()).Debug("[lease-gc] 无可回收的 lease")
		}
	}
	// 首轮延后:等客户端重连上来,doOnce 里那段 E1 防误伤才有会话可顶(理由见
	// defaultLeaseGCStartupGraceSec)。等待期间收到 ctx 取消就直接退出,不能拖住 shutdown。
	if startupGrace > 0 {
		timer := time.NewTimer(startupGrace)
		select {
		case <-ctx.Done():
			timer.Stop()
			logrus.Info("[lease-gc] 启动宽限期内 ctx 已取消,首轮回收未执行")
			return
		case <-timer.C:
		}
	}
	doOnce()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logrus.Info("[lease-gc] ctx 已取消,退出回收循环")
			return
		case <-t.C:
			doOnce()
		}
	}
}
