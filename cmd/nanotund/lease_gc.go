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
//   - [server].lease_gc_idle_days       默认 30,0/负 = 关闭定时回收(回归手动 cron 模型)
//   - [server].lease_gc_interval_hours  默认 24
//
// 关闭后 admin CLI 的 lease gc 子命令仍可工作,不受影响。

const (
	defaultLeaseGCIdleDays      = 30
	defaultLeaseGCIntervalHours = 24
)

// leaseGCCount 累计已回收的 lease 总数,/metrics + 日志摘要消费。
var leaseGCCount atomic.Uint64

// startLeaseGCLoop 在后台开一条 goroutine 周期性回收 idle lease。
// gw/store 为 nil 或 idleDays<=0 时 no-op。
func startLeaseGCLoop(gw *gatewayState, idleDays, intervalHours int) func() {
	if gw == nil || gw.store == nil {
		return func() {}
	}
	if idleDays <= 0 {
		// 显式关闭。打一条 INFO 留痕,运维事后查日志能确认。
		logrus.Info("[lease-gc] 已通过 [server].lease_gc_idle_days<=0 显式关闭定时回收,如需启用请重新设置")
		return func() {}
	}
	if intervalHours <= 0 {
		intervalHours = defaultLeaseGCIntervalHours
	}
	idle := time.Duration(idleDays) * 24 * time.Hour
	interval := time.Duration(intervalHours) * time.Hour
	go safeGlobalGoroutine("leaseGC", globalContextCancel, func() {
		runLeaseGCLoop(globalContext, gw.store, idle, interval)
	})
	return func() {}
}

// runLeaseGCLoop 抽出来便于 unit test 注入更短的 idle/interval。
func runLeaseGCLoop(ctx context.Context, st *store.Store, idle, interval time.Duration) {
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
