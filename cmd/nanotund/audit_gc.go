package main

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// P2-16: audit_logs 定时 prune + 体积监控
//
// 背景:logrotate 只管应用日志文件,**不**管 SQLite。audit_logs 表会随着登录失败 /
// kick / reload / takeover / acl drop 等事件每天积累几千到几十万行,长跑 N 个月后
// 整张 audit_logs + WAL 可以撑到几 GB,sqlite IO 退化、备份成本上升。
//
// 设计取舍:
//   - 保留窗口固定 30 天:合规要求一般 ≥ 30 天,典型生产 SLO 与 K2 用的 12/min ERROR
//     聚合也是 N 天对账,30 天够查;长于 30 天的审计应当导出到 log shipper / 冷存储。
//   - 周期 24h:Prune 本身耗时 ~100ms 量级,频率太高浪费 IO,太低让监控/磁盘吃紧;
//     pick 24h 与 logrotate.daily 节奏对齐。
//   - 启动时跑一次:防止「重启刚好错过 24h tick」让旧数据多堆一天。
//   - **不**做 VACUUM:VACUUM 会重建文件 + 长时间排他锁,运维风险大。SQLite
//     auto-vacuum 默认开启时空间会逐步回收,不开也只是磁盘占位 —— 不影响查询速度。
//     如需空间回收,运维手动 `sqlite3 ... 'VACUUM'`(维护窗口期)。
//
// 关闭:绑 globalContext;ctx 取消后退出。

const (
	auditPruneRetention = 30 * 24 * time.Hour
	auditPruneInterval  = 24 * time.Hour
	auditMonitorBigSize = 1_000_000 // 行数,超过这个值打 WARN 让运维感知
)

// startAuditGC 在后台起一条 goroutine 周期性 prune audit_logs。
// st 为 nil(测试场景兜底)时直接 no-op。
//
// 返回 cleanup func,但本 goroutine 是 ctx-aware,正常 shutdown 路径不依赖 cleanup;
// 留 cleanup 接口只为对称(以后接 metric / health 报告)。
func startAuditGC(st *store.Store) func() {
	if st == nil {
		return func() {}
	}
	go safeGlobalGoroutine("auditGC", globalContextCancel, func() {
		runAuditGCLoop(globalContext, st, auditPruneRetention, auditPruneInterval)
	})
	return func() {}
}

// runAuditGCLoop 抽出来便于 unit test 注入更短的 retention/interval。
//
// 进入立刻跑一次 prune(防错过 tick),然后按 interval ticker 循环;ctx.Done 时退出。
func runAuditGCLoop(ctx context.Context, st *store.Store, retention, interval time.Duration) {
	if ctx == nil {
		ctx = context.Background()
	}
	doOnce := func() {
		// per-iteration short ctx,防止 SIGTERM 时整个 DELETE 拖死 shutdown;
		// 同时避免被父 ctx 的 deadline 影响(父 ctx 通常是 background)。
		opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cutoff := time.Now().Add(-retention).Unix()
		n, err := st.PruneAuditBefore(opCtx, cutoff)
		if err != nil {
			logrus.WithError(err).Warn("[audit-gc] prune audit_logs 失败,下次再试")
			return
		}
		// 总量监控:超过阈值打 WARN,运维可以选择手动 VACUUM 或调短 retention。
		total, errC := st.CountAudit(opCtx)
		if errC != nil {
			logrus.WithError(errC).Debug("[audit-gc] count audit_logs 失败(忽略)")
		}
		fields := logrus.Fields{
			"pruned":    n,
			"retention": retention.String(),
			"total":     total,
			"cutoff":    cutoff,
		}
		if total >= auditMonitorBigSize {
			logrus.WithFields(fields).Warnf("[audit-gc] audit_logs 行数已超过 %d,建议运维检查磁盘占用 / 缩短保留窗口", auditMonitorBigSize)
		} else if n > 0 {
			logrus.WithFields(fields).Info("[audit-gc] prune 完成")
		} else {
			logrus.WithFields(fields).Debug("[audit-gc] 无需 prune")
		}
	}
	doOnce()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logrus.Info("[audit-gc] ctx 已取消,退出 prune 循环")
			return
		case <-t.C:
			doOnce()
		}
	}
}
