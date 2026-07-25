package main

import (
	"context"
	"time"

	"github.com/nanotun/server/store"

	"github.com/sirupsen/logrus"
)

// exit_mode=isolate 与「经其它客户端中转」的两个特性(出口节点、子网路由)是互斥的:
// isolate 在 FORWARD 链装 `-i <tun> -o <tun> DROP`,而这两类流量的回程都是普通 mesh 投递、
// 要过内核转发 —— 于是审批照常生效、admin exit list 照常打 ✓、数据面却整条黑洞。
//
// 三机实测(2026-07-25)踩到:isolate 下 A 经已批准的出口 C 出网 curl 全超时,已批准子网路由
// 192.168.88.0/24 也 100% 不通,而 server 侧还打出了「会话开始经出口节点转发公网流量」的审计。
// 控制面已改成当场拒绝出口选择(见 handleEgressSelectFrame);这里补启动期的一次性提醒,
// 让「库里已经批过一堆、换成 isolate 后集体失效」这件事在日志里说清楚。

// countIsolateBlockedApprovals 统计已批准的路由里有多少属于「isolate 下不会生效」的中转类:
// 出口设备按 device 去重(0.0.0.0/0 与 ::/0 属同一台设备,不该算两个),子网路由按条计。
func countIsolateBlockedApprovals(routes []store.SubnetRoute) (exitDevices, subnetRoutes int) {
	seenExitDev := make(map[int64]struct{})
	for _, r := range routes {
		if r.CIDR == "0.0.0.0/0" || r.CIDR == "::/0" {
			seenExitDev[r.DeviceID] = struct{}{}
			continue
		}
		subnetRoutes++
	}
	return len(seenExitDev), subnetRoutes
}

// warnIsolateBlocksApprovedRelays 在 exit_mode=isolate 且库里已有中转类审批时打一条 WARN。
// best-effort:非 isolate 直接返回;DB 查不动只 Debug(启动不该因为一条提醒而变吵或变慢)。
func warnIsolateBlocksApprovedRelays(ctx context.Context, gw *gatewayState) {
	if gw == nil || gw.store == nil || !clientIsolateMode.Load() {
		return
	}
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	routes, err := gw.store.ListRoutesByStatus(dbCtx, "approved")
	if err != nil {
		logrus.WithError(err).Debug("[isolate] 查已批准路由失败,跳过 isolate 兼容性提醒")
		return
	}
	exitDevices, subnetRoutes := countIsolateBlockedApprovals(routes)
	if exitDevices == 0 && subnetRoutes == 0 {
		return
	}
	logrus.WithFields(logrus.Fields{
		"exit_devices":  exitDevices,
		"subnet_routes": subnetRoutes,
	}).Warn("[isolate] exit_mode=isolate 会 DROP 所有客户端间转发:这些已批准的出口设备 / 子网路由在本模式下不会承载流量" +
		"(要用它们请改 exit_mode=mesh;要维持隔离请用 nanotun-admin exit revoke / route delete 清掉,避免客户端装上黑洞路由)")
}
