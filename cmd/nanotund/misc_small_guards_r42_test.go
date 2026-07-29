package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// TestByDeviceLookups_AnonymousDeviceIsNeverAForwardingTarget:deviceID==0 是「没上报 UUID 的匿名会话」
// 的形状。两道防线各自都必须在:入索引侧拒绝把它记进 connByDevice,查询侧也拒绝 deviceID==0 的查询。
//
// 为什么要两层:出口/子网转发的目标 deviceID 来自审批表与客户端选择帧。任何一条读到 0(库里的历史脏行、
// 客户端漏填、解析失败降级)如果被解释成「匿名那一桶里随便挑一条」,流量就会投给一台没装 NAT、
// 甚至不属于该用户的机器。所以「查 0 恒 nil」不能只依赖「0 永远不入索引」。
func TestByDeviceLookups_AnonymousDeviceIsNeverAForwardingTarget(t *testing.T) {
	// 第一层:入索引侧。匿名会话即使 advertise 了出口,也不该出现在索引里。
	anon := &Connection{connIDStr: "anon-session", deviceID: 0}
	anon.advertisedExit.Store(true)
	anon.advertisedSubnetRoutes.Store(true)
	installDeviceConn(t, anon)

	connIDMapMu.RLock()
	_, indexed := connByDevice[0]
	connIDMapMu.RUnlock()
	if indexed {
		t.Error("匿名会话(deviceID=0)不该进 by-device 索引 —— 它不能当出口/子网转发目标")
	}

	// 第二层:查询侧。直接把 0 这一桶塞进索引(绕过入口守卫,模拟脏数据/未来改动),
	// 三个 lookup 仍必须返回 nil。
	connIDMapMu.Lock()
	connByDevice[0] = map[string]*Connection{anon.connIDStr: anon}
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connByDevice, 0)
		connIDMapMu.Unlock()
	})

	if got := lookupActiveConnByDevice(0); got != nil {
		t.Errorf("lookupActiveConnByDevice(0) 应为 nil,got %q", got.connIDStr)
	}
	if got := lookupRunningExitConnByDevice(0); got != nil {
		t.Errorf("lookupRunningExitConnByDevice(0) 应为 nil,got %q —— 会把公网流量投给匿名会话", got.connIDStr)
	}
	if got := lookupSubnetAdvertiserConnByDevice(0); got != nil {
		t.Errorf("lookupSubnetAdvertiserConnByDevice(0) 应为 nil,got %q —— 内网包会漏进匿名会话所在 LAN", got.connIDStr)
	}
}

// TestWarnIsolateBlocksApprovedRelays_SaysWhichKindsAreDeadAndHowMany:isolate 下已批准的出口/子网
// 全部黑洞,启动期必须把「有多少条已经批过但在本模式下不生效」说清楚 —— 否则运维只看到 admin 列表里
// 的 ✓,查不出为什么 curl 全超时(三机实测 2026-07-25 就是这么白查一轮的)。
func TestWarnIsolateBlocksApprovedRelays_SaysWhichKindsAreDeadAndHowMany(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "isolate_warn.db"), store.Options{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	gw := &gatewayState{store: st}

	prev := clientIsolateMode.Load()
	clientIsolateMode.Store(true)
	t.Cleanup(func() { clientIsolateMode.Store(prev) })

	user, err := st.CreateUser(ctx, store.NewUser{Username: "iso", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	// 一台出口设备(v4+v6 默认路由算一台)+ 两条子网路由。
	dev := mustUpsertDeviceForIsolateWarn(t, st, user.ID, "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", "exit-box")
	other := mustUpsertDeviceForIsolateWarn(t, st, user.ID, "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb", "lan-box")
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		mustApproveRouteForIsolateWarn(t, st, dev, cidr)
	}
	for _, cidr := range []string{"192.168.88.0/24", "10.77.0.0/16"} {
		mustApproveRouteForIsolateWarn(t, st, other, cidr)
	}

	hook := &countingLogHook{levels: []logrus.Level{logrus.WarnLevel}}
	logrus.AddHook(hook)
	t.Cleanup(func() { hook.mu.Lock(); hook.levels = []logrus.Level{logrus.PanicLevel}; hook.mu.Unlock() })

	warnIsolateBlocksApprovedRelays(ctx, gw)

	hook.mu.Lock()
	msgs := append([]string(nil), hook.msgs...)
	hook.mu.Unlock()
	var found bool
	for _, m := range msgs {
		if strings.Contains(m, "exit_mode=isolate") {
			found = true
		}
	}
	if !found {
		t.Fatalf("isolate 下有 1 台出口设备 + 2 条子网路由已批准,必须报警;实际 WARN=%v", msgs)
	}

	// 计数口径:同一台出口设备的 v4/v6 默认路由算一台,不是两条。
	routes, err := st.ListRoutesByStatus(ctx, "approved")
	if err != nil {
		t.Fatal(err)
	}
	exitDevices, subnetRoutes := countIsolateBlockedApprovals(routes)
	if exitDevices != 1 || subnetRoutes != 2 {
		t.Errorf("统计口径错:want 出口设备 1 / 子网 2,got %d / %d", exitDevices, subnetRoutes)
	}
}

// TestWarnIsolateBlocksApprovedRelays_DBFailureStaysQuiet:这条提醒是 best-effort。库查不动时
// 只该 Debug 掉,不能把启动日志变吵(更不能因为一条提醒失败就影响启动)。
func TestWarnIsolateBlocksApprovedRelays_DBFailureStaysQuiet(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "isolate_warn_closed.db"), store.Options{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = st.Close() // 关掉 → ListRoutesByStatus 必失败

	prev := clientIsolateMode.Load()
	clientIsolateMode.Store(true)
	t.Cleanup(func() { clientIsolateMode.Store(prev) })

	hook := &countingLogHook{levels: []logrus.Level{logrus.WarnLevel, logrus.ErrorLevel}}
	logrus.AddHook(hook)
	t.Cleanup(func() { hook.mu.Lock(); hook.levels = []logrus.Level{logrus.PanicLevel}; hook.mu.Unlock() })

	warnIsolateBlocksApprovedRelays(ctx, &gatewayState{store: st})

	if n := hook.count(); n != 0 {
		hook.mu.Lock()
		msgs := append([]string(nil), hook.msgs...)
		hook.mu.Unlock()
		t.Errorf("库查不动时这条提醒应静默(Debug),不该打 %d 条 WARN/ERROR:%v", n, msgs)
	}
}

// TestBroadcastShutdownClose_NegativeTimeoutFallsBackToTheDefault:配置里把 drain 超时写成负数
// (或调用方传了个未初始化的 Duration)时,必须回落到默认窗口,而不是拿负数当 0 用 —— 那样 Close 帧
// 刚写出去就 main return,listener.Close + http.Server.Shutdown 当场收走连接,客户端来不及处理
// 这一帧,看到的是一片「连接被重置」,于是按「异常断线」立刻重连:新进程刚起来就被重连风暴打爆,
// 正是这个 code(902)要避免的事。
//
// 观察量是「等了多久」,所以把默认窗口调小到毫秒级;负数与显式 0 各跑一次,两者必须分得开。
func TestBroadcastShutdownClose_NegativeTimeoutFallsBackToTheDefault(t *testing.T) {
	prev := shutdownDrainTimeout
	shutdownDrainTimeout = 250 * time.Millisecond
	t.Cleanup(func() { shutdownDrainTimeout = prev })

	// 广播只在「有 active session」时才走到等待那步,所以要装一条。linkConn 留 nil:
	// 写帧那步会跳过(与已被接管 / 正在清理的会话同一形状),本用例只关心等待时长。
	c := &Connection{connIDStr: "drain-timeout-probe"}
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		if cur, ok := connIDMap[c.connIDStr]; ok && cur == c {
			delete(connIDMap, c.connIDStr)
		}
		connIDMapMu.Unlock()
	})

	start := time.Now()
	broadcastShutdownClose(-time.Second)
	neg := time.Since(start)
	if neg < 200*time.Millisecond {
		t.Errorf("负超时应回落成默认窗口(%v),实际只等了 %v —— 客户端来不及收 Close 帧", shutdownDrainTimeout, neg)
	}

	// 显式 0 是「只发不等」(紧急 kill / 测试),必须真的不等。
	start = time.Now()
	broadcastShutdownClose(0)
	if zero := time.Since(start); zero > 150*time.Millisecond {
		t.Errorf("显式传 0 应立刻返回,实际等了 %v", zero)
	}
}

func mustUpsertDeviceForIsolateWarn(t *testing.T, st *store.Store, userID int64, uuid, name string) int64 {
	t.Helper()
	d, err := st.UpsertDevice(t.Context(), userID, uuid, name, "linux")
	if err != nil {
		t.Fatalf("upsert device %s: %v", name, err)
	}
	return d.ID
}

func mustApproveRouteForIsolateWarn(t *testing.T, st *store.Store, deviceID int64, cidr string) {
	t.Helper()
	ctx := t.Context()
	if _, err := st.UpsertAdvertisedRoute(ctx, deviceID, cidr); err != nil {
		t.Fatalf("upsert route %s: %v", cidr, err)
	}
	if err := st.SetRouteStatus(ctx, deviceID, cidr, "approved", ""); err != nil {
		t.Fatalf("approve route %s: %v", cidr, err)
	}
}
