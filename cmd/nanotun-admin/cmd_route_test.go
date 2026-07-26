package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/util"
)

// 回归（exit-node，live e2e 实测发现）：admin `route approve <device> 0.0.0.0/0` / `::/0` 必须被接受——
// 出口节点正是靠 admin 批准 device 的 /0 路由生效；早先 parseRouteTarget 走非出口归一器把 /0 一律拒掉
// （"cidr /0 not allowed"），导致**根本无法批准任何出口**，整个 exit-node 特性不可用。
func TestParseRouteTarget_AllowsExitDefaultRoutes(t *testing.T) {
	opts := &globalOpts{lang: langZH}
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		id, norm, err := parseRouteTarget(opts, []string{"3077", cidr})
		if err != nil {
			t.Fatalf("parseRouteTarget(%q) 应允许出口默认路由, got err=%v", cidr, err)
		}
		if id != 3077 {
			t.Fatalf("device id 解析错误: got %d want 3077", id)
		}
		if !util.IsExitDefaultRoute(norm) {
			t.Fatalf("归一后 %q 应仍是出口默认路由", norm)
		}
	}

	// 常规子网仍正常归一（网络地址形式）。
	if _, norm, err := parseRouteTarget(opts, []string{"5", "10.0.0.0/24"}); err != nil || norm != "10.0.0.0/24" {
		t.Fatalf("常规子网应正常: norm=%q err=%v", norm, err)
	}

	// 非法 cidr 仍拒。
	if _, _, err := parseRouteTarget(opts, []string{"5", "not-a-cidr"}); err == nil {
		t.Fatal("非法 cidr 应报错")
	}

	// 参数个数错误仍拒。
	if _, _, err := parseRouteTarget(opts, []string{"5"}); err == nil {
		t.Fatal("缺少 cidr 参数应报错")
	}
}

// route approve 对出口默认路由(0/0、::/0)有平台闸口(与 exit designate 同口径);
// 普通子网不受影响;--force 越过。
func TestRouteApprove_ExitPlatformGate(t *testing.T) {
	db := filepath.Join(t.TempDir(), "route-gate.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("gateuser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "77777777-8888-4999-8aaa-bbbbbbbbbbbb", "a-phone", "android")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	for _, cidr := range []string{"0.0.0.0/0", "192.168.50.0/24"} {
		if _, err := st.UpsertAdvertisedRoute(ctx, dev.ID, cidr); err != nil {
			t.Fatalf("upsert route %s: %v", cidr, err)
		}
	}
	_ = st.Close()

	devStr := fmt.Sprintf("%d", dev.ID)
	// android + 0/0 → 拦。
	c, _, stderr := runCLI(t, db, "", "route", "approve", devStr, "0.0.0.0/0")
	if c == 0 {
		t.Fatal("android 设备 approve 0/0 应被平台闸口拦下")
	}
	if !strings.Contains(stderr, "--force") {
		t.Fatalf("报错应提示 --force,实际: %s", stderr)
	}
	// 普通子网不受闸口影响。
	if c, _, e := runCLI(t, db, "", "route", "approve", devStr, "192.168.50.0/24"); c != 0 {
		t.Fatalf("普通子网 approve 不应被拦, code=%d stderr=%s", c, e)
	}
	// --force 越过。
	if c, _, e := runCLI(t, db, "", "route", "approve", devStr, "0.0.0.0/0", "--force"); c != 0 {
		t.Fatalf("--force 应放行, code=%d stderr=%s", c, e)
	}
}

// 深扫第八轮 MED 回归:CLI `route reject` 仅作用于 pending 行,与 web 一致。
// 对已 approved 的路由直接 reject 应被拒(防隐式撤销),--force 才越过;pending 行正常拒绝。
func TestRouteReject_PendingOnlyGuard(t *testing.T) {
	db := filepath.Join(t.TempDir(), "route-reject.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("rejuser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "99999999-1111-4222-8333-444444444444", "a-router", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	for _, cidr := range []string{"10.0.0.0/24", "10.0.1.0/24"} {
		if _, err := st.UpsertAdvertisedRoute(ctx, dev.ID, cidr); err != nil {
			t.Fatalf("upsert route %s: %v", cidr, err)
		}
	}
	// 把 10.0.0.0/24 批到 approved。
	if err := st.SetRouteStatus(ctx, dev.ID, "10.0.0.0/24", util.RouteStatusApproved, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	_ = st.Close()

	devStr := fmt.Sprintf("%d", dev.ID)
	// approved 行直接 reject → 被 pending-only 守卫拦下。
	c, _, stderr := runCLI(t, db, "", "route", "reject", devStr, "10.0.0.0/24")
	if c == 0 {
		t.Fatal("对 approved 路由 reject 应被拒(pending-only 守卫)")
	}
	if !strings.Contains(stderr, "pending") && !strings.Contains(stderr, "route delete") {
		t.Fatalf("报错应提示非 pending / 改用 route delete,实际: %s", stderr)
	}
	// --force 越过守卫,把 approved 强制降级为 rejected。
	if c, _, e := runCLI(t, db, "", "route", "reject", devStr, "10.0.0.0/24", "--force"); c != 0 {
		t.Fatalf("--force 应放行 reject, code=%d stderr=%s", c, e)
	}
	// pending 行正常 reject。
	if c, _, e := runCLI(t, db, "", "route", "reject", devStr, "10.0.1.0/24"); c != 0 {
		t.Fatalf("pending 路由 reject 应成功, code=%d stderr=%s", c, e)
	}
}

// 三机实测回归(2026-07-25):按族撤掉出口路由时,若另一族仍 approved,该 device **仍是合法出口**——
// 出口绑定按 device 判定,实测「只撤 0.0.0.0/0、留 ::/0」后使用方的 v4 出网 IP 仍是出口节点的公网 IP。
// 此前完全静默,操作者会以为已撤销 v4 出口。现在必须告警并指路 `exit revoke`。
func TestRouteDelete_WarnsWhenOtherExitFamilyStillApproved(t *testing.T) {
	db := filepath.Join(t.TempDir(), "route-exit-family.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("exituser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "12121212-3333-4444-8555-666666666666", "an-exit", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		if _, err := st.UpsertAdvertisedRoute(ctx, dev.ID, cidr); err != nil {
			t.Fatalf("upsert route %s: %v", cidr, err)
		}
		if err := st.SetRouteStatus(ctx, dev.ID, cidr, util.RouteStatusApproved, ""); err != nil {
			t.Fatalf("approve %s: %v", cidr, err)
		}
	}
	_ = st.Close()

	devStr := fmt.Sprintf("%d", dev.ID)
	// 只删 v4:v6 仍 approved → 必须告警 + 指路 exit revoke。
	c, _, stderr := runCLI(t, db, "", "route", "delete", devStr, "0.0.0.0/0", "--yes")
	if c != 0 {
		t.Fatalf("route delete 应成功, code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stderr, "::/0") || !strings.Contains(stderr, "exit revoke") {
		t.Fatalf("应告警另一族(::/0)仍生效并指路 exit revoke,实际 stderr: %s", stderr)
	}
	// 再删 v6:已无其它 approved 出口路由 → 不应再告警(否则是噪音)。
	c, _, stderr = runCLI(t, db, "", "route", "delete", devStr, "::/0", "--yes")
	if c != 0 {
		t.Fatalf("route delete(v6) 应成功, code=%d stderr=%s", c, stderr)
	}
	if strings.Contains(stderr, "exit revoke") {
		t.Fatalf("撤完最后一族不应再告警,实际 stderr: %s", stderr)
	}
}

// TestRouteApprove_WarnsOnDuplicateCIDRAcrossDevices:同一 CIDR 批给第二台设备时必须告警。
//
// 数据面 tiebreak 是确定的(lookupSubnetRoute 同长度取最小 deviceID),但 admin 侧此前毫无提示:
// 较小 deviceID 静默胜出,另一台身后的 LAN 经 mesh 完全不可达,而 admin 以为两台都在服务(甚至以为
// 做到了冗余)。设计文档 Open questions 把这条列为「剩余的是 UX」。
func TestRouteApprove_WarnsOnDuplicateCIDRAcrossDevices(t *testing.T) {
	db := filepath.Join(t.TempDir(), "route-dup-cidr.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("dupuser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	mkDev := func(uuid, name string) int64 {
		d, derr := st.UpsertDevice(ctx, u.ID, uuid, name, "linux")
		if derr != nil {
			t.Fatalf("upsert device %s: %v", name, derr)
		}
		return d.ID
	}
	dev1 := mkDev("11111111-2222-4333-8444-555555555555", "router-a")
	dev2 := mkDev("22222222-3333-4444-8555-666666666666", "router-b")
	const cidr = "192.168.77.0/24"
	const other = "10.9.9.0/24"
	for _, d := range []int64{dev1, dev2} {
		if _, err := st.UpsertAdvertisedRoute(ctx, d, cidr); err != nil {
			t.Fatalf("upsert route: %v", err)
		}
	}
	if _, err := st.UpsertAdvertisedRoute(ctx, dev2, other); err != nil {
		t.Fatalf("upsert other route: %v", err)
	}
	_ = st.Close()

	d1, d2 := fmt.Sprintf("%d", dev1), fmt.Sprintf("%d", dev2)
	// 第一台:没有别人持有该 CIDR → 不该告警(否则是噪音)。
	c, _, stderr := runCLI(t, db, "", "route", "approve", d1, cidr)
	if c != 0 {
		t.Fatalf("approve 应成功, code=%d stderr=%s", c, stderr)
	}
	if strings.Contains(stderr, "WARN") {
		t.Fatalf("首次批准不该告警重复,实际 stderr: %s", stderr)
	}
	// 第二台:同一 CIDR 已被 dev1 持有 → 必须告警,并指明胜出者是较小的 dev1。
	c, _, stderr = runCLI(t, db, "", "route", "approve", d2, cidr)
	if c != 0 {
		t.Fatalf("approve 应成功(只告警不阻断), code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stderr, "WARN") || !strings.Contains(stderr, cidr) {
		t.Fatalf("应告警该 CIDR 已批给别的设备,实际 stderr: %s", stderr)
	}
	if !strings.Contains(stderr, fmt.Sprintf("#%d", dev1)) {
		t.Fatalf("应指明胜出者为较小 deviceID #%d,实际 stderr: %s", dev1, stderr)
	}
	// 不同 CIDR 不该触发告警。
	c, _, stderr = runCLI(t, db, "", "route", "approve", d2, other)
	if c != 0 {
		t.Fatalf("approve 应成功, code=%d stderr=%s", c, stderr)
	}
	if strings.Contains(stderr, "WARN") {
		t.Fatalf("不同 CIDR 不该告警重复,实际 stderr: %s", stderr)
	}
}
