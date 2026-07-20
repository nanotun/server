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
