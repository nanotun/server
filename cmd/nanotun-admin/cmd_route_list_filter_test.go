package main

import (
	"fmt"
	"strings"
	"testing"

	"path/filepath"
)

// TestRouteList_StatusComposesWithDevice:`--status` 必须能和 `--device` 叠加。
//
// 三机 e2e 重建实验室时踩到(2026-08-03):预置脚本用
// `route list --device N --status approved | grep <cidr>` 判断某条子网批没批,
// 结果对着两条 **pending** 的子网报告「已是 approved」,于是没去批。
// 客户端那边表现为「宣告成功、审批看着有效,但流量一直不通」,e2e 里则是四条
// 「子网恢复」类断言红,而所有「子网被掐断」的断言照常绿 —— 因为从头到尾就没通过,
// 一条也没提示过真因。
//
// 根因是取数写成了 switch:给了 --device 就走 ListRoutesByDevice,--status 整个被丢掉。
// 这条命令最常见的用法恰恰是「这台设备还有什么等着我批」。
func TestRouteList_StatusComposesWithDevice(t *testing.T) {
	db := filepath.Join(t.TempDir(), "route-list-filter.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("filteruser"))
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
	dev1 := mkDev("11111111-2222-4333-8444-555555555555", "node-1")
	dev2 := mkDev("22222222-3333-4444-8555-666666666666", "node-2")

	const approvedCIDR = "10.77.0.0/24"   // dev1,稍后批准
	const pendingCIDR = "192.168.88.0/24" // dev1,保持 pending
	const otherCIDR = "10.88.0.0/24"      // dev2,用来验证 --device 仍在生效
	for dev, cidr := range map[int64]string{dev1: approvedCIDR, dev2: otherCIDR} {
		if _, err := st.UpsertAdvertisedRoute(ctx, dev, cidr); err != nil {
			t.Fatalf("upsert %s: %v", cidr, err)
		}
	}
	if _, err := st.UpsertAdvertisedRoute(ctx, dev1, pendingCIDR); err != nil {
		t.Fatalf("upsert %s: %v", pendingCIDR, err)
	}
	_ = st.Close()

	d1 := fmt.Sprintf("%d", dev1)
	if c, _, stderr := runCLI(t, db, "", "route", "approve", d1, approvedCIDR); c != 0 {
		t.Fatalf("approve %s: code=%d stderr=%s", approvedCIDR, c, stderr)
	}

	// --device + --status pending:只该看见 dev1 上那条 pending。
	c, stdout, stderr := runCLI(t, db, "", "route", "list", "--device", d1, "--status", "pending")
	if c != 0 {
		t.Fatalf("route list: code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stdout, pendingCIDR) {
		t.Errorf("--status pending 应列出 %s,实际输出:\n%s", pendingCIDR, stdout)
	}
	if strings.Contains(stdout, approvedCIDR) {
		t.Errorf("--status pending 不该列出已批准的 %s(这正是原缺陷),实际输出:\n%s", approvedCIDR, stdout)
	}
	if strings.Contains(stdout, otherCIDR) {
		t.Errorf("--device %s 不该列出别台设备的 %s,实际输出:\n%s", d1, otherCIDR, stdout)
	}

	// 反向:--status approved 只该看见已批准那条。
	c, stdout, stderr = runCLI(t, db, "", "route", "list", "--device", d1, "--status", "approved")
	if c != 0 {
		t.Fatalf("route list approved: code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stdout, approvedCIDR) {
		t.Errorf("--status approved 应列出 %s,实际输出:\n%s", approvedCIDR, stdout)
	}
	if strings.Contains(stdout, pendingCIDR) {
		t.Errorf("--status approved 不该列出 pending 的 %s,实际输出:\n%s", pendingCIDR, stdout)
	}

	// 不带 --status 时行为不变:该设备两条都在。
	c, stdout, stderr = runCLI(t, db, "", "route", "list", "--device", d1)
	if c != 0 {
		t.Fatalf("route list 无 status: code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stdout, approvedCIDR) || !strings.Contains(stdout, pendingCIDR) {
		t.Errorf("不带 --status 应列出该设备全部路由,实际输出:\n%s", stdout)
	}
}
