package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// TestRouteApprove_WarnsOnOverlappingCIDRAcrossDevices:批准一条**嵌套进别台设备已批准网段**的
// 更长掩码时必须告警。
//
// 三机实测(2026-07-26):A 的 172.20.10.0/24 正常服务着 172.20.10.10,C 宣告 172.20.10.0/25 被批准
// 之后,那台主机对所有请求方当场失联(最长前缀选中 C,C 身后没有这些主机)。route list 里两条都是
// approved,看不出谁盖了谁 —— 任何能宣告路由的客户端都能靠更长掩码悄悄截走别人网段的一段。
func TestRouteApprove_WarnsOnOverlappingCIDRAcrossDevices(t *testing.T) {
	db := filepath.Join(t.TempDir(), "route-overlap-cidr.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("ovuser"))
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
	const wide = "172.20.10.0/24"
	const narrow = "172.20.10.0/25"
	const unrelated = "10.9.9.0/24"
	if _, err := st.UpsertAdvertisedRoute(ctx, dev1, wide); err != nil {
		t.Fatalf("upsert wide: %v", err)
	}
	if _, err := st.UpsertAdvertisedRoute(ctx, dev2, narrow); err != nil {
		t.Fatalf("upsert narrow: %v", err)
	}
	if _, err := st.UpsertAdvertisedRoute(ctx, dev2, unrelated); err != nil {
		t.Fatalf("upsert unrelated: %v", err)
	}
	_ = st.Close()

	d1, d2 := fmt.Sprintf("%d", dev1), fmt.Sprintf("%d", dev2)
	if c, _, stderr := runCLI(t, db, "", "route", "approve", d1, wide); c != 0 {
		t.Fatalf("approve wide: code=%d stderr=%s", c, stderr)
	} else if strings.Contains(stderr, "WARN") {
		t.Fatalf("首条批准不该告警,实际 stderr: %s", stderr)
	}

	c, _, stderr := runCLI(t, db, "", "route", "approve", d2, narrow)
	if c != 0 {
		t.Fatalf("approve narrow 应成功(只告警不阻断): code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stderr, "WARN") || !strings.Contains(stderr, wide) {
		t.Fatalf("应告警与 %s 交叠,实际 stderr: %s", wide, stderr)
	}
	// 胜出者必须点名更长掩码那条(数据面按最长前缀)。
	if !strings.Contains(stderr, narrow) {
		t.Errorf("告警应点明 %s 胜出,实际 stderr: %s", narrow, stderr)
	}

	// 完全不交叠的另一条:不该被这条告警波及(噪音会让运维学会无视 WARN)。
	if c, _, stderr := runCLI(t, db, "", "route", "approve", d2, unrelated); c != 0 {
		t.Fatalf("approve unrelated: code=%d stderr=%s", c, stderr)
	} else if strings.Contains(stderr, "WARN") {
		t.Errorf("不交叠的网段不该告警,实际 stderr: %s", stderr)
	}
}
