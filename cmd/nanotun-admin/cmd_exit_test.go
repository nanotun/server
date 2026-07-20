package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/util"
)

// exitListRow 镜像 cmdExitList 的 JSON 输出（匿名 struct 的字段）。
type exitListRow struct {
	DeviceID   int64  `json:"device_id"`
	DeviceUUID string `json:"device_uuid"`
	DeviceName string `json:"device_name"`
	HasV4Exit  bool   `json:"has_v4_exit"`
	HasV6Exit  bool   `json:"has_v6_exit"`
	FixedVIPv4 string `json:"fixed_vip_v4"`
	FixedVIPv6 string `json:"fixed_vip_v6"`
}

func deviceExitRoutesApproved(t *testing.T, dbPath string, deviceID int64) (v4, v6 bool) {
	t.Helper()
	st := openStoreForTest(t, dbPath)
	defer st.Close()
	rows, err := st.ListRoutesByDevice(t.Context(), deviceID)
	if err != nil {
		t.Fatalf("list routes: %v", err)
	}
	for _, r := range rows {
		if r.Status != util.RouteStatusApproved {
			continue
		}
		switch r.CIDR {
		case util.ExitDefaultRouteV4:
			v4 = true
		case util.ExitDefaultRouteV6:
			v6 = true
		}
	}
	return v4, v6
}

// 平台闸口(与 web 同口径):iOS/Android 不能 designate;--force 可越过(CLI 逃生口)。
func TestExitDesignate_PlatformGate(t *testing.T) {
	db := filepath.Join(t.TempDir(), "exit-plat.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("phoneuser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "66666666-7777-4888-8999-aaaaaaaaaaaa", "my-phone", "ios")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	_ = st.Close()

	devStr := fmt.Sprintf("%d", dev.ID)
	c, _, stderr := runCLI(t, db, "", "exit", "designate", devStr, "--no-vip")
	if c == 0 {
		t.Fatal("ios 设备 designate 应被平台闸口拦下")
	}
	if !strings.Contains(stderr, "--force") {
		t.Fatalf("报错应提示 --force 逃生口,实际: %s", stderr)
	}
	if v4, v6 := deviceExitRoutesApproved(t, db, dev.ID); v4 || v6 {
		t.Fatalf("被拦的 designate 不应留下批准行, got v4=%v v6=%v", v4, v6)
	}

	// --force 显式越过(运维自担;如 platform token 异常的存量设备)。
	if c, _, e := runCLI(t, db, "", "exit", "designate", devStr, "--no-vip", "--force"); c != 0 {
		t.Fatalf("--force 应放行, code=%d stderr=%s", c, e)
	}
	if v4, v6 := deviceExitRoutesApproved(t, db, dev.ID); !v4 || !v6 {
		t.Fatalf("--force 后应 approve 0/0+::/0, got v4=%v v6=%v", v4, v6)
	}
}

// 一键指定出口的核心断言：不给 --v4/--v6 时，approve 0/0+::/0 并把**当前 lease 的 vIP 焊死**为 fixed。
func TestExitDesignate_ApprovesAndPinsLeaseVIP(t *testing.T) {
	db := filepath.Join(t.TempDir(), "exit-des.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("exituser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "11111111-2222-4333-8444-555555555555", "exit-box", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if _, err := st.UpsertLease(ctx, dev.ID, "100.64.0.30", "", false); err != nil {
		t.Fatalf("upsert lease: %v", err)
	}
	_ = st.Close()

	devStr := fmt.Sprintf("%d", dev.ID)
	c, stdout, stderr := runCLI(t, db, "", "exit", "designate", devStr)
	if c != 0 {
		t.Fatalf("exit designate: code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stdout, "已指定出口") {
		t.Fatalf("stdout 缺成功提示: %s", stdout)
	}

	if v4, v6 := deviceExitRoutesApproved(t, db, dev.ID); !v4 || !v6 {
		t.Fatalf("应 approve 0.0.0.0/0 + ::/0, got v4=%v v6=%v", v4, v6)
	}
	st2 := openStoreForTest(t, db)
	defer st2.Close()
	d2, err := st2.GetDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if d2.FixedVIPv4 != "100.64.0.30" {
		t.Fatalf("应把当前 lease v4 焊死为 fixed, 实际 fixed_v4=%q", d2.FixedVIPv4)
	}
}

// 显式 --v4/--v6（设备尚无 lease）：approve + 钉死指定 vIP。
func TestExitDesignate_ExplicitVIP(t *testing.T) {
	db := filepath.Join(t.TempDir(), "exit-exp.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("exituser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "22222222-3333-4444-8555-666666666666", "exit-box", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	_ = st.Close()

	devStr := fmt.Sprintf("%d", dev.ID)
	c, _, stderr := runCLI(t, db, "", "exit", "designate", devStr, "--v4", "100.64.0.99", "--v6", "fd00:200::99")
	if c != 0 {
		t.Fatalf("exit designate: code=%d stderr=%s", c, stderr)
	}
	if v4, v6 := deviceExitRoutesApproved(t, db, dev.ID); !v4 || !v6 {
		t.Fatalf("应 approve 0/0 + ::/0, got v4=%v v6=%v", v4, v6)
	}
	st2 := openStoreForTest(t, db)
	defer st2.Close()
	d2, err := st2.GetDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if d2.FixedVIPv4 != "100.64.0.99" || d2.FixedVIPv6 != "fd00:200::99" {
		t.Fatalf("固定 vIP 应为指定值, 实际 v4=%q v6=%q", d2.FixedVIPv4, d2.FixedVIPv6)
	}
}

// 设备无 lease 且未给 --v4/--v6：仍 approve 出口路由，但 vIP 未钉死 + stderr 警告。
func TestExitDesignate_NoLeaseWarnsButApproves(t *testing.T) {
	db := filepath.Join(t.TempDir(), "exit-nolease.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("exituser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "33333333-4444-4555-8666-777777777777", "exit-box", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	_ = st.Close()

	c, _, stderr := runCLI(t, db, "", "exit", "designate", fmt.Sprintf("%d", dev.ID))
	if c != 0 {
		t.Fatalf("exit designate: code=%d stderr=%s", c, stderr)
	}
	if v4, v6 := deviceExitRoutesApproved(t, db, dev.ID); !v4 || !v6 {
		t.Fatalf("即便没 lease 也应 approve 出口路由, got v4=%v v6=%v", v4, v6)
	}
	if !strings.Contains(stderr, "未能确定 vIP") {
		t.Fatalf("无 lease + 无 --v4/--v6 应警告未钉死 vIP, stderr=%s", stderr)
	}
}

// exit list 列出已指定的出口及固定 vIP。
func TestExitList_ShowsDesignated(t *testing.T) {
	db := filepath.Join(t.TempDir(), "exit-list.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("exituser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "44444444-5555-4666-8777-888888888888", "exit-box", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	_ = st.Close()

	devStr := fmt.Sprintf("%d", dev.ID)
	if c, _, e := runCLI(t, db, "", "exit", "designate", devStr, "--v4", "100.64.0.50"); c != 0 {
		t.Fatalf("designate: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "", "--json", "exit", "list")
	if c != 0 {
		t.Fatalf("exit list: code=%d stderr=%s", c, stderr)
	}
	var rows []exitListRow
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("parse exit list json: %v\n%s", err, stdout)
	}
	var found *exitListRow
	for i := range rows {
		if rows[i].DeviceID == dev.ID {
			found = &rows[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("exit list 应含已指定的 device %d, got %+v", dev.ID, rows)
	}
	if !found.HasV4Exit || !found.HasV6Exit {
		t.Fatalf("出口应有 v4+v6 exit 路由, got %+v", found)
	}
	if found.FixedVIPv4 != "100.64.0.50" {
		t.Fatalf("exit list 应展示固定 vIP, got fixed_v4=%q", found.FixedVIPv4)
	}
}

// exit revoke 删除出口路由；--clear-vip 同时清掉固定 vIP。
func TestExitRevoke_RemovesRoutesAndClearsVIP(t *testing.T) {
	db := filepath.Join(t.TempDir(), "exit-rev.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("exituser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "55555555-6666-4777-8888-999999999999", "exit-box", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	_ = st.Close()

	devStr := fmt.Sprintf("%d", dev.ID)
	if c, _, e := runCLI(t, db, "", "exit", "designate", devStr, "--v4", "100.64.0.60"); c != 0 {
		t.Fatalf("designate: %s", e)
	}
	// runCLI 总是带 --yes，故 revoke 的确认会自动通过。
	if c, _, e := runCLI(t, db, "", "exit", "revoke", devStr, "--clear-vip"); c != 0 {
		t.Fatalf("revoke: %s", e)
	}
	if v4, v6 := deviceExitRoutesApproved(t, db, dev.ID); v4 || v6 {
		t.Fatalf("revoke 后不应再有 approved 出口路由, got v4=%v v6=%v", v4, v6)
	}
	st2 := openStoreForTest(t, db)
	defer st2.Close()
	d2, err := st2.GetDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if d2.FixedVIPv4 != "" {
		t.Fatalf("--clear-vip 应清掉固定 vIP, 实际 fixed_v4=%q", d2.FixedVIPv4)
	}
}
