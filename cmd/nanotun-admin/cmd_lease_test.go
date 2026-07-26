package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// 深扫第八轮 MED 回归:CLI `lease set --v4/--v6` 必须校验 IP 格式与地址族
// (与 device set-fixed-vip 同口径),垃圾值/错族值不得写进 leases 表
// (否则设备下次登录收到即黑洞)。
func TestLeaseSet_ValidatesIPAndFamily(t *testing.T) {
	db := filepath.Join(t.TempDir(), "leaseset.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("leaseuser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "a-nas", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	_ = st.Close()

	devStr := fmt.Sprintf("%d", dev.ID)

	// 都不带 --v4/--v6 → 拒。
	if c, _, _ := runCLI(t, db, "", "lease", "set", devStr); c == 0 {
		t.Fatal("不带 --v4/--v6 应报错")
	}
	// 非 IP 字符串 → 拒。
	if c, _, _ := runCLI(t, db, "", "lease", "set", devStr, "--v4", "notanip"); c == 0 {
		t.Fatal("--v4 notanip 应被拒")
	}
	// 地址族错配:v4 传 IPv6 → 拒。
	if c, _, _ := runCLI(t, db, "", "lease", "set", devStr, "--v4", "fe80::1"); c == 0 {
		t.Fatal("--v4 fe80::1(IPv6)应被拒")
	}
	// 地址族错配:v6 传 IPv4 → 拒。
	if c, _, _ := runCLI(t, db, "", "lease", "set", devStr, "--v6", "100.64.0.9"); c == 0 {
		t.Fatal("--v6 100.64.0.9(IPv4)应被拒")
	}
	// 合法 v4 + v6 → 通过。
	if c, _, e := runCLI(t, db, "", "lease", "set", devStr,
		"--v4", "100.64.0.9", "--v6", "fd00::9"); c != 0 {
		t.Fatalf("合法 v4+v6 应成功, code=%d stderr=%s", c, e)
	}
}

// TestLeaseSet_WarnsWhenLoginPathCannotUsePin:钉的地址登录路径用不上时必须当场告警。
//
// 三机实测(2026-07-26):`lease set 1 --v4 10.201.0.1`(网关自身)和 `--v4 10.99.0.5`
// (mesh 之外)CLI 都只回一句「已分配」,`lease list` 也照常显示,而设备下次登录被
// preferredVIPUsable 判为不可用后静默改走自动分配 —— 运维照钉住值配的东西全对不上。
func TestLeaseSet_WarnsWhenLoginPathCannotUsePin(t *testing.T) {
	db := filepath.Join(t.TempDir(), "leasepin.db")
	st := openStoreForTest(t, db)
	ctx := t.Context()
	u, err := st.CreateUser(ctx, openStoreNewUser("pinuser"))
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeef", "pin-nas", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if err := st.SetMeshCIDRs(ctx, []string{"10.201.0.1/24", "fd00:200::1/64"}); err != nil {
		t.Fatalf("set mesh cidrs: %v", err)
	}
	_ = st.Close()
	devStr := fmt.Sprintf("%d", dev.ID)

	for _, tc := range []struct {
		name, flag, val, want string
	}{
		{"gateway", "--v4", "10.201.0.1", "gateway"},
		{"network", "--v4", "10.201.0.0", "network"},
		{"broadcast", "--v4", "10.201.0.255", "broadcast"},
		{"v6 gateway", "--v6", "fd00:200::1", "gateway"},
		{"out of mesh", "--v4", "10.99.0.5", "mesh"},
	} {
		code, _, stderr := runCLI(t, db, "", "lease", "set", devStr, tc.flag, tc.val)
		if code != 0 {
			t.Errorf("%s: 只应告警不应失败, code=%d stderr=%s", tc.name, code, stderr)
		}
		if !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: stderr 里应提到 %q, got %q", tc.name, tc.want, stderr)
		}
	}

	// 网段内的普通主机地址 → 一句告警都不该有。
	if code, _, stderr := runCLI(t, db, "", "lease", "set", devStr, "--v4", "10.201.0.42"); code != 0 ||
		strings.Contains(stderr, "WARN") {
		t.Errorf("网段内主机地址不应告警, code=%d stderr=%s", code, stderr)
	}
}
