package main

import (
	"fmt"
	"path/filepath"
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
