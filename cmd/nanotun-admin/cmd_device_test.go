package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// device create 预创建（指定 UUID，设备从未登录）→ 可直接 exit designate 预置为出口（先配后连）。
func TestDeviceCreate_PrecreateThenDesignate(t *testing.T) {
	db := filepath.Join(t.TempDir(), "devcreate.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "exitowner", "--psk", "p"); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	const uuid = "11111111-2222-4333-8444-555555555555"

	// 预创建设备（此前从未登录，devices 表里没有它）。
	c, out, e := runCLI(t, db, "", "device", "create", "exitowner", "--uuid", uuid, "--name", "exit-box")
	if c != 0 {
		t.Fatalf("device create: code=%d stderr=%s", c, e)
	}
	if !strings.Contains(out, "已预创建") || !strings.Contains(out, uuid) {
		t.Fatalf("device create 输出异常: %s", out)
	}

	// 已入库：device list 含该 uuid。
	c, ljson, _ := runCLI(t, db, "", "--json", "device", "list", "--user", "exitowner")
	if c != 0 {
		t.Fatalf("device list 失败")
	}
	if !strings.Contains(ljson, uuid) {
		t.Fatalf("预创建的设备应出现在 device list: %s", ljson)
	}

	// 取 device_id。
	st := openStoreForTest(t, db)
	u, err := st.GetUserByUsername(t.Context(), "exitowner")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	dev, err := st.GetDeviceByUUID(t.Context(), u.ID, uuid)
	if err != nil || dev == nil {
		t.Fatalf("预创建设备未入库: %v", err)
	}
	devID := dev.ID
	_ = st.Close()

	// 对预创建的设备（从未登录）直接 exit designate → 成功（先配后连的核心价值）。
	if c, _, e := runCLI(t, db, "", "exit", "designate", fmt.Sprintf("%d", devID), "--no-vip"); c != 0 {
		t.Fatalf("exit designate 预创建设备应成功: %s", e)
	}
	c, ejson, _ := runCLI(t, db, "", "--json", "exit", "list")
	if c != 0 {
		t.Fatalf("exit list 失败")
	}
	if !strings.Contains(ejson, uuid) {
		t.Fatalf("designate 后 exit list 应含该出口: %s", ejson)
	}
}

// 幂等：再次预创建同 UUID → 不报错，提示「已存在」。
func TestDeviceCreate_Idempotent(t *testing.T) {
	db := filepath.Join(t.TempDir(), "devcreate-idem.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "u1", "--psk", "p"); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	const uuid = "22222222-3333-4444-8555-666666666666"
	if c, _, e := runCLI(t, db, "", "device", "create", "u1", "--uuid", uuid); c != 0 {
		t.Fatalf("first create: %s", e)
	}
	c, out, e := runCLI(t, db, "", "device", "create", "u1", "--uuid", uuid, "--name", "renamed")
	if c != 0 {
		t.Fatalf("second create 应幂等成功: code=%d stderr=%s", c, e)
	}
	if !strings.Contains(out, "已存在") {
		t.Fatalf("重复预创建应提示已存在: %s", out)
	}
}

// 非法 UUID（非 v4）→ 报错拒绝（不入脏数据）。
func TestDeviceCreate_RejectsInvalidUUID(t *testing.T) {
	db := filepath.Join(t.TempDir(), "devcreate-bad.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "u1", "--psk", "p"); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	c, _, stderr := runCLI(t, db, "", "device", "create", "u1", "--uuid", "not-a-uuid")
	if c == 0 {
		t.Fatal("非法 UUID 应失败")
	}
	if !strings.Contains(stderr, "v4 UUID") {
		t.Fatalf("错误信息应提示 v4 UUID: %s", stderr)
	}
}
