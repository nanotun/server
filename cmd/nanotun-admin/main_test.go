package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
)

// openStoreForTest 打开（+ migrate）一个 SQLite db 给测试直接写状态用。
// 调用方负责在用完之后 st.Close()，因为同进程下后续 CLI 调用会重新 store.Open 同一个文件。
func openStoreForTest(t *testing.T, dbPath string) *store.Store {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("store.Open(%s): %v", dbPath, err)
	}
	if err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		t.Fatalf("store.Migrate: %v", err)
	}
	return st
}

// openStoreNewUser 造一个 store.NewUser 时常需要预先 hash PSK，封装一下让测试更紧凑。
func openStoreNewUser(username string) store.NewUser {
	hash, err := auth.HashPSK("p")
	if err != nil {
		panic(err)
	}
	return store.NewUser{Username: username, PSKHash: hash}
}

// runCLI 用 runRoot 跑一组参数；返回 (exitCode, stdout, stderr)。
func runCLI(t *testing.T, dbPath, stdin string, args ...string) (int, string, string) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	opts := &globalOpts{
		stdout: stdout,
		stderr: stderr,
		stdin:  strings.NewReader(stdin),
	}
	// 既有 CLI 测试大量按中文断言输出;CLI 默认已切英文,故测试统一 pin --lang zh,
	// 让这些断言继续校验中文 catalog + 逻辑。英文默认路径由 catalog parity + 冒烟测试覆盖。
	full := append([]string{"--db-path", dbPath, "--yes", "--lang", "zh"}, args...)
	rest, err := parseGlobalFlags(full, opts)
	if err != nil {
		t.Fatalf("parseGlobalFlags: %v", err)
	}
	code := runRoot(rest, opts)
	return code, stdout.String(), stderr.String()
}

func TestUserCRUDFlow(t *testing.T) {
	db := filepath.Join(t.TempDir(), "cli.db")

	code, stdout, stderr := runCLI(t, db, "", "user", "create", "alice", "--admin")
	if code != 0 {
		t.Fatalf("create alice failed: code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "alice") {
		t.Fatalf("missing alice in output: %s", stdout)
	}

	code, stdout, _ = runCLI(t, db, "", "--json", "user", "list")
	if code != 0 {
		t.Fatalf("list failed: code=%d", code)
	}
	var users []userView
	if err := json.Unmarshal([]byte(stdout), &users); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout)
	}
	if len(users) != 1 || users[0].Username != "alice" || !users[0].IsAdmin {
		t.Fatalf("unexpected users: %+v", users)
	}
	if strings.Contains(stdout, "PSKHash") || strings.Contains(stdout, "psk_hash") {
		t.Fatalf("user list --json must not expose psk_hash: %s", stdout)
	}

	// 0008(2026-05-23):用户级 set-fixed-vip 已废弃,直接走 store 层造一台 device 然后
	// 调 CLI 的 `device set-fixed-vip` 验证落库 + show。
	{
		st := openStoreForTest(t, db)
		u, err := st.GetUserByUsername(t.Context(), "alice")
		if err != nil {
			t.Fatalf("get alice: %v", err)
		}
		dev, err := st.UpsertDevice(t.Context(), u.ID,
			"aaaaaaaa-1111-4222-8333-444444444444", "alice-mac", "darwin")
		if err != nil {
			t.Fatalf("upsert alice dev: %v", err)
		}
		_ = st.Close()

		code, _, stderr = runCLI(t, db, "",
			"device", "set-fixed-vip", fmt.Sprintf("%d", dev.ID), "--v4", "100.64.0.10")
		if code != 0 {
			t.Fatalf("device set-fixed-vip failed: %s", stderr)
		}
	}

	code, stdout, _ = runCLI(t, db, "", "--json", "user", "show", "alice")
	if code != 0 {
		t.Fatalf("show failed")
	}
	var view userView
	if err := json.Unmarshal([]byte(stdout), &view); err != nil {
		t.Fatalf("parse show json: %v\n%s", err, stdout)
	}
	// P1#4(2026-05-26):user show --json 必须暴露 credential_id /
	// credential_created_at — client 端按 UUID 索引覆盖旧 PSK 的承诺,要求 JSON
	// 这条信道也能拿到。`user create` 默认会分配 UUID v4,因此 alice 的
	// CredentialID 必为 36 字符 UUID,CredentialCreatedAt 为正。
	if view.CredentialID == "" {
		t.Fatalf("user show --json 缺 credential_id: %s", stdout)
	}
	if view.CredentialCreatedAt == nil || *view.CredentialCreatedAt <= 0 {
		t.Fatalf("user show --json 缺 credential_created_at: %s", stdout)
	}
	// 0008:userView 不再含 fixed_vip_* 字段;改成查 device list --json 验证。
	code, stdout, _ = runCLI(t, db, "", "--json", "device", "list", "--user", "alice")
	if code != 0 {
		t.Fatalf("device list failed")
	}
	if !strings.Contains(stdout, `"FixedVIPv4":"100.64.0.10"`) &&
		!strings.Contains(stdout, `"fixed_vip_v4":"100.64.0.10"`) &&
		!strings.Contains(stdout, "100.64.0.10") {
		t.Fatalf("device list should expose fixed_vip_v4=100.64.0.10, got: %s", stdout)
	}

	code, _, _ = runCLI(t, db, "", "user", "disable", "alice")
	if code != 0 {
		t.Fatalf("disable failed")
	}
	code, stdout, _ = runCLI(t, db, "", "user", "show", "alice")
	if code != 0 {
		t.Fatalf("show after disable failed")
	}
	// runCLI 固定 --lang zh:disabled_at 标签走 user.show.disabledAt 的中文文案。
	if !strings.Contains(stdout, "禁用时间:") {
		t.Fatalf("show should contain disabled_at label: %s", stdout)
	}

	code, _, _ = runCLI(t, db, "", "user", "enable", "alice")
	if code != 0 {
		t.Fatalf("enable failed")
	}

	code, stdout, _ = runCLI(t, db, "", "user", "reset-psk", "alice")
	if code != 0 {
		t.Fatalf("reset-psk failed")
	}
	if !strings.Contains(stdout, "新 PSK：") {
		t.Fatalf("reset-psk output missing PSK line: %s", stdout)
	}

	code, _, _ = runCLI(t, db, "", "user", "delete", "alice")
	if code != 0 {
		t.Fatalf("delete alice failed")
	}
	code, stdout, _ = runCLI(t, db, "", "--json", "user", "list")
	if code != 0 {
		t.Fatalf("post-delete list failed")
	}
	var post []userView
	_ = json.Unmarshal([]byte(stdout), &post)
	if len(post) != 0 {
		t.Fatalf("expected 0 users after delete, got %+v", post)
	}
}

func TestACLFlow(t *testing.T) {
	db := filepath.Join(t.TempDir(), "acl.db")

	for _, name := range []string{"u1", "u2", "u3"} {
		if c, _, e := runCLI(t, db, "", "user", "create", name, "--psk", "secret"); c != 0 {
			t.Fatalf("create %s: %s", name, e)
		}
	}

	if c, _, e := runCLI(t, db, "", "acl", "allow", "u1", "u2"); c != 0 {
		t.Fatalf("allow u1->u2: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "acl", "deny", "u1", "u3"); c != 0 {
		t.Fatalf("deny u1->u3: %s", e)
	}

	c, stdout, _ := runCLI(t, db, "", "--json", "acl", "list")
	if c != 0 {
		t.Fatalf("acl list")
	}
	type aclRow struct {
		ID          int64  `json:"id"`
		Action      string `json:"action"`
		SrcUsername string `json:"src_username"`
		DstUsername string `json:"dst_username"`
	}
	var rows []aclRow
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("parse acl list: %v\n%s", err, stdout)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 acl rows, got %d", len(rows))
	}

	if c, _, e := runCLI(t, db, "", "acl", "del", "1"); c != 0 {
		t.Fatalf("acl del: %s", e)
	}
	c, stdout, _ = runCLI(t, db, "", "--json", "acl", "list")
	if c != 0 {
		t.Fatalf("acl list 2")
	}
	rows = nil
	_ = json.Unmarshal([]byte(stdout), &rows)
	if len(rows) != 1 {
		t.Fatalf("expected 1 acl row after del, got %d", len(rows))
	}
}

func TestDeviceAndLeaseFlow(t *testing.T) {
	db := filepath.Join(t.TempDir(), "dl.db")

	if c, _, e := runCLI(t, db, "", "user", "create", "u1", "--psk", "p"); c != 0 {
		t.Fatalf("create u1: %s", e)
	}

	// CLI 没暴露 device 创建（设备是登录路径上由服务端 upsert）；测试里走 store 直接写。
	// 这里我们用 setting set 兜底验证 setting 命令。
	if c, _, e := runCLI(t, db, "", "setting", "set", "test_key", "hello"); c != 0 {
		t.Fatalf("setting set: %s", e)
	}
	c, stdout, _ := runCLI(t, db, "", "setting", "get", "test_key")
	if c != 0 || strings.TrimSpace(stdout) != "hello" {
		t.Fatalf("setting get: code=%d stdout=%q", c, stdout)
	}

	c, _, _ = runCLI(t, db, "", "lease", "list")
	if c != 0 {
		t.Fatalf("lease list (empty)")
	}
}

func TestInitWizard(t *testing.T) {
	db := filepath.Join(t.TempDir(), "init.db")

	stdin := "wenhai\n\n" // 用户名 wenhai；PSK 自动生成
	c, stdout, e := runCLI(t, db, stdin, "init")
	if c != 0 {
		t.Fatalf("init: code=%d stderr=%s", c, e)
	}
	if !strings.Contains(stdout, "wenhai") || !strings.Contains(stdout, "PSK:") {
		t.Fatalf("init output unexpected: %s", stdout)
	}

	c, stdout, _ = runCLI(t, db, "", "setting", "get", "setup_completed")
	if c != 0 || strings.TrimSpace(stdout) != "1" {
		t.Fatalf("setup_completed not set; got %q", stdout)
	}

	// 抓首次 PSK hash 备用：第二次 noop init 不应改动 hash
	c, stdout, _ = runCLI(t, db, "", "--json", "user", "show", "wenhai")
	if c != 0 {
		t.Fatalf("show wenhai #1 failed")
	}
	psk1 := stdout

	// 再跑一次 init 默认 noop：成功，不重置 PSK
	c, out2, _ := runCLI(t, db, "wenhai\n", "init")
	if c != 0 {
		t.Fatalf("re-init should succeed (noop)")
	}
	if !strings.Contains(out2, "未做任何修改") {
		t.Fatalf("re-init should print noop notice; got: %s", out2)
	}
	c, stdout, _ = runCLI(t, db, "", "--json", "user", "show", "wenhai")
	if c != 0 || stdout != psk1 {
		t.Fatalf("noop init must not change user row; before=%s after=%s", psk1, stdout)
	}

	// 再加 --reset-psk 才会真正换：show 输出应当不一样（updated_at 至少不同）
	c, out3, _ := runCLI(t, db, "wenhai\n\n", "init", "--reset-psk")
	if c != 0 {
		t.Fatalf("init --reset-psk should succeed; got: %s", out3)
	}
	if !strings.Contains(out3, "PSK:") || !strings.Contains(out3, "仅重置 PSK") {
		t.Fatalf("init --reset-psk output unexpected: %s", out3)
	}
}

// 0008 device 维度版冲突测试:B device 的 lease 占了 100.64.0.10,给 A device
// 设 fixed_vip_v4=100.64.0.10 默认应当报错;加 --force 才放行。
func TestDeviceSetFixedVIP_CollisionGuard(t *testing.T) {
	db := filepath.Join(t.TempDir(), "fixedcoll.db")

	// 用 store 直接造一台离线设备 + 已 lease 的 IP,模拟另一个用户已经占了 100.64.0.10。
	st := openStoreForTest(t, db)
	ctx := t.Context()
	uB, err := st.CreateUser(ctx, openStoreNewUser("ub"))
	if err != nil {
		t.Fatalf("create ub: %v", err)
	}
	devB, err := st.UpsertDevice(ctx, uB.ID, "11111111-2222-4333-8444-555555555555", "ub-mac", "darwin")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if _, err := st.UpsertLease(ctx, devB.ID, "100.64.0.10", "", false); err != nil {
		t.Fatalf("upsert lease: %v", err)
	}

	// 给 ua 创建用户 + 一台 device,用 CLI 设撞 lease 的 fixed-vip 应被拒。
	uA, err := st.CreateUser(ctx, openStoreNewUser("ua"))
	if err != nil {
		t.Fatalf("create ua: %v", err)
	}
	devA, err := st.UpsertDevice(ctx, uA.ID, "22222222-3333-4444-8555-666666666666", "ua-mac", "darwin")
	if err != nil {
		t.Fatalf("upsert ua dev: %v", err)
	}
	_ = st.Close()

	devAStr := fmt.Sprintf("%d", devA.ID)
	c, _, stderr := runCLI(t, db, "", "device", "set-fixed-vip", devAStr, "--v4", "100.64.0.10")
	if c == 0 {
		t.Fatalf("device set-fixed-vip should fail on collision, got code=0")
	}
	if !strings.Contains(stderr, "冲突") || !strings.Contains(stderr, "--force") {
		t.Fatalf("error msg should mention 冲突 + --force, got: %s", stderr)
	}

	// 加 --force 应当放行(admin 知情)。
	if c, _, _ := runCLI(t, db, "", "device", "set-fixed-vip", devAStr, "--v4", "100.64.0.10", "--force"); c != 0 {
		t.Fatalf("--force should override collision, got code=%d", c)
	}
}

// 跟自己 device 的 lease 撞不算冲突:admin 通常是「把现有动态 IP 钉死」的姿势用本命令。
func TestDeviceSetFixedVIP_OwnLeaseNotCollision(t *testing.T) {
	db := filepath.Join(t.TempDir(), "fixedown.db")

	st := openStoreForTest(t, db)
	ctx := t.Context()
	ua, err := st.CreateUser(ctx, openStoreNewUser("ua"))
	if err != nil {
		t.Fatalf("create ua: %v", err)
	}
	devA, err := st.UpsertDevice(ctx, ua.ID, "11111111-2222-4333-8444-555555555555", "ua-mac", "darwin")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if _, err := st.UpsertLease(ctx, devA.ID, "100.64.0.20", "", false); err != nil {
		t.Fatalf("upsert lease: %v", err)
	}
	_ = st.Close()

	// 给 devA 自己已有 IP 钉死 —— 不应该报冲突。
	if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprintf("%d", devA.ID),
		"--v4", "100.64.0.20"); c != 0 {
		t.Fatalf("set own lease as fixed should succeed, got code=%d stderr=%s", c, e)
	}
}

// 非法 IP 字符串应当被 netip.ParseAddr 拒绝(不发到 store 层)。
func TestDeviceSetFixedVIP_InvalidIP(t *testing.T) {
	db := filepath.Join(t.TempDir(), "fixedbad.db")
	st := openStoreForTest(t, db)
	u, err := st.CreateUser(t.Context(), openStoreNewUser("ua"))
	if err != nil {
		t.Fatalf("create ua: %v", err)
	}
	dev, err := st.UpsertDevice(t.Context(), u.ID,
		"33333333-4444-4555-8666-777777777777", "ua-mac", "darwin")
	if err != nil {
		t.Fatalf("upsert ua dev: %v", err)
	}
	_ = st.Close()

	c, _, stderr := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprintf("%d", dev.ID),
		"--v4", "not-an-ip")
	if c == 0 {
		t.Fatalf("invalid IP should fail")
	}
	if !strings.Contains(stderr, "不是合法 IP") {
		t.Fatalf("error msg should mention 不是合法 IP, got: %s", stderr)
	}
}

func TestUnknownCommand(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x.db")
	c, _, stderr := runCLI(t, db, "", "nope")
	if c == 0 {
		t.Fatalf("unknown subcommand should fail")
	}
	// runCLI 固定 --lang zh:未知子命令走 cli.unknownSubcommandBare 的中文文案。
	if !strings.Contains(stderr, "未知子命令") {
		t.Fatalf("expected error message, got %s", stderr)
	}
}

// PSK 生成器的核心断言已搬到 `nanotun/util/psk_gen_test.go`(TestGeneratePSK_*),
// 那边是 single source of truth。此处不再保留 admin 本地副本测试 —— 之前的副本是
// admin / web 各自一份 `generatePSK()` 的产物,统一到 util 后没有必要再 admin 里
// 跑一遍同样的断言。
