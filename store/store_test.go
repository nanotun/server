package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// newTestStore 在临时目录里启一个 SQLite 文件库并迁移到最新 schema。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "nanotun_test.db")
	s, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func TestMigrateIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	for i := 0; i < 3; i++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate iter %d: %v", i, err)
		}
	}

	v, ok, err := s.SettingsGet(ctx, "schema_version")
	if err != nil {
		t.Fatalf("SettingsGet: %v", err)
	}
	if !ok || v != "21" {
		t.Fatalf("schema_version = %q ok=%v, want \"21\" true", v, ok)
	}

	// P2#7(2026-05-26):0014 把 dead table revoked_profiles 删了。这里直接走
	// sqlite_master 验证;DROP TABLE IF EXISTS 失败也不抛错(idempotent),想盯
	// 住实际效果就得断言「表确实不存在」。
	row := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='revoked_profiles'`)
	var n int
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count revoked_profiles: %v", err)
	}
	if n != 0 {
		t.Fatalf("0014 应当 DROP revoked_profiles,但 sqlite_master 仍能找到 %d 行", n)
	}

	// P3-c:0005_drop_default_cidr.sql 把这两条历史悬挂 setting 删干净了。
	// 任何还在 SettingsGet("default_cidr_v4") 的代码都是死代码 —— 这条断言充当回归保护。
	if _, ok, err := s.SettingsGet(ctx, "default_cidr_v4"); err != nil {
		t.Fatalf("SettingsGet default_cidr_v4: %v", err)
	} else if ok {
		t.Fatal("default_cidr_v4 应被 0005 migration 删除,不应再存在")
	}
	if _, ok, err := s.SettingsGet(ctx, "default_cidr_v6"); err != nil {
		t.Fatalf("SettingsGet default_cidr_v6: %v", err)
	} else if ok {
		t.Fatal("default_cidr_v6 应被 0005 migration 删除,不应再存在")
	}
}

func TestUserCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{
		Username:    "alice",
		PSKHash:     "hash-alice",
		IsAdmin:     true,
		ExitAllowed: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == 0 || u.Username != "alice" || !u.IsAdmin || !u.ExitAllowed {
		t.Fatalf("unexpected user: %+v", u)
	}

	got, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.ID != u.ID || got.PSKHash != "hash-alice" {
		t.Fatalf("GetUserByUsername mismatch: %+v", got)
	}

	if _, err := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "x"}); err == nil {
		t.Fatalf("expected unique violation on duplicate username")
	}

	if err := s.RotateUserPSK(ctx, u.ID, "hash-alice-2", nowUnix()); err != nil {
		t.Fatalf("RotateUserPSK: %v", err)
	}
	got, err = s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.PSKHash != "hash-alice-2" {
		t.Fatalf("psk_hash not updated: %q", got.PSKHash)
	}

	// 0008(2026-05-23):fixed_vip 已迁到 devices 表,user 上没有该字段。
	// 这里改为造一台 device 然后用 SetDeviceFixedVIP 验证。
	dev, err := s.UpsertDevice(ctx, u.ID,
		"deadbeef-1111-4222-8333-444444444444", "alice-mac", "darwin")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if err := s.SetDeviceFixedVIP(ctx, dev.ID, "100.64.0.10", ""); err != nil {
		t.Fatalf("SetDeviceFixedVIP: %v", err)
	}
	gotDev, err := s.GetDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if gotDev.FixedVIPv4 != "100.64.0.10" {
		t.Fatalf("device.FixedVIPv4 = %q, want 100.64.0.10", gotDev.FixedVIPv4)
	}

	if _, err := s.GetUserByUsername(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user err = %v, want ErrNotFound", err)
	}

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("ListUsers len = %d", len(users))
	}

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	users, _ = s.ListUsers(ctx)
	if len(users) != 0 {
		t.Fatalf("ListUsers after delete len = %d", len(users))
	}
}

// TestUpsertDevice_DedupName 验证「每用户设备名唯一」（Tailscale 式 -N 后缀）：
// 同名不同 uuid 去后缀；本设备重连不与自己冲突（不 churn）；归一后同名（空格/下划线）也算撞名。
// TestDeviceAlias_SurvivesUpsert 锁住 alias(0020)的核心不变量:
//  1. SetDeviceAlias 后 DisplayName 用别名;
//  2. 客户端重登录(UpsertDevice 覆盖 device_name)**不冲掉** alias;
//  3. 清空 alias 后 DisplayName 回落上报名。
func TestDeviceAlias_SurvivesUpsert(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u, err := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	d, err := s.UpsertDevice(ctx, u.ID, "uuid-alias", "GL-MT3000", "router")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if d.Alias != "" || d.DisplayName() != "GL-MT3000" {
		t.Fatalf("初始应无别名、展示上报名,got alias=%q display=%q", d.Alias, d.DisplayName())
	}

	if err := s.SetDeviceAlias(ctx, d.ID, "  sg-exit  "); err != nil {
		t.Fatalf("SetDeviceAlias: %v", err)
	}
	d2, _ := s.GetDevice(ctx, d.ID)
	if d2.Alias != "sg-exit" || d2.DisplayName() != "sg-exit" {
		t.Fatalf("设置后应 trim 且展示别名,got alias=%q display=%q", d2.Alias, d2.DisplayName())
	}

	// 客户端重登录改了主机名 → device_name 刷新,alias 不动。
	if _, err := s.UpsertDevice(ctx, u.ID, "uuid-alias", "OpenWrt-new", "router"); err != nil {
		t.Fatalf("UpsertDevice relogin: %v", err)
	}
	d3, _ := s.GetDevice(ctx, d.ID)
	if d3.DeviceName != "OpenWrt-new" {
		t.Fatalf("重登录应刷新上报名,got %q", d3.DeviceName)
	}
	if d3.Alias != "sg-exit" || d3.DisplayName() != "sg-exit" {
		t.Fatalf("重登录不应冲掉别名,got alias=%q display=%q", d3.Alias, d3.DisplayName())
	}

	// 清除 → 回落上报名。
	if err := s.SetDeviceAlias(ctx, d.ID, ""); err != nil {
		t.Fatalf("SetDeviceAlias clear: %v", err)
	}
	d4, _ := s.GetDevice(ctx, d.ID)
	if d4.Alias != "" || d4.DisplayName() != "OpenWrt-new" {
		t.Fatalf("清除后应回落上报名,got alias=%q display=%q", d4.Alias, d4.DisplayName())
	}

	// 不存在的 device → ErrNotFound。
	if err := s.SetDeviceAlias(ctx, 99999, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetDeviceAlias(不存在) = %v, want ErrNotFound", err)
	}
}

func TestUpsertDevice_DedupName(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u, err := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// 第一台：拿到裸名。
	d1, err := s.UpsertDevice(ctx, u.ID, "uuid-a", "homepi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice a: %v", err)
	}
	if d1.DeviceName != "homepi" {
		t.Fatalf("首台应保留裸名，got %q", d1.DeviceName)
	}

	// 第二台同名不同 uuid → 追加 -1。
	d2, err := s.UpsertDevice(ctx, u.ID, "uuid-b", "homepi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice b: %v", err)
	}
	if d2.DeviceName != "homepi-1" {
		t.Fatalf("重名第二台应为 homepi-1，got %q", d2.DeviceName)
	}

	// 第三台归一后同名（"home pi" → 归一 "home-pi"，而 "homepi" 归一 "homepi"，不同）→ 不撞，保留。
	// 但 "home_pi" 与 "home pi" 归一都是 "home-pi" → 第四台应被去重。
	d3, err := s.UpsertDevice(ctx, u.ID, "uuid-c", "home pi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice c: %v", err)
	}
	if d3.DeviceName != "home pi" {
		t.Fatalf("home pi 与 homepi 归一不同，应保留原名，got %q", d3.DeviceName)
	}
	d4, err := s.UpsertDevice(ctx, u.ID, "uuid-d", "home_pi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice d: %v", err)
	}
	if d4.DeviceName != "home_pi-1" {
		t.Fatalf("home_pi 归一撞 home pi，应为 home_pi-1，got %q", d4.DeviceName)
	}

	// 本设备（uuid-b）重连、仍报 "homepi" → 不与自己冲突，保持 homepi-1（不再叠加后缀）。
	d2b, err := s.UpsertDevice(ctx, u.ID, "uuid-b", "homepi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice b reconnect: %v", err)
	}
	if d2b.ID != d2.ID {
		t.Fatalf("重连应复用同一行 id")
	}
	if d2b.DeviceName != "homepi-1" {
		t.Fatalf("本设备重连不应叠加后缀，got %q", d2b.DeviceName)
	}

	// 另一用户可自由用同名（去重是 per-user）。
	u2, err := s.CreateUser(ctx, NewUser{Username: "bob", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	dOther, err := s.UpsertDevice(ctx, u2.ID, "uuid-a", "homepi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice other user: %v", err)
	}
	if dOther.DeviceName != "homepi" {
		t.Fatalf("跨用户同名应不受影响，got %q", dOther.DeviceName)
	}
}

func TestDeviceUpsertAndLease(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "bob", PSKHash: "hb", ExitAllowed: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	d1, err := s.UpsertDevice(ctx, u.ID, "uuid-1", "macbook", "darwin")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	first := d1.LastSeenAt

	d2, err := s.UpsertDevice(ctx, u.ID, "uuid-1", "macbook-renamed", "darwin")
	if err != nil {
		t.Fatalf("UpsertDevice repeat: %v", err)
	}
	if d2.ID != d1.ID {
		t.Fatalf("upsert should reuse id, got %d vs %d", d2.ID, d1.ID)
	}
	if d2.DeviceName != "macbook-renamed" {
		t.Fatalf("name not updated: %q", d2.DeviceName)
	}
	if d2.LastSeenAt < first {
		t.Fatalf("last_seen_at not advanced: %d -> %d", first, d2.LastSeenAt)
	}

	d3, err := s.UpsertDevice(ctx, u.ID, "uuid-2", "iphone", "ios")
	if err != nil {
		t.Fatalf("UpsertDevice second: %v", err)
	}
	devs, err := s.ListDevicesByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListDevicesByUser: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("device count = %d", len(devs))
	}

	if _, err := s.UpsertLease(ctx, d2.ID, "100.64.0.10", "", false); err != nil {
		t.Fatalf("UpsertLease #1: %v", err)
	}
	l, err := s.GetLeaseByDevice(ctx, d2.ID)
	if err != nil {
		t.Fatalf("GetLeaseByDevice: %v", err)
	}
	if l.VIPv4 != "100.64.0.10" || l.Manual {
		t.Fatalf("lease unexpected: %+v", l)
	}

	if _, err := s.UpsertLease(ctx, d3.ID, "100.64.0.11", "", true); err != nil {
		t.Fatalf("UpsertLease #2: %v", err)
	}

	v4, _, err := s.AllUsedVIPs(ctx)
	if err != nil {
		t.Fatalf("AllUsedVIPs: %v", err)
	}
	if !v4["100.64.0.10"] || !v4["100.64.0.11"] {
		t.Fatalf("AllUsedVIPs missing entries: %v", v4)
	}

	// 0008:fixed_vip 改 device 维度,AllUsedVIPs 也要把 devices.fixed_vip 算入。
	// 这里测「设了 fixed_vip 但还没产生 lease 的 device,它的 fixed IP 也被视为占用」。
	if err := s.SetDeviceFixedVIP(ctx, d2.ID, "100.64.0.99", ""); err != nil {
		t.Fatalf("SetDeviceFixedVIP: %v", err)
	}
	v4, _, err = s.AllUsedVIPs(ctx)
	if err != nil {
		t.Fatalf("AllUsedVIPs: %v", err)
	}
	if !v4["100.64.0.99"] {
		t.Fatalf("AllUsedVIPs should include device fixed vIP, got %v", v4)
	}
}

func TestACLBasics(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u1, err := s.CreateUser(ctx, NewUser{Username: "u1", PSKHash: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	u2, err := s.CreateUser(ctx, NewUser{Username: "u2", PSKHash: "h2"})
	if err != nil {
		t.Fatal(err)
	}
	u3, err := s.CreateUser(ctx, NewUser{Username: "u3", PSKHash: "h3"})
	if err != nil {
		t.Fatal(err)
	}

	if ok, err := s.IsAllowed(ctx, u1.ID, u2.ID); err != nil || !ok {
		t.Fatalf("empty acl should allow all: ok=%v err=%v", ok, err)
	}

	if _, err := s.AddACLPairBasic(ctx, u1.ID, u2.ID, ACLAllow); err != nil {
		t.Fatalf("AddACLPair allow: %v", err)
	}

	if ok, err := s.IsAllowed(ctx, u1.ID, u2.ID); err != nil || !ok {
		t.Fatalf("u1->u2 should be allowed: ok=%v err=%v", ok, err)
	}
	if ok, err := s.IsAllowed(ctx, u1.ID, u3.ID); err != nil || ok {
		t.Fatalf("u1->u3 should be denied (default deny): ok=%v err=%v", ok, err)
	}

	pair, err := s.AddACLPairBasic(ctx, u1.ID, u2.ID, ACLDeny)
	if err != nil {
		t.Fatalf("AddACLPair deny: %v", err)
	}
	if ok, err := s.IsAllowed(ctx, u1.ID, u2.ID); err != nil || ok {
		t.Fatalf("deny should win over allow: ok=%v err=%v", ok, err)
	}

	if err := s.DeleteACLPair(ctx, pair.ID); err != nil {
		t.Fatalf("DeleteACLPair: %v", err)
	}
	if ok, err := s.IsAllowed(ctx, u1.ID, u2.ID); err != nil || !ok {
		t.Fatalf("after delete u1->u2 should be allowed again: ok=%v err=%v", ok, err)
	}

	if ok, err := s.IsAllowed(ctx, u1.ID, u1.ID); err != nil || !ok {
		t.Fatalf("self-traffic should always pass: ok=%v err=%v", ok, err)
	}
}

func TestSettings(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	if _, ok, _ := s.SettingsGet(ctx, "missing"); ok {
		t.Fatalf("missing key reported present")
	}
	if err := s.SettingsSet(ctx, "k1", "v1"); err != nil {
		t.Fatalf("SettingsSet: %v", err)
	}
	v, ok, err := s.SettingsGet(ctx, "k1")
	if err != nil || !ok || v != "v1" {
		t.Fatalf("get k1 = %q ok=%v err=%v", v, ok, err)
	}
	if err := s.SettingsSet(ctx, "k1", "v2"); err != nil {
		t.Fatalf("SettingsSet update: %v", err)
	}
	v, _, _ = s.SettingsGet(ctx, "k1")
	if v != "v2" {
		t.Fatalf("get k1 after update = %q", v)
	}
}

func TestCountUsers(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	n, err := s.CountUsers(ctx)
	if err != nil || n != 0 {
		t.Fatalf("CountUsers initial = %d err=%v", n, err)
	}
	for i := 0; i < 3; i++ {
		_, err := s.CreateUser(ctx, NewUser{Username: name(i), PSKHash: "h"})
		if err != nil {
			t.Fatal(err)
		}
	}
	n, _ = s.CountUsers(ctx)
	if n != 3 {
		t.Fatalf("CountUsers = %d, want 3", n)
	}
}

func name(i int) string {
	return string(rune('a'+i)) + "user"
}

// TestBackfillUserCredentialID_Idempotent — P2#5(2026-05-26):
// 0013 BackfillUserCredentialID 必须幂等:连续多次调用,UUID 与 created_at 都
// 保持首次写入的值不变,后续返回 wrote=false。
//
// 这是 client 端「按 UUID 索引覆盖旧 PSK」承诺的根基:UUID 一旦写入就不能漂移,
// 连续 backfill 也不能改写。失败模式:race 下 (a) 后调用覆盖前调用值 → UUID 变;
// (b) wrote=true 错把第二次以后也当成「新写入」让 caller 误以为生成了新 UUID。
func TestBackfillUserCredentialID_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// 0013 之前的老 row:CredentialID / CredentialCreatedAt 都不传 → 入库 NULL。
	u, err := s.CreateUser(ctx, NewUser{Username: "legacy", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.CredentialID != "" || u.CredentialCreatedAt != 0 {
		t.Fatalf("老 user 的 credential 字段应为空:%+v", u)
	}

	const firstID = "0d4b1c4e-3a2f-4f7e-9c8d-12345678abcd"
	const firstTS = int64(1716000000)
	wrote, err := s.BackfillUserCredentialID(ctx, u.ID, firstID, firstTS)
	if err != nil {
		t.Fatalf("first backfill: %v", err)
	}
	if !wrote {
		t.Fatalf("first backfill 应为 wrote=true(老 row credential_id 为空)")
	}

	// 第二次:不同 UUID + 不同 ts 传入,但**不应**覆盖前次值 — 返回 wrote=false。
	const secondID = "8e2a59d1-fa11-4234-9d11-aaaaaa00bbbb"
	wrote, err = s.BackfillUserCredentialID(ctx, u.ID, secondID, firstTS+1000)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if wrote {
		t.Fatalf("second backfill 应为 wrote=false(已存在 credential_id)")
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.CredentialID != firstID {
		t.Fatalf("UUID 漂移:%q -> %q", firstID, got.CredentialID)
	}
	if got.CredentialCreatedAt != firstTS {
		t.Fatalf("ts 漂移:%d -> %d", firstTS, got.CredentialCreatedAt)
	}

	// 第三次:再来一次,也不能写。
	wrote, err = s.BackfillUserCredentialID(ctx, u.ID, "deadbeef-...", firstTS+9999)
	if err != nil {
		t.Fatalf("third backfill: %v", err)
	}
	if wrote {
		t.Fatalf("third backfill 应为 wrote=false")
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.CredentialID != firstID || got.CredentialCreatedAt != firstTS {
		t.Fatalf("第三次后值仍漂移:%+v", got)
	}
}

// TestRotateUserPSK_PreservesCredentialUUID — P2#5(2026-05-26):
// RotateUserPSK 只动 (psk_hash, credential_created_at),**不**动 credential_id。
// 这是「server 端 rotate-psk → 客户端扫新 QR 自动覆盖旧 PSK」承诺的核心。
//
// 同时验证 credential_created_at 单调递增(不严格单调,但至少不回退)。
func TestRotateUserPSK_PreservesCredentialUUID(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// 新 user:user_create 路径已经分配 UUID + ts。
	const initialID = "init-uuid-1234-5678-9abc-defghijk-XXXX"
	const initialTS = int64(1700000000)
	u, err := s.CreateUser(ctx, NewUser{
		Username:            "alice",
		PSKHash:             "hash-old",
		CredentialID:        initialID,
		CredentialCreatedAt: initialTS,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// rotate #1:新 psk_hash + 新 ts。UUID 不变。
	const rot1TS = initialTS + 60
	if err := s.RotateUserPSK(ctx, u.ID, "hash-new-1", rot1TS); err != nil {
		t.Fatalf("rotate #1: %v", err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.CredentialID != initialID {
		t.Fatalf("rotate 改了 UUID:%q -> %q", initialID, got.CredentialID)
	}
	if got.PSKHash != "hash-new-1" {
		t.Fatalf("rotate 没改 psk_hash:%q", got.PSKHash)
	}
	if got.CredentialCreatedAt != rot1TS {
		t.Fatalf("rotate 没刷 ts:%d", got.CredentialCreatedAt)
	}

	// rotate #2:再来一次。UUID 仍不变;ts 单调不回退。
	const rot2TS = rot1TS + 60
	if err := s.RotateUserPSK(ctx, u.ID, "hash-new-2", rot2TS); err != nil {
		t.Fatalf("rotate #2: %v", err)
	}
	got2, _ := s.GetUser(ctx, u.ID)
	if got2.CredentialID != initialID {
		t.Fatalf("rotate#2 改了 UUID:%q -> %q", initialID, got2.CredentialID)
	}
	if got2.CredentialCreatedAt < got.CredentialCreatedAt {
		t.Fatalf("rotate ts 单调性破坏:%d → %d", got.CredentialCreatedAt, got2.CredentialCreatedAt)
	}
	if got2.PSKHash != "hash-new-2" {
		t.Fatalf("rotate#2 没改 psk_hash")
	}
}

// TestRotateUserPSKAndEnsureCredential_ConcurrentCAS — 第六轮深扫 P1#2(CAS 版):
// 8 个 worker 共享一份 `u`(同一 PSKHash="h-old" snapshot),并发跑
// RotateUserPSKAndEnsureCredential。CAS(`WHERE psk_hash=h-old`)保证**恰好 1 个**
// worker 能落库,其余 N-1 个收 ErrPSKConcurrentRotation。
//
// 这同时验了原 P1-B 的相邻不变量 — 赢家的 credential_id 会被 backfill,且非赢家
// 不再走 backfill 分支(因为他们在 CAS 阶段已退出),所以「N-1 个 worker 进 backfill
// race」已成 dead path。但 EnsureUserCredentialID 入口仍有 backfill race(`credentials
// show` 并发),由 TestEnsureUserCredentialID_ConcurrentBackfill 单独覆盖。
//
// 反证:CAS 修复回归(`RotateUserPSKAndEnsureCredential` 改回无条件 RotateUserPSK),
// N 个 worker 都 err=nil + 各自 hash;只有最后写入者的 hash 留 DB,其余 N-1 worker
// 给 caller 渲染了无效 QR。本测试通过断言 winners==1 catch 这条回归。
func TestRotateUserPSKAndEnsureCredential_ConcurrentCAS(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "legacy_concurrent", PSKHash: "h-old"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.CredentialID != "" {
		t.Fatalf("CreateUser 不应自动 backfill UUID,got %q", u.CredentialID)
	}

	const goroutines = 8
	type result struct {
		credID string
		hash   string
		err    error
	}
	results := make([]result, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		idx := i
		hash := "h-new-" + name(idx)
		// 每个 goroutine 都拿一份 u snapshot(PSKHash="h-old"),模拟两个 admin
		// 同时从 CLI/Web GetUser 看到同一份 old state。CAS base 就是这个 "h-old"。
		uCopy := *u
		go func() {
			defer wg.Done()
			<-start
			cid, _, err := s.RotateUserPSKAndEnsureCredential(ctx, &uCopy, hash)
			results[idx] = result{credID: cid, hash: hash, err: err}
		}()
	}
	close(start)
	wg.Wait()

	finalU, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser final: %v", err)
	}
	if finalU.CredentialID == "" {
		t.Fatal("CAS 赢家应已 backfill credential_id,但 DB 仍为空")
	}

	var winners, casLosers int
	for i, r := range results {
		switch {
		case r.err == nil:
			winners++
			if r.hash != finalU.PSKHash {
				t.Errorf("winner worker[%d] hash=%q ≠ DB PSKHash=%q —— CAS 不该让多人都 nil-err",
					i, r.hash, finalU.PSKHash)
			}
			if r.credID != finalU.CredentialID {
				t.Errorf("winner worker[%d] credID=%q ≠ DB %q", i, r.credID, finalU.CredentialID)
			}
		case errors.Is(r.err, ErrPSKConcurrentRotation):
			casLosers++
		default:
			t.Errorf("worker[%d] 非预期 err: %v", i, r.err)
		}
	}
	// CAS 保证「同一 expectedOldHash 守门下只有 1 个赢家」,SQLite 也满足。
	if winners != 1 {
		t.Errorf("winners=%d,期望恰好 1(CAS 守门)", winners)
	}
	if casLosers != goroutines-1 {
		t.Errorf("casLosers=%d,期望恰好 %d(N-1 个 worker 必须收 ErrPSKConcurrentRotation)",
			casLosers, goroutines-1)
	}
}

// TestEnsureUserCredentialID_ConcurrentBackfill — 第六轮深扫 P1#2 拆分:
// EnsureUserCredentialID(`credentials show` 入口)直接走 BackfillUserCredentialID,
// **不**经过 CAS rotate 路径。两个 admin 同时对同一**老 user**(credential_id IS NULL)
// 调 credentials show,都试图 backfill UUID。SQL 的 `WHERE credential_id IS NULL`
// 守门让后到者拿 wrote=false,helper 必须重读 DB 拿权威 UUID 返回 —— 替原
// `TestRotateUserPSKAndEnsureCredential_ConcurrentBackfill` 在 CAS 之前覆盖的不变量。
func TestEnsureUserCredentialID_ConcurrentBackfill(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "legacy_show_concurrent", PSKHash: "h-old"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.CredentialID != "" {
		t.Fatalf("CreateUser 不应自动 backfill UUID,got %q", u.CredentialID)
	}

	const goroutines = 8
	type result struct {
		credID string
		err    error
	}
	results := make([]result, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		idx := i
		uCopy := *u
		go func() {
			defer wg.Done()
			<-start
			cid, _, err := s.EnsureUserCredentialID(ctx, &uCopy)
			results[idx] = result{credID: cid, err: err}
		}()
	}
	close(start)
	wg.Wait()

	finalU, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser final: %v", err)
	}
	if finalU.CredentialID == "" {
		t.Fatal("并发 backfill 后 DB credential_id 仍为空")
	}
	// 不变量:N worker 全部返回 nil err 且 credID == finalU.CredentialID。
	// 反证:helper 忽略 !wrote 直接吐自生 UUID 时,N-1 个 worker 返回未入库的随机 UUID,
	// 与 finalU 122 bit 熵下不可能碰撞 → 任一 mismatch 立即 catch。
	for i, r := range results {
		if r.err != nil {
			t.Errorf("worker[%d] 返回 err: %v", i, r.err)
			continue
		}
		if r.credID != finalU.CredentialID {
			t.Errorf("worker[%d] credID=%q ≠ DB %q (backfill !wrote 重读分支回归)",
				i, r.credID, finalU.CredentialID)
		}
	}
}

// TestRotateUserPSKAndEnsureCredential_EmptyPSKHashRefuses — 第七轮深扫 P1:
// 空 PSKHash 的 user snapshot 调本 helper 时必须**显式失败**,而不是退化到
// 无 CAS 的无条件 rotate。生产里这是不该发生的状态(0001 migration NOT NULL
// + CreateUser 拒空),但手工改库 / migration 出错时可能撞上;静默退回会重现
// P1#2 的双赢家无效 QR 行为。
func TestRotateUserPSKAndEnsureCredential_EmptyPSKHashRefuses(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "edge", PSKHash: "h-real"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// 模拟 stale snapshot:本地变量 PSKHash 抹空(模拟 caller 从一个有 bug 的
	// 旧迁移 / 修复路径上拿到的 User struct 没读 psk_hash 列),但 DB 行仍有 hash。
	uCopy := *u
	uCopy.PSKHash = ""

	_, _, err = s.RotateUserPSKAndEnsureCredential(ctx, &uCopy, "h-new")
	if err == nil {
		t.Fatalf("空 PSKHash 调 RotateUserPSKAndEnsureCredential 必须报错,but got nil")
	}
	if errors.Is(err, ErrPSKConcurrentRotation) {
		t.Fatalf("空 PSKHash 不该被识别成 CAS race(应是显式 refuse),got: %v", err)
	}

	// 确保 DB row 完全没被改:psk_hash + credential_id + credential_created_at
	// 都应保持原始值。第八轮深扫加强 — 单看 PSKHash 不足以反证「fallback 跑了
	// 但 RotateUserPSK 在 SQL 出错」之类的中间状态,把 credential 字段也锁死。
	finalU, gerr := s.GetUser(ctx, u.ID)
	if gerr != nil {
		t.Fatalf("GetUser: %v", gerr)
	}
	if finalU.PSKHash != "h-real" {
		t.Errorf("空 PSKHash refuse 后 DB.PSKHash=%q,应保持 %q —— P1#2 回归:fallback 路径被触发",
			finalU.PSKHash, "h-real")
	}
	if finalU.CredentialID != u.CredentialID {
		t.Errorf("空 PSKHash refuse 后 DB.CredentialID 被改:got %q want %q",
			finalU.CredentialID, u.CredentialID)
	}
	if finalU.CredentialCreatedAt != u.CredentialCreatedAt {
		t.Errorf("空 PSKHash refuse 后 DB.CredentialCreatedAt 被改:got %d want %d",
			finalU.CredentialCreatedAt, u.CredentialCreatedAt)
	}
}

// TestRotateUserPSK_CASLosesOnStaleSnapshot — 第六轮深扫 P1#2 简化覆盖:
// 单线程模拟「stale snapshot 落 CAS」场景。先 rotate 一次让 DB hash="h-new",
// 然后 caller 拿**老 snapshot**(PSKHash="h-old")再调一次 rotate —— CAS base
// "h-old" 不匹配 DB "h-new",必须收 ErrPSKConcurrentRotation,而**不**是悄悄
// 把 DB hash 覆盖成 caller 的新值(那就回到了 P1#2 出现的危险行为)。
//
// 这个 case 比并发版更可靠地 catch 回归,而且文档化了 CAS 语义,future 改动看到
// 测试名能立即懂意图。
func TestRotateUserPSK_CASLosesOnStaleSnapshot(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{
		Username:            "stale_view",
		PSKHash:             "h-old",
		CredentialID:        uuid.NewString(),
		CredentialCreatedAt: time.Now().UTC().Unix(),
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	staleSnapshot := *u // PSKHash="h-old"

	// 模拟另一个 admin 已经先一步 rotate 到了 "h-new"。
	if _, _, err := s.RotateUserPSKAndEnsureCredential(ctx, u, "h-new"); err != nil {
		t.Fatalf("初次 rotate 不该失败: %v", err)
	}

	// stale caller 拿过期 snapshot 再 rotate,期望 ErrPSKConcurrentRotation。
	_, _, err = s.RotateUserPSKAndEnsureCredential(ctx, &staleSnapshot, "h-bogus")
	if !errors.Is(err, ErrPSKConcurrentRotation) {
		t.Fatalf("stale snapshot rotate 应返回 ErrPSKConcurrentRotation,got: %v", err)
	}

	// 反证:DB 必须仍是上一步的 "h-new",**没**被 stale caller 的 "h-bogus" 覆盖。
	finalU, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if finalU.PSKHash != "h-new" {
		t.Errorf("CAS 失败应保护 DB hash 不变,got %q want %q —— P1#2 回归:CAS 守门失效",
			finalU.PSKHash, "h-new")
	}
}
