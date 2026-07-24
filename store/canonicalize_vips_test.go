package store

import "testing"

// TestCanonicalizeStoredVIPs 验证第九轮深扫 MED 的存量 VIP 一次性归一:
//  1. 非规范、无碰撞的 IPv6 值被重写为规范式;
//  2. 归一后会与**同表同列**另一行撞车的值被安全跳过(不因 UNIQUE 冲突让迁移失败、不误删);
//  3. 完成后置一次性标记,重跑幂等。
func TestCanonicalizeStoredVIPs(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	dA, err := s.UpsertDevice(ctx, u.ID, "uuid-a", "m-a", "linux")
	if err != nil {
		t.Fatal(err)
	}
	dB, err := s.UpsertDevice(ctx, u.ID, "uuid-b", "m-b", "linux")
	if err != nil {
		t.Fatal(err)
	}
	dC, err := s.UpsertDevice(ctx, u.ID, "uuid-c", "m-c", "linux")
	if err != nil {
		t.Fatal(err)
	}

	// 直接写库塞入 lease(绕过 UpsertLease 的 canonicalVIP),模拟第七轮修复前落库的存量:
	//   dA: 非规范 "FD00::2"  —— 归一后 "fd00::2" 会撞 dB → 应被跳过。
	//   dB: 已规范 "fd00::2"  —— 已规范,no-op。
	//   dC: 非规范 "2001:DB8::AB" —— 无碰撞,应被重写为 "2001:db8::ab"。
	ins := func(devID int64, v6 string) {
		t.Helper()
		if _, err := s.DB().ExecContext(ctx,
			`INSERT INTO leases(device_id, vip_v4, vip_v6, manual, assigned_at) VALUES(?, NULL, ?, 0, 0)`,
			devID, v6); err != nil {
			t.Fatalf("insert lease dev=%d v6=%q: %v", devID, v6, err)
		}
	}
	ins(dA.ID, "FD00::2")
	ins(dB.ID, "fd00::2")
	ins(dC.ID, "2001:DB8::AB")

	// newTestStore 的 Migrate 已跑过一次归一并置标记为 1;重置为 0 以便对新塞入的存量再跑一次。
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE app_settings SET value='0' WHERE key=?`, vipCanonicalizedKey); err != nil {
		t.Fatal(err)
	}
	if err := s.canonicalizeStoredVIPs(ctx); err != nil {
		t.Fatalf("canonicalizeStoredVIPs: %v", err)
	}

	get := func(devID int64) string {
		t.Helper()
		var v string
		if err := s.DB().QueryRowContext(ctx,
			`SELECT vip_v6 FROM leases WHERE device_id=?`, devID).Scan(&v); err != nil {
			t.Fatalf("read lease dev=%d: %v", devID, err)
		}
		return v
	}

	// dC:非规范无碰撞 → 重写为规范式。
	if got := get(dC.ID); got != "2001:db8::ab" {
		t.Fatalf("dC vip_v6 = %q, want 规范式 2001:db8::ab", got)
	}
	// dA:归一后撞 dB(同表同列已有 "fd00::2")→ 安全跳过,保持原值(不失败、不误删)。
	if got := get(dA.ID); got != "FD00::2" {
		t.Fatalf("dA vip_v6 = %q, 碰撞应跳过、保持原值 FD00::2", got)
	}
	// dB:已规范 → 不变。
	if got := get(dB.ID); got != "fd00::2" {
		t.Fatalf("dB vip_v6 = %q, want 不变 fd00::2", got)
	}

	// 标记应被重新置 1,且重跑幂等。
	if v, ok, err := s.SettingsGet(ctx, vipCanonicalizedKey); err != nil || !ok || v != "1" {
		t.Fatalf("vip_canonicalized = %q ok=%v err=%v, want \"1\"", v, ok, err)
	}
	if err := s.canonicalizeStoredVIPs(ctx); err != nil {
		t.Fatalf("canonicalizeStoredVIPs re-run: %v", err)
	}
	if got := get(dC.ID); got != "2001:db8::ab" {
		t.Fatalf("重跑后 dC vip_v6 = %q, 应幂等保持规范式", got)
	}
}
