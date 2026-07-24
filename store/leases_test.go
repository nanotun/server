package store

import (
	"testing"
	"time"
)

// TestCanonicalVIP_Unmap 第十五轮深扫 MED:canonicalVIP 归一 IPv4-mapped IPv6 到点分形(Unmap),
// 并折叠大小写 / 压缩零段;空串与非法值原样返回。保证写路径 / AllUsedVIPs 读侧 / 冲突守卫处于同一文本域。
func TestCanonicalVIP_Unmap(t *testing.T) {
	cases := []struct{ in, want string }{
		{"::ffff:10.0.0.1", "10.0.0.1"}, // v4-mapped → 点分形
		{"::ffff:a0a:a0a", "10.10.10.10"},
		{"10.0.0.1", "10.0.0.1"},
		{"FD00::2", "fd00::2"},                    // 大写折叠
		{"2001:DB8:0:0:0:0:0:AB", "2001:db8::ab"}, // 零段压缩
		{"", ""},
		{"not-an-ip", "not-an-ip"}, // 非法值原样返回(不 panic)
	}
	for _, c := range cases {
		if got := canonicalVIP(c.in); got != c.want {
			t.Errorf("canonicalVIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestGcOrphanLeases_FixedVIPGuard 验证 GC 纵深守卫:即便某条 lease 的 manual 漂移成 0(模拟历史行 / 外部
// 直接写库),只要它的 vip 仍等于该 device 的 fixed_vip,GcOrphanLeases 就不得回收它;普通空闲 lease 则正常回收。
func TestGcOrphanLeases_FixedVIPGuard(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	// dFixed:手钉 fixed_vip,但故意把 lease.manual 写成 0,考验守卫。
	dFixed, err := s.UpsertDevice(ctx, u.ID, "uuid-fixed", "m-fixed", "linux")
	if err != nil {
		t.Fatal(err)
	}
	// dPlain:普通设备,空闲 lease,应被回收。
	dPlain, err := s.UpsertDevice(ctx, u.ID, "uuid-plain", "m-plain", "linux")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.UpsertLease(ctx, dFixed.ID, "10.0.0.50", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertLease(ctx, dPlain.ID, "10.0.0.60", "", false); err != nil {
		t.Fatal(err)
	}
	// 把 fixed_vip 设到 dFixed(事务里也会把 manual 同步成 1)……
	if err := s.SetDeviceFixedVIP(ctx, dFixed.ID, "10.0.0.50", "", false); err != nil {
		t.Fatal(err)
	}
	// ……然后**故意**把 manual 打回 0,模拟漂移;此时只有 fixed_vip 实值守卫能挡住回收。
	if _, err := s.DB().ExecContext(ctx, `UPDATE leases SET manual=0 WHERE device_id=?`, dFixed.ID); err != nil {
		t.Fatal(err)
	}

	// 两台设备都推到很久以前,满足 idle 回收条件。
	old := time.Now().Add(-3600 * time.Second).Unix()
	if _, err := s.DB().ExecContext(ctx, `UPDATE devices SET last_seen_at=? WHERE id IN (?,?)`, old, dFixed.ID, dPlain.ID); err != nil {
		t.Fatal(err)
	}

	n, err := s.GcOrphanLeases(ctx, 60)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应只回收 1 条普通空闲 lease,got %d", n)
	}
	// fixed_vip 对应的 lease 必须还在。
	if _, err := s.GetLeaseByDevice(ctx, dFixed.ID); err != nil {
		t.Fatalf("fixed_vip lease 被误回收: %v", err)
	}
	// 普通 lease 应已被删。
	if _, err := s.GetLeaseByDevice(ctx, dPlain.ID); err == nil {
		t.Fatal("普通空闲 lease 应被回收但仍存在")
	}
}

// TestSetDeviceFixedVIP_SyncsManual 验证事务化后 devices.fixed_vip 与 leases.manual 同步:设固定→manual=1,
// 清固定→manual=0。
func TestSetDeviceFixedVIP_SyncsManual(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "bob", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.UpsertDevice(ctx, u.ID, "uuid-b", "m-b", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertLease(ctx, d.ID, "10.0.0.70", "", false); err != nil {
		t.Fatal(err)
	}

	if err := s.SetDeviceFixedVIP(ctx, d.ID, "10.0.0.70", "", false); err != nil {
		t.Fatal(err)
	}
	l, err := s.GetLeaseByDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Manual {
		t.Fatal("设固定 vIP 后 lease.manual 应为 true")
	}

	if err := s.SetDeviceFixedVIP(ctx, d.ID, "", "", false); err != nil {
		t.Fatal(err)
	}
	l, err = s.GetLeaseByDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if l.Manual {
		t.Fatal("清空固定 vIP 后 lease.manual 应为 false")
	}
}
