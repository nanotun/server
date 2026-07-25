package store

import (
	"fmt"
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

	// 第二十轮深扫 MED:预览计数必须与实删谓词**完全一致** —— 同样排除 fixed_vip 守卫命中的那条,只数 dPlain 的 1 条。
	if cnt, err := s.CountOrphanLeases(ctx, 60); err != nil {
		t.Fatal(err)
	} else if cnt != 1 {
		t.Fatalf("CountOrphanLeases 预览应为 1(与实删一致,排除 fixed_vip 那条),got %d", cnt)
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

// TestUpsertLease_DoesNotDowngradeManual 覆盖第二十一轮深扫 MED:UpsertLease 的 manual 是**单向置位** ——
// 登录分配路径(唯一生产调用方)只在「本次分到的 vIP == device.fixed_vip」时才传 true,若 false 能清掉现值,
// 管理员用 `lease set --v4 X`(--manual 默认 true、且不写 device.fixed_vip)钉下的租约就会在该设备下次重登时
// 被降级成 manual=0 → 之后 `lease gc` 到期即回收管理员手钉的 sticky 地址(fixed_vip 那条另有 GC 守卫兜底,
// 纯 manual 这条无人兜)。清 manual 的合法路径都不经 UpsertLease。
func TestUpsertLease_DoesNotDowngradeManual(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "erin", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.UpsertDevice(ctx, u.ID, "uuid-manual", "m-manual", "linux")
	if err != nil {
		t.Fatal(err)
	}

	// 管理员手钉一条 manual 租约(注意:**不**设 device.fixed_vip,故 GC 的 fixed_vip 守卫兜不到它)。
	if _, err := s.UpsertManualLeasePreservingEmpty(ctx, d.ID, "10.0.0.80", "", true); err != nil {
		t.Fatal(err)
	}

	// 设备重登:登录路径复用同一 vIP,但因 fixed_vip 为空而算出 manual=false。
	l, err := s.UpsertLease(ctx, d.ID, "10.0.0.80", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Manual {
		t.Fatal("登录路径传 manual=false 不应清掉管理员钉下的 manual=1")
	}

	// 端到端确认后果已闭合:设备推到很久以前,GC 也不应回收这条 manual 租约。
	old := time.Now().Add(-3600 * time.Second).Unix()
	if _, err := s.DB().ExecContext(ctx, `UPDATE devices SET last_seen_at=? WHERE id=?`, old, d.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := s.GcOrphanLeases(ctx, 60); err != nil {
		t.Fatal(err)
	} else if n != 0 {
		t.Fatalf("manual 租约不应被 GC 回收,got %d", n)
	}

	// 单向置位的另一半:传 true 仍能正常把 manual=0 抬成 1。
	if _, err := s.DB().ExecContext(ctx, `UPDATE leases SET manual=0 WHERE device_id=?`, d.ID); err != nil {
		t.Fatal(err)
	}
	l2, err := s.UpsertLease(ctx, d.ID, "10.0.0.80", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !l2.Manual {
		t.Fatal("UpsertLease 传 manual=true 应能置位 manual")
	}
}

// TestUpsertLease_ManualPreservationMatrix 穷举 (原行 v4,原行 v6) × (本次写入 v4,本次写入 v6) 全组合,把
// 「登录路径何时可以保留管理员手钉」这条语义**整体**钉住。
//
// 为什么要穷举:这条规则连续三轮出错 —— 第二十一轮写成无条件 manual=excluded.manual(登录把管理员手钉清掉);
// 第二十二轮改成无条件 MAX(全新地址继承手钉、永久免疫 GC);第二十二轮的修正只按「同族具体→具体」判换址,又漏了
// **跨族替换**(A4 为空、v6 被钉,本次只写 v4)。逐个补点测试显然拦不住这一类漏判,故改为矩阵。
//
// 规则(与 UpsertLease 文档同一句):传 false 时,仅当「原行至少一个具体地址被原封不动保住、且没有任何一族被换成
// 另一个具体地址」才保留。期望值在表里逐行**显式**写出,不用 Go 复算规则 —— 否则实现与期望可能一起错。
func TestUpsertLease_ManualPreservationMatrix(t *testing.T) {
	const (
		a4 = "10.0.0.90"
		b4 = "10.0.0.91"
		a6 = "fd00::90"
		b6 = "fd00::91"
	)
	cases := []struct {
		old4, old6 string // 原行(manual=1)
		new4, new6 string // 本次 UpsertLease 写入(manual=false)
		want       bool   // 期望 manual
		why        string
	}{
		// 原行只有 v4 被钉。
		{a4, "", a4, "", true, "A4 原封不动留下"},
		{a4, "", a4, b6, true, "A4 留下,另一族新增不影响手钉"},
		{a4, "", b4, "", false, "A4 被换成 B4"},
		{a4, "", b4, b6, false, "A4 被换成 B4"},
		{a4, "", "", a6, false, "跨族替换:A4 没留下"},
		{a4, "", "", b6, false, "跨族替换:A4 没留下"},

		// 原行只有 v6 被钉 —— 第二十三轮实测出的漏洞就在这一组。
		{"", a6, "", a6, true, "A6 原封不动留下"},
		{"", a6, a4, a6, true, "A6 留下,另一族新增不影响手钉"},
		{"", a6, b4, a6, true, "A6 留下"},
		{"", a6, "", b6, false, "A6 被换成 B6"},
		{"", a6, a4, "", false, "跨族替换:A6 没留下(第二十三轮漏洞点)"},
		{"", a6, b4, "", false, "跨族替换:A6 没留下(第二十三轮漏洞点)"},
		{"", a6, a4, b6, false, "A6 被换成 B6"},

		// 原行双栈都被钉。
		{a4, a6, a4, a6, true, "两族都原封不动"},
		{a4, a6, a4, "", true, "A4 留下(某族本次缺失不影响手钉)"},
		{a4, a6, "", a6, true, "A6 留下"},
		{a4, a6, b4, a6, false, "A4 被换掉(行级标记取保守方向)"},
		{a4, a6, a4, b6, false, "A6 被换掉"},
		{a4, a6, b4, b6, false, "两族都被换掉"},
		{a4, a6, b4, "", false, "A4 被换掉"},
		{a4, a6, "", b6, false, "A6 被换掉"},

		// 原行本无地址:没有手钉可依附,跟随传入值。
		{"", "", a4, "", false, "原行无地址"},
		{"", "", "", a6, false, "原行无地址"},
	}

	for _, tc := range cases {
		name := fmt.Sprintf("old(%s,%s)->new(%s,%s)", or(tc.old4, "-"), or(tc.old6, "-"), or(tc.new4, "-"), or(tc.new6, "-"))
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t)
			ctx := t.Context()
			u, err := s.CreateUser(ctx, NewUser{Username: "matrix", PSKHash: "h"})
			if err != nil {
				t.Fatal(err)
			}
			d, err := s.UpsertDevice(ctx, u.ID, "uuid-matrix", "m-matrix", "linux")
			if err != nil {
				t.Fatal(err)
			}
			// 直接建原行:UpsertManualLeasePreservingEmpty 无法把某族按需置成 NULL(空串按「保留」处理)。
			if _, err := s.DB().ExecContext(ctx,
				`INSERT INTO leases(device_id,vip_v4,vip_v6,manual,assigned_at) VALUES(?,?,?,1,?)`,
				d.ID, nullableString(tc.old4), nullableString(tc.old6), nowUnix(),
			); err != nil {
				t.Fatal(err)
			}

			l, err := s.UpsertLease(ctx, d.ID, tc.new4, tc.new6, false)
			if err != nil {
				t.Fatal(err)
			}
			if l.Manual != tc.want {
				t.Errorf("manual = %v, want %v(%s)", l.Manual, tc.want, tc.why)
			}
			// 地址本身恒按本次分配结果落库,与 manual 的判定无关。
			if l.VIPv4 != tc.new4 || l.VIPv6 != tc.new6 {
				t.Errorf("地址应恒按本次写入落库: got (%q,%q), want (%q,%q)", l.VIPv4, l.VIPv6, tc.new4, tc.new6)
			}
		})
	}
}

func or(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
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
