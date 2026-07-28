package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func mustUser(t *testing.T, s *Store, name string) *User {
	t.Helper()
	u, err := s.CreateUser(t.Context(), NewUser{Username: name, PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser %s: %v", name, err)
	}
	return u
}

func TestUpsertDevice_NormalizesWhatWouldOtherwiseSplitOneDeviceIntoTwoRows(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "normuser")

	if _, err := s.UpsertDevice(ctx, u.ID, "   ", "空 uuid", "linux"); err == nil {
		t.Fatal("裁剪后为空的 uuid 应被拒 —— 否则所有没上报 uuid 的客户端会挤在同一行上")
	}

	// uuid 走 trim + ToLower。SQLite 的 TEXT 比较是大小写敏感的,不归一的话同一台
	// 物理设备换个客户端版本(大小写不同)就会多出一行,租约和 vIP 全部另起一套。
	d1, err := s.UpsertDevice(ctx, u.ID, "AAAA-BBBB", "机器", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if d1.DeviceUUID != "aaaa-bbbb" {
		t.Fatalf("落库 uuid = %q,应小写化", d1.DeviceUUID)
	}
	d2, err := s.UpsertDevice(ctx, u.ID, "  aaaa-BBBB  ", "机器", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice 二次: %v", err)
	}
	if d2.ID != d1.ID {
		t.Fatalf("同一台设备变出了两行(id %d vs %d)", d1.ID, d2.ID)
	}

	// 设备名按字节截断但不能破 UTF-8 边界 —— 截半个汉字会让 MagicDNS 名变成乱码。
	long := strings.Repeat("测", DeviceNameMaxLen)
	d3, err := s.UpsertDevice(ctx, u.ID, "cccc", long, "linux")
	if err != nil {
		t.Fatalf("UpsertDevice 长名: %v", err)
	}
	if len(d3.DeviceName) > DeviceNameMaxLen {
		t.Fatalf("名字 %d 字节,超过上限 %d", len(d3.DeviceName), DeviceNameMaxLen)
	}
	if !utf8Valid(d3.DeviceName) {
		t.Fatalf("截断破坏了 UTF-8 边界: %q", d3.DeviceName)
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}

func TestUpsertDevice_DeduplicatesNamesAtTheDNSLevel(t *testing.T) {
	// MagicDNS 主机名以设备名为标签,重名会解析到错误的设备。去重按 NormalizeMagicHost
	// 归一后比较 —— "home pi" / "home_pi" / "home-pi" 在 DNS 层是同一个名字。
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "dnsuser")

	first, err := s.UpsertDevice(ctx, u.ID, "uuid-a", "home-pi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice a: %v", err)
	}
	if first.DeviceName != "home-pi" {
		t.Fatalf("第一台不该被改名: %q", first.DeviceName)
	}

	// 另一台设备报了 DNS 层等价的名字 → 追加 -1。
	second, err := s.UpsertDevice(ctx, u.ID, "uuid-b", "home pi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice b: %v", err)
	}
	if second.DeviceName == "home pi" {
		t.Fatal("撞名没被处理 —— 两台设备会争同一个 MagicDNS 名")
	}
	if !strings.HasSuffix(second.DeviceName, "-1") {
		t.Fatalf("第二台的名字 = %q,期望带 -1 后缀", second.DeviceName)
	}
	third, err := s.UpsertDevice(ctx, u.ID, "uuid-c", "home_pi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice c: %v", err)
	}
	if third.DeviceName == second.DeviceName {
		t.Fatalf("第三台跟第二台同名: %q", third.DeviceName)
	}

	// 自己重连不算跟自己撞名,名字必须稳定 —— 否则每次重连都会多一层 -N 后缀。
	again, err := s.UpsertDevice(ctx, u.ID, "uuid-b", "home pi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice b 重连: %v", err)
	}
	if again.DeviceName != second.DeviceName {
		t.Fatalf("重连后名字从 %q 变成了 %q", second.DeviceName, again.DeviceName)
	}

	// 归一后为空的名字(纯符号 / 纯非 ASCII)没有 MagicDNS 名,不参与去重,原样保留。
	for _, raw := range []string{"", "   ", "---", "办公室"} {
		d, err := s.UpsertDevice(ctx, u.ID, "uuid-sym-"+raw, raw, "linux")
		if err != nil {
			t.Fatalf("UpsertDevice %q: %v", raw, err)
		}
		if d.DeviceName != strings.TrimSpace(raw) && d.DeviceName != raw {
			t.Fatalf("名字 %q 被改成了 %q —— 没有 magic 名的设备不该参与去重", raw, d.DeviceName)
		}
	}

	// 跨用户不去重:两个用户各自的 MagicDNS 命名空间是分开的。
	u2 := mustUser(t, s, "dnsuser2")
	other, err := s.UpsertDevice(ctx, u2.ID, "uuid-d", "home-pi", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice d: %v", err)
	}
	if other.DeviceName != "home-pi" {
		t.Fatalf("跨用户被误去重: %q", other.DeviceName)
	}
}

func TestDeviceLookups_MissingRowsAreErrNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "lookupuser")

	for name, run := range map[string]func() error{
		"GetDevice":           func() error { _, e := s.GetDevice(ctx, 999999); return e },
		"GetDeviceByUUID":     func() error { _, e := s.GetDeviceByUUID(ctx, u.ID, "没有这个 uuid"); return e },
		"GetDeviceByUUIDAny":  func() error { _, e := s.GetDeviceByUUIDAny(ctx, "没有这个 uuid"); return e },
		"TouchDevice":         func() error { return s.TouchDevice(ctx, 999999) },
		"DeleteDevice":        func() error { return s.DeleteDevice(ctx, 999999) },
		"SetDeviceAlias":      func() error { return s.SetDeviceAlias(ctx, 999999, "别名") },
		"SetDeviceFixedVIP":   func() error { return s.SetDeviceFixedVIP(ctx, 999999, "10.0.0.1", "", false) },
		"SetDeviceRateLimit":  func() error { return s.SetDeviceRateLimit(ctx, 999999, 1000, 1000) },
		"SetDeviceExitPolicy": nil,
	} {
		if run == nil {
			continue
		}
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrNotFound) {
				t.Fatalf("err=%v,想要 ErrNotFound —— 静默成功会让 CLI/UI 显示「已修改」", err)
			}
		})
	}
}

func TestGetDeviceByUUIDAny_FailsClosedOnCrossTenantCollision(t *testing.T) {
	// (user_id, device_uuid) 才是 UNIQUE,所以同一个 uuid 可以分属不同用户 —— 而 uuid 是
	// 客户端自报的。端口转发按 target_device_uuid 在运行期解析 vIP,若撞到多行还「取最近
	// 活跃的那个」,低权用户注册一个与受害设备同 uuid 的设备并保持活跃,就能把本该投给受害
	// 设备的公网入站流量静默改投到自己身上。所以必须 fail-closed。
	s := newTestStore(t)
	ctx := t.Context()
	victim := mustUser(t, s, "victim")
	attacker := mustUser(t, s, "attacker")

	if _, err := s.UpsertDevice(ctx, victim.ID, "shared-uuid", "victim-box", "linux"); err != nil {
		t.Fatalf("UpsertDevice victim: %v", err)
	}
	// 只有一行时正常返回。
	if _, err := s.GetDeviceByUUIDAny(ctx, "shared-uuid"); err != nil {
		t.Fatalf("单行时应正常返回: %v", err)
	}

	if _, err := s.UpsertDevice(ctx, attacker.ID, "shared-uuid", "attacker-box", "linux"); err != nil {
		t.Fatalf("UpsertDevice attacker: %v", err)
	}
	got, err := s.GetDeviceByUUIDAny(ctx, "shared-uuid")
	if !errors.Is(err, ErrAmbiguousDevice) {
		t.Fatalf("err=%v got=%+v,想要 ErrAmbiguousDevice —— 挑一个返回就等于让 uuid 碰撞变成劫持", err, got)
	}
	// 大小写不同的查询也要撞上同样的歧义,不能靠改大小写绕过。
	if _, err := s.GetDeviceByUUIDAny(ctx, "SHARED-UUID"); !errors.Is(err, ErrAmbiguousDevice) {
		t.Fatalf("大写查询 err=%v,归一没生效就能绕过 fail-closed", err)
	}
}

func TestSetDeviceFixedVIP_CrossTableGuardAndForceRelease(t *testing.T) {
	// devices 上的 UNIQUE 索引只挡 device↔device 的 fixed_vip 撞车,挡不住「另一台设备的
	// **动态 lease** 正好占了这个地址」。这条跨表守卫此前没被执行过 —— 它挡的是双占黑洞。
	setup := func(t *testing.T) (*Store, *Device, *Device) {
		t.Helper()
		s := newTestStore(t)
		u := mustUser(t, s, "fixowner")
		a, err := s.UpsertDevice(t.Context(), u.ID, "uuid-fix-a", "a", "linux")
		if err != nil {
			t.Fatalf("UpsertDevice a: %v", err)
		}
		b, err := s.UpsertDevice(t.Context(), u.ID, "uuid-fix-b", "b", "linux")
		if err != nil {
			t.Fatalf("UpsertDevice b: %v", err)
		}
		// B 动态分到了 10.0.0.50。
		if _, err := s.UpsertLease(t.Context(), b.ID, "10.0.0.50", "", false); err != nil {
			t.Fatalf("UpsertLease b: %v", err)
		}
		return s, a, b
	}

	t.Run("不带 force 时拒绝并回滚", func(t *testing.T) {
		s, a, b := setup(t)
		ctx := t.Context()
		err := s.SetDeviceFixedVIP(ctx, a.ID, "10.0.0.50", "", false)
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("err=%v,想要 ErrDuplicate", err)
		}
		// 整个事务要回滚:A 不能留下 fixed_vip。
		gotA, err := s.GetDevice(ctx, a.ID)
		if err != nil {
			t.Fatalf("GetDevice a: %v", err)
		}
		if gotA.FixedVIPv4 != "" {
			t.Fatalf("A 的 fixed_vip = %q,冲突被拒后不该留下", gotA.FixedVIPv4)
		}
		// B 的 lease 也不能被动过。
		lb, err := s.GetLeaseByDevice(ctx, b.ID)
		if err != nil {
			t.Fatalf("GetLeaseByDevice b: %v", err)
		}
		if lb.VIPv4 != "10.0.0.50" {
			t.Fatalf("B 的 lease 被改成了 %q", lb.VIPv4)
		}
	})

	t.Run("带 force 时先释放对方的 lease 再钉", func(t *testing.T) {
		// force 的语义不是「无脑忽略冲突」—— 那会重新制造双占。它必须在同一事务里
		// 先把占着这个地址的**其它设备**的动态 lease 释放掉。
		s, a, b := setup(t)
		ctx := t.Context()
		if err := s.SetDeviceFixedVIP(ctx, a.ID, "10.0.0.50", "", true); err != nil {
			t.Fatalf("force 应当成功: %v", err)
		}
		gotA, err := s.GetDevice(ctx, a.ID)
		if err != nil {
			t.Fatalf("GetDevice a: %v", err)
		}
		if gotA.FixedVIPv4 != "10.0.0.50" {
			t.Fatalf("A 的 fixed_vip = %q,没钉上", gotA.FixedVIPv4)
		}
		lb, err := s.GetLeaseByDevice(ctx, b.ID)
		if err != nil {
			t.Fatalf("GetLeaseByDevice b: %v", err)
		}
		if lb.VIPv4 != "" {
			t.Fatalf("B 的 lease 仍持有 %q —— 两台设备同时占着这个地址,下行会在两条路之间漂",
				lb.VIPv4)
		}
		// 已用集里这个地址只应出现一次,且归属 A。
		v4, _, err := s.AllUsedVIPs(ctx)
		if err != nil {
			t.Fatalf("AllUsedVIPs: %v", err)
		}
		if !v4["10.0.0.50"] {
			t.Fatal("地址从已用集里消失了,会被再分配一次")
		}
	})

	t.Run("device 之间的 fixed_vip 撞车归一成 ErrDuplicate", func(t *testing.T) {
		s, a, b := setup(t)
		ctx := t.Context()
		if err := s.SetDeviceFixedVIP(ctx, a.ID, "10.0.0.77", "", false); err != nil {
			t.Fatalf("SetDeviceFixedVIP a: %v", err)
		}
		err := s.SetDeviceFixedVIP(ctx, b.ID, "10.0.0.77", "", false)
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("err=%v,想要 ErrDuplicate(UNIQUE 索引命中)", err)
		}
	})
}

func TestSetDeviceFixedVIP_MovesTheLeaseInsteadOfLeavingTwoAddressesOccupied(t *testing.T) {
	// 钉 fixed_vip 时要把该设备 lease 上的动态地址**搬到** fixed 值。不搬的话旧地址和新
	// fixed 会同时被算作已用,这台设备白占两个池地址,直到它下次登录或 GC 才释放。
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "moveowner")
	d, err := s.UpsertDevice(ctx, u.ID, "uuid-move", "m", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if _, err := s.UpsertLease(ctx, d.ID, "10.0.0.5", "fd00::5", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}

	if err := s.SetDeviceFixedVIP(ctx, d.ID, "10.0.0.60", "", false); err != nil {
		t.Fatalf("SetDeviceFixedVIP: %v", err)
	}
	l, err := s.GetLeaseByDevice(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetLeaseByDevice: %v", err)
	}
	if l.VIPv4 != "10.0.0.60" {
		t.Fatalf("lease v4 = %q,应被搬到 fixed 值", l.VIPv4)
	}
	if l.VIPv6 != "fd00::5" {
		t.Fatalf("lease v6 = %q,没钉 v6 时该族的动态地址要留着", l.VIPv6)
	}
	if !l.Manual {
		t.Fatal("manual 没同步成 1 —— GC 会把这条手钉的 lease 当空闲回收")
	}

	v4, _, err := s.AllUsedVIPs(ctx)
	if err != nil {
		t.Fatalf("AllUsedVIPs: %v", err)
	}
	if v4["10.0.0.5"] {
		t.Fatal("旧的动态地址还留在已用集里 —— 这台设备白占了两个池地址")
	}

	// 两族都清空 → manual 回落 0,lease 的动态地址保留。
	if err := s.SetDeviceFixedVIP(ctx, d.ID, "", "", false); err != nil {
		t.Fatalf("清 fixed_vip: %v", err)
	}
	l2, err := s.GetLeaseByDevice(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetLeaseByDevice: %v", err)
	}
	if l2.Manual {
		t.Fatal("清掉 fixed_vip 后 manual 应回落 0,否则这条 lease 永久免疫 GC")
	}
	if l2.VIPv4 != "10.0.0.60" {
		t.Fatalf("lease v4 = %q,清 fixed 不该把动态地址一起清掉", l2.VIPv4)
	}
}

func TestSetDeviceFixedVIP_CanonicalizesSoTwoSpellingsCannotBothBePinned(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "canonowner")
	a, _ := s.UpsertDevice(ctx, u.ID, "uuid-canon-a", "a", "linux")
	b, _ := s.UpsertDevice(ctx, u.ID, "uuid-canon-b", "b", "linux")

	if err := s.SetDeviceFixedVIP(ctx, a.ID, "", "FD00:0:0:0:0:0:0:CD", false); err != nil {
		t.Fatalf("SetDeviceFixedVIP a: %v", err)
	}
	gotA, _ := s.GetDevice(ctx, a.ID)
	if gotA.FixedVIPv6 != "fd00::cd" {
		t.Fatalf("落库 = %q,应规范化成 %q", gotA.FixedVIPv6, "fd00::cd")
	}
	if err := s.SetDeviceFixedVIP(ctx, b.ID, "", "fd00::cd", false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err=%v —— 同一地址的另一种写法必须被判成撞车", err)
	}
}

func TestSetDeviceAlias_TrimsAndTruncatesWithoutBreakingUTF8(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "aliasowner")
	d, _ := s.UpsertDevice(ctx, u.ID, "uuid-alias", "d", "linux")

	if err := s.SetDeviceAlias(ctx, d.ID, "  机房 A  "); err != nil {
		t.Fatalf("SetDeviceAlias: %v", err)
	}
	got, _ := s.GetDevice(ctx, d.ID)
	if got.Alias != "机房 A" {
		t.Fatalf("alias = %q,首尾空白应被裁掉", got.Alias)
	}

	long := strings.Repeat("别", DeviceAliasMaxLen)
	if err := s.SetDeviceAlias(ctx, d.ID, long); err != nil {
		t.Fatalf("SetDeviceAlias 长别名: %v", err)
	}
	got2, _ := s.GetDevice(ctx, d.ID)
	if len(got2.Alias) > DeviceAliasMaxLen {
		t.Fatalf("alias %d 字节,超过上限 %d", len(got2.Alias), DeviceAliasMaxLen)
	}
	if !utf8Valid(got2.Alias) {
		t.Fatalf("截断破坏了 UTF-8: %q", got2.Alias)
	}

	// 空串 = 清除,展示回落到客户端上报名。
	if err := s.SetDeviceAlias(ctx, d.ID, "   "); err != nil {
		t.Fatalf("清除别名: %v", err)
	}
	got3, _ := s.GetDevice(ctx, d.ID)
	if got3.Alias != "" {
		t.Fatalf("alias = %q,应被清空", got3.Alias)
	}
}

func TestBatchTouchDevices_SpansMoreThanOneChunk(t *testing.T) {
	// 分块是为了绕开 SQLite 的 host 参数上限。分块写错会让**部分**设备的 last_seen_at
	// 没被顶上去,那些设备的 vIP 在 lease gc 时被当成空闲回收 —— 长会话掉 IP。
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "touchowner")

	const n = 1201 // 跨三块(每块 500)
	ids := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		d, err := s.UpsertDevice(ctx, u.ID, fmt.Sprintf("uuid-touch-%d", i), "", "linux")
		if err != nil {
			t.Fatalf("UpsertDevice %d: %v", i, err)
		}
		ids = append(ids, d.ID)
	}
	// 全部推到很久以前。
	if _, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen_at=1 WHERE user_id=?`, u.ID); err != nil {
		t.Fatalf("回拨 last_seen_at: %v", err)
	}
	if err := s.BatchTouchDevices(ctx, ids); err != nil {
		t.Fatalf("BatchTouchDevices: %v", err)
	}
	var stale int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE user_id=? AND last_seen_at<=1`, u.ID).Scan(&stale); err != nil {
		t.Fatalf("COUNT: %v", err)
	}
	if stale != 0 {
		t.Fatalf("还有 %d 台设备没被 touch 到 —— 分块漏了,它们的 vIP 会被 GC 当空闲回收", stale)
	}
}

func TestDeviceDAL_DeadDBAndCorruptRowsNeverLookLikeSuccess(t *testing.T) {
	t.Run("损坏行不被静默跳过", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		u := mustUser(t, s, "corruptowner")
		d, _ := s.UpsertDevice(ctx, u.ID, "uuid-corrupt", "c", "linux")
		// rate_upload_bps 写成非数字。静默当成 0 会让这台设备的限速凭空消失
		// (0 = 跟随全局默认)。
		if _, err := s.db.ExecContext(ctx,
			`UPDATE devices SET rate_upload_bps='坏了' WHERE id=?`, d.ID); err != nil {
			t.Fatalf("注入损坏值: %v", err)
		}
		if _, err := s.GetDevice(ctx, d.ID); err == nil {
			t.Fatal("GetDevice 对损坏行报成功 —— 限速会被当成「未设置」")
		} else if errors.Is(err, ErrNotFound) {
			t.Fatalf("损坏被归一成 ErrNotFound: %v", err)
		}
		if _, err := s.ListDevicesByUser(ctx, u.ID); err == nil {
			t.Fatal("ListDevicesByUser 应当报错而不是跳过这一行")
		}
		if _, err := s.ListAllDevices(ctx); err == nil {
			t.Fatal("ListAllDevices 应当报错而不是跳过这一行")
		}
		if _, err := s.GetDeviceByUUIDAny(ctx, "uuid-corrupt"); err == nil {
			t.Fatal("GetDeviceByUUIDAny 应当报错")
		}
		if _, err := s.GetDeviceByUUID(ctx, u.ID, "uuid-corrupt"); err == nil {
			t.Fatal("GetDeviceByUUID 应当报错")
		}
	})

	t.Run("库关闭后每条路径都报错", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		u := mustUser(t, s, "deadowner")
		d, _ := s.UpsertDevice(ctx, u.ID, "uuid-dead", "c", "linux")
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		for name, run := range map[string]func() error{
			"UpsertDevice":       func() error { _, e := s.UpsertDevice(ctx, u.ID, "uuid-x", "x", "linux"); return e },
			"GetDevice":          func() error { _, e := s.GetDevice(ctx, d.ID); return e },
			"GetDeviceByUUID":    func() error { _, e := s.GetDeviceByUUID(ctx, u.ID, "uuid-dead"); return e },
			"GetDeviceByUUIDAny": func() error { _, e := s.GetDeviceByUUIDAny(ctx, "uuid-dead"); return e },
			"ListDevicesByUser":  func() error { _, e := s.ListDevicesByUser(ctx, u.ID); return e },
			"ListAllDevices":     func() error { _, e := s.ListAllDevices(ctx); return e },
			"TouchDevice":        func() error { return s.TouchDevice(ctx, d.ID) },
			"BatchTouchDevices":  func() error { return s.BatchTouchDevices(ctx, []int64{d.ID}) },
			"DeleteDevice":       func() error { return s.DeleteDevice(ctx, d.ID) },
			"SetDeviceAlias":     func() error { return s.SetDeviceAlias(ctx, d.ID, "a") },
			"SetDeviceFixedVIP":  func() error { return s.SetDeviceFixedVIP(ctx, d.ID, "10.0.0.1", "", false) },
			"SetDeviceRateLimit": func() error { return s.SetDeviceRateLimit(ctx, d.ID, 1, 1) },
		} {
			t.Run(name, func(t *testing.T) {
				if err := run(); err == nil {
					t.Fatal("库已关闭却报成功")
				}
			})
		}
	})
}

// 下面几个用 RAISE(ABORT) 触发器制造「事务半途失败」。这类路径用只读库或已关库都打不到
// (那两种情况第一条语句就失败了),而它们守的不变量恰恰最要紧:设备和它的公网转发必须
// 同生同死,fixed_vip 与 lease 必须同步 —— 半途提交出来的状态就是前面注释里描述的劫持
// 与双占场景。

func TestDeleteDevice_KeepsTheDeviceIfItsForwardsCannotBeReaped(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "pfrollback")
	d, err := s.UpsertDevice(ctx, u.ID, "uuid-pf-rb", "pf", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if _, err := s.UpsertLease(ctx, d.ID, "10.0.0.9", "", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if _, err := s.CreatePortForward(ctx, PortForward{
		PublicPort: 18081, Proto: "tcp", TargetDeviceUUID: "uuid-pf-rb",
		TargetIP: "10.0.0.9", TargetPort: 80, Enabled: true,
	}); err != nil {
		t.Fatalf("CreatePortForward: %v", err)
	}
	abortOn(t, s, "port_forwards", "DELETE")

	if err := s.DeleteDevice(ctx, d.ID); err == nil {
		t.Fatal("孤儿转发清不掉却报删除成功")
	}
	// 设备必须还在。若设备被删了而转发留着,谁再注册这个 uuid 就静默继承了公网入口。
	if _, err := s.GetDevice(ctx, d.ID); err != nil {
		t.Fatalf("设备被删了但转发还在 —— 正是要防的孤儿状态: %v", err)
	}
}

func TestDeleteDevice_SurfacesTheDeviceDeleteFailureItself(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mustUser(t, s, "devdelfail")
	d, err := s.UpsertDevice(ctx, u.ID, "uuid-del-fail", "d", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	abortOn(t, s, "devices", "DELETE")

	if err := s.DeleteDevice(ctx, d.ID); err == nil {
		t.Fatal("删设备失败却报成功")
	}
	if errors.Is(s.DeleteDevice(ctx, d.ID), ErrNotFound) {
		t.Fatal("写失败被归一成 ErrNotFound —— CLI 会显示「设备不存在」而不是「存储故障」")
	}
}

func TestSetDeviceFixedVIP_RollsBackWhenAnyStepInTheTransactionFails(t *testing.T) {
	// 三个失败点各自验一遍。共同的不变量:要么 devices.fixed_vip 和 leases 都改好,
	// 要么一个都不改。留下半途状态会让 GC 把手钉的地址当空闲回收,或者双占。
	newPair := func(t *testing.T) (*Store, *Device, *Device) {
		t.Helper()
		s := newTestStore(t)
		u := mustUser(t, s, "rbowner")
		a, err := s.UpsertDevice(t.Context(), u.ID, "uuid-rb-a", "a", "linux")
		if err != nil {
			t.Fatalf("UpsertDevice a: %v", err)
		}
		b, err := s.UpsertDevice(t.Context(), u.ID, "uuid-rb-b", "b", "linux")
		if err != nil {
			t.Fatalf("UpsertDevice b: %v", err)
		}
		return s, a, b
	}
	assertNotPinned := func(t *testing.T, s *Store, id int64) {
		t.Helper()
		got, err := s.GetDevice(t.Context(), id)
		if err != nil {
			t.Fatalf("GetDevice: %v", err)
		}
		if got.FixedVIPv4 != "" || got.FixedVIPv6 != "" {
			t.Fatalf("失败后仍留下了 fixed_vip: v4=%q v6=%q", got.FixedVIPv4, got.FixedVIPv6)
		}
	}

	t.Run("写 devices 本身失败", func(t *testing.T) {
		s, a, _ := newPair(t)
		abortOn(t, s, "devices", "UPDATE OF fixed_vip_v4")
		if err := s.SetDeviceFixedVIP(t.Context(), a.ID, "10.0.0.31", "", false); err == nil {
			t.Fatal("写失败却报成功")
		}
		assertNotPinned(t, s, a.ID)
	})

	t.Run("force 释放对方 lease 失败", func(t *testing.T) {
		s, a, b := newPair(t)
		if _, err := s.UpsertLease(t.Context(), b.ID, "10.0.0.32", "", false); err != nil {
			t.Fatalf("UpsertLease b: %v", err)
		}
		abortOn(t, s, "leases", "UPDATE")

		if err := s.SetDeviceFixedVIP(t.Context(), a.ID, "10.0.0.32", "", true); err == nil {
			t.Fatal("释放对方 lease 失败却报成功 —— 那就是双占")
		}
		assertNotPinned(t, s, a.ID)
		lb, err := s.GetLeaseByDevice(t.Context(), b.ID)
		if err != nil {
			t.Fatalf("GetLeaseByDevice b: %v", err)
		}
		if lb.VIPv4 != "10.0.0.32" {
			t.Fatalf("B 的 lease 被改成了 %q,事务没回滚干净", lb.VIPv4)
		}
	})

	t.Run("跨表守卫查不出来时不放行", func(t *testing.T) {
		s, a, _ := newPair(t)
		ctx := t.Context()
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE leases RENAME COLUMN vip_v6 TO vip_v6_drifted`); err != nil {
			t.Fatalf("改列名: %v", err)
		}
		if err := s.SetDeviceFixedVIP(ctx, a.ID, "10.0.0.33", "", false); err == nil {
			t.Fatal("守卫查询失败却照常钉上了 —— 查不出来就放行,双占无人拦")
		}
		assertNotPinned(t, s, a.ID)
	})

	t.Run("同步 lease 失败", func(t *testing.T) {
		s, a, _ := newPair(t)
		if _, err := s.UpsertLease(t.Context(), a.ID, "10.0.0.34", "", false); err != nil {
			t.Fatalf("UpsertLease a: %v", err)
		}
		abortOn(t, s, "leases", "UPDATE")

		if err := s.SetDeviceFixedVIP(t.Context(), a.ID, "10.0.0.35", "", false); err == nil {
			t.Fatal("同步 lease 失败却报成功 —— 会留下「fixed_vip 已设但 manual=0」的错位," +
				"GC 会把手钉的地址当空闲回收")
		}
		assertNotPinned(t, s, a.ID)
		la, err := s.GetLeaseByDevice(t.Context(), a.ID)
		if err != nil {
			t.Fatalf("GetLeaseByDevice a: %v", err)
		}
		if la.VIPv4 != "10.0.0.34" || la.Manual {
			t.Fatalf("lease 被改动了: vip=%q manual=%v", la.VIPv4, la.Manual)
		}
	})
}
