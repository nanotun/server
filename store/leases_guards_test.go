package store

import (
	"errors"
	"fmt"
	"testing"
)

// leases.go 里没被覆盖的那批分支,后果几乎都是同一个:**两台设备拿到同一个 vIP**。
// 那不会报错,只会让下行流量在两条路之间漂,表现为「时好时坏」的路由黑洞 —— 最难查的
// 一类故障。所以这里的重点是把每一道防双占的闸单独验一遍。

// seedLeaseDevices 造一个用户和 n 台设备。
func seedLeaseDevices(t *testing.T, s *Store, n int) []*Device {
	t.Helper()
	u, err := s.CreateUser(t.Context(), NewUser{Username: "leaseowner", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	out := make([]*Device, 0, n)
	for i := 0; i < n; i++ {
		d, err := s.UpsertDevice(t.Context(), u.ID,
			fmt.Sprintf("uuid-lease-%d", i), fmt.Sprintf("dev%d", i), "linux")
		if err != nil {
			t.Fatalf("UpsertDevice %d: %v", i, err)
		}
		out = append(out, d)
	}
	return out
}

func TestUpsertLease_RefusesAVIPAnotherDeviceAlreadyHolds(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	d := seedLeaseDevices(t, s, 2)

	if _, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.88", "fd00::88", false); err != nil {
		t.Fatalf("第一台设备取地址: %v", err)
	}

	for _, tc := range []struct{ name, v4, v6 string }{
		{"v4 撞车", "10.0.0.88", ""},
		{"v6 撞车", "", "fd00::88"},
		{"两族都撞", "10.0.0.88", "fd00::88"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.UpsertLease(ctx, d[1].ID, tc.v4, tc.v6, false)
			if !errors.Is(err, ErrDuplicate) {
				t.Fatalf("err=%v,想要 ErrDuplicate —— 登录路径靠 errors.Is 判定后重新分配;"+
					"透传裸驱动错误会被上层当成 IO 故障 Warn 掉,于是两台设备双占同一 vIP", err)
			}
			if _, err := s.GetLeaseByDevice(ctx, d[1].ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("冲突被拒后第二台设备却留下了租约: %v", err)
			}
		})
	}

	// 同一台设备重复写自己已持有的地址必须成功(幂等续租),否则每次重登都会被自己的
	// 上一条租约挡住。
	if _, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.88", "fd00::88", false); err != nil {
		t.Fatalf("同设备续租自己的地址被拒了: %v", err)
	}
}

func TestUpsertLease_RefusesAVIPPinnedAsAnotherDevicesFixedVIP(t *testing.T) {
	// 这是**跨表**守卫:SQLite 没法在 leases 与 devices 之间强制 UNIQUE,所以是写后校验、
	// 命中即回滚。这条路径此前从没被执行过 —— 而它挡的正是「管理员钉给 A 的地址被自动
	// 分配给了 B」这种双占。
	for _, tc := range []struct {
		name       string
		fixV4      string
		fixV6      string
		takeV4     string
		takeV6     string
		preserving bool
	}{
		{name: "v4 与他人 fixed_vip 冲突", fixV4: "10.0.0.99", takeV4: "10.0.0.99"},
		{name: "v6 与他人 fixed_vip 冲突", fixV6: "fd00::99", takeV6: "fd00::99"},
		{name: "preserving 版同样要挡", fixV4: "10.0.0.99", takeV4: "10.0.0.99", preserving: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			d := seedLeaseDevices(t, s, 2)
			if err := s.SetDeviceFixedVIP(t.Context(), d[0].ID, tc.fixV4, tc.fixV6, false); err != nil {
				t.Fatalf("SetDeviceFixedVIP: %v", err)
			}

			var err error
			if tc.preserving {
				_, err = s.UpsertManualLeasePreservingEmpty(t.Context(), d[1].ID, tc.takeV4, tc.takeV6, false)
			} else {
				_, err = s.UpsertLease(t.Context(), d[1].ID, tc.takeV4, tc.takeV6, false)
			}
			if !errors.Is(err, ErrDuplicate) {
				t.Fatalf("err=%v,想要 ErrDuplicate —— 这个地址是管理员钉给另一台设备的,"+
					"分给第二台就是双占,下行会在两条路之间漂", err)
			}
			// 写后校验命中要**回滚**。若只是返回错误但 INSERT 已提交,库里就真的双占了。
			if _, gerr := s.GetLeaseByDevice(t.Context(), d[1].ID); !errors.Is(gerr, ErrNotFound) {
				t.Fatalf("守卫报了错却没回滚,第二台设备的租约已经落库: %v", gerr)
			}
		})
	}

	// 反面:设备取**自己**的 fixed_vip 必须放行(守卫写的是 `id != ?`)。判反了管理员
	// 钉的地址反而谁也用不了。
	t.Run("取自己的 fixed_vip 要放行", func(t *testing.T) {
		s := newTestStore(t)
		d := seedLeaseDevices(t, s, 1)
		if err := s.SetDeviceFixedVIP(t.Context(), d[0].ID, "10.0.0.99", "fd00::99", false); err != nil {
			t.Fatalf("SetDeviceFixedVIP: %v", err)
		}
		if _, err := s.UpsertLease(t.Context(), d[0].ID, "10.0.0.99", "fd00::99", false); err != nil {
			t.Fatalf("设备取自己被钉的地址被拒了: %v", err)
		}
	})
}

func TestUpsertLease_CanonicalizesBeforeTheUniquenessChecks(t *testing.T) {
	// 同一个 v6 地址的两种写法必须被判成同一个地址,否则 UNIQUE 索引和跨表守卫都会
	// 认成两个,双占照旧发生。
	s := newTestStore(t)
	ctx := t.Context()
	d := seedLeaseDevices(t, s, 2)

	if _, err := s.UpsertLease(ctx, d[0].ID, "", "FD00:0:0:0:0:0:0:AB", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	got, err := s.GetLeaseByDevice(ctx, d[0].ID)
	if err != nil {
		t.Fatalf("GetLeaseByDevice: %v", err)
	}
	if got.VIPv6 != "fd00::ab" {
		t.Fatalf("落库 v6 = %q,应规范化成 %q", got.VIPv6, "fd00::ab")
	}
	// 用压缩小写形去抢,必须撞上。
	if _, err := s.UpsertLease(ctx, d[1].ID, "", "fd00::ab", false); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err=%v —— 同一地址的另一种写法没被判成冲突,这就是双占的来源", err)
	}
	// IPv4-mapped 形也要归一到点分形。
	if _, err := s.UpsertLease(ctx, d[1].ID, "::ffff:10.0.0.7", "", false); err != nil {
		t.Fatalf("UpsertLease mapped: %v", err)
	}
	got2, _ := s.GetLeaseByDevice(ctx, d[1].ID)
	if got2.VIPv4 != "10.0.0.7" {
		t.Fatalf("落库 v4 = %q,IPv4-mapped 应归一成点分形", got2.VIPv4)
	}
}

func TestAllUsedVIPs_ExcludesBothFamiliesFromBothTables(t *testing.T) {
	// 这个已用集是分配器的唯一输入。漏掉任何一项,分配器就会把已占地址再发一次。
	// v6 那半边此前完全没被验证过 —— 也就是说「v6 已用地址被排除」这件事一直是假设。
	s := newTestStore(t)
	ctx := t.Context()
	d := seedLeaseDevices(t, s, 3)

	if _, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.11", "fd00::11", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	// 只有 fixed_vip、还没拿到 lease 的设备也算占用 —— 否则管理员刚钉的地址会被
	// 分配给别人,那台设备登录时才撞 UNIQUE 失败。
	if err := s.SetDeviceFixedVIP(ctx, d[1].ID, "10.0.0.22", "fd00::22", false); err != nil {
		t.Fatalf("SetDeviceFixedVIP: %v", err)
	}

	v4, v6, err := s.AllUsedVIPs(ctx)
	if err != nil {
		t.Fatalf("AllUsedVIPs: %v", err)
	}
	for _, want := range []string{"10.0.0.11", "10.0.0.22"} {
		if !v4[want] {
			t.Errorf("v4 已用集缺 %s: %v", want, v4)
		}
	}
	for _, want := range []string{"fd00::11", "fd00::22"} {
		if !v6[want] {
			t.Errorf("v6 已用集缺 %s: %v", want, v6)
		}
	}
	if v4["10.0.0.33"] || v6["fd00::33"] {
		t.Error("没被占用的地址不该出现在已用集里")
	}

	// 非规范写法的存量行(canonicalizeStoredVIPs 因碰撞跳过时会留下)读侧也要归一,
	// 否则分配器拿规范式去比对,认不出这个地址已被占用。
	if _, err := s.db.ExecContext(ctx,
		`UPDATE leases SET vip_v6='FD00:0:0:0:0:0:0:44' WHERE device_id=?`, d[2].ID); err != nil {
		t.Fatalf("造非规范存量行: %v", err)
	}
	if _, err := s.UpsertLease(ctx, d[2].ID, "", "fd00::55", false); err != nil {
		// 上一步那台设备可能还没有 lease 行,补一条再改
		t.Logf("d[2] 先建 lease: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE leases SET vip_v6='FD00:0:0:0:0:0:0:44' WHERE device_id=?`, d[2].ID); err != nil {
		t.Fatalf("造非规范存量行: %v", err)
	}
	_, v6b, err := s.AllUsedVIPs(ctx)
	if err != nil {
		t.Fatalf("AllUsedVIPs: %v", err)
	}
	if !v6b["fd00::44"] {
		t.Fatalf("非规范存量行没被归一进已用集: %v —— 分配器会把这个地址再发一次", v6b)
	}
}

func TestGcOrphanLeases_IdleMustBePositiveOrItWouldWipeEveryLease(t *testing.T) {
	// idle<=0 时 cutoff = now,`last_seen_at < now` 对几乎所有设备成立 —— 这道闸没了,
	// 一次 `lease gc --idle 0` 就会把全网非手动租约清空,所有设备重登换 IP。
	s := newTestStore(t)
	ctx := t.Context()
	d := seedLeaseDevices(t, s, 1)
	if _, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.1", "", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}

	for _, idle := range []int64{0, -1, -3600} {
		t.Run(fmt.Sprintf("idle=%d", idle), func(t *testing.T) {
			if _, err := s.GcOrphanLeases(ctx, idle); err == nil {
				t.Fatal("GcOrphanLeases 应当拒绝非正的 idle")
			}
			// 预览侧的约定不同:返回 0 而不是报错(与「no-op」语义一致),
			// 但**绝不能**返回一个大于 0 的数,否则 CLI 会提示「将删除 N 条」。
			n, err := s.CountOrphanLeases(ctx, idle)
			if err != nil {
				t.Fatalf("CountOrphanLeases err=%v", err)
			}
			if n != 0 {
				t.Fatalf("CountOrphanLeases = %d,非正 idle 应当预览 0 条", n)
			}
			if _, err := s.GetLeaseByDevice(ctx, d[0].ID); err != nil {
				t.Fatalf("租约被删了: %v", err)
			}
		})
	}
}

func TestLeaseDAL_FailuresNeverLookLikeSuccess(t *testing.T) {
	t.Run("损坏行不被静默跳过", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		d := seedLeaseDevices(t, s, 1)
		if _, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.5", "", false); err != nil {
			t.Fatalf("UpsertLease: %v", err)
		}
		// assigned_at 写成非数字。AllUsedVIPs 不读这列,所以它仍能正确算出已用集;
		// 但 GetLeaseByDevice 要扫这列,必须报错而不是返回一条 assigned_at=0 的租约
		// (那会让 lease gc 把它当成「很久以前分配的」)。
		if _, err := s.db.ExecContext(ctx,
			`UPDATE leases SET assigned_at='坏了' WHERE device_id=?`, d[0].ID); err != nil {
			t.Fatalf("注入损坏值: %v", err)
		}
		if _, err := s.GetLeaseByDevice(ctx, d[0].ID); err == nil {
			t.Fatal("GetLeaseByDevice 对损坏行报成功")
		} else if errors.Is(err, ErrNotFound) {
			t.Fatalf("损坏被归一成 ErrNotFound: %v", err)
		}
	})

	// AllUsedVIPs 读两张表:先 leases,再 devices.fixed_vip。把 devices 的列改名可以让
	// **第二条**查询单独失败,打的是「前半程顺利、后半程出错」这条路径。
	// 这里的不变量最要紧:已用集宁可算不出来(报错),也绝不能少算一个地址 —— 少算就是
	// 把已占地址再发一次,直接双占。
	t.Run("已用集只算了一半时必须报错而不是返回残缺的集合", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		d := seedLeaseDevices(t, s, 2)
		if _, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.5", "", false); err != nil {
			t.Fatalf("UpsertLease: %v", err)
		}
		if err := s.SetDeviceFixedVIP(ctx, d[1].ID, "10.0.0.6", "", false); err != nil {
			t.Fatalf("SetDeviceFixedVIP: %v", err)
		}
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE devices RENAME COLUMN fixed_vip_v4 TO fixed_vip_v4_drifted`); err != nil {
			t.Fatalf("改列名: %v", err)
		}
		v4, _, err := s.AllUsedVIPs(ctx)
		if err == nil {
			t.Fatalf("只读到 leases 那一半却报成功,返回 %v —— 10.0.0.6 被钉给了别人,"+
				"这个残缺集合会让分配器把它再发一次", v4)
		}
	})

	// 跨表守卫那条查询自己失败时,也不能当成「没冲突」放行 —— 那等于守卫形同虚设。
	t.Run("跨表守卫查不出来时不能默认放行", func(t *testing.T) {
		for _, preserving := range []bool{false, true} {
			name := "UpsertLease"
			if preserving {
				name = "UpsertManualLeasePreservingEmpty"
			}
			t.Run(name, func(t *testing.T) {
				s := newTestStore(t)
				ctx := t.Context()
				d := seedLeaseDevices(t, s, 1)
				if _, err := s.db.ExecContext(ctx,
					`ALTER TABLE devices RENAME COLUMN fixed_vip_v6 TO fixed_vip_v6_drifted`); err != nil {
					t.Fatalf("改列名: %v", err)
				}
				var err error
				if preserving {
					_, err = s.UpsertManualLeasePreservingEmpty(ctx, d[0].ID, "10.0.0.9", "", false)
				} else {
					_, err = s.UpsertLease(ctx, d[0].ID, "10.0.0.9", "", false)
				}
				if err == nil {
					t.Fatal("守卫查询失败却照常写入了租约 —— 查不出来就放行,双占无人拦")
				}
				if _, gerr := s.GetLeaseByDevice(ctx, d[0].ID); !errors.Is(gerr, ErrNotFound) {
					t.Fatalf("报错了却没回滚: %v", gerr)
				}
			})
		}
	})

	t.Run("preserving 版的 lease 撞车也要归一成 ErrDuplicate", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		d := seedLeaseDevices(t, s, 2)
		if _, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.77", "", false); err != nil {
			t.Fatalf("UpsertLease: %v", err)
		}
		_, err := s.UpsertManualLeasePreservingEmpty(ctx, d[1].ID, "10.0.0.77", "", true)
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("err=%v,想要 ErrDuplicate —— admin CLI 靠它给出「这个地址已被占用」"+
				"的提示,而不是一条裸驱动错误", err)
		}
	})

	t.Run("表没了每条路径都报错", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		d := seedLeaseDevices(t, s, 1)
		if _, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.5", "", false); err != nil {
			t.Fatalf("UpsertLease: %v", err)
		}
		if _, err := s.db.ExecContext(ctx, `DROP TABLE leases`); err != nil {
			t.Fatalf("DROP TABLE: %v", err)
		}
		for name, run := range map[string]func() error{
			"GetLeaseByDevice": func() error { _, e := s.GetLeaseByDevice(ctx, d[0].ID); return e },
			"UpsertLease":      func() error { _, e := s.UpsertLease(ctx, d[0].ID, "10.0.0.6", "", false); return e },
			"UpsertPreserving": func() error {
				_, e := s.UpsertManualLeasePreservingEmpty(ctx, d[0].ID, "10.0.0.6", "", false)
				return e
			},
			"DeleteLease":       func() error { return s.DeleteLease(ctx, d[0].ID) },
			"AllUsedVIPs":       func() error { _, _, e := s.AllUsedVIPs(ctx); return e },
			"GcOrphanLeases":    func() error { _, e := s.GcOrphanLeases(ctx, 60); return e },
			"CountOrphanLeases": func() error { _, e := s.CountOrphanLeases(ctx, 60); return e },
		} {
			t.Run(name, func(t *testing.T) {
				if err := run(); err == nil {
					t.Fatal("leases 表都没了却报成功")
				}
			})
		}
	})

	t.Run("库关闭后连事务都开不起来", func(t *testing.T) {
		s := newTestStore(t)
		d := seedLeaseDevices(t, s, 1)
		ctx := t.Context()
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		for name, run := range map[string]func() error{
			"UpsertLease": func() error { _, e := s.UpsertLease(ctx, d[0].ID, "10.0.0.6", "", false); return e },
			"UpsertPreserving": func() error {
				_, e := s.UpsertManualLeasePreservingEmpty(ctx, d[0].ID, "10.0.0.6", "", false)
				return e
			},
			"AllUsedVIPs":    func() error { _, _, e := s.AllUsedVIPs(ctx); return e },
			"DeleteLease":    func() error { return s.DeleteLease(ctx, d[0].ID) },
			"GcOrphanLeases": func() error { _, e := s.GcOrphanLeases(ctx, 60); return e },
		} {
			t.Run(name, func(t *testing.T) {
				if err := run(); err == nil {
					t.Fatal("库已关闭却报成功")
				}
			})
		}
	})
}

func TestUpsertManualLeasePreservingEmpty_KeepsTheOtherFamilyAtomically(t *testing.T) {
	// admin CLI `lease set --v4 X`(不带 --v6)走这条路。空族=保留现值,而不是清空。
	// 判反了会把设备的 v6 地址悄悄抹掉,IPv6 侧直接失联。
	s := newTestStore(t)
	ctx := t.Context()
	d := seedLeaseDevices(t, s, 1)

	if _, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.7", "fd00::7", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	got, err := s.UpsertManualLeasePreservingEmpty(ctx, d[0].ID, "10.0.0.8", "", true)
	if err != nil {
		t.Fatalf("UpsertManualLeasePreservingEmpty: %v", err)
	}
	if got.VIPv4 != "10.0.0.8" {
		t.Fatalf("v4 = %q,应当被换成新值", got.VIPv4)
	}
	if got.VIPv6 != "fd00::7" {
		t.Fatalf("v6 = %q,只改 v4 时 v6 必须原样保留(空族=保留,不是清空)", got.VIPv6)
	}
	if !got.Manual {
		t.Fatal("manual 没置位")
	}

	// 与 UpsertLease 的语义差别要明确:那边空族**就是**清族。
	got2, err := s.UpsertLease(ctx, d[0].ID, "10.0.0.8", "", false)
	if err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if got2.VIPv6 != "" {
		t.Fatalf("v6 = %q,登录分配路径上空族应当清族", got2.VIPv6)
	}
}
