package store

// misc_guards_test.go:几个小表 DAL(via6_sites / subnet_routes / rate_settings /
// audit_logs / port_forwards / server_id)的入参守卫与失败可见性。
//
// 这些表单看都很简单,但它们的失败模式都是「静默」的:site_id 截断会把两个站点映射到同一
// 4via6 地址;路由审批写不进去却报成功,管理员以为放行了;限速三个键写一半,运行期看到的是
// 上行新值配下行旧值;audit 写失败被忽略,事后查不到任何痕迹。所以下面每个用例都盯着
// 「错误有没有传出来」和「库里剩下什么」,不只看返回值。

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// newDeadStore 建库跑完迁移后立刻关闭,用来验证「连接没了」时每个函数都报错。
func newDeadStore(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return s
}

// abortOnWhen 与 abortOn 同义,但可以只在某一行上触发,用于分辨同一事务里的第几步失败。
func abortOnWhen(t *testing.T, s *Store, table, op, when string) {
	t.Helper()
	name := fmt.Sprintf("boomw_%s_%s", table, strings.ReplaceAll(op, " ", "_"))
	_, err := s.db.ExecContext(t.Context(), fmt.Sprintf(
		`CREATE TRIGGER %s BEFORE %s ON %s WHEN %s BEGIN SELECT RAISE(ABORT, '注入的故障'); END`,
		name, op, table, when))
	if err != nil {
		t.Fatalf("建触发器: %v", err)
	}
}

func seedOneDevice(t *testing.T, s *Store, tag string) *Device {
	t.Helper()
	u := mustUser(t, s, "owner-"+tag)
	d, err := s.UpsertDevice(t.Context(), u.ID, "uuid-"+tag, "dev-"+tag, "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	return d
}

// ---------- via6_sites ----------

func TestSiteID_RefusesToTruncateOrReuse(t *testing.T) {
	// site_id 只有 16 位可用(4via6 地址里就那么多位)。超界的值若被 uint16 截断,
	// 两个不同站点会算出同一个 4via6 前缀,发往 A 站点的包会落到 B 站点 ——
	// 宁可整条路由解析失败,也不能悄悄投错。
	s := newTestStore(t)
	ctx := t.Context()
	d := seedOneDevice(t, s, "via6")

	t.Run("坏 device_id", func(t *testing.T) {
		for _, id := range []int64{0, -1} {
			_, err := s.GetOrAssignSiteID(ctx, id)
			if err == nil {
				t.Fatalf("device_id=%d 应被拒", id)
			}
			// 要在入参这一层就拒掉。靠外键兜底的话,运维看到的是
			// "FOREIGN KEY constraint failed",会去找那台不存在的设备。
			if !strings.Contains(err.Error(), "bad device_id") {
				t.Fatalf("device_id=%d 的报错不是入参校验: %v", id, err)
			}
		}
	})

	t.Run("分配是幂等的", func(t *testing.T) {
		first, err := s.GetOrAssignSiteID(ctx, d.ID)
		if err != nil {
			t.Fatalf("首次分配: %v", err)
		}
		second, err := s.GetOrAssignSiteID(ctx, d.ID)
		if err != nil {
			t.Fatalf("再次分配: %v", err)
		}
		if first != second {
			t.Fatalf("同一设备两次拿到 %d / %d —— site_id 一变,已下发的 4via6 地址全部指错地方",
				first, second)
		}
	})

	t.Run("设备不存在时不留下悬空站点", func(t *testing.T) {
		if _, err := s.GetOrAssignSiteID(ctx, 987654); err == nil {
			t.Fatal("给不存在的设备分配了 site_id —— 数据面反查会指向一个没有主人的站点")
		}
		var n int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM via6_sites WHERE device_id=987654`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 0 {
			t.Fatalf("留下了 %d 条悬空站点行", n)
		}
	})

	t.Run("超界的既存行一律报错而不是截断", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		d := seedOneDevice(t, s, "overflow")
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO via6_sites(site_id, device_id, created_at) VALUES(70000, ?, 0)`, d.ID); err != nil {
			t.Fatalf("插超界行: %v", err)
		}
		if sid, err := s.SiteIDByDevice(ctx, d.ID); err == nil {
			t.Fatalf("超界 site_id 被读成了 %d —— 70000 截成 uint16 就是 4464,撞上别的站点", sid)
		}
		if sid, err := s.GetOrAssignSiteID(ctx, d.ID); err == nil {
			t.Fatalf("分配路径也没拦住,返回 %d", sid)
		}
		// 列表路径的口径是「跳过坏行」而不是整表报废:一个站点坏掉不该让其他站点的路由表建不起来。
		m, err := s.ListVia6Sites(ctx)
		if err != nil {
			t.Fatalf("ListVia6Sites: %v", err)
		}
		if _, ok := m[d.ID]; ok {
			t.Fatal("超界行出现在路由表里了 —— 数据面会按截断值建映射")
		}
	})

	t.Run("库关掉之后一律报错", func(t *testing.T) {
		dead := newDeadStore(t)
		ops := map[string]func() error{
			"GetOrAssignSiteID": func() error { _, err := dead.GetOrAssignSiteID(ctx, 1); return err },
			"SiteIDByDevice":    func() error { _, err := dead.SiteIDByDevice(ctx, 1); return err },
			"DeviceIDBySiteID":  func() error { _, err := dead.DeviceIDBySiteID(ctx, 1); return err },
			"ListVia6Sites":     func() error { _, err := dead.ListVia6Sites(ctx); return err },
		}
		for name, run := range ops {
			t.Run(name, func(t *testing.T) {
				if err := run(); err == nil {
					t.Fatal("库已关闭却报成功")
				}
			})
		}
	})

	t.Run("未分配的反查是 ErrNotFound", func(t *testing.T) {
		if _, err := s.DeviceIDBySiteID(ctx, 60000); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err=%v,想要 ErrNotFound —— 非宣告方设备本来就不该有 site_id", err)
		}
	})
}

// ---------- subnet_routes ----------

func TestSubnetRoutes_ApprovalNeverSucceedsSilently(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	d := seedOneDevice(t, s, "routes")

	t.Run("入参守卫", func(t *testing.T) {
		if _, err := s.UpsertAdvertisedRoute(ctx, 0, "10.1.0.0/24"); err == nil {
			t.Fatal("device_id=0 应被拒")
		}
		if _, err := s.UpsertAdvertisedRoute(ctx, d.ID, "   "); err == nil {
			t.Fatal("空 cidr 应被拒 —— 空网段会被审批界面展示成一条什么都不放行的规则")
		}
		if err := s.SetRouteStatus(ctx, d.ID, "10.1.0.0/24", "approve", ""); err == nil {
			t.Fatal("拼错的状态应被拒 —— 落库后既不是 pending 也不是 approved,两边界面都看不见它")
		}
	})

	t.Run("重复上报不回退审批状态", func(t *testing.T) {
		const cidr = "10.2.0.0/24"
		if _, err := s.UpsertAdvertisedRoute(ctx, d.ID, cidr); err != nil {
			t.Fatalf("首次上报: %v", err)
		}
		if err := s.SetRouteStatus(ctx, d.ID, cidr, RouteStatusApproved, ""); err != nil {
			t.Fatalf("审批: %v", err)
		}
		again, err := s.UpsertAdvertisedRoute(ctx, d.ID, cidr)
		if err != nil {
			t.Fatalf("再次上报: %v", err)
		}
		if again.Status != RouteStatusApproved {
			t.Fatalf("状态被打回 %q —— 客户端一重连就把管理员的审批冲掉了", again.Status)
		}
	})

	t.Run("驳回原因只在 rejected 时保留", func(t *testing.T) {
		const cidr = "10.3.0.0/24"
		if _, err := s.UpsertAdvertisedRoute(ctx, d.ID, cidr); err != nil {
			t.Fatalf("上报: %v", err)
		}
		if err := s.SetRouteStatus(ctx, d.ID, cidr, RouteStatusRejected, "网段与总部冲突"); err != nil {
			t.Fatalf("驳回: %v", err)
		}
		got, err := s.GetRouteByDeviceCIDR(ctx, d.ID, cidr)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Reason != "网段与总部冲突" {
			t.Fatalf("reason=%q,驳回原因丢了管理员就得重新查一遍为什么", got.Reason)
		}
		if err := s.SetRouteStatus(ctx, d.ID, cidr, RouteStatusApproved, "忽略我"); err != nil {
			t.Fatalf("改判: %v", err)
		}
		got, err = s.GetRouteByDeviceCIDR(ctx, d.ID, cidr)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Reason != "" {
			t.Fatalf("改判成 approved 后 reason 还留着 %q —— 界面上会显示「已批准,原因:网段冲突」", got.Reason)
		}
	})

	t.Run("撤回只删 pending", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		d := seedOneDevice(t, s, "withdraw")
		for _, cidr := range []string{"10.4.0.0/24", "10.5.0.0/24"} {
			if _, err := s.UpsertAdvertisedRoute(ctx, d.ID, cidr); err != nil {
				t.Fatalf("上报 %s: %v", cidr, err)
			}
		}
		if err := s.SetRouteStatus(ctx, d.ID, "10.4.0.0/24", RouteStatusApproved, ""); err != nil {
			t.Fatalf("审批: %v", err)
		}
		n, err := s.DeleteAdvertisedRoutesForDevice(ctx, d.ID)
		if err != nil {
			t.Fatalf("撤回: %v", err)
		}
		if n != 1 {
			t.Fatalf("删了 %d 条,只该删掉那条 pending", n)
		}
		left, err := s.ListRoutesByDevice(ctx, d.ID)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(left) != 1 || left[0].Status != RouteStatusApproved {
			t.Fatalf("剩下 %+v —— 网络抖动导致的一次空上报不该抹掉已批准的网段", left)
		}
	})

	t.Run("行不存在时报 ErrNotFound", func(t *testing.T) {
		missing := map[string]func() error{
			"GetRouteByDeviceCIDR": func() error { _, err := s.GetRouteByDeviceCIDR(ctx, d.ID, "9.9.9.0/24"); return err },
			"SetRouteStatus": func() error {
				return s.SetRouteStatus(ctx, d.ID, "9.9.9.0/24", RouteStatusApproved, "")
			},
			"DeleteRoute": func() error { return s.DeleteRoute(ctx, d.ID, "9.9.9.0/24") },
		}
		for name, run := range missing {
			t.Run(name, func(t *testing.T) {
				if err := run(); !errors.Is(err, ErrNotFound) {
					t.Fatalf("err=%v,想要 ErrNotFound —— 审批一条不存在的路由却报成功,"+
						"管理员会以为已经放行", err)
				}
			})
		}
	})

	t.Run("坏行让列表整体报错而不是少一条", func(t *testing.T) {
		// 少一条比报错危险:管理员看不到某条已批准的网段,就以为它没放行,
		// 而数据面照样在转发那个网段的流量。
		s := newTestStore(t)
		ctx := t.Context()
		d := seedOneDevice(t, s, "corrupt-route")
		if _, err := s.UpsertAdvertisedRoute(ctx, d.ID, "10.6.0.0/24"); err != nil {
			t.Fatalf("上报: %v", err)
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE subnet_routes SET advertised_at='这不是时间戳' WHERE device_id=?`, d.ID); err != nil {
			t.Fatalf("弄坏行: %v", err)
		}
		lists := map[string]func() ([]SubnetRoute, error){
			"ListRoutesByDevice": func() ([]SubnetRoute, error) { return s.ListRoutesByDevice(ctx, d.ID) },
			"ListRoutesByStatus": func() ([]SubnetRoute, error) { return s.ListRoutesByStatus(ctx, RouteStatusPending) },
			"ListAllRoutes":      func() ([]SubnetRoute, error) { return s.ListAllRoutes(ctx) },
		}
		for name, run := range lists {
			t.Run(name, func(t *testing.T) {
				if out, err := run(); err == nil {
					t.Fatalf("读到坏行却返回 %d 条和 nil", len(out))
				}
			})
		}
		if _, err := s.GetRouteByDeviceCIDR(ctx, d.ID, "10.6.0.0/24"); err == nil {
			t.Fatal("单行查询也没报错")
		} else if errors.Is(err, ErrNotFound) {
			t.Fatalf("坏行被归一成 ErrNotFound: %v", err)
		}
	})

	t.Run("库关掉之后一律报错", func(t *testing.T) {
		dead := newDeadStore(t)
		ops := map[string]func() error{
			"UpsertAdvertisedRoute": func() error {
				_, err := dead.UpsertAdvertisedRoute(ctx, 1, "10.0.0.0/24")
				return err
			},
			"SetRouteStatus":     func() error { return dead.SetRouteStatus(ctx, 1, "10.0.0.0/24", RouteStatusApproved, "") },
			"DeleteRoute":        func() error { return dead.DeleteRoute(ctx, 1, "10.0.0.0/24") },
			"DeleteAdvertised":   func() error { _, err := dead.DeleteAdvertisedRoutesForDevice(ctx, 1); return err },
			"ListRoutesByDevice": func() error { _, err := dead.ListRoutesByDevice(ctx, 1); return err },
			"ListRoutesByStatus": func() error { _, err := dead.ListRoutesByStatus(ctx, "pending"); return err },
			"ListAllRoutes":      func() error { _, err := dead.ListAllRoutes(ctx); return err },
		}
		for name, run := range ops {
			t.Run(name, func(t *testing.T) {
				if err := run(); err == nil {
					t.Fatal("库已关闭却报成功")
				}
			})
		}
	})
}

// ---------- rate_settings ----------

func TestRateDefaults_WriteAllThreeKeysOrNone(t *testing.T) {
	// 三个键必须同生同死。留下「上行已改、下行还是旧值」的撕裂态,运维在设置页看到的
	// 是自己填的那一组,数据面执行的却是另一组,而且没有任何报错。
	ctx := t.Context()
	good := RateDefaults{UploadBPS: 1000, DownloadBPS: 2000, BurstBytes: RateBurstBytesMin}

	t.Run("非法入参", func(t *testing.T) {
		s := newTestStore(t)
		bad := []struct {
			name string
			d    RateDefaults
		}{
			{"上行为负", RateDefaults{UploadBPS: -1}},
			{"下行为负", RateDefaults{DownloadBPS: -1}},
			{"burst 为负", RateDefaults{BurstBytes: -1}},
			{"burst 小于下限", RateDefaults{BurstBytes: RateBurstBytesMin - 1}},
			{"burst 超上限", RateDefaults{BurstBytes: RateBurstBytesMax + 1}},
		}
		for _, tc := range bad {
			t.Run(tc.name, func(t *testing.T) {
				if err := s.SetRateDefaults(ctx, tc.d); !errors.Is(err, ErrInvalid) {
					t.Fatalf("err=%v,想要 ErrInvalid —— 写得进却在运行期被静默夹住,"+
						"就是「设了没生效」这类最难查的问题", err)
				}
			})
		}
		got, err := s.GetRateDefaults(ctx)
		if err != nil {
			t.Fatalf("GetRateDefaults: %v", err)
		}
		if got != (RateDefaults{}) {
			t.Fatalf("被拒的写落库了: %+v", got)
		}
	})

	t.Run("正常写入读回一致", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SetRateDefaults(ctx, good); err != nil {
			t.Fatalf("SetRateDefaults: %v", err)
		}
		got, err := s.GetRateDefaults(ctx)
		if err != nil {
			t.Fatalf("GetRateDefaults: %v", err)
		}
		if got != good {
			t.Fatalf("读回 %+v,写进去的是 %+v", got, good)
		}
	})

	for _, step := range []struct {
		name string
		key  string
	}{
		{"第一个键写失败", settingRateDefaultUploadBPS},
		{"第二个键写失败", settingRateDefaultDownloadBPS},
		{"第三个键写失败", settingRateBurstBytes},
	} {
		t.Run(step.name+"时三个键都不动", func(t *testing.T) {
			s := newTestStore(t)
			before, err := s.GetRateDefaults(ctx)
			if err != nil {
				t.Fatalf("GetRateDefaults: %v", err)
			}
			abortOnWhen(t, s, "app_settings", "UPDATE OF value",
				fmt.Sprintf("NEW.key = '%s'", step.key))

			if err := s.SetRateDefaults(ctx, good); err == nil {
				t.Fatal("写失败却报成功")
			}
			after, err := s.GetRateDefaults(ctx)
			if err != nil {
				t.Fatalf("GetRateDefaults: %v", err)
			}
			if after != before {
				t.Fatalf("失败后变成了 %+v(原本 %+v)—— 这就是撕裂态", after, before)
			}
		})
	}

	t.Run("手抠坏的值按 0 处理但不拒服务", func(t *testing.T) {
		// 0 = 沿用 toml / 代码默认。这里刻意选择容错:运维手改库改歪了,
		// 不该让整台服务器拒绝所有登录。
		s := newTestStore(t)
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO app_settings(key,value) VALUES(?,'notanumber')
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			settingRateDefaultUploadBPS); err != nil {
			t.Fatalf("写坏值: %v", err)
		}
		got, err := s.GetRateDefaults(ctx)
		if err != nil {
			t.Fatalf("GetRateDefaults: %v", err)
		}
		if got.UploadBPS != 0 {
			t.Fatalf("UploadBPS=%d,解不出来时应当按 0(不限)处理", got.UploadBPS)
		}
	})

	t.Run("库关掉之后读写都报错", func(t *testing.T) {
		dead := newDeadStore(t)
		if _, err := dead.GetRateDefaults(ctx); err == nil {
			t.Fatal("库已关闭却读成功")
		}
		if err := dead.SetRateDefaults(ctx, good); err == nil {
			t.Fatal("库已关闭却写成功")
		}
	})

	t.Run("CLI 原始写入的校验与运行期口径一致", func(t *testing.T) {
		for _, v := range []string{"", "abc", " 42 ", "42x", "-1"} {
			if err := ValidateNonNegativeInt64Setting(v); err == nil {
				t.Fatalf("%q 应被拒 —— 读路径 ParseInt 同样不 trim,放行了就会被静默当 0", v)
			}
		}
		if err := ValidateNonNegativeInt64Setting("0"); err != nil {
			t.Fatalf("0 应当合法: %v", err)
		}
		for _, v := range []string{"abc", " 4096 ", fmt.Sprint(RateBurstBytesMin - 1), fmt.Sprint(RateBurstBytesMax + 1)} {
			if err := ValidateRateBurstSetting(v); err == nil {
				t.Fatalf("burst %q 应被拒", v)
			}
		}
		for _, v := range []string{"0", fmt.Sprint(RateBurstBytesMin), fmt.Sprint(RateBurstBytesMax)} {
			if err := ValidateRateBurstSetting(v); err != nil {
				t.Fatalf("burst %q 应当合法: %v", v, err)
			}
		}
	})
}

// ---------- audit ----------

func TestAudit_NeverPretendsToHaveWritten(t *testing.T) {
	// 审计是「事后唯一的证据」。调用方普遍写成 `_ = st.Audit(...)`,所以这里唯一的
	// 防线就是:真写不进去时必须返回错误,让上层至少能打一条 warn。
	ctx := t.Context()
	s := newTestStore(t)

	t.Run("缺 actor/action 直接拒", func(t *testing.T) {
		if err := s.Audit(ctx, "", "login.success", "t", ""); err == nil {
			t.Fatal("空 actor 应被拒 —— 一条不知道是谁干的审计等于没有")
		}
		if err := s.Audit(ctx, "admin", "", "t", ""); err == nil {
			t.Fatal("空 action 应被拒")
		}
	})

	t.Run("nil store 上不 panic", func(t *testing.T) {
		var nilStore *Store
		if err := nilStore.Audit(ctx, "a", "b", "c", ""); err == nil {
			t.Fatal("nil store 应当返回错误")
		}
		if _, err := nilStore.PruneAuditBefore(ctx, 0); err == nil {
			t.Fatal("nil store 应当返回错误")
		}
		if _, err := nilStore.CountAudit(ctx); err == nil {
			t.Fatal("nil store 应当返回错误")
		}
	})

	t.Run("按时间与 action 过滤", func(t *testing.T) {
		s := newTestStore(t)
		for i, act := range []string{"login.success", "login.fail.bad_psk", "user_create"} {
			if _, err := s.db.ExecContext(ctx,
				`INSERT INTO audit_logs(actor, action, target, detail, at) VALUES('a',?,'t','',?)`,
				act, 1000+int64(i)); err != nil {
				t.Fatalf("插入: %v", err)
			}
		}
		got, err := s.QueryAudit(ctx, 1000, 1002, 0)
		if err != nil {
			t.Fatalf("QueryAudit: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("区间 [1000,1002) 拿到 %d 条,想要 2 条(右开)", len(got))
		}
		byAction, err := s.QueryAuditByAction(ctx, 0, 9999, "user_create", 0)
		if err != nil {
			t.Fatalf("QueryAuditByAction: %v", err)
		}
		if len(byAction) != 1 || byAction[0].Action != "user_create" {
			t.Fatalf("按 action 过滤拿到 %+v —— 过滤没下推到 SQL 时会出现「先取 N 条再过滤剩 0 条」", byAction)
		}
		n, err := s.CountAudit(ctx)
		if err != nil || n != 3 {
			t.Fatalf("CountAudit=%d err=%v", n, err)
		}
		deleted, err := s.PruneAuditBefore(ctx, 1002)
		if err != nil {
			t.Fatalf("PruneAuditBefore: %v", err)
		}
		if deleted != 2 {
			t.Fatalf("截掉 %d 条,想要 2 条", deleted)
		}
	})

	t.Run("坏行让查询整体报错而不是少一条", func(t *testing.T) {
		// 审计少一条就是「查不到那次操作」。宁可整次查询报错让运维知道库有问题,
		// 也不能返回一份看起来完整、实际缺了关键几行的清单。
		s := newTestStore(t)
		ctx := t.Context()
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO audit_logs(actor, action, target, detail, at) VALUES('a','user_delete','t','',1000.5)`); err != nil {
			t.Fatalf("插坏行: %v", err)
		}
		if out, err := s.QueryAudit(ctx, 0, 9999, 10); err == nil {
			t.Fatalf("读到坏行却返回 %d 条和 nil", len(out))
		}
		if out, err := s.QueryAuditByAction(ctx, 0, 9999, "user_delete", 10); err == nil {
			t.Fatalf("按 action 查读到坏行却返回 %d 条和 nil", len(out))
		}
	})

	t.Run("库关掉之后一律报错", func(t *testing.T) {
		dead := newDeadStore(t)
		ops := map[string]func() error{
			"Audit":            func() error { return dead.Audit(ctx, "a", "b", "c", "") },
			"PruneAuditBefore": func() error { _, err := dead.PruneAuditBefore(ctx, 1); return err },
			"CountAudit":       func() error { _, err := dead.CountAudit(ctx); return err },
			"QueryAudit":       func() error { _, err := dead.QueryAudit(ctx, 0, 1, 10); return err },
			"QueryAuditByAction": func() error {
				_, err := dead.QueryAuditByAction(ctx, 0, 1, "x", 10)
				return err
			},
		}
		for name, run := range ops {
			t.Run(name, func(t *testing.T) {
				if err := run(); err == nil {
					t.Fatal("库已关闭却报成功")
				}
			})
		}
	})
}

// ---------- port_forwards ----------

func TestPortForwards_GuardsAndFailureVisibility(t *testing.T) {
	ctx := t.Context()
	s := newTestStore(t)
	valid := PortForward{PublicPort: 20001, Proto: "tcp", TargetDeviceUUID: "uuid-pf",
		TargetIP: "10.9.0.1", TargetPort: 80, Enabled: true}

	t.Run("入参守卫", func(t *testing.T) {
		bad := []struct {
			name string
			pf   PortForward
		}{
			{"udp 还没支持", PortForward{PublicPort: 1, Proto: "udp", TargetDeviceUUID: "u", TargetIP: "1.1.1.1", TargetPort: 1}},
			{"公网端口为 0", PortForward{PublicPort: 0, TargetDeviceUUID: "u", TargetIP: "1.1.1.1", TargetPort: 1}},
			{"公网端口超界", PortForward{PublicPort: 65536, TargetDeviceUUID: "u", TargetIP: "1.1.1.1", TargetPort: 1}},
			{"目标端口为 0", PortForward{PublicPort: 1, TargetDeviceUUID: "u", TargetIP: "1.1.1.1", TargetPort: 0}},
			{"目标端口超界", PortForward{PublicPort: 1, TargetDeviceUUID: "u", TargetIP: "1.1.1.1", TargetPort: 65536}},
			{"没有目标设备", PortForward{PublicPort: 1, TargetIP: "1.1.1.1", TargetPort: 1}},
			{"没有目标地址", PortForward{PublicPort: 1, TargetDeviceUUID: "u", TargetPort: 1}},
		}
		for _, tc := range bad {
			t.Run(tc.name, func(t *testing.T) {
				if got, err := s.CreatePortForward(ctx, tc.pf); err == nil {
					t.Fatalf("应被拒却建成了 %+v —— 监听器起不来的规则留在库里,"+
						"管理员在界面上看到「已启用」但外面连不进来", got)
				}
			})
		}
	})

	t.Run("公网端口撞车归一成 ErrDuplicate", func(t *testing.T) {
		if _, err := s.CreatePortForward(ctx, valid); err != nil {
			t.Fatalf("CreatePortForward: %v", err)
		}
		dup := valid
		dup.TargetIP = "10.9.0.2"
		if _, err := s.CreatePortForward(ctx, dup); !errors.Is(err, ErrDuplicate) {
			t.Fatalf("err=%v,想要 ErrDuplicate —— 界面要提示「该端口已被占用」而不是「内部错误」", err)
		}
	})

	t.Run("行不存在时报 ErrNotFound", func(t *testing.T) {
		if _, err := s.GetPortForward(ctx, 987654); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err=%v,想要 ErrNotFound", err)
		}
		if err := s.DeletePortForward(ctx, 987654); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err=%v,想要 ErrNotFound", err)
		}
		if err := s.SetPortForwardEnabled(ctx, 987654, true); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err=%v,想要 ErrNotFound —— 静默成功会让管理员以为已经停用了这条转发", err)
		}
	})

	t.Run("坏行不会被当成一条正常规则", func(t *testing.T) {
		// enabled 列被读歪 = 一条本该停用的转发被启动,外网直接进来。
		s := newTestStore(t)
		ctx := t.Context()
		created, err := s.CreatePortForward(ctx, valid)
		if err != nil {
			t.Fatalf("CreatePortForward: %v", err)
		}
		if _, err := s.db.ExecContext(ctx,
			`UPDATE port_forwards SET created_at='这不是时间戳' WHERE id=?`, created.ID); err != nil {
			t.Fatalf("弄坏行: %v", err)
		}
		if _, err := s.GetPortForward(ctx, created.ID); err == nil {
			t.Fatal("坏行被当成正常规则返回了")
		} else if errors.Is(err, ErrNotFound) {
			t.Fatalf("坏行被归一成 ErrNotFound: %v", err)
		}
		if out, err := s.ListPortForwards(ctx); err == nil {
			t.Fatalf("列表读到坏行却返回 %d 条和 nil", len(out))
		}
		if out, err := s.ListEnabledPortForwards(ctx); err == nil {
			t.Fatalf("启用列表读到坏行却返回 %d 条和 nil —— 监听器会按一份不完整的清单启停", len(out))
		}
	})

	t.Run("库关掉之后一律报错", func(t *testing.T) {
		dead := newDeadStore(t)
		ops := map[string]func() error{
			"CreatePortForward":      func() error { _, err := dead.CreatePortForward(ctx, valid); return err },
			"GetPortForward":         func() error { _, err := dead.GetPortForward(ctx, 1); return err },
			"DeletePortForward":      func() error { return dead.DeletePortForward(ctx, 1) },
			"SetPortForwardEnabled":  func() error { return dead.SetPortForwardEnabled(ctx, 1, true) },
			"ListPortForwards":       func() error { _, err := dead.ListPortForwards(ctx); return err },
			"ListEnabledPortForward": func() error { _, err := dead.ListEnabledPortForwards(ctx); return err },
		}
		for name, run := range ops {
			t.Run(name, func(t *testing.T) {
				err := run()
				if err == nil {
					t.Fatal("库已关闭却报成功")
				}
				if errors.Is(err, ErrNotFound) {
					t.Fatalf("存储故障被归一成 ErrNotFound: %v", err)
				}
			})
		}
	})
}

// ---------- server_id ----------

func TestServerID_IsStableAndNeverInventedTwice(t *testing.T) {
	ctx := t.Context()

	t.Run("nil store 上不 panic", func(t *testing.T) {
		var nilStore *Store
		if _, err := nilStore.GetOrInitServerID(ctx); err == nil {
			t.Fatal("nil store 应当返回错误")
		}
		if _, err := nilStore.ensureServerID(ctx); err == nil {
			t.Fatal("nil store 应当返回错误")
		}
		if _, err := nilStore.GetServerID(ctx); err == nil {
			t.Fatal("nil store 应当返回错误")
		}
	})

	t.Run("迁移已经写好且反复读取不变", func(t *testing.T) {
		s := newTestStore(t)
		first, err := s.GetOrInitServerID(ctx)
		if err != nil {
			t.Fatalf("GetOrInitServerID: %v", err)
		}
		if len(first) != 36 {
			t.Fatalf("server_id=%q,期望 36 位 UUID", first)
		}
		second, err := s.GetOrInitServerID(ctx)
		if err != nil {
			t.Fatalf("再读: %v", err)
		}
		if second != first {
			t.Fatalf("两次读到 %q / %q —— 客户端按 server_id 去重,变了就会把同一台服务器当成两台",
				first, second)
		}
		ro, err := s.GetServerID(ctx)
		if err != nil {
			t.Fatalf("GetServerID: %v", err)
		}
		if ro != first {
			t.Fatalf("只读版拿到 %q,写版拿到 %q", ro, first)
		}
	})

	t.Run("空值会被救回来", func(t *testing.T) {
		s := newTestStore(t)
		if _, err := s.db.ExecContext(ctx,
			`UPDATE app_settings SET value='' WHERE key=?`, ServerIDKey); err != nil {
			t.Fatalf("清空: %v", err)
		}
		got, err := s.GetOrInitServerID(ctx)
		if err != nil {
			t.Fatalf("GetOrInitServerID: %v", err)
		}
		if got == "" {
			t.Fatal("空值没被救回来 —— 之后每张 QR 都缺 server_id,客户端无法去重")
		}
	})

	t.Run("救空值写不进去时报错", func(t *testing.T) {
		s := newTestStore(t)
		if _, err := s.db.ExecContext(ctx,
			`UPDATE app_settings SET value='' WHERE key=?`, ServerIDKey); err != nil {
			t.Fatalf("清空: %v", err)
		}
		abortOnWhen(t, s, "app_settings", "UPDATE OF value",
			fmt.Sprintf("NEW.key = '%s'", ServerIDKey))
		if _, err := s.ensureServerID(ctx); err == nil {
			t.Fatal("救空值失败却报成功")
		}
	})

	t.Run("只读库上缺 server_id 时软降级", func(t *testing.T) {
		// 只读连接写不进去。这里刻意不报错:profile show 仍然要能出 QR,
		// 只是这一张缺 server_id 字段。报错会让整个导出流程失败,代价更大。
		s, path := newStoreFileWithoutServerID(t)
		_ = s
		ro, err := Open(ctx, path, Options{ReadOnly: true})
		if err != nil {
			t.Fatalf("Open ro: %v", err)
		}
		t.Cleanup(func() { _ = ro.Close() })

		got, err := ro.GetOrInitServerID(ctx)
		if err != nil {
			t.Fatalf("只读库上应当软降级而不是报错: %v", err)
		}
		if got != "" {
			t.Fatalf("只读库上竟然拿到了 %q", got)
		}
		// 只读版同样不该报错,只是返回空。
		if v, err := ro.GetServerID(ctx); err != nil || v != "" {
			t.Fatalf("GetServerID=%q err=%v", v, err)
		}
	})

	t.Run("库关掉之后一律报错", func(t *testing.T) {
		dead := newDeadStore(t)
		if _, err := dead.GetOrInitServerID(ctx); err == nil {
			t.Fatal("库已关闭却读成功 —— 真·读故障不能伪装成「这次没有 server_id」")
		}
		if _, err := dead.ensureServerID(ctx); err == nil {
			t.Fatal("库已关闭却写成功")
		}
		if _, err := dead.GetServerID(ctx); err == nil {
			t.Fatal("库已关闭却读成功")
		}
	})
}

// newStoreFileWithoutServerID 造一个「跑过迁移但 server_id 行被删掉」的库文件,
// 模拟极端情况:管理员在只读连接上、库里还没有 server_id 时调 profile show。
func newStoreFileWithoutServerID(t *testing.T) (*Store, string) {
	t.Helper()
	ctx := t.Context()
	s := newTestStore(t)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM app_settings WHERE key=?`, ServerIDKey); err != nil {
		t.Fatalf("删 server_id: %v", err)
	}
	path := s.path
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return s, path
}
