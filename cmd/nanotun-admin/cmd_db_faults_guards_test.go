package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 这一批盯的是「读库中途失败」这类分支。它们平时不走,但真出事时(磁盘坏道、
// 迁移半途、外部工具改坏库)必须**明确报错并非零退出**,而不是把空结果当成
// 「没有这条数据」继续往下走 —— 后者会让运维照着空列表做决策。
//
// 注入手法:
//   - dropTable          删表 → 后续查询报 "no such table";
//   - relaxAppSettingsValue + NULL → SettingsGet 往 string 扫报错(模拟真·读故障);
//   - abortWritesOn      触发器 RAISE(ABORT) → 写失败。
//
// app_settings 不能整表删:runWithStore 的 mustExist 闸口靠它判定「库是否 init 过」,
// 删了会在打开阶段就 exit 2,压根走不到被测代码。

func dropTable(t *testing.T, db string, tables ...string) {
	t.Helper()
	stmts := make([]string, 0, len(tables)+2)
	// 关掉外键再删,免得被引用关系挡住(我们要的是「表没了」这个效果本身)。
	stmts = append(stmts, `PRAGMA foreign_keys = OFF`)
	for _, tb := range tables {
		stmts = append(stmts, `DROP TABLE IF EXISTS `+tb)
	}
	aclExec(t, db, stmts...)
}

// =========================================================================
// device list
// =========================================================================

func TestCmdDeviceList_ReadFailuresAreLoud(t *testing.T) {
	t.Run("全量列表读不出来要报错,不能打空表", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "dl1.db")
		dropTable(t, db, "devices")
		code, stdout, stderr := runCLI(t, db, "", "device", "list")
		if code == 0 {
			t.Fatalf("读失败却 exit 0,stdout=%q", stdout)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("非零退出但 stderr 空白,运维不知道发生了什么")
		}
	})

	t.Run("按用户过滤时读不出来也要报错", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "dl2.db")
		if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
			t.Fatalf("建用户: %s", e)
		}
		dropTable(t, db, "devices")
		if code, _, _ := runCLI(t, db, "", "device", "list", "--user", "alice"); code == 0 {
			t.Fatal("读失败却 exit 0 —— 会被当成「这个用户没有设备」")
		}
	})

	// --effective 要叠加全局默认限速。这一层读失败**不该**让整条命令失败:
	// 列表本身仍有价值,只是算不出最终生效值 —— 但必须 warn,否则运维会把 raw 值
	// 当成生效值看。
	t.Run("全局默认读不出来只告警,列表照出", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "dl3.db")
		if c, _, e := runCLI(t, db, "", "user", "create", "bob", "--psk", "psk-bob-12345"); c != 0 {
			t.Fatalf("建用户: %s", e)
		}
		setSettingValueNull(t, db, "rate_default_upload_bps")
		code, _, stderr := runCLI(t, db, "", "device", "list", "--effective")
		if code != 0 {
			t.Fatalf("算不出生效值不该让列表失败, code=%d stderr=%q", code, stderr)
		}
		// 必须钉住是**这一层**的告警。这条路上还有一条「读 server /status 失败」的
		// 告警(测试环境没有 control socket,它总会出现),只断言 stderr 非空的话,
		// settings 那条被整段删掉也照样过。
		if !strings.Contains(stderr, "settings") {
			t.Errorf("降级成 raw 值却没说是读 settings 失败 —— 运维会误把 raw 当生效值: %q", stderr)
		}
	})
}

// =========================================================================
// device create:平台归一的兜底
// =========================================================================

func TestCmdDeviceCreate_EmptyPlatformFallsBackToLinux(t *testing.T) {
	// 显式传空串(脚本里 `--platform "$PLAT"` 而 PLAT 未设时的常见形态)必须落到
	// 一个**具体**平台。留空会让下游 exit designate 的平台闸口拒掉这台预创建设备,
	// 而报错信息指向平台不支持,完全指不回这次 create。
	db := newInitializedDB(t, t.TempDir(), "dc.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "carol", "--psk", "psk-carol-1234"); c != 0 {
		t.Fatalf("建用户: %s", e)
	}
	code, stdout, stderr := runCLI(t, db, "", "device", "create", "carol",
		"--uuid", "11111111-2222-4333-8444-555555555555", "--platform", "")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "linux") {
		t.Errorf("空平台没回落 linux: %q", stdout)
	}
}

// =========================================================================
// 固定 vIP:冲突预检的错误路径与 --force
// =========================================================================

func TestFindFixedVIPConflict_ErrorsAreWrapped(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "fx.db")
	opts := &globalOpts{lang: langZH, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}

	t.Run("candidate 不是合法 IP", func(t *testing.T) {
		st := openStoreForTest(t, db)
		defer st.Close()
		if _, err := findFixedVIPConflict(t.Context(), st, opts, "10.0.0.999", 0); err == nil {
			t.Fatal("非法 IP 应报错 —— 否则会被当成「没冲突」而写进库")
		}
	})

	t.Run("空 candidate 直接放行", func(t *testing.T) {
		// 清除 fixed-vip 用的就是空串,不该被冲突检查拦下。
		st := openStoreForTest(t, db)
		defer st.Close()
		got, err := findFixedVIPConflict(t.Context(), st, opts, "", 1)
		if err != nil || got != "" {
			t.Fatalf("got=(%q,%v),期望空串 + nil", got, err)
		}
	})

	t.Run("设备表读不出来必须报错而不是「无冲突」", func(t *testing.T) {
		// 这条最关键:返回 ("", nil) 会被调用方当成「没人占用」,于是把已被占用的
		// vIP 钉给第二台设备,两台机器抢同一个地址。
		bad := newInitializedDB(t, t.TempDir(), "fx-bad.db")
		dropTable(t, bad, "devices")
		st := openStoreForTest(t, bad)
		defer st.Close()
		if _, err := findFixedVIPConflict(t.Context(), st, opts, "10.80.0.9", 0); err == nil {
			t.Fatal("列设备失败却报「无冲突」")
		}
	})

	t.Run("租约表读不出来同样报错", func(t *testing.T) {
		bad := newInitializedDB(t, t.TempDir(), "fx-lease.db")
		// 造一台**别的**设备,让循环真的走到 GetLeaseByDevice 那一步。
		seedExitDevice(t, bad, "dave", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
		dropTable(t, bad, "leases")
		st := openStoreForTest(t, bad)
		defer st.Close()
		if _, err := findFixedVIPConflict(t.Context(), st, opts, "10.80.0.9", 0); err == nil {
			t.Fatal("读租约失败却报「无冲突」")
		}
	})
}

func TestCmdDeviceSetFixedVIP_ForceOverridesConflicts(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "fv.db")
	d1 := seedExitDevice(t, db, "eve", "11111111-1111-4111-8111-111111111111")
	d2 := seedExitDevice(t, db, "frank", "22222222-2222-4222-8222-222222222222")

	// 先给 d1 钉一对 v4/v6。
	if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(d1),
		"--v4", "10.201.0.5", "--v6", "fd00:201::5"); c != 0 {
		t.Fatalf("给 d1 钉 vIP: %s", e)
	}

	// d2 抢同一对地址:默认必须拒(两台机器同址 = 数据面随机丢包,极难查)。
	for _, tc := range []struct{ flag, val string }{
		{"--v4", "10.201.0.5"},
		{"--v6", "fd00:201::5"},
	} {
		if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(d2), tc.flag, tc.val); c == 0 {
			t.Fatalf("%s 撞了 d1 却成功了", tc.flag)
		} else if !strings.Contains(e, tc.val) {
			t.Errorf("报错没回显撞的地址: %q", e)
		}
	}

	// --force 只越过**预检**,不越过 store 层 devices.fixed_vip_* 的 UNIQUE 索引:
	// 两台设备钉同一个地址是绝对不该落库的(下次登录双分配 → 黑洞),所以这条最终
	// 仍然失败。但告警必须先打出来 —— 运维得知道自己撞的是谁。
	for _, tc := range []struct{ flag, val string }{
		{"--v4", "10.201.0.5"},
		{"--v6", "fd00:201::5"},
	} {
		c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(d2), tc.flag, tc.val, "--force")
		if c == 0 {
			t.Fatalf("--force %s 把两台设备钉到了同一个 vIP —— UNIQUE 兜底没了", tc.flag)
		}
		if !strings.Contains(e, "WARN") || !strings.Contains(e, tc.val) {
			t.Errorf("--force %s 撞库前没先告警撞的是谁: %q", tc.flag, e)
		}
	}

	// 真正需要 --force 的场景是撞**租约**(从池里临时分出去的地址):UNIQUE 管不到
	// devices↔leases,所以这里 --force 才是有效的逃生口 —— 常用于「把设备现在正用的
	// 动态地址钉死」的邻居机器换手。
	t.Run("撞租约时 --force 是有效的逃生口", func(t *testing.T) {
		st := openStoreForTest(t, db)
		if _, err := st.UpsertLease(t.Context(), d1, "10.201.0.90", "fd00:201::90", false); err != nil {
			st.Close()
			t.Fatalf("给 d1 造租约: %v", err)
		}
		st.Close()

		for _, tc := range []struct{ flag, val string }{
			{"--v4", "10.201.0.90"},
			{"--v6", "fd00:201::90"},
		} {
			if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(d2), tc.flag, tc.val); c == 0 {
				t.Fatalf("%s 撞了 d1 的租约却直接放行了", tc.flag)
			} else if !strings.Contains(e, tc.val) {
				t.Errorf("报错没回显撞的地址: %q", e)
			}
			c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(d2), tc.flag, tc.val, "--force")
			if c != 0 {
				t.Fatalf("--force %s 应放行(撞的只是租约), code=%d stderr=%q", tc.flag, c, e)
			}
			if !strings.Contains(e, "WARN") {
				t.Errorf("--force %s 抢了别人正在用的地址却一声不吭: %q", tc.flag, e)
			}
		}
	})
}

// mesh 网段快照是 server 启动时落库的字符串。它可能是空、是老格式、是被人手改坏的
// 垃圾 —— 任何一种都只该让「越界提示」这个**附加**功能静默失效,不能影响钉地址本身。
func TestWarnFixedVIPOutOfMesh_ToleratesBrokenSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name string
		snap string
	}{
		{"整段是垃圾", "not-a-cidr"},
		{"逗号分隔的垃圾", "garbage, 10.0.0.0/8/9, ???"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newInitializedDB(t, t.TempDir(), "mesh.db")
			id := seedExitDevice(t, db, "grace", "33333333-3333-4333-8333-333333333333")
			aclExec(t, db, `INSERT INTO app_settings(key, value) VALUES ('`+store.MeshCIDRsKey+`', '`+tc.snap+`') `+
				`ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
			code, _, stderr := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(id), "--v4", "10.99.0.5")
			if code != 0 {
				t.Fatalf("快照坏了不该影响钉地址, code=%d stderr=%q", code, stderr)
			}
			// 解析不出任何网段就无从判断越界,不该硬造一条告警出来。
			if strings.Contains(stderr, "10.99.0.5") && strings.Contains(stderr, tc.snap) {
				t.Errorf("拿坏快照当依据发了越界告警: %q", stderr)
			}
		})
	}

	t.Run("快照读故障也不阻塞", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "mesh2.db")
		id := seedExitDevice(t, db, "heidi", "44444444-4444-4444-8444-444444444444")
		setSettingValueNull(t, db, store.MeshCIDRsKey)
		if code, _, stderr := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(id), "--v4", "10.99.0.5"); code != 0 {
			t.Fatalf("读快照失败不该让钉地址失败, code=%d stderr=%q", code, stderr)
		}
	})
}

// ipv4DirectedBroadcastPrefix 是 nanotund 侧同名函数的 CLI 副本,两份必须同语义:
// 判错会把网络里**能用**的地址标成 broadcast(或反过来把广播地址分给客户端)。
func TestIPv4DirectedBroadcastPrefix_FamilyAndMaskGates(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		wantOK bool
		want   string
	}{
		{"10.201.0.0/16", true, "10.201.255.255"},
		{"192.168.1.0/24", true, "192.168.1.255"},
		{"10.0.0.0/30", true, "10.0.0.3"},
		// RFC 3021:/31 与 /32 没有广播概念。
		{"10.0.0.0/31", false, ""},
		{"10.0.0.1/32", false, ""},
		// IPv6 压根没有广播。
		{"fd00::/64", false, ""},
		{"::/0", false, ""},
	} {
		p, err := netip.ParsePrefix(tc.prefix)
		if err != nil {
			t.Fatalf("ParsePrefix(%s): %v", tc.prefix, err)
		}
		got, ok := ipv4DirectedBroadcastPrefix(p)
		if ok != tc.wantOK {
			t.Errorf("%s: ok=%v, 期望 %v", tc.prefix, ok, tc.wantOK)
			continue
		}
		if ok && got.String() != tc.want {
			t.Errorf("%s: 广播地址=%s, 期望 %s", tc.prefix, got, tc.want)
		}
	}
}

// =========================================================================
// route
// =========================================================================

func TestCmdRouteList_ReadFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "rl.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "ivan", "--psk", "psk-ivan-12345"); c != 0 {
		t.Fatalf("建用户: %s", e)
	}
	dropTable(t, db, "devices")
	// --user 过滤要先把该用户的设备列出来。列不出来就无法判断哪些路由属于他,
	// 空结果会被当成「这个用户没宣告任何路由」。
	if code, stdout, _ := runCLI(t, db, "", "route", "list", "--user", "ivan"); code == 0 {
		t.Fatalf("读设备失败却 exit 0, stdout=%q", stdout)
	}
}

func TestCmdRouteApprove_PreflightReadFailures(t *testing.T) {
	t.Run("mesh 网段读故障时拒绝批准", func(t *testing.T) {
		// 批准具体子网前要排除与 server mesh 网段交叠(交叠会把发往离线 mesh 地址的包
		// 中继进宣告方 LAN)。判据读不出来时必须**拒**:放行等于把跨信任域泄漏的可能性
		// 交给运气。
		db := newInitializedDB(t, t.TempDir(), "ra.db")
		id := seedExitDevice(t, db, "judy", "55555555-5555-4555-8555-555555555555")
		setSettingValueNull(t, db, store.MeshCIDRsKey)
		code, _, stderr := runCLI(t, db, "", "route", "approve", fmt.Sprint(id), "192.168.77.0/24")
		if code == 0 {
			t.Fatal("读不出 mesh 网段却照批 —— 交叠检查形同虚设")
		}
		if !strings.Contains(stderr, "mesh") {
			t.Errorf("报错没说清是哪一步失败: %q", stderr)
		}
	})

	t.Run("批准出口默认路由时 owner 读故障要拒绝", func(t *testing.T) {
		// 0/0 的平台闸口 + owner 禁用检查是 fail-closed 的:读不到 owner 就不许批。
		db := newInitializedDB(t, t.TempDir(), "ra2.db")
		id := seedExitDevice(t, db, "ken", "66666666-6666-4666-8666-666666666666")
		dropTable(t, db, "users")
		code, _, stderr := runCLI(t, db, "", "route", "approve", fmt.Sprint(id), "0.0.0.0/0")
		if code == 0 {
			t.Fatal("读不到设备主人却照批出口 —— 禁用用户的死出口会挂进所有客户端")
		}
		if !strings.Contains(strings.ToLower(stderr), "owner") && !strings.Contains(stderr, "users") {
			t.Errorf("报错没指向 owner 这一步: %q", stderr)
		}
	})
}

// =========================================================================
// exit designate
// =========================================================================

func TestCmdExitDesignate_ReadAndWriteFailures(t *testing.T) {
	t.Run("owner 读故障 → 拒绝指派", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "ed1.db")
		id := seedExitDevice(t, db, "leo", "77777777-7777-4777-8777-777777777777")
		dropTable(t, db, "users")
		if code, _, stderr := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id)); code == 0 {
			t.Fatalf("读不到 owner 却指派成功了, stderr=%q", stderr)
		}
	})

	// 出口 = 批准 0/0 与 ::/0 两条路由 + 钉 vIP。这两步是**分开**的两次写(先 upsert
	// 出 pending 行,再置 approved),任一步失败都必须明确失败 —— 否则会留下
	// 「路由行在、状态还是 pending」或「只批了 v4」这类一半的出口:`exit list` 看不到它,
	// 而运维手里那条命令报的是成功。
	t.Run("宣告路由写失败 → 报错", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "ed2.db")
		id := seedExitDevice(t, db, "mallory", "88888888-8888-4888-8888-888888888888")
		abortWritesOn(t, db, "subnet_routes", "INSERT")
		code, _, stderr := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id))
		if code == 0 {
			t.Fatal("写失败却 exit 0")
		}
		if !strings.Contains(stderr, "route") {
			t.Errorf("报错没说清是批路由那步挂了: %q", stderr)
		}
	})

	t.Run("置 approved 写失败 → 报错且不留 pending 残行", func(t *testing.T) {
		// 只挡 UPDATE:upsert 出 pending 行这步照常成功,失败发生在「置 approved」那步。
		// 这条与上面一条走的是**不同**的两个 return,得分开验。
		db := newInitializedDB(t, t.TempDir(), "ed2b.db")
		id := seedExitDevice(t, db, "mallory2", "89898989-8989-4989-8989-898989898989")
		abortWritesOn(t, db, "subnet_routes", "UPDATE")
		code, _, stderr := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id))
		if code == 0 {
			t.Fatal("置 approved 失败却 exit 0 —— 会留下一条永远 pending 的出口路由")
		}
		if !strings.Contains(stderr, "route") {
			t.Errorf("报错没说清是哪一步: %q", stderr)
		}
		// 设备也不该被当成出口:半完成态里最坏的一种是「路由 pending、fixed vIP 已钉」。
		st := openStoreForTest(t, db)
		defer st.Close()
		rows, err := st.ListRoutesByDevice(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Status == "approved" {
				t.Errorf("写被挡下了却出现了 approved 行: %+v", r)
			}
		}
	})

	t.Run("--v6 auto 时从现有租约取地址", func(t *testing.T) {
		// designate 默认把设备**当前租约**焊成固定 vIP:重启 server 后出口地址不变,
		// 客户端侧的 exit 选择才稳定。v6 这一半此前没测过。
		db := newInitializedDB(t, t.TempDir(), "ed3.db")
		id := seedExitDevice(t, db, "nina", "99999999-9999-4999-8999-999999999999")
		st := openStoreForTest(t, db)
		if _, err := st.UpsertLease(t.Context(), id, "10.201.0.77", "fd00:201::77", false); err != nil {
			st.Close()
			t.Fatalf("UpsertLease: %v", err)
		}
		st.Close()

		code, stdout, stderr := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id))
		if code != 0 {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
		if !strings.Contains(stdout+stderr, "fd00:201::77") {
			t.Errorf("v6 租约没被焊成固定 vIP: stdout=%q stderr=%q", stdout, stderr)
		}
		st2 := openStoreForTest(t, db)
		defer st2.Close()
		d, err := st2.GetDevice(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if d.FixedVIPv6 != "fd00:201::77" {
			t.Errorf("库里 fixed_vip_v6=%q, 期望 fd00:201::77", d.FixedVIPv6)
		}
	})
}
