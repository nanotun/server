package main

// cmd_exit_route_guards_test.go(第二十二轮)—— `exit` 与 `route` 两组子命令的拒绝面。
//
// 这两组管的是「谁能替别人转发流量」,错一次的后果是跨信任域的流量泄漏或静默黑洞,
// 而且都不会在命令输出里表现出来:
//   - exit designate 是多次独立写事务(批路由 / 钉 vIP),半途失败会留下「已批准为出口但
//     vIP 没钉上」的残状态 —— 第九、十轮把所有确定性校验前移就是为了这个,这里要钉住
//     「拒绝时一条批准行都不许留下」;
//   - route approve 批的是别人宣告的网段,一旦与 mesh 或与另一台已批准的网段交叠,
//     受影响主机对所有请求方一起失联,而 route list 里两条都是 approved,看不出谁盖了谁。
//
// 所以本组的断言不只看退出码,还回库里查「有没有留下半截状态」。

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// seedExitDevice 建一个 linux 用户设备(平台闸口放行),返回 device_id。
func seedExitDevice(t *testing.T, db, username, uuid string) int64 {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	ctx := t.Context()
	u, err := st.GetUserByUsername(ctx, username)
	if err != nil {
		u, err = st.CreateUser(ctx, openStoreNewUser(username))
		if err != nil {
			t.Fatalf("create user %s: %v", username, err)
		}
	}
	d, err := st.UpsertDevice(ctx, u.ID, uuid, "box-"+username, "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	return d.ID
}

func disableUser(t *testing.T, db, username string) {
	t.Helper()
	if c, _, e := runCLI(t, db, "", "user", "disable", username); c != 0 {
		t.Fatalf("user disable %s: %s", username, e)
	}
}

func routeStatus(t *testing.T, db string, deviceID int64, cidr string) string {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	r, err := st.GetRouteByDeviceCIDR(t.Context(), deviceID, cidr)
	if err != nil {
		return ""
	}
	return r.Status
}

// =========================================================================
// exit:派发与用法
// =========================================================================

func TestCmdExit_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-usage.db")
	id := seedExitDevice(t, db, "eu", "aaaaaaaa-1111-4111-8111-111111111111")
	idStr := fmt.Sprint(id)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"不给子命令", []string{"exit"}},
		{"designate 不给 device", []string{"exit", "designate"}},
		{"designate 给两个 device", []string{"exit", "designate", idStr, idStr}},
		{"designate 未知 flag", []string{"exit", "designate", idStr, "--bogus"}},
		{"designate 的 id 不是数字", []string{"exit", "designate", "第一台"}},
		{"revoke 不给 device", []string{"exit", "revoke"}},
		{"revoke 给两个", []string{"exit", "revoke", idStr, idStr}},
		{"revoke 未知 flag", []string{"exit", "revoke", idStr, "--bogus"}},
		{"revoke 的 id 不是数字", []string{"exit", "revoke", "那一台"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", tc.args...)
			if code != 2 {
				t.Fatalf("用法错误应 exit 2, got %d stderr=%q", code, stderr)
			}
		})
	}

	if code, _, stderr := runCLI(t, db, "", "exit", "promote"); code == 0 {
		t.Fatal("未知子命令 exit promote 竟然成功了")
	} else if !strings.Contains(stderr, "promote") {
		t.Errorf("报错没回显敲错的子命令: %q", stderr)
	}

	// 用法错误一条批准行都不许留。
	if s := routeStatus(t, db, id, util.ExitDefaultRouteV4); s != "" {
		t.Fatalf("被拒的 designate 留下了 0.0.0.0/0 状态=%q", s)
	}
}

// device 不存在时要给本地化的「设备不存在」,不能裸抛 store 英文错误 ——
// 这条路径上 id 打错一位是最常见的手误。
func TestCmdExit_DeviceNotFound(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-404.db")
	for _, sub := range []string{"designate", "revoke"} {
		code, _, stderr := runCLI(t, db, "", "exit", sub, "9999")
		if code != 1 {
			t.Errorf("exit %s 不存在的 device 应 exit 1, got %d", sub, code)
		}
		if !strings.Contains(stderr, "9999") {
			t.Errorf("exit %s 报错没说是哪台: %q", sub, stderr)
		}
	}
}

// 所属用户被禁用的设备连不上 server,批了就是把一个死出口挂进所有客户端的出口下拉。
// 与 web /routes/exit/designate 同口径拦截,--force 是 CLI 专属逃生口。
func TestCmdExitDesignate_OwnerDisabledGate(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-owner.db")
	id := seedExitDevice(t, db, "sleeper", "bbbbbbbb-2222-4222-8222-222222222222")
	disableUser(t, db, "sleeper")
	idStr := fmt.Sprint(id)

	code, _, stderr := runCLI(t, db, "", "exit", "designate", idStr, "--no-vip")
	if code == 0 {
		t.Fatal("禁用用户的设备被批成了出口")
	}
	if !strings.Contains(stderr, "sleeper") {
		t.Errorf("报错没说是哪个用户被禁用: %q", stderr)
	}
	if !strings.Contains(stderr, "--force") {
		t.Errorf("报错应指出 --force 逃生口: %q", stderr)
	}
	if s := routeStatus(t, db, id, util.ExitDefaultRouteV4); s != "" {
		t.Fatalf("被拦下却留了批准行: 状态=%q", s)
	}

	if c, _, e := runCLI(t, db, "", "exit", "designate", idStr, "--no-vip", "--force"); c != 0 {
		t.Fatalf("--force 应放行: %s", e)
	}
	if s := routeStatus(t, db, id, util.ExitDefaultRouteV4); s != util.RouteStatusApproved {
		t.Fatalf("--force 之后 0.0.0.0/0 状态=%q", s)
	}
}

// --v4/--v6 写错族(把 IPv6 填进 --v4)必须当场拒。放过去的后果是 IPv6 被塞进
// fixed_vip_v4 列,分配时静默失效 —— 与 device set-fixed-vip / lease set 同口径。
func TestCmdExitDesignate_AddressFamilyGate(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-family.db")
	id := seedExitDevice(t, db, "famuser", "cccccccc-3333-4333-8333-333333333333")
	idStr := fmt.Sprint(id)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"--v4 收到 IPv6", []string{"--v4", "fd00::1"}},
		{"--v4 不是地址", []string{"--v4", "100.64.0"}},
		{"--v6 收到 IPv4", []string{"--v6", "100.64.0.1"}},
		{"--v6 收到 v4-mapped", []string{"--v6", "::ffff:100.64.0.1"}},
		{"--v6 不是地址", []string{"--v6", "fd00::/64"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"exit", "designate", idStr}, tc.args...)
			code, _, stderr := runCLI(t, db, "", args...)
			if code == 0 {
				t.Fatal("写错族的地址被接受了 —— 分配时会静默失效")
			}
			if strings.TrimSpace(stderr) == "" {
				t.Error("拒了却没说原因")
			}
			// 关键:族校验在任何持久化写入之前,所以不许留下批准行。
			if s := routeStatus(t, db, id, util.ExitDefaultRouteV4); s != "" {
				t.Fatalf("地址非法却已经批准了出口路由: 状态=%q", s)
			}
		})
	}
}

// 显式空串 = 「不动这一族」,不是「清空」。这是 --v4 ""/--v6 "" 与不传的区别所在,
// 也是唯一能把某一族保持原样的写法。
func TestCmdExitDesignate_EmptyStringMeansLeaveFamilyAlone(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-empty.db")
	id := seedExitDevice(t, db, "keepuser", "dddddddd-4444-4444-8444-444444444444")
	idStr := fmt.Sprint(id)

	// 先钉一个 v4,再用空串重跑:v4 必须保持原样(而非被清掉)。
	if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", idStr, "--v4", "100.64.0.21"); c != 0 {
		t.Fatalf("set-fixed-vip: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "exit", "designate", idStr, "--v4", "", "--v6", ""); c != 0 {
		t.Fatalf("designate: %s", e)
	}
	if got := getDevice(t, db, id).FixedVIPv4; got != "100.64.0.21" {
		t.Errorf("--v4 \"\" 应保持原值不动, 实际 %q", got)
	}
}

// vIP 冲突预检必须在**批准路由之前**发生。第九轮修的正是反过来的顺序:先持久化批准、
// 再发现冲突并 exit 1,于是留下「一纸批准焊死进所有客户端下拉,vIP 却没钉上」的半完成态,
// 而命令以失败收场让运维以为什么都没发生。
func TestCmdExitDesignate_VIPConflictFailsBeforeApprovingRoutes(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-conflict.db")
	holder := seedExitDevice(t, db, "holder", "eeeeeeee-5555-4555-8555-555555555555")
	cand := seedExitDevice(t, db, "cand", "ffffffff-6666-4666-8666-666666666666")
	if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(holder),
		"--v4", "100.64.0.31", "--v6", "fd00:200::31"); c != 0 {
		t.Fatalf("给 holder 钉 vIP: %s", e)
	}
	candStr := fmt.Sprint(cand)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"v4 撞上别人的 fixed", []string{"--v4", "100.64.0.31"}, "100.64.0.31"},
		{"v6 撞上别人的 fixed", []string{"--v6", "fd00:200::31"}, "fd00:200::31"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"exit", "designate", candStr}, tc.args...)
			code, _, stderr := runCLI(t, db, "", args...)
			if code == 0 {
				t.Fatal("vIP 冲突却成功了")
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("报错没说撞的是哪个地址: %q", stderr)
			}
			if !strings.Contains(stderr, "--force") {
				t.Errorf("报错应给出 --force 覆盖提示: %q", stderr)
			}
			if s := routeStatus(t, db, cand, util.ExitDefaultRouteV4); s != "" {
				t.Fatalf("冲突预检之前就批准了出口路由(第九轮的半完成态回归): 状态=%q", s)
			}
		})
	}

	// --force 越过冲突检查:此时才允许留下批准 + 钉上 vIP。
	if c, _, e := runCLI(t, db, "", "exit", "designate", candStr, "--v4", "100.64.0.32", "--force"); c != 0 {
		t.Fatalf("--force designate: %s", e)
	}
	if s := routeStatus(t, db, cand, util.ExitDefaultRouteV4); s != util.RouteStatusApproved {
		t.Fatalf("--force 之后应已批准, 状态=%q", s)
	}
}

// 非规范写法的 IPv6(大写、压缩形式不同)必须先规范化再比冲突。否则字符串比较不相等 →
// 预检漏判 → 批准路由之后 SetDeviceFixedVIP 才撞 UNIQUE,重开半完成态。
func TestCmdExitDesignate_NonCanonicalIPv6IsNormalizedBeforeConflictCheck(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-canon.db")
	holder := seedExitDevice(t, db, "holder", "11111111-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	cand := seedExitDevice(t, db, "cand", "22222222-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(holder), "--v6", "fd00:200::41"); c != 0 {
		t.Fatalf("给 holder 钉 v6: %s", e)
	}

	code, _, stderr := runCLI(t, db, "", "exit", "designate", fmt.Sprint(cand), "--v6", "FD00:0200:0000::0041")
	if code == 0 {
		t.Fatal("非规范写法绕过了 v6 冲突预检")
	}
	if s := routeStatus(t, db, cand, util.ExitDefaultRouteV6); s != "" {
		t.Fatalf("漏判冲突并批准了出口路由: 状态=%q", s)
	}
	_ = stderr
}

// 批路由这一步失败时不能报成功:它是整条命令里第一次持久化写入,失败了后面的钉 vIP
// 和审计都不该发生。
func TestCmdExitDesignate_RouteWriteFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-routefail.db")
	id := seedExitDevice(t, db, "rwfail", "33333333-cccc-4ccc-8ccc-cccccccccccc")
	abortWritesOn(t, db, "subnet_routes", "INSERT")

	code, stdout, stderr := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id), "--no-vip")
	if code == 0 {
		t.Fatalf("批路由失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "已指定出口") {
		t.Errorf("批路由失败却打了成功提示: %q", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败却没说原因")
	}
}

// 钉 vIP 这一步失败时同样不能报成功 —— 此时出口路由已经批了(多次独立事务、无法回滚),
// 但命令必须以失败收场,让运维知道要重跑(每步幂等,重跑可收敛)。
func TestCmdExitDesignate_FixedVIPWriteFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-vipfail.db")
	id := seedExitDevice(t, db, "vwfail", "44444444-dddd-4ddd-8ddd-dddddddddddd")
	abortWritesOn(t, db, "devices", "UPDATE")

	code, stdout, _ := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id), "--v4", "100.64.0.71")
	if code == 0 {
		t.Fatalf("钉 vIP 失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "已指定出口") {
		t.Errorf("钉 vIP 失败却打了成功提示: %q", stdout)
	}
	if got := getDevice(t, db, id).FixedVIPv4; got != "" {
		t.Errorf("写被拒了 fixed_vip_v4 却有值: %q", got)
	}
}

// =========================================================================
// exit list
// =========================================================================

// exit list 的表格路径,并确认它只认出口默认路由:一条普通子网路由被批准了也不该
// 让这台设备出现在出口列表里(否则运维会以为自己不小心把谁变成了出口)。
func TestCmdExitList_TableOnlyCountsExitRoutes(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-listtable.db")
	exitDev := seedExitDevice(t, db, "realexit", "55555555-eeee-4eee-8eee-eeeeeeeeeeee")
	subnetDev := seedExitDevice(t, db, "subnetter", "66666666-ffff-4fff-8fff-ffffffffffff")

	if c, _, e := runCLI(t, db, "", "exit", "designate", fmt.Sprint(exitDev), "--v4", "100.64.0.81"); c != 0 {
		t.Fatalf("designate: %s", e)
	}
	// 给另一台批一条普通子网路由(需要先有宣告行)。
	seedApprovedSubnetRoute(t, db, subnetDev, "192.168.77.0/24")

	code, stdout, stderr := runCLI(t, db, "", "exit", "list")
	if code != 0 {
		t.Fatalf("exit list: code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, fmt.Sprint(exitDev)) {
		t.Errorf("真出口不在列表里:\n%s", stdout)
	}
	if !strings.Contains(stdout, "100.64.0.81") {
		t.Errorf("表格没展示固定 vIP:\n%s", stdout)
	}
	if !strings.Contains(stdout, "✓") {
		t.Errorf("表格没用 ✓ 标出已批准的族:\n%s", stdout)
	}
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), fmt.Sprint(subnetDev)+" ") {
			t.Errorf("只批了子网路由的设备出现在出口列表里: %q", line)
		}
	}
}

// seedApprovedSubnetRoute 让某设备宣告并批准一条**非出口**的子网网段。
func seedApprovedSubnetRoute(t *testing.T, db string, deviceID int64, cidr string) {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	ctx := t.Context()
	if _, err := st.UpsertAdvertisedRoute(ctx, deviceID, cidr); err != nil {
		t.Fatalf("upsert route %s: %v", cidr, err)
	}
	if err := st.SetRouteStatus(ctx, deviceID, cidr, util.RouteStatusApproved, ""); err != nil {
		t.Fatalf("approve route %s: %v", cidr, err)
	}
}

// 路由表读不出来时,exit list 必须失败 —— 一张空的出口列表会让运维以为「没有出口」,
// 从而重复 designate 或误判故障。
func TestCmdExitList_QueryFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-listfail.db")
	aclExec(t, db, `ALTER TABLE subnet_routes RENAME TO subnet_routes_gone`)
	code, stdout, _ := runCLI(t, db, "", "exit", "list")
	if code == 0 {
		t.Fatalf("查不到路由表却 exit 0, stdout=%q", stdout)
	}
}

// =========================================================================
// exit revoke
// =========================================================================

// 撤销是危险操作:不带 --yes 时必须先问,答「不」要原样退出且什么都不改。
func TestCmdExitRevoke_ConfirmGuard(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-confirm.db")
	id := seedExitDevice(t, db, "confirmer", "77777777-1111-4111-9111-111111111111")
	idStr := fmt.Sprint(id)
	if c, _, e := runCLI(t, db, "", "exit", "designate", idStr, "--v4", "100.64.0.91"); c != 0 {
		t.Fatalf("designate: %s", e)
	}

	t.Run("答不", func(t *testing.T) {
		code, stdout, stderr := runCLIInteractive(t, db, "n\n", "exit", "revoke", idStr)
		if code != 0 {
			t.Fatalf("取消却以 %d 退出: %s", code, stderr)
		}
		if !strings.Contains(stdout, "取消") {
			t.Errorf("没告诉用户已取消: %q", stdout)
		}
		if s := routeStatus(t, db, id, util.ExitDefaultRouteV4); s != util.RouteStatusApproved {
			t.Fatalf("答了不,出口路由却被删了: 状态=%q", s)
		}
	})

	// 读不到回答(stdin 被关掉 / 非交互环境)按「否」处理并正常退出 —— 保守方向是
	// 「什么都不做」,而不是失败退出去污染上层脚本的错误处理。关键是绝不能当成同意。
	t.Run("stdin 直接 EOF 按否处理", func(t *testing.T) {
		code, stdout, stderr := runCLIInteractive(t, db, "", "exit", "revoke", idStr)
		if code != 0 {
			t.Fatalf("EOF 应按否处理并正常退出, got %d stderr=%s", code, stderr)
		}
		if !strings.Contains(stdout, "取消") {
			t.Errorf("没告诉用户已取消: %q", stdout)
		}
		if s := routeStatus(t, db, id, util.ExitDefaultRouteV4); s != util.RouteStatusApproved {
			t.Fatalf("EOF 却把出口撤了: 状态=%q", s)
		}
	})

	t.Run("答是", func(t *testing.T) {
		code, stdout, stderr := runCLIInteractive(t, db, "y\n", "exit", "revoke", idStr)
		if code != 0 {
			t.Fatalf("revoke: code=%d stderr=%s", code, stderr)
		}
		if !strings.Contains(stdout, "已撤销出口") {
			t.Errorf("stdout 缺成功提示: %q", stdout)
		}
		if s := routeStatus(t, db, id, util.ExitDefaultRouteV4); s != "" {
			t.Fatalf("答了是却没删掉: 状态=%q", s)
		}
		// --clear-vip 没给 → 固定 vIP 保留(基础设施地址不该被顺手清掉)。
		if got := getDevice(t, db, id).FixedVIPv4; got != "100.64.0.91" {
			t.Errorf("没给 --clear-vip 却清了固定 vIP: %q", got)
		}
	})
}

// 本来就没有出口路由的设备,revoke 要幂等成功(ErrNotFound 视作已撤),
// 但删掉的列表必须诚实地是空的。
func TestCmdExitRevoke_IdempotentOnNonExit(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-idem.db")
	id := seedExitDevice(t, db, "plain", "88888888-2222-4222-9222-222222222222")

	code, stdout, stderr := runCLI(t, db, "", "exit", "revoke", fmt.Sprint(id))
	if code != 0 {
		t.Fatalf("对非出口设备 revoke 应幂等成功, code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "[]") {
		t.Errorf("没删掉任何路由时应诚实报空: %q", stdout)
	}
}

// --clear-vip 那一步写失败时不能报成功:出口路由已删、vIP 还在,运维必须知道要重跑。
func TestCmdExitRevoke_ClearVIPWriteFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-clearfail.db")
	id := seedExitDevice(t, db, "cvfail", "99999999-3333-4333-9333-333333333333")
	if c, _, e := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id), "--v4", "100.64.0.95"); c != 0 {
		t.Fatalf("designate: %s", e)
	}
	abortWritesOn(t, db, "devices", "UPDATE")

	code, stdout, _ := runCLI(t, db, "", "exit", "revoke", fmt.Sprint(id), "--clear-vip")
	if code == 0 {
		t.Fatalf("清 vIP 失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "已撤销出口") {
		t.Errorf("清 vIP 失败却打了成功提示: %q", stdout)
	}
	if got := getDevice(t, db, id).FixedVIPv4; got != "100.64.0.95" {
		t.Errorf("写被拒了 vIP 却变了: %q", got)
	}
}

// =========================================================================
// route:派发与用法
// =========================================================================

func TestCmdRoute_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-usage.db")
	id := seedExitDevice(t, db, "ru", "aaaa1111-4444-4444-9444-444444444444")
	idStr := fmt.Sprint(id)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"不给子命令", []string{"route"}},
		{"approve 只给 device", []string{"route", "approve", idStr}},
		{"approve 给三个参数", []string{"route", "approve", idStr, "10.9.0.0/24", "extra"}},
		{"approve 未知 flag", []string{"route", "approve", idStr, "10.9.0.0/24", "--bogus"}},
		{"approve 的 id 不是数字", []string{"route", "approve", "第一台", "10.9.0.0/24"}},
		{"approve 的 cidr 非法", []string{"route", "approve", idStr, "10.9.0.0/33"}},
		{"reject 只给 device", []string{"route", "reject", idStr}},
		{"reject 未知 flag", []string{"route", "reject", idStr, "10.9.0.0/24", "--bogus"}},
		{"delete 只给 device", []string{"route", "delete", idStr}},
		{"delete 的 cidr 非法", []string{"route", "delete", idStr, "不是网段"}},
		{"list 未知 flag", []string{"route", "list", "--bogus"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", tc.args...)
			if code != 2 {
				t.Fatalf("用法错误应 exit 2, got %d stderr=%q", code, stderr)
			}
		})
	}

	if code, _, stderr := runCLI(t, db, "", "route", "revoke", idStr, "10.9.0.0/24"); code == 0 {
		t.Fatal("未知子命令 route revoke 竟然成功了")
	} else if !strings.Contains(stderr, "revoke") {
		t.Errorf("报错没回显敲错的子命令: %q", stderr)
	}
}

// route list 的过滤器:--device / --status / --user 各走不同的查询分支,
// --user 还要按「该用户名下的设备」二次过滤。过滤器错了会让运维看不到待审批的声明。
func TestCmdRouteList_Filters(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-list.db")
	devA := seedExitDevice(t, db, "owner-a", "bbbb2222-5555-4555-9555-555555555555")
	devB := seedExitDevice(t, db, "owner-b", "cccc3333-6666-4666-9666-666666666666")
	seedApprovedSubnetRoute(t, db, devA, "192.168.11.0/24")
	// devB 只宣告不批准 → pending。
	st := openStoreForTest(t, db)
	if _, err := st.UpsertAdvertisedRoute(t.Context(), devB, "192.168.22.0/24"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	_ = st.Close()

	t.Run("--device 只出这台", func(t *testing.T) {
		_, stdout, _ := runCLI(t, db, "", "route", "list", "--device", fmt.Sprint(devA))
		if !strings.Contains(stdout, "192.168.11.0/24") || strings.Contains(stdout, "192.168.22.0/24") {
			t.Errorf("--device 过滤不对:\n%s", stdout)
		}
	})

	t.Run("--status 只出 pending", func(t *testing.T) {
		_, stdout, _ := runCLI(t, db, "", "route", "list", "--status", "pending")
		if !strings.Contains(stdout, "192.168.22.0/24") || strings.Contains(stdout, "192.168.11.0/24") {
			t.Errorf("--status 过滤不对:\n%s", stdout)
		}
	})

	t.Run("--user 只出该用户名下设备的路由", func(t *testing.T) {
		_, stdout, _ := runCLI(t, db, "", "route", "list", "--user", "owner-b")
		if !strings.Contains(stdout, "192.168.22.0/24") || strings.Contains(stdout, "192.168.11.0/24") {
			t.Errorf("--user 过滤不对:\n%s", stdout)
		}
	})

	t.Run("--user 指向不存在的用户", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "route", "list", "--user", "ghost")
		if code == 0 {
			t.Fatal("不存在的用户不该静默返回空列表 —— 那会被当成「该用户没有路由」")
		}
		if !strings.Contains(stderr, "ghost") {
			t.Errorf("报错没说是哪个用户: %q", stderr)
		}
	})

	t.Run("路由表读不出来", func(t *testing.T) {
		bad := newInitializedDB(t, t.TempDir(), "route-listfail.db")
		aclExec(t, bad, `ALTER TABLE subnet_routes RENAME TO subnet_routes_gone`)
		if code, _, _ := runCLI(t, bad, "", "route", "list"); code == 0 {
			t.Fatal("查不到表却 exit 0 —— 空列表会被当成「没有待审批声明」")
		}
	})
}

// =========================================================================
// route approve
// =========================================================================

// approve 一条根本没被宣告过的路由要给本地化的「路由不存在」,而不是静默成功 ——
// 静默成功会让运维以为已经批了,而客户端那边永远等不到。
func TestCmdRouteApprove_NotFound(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-404.db")
	id := seedExitDevice(t, db, "nf", "dddd4444-7777-4777-9777-777777777777")

	code, _, stderr := runCLI(t, db, "", "route", "approve", fmt.Sprint(id), "10.44.0.0/24")
	if code != 1 {
		t.Fatalf("approve 不存在的声明应 exit 1, got %d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "10.44.0.0/24") {
		t.Errorf("报错没说是哪条: %q", stderr)
	}
}

// route approve 0/0 是绕过 exit designate 的旁门,平台闸口与 owner 禁用闸口都要在这里
// 同样生效(第十五轮):漏掉它等于闸口只焊了一半。
func TestCmdRouteApprove_ExitGatesAlsoApplyHere(t *testing.T) {
	t.Run("device 不存在时 fail-closed", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "route-exit-nodev.db")
		code, _, stderr := runCLI(t, db, "", "route", "approve", "4242", util.ExitDefaultRouteV4)
		if code == 0 {
			t.Fatal("查不到设备时必须拒绝,不能放行")
		}
		if !strings.Contains(stderr, "4242") {
			t.Errorf("报错没说是哪台: %q", stderr)
		}
	})

	t.Run("owner 被禁用", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "route-exit-owner.db")
		id := seedExitDevice(t, db, "offuser", "eeee5555-8888-4888-9888-888888888888")
		seedAdvertised(t, db, id, util.ExitDefaultRouteV4)
		disableUser(t, db, "offuser")

		code, _, stderr := runCLI(t, db, "", "route", "approve", fmt.Sprint(id), util.ExitDefaultRouteV4)
		if code == 0 {
			t.Fatal("禁用用户的设备被批成了出口(旁门漏了 owner 闸口)")
		}
		if !strings.Contains(stderr, "offuser") {
			t.Errorf("报错没说是哪个用户: %q", stderr)
		}
		if s := routeStatus(t, db, id, util.ExitDefaultRouteV4); s == util.RouteStatusApproved {
			t.Fatal("被拦下却还是批了")
		}

		// --force 越过后应真的批准,并提示这是出口路由。
		code, stdout, stderr := runCLI(t, db, "", "route", "approve", fmt.Sprint(id), util.ExitDefaultRouteV4, "--force")
		if code != 0 {
			t.Fatalf("--force approve: %s", stderr)
		}
		if !strings.Contains(stdout, "已批准") {
			t.Errorf("stdout 缺成功提示: %q", stdout)
		}
		if !strings.Contains(stderr, "exit-node") && !strings.Contains(stderr, "出口") {
			t.Errorf("批准 0/0 应说明这是出口路由: %q", stderr)
		}
	})
}

// seedAdvertised 只宣告不批准(pending)。
func seedAdvertised(t *testing.T, db string, deviceID int64, cidr string) {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	if _, err := st.UpsertAdvertisedRoute(t.Context(), deviceID, cidr); err != nil {
		t.Fatalf("upsert route %s: %v", cidr, err)
	}
}

// 与 server 自身 mesh 网段交叠的子网路由必须拒,且 --force 也不许越过 ——
// 交叠会把发往「当前离线的 mesh 地址」的包中继进宣告方的 LAN(跨信任域泄漏),
// 那是配置错误而不是策略权衡。
func TestCmdRouteApprove_RejectsMeshOverlapEvenWithForce(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-mesh.db")
	id := seedExitDevice(t, db, "meshy", "ffff6666-9999-4999-9999-999999999999")
	seedAdvertised(t, db, id, "100.64.0.0/24")

	st := openStoreForTest(t, db)
	if err := st.SetMeshCIDRs(t.Context(), []string{"100.64.0.0/10"}); err != nil {
		t.Fatalf("SetMeshCIDRs: %v", err)
	}
	_ = st.Close()

	for _, extra := range [][]string{nil, {"--force"}} {
		args := append([]string{"route", "approve", fmt.Sprint(id), "100.64.0.0/24"}, extra...)
		code, _, stderr := runCLI(t, db, "", args...)
		if code == 0 {
			t.Fatalf("%v: 与 mesh 交叠的网段被批准了", extra)
		}
		if !strings.Contains(stderr, "mesh") {
			t.Errorf("%v: 报错没说是与 mesh 交叠: %q", extra, stderr)
		}
		if s := routeStatus(t, db, id, "100.64.0.0/24"); s == util.RouteStatusApproved {
			t.Fatalf("%v: 被拒却还是批了", extra)
		}
	}

	// 不交叠的网段照常放行(闸口不能宽到把正常网段也卡住)。
	seedAdvertised(t, db, id, "192.168.66.0/24")
	if c, _, e := runCLI(t, db, "", "route", "approve", fmt.Sprint(id), "192.168.66.0/24"); c != 0 {
		t.Fatalf("不交叠的网段被误拦: %s", e)
	}
}

// 同一 CIDR 被批给多台设备时,数据面只认 deviceID 最小的那台,其余是死重。
// 告警必须把「谁会胜出」说清楚 —— 三台以上时也要排序后完整列出,否则运维以为做到了冗余。
func TestCmdRouteApprove_DuplicateWarningNamesWinnerAmongMany(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-dup3.db")
	const cidr = "192.168.99.0/24"
	ids := []int64{
		seedExitDevice(t, db, "d1", "10000000-0001-4001-9001-000000000001"),
		seedExitDevice(t, db, "d2", "10000000-0002-4002-9002-000000000002"),
		seedExitDevice(t, db, "d3", "10000000-0003-4003-9003-000000000003"),
	}
	for _, id := range ids[:2] {
		seedApprovedSubnetRoute(t, db, id, cidr)
	}
	seedAdvertised(t, db, ids[2], cidr)

	code, _, stderr := runCLI(t, db, "", "route", "approve", fmt.Sprint(ids[2]), cidr)
	if code != 0 {
		t.Fatalf("approve: %s", stderr)
	}
	if !strings.Contains(stderr, cidr) {
		t.Errorf("重复告警没提到 CIDR: %q", stderr)
	}
	// 另外两台都要被列出来(排序后),胜出者是 id 最小的那台。
	for _, id := range ids[:2] {
		if !strings.Contains(stderr, fmt.Sprint(id)) {
			t.Errorf("重复告警漏了设备 #%d: %q", id, stderr)
		}
	}
	winner := ids[0]
	if !strings.Contains(stderr, fmt.Sprintf("#%d", winner)) {
		t.Errorf("告警没点明胜出者 #%d: %q", winner, stderr)
	}
}

// 交叠告警要按最长前缀判胜负,**两个方向都要判对**:新批的更长时新的胜,
// 已有的更长时已有的胜。判反了运维会去删错的那一条,黑洞照旧。
func TestCmdRouteApprove_OverlapWinnerBothDirections(t *testing.T) {
	t.Run("已有的掩码更长", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "route-ov-old.db")
		a := seedExitDevice(t, db, "oa", "20000000-0001-4001-9001-000000000001")
		b := seedExitDevice(t, db, "ob", "20000000-0002-4002-9002-000000000002")
		seedApprovedSubnetRoute(t, db, a, "172.21.10.0/25")
		seedAdvertised(t, db, b, "172.21.10.0/24")

		code, _, stderr := runCLI(t, db, "", "route", "approve", fmt.Sprint(b), "172.21.10.0/24")
		if code != 0 {
			t.Fatalf("approve: %s", stderr)
		}
		if !strings.Contains(stderr, "172.21.10.0/25") {
			t.Errorf("告警没提到交叠的那条: %q", stderr)
		}
		// 胜出者应是掩码更长的 /25(设备 a)。
		if !strings.Contains(stderr, fmt.Sprintf("#%d", a)) {
			t.Errorf("胜出者应是 /25 的设备 #%d: %q", a, stderr)
		}
	})

	t.Run("新批的掩码更长", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "route-ov-new.db")
		a := seedExitDevice(t, db, "oa", "30000000-0001-4001-9001-000000000001")
		b := seedExitDevice(t, db, "ob", "30000000-0002-4002-9002-000000000002")
		seedApprovedSubnetRoute(t, db, a, "172.22.10.0/24")
		seedAdvertised(t, db, b, "172.22.10.0/25")

		code, _, stderr := runCLI(t, db, "", "route", "approve", fmt.Sprint(b), "172.22.10.0/25")
		if code != 0 {
			t.Fatalf("approve: %s", stderr)
		}
		if !strings.Contains(stderr, fmt.Sprintf("#%d", b)) {
			t.Errorf("胜出者应是新批的 /25 设备 #%d: %q", b, stderr)
		}
	})
}

// warnOverlappingApprovedCIDR 遇到解析不出来的 CIDR 必须闭嘴而不是 panic ——
// 库里可能留着老版本写进去的非规范字面量(CLI 侧的归一器保证不了历史数据)。
func TestWarnOverlappingApprovedCIDR_ToleratesUnparsableInput(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-ov-bad.db")
	id := seedExitDevice(t, db, "obad", "40000000-0001-4001-9001-000000000001")
	st := openStoreForTest(t, db)
	defer st.Close()

	opts, _ := newConfirmOpts("")
	// 新 CIDR 自己就解析不出来 → 直接 return,不该有任何输出、更不该 panic。
	warnOverlappingApprovedCIDR(t.Context(), st, opts, id, "不是网段")

	// 库里存着非法字面量时,遍历要跳过它继续看别的。
	seedApprovedSubnetRoute(t, db, id, "192.168.31.0/24")
	if _, err := st.DB().ExecContext(t.Context(),
		`UPDATE subnet_routes SET cidr = 'junk' WHERE cidr = '192.168.31.0/24'`); err != nil {
		t.Fatalf("弄坏 cidr: %v", err)
	}
	warnOverlappingApprovedCIDR(t.Context(), st, opts, id+1, "192.168.31.128/25")
}

// =========================================================================
// route reject / delete
// =========================================================================

// reject 只作用于 pending(与 web 对齐)。这条守卫堵的是「用 reject 悄悄撤销一条已批准
// 的路由」—— 它绕过了 delete 的确认与语义。
func TestCmdRouteReject_NotFoundAndForce(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-rej.db")
	id := seedExitDevice(t, db, "rj", "50000000-0001-4001-9001-000000000001")

	t.Run("声明不存在", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "route", "reject", fmt.Sprint(id), "10.55.0.0/24")
		if code != 1 {
			t.Fatalf("应 exit 1, got %d", code)
		}
		if !strings.Contains(stderr, "10.55.0.0/24") {
			t.Errorf("报错没说是哪条: %q", stderr)
		}
	})

	t.Run("--force 也拦不住不存在的声明", func(t *testing.T) {
		// --force 跳过的是「必须 pending」这道检查,不是「必须存在」。
		code, _, stderr := runCLI(t, db, "", "route", "reject", fmt.Sprint(id), "10.56.0.0/24", "--force")
		if code == 0 {
			t.Fatal("--force 把不存在的声明「拒绝」成功了")
		}
		if !strings.Contains(stderr, "10.56.0.0/24") {
			t.Errorf("报错没说是哪条: %q", stderr)
		}
	})

	t.Run("--force 可以拒已批准的", func(t *testing.T) {
		seedApprovedSubnetRoute(t, db, id, "10.57.0.0/24")
		if c, _, e := runCLI(t, db, "", "route", "reject", fmt.Sprint(id), "10.57.0.0/24"); c == 0 {
			t.Fatal("不带 --force 竟然把已批准的降级成 rejected 了")
		} else if e == "" {
			t.Error("拒了却没说原因")
		}
		if c, _, e := runCLI(t, db, "", "route", "reject", fmt.Sprint(id), "10.57.0.0/24", "--force"); c != 0 {
			t.Fatalf("--force reject: %s", e)
		}
		if s := routeStatus(t, db, id, "10.57.0.0/24"); s != util.RouteStatusRejected {
			t.Fatalf("--force 之后状态=%q", s)
		}
	})
}

// 按族 reject 掉一条出口路由后,若另一族仍被批准,这台机器**仍是合法出口**,
// 连另一族(含 IPv4)流量也照走它。三机实测坐实过,所以这里必须响亮告警。
func TestCmdRouteReject_WarnsWhenOtherExitFamilyStillApproved(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-rej-exit.db")
	id := seedExitDevice(t, db, "halfexit", "60000000-0001-4001-9001-000000000001")
	if c, _, e := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id), "--no-vip"); c != 0 {
		t.Fatalf("designate: %s", e)
	}
	// designate 之后两族都是 approved;reject 需要 pending,故用 --force。
	code, _, stderr := runCLI(t, db, "", "route", "reject", fmt.Sprint(id), util.ExitDefaultRouteV4, "--force")
	if code != 0 {
		t.Fatalf("reject: %s", stderr)
	}
	if !strings.Contains(stderr, util.ExitDefaultRouteV6) {
		t.Errorf("撤了 v4 而 v6 仍批准时必须告警仍是出口, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "exit revoke") {
		t.Errorf("告警要指路 exit revoke: %q", stderr)
	}
}

// 撤掉最后一族出口路由时**不该**再告警「另一族仍被批准」—— 噪声会让真正的告警失效。
func TestCmdRouteDelete_NoWarnWhenNoFamilyLeft(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-del-last.db")
	id := seedExitDevice(t, db, "lastexit", "70000000-0001-4001-9001-000000000001")
	if c, _, e := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id), "--no-vip"); c != 0 {
		t.Fatalf("designate: %s", e)
	}
	for _, cidr := range []string{util.ExitDefaultRouteV4, util.ExitDefaultRouteV6} {
		if c, _, e := runCLI(t, db, "", "route", "delete", fmt.Sprint(id), cidr); c != 0 {
			t.Fatalf("delete %s: %s", cidr, e)
		}
	}
	// 两族都删完之后再删(幂等失败)不该有残留告警;这里直接查表确认干净。
	if s := routeStatus(t, db, id, util.ExitDefaultRouteV6); s != "" {
		t.Fatalf("::/0 没删掉: %q", s)
	}
}

// route delete 的确认门:答「不」时什么都不改。
func TestCmdRouteDelete_ConfirmGuard(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-del-confirm.db")
	id := seedExitDevice(t, db, "dc", "80000000-0001-4001-9001-000000000001")
	seedApprovedSubnetRoute(t, db, id, "10.88.0.0/24")

	code, stdout, stderr := runCLIInteractive(t, db, "n\n", "route", "delete", fmt.Sprint(id), "10.88.0.0/24")
	if code != 0 {
		t.Fatalf("取消却以 %d 退出: %s", code, stderr)
	}
	if !strings.Contains(stdout, "取消") {
		t.Errorf("没告诉用户已取消: %q", stdout)
	}
	if s := routeStatus(t, db, id, "10.88.0.0/24"); s != util.RouteStatusApproved {
		t.Fatalf("答了不,路由却被删了: 状态=%q", s)
	}

	// 读不到回答(EOF)按「否」处理:正常退出但绝不能删。
	if code, _, e := runCLIInteractive(t, db, "", "route", "delete", fmt.Sprint(id), "10.88.0.0/24"); code != 0 {
		t.Fatalf("EOF 应按否处理并正常退出, got %d stderr=%s", code, e)
	}
	if s := routeStatus(t, db, id, "10.88.0.0/24"); s != util.RouteStatusApproved {
		t.Fatalf("EOF 却把路由删了: 状态=%q", s)
	}
}

// delete 不存在的路由要给本地化的「路由不存在」;删除被库拒绝时不能报成功。
func TestCmdRouteDelete_NotFoundAndWriteFailure(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-del-fail.db")
	id := seedExitDevice(t, db, "df", "90000000-0001-4001-9001-000000000001")

	code, _, stderr := runCLI(t, db, "", "route", "delete", fmt.Sprint(id), "10.99.0.0/24")
	if code != 1 {
		t.Fatalf("删不存在的路由应 exit 1, got %d", code)
	}
	if !strings.Contains(stderr, "10.99.0.0/24") {
		t.Errorf("报错没说是哪条: %q", stderr)
	}

	seedApprovedSubnetRoute(t, db, id, "10.99.0.0/24")
	abortWritesOn(t, db, "subnet_routes", "DELETE")
	code, stdout, _ := runCLI(t, db, "", "route", "delete", fmt.Sprint(id), "10.99.0.0/24")
	if code == 0 {
		t.Fatalf("删除失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "已删除") {
		t.Errorf("删除失败却打了成功提示: %q", stdout)
	}
	if s := routeStatus(t, db, id, "10.99.0.0/24"); s != util.RouteStatusApproved {
		t.Fatalf("写被拒了路由却没了: 状态=%q", s)
	}
}

// approve 写库失败(不是 ErrNotFound 那一支)时不能报成功。
func TestCmdRouteApprove_WriteFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "route-app-fail.db")
	id := seedExitDevice(t, db, "af", "a0000000-0001-4001-9001-000000000001")
	seedAdvertised(t, db, id, "10.77.0.0/24")
	abortWritesOn(t, db, "subnet_routes", "UPDATE")

	code, stdout, _ := runCLI(t, db, "", "route", "approve", fmt.Sprint(id), "10.77.0.0/24")
	if code == 0 {
		t.Fatalf("写库失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "已批准") {
		t.Errorf("写库失败却打了成功提示: %q", stdout)
	}
	if s := routeStatus(t, db, id, "10.77.0.0/24"); s == util.RouteStatusApproved {
		t.Fatal("写被拒了状态却变成 approved")
	}
}

// parseRouteTarget 是三个 verb 共用的入口:出口 /0 必须放行(否则根本无法批准出口),
// 而普通网段要被规范化成同一字面量(否则 approve 与 delete 引用不到同一行)。
func TestParseRouteTarget_NormalizesAndAcceptsExitRoutes(t *testing.T) {
	opts, _ := newConfirmOpts("")
	for _, tc := range []struct {
		in   string
		want string
	}{
		{util.ExitDefaultRouteV4, util.ExitDefaultRouteV4},
		{util.ExitDefaultRouteV6, util.ExitDefaultRouteV6},
		{"192.168.5.7/24", "192.168.5.0/24"}, // 主机位要被抹平
		{"FD00:0:0::/64", "fd00::/64"},       // IPv6 要规范化
	} {
		id, cidr, err := parseRouteTarget(opts, []string{"7", tc.in})
		if err != nil {
			t.Errorf("parseRouteTarget(%q): %v", tc.in, err)
			continue
		}
		if id != 7 {
			t.Errorf("device id=%d want 7", id)
		}
		if cidr != tc.want {
			t.Errorf("parseRouteTarget(%q) cidr=%q want %q", tc.in, cidr, tc.want)
		}
		if _, perr := netip.ParsePrefix(cidr); perr != nil {
			t.Errorf("归一后的 %q 解析不了: %v", cidr, perr)
		}
	}

	for _, args := range [][]string{
		{},
		{"7"},
		{"7", "10.0.0.0/24", "extra"},
		{"abc", "10.0.0.0/24"},
		{"7", "不是网段"},
	} {
		if _, _, err := parseRouteTarget(opts, args); err == nil {
			t.Errorf("parseRouteTarget(%v) 应报错", args)
		}
	}
}

// exitIsReadOnly 决定要不要以可写方式开库。判错的后果:list 这类只读命令在库被
// 别的进程占用时也会失败,或者写命令拿到只读句柄后半途报错。
func TestExitIsReadOnly(t *testing.T) {
	for _, tc := range []struct {
		rest []string
		want bool
	}{
		{nil, true},
		{[]string{"list"}, true},
		{[]string{"ls"}, true},
		{[]string{"designate", "1"}, false},
		{[]string{"revoke", "1"}, false},
		{[]string{"set", "1"}, false},
	} {
		if got := exitIsReadOnly(tc.rest); got != tc.want {
			t.Errorf("exitIsReadOnly(%v)=%v want %v", tc.rest, got, tc.want)
		}
	}
}

// exitMark 是表格里唯一表达「这一族批了没」的符号,渲染反了整张表都在说谎。
func TestExitMark(t *testing.T) {
	if exitMark(true) != "✓" || exitMark(false) != "-" {
		t.Errorf("exitMark: true=%q false=%q", exitMark(true), exitMark(false))
	}
}

// 确认 store 侧对出口平台的判断和 CLI 闸口用的是同一套口径 —— 两边漂移过一次,
// 结果是 CLI 放行了 web 会拒的设备。
func TestExitCapablePlatformParity(t *testing.T) {
	for _, p := range []string{"linux", "windows", "macos", "router"} {
		if !store.IsExitCapablePlatform(p) {
			t.Errorf("%s 应能作出口", p)
		}
	}
	for _, p := range []string{"ios", "android", "", "darwin"} {
		if store.IsExitCapablePlatform(p) {
			t.Errorf("%s 不该能作出口", p)
		}
	}
}

// exit designate 的审计必须落一条 —— 出口资格是基础设施变更,须可归因。
func TestCmdExitDesignate_WritesAudit(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "exit-audit.db")
	id := seedExitDevice(t, db, "auditee", "b0000000-0001-4001-9001-000000000001")
	if c, _, e := runCLI(t, db, "", "exit", "designate", fmt.Sprint(id), "--v4", "100.64.0.51"); c != 0 {
		t.Fatalf("designate: %s", e)
	}

	_, stdout, _ := runCLI(t, db, "", "audit", "list")
	if !strings.Contains(stdout, "exit_designate") {
		t.Errorf("审计里没有 exit_designate:\n%s", stdout)
	}
	if !strings.Contains(stdout, fmt.Sprintf("device:%d", id)) {
		t.Errorf("审计没记下是哪台设备:\n%s", stdout)
	}
}
