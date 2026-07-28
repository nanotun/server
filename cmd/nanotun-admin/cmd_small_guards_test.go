package main

// cmd_small_guards_test.go(第二十二轮)—— lease / audit / i18n / control_client 四处的零散拒绝面。
//
// 这几个文件都不长,但各有一条「错了不会报错」的路:
//   - lease set 写进垃圾地址,设备下次登录直接黑洞;
//   - audit list 的时间窗口算错一秒,「改完立刻核对审计」永远查不到;
//   - 翻译缺 key 时若回落错了,英文环境会突然冒出中文(或者反过来);
//   - control socket 返回非 2xx 时若不当错误处理,CLI 会报「已通知」而 server 什么都没做。

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// =========================================================================
// lease
// =========================================================================

func TestCmdLease_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "lease-usage.db")
	id := seedDevice(t, db, "lu", "aaaaaaaa-0001-4001-8001-000000000001")
	idStr := fmt.Sprint(id)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"不给子命令", []string{"lease"}},
		{"release 不给 device", []string{"lease", "release"}},
		{"release 给两个", []string{"lease", "release", idStr, idStr}},
		{"release 的 id 不是数字", []string{"lease", "release", "那一台"}},
		{"set 不给 device", []string{"lease", "set"}},
		{"set 给两个 device", []string{"lease", "set", idStr, idStr}},
		{"set 的 id 不是数字", []string{"lease", "set", "第一台", "--v4", "100.64.0.5"}},
		{"set 未知 flag", []string{"lease", "set", idStr, "--bogus"}},
		{"gc 未知 flag", []string{"lease", "gc", "--bogus"}},
		{"gc idle 为 0", []string{"lease", "gc", "--idle", "0"}},
		{"gc idle 为负", []string{"lease", "gc", "--idle", "-1h"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", tc.args...)
			if code != 2 {
				t.Fatalf("用法错误应 exit 2, got %d stderr=%q", code, stderr)
			}
		})
	}

	if code, _, stderr := runCLI(t, db, "", "lease", "pin", idStr); code == 0 {
		t.Fatal("未知子命令 lease pin 竟然成功了")
	} else if !strings.Contains(stderr, "pin") {
		t.Errorf("报错没回显敲错的子命令: %q", stderr)
	}
}

// lease set 必须至少给一族地址,且写错族/写垃圾要当场拒 —— 放过去的话垃圾会进
// vip_v4/vip_v6,设备下次登录拿到即黑洞(store 层只归一 UNIQUE 冲突,不验格式)。
func TestCmdLeaseSet_AddressValidation(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "lease-addr.db")
	id := seedDevice(t, db, "la", "aaaaaaaa-0002-4002-8002-000000000002")
	idStr := fmt.Sprint(id)

	t.Run("两族都不给", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "lease", "set", idStr)
		if code == 0 {
			t.Fatal("一族都不给却成功了")
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("拒了却没说原因")
		}
	})

	t.Run("设备不存在", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "lease", "set", "4242", "--v4", "100.64.0.5")
		if code == 0 {
			t.Fatal("给不存在的设备设 lease 竟然成功了")
		}
		if !strings.Contains(stderr, "4242") {
			t.Errorf("报错没说是哪台: %q", stderr)
		}
	})

	for _, tc := range []struct{ name, flag, val string }{
		{"--v4 收到 IPv6", "--v4", "fd00::1"},
		{"--v4 收到垃圾", "--v4", "notanip"},
		{"--v6 收到 IPv4", "--v6", "100.64.0.5"},
		{"--v6 收到 v4-mapped", "--v6", "::ffff:100.64.0.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", "lease", "set", idStr, tc.flag, tc.val)
			if code == 0 {
				t.Fatal("非法地址被写进 lease —— 设备下次登录即黑洞")
			}
			if !strings.Contains(stderr, tc.val) {
				t.Errorf("报错没回显那个值: %q", stderr)
			}
			if l := leaseOf(t, db, id); l != nil {
				t.Fatalf("被拒却写出了 lease: %+v", l)
			}
		})
	}
}

// seedOrphanLease 造一条会被 gc 回收的 lease:非手动 + 所属 device 很久没上线。
// idle 判据落在 **devices.last_seen_at**(不是 lease 自己的时间戳),把设备做旧才算孤儿。
func seedOrphanLease(t *testing.T, db string, deviceID int64, vip4 string) {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	if _, err := st.UpsertLease(t.Context(), deviceID, vip4, "", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	if _, err := st.DB().ExecContext(t.Context(),
		`UPDATE devices SET last_seen_at = 0 WHERE id = ?`, deviceID); err != nil {
		t.Fatalf("做旧 device.last_seen_at: %v", err)
	}
}

func leaseOf(t *testing.T, db string, deviceID int64) *store.Lease {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	l, err := st.GetLeaseByDevice(t.Context(), deviceID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		t.Fatalf("GetLeaseByDevice: %v", err)
	}
	return l
}

// lease set 的 --json 形态:脚本要能拿到最终落库的两族地址和 manual 标记。
func TestCmdLeaseSet_JSONOutput(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "lease-json.db")
	id := seedDevice(t, db, "lj", "aaaaaaaa-0003-4003-8003-000000000003")

	code, stdout, stderr := runCLI(t, db, "", "--json", "lease", "set", fmt.Sprint(id),
		"--v4", "100.64.0.12", "--v6", "fd00:200::12")
	if code != 0 {
		t.Fatalf("lease set --json: code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{"100.64.0.12", "fd00:200::12"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("JSON 里缺 %s:\n%s", want, stdout)
		}
	}
}

// 写 lease 失败时不能报成功:运维会以为地址已经钉好,而设备下次登录仍走自动分配。
func TestCmdLeaseSet_WriteFailureIsLoud(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "lease-wfail.db")
	id := seedDevice(t, db, "lw", "aaaaaaaa-0004-4004-8004-000000000004")
	abortWritesOn(t, db, "leases", "INSERT")

	code, stdout, _ := runCLI(t, db, "", "lease", "set", fmt.Sprint(id), "--v4", "100.64.0.13")
	if code == 0 {
		t.Fatalf("写失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "已分配") {
		t.Errorf("写失败却打了成功提示: %q", stdout)
	}
}

// lease release:没有 lease 的设备要给本地化提示;删除失败不能报成功。
func TestCmdLeaseRelease_NotFoundAndWriteFailure(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "lease-rel.db")
	id := seedDevice(t, db, "lr", "aaaaaaaa-0005-4005-8005-000000000005")

	code, _, stderr := runCLI(t, db, "", "lease", "release", fmt.Sprint(id))
	if code != 1 {
		t.Fatalf("释放不存在的 lease 应 exit 1, got %d", code)
	}
	if !strings.Contains(stderr, fmt.Sprint(id)) {
		t.Errorf("报错没说是哪台: %q", stderr)
	}

	if c, _, e := runCLI(t, db, "", "lease", "set", fmt.Sprint(id), "--v4", "100.64.0.14"); c != 0 {
		t.Fatalf("lease set: %s", e)
	}
	abortWritesOn(t, db, "leases", "DELETE")
	code, stdout, _ := runCLI(t, db, "", "lease", "release", fmt.Sprint(id))
	if code == 0 {
		t.Fatalf("删除失败却 exit 0, stdout=%q", stdout)
	}
	if l := leaseOf(t, db, id); l == nil {
		t.Fatal("写被拒了 lease 却没了")
	}
}

// lease list 读不出行时必须失败 —— 缺行的 lease 表会让运维以为某个 vIP 空闲,
// 从而把它手工钉给另一台设备。
func TestCmdLeaseList_UnreadableRowsFailLoudly(t *testing.T) {
	t.Run("表不在了", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "lease-notable.db")
		aclExec(t, db, `ALTER TABLE leases RENAME TO leases_gone`)
		if code, _, _ := runCLI(t, db, "", "lease", "list"); code == 0 {
			t.Fatal("查不到表却 exit 0")
		}
	})

	t.Run("行扫不出来", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "lease-badrow.db")
		id := seedDevice(t, db, "lb", "aaaaaaaa-0006-4006-8006-000000000006")
		if c, _, e := runCLI(t, db, "", "lease", "set", fmt.Sprint(id), "--v4", "100.64.0.15"); c != 0 {
			t.Fatalf("lease set: %s", e)
		}
		aclExec(t, db, `UPDATE leases SET assigned_at = 'oops'`)
		if code, _, _ := runCLI(t, db, "", "lease", "list"); code == 0 {
			t.Fatal("行扫不出来却 exit 0")
		}
	})
}

// lease gc 的三条路:--dry-run 只数不删;确认门答不则不删;真删之后报出条数。
// 计数与删除必须用同一个谓词(第二十轮修过:预览数比实删偏大,运维据此误判)。
func TestCmdLeaseGc_DryRunConfirmAndCount(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "lease-gc.db")
	id := seedDevice(t, db, "lg", "aaaaaaaa-0007-4007-8007-000000000007")
	seedOrphanLease(t, db, id, "100.64.0.16")

	t.Run("--dry-run 不删", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, db, "", "lease", "gc", "--idle", "1h", "--dry-run")
		if code != 0 {
			t.Fatalf("dry-run: code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("dry-run 一句话都不说,运维无从判断")
		}
		if leaseOf(t, db, id) == nil {
			t.Fatal("--dry-run 把 lease 删了")
		}
	})

	t.Run("答不则不删", func(t *testing.T) {
		code, stdout, stderr := runCLIInteractive(t, db, "n\n", "lease", "gc", "--idle", "1h")
		if code != 0 {
			t.Fatalf("取消却以 %d 退出: %s", code, stderr)
		}
		if !strings.Contains(stdout, "取消") {
			t.Errorf("没告诉用户已取消: %q", stdout)
		}
		if leaseOf(t, db, id) == nil {
			t.Fatal("答了不,lease 却被删了")
		}
	})

	t.Run("确认后回收并报数", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, db, "", "lease", "gc", "--idle", "1h")
		if code != 0 {
			t.Fatalf("gc: code=%d stderr=%s", code, stderr)
		}
		if !strings.Contains(stdout, "1") {
			t.Errorf("没报出回收条数: %q", stdout)
		}
		if leaseOf(t, db, id) != nil {
			t.Fatal("确认之后没回收")
		}
	})
}

// lease gc 在计数或删除失败时必须失败 —— 谎报「已回收 0 条」会让运维以为地址池干净,
// 而泄漏的 vIP 还在占着。
func TestCmdLeaseGc_FailuresAreLoud(t *testing.T) {
	t.Run("计数失败(dry-run)", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "lease-gc-cntfail.db")
		aclExec(t, db, `ALTER TABLE leases RENAME TO leases_gone`)
		if code, _, _ := runCLI(t, db, "", "lease", "gc", "--dry-run"); code == 0 {
			t.Fatal("数不出来却 exit 0")
		}
	})

	t.Run("删除失败", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "lease-gc-delfail.db")
		id := seedDevice(t, db, "lgd", "aaaaaaaa-0008-4008-8008-000000000008")
		seedOrphanLease(t, db, id, "100.64.0.17")
		abortWritesOn(t, db, "leases", "DELETE")

		code, stdout, _ := runCLI(t, db, "", "lease", "gc", "--idle", "1h")
		if code == 0 {
			t.Fatalf("删除失败却 exit 0, stdout=%q", stdout)
		}
	})
}

// =========================================================================
// audit
// =========================================================================

func TestCmdAudit_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "audit-usage.db")
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"不给子命令", []string{"audit"}, 2},
		{"多余位置参数", []string{"audit", "list", "extra"}, 2},
		{"未知 flag", []string{"audit", "list", "--bogus"}, 2},
		{"--since 为 0", []string{"audit", "list", "--since", "0"}, 1},
		{"--since 为负", []string{"audit", "list", "--since", "-1h"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", tc.args...)
			if code != tc.want {
				t.Fatalf("code=%d want %d stderr=%q", code, tc.want, stderr)
			}
		})
	}

	if code, _, stderr := runCLI(t, db, "", "audit", "purge"); code == 0 {
		t.Fatal("未知子命令 audit purge 竟然成功了(审计是 append-only)")
	} else if !strings.Contains(stderr, "purge") {
		t.Errorf("报错没回显敲错的子命令: %q", stderr)
	}
}

// 「改配置 → 立即核对审计」必须查得到:audit 行的 at 只到秒,窗口上界若用
// time.Now().Unix() 会把本秒内刚写的记录整批排除(CLI 这条曾经漏了 +1 补偿)。
func TestCmdAuditList_FindsRecordWrittenInTheSameSecond(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "audit-now.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "freshly", "--psk", "psk-fresh-1234"); c != 0 {
		t.Fatalf("user create: %s", e)
	}
	code, stdout, stderr := runCLI(t, db, "", "audit", "list")
	if code != 0 {
		t.Fatalf("audit list: code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "freshly") {
		t.Errorf("刚写的审计立刻就查不到 —— 时间窗上界又把本秒排除了:\n%s", stdout)
	}
}

// --action 是精确匹配,且过滤下推到 store(否则会出现「先取 100 条再过滤剩 3 条」)。
func TestCmdAuditList_ActionFilterIsExactAndPushedDown(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "audit-action.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "au1", "--psk", "psk-au1-12345"); c != 0 {
		t.Fatalf("user create: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "user", "disable", "au1"); c != 0 {
		t.Fatalf("user disable: %s", e)
	}

	// 先确认两类 action 都在。
	_, all, _ := runCLI(t, db, "", "audit", "list")
	if !strings.Contains(all, "user_create") || !strings.Contains(all, "user_disable") {
		t.Fatalf("前置数据不齐:\n%s", all)
	}

	code, stdout, stderr := runCLI(t, db, "", "audit", "list", "--action", "user_disable")
	if code != 0 {
		t.Fatalf("audit list --action: code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "user_disable") {
		t.Errorf("过滤把目标 action 也滤掉了:\n%s", stdout)
	}
	if strings.Contains(stdout, "user_create") {
		t.Errorf("--action 应是精确匹配,却带出了别的 action:\n%s", stdout)
	}

	// 前后空白要被容错(运维从文档里复制粘贴常带空格)。
	_, padded, _ := runCLI(t, db, "", "audit", "list", "--action", "  user_disable  ")
	if !strings.Contains(padded, "user_disable") {
		t.Errorf("带空白的 --action 没匹配上:\n%s", padded)
	}
}

func TestCmdAuditList_JSONAndQueryFailure(t *testing.T) {
	t.Run("--json", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "audit-json.db")
		if c, _, e := runCLI(t, db, "", "user", "create", "aj", "--psk", "psk-aj-123456"); c != 0 {
			t.Fatalf("user create: %s", e)
		}
		code, stdout, stderr := runCLI(t, db, "", "--json", "audit", "list")
		if code != 0 {
			t.Fatalf("audit list --json: code=%d stderr=%s", code, stderr)
		}
		// 注意字段名是 Go 风格的 "Action"/"At" 而非 snake_case:store.AuditLog 没有
		// json tag,这条是 CLI 里唯一不走 snake_case 的 --json 输出。这里按现状钉住,
		// 免得哪天有人「顺手统一一下」而悄悄改掉已经被脚本 jq 的字段名。
		for _, want := range []string{`"Action"`, `"Actor"`, `"At"`, "user_create"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("JSON 缺 %s:\n%s", want, stdout)
			}
		}
	})

	t.Run("查询失败", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "audit-fail.db")
		aclExec(t, db, `ALTER TABLE audit_logs RENAME TO audit_logs_gone`)
		code, _, stderr := runCLI(t, db, "", "audit", "list")
		if code == 0 {
			t.Fatal("查不到审计表却 exit 0 —— 空列表会被当成「没发生过任何变更」")
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("失败却没说原因")
		}
	})
}

// =========================================================================
// i18n
// =========================================================================

// --lang / 环境变量的取值五花八门(en_US.UTF-8、zh-CN、Chinese……)。归一化判错的后果
// 是运维明明指定了语言却拿到另一种,或者被当成非法值直接拒。
func TestNormalizeLang(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"en", langEN, true},
		{"EN", langEN, true},
		{"  en  ", langEN, true},
		{"english", langEN, true},
		{"en-US", langEN, true},
		{"en_US.UTF-8", langEN, true},
		{"zh", langZH, true},
		{"cn", langZH, true},
		{"chinese", langZH, true},
		{"zh-CN", langZH, true},
		{"zh_CN.UTF-8", langZH, true},
		{"", "", false},
		{"fr", "", false},
		{"english-ish", "", false}, // 不是前缀规则里的 en- / en_
	} {
		got, ok := normalizeLang(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("normalizeLang(%q)=(%q,%v) want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// 缺 key 的回落链:目标语言 → 英文 → key 本身。回落错了不会报错,只会让输出里
// 突然冒出一个裸 key(或另一种语言),而那通常发生在最需要看清提示的错误路径上。
func TestTranslate_FallbackChain(t *testing.T) {
	// 空语言按默认(英文)处理。
	if got := translate("", "common.usagePrefix"); got != translate(langEN, "common.usagePrefix") {
		t.Errorf("空语言没按默认英文处理: %q", got)
	}
	// 未知语言 → 英文表。
	if got := translate("fr", "common.usagePrefix"); got != translate(langEN, "common.usagePrefix") {
		t.Errorf("未知语言没回落到英文: %q", got)
	}
	// 两张表都没有的 key → 原样返回 key(而不是空串:空串会让整行提示消失)。
	const missing = "nope.this.key.does.not.exist"
	if got := translate(langZH, missing); got != missing {
		t.Errorf("缺 key 应原样返回 key, got %q", got)
	}
	if got := translate(langEN, missing); got != missing {
		t.Errorf("缺 key 应原样返回 key, got %q", got)
	}
	// 带参数时缺 key 仍要能格式化(不 panic),参数照旧带出来。
	if got := translate(langZH, missing, 7); !strings.Contains(got, missing) {
		t.Errorf("缺 key + 带参数: %q", got)
	}
}

// translateArgs:参数本身携带 LocaleKey 时要按目标语言翻好再交给 Sprintf ——
// 否则英文输出里会混出中文(store 层把内层诊断错误当 %s 透传时就会这样)。
func TestTranslateArgs_TranslatesNestedLocalizedErrors(t *testing.T) {
	inner := newLocErr("common.usagePrefix")
	zh := translate(langZH, "cli.unknownFlag", inner)
	en := translate(langEN, "cli.unknownFlag", inner)
	if zh == en {
		t.Errorf("内层错误没按目标语言翻译:zh=%q en=%q", zh, en)
	}
	if !strings.Contains(zh, translate(langZH, "common.usagePrefix")) {
		t.Errorf("zh 输出里没带上翻好的内层文案: %q", zh)
	}
	// 普通参数原样透传。
	if got := translate(langZH, "cli.unknownFlag", "--bogus"); !strings.Contains(got, "--bogus") {
		t.Errorf("普通参数被吃掉了: %q", got)
	}
}

// errText / notFoundErr 的边界:nil 要得空串(而不是 "<nil>"),非 not-found 的错误
// 要原样透出(而不是被翻成「不存在」把真正的故障盖掉)。
func TestErrTextAndNotFoundErr(t *testing.T) {
	opts := &globalOpts{lang: langZH}

	if got := opts.errText(nil); got != "" {
		t.Errorf("errText(nil)=%q, 期望空串", got)
	}
	if got := opts.errText(newLocErr("acl.notFound", 7)); !strings.Contains(got, "7") {
		t.Errorf("携带 LocaleKey 的错误没被翻译: %q", got)
	}
	if got := opts.errText(errors.New("plain boom")); got != "plain boom" {
		t.Errorf("普通错误应原样返回, got %q", got)
	}

	nf := opts.notFoundErr(store.ErrNotFound, "user.notFound", "ghost")
	if nf == nil || !strings.Contains(nf.Error(), "ghost") {
		t.Errorf("ErrNotFound 应被翻成本地化提示, got %v", nf)
	}
	boom := errors.New("disk on fire")
	if got := opts.notFoundErr(boom, "user.notFound", "ghost"); got != boom {
		t.Errorf("非 not-found 的错误被改写了: %v —— 真正的故障会被「不存在」盖掉", got)
	}
}

// =========================================================================
// control_client
// =========================================================================

// socket 路径的优先级:flag > 环境变量 > 默认值。判错会让 CLI 去敲一个不存在的
// socket,然后把「通知不到」当成 server 没在跑。
func TestResolveControlSocketPath_Precedence(t *testing.T) {
	t.Setenv("NANOTUN_CONTROL_SOCKET", "/tmp/from-env.sock")
	if got := resolveControlSocketPath("/tmp/from-flag.sock"); got != "/tmp/from-flag.sock" {
		t.Errorf("flag 应优先于环境变量, got %q", got)
	}
	if got := resolveControlSocketPath(""); got != "/tmp/from-env.sock" {
		t.Errorf("没给 flag 时应取环境变量, got %q", got)
	}
	t.Setenv("NANOTUN_CONTROL_SOCKET", "   ")
	if got := resolveControlSocketPath(""); got != defaultControlSocketPath {
		t.Errorf("环境变量全空白应视作未设, got %q", got)
	}
}

// controlDo 的三类失败:请求体序列化不了、method 本身非法、服务端回非 2xx。
// 第三类最要紧 —— 若把它当成成功,CLI 会报「已通知」而 server 什么都没做。
func TestControlDo_FailureModes(t *testing.T) {
	fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
		"/ok": jsonHandler(`{"ok":true}`),
		"/boom": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("reload failed: acl table locked"))
		},
	})
	cli := newControlHTTPClient(fc.path)

	t.Run("请求体序列化不了", func(t *testing.T) {
		_, err := controlDo(cli, "POST", "/ok", make(chan int))
		if err == nil {
			t.Fatal("无法序列化的 body 却报成功")
		}
		if !strings.Contains(err.Error(), "encode body") {
			t.Errorf("报错没指出是序列化失败: %v", err)
		}
	})

	t.Run("method 非法", func(t *testing.T) {
		if _, err := controlDo(cli, "BAD METHOD", "/ok", nil); err == nil {
			t.Fatal("非法 method 却报成功")
		}
	})

	t.Run("服务端回 500", func(t *testing.T) {
		body, err := controlDo(cli, "POST", "/boom", nil)
		if err == nil {
			t.Fatal("服务端 500 被当成了成功 —— CLI 会报「已通知」而 server 什么都没做")
		}
		// 服务端的 message 要透传给用户,否则运维只看到一个 500。
		msg := (&globalOpts{lang: langZH}).errText(err)
		if !strings.Contains(msg, "acl table locked") {
			t.Errorf("服务端错误信息没透传: %q", msg)
		}
		if !strings.Contains(msg, "500") {
			t.Errorf("没带上状态码: %q", msg)
		}
		if !strings.Contains(string(body), "acl table locked") {
			t.Errorf("body 也应原样返回: %q", body)
		}
	})

	t.Run("socket 不通", func(t *testing.T) {
		dead := newControlHTTPClient("/tmp/definitely-not-a-socket-nanotun-test")
		if _, err := controlDo(dead, "GET", "/ok", nil); err == nil {
			t.Fatal("socket 不存在却报成功")
		}
	})

	t.Run("正常路径", func(t *testing.T) {
		out, err := controlDo(cli, "POST", "/ok", map[string]string{"what": "acl"})
		if err != nil {
			t.Fatalf("controlDo: %v", err)
		}
		if !strings.Contains(string(out), "ok") {
			t.Errorf("body 没返回: %q", out)
		}
		if !containsAny(fc.requests(), `{"what":"acl"}`) {
			t.Errorf("请求体没发出去: %v", fc.requests())
		}
	})
}
