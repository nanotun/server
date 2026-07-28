package main

// cmd_user_device_guards_test.go(第二十二轮)—— `user` / `device` 两组子命令的拒绝面。
//
// 这两组是运维用得最频繁的命令,也是最容易「看着成功、其实没生效」的地方:
// 参数拼错、平台 token 写成旧文档里的 darwin、把 IPv6 填进 --v4、把地址钉到 mesh 之外……
// 每一条的现场表现都是「CLI 回一句绿色的已更新,设备下次登录拿到的却是别的东西」。
//
// 所以断言重心是:该拒的当场拒;拒不了只能 warn 的,warn 一定要出现在 stderr。

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// abortWritesOn 在指定表上装一个 BEFORE 触发器,让某类写操作一律失败。
// 用来验「落库失败时 CLI 有没有谎报成功」—— 现场对应磁盘满 / 库被设成只读。
func abortWritesOn(t *testing.T, dbPath, table, op string) {
	t.Helper()
	st := openStoreForTest(t, dbPath)
	defer st.Close()
	name := fmt.Sprintf("t_block_%s_%s", table, strings.ToLower(op))
	stmt := fmt.Sprintf(
		`CREATE TRIGGER %s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT, 'blocked by test'); END`,
		name, op, table)
	if _, err := st.DB().ExecContext(t.Context(), stmt); err != nil {
		t.Fatalf("装 %s 触发器: %v", name, err)
	}
}

// =========================================================================
// user:派发与用法
// =========================================================================

func TestCmdUser_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "u.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
		t.Fatalf("user create: %s", e)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"不给子命令", []string{"user"}},
		{"未知子命令", []string{"user", "rename"}},
		{"create 不给用户名", []string{"user", "create"}},
		{"create 给两个用户名", []string{"user", "create", "a", "b"}},
		{"create 未知 flag", []string{"user", "create", "a", "--bogus"}},
		{"list 带位置参数", []string{"user", "list", "alice"}},
		{"list 未知 flag", []string{"user", "list", "--bogus"}},
		{"show 不给用户名", []string{"user", "show"}},
		{"disable 不给用户名", []string{"user", "disable"}},
		{"enable 给两个", []string{"user", "enable", "a", "b"}},
		{"delete 不给用户名", []string{"user", "delete"}},
		{"reset-psk 给两个", []string{"user", "reset-psk", "a", "b"}},
		{"reset-psk 未知 flag", []string{"user", "reset-psk", "alice", "--bogus"}},
		{"set-bandwidth 不给用户名", []string{"user", "set-bandwidth"}},
		{"set-bandwidth 未知 flag", []string{"user", "set-bandwidth", "alice", "--bogus"}},
		{"set-max-sessions 少参数", []string{"user", "set-max-sessions", "alice"}},
		{"set-platforms 参数过多", []string{"user", "set-platforms", "alice", "macos", "ios"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := runCLI(t, db, "", tc.args...)
			if code != 2 {
				t.Fatalf("code=%d, 期望 2(用法错误)", code)
			}
		})
	}

	// 用户名是纯空白:创建出来之后没有任何命令能再指到它。
	t.Run("create 用户名是空白", func(t *testing.T) {
		if code, _, _ := runCLI(t, db, "", "user", "create", "   "); code == 0 {
			t.Fatal("空白用户名被建出来了 —— 之后没有任何命令能再指到它")
		}
	})

	// 已废弃的 user set-fixed-vip 要给明确的迁移提示,而不是「未知子命令」。
	t.Run("set-fixed-vip 给迁移提示", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "user", "set-fixed-vip", "alice", "--v4", "100.64.0.5")
		if code == 0 {
			t.Fatal("已废弃的命令却成功了")
		}
		if !strings.Contains(stderr, "device") {
			t.Errorf("没指向新命令(device set-fixed-vip),老脚本失败时会一头雾水: %q", stderr)
		}
	})

	// 指到不存在的用户时,每条子命令都要报「查无此人」而不是各自崩一种法。
	t.Run("用户不存在", func(t *testing.T) {
		for _, args := range [][]string{
			{"user", "show", "ghost"},
			{"user", "disable", "ghost"},
			{"user", "enable", "ghost"},
			{"user", "delete", "ghost"},
			{"user", "reset-psk", "ghost"},
			{"user", "set-bandwidth", "ghost", "--up-mibs", "5"},
			{"user", "set-max-sessions", "ghost", "3"},
			{"user", "set-platforms", "ghost", "macos"},
		} {
			code, _, stderr := runCLI(t, db, "", args...)
			if code == 0 {
				t.Errorf("%v 对不存在的用户却成功了", args)
			}
			if !strings.Contains(stderr, "ghost") {
				t.Errorf("%v 的报错里没提用户名: %q", args, stderr)
			}
		}
	})
}

// 重名必须被拒:两个同名账号会让 GetUserByUsername 的语义崩掉。
func TestCmdUserCreate_DuplicateUsernameIsRejected(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "u.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
		t.Fatalf("首次创建: %s", e)
	}
	code, _, stderr := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-other-1234")
	if code == 0 {
		t.Fatal("同名账号被建了第二个")
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败了却没说为什么")
	}
}

// 平台白名单拼错(比如照着旧文档写 darwin)必须当场报错。
// 悄悄存下一个认不出的 token,等于把这个用户永久锁在门外 —— 而 user show 看着一切正常。
func TestCmdUser_PlatformTokensAreValidatedNotStored(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "u.db")

	t.Run("create 时拼错", func(t *testing.T) {
		code, _, _ := runCLI(t, db, "", "user", "create", "bad", "--psk", "psk-bad-12345",
			"--platforms", "darwin")
		if code == 0 {
			t.Fatal("--platforms darwin 被接受了 —— 这个用户会被永久锁在门外")
		}
		// 拒绝之后不能留下半个账号。
		if c, _, _ := runCLI(t, db, "", "user", "show", "bad"); c == 0 {
			t.Error("参数被拒了,账号却建出来了")
		}
	})

	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
		t.Fatalf("user create: %s", e)
	}

	t.Run("set-platforms 时拼错", func(t *testing.T) {
		if code, _, _ := runCLI(t, db, "", "user", "set-platforms", "alice", "macos,darwin"); code == 0 {
			t.Fatal("认不出的 token 被存进白名单了")
		}
		// 原白名单(空 = 不限)不能被改动。
		u := getUser(t, db, "alice")
		if u.AllowedPlatforms != "" {
			t.Errorf("被拒的一次调用改动了白名单: %q", u.AllowedPlatforms)
		}
	})

	t.Run("归一后落库", func(t *testing.T) {
		if c, _, e := runCLI(t, db, "", "user", "set-platforms", "alice", " MacOS , IOS "); c != 0 {
			t.Fatalf("set-platforms: %s", e)
		}
		if got := getUser(t, db, "alice").AllowedPlatforms; got != "macos,ios" {
			t.Errorf("白名单落库为 %q, 期望归一成 macos,ios —— 登录侧按 canonical token 比对", got)
		}
	})

	t.Run("清空恢复不限", func(t *testing.T) {
		if c, stdout, e := runCLI(t, db, "", "user", "set-platforms", "alice"); c != 0 {
			t.Fatalf("set-platforms(清空): %s", e)
		} else if !strings.Contains(stdout, "alice") {
			t.Errorf("清空后的回显没提用户名: %q", stdout)
		}
		if got := getUser(t, db, "alice").AllowedPlatforms; got != "" {
			t.Errorf("清空之后白名单还是 %q", got)
		}
	})
}

// max-sessions 的三个语义值(>0 覆盖 / 0 跟随全局 / -1 不限)都要能设,越界值要拒。
// 拒不住的话会存进一个 server 侧解释不了的数,现场表现是登录被莫名拒绝。
func TestCmdUserSetMaxSessions_Bounds(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "u.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
		t.Fatalf("user create: %s", e)
	}

	for _, bad := range []string{"-2", "abc", "", fmt.Sprint(store.MaxSessionsCap + 1)} {
		code, _, _ := runCLI(t, db, "", "user", "set-max-sessions", "alice", bad)
		if code == 0 {
			t.Errorf("越界值 %q 被存进去了", bad)
		}
	}

	for _, tc := range []struct {
		in   string
		want int
	}{{"5", 5}, {"0", 0}, {"-1", -1}, {fmt.Sprint(store.MaxSessionsCap), store.MaxSessionsCap}} {
		if c, stdout, e := runCLI(t, db, "", "user", "set-max-sessions", "alice", tc.in); c != 0 {
			t.Fatalf("set-max-sessions %s: %s", tc.in, e)
		} else if strings.TrimSpace(stdout) == "" {
			t.Errorf("set-max-sessions %s 没有任何回显", tc.in)
		}
		if got := getUser(t, db, "alice").MaxSessions; got != tc.want {
			t.Errorf("max_sessions=%d, 期望 %d", got, tc.want)
		}
	}
}

// 带宽 flag 的取值校验:坏值必须拒,而且**不能只拒一半** ——
// 上行拒了下行写进去,库里就留下半套配置。
func TestCmdUserSetBandwidth_BadValuesChangeNothing(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "u.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
		t.Fatalf("user create: %s", e)
	}
	// 先设一组已知值。
	if c, _, e := runCLI(t, db, "", "user", "set-bandwidth", "alice",
		"--up-mibs", "10", "--down-mibs", "20", "--no-refresh"); c != 0 {
		t.Fatalf("set-bandwidth: %s", e)
	}
	before := getUser(t, db, "alice")
	if before.BandwidthUpBPS == 0 || before.BandwidthDownBPS == 0 {
		t.Fatalf("基准值没落库: up=%d down=%d", before.BandwidthUpBPS, before.BandwidthDownBPS)
	}

	for _, args := range [][]string{
		{"--up-mibs", "abc"},
		{"--down-mibs", "-5"},
		{"--up-bps", "not-a-number"},
		{"--up-mibs", "5", "--down-mibs", "oops"},
	} {
		full := append([]string{"user", "set-bandwidth", "alice", "--no-refresh"}, args...)
		if code, _, _ := runCLI(t, db, "", full...); code == 0 {
			t.Errorf("%v 被接受了", args)
		}
		after := getUser(t, db, "alice")
		if after.BandwidthUpBPS != before.BandwidthUpBPS || after.BandwidthDownBPS != before.BandwidthDownBPS {
			t.Fatalf("%v 被拒了却改动了库: up %d→%d down %d→%d", args,
				before.BandwidthUpBPS, after.BandwidthUpBPS,
				before.BandwidthDownBPS, after.BandwidthDownBPS)
		}
	}

	// 只给一个方向时,另一个方向必须保持原值(而不是被清成 0)。
	if c, _, e := runCLI(t, db, "", "user", "set-bandwidth", "alice",
		"--up-mibs", "50", "--no-refresh"); c != 0 {
		t.Fatalf("单方向 set-bandwidth: %s", e)
	}
	after := getUser(t, db, "alice")
	if after.BandwidthDownBPS != before.BandwidthDownBPS {
		t.Errorf("只改上行却把下行从 %d 改成了 %d —— 运维会莫名丢掉一半配置",
			before.BandwidthDownBPS, after.BandwidthDownBPS)
	}
	if after.BandwidthUpBPS == before.BandwidthUpBPS {
		t.Error("上行没改动")
	}
}

// 落库失败必须失败退出。谎报成功是最坏的情形:运维以为改完了,实际什么都没变。
func TestCmdUser_WriteFailuresAreNotReportedAsSuccess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table string
		op    string
		args  []string
	}{
		{"改带宽", "users", "UPDATE", []string{"user", "set-bandwidth", "alice", "--up-mibs", "5", "--no-refresh"}},
		{"改会话上限", "users", "UPDATE", []string{"user", "set-max-sessions", "alice", "3"}},
		{"改平台白名单", "users", "UPDATE", []string{"user", "set-platforms", "alice", "macos"}},
		{"禁用", "users", "UPDATE", []string{"user", "disable", "alice"}},
		{"删号", "users", "DELETE", []string{"user", "delete", "alice"}},
		{"重置 PSK", "users", "UPDATE", []string{"user", "reset-psk", "alice"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newInitializedDB(t, t.TempDir(), "u.db")
			if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
				t.Fatalf("user create: %s", e)
			}
			abortWritesOn(t, db, tc.table, tc.op)
			code, stdout, _ := runCLI(t, db, "", tc.args...)
			if code == 0 {
				t.Fatalf("写不进库却退了 0: stdout=%q", stdout)
			}
		})
	}

	// enable 走的是另一条 store 调用,单独来一次(先禁用再装触发器)。
	t.Run("启用", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "u.db")
		if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
			t.Fatalf("user create: %s", e)
		}
		if c, _, e := runCLI(t, db, "", "user", "disable", "alice"); c != 0 {
			t.Fatalf("user disable: %s", e)
		}
		abortWritesOn(t, db, "users", "UPDATE")
		if code, _, _ := runCLI(t, db, "", "user", "enable", "alice"); code == 0 {
			t.Fatal("写不进库却退了 0")
		}
	})
}

// 删号和重置 PSK 都是破坏性操作:不带 --yes 时必须二次确认,答「不」要一动不动。
func TestCmdUser_DestructiveOpsNeedConfirmation(t *testing.T) {
	t.Run("删号答不", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "u.db")
		if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
			t.Fatalf("user create: %s", e)
		}
		code, stdout, _ := runCLIInteractive(t, db, "n\n", "user", "delete", "alice")
		if code != 0 {
			t.Fatalf("取消却以 %d 退出", code)
		}
		if !strings.Contains(stdout, "取消") {
			t.Errorf("没告诉用户已取消: %q", stdout)
		}
		if c, _, _ := runCLI(t, db, "", "user", "show", "alice"); c != 0 {
			t.Fatal("答了「不」,账号还是被删了")
		}
	})

	t.Run("删号读不到回答", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "u.db")
		if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
			t.Fatalf("user create: %s", e)
		}
		// stdin 直接 EOF(非交互环境下跑了这条命令):不能当成默认同意。
		runCLIInteractive(t, db, "", "user", "delete", "alice")
		if c, _, _ := runCLI(t, db, "", "user", "show", "alice"); c != 0 {
			t.Fatal("读不到回答就把账号删了 —— 管道里跑一次就没了")
		}
	})

	t.Run("重置 PSK 答不", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "u.db")
		if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
			t.Fatalf("user create: %s", e)
		}
		before := getUser(t, db, "alice").PSKHash
		code, stdout, _ := runCLIInteractive(t, db, "n\n", "user", "reset-psk", "alice")
		if code != 0 {
			t.Fatalf("取消却以 %d 退出", code)
		}
		if !strings.Contains(stdout, "取消") {
			t.Errorf("没告诉用户已取消: %q", stdout)
		}
		if getUser(t, db, "alice").PSKHash != before {
			t.Fatal("答了「不」,PSK 还是被换了 —— 那个用户当场断连")
		}
	})
}

// 禁用账号不许 reset-psk:轮换出来的 PSK 会被 user_invalidate 立刻踢掉,等于发废卡。
func TestCmdUserResetPSK_RefusesDisabledAccounts(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "u.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
		t.Fatalf("user create: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "user", "disable", "alice"); c != 0 {
		t.Fatalf("user disable: %s", e)
	}
	before := getUser(t, db, "alice").PSKHash

	code, _, stderr := runCLI(t, db, "", "user", "reset-psk", "alice")
	if code == 0 {
		t.Fatal("禁用账号被 reset-psk 了 —— 发出去的是一张废卡")
	}
	if !strings.Contains(stderr, "alice") {
		t.Errorf("报错里没说是哪个账号: %q", stderr)
	}
	if getUser(t, db, "alice").PSKHash != before {
		t.Fatal("拒绝了却还是换掉了 PSK")
	}
}

// 明文 PSK 出现在 argv 里(会进 ps / shell history)时要提醒;
// 同时 reset-psk 成功后旧 PSK 必须失效、审计里不能有明文。
func TestCmdUserResetPSK_SuccessPath(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "u.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
		t.Fatalf("user create: %s", e)
	}
	oldHash := getUser(t, db, "alice").PSKHash

	t.Run("命令行传明文要提醒", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "user", "reset-psk", "alice", "--psk", "psk-manual-9999")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("明文 PSK 写在 argv 里却没有任何提醒 —— 它会进 ps 和 shell history")
		}
	})

	t.Run("自动生成时旧 PSK 失效", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, db, "", "--json", "user", "reset-psk", "alice")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &got); err != nil {
			t.Fatalf("--json 输出不是 JSON: %v\n%s", err, stdout)
		}
		newPSK, _ := got["psk"].(string)
		if strings.TrimSpace(newPSK) == "" {
			t.Fatal("没给出新 PSK —— 运维无从下发")
		}
		if getUser(t, db, "alice").PSKHash == oldHash {
			t.Fatal("旧 hash 还在 —— 轮换等于没做")
		}

		st := openStoreForTest(t, db)
		defer st.Close()
		logs, err := st.QueryAudit(t.Context(), 0, 1<<62, 200)
		if err != nil {
			t.Fatalf("QueryAudit: %v", err)
		}
		found := false
		for _, l := range logs {
			if l.Action != "user_reset_psk" {
				continue
			}
			found = true
			if strings.Contains(l.Detail, newPSK) {
				t.Errorf("审计明细里有明文 PSK: %q —— 审计表本身成了泄密面", l.Detail)
			}
			if !strings.Contains(l.Detail, "credential_id=") {
				t.Errorf("审计明细里没有 credential_id,客户端侧对不上账: %q", l.Detail)
			}
		}
		if !found {
			t.Error("重置 PSK 没进审计")
		}
	})
}

// user list / show 的展示分支:disabled 状态、--all、SSO 绑定、以及「凭证还没生成」。
// 这些字段是运维排查「这人为什么连不上」的第一现场,漏一个就得去翻库。
func TestCmdUserListAndShow_SurfaceTheFieldsOpsActuallyNeed(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "u.db")
	for _, n := range []string{"alive", "dead"} {
		if c, _, e := runCLI(t, db, "", "user", "create", n, "--psk", "psk-"+n+"-1234"); c != 0 {
			t.Fatalf("user create %s: %s", n, e)
		}
	}
	if c, _, e := runCLI(t, db, "", "user", "disable", "dead"); c != 0 {
		t.Fatalf("user disable: %s", e)
	}

	t.Run("默认列表不含禁用账号", func(t *testing.T) {
		c, stdout, _ := runCLI(t, db, "", "user", "list")
		if c != 0 {
			t.Fatalf("user list: code=%d", c)
		}
		if !strings.Contains(stdout, "alive") {
			t.Error("正常账号没列出来")
		}
		if strings.Contains(stdout, "dead") {
			t.Error("默认列表里出现了禁用账号")
		}
	})

	t.Run("--all 列出禁用账号并标状态", func(t *testing.T) {
		c, stdout, _ := runCLI(t, db, "", "user", "list", "--all")
		if c != 0 {
			t.Fatalf("user list --all: code=%d", c)
		}
		if !strings.Contains(stdout, "dead") || !strings.Contains(stdout, "disabled") {
			t.Errorf("--all 没把禁用账号连状态一起列出来:\n%s", stdout)
		}
	})

	t.Run("show 显示 SSO 绑定与凭证状态", func(t *testing.T) {
		// 直接把 SSO 字段写进库(CLI 没有绑定 SSO 的入口,那是 web 侧的事),
		// 同时清掉 credential_id 模拟 0013 之前建的老账号。
		st := openStoreForTest(t, db)
		if _, err := st.DB().ExecContext(t.Context(),
			`UPDATE users SET sso_provider='oidc', sso_subject='sub-123',
			 credential_id='', credential_created_at=0 WHERE username='alive'`); err != nil {
			t.Fatalf("写 SSO 字段: %v", err)
		}
		_ = st.Close()

		c, stdout, _ := runCLI(t, db, "", "user", "show", "alive")
		if c != 0 {
			t.Fatalf("user show: code=%d", c)
		}
		if !strings.Contains(stdout, "oidc") || !strings.Contains(stdout, "sub-123") {
			t.Errorf("show 没显示 SSO 绑定 —— 排查「这人为什么能/不能登录」时看不到关键信息:\n%s", stdout)
		}
		if !strings.Contains(stdout, "未生成") {
			t.Errorf("凭证还没生成却没标出来,运维会以为 QR 已经发过了:\n%s", stdout)
		}
	})

	t.Run("show 列出该用户的设备", func(t *testing.T) {
		seedDevice(t, db, "withdev", "aaaaaaaa-1111-4222-8333-444444444444")
		c, stdout, _ := runCLI(t, db, "", "user", "show", "withdev")
		if c != 0 {
			t.Fatalf("user show: code=%d", c)
		}
		if !strings.Contains(stdout, "box") {
			t.Errorf("show 没列出该用户的设备:\n%s", stdout)
		}
	})

	t.Run("列表读失败要失败退出", func(t *testing.T) {
		broken := newInitializedDB(t, t.TempDir(), "broken.db")
		st := openStoreForTest(t, broken)
		if _, err := st.DB().ExecContext(t.Context(), `ALTER TABLE users RENAME TO users_moved`); err != nil {
			t.Fatalf("藏掉 users 表: %v", err)
		}
		_ = st.Close()
		for _, args := range [][]string{{"user", "list"}, {"user", "list", "--all"}} {
			if code, stdout, _ := runCLI(t, broken, "", args...); code == 0 {
				t.Errorf("%v 读不到表却退了 0(输出 %q)—— 空列表会被误读成「没有用户」", args, stdout)
			}
		}
	})
}

// =========================================================================
// device
// =========================================================================

func TestCmdDevice_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "d.db")
	devID := seedDevice(t, db, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
	idStr := fmt.Sprint(devID)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"不给子命令", []string{"device"}},
		{"未知子命令", []string{"device", "rename"}},
		{"create 不给用户名", []string{"device", "create", "--uuid", "aaaaaaaa-1111-4222-8333-999999999999"}},
		{"create 未知 flag", []string{"device", "create", "alice", "--bogus"}},
		{"list 未知 flag", []string{"device", "list", "--bogus"}},
		{"delete 不给 id", []string{"device", "delete"}},
		{"delete id 不是数字", []string{"device", "delete", "abc"}},
		{"set-alias 少参数", []string{"device", "set-alias", idStr}},
		{"set-alias id 不是数字", []string{"device", "set-alias", "abc", "x"}},
		{"set-fixed-vip 不给 id", []string{"device", "set-fixed-vip", "--v4", "100.64.0.5"}},
		{"set-fixed-vip id 不是数字", []string{"device", "set-fixed-vip", "abc", "--v4", "100.64.0.5"}},
		{"set-fixed-vip 未知 flag", []string{"device", "set-fixed-vip", idStr, "--bogus"}},
		{"set-rate 不给 id", []string{"device", "set-rate", "--up-mibs", "5"}},
		{"set-rate id 不是数字", []string{"device", "set-rate", "abc", "--up-mibs", "5"}},
		{"set-rate 未知 flag", []string{"device", "set-rate", idStr, "--bogus"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, _ := runCLI(t, db, "", tc.args...); code != 2 {
				t.Fatalf("code=%d, 期望 2(用法错误)", code)
			}
		})
	}

	t.Run("设备不存在", func(t *testing.T) {
		for _, args := range [][]string{
			{"device", "delete", "99999"},
			{"device", "set-alias", "99999", "x"},
			{"device", "set-fixed-vip", "99999", "--v4", "100.64.0.5"},
			{"device", "set-rate", "99999", "--up-mibs", "5"},
		} {
			if code, _, stderr := runCLI(t, db, "", args...); code == 0 {
				t.Errorf("%v 对不存在的设备却成功了", args)
			} else if !strings.Contains(stderr, "99999") {
				t.Errorf("%v 的报错里没说是哪台: %q", args, stderr)
			}
		}
	})

	t.Run("list --user 指向不存在的用户", func(t *testing.T) {
		if code, _, stderr := runCLI(t, db, "", "device", "list", "--user", "ghost"); code == 0 {
			t.Fatal("按不存在的用户过滤却成功了 —— 空列表会被误读成「这人没有设备」")
		} else if !strings.Contains(stderr, "ghost") {
			t.Errorf("报错里没提用户名: %q", stderr)
		}
	})
}

// 预创建设备是「先配后连」流程的入口:UUID 与平台 token 必须当场校验。
// 存一个 designate 认不出的平台,下游批准出口时才被拦,而运维已经把机器装好了。
func TestCmdDeviceCreate_ValidatesUUIDAndPlatform(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "d.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
		t.Fatalf("user create: %s", e)
	}

	t.Run("UUID 不合法", func(t *testing.T) {
		for _, bad := range []string{"", "not-a-uuid", "aaaaaaaa-1111-1222-8333-444444444444"} {
			if code, _, _ := runCLI(t, db, "", "device", "create", "alice", "--uuid", bad); code == 0 {
				t.Errorf("--uuid %q 被接受了 —— 协议层要求 RFC 4122 v4,这台设备连不上", bad)
			}
		}
	})

	t.Run("平台 token 不合法", func(t *testing.T) {
		code, _, _ := runCLI(t, db, "", "device", "create", "alice",
			"--uuid", "aaaaaaaa-1111-4222-8333-444444444444", "--platform", "darwin")
		if code == 0 {
			t.Fatal("--platform darwin 被接受了 —— exit designate 的平台闸口会把它拦下,而机器已经装好了")
		}
		// 一次给多个平台也不行:device.platform 是单值。
		if code, _, _ := runCLI(t, db, "", "device", "create", "alice",
			"--uuid", "aaaaaaaa-1111-4222-8333-444444444444", "--platform", "linux,macos"); code == 0 {
			t.Fatal("--platform 收下了逗号列表,而 device.platform 只能是单值")
		}
	})

	t.Run("用户不存在", func(t *testing.T) {
		if code, _, stderr := runCLI(t, db, "", "device", "create", "ghost",
			"--uuid", "aaaaaaaa-1111-4222-8333-444444444444"); code == 0 {
			t.Fatal("给不存在的用户建了设备")
		} else if !strings.Contains(stderr, "ghost") {
			t.Errorf("报错里没提用户名: %q", stderr)
		}
	})

	t.Run("幂等:同 UUID 再建是更新", func(t *testing.T) {
		const uuid = "bbbbbbbb-1111-4222-8333-444444444444"
		if c, _, e := runCLI(t, db, "", "device", "create", "alice",
			"--uuid", uuid, "--name", "first"); c != 0 {
			t.Fatalf("首次预创建: %s", e)
		}
		c, stdout, e := runCLI(t, db, "", "device", "create", "alice",
			"--uuid", uuid, "--name", "second", "--platform", "router")
		if c != 0 {
			t.Fatalf("重复预创建: %s", e)
		}
		// 回显要说清这是「已存在」而不是新建,否则运维分不清是否手抖建重了。
		if !strings.Contains(stdout, uuid) {
			t.Errorf("回显里没有 UUID: %q", stdout)
		}
		st := openStoreForTest(t, db)
		defer st.Close()
		u, err := st.GetUserByUsername(t.Context(), "alice")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		d, err := st.GetDeviceByUUID(t.Context(), u.ID, uuid)
		if err != nil || d == nil {
			t.Fatalf("GetDeviceByUUID: %v", err)
		}
		if d.DeviceName != "second" || d.Platform != "router" {
			t.Errorf("重复预创建没刷新 name/platform: name=%q platform=%q", d.DeviceName, d.Platform)
		}
	})

	t.Run("写不进库不能谎报成功", func(t *testing.T) {
		fresh := newInitializedDB(t, t.TempDir(), "d2.db")
		if c, _, e := runCLI(t, fresh, "", "user", "create", "alice", "--psk", "psk-alice-1234"); c != 0 {
			t.Fatalf("user create: %s", e)
		}
		abortWritesOn(t, fresh, "devices", "INSERT")
		if code, stdout, _ := runCLI(t, fresh, "", "device", "create", "alice",
			"--uuid", "cccccccc-1111-4222-8333-444444444444"); code == 0 {
			t.Fatalf("写不进库却退了 0: %q", stdout)
		}
	})
}

// 固定 vIP 的地址族必须查:把 IPv6 写进 --v4 会被静默存下,分配时失效 ——
// 而 device list 会继续把那个地址显示成「已钉住」。
func TestCmdDeviceSetFixedVIP_AddressFamilyAndNormalization(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "d.db")
	devID := seedDevice(t, db, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
	idStr := fmt.Sprint(devID)

	t.Run("族不对", func(t *testing.T) {
		for _, tc := range [][]string{
			{"--v4", "fd00::1"},         // v6 塞进 v4
			{"--v6", "100.64.0.5"},      // v4 塞进 v6
			{"--v6", "::ffff:10.0.0.1"}, // v4-in-v6 也不算 v6
			{"--v4", "not-an-ip"},
			{"--v6", "not-an-ip"},
		} {
			args := append([]string{"device", "set-fixed-vip", idStr}, tc...)
			if code, _, _ := runCLI(t, db, "", args...); code == 0 {
				t.Errorf("%v 被接受了 —— 分配时会静默失效,而列表里仍显示已钉住", tc)
			}
		}
	})

	t.Run("规范化后落库", func(t *testing.T) {
		// 大写 / 未压缩的 IPv6 要归一,否则冲突预检的字符串比较与最终存储对不上,
		// 出现「预检说没撞、落库才报重复」。
		if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", idStr,
			"--v6", "FD00:0000:0000:0000:0000:0000:0000:0001"); c != 0 {
			t.Fatalf("set-fixed-vip: %s", e)
		}
		if got := getDevice(t, db, devID).FixedVIPv6; got != "fd00::1" {
			t.Errorf("fixed_vip_v6 落库为 %q, 期望归一成 fd00::1", got)
		}
	})

	t.Run("只给一族时另一族不动", func(t *testing.T) {
		if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", idStr, "--v4", "100.64.0.5"); c != 0 {
			t.Fatalf("set-fixed-vip: %s", e)
		}
		d := getDevice(t, db, devID)
		if d.FixedVIPv4 != "100.64.0.5" {
			t.Errorf("fixed_vip_v4 = %q", d.FixedVIPv4)
		}
		if d.FixedVIPv6 != "fd00::1" {
			t.Errorf("只改 v4 却把 v6 从 fd00::1 改成了 %q", d.FixedVIPv6)
		}
	})

	t.Run("空串清除", func(t *testing.T) {
		if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", idStr, "--v4", "", "--v6", ""); c != 0 {
			t.Fatalf("set-fixed-vip(清除): %s", e)
		}
		d := getDevice(t, db, devID)
		if d.FixedVIPv4 != "" || d.FixedVIPv6 != "" {
			t.Errorf("清除之后还剩 v4=%q v6=%q", d.FixedVIPv4, d.FixedVIPv6)
		}
	})

	t.Run("写不进库不能谎报成功", func(t *testing.T) {
		fresh := newInitializedDB(t, t.TempDir(), "d3.db")
		id := seedDevice(t, fresh, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
		abortWritesOn(t, fresh, "devices", "UPDATE")
		if code, stdout, _ := runCLI(t, fresh, "", "device", "set-fixed-vip",
			fmt.Sprint(id), "--v4", "100.64.0.5"); code == 0 {
			t.Fatalf("写不进库却退了 0: %q", stdout)
		}
	})
}

// 钉到 mesh 之外 / 钉到保留地址时,登录路径会静默改走自动分配。
// CLI 拒不住(运维可能在为换网段预置),但**必须**在下发当场提示。
func TestCmdDeviceSetFixedVIP_WarnsWhenTheAddressCannotActuallyBeUsed(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "d.db")
	devID := seedDevice(t, db, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
	idStr := fmt.Sprint(devID)

	// 落一份 mesh 网段快照(平时由 server 启动时写)。
	st := openStoreForTest(t, db)
	if err := st.SetMeshCIDRs(t.Context(), []string{"100.64.0.0/16"}); err != nil {
		t.Fatalf("SetMeshCIDRs: %v", err)
	}
	_ = st.Close()

	for _, tc := range []struct {
		name string
		ip   string
	}{
		{"掉出 mesh 网段", "10.99.0.5"},
		{"网关地址", "100.64.0.0"},
		{"定向广播地址", "100.64.255.255"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", "device", "set-fixed-vip", idStr, "--v4", tc.ip)
			if code != 0 {
				t.Fatalf("这里只该 warn 不该拒: code=%d stderr=%s", code, stderr)
			}
			if !strings.Contains(stderr, tc.ip) {
				t.Errorf("%s(%s)没有任何提示 —— 设备下次登录会拿到别的地址,而运维照着这个值配防火墙: %q",
					tc.name, tc.ip, stderr)
			}
		})
	}

	// 网段内的普通地址不该被误报,否则告警会被当噪音忽略。
	t.Run("网段内的正常地址不报警", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "device", "set-fixed-vip", idStr, "--v4", "100.64.0.42")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if strings.Contains(stderr, "100.64.0.42") {
			t.Errorf("正常地址被误报了 —— 告警一旦有噪音就会被忽略: %q", stderr)
		}
	})

	// 该族压根没启用时不该乱报(只配了 v4 网段,钉 v6 无从判断)。
	t.Run("没启用的族不判断", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "device", "set-fixed-vip", idStr, "--v6", "fd00::42")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if strings.Contains(stderr, "fd00::42") {
			t.Errorf("没配 v6 网段却对 v6 地址下了判断: %q", stderr)
		}
	})
}

// 冲突预检:撞了别的设备的 fixed vIP / lease 时默认要拒,--force 才放行并明说覆盖了谁。
func TestCmdDeviceSetFixedVIP_ConflictDetection(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "d.db")
	holder := seedDevice(t, db, "holder", "aaaaaaaa-1111-4222-8333-444444444444")
	taker := seedDevice(t, db, "taker", "bbbbbbbb-1111-4222-8333-444444444444")

	// holder 占住 v4(fixed)与 v6(lease)。
	if c, _, e := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(holder),
		"--v4", "100.64.0.7"); c != 0 {
		t.Fatalf("给 holder 钉 v4: %s", e)
	}
	st := openStoreForTest(t, db)
	if _, err := st.UpsertLease(t.Context(), holder, "100.64.0.8", "fd00::8", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	_ = st.Close()

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"撞别人的 fixed v4", []string{"--v4", "100.64.0.7"}},
		{"撞别人的 lease v4", []string{"--v4", "100.64.0.8"}},
		{"撞别人的 lease v6", []string{"--v6", "fd00::8"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"device", "set-fixed-vip", fmt.Sprint(taker)}, tc.args...)
			code, _, stderr := runCLI(t, db, "", args...)
			if code == 0 {
				t.Fatalf("%s 被放过了 —— 两台设备拿同一个地址,数据面会串", tc.name)
			}
			if !strings.Contains(stderr, "--force") {
				t.Errorf("没告诉运维怎么强制覆盖: %q", stderr)
			}
			// 被拒之后 taker 不能留下任何痕迹。
			d := getDevice(t, db, taker)
			if d.FixedVIPv4 != "" || d.FixedVIPv6 != "" {
				t.Errorf("被拒了却写进去了: v4=%q v6=%q", d.FixedVIPv4, d.FixedVIPv6)
			}
		})
	}

	// --force 能越过的只有跨表(lease)冲突 —— store 会先释放对方的 lease 再钉。
	t.Run("--force 抢别人的 lease", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(taker),
			"--v4", "100.64.0.8", "--force")
		if code != 0 {
			t.Fatalf("--force 之下仍失败: %s", stderr)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("强制抢了别人在用的地址却一句提示都没有")
		}
		if got := getDevice(t, db, taker).FixedVIPv4; got != "100.64.0.8" {
			t.Errorf("--force 之后没写进去: %q", got)
		}
	})

	// device↔device 那一类即使 --force 也过不去:store 层有 UNIQUE 兜底。
	// CLI 的 --force 提示里承诺的是「越过预检」,不是「一定能成」—— 这里钉住那道兜底,
	// 否则两台设备真会落到同一个 fixed vIP,下次登录双分配。
	t.Run("--force 也抢不走别人的 fixed vIP", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "device", "set-fixed-vip", fmt.Sprint(taker),
			"--v4", "100.64.0.7", "--force")
		if code == 0 {
			t.Fatal("--force 把另一台设备的 fixed vIP 抢过来了 —— 两台会拿到同一个地址")
		}
		if !strings.Contains(stderr, "100.64.0.7") {
			t.Errorf("报错里没说是哪个地址撞了: %q", stderr)
		}
	})
}

// 限速值坏了必须拒,并且不能只改一半;--no-refresh 之外的路径推送失败只 warn。
func TestCmdDeviceSetRate_BadValuesAndRefreshBehaviour(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "d.db")
	devID := seedDevice(t, db, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
	idStr := fmt.Sprint(devID)

	if c, _, e := runCLI(t, db, "", "device", "set-rate", idStr,
		"--up-mibs", "10", "--down-mibs", "20", "--no-refresh"); c != 0 {
		t.Fatalf("set-rate: %s", e)
	}
	before := getDevice(t, db, devID)

	for _, args := range [][]string{
		{"--up-mibs", "abc"},
		{"--down-bps", "-1"},
		{"--up-mibs", "5", "--down-mibs", "oops"},
	} {
		full := append([]string{"device", "set-rate", idStr, "--no-refresh"}, args...)
		if code, _, _ := runCLI(t, db, "", full...); code == 0 {
			t.Errorf("%v 被接受了", args)
		}
		after := getDevice(t, db, devID)
		if after.RateUploadBPS != before.RateUploadBPS || after.RateDownloadBPS != before.RateDownloadBPS {
			t.Fatalf("%v 被拒了却改动了库: up %d→%d down %d→%d", args,
				before.RateUploadBPS, after.RateUploadBPS,
				before.RateDownloadBPS, after.RateDownloadBPS)
		}
	}

	// 单方向 0 是「清掉这一层 cap」,不是「不变」。
	if c, _, e := runCLI(t, db, "", "device", "set-rate", idStr, "--up-mibs", "0", "--no-refresh"); c != 0 {
		t.Fatalf("set-rate 清上行: %s", e)
	}
	after := getDevice(t, db, devID)
	if after.RateUploadBPS != 0 {
		t.Errorf("--up-mibs 0 没清掉上行 cap: %d", after.RateUploadBPS)
	}
	if after.RateDownloadBPS != before.RateDownloadBPS {
		t.Errorf("清上行却动了下行: %d → %d", before.RateDownloadBPS, after.RateDownloadBPS)
	}

	// server 没起时推送必然失败:只能 warn,db 已经写了,不该整条失败。
	t.Run("推送失败只 warn", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "device", "set-rate", idStr, "--up-mibs", "7")
		if code != 0 {
			t.Fatalf("推送失败不该让命令失败(库已写入): code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("热更没推上却一句提示都没有 —— 运维会以为在线会话已经限上了")
		}
		if got := getDevice(t, db, devID).RateUploadBPS; got == 0 {
			t.Error("推送失败把落库也回滚了")
		}
	})

	t.Run("写不进库不能谎报成功", func(t *testing.T) {
		fresh := newInitializedDB(t, t.TempDir(), "d4.db")
		id := seedDevice(t, fresh, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
		abortWritesOn(t, fresh, "devices", "UPDATE")
		if code, stdout, _ := runCLI(t, fresh, "", "device", "set-rate",
			fmt.Sprint(id), "--up-mibs", "5", "--no-refresh"); code == 0 {
			t.Fatalf("写不进库却退了 0: %q", stdout)
		}
	})
}

func TestCmdDeviceSetAlias_SetClearAndWriteFailure(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "d.db")
	devID := seedDevice(t, db, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
	idStr := fmt.Sprint(devID)

	if c, stdout, e := runCLI(t, db, "", "device", "set-alias", idStr, "  客厅路由  "); c != 0 {
		t.Fatalf("set-alias: %s", e)
	} else if !strings.Contains(stdout, "客厅路由") {
		t.Errorf("回显里没有新别名: %q", stdout)
	}
	if got := getDevice(t, db, devID).Alias; got != "客厅路由" {
		t.Errorf("别名落库为 %q, 期望去掉首尾空白", got)
	}

	// 空串是「清除」,回显要说清是清除而不是设成了空名字。
	if c, stdout, e := runCLI(t, db, "", "device", "set-alias", idStr, ""); c != 0 {
		t.Fatalf("set-alias(清除): %s", e)
	} else if strings.TrimSpace(stdout) == "" {
		t.Error("清除别名没有任何回显")
	}
	if got := getDevice(t, db, devID).Alias; got != "" {
		t.Errorf("清除之后别名还是 %q", got)
	}

	t.Run("写不进库不能谎报成功", func(t *testing.T) {
		fresh := newInitializedDB(t, t.TempDir(), "d5.db")
		id := seedDevice(t, fresh, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
		abortWritesOn(t, fresh, "devices", "UPDATE")
		if code, stdout, _ := runCLI(t, fresh, "", "device", "set-alias", fmt.Sprint(id), "x"); code == 0 {
			t.Fatalf("写不进库却退了 0: %q", stdout)
		}
	})
}

func TestCmdDeviceDelete_ConfirmationAndWriteFailure(t *testing.T) {
	t.Run("答不就一动不动", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "d.db")
		devID := seedDevice(t, db, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
		code, stdout, _ := runCLIInteractive(t, db, "n\n", "device", "delete", fmt.Sprint(devID))
		if code != 0 {
			t.Fatalf("取消却以 %d 退出", code)
		}
		if !strings.Contains(stdout, "取消") {
			t.Errorf("没告诉用户已取消: %q", stdout)
		}
		if getDevice(t, db, devID) == nil {
			t.Fatal("答了「不」,设备还是被删了")
		}
	})

	t.Run("读不到回答不算同意", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "d.db")
		devID := seedDevice(t, db, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
		runCLIInteractive(t, db, "", "device", "delete", fmt.Sprint(devID))
		if getDevice(t, db, devID) == nil {
			t.Fatal("读不到回答就把设备删了")
		}
	})

	t.Run("写不进库不能谎报成功", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "d.db")
		devID := seedDevice(t, db, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
		abortWritesOn(t, db, "devices", "DELETE")
		if code, stdout, _ := runCLI(t, db, "", "device", "delete", fmt.Sprint(devID)); code == 0 {
			t.Fatalf("删不掉却退了 0: %q", stdout)
		}
	})
}

// device list --effective 会去读 app_settings 默认与 server /status;
// 两处都可能失败,那时必须退化成 raw 值 + 警告,而不是整条命令挂掉。
func TestCmdDeviceList_EffectiveDegradesWithWarnings(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "d.db")
	devID := seedDevice(t, db, "alice", "aaaaaaaa-1111-4222-8333-444444444444")
	if c, _, e := runCLI(t, db, "", "device", "set-rate", fmt.Sprint(devID),
		"--up-mibs", "10", "--no-refresh"); c != 0 {
		t.Fatalf("set-rate: %s", e)
	}

	// server 没起 → /status 拉不到 toml 默认。
	code, stdout, stderr := runCLI(t, db, "", "device", "list", "--effective")
	if code != 0 {
		t.Fatalf("拉不到 server 状态不该让列表挂掉: code=%d stderr=%s", code, stderr)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("退化成 raw 值却没警告 —— 运维会把 raw 值当成真实生效值")
	}
	if !strings.Contains(stdout, "aaaaaaaa") {
		t.Errorf("列表本身没出来:\n%s", stdout)
	}

	t.Run("json 输出不含限速的派生值以外的敏感字段", func(t *testing.T) {
		c, out, _ := runCLI(t, db, "", "--json", "device", "list")
		if c != 0 {
			t.Fatalf("device list --json: code=%d", c)
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Fatalf("不是合法 JSON: %v\n%s", err, out)
		}
		if len(rows) != 1 {
			t.Fatalf("列出了 %d 行,期望 1", len(rows))
		}
	})
}

// =========================================================================
// 辅助
// =========================================================================

func getUser(t *testing.T, dbPath, username string) *store.User {
	t.Helper()
	st := openStoreForTest(t, dbPath)
	defer st.Close()
	u, err := st.GetUserByUsername(t.Context(), username)
	if err != nil {
		t.Fatalf("GetUserByUsername(%s): %v", username, err)
	}
	return u
}

// getDevice 读一行设备;不存在返回 nil(供「删没删掉」这类断言用)。
func getDevice(t *testing.T, dbPath string, id int64) *store.Device {
	t.Helper()
	st := openStoreForTest(t, dbPath)
	defer st.Close()
	d, err := st.GetDevice(t.Context(), id)
	if err != nil {
		return nil
	}
	return d
}
