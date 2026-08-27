package main

// cmd_setting_guards_test.go(第二十二轮)—— `setting` 子命令族的拒绝面与副作用。
//
// 这条命令直接改的是 app_settings 表,而其中几行是**数据面每个包都要看**的开关
// (acl_default_action / mesh_enabled / rate_default_*)。这里最危险的不是写错值,
// 而是三类「看着成功了其实没生效」:
//
//   - 系统自管的 key(server_id 之类)被手改 → 与运行态分裂,现象千奇百怪;
//   - 打错 key(rate_defualt_upload_bps)→ 原样落库、照打 "written:",从此静静躺着;
//   - 值写进库了但没通知 server → 库里显示限速 8MiB,在线会话仍全速跑。

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// =========================================================================
// 用法与分派
// =========================================================================

func TestCmdSetting_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "s.db")

	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"不给子命令", []string{"setting"}, 2},
		{"未知子命令", []string{"setting", "frobnicate"}, 2},
		{"get 不给 key", []string{"setting", "get"}, 2},
		{"get 给两个 key", []string{"setting", "get", "a", "b"}, 2},
		{"set 只给 key", []string{"setting", "set", "advertised_host"}, 2},
		{"set 给三个参数", []string{"setting", "set", "a", "b", "c"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := runCLI(t, db, "", tc.args...)
			if code != tc.want {
				t.Fatalf("code=%d, 期望 %d", code, tc.want)
			}
		})
	}

	t.Run("读一个没写过的 key 要报错而不是打空行", func(t *testing.T) {
		code, stdout, _ := runCLI(t, db, "", "setting", "get", "never_written_key")
		if code == 0 {
			t.Fatalf("不存在的 key 却成功了,输出 %q", stdout)
		}
		if strings.TrimSpace(stdout) != "" {
			t.Errorf("不存在的 key 还打了东西到 stdout: %q —— 脚本会把它当值用", stdout)
		}
	})
}

// =========================================================================
// set 的三层闸门
// =========================================================================

// 系统自管的 key 必须硬拒。手改这些会让库里的值与 server 运行态分裂,
// 而分裂之后的现象(证书对不上、客户端连不上)完全指不回这次修改。
func TestCmdSettingSet_RefusesSystemManagedKeys(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "s.db")
	if len(systemManagedSettingKeys) == 0 {
		t.Skip("没有系统自管 key")
	}
	for key := range systemManagedSettingKeys {
		code, _, stderr := runCLI(t, db, "", "setting", "set", key, "whatever")
		if code == 0 {
			t.Errorf("%s 是系统自管的,却被手改成功了", key)
		}
		if !strings.Contains(stderr, key) {
			t.Errorf("%s: 拒绝信息里没提到这个 key: %q", key, stderr)
		}
	}
}

// magic_suffix 最容易被误当成「改后缀的开关」——运行期只认 config.toml，DB 写了零效果。
// 硬拒之外，指路必须点到真正的入口（config.toml / set-magic-suffix.sh），否则运维只会换个拼写再试。
func TestCmdSettingSet_MagicSuffixBlockedPointsToConfig(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "s.db")
	code, _, stderr := runCLI(t, db, "", "setting", "set", "magic_suffix", "nanotun")
	if code == 0 {
		t.Fatal("magic_suffix 被手改成功了 —— 它是 config.toml 的东西，DB 写了也没用")
	}
	// 指路要提到真正的入口（两种语言都含这两个字面量），别让人以为换个拼写就行。
	if !strings.Contains(stderr, "config.toml") || !strings.Contains(stderr, "set-magic-suffix") {
		t.Errorf("拒绝信息没指向 config.toml / set-magic-suffix.sh: %q", stderr)
	}
	// 拒了就不能落库 —— 留一行没人读的脏值比拒绝失败更误导。
	if code, out, _ := runCLI(t, db, "", "setting", "get", "magic_suffix"); code == 0 &&
		strings.Contains(out, "nanotun") {
		t.Errorf("被拒的 magic_suffix 还是进库了: %q", out)
	}
}

// 有校验器的 key 要拒坏值。这几个 key 一旦写进垃圾,数据面读取时的兜底行为
// 各不相同(有的 fail-open),排查时几乎不会有人想到去看 app_settings。
func TestCmdSettingSet_ValidatedKeysRejectGarbage(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "s.db")
	for _, tc := range []struct{ key, bad string }{
		{"acl_default_action", "maybe"},
		{"mesh_enabled", "sure"},
		{"rate_default_upload_bps", "-1"},
		{"rate_default_download_bps", "很快"},
		{"advertised_host", strings.Repeat("a", 4096)},
		{"server_dial_host", "not a host!!"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", "setting", "set", tc.key, tc.bad)
			if code == 0 {
				t.Fatalf("%s=%q 被接受了", tc.key, tc.bad)
			}
			if !strings.Contains(stderr, tc.key) {
				t.Errorf("错误信息里没说是哪个 key: %q", stderr)
			}
			// 拒绝了就不能落库 —— 留一行脏值比拒绝失败更难查。
			if code, out, _ := runCLI(t, db, "", "setting", "get", tc.key); code == 0 &&
				strings.Contains(out, strings.TrimSpace(tc.bad)) {
				t.Errorf("被拒的值还是进库了: %q", out)
			}
		})
	}
}

// 通过校验的值要落**规范形**:库里留下 "TRUE" / " Deny " 这种毛刺时,
// 读路径虽然容错,但下一个直接读表的人(或下一版代码)会踩空。
func TestCmdSettingSet_CanonicalizesAcceptedValues(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "s.db")
	for _, tc := range []struct{ key, in, want string }{
		{"acl_default_action", "DENY", "deny"},
		{"acl_default_action", " allow ", "allow"},
		{"mesh_enabled", "TRUE", "true"},
		{"mesh_enabled", "0", "false"},
		{"advertised_host", "  vpn.example.com  ", "vpn.example.com"},
	} {
		t.Run(tc.key+"="+tc.in, func(t *testing.T) {
			if code, _, e := runCLI(t, db, "", "setting", "set", tc.key, tc.in); code != 0 {
				t.Fatalf("code=%d stderr=%s", code, e)
			}
			code, out, _ := runCLI(t, db, "", "setting", "get", tc.key)
			if code != 0 {
				t.Fatalf("回读失败 code=%d", code)
			}
			if strings.TrimSpace(out) != tc.want {
				t.Fatalf("库里存的是 %q,期望规范形 %q", strings.TrimSpace(out), tc.want)
			}
		})
	}

	// mesh_enabled 走到 canonicalize 时值一定已通过校验;万一没有(将来有人
	// 换了校验器),原样返回而不是 panic 或吞掉。
	if got := canonicalizeValidatedSetting("mesh_enabled", "不是布尔"); got != "不是布尔" {
		t.Errorf("解析不了的布尔值被改成了 %q", got)
	}
}

// 打错 key 是最常见的手误,而且原样落库 + 打印 "written:" 会让人以为生效了。
// 必须有一声警告 —— 这是唯一的提示。
func TestCmdSettingSet_UnknownKeyStillWarns(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "s.db")
	code, stdout, stderr := runCLI(t, db, "", "setting", "set", "rate_defualt_upload_bps", "1000")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout+stderr, "rate_defualt_upload_bps") {
		t.Fatalf("打错的 key 没被念出来: stdout=%q stderr=%q", stdout, stderr)
	}
	// 警告要落在 stderr 或输出里能看见的位置,而不是只有一句 "written:"。
	if strings.TrimSpace(stderr) == "" {
		t.Error("打错 key 没有任何警告 —— 运维会以为已生效")
	}
}

// 落库 ≠ 生效:ACL 快照类 key 改完要通知 server;通知不到要给出提示,
// 而不是只打一句 "written:" 就完事。
func TestCmdSettingSet_ACLSnapshotKeysNotifyOrHint(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "s.db")

	t.Run("server 在跑就直接热更", func(t *testing.T) {
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/reload": jsonHandler(`{"ok":true,"what":"acl","rules":3}`)})
		code, _, stderr := runCLISock(t, db, fc.path, "setting", "set", "acl_default_action", "deny")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if !containsAny(fc.requests(), "/reload") {
			t.Fatalf("改了 ACL 快照 key 却没通知 server: %v", fc.requests())
		}
	})

	t.Run("server 不在就提示手动重载", func(t *testing.T) {
		code, _, stderr := runCLISock(t, db, filepath.Join(t.TempDir(), "nope.sock"),
			"setting", "set", "acl_default_action", "allow")
		if code != 0 {
			t.Fatalf("通知不到不该让命令失败: code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Fatal("通知不到却一声不吭 —— 运维会以为已经生效")
		}
	})
}

// 限速三件套:在线会话的限速器是连接上的对象,不推 /rate/refresh 就只是改了行 DB。
func TestCmdSettingSet_RateKeysPushRefresh(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "s.db")
	fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
		"/rate/refresh": jsonHandler(`{"ok":true,"updated":2}`)})

	code, _, stderr := runCLISock(t, db, fc.path,
		"setting", "set", "rate_default_upload_bps", "1048576")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if !containsAny(fc.requests(), "/rate/refresh") {
		t.Fatalf("改了默认限速却没推刷新: %v", fc.requests())
	}
}

// list 要把库里的 key 都列出来 —— 它是运维排查「到底哪个值不对」的第一站。
func TestCmdSettingList_ShowsWhatIsActuallyStored(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "s.db")
	if code, _, e := runCLI(t, db, "", "setting", "set", "advertised_host", "vpn.example.com"); code != 0 {
		t.Fatalf("set: %s", e)
	}
	for _, sub := range []string{"list", "ls"} {
		code, stdout, stderr := runCLI(t, db, "", "setting", sub)
		if code != 0 {
			t.Fatalf("%s: code=%d stderr=%s", sub, code, stderr)
		}
		if !strings.Contains(stdout, "advertised_host") || !strings.Contains(stdout, "vpn.example.com") {
			t.Fatalf("%s 没列出刚写的值:\n%s", sub, stdout)
		}
	}
}

// =========================================================================
// setting rate
// =========================================================================

func TestCmdSettingRate_ShowsChangesAndRefreshes(t *testing.T) {
	dir := t.TempDir()

	t.Run("多余位置参数是用法错误", func(t *testing.T) {
		db := newInitializedDB(t, dir, "pos.db")
		if code, _, _ := runCLI(t, db, "", "setting", "rate", "50"); code != 2 {
			t.Fatalf("code=%d, 期望 2 —— 少个 --up-mibs 的手误必须被指出来", code)
		}
	})

	t.Run("不带 flag 只展示当前值", func(t *testing.T) {
		db := newInitializedDB(t, dir, "show.db")
		code, stdout, stderr := runCLI(t, db, "", "setting", "rate")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Fatal("dry-run 什么也没显示")
		}
	})

	t.Run("坏的速率值要拒", func(t *testing.T) {
		db := newInitializedDB(t, dir, "bad.db")
		for _, args := range [][]string{
			{"setting", "rate", "--up-mibs", "快一点"},
			{"setting", "rate", "--down-bps", "-5"},
			{"setting", "rate", "--burst-kib", "巨大"},
		} {
			if code, _, _ := runCLI(t, db, "", args...); code == 0 {
				t.Errorf("%v 被接受了", args)
			}
		}
	})

	t.Run("改值要落库并推刷新", func(t *testing.T) {
		db := newInitializedDB(t, dir, "set.db")
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/rate/refresh": jsonHandler(`{"ok":true,"updated":1}`)})
		code, stdout, stderr := runCLISock(t, db, fc.path,
			"setting", "rate", "--up-mibs", "8", "--down-mibs", "16")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("改完一句不说,运维无从确认新值")
		}
		if !containsAny(fc.requests(), "/rate/refresh") {
			t.Fatalf("改了默认限速却没推刷新,在线会话仍走旧值: %v", fc.requests())
		}
		st := openStoreForTest(t, db)
		defer st.Close()
		cur, err := st.GetRateDefaults(t.Context())
		if err != nil {
			t.Fatalf("GetRateDefaults: %v", err)
		}
		if cur.UploadBPS != 8*1024*1024 || cur.DownloadBPS != 16*1024*1024 {
			t.Fatalf("落库的值不对: %+v", cur)
		}
	})

	t.Run("值没变也要照推一次刷新", func(t *testing.T) {
		// 库里的值可能是别的路径写进去的(直接改 DB / 迁移种子),那些路径不推刷新。
		// 此时若因「值一致」而什么都不做,运维就卡死在「库里显示限着、数据面全速跑」。
		db := newInitializedDB(t, dir, "same.db")
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/rate/refresh": jsonHandler(`{"ok":true,"updated":1}`)})
		if code, _, e := runCLISock(t, db, fc.path, "setting", "rate", "--up-mibs", "8"); code != 0 {
			t.Fatalf("第一次: %s", e)
		}
		before := len(fc.requests())
		code, stdout, stderr := runCLISock(t, db, fc.path, "setting", "rate", "--up-mibs", "8")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("值没变时一句不说,运维会以为命令没跑")
		}
		if len(fc.requests()) <= before {
			t.Fatalf("值一致就不推刷新了 —— 库与在线会话没法对齐: %v", fc.requests())
		}
	})

	t.Run("--no-refresh 不推,但改了 burst 要提醒", func(t *testing.T) {
		db := newInitializedDB(t, dir, "norefresh.db")
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/rate/refresh": jsonHandler(`{"ok":true}`)})
		code, _, stderr := runCLISock(t, db, fc.path,
			"setting", "rate", "--burst-kib", "512", "--no-refresh")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if len(fc.requests()) != 0 {
			t.Fatalf("--no-refresh 却还是推了: %v", fc.requests())
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("改了 burst 又跳过广播,却没提醒「下次任意刷新才会生效」")
		}
	})

	t.Run("推刷新失败只警告,不回滚已落库的值", func(t *testing.T) {
		db := newInitializedDB(t, dir, "warn.db")
		code, _, stderr := runCLISock(t, db, filepath.Join(t.TempDir(), "nope.sock"),
			"setting", "rate", "--up-mibs", "4")
		if code != 0 {
			t.Fatalf("通知不到不该让命令失败: code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("推不动刷新却一声不吭")
		}
		st := openStoreForTest(t, db)
		defer st.Close()
		cur, _ := st.GetRateDefaults(t.Context())
		if cur.UploadBPS != 4*1024*1024 {
			t.Fatalf("值没落库: %+v", cur)
		}
	})
}

// =========================================================================
// setting probe-dial-host
// =========================================================================

// 这条命令只验证不落库,所以它的**判断**就是全部产出。假阳性(把不可用的
// host 说成可用)最坏:运维照着 set 下去,客户端从此连不上。
func TestCmdSettingProbeDialHost_Verdicts(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "p.db")

	t.Run("不给 host", func(t *testing.T) {
		if code, _, _ := runCLI(t, db, "", "setting", "probe-dial-host"); code != 2 {
			t.Fatal("不给 host 应是用法错误")
		}
	})

	t.Run("给两个 host", func(t *testing.T) {
		if code, _, _ := runCLI(t, db, "", "setting", "probe-dial-host", "a.example.com", "b.example.com"); code != 2 {
			t.Fatal("给两个 host 应是用法错误")
		}
	})

	t.Run("空白 host", func(t *testing.T) {
		if code, _, _ := runCLI(t, db, "", "setting", "probe-dial-host", "   "); code == 0 {
			t.Fatal("空白 host 通过了")
		}
	})

	t.Run("语法就不合法", func(t *testing.T) {
		code, stdout, _ := runCLI(t, db, "", "setting", "probe-dial-host", "not a host!!")
		if code == 0 {
			t.Fatal("语法非法的 host 通过了")
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("没告诉运维是哪一关没过")
		}
	})

	t.Run("字面量 IP + skip-icmp 直接过", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, db, "",
			"setting", "probe-dial-host", "203.0.113.10", "--skip-icmp")
		if code != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("过了却什么也没说")
		}
	})

	t.Run("解析到本机地址要判失败", func(t *testing.T) {
		// DNS 投毒 / 私网 resolver 会把域名解到 127.0.0.1;此时 skip-icmp 绝不能放行,
		// 否则运维照着 set 下去,所有客户端都会去连自己。
		code, stdout, _ := runCLI(t, db, "",
			"setting", "probe-dial-host", "localhost", "--skip-icmp")
		if code == 0 {
			t.Fatalf("解析到本机地址却判通过了: %q", stdout)
		}
	})

	t.Run("解析不出来要判失败", func(t *testing.T) {
		code, stdout, _ := runCLI(t, db, "",
			"setting", "probe-dial-host", "nonexistent.invalid", "--skip-icmp", "--timeout", "5s")
		if code == 0 {
			t.Fatalf("解析不出来的域名却判通过了: %q", stdout)
		}
	})

	t.Run("完整 probe 的失败也要有明确判词", func(t *testing.T) {
		code, stdout, _ := runCLI(t, db, "",
			"setting", "probe-dial-host", "nonexistent.invalid", "--timeout", "5s")
		if code == 0 {
			t.Fatalf("解析不出来的域名却判通过了: %q", stdout)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("失败了却没有判词,运维不知道卡在 DNS 还是 ICMP")
		}
	})
}

// probe 的软失败判词里**不能**夹带 --skip-icmp 那条建议 —— 它得单独放在 hint 里,由调用处
// 决定打不打。
//
// 起因:向导(scripts/setup.sh)也调 probe,而云厂商默认封 ping,所以这条软失败在全新机器上
// 几乎每次都出现。它给的却是一条死路 —— nanotun-setup 没有 --skip-icmp 这个参数,照着敲的人
// 拿到的是 exit 2 加一页用法;而后半句「直接跑 setting set server_dial_host」正是向导下面两行
// 就要替他做的事。紧接着向导自己还会说「地址没填错的话直接继续即可」,两句话互相拆台。
//
// 两条判词合成一个字符串时,调用处就没有余地了 —— 要么连建议一起打,要么连判词一起吞。
// 所以这里锁的是「拆开」这件事本身:建议只能出现在 hint 键里。
func TestProbeICMPSoftFail_AdviceLivesInSeparateHint(t *testing.T) {
	for name, cat := range map[string]map[string]string{"zh": catZH, "en": catEN} {
		t.Run(name, func(t *testing.T) {
			body, ok := cat["setting.probe.icmpSoftFail"]
			if !ok {
				t.Fatal("找不到 setting.probe.icmpSoftFail")
			}
			// 判词本身只说「ICMP 不通」。夹带建议 = 向导里也会照打,而那条建议在向导里不成立。
			if strings.Contains(body, "--skip-icmp") {
				t.Errorf("判词里夹带了 --skip-icmp 的建议:%q\n"+
					"  向导也调 probe,而它没有这个参数(实测 exit 2)。建议要放进 "+
					"setting.probe.icmpSoftFailHint,由调用处按 NANOTUN_SETUP_WIZARD 决定打不打", body)
			}
			hint, ok := cat["setting.probe.icmpSoftFailHint"]
			if !ok {
				t.Fatal("找不到 setting.probe.icmpSoftFailHint —— 建议不该凭空消失,只是换了个键")
			}
			// 反过来也要成立:hint 空了或者不再提这个参数,等于直接敲 CLI 的人失去了唯一的出路。
			if !strings.Contains(hint, "--skip-icmp") {
				t.Errorf("hint 里没提 --skip-icmp:%q —— 直接敲 probe-dial-host 的人就没有出路了", hint)
			}
		})
	}
}
