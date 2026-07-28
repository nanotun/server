package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =========================================================================
// parseGlobalFlags:全局 flag 的三种写法 + env 兜底
//
// 这层解析出错的后果都是「静默指错库」,不是崩溃:`--db-path` 少个值、`--db=` 写成
// `--db =`、env 与 flag 优先级搞反,任何一处都会让命令对着另一个库跑并输出貌似成功的
// 结果。所以这里逐条钉住每种写法解析到哪个字段。
// =========================================================================

// parseFlags 跑一遍 parseGlobalFlags,返回 (剩余参数, opts, err)。
// 显式清掉两个 env,避免宿主环境(开发机常导出 NANOTUN_DB)污染断言。
func parseFlags(t *testing.T, args ...string) ([]string, *globalOpts, error) {
	t.Helper()
	t.Setenv("NANOTUN_DB", "")
	t.Setenv("NANOTUN_LANG", "")
	opts := &globalOpts{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	rest, err := parseGlobalFlags(args, opts)
	return rest, opts, err
}

func TestParseGlobalFlags_AllSpellings(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		check func(t *testing.T, rest []string, o *globalOpts)
	}{
		{"--db-path 分开写", []string{"--db-path", "/tmp/a.db", "user", "list"},
			func(t *testing.T, rest []string, o *globalOpts) {
				if o.dbPath != "/tmp/a.db" {
					t.Errorf("dbPath=%q", o.dbPath)
				}
				if strings.Join(rest, " ") != "user list" {
					t.Errorf("rest=%v —— flag 的值被当成子命令漏出去了", rest)
				}
			}},
		{"--db 简写", []string{"--db", "/tmp/b.db"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if o.dbPath != "/tmp/b.db" {
					t.Errorf("dbPath=%q", o.dbPath)
				}
			}},
		{"--db-path= 等号写法", []string{"--db-path=/tmp/c.db"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if o.dbPath != "/tmp/c.db" {
					t.Errorf("dbPath=%q", o.dbPath)
				}
			}},
		{"--db= 等号写法", []string{"--db=/tmp/d.db"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if o.dbPath != "/tmp/d.db" {
					t.Errorf("dbPath=%q", o.dbPath)
				}
			}},
		{"没给 --db-path 时用默认相对路径", []string{"user", "list"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if o.dbPath != "data/nanotun.db" {
					t.Errorf("默认库路径变了: %q —— install 脚本和文档都按这个写", o.dbPath)
				}
			}},
		{"--json", []string{"--json"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if !o.json {
					t.Error("--json 没解析上")
				}
			}},
		{"--yes", []string{"--yes"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if !o.yes {
					t.Error("--yes 没解析上")
				}
			}},
		{"-y 简写", []string{"-y"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if !o.yes {
					t.Error("-y 没解析上 —— 脚本里全用这个跳过确认")
				}
			}},
		{"--control-socket 分开写", []string{"--control-socket", "/run/x.sock"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if o.controlSocket != "/run/x.sock" {
					t.Errorf("controlSocket=%q", o.controlSocket)
				}
			}},
		{"--control-socket= 等号写法", []string{"--control-socket=/run/y.sock"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if o.controlSocket != "/run/y.sock" {
					t.Errorf("controlSocket=%q", o.controlSocket)
				}
			}},
		{"--lang 分开写", []string{"--lang", "zh"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if o.lang != langZH {
					t.Errorf("lang=%q", o.lang)
				}
			}},
		{"--lang= 等号写法", []string{"--lang=zh"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if o.lang != langZH {
					t.Errorf("lang=%q", o.lang)
				}
			}},
		{"默认语言是英文", []string{"user", "list"},
			func(t *testing.T, _ []string, o *globalOpts) {
				if o.lang != langDefault {
					t.Errorf("lang=%q, 期望默认 %q", o.lang, langDefault)
				}
			}},
		{"未知 flag 原样漏给子命令", []string{"user", "list", "--limit", "5"},
			func(t *testing.T, rest []string, _ *globalOpts) {
				// 全局层故意不用 flag.FlagSet:遇到没声明过的 flag 不能 fail,
				// 否则每加一个子命令 flag 都得在全局层登记一遍。
				if strings.Join(rest, " ") != "user list --limit 5" {
					t.Errorf("rest=%v —— 子命令自己的 flag 被全局层吃掉了", rest)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rest, opts, err := parseFlags(t, tc.args...)
			if err != nil {
				t.Fatalf("parseGlobalFlags(%v): %v", tc.args, err)
			}
			tc.check(t, rest, opts)
		})
	}
}

// 缺值的 flag 必须报错退出,不能把下一个参数(往往是子命令名)悄悄当成值吞掉 ——
// `nanotun-admin --db-path user list` 若不报错,就会去打开名叫 "user" 的库。
func TestParseGlobalFlags_MissingValueIsAnError(t *testing.T) {
	for _, args := range [][]string{
		{"--db-path"},
		{"--db"},
		{"--control-socket"},
		{"--lang"},
	} {
		t.Run(args[0], func(t *testing.T) {
			_, _, err := parseFlags(t, args...)
			if err == nil {
				t.Fatalf("%v 少了值却解析成功", args)
			}
			if !strings.Contains(err.Error(), args[0]) {
				t.Errorf("报错没回显是哪个 flag: %v", err)
			}
		})
	}
}

func TestParseGlobalFlags_BadLangIsRejected(t *testing.T) {
	for _, args := range [][]string{
		{"--lang", "klingon"},
		{"--lang=klingon"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, _, err := parseFlags(t, args...)
			if err == nil {
				t.Fatal("不支持的语言却解析成功了")
			}
			// 报错要同时给出敲错的值和可选集合,否则运维只能猜。
			if !strings.Contains(err.Error(), "klingon") || !strings.Contains(err.Error(), "en") {
				t.Errorf("报错既要回显输入也要列出可选值: %v", err)
			}
		})
	}
}

func TestParseGlobalFlags_EnvFallbacks(t *testing.T) {
	t.Run("NANOTUN_DB 兜底", func(t *testing.T) {
		t.Setenv("NANOTUN_DB", "/env/from-env.db")
		t.Setenv("NANOTUN_LANG", "")
		opts := &globalOpts{}
		if _, err := parseGlobalFlags([]string{"user", "list"}, opts); err != nil {
			t.Fatal(err)
		}
		if opts.dbPath != "/env/from-env.db" {
			t.Errorf("dbPath=%q —— env 没兜上", opts.dbPath)
		}
	})

	t.Run("--db-path 压过 NANOTUN_DB", func(t *testing.T) {
		t.Setenv("NANOTUN_DB", "/env/from-env.db")
		opts := &globalOpts{}
		if _, err := parseGlobalFlags([]string{"--db-path", "/flag/win.db"}, opts); err != nil {
			t.Fatal(err)
		}
		if opts.dbPath != "/flag/win.db" {
			t.Errorf("dbPath=%q —— 显式 flag 必须压过 env", opts.dbPath)
		}
	})

	t.Run("NANOTUN_LANG 兜底", func(t *testing.T) {
		t.Setenv("NANOTUN_LANG", "zh-CN")
		opts := &globalOpts{}
		if _, err := parseGlobalFlags(nil, opts); err != nil {
			t.Fatal(err)
		}
		if opts.lang != langZH {
			t.Errorf("lang=%q —— env 里的 zh-CN 该归一到 zh", opts.lang)
		}
	})

	t.Run("NANOTUN_LANG 写错时静默退回默认", func(t *testing.T) {
		// env 与 flag 在这里故意不同口径:flag 写错要立刻报错(是人在敲),
		// env 写错只退回默认(往往来自继承的 systemd 环境,不该让所有命令都跑不起来)。
		t.Setenv("NANOTUN_LANG", "klingon")
		opts := &globalOpts{}
		if _, err := parseGlobalFlags(nil, opts); err != nil {
			t.Fatalf("env 里语言写错不该让命令失败: %v", err)
		}
		if opts.lang != langDefault {
			t.Errorf("lang=%q, 期望退回 %q", opts.lang, langDefault)
		}
	})

	t.Run("--lang 压过 NANOTUN_LANG", func(t *testing.T) {
		t.Setenv("NANOTUN_LANG", "zh")
		opts := &globalOpts{}
		if _, err := parseGlobalFlags([]string{"--lang", "en"}, opts); err != nil {
			t.Fatal(err)
		}
		if opts.lang != "en" {
			t.Errorf("lang=%q —— 显式 --lang 必须压过 env", opts.lang)
		}
	})
}

// =========================================================================
// help / version / usage
// =========================================================================

func TestRunRoot_HelpAndVersion(t *testing.T) {
	run := func(t *testing.T, lang string, args ...string) (int, string, string) {
		t.Helper()
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		opts := &globalOpts{stdout: stdout, stderr: stderr, stdin: strings.NewReader(""), lang: lang}
		code := runRoot(args, opts)
		return code, stdout.String(), stderr.String()
	}

	// help 的三种写法都要 exit 0 并打到 **stdout** —— `nanotun-admin help | less` 是
	// 最常见的用法,打到 stderr 就什么都看不到。
	for _, a := range []string{"help", "-h", "--help"} {
		t.Run(a, func(t *testing.T) {
			code, stdout, stderr := run(t, langDefault, a)
			if code != 0 {
				t.Fatalf("%s 应 exit 0, got %d", a, code)
			}
			if !strings.Contains(stdout, "USAGE") {
				t.Errorf("%s 没把用法打到 stdout: %q / stderr=%q", a, stdout, stderr)
			}
		})
	}

	for _, a := range []string{"version", "--version"} {
		t.Run(a, func(t *testing.T) {
			code, stdout, _ := run(t, langDefault, a)
			if code != 0 {
				t.Fatalf("%s 应 exit 0, got %d", a, code)
			}
			if !strings.Contains(stdout, "nanotun-admin") || !strings.Contains(stdout, version) {
				t.Errorf("version 输出缺程序名或版本号: %q", stdout)
			}
		})
	}

	t.Run("中英两套 usage 都能出", func(t *testing.T) {
		var en, zh bytes.Buffer
		printUsage(&en, langDefault)
		printUsage(&zh, langZH)
		if en.Len() == 0 || zh.Len() == 0 {
			t.Fatalf("usage 为空: en=%d zh=%d", en.Len(), zh.Len())
		}
		if en.String() == zh.String() {
			t.Error("中英 usage 一模一样 —— 大概哪边的 catalog 没接上")
		}
		// 两边都必须列出所有顶层子命令,否则新加的命令没人知道怎么用。
		for _, sub := range []string{"init", "user", "device", "acl", "backup", "restore", "config"} {
			if !strings.Contains(en.String(), sub) {
				t.Errorf("英文 usage 里没提 %q", sub)
			}
			if !strings.Contains(zh.String(), sub) {
				t.Errorf("中文 usage 里没提 %q", sub)
			}
		}
	})
}

// =========================================================================
// runWithStoreOpts:打不开库时的三条岔路
//
// 这三条都必须「明确说是库的问题」。历史上它们要么静默造空库,要么把
// "no such table" 泄给运维 —— 两种都让人以为是数据问题而不是路径写错。
// =========================================================================

func TestRunWithStore_StatFailureIsNotMistakenForMissing(t *testing.T) {
	// 父目录是个**文件**,os.Stat 给 ENOTDIR(不是 ErrNotExist)。这条岔路要报
	// stat 的真实原因、exit 1;若与「文件不存在」混为一谈会 exit 2 并劝人去跑 init,
	// 而真因是路径中间有个文件。
	dir := t.TempDir()
	notADir := filepath.Join(dir, "plain-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, filepath.Join(notADir, "nested.db"), "", "user", "list")
	if code != 1 {
		t.Fatalf("stat 失败应 exit 1(区别于 not-exist 的 2), got %d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "stat db") {
		t.Errorf("没说清是 stat 挂了: %q", stderr)
	}
	if strings.Contains(stderr, "run `nanotun-admin init`") {
		t.Error("把 stat 失败当成「库不存在」了 —— 会把人引去跑 init,而真因是路径里夹了个文件")
	}
}

func TestRunWithStore_OpenFailureIsReported(t *testing.T) {
	// 库路径指到一个**目录**上:os.Stat 过得去(存在),store.Open 才失败。
	dir := t.TempDir()
	asDir := filepath.Join(dir, "iam-a-dir")
	if err := os.Mkdir(asDir, 0o700); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, asDir, "", "user", "list")
	if code != 1 {
		t.Fatalf("open 失败应 exit 1, got %d stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "open store") || !strings.Contains(stderr, asDir) {
		t.Errorf("报错要同时给出动作和路径: %q", stderr)
	}
}

func TestRunWithStore_NotInitializedVsGarbage(t *testing.T) {
	t.Run("空 SQLite 文件:提示库没 init", func(t *testing.T) {
		// 敲错 --db-path 的老命令会留下 0 表的空库。文件存在 → 过得了 os.Stat;
		// 于是必须靠 schema 判定拦下,否则后面每处读都报 "no such table",
		// 看不出真因是指错了库。
		db := filepath.Join(t.TempDir(), "empty.db")
		if err := os.WriteFile(db, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := runCLI(t, db, "", "user", "list")
		if code != 2 {
			t.Fatalf("空库应 exit 2, got %d stderr=%q", code, stderr)
		}
		if !strings.Contains(stderr, "not initialized") {
			t.Errorf("没提示库未初始化: %q", stderr)
		}
	})

	t.Run("根本不是 SQLite:报 schema 检查失败", func(t *testing.T) {
		// 写满垃圾字节:头 16 字节不是 "SQLite format 3\0",连 schema 都查不了。
		// 这条与上面一条不同 —— 不能劝人跑 init(init 不会覆盖已有文件),
		// 得让人看到「这文件不是库」。
		db := filepath.Join(t.TempDir(), "garbage.db")
		if err := os.WriteFile(db, bytes.Repeat([]byte{0xDE, 0xAD}, 4096), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := runCLI(t, db, "", "user", "list")
		if code == 0 {
			t.Fatal("对着一堆垃圾字节竟然跑成功了")
		}
		if !strings.Contains(stderr, db) {
			t.Errorf("报错里没给出文件路径: %q", stderr)
		}
	})

	t.Run("不存在的库:exit 2 且指向 init", func(t *testing.T) {
		code, _, stderr := runCLI(t, filepath.Join(t.TempDir(), "nope.db"), "", "user", "list")
		if code != 2 {
			t.Fatalf("库不存在应 exit 2, got %d stderr=%q", code, stderr)
		}
		if !strings.Contains(stderr, "db not found") || !strings.Contains(stderr, "init") {
			t.Errorf("既要说没找到,也要给出下一步: %q", stderr)
		}
	})
}

// 非首次部署入口的写子命令不许凭空造库:2026-07-26 实测 `device set-rate`(一个参数
// 都没给)会先在 cwd 下建出完整 schema 的 data/nanotun.db,再打 usage。
func TestSubCanBootstrapDB_OnlyDeploymentEntrypoints(t *testing.T) {
	for _, tc := range []struct {
		subcmd string
		rest   []string
		want   bool
	}{
		{"init", nil, true},
		{"user", []string{"create", "alice"}, true},
		{"user", []string{"list"}, false},
		{"user", nil, false},
		{"device", []string{"set-rate"}, false},
		{"acl", []string{"add"}, false},
		{"setting", []string{"set", "k", "v"}, false},
		{"backup", nil, false},
	} {
		got := subCanBootstrapDB(tc.subcmd, tc.rest)
		if got != tc.want {
			t.Errorf("subCanBootstrapDB(%q, %v)=%v, 期望 %v", tc.subcmd, tc.rest, got, tc.want)
		}
	}
}

// settingRateHasMutation 决定 `setting rate` 走只读还是读写连接:漏判一个写 flag,
// 命令就会在 query_only 连接上撞 SQLITE_READONLY 而不是改速率。
func TestSettingRateHasMutation_AllSpellings(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"--up-mibs", "5"}, true},
		{[]string{"--up-mibs=5"}, true},
		{[]string{"-up-mibs", "5"}, true},
		{[]string{"--down-mibs=0"}, true}, // 清零也是改
		{[]string{"--up-bps=1000"}, true},
		{[]string{"--down-bps=1000"}, true},
		{[]string{"--burst-kib=64"}, true},
		{[]string{"--no-refresh"}, false}, // 只影响是否通知 server,不写库
		{[]string{"--json"}, false},
	} {
		if got := settingRateHasMutation(tc.args); got != tc.want {
			t.Errorf("settingRateHasMutation(%v)=%v, 期望 %v", tc.args, got, tc.want)
		}
	}
}

func TestRouteAndCredentialsReadOnlyClassification(t *testing.T) {
	for _, tc := range []struct {
		rest []string
		want bool
	}{
		{nil, true},
		{[]string{"list"}, true},
		{[]string{"ls"}, true}, // 别名漏掉会让 route ls 白开写连接
		{[]string{"approve", "1"}, false},
		{[]string{"reject", "1"}, false},
		{[]string{"delete", "1"}, false},
		{[]string{"frobnicate"}, false}, // 不认识的一律按写,保守
	} {
		if got := routeIsReadOnly(tc.rest); got != tc.want {
			t.Errorf("routeIsReadOnly(%v)=%v, 期望 %v", tc.rest, got, tc.want)
		}
	}

	// credentials show 可能 backfill credential_id(0013 之前的老 row),按写处理。
	for _, tc := range []struct {
		rest []string
		want bool
	}{
		{nil, true},
		{[]string{"show", "alice"}, false},
		{[]string{"whatever"}, true},
	} {
		if got := credentialsIsReadOnly(tc.rest); got != tc.want {
			t.Errorf("credentialsIsReadOnly(%v)=%v, 期望 %v", tc.rest, got, tc.want)
		}
	}
}
