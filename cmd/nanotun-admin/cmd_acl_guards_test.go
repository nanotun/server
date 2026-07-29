package main

// cmd_acl_guards_test.go(第二十二轮)—— `acl` 子命令的拒绝面与展示面。
//
// ACL 是数据面唯一的放行/拦截依据,所以这组命令有两种特别难看出来的坏法:
//   - 参数被静默吃掉:`--port 8o80` 之类打错时若不当场拒,规则会带着 lo=hi=0(=任意端口)
//     落库,看列表只见一条「已生效」的规则,实际放行面比运维想的大得多;
//   - 落库了但没通知:数据面读的是内存 snapshot,不刷就只是往表里摆了条没约束力的规则。
//
// 断言重心相应地是「该拒的当场拒、退出码分得清用法错误(2)与运行错误(1)」以及
// 「表格/JSON 两条输出路径都把通配、端口区间、exit 规则渲染成人能看懂的样子」。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// seedACLUsers 建一批用户,供 acl 规则两端引用。
func seedACLUsers(t *testing.T, db string, names ...string) {
	t.Helper()
	for _, n := range names {
		if c, _, e := runCLI(t, db, "", "user", "create", n, "--psk", "psk-"+n+"-12345678"); c != 0 {
			t.Fatalf("user create %s: %s", n, e)
		}
	}
}

// aclExec 在库上直接跑一条 SQL,用来把表改坏(模拟迁移半途/人手改库)。
func aclExec(t *testing.T, db string, stmts ...string) {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	for _, s := range stmts {
		if _, err := st.DB().ExecContext(t.Context(), s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
}

// =========================================================================
// 派发与用法
// =========================================================================

func TestCmdACL_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl.db")
	seedACLUsers(t, db, "ua", "ub")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"不给子命令", []string{"acl"}},
		{"allow 只给一端", []string{"acl", "allow", "ua"}},
		{"allow 给三端", []string{"acl", "allow", "ua", "ub", "uc"}},
		{"deny 不给两端", []string{"acl", "deny"}},
		{"del 不给 id", []string{"acl", "del"}},
		{"del 给两个 id", []string{"acl", "del", "1", "2"}},
		{"del 的 id 不是数字", []string{"acl", "del", "第一条"}},
		{"--exit 却指名了 dst", []string{"acl", "allow", "ua", "ub", "--exit"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", tc.args...)
			if code != 2 {
				t.Fatalf("用法错误应 exit 2, got %d stderr=%q", code, stderr)
			}
			if strings.TrimSpace(stderr) == "" {
				t.Error("exit 2 却什么都没说")
			}
		})
	}

	// 未知子命令不是用法错误(与顶层 dispatch 一致走 exit 1),但必须把敲错的那个词回显,
	// 否则运维只看到「不支持」,不知道是自己拼错了还是版本太老。
	code, _, stderr := runCLI(t, db, "", "acl", "add")
	if code == 0 {
		t.Fatal("未知子命令 acl add 竟然成功了")
	}
	if !strings.Contains(stderr, "add") {
		t.Errorf("报错没回显敲错的子命令: %q", stderr)
	}
}

// acl allow/deny 的两端解析:任何一端指向不存在的用户都必须当场失败 ——
// 否则规则会带着 src/dst = NULL(通配)落库,把一条点对点规则悄悄放大成全局规则。
func TestCmdACLAddPair_UnknownUserOnEitherEnd(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-unknown.db")
	seedACLUsers(t, db, "ua")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"src 不存在", []string{"acl", "allow", "ghost", "ua"}},
		{"dst 不存在", []string{"acl", "allow", "ua", "ghost"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", tc.args...)
			if code == 0 {
				t.Fatal("引用不存在的用户竟然成功了")
			}
			if !strings.Contains(stderr, "ghost") {
				t.Errorf("报错没说是哪个用户找不到: %q", stderr)
			}
			if n := aclRuleCount(t, db); n != 0 {
				t.Fatalf("失败的 acl allow 留下了 %d 条规则", n)
			}
		})
	}
}

func aclRuleCount(t *testing.T, db string) int {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	rules, err := st.ListACLPairs(t.Context())
	if err != nil {
		t.Fatalf("ListACLPairs: %v", err)
	}
	return len(rules)
}

// =========================================================================
// flag 解析:splitACLAddFlags / parsePortRange
// =========================================================================

// splitACLAddFlags 是手写的解析器(要支持 flag 与位置参数混排),错一点就会把
// 参数当成位置参数吞掉。这里逐形式钉住。
func TestSplitACLAddFlags_Forms(t *testing.T) {
	t.Run("两种 --proto 写法等价", func(t *testing.T) {
		for _, args := range [][]string{
			{"--proto", "tcp", "ua", "ub"},
			{"--proto=tcp", "ua", "ub"},
		} {
			f, pos, err := splitACLAddFlags(args)
			if err != nil {
				t.Fatalf("%v: %v", args, err)
			}
			if f.proto != "tcp" {
				t.Errorf("%v: proto=%q want tcp", args, f.proto)
			}
			if len(pos) != 2 || pos[0] != "ua" || pos[1] != "ub" {
				t.Errorf("%v: 位置参数被吃掉了: %v", args, pos)
			}
		}
	})

	t.Run("--port 单端口撑成闭区间", func(t *testing.T) {
		f, _, err := splitACLAddFlags([]string{"ua", "ub", "--port", "443"})
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if f.portLo != 443 || f.portHi != 443 {
			t.Errorf("单端口应 lo=hi=443, got %d-%d", f.portLo, f.portHi)
		}
	})

	t.Run("--port-range 解析成闭区间", func(t *testing.T) {
		f, _, err := splitACLAddFlags([]string{"ua", "ub", "--port-range", "1024-2048"})
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if f.portLo != 1024 || f.portHi != 2048 {
			t.Errorf("got %d-%d want 1024-2048", f.portLo, f.portHi)
		}
	})

	t.Run("--exit 是纯开关", func(t *testing.T) {
		f, pos, err := splitACLAddFlags([]string{"ua", "*", "--exit"})
		if err != nil || !f.exit {
			t.Fatalf("exit=%v err=%v", f.exit, err)
		}
		if len(pos) != 2 {
			t.Errorf("--exit 不该吃掉后面的位置参数: %v", pos)
		}
	})

	// 缺参 / 非法值一律报错。放过任何一条的后果都是「规则落库时端口退化成 0-0
	// (任意端口)」—— 一条本想只开 443 的规则会变成全端口放行。
	for _, tc := range []struct {
		name    string
		args    []string
		wantSub string
	}{
		{"--proto 缺参", []string{"ua", "ub", "--proto"}, "--proto"},
		{"--port 缺参", []string{"ua", "ub", "--port"}, "--port"},
		{"--port 非数字", []string{"ua", "ub", "--port", "8o80"}, "8o80"},
		{"--port-range 缺参", []string{"ua", "ub", "--port-range"}, "--port-range"},
		{"--port-range 没有横杠", []string{"ua", "ub", "--port-range", "1024"}, "1024"},
		{"--port-range 横杠开头", []string{"ua", "ub", "--port-range", "-2048"}, "-2048"},
		{"--port-range 横杠结尾", []string{"ua", "ub", "--port-range", "1024-"}, "1024-"},
		{"--port-range lo 非数字", []string{"ua", "ub", "--port-range", "x-2048"}, "x"},
		{"--port-range hi 非数字", []string{"ua", "ub", "--port-range", "1024-y"}, "y"},
		{"--port-range lo>hi", []string{"ua", "ub", "--port-range", "2048-1024"}, "2048-1024"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := splitACLAddFlags(tc.args)
			if err == nil {
				t.Fatal("非法参数被静默接受 —— 规则会带着 0-0(任意端口)落库")
			}
			msg := (&globalOpts{lang: langZH}).errText(err)
			if !strings.Contains(msg, tc.wantSub) {
				t.Errorf("报错没回显出错的那段 %q: %s", tc.wantSub, msg)
			}
		})
	}
}

// =========================================================================
// 落库失败 / 展示
// =========================================================================

// 写入失败(磁盘满、库只读)时绝不能报成功:运维会以为规则已生效而不再复核。
func TestCmdACLAddPair_InsertFailureIsNotReportedAsSuccess(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-insfail.db")
	seedACLUsers(t, db, "ua", "ub")
	abortWritesOn(t, db, "acl_pairs", "INSERT")

	code, stdout, stderr := runCLI(t, db, "", "acl", "allow", "ua", "ub")
	if code == 0 {
		t.Fatalf("写库失败却 exit 0, stdout=%q", stdout)
	}
	if strings.Contains(stdout, "已新增") {
		t.Errorf("写库失败却打了成功提示: %q", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("写库失败却没在 stderr 说明原因")
	}
	if n := aclRuleCount(t, db); n != 0 {
		t.Fatalf("失败之后表里有 %d 条规则", n)
	}
}

// acl del:不存在的 id 要给本地化的「规则不存在」,而不是裸抛 store 的英文错误;
// 删除失败同样不能报成功。
func TestCmdACLDelete_NotFoundAndWriteFailure(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-del.db")
	seedACLUsers(t, db, "ua", "ub")

	t.Run("id 不存在", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "acl", "del", "4242")
		if code != 1 {
			t.Fatalf("删不存在的规则应 exit 1, got %d", code)
		}
		if !strings.Contains(stderr, "4242") {
			t.Errorf("报错没说是哪条 id: %q", stderr)
		}
	})

	t.Run("删除被库拒绝", func(t *testing.T) {
		if c, _, e := runCLI(t, db, "", "acl", "allow", "ua", "ub"); c != 0 {
			t.Fatalf("acl allow: %s", e)
		}
		id := firstACLID(t, db)
		abortWritesOn(t, db, "acl_pairs", "DELETE")
		code, stdout, _ := runCLI(t, db, "", "acl", "del", fmt.Sprint(id))
		if code == 0 {
			t.Fatalf("删除失败却 exit 0, stdout=%q", stdout)
		}
		if strings.Contains(stdout, "已删除") {
			t.Errorf("删除失败却打了成功提示: %q", stdout)
		}
		if n := aclRuleCount(t, db); n != 1 {
			t.Fatalf("规则不该被删掉, 剩 %d 条", n)
		}
	})
}

func firstACLID(t *testing.T, db string) int64 {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	rules, err := st.ListACLPairs(t.Context())
	if err != nil || len(rules) == 0 {
		t.Fatalf("ListACLPairs: %v (n=%d)", err, len(rules))
	}
	return rules[0].ID
}

// acl del 成功之后必须提示「还要刷 snapshot」—— 没有 --control-socket 时通知一定失败,
// 此时若静默,被删掉的 deny 规则会继续拦流量,而列表里已经看不到它,排障时无从下手。
func TestCmdACLDelete_TellsUserToReload(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-reload.db")
	seedACLUsers(t, db, "ua", "ub")
	if c, _, e := runCLI(t, db, "", "acl", "allow", "ua", "ub"); c != 0 {
		t.Fatalf("acl allow: %s", e)
	}
	id := firstACLID(t, db)

	code, stdout, stderr := runCLI(t, db, "", "acl", "del", fmt.Sprint(id))
	if code != 0 {
		t.Fatalf("acl del: code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "已删除") {
		t.Errorf("stdout 缺成功提示: %q", stdout)
	}
	if !strings.Contains(stderr, "reload") {
		t.Errorf("通知不到 server 时必须指路 reload, stderr=%q", stderr)
	}
	if n := aclRuleCount(t, db); n != 0 {
		t.Fatalf("del 之后还剩 %d 条", n)
	}
}

// acl list 的表格路径(默认输出)—— JSON 路径已有别处覆盖。这里把三种最容易渲染错的
// 单元格一次性钉住:通配端(*)、端口区间(lo-hi)、exit 规则的 dst(<exit>)。
func TestCmdACLList_TableRendersWildcardRangeAndExit(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-list.db")
	seedACLUsers(t, db, "ua", "ub")

	for _, args := range [][]string{
		{"acl", "allow", "ua", "ub", "--proto", "tcp", "--port-range", "1024-2048"},
		{"acl", "deny", "*", "ub"},
		{"acl", "allow", "ua", "*", "--exit"},
	} {
		if c, _, e := runCLI(t, db, "", args...); c != 0 {
			t.Fatalf("%v: %s", args, e)
		}
	}

	code, stdout, stderr := runCLI(t, db, "", "acl", "list")
	if code != 0 {
		t.Fatalf("acl list: code=%d stderr=%s", code, stderr)
	}
	for _, want := range []string{
		"1024-2048", // 端口区间不能被压成单个数字
		"<exit>",    // exit 规则的 dst 不是某个用户
		"ua(#",      // 具体用户端要带 username 和 id
		"*",         // 通配端
		"tcp",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("表格缺 %q:\n%s", want, stdout)
		}
	}

	// JSON 路径同样要能出这三条(表格与 JSON 是两段独立代码)。
	code, stdout, _ = runCLI(t, db, "", "--json", "acl", "list")
	if code != 0 {
		t.Fatalf("acl list --json: %d", code)
	}
	var rows []struct {
		Action    string `json:"action"`
		DstKind   string `json:"dst_kind"`
		DstPortLo int    `json:"dst_port_lo"`
		DstPortHi int    `json:"dst_port_hi"`
	}
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout)
	}
	if len(rows) != 3 {
		t.Fatalf("应有 3 条规则, got %d", len(rows))
	}
	var sawExit, sawRange bool
	for _, r := range rows {
		if r.DstKind == store.ACLDstKindExit {
			sawExit = true
		}
		if r.DstPortLo == 1024 && r.DstPortHi == 2048 {
			sawRange = true
		}
	}
	if !sawExit || !sawRange {
		t.Errorf("JSON 丢了 exit(%v) 或端口区间(%v): %s", sawExit, sawRange, stdout)
	}
}

// 表里的行读不出来时必须失败,不能打一张缺行的表 —— 缺行的 ACL 表会让运维
// 以为某条 deny 不存在,进而放开本已被拦住的访问。
func TestCmdACLList_UnreadableRowsFailLoudly(t *testing.T) {
	t.Run("表不在了", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "acl-notable.db")
		aclExec(t, db, `ALTER TABLE acl_pairs RENAME TO acl_pairs_gone`)
		code, stdout, stderr := runCLI(t, db, "", "acl", "list")
		if code == 0 {
			t.Fatalf("查不到表却 exit 0, stdout=%q", stdout)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Error("没说为什么失败")
		}
	})

	t.Run("端口列被写成了文本", func(t *testing.T) {
		db := newInitializedDB(t, t.TempDir(), "acl-badrow.db")
		seedACLUsers(t, db, "ua", "ub")
		if c, _, e := runCLI(t, db, "", "acl", "allow", "ua", "ub"); c != 0 {
			t.Fatalf("acl allow: %s", e)
		}
		aclExec(t, db, `UPDATE acl_pairs SET dst_port_lo = 'oops'`)
		code, stdout, _ := runCLI(t, db, "", "acl", "list")
		if code == 0 {
			t.Fatalf("行扫不出来却 exit 0, stdout=%q", stdout)
		}
	})
}

// =========================================================================
// 单元格渲染的纯函数
// =========================================================================

// formatACLEnd 的 `#%d` 分支只在「规则引用的用户已不在 users 表里」时出现 —— 那种库
// 状态没法从 CLI 造出来(外键级联会连规则一起删),但函数本身仍要能把 id 显示出来:
// 一条指向幽灵用户的规则在数据面照旧生效,列表里必须留下线索。
func TestFormatACLCells(t *testing.T) {
	if got := formatACLEnd(0, ""); got != "*" {
		t.Errorf("id=0 应显示通配, got %q", got)
	}
	if got := formatACLEnd(7, ""); got != "#7" {
		t.Errorf("用户名查不到时应退回 #id, got %q", got)
	}
	if got := formatACLEnd(7, "ua"); got != "ua(#7)" {
		t.Errorf("got %q", got)
	}
	if got := formatACLProto(""); got != "*" {
		t.Errorf("空 proto 应显示通配, got %q", got)
	}
	if got := formatACLProto("udp"); got != "udp" {
		t.Errorf("got %q", got)
	}
	for _, tc := range []struct {
		lo, hi int
		want   string
	}{
		{0, 0, "*"},
		{443, 443, "443"},
		{1024, 2048, "1024-2048"},
	} {
		if got := formatACLPort(tc.lo, tc.hi); got != tc.want {
			t.Errorf("formatACLPort(%d,%d)=%q want %q", tc.lo, tc.hi, got, tc.want)
		}
	}
}

// =========================================================================
// 缺回程提示的遍历分支
// =========================================================================

// warnAllowNeedsReverse 遍历现有规则找「能覆盖回程的 allow」。deny 规则和 exit 规则
// 都不算覆盖 —— 若把它们误当成覆盖,提示就会在真正缺回程时闭嘴,而那正是三机实测里
// 「ACL 看着配好了却完全不通」的现场。
func TestACLAllow_DenyAndExitRulesDoNotCountAsReverseCoverage(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-rev-scan.db")
	seedACLUsers(t, db, "ua", "ub")
	if c, _, e := runCLI(t, db, "", "setting", "set", "acl_default_action", "deny"); c != 0 {
		t.Fatalf("set default deny: %s", e)
	}
	// 先摆两条「长得像回程、其实不算」的规则:反向的 deny + 反向的 exit。
	for _, args := range [][]string{
		{"acl", "deny", "ub", "ua"},
		{"acl", "allow", "ub", "*", "--exit"},
	} {
		if c, _, e := runCLI(t, db, "", args...); c != 0 {
			t.Fatalf("%v: %s", args, e)
		}
	}

	code, _, stderr := runCLI(t, db, "", "acl", "allow", "ua", "ub")
	if code != 0 {
		t.Fatalf("acl allow: %s", stderr)
	}
	if !strings.Contains(stderr, reverseHintMark) {
		t.Errorf("反向只有 deny/exit 规则,仍缺回程 allow,必须提示; stderr=%q", stderr)
	}
}

// 反向的通配 allow(`allow * *`)确实覆盖回程,此时不该再噪扰。
func TestACLAllow_WildcardReverseCountsAsCoverage(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-rev-wild.db")
	seedACLUsers(t, db, "ua", "ub")
	if c, _, e := runCLI(t, db, "", "setting", "set", "acl_default_action", "deny"); c != 0 {
		t.Fatalf("set default deny: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "acl", "allow", "*", "*"); c != 0 {
		t.Fatalf("acl allow * *: %s", e)
	}
	code, _, stderr := runCLI(t, db, "", "acl", "allow", "ua", "ub")
	if code != 0 {
		t.Fatalf("acl allow: %s", stderr)
	}
	if strings.Contains(stderr, reverseHintMark) {
		t.Errorf("回程已被通配 allow 覆盖,不该提示; stderr=%q", stderr)
	}
}

// acl allow --json:JSON 路径不打人类提示,但审计和通知提示照旧要有 ——
// 脚本化调用同样需要知道「规则还没生效」。
func TestCmdACLAddPair_JSONOutput(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "acl-json.db")
	seedACLUsers(t, db, "ua", "ub")

	code, stdout, stderr := runCLI(t, db, "", "--json", "acl", "allow", "ua", "ub", "--proto", "udp", "--port", "53")
	if code != 0 {
		t.Fatalf("acl allow --json: code=%d stderr=%s", code, stderr)
	}
	var pair store.ACLPair
	if err := json.Unmarshal([]byte(stdout), &pair); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout)
	}
	if pair.Proto != "udp" || pair.DstPortLo != 53 || pair.DstPortHi != 53 {
		t.Errorf("JSON 里的 proto/端口不对: %+v", pair)
	}
	if pair.ID == 0 {
		t.Error("JSON 没带回新规则的 id")
	}
	if !strings.Contains(stderr, "reload") {
		t.Errorf("--json 也要提示刷 snapshot, stderr=%q", stderr)
	}
}

// server 在跑时,增删规则都必须真的把 reload 打过去 —— 而且 --json 也不例外。
//
// 既有用例验的是「通知不到时要指路手动 reload」,那条在没有 control socket 的环境下跑,
// 所以「通知这一步被 --json 跳过了」它看不出来。落库 ≠ 生效:数据面读的是内存快照,
// 删掉一条 deny 却不刷快照,那条规则会继续拦流量,而列表里已经查不到它 —— 排障时无从下手。
func TestCmdACL_AddAndDeleteAlwaysReloadTheSnapshot(t *testing.T) {
	for _, useJSON := range []bool{false, true} {
		name := "默认输出"
		if useJSON {
			name = "--json"
		}
		t.Run(name, func(t *testing.T) {
			db := newInitializedDB(t, t.TempDir(), "acl-notify.db")
			seedACLUsers(t, db, "ua", "ub")
			fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
				"/reload": jsonHandler(`{"ok":true,"what":"acl","rules":1}`)})

			add := []string{"acl", "deny", "ua", "ub"}
			if useJSON {
				add = append([]string{"--json"}, add...)
			}
			if code, _, stderr := runCLISock(t, db, fc.path, add...); code != 0 {
				t.Fatalf("acl deny: code=%d stderr=%s", code, stderr)
			}
			if !containsAny(fc.requests(), "/reload") {
				t.Fatalf("加了一条 deny 却没通知 server 刷快照,规则落库了但没有约束力: %v", fc.requests())
			}

			id := firstACLID(t, db)
			del := []string{"acl", "del", fmt.Sprint(id)}
			if useJSON {
				del = append([]string{"--json"}, del...)
			}
			before := len(fc.requests())
			if code, _, stderr := runCLISock(t, db, fc.path, del...); code != 0 {
				t.Fatalf("acl del: code=%d stderr=%s", code, stderr)
			}
			if len(fc.requests()) <= before {
				t.Fatalf("删了一条规则却没通知 server 刷快照,被删的 deny 会继续拦流量: %v", fc.requests())
			}
		})
	}
}
