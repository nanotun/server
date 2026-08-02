package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// TestConnectionList_ShowsEffectiveRate:UP_BPS / DOWN_BPS 列要展示数据面**当下生效**的 cap。
//
// 三机实测(2026-07-26):`setting rate --down-bps 150000` + `device set-rate 1 --down-bps 60000`
// 之后 A 的下行实测被限在 57 KB/s,而本表两列都是 "-"(= 不限速)—— 因为它读的是 bw_*_bps
// (users.bandwidth_*,本例为空),而不是 link_rate_*_bps。运维照着这张表会以为限速没生效。
func TestConnectionList_ShowsEffectiveRate(t *testing.T) {
	body := []byte(`{"ok":true,"conn_count":1,"server_version":"test","uptime":"1m","sessions":[
		{"conn_id":"abc","user_id":"u2","vips":["10.201.0.77"],"created_at":0,"exit_allowed":true,
		 "link_ready":true,"link_rate_down_bps":60000,"link_rate_up_bps":0}]}`)
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: &bytes.Buffer{}, lang: "zh"}
	if err := printConnectionList(opts, body, nil); err != nil {
		t.Fatalf("print: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "60000") {
		t.Errorf("应展示生效下行 cap 60000,实际输出:\n%s", got)
	}
}

// TestConnectionList_UnknownRateBeforeLinkReady:limiter 还没建起来时 LinkRate* 恒为 0,
// 那个 0 不代表「不限速」,不能渲染成 "-"。
func TestConnectionList_UnknownRateBeforeLinkReady(t *testing.T) {
	body := []byte(`{"ok":true,"conn_count":1,"server_version":"test","uptime":"1m","sessions":[
		{"conn_id":"abc","user_id":"u2","vips":["10.201.0.77"],"created_at":0,"exit_allowed":true,
		 "link_ready":false}]}`)
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: &bytes.Buffer{}, lang: "zh"}
	if err := printConnectionList(opts, body, nil); err != nil {
		t.Fatalf("print: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "?") {
		t.Errorf("limiter 未就绪应显示未知,实际输出:\n%s", got)
	}
}

// connListRow 取表格数据行(跳过前两行摘要与表头),按空白切成字段。
func connListRow(t *testing.T, out string) []string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("期望「摘要 2 行 + 表头 + 数据行」,实际:\n%s", out)
	}
	return strings.Fields(lines[3])
}

// TestConnectionList_SeparatesUsernameFromIDToken:USER 列是真实用户名,USER_ID 列是
// 控制面那个 "u<id>",两者必须分开。
//
// user_id 是**主键派生**的,跟用户名是两个命名空间,合在一列会撞车。三机实测
// (2026-08-02):库里 username="u4" 的账号主键是 3,它的会话在原来那个名为 USER 的列里
// 显示 "u3" —— 运维想踢 u4,照着这列挑出来的是别人的 conn_id。这里用的正是那组会撞车
// 的数据:username=u4 / user_id=u3,两列都摆对了才算过。
//
// 两列都要留:audit_logs.target 存的是 user_id(`audit list` 的 TARGET 原样打),
// 只留用户名的话看到 target=u3 就没法对到人了。
func TestConnectionList_SeparatesUsernameFromIDToken(t *testing.T) {
	body := []byte(`{"ok":true,"conn_count":1,"server_version":"test","uptime":"1m","sessions":[
		{"conn_id":"abc","user_id":"u3","vips":["10.201.0.3"],"created_at":0,"exit_allowed":true,
		 "link_ready":true}]}`)
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: &bytes.Buffer{}, lang: "zh"}
	if err := printConnectionList(opts, body, map[string]string{"u3": "u4"}); err != nil {
		t.Fatalf("print: %v", err)
	}
	f := connListRow(t, out.String())
	if len(f) < 4 || f[1] != "u4" || f[2] != "u3" {
		t.Errorf("期望 USER=u4 USER_ID=u3,实际字段 %q,输出:\n%s", f, out.String())
	}
}

// TestConnectionList_WithoutDBLeavesUsernameBlank:库不可读时(只有控制 socket 的机器)
// 这条命令仍要出结果 —— USER 留 "-",user_id 照常在 USER_ID 列里,不报错也不留空行。
func TestConnectionList_WithoutDBLeavesUsernameBlank(t *testing.T) {
	body := []byte(`{"ok":true,"conn_count":1,"server_version":"test","uptime":"1m","sessions":[
		{"conn_id":"abc","user_id":"u3","vips":["10.201.0.3"],"created_at":0,"exit_allowed":true,
		 "link_ready":true}]}`)
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: &bytes.Buffer{}, lang: "zh"}
	if err := printConnectionList(opts, body, nil); err != nil {
		t.Fatalf("print: %v", err)
	}
	f := connListRow(t, out.String())
	if len(f) < 4 || f[1] != "-" || f[2] != "u3" {
		t.Errorf("期望 USER=- USER_ID=u3,实际字段 %q,输出:\n%s", f, out.String())
	}
}

// TestResolveSessionUsernames_MissingDBDoesNotCreateOne:库不存在时不许顺手建一个。
//
// store.Open 对不存在的路径会造空库,这条命令又常在没配 --db-path 的机器上跑
// (它的卖点是只依赖控制 socket),不判存在就会在 cwd 拉出 data/nanotun.db。
func TestResolveSessionUsernames_MissingDBDoesNotCreateOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "nanotun.db")
	if got := resolveSessionUsernames(&globalOpts{dbPath: path}); got != nil {
		t.Errorf("库不存在应返回 nil,实际 %v", got)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("不该建库,但 %s 已存在(stat err=%v)", path, err)
	}
}

// TestResolveSessionUsernames_MapsIDTokenToUsername:真库上跑一遍,确认映射键是
// "u<id>" 而不是 id 本身 —— 键格式错了的话上面那些用假 map 的断言全是空转。
func TestResolveSessionUsernames_MapsIDTokenToUsername(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nanotun.db")
	st := openStoreForTest(t, path)
	u, err := st.CreateUser(t.Context(), store.NewUser{Username: "u4", PSKHash: "h"})
	if err != nil {
		t.Fatalf("建用户: %v", err)
	}
	st.Close()

	got := resolveSessionUsernames(&globalOpts{dbPath: path})
	want := "u" + strconv.FormatInt(u.ID, 10)
	if got[want] != "u4" {
		t.Errorf("期望 %q → \"u4\",实际映射 %v", want, got)
	}
}
