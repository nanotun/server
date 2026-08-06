package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// --json 是全局 flag,帮助里写的是「输出 JSON(供脚本用)」。凡是接受它的命令,stdout 就必须
// 是能直接喂给 jq 的东西。
//
// setting 一族曾是唯一的例外:get 吐裸值、list 吐表格,--json 完全不起作用,而且不报错。
// 统一加 --json 的封装脚本在这里拿到的是喂不进 jq 的文本 —— 偏偏 server_dial_host 这类值
// 正是装机脚本最常读的。
//
// 这条测试遍历所有数据类命令,新增命令若忘了接 --json,会在这里露馅。
func TestJSONFlagAlwaysProducesParseableJSON(t *testing.T) {
	db := filepath.Join(t.TempDir(), "cli.db")
	if code, _, errOut := runCLI(t, db, "", "init"); code != 0 {
		t.Fatalf("init: %s", errOut)
	}
	if code, _, errOut := runCLI(t, db, "", "user", "create", "alice"); code != 0 {
		t.Fatalf("user create: %s", errOut)
	}
	if code, _, errOut := runCLI(t, db, "", "setting", "set", "server_dial_host", "vpn.example.com"); code != 0 {
		t.Fatalf("setting set: %s", errOut)
	}

	cases := [][]string{
		{"user", "list"},
		{"user", "show", "alice"},
		{"device", "list"},
		{"lease", "list"},
		{"acl", "list"},
		{"audit", "list"},
		{"webadmin", "list"},
		{"route", "list"},
		{"exit", "list"},
		{"setting", "list"},
		{"setting", "get", "server_dial_host"},
		{"setting", "set", "server_dial_host", "vpn2.example.com"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			full := append([]string{"--json"}, args...)
			code, out, errOut := runCLI(t, db, "", full...)
			if code != 0 {
				t.Fatalf("code=%d err=%s", code, errOut)
			}
			if strings.TrimSpace(out) == "" {
				t.Fatal("--json 却没有任何 stdout")
			}
			var v any
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("stdout 不是合法 JSON: %v\n实际输出: %q", err, out)
			}
		})
	}
}

// 空表要给 [] 而不是 null:jq 的 `.[]`、`length` 在 null 上会炸或给出误导的答案,
// 而「一个用户都没有」恰恰是装机脚本最先遇到的状态。
func TestJSONEmptyListsAreArraysNotNull(t *testing.T) {
	db := filepath.Join(t.TempDir(), "cli.db")
	if code, _, errOut := runCLI(t, db, "", "init"); code != 0 {
		t.Fatalf("init: %s", errOut)
	}
	for _, args := range [][]string{
		{"device", "list"},
		{"lease", "list"},
		{"acl", "list"},
		{"setting", "list"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			full := append([]string{"--json"}, args...)
			code, out, errOut := runCLI(t, db, "", full...)
			if code != 0 {
				t.Fatalf("code=%d err=%s", code, errOut)
			}
			if strings.TrimSpace(out) == "null" {
				t.Errorf("空表输出了 null,应为 []: %q", out)
			}
			var arr []any
			if err := json.Unmarshal([]byte(out), &arr); err != nil {
				t.Fatalf("不是 JSON 数组: %v (%q)", err, out)
			}
		})
	}
}
