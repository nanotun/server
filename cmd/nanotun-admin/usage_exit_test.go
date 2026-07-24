package main

import (
	"path/filepath"
	"testing"
)

// TestUsageError_ExitCode2 锁死第十一轮深扫 LOW(保留项)的退出码归一:经 runWithStore 的
// 子命令,其「用法 / 参数错误」应返回 exit 2(与顶层 dispatch、restore、config lint、connection
// 的 usage 退出码一致),而非旧实现里被 runWithStore 统一吞成的 exit 1。
func TestUsageError_ExitCode2(t *testing.T) {
	db := filepath.Join(t.TempDir(), "cli.db")

	// 先建库(user create 会 open+migrate 生成 db 文件),后续只读子命令才能打开。
	if code, _, e := runCLI(t, db, "", "user", "create", "alice"); code != 0 {
		t.Fatalf("seed `user create alice`: code=%d stderr=%s", code, e)
	}

	cases := []struct {
		name string
		args []string
	}{
		{"user no-verb", []string{"user"}},
		{"user show missing arg", []string{"user", "show"}},
		{"device no-verb", []string{"device"}},
		{"acl no-verb", []string{"acl"}},
		{"lease no-verb", []string{"lease"}},
		// 第十二轮深扫 MED:route 无 verb 曾是漏网之鱼(仍返回 exit 1)。锁死为 2。
		{"route no-verb", []string{"route"}},
		{"exit no-verb", []string{"exit"}},
		{"setting no-verb", []string{"setting"}},
		{"audit no-verb", []string{"audit"}},
		{"credentials no-verb", []string{"credentials"}},
		// 第十二轮深扫 MED:**未知子命令**同样属用法错误 → exit 2(此前经 runWithStore 恒 exit 1)。
		{"user unknown-verb", []string{"user", "bogus"}},
		{"route unknown-verb", []string{"route", "bogus"}},
		{"device unknown-verb", []string{"device", "bogus"}},
		{"acl unknown-verb", []string{"acl", "bogus"}},
		{"lease unknown-verb", []string{"lease", "bogus"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, db, "", c.args...)
			if code != 2 {
				t.Fatalf("usage 错误应 exit 2, got %d (stderr=%q)", code, stderr)
			}
		})
	}

	// 对照:一次**真正的运行期**错误(不存在的用户)仍是 exit 1,不能被误判成 usage。
	if code, _, _ := runCLI(t, db, "", "user", "show", "nobody"); code != 1 {
		t.Fatalf("运行期错误(用户不存在)应 exit 1, got %d", code)
	}
}
