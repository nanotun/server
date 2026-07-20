package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestUserSetMaxSessions:CLI 写库 + show 展示 + 非法值拒绝。
func TestUserSetMaxSessions(t *testing.T) {
	db := filepath.Join(t.TempDir(), "maxsess.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "bob", "--psk", "p"); c != 0 {
		t.Fatalf("create user: %s", e)
	}

	// 默认跟随全局。
	c, stdout, _ := runCLI(t, db, "", "user", "show", "bob")
	if c != 0 {
		t.Fatalf("show: code=%d", c)
	}
	if !strings.Contains(stdout, "跟随全局") && !strings.Contains(stdout, "follow global") {
		t.Fatalf("默认 show 应显示跟随全局,got:\n%s", stdout)
	}

	if c, _, e := runCLI(t, db, "", "user", "set-max-sessions", "bob", "3"); c != 0 {
		t.Fatalf("set 3: %s", e)
	}
	c, stdout, _ = runCLI(t, db, "", "--json", "user", "show", "bob")
	if c != 0 {
		t.Fatalf("json show: code=%d", c)
	}
	if !strings.Contains(stdout, `"max_sessions": 3`) {
		t.Fatalf("json 应含 max_sessions=3,got %s", stdout)
	}

	if c, _, e := runCLI(t, db, "", "user", "set-max-sessions", "bob", "-1"); c != 0 {
		t.Fatalf("set -1: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "user", "set-max-sessions", "bob", "0"); c != 0 {
		t.Fatalf("set 0: %s", e)
	}

	// 非法值。
	if c, _, stderr := runCLI(t, db, "", "user", "set-max-sessions", "bob", "-2"); c == 0 {
		t.Fatal("-2 应失败")
	} else if !strings.Contains(stderr, "max_sessions") && !strings.Contains(stderr, "整数") && !strings.Contains(stderr, "integer") {
		t.Fatalf("报错应提到 max_sessions,got: %s", stderr)
	}
	if c, _, _ := runCLI(t, db, "", "user", "set-max-sessions", "bob"); c == 0 {
		t.Fatal("缺参数应失败")
	}
}
