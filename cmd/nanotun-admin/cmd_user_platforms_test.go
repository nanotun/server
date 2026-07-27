package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// userPlatforms 读回某用户当前的 allowed_platforms(空串 = 不限)。
func userPlatforms(t *testing.T, db, username string) string {
	t.Helper()
	c, stdout, stderr := runCLI(t, db, "", "--json", "user", "show", username)
	if c != 0 {
		t.Fatalf("user show %s: code=%d stderr=%s", username, c, stderr)
	}
	var got struct {
		AllowedPlatforms string `json:"allowed_platforms"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("解析 user show JSON 失败: %v\n%s", err, stdout)
	}
	return got.AllowedPlatforms
}

// TestUserSetPlatforms_WritesAndNormalizes 覆盖 CLI 的正向写入与归一化。
//
// 平台白名单是账号级访问控制,而 CLI 这个入口此前零测试。归一化(大小写/空格/
// 去重)错了不会报错,只会让白名单和管理员以为的不一样 —— 静默的访问控制偏差。
func TestUserSetPlatforms_WritesAndNormalizes(t *testing.T) {
	db := filepath.Join(t.TempDir(), "platforms.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	if got := userPlatforms(t, db, "alice"); got != "" {
		t.Fatalf("新建用户应不限平台, 实际 %q", got)
	}

	cases := []struct {
		name string
		arg  string
		want string
	}{
		{"基本写入", "macos,ios", "macos,ios"},
		{"大小写与空格归一", "  MacOS , IOS  ", "macos,ios"},
		{"重复 token 去重", "macos,macos,ios", "macos,ios"},
		{"单平台", "router", "router"},
		{"空串=清空(恢复不限)", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, _, e := runCLI(t, db, "", "user", "set-platforms", "alice", c.arg); code != 0 {
				t.Fatalf("set-platforms %q: %s", c.arg, e)
			}
			if got := userPlatforms(t, db, "alice"); got != c.want {
				t.Fatalf("set-platforms %q → %q, 期望 %q", c.arg, got, c.want)
			}
		})
	}

	// 省略 csv 参数同样是清空(与文档一致)。
	if c, _, e := runCLI(t, db, "", "user", "set-platforms", "alice", "linux"); c != 0 {
		t.Fatalf("预置 linux: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "user", "set-platforms", "alice"); c != 0 {
		t.Fatalf("省略 csv: %s", e)
	}
	if got := userPlatforms(t, db, "alice"); got != "" {
		t.Fatalf("省略 csv 应清空, 实际 %q", got)
	}
}

// TestUserSetPlatforms_TypoIsRejectedAndLeavesWhitelistIntact 是这组里最重要的一条。
//
// 拼错一个平台名(比如 "macosx")必须整条命令失败,且**原白名单一个字节都不能动**。
// 若实现改成「跳过不认识的 token 继续写」,`set-platforms alice macosx` 就会把
// 白名单悄悄写成空(= 不限)或半拉子集合:前者让管控失效,后者直接把用户锁在门外
// —— 两种都不会有任何报错。
func TestUserSetPlatforms_TypoIsRejectedAndLeavesWhitelistIntact(t *testing.T) {
	db := filepath.Join(t.TempDir(), "platforms_typo.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "bob", "--psk", "p"); c != 0 {
		t.Fatalf("create bob: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "user", "set-platforms", "bob", "macos,ios"); c != 0 {
		t.Fatalf("预置白名单: %s", e)
	}

	for _, bad := range []string{"macosx", "macos,windoze", "darwin", "macos,,ios,plan9"} {
		code, _, stderr := runCLI(t, db, "", "user", "set-platforms", "bob", bad)
		if code == 0 {
			t.Errorf("非法平台 %q 应失败", bad)
			continue
		}
		if !strings.Contains(stderr, "platform") && !strings.Contains(stderr, "平台") {
			t.Errorf("%q 的报错应点明是平台问题, got: %s", bad, stderr)
		}
		if got := userPlatforms(t, db, "bob"); got != "macos,ios" {
			t.Fatalf("拒绝 %q 后白名单被改成了 %q, 应保持 macos,ios", bad, got)
		}
	}
}

// TestUserSetPlatforms_ArgErrors 参数与目标校验。
func TestUserSetPlatforms_ArgErrors(t *testing.T) {
	db := filepath.Join(t.TempDir(), "platforms_args.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "carol", "--psk", "p"); c != 0 {
		t.Fatalf("create carol: %s", e)
	}
	if c, _, _ := runCLI(t, db, "", "user", "set-platforms"); c == 0 {
		t.Error("缺用户名应失败")
	}
	if c, _, _ := runCLI(t, db, "", "user", "set-platforms", "carol", "macos", "ios"); c == 0 {
		t.Error("多余参数应失败(平台列表是单个 csv 而非多个参数)")
	}
	if c, _, stderr := runCLI(t, db, "", "user", "set-platforms", "nobody", "macos"); c == 0 {
		t.Error("不存在的用户应失败")
	} else if !strings.Contains(stderr, "nobody") {
		t.Errorf("报错应带上用户名, got: %s", stderr)
	}
}

// TestUserSetPlatforms_WritesAudit 白名单变更必须留痕:出了访问事故要能回溯是谁改的。
func TestUserSetPlatforms_WritesAudit(t *testing.T) {
	db := filepath.Join(t.TempDir(), "platforms_audit.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "dave", "--psk", "p"); c != 0 {
		t.Fatalf("create dave: %s", e)
	}
	if c, _, e := runCLI(t, db, "", "user", "set-platforms", "dave", "windows"); c != 0 {
		t.Fatalf("set-platforms: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "", "audit", "list")
	if c != 0 {
		t.Fatalf("audit list: code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stdout, "user_platforms_set") {
		t.Fatalf("审计日志缺 user_platforms_set:\n%s", stdout)
	}
	if !strings.Contains(stdout, "windows") {
		t.Fatalf("审计明细应记下新白名单:\n%s", stdout)
	}
}
