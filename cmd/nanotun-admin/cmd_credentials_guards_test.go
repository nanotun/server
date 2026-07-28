package main

// cmd_credentials_guards_test.go(第二十二轮)—— `credentials show/list` 的拒绝面。
//
// 这条命令有一个别处没有的特性:`--rotate-psk` 会**先把新 PSK 写库**(旧 hash 当场失效),
// 之后才把明文交付给运维。于是「输出这一步失败」的代价被放大成不可逆:
// 用户现有客户端立刻断连,而运维手里也没有新密钥 —— 只能再 rotate 一次。
//
// 所以这里最要紧的一类断言是:**所有能在落库前判定的失败,都必须发生在落库之前**。
// 判据不是错误信息,而是「PSK 还能不能用」。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/auth"
)

// credUser 造一个已知明文 PSK 的用户。
func credUser(t *testing.T, db, username, psk string) {
	t.Helper()
	if code, _, e := runCLI(t, db, "", "user", "create", username, "--psk", psk); code != 0 {
		t.Fatalf("user create %s: %s", username, e)
	}
}

// pskStillValid 回答「库里的 hash 还认这个明文吗」——「PSK 有没有被动过」的唯一判据。
func pskStillValid(t *testing.T, db, username, psk string) bool {
	t.Helper()
	st := openStoreForTest(t, db)
	defer st.Close()
	u, err := st.GetUserByUsername(t.Context(), username)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	ok, err := auth.VerifyPSK(psk, u.PSKHash)
	if err != nil {
		t.Fatalf("VerifyPSK: %v", err)
	}
	return ok
}

// =========================================================================
// 用法
// =========================================================================

func TestCmdCredentials_UsageGuards(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "c.db")
	credUser(t, db, "alice", "psk-alice-123456")

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"不给子命令", []string{"credentials"}},
		{"未知子命令", []string{"credentials", "export"}},
		{"show 不给用户名", []string{"credentials", "show"}},
		{"show 给两个用户名", []string{"credentials", "show", "alice", "bob"}},
		{"show 用户名是空白", []string{"credentials", "show", "  ", "--psk", "x"}},
		{"--psk 与 --rotate-psk 互斥", []string{"credentials", "show", "alice", "--psk", "x", "--rotate-psk"}},
		{"两个都不给", []string{"credentials", "show", "alice"}},
		{"format 不认识", []string{"credentials", "show", "alice", "--psk", "psk-alice-123456", "--format", "yaml"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := runCLI(t, db, "", tc.args...)
			if code != 2 {
				t.Fatalf("code=%d, 期望 2(用法错误)—— 脚本靠退出码区分「我写错了」和「库出问题了」", code)
			}
		})
	}

	t.Run("用户不存在", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "credentials", "show", "ghost", "--psk", "x")
		if code == 0 {
			t.Fatal("不存在的用户却成功了")
		}
		if !strings.Contains(stderr, "ghost") {
			t.Errorf("没说清是哪个用户: %q", stderr)
		}
	})
}

// =========================================================================
// 只读路径(--psk)
// =========================================================================

// 明文对不上时绝不能输出:那样会给出一份**无效**的 credentials,
// 用户扫了码却连不上,而运维手里的 QR 看着完全正常。
func TestCmdCredentialsShow_WrongPSKRefusesToEmitAnything(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "c.db")
	credUser(t, db, "alice", "psk-alice-123456")

	code, stdout, stderr := runCLI(t, db, "", "credentials", "show", "alice", "--psk", "psk-wrong-000000")
	if code == 0 {
		t.Fatal("PSK 不匹配却输出了凭证")
	}
	if strings.Contains(stdout, "nanotun-cred://") || strings.Contains(stdout, "psk") {
		t.Fatalf("失败路径还是吐了点什么出来: %q", stdout)
	}
	// 提示要指向 --rotate-psk,否则运维只会反复试密码。
	if !strings.Contains(stderr, "rotate") {
		t.Errorf("没提示可以用 --rotate-psk: %q", stderr)
	}
}

// 三种文本格式都要能输出,且 url 形式必须是客户端认得的那个 scheme。
func TestCmdCredentialsShow_TextFormats(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "c.db")
	const psk = "psk-alice-123456"
	credUser(t, db, "alice", psk)

	t.Run("json", func(t *testing.T) {
		code, stdout, e := runCLI(t, db, "", "credentials", "show", "alice", "--psk", psk, "--format", "json")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, e)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("输出不是合法 JSON: %v\n%s", err, stdout)
		}
		if got["username"] != "alice" {
			t.Errorf("username 不对: %v", got["username"])
		}
		if got["psk"] != psk {
			t.Errorf("psk 不是运维给的那个明文: %v", got["psk"])
		}
		if id, _ := got["id"].(string); strings.TrimSpace(id) == "" {
			if id2, _ := got["credential_id"].(string); strings.TrimSpace(id2) == "" {
				t.Errorf("没有 credential_id,客户端无法区分多服务器: %s", stdout)
			}
		}
	})

	t.Run("url", func(t *testing.T) {
		code, stdout, e := runCLI(t, db, "", "credentials", "show", "alice", "--psk", psk, "--format", "url")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, e)
		}
		if !strings.Contains(stdout, "nanotun-cred://") {
			t.Fatalf("URL 形式的 scheme 不对,客户端不认: %q", stdout)
		}
	})

	t.Run("both 两段都在", func(t *testing.T) {
		code, stdout, e := runCLI(t, db, "", "credentials", "show", "alice", "--psk", psk, "--format", "both")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, e)
		}
		if !strings.Contains(stdout, "nanotun-cred://") || !strings.Contains(stdout, "\"username\"") {
			t.Fatalf("both 少了一段:\n%s", stdout)
		}
	})

	t.Run("全局 --json 压过 --format", func(t *testing.T) {
		code, stdout, e := runCLI(t, db, "", "--json", "credentials", "show", "alice",
			"--psk", psk, "--format", "url")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, e)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &got); err != nil {
			t.Fatalf("--json 之下输出的不是 JSON: %v\n%s", err, stdout)
		}
	})

	t.Run("writeCredentials 不认识的格式要报错", func(t *testing.T) {
		var sb strings.Builder
		if err := writeCredentials(&sb, &credentialsSchema{Username: "alice"}, "toml"); err == nil {
			t.Fatal("不支持的格式却写出来了")
		}
	})
}

// --output 写文件时权限必须是 0600(文件里是明文 PSK),且默认不许覆盖已有文件。
func TestCmdCredentialsShow_OutputFileIsPrivateAndNoClobber(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "c.db")
	const psk = "psk-alice-123456"
	credUser(t, db, "alice", psk)
	out := filepath.Join(dir, "alice.json")

	code, _, stderr := runCLI(t, db, "", "credentials", "show", "alice", "--psk", psk, "--output", out)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatalf("产物不存在: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("产物权限 %o,期望 600 —— 文件里是明文 PSK", perm)
	}

	// 默认拒绝覆盖:那个文件里可能是上一个用户的明文凭证。
	code, _, stderr = runCLI(t, db, "", "credentials", "show", "alice", "--psk", psk, "--output", out)
	if code == 0 {
		t.Fatal("已存在的产物被默默覆盖了")
	}
	if !strings.Contains(stderr, out) {
		t.Errorf("没说清是哪个文件: %q", stderr)
	}

	// --force 才允许。
	if code, _, stderr := runCLI(t, db, "", "credentials", "show", "alice",
		"--psk", psk, "--output", out, "--force"); code != 0 {
		t.Fatalf("--force 之下仍失败: code=%d stderr=%s", code, stderr)
	}
}

// =========================================================================
// rotate 路径:落库前必须把所有确定性失败挡住
// =========================================================================

// 这一组是本文件的核心:每一条都要求 PSK **没有**被动过。
// 任何一条漏了,现场表现都是「用户突然连不上,而运维手里没有新密钥」。
func TestCmdCredentialsShowRotate_DeterministicFailuresHappenBeforeTheWrite(t *testing.T) {
	const psk = "psk-alice-123456"

	cases := []struct {
		name string
		args func(dir string) []string
		prep func(t *testing.T, dir string)
	}{
		{
			name: "qr-png 缺 --output",
			args: func(string) []string {
				return []string{"credentials", "show", "alice", "--rotate-psk", "--format", "qr-png"}
			},
		},
		{
			name: "--output 的父目录不存在",
			args: func(dir string) []string {
				return []string{"credentials", "show", "alice", "--rotate-psk",
					"--output", filepath.Join(dir, "no-such-dir", "alice.json")}
			},
		},
		{
			name: "--output 已存在且没给 --force",
			args: func(dir string) []string {
				return []string{"credentials", "show", "alice", "--rotate-psk",
					"--output", filepath.Join(dir, "taken.json")}
			},
			prep: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "taken.json"), []byte("{}"), 0o600); err != nil {
					t.Fatalf("占位: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			db := newInitializedDB(t, dir, "c.db")
			credUser(t, db, "alice", psk)
			if tc.prep != nil {
				tc.prep(t, dir)
			}
			code, _, stderr := runCLI(t, db, "", tc.args(dir)...)
			if code == 0 {
				t.Fatalf("这条本该失败: stderr=%s", stderr)
			}
			if !pskStillValid(t, db, "alice", psk) {
				t.Fatal("输出失败了,PSK 却已经被换掉 —— 用户当场断连,运维手里也没有新密钥")
			}
		})
	}
}

// 禁用账号不许 rotate:轮换出来的 PSK 会被 user_invalidate 立刻踢掉,等于发废卡。
func TestCmdCredentialsShowRotate_RefusesDisabledAccounts(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "c.db")
	const psk = "psk-alice-123456"
	credUser(t, db, "alice", psk)
	if code, _, e := runCLI(t, db, "", "user", "disable", "alice"); code != 0 {
		t.Fatalf("disable: %s", e)
	}

	code, _, stderr := runCLI(t, db, "", "credentials", "show", "alice", "--rotate-psk")
	if code == 0 {
		t.Fatal("禁用账号被 rotate 了 —— 发出去的是一张废卡")
	}
	if !strings.Contains(stderr, "alice") {
		t.Errorf("没说清是哪个账号: %q", stderr)
	}
	if !pskStillValid(t, db, "alice", psk) {
		t.Fatal("拒绝了却还是把 PSK 换掉了")
	}

	// 只读路径要允许:运维需要看「这个禁用账号现有凭证长什么样」来排查。
	if code, _, stderr := runCLI(t, db, "", "credentials", "show", "alice", "--psk", psk); code != 0 {
		t.Fatalf("禁用账号的只读查看被挡住了: code=%d stderr=%s", code, stderr)
	}
}

// rotate 是破坏性操作,不带 --yes 时要二次确认;答「不」必须什么都不动,并以 0 退出。
func TestCmdCredentialsShowRotate_DecliningLeavesThePSKAlone(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "c.db")
	const psk = "psk-alice-123456"
	credUser(t, db, "alice", psk)

	code, stdout, stderr := runCLIInteractive(t, db, "n\n", "credentials", "show", "alice", "--rotate-psk")
	if code != 0 {
		t.Fatalf("取消却以 %d 退出 stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "取消") {
		t.Errorf("没告诉用户已取消: %q", stdout)
	}
	if !pskStillValid(t, db, "alice", psk) {
		t.Fatal("用户答了「不」,PSK 却被换了")
	}
}

// rotate 成功时:新 PSK 必须与输出里的明文一致(否则运维发出去的卡是废的),
// 老 PSK 必须失效,并且要留下一条审计 —— 且审计里绝不能有明文。
func TestCmdCredentialsShowRotate_SucceedsCoherentlyAndAuditsWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "c.db")
	const oldPSK = "psk-alice-123456"
	credUser(t, db, "alice", oldPSK)

	code, stdout, stderr := runCLI(t, db, "", "--json", "credentials", "show", "alice", "--rotate-psk")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &got); err != nil {
		t.Fatalf("输出不是 JSON: %v\n%s", err, stdout)
	}
	newPSK, _ := got["psk"].(string)
	if strings.TrimSpace(newPSK) == "" {
		t.Fatal("rotate 成功却没给出新明文 —— 运维无从下发")
	}
	if newPSK == oldPSK {
		t.Fatal("rotate 之后 PSK 没变")
	}
	if !pskStillValid(t, db, "alice", newPSK) {
		t.Fatal("输出的明文与库里的 hash 对不上 —— 发出去的是废卡")
	}
	if pskStillValid(t, db, "alice", oldPSK) {
		t.Fatal("老 PSK 还能用 —— 轮换等于没做")
	}

	// 审计:要有记录,且不能含明文 PSK。
	st := openStoreForTest(t, db)
	defer st.Close()
	logs, err := st.QueryAudit(t.Context(), 0, 1<<62, 100)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	found := false
	for _, l := range logs {
		if l.Action == "credentials_rotate_psk" {
			found = true
			if strings.Contains(l.Detail, newPSK) || strings.Contains(l.Detail, oldPSK) {
				t.Errorf("审计明细里有明文 PSK: %q —— 审计表本身成了泄密面", l.Detail)
			}
			if !strings.Contains(l.Detail, "alice") {
				t.Errorf("审计明细里没说轮换的是谁: %q", l.Detail)
			}
		}
	}
	if !found {
		t.Error("轮换 PSK 这种破坏性操作没进审计")
	}
}

// qr 走终端、qr-png 走文件,两条都要真出东西;qr 带了 --output 要提醒被忽略,
// 否则运维会以为文件写好了,回头去找却什么也没有。
func TestCmdCredentialsShow_QRPaths(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "c.db")
	const psk = "psk-alice-123456"
	credUser(t, db, "alice", psk)

	t.Run("终端 qr", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, db, "", "credentials", "show", "alice",
			"--psk", psk, "--format", "qr")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Fatal("终端二维码是空的")
		}
	})

	t.Run("qr 带 --output 要提醒被忽略", func(t *testing.T) {
		out := filepath.Join(dir, "ignored.png")
		code, _, stderr := runCLI(t, db, "", "credentials", "show", "alice",
			"--psk", psk, "--format", "qr", "--output", out)
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if !strings.Contains(stderr, out) {
			t.Errorf("没提醒 --output 被忽略: %q", stderr)
		}
		if _, err := os.Stat(out); err == nil {
			t.Error("说是忽略,却真写了文件")
		}
	})

	t.Run("qr-png 落文件", func(t *testing.T) {
		out := filepath.Join(dir, "alice.png")
		code, _, stderr := runCLI(t, db, "", "credentials", "show", "alice",
			"--psk", psk, "--format", "qr-png", "--output", out)
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		body, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("产物不存在: %v", err)
		}
		if !strings.HasPrefix(string(body), "\x89PNG") {
			t.Fatalf("产物不是 PNG(前 8 字节 %q)", body[:min(8, len(body))])
		}
	})

	t.Run("qr-png 缺 --output(只读路径)", func(t *testing.T) {
		code, _, _ := runCLI(t, db, "", "credentials", "show", "alice",
			"--psk", psk, "--format", "qr-png")
		if code == 0 {
			t.Fatal("qr-png 不给 --output 却成功了")
		}
	})
}

// =========================================================================
// credentials list
// =========================================================================

// 列表必须**包含禁用账号**:否则禁用账号在 admin 视角里隐身,而它手上的凭证仍然存在。
func TestCmdCredentialsList_IncludesDisabledAndOnlyThoseWithCredentials(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "c.db")
	credUser(t, db, "with-cred", "psk-with-cred-1234")
	credUser(t, db, "gone-dark", "psk-gone-dark-1234")
	// 给这两个都发过凭证。
	for _, u := range []string{"with-cred", "gone-dark"} {
		psk := "psk-" + u + "-1234"
		if code, _, e := runCLI(t, db, "", "credentials", "show", u, "--psk", psk); code != 0 {
			t.Fatalf("发凭证 %s: %s", u, e)
		}
	}
	if code, _, e := runCLI(t, db, "", "user", "disable", "gone-dark"); code != 0 {
		t.Fatalf("disable: %s", e)
	}

	t.Run("表格", func(t *testing.T) {
		for _, sub := range []string{"list", "ls"} {
			code, stdout, stderr := runCLI(t, db, "", "credentials", sub)
			if code != 0 {
				t.Fatalf("%s: code=%d stderr=%s", sub, code, stderr)
			}
			for _, want := range []string{"with-cred", "gone-dark"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("%s 的输出里少了 %s(禁用账号也必须列出,它手上的凭证还在):\n%s", sub, want, stdout)
				}
			}
		}
	})

	t.Run("json", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, db, "", "--json", "credentials", "list")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		var rows []struct {
			Username     string `json:"username"`
			CredentialID string `json:"credential_id"`
			DisabledAt   int64  `json:"disabled_at"`
		}
		if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
			t.Fatalf("不是合法 JSON: %v\n%s", err, stdout)
		}
		if len(rows) != 2 {
			t.Fatalf("列出了 %d 行,期望 2: %+v", len(rows), rows)
		}
		for _, r := range rows {
			if strings.TrimSpace(r.CredentialID) == "" {
				t.Errorf("%s 没有 credential_id,却被列进了「已发凭证」清单", r.Username)
			}
			if r.Username == "gone-dark" && r.DisabledAt == 0 {
				t.Error("禁用状态没体现出来,运维会以为这张卡还活着")
			}
		}
		// 绝不能带明文 PSK / hash 出来 —— 这条命令的输出常被贴进工单。
		if strings.Contains(stdout, "psk") {
			t.Errorf("列表输出里出现了 psk 字样: %s", stdout)
		}
	})
}
