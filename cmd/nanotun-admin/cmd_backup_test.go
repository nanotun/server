package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// G2 regression:copyFileAtomic 错误路径必须清理 .tmp,否则下次备份残留半截
// 文件。本测试用 src 不可读触发 Open 失败前的 tmp 状态;真正的「Sync 失败」
// 路径在 unit-test 难以伪造(需要 mock os.File),改为验证「正常路径完成后
// 不留 tmp」+「目标已存在时被原子替换」这两个核心契约。
func TestCopyFileAtomic_NoTmpResidueOnSuccess(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFileAtomic(src, dst); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "payload" {
		t.Fatalf("dst content mismatch")
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("成功路径下不应残留 .tmp: stat err=%v", err)
	}

	// 第二次 copy 覆盖现有 dst,验证 atomic rename 正确替换。
	if err := os.WriteFile(src, []byte("payload-v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFileAtomic(src, dst); err != nil {
		t.Fatalf("copy v2: %v", err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "payload-v2" {
		t.Fatalf("覆盖后 dst content = %q", got)
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("覆盖路径下不应残留 .tmp: stat err=%v", err)
	}
}

func TestCopyFileAtomic_OpenSrcFailReturnsErr(t *testing.T) {
	dir := t.TempDir()
	err := copyFileAtomic(filepath.Join(dir, "no-such"), filepath.Join(dir, "dst"))
	if err == nil {
		t.Fatal("expected error when src missing")
	}
}

func TestCmdBackup_WritesFileAndPreservesRows(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "src.db")
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"}); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, dbPath: dbPath, yes: true, lang: langZH}
	backupPath := filepath.Join(dir, "snapshot.db")
	if err := cmdBackup(ctx, st, opts, []string{"--out", backupPath}); err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup file missing: %v", err)
	}

	// 打开备份再确认 alice 还在。
	bk, err := store.Open(ctx, backupPath, store.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer bk.Close()
	users, err := bk.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("backup users mismatch: %+v", users)
	}
}

func TestCmdBackup_RefusesExistingTarget(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "src.db")
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.Migrate(ctx)
	target := filepath.Join(dir, "exists.db")
	if err := os.WriteFile(target, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, dbPath: dbPath, yes: true, lang: langZH}
	err = cmdBackup(ctx, st, opts, []string{"--out", target})
	if err == nil || !strings.Contains(err.Error(), "已存在") {
		t.Fatalf("expected 拒绝覆盖已存在文件, got err=%v", err)
	}
}

func TestCmdVacuum_Smoke(t *testing.T) {
	ctx := t.Context()
	dbPath := filepath.Join(t.TempDir(), "v.db")
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, dbPath: dbPath, yes: true, lang: langZH}
	if err := cmdVacuum(ctx, st, opts, nil); err != nil {
		t.Fatalf("cmdVacuum: %v", err)
	}
	if !strings.Contains(out.String(), "VACUUM 完成") {
		t.Fatalf("expected VACUUM 完成 in output, got %q", out.String())
	}
}

// newNanotunDB 建一份迁移完毕、含指定用户的真实 nanotun 库,供 restore 用例当源/目标。
func newNanotunDB(t *testing.T, path, username string) {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if username != "" {
		if _, err := st.CreateUser(ctx, store.NewUser{Username: username, PSKHash: "h"}); err != nil {
			t.Fatal(err)
		}
	}
}

func usersInDB(t *testing.T, path string) []string {
	t.Helper()
	st, err := store.Open(t.Context(), path, store.Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer st.Close()
	us, err := st.ListUsers(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(us))
	for _, u := range us {
		names = append(names, u.Username)
	}
	return names
}

func TestCmdRestore_AtomicCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	dst := filepath.Join(dir, "dst.db")
	newNanotunDB(t, src, "fresh")
	newNanotunDB(t, dst, "stale")

	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, dbPath: dst, yes: true,
		controlSocket: "/tmp/this-does-not-exist.sock"}
	code := cmdRestore(opts, []string{src})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (out=%s)", code, out.String())
	}
	if got := usersInDB(t, dst); len(got) != 1 || got[0] != "fresh" {
		t.Fatalf("expected dst to hold the snapshot's user, got %v", got)
	}
	// 覆盖前的现库必须留一份可回退的旁路副本。
	saved, _ := filepath.Glob(dst + ".pre-restore-*")
	if len(saved) != 1 {
		t.Fatalf("expected exactly one pre-restore snapshot, got %v", saved)
	}
	if got := usersInDB(t, saved[0]); len(got) != 1 || got[0] != "stale" {
		t.Fatalf("pre-restore snapshot should hold the old DB, got %v", got)
	}
}

// 核心回归:restore 此前对源文件零校验,一个 15 字节文本文件就能把生产库覆盖成
// 「file is not a database」并报 success。三类坏源都必须在落盘前被拦下,且 dst 分毫未动。
func TestCmdRestore_RejectsInvalidSource(t *testing.T) {
	cases := []struct {
		name string
		// build 产出源文件内容;返回 true 表示已自行写好 src。
		build func(t *testing.T, src string)
	}{
		{"plain text", func(t *testing.T, src string) {
			if err := os.WriteFile(src, []byte("hello not a db\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty file", func(t *testing.T, src string) {
			if err := os.WriteFile(src, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated sqlite", func(t *testing.T, src string) {
			full := filepath.Join(filepath.Dir(src), "full.db")
			newNanotunDB(t, full, "x")
			raw, err := os.ReadFile(full)
			if err != nil {
				t.Fatal(err)
			}
			// 保留合法文件头,砍掉后半 —— 模拟半截下载的备份。
			if err := os.WriteFile(src, raw[:len(raw)/2], 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"foreign sqlite db", func(t *testing.T, src string) {
			db, err := sql.Open("sqlite", src)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec("CREATE TABLE bookmarks (id INTEGER PRIMARY KEY)"); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "src.db")
			dst := filepath.Join(dir, "dst.db")
			tc.build(t, src)
			newNanotunDB(t, dst, "keepme")

			out := &bytes.Buffer{}
			opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, dbPath: dst, yes: true,
				controlSocket: "/tmp/this-does-not-exist.sock"}
			if code := cmdRestore(opts, []string{src}); code == 0 {
				t.Fatalf("expected non-zero exit for %s source, out=%s", tc.name, out.String())
			}
			if got := usersInDB(t, dst); len(got) != 1 || got[0] != "keepme" {
				t.Fatalf("live DB must be untouched, got %v", got)
			}
			if saved, _ := filepath.Glob(dst + ".pre-restore-*"); len(saved) != 0 {
				t.Fatalf("must not snapshot when the source is rejected, got %v", saved)
			}
		})
	}
}

// 防御:src 不存在时立刻报错,不破坏 dst。
func TestCmdRestore_MissingSrcKeepsDst(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.db")
	if err := os.WriteFile(dst, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, dbPath: dst, yes: true,
		controlSocket: "/tmp/this-does-not-exist.sock"}
	code := cmdRestore(opts, []string{filepath.Join(dir, "nope.db")})
	if code == 0 {
		t.Fatal("expected non-zero exit on missing src")
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "untouched" {
		t.Fatalf("dst should be untouched, got %q", got)
	}
}

// 仅触发 backup 命令行 flag 路径,避免子命令重构后 flag 解析回归。
func TestCmdBackup_FlagParseUnknownErrs(t *testing.T) {
	ctx := context.Background()
	st := &store.Store{}
	out := &bytes.Buffer{}
	opts := &globalOpts{stdout: out, stderr: out, yes: true}
	if err := cmdBackup(ctx, st, opts, []string{"--mystery"}); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}
