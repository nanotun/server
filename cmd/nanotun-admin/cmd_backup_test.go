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

// backup 与 restore 总是成对出现,而 restore 的路径是位置参数。此前 backup 只认 --out,
// 敲成 `backup out.db` 回的是「unknown flag "out.db"」—— 一个裸路径不是 flag,那句话连
// 「它其实该是输出路径」都没说出来。灾难现场是凭记忆敲命令的,记混哪个带 flag 迟早发生。
func TestCmdBackup_TakesPathPositionallyLikeRestore(t *testing.T) {
	newStore := func(t *testing.T, dir string) *store.Store {
		t.Helper()
		st, err := store.Open(t.Context(), filepath.Join(dir, "src.db"), store.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := st.Migrate(t.Context()); err != nil {
			t.Fatal(err)
		}
		return st
	}

	t.Run("裸路径与 --out 等价", func(t *testing.T) {
		dir := t.TempDir()
		st := newStore(t, dir)
		out := &bytes.Buffer{}
		opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, yes: true, lang: langZH}
		p := filepath.Join(dir, "positional.db")
		if err := cmdBackup(t.Context(), st, opts, []string{p}); err != nil {
			t.Fatalf("cmdBackup: %v", err)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("备份没写到位置参数给的路径: %v", err)
		}
	})

	t.Run("两处都给就是用法错误", func(t *testing.T) {
		dir := t.TempDir()
		st := newStore(t, dir)
		out := &bytes.Buffer{}
		opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, yes: true, lang: langZH}
		err := cmdBackup(t.Context(), st, opts,
			[]string{filepath.Join(dir, "a.db"), "--out", filepath.Join(dir, "b.db")})
		if err == nil {
			t.Fatal("给了两个输出路径应当报错,而不是悄悄用其中一个")
		}
		// 悄悄挑一个写出去最糟:人以为备份在 a,实际在 b,发现时已经是要用它的时候。
		if _, e := os.Stat(filepath.Join(dir, "a.db")); e == nil {
			t.Error("报错了却还是写出了文件")
		}
		if _, e := os.Stat(filepath.Join(dir, "b.db")); e == nil {
			t.Error("报错了却还是写出了文件")
		}
	})

	t.Run("真打错 flag 仍要拦", func(t *testing.T) {
		dir := t.TempDir()
		st := newStore(t, dir)
		out := &bytes.Buffer{}
		opts := &globalOpts{stdout: out, stderr: out, stdin: os.Stdin, yes: true, lang: langZH}
		if err := cmdBackup(t.Context(), st, opts, []string{"--oout", "x.db"}); err == nil {
			t.Fatal("--oout 是拼错的 flag,不该被当成路径收下")
		}
	})
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
