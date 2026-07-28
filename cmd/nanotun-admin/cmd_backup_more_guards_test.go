package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// backupDirect 用**指定的连接**跑 cmdBackup / cmdVacuum,绕开 main.go 的连接选型。
// 这层是为了验证「连接开错了会怎样」:VACUUM / VACUUM INTO 在 query_only 连接上
// 会被 SQLite 拒(attempt to write a readonly database)。main.go 的
// runWithStoreNoMigrate 就是为此而存在 —— 若哪天有人把 backup 归到只读子命令里,
// 下面这两条会立刻把后果摆出来。
func withStoreConn(t *testing.T, db string, readOnly bool) (*store.Store, *globalOpts, *bytes.Buffer) {
	t.Helper()
	st, err := store.Open(t.Context(), db, store.Options{ReadOnly: readOnly})
	if err != nil {
		t.Fatalf("store.Open(readOnly=%v): %v", readOnly, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	out := &bytes.Buffer{}
	return st, &globalOpts{lang: langZH, yes: true, stdout: out, stderr: &bytes.Buffer{}}, out
}

func TestCmdBackup_VacuumIntoNeedsAWriteConnection(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "src.db")
	out := filepath.Join(dir, "snap.db")

	st, opts, _ := withStoreConn(t, db, true)
	err := cmdBackup(t.Context(), st, opts, []string{"--out", out})
	if err == nil {
		t.Fatal("只读连接上 VACUUM INTO 竟然成功了 —— 那上面 runWithStoreNoMigrate 的注释就过期了")
	}
	// 报错必须指向 VACUUM 这一步,而不是含糊的 "readonly database":
	// 后者会让人以为是文件权限问题,去 chmod 生产库。
	if !strings.Contains(strings.ToLower(err.Error()), "vacuum") {
		t.Errorf("报错没提 VACUUM: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("失败了还留下了目标文件 —— 半截备份最危险,它能过 os.Stat 却恢复不了")
	}
}

func TestCmdVacuum_FailureIsReported(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "vac.db")
	st, opts, stdout := withStoreConn(t, db, true)
	err := cmdVacuum(t.Context(), st, opts, nil)
	if err == nil {
		t.Fatal("只读连接上 VACUUM 竟然成功了")
	}
	if strings.Contains(stdout.String(), "完成") {
		t.Errorf("失败却报了完成: %q", stdout.String())
	}
}

// 备份路径本身不合法(名字超过文件名长度上限)时,VACUUM 已经把快照写进临时目录、
// 只有最后的发布(硬链接到目标路径)会失败。这条路径必须报错 —— 否则运维看到
// 「已写入 <path>」而那个路径根本不存在,下次真要恢复时才发现。
func TestCmdBackup_PublishFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "src.db")
	tooLong := filepath.Join(dir, strings.Repeat("n", 300)+".db")

	st, opts, stdout := withStoreConn(t, db, false)
	err := cmdBackup(t.Context(), st, opts, []string{"--out", tooLong})
	if err == nil {
		t.Fatalf("超长文件名却报成功: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), tooLong) {
		t.Errorf("失败了还说「已写入」: %q", stdout.String())
	}
	// 临时目录必须收干净:每次失败留一个 .nanotun-backup-* 会慢慢把磁盘吃满,
	// 而里面每一份都是完整的密材副本。
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".nanotun-backup-") {
			t.Errorf("留下了临时备份目录 %s —— 里面是一整份密材", e.Name())
		}
	}
}

// =========================================================================
// writeFileTight:QR / profile 落盘的那层
// =========================================================================

func TestWriteFileTight_StatErrorIsNotMistakenForAbsent(t *testing.T) {
	// 路径中间夹了个普通文件 → Lstat 给 ENOTDIR。这不是「目标不存在」,不能继续往下写;
	// 混为一谈的话后面 CreateTemp 会以另一个更含糊的错误收场。
	dir := t.TempDir()
	plain := filepath.Join(dir, "a-file")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeFileTight(filepath.Join(plain, "nested.png"), []byte("data"), 0o600, false)
	if err == nil {
		t.Fatal("路径不合法却写成功了")
	}
	if !strings.Contains(err.Error(), "stat") {
		t.Errorf("报错没指向 stat 这一步: %v", err)
	}
}

func TestWriteFileTight_NoClobberAndForce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.png")

	if err := writeFileTight(target, []byte("first"), 0o600, false); err != nil {
		t.Fatalf("首次写入: %v", err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	// 这层落的是 QR / profile,内容含 PSK 与 mTLS 私钥:从创建那一刻就必须是 0600。
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("权限 %o,期望 600", perm)
	}

	// force=false 不许覆盖:含密产物被静默覆盖后,已经发给用户的那份就再也导不出来了。
	//
	// 注意这里只能验到「Lstat 那一刻目标已存在」这半边。落盘用 os.Link 而非 os.Rename
	// (link 目标已存在即 EEXIST)是为了关掉 Lstat 与落盘之间的 race 窗口 —— 那半边
	// 只有在并发抢建时才有区别,没有可移植的确定性测法。把 Link 换成 Rename 的变异
	// 因此抓不住;它靠代码注释与 review 守。
	if err := writeFileTight(target, []byte("second"), 0o600, false); err == nil {
		t.Fatal("force=false 却覆盖了已有文件")
	} else if !strings.Contains(err.Error(), "--force") {
		t.Errorf("报错没告诉运维怎么继续: %v", err)
	}
	if b, rerr := os.ReadFile(target); rerr != nil || string(b) != "first" {
		t.Errorf("拒绝覆盖之后内容却变了: %q (%v)", b, rerr)
	}

	// force=true 走原子替换。
	if err := writeFileTight(target, []byte("second"), 0o600, true); err != nil {
		t.Fatalf("force=true: %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "second" {
		t.Errorf("force 之后内容没换: %q", b)
	}

	// 无论哪条路都不许留临时文件(它们与目标同权限、同内容)。
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".out.png.tmp-") {
			t.Errorf("留下临时文件 %s", e.Name())
		}
	}
}

// 已存在的**符号链接**也算「目标已存在」:跟随它写等于把密材写到链接指向的地方。
func TestWriteFileTight_ExistingSymlinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("important"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "out.png")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("这个文件系统建不了符号链接: %v", err)
	}
	if err := writeFileTight(link, []byte("secret"), 0o600, false); err == nil {
		t.Fatal("跟着符号链接把密材写出去了")
	}
	if b, _ := os.ReadFile(victim); string(b) != "important" {
		t.Errorf("受害文件被覆写了: %q", b)
	}
}
