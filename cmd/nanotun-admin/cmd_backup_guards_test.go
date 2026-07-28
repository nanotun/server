package main

// cmd_backup_guards_test.go(第二十二轮)—— backup / restore / vacuum 的拒绝面。
//
// 这三条命令是整个系统里唯一能「一句话报废生产库」的地方,所以每一道校验都要钉死:
//
//   - backup 落盘的是**全部密材**(PSK 哈希、TOTP secret、mTLS key)。权限或
//     no-clobber 出错都不会报错,只会静静留下一份别人读得到、或被别人换掉的库;
//   - restore 覆盖前必须验源:半截下载的备份、拿错的 tar.gz、0 字节的 cron 产物
//     一旦盖上去,server 会把它自动迁移成一个空库 —— 看着一切正常,用户全没了;
//   - restore 还必须确认没人正持有现库:漏了这一步,残留进程会继续往被 unlink
//     的旧 inode 写,全程零报错,而那些数据谁也读不到。

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =========================================================================
// backup
// =========================================================================

func TestCmdBackup_WritesAPrivateSnapshotAndRefusesToClobber(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "src.db")
	out := filepath.Join(dir, "snap.db")

	code, stdout, stderr := runCLI(t, db, "", "backup", "--out", out)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, out) {
		t.Errorf("输出里没写清备份落在哪:%q", stdout)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatalf("备份文件不存在: %v", err)
	}
	// 0600:备份含全部密材,同机其它本地用户不能读。
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("备份权限是 %o,期望 600 —— 同机其它用户能读走整库密材", perm)
	}
	if fi.Size() == 0 {
		t.Error("备份是 0 字节")
	}
	// 备份必须是一个能打开、且认得出是 nanotun 库的文件 —— 否则恢复时才发现就晚了。
	if err := validateRestoreSource(out); err != nil {
		t.Errorf("刚做出来的备份自己都过不了恢复校验: %v", err)
	}

	// 重复跑同一条命令不能覆盖已有文件(运维手滑重跑是常态)。
	code, _, stderr = runCLI(t, db, "", "backup", "--out", out)
	if code == 0 {
		t.Fatal("目标已存在却照样备份 —— 上一份被静默覆盖")
	}
	if !strings.Contains(stderr, out) {
		t.Errorf("没说清是哪个文件已存在: %q", stderr)
	}
}

// --out 的两种写法都要认,缺值和写错 flag 要按用法错误退 2(而不是 1):
// 脚本靠退出码区分「我把命令写错了」和「库出问题了」。
func TestCmdBackup_FlagParsing(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "src.db")

	t.Run("--out=PATH 等号写法", func(t *testing.T) {
		out := filepath.Join(dir, "eq.db")
		if code, _, stderr := runCLI(t, db, "", "backup", "--out="+out); code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if _, err := os.Stat(out); err != nil {
			t.Fatalf("等号写法没落盘: %v", err)
		}
	})

	t.Run("-o 短写法", func(t *testing.T) {
		out := filepath.Join(dir, "short.db")
		if code, _, stderr := runCLI(t, db, "", "backup", "-o", out); code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if _, err := os.Stat(out); err != nil {
			t.Fatalf("短写法没落盘: %v", err)
		}
	})

	t.Run("--out 缺路径", func(t *testing.T) {
		code, _, _ := runCLI(t, db, "", "backup", "--out")
		if code != 2 {
			t.Fatalf("code=%d, 期望 2(用法错误)", code)
		}
	})

	t.Run("不认识的 flag", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "backup", "--compress")
		if code == 0 {
			t.Fatal("不认识的 flag 被默默忽略了 —— 运维会以为自己开了压缩")
		}
		if !strings.Contains(stderr, "--compress") {
			t.Errorf("没指出是哪个 flag: %q", stderr)
		}
	})
}

// 目标目录不存在时要报错,不能悄悄把备份丢到别处(比如当前工作目录)。
func TestCmdBackup_UnwritableTargetIsReported(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "src.db")
	code, _, stderr := runCLI(t, db, "",
		"backup", "--out", filepath.Join(dir, "no-such-dir", "snap.db"))
	if code == 0 {
		t.Fatal("目录不存在却报备份成功")
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败了却什么也没说")
	}
}

// 不带 --out 时按时间戳落在当前目录。这条路径平时没人测,但它才是运维手敲的默认用法。
func TestCmdBackup_DefaultNameLandsInWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "src.db")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	if code, _, stderr := runCLI(t, db, "", "backup"); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	found := ""
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "backup-") && strings.HasSuffix(e.Name(), ".db") {
			found = e.Name()
		}
	}
	if found == "" {
		t.Fatalf("默认名的备份没出现在工作目录里: %v", entries)
	}
}

// =========================================================================
// restore:验源
// =========================================================================

func TestValidateRestoreSource_RejectsEverythingThatIsNotOurDatabase(t *testing.T) {
	dir := t.TempDir()

	writeFile := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatalf("写 %s: %v", name, err)
		}
		return p
	}

	t.Run("文件不存在", func(t *testing.T) {
		if err := validateRestoreSource(filepath.Join(dir, "nope.db")); err == nil {
			t.Fatal("不存在的文件却通过了校验")
		}
	})

	t.Run("0 字节(cron 半路死掉的产物)", func(t *testing.T) {
		if err := validateRestoreSource(writeFile("empty.db", nil)); err == nil {
			t.Fatal("0 字节文件通过了校验 —— 盖上去生产库当场报废")
		}
	})

	t.Run("纯文本 / 拿错的 tar.gz", func(t *testing.T) {
		if err := validateRestoreSource(writeFile("notes.txt", []byte("这不是数据库"))); err == nil {
			t.Fatal("文本文件通过了校验")
		}
	})

	t.Run("头几个字节像 SQLite 但内容是垃圾", func(t *testing.T) {
		body := append([]byte(sqliteMagic), []byte("垃圾垃圾垃圾垃圾垃圾")...)
		if err := validateRestoreSource(writeFile("fake.db", body)); err == nil {
			t.Fatal("伪造魔数的垃圾文件通过了校验")
		}
	})

	t.Run("是合法 SQLite 库但不是 nanotun 的", func(t *testing.T) {
		// 这一道最关键:前两道全过,盖上去后 server 会把它自动迁移成一个**空库**,
		// 看起来一切正常,实际上全部用户 / 设备 / 租约凭空消失。
		other := filepath.Join(dir, "someone-elses.db")
		st := openStoreForTest(t, other)
		if _, err := st.DB().ExecContext(t.Context(),
			`DROP TABLE users`); err != nil {
			t.Fatalf("拆掉哨兵表: %v", err)
		}
		_ = st.Close()
		err := validateRestoreSource(other)
		if err == nil {
			t.Fatal("缺核心表的库通过了校验 —— 恢复后用户会凭空消失")
		}
		if !strings.Contains(err.Error(), "users") {
			t.Errorf("没说清缺哪张表: %v", err)
		}
	})

	t.Run("自家的库要放行", func(t *testing.T) {
		ours := newInitializedDB(t, dir, "ours.db")
		if err := validateRestoreSource(ours); err != nil {
			t.Fatalf("自家的库被挡住了: %v", err)
		}
	})
}

// =========================================================================
// restore:流程
// =========================================================================

func TestCmdRestore_UsageAndFlagGuards(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "prod.db")
	src := newInitializedDB(t, dir, "snap.db")

	t.Run("不给源文件", func(t *testing.T) {
		if code, _, _ := runCLI(t, db, "", "restore"); code != 2 {
			t.Fatalf("code=%d, 期望 2(用法错误)", code)
		}
	})

	t.Run("不认识的 flag", func(t *testing.T) {
		code, _, stderr := runCLI(t, db, "", "restore", src, "--force")
		if code != 2 {
			t.Fatalf("code=%d, 期望 2", code)
		}
		if !strings.Contains(stderr, "--force") {
			t.Errorf("没指出是哪个 flag: %q", stderr)
		}
	})
}

// 恢复成功要留下三样东西:新库就位、旧库有一份 pre-restore 副本、-wal/-shm 残留被清掉。
//
// 那份副本是唯一的后悔路:恢复到过旧的快照时,「上次备份之后」的全部变更都在里面。
// -wal 不清则更糟 —— 新库配旧 WAL,server 拿到的是一份不一致的状态。
func TestCmdRestore_KeepsAnEscapeHatchAndCleansWALResidue(t *testing.T) {
	dir := t.TempDir()
	prod := newInitializedDB(t, dir, "prod.db")
	// 生产库里有一个用户,备份里没有 —— 恢复后应当消失,副本里应当还在。
	if code, _, e := runCLI(t, prod, "", "user", "create", "will-vanish", "--psk", "p"); code != 0 {
		t.Fatalf("造用户: %s", e)
	}
	snap := newInitializedDB(t, dir, "snap.db")
	// 造 -wal / -shm 残留。
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(prod+suffix, []byte("stale"), 0o600); err != nil {
			t.Fatalf("造 %s 残留: %v", suffix, err)
		}
	}

	code, stdout, stderr := runCLI(t, prod, "", "restore", snap)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, prod) {
		t.Errorf("输出没说清恢复到了哪里: %q", stdout)
	}
	// 后悔路:pre-restore 副本必须存在,且里面那个用户还在。
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	saved := ""
	for _, e := range entries {
		if strings.Contains(e.Name(), ".pre-restore-") && !strings.HasSuffix(e.Name(), "-wal") {
			saved = filepath.Join(dir, e.Name())
		}
	}
	if saved == "" {
		t.Fatalf("没留下 pre-restore 副本 —— 误恢复之后没有回头路: %v", entries)
	}
	st := openStoreForTest(t, saved)
	defer st.Close()
	if u, err := st.GetUserByUsername(t.Context(), "will-vanish"); err != nil || u == nil {
		t.Errorf("副本里没有恢复前的数据(err=%v) —— 这条后悔路是假的", err)
	}

	// WAL / SHM 残留必须清掉。
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(prod + suffix); err == nil {
			t.Errorf("%s 残留没清 —— server 会拿到一份不一致的 WAL", suffix)
		}
	}
}

// 源文件不合法时必须在**落盘之前**退出,现库一个字节都不能动。
func TestCmdRestore_BadSourceLeavesProductionUntouched(t *testing.T) {
	dir := t.TempDir()
	prod := newInitializedDB(t, dir, "prod.db")
	if code, _, e := runCLI(t, prod, "", "user", "create", "keeper", "--psk", "p"); code != 0 {
		t.Fatalf("造用户: %s", e)
	}
	before, err := os.ReadFile(prod)
	if err != nil {
		t.Fatalf("读现库: %v", err)
	}

	bad := filepath.Join(dir, "half-downloaded.db")
	if err := os.WriteFile(bad, []byte("SQLite format 3\x00 然后就断了"), 0o600); err != nil {
		t.Fatalf("造坏备份: %v", err)
	}

	code, _, stderr := runCLI(t, prod, "", "restore", bad)
	if code == 0 {
		t.Fatal("坏备份被恢复上去了")
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败了却没说原因")
	}
	after, err := os.ReadFile(prod)
	if err != nil {
		t.Fatalf("重读现库: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("校验失败的恢复动了现库")
	}
	// 用户还在。
	st := openStoreForTest(t, prod)
	defer st.Close()
	if u, err := st.GetUserByUsername(t.Context(), "keeper"); err != nil || u == nil {
		t.Errorf("现库数据被动过了(err=%v)", err)
	}
}

// nanotund 还在跑就不许恢复:它持有旧 inode,替换后写入全进孤儿文件且零报错。
// --force-while-running 是运维显式承担风险的开关,那时要打醒目警告。
func TestCmdRestore_RefusesWhileTheServerIsRunning(t *testing.T) {
	dir := t.TempDir()
	prod := newInitializedDB(t, dir, "prod.db")
	snap := newInitializedDB(t, dir, "snap.db")
	fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
		"/status": jsonHandler(`{"ok":true,"conn_count":3}`)})

	code, _, stderr := runCLISock(t, prod, fc.path, "restore", snap)
	if code == 0 {
		t.Fatal("server 在跑却照样恢复 —— 之后的写入全进孤儿文件")
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("拒绝了却没说是因为 server 在跑")
	}

	// 带上 --force-while-running:允许,但必须留下警告。
	code, _, stderr = runCLISock(t, prod, fc.path, "restore", snap, "--force-while-running")
	if code != 0 {
		t.Fatalf("显式 force 之后仍失败: code=%d stderr=%s", code, stderr)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("强制恢复没有任何警告 —— 这是最危险的一条路径")
	}
}

// 二次确认答「不」时不能动库,而且要以 0 退出 —— 用户主动取消不是失败,
// 脚本按非 0 判失败会触发不必要的告警。
func TestCmdRestore_DecliningTheConfirmationChangesNothing(t *testing.T) {
	dir := t.TempDir()
	prod := newInitializedDB(t, dir, "prod.db")
	if code, _, e := runCLI(t, prod, "", "user", "create", "keeper", "--psk", "p"); code != 0 {
		t.Fatalf("造用户: %s", e)
	}
	snap := newInitializedDB(t, dir, "snap.db")
	before, _ := os.ReadFile(prod)

	code, stdout, stderr := runCLIInteractive(t, prod, "n\n", "restore", snap)
	if code != 0 {
		t.Fatalf("取消却以 %d 退出 stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "取消") {
		t.Errorf("没告诉用户已取消: %q", stdout)
	}
	after, _ := os.ReadFile(prod)
	if string(before) != string(after) {
		t.Fatal("用户答了「不」,库却被改了")
	}
}

// =========================================================================
// vacuum
// =========================================================================

func TestCmdVacuum_CompactsAndRespectsTheCancel(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "vac.db")

	t.Run("答不 → 打印已取消并 exit 0", func(t *testing.T) {
		code, stdout, stderr := runCLIInteractive(t, db, "n\n", "vacuum")
		if code != 0 {
			t.Fatalf("取消却以 %d 退出 stderr=%s", code, stderr)
		}
		if !strings.Contains(stdout, "取消") {
			t.Errorf("没告诉用户已取消: %q", stdout)
		}
	})

	t.Run("确认后真的重建库", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, db, "", "vacuum")
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("vacuum 完了一句话都不说,运维无从确认")
		}
		// 库还能用 —— VACUUM 之后打不开是最糟的结果。
		st := openStoreForTest(t, db)
		defer st.Close()
		if _, err := st.CountUsers(t.Context()); err != nil {
			t.Errorf("vacuum 之后库不可用: %v", err)
		}
	})
}

// =========================================================================
// 底层文件动作
// =========================================================================

// copyFileAtomic 的失败必须**不留残骸**:半截的临时文件会占盘,而且看起来
// 像一份可用的备份。
func TestCopyFileAtomic_FailuresLeaveNoDebris(t *testing.T) {
	dir := t.TempDir()

	t.Run("源文件不存在", func(t *testing.T) {
		err := copyFileAtomic(filepath.Join(dir, "nope"), filepath.Join(dir, "dst"))
		if err == nil {
			t.Fatal("源不存在却报成功")
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("失败后留下了 %v", entries)
		}
	})

	t.Run("目标目录不存在", func(t *testing.T) {
		src := filepath.Join(dir, "src")
		if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
			t.Fatalf("写源: %v", err)
		}
		if err := copyFileAtomic(src, filepath.Join(dir, "no-such-dir", "dst")); err == nil {
			t.Fatal("目标目录不存在却报成功")
		}
	})

	t.Run("成功时权限收紧到 600", func(t *testing.T) {
		src := filepath.Join(dir, "src2")
		dst := filepath.Join(dir, "dst2")
		if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
			t.Fatalf("写源: %v", err)
		}
		if err := copyFileAtomic(src, dst); err != nil {
			t.Fatalf("copyFileAtomic: %v", err)
		}
		fi, err := os.Stat(dst)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("目标权限 %o,期望 600(拷的是整库密材)", perm)
		}
		// 临时文件不能留下。
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.Contains(e.Name(), ".tmp-") {
				t.Errorf("留下了临时文件 %s", e.Name())
			}
		}
	})
}

// 现库不存在时(全新机器上直接 restore)不算错,只是没有副本可留。
func TestSnapshotBeforeRestore_NoDatabaseYetIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	saved, err := snapshotBeforeRestore(filepath.Join(dir, "not-there.db"))
	if err != nil {
		t.Fatalf("现库不存在被当成了错误: %v", err)
	}
	if saved != "" {
		t.Fatalf("凭空报告了一份副本: %q", saved)
	}
}

// 同一秒内重复恢复:副本已存在即达成目的,不能因此失败整条恢复。
func TestSnapshotBeforeRestore_SameSecondRetryIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "prod.db")
	first, err := snapshotBeforeRestore(db)
	if err != nil {
		t.Fatalf("第一次: %v", err)
	}
	second, err := snapshotBeforeRestore(db)
	if err != nil {
		t.Fatalf("同一秒内第二次却失败了: %v", err)
	}
	if first != second {
		t.Logf("两次副本名不同(跨秒了): %q / %q", first, second)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatalf("副本不存在: %v", err)
	}
}

// =========================================================================
// 第二十二轮补:剩下的失败路径
// =========================================================================

// requireNonRoot 跳过依赖「目录不可写」的用例 —— root 无视权限位。
func requireNonRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("以 root 运行时目录权限位不起作用")
	}
}

// readOnlyDir 造一个 0500 的目录(可读可进、不可写),用完自动恢复以便 t.TempDir 清理。
func readOnlyDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod 0500 %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

// backup 的 no-clobber 是靠 os.Link(原子 EEXIST)兜的,不是靠前面那次 os.Stat ——
// 第十轮把 Rename 换成 Link 就是为了这个。悬空符号链接是能同时骗过 Stat、又让 Link
// 撞 EEXIST 的现成场景:Stat 跟随链接看到「不存在」,Link 却在链接自身上撞车。
// 若哪天有人把 Link 换回 Rename,备份就会顺着链接把整库密材写到攻击者指定的位置。
func TestCmdBackup_DanglingSymlinkTargetIsRefused(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "src.db")
	out := filepath.Join(dir, "snap.db")
	victim := filepath.Join(dir, "does-not-exist-yet")
	if err := os.Symlink(victim, out); err != nil {
		t.Fatalf("造悬空符号链接: %v", err)
	}

	code, _, stderr := runCLI(t, db, "", "backup", "--out", out)
	if code == 0 {
		t.Fatal("备份顺着悬空符号链接写了出去 —— 整库密材落到了链接目标处")
	}
	if !strings.Contains(stderr, out) {
		t.Errorf("没说清是哪个路径被占了: %q", stderr)
	}
	if _, err := os.Stat(victim); err == nil {
		t.Fatal("链接目标被创建了 —— 说明真写过去了")
	}
	// 目录里不该留下临时目录残骸。
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".nanotun-backup-") {
			t.Errorf("留下了临时目录 %s", e.Name())
		}
	}
}

// restore 没有 --db-path 时必须直接拒:没有目标路径却继续往下走,只会在更深处
// 用空字符串拼出莫名其妙的路径。
func TestCmdRestore_WithoutDBPathRefuses(t *testing.T) {
	dir := t.TempDir()
	src := newInitializedDB(t, dir, "snap.db")
	opts, _ := newConfirmOpts("")
	opts.yes = true
	opts.dbPath = ""
	errb := &bytes.Buffer{}
	opts.stderr = errb

	if code := cmdRestore(opts, []string{src}); code == 0 {
		t.Fatal("没有 --db-path 却报恢复成功")
	}
	if strings.TrimSpace(errb.String()) == "" {
		t.Error("拒了却没说是缺 --db-path")
	}
}

// pre-restore 副本做不出来时必须**在覆盖之前**中止 —— 那份副本是误恢复后唯一的后悔路,
// 悄悄跳过它去覆盖生产库,等于把「恢复到过旧快照」变成不可逆操作。
func TestCmdRestore_SnapshotFailureAbortsBeforeOverwriting(t *testing.T) {
	requireNonRoot(t)
	dir := t.TempDir()
	prod := newInitializedDB(t, dir, "prod.db")
	if code, _, e := runCLI(t, prod, "", "user", "create", "keeper", "--psk", "p"); code != 0 {
		t.Fatalf("造用户: %s", e)
	}
	before, err := os.ReadFile(prod)
	if err != nil {
		t.Fatalf("读现库: %v", err)
	}
	// 备份源放在别处,只让**生产库所在目录**不可写:副本(硬链接)建不出来。
	srcDir := t.TempDir()
	snap := newInitializedDB(t, srcDir, "snap.db")
	readOnlyDir(t, dir)

	code, stdout, stderr := runCLI(t, prod, "", "restore", snap)
	if code == 0 {
		t.Fatalf("留不下副本却照样恢复, stdout=%q", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败却没说原因")
	}
	after, err := os.ReadFile(prod)
	if err != nil {
		t.Fatalf("重读现库: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("副本没留成,生产库却已经被动过了")
	}
}

// 拷贝这一步失败时同样要报错。这里现库尚不存在(全新机器),所以副本环节被跳过,
// 失败点落在 copyFileAtomic —— 若它谎报成功,脚本会以为部署完成而库根本没落地。
func TestCmdRestore_CopyFailureIsReported(t *testing.T) {
	requireNonRoot(t)
	dir := t.TempDir()
	srcDir := t.TempDir()
	snap := newInitializedDB(t, srcDir, "snap.db")
	prod := filepath.Join(dir, "prod.db") // 故意不创建
	readOnlyDir(t, dir)

	code, stdout, stderr := runCLI(t, prod, "", "restore", snap)
	if code == 0 {
		t.Fatalf("目标目录不可写却报恢复成功, stdout=%q", stdout)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("失败却没说原因")
	}
	if _, err := os.Stat(prod); err == nil {
		t.Fatal("说是失败了,库文件却出现了")
	}
}

// snapshotBeforeRestore 只把「现库不存在」当成非错误。其它 Stat 失败(比如路径中间
// 那一段其实是个文件)必须原样上报 —— 否则会被误判成「全新机器」,直接跳过后悔路。
func TestSnapshotBeforeRestore_OtherStatErrorsPropagate(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("写文件: %v", err)
	}
	saved, err := snapshotBeforeRestore(filepath.Join(notADir, "prod.db"))
	if err == nil {
		t.Fatal("路径中间是个文件,却被当成「现库不存在」放过了")
	}
	if saved != "" {
		t.Errorf("失败却报告了副本路径: %q", saved)
	}
}

// 建副本的硬链接失败(目录不可写)不能被当成「没有现库」—— 那会让 restore 以为
// 不需要留后悔路,继续往下覆盖。
func TestSnapshotBeforeRestore_LinkFailurePropagates(t *testing.T) {
	requireNonRoot(t)
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "prod.db")
	readOnlyDir(t, dir)

	saved, err := snapshotBeforeRestore(db)
	if err == nil {
		t.Fatal("目录不可写却报告副本已建好")
	}
	if saved != "" {
		t.Errorf("失败却报告了副本路径: %q", saved)
	}
}

// 源是个目录时 io.Copy 会在读的那一步失败。这条路径要保证临时文件被清掉 ——
// 残留的半截文件看起来就像一份可用的备份。
func TestCopyFileAtomic_SourceIsDirectoryLeavesNoDebris(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "adir")
	if err := os.Mkdir(srcDir, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	dst := filepath.Join(dir, "dst.db")

	if err := copyFileAtomic(srcDir, dst); err == nil {
		t.Fatal("源是目录却报拷贝成功")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Error("失败却生成了目标文件")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("留下了临时文件 %s", e.Name())
		}
	}
}

// 目标已经是个目录时,最后那一步 rename 会失败。同样要清临时文件。
func TestCopyFileAtomic_DestinationIsDirectoryLeavesNoDebris(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatalf("写源: %v", err)
	}
	dst := filepath.Join(dir, "dst.db")
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	if err := copyFileAtomic(src, dst); err == nil {
		t.Fatal("目标是目录却报拷贝成功")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("留下了临时文件 %s", e.Name())
		}
	}
}

// integrity_check 报告损坏(而不是直接打不开)的备份也要挡住:这类文件魔数正确、
// 能被 SQLite 打开,盖上去之后要等 server 真去读那几页才炸,现场最难排查。
func TestValidateRestoreSource_CorruptPagesAreRejected(t *testing.T) {
	dir := t.TempDir()
	good := newInitializedDB(t, dir, "good.db")
	// 先塞点数据,确保 b-tree 有实际内容页可供破坏。
	if c, _, e := runCLI(t, good, "", "user", "create", "u1", "--psk", "p"); c != 0 {
		t.Fatalf("造用户: %s", e)
	}
	body, err := os.ReadFile(good)
	if err != nil {
		t.Fatalf("读库: %v", err)
	}
	if len(body) < 8192 {
		t.Skipf("库只有 %d 字节,没有可破坏的内容页", len(body))
	}
	// 保留第 1 页(文件头 + schema 根页),把后面几页涂掉:魔数仍对、仍能打开,
	// 但 integrity_check 会报出问题。
	for i := 4096; i < len(body) && i < 4096*4; i++ {
		body[i] = 0x5a
	}
	bad := filepath.Join(dir, "corrupt.db")
	if err := os.WriteFile(bad, body, 0o600); err != nil {
		t.Fatalf("写坏库: %v", err)
	}

	err = validateRestoreSource(bad)
	if err == nil {
		t.Fatal("页损坏的备份通过了校验 —— server 读到那几页时才会炸")
	}
	if !strings.Contains(err.Error(), "integrity_check") {
		t.Errorf("应由 integrity_check 拦下,实际: %v", err)
	}
}
