package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nanotun/server/store"
)

// P1#10: nanotun-admin backup / restore / vacuum
//
// 设计:
//   * backup:用 SQLite `VACUUM INTO '<path>'` 拿一份强一致快照。它本身是只读
//     操作(只读源库,只写目标文件),与 server 写并发不互锁(WAL 模式下)。
//     输出文件路径默认 ./backup-YYYYMMDD-HHMMSS.db,可用 --out PATH 指定。
//   * restore:把指定 .db 拷贝到生产路径。强烈建议 server 已停;运行中替换
//     会导致 server 仍持有老 inode 的句柄,新 admin / migration 看到的是新文件,
//     状态会分裂。所以默认拒绝写到 db_path(除非 --force-while-running)。
//   * vacuum:重建 sqlite 文件,回收空闲页;期间整张库被独占 ~秒级。建议在
//     维护窗口跑;运行中跑会阻塞所有读写直到完成。
//
// 全部命令都需要写连接(VACUUM 不能在 query_only 下跑),dispatcher 已设置 readOnly=false / true 见 main.go。

const backupFileMode = 0o600

// cmdBackup:`nanotun-admin backup [--out PATH]`
func cmdBackup(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	out := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out", "-o":
			if i+1 >= len(args) {
				// 第十四轮深扫 LOW:缺 flag 取值属用法错误 → exit 2。
				return usageError(opts.T("backup.outNeedsPath"))
			}
			out = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "--out=") {
				out = args[i][len("--out="):]
			} else {
				return newLocErr("cli.unknownFlag", args[i])
			}
		}
	}
	if out == "" {
		out = fmt.Sprintf("backup-%s.db", time.Now().Format("20060102-150405"))
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("backup.absOutFail"), err)
	}
	// VACUUM INTO 要求目标文件不存在;运维误重复跑容易撞 "file exists"。
	if _, err := os.Stat(abs); err == nil {
		return errors.New(opts.T("backup.targetExists", abs))
	}
	opCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// 权限窗口加固(修 backup VACUUM TOCTOU):备份库含全部密材(PSK 哈希 / TOTP secret / mTLS key)。
	// SQLite `VACUUM INTO` 由引擎自己创建目标文件,受进程 umask 影响常落 0644 —— 到我们后续 os.Chmod(0600)
	// 之间存在一个「世界可读」窗口,同机其它本地用户可趁机读走整库。且直接 VACUUM INTO 用户给的路径时,
	// 若该路径落在他人可写目录还可能被符号链接/抢建做手脚。
	//
	// 做法:先在**目标同目录**下建一个 0700 私有临时目录(os.MkdirTemp 恒 0700,别人无法进入),把 VACUUM INTO
	// 写进该目录内 —— 即便文件被创建成 0644,外部也因父目录 0700 无法访问;随后 chmod 0600 + rename 到最终
	// 路径(同文件系统,原子)。全程备份内容对 group/other 不可见,消除窗口;临时目录用完即删。
	tmpDir, err := os.MkdirTemp(filepath.Dir(abs), ".nanotun-backup-*")
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("backup.vacuumIntoFail"), err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	tmpPath := filepath.Join(tmpDir, "backup.db")

	// 用 SQL 注入风险低(路径由我们拼),但仍用单引号转义防呆。
	escaped := strings.ReplaceAll(tmpPath, "'", "''")
	if _, err := st.DB().ExecContext(opCtx, fmt.Sprintf("VACUUM INTO '%s'", escaped)); err != nil {
		return fmt.Errorf("%s: %w", opts.T("backup.vacuumIntoFail"), err)
	}
	if err := os.Chmod(tmpPath, backupFileMode); err != nil {
		return fmt.Errorf("%s: %w", opts.T("backup.vacuumIntoFail"), err)
	}
	// 第十轮深扫 LOW:发布用 os.Link(硬链接)而非 os.Rename。Rename 会**覆盖**已存在的目标,
	// 令上面 os.Stat 的「不存在才继续」no-clobber 检查形同虚设 —— Stat→publish 之间他人(或并发的
	// 第二次 backup)抢建同名文件时会被静默覆盖。os.Link 在目标已存在时返回 EEXIST(原子 no-clobber),
	// 与 writeFileTight 同口径。tmpPath 与 abs 同文件系统(tmpDir 建在 abs 父目录下),硬链接可用;
	// 链接成功后 tmpPath 仍由 defer 的 os.RemoveAll(tmpDir) 清掉,只留最终 abs。
	if err := os.Link(tmpPath, abs); err != nil {
		if os.IsExist(err) {
			return errors.New(opts.T("backup.targetExists", abs))
		}
		return fmt.Errorf("%s: %w", opts.T("backup.vacuumIntoFail"), err)
	}
	fmt.Fprintln(opts.stdout, opts.T("backup.written", abs))
	return nil
}

// cmdRestore:`nanotun-admin restore <src.db> [--force-while-running]`
//
// 不走 runWithStore —— 因为我们要先确认 server 不在跑(没有 control socket
// 或者用户显式 --force);然后用文件拷贝替换。打开 DB 反而会让自己变成另一个
// 持有者,容易把 WAL 卡死。
func cmdRestore(opts *globalOpts, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(opts.stderr, opts.usage("nanotun-admin restore <src.db> [--force-while-running]"))
		return 2
	}
	src := args[0]
	force := false
	for _, a := range args[1:] {
		if a == "--force-while-running" {
			force = true
		} else {
			fmt.Fprintln(opts.stderr, opts.T("cli.unknownFlag", a))
			return 2
		}
	}
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		fmt.Fprintln(opts.stderr, opts.T("backup.absSrcFail", err.Error()))
		return 1
	}
	dst := opts.dbPath
	if dst == "" {
		fmt.Fprintln(opts.stderr, opts.T("backup.noDBPath"))
		return 1
	}
	dstAbs, _ := filepath.Abs(dst)

	if !force {
		if serverIsRunning(opts) {
			fmt.Fprintln(opts.stderr, opts.T("backup.serverRunning"))
			return 1
		}
	} else {
		fmt.Fprintln(opts.stderr, opts.T("backup.forceWarn"))
	}

	if !opts.yes {
		ok, _ := confirm(opts, opts.T("backup.confirmRestore", srcAbs, dstAbs))
		if !ok {
			fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
			return 0
		}
	}

	if err := copyFileAtomic(srcAbs, dstAbs); err != nil {
		fmt.Fprintln(opts.stderr, opts.T("backup.copyFail", err.Error()))
		return 1
	}
	// 一并清掉 -wal / -shm 残留,避免新进程拿到不一致的 WAL 文件。
	_ = os.Remove(dstAbs + "-wal")
	_ = os.Remove(dstAbs + "-shm")

	fmt.Fprintln(opts.stdout, opts.T("backup.restored", srcAbs, dstAbs))
	return 0
}

// cmdVacuum:`nanotun-admin vacuum`
func cmdVacuum(ctx context.Context, st *store.Store, opts *globalOpts, _ []string) error {
	if !opts.yes {
		ok, _ := confirm(opts, opts.T("backup.confirmVacuum"))
		if !ok {
			// 第八轮深扫 LOW:用户主动取消不是错误 → 打印「已取消」并 exit 0,与 restore 取消路径一致
			// (此前返回 error → exit 1,脚本会误判为失败)。
			fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
			return nil
		}
	}
	opCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, err := st.DB().ExecContext(opCtx, "VACUUM"); err != nil {
		return fmt.Errorf("%s: %w", opts.T("backup.vacuumFail"), err)
	}
	fmt.Fprintln(opts.stdout, opts.T("backup.vacuumDone"))
	return nil
}

// copyFileAtomic 把 src 拷到一个私有临时文件,fsync 后 rename → dst,保证半截文件不会被 server 拿来用。
//
// 第三轮深扫 LM1 加固:此前临时文件用**可预测**名 dst+".tmp" 且 `O_CREATE|O_WRONLY|O_TRUNC`(无 O_EXCL)。
// restore 拷贝的是**整库密材**(PSK 哈希 / TOTP secret / mTLS key)。若 db 目录他人可写、或攻击者预置
// <dst>.tmp 为符号链接,OpenFile 会**跟随**它把整库写到链接目标(泄密 / 覆写受害文件);且既有 <dst>.tmp
// 为 0644 时会**保留**该松权限。改用 os.CreateTemp(内部 O_CREATE|O_EXCL + 随机后缀,0600)+ 显式 fchmod +
// fsync + 原子 rename —— 与 writeFileTight / cmdBackup 同姿态,消除符号链接跟随与权限保留窗口。
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	out, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmp := out.Name()
	// G2(2026-05-22):Copy / Chmod / Sync / Close / Rename 任一失败都必须清理 tmp,
	// 否则残留半截文件占盘且持续没人收。
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy: %w", err)
	}
	// CreateTemp 已是 0600;显式 fchmod 到 backupFileMode,确保与既定权限一致(rename 前生效,无宽权限窗口)。
	if err := out.Chmod(backupFileMode); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// serverIsRunning 探测 control socket 是否能联通。
func serverIsRunning(opts *globalOpts) bool {
	cli := newControlHTTPClient(resolveControlSocketPath(opts.controlSocket))
	_, err := controlDo(cli, "GET", "/status", nil)
	return err == nil
}
