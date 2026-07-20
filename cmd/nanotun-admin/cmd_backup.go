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
				return errors.New(opts.T("backup.outNeedsPath"))
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
	// 用 SQL 注入风险低(abs 来自命令行),但还是用单引号转义防呆。
	escaped := strings.ReplaceAll(abs, "'", "''")
	opCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err := st.DB().ExecContext(opCtx, fmt.Sprintf("VACUUM INTO '%s'", escaped)); err != nil {
		return fmt.Errorf("%s: %w", opts.T("backup.vacuumIntoFail"), err)
	}
	_ = os.Chmod(abs, backupFileMode)
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
			return errors.New(opts.T("common.canceled"))
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

// copyFileAtomic 把 src 拷到 dst.tmp,然后 rename → dst,保证半截文件不会被
// server 拿来用。dst 已存在时直接覆盖。
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, backupFileMode)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy: %w", err)
	}
	// G2(2026-05-22):Sync / Close / Rename 任一失败都必须清理 tmp,
	// 否则下次 backup 看到陈旧 .tmp,容易让人误以为是上次成功的备份;
	// 残留半截文件占盘且持续没人收。
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
