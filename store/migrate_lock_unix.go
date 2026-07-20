//go:build !windows && !plan9

package store

import (
	"fmt"
	"os"
	"syscall"
)

// acquireMigrateLock 用 flock(LOCK_EX) 串行化跨进程 Migrate 调用。
//
// 背景:
//   - sync.Mutex 只在单进程内有效;
//   - vpn-server-systemd + nanotun-admin 是两个独立进程,都会调 Store.Migrate(admin
//     CLI 启动时会先 ensure migration 到最新);
//   - SQLite WAL 模式下并发 ALTER TABLE / CREATE INDEX 容易出现「table is locked」
//     或更糟的元数据不一致(尤其是「迁移本身在 BEGIN 之外的语句,比如 PRAGMA」);
//   - 我们用 <db>.migrate.lock 文件 + LOCK_EX 强串行化,而**不**直接锁 db 文件本身
//     (modernc.org/sqlite 自己管理 db 文件的 OS lock,会冲突)。
//
// 调用约定:
//   - 成功返回 (closer, nil),closer() 必须在 Migrate 完成后调用,负责 Funlock + Close;
//   - 多次同进程内调用同一个 path 是允许的(syscall.Flock 是按 fd,不会自死锁);
//   - 锁文件长期存在(以 .migrate.lock 为名),首次创建留下空文件;失败不会留垃圾。
//
// 不使用 LOCK_NB:这里允许阻塞,因为 Migrate 不是热路径,等几秒比让运维去手工排查
// "为什么数据库迁移没执行" 简单得多。
func acquireMigrateLock(dbPath string) (func(), error) {
	if dbPath == ":memory:" || dbPath == "" {
		// 内存库 / 测试场景不需要文件锁:不存在跨进程并发。
		return func() {}, nil
	}
	lockPath := dbPath + ".migrate.lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: open migrate lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("store: flock migrate lock %s: %w", lockPath, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
