package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// isUniqueConstraintErr 判断一个 error 是否是 SQLite UNIQUE 约束冲突。
//
// modernc.org/sqlite 把 result code 嵌在 error message 里(形如
// "constraint failed: UNIQUE constraint failed: users.username (2067)"),
// 但 export 的 sentinel 既不稳定(包 minor 版本可能换)也未导出 result code 常量。
// 文档建议字符串匹配 "UNIQUE constraint failed",这正是这里的做法。
//
// 优势:
//   - 不依赖具体 modernc.org/sqlite 版本的内部错误类型;
//   - 同时兼容 mattn/go-sqlite3 / database/sql 包装后的 wrapper(message 一致);
//   - 失败匹配时退化为「不是 UNIQUE 冲突」——调用方按其它错误处理(更安全的方向)。
//
// 已知的两类等价文本:
//   - "UNIQUE constraint failed: ..."   (modernc.org/sqlite)
//   - "constraint failed: UNIQUE ..."   (旧版部分包装)
func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed: UNIQUE")
}

// IsUnrecoverable 判断一个打库 / 迁移错误是否**重启一万次也不会好**。
//
// 用途是让调用方挑退出码:systemd 单元把「修不好」的那几个 code 列进
// RestartPreventExitStatus,单元直接落到 failed,`systemctl status` 一眼看到死因;
// 其余的照旧 Restart=on-failure —— 库被别的进程占着写锁、磁盘一时写满、挂载还没
// 就绪,这些等一会儿真能自己好,不该因为一次抖动就要人工介入。
//
// 只收录**确定性**的三类,宁可漏判(退回可重启)也不误判(把能自愈的场景钉死):
//   - schema 比程序新:降级回来了,见 migrations.go 的守卫
//   - database disk image is malformed:SQLITE_CORRUPT,库页损坏
//   - file is not a database:SQLITE_NOTADB,压根不是 SQLite 文件(拿错文件 / 被覆盖)
//
// 错误码同样按 modernc.org/sqlite 的惯例走文本匹配,理由见 isUniqueConstraintErr。
func IsUnrecoverable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrSchemaFromFuture) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database disk image is malformed") ||
		strings.Contains(msg, "file is not a database")
}

// diskFullHint 在「其实是盘满了」的错误后面补一句人话。
//
// 盘满时 SQLite 未必说 "database or disk is full"。建表这类要落盘的动作报的是
// **"disk I/O error (4874)"**,而这句话会把人往完全错误的方向带:看见 I/O error 的第一反应
// 是硬盘要坏了、是不是该换机器,没人会想到去 df 一眼。2026-08-07 实测:库所在文件系统写满的
// 机器上跑安装脚本,屏幕上只有
//
//	migrate: store: create app_settings: disk I/O error (4874)
//
// 一句,而清出几百 KB 就一切正常。
//
// 判定不靠猜错误码,直接去库目录里试着写一小块 —— 能不能写,本来就是这里唯一关心的事。
// 写得进去就说明另有原因,那时一个字都不加,免得把真的 I/O 故障说成盘满。
func diskFullHint(dbPath string, err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "disk i/o error") && !strings.Contains(msg, "disk is full") {
		return err
	}
	dir := filepath.Dir(dbPath)
	if dirWritable(dir) {
		return err
	}
	return fmt.Errorf("%w\n"+
		"  Cannot write to %s — this filesystem is full (or the quota is exhausted).\n"+
		"  SQLite reports \"disk I/O error\" here, which looks like a failing disk; freeing space is all it takes:\n"+
		"    df -h %s\n"+
		"    du -xh %s | sort -h | tail   # what is using it\n"+
		"  Logs eating the disk is the most common cause; journalctl --vacuum-size=200M is usually enough.", err, dir, dir, dir)
}

// dirWritable 试着在 dir 里写 64 KB 再删掉,报告成功与否。
//
// 用真写一次而不是 statfs:要判的就是「现在能不能往这儿落盘」,而这件事还会被配额、
// 只读挂载、预留块这些 statfs 看不全的东西左右。判不出来(比如建不了临时文件)时返回 true,
// 也就是不下结论 —— 宁可少说一句,不可把别的故障说成盘满。
func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".nanotun-space-")
	if err != nil {
		return true
	}
	defer func() { _ = os.Remove(f.Name()); _ = f.Close() }()
	if _, err := f.Write(make([]byte, 64<<10)); err != nil {
		return false
	}
	return f.Sync() == nil
}
