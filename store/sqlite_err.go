package store

import (
	"errors"
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
