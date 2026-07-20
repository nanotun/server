package store

import (
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
