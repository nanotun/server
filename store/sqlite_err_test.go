package store

import (
	"errors"
	"fmt"
	"testing"
)

// TestIsUnrecoverable 钉住「哪些库错误值得让 systemd 停手」这条线。
//
// 判错的两个方向代价不同:漏判 = 退回 Restart=on-failure,最多多刷几行 journal;
// 误判 = 把一个等一会儿能自己好的场景(写锁 / 磁盘一时满)钉成 failed,要人工介入。
// 所以下面「不该判为永久」的用例比另一半更要紧。
func TestIsUnrecoverable(t *testing.T) {
	permanent := map[string]error{
		"schema 比程序新(降级)": fmt.Errorf("wrap: %w", ErrSchemaFromFuture),
		"库页损坏":            errors.New("store: ping: database disk image is malformed (11)"),
		"压根不是 SQLite 文件":  errors.New("store: open: file is not a database (26)"),
	}
	for name, err := range permanent {
		if !IsUnrecoverable(err) {
			t.Errorf("%s 应判为永久故障,却判成了可重启: %v", name, err)
		}
	}

	transient := map[string]error{
		"nil":       nil,
		"被占着写锁":     errors.New("store: begin tx: database is locked (5)"),
		"表被占用":      errors.New("store: exec: database table is locked (6)"),
		"磁盘写满":      errors.New("store: exec: database or disk is full (13)"),
		"没有写权限":     errors.New("store: open: unable to open database file (14)"),
		"目录还没挂上":    errors.New("store: open: no such file or directory"),
		"UNIQUE 冲突": errors.New("UNIQUE constraint failed: users.username (2067)"),
	}
	for name, err := range transient {
		if IsUnrecoverable(err) {
			t.Errorf("%s 不该被钉成永久故障(会要人工介入): %v", name, err)
		}
	}
}
