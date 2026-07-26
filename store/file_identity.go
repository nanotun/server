package store

import (
	"context"
	"fmt"
	"os"
	"time"
)

// 库文件被「掉包」的检测。
//
// 背景(2026-07-26 实测):nanotund 与 nanotun-web 是两个进程,共享同一个 SQLite 文件。
// `nanotun-admin restore` 的守栏只探 nanotund 的 control socket,不知道 nanotun-web 也开着;
// 而 restore / 手工 `cp backup.db` 都是**换 inode**(写临时文件再 rename),不是原地覆盖。
// 于是按文档流程「stop nanotun → restore → start nanotun」之后:
//
//	nanotund  → 新文件,正常;
//	nanotun-web → 仍持有那个已被 unlink 的旧 inode。
//
// 后果是彻底静默的:Web 后台建用户返回 303 成功、把一次性 PSK 发给了终端用户,
// 数据却写进一个没人能读到的文件。既不报错、也没有任何日志,直到有人发现
// 「后台明明建过的账号连不上」为止 —— 而这正好发生在灾难恢复之后,最不容易被察觉的时刻。
//
// 单个进程无法阻止别人换文件,但可以**发现**并大声退出:两个 unit 都是
// Restart=on-failure,退出后自动拉起就会重新打开新文件,自愈且不再静默丢数据。

// FileIdentity 是打开时那个文件的身份(设备号 + inode)。
type FileIdentity struct {
	Dev uint64
	Ino uint64
}

// Identity 返回 Store 打开的文件在**当前路径上**的身份。
// 内存库或平台不支持时返回 ok=false。
func fileIdentityOf(path string) (FileIdentity, bool) {
	if path == "" || path == ":memory:" {
		return FileIdentity{}, false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return FileIdentity{}, false
	}
	return sysFileIdentity(fi)
}

// CheckFileIdentity 比较「打开时记住的身份」与「路径上现在的身份」。
//
// 返回 error 仅在**确认被掉包**时:路径存在、可 stat、但 dev/ino 与开库时不同。
// 路径暂时消失(rename 中间态 / 备份脚本挪走又挪回)只返回 nil —— 宁可漏报也不误杀,
// 真正的掉包会在下一轮被稳定检出。
func (s *Store) CheckFileIdentity() error {
	if s == nil || !s.identityOK {
		return nil
	}
	cur, ok := fileIdentityOf(s.path)
	if !ok {
		return nil
	}
	if cur == s.identity {
		return nil
	}
	return fmt.Errorf("store: 数据库文件已被替换(%s):打开时 dev=%d ino=%d,现在 dev=%d ino=%d;"+
		"本进程仍在写那个已被删除的旧文件,所有写入都不会被其他进程看到",
		s.path, s.identity.Dev, s.identity.Ino, cur.Dev, cur.Ino)
}

// WatchFileIdentity 每 interval 检查一次库文件是否被掉包,确认被换则调 onSwapped 一次后返回。
// ctx 取消或 Store 不支持检测时直接返回。调用方通常在 onSwapped 里打 ERROR 日志并退出进程。
func (s *Store) WatchFileIdentity(ctx context.Context, interval time.Duration, onSwapped func(error)) {
	if s == nil || !s.identityOK || onSwapped == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.CheckFileIdentity(); err != nil {
				onSwapped(err)
				return
			}
		}
	}
}
