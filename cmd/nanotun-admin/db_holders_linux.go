//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// processesHoldingFile 扫 /proc 找出还打开着 path(或其 -wal/-shm)的进程,
// 返回 "name(pid)" 列表,自己除外。
//
// 用途见 cmdRestore:control socket 只能证明 nanotund 在不在,证明不了 nanotun-web
// 或者别人手工开的 sqlite3 会话在不在。restore 换的是 inode,这些进程不会收到任何
// 通知,只会继续往被 unlink 的旧文件里写,静默丢数据。
//
// 权限不足时(非 root)扫不到别人的 /proc/<pid>/fd,返回空 —— 只能少报不能误报,
// 不因为扫不动就把合法的 restore 挡下来。
func processesHoldingFile(path string) []string {
	targets := map[string]bool{path: true, path + "-wal": true, path + "-shm": true}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var out []string
	seen := map[int]bool{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self || seen[pid] {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// 已被删除的文件在 readlink 里带 " (deleted)" 后缀;那种进程正是我们最想
			// 报出来的(上一次 restore 的遗留),所以剥掉后缀再比。
			link = strings.TrimSuffix(link, " (deleted)")
			if !targets[link] {
				continue
			}
			name := processName(pid)
			seen[pid] = true
			out = append(out, fmt.Sprintf("%s(pid %d)", name, pid))
			break
		}
	}
	return out
}

func processName(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}
