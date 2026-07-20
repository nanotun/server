//go:build !windows

package main

import "syscall"

// E2:control socket bind 前后用 umask 077 把世界/其它组写权限关掉,避免
// `net.Listen("unix",...)` 创建文件 → 后续 Chmod 之间的微秒窗口被其它本地用户
// 抢着 connect。Linux + Darwin 都走这条;Windows 没有 unix socket file mode 概念,
// 走 control_socket_umask_other.go 的 noop。
func setRestrictiveUmask() int {
	return syscall.Umask(0o077)
}

func restoreUmask(prev int) {
	syscall.Umask(prev)
}
