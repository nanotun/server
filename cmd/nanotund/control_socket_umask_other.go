//go:build windows

package main

// E2:Windows 没有 unix socket 文件权限语义,umask helper 走 noop。
func setRestrictiveUmask() int { return 0 }
func restoreUmask(_ int)       {}
