//go:build !linux

package main

// ReleaseConntrackForIP 仅在 Linux 上通过 netlink 清理 conntrack；非 Linux 为 no-op。
func ReleaseConntrackForIP(clientIP string) (uint, error) {
	return 0, nil
}
