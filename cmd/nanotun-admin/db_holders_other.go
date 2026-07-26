//go:build !linux

package main

// 非 Linux 上没有 /proc/<pid>/fd 这种统一入口,放弃探测。
// server 与 web 后台只在 Linux 上部署,这里保持可编译即可。
func processesHoldingFile(string) []string { return nil }
