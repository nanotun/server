//go:build !linux

package main

// J2:非 Linux 平台没有 systemd,sd_notify 全部 no-op。
// 让 server.go 调用点不需要 build tag,平台差异在此封装。

import "context"

func sdNotifyReady()                         {}
func sdNotifyStopping()                      {}
func startSDWatchdog(_ context.Context) bool { return false }
