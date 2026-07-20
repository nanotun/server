//go:build !linux

package main

// V1(2026-05-26):非 Linux 平台 stub。
//
// nanotun-web 生产部署是 linux/amd64,但开发同学在 macOS / Windows 上跑 `go build`、
// `go test` 时不能编译挂。这里返回 ErrSysmonUnsupported,handler_sysmon 把它翻译
// 成 HTTP 503 + JSON 提示 "本平台不支持系统监控,请在 Linux 部署后查看"。
//
// 不做 mac syscall(sysctl) / Windows perf counter 实现的原因:
//   - 用户场景 100% 是部署侧使用 — 自己开发机看 mac CPU 没意义;
//   - 跨平台 sysctl 接口差异大 + cgo,引入只有维护成本没有用户价值。

func collectSysmonSnapshot() (*SysmonSnapshot, error) {
	return nil, ErrSysmonUnsupported
}
