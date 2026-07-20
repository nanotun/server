package main

import (
	"runtime/debug"

	"github.com/sirupsen/logrus"
)

// safeGoroutine 在 goroutine 入口装 defer recover。所有数据面 / 后台 goroutine
// 都应该走这一层,否则任一 panic 都会拖垮整个 nanotund 进程,所有在线用户瞬断,
// `cleanupConnection` 也不会被执行(connIDMap / clientIPUsed / TunChan 留存进程死亡前)。
//
// 两种策略:
//   - safeGoroutine(name, fn):per-connection / 短生命 goroutine 用。panic 只打日志
//   - 调可选 onPanic 钩子,**不**触发进程关闭。一条连接挂不应该影响其它连接。
//   - safeGlobalGoroutine(name, fn):全局长生命(TUN read/write、demux、保活监听等)用。
//     panic 触发 globalContextCancel,让 SIGTERM 路径的 defer 链跑完(graceful shutdown),
//     systemd 重启;**不**用裸 panic 让 Go runtime 直接 exit。
//
// 调用方式都是 `go safeGoroutine("xx", func(){ ... })`,而非函数包装器,目的是让
// 调用点保留 `go` 字面量,grep `go func`/`go safe*` 都能找到所有并发起点。
func safeGoroutine(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			logrus.WithFields(logrus.Fields{
				"goroutine": name,
				"panic":     r,
				"stack":     string(debug.Stack()),
			}).Error("[safeGoroutine] goroutine panic,已捕获,**不**关闭进程")
		}
	}()
	fn()
}

// safeGlobalGoroutine 给关键全局长生命 goroutine 用:panic 时记录 stack 后**触发
// graceful shutdown**(globalContextCancel),让 main 中 defer 链完整跑完 → systemd
// 拉起 fresh 实例。这样比裸 panic / os.Exit 更稳:
//   - 老 iptables 规则会被 sweep
//   - TUN 设备会被 close
//   - DB WAL 会被 checkpoint
//
// 注意:不在这里调 globalContextCancel() 自身,而是写到调用方注入的 cancel 函数,
// 避免本包对 main 的全局变量产生反向依赖。
func safeGlobalGoroutine(name string, cancel func(), fn func()) {
	defer func() {
		if r := recover(); r != nil {
			logrus.WithFields(logrus.Fields{
				"goroutine": name,
				"panic":     r,
				"stack":     string(debug.Stack()),
			}).Error("[safeGlobalGoroutine] 关键 goroutine panic,触发 graceful shutdown")
			if cancel != nil {
				cancel()
			}
		}
	}()
	fn()
}
