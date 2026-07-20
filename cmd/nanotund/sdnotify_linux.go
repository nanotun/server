//go:build linux

package main

// J2(2026-05-22)sd_notify 极简实现。
//
// 为什么不引入 github.com/coreos/go-systemd?
//   - 那个包还顺带绑了 systemd D-Bus 客户端代码,体积膨胀 + 多了一份维护负担;
//   - sd_notify 协议本身只是「往 NOTIFY_SOCKET 发个 datagram」,30 行能写完;
//   - 让本仓库继续保持 "无 CGO + 最小依赖" 的部署友好属性。
//
// 协议参考: man 3 sd_notify
//   - NOTIFY_SOCKET 环境变量给路径,@ 前缀表示 abstract socket(Linux only);
//   - 普通路径就是文件系统路径;
//   - 通过 SOCK_DGRAM 发文本,字段以 \n 分隔。
//     READY=1     —— 启动完成(配合 Type=notify);
//     WATCHDOG=1  —— 心跳(配合 WatchdogSec=N);
//     STOPPING=1  —— 进入 graceful shutdown(可选,只为日志好看)。

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// notifyOnce 串行化 sd_notify 写入(systemd 接受并发 datagram,但本地复用 conn 更省 FD)。
var (
	notifyOnce sync.Once
	notifyConn *net.UnixConn
	notifyAddr *net.UnixAddr
	notifyErr  error
)

func initNotify() {
	notifyOnce.Do(func() {
		addr := os.Getenv("NOTIFY_SOCKET")
		if addr == "" {
			notifyErr = errors.New("NOTIFY_SOCKET 未设置(未运行在 systemd Type=notify 下)")
			return
		}
		ua := &net.UnixAddr{Net: "unixgram"}
		// abstract socket 前缀:'@' → "\x00path"(Linux 专属命名空间)。
		if addr[0] == '@' {
			ua.Name = "\x00" + addr[1:]
		} else {
			ua.Name = addr
		}
		conn, err := net.DialUnix("unixgram", nil, ua)
		if err != nil {
			notifyErr = err
			return
		}
		notifyConn = conn
		notifyAddr = ua
	})
}

// sdNotifyReady 启动期发 READY=1。systemd Type=notify 会卡在 ActiveState=activating
// 直到我们发这条;之后转 active。失败只 Debug,因为可能就是没跑在 systemd 下。
func sdNotifyReady() {
	initNotify()
	if notifyErr != nil || notifyConn == nil {
		return
	}
	if _, err := notifyConn.Write([]byte("READY=1\nSTATUS=ready\n")); err != nil {
		logrus.WithError(err).Debug("[sdnotify] READY 写入失败")
	}
}

// sdNotifyStopping graceful shutdown 进入时发 STOPPING=1,让 systemctl status 显示
// "deactivating" 而非看起来卡住。
func sdNotifyStopping() {
	initNotify()
	if notifyErr != nil || notifyConn == nil {
		return
	}
	_, _ = notifyConn.Write([]byte("STOPPING=1\nSTATUS=stopping\n"))
}

// startSDWatchdog 如果 systemd 给了 WATCHDOG_USEC,起一条 goroutine 按 USEC/2 间隔
// 发心跳。systemd 在 N 秒内没收到 WATCHDOG=1 就 SIGTERM 重启进程,自愈死锁。
//
// 返回 false 表示没启用(没跑在 systemd 下 / 没设 WatchdogSec=)。
func startSDWatchdog(ctx context.Context) bool {
	initNotify()
	if notifyErr != nil || notifyConn == nil {
		return false
	}
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return false
	}
	// systemd 还会把 WATCHDOG_PID 设为它期望发心跳的 pid;不匹配就不要发,
	// 避免父进程已经 fork-exec 子进程后,子进程错误地继承 socket 来发心跳。
	if pidStr := os.Getenv("WATCHDOG_PID"); pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err == nil && pid != os.Getpid() {
			return false
		}
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		return false
	}
	// 每 USEC/2 发一次,留 50% 余量给调度抖动;最低 1s 防止过频。
	interval := time.Duration(usec/2) * time.Microsecond
	if interval < time.Second {
		interval = time.Second
	}
	go safeGlobalGoroutine("sdWatchdog", globalContextCancel, func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		logrus.WithFields(logrus.Fields{
			"interval":      interval.String(),
			"watchdog_usec": usec,
		}).Info("[sdnotify] systemd watchdog 已启用,本进程会定时上报心跳")
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := notifyConn.Write([]byte("WATCHDOG=1\n")); err != nil {
					logrus.WithError(err).Warn("[sdnotify] WATCHDOG 写入失败")
				}
			}
		}
	})
	return true
}
