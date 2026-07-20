package main

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/util"
)

// CloseCodeShutdown 是 server 主动 graceful shutdown 时,广播给所有 active session
// 的 LinkTypeClose code。
//
// 客户端收到 code == CloseCodeShutdown 的 Close 帧后:
//   - 不要立即触发 on_disconnected 重连风暴(很多客户端 reconnect=immediately 会让
//     新进程刚起来就被打爆);
//   - 推荐显式 backoff 5-30s 再重连(下个 nanotun 实例此时已 active);
//   - UI 上可以提示「服务器维护中」。
//
// 1xx 是预留 hy2 / 旧后端 内部值,我们的服务端业务侧 code 全部在 9xx 段。902
// 命名上参考 HTTP 503 "Service Unavailable"(=> 5+03 不可用)但避开了 5xx 段,
// 避免与现有 kick code(部分 5xx)歧义。
const CloseCodeShutdown = 902

// ShutdownReason 是上行广播的 CloseMsg.Reason 文本,客户端会原样进日志 / UI。
// 故意写得「人类可读」,因为现场调试人员看到「server shutting down」比看到「902」
// 直观得多;客户端如果做了 i18n,可以基于 CloseCodeShutdown 重写文案。
const ShutdownReason = "服务器维护中,请稍后重连"

// shutdownDrainTimeout 是 broadcastShutdownClose 写完所有 Close 帧后,
// 给客户端 ACK + 关连接的窗口。默认 3s 是经验值:
//   - 一条 LinkTypeClose 帧 < 1KB,WSS / smux 上传写入 < 100ms;
//   - 客户端收到后会自行 Close,server 等 3s 让 socket 完成 RST/FIN 四次握手;
//   - 太短(<1s)会让一部分远端客户端在网络抖动时漏收;
//   - 太长(>10s)拖慢 systemd 升级体验,且 systemd 默认 TimeoutStopSec=30s 不能超。
//
// 可通过 [server].shutdown_drain_timeout_ms 覆盖,0 = 完全不等(只发不等),
// 这样在测试 / 紧急 kill 时能立刻退。
const shutdownDrainTimeout = 3 * time.Second

// broadcastShutdownClose 给所有 active session 发一帧 LinkTypeClose(graceful)。
//
// 工作流:
//  1. 持 connIDMapMu(读锁),浅拷贝出当前所有 Connection 指针。锁外做写帧。
//  2. 并发对每条 conn 写 Close 帧。每条写都持自己的 linkWrMu,与 kick / takeover
//     路径互斥,避免与「同一时刻 backend 推过来的 kick」抢同一个 linkConn。
//  3. 等 timeout 让客户端收到 → 客户端自行 close raw → server 端 readLoop EOF →
//     runLinkTunnel 退出 → cleanupConnection 释放资源(由各自 handleVPNLink 的
//     defer 兜底);也允许客户端没 ACK 就被超时关闭 raw,反正 main return 时
//     vpnLn.Close + http.Server.Shutdown 会清掉残留连接。
//  4. **不**主动 Close raw(让客户端先 close 减少 TIME_WAIT 在 server 端堆积)。
//
// 与 cleanupConnection 的关系:这里**不**修改 Connection / clientIPUsed / connIDMap,
// 只发一帧告知客户端「我要走了」。真正的资源释放仍由各自 handleVPNLink 的 defer
// cleanupConnection 触发(主进程 return 之前一切 goroutine 都会跑完 defer)。
func broadcastShutdownClose(drainTimeout time.Duration) {
	if drainTimeout < 0 {
		drainTimeout = shutdownDrainTimeout
	}

	// 步骤 1:浅拷贝出 snapshot,避免持锁期间发 IO。
	connIDMapMu.RLock()
	conns := make([]*Connection, 0, len(connIDMap))
	for _, c := range connIDMap {
		if c != nil {
			conns = append(conns, c)
		}
	}
	connIDMapMu.RUnlock()

	if len(conns) == 0 {
		logrus.Info("[shutdown-drain] 无 active session,跳过 Close 广播")
		return
	}

	closeBody, err := util.MarshalCloseJSON(CloseCodeShutdown, ShutdownReason)
	if err != nil {
		logrus.WithError(err).Warn("[shutdown-drain] 构造 CloseMsg 失败,跳过广播")
		return
	}

	logrus.Infof("[shutdown-drain] 向 %d 个 active session 广播 LinkTypeClose(code=%d)...",
		len(conns), CloseCodeShutdown)

	// 步骤 2:并发写。每条 conn 一个 goroutine,避免单条慢连接拖死整个广播。
	// 写帧本身有 c.linkWrMu 串行化,kick / takeover 路径并发安全。
	var wg sync.WaitGroup
	var sentN, failN int64
	var statsMu sync.Mutex
	for _, c := range conns {
		c := c
		wg.Add(1)
		// 注意:safeGoroutine 是同步包装器,必须靠外层 `go` 才能真正并发跑;
		// 见 cmd/nanotund/safego.go 注释。如果落掉 `go`,这里会顺序执行,放大慢连接拖死整体广播的风险。
		go safeGoroutine("shutdownClose/"+c.connIDStr, func() {
			defer wg.Done()
			c.linkWrMu.Lock()
			defer c.linkWrMu.Unlock()
			// takeover 完成的老 conn(takenOver=true)与 cleanupConnection 即将关闭
			// 的 conn,linkConn 可能已经 nil;此时跳过即可,该客户端连接早已结束。
			if c.linkConn == nil {
				return
			}
			// 给 WriteLinkFrame 一个 1s 写截止时间,避免对方 socket buffer 满 / 网络抖动
			// 时这里阻塞拖慢整个广播。底层 net.Conn 是 *net.TCPConn / ws_stream_conn,
			// 都支持 SetWriteDeadline。
			if dl, ok := c.linkConn.(interface{ SetWriteDeadline(time.Time) error }); ok {
				_ = dl.SetWriteDeadline(time.Now().Add(1 * time.Second))
				defer func() { _ = dl.SetWriteDeadline(time.Time{}) }()
			}
			if err := util.WriteLinkFrame(c.linkConn, util.LinkTypeClose, closeBody); err != nil {
				statsMu.Lock()
				failN++
				statsMu.Unlock()
				return
			}
			statsMu.Lock()
			sentN++
			statsMu.Unlock()
		})
	}

	// 等所有 write goroutine 完成(每条 1s 写 deadline,最坏 1s + 调度延迟)。
	wg.Wait()
	logrus.Infof("[shutdown-drain] Close 帧广播完成: 成功 %d / 失败 %d", sentN, failN)

	// 步骤 3:drain timeout 给客户端收帧 + 关 raw 的时间。0 = 不等。
	if drainTimeout > 0 {
		logrus.Infof("[shutdown-drain] 等待 %s 让客户端 graceful close...", drainTimeout)
		time.Sleep(drainTimeout)
	}
}
