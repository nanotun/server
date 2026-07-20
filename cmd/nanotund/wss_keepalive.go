package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/util"
)

// G_wss_ping:WSS 数据面应用层 Ping/Pong 默认参数。
//
// 历史背景:数据面 WSS 在 hy2 / REALITY 之外的纯 wss 链路上,没有任何 application-layer
// 心跳 —— smux 自己的 KeepAlive 跑在 wss 之上,但「smux still active 不代表底层 wss
// 链路活着」(NAT 中间盒可能让 TCP 半开,smux ACK 仍回 syscall 成功但实际不出网)。
// 添加 server→client 主动 Ping 检测,N 次没回 Pong 直接 Close 连接,客户端走 reconnect。
//
// 默认 30s/3 次 = 90s 检出窗口:
//   - 比 NAT 默认 TCP 闲置超时(运营商常 5-15min)快 5-10x,在用户感知前断重连;
//   - 比 5s 这种激进值宽松,普通网络抖动(单包丢 30s 还没复)不会乱杀连接;
//   - 与 smux KeepAliveTimeout(默认 30s)同量级,在两者都开时优先 smux 自检,
//     兜底由本机制保证「smux 没检出但底层 wss 真死」也能被发现。
const (
	defaultDataPlanePingInterval      = 30 * time.Second
	defaultDataPlanePingMissThreshold = 3
	dataPlanePingWriteDeadline        = 5 * time.Second // 单次 Ping 写超时;借 C3 已落地的 deadliner 机制
	dataPlanePingPayloadLen           = 8               // 64-bit 随机 nonce,便于客户端原样回显,服务端不强校验仅观测延迟分布
)

// startWSSDataPlaneKeepalive 是 runLinkTunnel 的伴随 goroutine。
//
// 行为:
//   - 每 interval 一次 Ping(payload 是 nonce + 自增序号,客户端原样回 Pong);
//   - 每周期检查 lastPongAtNano:若距今 > missThreshold * interval(且不是 0,
//     未收到过任何 Pong 也算「无心跳」)→ 关 linkConn,触发上层 cleanupConnection。
//   - ctx.Done 或写帧失败 → 退出 goroutine,不主动 Close(已 cancel 的上层会清理)。
//
// 0/负 interval = no-op,直接退出,保持向后兼容(新代码部署、配置没开时无副作用)。
func startWSSDataPlaneKeepalive(ctx context.Context, c *Connection, w io.Writer, remote string, interval time.Duration, missThreshold int) {
	if interval <= 0 {
		return // 配置禁用
	}
	// 深扫第八轮 MED:防御性下限,专防「ticker 高频空转」这类真正的 CPU 刷屏。
	// 主修在 config.Duration.UnmarshalText —— 裸整数(如 `data_plane_ping_interval = 30`
	// 本意 30s 却被当 30ns)已在解析期直接拒绝。这里只再兜一道**亚毫秒**下限:任何
	// <1ms 的间隔(如误写 "500us")一律夹到 1ms 并告警,挡住 ns/us 级别的失控自旋。
	// 阈值刻意取 1ms 而非「秒级」,以免误伤合法的短间隔(测试与激进保活可用几十 ms)。
	const minPingInterval = time.Millisecond
	if interval < minPingInterval {
		logrus.WithFields(logrus.Fields{
			"remote":  remote,
			"got":     interval.String(),
			"clamped": minPingInterval.String(),
		}).Warn("[keepalive] data_plane_ping_interval 小于 1ms,已夹到 1ms(疑似漏写单位导致次毫秒自旋)")
		interval = minPingInterval
	}
	if missThreshold <= 0 {
		missThreshold = defaultDataPlanePingMissThreshold
	}

	// 写一个 Ping。返回 false 表示需要退出 goroutine(写失败 / 上层 cancel)。
	writePing := func(seq uint32) bool {
		payload := make([]byte, dataPlanePingPayloadLen)
		// 前 4B 序号,后 4B 随机 nonce。序号便于客户端日志看出丢包,nonce 防 replay 比对。
		binary.BigEndian.PutUint32(payload[0:4], seq)
		_, _ = rand.Read(payload[4:])

		c.linkWrMu.Lock()
		if dl, ok := w.(deadliner); ok {
			_ = dl.SetWriteDeadline(time.Now().Add(dataPlanePingWriteDeadline))
		}
		err := util.WriteLinkFrame(w, util.LinkTypePing, payload)
		if dl, ok := w.(deadliner); ok {
			_ = dl.SetWriteDeadline(time.Time{})
		}
		c.linkWrMu.Unlock()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"remote": remote, "seq": seq,
			}).WithError(err).Debug("[keepalive] Ping 写失败,退出 keepalive goroutine(上层 read/write loop 会清理)")
			return false
		}
		return true
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	var seq uint32 = 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			seq++
			if !writePing(seq) {
				return
			}
			// 判活窗口:miss = (现在时刻 - lastPongAt) > missThreshold * interval
			//   - lastPongAt == 0 表示从未收到过 Pong,但我们刚启动也是 0,得用 "启动以来时长"
			//     而不是绝对 0 来判,否则启动后第一次 Ping 间隔到点立刻被判死。
			//   - 这里用一个简单的 grace:启动前 missThreshold 次 Ping 内不判死。
			if seq <= uint32(missThreshold) {
				continue
			}
			lastPongAt := c.lastPongAtNano.Load()
			now := time.Now().UnixNano()
			missWindow := int64(missThreshold) * interval.Nanoseconds()
			if lastPongAt == 0 || now-lastPongAt > missWindow {
				lastPongAgo := "(never)"
				if lastPongAt > 0 {
					lastPongAgo = time.Duration(now - lastPongAt).String()
				}
				logrus.WithFields(logrus.Fields{
					"remote":      remote,
					"conn_id":     c.connID,
					"user_id":     c.userID,
					"last_pong":   lastPongAgo,
					"miss_window": time.Duration(missWindow).String(),
					"ping_seq":    seq,
				}).Warn("[keepalive] 数据面 WSS 连续 N 次 Ping 无 Pong,判定僵尸连接,主动 Close 触发客户端重连")
				_ = c.linkConn.Close()
				return
			}
		}
	}
}
