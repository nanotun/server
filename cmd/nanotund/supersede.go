package main

// 同 device_uuid 单实例(2026-05-23 引入)。
//
// 背景:
//
//   登录路径另有按 userID 的会话数上限(evictOldestSessionsLocked;默认不限,可配全局/账号级)。
//   后果是:同一台设备用同一 device_uuid 反复登录时,只要总数没满 5,旧会话不会被
//   主动踢 —— 客户端 crash 重启 / 切网络 / 后台 wakeup,都会变成「两条 conn 并存
//   到 5 min 后才被 idle GC」。两条 conn 在数据面跑同一 device 的 vIP,demux 路
//   由谁先到谁先用,行为是 race。
//
//   智能模式 takeover 路径(handleTakeoverLogin)已经能正确"新替旧",但要求客户
//   端主动带 takeover_secret —— secret 只在客户端内存里,crash 后就丢了,只能走
//   primary login 重连,落回上述并存问题。
//
// 解决方案:
//
//   登录路径完成 authenticate + Connection 注册后,在同一 connIDMapMu 锁段里扫
//   描 connByUser[userID],把所有 (deviceUUID 与新 conn 相同 && 不是自己 && 未
//   被 takenOver) 的旧 conn 标记成 supersede victims;锁外异步 close 它们的 link
//   触发标准 cleanup 路径(释放 vIP / lease / TunChan)。新 conn 接着等老 conn
//   tunnelDone(带 5s 超时)再走 alloc,这样新 conn 的 preferredLeasedVIPs 能拿
//   到刚释放的相同 vIP,保证「同 device 重登 IP 不变」。
//
// 设计取舍:
//
//   - **仅按 deviceUUID 匹配,不按 deviceID**:deviceUUID 是客户端持久化的标识,
//     deviceID 是 server 内部主键,两者通常一对一,但场景如 device 被 admin
//     删除后客户端重登会拿到新 deviceID —— 这种场景下 deviceUUID 一致就视为
//     同设备,正合预期。
//   - **deviceUUID 为空时跳过**:客户端没上报 / RFC 4122 v4 不合法 / UpsertDevice
//     失败,authResult.Device 都为 nil,这条 conn 不参与 supersede。"匿名 device"
//     不互相踢,避免老客户端 / 测试桩之间误踢。
//   - **跳过 takenOver==true**:正在被 handleTakeoverLogin 接管的旧 conn 不算
//     "占用 vIP",再去 supersede 它没意义且可能造成 takeover 路径的 race。
//   - **不复用 takeover 的 vIP 过户机制**:那条路径需要客户端配合(secret),且要
//     做 TunChan 浅拷贝 + double-demux 同步;这里走的是「让旧 conn 完整 cleanup
//     释放 vIP → 新 conn 走完整 alloc 路径捡回相同 vIP」,代码改动小,语义清晰。
//   - **5s 等待超时**:close + readLoop EOF + cleanup 实测 < 100ms;5s 是「给慢
//     客户端 / 卡 IO 留余量」与「不让握手响应超时」的平衡。超时后仍允许新 conn
//     继续(打 warn),最坏后果是 alloc 可能给新 conn 一个不同 vIP(因为
//     clientIPUsed 还没释放),与「不实现 supersede」的行为退化等价。

import (
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// sessionSupersedeCount 累计「同 device_uuid 重登踢旧」事件数,/metrics 暴露为
// nanotun_session_supersede_total。client 端疯狂 reconnect 的 outlier 用它就能看见。
var sessionSupersedeCount atomic.Uint64

// supersedeWaitTimeout:supersede victim cleanup 的最大等待时间。
//
// 选 5s 的理由:
//   - 正常 close → readLoop EOF → cleanupConnection 全程 < 100ms;
//   - tunDemuxWriteDeadline 也是 5s,所以即使数据面卡住,5s 内 readLoop 也能退;
//   - 与 client 端 LoginResp 接收超时(15s)留出余量,避免新 conn 因等老 cleanup
//     而错过 LoginResp 写入窗口。
const supersedeWaitTimeout = 5 * time.Second

// findSupersededByDeviceLocked 返回所有需要被新 conn 取代的同设备旧 conn。
//
// 调用约定:
//   - **必须**在持有 connIDMapMu 写锁的情况下调用(因为读 connByUser);
//   - 调用前 newConn 已经写入 connIDMap + connByUser(否则会漏掉「同一 conn 被
//     自己匹配上」的防护 —— 不过这里也用 != 比较指针双保险)。
//
// 返回值:
//   - nil:newConn.deviceUUID 为空、newConn.userID 为空、或确实没有同 device 旧 conn。
//   - 非空切片:所有匹配上的旧 *Connection,调用方负责锁外 close + 等 cleanup。
//
// 复杂度 O(N_user):跟 evictOldestSessionsLocked 走同一张 by-user 索引,
// N_user 通常很小(受全局/账号级会话上限约束;默认都不限时也远小于全表),开销可忽略。
func findSupersededByDeviceLocked(newConn *Connection) []*Connection {
	if newConn == nil || newConn.userID == "" || newConn.deviceUUID == "" {
		return nil
	}
	sub := connByUser[newConn.userID]
	if len(sub) <= 1 {
		// 只有 newConn 自己 / 空集 —— 不可能有同 device 旧 conn 需要踢。
		return nil
	}
	var victims []*Connection
	for _, old := range sub {
		if old == nil || old == newConn {
			continue
		}
		if old.deviceUUID != newConn.deviceUUID {
			continue
		}
		// takenOver 的 conn 正在被 handleTakeoverLogin 处理,vIP/TunChan
		// 即将过户;不要在这里横插一脚去 close 它,可能破坏 takeover 时序。
		if old.takenOver.Load() {
			continue
		}
		victims = append(victims, old)
	}
	return victims
}

// dedupVictims 把 supersede 列表与 evict 列表合并去重,避免对同一条旧 conn 写两次 audit
// 与 close。
//
// 用 map[*Connection]struct{} 作为 set;返回顺序按「先 supersede 后 evict」,保持
// 调用方记日志时易读。
func dedupVictims(supersededVictims, evictedVictims []*Connection) []*Connection {
	if len(supersededVictims) == 0 && len(evictedVictims) == 0 {
		return nil
	}
	seen := make(map[*Connection]struct{}, len(supersededVictims)+len(evictedVictims))
	out := make([]*Connection, 0, len(supersededVictims)+len(evictedVictims))
	for _, c := range supersededVictims {
		if c == nil {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	for _, c := range evictedVictims {
		if c == nil {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// waitConnsCleanup 等到一批 conn 全部 tunnelDone(标志 cleanupConnection 完整执行完),
// 或达到 supersedeWaitTimeout 兜底返回。每条 conn 各自计算超时(不共享 timer),
// 但因为它们是并发 close 的,实际墙钟时间 ≈ 最慢一条的 cleanup 耗时。
//
// 仅给 supersede 路径用;evict 路径不需要等(它们是不同 device,vIP 与新 conn 无关)。
func waitConnsCleanup(victims []*Connection) {
	if len(victims) == 0 {
		return
	}
	for _, v := range victims {
		if v == nil || v.tunnelDone == nil {
			continue
		}
		select {
		case <-v.tunnelDone:
			// 老 conn 已彻底退出,clientIPUsed[vIP] 已被它 cleanup 释放,
			// 新 conn 后续 preferredLeasedVIPs + AllocClientIP 就能拿回相同 vIP。
		case <-time.After(supersedeWaitTimeout):
			logrus.WithFields(logrus.Fields{
				"victim_conn_id_str": v.connIDStr,
				"victim_device_uuid": v.deviceUUID,
				"timeout":            supersedeWaitTimeout.String(),
			}).Warn("[supersede] 等老 conn cleanup 超时,继续登录(新 conn 可能拿到不同 vIP,与无 supersede 行为退化等价)")
		}
	}
}
