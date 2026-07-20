package main

// exit-node:by-device 会话索引。
//
// 数据结构:
//
//   connByDevice map[deviceID]map[connIDStr]*Connection
//
// 与 connIDMap / connByUser 共享 connIDMapMu;每次写 connIDMap 时顺手维护,语义与
// connByUser 完全一致(add/delete 带 cur==c 守卫,接管路径先删 old 再加 new)。
//
// 用途:数据面 exit 转发热路径需要 O(1) 把「目标出口 deviceID」解析成在线 *Connection
// (lookupActiveConnByDevice),per-packet 调用,不能扫 connIDMap。
//
// 一个 device 理论上可有多条并发会话(同一台机器多链路/接管窗口),lookup 返回任意一条
// 未被接管的 active 会话即可(出口转发只需要一条可投递的链路)。

var connByDevice = make(map[int64]map[string]*Connection)

// connByDeviceAddLocked 把 conn 加入 by-device 索引。调用方必须已持 connIDMapMu(写锁)。
// deviceID==0(匿名/未上报 UUID)不入索引 —— 匿名设备不能当出口目标。
func connByDeviceAddLocked(c *Connection) {
	if c == nil || c.deviceID == 0 || c.connIDStr == "" {
		return
	}
	sub := connByDevice[c.deviceID]
	if sub == nil {
		sub = make(map[string]*Connection, 2)
		connByDevice[c.deviceID] = sub
	}
	sub[c.connIDStr] = c
}

// connByDeviceDeleteLocked 把 conn 从 by-device 索引移除。调用方必须已持 connIDMapMu(写锁)。
// 守卫:仅当索引里该 connIDStr 仍指向同一 *Connection 时才删(接管路径不误删新 conn)。
func connByDeviceDeleteLocked(c *Connection) {
	if c == nil || c.deviceID == 0 || c.connIDStr == "" {
		return
	}
	sub := connByDevice[c.deviceID]
	if sub == nil {
		return
	}
	if cur, ok := sub[c.connIDStr]; ok && cur == c {
		delete(sub, c.connIDStr)
	}
	if len(sub) == 0 {
		delete(connByDevice, c.deviceID)
	}
}

// lookupActiveConnByDevice 返回该 deviceID 下一条未被接管(!takenOver)、未被踢除(!superseded)的在线会话(无则 nil)。
// 自带 connIDMapMu RLock,调用方不要持锁。数据面 exit 转发热路径用。superseded 排除见 lookupRunningExitConnByDevice。
func lookupActiveConnByDevice(deviceID int64) *Connection {
	if deviceID == 0 {
		return nil
	}
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	sub := connByDevice[deviceID]
	for _, c := range sub {
		if c != nil && !c.takenOver.Load() && !c.superseded.Load() {
			return c
		}
	}
	return nil
}

// lookupRunningExitConnByDevice 返回该 deviceID 下一条「真在跑出口」的在线会话(advertisedExit && !takenOver &&
// !superseded,无则 nil)。接管/重连窗口内同 device 可能并存多条会话且 advertisedExit 不同,
// 转发热路径必须挑出真正声明了出口(装了 NAT)的那条,否则 lookupActiveConnByDevice 的「首个 !takenOver」可能命中
// 非出口会话 → 把公网流量转给没装 NAT 的会话黑洞 / 误判离线丢包(Bugbot 第二轮 #1)。
// **!superseded 守卫**:出口机切网络 fresh 重登录时,旧 conn 被 supersede(关链路 + 异步清理)但不设 takenOver、不清
// advertisedExit;若不排除,「已踢未清」窗口里它是该 device 唯一 advertisedExit 会话(新 conn 尚未重发 advertise)→
// 被确定性选中 → 出口流量投进已关闭旧链路黑洞。见 Connection.superseded。自带 connIDMapMu RLock。
func lookupRunningExitConnByDevice(deviceID int64) *Connection {
	if deviceID == 0 {
		return nil
	}
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	sub := connByDevice[deviceID]
	for _, c := range sub {
		if c != nil && !c.takenOver.Load() && !c.superseded.Load() && c.advertisedExit.Load() {
			return c
		}
	}
	return nil
}

// lookupSubnetAdvertiserConnByDevice 返回该 deviceID 下一条「真在跑子网路由器」的在线会话
// (advertisedSubnetRoutes && !takenOver,无则 nil)。与 lookupRunningExitConnByDevice 完全同理(SR-M4 深扫):
// 接管/重连窗口内同 device 可能并存多条会话,且「历史 approved 某网段、但本次以普通客户端连入(没跑 --advertise-routes、
// 没装 subnet NAT)」的会话**绝不能**当子网转发目标——否则未 NAT 的 mesh vIP 包会漏进宣告方 LAN + 无回程黑洞。
// forwardPacketToSubnetRoute 用它替代 lookupActiveConnByDevice 的「首个 !takenOver」。自带 connIDMapMu RLock。
func lookupSubnetAdvertiserConnByDevice(deviceID int64) *Connection {
	if deviceID == 0 {
		return nil
	}
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	sub := connByDevice[deviceID]
	for _, c := range sub {
		if c != nil && !c.takenOver.Load() && !c.superseded.Load() && c.advertisedSubnetRoutes.Load() {
			return c
		}
	}
	return nil
}
