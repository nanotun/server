package main

// P3-a(2026-05-22):by-user 会话索引辅助。
//
// 数据结构:
//
//   connByUser map[userID]map[connIDStr]*Connection
//
// 与 connIDMap 共享 connIDMapMu;每次写 connIDMap 时都要顺手调对应 helper,
// 否则两者漂移 → evict 漏踢 / user_invalidate 误踢。
//
// 复杂度:
//   - Add / Delete : O(1) 哈希查找 + 一次内层 map 操作。
//   - byUserCount  : O(1)。
//   - byUserList   : O(N_user),N_user 是该 user 的活跃会话数(典型 ≤ 5)。
//
// 用 nested map 而非 slice 的理由:Delete 在 hot path(每次 cleanupConnection 都跑),
// slice 删除 O(N_user) + 顺序敏感,nested map 删除 O(1)。
// 排序在 evictOldestSessionsLocked 里按 createdAt 临时跑,N_user 通常远小于全表,
// 排序成本可忽略。

// connByUserAddLocked 把 conn 加入 by-user 索引。
// 调用方必须已持 connIDMapMu(写锁)。
func connByUserAddLocked(c *Connection) {
	if c == nil || c.userID == "" || c.connIDStr == "" {
		return
	}
	sub := connByUser[c.userID]
	if sub == nil {
		sub = make(map[string]*Connection, 4)
		connByUser[c.userID] = sub
	}
	sub[c.connIDStr] = c
}

// connByUserDeleteLocked 把 conn 从 by-user 索引移除。
// 调用方必须已持 connIDMapMu(写锁)。
//
// 守卫:仅当当前索引里这条 connIDStr 指向同一个 *Connection 时才删,避免接管路径下
// 新 conn 覆盖了同 connIDStr,旧 conn cleanup 把新条目误删。
// 这条守卫和 connIDMap 删除处的 `cur == c` 完全对齐。
func connByUserDeleteLocked(c *Connection) {
	if c == nil || c.userID == "" || c.connIDStr == "" {
		return
	}
	sub := connByUser[c.userID]
	if sub == nil {
		return
	}
	if cur, ok := sub[c.connIDStr]; ok && cur == c {
		delete(sub, c.connIDStr)
	}
	if len(sub) == 0 {
		delete(connByUser, c.userID)
	}
}

// byUserSnapshotLocked 返回该 userID 下所有 Connection 的浅拷贝切片。
// 调用方必须已持 connIDMapMu(读锁或写锁)。
//
// 返回切片可在锁外安全使用,但 *Connection 内部字段仍可能并发变(takenOver 等),
// 调用方按各自字段的 atomic / mu 语义读取。
func byUserSnapshotLocked(userID string) []*Connection {
	sub := connByUser[userID]
	if len(sub) == 0 {
		return nil
	}
	out := make([]*Connection, 0, len(sub))
	for _, c := range sub {
		out = append(out, c)
	}
	return out
}

// E1(2026-05-22):activeDeviceIDsSnapshot 返回当前所有 active session 持有的
// deviceID 集合,去重后返回。给 lease_gc 在跑 GcOrphanLeases 前刷新这些
// device 的 last_seen_at 用,避免长会话期间的 vIP 被误回收。
//
// 自带 connIDMapMu RLock,调用方不需要持锁(也不能,会自锁)。
func activeDeviceIDsSnapshot() []int64 {
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	seen := make(map[int64]struct{}, 16)
	for _, c := range connIDMap {
		if c == nil || c.deviceID == 0 {
			continue
		}
		seen[c.deviceID] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]int64, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out
}
