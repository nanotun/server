package main

import (
	"sort"
	"testing"
)

// 清空全局 by-user 索引,避免跨测试污染(scanAndKickInvalidUsers 真扫表)。
func resetConnByUserForTest(t *testing.T) {
	t.Helper()
	connIDMapMu.Lock()
	for k := range connByUser {
		delete(connByUser, k)
	}
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		for k := range connByUser {
			delete(connByUser, k)
		}
		connIDMapMu.Unlock()
	})
}

// P3-a:by-user 索引 add/delete 基本路径。
func TestConnByUser_AddDelete(t *testing.T) {
	resetConnByUserForTest(t)

	a := &Connection{userID: "u1", connIDStr: "a"}
	b := &Connection{userID: "u1", connIDStr: "b"}
	c := &Connection{userID: "u2", connIDStr: "c"}

	connIDMapMu.Lock()
	connByUserAddLocked(a)
	connByUserAddLocked(b)
	connByUserAddLocked(c)
	connIDMapMu.Unlock()

	connIDMapMu.RLock()
	u1 := byUserSnapshotLocked("u1")
	u2 := byUserSnapshotLocked("u2")
	u3 := byUserSnapshotLocked("u3")
	connIDMapMu.RUnlock()

	if len(u1) != 2 {
		t.Fatalf("u1 应有 2 条,got %d", len(u1))
	}
	if len(u2) != 1 {
		t.Fatalf("u2 应有 1 条,got %d", len(u2))
	}
	if len(u3) != 0 {
		t.Fatalf("u3 应有 0 条,got %d", len(u3))
	}

	ids := []string{u1[0].connIDStr, u1[1].connIDStr}
	sort.Strings(ids)
	if ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("u1 内容预期 [a b],got %v", ids)
	}

	connIDMapMu.Lock()
	connByUserDeleteLocked(a)
	connIDMapMu.Unlock()
	connIDMapMu.RLock()
	if got := byUserSnapshotLocked("u1"); len(got) != 1 || got[0].connIDStr != "b" {
		t.Fatalf("删 a 后只剩 b,got %v", connIDsOf(got))
	}
	connIDMapMu.RUnlock()

	// 删 b 后 u1 整个 user 桶应消失,len(connByUser["u1"]) == 0 + map 已 delete。
	connIDMapMu.Lock()
	connByUserDeleteLocked(b)
	if _, exists := connByUser["u1"]; exists {
		t.Fatal("u1 桶应已被 delete")
	}
	connIDMapMu.Unlock()
}

// P3-a:守卫语义 —— 同 connIDStr 被新 *Connection 覆盖时,删除旧 conn 不应误删新条目。
// 模拟接管路径:oldConn 先 add,然后 newConn 覆盖,然后 oldConn cleanup。
func TestConnByUser_DeleteGuard_TakeoverOverwrite(t *testing.T) {
	resetConnByUserForTest(t)

	oldConn := &Connection{userID: "u9", connIDStr: "s1"}
	newConn := &Connection{userID: "u9", connIDStr: "s1"}

	connIDMapMu.Lock()
	connByUserAddLocked(oldConn)
	// 接管:先删 old(此时索引还指 old)再加 new。
	connByUserDeleteLocked(oldConn)
	connByUserAddLocked(newConn)
	// 此时再调一次 delete(oldConn),不应误删 newConn —— 守卫 cur == c。
	connByUserDeleteLocked(oldConn)
	connIDMapMu.Unlock()

	connIDMapMu.RLock()
	snap := byUserSnapshotLocked("u9")
	connIDMapMu.RUnlock()
	if len(snap) != 1 || snap[0] != newConn {
		t.Fatalf("守卫失效:index 应只剩 newConn,got %v", snap)
	}
}

func connIDsOf(cs []*Connection) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.connIDStr)
	}
	return out
}
