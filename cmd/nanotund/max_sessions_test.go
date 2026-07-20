package main

import (
	"testing"
	"time"

	"github.com/nanotun/server/config"
)

// TestEffectiveMaxSessions:0021 两级叠加 —— 账号级优先,0 跟随全局,全局缺省不限制。
func TestEffectiveMaxSessions(t *testing.T) {
	gw := &gatewayState{cfg: &config.Config{}}

	cases := []struct {
		name    string
		userCap int
		global  int
		want    int
	}{
		{"双零=不限", 0, 0, 0},
		{"跟随全局 5", 0, 5, 5},
		{"跟随全局 -1(显式不限)", 0, -1, 0},
		{"账号覆盖 3(全局 10)", 3, 10, 3},
		{"账号覆盖更松 20(全局 5)", 20, 5, 20},
		{"账号显式不限(全局 5)", -1, 5, 0},
		{"账号显式不限(全局也不限)", -1, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gw.cfg.Server.MaxSessionsPerUser = c.global
			conn := &Connection{maxSessionsAtLogin: c.userCap}
			if got := effectiveMaxSessions(gw, conn); got != c.want {
				t.Fatalf("effectiveMaxSessions(user=%d,global=%d)=%d, want %d",
					c.userCap, c.global, got, c.want)
			}
		})
	}
	if got := effectiveMaxSessions(nil, &Connection{}); got != 0 {
		t.Fatalf("nil gw 应不限,got %d", got)
	}
	if got := effectiveMaxSessions(&gatewayState{}, &Connection{}); got != 0 {
		t.Fatalf("nil cfg 应不限,got %d", got)
	}
}

// TestEvictOldestSessionsLocked_RespectsEffectiveCap:默认不限 → 不踢;
// 账号级 cap=2 时第 3 个登录踢最老。
func TestEvictOldestSessionsLocked_RespectsEffectiveCap(t *testing.T) {
	resetConnByUserForSupersedeTest(t)
	gw := &gatewayState{cfg: &config.Config{}} // 全局不限

	old1 := makeFakeConn(t, "a", "u-cap", "d1")
	old1.createdAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	old2 := makeFakeConn(t, "b", "u-cap", "d2")
	old2.createdAt = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	newC := makeFakeConn(t, "c", "u-cap", "d3")
	newC.createdAt = time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	newC.maxSessionsAtLogin = 2

	connIDMapMu.Lock()
	victims := evictOldestSessionsLocked(gw, newC)
	connIDMapMu.Unlock()
	if len(victims) != 1 || victims[0] != old1 {
		t.Fatalf("cap=2 时应踢最老 old1,got %v", victims)
	}

	// 账号级 0 + 全局 0 → 不限,不踢。
	newC.maxSessionsAtLogin = 0
	connIDMapMu.Lock()
	victims = evictOldestSessionsLocked(gw, newC)
	connIDMapMu.Unlock()
	if len(victims) != 0 {
		t.Fatalf("双零不限时应不踢,got %d victims", len(victims))
	}
}

// TestEvictOldestSessionsLocked_SkipsSuperseded:0021 深扫回归 —— 已被 supersede
// 标记的垂死会话不占配额。修复前的现场:cap=2,B(最老,健康,设备 D2)+ A(较新,
// 设备 D1);D1 fresh 重登产生新 conn C,A 被 supersede。若 evict 把 A 计入总数,
// total=3>2 会按「踢最老」误踢健康的 B —— 而 supersede 完成后总数本来就是 2,没超。
func TestEvictOldestSessionsLocked_SkipsSuperseded(t *testing.T) {
	resetConnByUserForSupersedeTest(t)
	gw := &gatewayState{cfg: &config.Config{}} // 全局不限,吃账号级 cap

	healthy := makeFakeConn(t, "h", "u-sup", "d2")
	healthy.createdAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	dying := makeFakeConn(t, "s", "u-sup", "d1")
	dying.createdAt = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	dying.superseded.Store(true) // 同 device 重登被 supersede,等待 cleanup
	newC := makeFakeConn(t, "n", "u-sup", "d1")
	newC.createdAt = time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	newC.maxSessionsAtLogin = 2

	connIDMapMu.Lock()
	victims := evictOldestSessionsLocked(gw, newC)
	connIDMapMu.Unlock()
	if len(victims) != 0 {
		t.Fatalf("垂死会话不占配额,healthy+newC=2<=cap=2 不应踢,got %d victims(误伤 %q)",
			len(victims), victims[0].connIDStr)
	}
}
