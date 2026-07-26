package main

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// crossLayerFixture 装一条「有 device 也有 user」的 conn:两条 refresh 接口都会命中它,
// 且 Connection 上的 device / user 快照都故意留成登录时的宽松值(20 MiB/s),用来验证
// 接口不再相信这些快照。
func crossLayerFixture(t *testing.T, dbName string) (
	*store.Store, *gatewayState, string, *Connection, *rateLimitedConn, int64, int64,
) {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), dbName), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{Username: "xl", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := st.UpsertDevice(ctx, user.ID, "00000000-0000-4000-8000-0000000000c1", "xl-dev", "linux")
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	t.Cleanup(cleanup)

	const loginSnapshot = 20 * 1024 * 1024
	rwc := newRateLimitedConn(newFakeLinkConn(), nil, nil, context.Background())
	c := &Connection{
		connIDStr:         "xl-conn",
		userID:            userIDFromStoreID(user.ID),
		deviceID:          dev.ID,
		deviceUUID:        dev.DeviceUUID,
		linkConn:          rwc,
		deviceRateUpBPS:   loginSnapshot,
		deviceRateDownBPS: loginSnapshot,
		bwUpBPS:           loginSnapshot,
		bwDownBPS:         loginSnapshot,
		tunnelDone:        make(chan struct{}),
		createdAt:         time.Now(),
	}
	c.rlConn.Store(rwc)
	installConn(t, c)
	return st, gw, sockPath, c, rwc, user.ID, dev.ID
}

// TestRateRefresh_KeepsFreshUserQuota:先把 user 配额压到 512 KB/s(等价于 CLI
// `user set-bandwidth`),再改 device 限速触发 /rate/refresh。device 那层比 user 宽,
// 所以生效值必须仍是 user 的 512 KB/s。
//
// 回归的是 2026-07-26 三机实测出的静默弹回:/rate/refresh 当时拿 c.bwDownBPS(登录快照,
// 20 MiB/s)去算 min,于是 device 一改,刚压下去的用户配额就没了,实测吞吐从 0.46 MB/s
// 升回 1.19 MB/s,只有让该会话重连才恢复。
func TestRateRefresh_KeepsFreshUserQuota(t *testing.T) {
	st, _, sockPath, _, rwc, userID, devID := crossLayerFixture(t, "xl_rate.db")
	ctx := t.Context()

	const userQuota = 512 * 1000
	const deviceLimit = 1500 * 1000
	if err := st.SetUserBandwidth(ctx, userID, userQuota, userQuota); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDeviceRateLimit(ctx, devID, deviceLimit, deviceLimit); err != nil {
		t.Fatal(err)
	}

	status, out := controlReq(t, sockPath, "POST", "/rate/refresh", map[string]any{"device_id": devID})
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	up, down, _, _ := rwc.snapshotLimits()
	if up != userQuota || down != userQuota {
		t.Errorf("device refresh must keep the fresh user quota: want %d/%d, got %d/%d body=%s",
			userQuota, userQuota, up, down, out)
	}
}

// TestUserRateRefresh_KeepsFreshDeviceLimit:反方向 —— 先把 device 限速压到 512 KB/s,
// 再改 user 配额(更宽)触发 /users/rate/refresh,生效值必须仍是 device 的 512 KB/s。
func TestUserRateRefresh_KeepsFreshDeviceLimit(t *testing.T) {
	st, _, sockPath, _, rwc, userID, devID := crossLayerFixture(t, "xl_user.db")
	ctx := t.Context()

	const deviceLimit = 512 * 1000
	const userQuota = 1500 * 1000
	if err := st.SetDeviceRateLimit(ctx, devID, deviceLimit, deviceLimit); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserBandwidth(ctx, userID, userQuota, userQuota); err != nil {
		t.Fatal(err)
	}

	status, out := controlReq(t, sockPath, "POST", "/users/rate/refresh", map[string]any{"user_id": userID})
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	up, down, _, _ := rwc.snapshotLimits()
	if up != deviceLimit || down != deviceLimit {
		t.Errorf("user refresh must keep the fresh device limit: want %d/%d, got %d/%d body=%s",
			deviceLimit, deviceLimit, up, down, out)
	}
}

// TestRateRefresh_StillNotWritingBackSnapshots:两条接口都不许回写 Connection 上的快照
// 字段(会与 takeover 路径 race)。重读改的是「算的时候用什么」,不是「把库里的值搬到 conn 上」。
func TestRateRefresh_StillNotWritingBackSnapshots(t *testing.T) {
	st, _, sockPath, c, _, userID, devID := crossLayerFixture(t, "xl_nowriteback.db")
	ctx := t.Context()
	if err := st.SetUserBandwidth(ctx, userID, 300, 600); err != nil {
		t.Fatal(err)
	}
	if err := st.SetDeviceRateLimit(ctx, devID, 400, 800); err != nil {
		t.Fatal(err)
	}
	if status, out := controlReq(t, sockPath, "POST", "/rate/refresh", nil); status != http.StatusOK {
		t.Fatalf("rate refresh status %d body=%s", status, out)
	}
	if status, out := controlReq(t, sockPath, "POST", "/users/rate/refresh",
		map[string]any{"user_id": userID}); status != http.StatusOK {
		t.Fatalf("user rate refresh status %d body=%s", status, out)
	}
	const loginSnapshot = 20 * 1024 * 1024
	if c.deviceRateUpBPS != loginSnapshot || c.deviceRateDownBPS != loginSnapshot ||
		c.bwUpBPS != loginSnapshot || c.bwDownBPS != loginSnapshot {
		t.Errorf("snapshots must stay untouched: dev=%d/%d user=%d/%d",
			c.deviceRateUpBPS, c.deviceRateDownBPS, c.bwUpBPS, c.bwDownBPS)
	}
}
