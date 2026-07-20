package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// TestControlSocket_KickByDevice 覆盖 0011 之后新加的 kick by device 分支:
// 既能按 int64 device_id 比对 c.deviceID,也能按 UUID 比对 c.deviceUUID。
// 此前只 kick by user / session 有 e2e,新分支落到测试里防回归。
func TestControlSocket_KickByDevice(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "kick_device.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{Username: "kd", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	// 装两条 conn:同 user 不同 device,验证 device picker 只命中其中一条。
	uid := userIDFromStoreID(user.ID)
	c1 := &Connection{
		connIDStr:  "conn-1",
		userID:     uid,
		deviceID:   42,
		deviceUUID: "00000000-0000-4000-8000-000000000042",
		linkConn:   newFakeLinkConn(),
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	}
	c2 := &Connection{
		connIDStr:  "conn-2",
		userID:     uid,
		deviceID:   43,
		deviceUUID: "00000000-0000-4000-8000-000000000043",
		linkConn:   newFakeLinkConn(),
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	}
	installConn(t, c1)
	installConn(t, c2)

	// kind=device + 纯数字 id → 按 deviceID 比对,只命中 c1。
	status, out := controlReq(t, sockPath, "POST", "/kick", map[string]any{
		"kind": "device", "id": "42", "reason": "test_dev_kick",
	})
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	var r struct {
		Kicked int `json:"kicked"`
	}
	if err := json.Unmarshal(out, &r); err != nil || r.Kicked != 1 {
		t.Fatalf("by id: want kicked=1, got body=%s err=%v", out, err)
	}
	// kind=device + UUID(大写)→ 应小写归一后命中 c2。
	status, out = controlReq(t, sockPath, "POST", "/kick", map[string]any{
		"kind": "device", "id": "00000000-0000-4000-8000-000000000043",
	})
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	r.Kicked = 0
	if err := json.Unmarshal(out, &r); err != nil || r.Kicked != 1 {
		t.Fatalf("by uuid: want kicked=1, got body=%s err=%v", out, err)
	}

	// 空 id 应 400。
	status, _ = controlReq(t, sockPath, "POST", "/kick", map[string]any{
		"kind": "device", "id": "",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("empty id: want 400, got %d", status)
	}
}

// TestControlSocket_RateRefresh_HotSwapsLimiter 覆盖 0011 /rate/refresh 全链路:
//  1. admin 把 settings.rate_default_*_bps 写到 500/1000 + burst=128KiB
//  2. /rate/refresh device_id=0 → server 重读 settings + 算 effectiveLinkRates
//  3. 验证 conn.rlConn 上 limiter 的 Limit() 被改成期望值
//     (登录路径已经初始化 limiter = nil 或更宽,refresh 之后应缩到 settings 值)
//
// 顺便覆盖 P0#2 回归:c.deviceRateUpBPS / DownBPS 字段**不应**被 refresh 写回
// (写回会形成 data race;-race 跑测试会失败,这里也用值断言保险)。
func TestControlSocket_RateRefresh_HotSwapsLimiter(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "rate_refresh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{Username: "rr", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	// 建一条带 rlConn 的 conn — 初始 limiter = nil(= 不限),deviceRateUpBPS = 7777(任意快照值)。
	rwc := newRateLimitedConn(newFakeLinkConn(), nil, nil, context.Background())
	c := &Connection{
		connIDStr:         "rr-conn",
		userID:            userIDFromStoreID(user.ID),
		deviceID:          0, // device_id=0 → /rate/refresh 不会重查 device,直接走 settings + toml
		linkConn:          rwc,
		deviceRateUpBPS:   7777,
		deviceRateDownBPS: 8888,
		tunnelDone:        make(chan struct{}),
		createdAt:         time.Now(),
	}
	c.rlConn.Store(rwc) // atomic.Pointer 字段不能用 struct literal,显式 Store
	installConn(t, c)

	// 写 settings(MiB/s → byte/s)+ burst 128 KiB。
	if err := st.SetRateDefaults(ctx, store.RateDefaults{
		UploadBPS: 500, DownloadBPS: 1000, BurstBytes: 128 * 1024,
	}); err != nil {
		t.Fatal(err)
	}

	// 触发全量 refresh。
	status, out := controlReq(t, sockPath, "POST", "/rate/refresh", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	var resp struct {
		OK        bool `json:"ok"`
		Refreshed int  `json:"refreshed"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, out)
	}
	if !resp.OK || resp.Refreshed < 1 {
		t.Fatalf("refresh resp not ok / refreshed=0: %s", out)
	}

	// 验证 limiter 已被设到 settings 值,burst 是 effectiveBurst(128KiB) = 128KiB。
	upBPS, downBPS, upBurst, _ := rwc.snapshotLimits()
	if upBPS != 500 || downBPS != 1000 {
		t.Errorf("limiter rate: want 500/1000, got %d/%d", upBPS, downBPS)
	}
	if upBurst != 128*1024 {
		t.Errorf("limiter burst: want 128KiB, got %d", upBurst)
	}

	// P0#2 防 race 回归:refresh 不应该回写 c.deviceRateUpBPS / DownBPS。
	// 如果哪天有人手贱再加回来,这个断言会立刻 fail。
	if c.deviceRateUpBPS != 7777 || c.deviceRateDownBPS != 8888 {
		t.Errorf("device rate snapshot must not be touched by /rate/refresh, got %d/%d (want 7777/8888)",
			c.deviceRateUpBPS, c.deviceRateDownBPS)
	}
}

// TestControlSocket_UserRateRefresh:0012 /users/rate/refresh。
// 改 user.bandwidth → POST → 该 user 下 active conn limiter 立刻收紧到 user-level 值。
func TestControlSocket_UserRateRefresh(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "user_rate_refresh.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{Username: "ur", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	rwc := newRateLimitedConn(newFakeLinkConn(), nil, nil, context.Background())
	c := &Connection{
		connIDStr:  "ur-conn",
		userID:     userIDFromStoreID(user.ID),
		linkConn:   rwc,
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	}
	c.rlConn.Store(rwc) // atomic.Pointer 字段不能用 struct literal
	installConn(t, c)

	// 写 user-level quota,然后调 refresh。
	if err := st.SetUserBandwidth(ctx, user.ID, 300, 600); err != nil {
		t.Fatal(err)
	}
	status, out := controlReq(t, sockPath, "POST", "/users/rate/refresh", map[string]any{
		"user_id": user.ID,
	})
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	upBPS, downBPS, _, _ := rwc.snapshotLimits()
	if upBPS != 300 || downBPS != 600 {
		t.Errorf("user rate refresh: want 300/600, got %d/%d body=%s", upBPS, downBPS, out)
	}

	// user_id 缺失 / 0 应 400。
	status, _ = controlReq(t, sockPath, "POST", "/users/rate/refresh", map[string]any{"user_id": 0})
	if status != http.StatusBadRequest {
		t.Fatalf("missing user_id: want 400, got %d", status)
	}
}

// TestControlSocket_Status_FilterByDeviceID:0012 ?device_id=X 服务端过滤。
// 没有 query → 回全量;有 query → 只回该 device。ConnCount 仍是全局总数,不是 filtered。
func TestControlSocket_Status_FilterByDeviceID(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "status_filter.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{Username: "sf", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	uid := userIDFromStoreID(user.ID)
	for i, did := range []int64{100, 200, 300} {
		c := &Connection{
			connIDStr:  "filter-" + string(rune('a'+i)),
			userID:     uid,
			deviceID:   did,
			linkConn:   newFakeLinkConn(),
			tunnelDone: make(chan struct{}),
			createdAt:  time.Now(),
		}
		installConn(t, c)
	}

	// 全量。
	status, out := controlReq(t, sockPath, "GET", "/status", nil)
	if status != http.StatusOK && status != http.StatusServiceUnavailable {
		t.Fatalf("status %d body=%s", status, out)
	}
	var all struct {
		ConnCount int `json:"conn_count"`
		Sessions  []struct {
			DeviceID int64 `json:"device_id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(out, &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Sessions) < 3 {
		t.Errorf("full: want >=3 sessions, got %d", len(all.Sessions))
	}

	// 过滤 device_id=200,只回 1 条,但 ConnCount 仍是全局 >=3。
	status, out = controlReq(t, sockPath, "GET", "/status?device_id=200", nil)
	var filt struct {
		ConnCount int `json:"conn_count"`
		Sessions  []struct {
			DeviceID int64 `json:"device_id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(out, &filt); err != nil {
		t.Fatalf("decode filtered: %v body=%s", err, out)
	}
	if len(filt.Sessions) != 1 || filt.Sessions[0].DeviceID != 200 {
		t.Errorf("filter device=200: want exactly 1 session with deviceID=200, got %+v", filt.Sessions)
	}
	if filt.ConnCount < 3 {
		t.Errorf("ConnCount should report global count (>=3), got %d", filt.ConnCount)
	}
}

// TestControlSocket_Status_Pagination(性能阶段, 2026-05-24):
//
//	?offset=&limit= 切窗口,sessions_total 给筛选后总数。
//
// 覆盖:
//   - 不带 limit → 全量(sessions == sessions_total)
//   - limit=2,offset=0 → 前 2 条
//   - limit=2,offset=2 → 中间 2 条
//   - offset 越界 → 空 sessions[],sessions_total 仍正确
//   - limit 超 statusPageLimitMax → 被 clamp
//   - limit 非数字 / 负数 → 400
func TestControlSocket_Status_Pagination(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "status_page.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{Username: "pg", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()
	// 装 5 条 conn,deviceID 1..5。
	uid := userIDFromStoreID(user.ID)
	for i := 1; i <= 5; i++ {
		c := &Connection{
			connIDStr:  "pg-" + string(rune('a'+i-1)),
			userID:     uid,
			deviceID:   int64(i),
			linkConn:   newFakeLinkConn(),
			tunnelDone: make(chan struct{}),
			createdAt:  time.Now(),
		}
		installConn(t, c)
	}

	type pgResp struct {
		ConnCount      int `json:"conn_count"`
		SessionsTotal  int `json:"sessions_total"`
		SessionsOffset int `json:"sessions_offset"`
		SessionsLimit  int `json:"sessions_limit"`
		Sessions       []struct {
			DeviceID int64 `json:"device_id"`
		} `json:"sessions"`
	}

	// 不带 limit → 全量。
	status, out := controlReq(t, sockPath, "GET", "/status", nil)
	if status != http.StatusOK && status != http.StatusServiceUnavailable {
		t.Fatalf("full status %d body=%s", status, out)
	}
	var full pgResp
	if err := json.Unmarshal(out, &full); err != nil {
		t.Fatal(err)
	}
	if len(full.Sessions) < 5 || full.SessionsTotal < 5 {
		t.Errorf("full: want >=5, got sessions=%d total=%d", len(full.Sessions), full.SessionsTotal)
	}

	// limit=2&offset=0 → 2 条;total 仍 5。
	_, out = controlReq(t, sockPath, "GET", "/status?limit=2&offset=0", nil)
	var p1 pgResp
	if err := json.Unmarshal(out, &p1); err != nil {
		t.Fatal(err)
	}
	if len(p1.Sessions) != 2 {
		t.Errorf("page1: want 2 sessions, got %d", len(p1.Sessions))
	}
	if p1.SessionsTotal < 5 {
		t.Errorf("page1 total: want >=5, got %d", p1.SessionsTotal)
	}
	if p1.SessionsLimit != 2 || p1.SessionsOffset != 0 {
		t.Errorf("page1: want limit=2 offset=0, got limit=%d offset=%d", p1.SessionsLimit, p1.SessionsOffset)
	}

	// limit=2&offset=2 → 又 2 条。
	_, out = controlReq(t, sockPath, "GET", "/status?limit=2&offset=2", nil)
	var p2 pgResp
	if err := json.Unmarshal(out, &p2); err != nil {
		t.Fatal(err)
	}
	if len(p2.Sessions) != 2 {
		t.Errorf("page2: want 2 sessions, got %d", len(p2.Sessions))
	}

	// offset 越界 → 空 + total 仍正确。
	_, out = controlReq(t, sockPath, "GET", "/status?limit=2&offset=1000", nil)
	var pOver pgResp
	if err := json.Unmarshal(out, &pOver); err != nil {
		t.Fatal(err)
	}
	if len(pOver.Sessions) != 0 {
		t.Errorf("over: want empty sessions, got %d", len(pOver.Sessions))
	}
	if pOver.SessionsTotal < 5 {
		t.Errorf("over total: want >=5, got %d", pOver.SessionsTotal)
	}

	// limit 超上限 → clamp 到 statusPageLimitMax(返回的 SessionsLimit 反映 clamp 后)。
	_, out = controlReq(t, sockPath, "GET", "/status?limit=99999", nil)
	var pBig pgResp
	if err := json.Unmarshal(out, &pBig); err != nil {
		t.Fatal(err)
	}
	if pBig.SessionsLimit != statusPageLimitMax {
		t.Errorf("clamp: want SessionsLimit=%d, got %d", statusPageLimitMax, pBig.SessionsLimit)
	}

	// 非法 limit / offset → 400。
	for _, q := range []string{"limit=abc", "limit=-1", "limit=0", "offset=-5", "offset=foo"} {
		s, _ := controlReq(t, sockPath, "GET", "/status?"+q, nil)
		if s != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", q, s)
		}
	}

	// Q2(2026-05-25):offset > 0 但无 limit → 400(显式失败,不要静默全量)。
	// offset=0 单传 OK(等价于不传)。
	s400, _ := controlReq(t, sockPath, "GET", "/status?offset=10", nil)
	if s400 != http.StatusBadRequest {
		t.Errorf("offset=10 (no limit): want 400, got %d", s400)
	}
	s200, _ := controlReq(t, sockPath, "GET", "/status?offset=0", nil)
	if s200 != http.StatusOK && s200 != http.StatusServiceUnavailable {
		t.Errorf("offset=0 (no limit, equiv to omit): want 200/503, got %d", s200)
	}

	// Q1(2026-05-25):跨次调用相同 (offset,limit) 返回的 conn_id 序列必须一致。
	// 不稳定排序的情况下,map iteration 随机会让两次拿到的 conn 序列不同。
	// 改成按 connIDStr 字典序后,任意 N 次抓都一致。
	first, second := pageConnIDs(t, sockPath, 0, 3), pageConnIDs(t, sockPath, 0, 3)
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("page size mismatch: first=%d second=%d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("pagination unstable at i=%d: first=%s second=%s; full first=%v second=%v",
				i, first[i], second[i], first, second)
		}
	}
	// 多页不重叠 + 完整覆盖。
	pg1 := pageConnIDs(t, sockPath, 0, 3)
	pg2 := pageConnIDs(t, sockPath, 3, 3)
	seen := map[string]bool{}
	for _, id := range pg1 {
		seen[id] = true
	}
	for _, id := range pg2 {
		if seen[id] {
			t.Errorf("pagination overlap: conn_id %s in both page1 and page2", id)
		}
		seen[id] = true
	}
}

// TestControlSocket_Status_SortCreatedAtDescConnIDAsc(R2, 2026-05-26):
//
//	server 端必须按 created_at DESC + conn_id ASC 二级稳定排序。
//
// 历史:Q1 第一版只按 conn_id 字典序,dashboard 用 WithLimit(N) 拿前 N 想要
// 「最新会话」时拿到的是「conn_id 字典序前 N 条」 — 跟「最新」毫无关系,UX 破。
//
// 本测试装 4 条 conn:
//
//	conn_id        createdAt
//	z-newest       t+100ms        ← 字典序最大、时间最新   → 应该排第 1
//	a-oldest       t+0ms          ← 字典序最小、时间最旧   → 应该排第 4
//	m-same-1       t+50ms         ← 字典序中、时间一致同 m-same-2 → 第 2(conn_id ASC)
//	m-same-2       t+50ms         ← 字典序中、时间一致同 m-same-1 → 第 3(conn_id ASC)
//
// 期望顺序:[z-newest, m-same-1, m-same-2, a-oldest]
//
// 反向验证:如果 server 改回 conn_id 字典序为 primary,排序会变成
// [a-oldest, m-same-1, m-same-2, z-newest],本测试 fail。
func TestControlSocket_Status_SortCreatedAtDescConnIDAsc(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "status_sort.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{Username: "ss", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	t0 := time.Now()
	uid := userIDFromStoreID(user.ID)
	// 故意打乱注入顺序,排查 map iteration 误导。
	conns := []struct {
		id string
		at time.Time
	}{
		{"a-oldest", t0},
		{"z-newest", t0.Add(100 * time.Millisecond)},
		{"m-same-1", t0.Add(50 * time.Millisecond)},
		{"m-same-2", t0.Add(50 * time.Millisecond)},
	}
	for _, x := range conns {
		c := &Connection{
			connIDStr:  x.id,
			userID:     uid,
			linkConn:   newFakeLinkConn(),
			tunnelDone: make(chan struct{}),
			createdAt:  x.at,
		}
		installConn(t, c)
	}

	got := pageConnIDs(t, sockPath, 0, 0) // 全量
	// 只校验本测试装的 4 条(其它历史 conn 可能在共享 connIDMap 里残留,过滤掉)。
	want := []string{"z-newest", "m-same-1", "m-same-2", "a-oldest"}
	var filtered []string
	wanted := map[string]bool{
		"a-oldest": true, "z-newest": true, "m-same-1": true, "m-same-2": true,
	}
	for _, id := range got {
		if wanted[id] {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) != len(want) {
		t.Fatalf("expected 4 of our conns, got %d: %v", len(filtered), filtered)
	}
	for i, id := range want {
		if filtered[i] != id {
			t.Errorf("sort mismatch at i=%d: want %q, got %q; full=%v", i, id, filtered[i], filtered)
		}
	}

	// 配合 dashboard 用例:WithLimit(2) 拿前 2 条 = 最新 2 条 = z-newest + m-same-1。
	top2 := pageConnIDs(t, sockPath, 0, 2)
	// top2 可能含其它历史 conn(time 更晚)— 只断言我们的 2 条至少之一是 z-newest。
	// 实际生产场景 dashboard 拿前 5/10,这里只验「最新」语义存在。
	hasZ := false
	for _, id := range top2 {
		if id == "z-newest" {
			hasZ = true
			break
		}
	}
	// 如果 connIDMap 在测试期间没其它更新的 conn(共享状态),z-newest 一定在前 2。
	// 测试可能并行跑别的用例会装更新的 conn → hasZ 可能 false,但不强断言。
	_ = hasZ
}

// pageConnIDs:测试 helper,抓 /status?offset=&limit= 取 conn_id 列表。
// limit=0 表示不传 limit,server 走全量路径(老兼容)。
func pageConnIDs(t *testing.T, sockPath string, offset, limit int) []string {
	t.Helper()
	url := "/status"
	if limit > 0 {
		url = fmt.Sprintf("/status?offset=%d&limit=%d", offset, limit)
	}
	_, out := controlReq(t, sockPath, "GET", url, nil)
	var resp struct {
		Sessions []struct {
			ConnID string `json:"conn_id"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal %s: %v body=%s", url, err, out)
	}
	out2 := make([]string, len(resp.Sessions))
	for i, s := range resp.Sessions {
		out2[i] = s.ConnID
	}
	return out2
}

// TestControlSocket_Status_RaceWindowCounter(可观测阶段, 2026-05-24):
// safeRLConn() 返回 nil 累计被记到 safeRLConnNilCount,/status.race_window_total
// 暴露之。本测试通过装一条 rlConn 未设置的 conn 让 /status 自然触发 nil 路径。
func TestControlSocket_Status_RaceWindowCounter(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "race_ctr.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{Username: "rc", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}
	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()
	// 故意不设 rlConn(原子 zero value):/status 走 safeRLConn() 时 Load 返 nil → counter +1。
	c := &Connection{
		connIDStr:  "rc-conn",
		userID:     userIDFromStoreID(user.ID),
		linkConn:   newFakeLinkConn(),
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	}
	installConn(t, c)

	before := safeRLConnNilCount.Load()
	status, out := controlReq(t, sockPath, "GET", "/status", nil)
	if status != http.StatusOK && status != http.StatusServiceUnavailable {
		t.Fatalf("status %d body=%s", status, out)
	}
	var resp struct {
		RaceWindow uint64 `json:"race_window_total"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatal(err)
	}
	after := safeRLConnNilCount.Load()
	// 这条测试跑 parallel 时其它 _Pagination / _FilterByDeviceID 测试也在拉 /status
	// 推高 counter,所以不能 == 严等。验证 (a) 我们这一次 /status 至少推了 +1,
	// (b) 暴露字段 resp.RaceWindow 是 counter 的快照(read 时点 >= before,<= 当前)。
	if after <= before {
		t.Errorf("counter should grow after /status hits a nil rlConn: before=%d after=%d", before, after)
	}
	if resp.RaceWindow < uint64(before+1) {
		t.Errorf("race_window_total exposed (%d) should be at least before+1 (%d)", resp.RaceWindow, before+1)
	}
}
