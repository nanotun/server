package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// 管理面还剩三处「回报成功但没做对事」的形状。
//
//   - /rate/refresh?device_id=N 是「只刷这一台」。参数被忽略就变成全量刷:几千条在线会话每条都要查一次库
//     再重设限速器,一次点击能把管理面和 DB 拖住,而响应仍是 ok。
//   - 同一台设备的多条会话(多网卡 / 重连残留)刷限速时必须复用同一次 DB 查询结果。不复用就是 N 条会话
//     查 N 次库,同样只在会话多的时候才浮出来。
//   - /reload?what=routes 的响应里带当前生效的路由条数,是管理员确认「批准真的落到转发表里了」的唯一读数。
//     恒回 0 的话,他会以为批准没生效而反复重试。

// TestControlSocketRateRefresh_ScopesToTheGivenDeviceAndReusesOneDBLookup 定向刷只动目标设备,且同设备只查一次库。
func TestControlSocketRateRefresh_ScopesToTheGivenDeviceAndReusesOneDBLookup(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	_, devID := mustCreateUserAndDevice(t, gw, "rate-scoped")
	_, otherDev := mustCreateUserAndDevice(t, gw, "rate-untouched")

	// 目标设备上挂两条会话(同一台设备的多条链路),另一台设备挂一条。
	mk := func(sid string, deviceID int64) *rateLimitedConn {
		rl := newRateLimitedConn(newFakeLinkConn(), nil, nil, context.Background())
		c := &Connection{
			connIDStr:  sid,
			userID:     "1",
			deviceID:   deviceID,
			linkConn:   rl,
			tunnelDone: make(chan struct{}),
			createdAt:  time.Now(),
		}
		c.rlConn.Store(rl) // atomic.Pointer 字段不能写在 struct literal 里
		installConn(t, c)
		return rl
	}
	// 库里给目标设备配了限速,另一台没有。
	if err := gw.store.SetDeviceRateLimit(t.Context(), devID, 7000, 8000); err != nil {
		t.Fatalf("配设备限速: %v", err)
	}
	first := mk("scoped-a", devID)
	second := mk("scoped-b", devID)
	untouched := mk("other-dev", otherDev)
	untouched.SetUploadLimit(1234, 4096) // 一个能看出「有没有被动过」的标记值

	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	status, out := controlReq(t, sockPath, "POST", "/rate/refresh?device_id="+strconv.FormatInt(devID, 10), nil)
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}

	for name, rl := range map[string]*rateLimitedConn{"第一条": first, "第二条": second} {
		up, down, _, _ := rl.snapshotLimits()
		if up != 7000 || down != 8000 {
			t.Errorf("%s会话没被刷到库里的限速(up=%d down=%d)—— 定向刷漏了同一设备上的别的会话", name, up, down)
		}
	}
	if up, _, _, _ := untouched.snapshotLimits(); up != 1234 {
		t.Errorf("别的设备的会话被一起改了(up=%d)—— device_id 参数没起作用,这是一次全量刷", up)
	}
}

// TestControlSocketReloadRoutes_ReportsHowManyRoutesAreLive routes reload 要回报当前生效条数。
func TestControlSocketReloadRoutes_ReportsHowManyRoutesAreLive(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "reload-routes")
	approveExitRoute(t, devID, "192.168.77.0/24")
	// reload 会把这份表装进全局并留在那儿。不还原的话,后面任何跑登录的用例都会在握手中间
	// 收到一帧 RoutesList(pushInitialRoutesList 的正常行为),读帧的断言就对不上了。
	prevTable := subnetRouteTable.Load()
	t.Cleanup(func() { subnetRouteTable.Store(prevTable) })

	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	status, out := controlReq(t, sockPath, "POST", "/reload?what=routes", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	var resp struct {
		OK     bool `json:"ok"`
		Routes int  `json:"routes"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("解响应: %v body=%s", err, out)
	}
	if !resp.OK {
		t.Fatalf("routes reload 回了 ok=false: %s", out)
	}
	if resp.Routes != 1 {
		t.Errorf("回报生效路由 %d 条,want 1 —— 管理员看不到批准是否真的落进转发表,只能反复重试", resp.Routes)
	}
}

// TestControlSocketRateRefresh_KeepsWorkingWithoutARateLimiterOnTheSession 会话上没有限速器时不能崩。
//
// 登录早期 / 桩连接上 rateConn 可能是 nil。管理面在这种会话上刷限速必须安静跳过 —— 一个 panic
// 会掀翻整个管理面 goroutine,之后所有 reload / kick / status 全部不可用。
func TestControlSocketRateRefresh_KeepsWorkingWithoutARateLimiterOnTheSession(t *testing.T) {
	resetServerGlobals(t)
	gw := newRouteTestGateway(t)

	installConn(t, &Connection{
		connIDStr:  "no-limiter",
		userID:     "1",
		linkConn:   newFakeLinkConn(),
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	})
	rl := newRateLimitedConn(newFakeLinkConn(), rate.NewLimiter(100, 1024), nil, context.Background())
	withLimiter := &Connection{
		connIDStr:  "with-limiter",
		userID:     "1",
		linkConn:   rl,
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	}
	withLimiter.rlConn.Store(rl)
	installConn(t, withLimiter)

	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	status, out := controlReq(t, sockPath, "POST", "/rate/refresh", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
}
