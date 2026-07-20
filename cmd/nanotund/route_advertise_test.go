package main

import (
	"bytes"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// routeFakeConn 是测试用的 fake linkConn:只记 Write,Close 立刻完成。
type routeFakeConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *routeFakeConn) Read(p []byte) (int, error) { return 0, nil }
func (c *routeFakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}
func (c *routeFakeConn) Close() error { return nil }
func (c *routeFakeConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := make([]byte, c.buf.Len())
	copy(b, c.buf.Bytes())
	return b
}

func newRouteTestGateway(t *testing.T) *gatewayState {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "route.db"), store.Options{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &gatewayState{store: st}
}

func mustCreateUserAndDevice(t *testing.T, gw *gatewayState, username string) (int64, int64) {
	t.Helper()
	ctx := t.Context()
	u, err := gw.store.CreateUser(ctx, store.NewUser{Username: username, PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	d, err := gw.store.UpsertDevice(ctx, u.ID, "11111111-1111-4111-8111-111111111111", "dev1", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	return u.ID, d.ID
}

// 路由 advertise → 落库 + 回 status 帧。
func TestHandleRouteAdvertiseFrame_HappyPath(t *testing.T) {
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })

	_, deviceID := mustCreateUserAndDevice(t, gw, "alice")
	fake := &routeFakeConn{}
	c := &Connection{userID: "u1", deviceID: deviceID, linkConn: fake}

	body, _ := util.MarshalRouteAdvertise([]string{"192.168.1.5/24", "10.0.0.0/8", "not-a-cidr"})
	handleRouteAdvertiseFrame(t.Context(), c, body)

	rows, _ := gw.store.ListRoutesByDevice(t.Context(), deviceID)
	if len(rows) != 2 {
		t.Fatalf("expected 2 valid rows, got %d (%+v)", len(rows), rows)
	}
	gotCIDRs := map[string]bool{}
	for _, r := range rows {
		gotCIDRs[r.CIDR] = true
		if r.Status != store.RouteStatusPending {
			t.Fatalf("status = %q, want pending", r.Status)
		}
	}
	if !gotCIDRs["192.168.1.0/24"] || !gotCIDRs["10.0.0.0/8"] {
		t.Fatalf("missing normalized cidr: %+v", gotCIDRs)
	}

	typ, payload, err := util.ReadLinkFrame(bytes.NewReader(fake.bytes()))
	if err != nil {
		t.Fatalf("ReadLinkFrame: %v", err)
	}
	if typ != util.LinkTypeRouteApproveStatus {
		t.Fatalf("reply type = %d, want %d", typ, util.LinkTypeRouteApproveStatus)
	}
	rs, err := util.ParseRouteApproveStatus(payload)
	if err != nil {
		t.Fatalf("ParseRouteApproveStatus: %v", err)
	}
	if len(rs.Updated) != 2 {
		t.Fatalf("status updated len = %d, want 2", len(rs.Updated))
	}
}

// 匿名 device(deviceID=0)→ 拒绝整帧,不落库。
func TestHandleRouteAdvertiseFrame_Anonymous(t *testing.T) {
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })

	fake := &routeFakeConn{}
	c := &Connection{userID: "u1", deviceID: 0, linkConn: fake}

	body, _ := util.MarshalRouteAdvertise([]string{"192.168.1.0/24"})
	handleRouteAdvertiseFrame(t.Context(), c, body)

	if len(fake.bytes()) != 0 {
		t.Fatal("anonymous device 不应回 status 帧")
	}
}

// 空 routes 列表 → 删除 pending,不动 approved。
func TestHandleRouteAdvertiseFrame_EmptyKeepsApproved(t *testing.T) {
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })

	_, deviceID := mustCreateUserAndDevice(t, gw, "bob")

	if _, err := gw.store.UpsertAdvertisedRoute(t.Context(), deviceID, "10.0.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if _, err := gw.store.UpsertAdvertisedRoute(t.Context(), deviceID, "10.0.1.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := gw.store.SetRouteStatus(t.Context(), deviceID, "10.0.0.0/24", store.RouteStatusApproved, ""); err != nil {
		t.Fatal(err)
	}

	fake := &routeFakeConn{}
	c := &Connection{userID: "u1", deviceID: deviceID, linkConn: fake}

	body, _ := util.MarshalRouteAdvertise(nil)
	handleRouteAdvertiseFrame(t.Context(), c, body)

	rows, _ := gw.store.ListRoutesByDevice(t.Context(), deviceID)
	if len(rows) != 1 || rows[0].CIDR != "10.0.0.0/24" {
		t.Fatalf("empty advertise 应只删 pending,留下 approved;现 rows=%+v", rows)
	}
}

// unionPrefixes:去重 + prev=nil + 上限截断(第 7/8 轮深扫)。
func TestUnionPrefixes(t *testing.T) {
	p := func(s string) netip.Prefix { return netip.MustParsePrefix(s).Masked() }
	a := []netip.Prefix{p("192.168.1.0/24"), p("10.0.0.0/8")}
	b := []netip.Prefix{p("10.0.0.0/8"), p("172.16.0.0/12")} // 10/8 与 a 重复
	if out := unionPrefixes(&a, b); len(out) != 3 {
		t.Fatalf("union 去重后应 3 条,得 %d", len(out))
	}
	if out := unionPrefixes(nil, b); len(out) != 2 {
		t.Fatalf("prev=nil 应 2 条,得 %d", len(out))
	}
	// 上限截断:造 > maxAdvertisedRoutesPerConn 条不同 /24。
	big := make([]netip.Prefix, 0, maxAdvertisedRoutesPerConn+50)
	for i := 0; i < maxAdvertisedRoutesPerConn+50; i++ {
		big = append(big, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 24))
	}
	if out := unionPrefixes(nil, big); len(out) != maxAdvertisedRoutesPerConn {
		t.Fatalf("超上限应截断到 %d,得 %d", maxAdvertisedRoutesPerConn, len(out))
	}
}

// 非空(非出口)advertise → 置 advertisedSubnetRoutes 且填充 advertisedRoutes(供 forwardPacketToSubnetRoute per-CIDR 门控)。
func TestHandleRouteAdvertiseFrame_PopulatesAdvertisedRoutes(t *testing.T) {
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })

	_, deviceID := mustCreateUserAndDevice(t, gw, "carol")
	fake := &routeFakeConn{}
	c := &Connection{userID: "u1", deviceID: deviceID, linkConn: fake}

	body, _ := util.MarshalRouteAdvertise([]string{"192.168.5.0/24", "10.9.0.0/16"})
	handleRouteAdvertiseFrame(t.Context(), c, body)

	if !c.advertisedSubnetRoutes.Load() {
		t.Fatal("非空子网 advertise 后应置 advertisedSubnetRoutes=true")
	}
	pfxs := c.advertisedRoutes.Load()
	if pfxs == nil || len(*pfxs) != 2 {
		t.Fatalf("advertisedRoutes 应含 2 条,得 %v", pfxs)
	}
	has := func(a netip.Addr) bool {
		for _, pf := range *pfxs {
			if pf.Contains(a) {
				return true
			}
		}
		return false
	}
	if !has(netip.MustParseAddr("192.168.5.10")) || has(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("advertisedRoutes 命中语义错误(集内应命中、集外应不命中)")
	}
}

// 第 9 轮深扫:同一会话再次 advertise(全量、收窄)→ advertisedRoutes 以**本帧为准 replace**,剔除已移除网段
// (非 union 累积——否则 takeover 重连带着继承的旧集会漏剔除,per-CIDR 门控失效)。
func TestHandleRouteAdvertiseFrame_ReadvertiseReplaces(t *testing.T) {
	gw := newRouteTestGateway(t)
	oldGW := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = oldGW })

	_, deviceID := mustCreateUserAndDevice(t, gw, "dave")
	fake := &routeFakeConn{}
	c := &Connection{userID: "u1", deviceID: deviceID, linkConn: fake}

	// 首帧宣告 {X, Y}。
	body1, _ := util.MarshalRouteAdvertise([]string{"192.168.5.0/24", "10.9.0.0/16"})
	handleRouteAdvertiseFrame(t.Context(), c, body1)
	if pfxs := c.advertisedRoutes.Load(); pfxs == nil || len(*pfxs) != 2 {
		t.Fatalf("首帧后应含 2 条,得 %v", pfxs)
	}

	// 再帧收窄到 {X}(模拟 takeover 后重连带来的窄全量帧;此前继承/累积的 {X,Y} 应被 replace 掉 Y)。
	body2, _ := util.MarshalRouteAdvertise([]string{"192.168.5.0/24"})
	handleRouteAdvertiseFrame(t.Context(), c, body2)
	pfxs := c.advertisedRoutes.Load()
	if pfxs == nil || len(*pfxs) != 1 {
		t.Fatalf("收窄再帧后应只剩 1 条(replace 非 union),得 %v", pfxs)
	}
	has := func(a netip.Addr) bool {
		for _, pf := range *pfxs {
			if pf.Contains(a) {
				return true
			}
		}
		return false
	}
	if !has(netip.MustParseAddr("192.168.5.10")) || has(netip.MustParseAddr("10.9.0.1")) {
		t.Fatal("收窄后应只保留 192.168.5.0/24、剔除 10.9.0.0/16")
	}
}
