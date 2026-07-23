package main

import (
	"context"
	"net/netip"
	"testing"

	"github.com/nanotun/server/store"
)

// setGlobalContextForTest 给 resolveDeviceVIP 用的 globalContext 一个干净根并还原（否则 WithTimeout(nil,...) panic）。
func setGlobalContextForTest(t *testing.T) {
	t.Helper()
	prevCtx, prevCancel := globalContext, globalContextCancel
	globalContext, globalContextCancel = context.WithCancel(context.Background())
	t.Cleanup(func() {
		globalContextCancel()
		globalContext, globalContextCancel = prevCtx, prevCancel
	})
}

func newDialTestManager(t *testing.T, gw *gatewayState) *portForwardManager {
	t.Helper()
	return &portForwardManager{
		gw:       gw,
		meshV4:   netip.MustParsePrefix("10.201.0.0/16").Masked(), // 10.201.x = vIP(node)，其余 = LAN
		vipCache: make(map[string]vipCacheEntry),
	}
}

// LAN 目标：直接用配置的静态 IP（不碰设备解析），ok=true。
func TestResolveDialTarget_LANUsesConfigured(t *testing.T) {
	setGlobalContextForTest(t)
	gw := newRouteTestGateway(t)
	m := newDialTestManager(t, gw)

	pf := store.PortForward{PublicPort: 2222, TargetDeviceUUID: "no-such", TargetIP: "192.168.8.5", TargetPort: 22}
	target, ok := m.resolveDialTarget(pf)
	if !ok || target != "192.168.8.5:22" {
		t.Fatalf("LAN 目标应返回配置 IP, got %q ok=%v", target, ok)
	}
}

// node 目标、设备当前 vIP 未变：拨该 vIP，ok=true。
func TestResolveDialTarget_NodeNoDrift(t *testing.T) {
	setGlobalContextForTest(t)
	gw := newRouteTestGateway(t)
	_, deviceID := mustCreateUserAndDevice(t, gw, "alice")
	if err := gw.store.SetDeviceFixedVIP(t.Context(), deviceID, "10.201.0.6", "", false); err != nil {
		t.Fatal(err)
	}
	const uuid = "11111111-1111-4111-8111-111111111111"
	m := newDialTestManager(t, gw)

	pf := store.PortForward{PublicPort: 2222, TargetDeviceUUID: uuid, TargetIP: "10.201.0.6", TargetPort: 22}
	target, ok := m.resolveDialTarget(pf)
	if !ok || target != "10.201.0.6:22" {
		t.Fatalf("node 目标无漂移应拨该 vIP, got %q ok=%v", target, ok)
	}
}

// node 目标、设备 vIP 已漂移：改拨设备**当前** vIP（而非配置里的陈旧值），ok=true。
func TestResolveDialTarget_NodeDriftUsesCurrent(t *testing.T) {
	setGlobalContextForTest(t)
	gw := newRouteTestGateway(t)
	_, deviceID := mustCreateUserAndDevice(t, gw, "alice")
	if err := gw.store.SetDeviceFixedVIP(t.Context(), deviceID, "10.201.0.9", "", false); err != nil { // 当前是 .9
		t.Fatal(err)
	}
	const uuid = "11111111-1111-4111-8111-111111111111"
	m := newDialTestManager(t, gw)

	pf := store.PortForward{PublicPort: 2222, TargetDeviceUUID: uuid, TargetIP: "10.201.0.6", TargetPort: 22} // 配置陈旧 .6
	target, ok := m.resolveDialTarget(pf)
	if !ok || target != "10.201.0.9:22" {
		t.Fatalf("node 目标漂移应拨当前 vIP .9, got %q ok=%v", target, ok)
	}
}

// node 目标、设备已删除（UUID 解析不到）：fail-close（ok=false），绝不盲拨陈旧配置 vIP。
func TestResolveDialTarget_NodeDeletedFailClose(t *testing.T) {
	setGlobalContextForTest(t)
	gw := newRouteTestGateway(t)
	m := newDialTestManager(t, gw)

	pf := store.PortForward{PublicPort: 2222, TargetDeviceUUID: "ffffffff-ffff-4fff-8fff-ffffffffffff", TargetIP: "10.201.0.6", TargetPort: 22}
	if target, ok := m.resolveDialTarget(pf); ok {
		t.Fatalf("设备已删应 fail-close，绝不返回陈旧 vIP, got %q ok=%v", target, ok)
	}
}

// node 目标、设备在册但当前无 vIP（无 fixed、无 lease）：fail-close，绝不盲拨陈旧配置 vIP（可能已归属他人）。
func TestResolveDialTarget_NodeNoVIPFailClose(t *testing.T) {
	setGlobalContextForTest(t)
	gw := newRouteTestGateway(t)
	mustCreateUserAndDevice(t, gw, "alice") // 设备在册，但未设 fixed vIP、无 lease
	const uuid = "11111111-1111-4111-8111-111111111111"
	m := newDialTestManager(t, gw)

	pf := store.PortForward{PublicPort: 2222, TargetDeviceUUID: uuid, TargetIP: "10.201.0.6", TargetPort: 22}
	if target, ok := m.resolveDialTarget(pf); ok {
		t.Fatalf("设备当前无 vIP 应 fail-close, got %q ok=%v", target, ok)
	}
}
