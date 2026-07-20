package main

import (
	"net/netip"
	"testing"

	"github.com/nanotun/server/util"
)

// P0-3(2026-05-22)现场触发的 race:同 vIP 重连后,老 conn cleanup 把新 conn 的
// chan 一起从 demux map 里 unregister 掉,导致新连接 server→client 方向黑洞。
//
// 单测覆盖:
//   1) register 后再 register(同 IP):覆盖语义,留新 chan ✓
//   2) 老 conn 带 tunChan=v1 unregister:identity 不匹配(map[ip]=v2),保留 v2 ✓
//   3) 新 conn 带 tunChan=v2 unregister:identity 匹配,删除 ✓
//   4) action.tunChan == nil 的历史调用方:fallback 无条件删 ✓

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// TestApplyTunChanRegisterAction_OverwriteOnReRegister 验证同 vIP 重新 register 覆盖。
func TestApplyTunChanRegisterAction_OverwriteOnReRegister(t *testing.T) {
	m := map[netip.Addr]chan *util.TunPacket{}
	ip := mustAddr("10.201.0.5")
	chV1 := make(chan *util.TunPacket, 1)
	chV2 := make(chan *util.TunPacket, 1)

	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 0, ip: ip, tunChan: chV1})
	if m[ip] != chV1 {
		t.Fatalf("register v1: want %p, got %p", chV1, m[ip])
	}

	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 0, ip: ip, tunChan: chV2})
	if m[ip] != chV2 {
		t.Fatalf("re-register v2: want %p, got %p", chV2, m[ip])
	}
}

// TestApplyTunChanRegisterAction_StaleUnregisterPreservesNewChan 是 P0-3 主要回归测试。
//
// 场景:iOS 同 vIP 重连,顺序:
//
//	T0: v1 register → map[ip]=v1
//	T1: v2 register → map[ip]=v2  (新连接接管)
//	T2: v1 unregister(老 conn cleanup) → 必须保留 v2,不能删除 map[ip]
//
// 现场症状:T2 后 map[ip] 空,server→client 方向全部丢包,ping 100% loss。
func TestApplyTunChanRegisterAction_StaleUnregisterPreservesNewChan(t *testing.T) {
	m := map[netip.Addr]chan *util.TunPacket{}
	ip := mustAddr("10.201.0.5")
	chV1 := make(chan *util.TunPacket, 1)
	chV2 := make(chan *util.TunPacket, 1)

	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 0, ip: ip, tunChan: chV1})
	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 0, ip: ip, tunChan: chV2})

	// 老 conn(v1)的 cleanup 跑:必须带 tunChan=v1,identity 不匹配 → 跳过删除。
	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 1, ip: ip, tunChan: chV1})
	if m[ip] != chV2 {
		t.Fatalf("stale v1 unregister broke v2 registration: map[ip]=%p, want %p", m[ip], chV2)
	}

	// 新 conn(v2)主动 cleanup:identity 匹配 → 真删。
	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 1, ip: ip, tunChan: chV2})
	if _, ok := m[ip]; ok {
		t.Fatalf("self-owned v2 unregister did not delete map entry")
	}
}

// TestApplyTunChanRegisterAction_LegacyNilTunChanFallback 兼容旧调用方语义。
//
// 历史代码里 action=1 时 tunChan 字段未填(零值 nil)。新逻辑保留兼容:
// nil 时回退到无条件删除,避免单测 / 第三方 fork 触发新 identity 路径反而出错。
func TestApplyTunChanRegisterAction_LegacyNilTunChanFallback(t *testing.T) {
	m := map[netip.Addr]chan *util.TunPacket{}
	ip := mustAddr("10.201.0.5")
	ch := make(chan *util.TunPacket, 1)

	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 0, ip: ip, tunChan: ch})
	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 1, ip: ip /* tunChan: nil */})
	if _, ok := m[ip]; ok {
		t.Fatalf("nil-tunChan unregister should fall back to unconditional delete, got map[ip]=%p", m[ip])
	}
}

// TestApplyTunChanRegisterAction_UnregisterAfterSelfRegister 普通成对操作。
func TestApplyTunChanRegisterAction_UnregisterAfterSelfRegister(t *testing.T) {
	m := map[netip.Addr]chan *util.TunPacket{}
	ip := mustAddr("fd00:200::5")
	ch := make(chan *util.TunPacket, 1)

	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 0, ip: ip, tunChan: ch})
	applyTunChanRegisterAction(m, registerTunReadChanAction{action: 1, ip: ip, tunChan: ch})
	if _, ok := m[ip]; ok {
		t.Fatalf("normal pair register/unregister should leave map empty")
	}
}
