package main

import (
	"math"
	"testing"
)

// conv_id 计数器回绕时必须跳过 0。
//
// 0 在这套代码里是「没有连接」的哨兵值(handleVPNLink 自己就在下游用 `convID == 0` 判分配失败)。
// 计数器是 uint32,长跑节点转够 42 亿条连接就会回绕到 0 —— 那一刻若不跳过,恰好落在 0 上的那次
// 登录会被自己的下游判成「分配失败」而拒登,而 takeover 侧更糟:连接会带着 0 号 ID 进 connections 表,
// 与「无连接」不可区分。这类 bug 只在长跑几个月后随机发作一次,现场基本无法复现。

// TestLogin_SkipsZeroWhenTheConvIDCounterWrapsAround 登录路径:回绕那一刻仍要发得出可用的 conv_id。
func TestLogin_SkipsZeroWhenTheConvIDCounterWrapsAround(t *testing.T) {
	env := newLoginGateEnv(t)
	withDualStackTUN(t, "10.99.0.1/24", "")
	// 下一次 Add(1) 正好回绕成 0。
	env.gw.nextConvID.Store(math.MaxUint32)

	got := dualStackLogin(t, env, stormAddr(45), "known", "right-psk",
		"11111111-2222-4333-8444-000000000045")
	if got.resp.Code != 0 {
		t.Fatalf("计数器回绕不该让这次登录失败: %+v", got.resp)
	}

	connectionsMu.Lock()
	defer connectionsMu.Unlock()
	if _, zero := connections[0]; zero {
		t.Error("回绕后把 0 当成了正常 conv_id —— 它是「没有连接」的哨兵值,这条会话与「不存在」无法区分")
	}
	if len(connections) != 1 {
		t.Fatalf("connections 里应恰好一条会话,实际 %d 条", len(connections))
	}
}

// TestTakeover_SkipsZeroWhenTheConvIDCounterWrapsAround 接管路径:同一道闸,单独一份实现。
//
// 两处是各自写的 for 循环,补一处不会连带补上另一处 —— 接管这边漏掉的话,新连接会以 0 号 ID
// 进 connections 表,而 cleanup / kick 都按这个 ID 找连接。
func TestTakeover_SkipsZeroWhenTheConvIDCounterWrapsAround(t *testing.T) {
	fx := newTakeoverFixture(t)
	fx.gw.nextConvID.Store(math.MaxUint32)

	resp := runTakeoverOK(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("计数器回绕不该让接管失败: %+v", resp)
	}
	newConn := currentConnForSID(t, fx.sid, fx.oldConn)
	if newConn.connID == 0 {
		t.Error("接管后的新连接拿到 0 号 conv_id —— 它与「没有连接」同值,按 ID 的清理与踢线都会认错人")
	}
}
