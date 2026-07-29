package main

import (
	"testing"
	"time"
)

// 接管落定之后要补一次出口复核。
//
// 这道闸补的是一个窄竞态:admin 撤销出口时,`revalidateExitBindings` 扫的是当时的 connIDMap ——
// 如果它扫到的是**还没标记 takenOver 的老连接**,CAS 就落在那条即将死掉的连接上,而真正在跑的
// 新连接漏掉了。结果是「出口已经撤销了,但那台客户端还在从它出网」:后台看到的是已撤销,数据面
// 上流量照走,直到客户端下次重连才对上。热切换是弱网下的常规动作,这个窗口不难撞上。
//
// 所以接管在收尾处对「继承了出口绑定」的会话补扫一次。幂等、不误撤销(查不动库时一律保留)。

// TestTakeover_RevalidatesAnInheritedExitBindingRightAfterTheHandover 继承来的出口若已不再被批准,接管后必须被改判。
func TestTakeover_RevalidatesAnInheritedExitBindingRightAfterTheHandover(t *testing.T) {
	fx := newTakeoverFixture(t)
	// revalidateExitBindings 从全局 gatewayInstance 取 store。
	prev := gatewayInstance
	gatewayInstance = fx.gw
	t.Cleanup(func() { gatewayInstance = prev })

	// 老链路绑着一台**库里查不到已批准 0/0 路由**的设备 —— 等价于「出口刚被撤销」。
	const revokedDev int64 = 4242
	fx.oldConn.egressDeviceID.Store(revokedDev)

	resp := runTakeoverOK(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("合法接管应成功: %+v", resp)
	}
	newConn := currentConnForSID(t, fx.sid, fx.oldConn)

	// 补扫是异步的,给它一个有界窗口。
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := newConn.egressDeviceID.Load()
		if got == egressFailClosed {
			return // 已改判 fail-closed:撤销真的兑现到了新连接上
		}
		if time.Now().After(deadline) {
			t.Fatalf("接管后新连接仍绑着已撤销的出口(egressDeviceID=%d)—— 后台显示已撤销,这台客户端却还在从那个出口出网,直到它下次重连", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
