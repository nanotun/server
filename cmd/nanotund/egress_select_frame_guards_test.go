package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/nanotun/server/util"
)

// 出口选择这一帧的拒绝分支。
//
// 这条路上「拒绝」有两种写法,差别是安全性的:一种是**明确拒绝**(回 ack、把绑定置成 fail-closed
// 哨兵,数据面就地丢包),另一种是**静默回落 server 自出口**。后者曾经真实存在:用户点名经 C 出网、
// 服务器答「不行」,然后把他的公网流量从 server 自己的公网 IP 送出去 —— 三机实测(2026-07-25)复现
// 到出网 IP 变成 server 的地址,而用户侧唯一线索是客户端一行日志。整条选择路径因此改成:凡是不能
// 兑现的选择,一律 fail-closed,绝不悄悄换一条出网路径。
//
// 下面几条盯的是尚无断言的那几个拒绝分支,其中两条方向相反、都不能错:
//   - 没有出口权限 → 明确拒绝(而不是绑上去让数据面兜);
//   - DB 暂时查不动 → **不改现状**、回 try_again 让客户端重试(而不是当成「未批准」把人踢回 server)。

func TestHandleEgressSelectFrame_RefusesWhatItCannotHonor(t *testing.T) {
	t.Run("nil 会话不炸", func(t *testing.T) {
		body, err := util.MarshalEgressSelect("server")
		if err != nil {
			t.Fatal(err)
		}
		handleEgressSelectFrame(t.Context(), nil, body) // 不该 panic
	})

	t.Run("帧解析不了就丢并计数", func(t *testing.T) {
		fake := newFakeLinkConn()
		c := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true, linkConn: fake}
		c.egressDeviceID.Store(77)
		before := egressSelectFailed.Load()

		handleEgressSelectFrame(t.Context(), c, []byte{0xff, 0x00})

		if egressSelectFailed.Load() != before+1 {
			t.Error("解析失败应记 egressSelectFailed")
		}
		if got := c.egressDeviceID.Load(); got != 77 {
			t.Errorf("坏帧不该动现有绑定,egressDeviceID=%d", got)
		}
		if len(fake.writeBuf) != 0 {
			t.Error("坏帧不该回 ack —— 连它要什么都没解析出来")
		}
	})

	t.Run("没有出口权限:明确拒绝,不绑定", func(t *testing.T) {
		gw := withEgressTestGateway(t)
		exitUUID := "11111111-2222-4333-8444-555555555555"
		seedApprovedExitDevice(t, gw.store, exitUUID)

		fake := newFakeLinkConn()
		// exitAllowed=false:这个用户没被授予「经出口节点出网」的权限。
		c := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: false, linkConn: fake}
		body, err := util.MarshalEgressSelect(exitUUID)
		if err != nil {
			t.Fatal(err)
		}
		before := egressSelectRejected.Load()

		handleEgressSelectFrame(t.Context(), c, body)

		if egressSelectRejected.Load() != before+1 {
			t.Error("应记 egressSelectRejected")
		}
		if got := c.egressDeviceID.Load(); got != 0 {
			t.Errorf("无权限的选择不该产生任何绑定,egressDeviceID=%d", got)
		}
		assertEgressAck(t, fake, false, "exit_not_allowed")
	})

	t.Run("DB 查不动:回 try_again 且一个字都不改", func(t *testing.T) {
		gw := withEgressTestGateway(t)
		exitUUID := "11111111-2222-4333-8444-555555555555"
		seedApprovedExitDevice(t, gw.store, exitUUID)

		fake := newFakeLinkConn()
		c := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true, linkConn: fake}
		// 现状:已经绑在某台出口上,而且记着意图。
		c.egressDeviceID.Store(77)
		c.desiredExitDeviceID.Store(77)
		c.desiredExitUUID.Store("old-uuid")

		// 把出口路由表藏起来 → resolveApprovedExitDeviceID 返回「查不动」。
		if _, err := gw.store.DB().ExecContext(t.Context(),
			`ALTER TABLE subnet_routes RENAME TO subnet_routes_gone`); err != nil {
			t.Fatalf("藏表: %v", err)
		}
		body, err := util.MarshalEgressSelect(exitUUID)
		if err != nil {
			t.Fatal(err)
		}
		before := egressSelectRejected.Load()

		handleEgressSelectFrame(t.Context(), c, body)

		if egressSelectRejected.Load() != before+1 {
			t.Error("应记 egressSelectRejected")
		}
		// 关键:一次 DB 抖动不许改变任何既有状态,否则用户会被从他选定的出口踢回 server。
		if got := c.egressDeviceID.Load(); got != 77 {
			t.Errorf("DB 查不动时改动了绑定:egressDeviceID=%d(期望仍为 77)—— "+
				"一次数据库抖动就把用户从选定出口踢走", got)
		}
		if got := c.desiredExitDeviceID.Load(); got != 77 {
			t.Errorf("DB 查不动时改动了意图:desiredExitDeviceID=%d", got)
		}
		if got := c.desiredExitUUID.Load(); got != "old-uuid" {
			t.Errorf("DB 查不动时改动了意图 UUID:%q", got)
		}
		// try_again 是「可重试」的信号;回 not_approved 会让客户端以为该出口已被撤销。
		assertEgressAck(t, fake, false, "try_again")
	})
}

// TestHandleEgressSelectFrame_ResetsTheOneShotGatesOnEverySelect 每次(重新)选择都要复位两个一次性闸。
//
// 这两个闸是为了「别把同一件事说一百遍」:出口离线只通知一次、开始经出口转发只记一条审计。
// 但它们必须在**每次**选择时复位 —— 否则换到新出口之后,新出口离线不再通知(用户干等),
// 换出口这件事也不再进审计(事后查不到他曾经经哪台机器出网)。
func TestHandleEgressSelectFrame_ResetsTheOneShotGatesOnEverySelect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		egress func(t *testing.T) (string, *gatewayState)
	}{
		{"选回 server", func(t *testing.T) (string, *gatewayState) {
			return "server", withEgressTestGateway(t)
		}},
		{"选一台已批准的出口", func(t *testing.T) (string, *gatewayState) {
			gw := withEgressTestGateway(t)
			uuid := "11111111-2222-4333-8444-555555555555"
			seedApprovedExitDevice(t, gw.store, uuid)
			return uuid, gw
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			egress, _ := tc.egress(t)
			fake := newFakeLinkConn()
			c := &Connection{userID: "u1", connIDStr: "a", deviceID: 11, exitAllowed: true, linkConn: fake}
			// 假装上一段连接里两件事都已经说过了。
			c.exitOfflineNotified = true
			c.exitFwdAudited = true

			body, err := util.MarshalEgressSelect(egress)
			if err != nil {
				t.Fatal(err)
			}
			handleEgressSelectFrame(t.Context(), c, body)

			if c.exitOfflineNotified {
				t.Error("重新选择后 exitOfflineNotified 未复位 —— 新出口离线时用户收不到通知,只会干等")
			}
			if c.exitFwdAudited {
				t.Error("重新选择后 exitFwdAudited 未复位 —— 换出口这件事不会再进审计")
			}
		})
	}
}

// assertEgressAck 从 fake linkConn 的写缓冲里解出最后一帧 EgressSelectAck 并比对。
func assertEgressAck(t *testing.T, fake *fakeLinkConn, wantAccepted bool, wantReason string) {
	t.Helper()
	if len(fake.writeBuf) == 0 {
		t.Fatal("没有回 ack —— 客户端会一直等着,不知道自己的选择有没有被接受")
	}
	ack, ok := lastEgressAck(t, fake.writeBuf)
	if !ok {
		t.Fatalf("写缓冲里没有 EgressSelectAck 帧: % x", fake.writeBuf)
	}
	if ack.Accepted != wantAccepted {
		t.Errorf("ack.Accepted = %v,期望 %v", ack.Accepted, wantAccepted)
	}
	if wantReason != "" && ack.Reason != wantReason {
		t.Errorf("ack.Reason = %q,期望 %q —— 理由错了客户端就会做错的后续动作"+
			"(try_again 该重试,not_approved 该认为出口已撤销)", ack.Reason, wantReason)
	}
}

// lastEgressAck 扫 link 帧流,取最后一帧 EgressSelectAck。
func lastEgressAck(t *testing.T, buf []byte) (util.EgressSelectAck, bool) {
	t.Helper()
	var out util.EgressSelectAck
	found := false
	// link 帧:2 字节大端长度(含类型字节)+ 1 字节类型 + payload。
	for off := 0; off+3 <= len(buf); {
		l := int(binary.BigEndian.Uint16(buf[off : off+2]))
		if l < 1 || off+2+l > len(buf) {
			break
		}
		if buf[off+2] == util.LinkTypeEgressSelectAck {
			if ack, err := util.ParseEgressSelectAck(buf[off+3 : off+2+l]); err == nil && ack != nil {
				out, found = *ack, true
			}
		}
		off += 2 + l
	}
	return out, found
}

// TestSendEgressSelectAck_StaysQuietWhenThereIsNoLink 回 ack 是 best-effort:
// 没有链路(会话正在拆 / 已被接管)时必须安静返回,不能 panic —— 它的调用点全在拒绝路径上,
// 在那里 panic 等于「一个非法请求就能带走整条会话」。
func TestSendEgressSelectAck_StaysQuietWhenThereIsNoLink(t *testing.T) {
	sendEgressSelectAck(nil, util.EgressSelectAck{Accepted: true})
	sendEgressSelectAck(&Connection{userID: "u1"}, util.EgressSelectAck{Accepted: true})

	// 写失败(对端已关)只记日志,不 panic、不阻塞。
	fake := newFakeLinkConn()
	fake.writeErr = errors.New("对端已关")
	c := &Connection{userID: "u1", connIDStr: "a", linkConn: fake}
	sendEgressSelectAck(c, util.EgressSelectAck{Accepted: false, Reason: "try_again"})
}

// TestServerSelfEgressV6FastFail_OnlyFiresOnPublicV6WhenWeKnowThereIsNoV6 server 自出口的 v6 快失败。
//
// 判断错方向的两种坏法:该快失败时不快失败 → 包写进 server TUN 被内核黑洞,客户端要等到
// TCP 超时才回落 v4(体验上是「v6 网站打不开、转圈几十秒」);不该快失败时快失败 → 把本来
// 走得通的 v6 流量全打回去。所以三个条件缺一不可:已探明、确实无 v6、目的是公网 v6。
func TestServerSelfEgressV6FastFail_OnlyFiresOnPublicV6WhenWeKnowThereIsNoV6(t *testing.T) {
	prevKnown, prevHas := serverV6EgressKnown.Load(), serverV6EgressHas.Load()
	t.Cleanup(func() { serverV6EgressKnown.Store(prevKnown); serverV6EgressHas.Store(prevHas) })

	c := &Connection{userID: "u1", connIDStr: "a", linkConn: newFakeLinkConn()}

	t.Run("还没探明:放行(维持旧行为)", func(t *testing.T) {
		serverV6EgressKnown.Store(false)
		serverV6EgressHas.Store(false)
		if serverSelfEgressV6FastFail(c, mkIPv6Pkt(t, "2606:4700::1111")) {
			t.Error("v6 能力尚未探明时不该快失败 —— 启动那几秒会把能走的 v6 也打回去")
		}
	})

	t.Run("包解析不了:放行", func(t *testing.T) {
		serverV6EgressKnown.Store(true)
		serverV6EgressHas.Store(false)
		if serverSelfEgressV6FastFail(c, []byte{0x60, 0x00}) {
			t.Error("解不出五元组的包不归这条路径处理")
		}
	})

	t.Run("有 v6 出网:放行", func(t *testing.T) {
		serverV6EgressKnown.Store(true)
		serverV6EgressHas.Store(true)
		if serverSelfEgressV6FastFail(c, mkIPv6Pkt(t, "2606:4700::1111")) {
			t.Error("本机有 v6 出网时不该快失败")
		}
	})

	t.Run("确无 v6 + 目的是公网 v6:快失败并计数", func(t *testing.T) {
		serverV6EgressKnown.Store(true)
		serverV6EgressHas.Store(false)
		before := serverEgressDroppedNoV6.Load()
		if !serverSelfEgressV6FastFail(c, mkIPv6Pkt(t, "2606:4700::1111")) {
			t.Fatal("确无 v6 出网时公网 v6 目的必须就地快失败,而不是写进 TUN 让内核黑洞")
		}
		if serverEgressDroppedNoV6.Load() != before+1 {
			t.Error("应记 serverEgressDroppedNoV6")
		}
	})

	t.Run("mesh 内的 ULA 不受影响", func(t *testing.T) {
		serverV6EgressKnown.Store(true)
		serverV6EgressHas.Store(false)
		if serverSelfEgressV6FastFail(c, mkIPv6Pkt(t, "fd00::2")) {
			t.Error("ULA(mesh / 4via6)与公网出网无关,不该被打回")
		}
	})
}

// mkIPv6Pkt 造一个最小 IPv6 包(仅填目的地址,足够 parsePacketTuple 用)。
func mkIPv6Pkt(t *testing.T, dst string) []byte {
	t.Helper()
	p := make([]byte, 40)
	p[0] = 0x60 // version 6
	p[6] = 6    // next header: TCP
	d := netip.MustParseAddr(dst).As16()
	copy(p[24:40], d[:])
	return p
}
