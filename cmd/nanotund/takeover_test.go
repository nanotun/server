package main

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// TestGenerateTakeoverSecret 校验 secret 是 64 字符 hex 且每次唯一（极小概率冲突可忽略）。
func TestGenerateTakeoverSecret(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		s := generateTakeoverSecret()
		if len(s) != 64 {
			t.Fatalf("expected len 64, got %d (s=%q)", len(s), s)
		}
		if _, err := hex.DecodeString(s); err != nil {
			t.Fatalf("expected hex, decode err: %v (s=%q)", err, s)
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("collision after %d draws: %s", i+1, s)
		}
		seen[s] = struct{}{}
	}
}

// TestCleanupConnection_TakenOverSkipsVIPRelease 验证 takenOver=true 路径：
//   - connIDMap[connIDStr] 上的 cur 已经是新 conn 时，老 conn 的 cleanup 不会误删；
//   - clientIPs 中的 vip 不会被从 clientIPUsed 表里删除（即没有触碰 vip 释放分支）；
//   - connections[c.connID] 上的本 conn 项被删除。
//
// 不依赖 sharedTUN:takenOver=true 路径下 cleanupConnection 仅清理 connections 表项,
// 不会去碰 vIP / TunChan / Conntrack,因此完全 in-process 就能跑。
func TestCleanupConnection_TakenOverSkipsVIPRelease(t *testing.T) {
	const sid = "fake-session-id-takeover-skip"
	const vip = "10.99.0.99"

	clientIPUsedMu.Lock()
	clientIPUsed[vip] = true
	clientIPUsedMu.Unlock()
	t.Cleanup(func() {
		clientIPUsedMu.Lock()
		delete(clientIPUsed, vip)
		clientIPUsedMu.Unlock()
	})

	oldConn := &Connection{
		connIDStr: sid,
		userID:    "u-1",
		// TunChan 故意为 nil，避免 cleanup 走入 drainAndCloseTunChan/registerTunReadChan，
		// takenOver=true 路径本来就跳过这些，正是要验证的不变量。
		connID: 111,
	}
	// S1(2026-05-26):clientIPs 是 atomic.Pointer,不能 struct literal,显式 Store。
	ips := []util.VirtualIPAssignment{{VirtualIP: vip}}
	oldConn.clientIPs.Store(&ips)
	oldConn.takenOver.Store(true)

	newConn := &Connection{connIDStr: sid, connID: 222}

	connIDMapMu.Lock()
	connIDMap[sid] = newConn // 模拟接管后已被新 conn 覆盖
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		if cur, ok := connIDMap[sid]; ok && cur == newConn {
			delete(connIDMap, sid)
		}
		connIDMapMu.Unlock()
	})

	connectionsMu.Lock()
	connections[oldConn.connID] = oldConn
	connections[newConn.connID] = newConn
	connectionsMu.Unlock()
	t.Cleanup(func() {
		connectionsMu.Lock()
		delete(connections, newConn.connID)
		connectionsMu.Unlock()
	})

	cleanupConnection(oldConn)

	connIDMapMu.RLock()
	gotMap := connIDMap[sid]
	connIDMapMu.RUnlock()
	if gotMap != newConn {
		t.Fatalf("connIDMap[%s] expected newConn, got %v", sid, gotMap)
	}

	connectionsMu.RLock()
	_, oldStillThere := connections[oldConn.connID]
	_, newStillThere := connections[newConn.connID]
	connectionsMu.RUnlock()
	if oldStillThere {
		t.Fatalf("expected connections[%d] (oldConn) to be deleted", oldConn.connID)
	}
	if !newStillThere {
		t.Fatalf("expected connections[%d] (newConn) to remain", newConn.connID)
	}

	clientIPUsedMu.Lock()
	stillUsed := clientIPUsed[vip]
	clientIPUsedMu.Unlock()
	if !stillUsed {
		t.Fatalf("vip %s should still be in clientIPUsed (takeover path must skip release)", vip)
	}
}

// TestCleanupConnection_NormalConnIDMapGuard 验证非接管路径下，
// 若 connIDMap[connIDStr] 已被其它 conn 覆盖（守卫 cur == c 不成立），cleanup 也不会误删。
func TestCleanupConnection_NormalConnIDMapGuard(t *testing.T) {
	const sid = "fake-session-id-guard"

	c := &Connection{connIDStr: sid, connID: 333}
	other := &Connection{connIDStr: sid, connID: 334}

	connIDMapMu.Lock()
	connIDMap[sid] = other
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		if cur, ok := connIDMap[sid]; ok && cur == other {
			delete(connIDMap, sid)
		}
		connIDMapMu.Unlock()
	})

	connectionsMu.Lock()
	connections[c.connID] = c
	connectionsMu.Unlock()

	// userID="" → cleanup 跳过 bc.SessionRelease，bc=nil 不会 panic。
	c.userID = ""
	cleanupConnection(c)

	connIDMapMu.RLock()
	got := connIDMap[sid]
	connIDMapMu.RUnlock()
	if got != other {
		t.Fatalf("connIDMap[%s] expected other, got %v", sid, got)
	}

	connectionsMu.RLock()
	_, stillThere := connections[c.connID]
	connectionsMu.RUnlock()
	if stillThere {
		t.Fatalf("expected connections[%d] to be deleted", c.connID)
	}
}

// readResp 从 client 端读一帧 LoginResp。
//
// 超时给到 15s(与客户端真实的 LoginResp 接收超时同口径),不是 2s:接管路径上有一次 argon2 校验,
// 那是**故意**昂贵的。全包跑(尤其 -race)时机器很忙,2s 的余量不够 —— 实测在两轮全量里各偶发过一次
// `read pipe: i/o timeout`,而隔离压测怎么跑都不复现。harness 上的超时只为「别永远挂着」,
// 卡得紧一点不会让任何断言更严格,只会换来偶发红。
func readResp(t *testing.T, conn net.Conn) *util.LoginResp {
	t.Helper()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	typ, payload, err := util.ReadLinkFrame(conn)
	if err != nil {
		t.Fatalf("client read LoginResp: %v", err)
	}
	if typ != util.LinkTypeLoginResp {
		t.Fatalf("expected LoginResp(=%d), got %d", util.LinkTypeLoginResp, typ)
	}
	resp, err := util.ParseLoginRespLinkPayload(payload)
	if err != nil {
		t.Fatalf("parse LoginResp: %v", err)
	}
	return resp
}

// awaitDone 等异步 handler 退出，超时则报错。
func awaitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("handler did not return in time")
	}
}

// makeTakeoverReq 构造一个 takeover LoginReq（不依赖 helper，以免误踩 helper 兼容性）。
func makeTakeoverReq(sid, secret, transport string) *util.LoginReq {
	return &util.LoginReq{
		Purpose:           util.PurposeTakeover,
		TakeoverSessionID: sid,
		TakeoverSecret:    secret,
		Transport:         transport,
	}
}

func TestHandleTakeoverLogin_EmptySessionID(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTakeoverLogin(serverConn, nil, makeTakeoverReq("", "any", "hy2"), "test-remote", "")
	}()

	resp := readResp(t, clientConn)
	if resp.Code == 0 {
		t.Fatalf("expected non-zero code, got %+v", resp)
	}
	if resp.Message == "" {
		t.Fatalf("expected non-empty message")
	}
	awaitDone(t, done)
}

func TestHandleTakeoverLogin_SessionNotFound(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTakeoverLogin(serverConn, nil,
			makeTakeoverReq("non-existent-sid-aabbccdd", "any-secret", "hy2"),
			"test-remote-2", "")
	}()

	resp := readResp(t, clientConn)
	if resp.Code == 0 {
		t.Fatalf("expected non-zero code, got: %+v", resp)
	}
	awaitDone(t, done)
}

func TestHandleTakeoverLogin_SecretMismatch(t *testing.T) {
	const sid = "test-secret-mismatch-sid"
	const correct = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	oldClient, oldServer := net.Pipe()
	defer oldClient.Close()
	defer oldServer.Close()

	oldConn := &Connection{
		connIDStr:      sid,
		userID:         "u-old",
		linkConn:       oldServer,
		takeoverSecret: correct,
		tunnelDone:     make(chan struct{}),
	}
	connIDMapMu.Lock()
	connIDMap[sid] = oldConn
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		if cur, ok := connIDMap[sid]; ok && cur == oldConn {
			delete(connIDMap, sid)
		}
		connIDMapMu.Unlock()
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTakeoverLogin(serverConn, nil,
			makeTakeoverReq(sid, "wrong-secret-deadbeef", "hy2"),
			"test-remote-3", "")
	}()

	resp := readResp(t, clientConn)
	if resp.Code == 0 {
		t.Fatalf("expected non-zero code on secret mismatch, got: %+v", resp)
	}
	awaitDone(t, done)

	if oldConn.takenOver.Load() {
		t.Fatalf("oldConn must not be marked takenOver on secret mismatch")
	}
}

// 防御「空 secret 全等」bypass:如果 oldConn 的 takeoverSecret 是空(crypto/rand 失败),
// attacker 拿到 session_id 发个空 secret,ConstantTimeCompare("", "") 会返回 1 ——
// handleTakeoverLogin 必须在 ConstantTimeCompare 之前拒绝空 secret。
func TestHandleTakeoverLogin_RejectEmptySecret(t *testing.T) {
	const sid = "test-empty-secret-sid"

	oldClient, oldServer := net.Pipe()
	defer oldClient.Close()
	defer oldServer.Close()

	// 模拟 oldConn 的 takeoverSecret 是空(罕见的 crypto/rand 失败场景)。
	oldConn := &Connection{
		connIDStr:      sid,
		userID:         "u-old",
		linkConn:       oldServer,
		takeoverSecret: "", // 关键:空 secret
		tunnelDone:     make(chan struct{}),
	}
	connIDMapMu.Lock()
	connIDMap[sid] = oldConn
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		if cur, ok := connIDMap[sid]; ok && cur == oldConn {
			delete(connIDMap, sid)
		}
		connIDMapMu.Unlock()
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// attacker 也发空 secret,naive ConstantTimeCompare 会让两边都通过。
		handleTakeoverLogin(serverConn, nil,
			makeTakeoverReq(sid, "", "hy2"),
			"attacker-remote", "")
	}()

	resp := readResp(t, clientConn)
	if resp.Code == 0 {
		t.Fatalf("expected non-zero code on empty secret, got: %+v", resp)
	}
	awaitDone(t, done)

	if oldConn.takenOver.Load() {
		t.Fatalf("oldConn must NOT be taken over via empty secret")
	}
}

// TestParseLoginReq_TakeoverFieldsRoundtrip 验证 LoginReq + takeover 字段 JSON 兼容性
// （从 server 端 parser 视角，再次校验 PR1 协议字段在 server 包内可用）。
// TestHandleTakeoverLogin_AbortsWhenKickedMidWindow 覆盖第二十一轮深扫 MED:接管**提交前**必须复检
// oldConn.superseded,否则落在「argon2 后复检(server.go:3468)」与「提交(connIDMapMu 段)」之间的一次踢除
// 会被绕过 —— kickConnForUserInvalidate 不持 takeoverMu,只置 superseded + 关老链路,而提交若不复检就照常
// 把 newConn 发布到 connIDMap[sid] 并过户 vIP,会话带着同一 sid 在新链路上继续存活。周期扫描能自愈三种
// 自动踢除,但**管理员显式 kick**(control_socket)是一次性的,还会向管理员报「已踢除」→ 静默失败。
//
// 用 net.Pipe 无缓冲这一特性把踢除**确定性**地插进窗口:server 写 ConvSalt 会阻塞到本测试去读,而提交严格
// 晚于该写返回,故在「读 ConvSalt 之前」置 superseded 必然落在窗口内。
func TestHandleTakeoverLogin_AbortsWhenKickedMidWindow(t *testing.T) {
	resetServerGlobals(t)
	gw, st := newPSKGateway(t)
	ctx := t.Context()

	// 真实 argon2 PSK:authVerifier 是具体类型,无法注入假实现。
	hash, err := auth.HashPSK("takeover-pw")
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.CreateUser(ctx, store.NewUser{Username: "eve", PSKHash: hash})
	if err != nil {
		t.Fatal(err)
	}

	const sid = "test-kick-midwindow-sid"
	secret := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	oldIPs := []util.VirtualIPAssignment{{
		VirtualIP: "10.201.0.5",
		Mask:      "255.255.0.0",
		Gateway:   "10.201.0.1/16",
		TunChan:   make(chan *util.TunPacket, 4),
	}}
	oldConn := &Connection{
		connIDStr:      sid,
		userID:         userIDFromStoreID(u.ID),
		linkConn:       &routeFakeConn{}, // 缓冲写:老链路的 TakenOver 通知不阻塞(它排在提交之前)
		takeoverSecret: secret,
		tunnelDone:     make(chan struct{}),
	}
	oldConn.clientIPs.Store(&oldIPs)

	connIDMapMu.Lock()
	connIDMap[sid] = oldConn
	connIDMapMu.Unlock()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTakeoverLogin(serverConn, gw, &util.LoginReq{
			Purpose:           util.PurposeTakeover,
			TakeoverSessionID: sid,
			TakeoverSecret:    secret,
			Transport:         "hy2",
			Name:              "eve",
			Token:             "takeover-pw",
		}, "test-remote-kick", "")
	}()

	// 1) 先收 LoginResp —— 此刻 server 已过 3468 复检,正走向提交(接管在客户端看来已成功)。
	if resp := readResp(t, clientConn); resp.Code != 0 {
		t.Fatalf("接管应已通过校验并回 code=0,got %+v", resp)
	}

	// 2) 模拟 admin kick 落进窗口:置 superseded(kickConnForUserInvalidate 关链路前做的第一件事)。
	oldConn.superseded.Store(true)

	// 3) 读掉 ConvSalt,放 server 继续走到提交点 —— 此后它必须发现 superseded 并放弃接管。
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))
	typ, _, rerr := util.ReadLinkFrame(clientConn)
	if rerr != nil {
		t.Fatalf("读 ConvSalt 失败: %v", rerr)
	}
	if typ != util.LinkTypeConvSaltMsg {
		t.Fatalf("期望 ConvSaltMsg(=%d),got %d", util.LinkTypeConvSaltMsg, typ)
	}
	// 注意失败模式:守卫若缺失,handleTakeoverLogin 会提交并继续走老链路 teardown → 等
	// oldConn.tunnelDone(本测试从不关它)→ 进 newConn 的 runLinkTunnel,**永不返回**。
	// 所以回归时先在这里以「handler did not return in time」告警,而不是命中下面的状态断言。
	awaitDone(t, done)

	// 接管必须被放弃:oldConn 不得标 takenOver(否则其 cleanup 会跳过 vIP / SessionRelease 回收,
	// 被踢的会话资源永久滞留),连表也不得被换成 newConn。
	if oldConn.takenOver.Load() {
		t.Fatal("窗口内被踢除时不应把 oldConn 标为 takenOver(接管应放弃)")
	}
	connIDMapMu.RLock()
	cur := connIDMap[sid]
	connIDMapMu.RUnlock()
	if cur != oldConn {
		t.Fatalf("connIDMap[sid] 应仍是 oldConn(接管放弃),却被换成了 %p", cur)
	}
	// rollback defer 必须把 newConn 从 connections 表撤掉(测试没往里放 oldConn,故应为空)。
	connectionsMu.Lock()
	n := len(connections)
	connectionsMu.Unlock()
	if n != 0 {
		t.Fatalf("放弃接管后 connections 应被回滚为空,仍有 %d 条(newConn 泄漏)", n)
	}
}

func TestParseLoginReq_TakeoverFieldsRoundtrip(t *testing.T) {
	in := &util.LoginReq{
		Name:              "u",
		Token:             "psk-tok",
		Purpose:           util.PurposeTakeover,
		TakeoverSessionID: "sid-xyz",
		TakeoverSecret:    "sec-xyz",
		Transport:         "hy2",
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := util.ParseLoginReqLinkPayload(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Purpose != in.Purpose ||
		out.TakeoverSessionID != in.TakeoverSessionID ||
		out.TakeoverSecret != in.TakeoverSecret ||
		out.Transport != in.Transport {
		t.Fatalf("roundtrip mismatch: in=%+v out=%+v", in, out)
	}
}
