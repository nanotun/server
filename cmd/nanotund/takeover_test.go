package main

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"testing"
	"time"

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

// readResp 从 client 端读一帧 LoginResp，超时 2s。
func readResp(t *testing.T, conn net.Conn) *util.LoginResp {
	t.Helper()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
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
