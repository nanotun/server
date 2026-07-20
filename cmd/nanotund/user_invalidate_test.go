package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// fakeLinkConn 实现 io.ReadWriteCloser + SetWriteDeadline,把所有写都丢到一个
// 内存 buffer,Close 时把内部标志置为 true,便于断言 close 被调用。
type fakeLinkConn struct {
	closed   chan struct{}
	writeBuf []byte
}

func newFakeLinkConn() *fakeLinkConn {
	return &fakeLinkConn{closed: make(chan struct{})}
}

func (c *fakeLinkConn) Read(p []byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}
func (c *fakeLinkConn) Write(p []byte) (int, error) {
	c.writeBuf = append(c.writeBuf, p...)
	return len(p), nil
}
func (c *fakeLinkConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *fakeLinkConn) SetWriteDeadline(_ time.Time) error { return nil }

func newTestGatewayForUserInvalidate(t *testing.T) *gatewayState {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ui.db"), store.Options{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &gatewayState{store: st}
}

func installConn(t *testing.T, c *Connection) {
	t.Helper()
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connByUserAddLocked(c) // P3-a:必须同步 by-user 索引,否则 scanAndKickInvalidUsers 找不到
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		if cur, ok := connIDMap[c.connIDStr]; ok && cur == c {
			delete(connIDMap, c.connIDStr)
		}
		connByUserDeleteLocked(c)
		connIDMapMu.Unlock()
	})
}

// TestScanAndKick_NoOpForActiveUser:user 没改过任何字段时,不应该踢已建立 session。
func TestScanAndKick_NoOpForActiveUser(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	ctx := t.Context()
	user, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "psk-hash-alice"})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeLinkConn()
	c := &Connection{
		connIDStr:      "conn-active",
		userID:         userIDFromStoreID(user.ID),
		linkConn:       fake,
		pskHashAtLogin: "psk-hash-alice",
		tunnelDone:     make(chan struct{}),
		createdAt:      time.Now(),
	}
	installConn(t, c)
	scanAndKickInvalidUsers(ctx, gw)
	select {
	case <-fake.closed:
		t.Fatal("active user 不应触发 close")
	default:
	}
}

// TestScanAndKick_DisabledUser:user.disabled_at != 0 → 踢线 + audit。
func TestScanAndKick_DisabledUser(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	ctx := t.Context()
	user, err := gw.store.CreateUser(ctx, store.NewUser{Username: "bob", PSKHash: "psk-bob"})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeLinkConn()
	c := &Connection{
		connIDStr:      "conn-bob",
		userID:         userIDFromStoreID(user.ID),
		linkConn:       fake,
		pskHashAtLogin: "psk-bob",
		tunnelDone:     make(chan struct{}),
		createdAt:      time.Now(),
	}
	installConn(t, c)
	if err := gw.store.DisableUser(ctx, user.ID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	scanAndKickInvalidUsers(ctx, gw)
	select {
	case <-fake.closed:
	case <-time.After(time.Second):
		t.Fatal("disabled user 应触发 close")
	}

	// exit-node 黑洞修复回归：kick 必须在 close 前置 superseded，使被踢会话若是某 device 的在跑出口/子网路由器，
	// 立即从 by-device 转发目标里摘除（不等异步 cleanup），避免「已踢未清」窗口把请求方流量投进死链路黑洞。
	if !c.superseded.Load() {
		t.Fatal("被 kick 的 conn 应置 superseded=true（防出口/子网转发黑洞）")
	}

	// audit: kick.user_invalidate 写过一行,detail 含 reason=user_disabled
	rows, err := gw.store.QueryAudit(ctx, 0, time.Now().Add(time.Hour).Unix(), 50)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	var found bool
	for _, r := range rows {
		if r.Action == "kick_user_invalidate" && r.Target == userIDFromStoreID(user.ID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("kick_user_invalidate audit not found: %+v", rows)
	}
}

// TestScanAndKick_PSKRotated:user.psk_hash 与登录时的 snapshot 不同 → 踢线。
func TestScanAndKick_PSKRotated(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	ctx := t.Context()
	user, err := gw.store.CreateUser(ctx, store.NewUser{Username: "carol", PSKHash: "psk-old"})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeLinkConn()
	c := &Connection{
		connIDStr:      "conn-carol",
		userID:         userIDFromStoreID(user.ID),
		linkConn:       fake,
		pskHashAtLogin: "psk-old",
		tunnelDone:     make(chan struct{}),
		createdAt:      time.Now(),
	}
	installConn(t, c)
	if err := gw.store.RotateUserPSK(ctx, user.ID, "psk-new-rotated", time.Now().UTC().Unix()); err != nil {
		t.Fatalf("RotateUserPSK: %v", err)
	}
	scanAndKickInvalidUsers(ctx, gw)
	select {
	case <-fake.closed:
	case <-time.After(time.Second):
		t.Fatal("psk rotated user 应触发 close")
	}
}

// TestScanAndKick_PSKRotatedAfterTakeover:回归 P1-1。
// 时序:primary 登录(c1, pskHashAtLogin=psk-old) → takeover 切链路(c2,
// 由 server.go takeover 分支赋 newConn.pskHashAtLogin = 本次握手 PSK 的 hash;
// 老 conn 标记 takenOver=true 后从 connIDMap 移除) → admin RotateUserPSK("psk-new")
// → 周期扫描应当踢掉 takeover 后的 c2(因为 newConn 必须带本次握手 PSK 的
// 快照,否则 user_invalidate 拿到空字符串就跳过这条会话,旧 PSK 持有者继续在线)。
//
// 没有 P1-1 修复时:c2.pskHashAtLogin == "" → userInvalidReason 不命中
// psk_rotated 分支 → c2 不被踢,**该测试 select 命中 timeout 失败**。
//
// 第三轮深扫修正:server.go 的 takeover 改为 **authResult.User.PSKHash 优先**
// (本次握手 PSK 的 hash = DB 当下值),oldConn 仅作防御性 fallback。此处构造
// 同步更新优先级,保持测试反映生产逻辑。`user.PSKHash` 在 RotateUserPSK 前
// 仍是 "psk-old",与 oldConn.pskHashAtLogin 等价,结果不变,但赋值姿势对齐。
func TestScanAndKick_PSKRotatedAfterTakeover(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	ctx := t.Context()
	user, err := gw.store.CreateUser(ctx, store.NewUser{Username: "erin", PSKHash: "psk-old"})
	if err != nil {
		t.Fatal(err)
	}
	uidStr := userIDFromStoreID(user.ID)

	oldFake := newFakeLinkConn()
	oldConn := &Connection{
		connIDStr:      "conn-erin-primary",
		userID:         uidStr,
		linkConn:       oldFake,
		pskHashAtLogin: "psk-old",
		tunnelDone:     make(chan struct{}),
		createdAt:      time.Now().Add(-time.Minute),
	}
	installConn(t, oldConn)
	oldConn.takenOver.Store(true)

	connIDMapMu.Lock()
	delete(connIDMap, oldConn.connIDStr)
	connByUserDeleteLocked(oldConn)
	connIDMapMu.Unlock()

	newFake := newFakeLinkConn()
	newConn := &Connection{
		connIDStr: oldConn.connIDStr,
		userID:    oldConn.userID,
		linkConn:  newFake,
		pskHashAtLogin: func() string {
			if user.PSKHash != "" {
				return user.PSKHash
			}
			return oldConn.pskHashAtLogin
		}(),
		tunnelDone: make(chan struct{}),
		createdAt:  time.Now(),
	}
	installConn(t, newConn)

	if err := gw.store.RotateUserPSK(ctx, user.ID, "psk-new", time.Now().UTC().Unix()); err != nil {
		t.Fatalf("RotateUserPSK: %v", err)
	}

	scanAndKickInvalidUsers(ctx, gw)

	select {
	case <-newFake.closed:
	case <-time.After(time.Second):
		t.Fatal("takeover 后的 newConn 未继承 pskHashAtLogin,扫描漏踢(P1-1 回归)")
	}

	rows, err := gw.store.QueryAudit(ctx, 0, time.Now().Add(time.Hour).Unix(), 50)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	var found bool
	for _, r := range rows {
		if r.Action == "kick_user_invalidate" && r.Target == uidStr {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("kick_user_invalidate audit 未写: %+v", rows)
	}
}

// TestScanAndKick_PlatformDenied(2026-07-18):admin 把 allowed_platforms 改成不含
// 某在线会话的登录平台 → **只踢那一条**(per-conn 判定);合规平台的会话不动;
// close 帧的 code 必须是 910(客户端当终止码,不重连),不是 905。
func TestScanAndKick_PlatformDenied(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	ctx := t.Context()
	user, err := gw.store.CreateUser(ctx, store.NewUser{Username: "frank", PSKHash: "psk-frank"})
	if err != nil {
		t.Fatal(err)
	}
	uidStr := userIDFromStoreID(user.ID)

	macFake := newFakeLinkConn()
	macConn := &Connection{
		connIDStr:       "conn-frank-mac",
		userID:          uidStr,
		linkConn:        macFake,
		pskHashAtLogin:  "psk-frank",
		platformAtLogin: "macos",
		tunnelDone:      make(chan struct{}),
		createdAt:       time.Now(),
	}
	installConn(t, macConn)

	androidFake := newFakeLinkConn()
	androidConn := &Connection{
		connIDStr:       "conn-frank-android",
		userID:          uidStr,
		linkConn:        androidFake,
		pskHashAtLogin:  "psk-frank",
		platformAtLogin: "android",
		tunnelDone:      make(chan struct{}),
		createdAt:       time.Now(),
	}
	installConn(t, androidConn)

	// 白名单未设(空)→ 两条都不踢。
	scanAndKickInvalidUsers(ctx, gw)
	select {
	case <-macFake.closed:
		t.Fatal("空白名单不应踢 macos 会话")
	case <-androidFake.closed:
		t.Fatal("空白名单不应踢 android 会话")
	default:
	}

	// 收紧到只允许 macos → android 会话应被踢,macos 会话保留。
	if err := gw.store.SetUserAllowedPlatforms(ctx, user.ID, "macos"); err != nil {
		t.Fatalf("SetUserAllowedPlatforms: %v", err)
	}
	scanAndKickInvalidUsers(ctx, gw)
	select {
	case <-androidFake.closed:
	case <-time.After(time.Second):
		t.Fatal("android 会话不在白名单内,应触发 close")
	}
	select {
	case <-macFake.closed:
		t.Fatal("macos 会话在白名单内,不应被踢")
	default:
	}

	// close 帧 code 必须是 910(五端把 910 当终止码;905 会让客户端先空跑一轮重连)。
	if !bytes.Contains(androidFake.writeBuf, []byte(`"code":910`)) {
		t.Fatalf("close 帧应携带 code=910,实际写出: %s", string(androidFake.writeBuf))
	}

	// audit 里能看到 platform_denied 的踢线记录。
	rows, err := gw.store.QueryAudit(ctx, 0, time.Now().Add(time.Hour).Unix(), 50)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	var found bool
	for _, r := range rows {
		if r.Action == "kick_user_invalidate" && r.Target == uidStr &&
			strings.Contains(r.Detail, "platform_denied") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("platform_denied 踢线 audit 未写: %+v", rows)
	}
}

// TestScanAndKick_DeletedUser:user 行不存在 → 踢线。
func TestScanAndKick_DeletedUser(t *testing.T) {
	gw := newTestGatewayForUserInvalidate(t)
	ctx := t.Context()
	user, err := gw.store.CreateUser(ctx, store.NewUser{Username: "dave", PSKHash: "psk-dave"})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeLinkConn()
	c := &Connection{
		connIDStr:      "conn-dave",
		userID:         userIDFromStoreID(user.ID),
		linkConn:       fake,
		pskHashAtLogin: "psk-dave",
		tunnelDone:     make(chan struct{}),
		createdAt:      time.Now(),
	}
	installConn(t, c)
	if err := gw.store.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	scanAndKickInvalidUsers(ctx, gw)
	select {
	case <-fake.closed:
	case <-time.After(time.Second):
		t.Fatal("deleted user 应触发 close")
	}
}

// 防御:net.Conn 当 linkConn 时也能被关闭(避免 type assertion 漏了 *net.TCPConn)。
func TestKickConnForUserInvalidate_NetPipeWorks(t *testing.T) {
	srv, cli := net.Pipe()
	defer cli.Close()

	c := &Connection{
		connIDStr:      "conn-np",
		userID:         "u10",
		linkConn:       srv,
		pskHashAtLogin: "h-old",
		tunnelDone:     make(chan struct{}),
		createdAt:      time.Now(),
	}
	installConn(t, c)
	kickConnForUserInvalidate(context.Background(), nil, c, 10, "psk_rotated")

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4)
		_, _ = cli.Read(buf)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("远端 net.Pipe 未感知 close (写 + Close 应触发 EOF)")
	}
}
