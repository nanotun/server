package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// testB64Std 暴露 std base64 给同包测试的 base64StdDecode helper。
var testB64Std = base64.StdEncoding

// TestPSKLoginEndToEndOverPipe 在 server-level 验证 PSK 自托管模式：
//
//   - 用 store 预置一个用户（PSK = "hunter2"）；
//   - 用 net.Pipe() 模拟一对 client/server 连接，server 端跑 handleVPNLink；
//   - client 端发标准 LinkTypeLoginReq 帧（携带 device_uuid / device_name）；
//   - 期望收到 code=0 的 LoginResp、紧跟一帧 LinkTypeConvSaltMsg；
//   - 期望 store.devices 表里多了对应 (user_id, device_uuid) 行。
//
// 由于 sharedTUN 在测试里不创建，vIP 分配会被跳过、lease 不会落库 —— 这部分由
// alloc_lease_test.go 的单元测试覆盖。本测试聚焦「登录帧握手 + device upsert」
// 这条 server.go 集成路径，避免和真 TUN 设备耦合。
func TestPSKLoginEndToEndOverPipe(t *testing.T) {
	resetServerGlobals(t)

	ctx := t.Context()

	// 1) 预置 store + 用户。
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "psk_e2e.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pskHash, err := auth.HashPSK("hunter2")
	if err != nil {
		t.Fatalf("HashPSK: %v", err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{
		Username:    "alice",
		PSKHash:     pskHash,
		ExitAllowed: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// 2) 拼一个 PSK 模式的 gateway。
	cfg := &config.Config{}
	gw := &gatewayState{
		cfg:          cfg,
		store:        st,
		authVerifier: auth.NewVerifier(st),
	}

	// 3) net.Pipe 一对相连的 conn；server 端进 handleVPNLink。
	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		handleVPNLink(serverEnd, gw)
	}()

	// 4a) P2#16:先跑一遍 PoW handshake(server 始终启用 PoW)。
	pow := runClientPoWHandshake(t, clientEnd)

	// 4b) 客户端发 LoginReq(带 device_uuid + PoW)。
	loginPayload, err := marshalLoginReqWithPoW(
		"alice", "hunter2",
		"client", "darwin", "tcp",
		// 必须是合法 RFC 4122 v4：authenticatePSK 现在严格校验，非 v4 会按「未提供」降级。
		"11111111-2222-4333-8444-555555555555", "Alice's MacBook",
		pow,
	)
	if err != nil {
		t.Fatalf("marshalLoginReqWithPoW: %v", err)
	}
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, loginPayload, 2*time.Second); err != nil {
		t.Fatalf("write login frame: %v", err)
	}

	// 5) 客户端读 LoginResp。
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if err != nil {
		t.Fatalf("read LoginResp: %v", err)
	}
	if typ != util.LinkTypeLoginResp {
		t.Fatalf("first frame typ = %d, want %d (LoginResp)", typ, util.LinkTypeLoginResp)
	}
	var resp util.LoginResp
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("unmarshal LoginResp: %v\n%s", err, payload)
	}
	if resp.Code != 0 {
		t.Fatalf("LoginResp code = %d msg=%q, want 0", resp.Code, resp.Message)
	}
	if resp.UserID != "u"+itoaInt64(user.ID) {
		t.Fatalf("LoginResp UserID = %q, want u%d", resp.UserID, user.ID)
	}
	if resp.SessionID == "" || resp.TakeoverSecret == "" {
		t.Fatalf("LoginResp 缺少 session_id / takeover_secret: %+v", resp)
	}

	// 6) 客户端读 ConvSaltLite。
	typ2, payload2, err := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if err != nil {
		t.Fatalf("read ConvSaltLite: %v", err)
	}
	if typ2 != util.LinkTypeConvSaltMsg {
		t.Fatalf("second frame typ = %d, want %d (ConvSaltMsg)", typ2, util.LinkTypeConvSaltMsg)
	}
	salt, err := util.ParseConvSaltLiteLinkPayload(payload2)
	if err != nil {
		t.Fatalf("ParseConvSaltLite: %v\n%s", err, payload2)
	}
	// sharedTUN 未启用 → 不应分配 vIP。这条断言把「登录走通了 + vIP 被正确跳过」一锅端测掉。
	if len(salt.VirtualIPAssignments) != 0 {
		t.Fatalf("ConvSaltLite VirtualIPAssignments = %d, want 0 (no shared TUN)", len(salt.VirtualIPAssignments))
	}

	// 7) device 表里应已 upsert 出新行。
	dev, err := st.GetDeviceByUUID(ctx, user.ID, "11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("GetDeviceByUUID: %v", err)
	}
	if dev.DeviceName != "Alice's MacBook" || dev.Platform != "darwin" {
		t.Fatalf("device upsert mismatch: %+v", dev)
	}

	// 8) 关掉 client 端 → server-side runLinkTunnel 拿到 EOF 后退出。
	_ = clientEnd.Close()
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatalf("handleVPNLink 没有在 3s 内退出（可能卡在 runLinkTunnel）")
	}
}

// TestPSKLoginEndToEndBadPSK：对端给了错误 PSK，应当收到非 0 LoginResp 然后立即关闭。
func TestPSKLoginEndToEndBadPSK(t *testing.T) {
	resetServerGlobals(t)

	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "psk_bad.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	hash, _ := auth.HashPSK("right-pass")
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "bob", PSKHash: hash}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	gw := &gatewayState{cfg: cfg, store: st, authVerifier: auth.NewVerifier(st)}

	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		handleVPNLink(serverEnd, gw)
	}()

	// P2#16:先跑 PoW handshake(server 始终启用)。
	pow := runClientPoWHandshake(t, clientEnd)

	body, _ := marshalLoginReqWithPoW("bob", "WRONG", "c", "linux", "tcp", "u-bob", "", pow)
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 2*time.Second); err != nil {
		t.Fatalf("write: %v", err)
	}

	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != util.LinkTypeLoginResp {
		t.Fatalf("typ = %d, want LoginResp", typ)
	}
	var resp util.LoginResp
	_ = json.Unmarshal(payload, &resp)
	if resp.Code == 0 {
		t.Fatalf("expected non-zero code on bad psk, got %+v", resp)
	}

	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("handleVPNLink 应当在写完 LoginResp 后立即返回")
	}
}

// resetServerGlobals 在测试间清掉可能被前一次测试污染的包级 map / context。
//
// handleVPNLink 会写到 connections / connIDMap，本测试用不到 demux 但希望干净起步。
func resetServerGlobals(t *testing.T) {
	t.Helper()

	connectionsMu.Lock()
	connections = make(map[uint32]*Connection)
	connectionsMu.Unlock()

	connIDMapMu.Lock()
	connIDMap = make(map[string]*Connection)
	connIDMapMu.Unlock()

	clientIPUsedMu.Lock()
	clientIPUsed = make(map[string]bool)
	clientIPUsedMu.Unlock()

	// PoW 全局状态:跨测试清空。
	// 三层:
	//   - lazyPoWFallback (sync.Mutex + nil-reset): 上一测试构造的 PoWService 含
	//     ipFailures 累积 + hmacKey 让 challenge replay map 跨测试串台,必须清;
	//   - globalPoWIPLimiter (per-IP 出题速率): net.Pipe 所有测试共享 host="pipe",
	//     burst=10 用满后限速 → 后续测试 false-positive;
	//   - globalPoWIssueLimiter (全局 1000/s): 测试集小,实际不易触顶,但顺手重建。
	resetLazyPoWForTest()
	globalPoWIPLimiter.ResetForTest()
	ResetGlobalPoWIssueLimiterForTest()

	// 给 globalContext 一个干净的根；handleVPNLink 用到时会自己回退到 Background()，
	// 但显式赋值避免不同测试之间 cancel 信号串台。
	prevCancel := globalContextCancel
	globalContext, globalContextCancel = context.WithCancel(context.Background())
	t.Cleanup(func() {
		if globalContextCancel != nil {
			globalContextCancel()
		}
		if prevCancel != nil {
			prevCancel()
		}
	})
}

// runClientPoWHandshake 在 net.Pipe 测试中扮演客户端,完整跑一遍 PoW 帧序列:
//  1. 发 LinkTypePoWChallengeReq(空 body);
//  2. 读 LinkTypePoWChallenge,解出 nonce;
//  3. 把题目元数据 + nonce 拼成 LoginReqPoW 返回(调用方填进 LoginReq.Pow)。
//
// 难度由 server 决定(由 gw.powService.ComputeDifficulty 算),测试场景下默认
// failures_enable=0 → base_difficulty=8,客户端 ~5ms 内解出。
func runClientPoWHandshake(t *testing.T, clientEnd net.Conn) util.LoginReqPoW {
	t.Helper()
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypePoWChallengeReq, nil, 2*time.Second); err != nil {
		t.Fatalf("write PoWChallengeReq: %v", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if err != nil {
		t.Fatalf("read PoWChallenge: %v", err)
	}
	if typ != util.LinkTypePoWChallenge {
		t.Fatalf("typ=%d want LinkTypePoWChallenge", typ)
	}
	ch, errP := util.ParseLinkPoWChallengePayload(payload)
	if errP != nil {
		t.Fatalf("ParseLinkPoWChallengePayload: %v", errP)
	}
	saltBytes, errS := base64StdDecode(ch.Salt)
	if errS != nil || len(saltBytes) != powSaltBytes {
		t.Fatalf("salt decode: %v (%d bytes)", errS, len(saltBytes))
	}
	// 复用 server.go 的 powHash / powVerify(同包),所以这里直接调内部函数解 nonce。
	var nonce uint64
	for ; nonce < (1 << 32); nonce++ {
		if powVerify(ch.ChallengeID, saltBytes, ch.Difficulty, nonce) {
			break
		}
	}
	return util.LoginReqPoW{
		ChallengeID: ch.ChallengeID,
		Salt:        ch.Salt,
		Difficulty:  ch.Difficulty,
		ExpiresAt:   ch.ExpiresAt,
		Signature:   ch.Signature,
		Nonce:       nonce,
	}
}

// base64StdDecode 是 server 测试用的 std base64 解码 wrapper。
func base64StdDecode(s string) ([]byte, error) {
	return testB64Std.DecodeString(s)
}

// marshalLoginReqWithPoW 测试 helper:把 LoginReqPoW 注入 LoginReq.Pow 字段后 marshal。
//
// 用法:先 runClientPoWHandshake 拿到 pow,再调本函数;不用 util.MarshalLoginReqWithDeviceJSON,
// 因为那个公开 helper 没暴露 Pow 字段(也不应该在生产路径上暴露,client 端构造 LoginReq 时
// 自己组装 Pow)。
func marshalLoginReqWithPoW(
	name, token, typ, platform, transport, deviceUUID, deviceName string,
	pow util.LoginReqPoW,
) ([]byte, error) {
	req := util.LoginReq{
		Name:       name,
		Token:      token,
		Type:       typ,
		Platform:   platform,
		Transport:  transport,
		DeviceUUID: deviceUUID,
		DeviceName: deviceName,
		Pow:        pow,
	}
	return json.Marshal(req)
}

// 把读写帧的超时操作包成 helper，避免 net.Pipe 的同步特性让测试卡住。
func writeLinkFrameWithDeadline(c net.Conn, typ byte, payload []byte, d time.Duration) error {
	if err := c.SetWriteDeadline(time.Now().Add(d)); err != nil && !errors.Is(err, errDeadlineUnsupported) {
		return err
	}
	defer func() { _ = c.SetWriteDeadline(time.Time{}) }()
	return util.WriteLinkFrame(c, typ, payload)
}

func readLinkFrameWithDeadline(c net.Conn, d time.Duration) (byte, []byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil && !errors.Is(err, errDeadlineUnsupported) {
		return 0, nil, err
	}
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	return util.ReadLinkFrame(c)
}

// errDeadlineUnsupported：某些 conn（很老的 net.Pipe 实现）不支持 deadline，
// 我们显式忽略这类错误。Go 1.10+ 的 net.Pipe 已支持，但保留兼容。
var errDeadlineUnsupported = errors.New("deadline unsupported (ignored)")

func itoaInt64(n int64) string {
	if n == 0 {
		return "0"
	}
	out := []byte{}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	if neg {
		out = append([]byte{'-'}, out...)
	}
	return string(out)
}
