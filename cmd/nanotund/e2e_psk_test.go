package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// P1-12: PSK 模式 e2e 集成测试。覆盖以下两条历史「只有人工测过」的回归路径:
//
//   1. PSK 登录走通后,SIGTERM 触发的 broadcastShutdownClose 应当往该客户端
//      写一帧 LinkTypeClose(graceful);
//   2. SIGHUP 触发的 applyConfigReload 走 **真实 TOML 解析**(loadConfig 而非
//      测试 closure),log.level 应当从 info 改成 debug。
//
// 这两条之前各自有 unit test(shutdown_drain_test / reload_test),但都是用
// 假 conn / 假 loader,真正的 server.go 接线没人测过,任何重构都可能让 e2e 链
// 断在「unit test 都过、集成场景失败」这个最差的位置(参考 2026-05-21 事故)。

// TestPSK_LoginShutdownDrain 完整跑一遍「PSK 登录 → broadcastShutdownClose」。
//
// 步骤:
//
//  1. 起内存 store + 预置用户 "alice"/PSK "psk-pw";
//  2. net.Pipe 模拟一条客户端 ↔ server 链接,server 端跑 handleVPNLink;
//  3. 客户端发 LoginReq → 收到 LoginResp(code=0) + ConvSaltMsg;
//  4. **此时连接进入 runLinkTunnel 读循环**(server 端阻塞读),客户端不再读;
//  5. 触发 broadcastShutdownClose(0)→ server 应当写一帧 LinkTypeClose;
//  6. 客户端读出该帧,断言 code=CloseCodeShutdown,reason=ShutdownReason。
func TestPSK_LoginShutdownDrain(t *testing.T) {
	resetServerGlobals(t)

	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "psk_drain.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pskHash, err := auth.HashPSK("psk-pw")
	if err != nil {
		t.Fatalf("HashPSK: %v", err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: pskHash, ExitAllowed: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
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

	// 发 LoginReq(合法 v4 UUID + PoW)
	body, err := marshalLoginReqWithPoW(
		"alice", "psk-pw",
		"client", "darwin", "tcp",
		"11111111-2222-4333-8444-555555555555", "MacBook",
		pow,
	)
	if err != nil {
		t.Fatalf("marshalLoginReqWithPoW: %v", err)
	}
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 2*time.Second); err != nil {
		t.Fatalf("write LoginReq: %v", err)
	}

	// 收 LoginResp
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if err != nil {
		t.Fatalf("read LoginResp: %v", err)
	}
	if typ != util.LinkTypeLoginResp {
		t.Fatalf("typ=%d want LoginResp", typ)
	}
	var resp util.LoginResp
	_ = json.Unmarshal(payload, &resp)
	if resp.Code != 0 {
		t.Fatalf("LoginResp code=%d msg=%q want 0", resp.Code, resp.Message)
	}

	// 收 ConvSaltLite
	typ2, _, err := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if err != nil {
		t.Fatalf("read ConvSaltMsg: %v", err)
	}
	if typ2 != util.LinkTypeConvSaltMsg {
		t.Fatalf("typ2=%d want ConvSaltMsg", typ2)
	}

	// 给 server 端 100ms 把 c 注册进 connIDMap(handleVPNLink 在登录响应之后才走
	// 这一步,然后进 runLinkTunnel 阻塞读)。短轮询比无脑 Sleep 稳。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connIDMapMu.RLock()
		n := len(connIDMap)
		connIDMapMu.RUnlock()
		if n >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	connIDMapMu.RLock()
	if len(connIDMap) == 0 {
		connIDMapMu.RUnlock()
		t.Fatal("server 未把会话注册进 connIDMap,链路握手可能未完成")
	}
	connIDMapMu.RUnlock()

	// 触发 graceful shutdown 广播。drainTimeout=0 立刻返回(不 Sleep)。
	go broadcastShutdownClose(0)

	// 客户端应当收到 LinkTypeClose
	typC, payC, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second)
	if err != nil {
		t.Fatalf("read shutdown Close frame: %v", err)
	}
	if typC != util.LinkTypeClose {
		t.Fatalf("typC=%d want LinkTypeClose", typC)
	}
	msg, err := util.ParseCloseLinkPayload(payC)
	if err != nil {
		t.Fatalf("ParseCloseLinkPayload: %v\n%s", err, payC)
	}
	if msg.Code != CloseCodeShutdown {
		t.Fatalf("Close.Code=%d want %d", msg.Code, CloseCodeShutdown)
	}
	if msg.Reason != ShutdownReason {
		t.Fatalf("Close.Reason=%q want %q", msg.Reason, ShutdownReason)
	}

	// 客户端断开 → server runLinkTunnel 拿到 EOF/ErrClosedPipe 后退出。
	_ = clientEnd.Close()
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("handleVPNLink 未在 client 关闭后 3s 内退出")
	}
}

// TestReload_SIGHUP_FromDiskTOML 验证 applyConfigReload + 真实 loadConfig 路径:
//
//  1. 写出初始 config.toml(log.level = "info");
//  2. 构造 reloadState 指向该文件,跑一次 applyConfigReload(等价于初装时);
//  3. 覆写文件改成 log.level = "debug";
//  4. 再跑 applyConfigReload —— 这次走 **loadConfig** (toml.Unmarshal 真实路径);
//  5. 断言 logrus 全局级别 = debug + rs.cfg.Log.Level == "debug"。
//
// 与 reload_test.go 已有用例的区别:已有的用 closure loader,本测试用真 toml + 真
// 磁盘 I/O,如果 toml 字段 tag / loadConfig 默认值处理出错,本测试会比 reload_test
// 更先发现。
func TestReload_SIGHUP_FromDiskTOML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	const initialTOML = `
[log]
level = "info"

[server]
listen_addr = ":8080"
`
	if err := os.WriteFile(cfgPath, []byte(initialTOML), 0o644); err != nil {
		t.Fatalf("write initial toml: %v", err)
	}

	cur, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig initial: %v", err)
	}
	rs := &reloadState{
		configPath: cfgPath,
		cfg:        &cur,
		jumpFW:     newJumpHostFirewall(false, 8080),
	}

	prevLvl := logrus.GetLevel()
	logrus.SetLevel(logrus.InfoLevel)
	defer logrus.SetLevel(prevLvl)

	// 覆写 toml,改 log.level
	const updatedTOML = `
[log]
level = "debug"

[server]
listen_addr = ":8080"
`
	if err := os.WriteFile(cfgPath, []byte(updatedTOML), 0o644); err != nil {
		t.Fatalf("rewrite toml: %v", err)
	}

	applied, _ := applyConfigReload(rs, loadConfig)
	if !containsString(applied, "log.level") {
		t.Fatalf("applied=%v missing log.level", applied)
	}
	if logrus.GetLevel() != logrus.DebugLevel {
		t.Fatalf("logrus level=%v want debug", logrus.GetLevel())
	}
	if rs.cfg.Log.Level != "debug" {
		t.Fatalf("rs.cfg.Log.Level=%q want debug", rs.cfg.Log.Level)
	}
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
		// 容忍 reload.go 给字段名带 "(...)" 后缀的情况(jumpFW deferred 等),避免脆性
		if strings.HasPrefix(s, want+"(") {
			return true
		}
	}
	return false
}
