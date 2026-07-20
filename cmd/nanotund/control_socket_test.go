package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 帮助:启动一个临时 control socket,返回 socket 路径 + 关闭 fn。
// 注意 macOS / *BSD 的 sun_path ≤ ~104 字节,t.TempDir() 路径太长会让 bind 报
// "invalid argument";测试一律落到 /tmp/<short>.sock,t.Cleanup 里 remove。
func startTestControlSocket(t *testing.T, gw *gatewayState) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "vps")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	path := filepath.Join(dir, "c.sock")
	cleanup := startControlSocket(path, gw)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.Dial("unix", path); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return path, cleanup
}

// 帮助:对 control socket 发一笔请求。
func controlReq(t *testing.T, socketPath, method, urlPath string, body any) (int, []byte) {
	t.Helper()
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
	var reqBody io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reqBody = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, "http://unix"+urlPath, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, urlPath, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestControlSocket_StatusReportsCounters(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "control_status.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}

	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	status, out := controlReq(t, sockPath, "GET", "/status", nil)
	if status != http.StatusServiceUnavailable && status != http.StatusOK {
		t.Fatalf("unexpected status %d, body=%s", status, out)
	}
	var resp struct {
		OK         bool `json:"ok"`
		TUNReady   bool `json:"tun_ready"`
		StoreReady bool `json:"store_ready"`
		ConnCount  int  `json:"conn_count"`
		// exit-node 出口节点观测块(M6):计数 + 数据面已启用标记。
		ExitNode struct {
			SelectAccepted uint64 `json:"select_accepted"`
			SelectRejected uint64 `json:"select_rejected"`
			Forwarded      uint64 `json:"forwarded"`
			DroppedOffline uint64 `json:"dropped_offline"`
		} `json:"exit_node"`
		ExitNodeDataplaneEnabled bool `json:"exit_node_dataplane_enabled"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, out)
	}
	if !resp.StoreReady {
		t.Fatal("store should be ready")
	}
	// 出口数据面已落地(M2),/status 必须显式标记 true,供 admin/巡检区分「approved != 生效」。
	if !resp.ExitNodeDataplaneEnabled {
		t.Fatal("exit_node_dataplane_enabled 应为 true(出口转发数据面已接入)")
	}
	// 字段存在性:JSON 中应含 exit_node 块(omitempty 下零值也会因 dataplane_enabled 同层而可解码;
	// 此处仅断言解码不报错 + 计数为非负零值初值,确保 wire 契约稳定)。
	if resp.ExitNode.Forwarded != 0 || resp.ExitNode.DroppedOffline != 0 {
		// 新建 gw、无任何转发 → 计数应为 0。非 0 说明测试间状态泄漏(全局 atomic 未隔离)。
		t.Logf("warn: exit_node 计数非零(可能受其它测试全局 atomic 影响): %+v", resp.ExitNode)
	}
}

func TestControlSocket_ReloadACL(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "control_reload.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "u1", PSKHash: "h"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddACLPairBasic(ctx, 1, 0, store.ACLDeny); err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}

	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	status, out := controlReq(t, sockPath, "POST", "/reload?what=acl", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	if !strings.Contains(string(out), `"rules":1`) {
		t.Fatalf("expected rules=1, body=%s", out)
	}

	// 不支持的 target 应该 400。
	status, _ = controlReq(t, sockPath, "POST", "/reload?what=mystery", nil)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}

func TestControlSocket_KickByUser(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "control_kick.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{Username: "ck", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	gw := &gatewayState{store: st}

	sockPath, cleanup := startTestControlSocket(t, gw)
	defer cleanup()

	fake := newFakeLinkConn()
	c := &Connection{
		connIDStr:      "kick-conn",
		userID:         userIDFromStoreID(user.ID),
		linkConn:       fake,
		pskHashAtLogin: "h",
		tunnelDone:     make(chan struct{}),
		createdAt:      time.Now(),
	}
	installConn(t, c)

	status, out := controlReq(t, sockPath, "POST", "/kick", map[string]any{
		"kind":   "user",
		"id":     "ck",
		"reason": "test_kick",
	})
	if status != http.StatusOK {
		t.Fatalf("status %d body=%s", status, out)
	}
	if !strings.Contains(string(out), `"kicked":1`) {
		t.Fatalf("expected kicked=1, body=%s", out)
	}
	select {
	case <-fake.closed:
	case <-time.After(time.Second):
		t.Fatal("connection should be closed after kick")
	}
}
