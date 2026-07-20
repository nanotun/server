package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestStartEmbeddedHysteria_PortUnionBindsPrimary 端口并集时仅 bind「数值最小」端口,
// 另一端在 redirect 装上之前仍可由其它进程占用。
//
// P2-13(2026-05-22): 修历史 flaky。`PrimaryPortFromUDPListenAddr` 内部用
// `hyutils.ParsePortUnion` 解析端口并集,**按数值排序**返回首个端口 —— 与「listen 串里
// 写哪个就是 primary」无关。旧测试用 pickFreeUDPPort 随机抽两个端口,断言 gotPort
// == 第一个写入的(`primary`),50% 概率失败(当 secondary < primary 时)。
//
// 现在两条修正:
//  1. 用 `min(primary, secondary)` 表达正确的 expected,**不**依赖随机端口大小关系;
//  2. 同样把 boundPrimary / freePort 也用对换后的变量名,避免阅读混淆。
func TestStartEmbeddedHysteria_PortUnionBindsPrimary(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestHy2ServerTLS(t, dir)
	a := pickFreeUDPPort(t)
	b := pickFreeUDPPort(t)
	for b == a {
		b = pickFreeUDPPort(t)
	}
	// 仍按「a,b」写入 listen 串,验证不论哪边数值小,绑定的都是数值最小那个。
	listen := fmt.Sprintf("127.0.0.1:%d,%d", a, b)
	cfg := testHysteriaConfig(t, listen, "test-hop-pw", cert, key)

	hySrv, gotPort, hopCleanup, err := startEmbeddedHysteria(&cfg, ":0", "ws://127.0.0.1:9/", nil, nil)
	if err != nil {
		t.Fatalf("startEmbeddedHysteria: %v", err)
	}
	if hopCleanup != nil {
		defer hopCleanup()
	}
	if hySrv == nil {
		t.Fatal("expected hy2 server")
	}
	defer hySrv.Close()
	expectedBound := a
	expectedFree := b
	if b < a {
		expectedBound = b
		expectedFree = a
	}
	if gotPort != expectedBound {
		t.Fatalf("udp port=%d want bound(min) %d (listen=%s)", gotPort, expectedBound, listen)
	}
	if _, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", expectedFree)); err != nil {
		t.Fatalf("free port %d should remain bindable before redirect: %v", expectedFree, err)
	}
	go func() { _ = hySrv.Serve() }()
	time.Sleep(100 * time.Millisecond)
}

func rustCommonDir(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("RUST_VPN_CLIENT_LIB_COMMON_DIR"); v != "" {
		return v
	}
	candidates := []string{
		filepath.Join("..", "..", "rust_vpn_client_lib_common"),
		filepath.Join("..", "rust_vpn_client_lib_common"),
	}
	if _, thisFile, _, ok := runtime.Caller(0); ok {
		serverDir := filepath.Dir(thisFile)
		candidates = append(candidates, filepath.Join(serverDir, "..", "..", "rust_vpn_client_lib_common"))
	}
	for _, p := range candidates {
		if _, err := os.Stat(filepath.Join(p, "Cargo.toml")); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	t.Skip("未找到 rust_vpn_client_lib_common（可设 RUST_VPN_CLIENT_LIB_COMMON_DIR）")
	return ""
}

func runRustHy2Probe(t *testing.T, hy2JSON string) {
	t.Helper()
	dir := rustCommonDir(t)
	cmd := exec.Command("cargo", "run", "--quiet", "--example", "hy2_probe")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "HY2_PROBE_JSON="+hy2JSON)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rust hy2_probe failed: %v\n%s", err, out)
	}
	t.Logf("rust hy2_probe ok:\n%s", out)
}

// TestHy2PortHop_RustProbePrimary 启动嵌入式 hy2 后由 Rust hy2_probe 做 QUIC+H3 认证探测（端到端）。
func TestHy2PortHop_RustProbePrimary(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestHy2ServerTLS(t, dir)
	primary := pickFreeUDPPort(t)
	cfg := testHysteriaConfig(t, fmt.Sprintf("127.0.0.1:%d", primary), "hop-probe-pw", cert, key)

	hySrv, gotPort, hopCleanup, err := startEmbeddedHysteria(&cfg, ":0", "ws://127.0.0.1:9/", nil, nil)
	if err != nil {
		t.Fatalf("startEmbeddedHysteria: %v", err)
	}
	if hopCleanup != nil {
		defer hopCleanup()
	}
	defer hySrv.Close()
	if gotPort != primary {
		t.Fatalf("listen port=%d want %d", gotPort, primary)
	}
	go func() { _ = hySrv.Serve() }()
	time.Sleep(500 * time.Millisecond)

	hy2JSON, _ := json.Marshal(map[string]any{
		"address":           fmt.Sprintf("127.0.0.1:%d", primary),
		"auth":              "hop-probe-pw",
		"tls_sni":           "localhost",
		"tls_insecure_hint": true,
	})
	runRustHy2Probe(t, string(hy2JSON))
}
