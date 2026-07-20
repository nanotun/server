//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestHy2PortHop_E2E_IptablesRedirect 在 Linux + root/CAP_NET_ADMIN 下验证次端口经 iptables REDIRECT 后 Rust 客户端可握手。
func TestHy2PortHop_E2E_IptablesRedirect(t *testing.T) {
	if os.Getenv("NANOTUN_SKIP_IPTABLES_E2E") == "1" {
		t.Skip("NANOTUN_SKIP_IPTABLES_E2E=1")
	}
	if os.Geteuid() != 0 {
		t.Skip("需要 root 以安装 iptables REDIRECT（sudo go test -run TestHy2PortHop_E2E）")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables 不在 PATH")
	}

	dir := t.TempDir()
	cert, key := writeTestHy2ServerTLS(t, dir)
	primary := pickFreeUDPPort(t)
	secondary := pickFreeUDPPort(t)
	for secondary == primary {
		secondary = pickFreeUDPPort(t)
	}
	listen := fmt.Sprintf("127.0.0.1:%d,%d", primary, secondary)
	cfg := testHysteriaConfig(t, listen, "hop-ipt-pw", cert, key)

	hySrv, gotPort, hopCleanup, err := startEmbeddedHysteria(&cfg, ":0", "ws://127.0.0.1:9/", nil, nil)
	if err != nil {
		t.Fatalf("startEmbeddedHysteria: %v", err)
	}
	if hopCleanup == nil {
		t.Fatal("expected iptables cleanup func for port union")
	}
	defer hopCleanup()
	defer hySrv.Close()
	if gotPort != primary {
		t.Fatalf("port=%d want %d", gotPort, primary)
	}
	go func() { _ = hySrv.Serve() }()
	time.Sleep(200 * time.Millisecond)

	// 仅连次端口（须已 REDIRECT 到 primary）
	hy2 := map[string]any{
		"address":           fmt.Sprintf("127.0.0.1:%d", secondary),
		"auth":              "hop-ipt-pw",
		"tls_sni":           "localhost",
		"tls_insecure_hint": true,
	}
	raw, _ := json.Marshal(hy2)
	runRustHy2Probe(t, string(raw))

	// 多端口 address + 短 hop 间隔（覆盖客户端 port hopping 路径）
	hy2Hop := map[string]any{
		"address":           fmt.Sprintf("127.0.0.1:%d,%d", primary, secondary),
		"auth":              "hop-ipt-pw",
		"tls_sni":           "localhost",
		"tls_insecure_hint": true,
		"hop_interval_sec":  uint64(5),
	}
	raw2, _ := json.Marshal(hy2Hop)
	runRustHy2Probe(t, string(raw2))
}

// TestHy2PortHop_IptablesRulesInstalled 断言 plan 出的规则已写入 nat PREROUTING。
func TestHy2PortHop_IptablesRulesInstalled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root")
	}
	primary := pickFreeUDPPort(t)
	secondary := pickFreeUDPPort(t)
	cleanup, err := setupHy2UDPPortHopRedirect(uint16(primary), fmt.Sprintf("%d,%d", primary, secondary), "")
	if err != nil {
		t.Fatalf("setup redirect: %v", err)
	}
	defer cleanup()

	out, err := exec.Command("iptables", "-t", "nat", "-S", "PREROUTING").CombinedOutput()
	if err != nil {
		t.Fatalf("iptables -S: %v %s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, hy2PortHopIptComment) || !strings.Contains(s, fmt.Sprintf("--dport %d", secondary)) {
		t.Fatalf("missing redirect rule in PREROUTING:\n%s", s)
	}
}
