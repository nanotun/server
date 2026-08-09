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
// P2-13(2026-05-22)曾把本测试改成断言「绑定数值最小的端口」——那是迁就当时
// `PrimaryPortFromUDPListenAddr` 内部 `hyutils.ParsePortUnion` 会排序的实现,
// 而文档与配置注释一直承诺「listen 串里写在最前的那个就是 primary」。
// 2026-07-25 已把实现改回按书写顺序取首个端口(见 util.PrimaryPortFromUDPListenAddr),
// 于是这里断言 gotPort == 写在最前的 a,与端口数值大小无关(也就不会 flaky)。
//
// 端口跳跃的安装从 setupHy2PortHopFn 接缝桩掉:真安装要写 iptables,Linux 上非 root 直接
// `Permission denied (you must be root)`。此前没桩,于是这条在开发机(macOS 不编 iptables 那支)
// 和三机(root)上一直绿,**在 CI runner 上首次实跑就红** —— 而它要验的是「绑哪个端口」,
// 跟规则装不装毫无关系。桩掉比 `Geteuid() != 0 就 Skip` 好:后者会让 runner 上白丢这份覆盖。
// 真安装那条路径由 hysteria_porthop_e2e_linux_test.go 负责(它才该要求 root)。
func TestStartEmbeddedHysteria_PortUnionBindsPrimary(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestHy2ServerTLS(t, dir)
	a := pickFreeUDPPort(t)
	b := pickFreeUDPPort(t)
	for b == a {
		b = pickFreeUDPPort(t)
	}
	// 按「a,b」写入 listen 串:不论 b 是否比 a 小,绑定的都该是写在最前的 a。
	listen := fmt.Sprintf("127.0.0.1:%d,%d", a, b)

	// 顺带把接缝收到的实参也钉住:主端口必须是书写顺序首个,并集必须是整串端口 ——
	// 只看 gotPort 的话,「绑对了但拿错的端口去装 redirect」这种错配是看不见的。
	var gotHopPrimary uint16
	var gotHopUnion string
	prevHop := setupHy2PortHopFn
	setupHy2PortHopFn = func(primary uint16, union, iface string) (func(), error) {
		gotHopPrimary, gotHopUnion = primary, union
		return func() {}, nil
	}
	t.Cleanup(func() { setupHy2PortHopFn = prevHop })

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
	expectedBound, expectedFree := a, b
	if gotPort != expectedBound {
		t.Fatalf("udp port=%d,want 绑定书写顺序首个端口 %d (listen=%s)", gotPort, expectedBound, listen)
	}
	if _, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", expectedFree)); err != nil {
		t.Fatalf("free port %d should remain bindable before redirect: %v", expectedFree, err)
	}
	if gotHopPrimary != uint16(expectedBound) {
		t.Errorf("装 redirect 用的主端口=%d,want %d —— 绑一个端口却把另一个装成 redirect 目标,入包会被打到没人听的端口上", gotHopPrimary, expectedBound)
	}
	if want := fmt.Sprintf("%d,%d", a, b); gotHopUnion != want {
		t.Errorf("装 redirect 用的端口并集=%q,want %q", gotHopUnion, want)
	}
	go func() { _ = hySrv.Serve() }()
	time.Sleep(100 * time.Millisecond)
}

// TestStartEmbeddedHysteria_SweepsOrphanRulesWhenNotHopping 复现并锁死一个线上残留缺口:
//
// 把 listen_addr 从 ":443,20000-20010" 改回 ":443" 再 systemctl restart 后,旧的
// `nanotun_hy2_porthop` REDIRECT 规则一直躺在 PREROUTING —— 因为 setup 路径里那次「装之前先
// sweep」只在「本次也装跳跃」时才跑,撤掉范围后 setup 整个不被调用,残留没人认领。修复是在
// 「本次不装跳跃」的两条路(hy2 关掉 / 还开着但只监听单口)上都主动收一次残留。
//
// 三个子用例分别钉死:装跳跃只走 setup、不误扫;单口只 sweep、不装规则;hy2 关掉仍 sweep。
// 跳跃安装 / 残留清理都从接缝(setupHy2PortHopFn / sweepHy2PortHopFn)桩掉:真动作要写 iptables,
// 非 root / 非 Linux 上不可用,这里只验「哪条路被走了」。
func TestStartEmbeddedHysteria_SweepsOrphanRulesWhenNotHopping(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeTestHy2ServerTLS(t, dir)

	stubSeams := func(t *testing.T) (setupCalls, sweepCalls *int) {
		t.Helper()
		var sc, wc int
		prevSetup, prevSweep := setupHy2PortHopFn, sweepHy2PortHopFn
		setupHy2PortHopFn = func(uint16, string, string) (func(), error) { sc++; return func() {}, nil }
		sweepHy2PortHopFn = func() int { wc++; return 2 }
		t.Cleanup(func() { setupHy2PortHopFn, sweepHy2PortHopFn = prevSetup, prevSweep })
		return &sc, &wc
	}

	t.Run("装跳跃:只走 setup、不误扫残留", func(t *testing.T) {
		setupCalls, sweepCalls := stubSeams(t)
		a := pickFreeUDPPort(t)
		b := pickFreeUDPPort(t)
		for b == a {
			b = pickFreeUDPPort(t)
		}
		cfg := testHysteriaConfig(t, fmt.Sprintf("127.0.0.1:%d,%d", a, b), "hop-pw", cert, key)
		hySrv, _, hopCleanup, err := startEmbeddedHysteria(&cfg, ":0", "ws://127.0.0.1:9/", nil, nil)
		if err != nil {
			t.Fatalf("startEmbeddedHysteria: %v", err)
		}
		if hopCleanup != nil {
			defer hopCleanup()
		}
		if hySrv != nil {
			defer hySrv.Close()
		}
		if *setupCalls != 1 {
			t.Errorf("端口并集应装一次跳跃,setupHy2PortHopFn 实际被调用 %d 次(想要 1)", *setupCalls)
		}
		if *sweepCalls != 0 {
			t.Errorf("装跳跃这条路不该再走孤儿 sweep(setup 内部自带 sweep),却调用 %d 次", *sweepCalls)
		}
	})

	t.Run("hy2 开着但单口:只 sweep 残留、不装规则", func(t *testing.T) {
		setupCalls, sweepCalls := stubSeams(t)
		port := pickFreeUDPPort(t)
		cfg := testHysteriaConfig(t, fmt.Sprintf("127.0.0.1:%d", port), "single-port-pw", cert, key)
		hySrv, _, hopCleanup, err := startEmbeddedHysteria(&cfg, ":0", "ws://127.0.0.1:9/", nil, nil)
		if err != nil {
			t.Fatalf("startEmbeddedHysteria: %v", err)
		}
		if hopCleanup != nil {
			defer hopCleanup()
		}
		if hySrv != nil {
			defer hySrv.Close()
		}
		if *setupCalls != 0 {
			t.Errorf("单口不该装跳跃规则,setupHy2PortHopFn 却被调用 %d 次", *setupCalls)
		}
		if *sweepCalls != 1 {
			t.Fatalf("单口应收一次残留,sweepHy2PortHopFn 实际被调用 %d 次(想要 1)—— 撤掉端口范围后残留没人清正是这条", *sweepCalls)
		}
	})

	t.Run("hy2 关掉:仍 sweep 残留、不返回 server", func(t *testing.T) {
		setupCalls, sweepCalls := stubSeams(t)
		// 密码留空 → HysteriaActive()==false,startEmbeddedHysteria 早退但仍要先收残留。
		cfg := testHysteriaConfig(t, "127.0.0.1:0", "", cert, key)
		hySrv, _, hopCleanup, err := startEmbeddedHysteria(&cfg, ":0", "ws://127.0.0.1:9/", nil, nil)
		if err != nil {
			t.Fatalf("startEmbeddedHysteria: %v", err)
		}
		if hopCleanup != nil {
			hopCleanup()
		}
		if hySrv != nil {
			hySrv.Close()
			t.Errorf("hy2 关掉时不该返回 server")
		}
		if *setupCalls != 0 {
			t.Errorf("hy2 关掉不该装跳跃规则,却调用 setup %d 次", *setupCalls)
		}
		if *sweepCalls != 1 {
			t.Fatalf("hy2 关掉应收一次残留,sweep 实际 %d 次(想要 1)", *sweepCalls)
		}
	})
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
