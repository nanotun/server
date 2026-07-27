package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/certs"
)

// 既有 QR 测试量的都是合成 payload（strings.Repeat 出来的定长串），验的是编码器
// 在给定字节数下的降级行为。这一组反过来：先用真实 CLI 导出最坏情况 profile，
// 再看它到底占多少预算 —— 前者保证「2500 字节能编出码」，后者保证「真实 profile
// 不会悄悄涨到 2500 字节以上」。两者缺一不可。

// writeFixtureConfigQRWorstCase 写一份「二维码最坏情况」server config：
// hy2 mTLS（buildProfileV2 会给每个入口签发独立客户端证书，是 profile 里最大的字段）
// + 可选端口跳跃。单独一份而不复用 writeFixtureConfigWithMTLS，避免动既有断言基线。
func writeFixtureConfigQRWorstCase(t *testing.T, dir, name string, portHop bool) string {
	t.Helper()
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	caCert := filepath.Join(certDir, name+"-ca.pem")
	caKey := filepath.Join(certDir, name+"-ca-key.pem")
	if err := certs.GenerateTestCA(caCert, caKey); err != nil {
		t.Fatal(err)
	}
	hy2Listen := ":443"
	hopLine := ""
	if portHop {
		// 多段并集是真实跳跃部署的写法，导出时经 PortUnionStringFromUDPListenAddr 落成 udp_ports。
		hy2Listen = ":443,8443,20000-50000"
		hopLine = "port_hop_interval_sec = 30\n"
	}
	body := `
[server]
listen_addr = ":8080"

[reality]
listen_addr = ":8443"
dest = "www.microsoft.com:443"
private_key = "` + realityPrivateKeyB64 + `"
server_names = ["www.microsoft.com"]
short_ids = ["abcd1234"]

[hysteria]
listen_addr = "` + hy2Listen + `"
tls_cert_file = "/tmp/cert.pem"
tls_key_file = "/tmp/key.pem"
tls_client_ca_file = "certs/` + name + `-ca.pem"
password = "hello"
report_tls_sni = "vpn.example.com"
report_tls_insecure_hint = true
` + hopLine
	path := filepath.Join(dir, "config-"+name+".toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// exportProfileForQR 走完整 CLI 导出 v2 profile（每个 node 一个入口）。
func exportProfileForQR(t *testing.T, dir, cfg string, nodes ...string) profileSchema {
	t.Helper()
	db := filepath.Join(dir, "qrcap.db")
	if _, err := os.Stat(db); os.IsNotExist(err) {
		if c, _, e := runCLI(t, db, "", "user", "create", "qruser", "--psk", "p"); c != 0 {
			t.Fatalf("create qruser: %s", e)
		}
	}
	args := []string{"profile", "show", "qruser", "--host", "exit.example.com", "--config", cfg}
	for _, n := range nodes {
		args = append(args, "--node", n)
	}
	c, stdout, stderr := runCLI(t, db, "", args...)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s", c, stderr)
	}
	return parseProfileJSON(t, stdout)
}

// requireWorstCaseIngredients 确认最坏情况的成分都在。少了任何一样，容量测试就会
// 静默退化成「量一个小 profile 有没有超」——永远不会红，也就永远没在守东西。
func requireWorstCaseIngredients(t *testing.T, p profileSchema, wantNodes int) {
	t.Helper()
	if len(p.Nodes) != wantNodes {
		t.Fatalf("nodes=%d want %d", len(p.Nodes), wantNodes)
	}
	for i, n := range p.Nodes {
		if n.Hy2 == nil {
			t.Fatalf("node%d 缺 hy2 段", i)
		}
		if !strings.Contains(n.Hy2.Address, ",") {
			t.Fatalf("node%d 端口跳跃未生效: address=%q 应含端口并集", i, n.Hy2.Address)
		}
		if n.Hy2.HopIntervalSec == 0 {
			t.Fatalf("node%d 端口跳跃未生效: hop_interval_sec 为 0", i)
		}
		if n.Hy2.ClientCertPEM == "" || n.Hy2.ClientKeyPEM == "" {
			t.Fatalf("node%d mTLS 未生效: 缺客户端证书", i)
		}
		if n.Reality == nil || n.Reality.PublicKey == "" {
			t.Fatalf("node%d 缺 reality 段", i)
		}
	}
}

// TestProfileQRCapacity_SingleNodeWorstCaseStillFits 是二维码容量的回归闸门。
//
// 单入口 + mTLS + 端口跳跃是「必须还能扫码」的那个场景：多入口早就超预算了
// （见 buildProfileV2 注释），单入口是二维码分发仅存的可用路径。这里既量字节数，
// 也真去编一次码 —— 只比数字的话，编码器自身的容量口径变了不会被发现。
func TestProfileQRCapacity_SingleNodeWorstCaseStillFits(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFixtureConfigQRWorstCase(t, dir, "hop", true)
	p := exportProfileForQR(t, dir, cfg, "1.2.3.4")
	requireWorstCaseIngredients(t, p, 1)

	url, err := profileToURL(&p)
	if err != nil {
		t.Fatalf("profileToURL: %v", err)
	}
	if len(url) > qrLowMaxURLBytes {
		t.Fatalf("单入口最坏情况 profile 已装不进二维码: URL %d 字节 > 上限 %d,"+
			"二维码分发这条路等于断了", len(url), qrLowMaxURLBytes)
	}
	t.Logf("单入口 mTLS + 端口跳跃: URL %d 字节, 余量 %d", len(url), qrLowMaxURLBytes-len(url))

	png := filepath.Join(dir, "worst-case.png")
	if err := writeQRPNG(qrTestOpts(), png, url, false); err != nil {
		t.Fatalf("最坏情况 profile 应能生成二维码 PNG: %v", err)
	}
	var term strings.Builder
	if err := writeQRTerminal(qrTestOpts(), &term, url); err != nil {
		t.Fatalf("最坏情况 profile 应能生成终端二维码: %v", err)
	}
	// qrterminal 编码失败时不报错也不输出，只能靠输出长度识别静默失败。
	if term.Len() < 500 {
		t.Fatalf("终端二维码疑似静默失败, 输出仅 %d 字节", term.Len())
	}
}

// TestProfileQRCapacity_PortHopOverheadPerNode 量端口跳跃在真实 profile 上的字节开销。
//
// 开销本身不大（并集串 + hop_interval_sec），但它吃的是单入口那点余量。哪天并集
// 改成逐端口枚举、或者 hop 参数扩成对象，这里会先红，而不是等用户扫不出码。
func TestProfileQRCapacity_PortHopOverheadPerNode(t *testing.T) {
	dir := t.TempDir()
	plainCfg := writeFixtureConfigQRWorstCase(t, dir, "plain", false)
	hopCfg := writeFixtureConfigQRWorstCase(t, dir, "hop", true)

	plain := exportProfileForQR(t, dir, plainCfg, "1.2.3.4")
	if len(plain.Nodes) != 1 || plain.Nodes[0].Hy2 == nil {
		t.Fatalf("基线 profile 结构异常: %+v", plain.Nodes)
	}
	if plain.Nodes[0].Hy2.HopIntervalSec != 0 || strings.Contains(plain.Nodes[0].Hy2.Address, ",") {
		t.Fatalf("基线不该带跳跃: address=%q hop=%d",
			plain.Nodes[0].Hy2.Address, plain.Nodes[0].Hy2.HopIntervalSec)
	}
	hop := exportProfileForQR(t, dir, hopCfg, "1.2.3.4")
	requireWorstCaseIngredients(t, hop, 1)

	plainURL, err := profileToURL(&plain)
	if err != nil {
		t.Fatalf("profileToURL(plain): %v", err)
	}
	hopURL, err := profileToURL(&hop)
	if err != nil {
		t.Fatalf("profileToURL(hop): %v", err)
	}
	delta := len(hopURL) - len(plainURL)
	t.Logf("端口跳跃开销: %d 字节/节点 (无跳跃 %d → 有跳跃 %d)", delta, len(plainURL), len(hopURL))

	// 上界放宽到 300：每次导出都现签 mTLS 证书，PEM 长度本身有几十字节抖动，
	// 卡太紧会变成随机失败。300 仍能抓住数量级变化。
	const maxHopOverheadBytes = 300
	if delta <= 0 {
		t.Fatalf("端口跳跃应让 profile 变大, 实测 %d 字节 —— 跳跃字段可能根本没导出", delta)
	}
	if delta > maxHopOverheadBytes {
		t.Fatalf("端口跳跃开销 %d 字节/节点, 超过预期上界 %d,"+
			"单入口二维码余量会被吃掉", delta, maxHopOverheadBytes)
	}
}

// TestProfileQRCapacity_MultiNodeOverflowsLoudly 固化「每节点独立 mTLS 证书 →
// 两个入口起就装不进二维码」这个已知取舍（buildProfileV2 注释里写明的代价）。
//
// 重点不是「它超了」，而是超了之后必须明确报错：writeQRTerminal 底下的 qrterminal
// 在编码失败时既不返回 error 也不输出任何字符，admin 只会看到一片空白。
func TestProfileQRCapacity_MultiNodeOverflowsLoudly(t *testing.T) {
	dir := t.TempDir()
	cfg := writeFixtureConfigQRWorstCase(t, dir, "multi", true)
	p := exportProfileForQR(t, dir, cfg, "1.2.3.4", "id=sg,host=5.6.7.8")
	requireWorstCaseIngredients(t, p, 2)

	url, err := profileToURL(&p)
	if err != nil {
		t.Fatalf("profileToURL: %v", err)
	}
	if len(url) <= qrLowMaxURLBytes {
		t.Fatalf("双入口 profile 现在只有 %d 字节, 已能进二维码(上限 %d)——"+
			"容量基线变了, buildProfileV2 注释与本测试都需要更新", len(url), qrLowMaxURLBytes)
	}
	t.Logf("双入口 mTLS + 端口跳跃: URL %d 字节, 超出上限 %d", len(url), len(url)-qrLowMaxURLBytes)

	if err := writeQRPNG(qrTestOpts(), filepath.Join(dir, "multi.png"), url, false); err == nil {
		t.Fatal("双入口超容量时 writeQRPNG 应报错")
	} else if !strings.Contains(err.Error(), "URL length") {
		t.Fatalf("错误应点明 URL 长度, 实际: %v", err)
	}
	var term strings.Builder
	if err := writeQRTerminal(qrTestOpts(), &term, url); err == nil {
		t.Fatal("双入口超容量时 writeQRTerminal 应报错而非静默输出空白")
	} else if !strings.Contains(err.Error(), "URL length") {
		t.Fatalf("错误应点明 URL 长度, 实际: %v", err)
	}

	// 端到端：admin 真敲 --format qr-png 时要拿到非零退出 + 可读的原因。
	db := filepath.Join(dir, "qrcap.db")
	c, _, stderr := runCLI(t, db, "",
		"profile", "show", "qruser",
		"--host", "exit.example.com",
		"--config", cfg,
		"--node", "1.2.3.4",
		"--node", "id=sg,host=5.6.7.8",
		"--format", "qr-png",
		"--output", filepath.Join(dir, "cli-multi.png"),
	)
	if c == 0 {
		t.Fatal("CLI 导出超容量二维码应非零退出")
	}
	if !strings.Contains(stderr, "URL 长度") {
		t.Fatalf("CLI 错误应点明 URL 长度, 实际: %s", stderr)
	}
}
