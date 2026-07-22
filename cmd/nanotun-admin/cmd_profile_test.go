package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/nanotun/server/certs"
	"github.com/nanotun/server/config"
)

// realityPrivateKeyB64 与 nanotun/config/reality_test.go 同向量，确保跨包协议一致。
const realityPrivateKeyB64 = "2pagi_xOuxmKJQNLl8lQ_Hh8kj7Nt8VUlV_lzGLk5Bg"

// G3 regression:openProfileOutput 返回的 closer 必须在 Close 前 fsync,否则
// 掉电后用户拿到 0 字节 profile。这里通过断言写入后内容确实在磁盘可读来覆盖
// 主要语义(syscall.Fsync 本身无法 unit-test mock,但 close+reopen 后内容
// 完整即说明 closer 行为正确)。
func TestOpenProfileOutput_SyncsBeforeClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")

	w, closer, err := openProfileOutput(path, nil, false)
	if err != nil {
		t.Fatalf("openProfileOutput: %v", err)
	}
	const payload = `{"k":"v"}`
	if _, err := w.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	closer()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("payload mismatch: got=%q want=%q", got, payload)
	}

	// 也验证空路径走 fallback 分支不 panic。
	var fallback strings.Builder
	w2, closer2, err := openProfileOutput("", &fallback, false)
	if err != nil {
		t.Fatalf("fallback path: %v", err)
	}
	_, _ = w2.Write([]byte("x"))
	closer2()
	if fallback.String() != "x" {
		t.Fatalf("fallback content = %q", fallback.String())
	}
}

// writeFixtureConfig 写一份最小可用的 nanotun server config.toml；只填 profile 关心的字段。
//
// 默认 fixture 不带 [server] 段的 tls_cert_file，方便老测试断言 gateway_tls 不被默认写入；
// 需要带 TLS / ws path 的测试请用 [`writeFixtureConfigWithGateway`]。
func writeFixtureConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	body := `
[server]
listen_addr = ":8080"

[reality]
listen_addr = ":8443"
dest = "www.microsoft.com:443"
private_key = "` + realityPrivateKeyB64 + `"
server_names = ["www.microsoft.com", "fallback.example.com"]
short_ids = ["abcd1234", "ee"]

[hysteria]
listen_addr = ":443"
tls_cert_file = "/tmp/cert.pem"
tls_key_file = "/tmp/key.pem"
password = "hello"
report_tls_sni = "vpn.example.com"
report_tls_insecure_hint = true
mtu = 1280
quic_max_idle_timeout_sec = 15
obfs_salamander_password = "salt-test-1234"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture config: %v", err)
	}
	return path
}

func writeFixtureConfigPortHop(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	body := `
[server]
listen_addr = ":8080"

[hysteria]
listen_addr = ":443,8443,5000-5100"
port_hop_interval_sec = 30
tls_cert_file = "/tmp/cert.pem"
tls_key_file = "/tmp/key.pem"
password = "hello"
report_tls_insecure_hint = true
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture config: %v", err)
	}
	return path
}

// parseProfileJSON 把 profile show --format json 的 stdout 解为 profileSchema；
// stdout 形如 `{...}\n`（json.Encoder.Encode 带尾换行）。
func parseProfileJSON(t *testing.T, stdout string) profileSchema {
	t.Helper()
	var p profileSchema
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &p); err != nil {
		t.Fatalf("parse profile json: %v\n%s", err, stdout)
	}
	return p
}

func TestDeriveRealityPublicKey_MatchesCurve25519(t *testing.T) {
	priv := bytesRepeat32(0x09)
	pub, err := DeriveRealityPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 32 {
		t.Fatalf("public key len=%d, want 32", len(pub))
	}
	want, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(pub, want) {
		t.Fatalf("public key mismatch\n got %x\nwant %x", pub, want)
	}

	// 跨包一致性：与 config.DecodeRealityPrivateKey 同一私钥 → derive 一次，重复 derive 应稳定。
	priv2, err := decodeBase64Any(realityPrivateKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	pub2a, _ := DeriveRealityPublicKey(priv2)
	pub2b, _ := DeriveRealityPublicKey(priv2)
	if !bytesEqual(pub2a, pub2b) {
		t.Fatalf("derive not deterministic")
	}
}

func TestDeriveRealityPublicKey_RejectsBadLength(t *testing.T) {
	if _, err := DeriveRealityPublicKey(make([]byte, 31)); err == nil {
		t.Fatalf("expected error for 31-byte key")
	}
	if _, err := DeriveRealityPublicKey(nil); err == nil {
		t.Fatalf("expected error for nil key")
	}
}

func TestProfileShow_V2MultiNode(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v2.db")
	cfg := writeFixtureConfig(t, dir)
	const knownPSK = "v2-multi-psk"
	if c, _, e := runCLI(t, db, "", "user", "create", "bob", "--psk", knownPSK); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "bob",
		"--host", "exit.example.com",
		"--config", cfg,
		"--node", "1.2.3.4",
		"--node", "id=sg,name=新加坡,host=5.6.7.8",
	)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s stdout=%s", c, stderr, stdout)
	}
	p := parseProfileJSON(t, stdout)
	if p.Version != profileSchemaVersionV2 {
		t.Fatalf("version=%d want %d", p.Version, profileSchemaVersionV2)
	}
	if p.Host != "exit.example.com" {
		t.Fatalf("exit host=%q", p.Host)
	}
	if len(p.Nodes) != 2 {
		t.Fatalf("nodes len=%d", len(p.Nodes))
	}
	// v2 完全不共享：节点级带完整 reality / hy2 字段（含独立 cert/key），顶层不再放公共默认。
	if p.Reality != nil || p.Hy2 != nil {
		t.Fatalf("v2 (no-share) should NOT have top-level reality/hy2; got reality=%v hy2=%v", p.Reality, p.Hy2)
	}
	if p.Nodes[0].Hy2 == nil || p.Nodes[0].Hy2.Address != "1.2.3.4:443" {
		t.Fatalf("node0 hy2 address=%v", p.Nodes[0].Hy2)
	}
	if p.Nodes[0].Hy2.Auth == "" {
		t.Fatalf("node-level hy2 should carry full fields: %+v", p.Nodes[0].Hy2)
	}
	if p.Nodes[1].ID != "sg" || p.Nodes[1].Name != "新加坡" {
		t.Fatalf("node1 id/name=%q/%q", p.Nodes[1].ID, p.Nodes[1].Name)
	}
	if p.Nodes[1].Reality == nil || p.Nodes[1].Reality.Address != "5.6.7.8:8443" {
		t.Fatalf("node1 reality address=%v", p.Nodes[1].Reality)
	}
	if p.Nodes[1].Reality.PublicKey == "" || p.Nodes[1].Reality.ServerName == "" {
		t.Fatalf("node-level reality should carry full fields: %+v", p.Nodes[1].Reality)
	}
	url, err := profileToURL(&p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, profileURLPrefixV2) {
		t.Fatalf("url prefix=%q", url[:min(24, len(url))])
	}
}

func TestProfileShowExportsHy2PortHop(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "test.db")
	cfg := writeFixtureConfigPortHop(t, dir)
	const knownPSK = "hop-psk-test"
	if c, _, e := runCLI(t, db, "", "user", "create", "hopuser", "--psk", knownPSK); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "hopuser",
		"--host", "vpn.example.com",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s stdout=%s", c, stderr, stdout)
	}
	p := parseProfileJSON(t, stdout)
	if p.Hy2 == nil {
		t.Fatal("hy2 missing")
	}
	if p.Hy2.UDPPort != 443 {
		t.Fatalf("udp_port=%d", p.Hy2.UDPPort)
	}
	if p.Hy2.UDPPorts != "443,8443,5000-5100" {
		t.Fatalf("udp_ports=%q", p.Hy2.UDPPorts)
	}
	if p.Hy2.HopIntervalSec != 30 {
		t.Fatalf("hop_interval_sec=%d", p.Hy2.HopIntervalSec)
	}
}

func TestPortFromListenAddr(t *testing.T) {
	cases := map[string]uint16{
		"":                0,
		":443":            443,
		"0.0.0.0:8443":    8443,
		"[::]:8444":       8444,
		"vpn.example:80":  80,
		"127.0.0.1:65535": 65535,
		":0":              0, // 0 端口被视为「无效/未配」
		":notanumber":     0,
		"no-colon":        0,
	}
	for in, want := range cases {
		if got := portFromListenAddr(in); got != want {
			t.Errorf("portFromListenAddr(%q)=%d want %d", in, got, want)
		}
	}
}

// TestProfileShow_BasicJSON 走 happy path：建用户、写 config、用 --psk + --host 输出 JSON
// profile，断言 JSON 字段、reality 公钥与私钥派生一致、hy2 段端口/auth 来自 config。
func TestProfileShow_BasicJSON(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)

	const knownPSK = "alpha-bravo-charlie-delta-echo"
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", knownPSK); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "vpn.example.com",
		"--config", cfg,
		"--name", "primary",
		"--note", "for-mac",
	)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s stdout=%s", c, stderr, stdout)
	}

	p := parseProfileJSON(t, stdout)
	if p.Version != profileSchemaVersion {
		t.Fatalf("version=%d want %d", p.Version, profileSchemaVersion)
	}
	if p.Host != "vpn.example.com" {
		t.Fatalf("host=%s", p.Host)
	}
	// 0013(2026-05-25):username + psk 已剥离到 credentials schema(见 cmd_credentials_test.go)。
	if p.Name != "primary" {
		t.Fatalf("name=%q", p.Name)
	}
	if p.Note != "for-mac" {
		t.Fatalf("note=%q", p.Note)
	}
	if p.GatewayTCPPort != 0 {
		t.Fatalf("default gateway port should be omitted; got %d", p.GatewayTCPPort)
	}
	if p.GatewayTLS != nil || p.GatewayWSPath != "" || p.GatewayTLSSNI != "" || p.GatewayTLSInsecureHint != nil {
		t.Fatalf("默认 client profile 不应含 gateway_*（环回 path 不发给终端），实际 tls=%+v path=%q", p.GatewayTLS, p.GatewayWSPath)
	}

	if p.Reality == nil {
		t.Fatalf("reality section missing")
	}
	if p.Reality.Port != 8443 {
		t.Fatalf("reality.port=%d", p.Reality.Port)
	}
	if p.Reality.ServerName != "www.microsoft.com" {
		t.Fatalf("reality.server_name=%q", p.Reality.ServerName)
	}
	if p.Reality.ShortID != "abcd1234" {
		t.Fatalf("reality.short_id=%q", p.Reality.ShortID)
	}
	if len(p.Reality.ShortIDs) != 2 || p.Reality.ShortIDs[0] != "abcd1234" || p.Reality.ShortIDs[1] != "ee" {
		t.Fatalf("reality.short_ids=%v", p.Reality.ShortIDs)
	}
	if p.Reality.Fingerprint != "chrome" {
		t.Fatalf("reality.fingerprint=%q", p.Reality.Fingerprint)
	}
	if p.Reality.PublicKey == "" {
		t.Fatalf("reality.public_key should be derived from config private_key")
	}
	// 公钥应能 base64 解出 32 字节 + 与从 fixture 私钥计算的派生值一致
	priv, err := decodeBase64Any(realityPrivateKeyB64)
	if err != nil {
		t.Fatalf("decode fixture priv: %v", err)
	}
	wantPub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	gotPub, err := decodeBase64Any(p.Reality.PublicKey)
	if err != nil {
		t.Fatalf("decode profile public_key: %v", err)
	}
	if !bytesEqual(gotPub, wantPub) {
		t.Fatalf("reality public_key mismatch\n got %x\nwant %x", gotPub, wantPub)
	}

	if p.Hy2 == nil {
		t.Fatalf("hy2 section missing")
	}
	if p.Hy2.UDPPort != 443 {
		t.Fatalf("hy2.udp_port=%d", p.Hy2.UDPPort)
	}
	if p.Hy2.Auth != "hello" {
		t.Fatalf("hy2.auth=%q", p.Hy2.Auth)
	}
	if p.Hy2.TLSSNI != "vpn.example.com" {
		t.Fatalf("hy2.tls_sni=%q", p.Hy2.TLSSNI)
	}
	if p.Hy2.TLSInsecureHint == nil || *p.Hy2.TLSInsecureHint != true {
		t.Fatalf("hy2.tls_insecure_hint should default true")
	}
	if p.Hy2.ObfsType != "salamander" {
		t.Fatalf("hy2.obfs_type=%q", p.Hy2.ObfsType)
	}
	if p.Hy2.ObfsSalamanderPassword != "salt-test-1234" {
		t.Fatalf("hy2.obfs_password=%q", p.Hy2.ObfsSalamanderPassword)
	}
	if p.Hy2.MTU != 1280 {
		t.Fatalf("hy2.mtu=%d", p.Hy2.MTU)
	}
	if p.Hy2.QUICMaxIdleTimeoutSec != 15 {
		t.Fatalf("hy2.quic_max_idle_timeout_sec=%d", p.Hy2.QUICMaxIdleTimeoutSec)
	}
}

// TestProfileShow_FormatURL 验证 url 格式：nanotun://v1?d=<base64-rawurl>，反解后等同 JSON。
func TestProfileShow_FormatURL(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "vpn.example.com",
		"--config", cfg,
		"--format", "url",
	)
	if c != 0 {
		t.Fatalf("profile show url failed")
	}
	line := strings.TrimSpace(stdout)
	if !strings.HasPrefix(line, profileURLPrefix) {
		t.Fatalf("missing url prefix: %q", line)
	}
	payload := strings.TrimPrefix(line, profileURLPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode rawurl: %v", err)
	}
	var p profileSchema
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("payload not json: %v\n%s", err, raw)
	}
	// 0013(2026-05-25):username/psk 已剥离;校验 host 即可证明 URL roundtrip 工作正常。
	if p.Host != "vpn.example.com" {
		t.Fatalf("url-decoded profile host mismatch: %+v", p)
	}
}

// TestProfileShow_FormatBoth 验证 both 同时打印 pretty json + url。
func TestProfileShow_FormatBoth(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--format", "both",
	)
	if c != 0 {
		t.Fatalf("profile show both failed")
	}
	if !strings.Contains(stdout, "\"host\": \"h\"") {
		t.Fatalf("missing pretty json segment: %s", stdout)
	}
	if !strings.Contains(stdout, profileURLPrefix) {
		t.Fatalf("missing url segment: %s", stdout)
	}
}

// TestProfileShow_FlagValidation:0013(2026-05-25)解耦后 profile show 仅校验
// host 必填 + format 合法;PSK 相关 flag 已移到 credentials show。
func TestProfileShow_FlagValidation(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, _, _ := runCLI(t, db, "",
		"profile", "show", "alice",
	)
	if c == 0 {
		t.Fatalf("missing --host should fail")
	}
	c, _, _ = runCLI(t, db, "",
		"profile", "show", "alice", "--host", "h", "--format", "xml",
	)
	if c == 0 {
		t.Fatalf("--format xml should fail")
	}
}

// TestProfileShow_NoConfig：config 文件不存在时 → warn 但 cmd 不失败；
// reality / hy2 都为 nil（因为没数据），但 profile 主体仍可用。
func TestProfileShow_NoConfig(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", filepath.Join(dir, "missing.toml"),
	)
	if c != 0 {
		t.Fatalf("missing config should warn not fail; code=%d", c)
	}
	if !strings.Contains(stderr, "[warn]") {
		t.Fatalf("expected warn on stderr, got: %s", stderr)
	}
	p := parseProfileJSON(t, stdout)
	if p.Reality != nil {
		t.Fatalf("reality should be nil without config: %+v", p.Reality)
	}
	if p.Hy2 != nil {
		t.Fatalf("hy2 should be nil without config: %+v", p.Hy2)
	}
}

// TestProfileShow_NoSection：--no-reality / --no-hy2 时段被显式去除。
func TestProfileShow_NoSection(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--no-reality",
	)
	if c != 0 {
		t.Fatalf("no-reality failed")
	}
	p := parseProfileJSON(t, stdout)
	if p.Reality != nil {
		t.Fatalf("reality should be nil with --no-reality")
	}
	if p.Hy2 == nil {
		t.Fatalf("hy2 should still exist")
	}

	c, stdout, _ = runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--no-hy2",
	)
	if c != 0 {
		t.Fatalf("no-hy2 failed")
	}
	p = parseProfileJSON(t, stdout)
	if p.Hy2 != nil {
		t.Fatalf("hy2 should be nil with --no-hy2")
	}
	if p.Reality == nil {
		t.Fatalf("reality should still exist")
	}
}

// TestProfileShow_PortOverride：--reality-port / --hy2-udp-port 等覆盖优先于 config。
func TestProfileShow_PortOverride(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--reality-port", "9999",
		"--hy2-udp-port", "53",
		"--gateway-port", "12345",
	)
	if c != 0 {
		t.Fatalf("override failed")
	}
	p := parseProfileJSON(t, stdout)
	if p.GatewayTCPPort != 12345 {
		t.Fatalf("gateway_tcp_port=%d", p.GatewayTCPPort)
	}
	if p.Reality == nil || p.Reality.Port != 9999 {
		t.Fatalf("reality port override missing: %+v", p.Reality)
	}
	if p.Hy2 == nil || p.Hy2.UDPPort != 53 {
		t.Fatalf("hy2 udp port override missing: %+v", p.Hy2)
	}
}

// TestProfileShow_Output：--output 写文件而非 stdout。
func TestProfileShow_OutputFile(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	out := filepath.Join(dir, "alice.profile.json")
	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--output", out,
	)
	if c != 0 {
		t.Fatalf("output to file failed")
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("stdout should be empty when --output is set: %q", stdout)
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	// 0013(2026-05-25):username + psk 已剥离;只断言能解出合法 profile schema
	// (parseProfileJSON 内部 t.Fatalf 失败,这里到达即说明 JSON 合法 + 含 host 等核心字段)。
	p := parseProfileJSON(t, string(body))
	if p.Host == "" {
		t.Fatalf("file profile missing host: %+v", p)
	}
}

// TestProfileShow_GlobalJSONFlag：全局 --json 强制 compact 一行 JSON（脚本管线友好）。
func TestProfileToURL_MatchesWriteURL(t *testing.T) {
	// 0013(2026-05-25):username + psk 已从 profile 剥离,这里 hardcoded JSON 也去掉。
	p := parseProfileJSON(t, `{"version":1,"host":"h"}`)
	url, err := profileToURL(&p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(url, profileURLPrefix) {
		t.Fatalf("prefix: %q", url)
	}
	var buf strings.Builder
	if err := writeURL(&buf, &p); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != url {
		t.Fatalf("writeURL vs profileToURL:\n  %q\n  %q", buf.String(), url)
	}
}

// qrTestOpts 给直接调用 writeQRPNG / writeQRTerminal 的单测提供一个最小 opts。
// lang=en(CLI 默认),stdout/stderr 用 discardable builder,不污染测试输出。
func qrTestOpts() *globalOpts {
	return &globalOpts{lang: langEN, stdout: &strings.Builder{}, stderr: &strings.Builder{}}
}

// TestOpenProfileOutput_RefusesExistingUnlessForce 验证含密 profile 输出默认不覆盖既有文件(O_EXCL),
// 仅 --force 时覆盖。
func TestOpenProfileOutput_RefusesExistingUnlessForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(path, []byte("old-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 默认拒绝覆盖。
	if _, _, err := openProfileOutput(path, nil, false); err == nil {
		t.Fatal("openProfileOutput 应拒绝覆盖已存在文件(默认)")
	}
	// 原文件未被截断。
	if b, _ := os.ReadFile(path); string(b) != "old-secret" {
		t.Fatalf("拒绝覆盖后原文件应保持不变,got %q", b)
	}
	// force 允许覆盖。
	w, closer, err := openProfileOutput(path, nil, true)
	if err != nil {
		t.Fatalf("force 应允许覆盖: %v", err)
	}
	_, _ = w.Write([]byte("new"))
	closer()
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("force 覆盖后应为新内容,got %q", b)
	}
}

// TestWriteFileTight_RefusesExistingUnlessForce 验证 QR-PNG 落盘的原子写默认不覆盖既有文件。
func TestWriteFileTight_RefusesExistingUnlessForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "qr.png")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileTight(path, []byte("new"), 0o600, false); err == nil {
		t.Fatal("writeFileTight 应拒绝覆盖已存在文件(默认)")
	}
	if b, _ := os.ReadFile(path); string(b) != "old" {
		t.Fatalf("拒绝覆盖后原文件应不变,got %q", b)
	}
	if err := writeFileTight(path, []byte("new"), 0o600, true); err != nil {
		t.Fatalf("force 应允许覆盖: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("force 覆盖后应为新内容,got %q", b)
	}
	// 落盘权限仍为 0600。
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o want 0600", st.Mode().Perm())
	}
}

func TestWriteQRPNG_WritesValidPNG(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.png")
	const payload = "nanotun://v1?d=eyJ2ZXJzaW9uIjoxfQ"
	if err := writeQRPNG(qrTestOpts(), path, payload, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8 || string(data[1:4]) != "PNG" {
		t.Fatalf("not a PNG file: %x", data[:min(8, len(data))])
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o want 0600", st.Mode().Perm())
	}
}

// TestWriteQRPNG_LargePayloadFallbacksToLow 验证 v40-M 容量(~2331)装不下时,
// writeQRPNG 自动降级 v40-L(~2953)继续生成。这条线是 server profile QR step-up
// 的核心路径 —— hy2 mTLS 客户端证书 PEM(~900 字节)+ REALITY config + server_id
// 让真实 profile URL 普遍 ~2500 字节。
func TestWriteQRPNG_LargePayloadFallbacksToLow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.png")
	// 构造 2500 字节 URL:nanotun://v2?d= 前缀 + 长 base64url 内容。
	// 用 alphabet 字符避免触碰 byte mode 之外的优化路径。
	payload := "nanotun://v2?d=" + strings.Repeat("AbCd1234_-", 248) // 2500 字符
	if len(payload) <= 2331 || len(payload) > 2900 {
		t.Fatalf("test payload size = %d, want (2331, 2900]", len(payload))
	}
	if err := writeQRPNG(qrTestOpts(), path, payload, false); err != nil {
		t.Fatalf("writeQRPNG large payload failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8 || string(data[1:4]) != "PNG" {
		t.Fatalf("not a PNG file: %x", data[:min(8, len(data))])
	}
}

// TestWriteQRPNG_OverflowReturnsClearError 验证 payload 超过 v40-L 容量时,
// writeQRPNG 返回带「URL 长度」字样的明确错误,而不是 go-qrcode 的模糊
// 「content too long to encode」。
func TestWriteQRPNG_OverflowReturnsClearError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overflow.png")
	payload := "nanotun://v2?d=" + strings.Repeat("A", 3000) // > 2900
	err := writeQRPNG(qrTestOpts(), path, payload, false)
	if err == nil {
		t.Fatalf("expected error for oversized payload")
	}
	if !strings.Contains(err.Error(), "URL length") {
		t.Fatalf("error message should mention URL length, got: %v", err)
	}
}

// TestWriteQRTerminal_LargePayloadDoesNotSilentlyFail 验证 Medium 容量超时,
// 终端二维码不再走 qrterminal 的 silent-fail 路径,而是输出 [warn] 提示 +
// 降级 Low 后正常写出 QR 字符。
func TestWriteQRTerminal_LargePayloadDoesNotSilentlyFail(t *testing.T) {
	payload := "nanotun://v2?d=" + strings.Repeat("AbCd1234_-", 248) // 2500 字符
	if len(payload) <= 2331 || len(payload) > 2900 {
		t.Fatalf("test payload size = %d, want (2331, 2900]", len(payload))
	}
	var buf strings.Builder
	if err := writeQRTerminal(qrTestOpts(), &buf, payload); err != nil {
		t.Fatalf("writeQRTerminal large payload should fallback OK, got: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[warn]") {
		t.Fatalf("expected [warn] fallback notice, output:\n%s", out[:min(500, len(out))])
	}
	// qrterminal 用 \033[40m / \033[47m 之一的 ANSI 背景色块,有内容即非空。
	if len(out) < 500 {
		t.Fatalf("terminal QR output too short, got %d bytes (silent fail?)", len(out))
	}
}

// TestWriteQRTerminal_OverflowReturnsClearError 验证 super-long URL 返回带
// 「URL 长度」字样的明确错误。
func TestWriteQRTerminal_OverflowReturnsClearError(t *testing.T) {
	payload := "nanotun://v2?d=" + strings.Repeat("A", 3000) // > 2900
	var buf strings.Builder
	err := writeQRTerminal(qrTestOpts(), &buf, payload)
	if err == nil {
		t.Fatalf("expected error for oversized payload")
	}
	if !strings.Contains(err.Error(), "URL length") {
		t.Fatalf("error message should mention URL length, got: %v", err)
	}
}

func TestProfileShow_FormatQRPng(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	png := filepath.Join(dir, "alice.png")
	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--format", "qr-png",
		"--output", png,
	)
	if c != 0 {
		t.Fatalf("qr-png failed")
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("qr-png stdout should be empty, got %q", stdout)
	}
	data, err := os.ReadFile(png)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 8 || string(data[1:4]) != "PNG" {
		t.Fatalf("output not png")
	}
}

func TestProfileShow_FormatQR_Terminal(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--format", "qr",
	)
	if c != 0 {
		t.Fatalf("qr failed")
	}
	if !strings.Contains(stdout, "nanotun://") && !strings.Contains(stdout, "█") {
		// qrterminal 用块字符；部分终端主题可能不同，至少应有提示行
		if !strings.Contains(stdout, "手机扫描") {
			t.Fatalf("unexpected qr stdout: %q", stdout)
		}
	}
}

func TestProfileShow_QRPngRequiresOutput(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, _, stderr := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--format", "qr-png",
	)
	if c == 0 {
		t.Fatal("qr-png without --output should fail")
	}
	if !strings.Contains(stderr, "--output") {
		t.Fatalf("stderr=%q", stderr)
	}
}

func TestProfileShow_GlobalJSONFlag(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, stdout, _ := runCLI(t, db, "",
		"--json",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--format", "url", // 应被全局 --json 覆盖
	)
	if c != 0 {
		t.Fatalf("global --json failed")
	}
	if strings.HasPrefix(strings.TrimSpace(stdout), profileURLPrefix) {
		t.Fatalf("global --json should override --format url: %q", stdout)
	}
	if strings.Contains(stdout, "\n  ") {
		t.Fatalf("global --json should be compact (no indent): %q", stdout)
	}
	_ = parseProfileJSON(t, stdout)
}

// writeFixtureConfigWithGateway 写一份带 [server].tls_cert_file / vpn_websocket_path 的 fixture，
// 用来覆盖 gateway_tls / gateway_ws_path 派生路径。
// writeFixtureConfigWithMTLS 写带 [hysteria].tls_client_ca_file 的 fixture，并在 dir/certs 下生成测试 CA。
func writeFixtureConfigWithMTLS(t *testing.T, dir string) string {
	t.Helper()
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	caCertPath := filepath.Join(certDir, "test-client-ca.pem")
	caKeyPath := filepath.Join(certDir, "test-client-ca-key.pem")
	if err := certs.GenerateTestCA(caCertPath, caKeyPath); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config-mtls.toml")
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
listen_addr = ":443"
tls_cert_file = "/tmp/cert.pem"
tls_key_file = "/tmp/key.pem"
tls_client_ca_file = "certs/test-client-ca.pem"
password = "hello"
report_tls_sni = "localhost"
report_tls_insecure_hint = true
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFixtureConfigWithGateway(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config-tls.toml")
	body := `
[server]
listen_addr = ":8080"
vpn_websocket_path = "/internal/nanotun/data-plane/ws/v1/abc-fixture"
tls_cert_file = "/tmp/srv-cert.pem"
tls_key_file  = "/tmp/srv-key.pem"

[reality]
listen_addr = ":8443"
dest = "www.microsoft.com:443"
private_key = "` + realityPrivateKeyB64 + `"
server_names = ["www.microsoft.com"]
short_ids = ["abcd1234"]

[hysteria]
listen_addr = ":443"
tls_cert_file = "/tmp/cert.pem"
tls_key_file = "/tmp/key.pem"
password = "hello"
report_tls_sni = "vpn.example.com"
report_tls_insecure_hint = true
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture-tls config: %v", err)
	}
	return path
}

func TestProfileShow_V2_IssuesUniqueHy2MTLSCertPerNode(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v2-mtls.db")
	cfg := writeFixtureConfigWithMTLS(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "carol", "--psk", "p"); c != 0 {
		t.Fatalf("create carol: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "carol",
		"--host", "exit.example.com",
		"--config", cfg,
		"--node", "1.2.3.4",
		"--node", "id=sg,host=5.6.7.8",
		"--node", "id=hk,host=9.9.9.9",
	)
	if c != 0 {
		t.Fatalf("profile show v2 mtls: code=%d stderr=%s", c, stderr)
	}
	p := parseProfileJSON(t, stdout)
	if len(p.Nodes) != 3 {
		t.Fatalf("nodes=%d", len(p.Nodes))
	}
	// 完全不共享：顶层不放 cert/key，每节点 hy2 独立携带自己的 cert+key。
	if p.Hy2 != nil {
		t.Fatalf("v2 (no-share) should NOT have top-level hy2: %+v", p.Hy2)
	}
	certs := make(map[string]struct{}, len(p.Nodes))
	keys := make(map[string]struct{}, len(p.Nodes))
	for i, n := range p.Nodes {
		if n.Hy2 == nil || n.Hy2.ClientCertPEM == "" || n.Hy2.ClientKeyPEM == "" {
			t.Fatalf("node%d missing per-node mTLS cert/key: %+v", i, n.Hy2)
		}
		if n.Hy2.MTLSRequired == nil || !*n.Hy2.MTLSRequired {
			t.Fatalf("node%d mtls_required not set", i)
		}
		certs[n.Hy2.ClientCertPEM] = struct{}{}
		keys[n.Hy2.ClientKeyPEM] = struct{}{}
	}
	if len(certs) != 3 || len(keys) != 3 {
		t.Fatalf("expected 3 distinct per-node certs/keys, got certs=%d keys=%d", len(certs), len(keys))
	}
}

func TestProfileShow_V2_RejectsDuplicateNodeID(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v2-dup.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "dave", "--psk", "p"); c != 0 {
		t.Fatalf("create dave: %s", e)
	}
	c, _, stderr := runCLI(t, db, "",
		"profile", "show", "dave",
		"--host", "exit.example.com",
		"--config", cfg,
		"--node", "id=hk,host=1.2.3.4",
		"--node", "id=hk,host=5.6.7.8",
	)
	if c == 0 {
		t.Fatal("expected non-zero exit for duplicate node id")
	}
	if !strings.Contains(stderr, "id=\"hk\"") && !strings.Contains(stderr, "id=hk") {
		t.Fatalf("stderr should mention duplicate id, got: %s", stderr)
	}
}

// TestProfileShow_V2_SizeBudget 用 fixture 端口跳跃 + 无 mTLS 配置量出 1/2/3/5 入口的
// JSON 体积与 nanotun:// URL 长度。"做"了优化（顶层共享 + 节点只剩 address）后，
// 节点增量应 < 80 B，3 节点 URL 应能塞进 QR Medium（≤2331 B）。
func TestProfileShow_V2_SizeBudget(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "size.db")
	cfg := writeFixtureConfigPortHop(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "sizer", "--psk", "p"); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	hosts := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
	for _, n := range []int{1, 2, 3, 5} {
		args := []string{
			"profile", "show", "sizer",
			"--host", "exit.example.com",
			"--config", cfg,
		}
		for i := 0; i < n; i++ {
			args = append(args, "--node", "id=line"+strconvItoa(i+1)+",host="+hosts[i])
		}
		c, stdout, stderr := runCLI(t, db, "", args...)
		if c != 0 {
			t.Fatalf("show %d nodes: %s", n, stderr)
		}
		jsonBytes := len(strings.TrimSpace(stdout))
		// URL: nanotun://v2/<base64url(json)>
		// base64 输出长度 ≈ ceil(jsonBytes/3)*4，再加 "nanotun://v2/" 前缀。
		urlBytes := 13 + ((jsonBytes+2)/3)*4
		t.Logf("[size] nodes=%d json=%d B  url≈%d B  (QR Medium 2331 / Low 2953)",
			n, jsonBytes, urlBytes)
		// 回归保护：无 mTLS 5 节点也必须能塞进 QR Medium（2331 B）。
		if urlBytes > 2331 {
			t.Fatalf("nodes=%d URL %d > QR Medium 2331; optimization regressed", n, urlBytes)
		}
	}
}

func strconvItoa(i int) string { return fmt.Sprintf("%d", i) }

// TestProfileShow_V2_SizeBudget_WithMTLS 量化"开 mTLS"的 1/2/3 入口体积。
//
// 现在 v2 走"完全不共享"：每节点独立 Ed25519 证书 → 每节点增量 ~1.8 KB。
// 1 节点能进 QR Medium 2331；2 节点起爆 QR Low 2953，走文件 / 复制粘贴分发。
// 断言只对单节点严格化，多节点仅记录体积供决策。
func TestProfileShow_V2_SizeBudget_WithMTLS(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "size-mtls.db")
	cfg := writeFixtureConfigWithMTLS(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "mtlsizer", "--psk", "p"); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	hosts := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	for _, n := range []int{1, 2, 3} {
		args := []string{
			"profile", "show", "mtlsizer",
			"--host", "exit.example.com",
			"--config", cfg,
		}
		for i := 0; i < n; i++ {
			args = append(args, "--node", "id=line"+strconvItoa(i+1)+",host="+hosts[i])
		}
		c, stdout, stderr := runCLI(t, db, "", args...)
		if c != 0 {
			t.Fatalf("show mTLS %d nodes: %s", n, stderr)
		}
		jsonBytes := len(strings.TrimSpace(stdout))
		urlBytes := 13 + ((jsonBytes+2)/3)*4
		t.Logf("[size-mTLS] nodes=%d json=%d B  url≈%d B  (QR Medium 2331 / Low 2953)",
			n, jsonBytes, urlBytes)
		// 不共享后：1 节点必须进 QR Medium（Ed25519 证书的关键收益）。
		// 2+ 节点+mTLS 不强约束（设计上放弃 QR，走文件分发）。
		if n == 1 && urlBytes > 2331 {
			t.Fatalf("single-node mTLS URL %d > QR Medium 2331; Ed25519 regressed", urlBytes)
		}
	}
	// v1 单节点 + mTLS（无 nodes[]，对照组）。
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "mtlsizer",
		"--host", "exit.example.com",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("show v1 mTLS: %s", stderr)
	}
	jsonBytes := len(strings.TrimSpace(stdout))
	urlBytes := 13 + ((jsonBytes+2)/3)*4
	t.Logf("[size-mTLS] v1 single   json=%d B  url≈%d B", jsonBytes, urlBytes)
}

func TestProfileShow_IssuesHy2ClientCertWhenMTLS(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfigWithMTLS(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "vpn.example.com",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("profile show mtls: stderr=%s", stderr)
	}
	p := parseProfileJSON(t, stdout)
	if p.Hy2 == nil {
		t.Fatal("hy2 missing")
	}
	if p.Hy2.MTLSRequired == nil || !*p.Hy2.MTLSRequired {
		t.Fatalf("mtls_required=%+v", p.Hy2.MTLSRequired)
	}
	if p.Hy2.ClientCertPEM == "" || p.Hy2.ClientKeyPEM == "" {
		t.Fatal("expected issued client cert/key in profile")
	}
	if !strings.Contains(p.Hy2.ClientCertPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("bad cert pem: %q", p.Hy2.ClientCertPEM[:40])
	}
}

func TestProfileShow_GatewayWithTLS_FromConfig(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfigWithGateway(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "vpn.example.com",
		"--config", cfg,
		"--with-gateway",
	)
	if c != 0 {
		t.Fatalf("profile show with TLS config failed")
	}
	p := parseProfileJSON(t, stdout)
	if p.GatewayTLS == nil || *p.GatewayTLS != true {
		t.Fatalf("gateway_tls 应当为 true（cert/key 都非空），实际 %+v", p.GatewayTLS)
	}
	if p.GatewayWSPath != "/internal/nanotun/data-plane/ws/v1/abc-fixture" {
		t.Fatalf("gateway_ws_path=%q", p.GatewayWSPath)
	}
	if p.GatewayTLSInsecureHint == nil || *p.GatewayTLSInsecureHint != true {
		t.Fatalf("auto 模式 + TLS 启用 ⇒ insecure_hint 默认 true；实际 %+v", p.GatewayTLSInsecureHint)
	}
	// 默认端口 8080 应该被省略
	if p.GatewayTCPPort != 0 {
		t.Fatalf("gateway_tcp_port 默认 8080 不应写入，实际 %d", p.GatewayTCPPort)
	}
}

func TestProfileShow_GatewayPlainNoTLSField(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	// 默认 fixture：[server] 仅 listen_addr，无 cert，无 ws path
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("profile show plain failed")
	}
	p := parseProfileJSON(t, stdout)
	if p.GatewayTLS != nil {
		t.Fatalf("plain WS 部署不应写 gateway_tls，实际 %+v", p.GatewayTLS)
	}
	if p.GatewayWSPath != "" {
		t.Fatalf("无 vpn_websocket_path 配置时不应写 gateway_ws_path，实际 %q", p.GatewayWSPath)
	}
	if p.GatewayTLSInsecureHint != nil {
		t.Fatalf("plain WS 不应写 insecure_hint，实际 %+v", p.GatewayTLSInsecureHint)
	}
}

func TestProfileShow_DefaultOmitsGatewayEvenWithTLSConfig(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfigWithGateway(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("profile show failed")
	}
	p := parseProfileJSON(t, stdout)
	if p.GatewayTLS != nil || p.GatewayWSPath != "" || p.GatewayTLSSNI != "" || p.GatewayTLSInsecureHint != nil || p.GatewayTCPPort != 0 {
		t.Fatalf("默认不应写 gateway_*，实际 path=%q tls=%+v", p.GatewayWSPath, p.GatewayTLS)
	}
}

func TestProfileShow_NoGateway(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfigWithGateway(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}
	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--with-gateway",
		"--no-gateway",
	)
	if c != 0 {
		t.Fatalf("--no-gateway failed")
	}
	p := parseProfileJSON(t, stdout)
	if p.GatewayTLS != nil || p.GatewayWSPath != "" || p.GatewayTLSSNI != "" || p.GatewayTLSInsecureHint != nil || p.GatewayTCPPort != 0 {
		t.Fatalf("--no-gateway 时所有 gateway_* 字段都不应写入，实际 %+v", p)
	}
}

func TestProfileShow_GatewayFlagOverrides(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfigWithGateway(t, dir) // 带 TLS 的 fixture
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	// 即使 server 启了 TLS，用户显式 --gateway-tls=false（视作部署时 LB 终止 TLS）
	c, stdout, _ := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "h",
		"--config", cfg,
		"--gateway-tls", "false",
		"--gateway-tls-insecure", "false",
		"--gateway-path", "custom/path",
		"--gateway-tls-sni", "fronted.example.com",
		"--gateway-port", "9090",
	)
	if c != 0 {
		t.Fatalf("flag override failed")
	}
	p := parseProfileJSON(t, stdout)
	if p.GatewayTLS == nil || *p.GatewayTLS != false {
		t.Fatalf("--gateway-tls=false 应胜过 config，实际 %+v", p.GatewayTLS)
	}
	if p.GatewayTLSInsecureHint == nil || *p.GatewayTLSInsecureHint != false {
		t.Fatalf("--gateway-tls-insecure=false 应胜过 auto，实际 %+v", p.GatewayTLSInsecureHint)
	}
	if p.GatewayWSPath != "/custom/path" {
		t.Fatalf("--gateway-path 应被 normalize 加上 /；实际 %q", p.GatewayWSPath)
	}
	if p.GatewayTLSSNI != "fronted.example.com" {
		t.Fatalf("gateway_tls_sni=%q", p.GatewayTLSSNI)
	}
	if p.GatewayTCPPort != 9090 {
		t.Fatalf("gateway_tcp_port=%d", p.GatewayTCPPort)
	}
}

func TestParseGatewayTLSFlag_Table(t *testing.T) {
	tlsCfg := &config.Config{}
	tlsCfg.Server.TLSCertFile = "c.pem"
	tlsCfg.Server.TLSKeyFile = "k.pem"
	plainCfg := &config.Config{}

	cases := []struct {
		name string
		flag string
		cfg  *config.Config
		want *bool // nil = expect nil
		err  bool
	}{
		{"true", "true", nil, ptrBool(true), false},
		{"false", "false", nil, ptrBool(false), false},
		{"auto-with-cert", "auto", tlsCfg, ptrBool(true), false},
		{"auto-without-cert", "auto", plainCfg, nil, false},
		{"auto-no-cfg", "auto", nil, nil, false},
		{"empty", "", tlsCfg, ptrBool(true), false},
		{"bad", "TRUE\n\nyes", tlsCfg, nil, true},
	}
	for _, c := range cases {
		got, err := parseGatewayTLSFlag(c.flag, c.cfg)
		if (err != nil) != c.err {
			t.Errorf("%s: err=%v want err=%v", c.name, err, c.err)
			continue
		}
		if !boolPtrEq(got, c.want) {
			t.Errorf("%s: got=%v want=%v", c.name, derefPtrBool(got), derefPtrBool(c.want))
		}
	}
}

func TestParseGatewayTLSInsecureFlag_Table(t *testing.T) {
	cases := []struct {
		name  string
		flag  string
		gwTLS *bool
		want  *bool
		err   bool
	}{
		{"true", "true", nil, ptrBool(true), false},
		{"false", "false", ptrBool(true), ptrBool(false), false},
		{"auto-tls-on", "auto", ptrBool(true), ptrBool(true), false},
		{"auto-tls-off", "auto", ptrBool(false), nil, false},
		{"auto-tls-nil", "auto", nil, nil, false},
		{"empty-tls-on", "", ptrBool(true), ptrBool(true), false},
		{"bad", "yes", ptrBool(true), nil, true},
	}
	for _, c := range cases {
		got, err := parseGatewayTLSInsecureFlag(c.flag, c.gwTLS)
		if (err != nil) != c.err {
			t.Errorf("%s: err=%v want err=%v", c.name, err, c.err)
			continue
		}
		if !boolPtrEq(got, c.want) {
			t.Errorf("%s: got=%v want=%v", c.name, derefPtrBool(got), derefPtrBool(c.want))
		}
	}
}

// helpers --------------------------------------------------------------------

func bytesRepeat32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ptrBool(v bool) *bool { return &v }

func derefPtrBool(p *bool) string {
	if p == nil {
		return "nil"
	}
	if *p {
		return "true"
	}
	return "false"
}

func boolPtrEq(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// decodeBase64Any 与 config.decodeRealityPrivateKey 行为一致（多种 base64 变体回退）。
// 只在测试里用，避免直接暴露包内函数。
func decodeBase64Any(s string) ([]byte, error) {
	encs := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, e := range encs {
		b, err := e.DecodeString(s)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// =============================================================================
// server_id 字段(2026-05-26 第十一轮 + UUID 引入)
// =============================================================================
//
// 与 credentials.id 对称的「服务器实例永久指纹」。锁住以下不变量:
//   1. profile show 必带 server_id 字段(非空,36 位 UUID,uuid.Parse 通过)
//   2. 同一 db 多次 profile show:server_id 完全一致(永久不变)
//   3. v1 / v2(多节点)路径都有
//   4. nanotun:// URL base64 解码出的 JSON 也含 server_id(wire 透传)

// TestProfileShow_ServerIDPresent:profile show 输出含合法 UUID v4 形式的 server_id。
func TestProfileShow_ServerIDPresent(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "sid.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "sid-test-psk"); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "vpn.example.com",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s", c, stderr)
	}
	p := parseProfileJSON(t, stdout)

	if p.ServerID == "" {
		t.Fatal("profile.server_id 不应为空")
	}
	if len(p.ServerID) != 36 {
		t.Errorf("server_id 长度 %d, 期望 36(标准 UUID)", len(p.ServerID))
	}
	// 大致形状:8-4-4-4-12 hyphen 位置 — 不强校验 version nibble,避免依赖
	// google/uuid 的具体输出格式(UUIDv4 / UUIDv7 都可接受)。
	if strings.Count(p.ServerID, "-") != 4 {
		t.Errorf("server_id %q 不像 UUID(hyphen 数 != 4)", p.ServerID)
	}
}

// TestProfileShow_ServerIDStableAcrossInvocations:同一 db 跑 5 次 profile show,
// server_id 完全一致 —— 这是「永久指纹」语义的核心断言。如果有人重构把
// GetOrInitServerID 换成 SettingsSet UPSERT,这条会 catch 到。
func TestProfileShow_ServerIDStableAcrossInvocations(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "stable.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "bob", "--psk", "stable-psk"); c != 0 {
		t.Fatalf("create user: %s", e)
	}

	var first string
	for i := 0; i < 5; i++ {
		c, stdout, stderr := runCLI(t, db, "",
			"profile", "show", "bob",
			"--host", "vpn.example.com",
			"--config", cfg,
		)
		if c != 0 {
			t.Fatalf("iter %d: code=%d stderr=%s", i, c, stderr)
		}
		p := parseProfileJSON(t, stdout)
		if i == 0 {
			first = p.ServerID
			if first == "" {
				t.Fatal("iter 0: server_id 空")
			}
		} else if p.ServerID != first {
			t.Fatalf("iter %d: server_id 变了 %q → %q(违反永久不变承诺)",
				i, first, p.ServerID)
		}
	}
}

// TestProfileShow_ServerIDOnV2:v2(多节点)路径同样写出 server_id。
func TestProfileShow_ServerIDOnV2(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "v2sid.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "carol", "--psk", "v2sid-psk"); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "carol",
		"--host", "exit.example.com",
		"--config", cfg,
		"--node", "1.2.3.4",
	)
	if c != 0 {
		t.Fatalf("profile show v2: code=%d stderr=%s", c, stderr)
	}
	p := parseProfileJSON(t, stdout)
	if p.Version != profileSchemaVersionV2 {
		t.Fatalf("version=%d want %d", p.Version, profileSchemaVersionV2)
	}
	if p.ServerID == "" {
		t.Fatal("v2 profile 也必须含 server_id")
	}
}

// TestProfileShow_ServerIDInURL:--format url 输出的 nanotun:// 反解后 JSON 也含
// server_id —— wire 透传契约,客户端从 URL parse 后能直接拿到 server_id 字段。
func TestProfileShow_ServerIDInURL(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "urlsid.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "dave", "--psk", "url-psk"); c != 0 {
		t.Fatalf("create user: %s", e)
	}
	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "dave",
		"--host", "vpn.example.com",
		"--config", cfg,
		"--format", "url",
	)
	if c != 0 {
		t.Fatalf("profile show url: code=%d stderr=%s", c, stderr)
	}
	url := strings.TrimSpace(stdout)
	if !strings.HasPrefix(url, profileURLPrefix) {
		t.Fatalf("url prefix not matched: %s", url[:min(40, len(url))])
	}
	payload := strings.TrimPrefix(url, profileURLPrefix)
	body, err := decodeBase64Any(payload)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var p profileSchema
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("json: %v\n%s", err, body)
	}
	if p.ServerID == "" {
		t.Fatal("URL 反解出的 profile.server_id 不应为空")
	}
}

// TestProfileShow_ServerIDPersistsAcrossUsers:同一 DB 给不同用户出 profile,
// server_id 一致(身份是「服务器」级,与 user 无关)。
func TestProfileShow_ServerIDPersistsAcrossUsers(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "multiuser.db")
	cfg := writeFixtureConfig(t, dir)
	for _, u := range []string{"u1", "u2", "u3"} {
		if c, _, e := runCLI(t, db, "", "user", "create", u, "--psk", "multi-"+u); c != 0 {
			t.Fatalf("create %s: %s", u, e)
		}
	}
	var first string
	for _, u := range []string{"u1", "u2", "u3"} {
		c, stdout, stderr := runCLI(t, db, "",
			"profile", "show", u,
			"--host", "vpn.example.com",
			"--config", cfg,
		)
		if c != 0 {
			t.Fatalf("show %s: code=%d stderr=%s", u, c, stderr)
		}
		p := parseProfileJSON(t, stdout)
		if first == "" {
			first = p.ServerID
		}
		if p.ServerID != first {
			t.Errorf("user %s 的 server_id %q 与 %q(u1)不一致 — server_id 应与 user 无关",
				u, p.ServerID, first)
		}
	}
}

// TestProfileShow_ServerLevelNoUsername:2026-05-26·server_id 链路第五轮 P1 修复 —
// CLI 接受省略 `<username>` 位置参,走 server-level 模式(不再 GetUserByUsername)。
//
// 历史问题:nanotun-web 的「服务器配置 QR」按钮 fork CLI 时硬塞 `admin.Username`,
// 假设 web admin 名等于某 VPN user 名;非本部署中**此巧合不成立时整个页面 break**。
// 修复后 web 不传位置参,CLI 用合成 CN "vpnport-server-profile-<rand>"。
//
// 本测试断言两件事:
//  1. `profile show` 无位置参 + 有 --host → 退出码 0,产出 valid JSON 含 server_id;
//  2. 该模式下**不需要**任何 VPN user 行存在(只 create config + 跑命令,users 表空)。
func TestProfileShow_ServerLevelNoUsername(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "noser.db")
	cfg := writeFixtureConfig(t, dir)
	// `profile show` 只读不跑 Migrate,先用 `setting set` 触发一次写 → Migrate
	// + ensureServerID 生效;模拟运维通常流程:先 init,再扫 QR。
	if c, _, e := runCLI(t, db, "", "setting", "set", "setup_completed", "1"); c != 0 {
		t.Fatalf("seed migrate: %s", e)
	}
	// 故意**不**建任何 user — 验证 server-level 模式不依赖 users 行。

	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show",
		"--host", "vpn.example.com",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("server-level profile show 应成功;code=%d stderr=%s stdout=%s", c, stderr, stdout)
	}
	p := parseProfileJSON(t, stdout)
	if p.ServerID == "" {
		t.Fatalf("server-level profile 仍应含 server_id;stdout=%s stderr=%s", stdout, stderr)
	}
	if p.Host != "vpn.example.com" {
		t.Errorf("host = %q, want vpn.example.com", p.Host)
	}
}

// TestProfileShow_LegacyPerUserStillValidates:老的 per-user 模式(传位置参)仍要求
// VPN user 存在 — 这是「行为冻结」回归保护:重构 P1 时不能顺手破坏老 CLI 用户的
// 「显式名字 → 校验存在 → 才生成 cert」习惯。
func TestProfileShow_LegacyPerUserStillValidates(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "leg.db")
	cfg := writeFixtureConfig(t, dir)
	// 触发 Migrate(同上 TestProfileShow_ServerLevelNoUsername 注释),否则
	// users 表不存在会先报 "no such table",混淆「user 不存在」的预期错误。
	if c, _, e := runCLI(t, db, "", "setting", "set", "setup_completed", "1"); c != 0 {
		t.Fatalf("seed migrate: %s", e)
	}

	// 不建任何 user,显式传一个不存在的名字 → 应当 fail。
	c, _, stderr := runCLI(t, db, "",
		"profile", "show", "ghost-user",
		"--host", "h",
		"--config", cfg,
	)
	if c == 0 {
		t.Fatal("传不存在的 username 应失败(per-user 模式校验 user 存在)")
	}
	// 深扫第十二轮 LOW:profile show 的 user 解析改走 notFoundErr,ErrNotFound 统一本地化为
	// "用户不存在:<name>"(此前是 "查询用户 <name>: store: not found" 泄英文)。
	if !strings.Contains(stderr, "用户不存在") {
		t.Errorf("error message 应提示 \"用户不存在\";got: %s", stderr)
	}
}

// TestProfileShow_TwoPositionalArgsRejected:位置参 > 1 时报 usage(防止
// `profile show <user> <extra>` 的拼写错误悄悄通过)。
func TestProfileShow_TwoPositionalArgsRejected(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "two.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "setting", "set", "setup_completed", "1"); c != 0 {
		t.Fatalf("seed migrate: %s", e)
	}

	c, _, stderr := runCLI(t, db, "",
		"profile", "show", "alice", "bob",
		"--host", "h",
		"--config", cfg,
	)
	if c == 0 {
		t.Fatal("两个位置参应报 usage")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("error message 应含 usage hint;got: %s", stderr)
	}
}

// =============================================================================
// 2026-05-26 第六轮拆字段:--dial-host / --advertised-host wire 分拆断言
// =============================================================================
//
// 第十轮扫描发现现有 cmd_profile_test.go 全部用 --host(deprecated alias),
// 没有任何 test 直接验证新 flag 写入 JSON 的 host / advertised_host 是否分别
// 落到正确字段。本组测试覆盖三种入参 + 三种 wire 期望:
//
//   --dial-host D + --advertised-host L → host=D, advertised_host=L
//   --dial-host D 单独                  → host=D, advertised_host 字段缺(omitempty)
//   --host H(deprecated alias)         → host=H, advertised_host 字段缺(不 fallback 到 H)
//
// 关键不变量:advertised_host 必须**仅**来自 --advertised-host,不允许 fallback
// 到 dial 值(否则客户端 UI 副标题会展示 IP,失去 label 语义)。
// 注:cmd_profile_test.go 的 fixture 已经写了 reality / hy2 config,这里不重复。

func TestProfileShow_DialAndAdvertisedHostSplit(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "alice",
		"--dial-host", "203.0.113.10",
		"--advertised-host", "prod-tokyo-1",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s", c, stderr)
	}
	p := parseProfileJSON(t, stdout)
	if p.Host != "203.0.113.10" {
		t.Errorf("host 字段应是 dial(--dial-host),实际 %q", p.Host)
	}
	if p.AdvertisedHost != "prod-tokyo-1" {
		t.Errorf("advertised_host 字段应是 label(--advertised-host),实际 %q", p.AdvertisedHost)
	}
}

func TestProfileShow_DialHostOnly_AdvertisedOmitted(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "alice",
		"--dial-host", "203.0.113.10",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s", c, stderr)
	}
	p := parseProfileJSON(t, stdout)
	if p.Host != "203.0.113.10" {
		t.Errorf("host 字段应是 dial,实际 %q", p.Host)
	}
	if p.AdvertisedHost != "" {
		t.Errorf("advertised_host 应缺失(omitempty),不应 fallback 到 dial — 实际 %q",
			p.AdvertisedHost)
	}
	// 关键不变量:JSON 实际文本里**根本不应出现** advertised_host key
	// (omitempty 在 struct tag 已声明,Marshal 会跳过空字段)。
	if strings.Contains(stdout, "\"advertised_host\"") {
		t.Errorf("空 advertised_host 不应序列化到 JSON wire — stdout 含字段名: %s", stdout)
	}
}

func TestProfileShow_DeprecatedHostFlag_NoAdvertisedFallback(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	if c, _, e := runCLI(t, db, "", "user", "create", "alice", "--psk", "p"); c != 0 {
		t.Fatalf("create alice: %s", e)
	}

	c, stdout, stderr := runCLI(t, db, "",
		"profile", "show", "alice",
		"--host", "203.0.113.10",
		"--config", cfg,
	)
	if c != 0 {
		t.Fatalf("profile show: code=%d stderr=%s", c, stderr)
	}
	p := parseProfileJSON(t, stdout)
	if p.Host != "203.0.113.10" {
		t.Errorf("--host(deprecated alias)应等同 --dial-host 写入 host 字段;实际 %q",
			p.Host)
	}
	// 关键不变量:--host 不应 fallback 到 advertised_host —— 否则升级期 ops 用
	// 老 muscle memory 跑 `profile show --host vpn.example.com`,advertised_host
	// 会自动等于 vpn.example.com,客户端 UI 副标题展示 IP / 域名,失去 label
	// 拆字段的全部意义。
	if p.AdvertisedHost != "" {
		t.Errorf("--host 老 alias 写值不应同时 fallback 到 advertised_host;实际 %q",
			p.AdvertisedHost)
	}
}
