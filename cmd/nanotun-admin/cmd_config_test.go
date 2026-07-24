package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// J4 regression:nanotun-admin config lint。
// 三条契约:
//   - 干净配置 → exit 0
//   - 未知字段 → exit 3,stderr 列出字段名
//   - TOML 语法错 → exit 4

func writeTOML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runConfigLint(t *testing.T, path string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	opts := &globalOpts{stdout: &stdout, stderr: &stderr, lang: langZH}
	code := cmdConfig(opts, []string{"lint", path})
	return code, stdout.String(), stderr.String()
}

func TestConfigLint_ValidConfig_Exit0(t *testing.T) {
	const valid = `
[log]
level = "info"

[server]
listen_addr = "0.0.0.0:443"
`
	code, out, errMsg := runConfigLint(t, writeTOML(t, valid))
	if code != 0 {
		t.Fatalf("有效配置应 exit 0, got %d, stderr=%q", code, errMsg)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("stdout 应含 OK, got %q", out)
	}
}

func TestConfigLint_UnknownField_Exit3(t *testing.T) {
	// 拼错的字段名:lease_gc_idle_day(漏 s)是真实用户出现过的错。
	const typo = `
[server]
listen_addr = "0.0.0.0:443"
lease_gc_idle_day = 30
`
	code, _, errMsg := runConfigLint(t, writeTOML(t, typo))
	if code != 3 {
		t.Fatalf("拼错字段应 exit 3, got %d, stderr=%q", code, errMsg)
	}
	if !strings.Contains(errMsg, "lease_gc_idle_day") {
		t.Errorf("stderr 应点名 lease_gc_idle_day, got %q", errMsg)
	}
}

func TestConfigLint_SyntaxError_Exit4(t *testing.T) {
	// 缺右引号,toml 解析直接失败。
	const broken = `
[server]
listen_addr = "0.0.0.0:443
`
	code, _, errMsg := runConfigLint(t, writeTOML(t, broken))
	if code != 4 {
		t.Fatalf("语法错应 exit 4, got %d, stderr=%q", code, errMsg)
	}
	if !strings.Contains(errMsg, "TOML 解析失败") {
		t.Errorf("stderr 应含解析失败提示, got %q", errMsg)
	}
}

func TestConfigLint_MissingFile_Exit1(t *testing.T) {
	code, _, errMsg := runConfigLint(t, "/nonexistent/path/config.toml")
	if code != 1 {
		t.Fatalf("文件不存在应 exit 1, got %d, stderr=%q", code, errMsg)
	}
}

// e_config_lint:语义非法的配置(字段名都对、值不合法)以前会误报 OK。现应 exit 3。
func TestConfigLint_SemanticInvalid_Exit3(t *testing.T) {
	cases := map[string]string{
		"negative_rate": `
[server]
listen_addr = "0.0.0.0:443"
upload_rate = -1
`,
		"bad_cidr": `
[server]
listen_addr = "0.0.0.0:443"
[tun]
subnets = ["not-a-cidr"]
`,
		"bad_exit_mode": `
[server]
listen_addr = "0.0.0.0:443"
[tun]
exit_mode = "isolat"
`,
		"hy2_out_of_range": `
[server]
listen_addr = "0.0.0.0:443"
[hysteria]
password = "0123456789abcdef01"
tls_cert_file = "/tmp/c.pem"
tls_key_file = "/tmp/k.pem"
mtu = 100
`,
		// 第七轮深扫 MED:以下四条都是启动期 Fatal(ExitConfigSemantic)但 lint 从前漏查的。
		// PoW 难度越界(30 > 上限 22)。
		"pow_difficulty_out_of_range": `
[server]
listen_addr = "0.0.0.0:443"
[server.pow]
base_difficulty = 30
`,
		// PoW 顺序倒置:ramp(8) < base(10),自适应升级失效。
		"pow_order_inverted": `
[server]
listen_addr = "0.0.0.0:443"
[server.pow]
base_difficulty = 10
ramp_difficulty = 8
`,
		// [server] TLS 半配:只填 cert 不填 key,HTTPS/WSS 监听起不来。
		"server_tls_half_set": `
[server]
listen_addr = "0.0.0.0:443"
tls_cert_file = "/tmp/c.pem"
`,
		// jump_host_firewall 开启却空名单 = 全网开放陷阱。
		"jump_host_no_allowed_ips": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
`,
		// 第七轮:jump_host_protected_ports 拼错(proto 写成 "tc")→ runtime 会静默跳过 → 漏保护。
		"jump_host_protected_ports_typo": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["10.0.0.1"]
jump_host_protected_ports = ["tc/8443", "udp/443"]
`,
		// 第十四轮深扫 LOW(为第十三轮 ValidateJumpHostFirewall 逐条 IPv4 校验补 lint 回归):
		// allowed_ips 含非法条目(runtime sanitizeJumpHostIPv4s 会静默丢弃 → 预期跳板机被挡死)。
		"jump_host_allowed_ips_not_ip": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["10.0.0.1", "not-an-ip"]
`,
		// allowed_ips 只支持纯 IPv4:CIDR 不认(runtime 会丢)。
		"jump_host_allowed_ips_cidr": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["10.0.0.0/24"]
`,
		// allowed_ips 只支持 IPv4:IPv6 不认(runtime 会丢)。
		"jump_host_allowed_ips_ipv6": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["fd00::1"]
`,
		// allowed_ips 全空白项 → 有效项为 0,等于只允许 127.0.0.1 → 预期跳板机被挡死。
		"jump_host_allowed_ips_all_blank": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["  ", ""]
`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, errMsg := runConfigLint(t, writeTOML(t, cfg))
			if code != 3 {
				t.Fatalf("语义非法配置应 exit 3, got %d, stderr=%q", code, errMsg)
			}
		})
	}
}

// 第七轮深扫 MED:补齐的三处校验对**合法**配置必须放行(避免误伤把开箱即用的配置卡死)。
// 覆盖:PoW 全配齐且顺序正确 / [server] TLS 成对配 / jump_host_firewall 开启且有名单。
func TestConfigLint_StartupSemantics_ValidPasses(t *testing.T) {
	cases := map[string]string{
		// PoW 显式配齐、区间与顺序都合法。
		"pow_valid_explicit": `
[server]
listen_addr = "0.0.0.0:443"
[server.pow]
failures_enable = 3
base_difficulty = 8
ramp_difficulty = 14
step_per_failure = 2
adaptive_ceiling = 22
ttl_sec = 300
`,
		// PoW 段完全缺省(零值 → 默认),必须通过。
		"pow_all_defaults": `
[server]
listen_addr = "0.0.0.0:443"
[server.pow]
`,
		// [server] TLS 成对配齐。
		"server_tls_pair_set": `
[server]
listen_addr = "0.0.0.0:443"
tls_cert_file = "/tmp/c.pem"
tls_key_file = "/tmp/k.pem"
`,
		// jump_host_firewall 开启且提供名单。
		"jump_host_with_ips": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["10.0.0.1", "10.0.0.2"]
`,
		// 第十四轮深扫 LOW:空白项被容忍(与 runtime skip 空串一致),只要至少留一个合法 IPv4 就放行。
		"jump_host_allowed_ips_blank_tolerated": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["10.0.0.1", "  "]
`,
		// 第十四轮深扫 LOW:firewall 关闭时 allowed_ips 非法也不该拦(死配置不报错,与 protected_ports 同口径)。
		"jump_host_allowed_ips_ignored_when_off": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_allowed_ips = ["not-an-ip"]
`,
		// 第七轮:合法的 protected_ports(单端口 + 范围两种写法)应放行。
		"jump_host_protected_ports_valid": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["10.0.0.1"]
jump_host_protected_ports = ["tcp/8443", "udp/443", "tcp/2000-2100"]
`,
		// 第七轮:firewall 关闭时 protected_ports 被忽略,即使写错也不该拦(死配置不报错)。
		"jump_host_protected_ports_ignored_when_off": `
[server]
listen_addr = "0.0.0.0:443"
jump_host_protected_ports = ["garbage"]
`,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errMsg := runConfigLint(t, writeTOML(t, cfg))
			if code != 0 {
				t.Fatalf("合法配置应 exit 0, got %d, stderr=%q", code, errMsg)
			}
			if !strings.Contains(out, "OK") {
				t.Errorf("stdout 应含 OK, got %q", out)
			}
		})
	}
}
