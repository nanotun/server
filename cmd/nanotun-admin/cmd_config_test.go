package main

import (
	"bytes"
	"fmt"
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

[tun]
subnets = ["10.201.0.0/16"]
`
	code, out, errMsg := runConfigLint(t, writeTOML(t, valid))
	if code != 0 {
		t.Fatalf("有效配置应 exit 0, got %d, stderr=%q", code, errMsg)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("stdout 应含 OK, got %q", out)
	}
}

// TestConfigLint_WarnsAboutUnreadableCerts:证书读不到只警告,不改退出码。
//
// 漏掉这条警告等于给假绿灯 —— 人照着 OK 去 restart,server 因 ExitTLSCert 当场趴下;
// 但判成失败又会堵死「在别的机器上验一份配置模板」这条正当用法(CI 就是这么用的)。
func TestConfigLint_WarnsAboutUnreadableCerts(t *testing.T) {
	const tmpl = `
[server]
listen_addr = "0.0.0.0:443"
tls_cert_file = %q
tls_key_file = %q

[tun]
subnets = ["10.201.0.0/16"]
`
	t.Run("文件不存在时警告但仍 exit 0", func(t *testing.T) {
		path := writeTOML(t, fmt.Sprintf(tmpl, "certs/nope.pem", "certs/nokey.pem"))
		code, out, errMsg := runConfigLint(t, path)
		if code != 0 {
			t.Fatalf("只该警告不该失败,got exit %d", code)
		}
		if !strings.Contains(out, "OK") {
			t.Errorf("stdout 仍应有 OK, got %q", out)
		}
		for _, want := range []string{"nope.pem", "nokey.pem", "exit 20"} {
			if !strings.Contains(errMsg, want) {
				t.Errorf("警告里应提到 %q, got %q", want, errMsg)
			}
		}
	})

	t.Run("文件齐全时一声不吭", func(t *testing.T) {
		dir := t.TempDir()
		for _, n := range []string{"c.pem", "k.pem"} {
			if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		p := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(p, []byte(fmt.Sprintf(tmpl, "c.pem", "k.pem")), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, errMsg := runConfigLint(t, p)
		if code != 0 {
			t.Fatalf("exit %d, stderr=%q", code, errMsg)
		}
		// 相对路径必须按 config.toml 所在目录解析(与 unit 的 WorkingDirectory 同口径),
		// 否则换个 cwd 跑 lint 会把一份好配置全报成缺文件。
		if strings.Contains(errMsg, "警告") {
			t.Errorf("证书都在,不该有警告: %q", errMsg)
		}
	})
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
//
// 每条 fixture 都要带 wantErr —— lintSemantic 是一串顺序 return,只断言 exit 3 会让用例
// 空过:第十六轮加进来的 ValidateTUNSubnets(「subnets 与 subnets6 皆空 → 启动 Fatal」)排在
// pow / TLS / 跳板机三条之前,而这些 fixture 原本都不带 [tun] 段 —— 于是它们全在 subnets
// 那一步就退出了,pow_difficulty_out_of_range 之类根本没验到 pow。下面的 fixture 一律自带
// [tun],并按报错内容钉住「是哪条校验拦下的」。
func TestConfigLint_SemanticInvalid_Exit3(t *testing.T) {
	const validTUN = "\n[tun]\nsubnets = [\"10.201.0.0/16\"]\n"
	cases := map[string]struct {
		cfg string
		// wantErr 是 stderr 里必须出现的片段,用来钉住「拦下它的是哪条校验」。
		wantErr string
	}{
		"negative_rate": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
upload_rate = -1
`, wantErr: "upload_rate"},
		"bad_cidr": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
[tun]
subnets = ["not-a-cidr"]
`, wantErr: "not-a-cidr"},
		"bad_exit_mode": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
[tun]
subnets = ["10.201.0.0/16"]
exit_mode = "isolat"
`, wantErr: "exit_mode"},
		// hy2 三件套只配了 password:runtime 起不了 hy2 监听,而 lint 从前不看。
		"hy2_credentials_half_set": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
[hysteria]
password = "0123456789abcdef01"
`, wantErr: "tls_cert_file"},
		"hy2_out_of_range": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
[hysteria]
password = "0123456789abcdef01"
tls_cert_file = "/tmp/c.pem"
tls_key_file = "/tmp/k.pem"
mtu = 100
`, wantErr: "mtu"},
		// REALITY 启用(listen_addr 非空)但 private_key 缺:握手起不来。
		"reality_missing_key": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
[reality]
listen_addr = ":8443"
dest = "www.microsoft.com:443"
server_names = ["www.microsoft.com"]
`, wantErr: "reality"},
		// exit_dns_redirect 拼错("of"):runtime 会静默回退 auto —— 想关 DNS 接管反而打开了。
		"bad_exit_dns_redirect": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
[tun]
subnets = ["10.201.0.0/16"]
exit_dns_redirect = "of"
`, wantErr: "exit_dns_redirect"},
		"bad_exit_deny_private": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
[tun]
subnets = ["10.201.0.0/16"]
exit_deny_private = "link-loca"
`, wantErr: "exit_deny_private"},
		// subnets 与 subnets6 皆空 → 启动期 Fatal。
		"tun_subnets_all_empty": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
`, wantErr: "subnets"},
		// 第七轮深扫 MED:以下都是启动期 Fatal(ExitConfigSemantic)但 lint 从前漏查的。
		// PoW 难度越界(30 > 上限 22)。
		"pow_difficulty_out_of_range": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
[server.pow]
base_difficulty = 30
`, wantErr: "difficulty"},
		// PoW 顺序倒置:ramp(8) < base(10),自适应升级失效。
		"pow_order_inverted": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
[server.pow]
base_difficulty = 10
ramp_difficulty = 8
`, wantErr: "ramp_difficulty"},
		// [server] TLS 半配:只填 cert 不填 key,HTTPS/WSS 监听起不来。
		"server_tls_half_set": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
tls_cert_file = "/tmp/c.pem"
`, wantErr: "tls_key_file"},
		// jump_host_firewall 开启却空名单 = 全网开放陷阱。
		"jump_host_no_allowed_ips": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
`, wantErr: "jump_host_allowed_ips"},
		// 第七轮:jump_host_protected_ports 拼错(proto 写成 "tc")→ runtime 会静默跳过 → 漏保护。
		"jump_host_protected_ports_typo": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["10.0.0.1"]
jump_host_protected_ports = ["tc/8443", "udp/443"]
`, wantErr: "jump_host_protected_ports"},
		// 第十四轮深扫 LOW(为第十三轮 ValidateJumpHostFirewall 逐条 IPv4 校验补 lint 回归):
		// allowed_ips 含非法条目(runtime sanitizeJumpHostIPv4s 会静默丢弃 → 预期跳板机被挡死)。
		"jump_host_allowed_ips_not_ip": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["10.0.0.1", "not-an-ip"]
`, wantErr: "not-an-ip"},
		// allowed_ips 只支持纯 IPv4:CIDR 不认(runtime 会丢)。
		"jump_host_allowed_ips_cidr": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["10.0.0.0/24"]
`, wantErr: "10.0.0.0/24"},
		// allowed_ips 只支持 IPv4:IPv6 不认(runtime 会丢)。
		"jump_host_allowed_ips_ipv6": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["fd00::1"]
`, wantErr: "fd00::1"},
		// allowed_ips 全空白项 → 有效项为 0,等于只允许 127.0.0.1 → 预期跳板机被挡死。
		"jump_host_allowed_ips_all_blank": {cfg: `
[server]
listen_addr = "0.0.0.0:443"
jump_host_firewall = true
jump_host_allowed_ips = ["  ", ""]
`, wantErr: "jump_host_allowed_ips"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := tc.cfg
			// 除了专门测 subnets 的那条,其余都补一段合法 [tun] —— 否则 ValidateTUNSubnets
			// 会先把它们拦掉,后面几条校验一次都走不到,用例变成空过。
			if !strings.Contains(cfg, "[tun]") && name != "tun_subnets_all_empty" {
				cfg += validTUN
			}
			code, _, errMsg := runConfigLint(t, writeTOML(t, cfg))
			if code != 3 {
				t.Fatalf("语义非法配置应 exit 3, got %d, stderr=%q", code, errMsg)
			}
			if !strings.Contains(errMsg, tc.wantErr) {
				t.Fatalf("报错里没提 %q —— 可能是被别的校验先拦下了,这条其实没验到:\n%s",
					tc.wantErr, errMsg)
			}
		})
	}
}

// config lint 的用法门:参数个数不对时给 usage + exit 2,而不是拿第一个参数硬试。
func TestConfigLint_ArityGuard(t *testing.T) {
	p := writeTOML(t, "[server]\nlisten_addr = \"0.0.0.0:443\"\n[tun]\nsubnets = [\"10.201.0.0/16\"]\n")
	for _, args := range [][]string{
		{"lint"},
		{"lint", p, p},
	} {
		code, _, stderr := func() (int, string, string) {
			var stdout, errb bytes.Buffer
			opts := &globalOpts{stdout: &stdout, stderr: &errb, lang: langZH}
			return cmdConfig(opts, args), stdout.String(), errb.String()
		}()
		if code != 2 {
			t.Errorf("config %v 应 exit 2, got %d", args, code)
		}
		if !strings.Contains(stderr, "config lint") {
			t.Errorf("config %v 没给出 usage: %q", args, stderr)
		}
	}
}

// config 的派发门:不给子命令 / 未知子命令 → exit 2 + usage;help → exit 0。
func TestCmdConfig_Dispatch(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		var stdout, errb bytes.Buffer
		opts := &globalOpts{stdout: &stdout, stderr: &errb, lang: langZH}
		return cmdConfig(opts, args), stdout.String(), errb.String()
	}

	if code, _, stderr := run(); code != 2 || strings.TrimSpace(stderr) == "" {
		t.Errorf("不给子命令: code=%d stderr=%q", code, stderr)
	}
	if code, _, stderr := run("check"); code != 2 {
		t.Errorf("未知子命令: code=%d stderr=%q", code, stderr)
	} else if !strings.Contains(stderr, "check") {
		t.Errorf("未知子命令没回显敲错的那个词: %q", stderr)
	}
	for _, h := range []string{"help", "-h", "--help"} {
		if code, stdout, _ := run(h); code != 0 || strings.TrimSpace(stdout) == "" {
			t.Errorf("config %s: code=%d stdout=%q", h, code, stdout)
		}
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
			// 这些 fixture 只关心 [server] 语义、均不含 [tun];补一段合法 subnets 以满足第十六轮新增的
			// ValidateTUNSubnets(「两者皆空 → 启动 Fatal」),使它们仍是**整体合法**的配置。
			cfg += "\n[tun]\nsubnets = [\"10.201.0.0/16\"]\n"
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
