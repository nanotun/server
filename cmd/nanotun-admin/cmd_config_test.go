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
