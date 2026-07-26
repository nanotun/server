package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSettingSet_UnknownKeyWarns:未知 key 仍写入(有意保留的兼容口子),但必须在 stderr
// 吼一声,并列出拼写相近的已知 key。回归实测踩到的正是这条:
// `setting set default_rate_down_bps 1048576` 回报 "written:" 却零效果,真正的 key 是
// rate_default_download_bps。
func TestSettingSet_UnknownKeyWarns(t *testing.T) {
	db := filepath.Join(t.TempDir(), "unknownkey.db")
	if code, _, e := runCLI(t, db, "", "user", "create", "seed", "--psk", "s3cret"); code != 0 {
		t.Fatalf("seed: %s", e)
	}

	code, stdout, stderr := runCLI(t, db, "", "setting", "set", "default_rate_down_bps", "1048576")
	if code != 0 {
		t.Fatalf("未知 key 应仍写入成功(兼容口子): code=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "default_rate_down_bps=1048576") {
		t.Errorf("stdout 应保持 written: 一行不变(脚本解析依赖),得到 %q", stdout)
	}
	warned := strings.Contains(strings.ToUpper(stderr), "WARNING") || strings.Contains(stderr, "警告")
	if !strings.Contains(stderr, "default_rate_down_bps") || !warned {
		t.Errorf("stderr 应有未知 key 告警,得到 %q", stderr)
	}
	if !strings.Contains(stderr, "rate_default_download_bps") {
		t.Errorf("应提示拼写相近的 rate_default_download_bps,得到 %q", stderr)
	}
	// 值确实落库了(告警不等于拒绝)。
	if code, out, _ := runCLI(t, db, "", "setting", "get", "default_rate_down_bps"); code != 0 ||
		!strings.Contains(out, "1048576") {
		t.Errorf("未知 key 应真的写进去: code=%d out=%q", code, out)
	}
}

// TestSettingSet_KnownKeyNoWarn:已知 key 不该被告警骚扰。
func TestSettingSet_KnownKeyNoWarn(t *testing.T) {
	db := filepath.Join(t.TempDir(), "knownkey.db")
	if code, _, e := runCLI(t, db, "", "user", "create", "seed", "--psk", "s3cret"); code != 0 {
		t.Fatalf("seed: %s", e)
	}
	for _, k := range []string{"rate_default_download_bps", "acl_default_action", "advertised_host"} {
		val := map[string]string{
			"rate_default_download_bps": "1048576",
			"acl_default_action":        "allow",
			"advertised_host":           "vpn.example.com",
		}[k]
		code, _, stderr := runCLI(t, db, "", "setting", "set", k, val)
		if code != 0 {
			t.Fatalf("set %s: code=%d stderr=%s", k, code, stderr)
		}
		if strings.Contains(strings.ToUpper(stderr), "WARNING") || strings.Contains(stderr, "警告") {
			t.Errorf("已知 key %s 不该告警,得到 %q", k, stderr)
		}
	}
}

// TestKnownSettingKeysCoversBothTables:两张表里的 key 都得算「已知」,否则系统托管 key
// 被 block 之前会先挨一顿「未知 key」告警,自相矛盾。
func TestKnownSettingKeysCoversBothTables(t *testing.T) {
	known := make(map[string]bool)
	for _, k := range knownSettingKeys() {
		known[k] = true
	}
	for k := range systemManagedSettingKeys {
		if !known[k] {
			t.Errorf("系统托管 key %q 不在已知集合里", k)
		}
	}
	for k := range validatedSettingKeys {
		if !known[k] {
			t.Errorf("已校验 key %q 不在已知集合里", k)
		}
	}
}

// TestSettingKeysLookAlike:相近判据既要认出词序颠倒/长短词(实测那条),也不能把八竿子
// 打不着的 key 全列出来 —— 提示里塞满无关项等于没提示。
func TestSettingKeysLookAlike(t *testing.T) {
	alike := [][2]string{
		{"rate_default_download_bps", "default_rate_down_bps"}, // 实测踩到的那条:词序颠倒 + down/download
		{"rate_default_upload_bps", "rate_default_up_bps"},
		{"rate_burst_bytes", "rate_burst_byte"}, // 单纯少个字母
		{"advertised_host", "advertised_hosts"},
	}
	for _, tc := range alike {
		if !settingKeysLookAlike(tc[0], tc[1]) {
			t.Errorf("%q 与 %q 应判为相近", tc[0], tc[1])
		}
	}
	notAlike := [][2]string{
		{"advertised_host", "mesh_enabled"},
		{"server_id", "rate_burst_bytes"},
		{"acl_default_action", "setup_completed"},
	}
	for _, tc := range notAlike {
		if settingKeysLookAlike(tc[0], tc[1]) {
			t.Errorf("%q 与 %q 不该判为相近", tc[0], tc[1])
		}
	}
}

func TestLevenshtein(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"abc", "ab", 1},
		{"", "abc", 3},
		{"kitten", "sitting", 3},
	} {
		if got := levenshtein(tc.a, tc.b); got != tc.want {
			t.Errorf("levenshtein(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
