package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// runSettingCLI 跑一条带假 control socket 的 nanotun-admin 命令,返回 exit code 与两路输出。
func runSettingCLI(t *testing.T, db, sock string, args ...string) (int, string, string) {
	t.Helper()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	opts := &globalOpts{stdout: stdout, stderr: stderr, stdin: strings.NewReader("")}
	full := append([]string{"--db-path", db, "--yes", "--lang", "zh", "--control-socket", sock}, args...)
	rest, perr := parseGlobalFlags(full, opts)
	if perr != nil {
		t.Fatalf("parseGlobalFlags: %v", perr)
	}
	return runRoot(rest, opts), stdout.String(), stderr.String()
}

// TestSettingSet_PushesRateRefresh:限速三件套走 raw `setting set` 也必须推 /rate/refresh。
//
// 三机实测(2026-07-26):`setting set rate_default_download_bps 100000` 之后 `setting list` /
// `setting rate` 都显示限着 0.10 MiB/s,而实际下载仍有 620 KB/s —— 在线会话上的 rate.Limiter
// 是连接上的对象,不推刷新就只是改了行 DB。
func TestSettingSet_PushesRateRefresh(t *testing.T) {
	db := filepath.Join(t.TempDir(), "ratenotify.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "seed", "--psk", "secret"); c != 0 {
		t.Fatalf("seed: %s", e)
	}
	sock, hits := startFakeControl(t)

	for _, tc := range []struct{ key, val string }{
		{"rate_default_download_bps", "100000"},
		{"rate_default_upload_bps", "200000"},
		{"rate_burst_bytes", "65536"},
	} {
		before := len(hits())
		code, _, stderr := runSettingCLI(t, db, sock, "setting", "set", tc.key, tc.val)
		if code != 0 {
			t.Fatalf("setting set %s: %s", tc.key, stderr)
		}
		after := hits()
		if len(after) != before+1 {
			t.Fatalf("set %s 应触发一次 rate refresh,hits=%v", tc.key, after)
		}
		if last := after[len(after)-1]; last != "POST /rate/refresh" {
			t.Errorf("set %s 通知内容不对: %q", tc.key, last)
		}
		if !strings.Contains(stderr, "即时生效") {
			t.Errorf("set %s 应告知已即时生效,stderr=%q", tc.key, stderr)
		}
	}
}

// TestSettingRate_ReappliesWhenValuesUnchanged:值与库里一致时,`setting rate` 仍要推一次刷新。
//
// 否则「别的路径把值写进了库、但没推给在线会话」就无解:唯一能生效的命令因为值一致而拒绝动手,
// 显示限着、数据面全速跑,只能改成别的值再改回来或重启 server(三机实测踩到)。
func TestSettingRate_ReappliesWhenValuesUnchanged(t *testing.T) {
	db := filepath.Join(t.TempDir(), "ratereapply.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "seed", "--psk", "secret"); c != 0 {
		t.Fatalf("seed: %s", e)
	}
	sock, hits := startFakeControl(t)

	if code, _, stderr := runSettingCLI(t, db, sock, "setting", "rate", "--down-bps", "100000"); code != 0 {
		t.Fatalf("首次设置: %s", stderr)
	}
	before := len(hits())

	// 同一个值再来一次:不写库,但必须重推刷新。
	code, stdout, stderr := runSettingCLI(t, db, sock, "setting", "rate", "--down-bps", "100000")
	if code != 0 {
		t.Fatalf("重复设置: %s", stderr)
	}
	after := hits()
	if len(after) != before+1 {
		t.Fatalf("值未变也应重推一次刷新,hits=%v", after)
	}
	if last := after[len(after)-1]; last != "POST /rate/refresh" {
		t.Errorf("刷新请求不对: %q", last)
	}
	if !strings.Contains(stdout, "重推") {
		t.Errorf("应告知已重推刷新,stdout=%q", stdout)
	}
}

// TestSettingRate_NoRefreshFlagStillHonoredWhenUnchanged:--no-refresh 是运维显式说「别动在线会话」,
// 值未变的分支也得听。
func TestSettingRate_NoRefreshFlagStillHonoredWhenUnchanged(t *testing.T) {
	db := filepath.Join(t.TempDir(), "ratenorefresh.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "seed", "--psk", "secret"); c != 0 {
		t.Fatalf("seed: %s", e)
	}
	sock, hits := startFakeControl(t)

	if code, _, stderr := runSettingCLI(t, db, sock, "setting", "rate", "--down-bps", "100000", "--no-refresh"); code != 0 {
		t.Fatalf("首次设置: %s", stderr)
	}
	before := len(hits())
	if code, _, stderr := runSettingCLI(t, db, sock, "setting", "rate", "--down-bps", "100000", "--no-refresh"); code != 0 {
		t.Fatalf("重复设置: %s", stderr)
	}
	if after := hits(); len(after) != before {
		t.Errorf("--no-refresh 不该推刷新,hits=%v", after)
	}
}

// TestRateRefreshKeysAreValidated:会被主动推给 server 的 key 必须先过写入校验(同 ACL 快照那组)。
func TestRateRefreshKeysAreValidated(t *testing.T) {
	for k := range rateRefreshSettingKeys {
		if _, ok := validatedSettingKeys[k]; !ok {
			t.Errorf("%q 会被主动推给 server,必须先过写入校验", k)
		}
	}
}
