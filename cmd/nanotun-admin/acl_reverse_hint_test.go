package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// aclRun 在同一个库上跑一条 admin 命令,返回 (exit code, stdout, stderr)。
// 不给 --control-socket,通知必然失败 —— 本组用例只关心「缺回程」这条提示,
// 通知失败的那行是预期噪声。
func aclRun(t *testing.T, db string, args ...string) (int, string, string) {
	t.Helper()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	opts := &globalOpts{stdout: stdout, stderr: stderr, stdin: strings.NewReader("")}
	full := append([]string{"--db-path", db, "--yes", "--lang", "zh"}, args...)
	rest, err := parseGlobalFlags(full, opts)
	if err != nil {
		t.Fatalf("parseGlobalFlags: %v", err)
	}
	return runRoot(rest, opts), stdout.String(), stderr.String()
}

const reverseHintMark = "回程包会被丢"

// TestACLAllow_HintsMissingReverseUnderDefaultDeny:默认 deny 下只加一半 allow 会「完全不通」,
// 必须提示还差回程那条。三机实测过:只有 allow testcli u4 时 A→C 的 ping 全丢。
func TestACLAllow_HintsMissingReverseUnderDefaultDeny(t *testing.T) {
	db := filepath.Join(t.TempDir(), "aclrev.db")
	for _, n := range []string{"ua", "ub"} {
		if c, _, e := aclRun(t, db, "user", "create", n, "--psk", "secret"); c != 0 {
			t.Fatalf("create %s: %s", n, e)
		}
	}
	if c, _, e := aclRun(t, db, "setting", "set", "acl_default_action", "deny"); c != 0 {
		t.Fatalf("set default deny: %s", e)
	}

	c, _, stderr := aclRun(t, db, "acl", "allow", "ua", "ub")
	if c != 0 {
		t.Fatalf("acl allow: %s", stderr)
	}
	if !strings.Contains(stderr, reverseHintMark) {
		t.Errorf("应提示缺回程规则,stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "acl allow ub ua") {
		t.Errorf("提示里应给出可直接照抄的反向命令,stderr=%q", stderr)
	}

	// 补上回程后,再加同类规则不该再提示。
	if c, _, e := aclRun(t, db, "acl", "allow", "ub", "ua"); c != 0 {
		t.Fatalf("acl allow 反向: %s", e)
	}
	c, _, stderr = aclRun(t, db, "acl", "allow", "ua", "ub", "--proto", "tcp", "--port", "443")
	if c != 0 {
		t.Fatalf("acl allow tcp/443: %s", stderr)
	}
	if strings.Contains(stderr, reverseHintMark) {
		t.Errorf("回程已被 allow 覆盖,不该再提示,stderr=%q", stderr)
	}
}

// TestACLAllow_NoHintWhenDefaultAllow:默认 allow 下单条 allow 只是收窄不了什么,
// 回程本来就通,别拿无关提示吓人。
func TestACLAllow_NoHintWhenDefaultAllow(t *testing.T) {
	db := filepath.Join(t.TempDir(), "aclrev2.db")
	for _, n := range []string{"ua", "ub"} {
		if c, _, e := aclRun(t, db, "user", "create", n, "--psk", "secret"); c != 0 {
			t.Fatalf("create %s: %s", n, e)
		}
	}
	c, _, stderr := aclRun(t, db, "acl", "allow", "ua", "ub")
	if c != 0 {
		t.Fatalf("acl allow: %s", stderr)
	}
	if strings.Contains(stderr, reverseHintMark) {
		t.Errorf("默认 allow 时不该提示,stderr=%q", stderr)
	}
}

// TestACLAllow_NoHintForWildcardOrDenyOrExit:通配 / deny / exit 三类都不该触发提示 ——
// `allow * ub` 本身就覆盖了回程方向的 src,deny 与 exit 规则不涉及「缺一半」。
func TestACLAllow_NoHintForWildcardOrDenyOrExit(t *testing.T) {
	db := filepath.Join(t.TempDir(), "aclrev3.db")
	for _, n := range []string{"ua", "ub"} {
		if c, _, e := aclRun(t, db, "user", "create", n, "--psk", "secret"); c != 0 {
			t.Fatalf("create %s: %s", n, e)
		}
	}
	if c, _, e := aclRun(t, db, "setting", "set", "acl_default_action", "deny"); c != 0 {
		t.Fatalf("set default deny: %s", e)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"通配 src", []string{"acl", "allow", "*", "ub"}},
		{"通配 dst", []string{"acl", "allow", "ua", "*"}},
		{"deny 规则", []string{"acl", "deny", "ua", "ub", "--proto", "udp"}},
		{"exit 规则", []string{"acl", "allow", "ua", "*", "--exit"}},
	} {
		c, _, stderr := aclRun(t, db, tc.args...)
		if c != 0 {
			t.Fatalf("%s: %s", tc.name, stderr)
		}
		if strings.Contains(stderr, reverseHintMark) {
			t.Errorf("%s 不该提示缺回程,stderr=%q", tc.name, stderr)
		}
	}
}
