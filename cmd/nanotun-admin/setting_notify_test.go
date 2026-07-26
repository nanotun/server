package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// startFakeControl 起一个假的 control socket,记录收到的请求。
// socket 路径放 os.MkdirTemp 下的短目录:t.TempDir() 带测试名,容易顶穿 unix socket 的路径长度上限。
func startFakeControl(t *testing.T) (sock string, hits func() []string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ntc")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock = filepath.Join(dir, "c.sock")

	var mu sync.Mutex
	var got []string
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket 不可用: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true,"what":"acl"}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return sock, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// TestSettingSet_NotifiesServerForSnapshotKeys:mesh_enabled / acl_default_action 这两个
// **全局开关**落库后必须主动通知 server 刷新内存快照。
//
// 三机实测过的坑:`setting set mesh_enabled false` 之后 `setting list` 显示 false,而
// /status 里 mesh_enabled 仍是 true、客户端互访一路畅通,直到有人 SIGHUP。管理员多半是在
// 「先把互访断掉」的场合敲这条命令的,静默空转比没有这个开关更危险。
func TestSettingSet_NotifiesServerForSnapshotKeys(t *testing.T) {
	db := filepath.Join(t.TempDir(), "setnotify.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "seed", "--psk", "secret"); c != 0 {
		t.Fatalf("seed: %s", e)
	}
	sock, hits := startFakeControl(t)

	run := func(args ...string) (int, string) {
		stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
		opts := &globalOpts{stdout: stdout, stderr: stderr, stdin: strings.NewReader("")}
		full := append([]string{"--db-path", db, "--yes", "--lang", "zh", "--control-socket", sock}, args...)
		rest, perr := parseGlobalFlags(full, opts)
		if perr != nil {
			t.Fatalf("parseGlobalFlags: %v", perr)
		}
		return runRoot(rest, opts), stderr.String()
	}

	for _, tc := range []struct{ key, val string }{
		{"mesh_enabled", "false"},
		{"acl_default_action", "deny"},
	} {
		before := len(hits())
		code, stderr := run("setting", "set", tc.key, tc.val)
		if code != 0 {
			t.Fatalf("setting set %s: %s", tc.key, stderr)
		}
		after := hits()
		if len(after) != before+1 {
			t.Fatalf("set %s 应触发一次 reload 通知,hits=%v", tc.key, after)
		}
		if last := after[len(after)-1]; last != "POST /reload?what=acl" {
			t.Errorf("set %s 通知内容不对: %q", tc.key, last)
		}
		if !strings.Contains(stderr, "即时生效") {
			t.Errorf("set %s 应告知已即时生效,stderr=%q", tc.key, stderr)
		}
	}
}

// TestSettingSet_NoNotifyForUnrelatedKeys:与内存快照无关的 key 不该白打一次 control socket
// (server 没跑时那会平白多一行 warn,吓人)。
func TestSettingSet_NoNotifyForUnrelatedKeys(t *testing.T) {
	db := filepath.Join(t.TempDir(), "setnonotify.db")
	if c, _, e := runCLI(t, db, "", "user", "create", "seed", "--psk", "secret"); c != 0 {
		t.Fatalf("seed: %s", e)
	}
	sock, hits := startFakeControl(t)

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	opts := &globalOpts{stdout: stdout, stderr: stderr, stdin: strings.NewReader("")}
	full := []string{"--db-path", db, "--yes", "--lang", "zh", "--control-socket", sock,
		"setting", "set", "advertised_host", "vpn.example.com"}
	rest, perr := parseGlobalFlags(full, opts)
	if perr != nil {
		t.Fatalf("parseGlobalFlags: %v", perr)
	}
	if code := runRoot(rest, opts); code != 0 {
		t.Fatalf("setting set advertised_host: %s", stderr.String())
	}
	if h := hits(); len(h) != 0 {
		t.Errorf("advertised_host 不在内存快照里,不该通知 server,hits=%v", h)
	}
}

// TestACLSnapshotKeysAreValidated:这两个 key 同时也必须在 validatedSettingKeys 里 ——
// 拼错值(比如 mesh_enabled=flase)会被数据面兜到默认值,通知得再及时也是错的。
func TestACLSnapshotKeysAreValidated(t *testing.T) {
	for k := range aclSnapshotSettingKeys {
		if _, ok := validatedSettingKeys[k]; !ok {
			t.Errorf("%q 会被主动推给 server,必须先过写入校验", k)
		}
	}
}
