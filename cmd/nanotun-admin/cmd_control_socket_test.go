package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// reload / kick / connection 这三条命令是运维在故障现场敲的。它们的退出码得可靠:
// 脚本靠 2 区分「命令敲错了」、靠 1 区分「服务端不通」。此前这三条一行测试都没有。

// fakeControlSocket 起一个假的 nanotund 控制面并返回 socket 路径。
type fakeControlSocket struct {
	path string
	mu   sync.Mutex
	reqs []string
}

func newFakeControlSocket(t *testing.T, routes map[string]http.HandlerFunc) *fakeControlSocket {
	t.Helper()
	// unix socket 路径有 ~104 字节上限,t.TempDir() 会把测试名拼进去直接超限。
	dir, err := os.MkdirTemp("", "nta")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	fc := &fakeControlSocket{path: path}
	mux := http.NewServeMux()
	for p, h := range routes {
		mux.HandleFunc(p, h)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			line += "?" + r.URL.RawQuery
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			line += " " + string(body)
		}
		fc.mu.Lock()
		fc.reqs = append(fc.reqs, line)
		fc.mu.Unlock()
		mux.ServeHTTP(w, r)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return fc
}

func (f *fakeControlSocket) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

// runCLISock 跟 runCLI 一样,但额外把控制面 socket 指到假服务上。
func runCLISock(t *testing.T, db, sock string, args ...string) (int, string, string) {
	t.Helper()
	full := append([]string{"--control-socket", sock}, args...)
	return runCLI(t, db, "", full...)
}

func TestCmdReload_TargetsWhateverTheOperatorTyped(t *testing.T) {
	db := filepath.Join(t.TempDir(), "reload.db")
	fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
		"/reload": jsonHandler(`{"ok":true,"what":"acl","rules":12}`)})

	t.Run("不带参数默认重载 ACL", func(t *testing.T) {
		c, out, e := runCLISock(t, db, fc.path, "reload")
		if c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if !strings.Contains(out, "12") {
			t.Fatalf("输出里应带上生效条数,运维靠它确认真的重载了: %q", out)
		}
		if !containsAny(fc.requests(), "what=acl") {
			t.Fatalf("默认目标应是 acl,实际发出: %v", fc.requests())
		}
	})

	for _, what := range []string{"routes", "exits", "portforward"} {
		t.Run("reload "+what, func(t *testing.T) {
			fc2 := newFakeControlSocket(t, map[string]http.HandlerFunc{
				"/reload": jsonHandler(`{"ok":true,"what":"` + what + `"}`)})
			if c, _, e := runCLISock(t, db, fc2.path, "reload", what); c != 0 {
				t.Fatalf("code=%d stderr=%s", c, e)
			}
			if !containsAny(fc2.requests(), "what="+what) {
				t.Fatalf("目标没透传,实际发出: %v", fc2.requests())
			}
		})
	}

	t.Run("--json 原样吐服务端响应", func(t *testing.T) {
		c, out, _ := runCLISock(t, db, fc.path, "--json", "reload")
		if c != 0 {
			t.Fatalf("code=%d", c)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("--json 的输出必须是可解析 JSON,脚本要 jq 它: %v(%q)", err, out)
		}
	})

	t.Run("服务端回了非 JSON 也不崩", func(t *testing.T) {
		fc3 := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/reload": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("OK"))
			}})
		if c, out, _ := runCLISock(t, db, fc3.path, "reload"); c != 0 || !strings.Contains(out, "OK") {
			t.Fatalf("解析不了就原样打出来即可,code=%d out=%q", c, out)
		}
	})

	t.Run("服务端不通 → exit 1", func(t *testing.T) {
		if c, _, _ := runCLISock(t, db, "/tmp/绝对不存在的.sock", "reload"); c != 1 {
			t.Fatalf("退出码 %d,期望 1(执行失败,不是用法错)", c)
		}
	})
}

func TestCmdKick_ValidatesArgumentsBeforeDialingTheServer(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kick.db")
	fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
		"/kick": jsonHandler(`{"ok":true,"kicked":2,"reason":"kicked_by_admin","conn_ids":["c1","c2"]}`)})

	t.Run("正常踢线", func(t *testing.T) {
		c, out, e := runCLISock(t, db, fc.path, "kick", "user", "alice")
		if c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if !strings.Contains(out, "c1") || !strings.Contains(out, "c2") {
			t.Fatalf("应列出被踢掉的会话 id,运维要拿它核对: %q", out)
		}
	})

	t.Run("带上原因", func(t *testing.T) {
		fc2 := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/kick": jsonHandler(`{"ok":true,"kicked":1,"reason":"欠费"}`)})
		if c, _, e := runCLISock(t, db, fc2.path, "kick", "device", "7", "--reason", "欠费"); c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if !containsAny(fc2.requests(), "欠费") {
			t.Fatalf("原因没发给服务端,客户端就只看到「连接断开」: %v", fc2.requests())
		}
	})

	// 参数校验必须发生在拨号之前。否则服务端不通时,「kind 写错」会被报成
	// 「连不上」(exit 1),退出码随服务可达性漂移,脚本没法判断。
	t.Run("参数错时退出码不随服务端可达性漂移", func(t *testing.T) {
		cases := []struct {
			name string
			args []string
		}{
			{"缺参数", []string{"kick"}},
			{"只给 kind", []string{"kick", "user"}},
			{"kind 不认识", []string{"kick", "everything", "x"}},
			{"--reason 没给值", []string{"kick", "user", "alice", "--reason"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				withServer, _, _ := runCLISock(t, db, fc.path, tc.args...)
				noServer, _, _ := runCLISock(t, db, "/tmp/绝对不存在的.sock", tc.args...)
				if withServer != 2 {
					t.Fatalf("服务端可达时退出码 %d,期望 2", withServer)
				}
				if noServer != 2 {
					t.Fatalf("服务端不可达时退出码 %d,期望 2 —— 用法错不该被「连不上」盖掉", noServer)
				}
			})
		}
	})

	t.Run("不认识的 flag", func(t *testing.T) {
		if c, _, _ := runCLISock(t, db, fc.path, "kick", "user", "alice", "--force"); c == 0 {
			t.Fatal("不认识的 flag 应报错,静默忽略会让人以为参数生效了")
		}
	})

	t.Run("服务端不通", func(t *testing.T) {
		if c, _, _ := runCLISock(t, db, "/tmp/绝对不存在的.sock", "kick", "user", "alice"); c != 1 {
			t.Fatalf("退出码 %d,期望 1", c)
		}
	})
}

func TestCmdConnection_ListsSessionsAndPassesPaginationThrough(t *testing.T) {
	db := filepath.Join(t.TempDir(), "conn.db")
	const statusJSON = `{"ok":true,"conn_count":1,"sessions_total":1,"sessions":[` +
		`{"conn_id":"c1","user_id":"u1","device_name":"box","vips":["10.80.0.5"]}]}`
	fc := newFakeControlSocket(t, map[string]http.HandlerFunc{"/status": jsonHandler(statusJSON)})

	t.Run("默认列出会话", func(t *testing.T) {
		c, out, e := runCLISock(t, db, fc.path, "connection", "list")
		if c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		if !strings.Contains(out, "c1") {
			t.Fatalf("会话没列出来: %q", out)
		}
	})

	t.Run("不带子命令等同于 list", func(t *testing.T) {
		if c, out, _ := runCLISock(t, db, fc.path, "connection"); c != 0 || !strings.Contains(out, "c1") {
			t.Fatalf("code=%d out=%q", c, out)
		}
	})

	t.Run("status 子命令吐原始响应", func(t *testing.T) {
		c, out, _ := runCLISock(t, db, fc.path, "connection", "status")
		if c != 0 {
			t.Fatalf("code=%d", c)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("status 应吐可解析 JSON: %v", err)
		}
	})

	t.Run("分页参数透传给服务端", func(t *testing.T) {
		fc2 := newFakeControlSocket(t, map[string]http.HandlerFunc{"/status": jsonHandler(statusJSON)})
		if c, _, e := runCLISock(t, db, fc2.path, "conn", "list", "--limit", "10", "--offset", "20"); c != 0 {
			t.Fatalf("code=%d stderr=%s", c, e)
		}
		reqs := fc2.requests()
		if !containsAny(reqs, "limit=10") || !containsAny(reqs, "offset=20") {
			t.Fatalf("分页没透传,服务端会把全部会话都吐回来: %v", reqs)
		}
	})

	// 同 kick:先校验再拨号,退出码才稳定。
	t.Run("用法错的退出码不随服务端可达性漂移", func(t *testing.T) {
		for _, args := range [][]string{
			{"connection", "自爆"},
			{"connection", "list", "多余的参数"},
			{"connection", "list", "--limit"},
			{"connection", "list", "--limit", "abc"},
		} {
			t.Run(strings.Join(args, "_"), func(t *testing.T) {
				withServer, _, _ := runCLISock(t, db, fc.path, args...)
				noServer, _, _ := runCLISock(t, db, "/tmp/绝对不存在的.sock", args...)
				if withServer != 2 || noServer != 2 {
					t.Fatalf("退出码 可达=%d 不可达=%d,都应为 2", withServer, noServer)
				}
			})
		}
	})

	t.Run("服务端不通", func(t *testing.T) {
		if c, _, _ := runCLISock(t, db, "/tmp/绝对不存在的.sock", "connection", "list"); c != 1 {
			t.Fatalf("退出码应为 1")
		}
	})
}

// device list --effective 要把服务端的全局限速一起算进来。控制面不通时不能整条
// 命令失败 —— 那只是"算不出最终生效值",列表本身还是有用的。
func TestFetchRateConfigFromControl_ReadsTheGlobalFloorFromTheServer(t *testing.T) {
	fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
		"/status": jsonHandler(`{"rate_config":{"toml_up_bps":1000,"toml_down_bps":2000}}`)})

	opts := &globalOpts{controlSocket: fc.path, stdout: io.Discard, stderr: io.Discard}
	got, err := fetchRateConfigFromControl(opts)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got.TomlUpBPS != 1000 || got.TomlDownBPS != 2000 {
		t.Fatalf("读到 %+v", got)
	}

	t.Run("服务端不通", func(t *testing.T) {
		bad := &globalOpts{controlSocket: "/tmp/绝对不存在的.sock", stdout: io.Discard, stderr: io.Discard}
		if _, err := fetchRateConfigFromControl(bad); err == nil {
			t.Fatal("应报错,由调用方决定要不要降级")
		}
	})

	t.Run("响应解析不了", func(t *testing.T) {
		fc2 := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/status": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("垃圾")) }})
		o := &globalOpts{controlSocket: fc2.path, stdout: io.Discard, stderr: io.Discard}
		if _, err := fetchRateConfigFromControl(o); err == nil {
			t.Fatal("应报错")
		}
	})
}

func containsAny(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}
