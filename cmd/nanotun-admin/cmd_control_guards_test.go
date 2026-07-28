package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// =========================================================================
// kick:--json 直通 与 服务端乱回话时的降级
// =========================================================================

func TestCmdKick_JSONPassthroughAndGarbageDowngrade(t *testing.T) {
	db := filepath.Join(t.TempDir(), "kick2.db")

	t.Run("--json 原样吐服务端响应", func(t *testing.T) {
		const raw = `{"ok":true,"kicked":3,"conn_ids":["a","b","c"],"reason":"maintenance"}`
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{"/kick": jsonHandler(raw)})
		code, stdout, stderr := runCLISock(t, db, fc.path, "--json", "kick", "user", "alice")
		if code != 0 {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
		// --json 的契约是「stdout 是一整段可 jq 的 JSON」,不能混进人读的表格。
		var v map[string]any
		if err := json.Unmarshal([]byte(stdout), &v); err != nil {
			t.Fatalf("--json 输出不可解析: %v (%q)", err, stdout)
		}
		if v["kicked"] != float64(3) {
			t.Errorf("服务端的字段没原样透传: %v", v)
		}
	})

	t.Run("服务端回非 JSON 时原样打出,不报错", func(t *testing.T) {
		// 版本错配(老 nanotund 回纯文本)不该让 kick 报失败:会话其实已经踢了,
		// 报错会诱使运维再踢一遍甚至去重启 server。
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/kick": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("kicked 2 sessions"))
			}})
		code, stdout, _ := runCLISock(t, db, fc.path, "kick", "session", "c1")
		if code != 0 {
			t.Fatalf("解析不了不等于失败, code=%d", code)
		}
		if !strings.Contains(stdout, "kicked 2 sessions") {
			t.Errorf("没把原始响应透出来,运维就完全不知道服务端说了什么: %q", stdout)
		}
	})
}

// =========================================================================
// connection list:表格渲染的几种取值
// =========================================================================

func TestPrintConnectionList_RendersEdgeValues(t *testing.T) {
	db := filepath.Join(t.TempDir(), "conn2.db")

	t.Run("没有 VIP 的会话显示占位而不是空列", func(t *testing.T) {
		// vips 为空(刚握手、还没分到 lease)时留空列会让表格错位,后面几列全对不上标题。
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/status": jsonHandler(`{"ok":true,"conn_count":1,"sessions":[` +
				`{"conn_id":"c1","user_id":"u1","vips":[],"exit_allowed":false,` +
				`"link_ready":true,"link_rate_up_bps":0,"link_rate_down_bps":0}]}`)})
		code, stdout, stderr := runCLISock(t, db, fc.path, "connection", "list")
		if code != 0 {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
		if !strings.Contains(stdout, "-") {
			t.Errorf("空 vips 没渲染成占位: %q", stdout)
		}
		if !strings.Contains(stdout, "no") {
			t.Errorf("exit_allowed=false 该显示 no: %q", stdout)
		}
	})

	t.Run("多个 VIP 用逗号连起来", func(t *testing.T) {
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/status": jsonHandler(`{"ok":true,"conn_count":1,"sessions":[` +
				`{"conn_id":"c1","user_id":"u1","vips":["10.80.0.5","fd00::5"],` +
				`"exit_allowed":true,"link_ready":true,` +
				`"link_rate_up_bps":1000,"link_rate_down_bps":2000}]}`)})
		code, stdout, _ := runCLISock(t, db, fc.path, "connection", "list")
		if code != 0 {
			t.Fatalf("code=%d", code)
		}
		if !strings.Contains(stdout, "10.80.0.5,fd00::5") {
			t.Errorf("双栈 VIP 没连在一列里: %q", stdout)
		}
		// 展示的必须是 link_rate_*(生效 cap),不是登录时凝固的 bw_*。
		if !strings.Contains(stdout, "1000") || !strings.Contains(stdout, "2000") {
			t.Errorf("生效限速没展示: %q", stdout)
		}
	})

	t.Run("limiter 还没建起来时显示 ? 而不是不限速", func(t *testing.T) {
		// link_ready=false 时 link_rate_* 的 0 是「尚未初始化」,渲染成 "-"(不限速)
		// 会让运维以为限速没生效而重复下发。
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/status": jsonHandler(`{"ok":true,"conn_count":1,"sessions":[` +
				`{"conn_id":"c1","user_id":"u1","vips":["10.80.0.5"],` +
				`"link_ready":false,"link_rate_up_bps":0,"link_rate_down_bps":0}]}`)})
		code, stdout, _ := runCLISock(t, db, fc.path, "connection", "list")
		if code != 0 {
			t.Fatalf("code=%d", code)
		}
		if !strings.Contains(stdout, "?") {
			t.Errorf("link_ready=false 应显示 ?,实际: %q", stdout)
		}
	})

	t.Run("--json 直通,不渲染表格", func(t *testing.T) {
		const raw = `{"ok":true,"conn_count":2,"sessions":[],"acl_drop_total":9}`
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{"/status": jsonHandler(raw)})
		code, stdout, _ := runCLISock(t, db, fc.path, "--json", "connection", "list")
		if code != 0 {
			t.Fatalf("code=%d", code)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(stdout), &v); err != nil {
			t.Fatalf("--json 输出不可解析: %v (%q)", err, stdout)
		}
		if strings.Contains(stdout, "CONN_ID") {
			t.Error("--json 里混进了给人看的表头,jq 会直接失败")
		}
	})

	t.Run("服务端响应解析不了 → exit 1", func(t *testing.T) {
		// 与「用法错」的 2 区分开:这是运行期故障(版本错配 / 代理插了 HTML 错误页)。
		fc := newFakeControlSocket(t, map[string]http.HandlerFunc{
			"/status": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
			}})
		code, _, stderr := runCLISock(t, db, fc.path, "connection", "list")
		if code != 1 {
			t.Fatalf("解析失败应 exit 1, got %d stderr=%q", code, stderr)
		}
		if !strings.Contains(stderr, "status") {
			t.Errorf("报错没说清是解析 status 挂了: %q", stderr)
		}
	})
}

func TestJoinStringsAndBpsOrDash(t *testing.T) {
	// 两个小格式化函数各自的 0 值分支:表格里的 "-" 全靠它们,渲染成空串就会串列。
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, "-"},
		{[]string{}, "-"},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a,b"},
		{[]string{"a", "b", "c"}, "a,b,c"},
	} {
		if got := joinStrings(tc.in, ","); got != tc.want {
			t.Errorf("joinStrings(%v)=%q, 期望 %q", tc.in, got, tc.want)
		}
	}

	for _, tc := range []struct {
		in   int64
		want string
	}{
		{0, "-"},
		{-1, "-"},
		{1, "1"},
		{1000000, "1000000"},
	} {
		if got := bpsOrDash(tc.in); got != tc.want {
			t.Errorf("bpsOrDash(%d)=%q, 期望 %q", tc.in, got, tc.want)
		}
	}
}
