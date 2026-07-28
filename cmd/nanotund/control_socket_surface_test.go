package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// control socket 是**无鉴权**的特权面:能读那个 socket 文件就能踢会话、改限速、
// reload 策略。它的安全前提完全落在文件权限上,可用性前提落在参数校验上 ——
// 这两类此前基本没有测试。

func newControlEnv(t *testing.T) (*gatewayState, string) {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ctl.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	gw := &gatewayState{store: st}
	sock, cleanup := startTestControlSocket(t, gw)
	t.Cleanup(cleanup)
	return gw, sock
}

// 每个 endpoint 都必须拒绝错误的 method。GET 能触发 reload / kick 这类副作用的话,
// 一个被诱导的浏览器请求或者一次误敲的 curl 就能踢掉所有在线用户。
func TestControlSocket_EveryEndpointRejectsTheWrongMethod(t *testing.T) {
	_, sock := newControlEnv(t)

	cases := []struct {
		path      string
		wantVerb  string
		wrongVerb string
	}{
		{"/status", "GET", "POST"},
		{"/rate/config", "GET", "POST"},
		{"/sysmon/counters", "GET", "POST"},
		{"/portforward/status", "GET", "POST"},
		{"/reload", "POST", "GET"},
		{"/kick", "POST", "GET"},
		{"/rate/refresh", "POST", "GET"},
		{"/users/rate/refresh", "POST", "GET"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			code, _ := controlReq(t, sock, tc.wrongVerb, tc.path, nil)
			if code != 405 {
				t.Fatalf("%s %s 应回 405,got %d —— 写操作能用 GET 触发是很危险的",
					tc.wrongVerb, tc.path, code)
			}
		})
	}
}

// 这三个只读 endpoint 是 web 后台高频轮询的。它们返回的形状变了,前端只会显示
// 一片空白,而服务端日志里什么都没有。
func TestControlSocket_ReadOnlyEndpointsReturnTheShapeWebExpects(t *testing.T) {
	_, sock := newControlEnv(t)

	t.Run("sysmon/counters", func(t *testing.T) {
		vpnBytesUp.Store(1234)
		vpnBytesDown.Store(5678)
		t.Cleanup(func() { vpnBytesUp.Store(0); vpnBytesDown.Store(0) })

		code, body := controlReq(t, sock, "GET", "/sysmon/counters", nil)
		if code != 200 {
			t.Fatalf("code=%d body=%s", code, body)
		}
		var got struct {
			TSMs      int64 `json:"ts_ms"`
			Uptime    int64 `json:"uptime_seconds"`
			BytesUp   int64 `json:"vpn_bytes_up"`
			BytesDown int64 `json:"vpn_bytes_down"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("解析失败: %v(body=%s)", err, body)
		}
		if got.BytesUp != 1234 || got.BytesDown != 5678 {
			t.Fatalf("计数器不对: up=%d down=%d", got.BytesUp, got.BytesDown)
		}
		if got.TSMs <= 0 {
			t.Fatal("ts_ms 应为当前毫秒时间戳")
		}
		if got.Uptime < 0 {
			t.Fatalf("uptime 不该为负,got %d", got.Uptime)
		}
	})

	t.Run("portforward/status", func(t *testing.T) {
		code, body := controlReq(t, sock, "GET", "/portforward/status", nil)
		if code != 200 {
			t.Fatalf("code=%d body=%s", code, body)
		}
		var got struct {
			OK       bool                `json:"ok"`
			Forwards []portForwardStatus `json:"forwards"`
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("解析失败: %v(body=%s)", err, body)
		}
		if !got.OK {
			t.Fatal("ok 应为 true")
		}
	})

	t.Run("rate/config", func(t *testing.T) {
		code, body := controlReq(t, sock, "GET", "/rate/config", nil)
		if code != 200 {
			t.Fatalf("code=%d body=%s", code, body)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("解析失败: %v(body=%s)", err, body)
		}
		if len(got) == 0 {
			t.Fatal("rate_config 不该是空对象 —— web 的四层限速兜底全靠它")
		}
		// 与 /status 里的同名字段必须一致,否则两个页面显示的限速对不上。
		// (单测里 TUN 没起,/status 会以 503 汇报未就绪,但 body 照样是完整的。)
		_, sbody := controlReq(t, sock, "GET", "/status", nil)
		var st struct {
			RateConfig map[string]any `json:"rate_config"`
		}
		if err := json.Unmarshal(sbody, &st); err != nil {
			t.Fatalf("解析 /status: %v", err)
		}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(st.RateConfig)
		if string(a) != string(b) {
			t.Fatalf("/rate/config 与 /status.rate_config 不一致:\n  %s\n  %s", a, b)
		}
	})
}

// 数字参数拼错时必须显式 400。静默回退到「全量」的话,运维敲错一个字符就会
// 触发一次全量刷新(N 条连接重算限速),而且他以为自己只动了一台设备。
func TestControlSocket_MalformedNumericParamsAre400NotSilentFallback(t *testing.T) {
	_, sock := newControlEnv(t)

	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"status device_id 非数字", "GET", "/status?device_id=abc", 400},
		{"status device_id 带前缀", "GET", "/status?device_id=device_5", 400},
		{"status device_id 为负", "GET", "/status?device_id=-1", 400},
		// 合法参数走到底,单测里 TUN 没起 → 503(见下面那条健康信号的用例),
		// 关键是它**不是** 400:参数校验放行了。
		{"status device_id 合法", "GET", "/status?device_id=5", 503},
		{"status device_id 为空 = 全量", "GET", "/status?device_id=", 503},

		{"rate/refresh device_id 非数字", "POST", "/rate/refresh?device_id=abc", 400},
		{"rate/refresh device_id 为负", "POST", "/rate/refresh?device_id=-3", 400},
		{"rate/refresh 无参 = 全量刷", "POST", "/rate/refresh", 200},

		{"users/rate/refresh user_id 非数字", "POST", "/users/rate/refresh?user_id=abc", 400},
		{"users/rate/refresh 缺 user_id", "POST", "/users/rate/refresh", 400},
		{"users/rate/refresh user_id=0", "POST", "/users/rate/refresh?user_id=0", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := controlReq(t, sock, tc.method, tc.path, nil)
			if code != tc.want {
				t.Fatalf("code=%d want %d(body=%s)", code, tc.want, body)
			}
		})
	}
}

// /status 的 HTTP 码本身就是健康信号:TUN 没起来时必须 503,同时 body 里要如实
// 写清是哪一环没就绪。全都回 200 的话,滚动升级时流量会被打进一个还没通数据面的节点。
func TestControlSocketStatus_HTTPCodeIsItselfTheReadinessSignal(t *testing.T) {
	prev := sharedTUN
	sharedTUN = nil
	t.Cleanup(func() { sharedTUN = prev })

	_, sock := newControlEnv(t)
	code, body := controlReq(t, sock, "GET", "/status", nil)
	if code != 503 {
		t.Fatalf("TUN 未就绪时 /status 应回 503,got %d", code)
	}
	var got struct {
		OK         bool `json:"ok"`
		TUNReady   bool `json:"tun_ready"`
		StoreReady bool `json:"store_ready"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("解析失败: %v(body=%s)", err, body)
	}
	if got.OK || got.TUNReady {
		t.Fatalf("body 该如实报告 ok=false tun_ready=false: %s", body)
	}
	if !got.StoreReady {
		t.Fatalf("store 是好的,不该被一起报成未就绪: %s", body)
	}
}

func TestControlSocketReload_KnowsItsTargetsAndRefusesTheRest(t *testing.T) {
	_, sock := newControlEnv(t)

	t.Run("默认目标是 acl", func(t *testing.T) {
		code, body := controlReq(t, sock, "POST", "/reload", nil)
		if code != 200 {
			t.Fatalf("code=%d body=%s", code, body)
		}
		var got struct {
			OK   bool   `json:"ok"`
			What string `json:"what"`
		}
		_ = json.Unmarshal(body, &got)
		if !got.OK || got.What != "acl" {
			t.Fatalf("不带 what 时应默认 reload acl,got %s", body)
		}
	})

	for _, what := range []string{"acl", "exits", "routes", "portforward"} {
		t.Run("what="+what, func(t *testing.T) {
			code, body := controlReq(t, sock, "POST", "/reload?what="+what, nil)
			if code != 200 {
				t.Fatalf("code=%d body=%s", code, body)
			}
			var got struct {
				OK   bool   `json:"ok"`
				What string `json:"what"`
			}
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("解析失败: %v(body=%s)", err, body)
			}
			if !got.OK || got.What != what {
				t.Fatalf("响应里应回显目标 %q,got %s", what, body)
			}
		})
	}

	t.Run("不认识的目标要报错而不是静默成功", func(t *testing.T) {
		code, body := controlReq(t, sock, "POST", "/reload?what=logs", nil)
		if code != 400 {
			t.Fatalf("code=%d want 400(body=%s)", code, body)
		}
		if !strings.Contains(string(body), "logs") {
			t.Fatalf("错误里应回显那个拼错的目标,方便看出敲了什么: %s", body)
		}
	})
}

// store 没起来时,依赖 DB 的 reload 目标必须回 503 而不是假装成功 ——
// 假装成功会让运维以为策略已经生效。
func TestControlSocketReload_ReportsUnavailableWhenStoreIsMissing(t *testing.T) {
	sock, cleanup := startTestControlSocket(t, &gatewayState{})
	t.Cleanup(cleanup)

	for _, what := range []string{"acl", "exits", "routes"} {
		t.Run(what, func(t *testing.T) {
			code, body := controlReq(t, sock, "POST", "/reload?what="+what, nil)
			if code != 503 {
				t.Fatalf("code=%d want 503(body=%s)", code, body)
			}
		})
	}
	// portforward 不查 DB(管理器未启用时返回 0),应当仍是 200。
	if code, body := controlReq(t, sock, "POST", "/reload?what=portforward", nil); code != 200 {
		t.Fatalf("portforward 应回 200,got %d(%s)", code, body)
	}
}

func TestControlSocketKick_ValidatesTheTargetBeforeTouchingAnySession(t *testing.T) {
	gw, sock := newControlEnv(t)
	u, err := gw.store.CreateUser(t.Context(), store.NewUser{Username: "kicker", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cases := []struct {
		name string
		body any
		want int
		why  string
	}{
		{"body 不是 JSON", "这不是json", 400, ""},
		{"kind 不认识", map[string]any{"kind": "everything", "id": "x"}, 400,
			"未知 kind 静默当成「什么都不踢」的话,管理员会以为处置生效了"},
		{"kind 为空", map[string]any{"id": "x"}, 400, ""},
		{"device 但 id 为空", map[string]any{"kind": "device", "id": "  "}, 400,
			"空 id 会匹配到所有 deviceUUID 为空的连接"},
		{"user 不存在", map[string]any{"kind": "user", "id": "no-such-user"}, 404, ""},
		{"user 存在", map[string]any{"kind": "user", "id": "kicker"}, 200, ""},
		{"user 用 u<id> 形式", map[string]any{"kind": "user", "id": "u" + itoa64(u.ID)}, 200, ""},
		{"user 用纯数字 id", map[string]any{"kind": "user", "id": itoa64(u.ID)}, 200, ""},
		{"session 不存在也算成功(踢了 0 条)", map[string]any{"kind": "session", "id": "no-such-conn"}, 200, ""},
		{"device 用 UUID", map[string]any{"kind": "device", "id": "00000000-0000-4000-8000-000000000001"}, 200, ""},
		{"device 用数字 id", map[string]any{"kind": "device", "id": "42"}, 200, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := controlReq(t, sock, "POST", "/kick", tc.body)
			if code != tc.want {
				t.Fatalf("code=%d want %d(%s)\nbody=%s", code, tc.want, tc.why, body)
			}
			if code != 200 {
				return
			}
			var got controlKickResp
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("解析失败: %v(%s)", err, body)
			}
			if !got.OK {
				t.Fatalf("ok 应为 true: %s", body)
			}
			if got.Reason == "" {
				t.Fatal("响应要带上 reason —— 客户端收到的下线原因就是它,空了用户只看到「连接断开」")
			}
		})
	}

	// 不指定 reason 时要有一个默认值。
	code, body := controlReq(t, sock, "POST", "/kick", map[string]any{"kind": "session", "id": "x"})
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	var got controlKickResp
	_ = json.Unmarshal(body, &got)
	if got.Reason != "kicked_by_admin" {
		t.Fatalf("默认 reason 应为 kicked_by_admin,got %q", got.Reason)
	}
}

func TestResolveControlKickUser_AcceptsEveryFormAdminsActuallyType(t *testing.T) {
	gw, _ := newControlEnv(t)
	ctx := t.Context()
	u, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cases := []struct {
		name   string
		raw    string
		wantID int64
		wantOK bool
	}{
		{"u 前缀形式", "u" + itoa64(u.ID), u.ID, true},
		{"纯数字", itoa64(u.ID), u.ID, true},
		{"用户名", "alice", u.ID, true},
		{"空", "", 0, false},
		{"不存在的用户名", "nobody", 0, false},
		{"看着像数字但混了字母", "12ab", 0, false},
		{"u 前缀但不是数字", "uabc", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := resolveControlKickUser(ctx, gw, tc.raw)
			if ok != tc.wantOK || (ok && id != tc.wantID) {
				t.Fatalf("resolveControlKickUser(%q) = (%d,%v),want (%d,%v)",
					tc.raw, id, ok, tc.wantID, tc.wantOK)
			}
		})
	}

	// 没有 store 时按用户名查不了,但 u<id> / 纯数字仍该能解析。
	bare := &gatewayState{}
	if _, ok := resolveControlKickUser(ctx, bare, "alice"); ok {
		t.Fatal("没有 store 时用户名解析不出来,不该硬编一个 id")
	}
	if id, ok := resolveControlKickUser(ctx, bare, "u7"); !ok || id != 7 {
		t.Fatalf("u<id> 形式不依赖 store,got (%d,%v)", id, ok)
	}
}

// control socket 无鉴权,安全前提就是「只有 owner 能读这个文件」。
// 这几条 fail-closed 一旦失效,任何本地用户都能踢会话、改限速。
func TestPrepareControlSocketPath_FailsClosedOnUnsafeLocations(t *testing.T) {
	t.Run("空路径", func(t *testing.T) {
		if err := prepareControlSocketPath(""); err == nil {
			t.Fatal("空路径应报错")
		}
	})

	t.Run("父目录不存在时新建并收紧到 0700", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "sub", "nested")
		if err := prepareControlSocketPath(filepath.Join(dir, "c.sock")); err != nil {
			t.Fatalf("应能创建: %v", err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if info.Mode().Perm() != controlSocketDirMode {
			t.Fatalf("新建目录权限为 %v,应收紧到 %v —— "+
				"父目录能被别人写就意味着别人能删掉我们的 socket 再放一个自己的上去",
				info.Mode().Perm(), controlSocketDirMode)
		}
	})

	t.Run("父目录 group/other 可写且无 sticky 时拒绝", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "wide")
		if err := os.Mkdir(dir, 0o777); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		err := prepareControlSocketPath(filepath.Join(dir, "c.sock"))
		if err == nil {
			t.Fatal("在人人可写且无 sticky 的目录里放无鉴权 socket 应被拒绝 —— " +
				"本地任何用户都能 unlink 掉再 squat 一个,管理员的 kick/reload 就发给攻击者了")
		}
		if !strings.Contains(err.Error(), "权限不安全") {
			t.Fatalf("错误应说明是权限问题: %v", err)
		}
	})

	t.Run("带 sticky 的共享目录可以接受", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "sticky")
		if err := os.Mkdir(dir, 0o777); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		if err := prepareControlSocketPath(filepath.Join(dir, "c.sock")); err != nil {
			t.Fatalf("sticky 目录(如 /tmp)里别人删不掉我们的文件,应当放行: %v", err)
		}
	})

	t.Run("同名的普通文件不会被误删", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "c.sock")
		if err := os.WriteFile(p, []byte("运维放在这里的重要文件"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		err := prepareControlSocketPath(p)
		if err == nil {
			t.Fatal("同名的普通文件应报错而不是被删掉")
		}
		if _, serr := os.Stat(p); serr != nil {
			t.Fatalf("那个文件被删了: %v", serr)
		}
	})
}

// socket 文件本身必须是 0600。这是整个控制面唯一的门禁。
func TestStartControlSocket_SocketIsOwnerOnlyOrItRefusesToServe(t *testing.T) {
	// unix socket 路径有 ~104 字节上限,t.TempDir() 的路径在 macOS 上超了,
	// 所以跟别处一样落在 /tmp 下。
	dir, err := os.MkdirTemp("/tmp", "ctl")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	path := filepath.Join(dir, "c.sock")
	cleanup := startControlSocket(path, &gatewayState{})
	defer cleanup()

	deadline := time.Now().Add(2 * time.Second)
	var info os.FileInfo
	for time.Now().Before(deadline) {
		if info, err = os.Stat(path); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("socket 没建起来: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("socket 权限是 %v,group/other 位必须全 0 —— 控制面无鉴权,这是唯一的门禁", perm)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("路径上不是 socket: %v", info.Mode())
	}
}

func TestStartControlSocket_OffAndEmptyPathAreNoOps(t *testing.T) {
	for _, p := range []string{"off", "OFF", "  off  "} {
		t.Run("path="+p, func(t *testing.T) {
			cleanup := startControlSocket(p, &gatewayState{})
			if cleanup == nil {
				t.Fatal("关闭管理面时也要返回可调用的 cleanup")
			}
			cleanup()
			if _, err := os.Stat("off"); err == nil {
				t.Fatal("不该真的在当前目录建一个叫 off 的文件")
			}
		})
	}

	t.Run("路径准备失败时不启动但不崩", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "occupied")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cleanup := startControlSocket(p, &gatewayState{})
		if cleanup == nil {
			t.Fatal("失败时也要返回可调用的 cleanup")
		}
		cleanup()
	})
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
