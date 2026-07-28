package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 这一批补的是分发表、凭证 QR、会话联表、私钥落盘这几处 —— 它们要么只被
// happy path 扫过,要么根本没人碰过错误分支。

// routeAuthed 是登录后的总分发表。它的顺序有讲究:/routes/exit/ 必须排在
// 通配的 /routes/ 前面,否则 "exit" 会被当成 device_id 解析失败。这条测试
// 遍历每个分支,确认路径落到了对的 handler(而不是 404 或者错的那个)。
func TestRouteAuthed_EveryPathLandsOnItsOwnHandler(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "dispatcher", "pw-dispatch-123456")

	// 详情页的 handler 会去查库,查不到就是 404 —— 那样分不清「路由没接上」和
	// 「行不存在」。先把 id=1 的用户和设备种出来。
	u, err := s.store.CreateUser(t.Context(), store.NewUser{Username: "routed", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := s.store.UpsertDevice(t.Context(), u.ID, "route-uuid", "box", "linux"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	// 所有分支都用 GET 走一遍:关心的是"有没有被分发出去",不是 handler 内部结果。
	// 404 说明这条路径掉出了分发表 —— 那就是页面上一个点不开的链接。
	paths := []string{
		"/", "/users", "/users/new", "/users/1",
		"/devices", "/devices/1",
		"/leases", "/leases/1",
		"/acl", "/acl/new", "/acl/1",
		"/routes", "/routes/exit/1", "/routes/1/10.0.0.0%2F8/approve",
		"/port-forwards", "/port-forwards/new", "/port-forwards/1",
		"/sessions", "/me", "/me/totp/setup",
		"/audit", "/admins", "/admins/new", "/admins/1",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := withAdminCtx(httptest.NewRequest(http.MethodGet, p, nil), admin)
			w := httptest.NewRecorder()
			s.routeAuthed(w, req)
			if w.Code == http.StatusNotFound {
				t.Fatalf("%s 掉出了分发表 —— 页面上会是一个点不开的链接", p)
			}
		})
	}

	t.Run("认不出的路径给 404", func(t *testing.T) {
		req := withAdminCtx(httptest.NewRequest(http.MethodGet, "/根本没有这个页面", nil), admin)
		w := httptest.NewRecorder()
		s.routeAuthed(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("code=%d,期望 404", w.Code)
		}
	})

	// /routes/exit/ 排在 /routes/ 之前:顺序反了的话 exit 指定功能整个失效。
	t.Run("exit 前缀优先于通配的 routes 前缀", func(t *testing.T) {
		req := withAdminCtx(httptest.NewRequest(http.MethodGet, "/routes/exit/1", nil), admin)
		w := httptest.NewRecorder()
		s.routeAuthed(w, req)
		// handleRouteAction 会拿 "exit" 去 parseInt 然后 400;落到 handleExitAction
		// 则是 405(它只收 POST)。用这个差别区分究竟进了谁。
		if w.Code == http.StatusBadRequest {
			t.Fatal("被通配的 /routes/ 抢走了 —— \"exit\" 被当成了 device_id")
		}
	})
}

// web_sessions 表没人清理就会一直涨:每次登录一行,过期了也不删。
func TestRunSessionGC_ActuallyPrunesAndStopsWithTheContext(t *testing.T) {
	s := newServerQRTestServer(t)
	ctx := t.Context()

	admin := createTestAdmin(t, s, "gcadmin", "pw-gc-1234567890")
	// 一条早就过期的会话 + 一条还活着的。GC 只该动前者。
	const deadSID = "sess_dead_aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Now().Unix()
	if err := s.store.CreateWebSession(ctx, store.WebSession{
		ID: deadSID, AdminID: admin.ID, CreatedAt: now - 7200, ExpiresAt: now - 3600,
	}); err != nil {
		t.Fatalf("CreateWebSession(过期): %v", err)
	}
	liveCookie, liveSID := loginAs(t, s, admin)
	_ = liveCookie

	old := sessionGCInterval
	sessionGCInterval = 10 * time.Millisecond
	t.Cleanup(func() { sessionGCInterval = old })

	gctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); s.runSessionGC(gctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := s.store.GetWebSession(ctx, deadSID); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("等了 5 秒过期会话还在 —— GC 循环没真的跑清理")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := s.store.GetWebSession(ctx, liveSID); err != nil {
		t.Fatalf("把还没过期的会话也清掉了(用户会被莫名踢下线): %v", err)
	}

	// ctx 取消后必须退出,否则进程关不干净。
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后 GC 循环没退出")
	}
}

func TestBuildCredentialsURLAndQR_EmitsAScannablePayloadOrNothingAtAll(t *testing.T) {
	const credID = "6f1d4f2e-0000-4000-8000-000000000001"

	t.Run("正常出 URL + PNG", func(t *testing.T) {
		u, qr := buildCredentialsURLAndQR(credID, "alice", "psk-plain", 1_700_000_000,
			"vpn.example.com", "srv-1")
		if u == "" {
			t.Fatal("URL 是空的")
		}
		if !strings.HasPrefix(u, "nanotun-cred://") {
			t.Fatalf("scheme 不对,客户端认不出来: %q", u)
		}
		if !strings.HasPrefix(string(qr), "data:image/png;base64,") {
			t.Fatalf("QR 应是内联 data URL(页面直接 <img src>): %q", qr[:min(40, len(qr))])
		}

		// 扫出来的东西要能解回同一份凭证 —— 否则客户端扫了个寂寞。
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(u, util.CredentialsURLPrefix))
		if err != nil {
			t.Fatalf("payload 不是合法 base64url: %v", err)
		}
		var got util.CredentialsSchema
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("payload 不是合法 JSON: %v", err)
		}
		if got.ID != credID || got.Username != "alice" || got.PSK != "psk-plain" {
			t.Fatalf("round-trip 掉字段: %+v", got)
		}
		if got.Host != "vpn.example.com" || got.ServerID != "srv-1" {
			t.Fatalf("host/server_id 丢了,客户端不知道连哪台: %+v", got)
		}
	})

	// 缺 credential_id 或 PSK 时宁可什么都不给:一张缺字段的二维码扫进客户端
	// 只会变成一个连不上、又看不出为什么的配置。
	t.Run("缺关键字段就两个都空", func(t *testing.T) {
		cases := []struct{ credID, psk string }{
			{"", "psk"}, {"   ", "psk"}, {credID, ""}, {credID, "  "}, {"", ""},
		}
		for _, tc := range cases {
			u, qr := buildCredentialsURLAndQR(tc.credID, "alice", tc.psk, 0, "h", "s")
			if u != "" || qr != "" {
				t.Fatalf("credID=%q psk=%q 却给了 (%q,%q)", tc.credID, tc.psk, u, qr)
			}
		}
	})

	t.Run("host 为空也照出", func(t *testing.T) {
		// 还没配 advertised_host 的新装机器就是这个状态,不能因此不给凭证。
		u, qr := buildCredentialsURLAndQR(credID, "alice", "psk", 0, "", "")
		if u == "" || qr == "" {
			t.Fatalf("got (%q,%q)", u, qr)
		}
	})
}

// /sessions 页面靠 collectSessionsForView 把控制面的 session 列表和库里的
// user/device 联起来。控制面出错要如实报错,联表查不到只能留空 —— 不能整页崩掉。
func TestCollectSessionsForView_JoinsStoreDataAndSurvivesMissingRows(t *testing.T) {
	s := newTestServerMinimal(t)
	ctx := t.Context()

	u, err := s.store.CreateUser(ctx, store.NewUser{Username: "sessuser", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	d, err := s.store.UpsertDevice(ctx, u.ID, "aaaa-bbbb", "laptop", "macos")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	statusJSON := func(sessions string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"sessions":` + sessions + `}`))
		}
	}

	t.Run("联上 username 和 device_name", func(t *testing.T) {
		body, _ := json.Marshal([]map[string]any{{
			"conn_id":     "c1",
			"user_id":     "u" + strconv.FormatInt(u.ID, 10),
			"device_id":   d.ID,
			"device_uuid": "aaaa-bbbb",
			"vips":        []string{"10.80.0.5", "fd00::5"},
			"link_ready":  true,
		}})
		fc := newFakeControl(t, map[string]http.HandlerFunc{"/status": statusJSON(string(body))})
		s.control = fc.client

		views, err := s.collectSessionsForView(ctx)
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if len(views) != 1 {
			t.Fatalf("应有 1 条,got %d", len(views))
		}
		v := views[0]
		if v.Username != "sessuser" {
			t.Fatalf("username 没联上: %+v —— 页面上就只剩一串 u<id>", v)
		}
		if v.DeviceName != d.DisplayName() || v.Platform != "macos" {
			t.Fatalf("设备信息没联上: %+v", v)
		}
		// v4/v6 要分列显示,混在一起的话表格里 IPv6 会挤掉 IPv4 那列。
		if v.VIPv4 != "10.80.0.5" || v.VIPv6 != "fd00::5" {
			t.Fatalf("v4/v6 分列错了: v4=%q v6=%q", v.VIPv4, v.VIPv6)
		}
		if !v.LinkReady {
			t.Fatal("link_ready 丢了")
		}
	})

	t.Run("user/device 查不到就留空,不影响其它行", func(t *testing.T) {
		body, _ := json.Marshal([]map[string]any{
			{"conn_id": "c-ghost", "user_id": "u999999", "device_id": 999999},
			{"conn_id": "c-anon", "user_id": ""},
			{"conn_id": "c-ok", "user_id": "u" + strconv.FormatInt(u.ID, 10), "device_id": d.ID},
		})
		fc := newFakeControl(t, map[string]http.HandlerFunc{"/status": statusJSON(string(body))})
		s.control = fc.client

		views, err := s.collectSessionsForView(ctx)
		if err != nil {
			t.Fatalf("查不到的行不该让整页失败: %v", err)
		}
		if len(views) != 3 {
			t.Fatalf("三行都该保留,got %d", len(views))
		}
		if views[0].Username != "" || views[0].DeviceName != "" {
			t.Fatalf("查不到就该留空: %+v", views[0])
		}
		if views[1].StoreUserID != 0 {
			t.Fatalf("匿名会话不该解出 user id: %+v", views[1])
		}
		if views[2].Username != "sessuser" {
			t.Fatalf("正常那行被前面的坏行带崩了: %+v", views[2])
		}
	})

	t.Run("控制面不通如实报错", func(t *testing.T) {
		s.control = newControlClient("/tmp/绝对不存在的.sock")
		if _, err := s.collectSessionsForView(ctx); err == nil {
			t.Fatal("应报错 —— 静默返回空列表会被看成「当前无人在线」")
		}
	})

	t.Run("控制面回垃圾", func(t *testing.T) {
		fc := newFakeControl(t, map[string]http.HandlerFunc{
			"/status": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("不是 JSON")) }})
		s.control = fc.client
		if _, err := s.collectSessionsForView(ctx); err == nil {
			t.Fatal("解不出来要报错")
		}
	})
}

// writePEMFile 落的是自签的 EC 私钥。它刻意走「随机名临时文件 → fchmod → fsync
// → 原子 rename」,为的是不跟随符号链接、不留世界可读窗口。
func TestWritePEMFile_LandsAtomicallyWithTheRequestedMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	der := []byte{0x30, 0x01, 0x02, 0x03}

	if err := writePEMFile(path, "EC PRIVATE KEY", der, 0o600); err != nil {
		t.Fatalf("writePEMFile: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "EC PRIVATE KEY" || string(blk.Bytes) != string(der) {
		t.Fatalf("PEM 内容不对: %q", raw)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("权限 0o%o —— 私钥不能给 group/others 看到", perm)
	}

	// 不留临时文件:每次续签都漏一个 .tmp-xxxx 的话,CertDir 会慢慢堆满。
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("目录里剩了临时文件: %v", names)
	}

	t.Run("覆盖已有文件", func(t *testing.T) {
		der2 := []byte{0xAA, 0xBB}
		if err := writePEMFile(path, "CERTIFICATE", der2, 0o644); err != nil {
			t.Fatalf("writePEMFile: %v", err)
		}
		raw, _ := os.ReadFile(path)
		blk, _ := pem.Decode(raw)
		if blk == nil || blk.Type != "CERTIFICATE" || string(blk.Bytes) != string(der2) {
			t.Fatalf("没覆盖成功: %q", raw)
		}
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o644 {
			t.Fatalf("权限 0o%o", st.Mode().Perm())
		}
	})

	t.Run("目录不存在时报错而不是静默丢失", func(t *testing.T) {
		err := writePEMFile(filepath.Join(dir, "没有这个目录", "key.pem"), "X", der, 0o600)
		if err == nil {
			t.Fatal("应报错 —— 静默失败会让服务带着一份不存在的证书起来")
		}
		if !strings.Contains(err.Error(), "create temp") {
			t.Fatalf("错误里应说明是哪一步失败: %v", err)
		}
	})
}

// 模板函数注册表:漏注册一个,用到它的页面在渲染期整页 500,而且只有访问到
// 那一页才发现。这里把每个函数都在真模板里跑一遍。
func TestTemplateFuncs_EveryRegisteredHelperActuallyRuns(t *testing.T) {
	fm := templateFuncs()

	for _, name := range []string{
		"fmtTime", "fmtDuration", "fmtBool", "fmtBytes", "rateBytes",
		"trim", "upper", "lower", "isEmpty", "join", "contains",
		"add", "sub", "int64", "qrPayload", "T", "Th",
	} {
		if _, ok := fm[name]; !ok {
			t.Errorf("模板函数 %q 没注册 —— 用到它的页面会整页 500", name)
		}
	}

	src := `{{fmtTime 0}}|{{fmtDuration 0}}|{{fmtBool true}}|{{fmtBytes 2048}}|` +
		`{{rateBytes 1048576}}|{{trim "  x  "}}|{{upper "a"}}|{{lower "B"}}|` +
		`{{isEmpty "  "}}|{{join .List ","}}|{{contains "abc" "b"}}|` +
		`{{add 1 2}}|{{sub 5 3}}|{{int64 .N}}|{{qrPayload "seed"}}|{{T "nav.users"}}`
	tmpl, err := template.New("x").Funcs(fm).Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, map[string]any{"List": []string{"a", "b"}, "N": 7}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := sb.String()
	for _, want := range []string{"2.0 KiB", "x", "A", "b", "true", "a,b", "3", "2", "7"} {
		if !strings.Contains(out, want) {
			t.Fatalf("输出里缺 %q:\n%s", want, out)
		}
	}
	// T 应当解出真实译文,而不是把 key 原样吐出来。
	if strings.Contains(out, "nav.users") {
		t.Fatalf("i18n 没绑上,页面上会显示成 key:\n%s", out)
	}
}

func TestHandleUserNew_ValidatesBeforeItEverTouchesTheStore(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "usercreator", "pw-create-1234567")
	admin.Role = "admin"

	post := func(form url.Values) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleUserNew(w, mePost(t, s, admin, "/users/new", form, ""))
		return w
	}
	countUsers := func() int {
		rows, err := s.store.ListUsersAll(t.Context())
		if err != nil {
			t.Fatalf("ListUsersAll: %v", err)
		}
		return len(rows)
	}

	t.Run("GET 渲染空表单", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleUserNew(w, withAdminCtx(httptest.NewRequest(http.MethodGet, "/users/new", nil), admin))
		if w.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("用户名为空", func(t *testing.T) {
		before := countUsers()
		w := post(url.Values{"username": {"   "}})
		if w.Code != http.StatusOK {
			t.Fatalf("应回表单页(带错误提示),code=%d", w.Code)
		}
		if countUsers() != before {
			t.Fatal("空用户名却建出了账号")
		}
	})

	t.Run("平台白名单里塞了不认识的值", func(t *testing.T) {
		before := countUsers()
		w := post(url.Values{"username": {"platuser"}, "platforms": {"macos", "塞班"}})
		if w.Code != http.StatusOK {
			t.Fatalf("code=%d", w.Code)
		}
		if countUsers() != before {
			t.Fatal("非法平台却建出了账号")
		}
		// 页面上不能出现 store 层的英文原文 —— 那是内部实现细节。
		if strings.Contains(w.Body.String(), "store:") {
			t.Fatalf("把 store 层错误原样回显到页面了:\n%s", w.Body.String())
		}
	})

	t.Run("重名给友好提示而不是 500", func(t *testing.T) {
		if w := post(url.Values{"username": {"dupuser"}}); w.Code != http.StatusSeeOther {
			t.Fatalf("首次创建 code=%d body=%s", w.Code, w.Body.String())
		}
		before := countUsers()
		w := post(url.Values{"username": {"dupuser"}})
		if w.Code == http.StatusInternalServerError {
			t.Fatal("重名是可操作的用户级反馈,不该是 500")
		}
		if countUsers() != before {
			t.Fatal("重名却又建了一个")
		}
	})

	t.Run("正常创建同时分配 credential_id", func(t *testing.T) {
		w := post(url.Values{"username": {"freshuser"}, "is_admin": {"on"}, "exit_allowed": {"on"}})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
		}
		u, err := s.store.GetUserByUsername(t.Context(), "freshuser")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		if u.CredentialID == "" {
			t.Fatal("建号时没分配 credential_id —— 客户端首次扫码就拿不到 UUID")
		}
		if u.CredentialCreatedAt == 0 {
			t.Fatal("credential_created_at 是 0")
		}
		if !u.IsAdmin || !u.ExitAllowed {
			t.Fatalf("勾选项没落库: %+v", u)
		}
		// 一次性展示页的跳转里不能带明文 PSK。
		if loc := w.Header().Get("Location"); strings.Contains(loc, u.PSKHash) || strings.Contains(loc, "psk=") {
			t.Fatalf("跳转 URL 里带了凭证: %q", loc)
		}
	})
}
