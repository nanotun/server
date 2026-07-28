package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件是「Web 写路径」测试的公共脚手架。
//
// 这些 handler 此前几乎零覆盖:CLI 侧的同名操作都有测试,Web 侧没有,而两条路
// 各写各的表单解析与副作用。测法沿用 handler_routes_test.go 的成例 —— 绕过
// session/CSRF 中间件、直接调 handler,只钉「表单怎么解析、库里变成什么样、
// 控制面收到了什么」。CSRF 与 RBAC 由中间件负责,已有 e2e(60-web.sh)覆盖。

// newAdminPostRequest 造一个带 admin 身份的表单 POST(绕过 session 中间件)。
func newAdminPostRequest(t *testing.T, target string, form url.Values) *http.Request {
	t.Helper()
	body := ""
	if form != nil {
		body = form.Encode()
	}
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	admin := &store.WebAdmin{ID: 1, Username: "tester", Role: "admin"}
	return req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, admin))
}

// fakeControl 是一个假的 nanotund 控制面:按路由表响应,并记录收到的每个请求。
// 记录是为了断言「Web 改完之后确实通知了数据面」—— 只看 HTTP 状态码是看不出来的。
type fakeControl struct {
	client *controlClient
	mu     sync.Mutex
	reqs   []string
}

// newFakeControl 起监听并返回句柄。routes 的 key 是路径(如 "/reload"),
// 未列出的路径一律 404。
func newFakeControl(t *testing.T, routes map[string]http.HandlerFunc) *fakeControl {
	t.Helper()
	// unix socket 路径有 ~104 字节上限,t.TempDir() 会把测试名拼进去直接超限。
	dir, err := os.MkdirTemp("", "ntw")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	fc := &fakeControl{client: newControlClient(sock)}
	mux := http.NewServeMux()
	for path, h := range routes {
		mux.HandleFunc(path, h)
	}
	srv := &http.Server{Handler: http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fc.record(r)
			mux.ServeHTTP(w, r)
		})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return fc
}

func (f *fakeControl) record(r *http.Request) {
	line := r.Method + " " + r.URL.Path
	if r.URL.RawQuery != "" {
		line += "?" + r.URL.RawQuery
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, line)
	f.mu.Unlock()
}

func (f *fakeControl) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

// sawPath 报告是否收到过某个路径的请求(忽略 query)。
func (f *fakeControl) sawPath(path string) bool {
	for _, r := range f.requests() {
		if strings.Contains(r, " "+path) {
			return true
		}
	}
	return false
}

// controlOK 返回一个恒成功的控制面路由表(reload / rate refresh / kick)。
func controlOK() map[string]http.HandlerFunc {
	ok := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"count":0,"kicked":1}`))
	}
	return map[string]http.HandlerFunc{
		"/reload":             ok,
		"/rate/refresh":       ok,
		"/users/rate/refresh": ok,
		"/kick":               ok,
	}
}

// controlBroken 返回一个恒 500 的控制面:用来验证「数据面没收到 / 失败了」时
// Web 侧是否**如实告知**,而不是照样报成功。
func controlBroken() map[string]http.HandlerFunc {
	fail := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}
	return map[string]http.HandlerFunc{
		"/reload":             fail,
		"/rate/refresh":       fail,
		"/users/rate/refresh": fail,
		"/kick":               fail,
	}
}

// flashKindOf 从 redirect 的 Location(或裸 query 串)里取 flash_kind。
// flashQuery 在 kind=="ok" 时**省略**该参数,所以缺省即 "ok"。
func flashKindOf(t *testing.T, locationOrQuery string) string {
	t.Helper()
	q := locationOrQuery
	if i := strings.Index(q, "?"); i >= 0 {
		q = q[i+1:]
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		t.Fatalf("解析 flash query %q: %v", locationOrQuery, err)
	}
	if k := vals.Get("flash_kind"); k != "" {
		return k
	}
	return "ok"
}

// flashTextOf 取 flash 文案本体。
func flashTextOf(t *testing.T, locationOrQuery string) string {
	t.Helper()
	q := locationOrQuery
	if i := strings.Index(q, "?"); i >= 0 {
		q = q[i+1:]
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		t.Fatalf("解析 flash query %q: %v", locationOrQuery, err)
	}
	return vals.Get("flash")
}
