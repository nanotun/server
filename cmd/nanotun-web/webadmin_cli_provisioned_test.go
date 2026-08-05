package main

// webadmin_cli_provisioned_test.go —— 装机脚本建的后台账号,网页这边到底认不认。
//
// 背景:管理员现在有两条出生路径 —— 网页 /setup,和 `nanotun-admin webadmin create`
// (装机向导走的就是后者,为的是不把 /setup 那个「谁先打开谁是管理员」的窗口留在公网上)。
// 两条路各自都有测试,但它们中间那道缝没人守:CLI 用 auth.HashPSK 写哈希,网页登录用
// AttemptLogin 读。这两个函数各自都对,却完全可能对不上 —— 参数漂了、格式换了、
// 或者哪天有谁给 CLI 换了个「更合适」的哈希实现。
//
// 那种坏法尤其阴:CLI 说「已创建」,库里也确实有那一行,list 看着一切正常,只有等运维
// 第一次打开浏览器时才发现密码永远不对 —— 而那时候 /setup 早关了(表非空),他连抢救
// 入口都没有,只能进库手改。
//
// 所以这里不复述 CLI 的步骤,而是**真的把它编出来跑一遍**,再把库交给网页登录那条函数。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// provisionAdminViaCLI 编出 nanotun-admin,在 dbPath 上建一个 Web 管理员,返回合并输出。
func provisionAdminViaCLI(t *testing.T, dbPath, username, password string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "nanotun-admin")
	out, err := exec.Command("go", "build", "-o", bin, "../nanotun-admin").CombinedOutput()
	if err != nil {
		t.Fatalf("编 nanotun-admin: %v\n%s", err, out)
	}

	run := func(stdin string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, append([]string{"--db-path", dbPath}, args...)...)
		cmd.Stdin = strings.NewReader(stdin)
		// 宿主常导出 NANOTUN_DB / NANOTUN_WEB_ADMIN_PASSWORD 指向真环境;子进程必须与它们无关。
		cmd.Env = append(os.Environ(), "NANOTUN_DB=", "NANOTUN_LANG=", "NANOTUN_WEB_ADMIN_PASSWORD=")
		o, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("nanotun-admin %v: %v\n%s", args, e, o)
		}
		return string(o)
	}

	run("", "init")
	return run(password, "webadmin", "create", username, "--password-stdin")
}

// TestWebAdminProvisionedByCLI_CanActuallyLogIn 走网页登录用的同一个 AttemptLogin。
func TestWebAdminProvisionedByCLI_CanActuallyLogIn(t *testing.T) {
	if testing.Short() {
		t.Skip("要编 nanotun-admin 二进制")
	}
	dbPath := filepath.Join(t.TempDir(), "nanotun.db")
	const (
		user = "ops"
		pw   = "Str0ng-Console-Pass"
	)
	if out := provisionAdminViaCLI(t, dbPath, user, pw); !strings.Contains(out, user) {
		t.Fatalf("CLI 没说建了谁:%s", out)
	}

	ctx := t.Context()
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	cfg := defaultConfig()
	res := AttemptLogin(ctx, st, cfg, user, pw, "10.0.0.1")
	if res.Err != nil {
		t.Fatalf("装机脚本建的账号登不进网页:%v —— 后台从此无人进得去(/setup 已因表非空而关闭)", res.Err)
	}
	if res.Admin == nil || res.Admin.Username != user {
		t.Fatalf("登录成功但拿回来的不是这个人:%+v", res.Admin)
	}
	// 角色也得对:首位若是 viewer,控制台被永久锁成只读,而且没人能提权。
	if res.Admin.Role != "admin" {
		t.Fatalf("首位管理员角色 = %q,应为 admin", res.Admin.Role)
	}
}

// TestWebAdminProvisionedByCLI_WrongPasswordStillRejected:上一条若因为哈希退化成
// 「什么都验得过」而变绿,这条会揪出来。
func TestWebAdminProvisionedByCLI_WrongPasswordStillRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("要编 nanotun-admin 二进制")
	}
	dbPath := filepath.Join(t.TempDir(), "nanotun.db")
	provisionAdminViaCLI(t, dbPath, "ops", "Str0ng-Console-Pass")

	ctx := t.Context()
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	res := AttemptLogin(ctx, st, defaultConfig(), "ops", "Str0ng-Console-Pass-x", "10.0.0.1")
	if res.Err == nil {
		t.Fatal("错密码也登进去了")
	}
	if !errors.Is(res.Err, ErrAuthBadCredentials) {
		t.Fatalf("拒的理由不对:%v", res.Err)
	}
}

// TestWebAdminProvisionedByCLI_GetsASessionFromTheRealLoginHandler 把上面那条推到 HTTP 层。
//
// AttemptLogin 只回答「这对用户名密码算不算数」;而人在浏览器里点「登录」之后真正跑的是
// handleLogin —— 它还要过 CSRF、验证码,再决定发不发会话。装机脚本建的账号如果在这一层
// 被卡住(比如角色不对导致后续判定分叉、或者 enabled 位没置上),前面几条测试全绿,运维
// 照样进不去后台。所以这里走一遍完整的 POST /login,断言拿到的是会话而不是别的什么。
func TestWebAdminProvisionedByCLI_GetsASessionFromTheRealLoginHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("要编 nanotun-admin 二进制")
	}
	dbPath := filepath.Join(t.TempDir(), "nanotun.db")
	const (
		user = "ops"
		pw   = "Str0ng-Console-Pass"
	)
	provisionAdminViaCLI(t, dbPath, user, pw)

	ctx := t.Context()
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	stop := make(chan struct{})
	defer close(stop)
	s := &Server{
		cfg:            defaultConfig(),
		store:          st,
		sess:           NewSessionService(st, defaultConfig()),
		audit:          NewAuditor(st),
		tmpl:           tmpl,
		credFlash:      newCredentialsFlashStore(stop),
		stepUpFailures: NewIPFailureTracker(),
		startedAt:      time.Now(),
	}

	w := httptest.NewRecorder()
	s.handleLogin(w, loginPost(t, s, url.Values{
		"username": {user}, "password": {pw},
	}, "10.0.0.9"))

	if w.Code != http.StatusFound {
		t.Fatalf("code=%d,期望 302(登录成功后跳转);装机脚本建的账号在网页上登不进去", w.Code)
	}
	if !hasSessionCookie(w) {
		t.Fatal("没拿到会话 cookie —— 后台进不去")
	}
}
