package main

// main_startup_guards_test.go(第二十一轮)—— 启动编排。
//
// main() 本体没法在测试进程里跑(全局 flag、logrus.Fatal、ListenAndServeTLS),
// 所以分两层测:
//
//   1. 能抽出来的部件(flag 优先级、模板装载、session GC 循环)直接单测;
//   2. 整条启动路径编一个真二进制、当子进程跑 —— 这是唯一能验证「配置错了会不会
//      拒绝启动」「起来之后 TLS 是否真能握手」「收到 SIGTERM 是否干净退出」的方式。
//
// 第 2 层特别重要:这三件事错了都不会在任何单测里露头,只会在部署那一刻表现为
// 「服务起不来」或者更糟的「起来了但监听在预期之外的地址上」。

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nanotun/server/store"
)

// =========================================================================
// flag / env 优先级
// =========================================================================

// 显式 -allow-setup=false 必须压过环境变量。压不过的话,systemd unit 里留的
// NANOTUN_WEB_ALLOW_SETUP=1 会把 /setup 重新打开 —— 那是一个「谁先到谁当管理员」
// 的接口,对公网开着等于把后台送人。
func TestApplyFlagPrecedence_ExplicitAllowSetupBeatsEnv(t *testing.T) {
	t.Setenv("NANOTUN_WEB_ALLOW_SETUP", "1")
	cfg := defaultConfig()
	applyFlagPrecedence(&cfg, map[string]bool{"allow-setup": true}, flagOverrides{allowSetup: false})
	if cfg.AllowSetup {
		t.Fatal("显式 -allow-setup=false 被环境变量压回去了 —— /setup 会对公网敞开")
	}

	// 反向:没显式给 flag 时,env 说什么就是什么。
	cfg = defaultConfig()
	cfg.AllowSetup = false
	applyFlagPrecedence(&cfg, map[string]bool{}, flagOverrides{})
	if !cfg.AllowSetup {
		t.Fatal("没给 flag 时 env 的 ALLOW_SETUP=1 没生效")
	}
}

// =========================================================================
// 模板装载
// =========================================================================

func TestLoadTemplates_FailuresAreReportedAtStartup(t *testing.T) {
	stubTemplateFS := func(t *testing.T, f fs.FS) {
		t.Helper()
		orig := templateSourceFS
		templateSourceFS = f
		t.Cleanup(func() { templateSourceFS = orig })
	}

	t.Run("模板语法错要在启动时就炸", func(t *testing.T) {
		stubTemplateFS(t, fstest.MapFS{
			"templates/broken.html": &fstest.MapFile{Data: []byte(`{{if .Oops}}没有 end`)},
		})
		if _, err := loadTemplates(); err == nil {
			t.Fatal("模板语法错却装载成功 —— 会变成用户点到那一页才 500")
		} else if !strings.Contains(err.Error(), "broken.html") {
			t.Fatalf("err=%v, 没指出是哪个模板", err)
		}
	})

	t.Run("非 html 文件跳过而不是当模板 parse", func(t *testing.T) {
		stubTemplateFS(t, fstest.MapFS{
			"templates/ok.html":     &fstest.MapFile{Data: []byte(`hi`)},
			"templates/README.md":   &fstest.MapFile{Data: []byte("{{ 这不是模板 }}")},
			"templates/partials/.x": &fstest.MapFile{Data: []byte("{{ 也不是 }}")},
		})
		tm, err := loadTemplates()
		if err != nil {
			t.Fatalf("非模板文件把装载搞崩了: %v", err)
		}
		if tm.Lookup("ok.html") == nil {
			t.Fatal("正常模板没装进去")
		}
		if tm.Lookup("README.md") != nil {
			t.Fatal("非 .html 文件被当模板装进去了")
		}
	})

	t.Run("读不出文件内容要报错", func(t *testing.T) {
		stubTemplateFS(t, unreadableFS{
			FS:   fstest.MapFS{"templates/a.html": &fstest.MapFile{Data: []byte("hi")}},
			deny: "templates/a.html",
		})
		if _, err := loadTemplates(); err == nil {
			t.Fatal("模板读不出来却报装载成功")
		}
	})

	t.Run("遍历出错要往上抛", func(t *testing.T) {
		// 连 templates 目录都不存在:WalkDir 的第一次回调就带着错误进来。
		stubTemplateFS(t, fstest.MapFS{"other/a.html": &fstest.MapFile{Data: []byte("hi")}})
		if _, err := loadTemplates(); err == nil {
			t.Fatal("模板目录整个不存在却报装载成功")
		}
	})
}

// 语言模板集构建失败必须往上抛。这一步是启动时一次性付掉 Clone 成本,失败了
// 若兜底成 nil map,每个请求都会走 renderPage 里的逐请求 Clone —— 页面还能开,
// 但每次渲染多一次深拷贝,而且没人知道降级了。
func TestBuildLangTemplates_CloneFailureIsReported(t *testing.T) {
	spent := template.Must(template.New("spent").Parse("hi"))
	if err := spent.Execute(io.Discard, nil); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := buildLangTemplates(spent); err == nil {
		t.Fatal("已执行过的模板不可 Clone,这里却报成功")
	}

	// 正常情况下每种支持语言都要有一套,漏一种会让该语言的用户看到英文兜底。
	got, err := buildLangTemplates(template.Must(template.New("t.html").Parse("hi")))
	if err != nil {
		t.Fatalf("buildLangTemplates: %v", err)
	}
	for _, lang := range supportedLangs {
		if got[lang] == nil {
			t.Errorf("语言 %s 没有对应的模板集", lang)
		}
	}
}

// unreadableFS 让指定路径 Open 失败,用来模拟「文件在,但读不出来」。
type unreadableFS struct {
	fs.FS
	deny string
}

func (u unreadableFS) Open(name string) (fs.File, error) {
	if name == u.deny {
		return nil, errors.New("injected: 读不出来")
	}
	return u.FS.Open(name)
}

// =========================================================================
// session GC 循环
// =========================================================================

// 清理失败时必须继续跑下一跳(过期会话的清理本身已由
// TestRunSessionGC_ActuallyPrunesAndStopsWithTheContext 覆盖)。
// 停在第一个错误上的话,web_sessions 表会一直长 —— 长到几十万行之后每次登录校验
// 都要扫过它们,后台整体变慢,而没有任何一条日志指向真正的原因。
func TestRunSessionGC_KeepsTickingAfterAFailedSweep(t *testing.T) {
	s := newMeTestServer(t)
	orig := sessionGCInterval
	sessionGCInterval = 5 * time.Millisecond
	t.Cleanup(func() { sessionGCInterval = orig })

	// 让清理必然失败:直接把表改名。GC 应该记一条 Warn 然后继续跑,不能退出循环。
	if _, err := s.store.DB().ExecContext(t.Context(),
		`ALTER TABLE web_sessions RENAME TO web_sessions_hidden`); err != nil {
		t.Fatalf("藏表: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		s.runSessionGC(ctx)
		close(done)
	}()

	// 给它跑几跳的时间;只要没提前退出就说明失败不会终结循环。
	time.Sleep(60 * time.Millisecond)
	select {
	case <-done:
		cancel()
		t.Fatal("一次清理失败就把 GC 循环终结了 —— 之后 web_sessions 再没人清")
	default:
	}

	// ctx 取消是唯一的退出条件。
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后 GC 循环没退出")
	}
}

// =========================================================================
// 整条启动路径:编真二进制,当子进程跑
// =========================================================================

var (
	webBinOnce sync.Once
	webBinPath string
	webBinErr  error
)

// subprocCoverDir:设了它就把子进程的语句计数落到该目录(需要 go1.20+ 的
// `go build -cover`)。
//
// main() 的函数体在测试进程里跑不到 —— 全局 flag 只能 Parse 一次、logrus.Fatal
// 直接 exit、ListenAndServeTLS 要真的占端口。下面这几个子进程测试验的是它的**行为**,
// 但那份覆盖数据落在子进程里,`go test -coverprofile` 收不到。给覆盖率流水线一个
// 开关:设上 NANOTUN_SUBPROC_COVERDIR,再用 `go tool covdata textfmt` 把它并进基线,
// 启动编排那 90 多条语句才会出现在分子里(见 docs/COVERAGE.md)。
const subprocCoverDirEnv = "NANOTUN_SUBPROC_COVERDIR"

// buildWebBinary 把 nanotun-web 编出来(每次测试运行只编一次)。
func buildWebBinary(t *testing.T) string {
	t.Helper()
	webBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "nanotun-web-bin-*")
		if err != nil {
			webBinErr = err
			return
		}
		bin := filepath.Join(dir, "nanotun-web")
		args := []string{"build", "-o", bin}
		if os.Getenv(subprocCoverDirEnv) != "" {
			args = append(args, "-cover", "-covermode=atomic",
				"-coverpkg=github.com/nanotun/server/...")
		}
		cmd := exec.Command("go", append(args, ".")...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			webBinErr = fmt.Errorf("go build: %v\n%s", err, out)
			return
		}
		webBinPath = bin
	})
	if webBinErr != nil {
		t.Fatalf("编 nanotun-web: %v", webBinErr)
	}
	return webBinPath
}

// subprocEnv 给子进程补上 GOCOVERDIR(没开插桩时返回原样)。
func subprocEnv(t *testing.T, env []string) []string {
	t.Helper()
	dir := os.Getenv(subprocCoverDirEnv)
	if dir == "" {
		return env
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("建 GOCOVERDIR: %v", err)
	}
	return append(env, "GOCOVERDIR="+dir)
}

// runWebBinary 跑一次二进制并等它自己退出,返回退出码与合并输出。
func runWebBinary(t *testing.T, args []string, env []string, timeout time.Duration) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, buildWebBinary(t), args...)
	cmd.Env = append(os.Environ(), subprocEnv(t, env)...)
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("跑二进制: %v\n%s", err, out)
	}
	return code, string(out)
}

// -version 要打印版本并立刻退出,不能顺手去开数据库 / 建证书 ——
// 运维在装机脚本里就靠它探版本,那时 /var/lib 可能还不存在。
func TestWebBinary_VersionExitsCleanlyWithoutTouchingAnything(t *testing.T) {
	if testing.Short() {
		t.Skip("要编二进制,-short 下跳过")
	}
	code, out := runWebBinary(t, []string{"-version"}, nil, 60*time.Second)
	if code != 0 {
		t.Fatalf("exit=%d, 期望 0\n%s", code, out)
	}
	if !strings.Contains(out, "nanotun-web") {
		t.Fatalf("没打印版本: %q", out)
	}
	if strings.Contains(out, "打开数据库") || strings.Contains(out, "TLS") {
		t.Fatalf("-version 顺手做了别的事: %q", out)
	}
}

// 配置不合法必须拒绝启动(非 0 退出),不能带着一份坏配置跑起来。
// 尤其是 lockout-seconds=0:那会让账号锁定永不生效,而服务看着一切正常。
func TestWebBinary_RefusesToStartOnBadConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("要编二进制,-short 下跳过")
	}
	base := t.TempDir()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"库路径是相对路径", []string{"-db", "web.db"}},
		{"锁定时长为 0", []string{"-db", filepath.Join(base, "a.db"), "-lockout-seconds", "0"}},
		{"监听地址没端口", []string{"-db", filepath.Join(base, "b.db"), "-listen", "0.0.0.0"}},
		{"可信反代写错", []string{"-db", filepath.Join(base, "c.db"), "-trusted-proxies", "10.0.0.0/33"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(tc.args, "-cert-dir", filepath.Join(base, "certs"))
			code, out := runWebBinary(t, args, nil, 60*time.Second)
			if code == 0 {
				t.Fatalf("坏配置却启动成功了\n%s", out)
			}
			if !strings.Contains(out, "配置校验失败") {
				t.Fatalf("退出原因不是配置校验: %q", out)
			}
		})
	}
}

// 启动期的致命故障必须让进程退出(非 0),而不是「起来了但少半条腿」:
// 数据库打不开却在监听,用户会看到一堆 500;证书建不出来却在监听,浏览器
// 连不上却又没有任何日志说清原因。systemd 是 Restart=on-failure,退出才有重试。
func TestWebBinary_FatalStartupFailuresExitNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("要编二进制,-short 下跳过")
	}
	base := t.TempDir()

	t.Run("库路径指向一个目录", func(t *testing.T) {
		dbAsDir := filepath.Join(base, "db-is-a-dir")
		if err := os.Mkdir(dbAsDir, 0o700); err != nil {
			t.Fatalf("造目录: %v", err)
		}
		code, out := runWebBinary(t, []string{
			"-listen", "127.0.0.1:" + itoa(int64(freePort(t))),
			"-db", dbAsDir,
			"-cert-dir", filepath.Join(base, "certs-a"),
		}, nil, 60*time.Second)
		if code == 0 {
			t.Fatalf("库打不开却启动成功\n%s", out)
		}
		if !strings.Contains(out, "打开数据库") && !strings.Contains(out, "迁移") {
			t.Fatalf("退出原因看不出是数据库问题: %q", out)
		}
	})

	t.Run("证书目录被一个普通文件挡住", func(t *testing.T) {
		blocker := filepath.Join(base, "not-a-dir")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("造挡路文件: %v", err)
		}
		code, out := runWebBinary(t, []string{
			"-listen", "127.0.0.1:" + itoa(int64(freePort(t))),
			"-db", filepath.Join(base, "certfail.db"),
			"-cert-dir", filepath.Join(blocker, "certs"),
		}, nil, 60*time.Second)
		if code == 0 {
			t.Fatalf("证书建不出来却启动成功\n%s", out)
		}
		if !strings.Contains(out, "TLS 证书") {
			t.Fatalf("退出原因看不出是证书问题: %q", out)
		}
	})

	t.Run("端口已被占用", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("占端口: %v", err)
		}
		defer func() { _ = ln.Close() }()
		code, out := runWebBinary(t, []string{
			"-listen", ln.Addr().String(),
			"-db", filepath.Join(base, "portfail.db"),
			"-cert-dir", filepath.Join(base, "certs-b"),
		}, nil, 60*time.Second)
		if code == 0 {
			t.Fatalf("端口被占却报启动成功(而且没人在服务)\n%s", out)
		}
		if !strings.Contains(out, "HTTP server") {
			t.Fatalf("退出原因看不出是监听失败: %q", out)
		}
	})
}

// 迁移失败必须拒绝启动。带着一份旧 schema 跑起来最坏:读得到、写不进,
// 每个写操作在不同的地方以不同的方式失败,现场极难判断。
func TestWebBinary_RefusesToStartWhenMigrationCannotApply(t *testing.T) {
	if testing.Short() {
		t.Skip("要编二进制,-short 下跳过")
	}
	base := t.TempDir()
	dbPath := filepath.Join(base, "conflict.db")

	// 造一个能打开、但迁移必然撞车的库:预先占用 users 这个表名(且形状不对)。
	st, err := store.Open(t.Context(), dbPath, store.Options{})
	if err != nil {
		t.Fatalf("建库: %v", err)
	}
	if _, err := st.DB().ExecContext(t.Context(),
		`CREATE TABLE users (whatever INTEGER)`); err != nil {
		t.Fatalf("占表名: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("关库: %v", err)
	}

	code, out := runWebBinary(t, []string{
		"-listen", "127.0.0.1:" + itoa(int64(freePort(t))),
		"-db", dbPath,
		"-cert-dir", filepath.Join(base, "certs"),
	}, nil, 60*time.Second)
	if code == 0 {
		t.Fatalf("迁移撞车却启动成功\n%s", out)
	}
	if !strings.Contains(out, "迁移") {
		t.Fatalf("退出原因看不出是迁移失败: %q", out)
	}
}

// 全新安装 + setup 向导开着 + 监听地址不是环回 = 谁先连上谁当管理员。
// 这个组合必须在启动日志里显著告警,否则运维只会在事后从审计里看到一个
// 陌生的首个管理员。
//
// 这里故意让证书那一步失败:告警发生在监听之前,于是进程打完就退出,
// 测试全程不会真的把端口开到公网上。
func TestWebBinary_WarnsAboutPublicSetupOnAFreshInstall(t *testing.T) {
	if testing.Short() {
		t.Skip("要编二进制,-short 下跳过")
	}
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("造挡路文件: %v", err)
	}
	code, out := runWebBinary(t, []string{
		"-listen", "0.0.0.0:" + itoa(int64(freePort(t))),
		"-db", filepath.Join(base, "fresh.db"),
		"-cert-dir", filepath.Join(blocker, "certs"), // 保证在监听之前就退出
	}, nil, 60*time.Second)
	if code == 0 {
		t.Fatalf("这一路本该在建证书时退出\n%s", out)
	}
	if !strings.Contains(out, "抢占首个管理员") {
		t.Fatalf("没有 TOFU 抢占告警:\n%s", out)
	}
	// server_dial_host 未配置的启动告警同理:漏了它,QR 功能瘫痪却只有
	// dashboard 上一行红字,监控完全看不到。
	if !strings.Contains(out, "server_dial_host") {
		t.Errorf("没有 server_dial_host 未配置告警:\n%s", out)
	}
}

// -v 与 -trusted-proxies 这两个开关要真的生效:前者决定 journalctl 里有没有
// debug 细节,后者决定 X-Forwarded-For 到底认不认 —— 认错了审计与限流会一起
// 记到反代的地址上,等于对真实来源失明。
func TestWebBinary_VerboseAndTrustedProxiesTakeEffect(t *testing.T) {
	if testing.Short() {
		t.Skip("要编二进制,-short 下跳过")
	}
	base := t.TempDir()
	// 故意配一个坏的可信反代:进程会在打完这两条启动日志之前退出,
	// 免得测试还要去起一个真监听。
	code, out := runWebBinary(t, []string{
		"-v",
		"-trusted-proxies", "127.0.0.1,10.0.0.0/8",
		"-db", "relative-on-purpose.db",
		"-cert-dir", filepath.Join(base, "certs"),
	}, nil, 60*time.Second)
	if code == 0 {
		t.Fatalf("相对库路径却启动成功\n%s", out)
	}
	// -v 这一路本身没有 debug 输出可断言(启动期都是 info 级),这里只保证它
	// 不改变启动判定:同一份坏配置带不带 -v 都必须被拒。
	if !strings.Contains(out, "配置校验失败") {
		t.Fatalf("带 -v 之后连拒绝原因都变了: %q", out)
	}

	// 可信反代生效的证据要在真正起服务的那一路看:换一份合法配置跑起来。
	addr := "127.0.0.1:" + itoa(int64(freePort(t)))
	cmd := exec.Command(buildWebBinary(t),
		"-trusted-proxies", "127.0.0.1,10.0.0.0/8",
		"-listen", addr,
		"-db", filepath.Join(base, "ok.db"),
		"-cert-dir", filepath.Join(base, "certs-ok"),
	)
	cmd.Env = append(os.Environ(), subprocEnv(t, nil)...)
	var mu sync.Mutex
	var buf strings.Builder
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := pr.Read(b)
			if n > 0 {
				mu.Lock()
				buf.Write(b[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
		_ = pw.Close()
	})

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := buf.String()
		mu.Unlock()
		if strings.Contains(got, "X-Forwarded-For") {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	got := buf.String()
	mu.Unlock()
	t.Fatalf("配了可信反代却没有任何一条日志说 XFF 解析已启用:\n%s", got)
}

// 完整启动一次:自签证书要现场生成、TLS 要真能握手、/healthz 要通,
// 收到 SIGTERM 要干净退出(exit 0 + "已退出")。
//
// 这是唯一覆盖「装机后第一次启动」的测试。这条路径上任何一步坏掉,症状都是
// 服务起不来或起来了握不上手,而在单测里全都看不见。
func TestWebBinary_StartsServesTLSAndShutsDownOnSIGTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("要编二进制,-short 下跳过")
	}
	base := t.TempDir()
	addr := "127.0.0.1:" + itoa(int64(freePort(t)))
	certDir := filepath.Join(base, "certs")

	cmd := exec.Command(buildWebBinary(t),
		"-listen", addr,
		"-db", filepath.Join(base, "web.db"),
		"-cert-dir", certDir,
		"-control-socket", filepath.Join(base, "control.sock"),
	)
	cmd.Env = append(os.Environ(), subprocEnv(t, nil)...)
	var mu sync.Mutex
	var buf strings.Builder
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := pr.Read(b)
			if n > 0 {
				mu.Lock()
				buf.Write(b[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	logs := func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_ = pw.Close()
	})

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			// 自签证书:这里要验的是「TLS 握得上、服务在应答」,不是证书链。
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	deadline := time.Now().Add(30 * time.Second)
	ok := false
	for time.Now().Before(deadline) {
		resp, err := client.Get("https://" + addr + "/healthz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ok = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("30 秒内没能通过 TLS 访问 /healthz\n%s", logs())
	}
	// 证书对必须落在指定目录里 —— 落错地方会让下次启动又签一张新的,
	// 用户每次重启都要重新确认指纹。
	for _, name := range []string{certFileName, keyFileName} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			t.Errorf("证书目录里没有 %s: %v", name, err)
		}
	}

	// SIGTERM → 优雅退出。
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("发 SIGTERM: %v", err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		if err != nil {
			t.Fatalf("收到 SIGTERM 后异常退出: %v\n%s", err, logs())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("收到 SIGTERM 后 20 秒还没退出\n%s", logs())
	}
	_ = pw.Close()
	if !strings.Contains(logs(), "已退出") {
		t.Errorf("退出日志里没有收尾标记:\n%s", logs())
	}
}

// 库文件被掉包(典型场景:按文档做完 `nanotun-admin restore`)之后必须立刻退出。
//
// 不退出的后果比崩掉严重得多:进程还攥着那个已被 unlink 的旧 inode,建用户照样
// 返回成功、一次性 PSK 照样发出去,数据却写进没人读得到的文件,全程零报错。
// systemd 是 Restart=on-failure,退出即重启、重启即打开新文件。
//
// 探测是 15 秒一跳,所以这条测试天然慢。它验的是别处完全无法验证的一件事。
func TestWebBinary_ExitsWhenTheDatabaseFileIsSwappedUnderneath(t *testing.T) {
	if testing.Short() {
		t.Skip("要编二进制且要等一轮 15s 探测,-short 下跳过")
	}
	base := t.TempDir()
	dbPath := filepath.Join(base, "web.db")
	addr := "127.0.0.1:" + itoa(int64(freePort(t)))

	cmd := exec.Command(buildWebBinary(t),
		"-listen", addr,
		"-db", dbPath,
		"-cert-dir", filepath.Join(base, "certs"),
	)
	cmd.Env = append(os.Environ(), subprocEnv(t, nil)...)
	var mu sync.Mutex
	var buf strings.Builder
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := pr.Read(b)
			if n > 0 {
				mu.Lock()
				buf.Write(b[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	logs := func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
	waitErr := make(chan error, 1)
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_ = pw.Close()
	})

	// 等它真的起来(库已打开)。
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(logs(), "等待请求") {
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(logs(), "等待请求") {
		t.Fatalf("30 秒内没起起来:\n%s", logs())
	}

	// 掉包:把库文件换成另一个 inode(restore 就是这么干的)。
	replacement := filepath.Join(base, "restored.db")
	st, err := store.Open(t.Context(), replacement, store.Options{})
	if err != nil {
		t.Fatalf("造替换库: %v", err)
	}
	if err := st.Migrate(t.Context()); err != nil {
		t.Fatalf("迁移替换库: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("关替换库: %v", err)
	}
	if err := os.Rename(replacement, dbPath); err != nil {
		t.Fatalf("掉包: %v", err)
	}

	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		// Fatal 退出,退出码必须非 0,systemd 才会重启。
		if err == nil {
			t.Fatalf("库被掉包后以 0 退出 —— systemd 不会重启它\n%s", logs())
		}
	case <-time.After(45 * time.Second):
		t.Fatalf("库被掉包 45 秒后进程还在跑,继续往死文件里写:\n%s", logs())
	}
	if !strings.Contains(logs(), "已被替换") {
		t.Errorf("退出原因没说清是库被替换:\n%s", logs())
	}
}

// freePort 借一个立刻释放的端口号。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("借端口: %v", err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}
