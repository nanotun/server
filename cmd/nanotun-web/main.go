// Package main 是 nanotun-web 后台的入口。详细架构见 README.md。
package main

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// 版本信息,可在 build 时通过 -ldflags '-X main.webVersion=...' 注入。
var webVersion = "dev"

//go:embed templates/*.html templates/partials/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Server 是整套 nanotun-web 进程的核心容器。
//
// 持有的依赖:
//   - cfg:启动配置;
//   - store:SQLite(读 + 写);
//   - sess:session 服务;
//   - audit:写 store.Audit 的薄包装(actor = "web:<username>");
//   - control:nanotund control socket 客户端;
//   - tmpl:embed 出来的全部模板。
type Server struct {
	cfg     Config
	store   *store.Store
	sess    *SessionService
	audit   *Auditor
	control *controlClient
	tmpl    *template.Template

	// tmplByLang(2026-07-19 第十一轮性能):按语言预 Clone + 绑定 i18n funcs 的
	// 模板集。此前 renderPage 每个请求都 Clone 整套 30+ 模板(深拷贝 parse tree)
	// 只为了绑定当前语言的 T/Th —— 语言总共就 zh/en 两种,启动时各克隆一份,
	// 请求路径零拷贝。html/template 并发 Execute 是官方保证安全的。
	// 为 nil 时(手工构造 Server 的老测试)renderPage 回落到逐请求 Clone。
	tmplByLang map[string]*template.Template

	// credFlash:一次性凭证 PRG flash store(P1#2 / 0013 解耦)。
	// 用于 user create / reset-psk 路径写入 PSK + 凭证 QR,GET 一次性消费。
	// 见 credentials_flash.go。
	credFlash *credentialsFlashStore

	// stepUpFailures:step-up 二次密码验证的 IP 级失败计数(2026-05-26 引入)。
	// 与 sess.ipFailures 隔离:主登录失败不影响 step-up 配额,反之亦然 —
	// 避免「主登录五次失败把 admin 锁了,顺带把 step-up 永久封禁」的串扰。
	// 用同款 IPFailureTracker(滑窗 5min,5 次锁定);专门给 /server-qr/reveal
	// 这类敏感视图操作做爆破防护。
	stepUpFailures *IPFailureTracker

	// startedAt 用于 /metrics uptime。
	startedAt time.Time
}

func main() {
	cfg := defaultConfig()
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "监听地址 host:port,默认 0.0.0.0:7443")
	flag.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite 数据库路径(与 nanotund 共享)")
	flag.StringVar(&cfg.ControlSocketPath, "control-socket", cfg.ControlSocketPath, "nanotund control socket 路径")
	flag.StringVar(&cfg.CertDir, "cert-dir", cfg.CertDir, "TLS 证书目录(cert.pem + key.pem)")
	extraSANs := flag.String("extra-sans", "", "证书 SAN 额外条目,逗号分隔,如 admin.example.com,1.2.3.4")
	flag.Int64Var(&cfg.SessionTTLSec, "session-ttl", cfg.SessionTTLSec, "session 滑动过期窗口(秒)")
	flag.Int64Var(&cfg.MaxLoginFailures, "max-login-failures", cfg.MaxLoginFailures, "连续登录失败 N 次后锁定")
	flag.Int64Var(&cfg.LockoutSeconds, "lockout-seconds", cfg.LockoutSeconds, "锁定时长(秒)")
	flag.BoolVar(&cfg.EnableDebug, "debug", cfg.EnableDebug, "暴露 /debug/* 路由(生产关)")
	noAutoReload := flag.Bool("no-auto-reload", false, "ACL 改动后不自动通知 server reload(默认自动)")
	verbose := flag.Bool("v", false, "更详细的日志(debug 级)")
	showVersion := flag.Bool("version", false, "打印版本并退出")
	flag.Parse()

	if *showVersion {
		fmt.Println("nanotun-web", webVersion)
		return
	}

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	if *extraSANs != "" {
		for _, s := range strings.Split(*extraSANs, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.ExtraSANs = append(cfg.ExtraSANs, s)
			}
		}
	}
	if *noAutoReload {
		cfg.AutoReloadOnACLChange = false
	}

	cfg.applyEnvOverrides()
	if err := cfg.Validate(); err != nil {
		logrus.WithError(err).Fatal("[web] 配置校验失败,退出")
	}

	logrus.WithFields(logrus.Fields{
		"version":  webVersion,
		"listen":   cfg.ListenAddr,
		"db":       cfg.DBPath,
		"control":  cfg.ControlSocketPath,
		"cert_dir": cfg.CertDir,
	}).Info("[web] 启动 nanotun-web")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.Open(ctx, cfg.DBPath, store.Options{})
	if err != nil {
		logrus.WithError(err).Fatal("[web] 打开数据库失败")
	}
	defer func() { _ = st.Close() }()

	// 执行迁移。与 nanotund 同一个 migrate 流程,跨进程 flock 保证安全。
	// 若 nanotund 已经迁移到 N,这里会变 no-op。
	if err := st.Migrate(ctx); err != nil {
		logrus.WithError(err).Fatal("[web] 数据库迁移失败")
	}

	// 2026-05-27 第十四轮(B1):startup readiness 检测 server_dial_host 配置。
	//
	// 历史上只有 dashboard 顶部红 banner 提示 admin「server_dial_host 未配置」,
	// 部署后 ops 不去看 / 监控不到 dashboard 就完全意识不到 QR 功能瘫痪。
	// 启动日志 Warn 让 journalctl / log shipper 也能告警此问题。
	//
	// 检测**只读**(GetServerDialHost),不影响启动流程 — 即使未配置,web 进程
	// 仍正常启动(其它功能如用户管理 / dashboard 都还能用),只是 QR 生成会 412。
	if dialHost, _ := st.GetServerDialHost(ctx); dialHost == "" {
		logrus.Warn("[web] server_dial_host 未配置 — 服务器 QR 生成功能不可用,请到 /settings 页配置真实拨号目标(IPv4/IPv6/RFC1035 域名)")
	}

	tmpl, err := loadTemplates()
	if err != nil {
		logrus.WithError(err).Fatal("[web] 模板加载失败")
	}
	tmplByLang, err := buildLangTemplates(tmpl)
	if err != nil {
		logrus.WithError(err).Fatal("[web] 语言模板集构建失败")
	}

	credFlashStop := make(chan struct{})
	defer close(credFlashStop)
	srv := &Server{
		cfg:            cfg,
		store:          st,
		sess:           NewSessionService(st, cfg),
		audit:          NewAuditor(st),
		control:        newControlClient(cfg.ControlSocketPath),
		tmpl:           tmpl,
		tmplByLang:     tmplByLang,
		credFlash:      newCredentialsFlashStore(credFlashStop),
		stepUpFailures: NewIPFailureTracker(),
		startedAt:      time.Now(),
	}

	mux := srv.routes()

	// 后台 GC:定期 prune expired web_sessions。每 10 分钟跑一次,失败 Warn。
	go srv.runSessionGC(ctx)

	// PoW GC:定期清理已消费的 challenge_id 与陈旧的 IP 失败计数。
	// 共用一个 goroutine,内部 ticker 60s,不会跟 SessionGC 抢锁。
	powStop := make(chan struct{})
	go func() {
		tick := time.NewTicker(60 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-powStop:
				return
			case <-tick.C:
				srv.sess.pruneExpiredPoW()
				srv.sess.ipFailures.Prune()
				// step-up 计数器跟主登录隔离实例,prune 同样跟着 PoW GC 走,
				// 避免再起一个 goroutine 维护同尺度的 sliding window。
				srv.stepUpFailures.Prune()
			}
		}
	}()
	defer close(powStop)

	certPath, keyPath, err := ensureTLSCert(cfg.CertDir, cfg.ExtraSANs)
	if err != nil {
		logrus.WithError(err).Fatal("[web] TLS 证书初始化失败")
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
		},
	}

	// 信号处理:SIGINT/SIGTERM → graceful shutdown。
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		defer signal.Stop(sigCh)
		<-sigCh
		logrus.Info("[web] 收到退出信号,开始优雅退出")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	logrus.WithFields(logrus.Fields{
		"addr": cfg.ListenAddr,
		"cert": certPath,
	}).Info("[web] TLS 服务就绪,等待请求")

	if err := httpSrv.ListenAndServeTLS(certPath, keyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logrus.WithError(err).Fatal("[web] HTTP server 异常退出")
	}
	logrus.Info("[web] 已退出")
}

// loadTemplates 把 templates/ 下所有 .html 一次性 parse,attach common funcs。
//
// 模板命名规则:templates/foo/bar.html 在 t.Lookup 时叫 "foo/bar.html"。
// html/template.ParseFS 默认会用 filepath.Base 作为模板名,这会让
// "login.html" 与 "partials/login.html" 冲突,所以这里手动 ReadFile + t.New(name).Parse。
func loadTemplates() (*template.Template, error) {
	t := template.New("").Funcs(templateFuncs())
	err := fs.WalkDir(templatesFS, "templates", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".html") {
			return nil
		}
		body, err := fs.ReadFile(templatesFS, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		// 去掉前缀 "templates/" 得到 "login.html" / "partials/header.html"。
		name := strings.TrimPrefix(path, "templates/")
		if _, err := t.New(name).Parse(string(body)); err != nil {
			return fmt.Errorf("parse %s: %w", name, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// buildLangTemplates 为每种支持语言各克隆一套模板并绑定该语言的 T/Th/fmtDuration。
// 启动时一次性付掉 Clone 成本,renderPage 请求路径按语言直取,不再逐请求深拷贝。
func buildLangTemplates(base *template.Template) (map[string]*template.Template, error) {
	out := make(map[string]*template.Template, len(supportedLangs))
	for _, lang := range supportedLangs {
		c, err := base.Clone()
		if err != nil {
			return nil, fmt.Errorf("clone templates for lang %s: %w", lang, err)
		}
		out[lang] = c.Funcs(i18nFuncs(lang))
	}
	return out, nil
}

// runSessionGC 周期性清理过期 session,避免 web_sessions 表无限增长。
func (s *Server) runSessionGC(ctx context.Context) {
	tk := time.NewTicker(10 * time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			n, err := s.store.PruneExpiredWebSessions(cctx)
			cancel()
			if err != nil {
				logrus.WithError(err).Warn("[web] 清理过期 session 失败")
				continue
			}
			if n > 0 {
				logrus.WithField("removed", n).Info("[web] 清理过期 session")
			}
		}
	}
}
