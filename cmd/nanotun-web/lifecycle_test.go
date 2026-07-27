package main

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// 本文件覆盖进程级的边角:后台 GC goroutine 的退出、模板的多语言克隆、
// 以及回滚用的 cookie 清除。
//
// 这些都不在请求路径上,所以任何 handler 测试都碰不到它们。它们出问题的方式
// 也不一样 —— 不是某个页面报错,而是「关不掉」「启动就崩」「cookie 清不干净」。

// -------------------------------------------------------------------------
// 后台 goroutine 的退出
// -------------------------------------------------------------------------

// TestRunSessionGC_ExitsOnContextCancel:GC 循环用 10 分钟 ticker,测不了它的清理
// 节奏,但能测它认不认 ctx。不认的话进程收到 SIGTERM 后这个 goroutine 会挂着
// 持有 store 句柄,优雅退出变成硬等超时。
func TestRunSessionGC_ExitsOnContextCancel(t *testing.T) {
	s := newTestServerMinimal(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() { s.runSessionGC(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后 runSessionGC 没退出(它在等下一个 10 分钟 tick)")
	}
}

func TestRunPoWGC_ExitsOnStopChannel(t *testing.T) {
	sess := newMeTestServer(t).sess
	stop := make(chan struct{})

	done := make(chan struct{})
	go func() { sess.runPoWGC(stop); close(done) }()

	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop 关闭后 runPoWGC 没退出")
	}
}

// TestPruneExpiredPoW_DropsExpiredKeepsLive:GC 的实际清理逻辑。三张表
// (powUsed / captchaUsed / pendingUsed)共用一轮清扫,漏掉任何一张就是一处
// 随登录量线性增长、永不释放的内存。
func TestPruneExpiredPoW_DropsExpiredKeepsLive(t *testing.T) {
	sess := newMeTestServer(t).sess

	now := nowUnix()
	for _, m := range []*sync.Map{&sess.powUsed, &sess.captchaUsed, &sess.pendingUsed} {
		m.Store("expired", now-1)
		m.Store("live", now+600)
		m.Store("garbage-type", "not-an-int64") // 类型不对也要当垃圾清掉
	}

	sess.pruneExpiredPoW()

	for name, m := range map[string]*sync.Map{
		"powUsed": &sess.powUsed, "captchaUsed": &sess.captchaUsed, "pendingUsed": &sess.pendingUsed,
	} {
		if _, ok := m.Load("expired"); ok {
			t.Errorf("%s: 过期项没被清掉", name)
		}
		if _, ok := m.Load("garbage-type"); ok {
			t.Errorf("%s: 类型异常项没被清掉", name)
		}
		// 还没到期的必须留着 —— 清早了就等于让一枚用过的 nonce 重新可用,
		// PoW / captcha / pending-2FA 的一次性保证当场失效。
		if _, ok := m.Load("live"); !ok {
			t.Errorf("%s: 未过期项被误清,一次性 nonce 可被重放", name)
		}
	}
	if n := sess.powUsedSnapshot(); n != 1 {
		t.Fatalf("powUsedSnapshot=%d, 期望 1(只剩 live)", n)
	}
}

// -------------------------------------------------------------------------
// 多语言模板
// -------------------------------------------------------------------------

// TestBuildLangTemplates_OneSetPerLanguage:启动时一次性克隆,失败会让整个进程
// 起不来。更隐蔽的是「克隆成功但语言函数没绑上」—— 那样英文页会渲染出中文。
func TestBuildLangTemplates_OneSetPerLanguage(t *testing.T) {
	base, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	set, err := buildLangTemplates(base)
	if err != nil {
		t.Fatalf("buildLangTemplates: %v", err)
	}
	if len(set) != len(supportedLangs) {
		t.Fatalf("得到 %d 套模板,支持 %d 种语言", len(set), len(supportedLangs))
	}
	for _, lang := range supportedLangs {
		tmpl, ok := set[lang]
		if !ok || tmpl == nil {
			t.Fatalf("语言 %q 没有对应模板", lang)
		}
		// 每种语言必须是独立的克隆:共享同一个 *Template 的话,最后一次
		// Funcs() 会赢,所有语言都渲染成同一种。
		if lang != supportedLangs[0] && tmpl == set[supportedLangs[0]] {
			t.Fatalf("语言 %q 与 %q 指向同一个模板对象", lang, supportedLangs[0])
		}
	}
	// 抽一个 i18n 函数验证绑定确实按语言分开了。
	renderT := func(tmpl *template.Template) string {
		x, err := tmpl.Clone()
		if err != nil {
			t.Fatalf("Clone: %v", err)
		}
		p, err := x.New("probe").Parse(`{{T "page.login.title"}}`)
		if err != nil {
			t.Fatalf("Parse probe: %v", err)
		}
		var sb strings.Builder
		if err := p.ExecuteTemplate(&sb, "probe", nil); err != nil {
			t.Fatalf("Execute probe: %v", err)
		}
		return sb.String()
	}
	if len(supportedLangs) > 1 {
		a, b := renderT(set[supportedLangs[0]]), renderT(set[supportedLangs[1]])
		if a == b {
			t.Fatalf("%q 与 %q 渲染出同一串 %q,语言函数没按语言绑定",
				supportedLangs[0], supportedLangs[1], a)
		}
	}
}

// -------------------------------------------------------------------------
// cookie 回滚
// -------------------------------------------------------------------------

// TestClearSessionCookie_ExpiresWithSameAttributes:用在「session 已发但后续步骤
// 失败」的回滚路径上(比如恢复码登录时 MarkRecoveryCodeUsed 失败)。
//
// 浏览器按 (name, domain, path) 匹配 cookie:属性对不上,新发的这条不会覆盖旧的,
// 而是并存 —— 回滚就成了空操作,库里的 session 已删、浏览器还揣着那个 id 到处发。
func TestClearSessionCookie_ExpiresWithSameAttributes(t *testing.T) {
	s := newMeTestServer(t)
	w := httptest.NewRecorder()

	s.sess.clearSessionCookie(w)

	cks := w.Result().Cookies()
	if len(cks) != 1 {
		t.Fatalf("发了 %d 个 cookie, 期望 1", len(cks))
	}
	ck := cks[0]
	if ck.Name != s.sess.cookieName(sessionCookieName) {
		t.Fatalf("name=%q, 期望 %q", ck.Name, s.sess.cookieName(sessionCookieName))
	}
	if ck.Value != "" {
		t.Fatalf("清除用的 cookie 还带着值 %q", ck.Value)
	}
	if ck.MaxAge >= 0 {
		t.Fatalf("MaxAge=%d, 期望负数(立即过期)", ck.MaxAge)
	}
	if ck.Path != "/" {
		t.Fatalf("Path=%q, 期望 /(与签发时一致,否则覆盖不到)", ck.Path)
	}
	if !ck.HttpOnly {
		t.Fatal("HttpOnly 丢了")
	}
	if ck.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite=%v, 期望 Lax", ck.SameSite)
	}
	if ck.Secure != s.sess.cookieSecure {
		t.Fatalf("Secure=%v, 期望与签发时一致(%v)", ck.Secure, s.sess.cookieSecure)
	}
}
