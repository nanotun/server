package main

// handler_server_qr_guards_test.go —— /server-qr step-up 与两个 host setting 的
// **失败与边界**路径。handler_server_qr_test.go 已经把主流程(冷却、密码错、
// TOTP 门、DNS/ICMP 分流)测过了,这里补的是那些「出错时会静默降级」的地方:
//
//   - 方法 / 角色守卫:四个入口都要挡住 GET/POST 错配与 viewer;
//   - 锁内重读账号:读不到 → 500,已停用 → 403(绝不能凭请求初的快照放行);
//   - 两个 host setting 的读失败:dial 读不出来要 500(不能当"未配置"走 412),
//     advertised 读不出来只降级(它只是展示 label,不该拖垮 QR);
//   - argon2 排不上号 / 消费时间步时 DB 抖动:都是 503 且不计冷却;
//   - 真正 reveal 成功那一条:PNG 内联 + URL 兜底 + audit,以及 CLI 输出的各种畸形
//     (空 stdout、超长 stderr、URL 长到 QR 装不下);
//   - 写 setting 失败要报错;拨测四种结果 × skip_probe 的分流与各自的 flash 文案。
//
// 用 newMeTestServer(真实模板)而不是 newServerQRTestServer:reveal 成功页要断言
// data: URL 真的内联进了 HTML,minimal server 会把它降级成纯文本从而测不到。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// fakeAdminCLI 写一个假的 nanotun-admin:把 stdout / stderr / 退出码写死,
// 忽略所有参数。真 CLI 要一整套 config.toml + 密钥材料,而本文件关心的是
// 「拿到这样的输出后 handler 怎么办」。
func fakeAdminCLI(t *testing.T, s *Server, stdout, stderr string, exit int) {
	t.Helper()
	path := t.TempDir() + "/nanotun-admin"
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$STDOUT_TEXT\"\nprintf '%%s' \"$STDERR_TEXT\" >&2\nexit %d\n", exit)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("写假 CLI: %v", err)
	}
	t.Setenv("STDOUT_TEXT", stdout)
	t.Setenv("STDERR_TEXT", stderr)
	s.cfg.VPNPortAdminPath = path
	s.cfg.ServerConfigPath = t.TempDir() + "/config.toml"
}

// breakSettingRead 让**指定的一个** setting 读出来就报错,其余 key 照常。
//
// 做法:把真表改名藏到后面,原名换成一张视图,视图对那个 key 吐 NULL —— 扫进
// string 必然失败。之所以要这么绕:value 列有 NOT NULL 约束,直接写 NULL 进不去;
// 而把整张 app_settings 干掉会让所有 setting 一起失败,分不清「dial 读不出来」
// 和「advertised 读不出来」这两条本该走不同分支的路。视图是只读的,调用后不要
// 再指望写 setting 成功。
func breakSettingRead(t *testing.T, s *Server, key string) {
	t.Helper()
	stmts := []string{
		`ALTER TABLE app_settings RENAME TO app_settings_real`,
		`CREATE VIEW app_settings(key, value) AS
		 SELECT key, CASE WHEN key='` + key + `' THEN NULL ELSE value END FROM app_settings_real`,
	}
	for _, q := range stmts {
		if _, err := s.store.DB().ExecContext(t.Context(), q); err != nil {
			t.Fatalf("造 %s 读故障: %v", key, err)
		}
	}
	if _, _, err := s.store.SettingsGet(t.Context(), key); err == nil {
		t.Fatalf("%s 仍能读出来 —— 故障没造出来", key)
	}
	other := store.ServerDialHostKey
	if key == other {
		other = store.AdvertisedHostKey
	}
	if _, _, err := s.store.SettingsGet(t.Context(), other); err != nil {
		t.Fatalf("误伤了 %s 的读:%v", other, err)
	}
}

// revealReq 造一个带身份的 reveal POST(CSRF 由上层中间件负责,这里直接打 handler)。
func revealReq(t *testing.T, admin *store.WebAdmin, ip string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/server-qr/reveal",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if ip != "" {
		req.RemoteAddr = ip + ":12345"
	}
	return withAdminCtx(req, admin)
}

// readyToReveal 铺好「除 step-up 之外一切就绪」的起点:dial + advertised 都配好。
func readyToReveal(t *testing.T, s *Server) {
	t.Helper()
	if err := s.store.SetServerDialHost(t.Context(), "vpn.example.com"); err != nil {
		t.Fatalf("SetServerDialHost: %v", err)
	}
	if err := s.store.SetAdvertisedHost(t.Context(), "东京 1 号"); err != nil {
		t.Fatalf("SetAdvertisedHost: %v", err)
	}
}

// locErrKeyOf 取出错误链上的本地化 key(取不到返回 "")。断言 key 而不是文案:
// 文案会随翻译改动,key 才是「走的是哪条错误路径」的稳定标识。
func locErrKeyOf(err error) string {
	var le localizedError
	if !errors.As(err, &le) {
		return ""
	}
	k, _ := le.LocaleKey()
	return k
}

func settingsPost(t *testing.T, admin *store.WebAdmin, path string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return withAdminCtx(req, admin)
}

// -------------------------------------------------------------------------
// 方法 / 角色守卫
// -------------------------------------------------------------------------

func TestServerQREntries_MethodAndRoleGuards(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	viewerHash, _ := HashWebPassword("ViewerPass123!")
	viewer, err := s.store.CreateWebAdmin(t.Context(), store.NewWebAdmin{
		Username: "eve", PasswordHash: viewerHash, Role: "viewer",
	})
	if err != nil {
		t.Fatalf("建 viewer: %v", err)
	}

	entries := []struct {
		name      string
		path      string
		handler   func(http.ResponseWriter, *http.Request)
		want      string // 正确方法
		badMethod string
	}{
		{"密码页", "/server-qr", s.handleServerQR, http.MethodGet, http.MethodPost},
		{"reveal", "/server-qr/reveal", s.handleServerQRReveal, http.MethodPost, http.MethodGet},
		{"advertised-host", "/settings/advertised-host", s.handleSettingsAdvertisedHostSet, http.MethodPost, http.MethodGet},
		{"dial-host", "/settings/server-dial-host", s.handleSettingsServerDialHostSet, http.MethodPost, http.MethodGet},
	}
	for _, e := range entries {
		t.Run(e.name+"/方法错", func(t *testing.T) {
			req := withAdminCtx(httptest.NewRequest(e.badMethod, e.path, nil), admin)
			w := httptest.NewRecorder()
			e.handler(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("code=%d, 期望 405", w.Code)
			}
			if got := w.Header().Get("Allow"); got != e.want {
				t.Fatalf("Allow=%q, 期望 %q", got, e.want)
			}
		})
		t.Run(e.name+"/viewer", func(t *testing.T) {
			req := withAdminCtx(httptest.NewRequest(e.want, e.path, strings.NewReader("")), viewer)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			e.handler(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("viewer code=%d, 期望 403", w.Code)
			}
		})
	}
	// viewer 的四次尝试都不该留下任何 QR 相关审计。
	for _, action := range []string{
		"server_profile_qr_show", "server_profile_qr_failed",
		"settings_advertised_host_set", "settings_server_dial_host_set",
	} {
		if n := countAudit(t, s, action); n != 0 {
			t.Errorf("viewer 路径写了 %s audit %d 条", action, n)
		}
	}
}

// -------------------------------------------------------------------------
// 锁内重读账号
// -------------------------------------------------------------------------

// 重读账号失败要 500 —— 不能因为"读不出来"就沿用请求初的快照继续 step-up。
// 这里刻意备好一个能出活的假 CLI:若 handler 退回快照,这条请求会一路走到
// 200 + 真把 QR 显示出来,断言才抓得住"沿用快照"这种写法。
func TestServerQRReveal_ReloadFailureIs500(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	readyToReveal(t, s)
	fakeAdminCLI(t, s, "nanotun://v2?d=abc", "", 0)
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE web_admins SET created_at='not-a-number' WHERE id=?`, admin.ID); err != nil {
		t.Fatalf("弄坏 admin 行: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, revealReq(t, admin, "10.20.0.1",
		url.Values{"password": {"GoodStrong1!Pass"}}))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
	if n := countAudit(t, s, "server_profile_qr_show"); n != 0 {
		t.Fatal("读不到账号却写了 _show audit")
	}
}

// 请求初的快照还是 enabled,但账号已经在库里被停用 —— 必须拒,而且不是"密码错"。
func TestServerQRReveal_DisabledAdminIsForbidden(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "GoodStrong1!Pass"
	admin := createTestAdmin(t, s, "root", pw)
	createTestAdmin(t, s, "keeper", pw) // 留一个 admin,避免撞最后管理员下限
	readyToReveal(t, s)
	if err := s.store.SetWebAdminEnabled(t.Context(), admin.ID, false); err != nil {
		t.Fatalf("SetWebAdminEnabled(false): %v", err)
	}

	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, revealReq(t, admin, "10.20.0.2", url.Values{"password": {pw}}))

	if w.Code != http.StatusForbidden {
		t.Fatalf("code=%d, 期望 403", w.Code)
	}
	if n := countAudit(t, s, "server_profile_qr_show"); n != 0 {
		t.Fatal("停用账号却写了 _show audit")
	}
	if n := s.stepUpFailures.Recent("10.20.0.2"); n != 0 {
		t.Fatalf("停用不是密码错,却记了 %d 次 step-up 失败", n)
	}
}

// -------------------------------------------------------------------------
// 两个 host setting 的读失败
// -------------------------------------------------------------------------

// dial host 读失败必须 500。若当成空串走「未配置」那条 412,admin 会被引去
// /settings 重填一个其实已经填好的值,真正的 DB 故障被藏起来。
func TestServerQRReveal_DialHostReadFailureIs500NotUnset(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	readyToReveal(t, s)
	breakSettingRead(t, s, store.ServerDialHostKey)

	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, revealReq(t, admin, "10.20.0.3",
		url.Values{"password": {"GoodStrong1!Pass"}}))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
	if n := countAudit(t, s, "server_profile_qr_no_dial_host"); n != 0 {
		t.Fatal("读失败被记成了「未配置 dial host」")
	}
}

// advertised host 只是展示 label:读不出来要继续出 QR(丢 label 而已),
// 不能把整条 reveal 拖成 500。
func TestServerQRReveal_AdvertisedHostReadFailureStillReveals(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "GoodStrong1!Pass"
	admin := createTestAdmin(t, s, "root", pw)
	readyToReveal(t, s)
	breakSettingRead(t, s, store.AdvertisedHostKey)
	fakeAdminCLI(t, s, "nanotun://v2?d=abc", "", 0)

	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, revealReq(t, admin, "10.20.0.4", url.Values{"password": {pw}}))

	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, 期望 200(label 读不出来不该阻断 QR),body=%q",
			w.Code, trimForLog(w.Body.String()))
	}
	detail := auditDetailFor(t, s, "server_profile_qr_show")
	if !strings.Contains(detail, "advertised_host=") {
		t.Fatalf("_show audit detail 没记 advertised_host: %q", detail)
	}
	if strings.Contains(detail, "advertised_host=东京") {
		t.Fatalf("label 读失败却把旧值写进了 audit: %q", detail)
	}
}

// -------------------------------------------------------------------------
// step-up 的两种「暂时不可用」
// -------------------------------------------------------------------------

// argon2 排不上号 → 503,且不计冷却:压满 CPU 不该能把 admin 关在门外 5 分钟。
func TestServerQRReveal_Argon2UnavailableIs503AndNotCounted(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "GoodStrong1!Pass"
	admin := createTestAdmin(t, s, "root", pw)
	readyToReveal(t, s)
	const ip = "10.21.0.1"

	stop := saturateArgon2(t, 4*time.Second)
	defer stop()

	var got503 bool
	for i := 0; i < 8 && !got503; i++ {
		req := revealReq(t, admin, ip, url.Values{"password": {pw}})
		ctx, cancel := context.WithTimeout(req.Context(), 200*time.Millisecond)
		w := httptest.NewRecorder()
		s.handleServerQRReveal(w, req.WithContext(ctx))
		cancel()
		if w.Code == http.StatusServiceUnavailable {
			got503 = true
		}
	}
	if !got503 {
		t.Fatal("排不上号时没有回 503")
	}
	if n := s.stepUpFailures.Recent(ip); n != 0 {
		t.Fatalf("容量抖动被记了 %d 次 step-up 失败", n)
	}
	if n := countAudit(t, s, "server_profile_qr_password_fail"); n != 0 {
		t.Fatalf("容量抖动写了 %d 条 password_fail audit", n)
	}
}

// hash 存坏了(解析失败)与密码错同权:401 + 计冷却 + 统一 reason,
// 不能给出「这个账号的 hash 坏了」这种可区分信号。
func TestServerQRReveal_BrokenHashLooksLikeAWrongPassword(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	readyToReveal(t, s)
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE web_admins SET password_hash='$argon2id$broken' WHERE id=?`, admin.ID); err != nil {
		t.Fatalf("弄坏 hash: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, revealReq(t, admin, "10.21.0.2",
		url.Values{"password": {"GoodStrong1!Pass"}}))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d, 期望 401", w.Code)
	}
	if n := s.stepUpFailures.Recent("10.21.0.2"); n != 1 {
		t.Fatalf("冷却计数=%d, 期望 1", n)
	}
	detail := auditDetailFor(t, s, "server_profile_qr_password_fail")
	if !strings.Contains(detail, "reason=wrong_password") {
		t.Fatalf("hash 坏了应沿用统一 reason,实际 detail=%q", detail)
	}
	if n := countAudit(t, s, "server_profile_qr_show"); n != 0 {
		t.Fatal("hash 坏了却 reveal 了")
	}
}

// 消费时间步时 DB 抖动 → 503 且不计冷却(与密码步的容量抖动同口径),
// 否则一次写失败就把 admin 往冷却里推一格。
func TestServerQRReveal_TOTPStepUnavailableIs503(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "GoodStrong1!Pass"
	admin := createTestAdmin(t, s, "root", pw)
	secret := enableTestTOTP(t, s, admin)
	readyToReveal(t, s)
	abortSQLiteWrites(t, s, "no_totp_step", "web_admins", "UPDATE OF totp_last_used_step", "")

	form := url.Values{"password": {pw}, "code": {currentTOTPCode(t, secret)}}
	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, revealReq(t, admin, "10.21.0.3", form))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d, 期望 503,body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if n := s.stepUpFailures.Recent("10.21.0.3"); n != 0 {
		t.Fatalf("写失败被记了 %d 次 step-up 失败", n)
	}
	if n := countAudit(t, s, "server_profile_qr_totp_fail"); n != 0 {
		t.Fatal("写失败被记成了 totp_fail")
	}
}

// 密码连错到第 5 次:这一次就要回 429 并明确告知已锁定。若只是照旧回 401,
// 管理员会以为还能再试,直到下一次请求才发现被锁 —— 而那条提示来自另一个分支。
func TestServerQRReveal_PasswordWrongLocksAtTheLimit(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
	readyToReveal(t, s)
	const ip = "10.21.0.5"
	for i := 0; i < stepUpMaxFailures-1; i++ {
		s.stepUpFailures.Inc(ip)
	}

	req := revealReq(t, admin, ip, url.Values{"password": {"wrong-one"}})
	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("第 %d 次密码错 code=%d, 期望 429", stepUpMaxFailures, w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, tr(req, "serverQr.passwordWrongLocked")) {
		t.Fatalf("页面没告知已锁定,body=%q", trimForLog(body))
	}
	if n := countAudit(t, s, "server_profile_qr_password_fail"); n != 1 {
		t.Fatalf("_password_fail audit=%d, 期望 1", n)
	}
}

// TOTP 连错到第 5 次:这一次就要回 429(而不是照旧 401 等下一次请求才拦)。
func TestServerQRReveal_TOTPWrongLocksAtTheLimit(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "GoodStrong1!Pass"
	admin := createTestAdmin(t, s, "root", pw)
	enableTestTOTP(t, s, admin)
	readyToReveal(t, s)
	const ip = "10.21.0.4"
	for i := 0; i < stepUpMaxFailures-1; i++ {
		s.stepUpFailures.Inc(ip)
	}

	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, revealReq(t, admin, ip,
		url.Values{"password": {pw}, "code": {"000000"}}))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("第 %d 次 TOTP 错 code=%d, 期望 429", stepUpMaxFailures, w.Code)
	}
	if n := countAudit(t, s, "server_profile_qr_totp_fail"); n != 1 {
		t.Fatalf("_totp_fail audit=%d, 期望 1", n)
	}
}

// -------------------------------------------------------------------------
// reveal 成功
// -------------------------------------------------------------------------

// 成功页要同时给出内联 PNG 和 URL 文本(扫码失败的兜底),并写 _show audit;
// 成功还要把本 IP 的失败计数衰减掉。
func TestServerQRReveal_SuccessInlinesPNGAndURL(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "GoodStrong1!Pass"
	admin := createTestAdmin(t, s, "root", pw)
	readyToReveal(t, s)
	const urlText = "nanotun://v2?d=Zm9vYmFyYmF6"
	fakeAdminCLI(t, s, urlText+"\n", "", 0)
	const ip = "10.22.0.1"
	s.stepUpFailures.Inc(ip)
	s.stepUpFailures.Inc(ip)

	w := httptest.NewRecorder()
	s.handleServerQRReveal(w, revealReq(t, admin, ip, url.Values{"password": {pw}}))

	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, 期望 200,body=%q", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	if !strings.Contains(body, "data:image/png;base64,") {
		t.Fatal("成功页没有内联 PNG")
	}
	if !strings.Contains(body, urlText) {
		t.Fatalf("成功页没给出 URL 文本兜底(扫码失败就没救了),body=%q", trimForLog(body))
	}
	serverID, err := s.store.GetServerID(t.Context())
	if err != nil {
		t.Fatalf("GetServerID: %v", err)
	}
	if !strings.Contains(body, serverID) {
		t.Fatal("成功页没展示 server_id")
	}
	detail := auditDetailFor(t, s, "server_profile_qr_show")
	for _, want := range []string{"dial_host=vpn.example.com", "advertised_host=东京 1 号"} {
		if !strings.Contains(detail, want) {
			t.Errorf("_show audit detail 缺 %q,实际 %q", want, detail)
		}
	}
	// 敏感内容绝不进审计。
	if strings.Contains(detail, urlText) {
		t.Fatalf("audit 里写进了 profile URL: %q", detail)
	}
	if n := s.stepUpFailures.Recent(ip); n >= 2 {
		t.Fatalf("step-up 成功后失败计数没衰减,仍是 %d", n)
	}
}

// -------------------------------------------------------------------------
// CLI 输出的畸形与 QR 容量
// -------------------------------------------------------------------------

func TestBuildServerProfileQR_CLIOutputEdges(t *testing.T) {
	t.Run("空 stdout 不能当成功", func(t *testing.T) {
		s := newMeTestServer(t)
		fakeAdminCLI(t, s, "   \n", "", 0)
		_, png, err := s.buildServerProfileQRAndURL(t.Context(), "vpn.example.com", "")
		if err == nil {
			t.Fatal("CLI 什么都没输出却当成功了")
		}
		// 必须是「CLI 没给出 URL」这条错。若只依赖下游二维码编码器碰巧拒绝空串,
		// 换个编码器实现就会退化成「渲出一张空白 QR 当成功」。
		if key := locErrKeyOf(err); key != "serverQr.cliEmptyURL" {
			t.Fatalf("错误 key=%q, 期望 serverQr.cliEmptyURL(实际 %v)", key, err)
		}
		if png != nil {
			t.Fatal("没有 URL 却渲出了 PNG")
		}
	})

	t.Run("超长 stderr 截断", func(t *testing.T) {
		s := newMeTestServer(t)
		long := strings.Repeat("x", 300)
		fakeAdminCLI(t, s, "", long, 1)
		_, _, err := s.buildServerProfileQRAndURL(t.Context(), "vpn.example.com", "")
		if err == nil {
			t.Fatal("CLI 失败却返回 nil error")
		}
		msg := err.Error()
		if !strings.Contains(msg, "…") {
			t.Fatalf("超长 stderr 没被截断: %q", msg)
		}
		if strings.Contains(msg, long) {
			t.Fatal("整段 stderr 被原样带出(可能泄露磁盘路径)")
		}
	})

	t.Run("只带 stderr 第一行", func(t *testing.T) {
		s := newMeTestServer(t)
		// 第一行很短(不会触发截断),第二行才是要被丢掉的那部分 —— 后续行常含
		// 配置路径 / 栈信息,不该出现在管理员的错误页上。
		fakeAdminCLI(t, s, "", "boom\n/etc/nanotun/config.toml 里第 3 行有问题", 1)
		_, _, err := s.buildServerProfileQRAndURL(t.Context(), "vpn.example.com", "")
		if err == nil {
			t.Fatal("CLI 失败却返回 nil error")
		}
		msg := err.Error()
		if !strings.Contains(msg, "boom") {
			t.Fatalf("第一行没带上: %q", msg)
		}
		if strings.Contains(msg, "/etc/nanotun/config.toml") {
			t.Fatalf("第二行也被带出来了: %q", msg)
		}
	})

	t.Run("CLI 失败且 stderr 为空时退回 exec 错", func(t *testing.T) {
		s := newMeTestServer(t)
		fakeAdminCLI(t, s, "", "", 3)
		_, _, err := s.buildServerProfileQRAndURL(t.Context(), "vpn.example.com", "")
		if err == nil || strings.TrimSpace(err.Error()) == "" {
			t.Fatalf("stderr 为空时应退回 exec 错,实际 %v", err)
		}
	})

	t.Run("URL 长到 QR 装不下", func(t *testing.T) {
		s := newMeTestServer(t)
		// v40-L 上限约 2953 字节,超过就两级纠错都编不出来。
		fakeAdminCLI(t, s, "nanotun://v2?d="+strings.Repeat("a", 4000), "", 0)
		urlText, png, err := s.buildServerProfileQRAndURL(t.Context(), "vpn.example.com", "")
		if err == nil {
			t.Fatal("URL 超出 QR 容量却当成功了")
		}
		if png != nil {
			t.Fatal("编码失败却返回了 PNG")
		}
		// 仍要把 URL 文本带回去 —— 页面即使没有 PNG 也能让 admin 复制链接。
		if urlText == "" {
			t.Fatal("编码失败时把 URL 文本也丢了")
		}
	})

	t.Run("超出 Medium 容量时降级 Low", func(t *testing.T) {
		s := newMeTestServer(t)
		// 夹在 Medium(约 2331)与 Low(约 2953)之间:Medium 编不出、Low 可以。
		fakeAdminCLI(t, s, "nanotun://v2?d="+strings.Repeat("a", 2600), "", 0)
		_, png, err := s.buildServerProfileQRAndURL(t.Context(), "vpn.example.com", "")
		if err != nil {
			t.Fatalf("应降级到 Low 纠错并成功,实际 %v", err)
		}
		if len(png) == 0 {
			t.Fatal("降级后没拿到 PNG")
		}
	})

	t.Run("未配路径时用默认值", func(t *testing.T) {
		s := newMeTestServer(t)
		s.cfg.VPNPortAdminPath = ""
		s.cfg.ServerConfigPath = ""
		// 默认 /usr/local/bin/nanotun-admin 在测试机上通常不存在 —— 这里只要求
		// 「按默认路径去执行并如实报错」,不能因为路径空就 panic 或静默成功。
		_, _, err := s.buildServerProfileQRAndURL(t.Context(), "vpn.example.com", "label")
		if err == nil {
			t.Skip("本机装了 /usr/local/bin/nanotun-admin,跳过默认路径断言")
		}
	})
}

// -------------------------------------------------------------------------
// 两个 setting 的写失败
// -------------------------------------------------------------------------

func TestSettingsHostWrites_FailuresAreReported(t *testing.T) {
	t.Run("advertised host", func(t *testing.T) {
		s := newMeTestServer(t)
		admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
		abortSQLiteWrites(t, s, "no_settings_write_adv", "app_settings", "UPDATE", "")
		abortSQLiteWrites(t, s, "no_settings_insert_adv", "app_settings", "INSERT", "")

		w := httptest.NewRecorder()
		s.handleSettingsAdvertisedHostSet(w, settingsPost(t, admin, "/settings/advertised-host",
			url.Values{"advertised_host": {"东京 1 号"}}))

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d, 期望 500", w.Code)
		}
		if n := countAudit(t, s, "settings_advertised_host_set"); n != 0 {
			t.Fatal("写失败却写了成功 audit")
		}
	})

	t.Run("dial host", func(t *testing.T) {
		s := newMeTestServer(t)
		admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
		stubProbe(t, nil)
		abortSQLiteWrites(t, s, "no_settings_write_dial", "app_settings", "UPDATE", "")
		abortSQLiteWrites(t, s, "no_settings_insert_dial", "app_settings", "INSERT", "")

		w := httptest.NewRecorder()
		s.handleSettingsServerDialHostSet(w, settingsPost(t, admin, "/settings/server-dial-host",
			url.Values{"server_dial_host": {"203.0.113.10"}}))

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d, 期望 500", w.Code)
		}
		if n := countAudit(t, s, "settings_server_dial_host_set"); n != 0 {
			t.Fatal("写失败却写了成功 audit")
		}
		got, _ := s.store.GetServerDialHost(t.Context())
		if got != "" {
			t.Fatalf("写失败却落库为 %q", got)
		}
	})
}

// -------------------------------------------------------------------------
// 拨测四种结果 × skip_probe
// -------------------------------------------------------------------------

// stubProbe 把拨测替换成固定结果。
func stubProbe(t *testing.T, err error) {
	t.Helper()
	orig := probeServerDialHost
	probeServerDialHost = func(context.Context, string) error { return err }
	t.Cleanup(func() { probeServerDialHost = orig })
}

// 未分类的拨测错:不勾 skip 时必须拦下(412),勾了才放行。这条分支决定了
// 「将来 Probe 多返回一种错」时是默认放行还是默认拦下 —— 必须是拦下。
func TestSettingsServerDialHostSet_UnknownProbeErrorFailsClosed(t *testing.T) {
	weird := errors.New("拨测遇到没见过的情况")

	t.Run("不勾 skip 就拦下", func(t *testing.T) {
		s := newMeTestServer(t)
		admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
		stubProbe(t, weird)

		w := httptest.NewRecorder()
		s.handleSettingsServerDialHostSet(w, settingsPost(t, admin, "/settings/server-dial-host",
			url.Values{"server_dial_host": {"vpn.example.com"}}))

		if w.Code != http.StatusPreconditionFailed {
			t.Fatalf("code=%d, 期望 412", w.Code)
		}
		if got, _ := s.store.GetServerDialHost(t.Context()); got != "" {
			t.Fatalf("拦下了却落库为 %q", got)
		}
		if n := countAudit(t, s, "settings_server_dial_host_set_probe_unknown"); n != 1 {
			t.Fatalf("_probe_unknown audit=%d, 期望 1", n)
		}
		if n := countAudit(t, s, "settings_server_dial_host_set"); n != 0 {
			t.Fatal("拦下了却写成功 audit")
		}
	})

	t.Run("勾了 skip 才入库", func(t *testing.T) {
		s := newMeTestServer(t)
		admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
		stubProbe(t, weird)

		w := httptest.NewRecorder()
		s.handleSettingsServerDialHostSet(w, settingsPost(t, admin, "/settings/server-dial-host",
			url.Values{"server_dial_host": {"vpn.example.com"}, "skip_probe": {"1"}}))

		if w.Code != http.StatusSeeOther {
			t.Fatalf("code=%d, 期望 303,body=%q", w.Code, trimForLog(w.Body.String()))
		}
		if got, _ := s.store.GetServerDialHost(t.Context()); got != "vpn.example.com" {
			t.Fatalf("勾了 skip 应入库,实际 %q", got)
		}
		if n := countAudit(t, s, "settings_server_dial_host_set_probe_unknown_skipped"); n != 1 {
			t.Fatalf("_probe_unknown_skipped audit=%d, 期望 1", n)
		}
		if d := auditDetailFor(t, s, "settings_server_dial_host_set"); !strings.Contains(d, "probe=probe_unknown_skipped") {
			t.Fatalf("成功 audit 的 probe 字段不对: %q", d)
		}
	})
}

// 五种保存结果各有各的 flash 文案:admin 靠它判断「这次到底验过了什么」。
// 尤其字面 IP + 跳过 ICMP 那条不能说「DNS 已通过」—— 字面 IP 压根没查 DNS。
func TestSettingsServerDialHostSet_FlashSaysWhatWasActuallyVerified(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		probeErr  error
		skipProbe bool
		wantKey   string
		wantProbe string
	}{
		{"域名全通过", "vpn.example.com", nil, false,
			"flash.dialHostUpdatedProbedOk", "probe=probed_ok"},
		{"字面 IP 通过", "203.0.113.10", nil, false,
			"flash.dialHostUpdatedLiteralOk", "probe=probed_literal_ip"},
		{"域名跳过 ICMP", "vpn.example.com", store.ErrServerDialHostICMPSoftFail, true,
			"flash.dialHostUpdatedIcmpSkipped", "probe=icmp_softfail_skipped"},
		{"字面 IP 跳过 ICMP", "203.0.113.10", store.ErrServerDialHostICMPSoftFail, true,
			"flash.dialHostUpdatedLiteralIcmpSkipped", "probe=icmp_softfail_skipped"},
		{"未分类错跳过", "vpn.example.com", errors.New("怪错"), true,
			"flash.dialHostUpdatedProbeUnknownSkipped", "probe=probe_unknown_skipped"},
		{"清除", "", nil, false, "flash.dialHostCleared", "probe=cleared"},
	}
	seen := map[string]string{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newMeTestServer(t)
			admin := createTestAdmin(t, s, "root", "GoodStrong1!Pass")
			stubProbe(t, c.probeErr)

			form := url.Values{"server_dial_host": {c.host}}
			if c.skipProbe {
				form.Set("skip_probe", "1")
			}
			req := settingsPost(t, admin, "/settings/server-dial-host", form)
			w := httptest.NewRecorder()
			s.handleSettingsServerDialHostSet(w, req)

			if w.Code != http.StatusSeeOther {
				t.Fatalf("code=%d, 期望 303,body=%q", w.Code, trimForLog(w.Body.String()))
			}
			loc := w.Header().Get("Location")
			want := tr(req, c.wantKey)
			if !strings.Contains(loc, url.QueryEscape(want)) {
				t.Fatalf("Location=%q 里没有 %q(%s)", loc, want, c.wantKey)
			}
			if d := auditDetailFor(t, s, "settings_server_dial_host_set"); !strings.Contains(d, c.wantProbe) {
				t.Fatalf("audit detail=%q, 期望含 %q", d, c.wantProbe)
			}
			// 六种结果的文案必须互不相同,否则 admin 分不清验过什么。
			if prev, dup := seen[want]; dup {
				t.Fatalf("%s 与 %s 共用同一句文案 %q", c.name, prev, want)
			}
			seen[want] = c.name
		})
	}
}
