package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 本文件补 /me 与 /me/totp/* 上「出错的时候」那一半:读不到账号、写不进库、
// 冷却已到、时间步消费失败、吊销/换发会话失败。
//
// 这些分支的共同点是:走到它们的时候,系统已经处于异常状态,而此刻做的选择决定了
// 用户是"被挡住"还是"被锁死":
//   - 读不到账号行时若继续往下走,就是拿请求开始时的旧快照做 step-up 判定;
//   - 启用 2FA 时恢复码写不进去,却把 totp_enabled 翻成 1 —— 账号从此没有任何应急入口;
//   - 关闭 2FA 时那条 UPDATE 失败却回了"已关闭",用户以为解绑了,实际下次登录还要码;
//   - 消费时间步的 DB 抖动若当成码错,正确的码会把自己推进 step-up 冷却。

// anonymize 去掉请求上下文里的 admin 身份(模拟中间件没放行/会话已失效),
// 表单与 cookie 原样保留 —— 这样测的就是 handler 自己那道兜底,而不是 CSRF。
func anonymize(r *http.Request) *http.Request {
	return r.WithContext(context.Background())
}

// primeStepUpCooldown 把某 IP 的 step-up 失败计数顶到冷却线。
func primeStepUpCooldown(s *Server, ip string) {
	for i := 0; i < stepUpMaxFailures; i++ {
		s.stepUpFailures.Inc(ip)
	}
}

// meHandlers 是 /me 下所有写动作,便于逐个过同一道断言。
func meHandlers(s *Server) []struct {
	name string
	path string
	fn   func(http.ResponseWriter, *http.Request)
} {
	return []struct {
		name string
		path string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"setup", "/me/totp/setup", s.handleMeTOTPSetup},
		{"enable", "/me/totp/enable", s.handleMeTOTPEnable},
		{"disable", "/me/totp/disable", s.handleMeTOTPDisable},
		{"regen", "/me/totp/regen-codes", s.handleMeTOTPRegen},
	}
}

// =========================================================================
// 身份与方法的兜底
// =========================================================================

// 没有身份就不许动 2FA —— 中间件之外每个 handler 自己也要兜一道。
//
// 这些 handler 之所以不能只依赖中间件:/me/totp/* 是 dispatcher 分发进来的,
// 将来任何路由改动(挂错中间件、加一条新路径)都不该让"匿名请求改 2FA"成为可能。
func TestMe_AnonymousRequestsAreSentToLogin(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")

	for _, h := range meHandlers(s) {
		w := httptest.NewRecorder()
		h.fn(w, anonymize(mePost(t, s, admin, h.path, url.Values{"code": {"123456"}}, "10.30.0.1")))
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("%s: code=%d loc=%q, 期望 302 /login", h.name, w.Code, w.Header().Get("Location"))
		}
	}

	// 一次性恢复码页与个人页同理。
	for _, c := range []struct {
		name string
		req  *http.Request
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"codes", httptest.NewRequest(http.MethodGet, "/me/totp/codes?token=x", nil), s.handleMeTOTPCodesFlash},
		{"me", httptest.NewRequest(http.MethodGet, "/me", nil), s.handleMe},
	} {
		w := httptest.NewRecorder()
		c.fn(w, c.req)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
			t.Errorf("%s: code=%d loc=%q, 期望 302 /login", c.name, w.Code, w.Header().Get("Location"))
		}
	}
}

// /me 只认 GET。
func TestMe_RejectsNonGET(t *testing.T) {
	s := newMeTestServer(t)
	for _, m := range []string{http.MethodPost, http.MethodDelete} {
		w := httptest.NewRecorder()
		s.handleMe(w, httptest.NewRequest(m, "/me", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: code=%d, 期望 405", m, w.Code)
		}
		if got := w.Header().Get("Allow"); got != "GET" {
			t.Errorf("%s: Allow=%q", m, got)
		}
	}
}

// 一次性恢复码页只认 GET(它是 PRG 的 G,POST 进来说明有人在重发写请求)。
func TestMeTOTPCodes_RejectsNonGET(t *testing.T) {
	s := newMeTestServer(t)
	w := httptest.NewRecorder()
	s.handleMeTOTPCodesFlash(w, httptest.NewRequest(http.MethodPost, "/me/totp/codes", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d, 期望 405", w.Code)
	}
}

// =========================================================================
// 读不到账号行
// =========================================================================

// 查不到当前账号时,所有 step-up 都必须停在这里。
//
// 这一步读的是**锁内最新**的账号行:密码 hash、enabled、totp_secret 全靠它。
// 读失败却继续用请求开始时的快照,等于把「应急改密 / 停用」的时间窗又打开。
func TestMe_AccountReadFailureStopsEveryStepUp(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	reqs := map[string]*http.Request{}
	for _, h := range meHandlers(s) {
		reqs[h.name] = mePost(t, s, admin, h.path,
			url.Values{"password": {"AdminPass123!"}, "code": {"123456"}}, "10.31.0.1")
	}
	if err := s.store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	want := map[string]int{
		"setup":   http.StatusInternalServerError,
		"enable":  http.StatusInternalServerError,
		"disable": http.StatusInternalServerError,
		// regen 把「读不到 / 没开 2FA」合并成同一句提示(都引导去开 2FA),故是 400。
		"regen": http.StatusBadRequest,
	}
	for _, h := range meHandlers(s) {
		w := httptest.NewRecorder()
		h.fn(w, reqs[h.name])
		if w.Code != want[h.name] {
			t.Errorf("%s: code=%d, 期望 %d", h.name, w.Code, want[h.name])
		}
	}
}

// 账号被停用后,自助改 2FA 的入口全部关闭(会话可能还没过期)。
func TestMe_DisabledAccountCannotTouchTwoFactor(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	if err := s.store.SetWebAdminEnabled(t.Context(), admin.ID, false); err != nil {
		t.Fatalf("SetWebAdminEnabled: %v", err)
	}

	for _, c := range []struct {
		name string
		path string
		form url.Values
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"disable", "/me/totp/disable", url.Values{"code": {totpCodeFor(t, secret)}}, s.handleMeTOTPDisable},
		{"regen", "/me/totp/regen-codes", url.Values{"code": {totpCodeFor(t, secret)}}, s.handleMeTOTPRegen},
	} {
		w := httptest.NewRecorder()
		c.fn(w, mePost(t, s, admin, c.path, c.form, "10.32.0.1"))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: code=%d, 期望 403(body=%q)", c.name, w.Code, trimForLog(w.Body.String()))
		}
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if !cur.TOTPEnabled {
		t.Fatal("停用账号的 2FA 被关掉了")
	}
}

// =========================================================================
// step-up 冷却
// =========================================================================

// 冷却已到时,enable / disable / regen 一律 429,且不动任何状态。
//
// 这三条路径都是「输一个 6 位码就生效」的敏感操作。少了冷却,劫持到会话的人
// 可以对 6 位码提速爆破(HMAC 便宜,不过 argon2),成功即拿到长期第二因子或把
// 合法用户的 2FA 关掉。
func TestMe_CooldownBlocksEveryCodePath(t *testing.T) {
	const pw = "AdminPass123!"
	cases := []struct {
		name  string
		path  string
		audit string
		setup func(t *testing.T, s *Server, admin *store.WebAdmin) url.Values
		fn    func(s *Server) func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "enable", path: "/me/totp/enable", audit: "totp_enable_locked",
			setup: func(t *testing.T, s *Server, admin *store.WebAdmin) url.Values {
				secret, err := GenerateTOTPSecret()
				if err != nil {
					t.Fatalf("GenerateTOTPSecret: %v", err)
				}
				if err := s.store.SetWebAdminTOTPSecret(t.Context(), admin.ID, secret); err != nil {
					t.Fatalf("SetWebAdminTOTPSecret: %v", err)
				}
				return url.Values{"code": {totpCodeFor(t, secret)}}
			},
			fn: func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleMeTOTPEnable },
		},
		{
			name: "disable", path: "/me/totp/disable", audit: "totp_disable_locked",
			setup: func(t *testing.T, s *Server, admin *store.WebAdmin) url.Values {
				secret, _ := enableTOTPDirect(t, s, admin, 1)
				return url.Values{"code": {totpCodeFor(t, secret)}}
			},
			fn: func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleMeTOTPDisable },
		},
		{
			name: "regen", path: "/me/totp/regen-codes", audit: "totp_regen_locked",
			setup: func(t *testing.T, s *Server, admin *store.WebAdmin) url.Values {
				secret, _ := enableTOTPDirect(t, s, admin, 1)
				return url.Values{"code": {totpCodeFor(t, secret)}}
			},
			fn: func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleMeTOTPRegen },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			admin := createTestAdmin(t, s, "alice", pw)
			form := tc.setup(t, s, admin)
			before, _ := s.store.GetWebAdmin(t.Context(), admin.ID)

			const ip = "10.33.0.1"
			primeStepUpCooldown(s, ip)
			w := httptest.NewRecorder()
			tc.fn(s)(w, mePost(t, s, admin, tc.path, form, ip))

			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("code=%d, 期望 429(body=%q)", w.Code, trimForLog(w.Body.String()))
			}
			after, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
			if after.TOTPEnabled != before.TOTPEnabled {
				t.Fatalf("冷却期内 2FA 状态被改了: %v → %v", before.TOTPEnabled, after.TOTPEnabled)
			}
			assertAuditAction(t, s, tc.audit)
		})
	}
}

// 连续错到第 N 次要直接给 429(而不是继续 401/400 让人接着试)。
//
// 边界在于:阈值检查用的是**本次之前**的计数,所以第 N 次错误必须由「Inc 之后
// 立刻判定」这条分支接住。差一位的话,冷却窗口实际是 N+1 次。
func TestMe_LastAllowedFailureAlreadyReturns429(t *testing.T) {
	const pw = "AdminPass123!"

	t.Run("setup 密码", func(t *testing.T) {
		s := newMeTestServer(t)
		admin := createTestAdmin(t, s, "alice", pw)
		const ip = "10.34.0.1"
		var last int
		for i := 0; i < stepUpMaxFailures; i++ {
			w := httptest.NewRecorder()
			s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
				url.Values{"password": {"WrongPass123!"}}, ip))
			last = w.Code
		}
		if last != http.StatusTooManyRequests {
			t.Fatalf("第 %d 次错密码 code=%d, 期望 429", stepUpMaxFailures, last)
		}
	})

	t.Run("enable 验证码", func(t *testing.T) {
		s := newMeTestServer(t)
		admin := createTestAdmin(t, s, "alice", pw)
		secret, err := GenerateTOTPSecret()
		if err != nil {
			t.Fatalf("GenerateTOTPSecret: %v", err)
		}
		if err := s.store.SetWebAdminTOTPSecret(t.Context(), admin.ID, secret); err != nil {
			t.Fatalf("SetWebAdminTOTPSecret: %v", err)
		}
		const ip = "10.34.0.2"
		var last int
		for i := 0; i < stepUpMaxFailures; i++ {
			w := httptest.NewRecorder()
			s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
				url.Values{"code": {"000000"}}, ip))
			last = w.Code
		}
		if last != http.StatusTooManyRequests {
			t.Fatalf("第 %d 次错码 code=%d, 期望 429", stepUpMaxFailures, last)
		}
		cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
		if cur.TOTPEnabled {
			t.Fatal("连错这么多次反而把 2FA 启用了")
		}
	})
}

// =========================================================================
// 写库失败
// =========================================================================

// secret 存不进库,就不能给用户看二维码 —— 否则用户扫了码、下一步却永远验不过。
func TestMeTOTPSetup_SecretWriteFailureShowsNoQR(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	abortSQLiteWrites(t, s, "kill_secret_write", "web_admins", "UPDATE",
		"NEW.totp_secret IS NOT OLD.totp_secret")

	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {pw}}, "10.35.0.1"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500(body=%q)", w.Code, trimForLog(w.Body.String()))
	}
	if strings.Contains(w.Body.String(), "data:image/png") {
		t.Fatal("secret 没存进库却把二维码画出来了")
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.TOTPSecret != "" {
		t.Fatalf("库里留下了 secret: %q", cur.TOTPSecret)
	}
}

// 二维码里的账号标签不能带端口号。
//
// otpauth 的 label 是给人看的(authenticator 列表里那一行)。带上 :8443 不影响算法,
// 但同一台机器换端口后会多出一条看起来陌生的条目,用户分不清哪个才是当前的。
func TestMeTOTPSetup_QRLabelDropsThePort(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)

	req := mePost(t, s, admin, "/me/totp/setup", url.Values{"password": {pw}}, "10.36.0.1")
	req.Host = "console.example.com:8443"
	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	if !strings.Contains(body, "alice@console.example.com") {
		t.Errorf("页面里没有去掉端口的账号标签")
	}
	if strings.Contains(body, "console.example.com:8443") {
		t.Errorf("账号标签里带上了端口号")
	}
}

// 恢复码写不进去时,绝不能把 totp_enabled 翻成 1。
//
// 「2FA 已开但一条恢复码都没有」是最糟的状态:换手机 / 丢 authenticator 之后没有
// 任何自助入口,而系统里也没有「管理员帮别人清 2FA」这个动作。启用必须是原子的。
func TestMeTOTPEnable_RecoveryCodeWriteFailureLeavesTOTPOff(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := s.store.SetWebAdminTOTPSecret(t.Context(), admin.ID, secret); err != nil {
		t.Fatalf("SetWebAdminTOTPSecret: %v", err)
	}
	abortSQLiteWrites(t, s, "kill_recovery_insert", "web_admin_recovery_codes", "INSERT", "")

	w := httptest.NewRecorder()
	s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {totpCodeFor(t, secret)}}, "10.37.0.1"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500(body=%q)", w.Code, trimForLog(w.Body.String()))
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.TOTPEnabled {
		t.Fatal("恢复码没写进去,2FA 却被启用了 —— 账号从此没有应急入口")
	}
}

// 关 2FA 那条 UPDATE 失败时要显式报错,不能回"已关闭"。
func TestMeTOTPDisable_WriteFailureDoesNotReportSuccess(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	_, codes := enableTOTPDirect(t, s, admin, 1)
	abortSQLiteWrites(t, s, "kill_totp_off", "web_admins", "UPDATE",
		"NEW.totp_enabled <> OLD.totp_enabled")

	w := httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
		url.Values{"recovery_code": {codes[0]}}, "10.38.0.1"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500(body=%q)", w.Code, trimForLog(w.Body.String()))
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if !cur.TOTPEnabled {
		t.Fatal("写失败却真把 2FA 关了")
	}
}

// 重刷恢复码写库失败:旧码不能丢,提示也不能是"已刷新"。
func TestMeTOTPRegen_WriteFailureKeepsOldCodes(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 2)
	abortSQLiteWrites(t, s, "kill_regen", "web_admin_recovery_codes", "DELETE", "")

	w := httptest.NewRecorder()
	s.handleMeTOTPRegen(w, mePost(t, s, admin, "/me/totp/regen-codes",
		url.Values{"code": {totpCodeFor(t, secret)}}, "10.39.0.1"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500(body=%q)", w.Code, trimForLog(w.Body.String()))
	}
	left, err := s.store.ListUnusedRecoveryCodes(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("ListUnusedRecoveryCodes: %v", err)
	}
	if len(left) != 2 {
		t.Fatalf("剩 %d 条旧恢复码, 期望 2 条(刷新失败不该把旧码删掉)", len(left))
	}
}

// =========================================================================
// 时间步消费失败 → 503,不算码错
// =========================================================================

// enable / disable / regen 三条路径上,「记一下这枚码用过了」写库失败都要回 503。
//
// 判成码错的代价是:用户输的是**正确**的码,却被记一次 step-up 失败;库抖几下就把
// 自己锁进 5 分钟冷却,而他什么都没做错。
func TestMe_StepConsumeFailureIs503AndNotCountedAsWrongCode(t *testing.T) {
	const pw = "AdminPass123!"
	cases := []struct {
		name  string
		path  string
		setup func(t *testing.T, s *Server, admin *store.WebAdmin) (url.Values, func())
		fn    func(s *Server) func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "enable", path: "/me/totp/enable",
			setup: func(t *testing.T, s *Server, admin *store.WebAdmin) (url.Values, func()) {
				secret, err := GenerateTOTPSecret()
				if err != nil {
					t.Fatalf("GenerateTOTPSecret: %v", err)
				}
				if err := s.store.SetWebAdminTOTPSecret(t.Context(), admin.ID, secret); err != nil {
					t.Fatalf("SetWebAdminTOTPSecret: %v", err)
				}
				return url.Values{"code": {totpCodeFor(t, secret)}}, func() {}
			},
			fn: func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleMeTOTPEnable },
		},
		{
			name: "disable", path: "/me/totp/disable",
			setup: func(t *testing.T, s *Server, admin *store.WebAdmin) (url.Values, func()) {
				secret, _ := enableTOTPDirect(t, s, admin, 1)
				return url.Values{"code": {totpCodeFor(t, secret)}}, func() {}
			},
			fn: func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleMeTOTPDisable },
		},
		{
			name: "regen", path: "/me/totp/regen-codes",
			setup: func(t *testing.T, s *Server, admin *store.WebAdmin) (url.Values, func()) {
				secret, _ := enableTOTPDirect(t, s, admin, 1)
				return url.Values{"code": {totpCodeFor(t, secret)}}, func() {}
			},
			fn: func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleMeTOTPRegen },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			admin := createTestAdmin(t, s, "alice", pw)
			form, _ := tc.setup(t, s, admin)
			// 只打掉"消费时间步"那条 UPDATE。
			abortSQLiteWrites(t, s, "kill_step_consume", "web_admins", "UPDATE",
				"NEW.totp_last_used_step <> OLD.totp_last_used_step")

			const ip = "10.40.0.1"
			w := httptest.NewRecorder()
			tc.fn(s)(w, mePost(t, s, admin, tc.path, form, ip))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("code=%d, 期望 503(body=%q)", w.Code, trimForLog(w.Body.String()))
			}
			if n := s.stepUpFailures.Recent(ip); n != 0 {
				t.Fatalf("被记了 %d 次 step-up 失败 —— 正确的码不该因为库抖动进冷却", n)
			}
		})
	}
}

// =========================================================================
// 吊销 / 换发会话失败:留痕,但不阻断
// =========================================================================

// 启用 / 关闭 2FA 之后要吊销其余会话并给当前操作者换发 token。这一步失败时:
// 2FA 的状态变更**已经落库**,不能因为收尾失败就回滚或报错(否则用户会重试,
// 而重试的前提是再输一次码);正确做法是留审计痕迹,退化成"下次登录才彻底生效"。
func TestMe_SessionSweepFailureIsAuditedButNotFatal(t *testing.T) {
	const pw = "AdminPass123!"
	cases := []struct {
		name    string
		trigger [3]string // table, op, when
		audit   string
	}{
		{"删不掉旧会话", [3]string{"web_sessions", "DELETE", ""}, "totp_enable_revoke_failed"},
		{"换发不出新会话", [3]string{"web_sessions", "INSERT", ""}, "totp_enable_reissue_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			admin := createTestAdmin(t, s, "alice", pw)
			secret, err := GenerateTOTPSecret()
			if err != nil {
				t.Fatalf("GenerateTOTPSecret: %v", err)
			}
			if err := s.store.SetWebAdminTOTPSecret(t.Context(), admin.ID, secret); err != nil {
				t.Fatalf("SetWebAdminTOTPSecret: %v", err)
			}
			// DELETE 触发器要有行可删才会响,先造一条会话。
			if _, err := s.sess.IssueSession(t.Context(), httptest.NewRecorder(),
				admin.ID, "10.41.0.9", "ua"); err != nil {
				t.Fatalf("IssueSession: %v", err)
			}
			abortSQLiteWrites(t, s, "kill_sess", tc.trigger[0], tc.trigger[1], tc.trigger[2])

			w := httptest.NewRecorder()
			s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
				url.Values{"code": {totpCodeFor(t, secret)}}, "10.41.0.1"))
			if w.Code != http.StatusSeeOther {
				t.Fatalf("code=%d, 期望 303(收尾失败不该阻断启用;body=%q)",
					w.Code, trimForLog(w.Body.String()))
			}
			cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
			if !cur.TOTPEnabled {
				t.Fatal("2FA 没有被启用")
			}
			assertAuditAction(t, s, tc.audit)
		})
	}
}

// 关闭 2FA 的收尾同理。
func TestMeTOTPDisable_SessionSweepFailureIsAuditedButNotFatal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		op    string
		audit string
	}{
		{"删不掉旧会话", "DELETE", "totp_disable_revoke_failed"},
		{"换发不出新会话", "INSERT", "totp_disable_reissue_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			admin := createTestAdmin(t, s, "alice", "AdminPass123!")
			_, codes := enableTOTPDirect(t, s, admin, 1)
			if _, err := s.sess.IssueSession(t.Context(), httptest.NewRecorder(),
				admin.ID, "10.42.0.9", "ua"); err != nil {
				t.Fatalf("IssueSession: %v", err)
			}
			abortSQLiteWrites(t, s, "kill_sess", "web_sessions", tc.op, "")

			w := httptest.NewRecorder()
			s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
				url.Values{"recovery_code": {codes[0]}}, "10.42.0.1"))
			if w.Code != http.StatusSeeOther {
				t.Fatalf("code=%d, 期望 303(body=%q)", w.Code, trimForLog(w.Body.String()))
			}
			cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
			if cur.TOTPEnabled {
				t.Fatal("2FA 没有被关闭")
			}
			assertAuditAction(t, s, tc.audit)
		})
	}
}

// =========================================================================
// 杂项闸门
// =========================================================================

// enable 时 2FA 已经开着 → 直接回 /me,不走第二遍启用。
func TestMeTOTPEnable_AlreadyEnabledJustRedirects(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)

	w := httptest.NewRecorder()
	s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {totpCodeFor(t, secret)}}, "10.43.0.1"))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d, 期望 303", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/me") {
		t.Errorf("Location=%q, 期望回 /me", loc)
	}
}

// 二维码画不出来(URI 超出 QR 容量)时要显式报错,而不是给一张坏图。
//
// 反向代理把 Host 头改成一长串(或者被人手工塞进来)时,otpauth URI 会超过 QR
// 版本 40 的上限。此时页面上是个 broken icon,用户只会以为"网页坏了",
// 而实际是这一步彻底不可用 —— 要么报错要么就别渲染。
func TestMeTOTPSetup_UnrenderableQRIsAnError(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)

	req := mePost(t, s, admin, "/me/totp/setup", url.Values{"password": {pw}}, "10.45.0.1")
	req.Host = strings.Repeat("h", 4000) // 远超 QR 容量
	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500(body=%q)", w.Code, trimForLog(w.Body.String()))
	}
	if strings.Contains(w.Body.String(), "data:image/png") {
		t.Fatal("画不出来却还是输出了一张图")
	}
}

// 验过码之后 secret 被换掉(并发重开 setup)→ 409,绝不能把新 secret 启用。
//
// 攻击面很具体:受害者在自己的页面上验过**他手机上**的 secret S1,同会话的攻击者
// 抢在写库前把 secret 换成 S2。若 enable 只看"有 secret 就行",启用的就是 S2 ——
// 受害者手机上的码从此全部失效,第二因子落到攻击者手里。
//
// 造法:用一个 AFTER UPDATE 触发器搭车 —— 消费时间步的那条 UPDATE 一落地就把
// secret 改掉,正好落在"验完码"与"写 enabled"之间,比起线程调度更精确。
func TestMeTOTPEnable_SecretRotatedBeforeWriteIsAConflict(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := s.store.SetWebAdminTOTPSecret(t.Context(), admin.ID, secret); err != nil {
		t.Fatalf("SetWebAdminTOTPSecret: %v", err)
	}
	rotated, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if _, err := s.store.DB().ExecContext(t.Context(),
		`CREATE TRIGGER rotate_secret_midway AFTER UPDATE ON web_admins
		   WHEN NEW.totp_last_used_step <> OLD.totp_last_used_step
		 BEGIN
		   UPDATE web_admins SET totp_secret='`+rotated+`' WHERE id=NEW.id;
		 END`); err != nil {
		t.Fatalf("装换 secret 的触发器: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {totpCodeFor(t, secret)}}, "10.46.0.1"))

	if w.Code != http.StatusConflict {
		t.Fatalf("code=%d, 期望 409(body=%q)", w.Code, trimForLog(w.Body.String()))
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.TOTPEnabled {
		t.Fatal("被换掉的 secret 被启用了")
	}
	left, err := s.store.ListUnusedRecoveryCodes(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("ListUnusedRecoveryCodes: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("冲突路径写进了 %d 条恢复码", len(left))
	}
}

// argon2 排不上号时,setup 的密码 step-up 要回 503,不计冷却。
//
// 与登录密码步同一道理:容量抖动不是用户之过,记成"密码错"的话,压满 CPU 就能
// 让管理员自助开 2FA 的入口被冷却 5 分钟。
func TestMeTOTPSetup_Argon2UnavailableReturns503(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	const ip = "10.47.0.1"

	stop := saturateArgon2(t, 4*time.Second)
	defer stop()

	var got503 bool
	for i := 0; i < 8 && !got503; i++ {
		req := mePost(t, s, admin, "/me/totp/setup", url.Values{"password": {pw}}, ip)
		// 从原 ctx 派生,别把 middleware 放进去的 admin 身份丢掉。
		ctx, cancel := context.WithTimeout(req.Context(), 200*time.Millisecond)
		w := httptest.NewRecorder()
		s.handleMeTOTPSetup(w, req.WithContext(ctx))
		cancel()
		if w.Code == http.StatusServiceUnavailable {
			got503 = true
		}
	}
	if !got503 {
		t.Fatal("排不上号时没有回 503")
	}
	if n := s.stepUpFailures.Recent(ip); n != 0 {
		t.Fatalf("被记了 %d 次 step-up 失败", n)
	}
}

// regen 空验证码不计冷却(与 disable / setup 的空输入一致)。
func TestMeTOTPRegen_EmptyCodeIsNotCounted(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	enableTOTPDirect(t, s, admin, 1)

	const ip = "10.44.0.1"
	for i := 0; i < stepUpMaxFailures+2; i++ {
		w := httptest.NewRecorder()
		s.handleMeTOTPRegen(w, mePost(t, s, admin, "/me/totp/regen-codes", url.Values{}, ip))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("空码 code=%d, 期望 400", w.Code)
		}
	}
	if n := s.stepUpFailures.Recent(ip); n != 0 {
		t.Fatalf("空提交累加了 %d 次 step-up 失败", n)
	}
}
