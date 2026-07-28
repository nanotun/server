package main

// handler_auth_issue_guards_test.go(第二十轮)—— 登录/初始化页面上「凭据签发」
// 一步失败时的行为,以及 AttemptLogin 里几条只有在库/argon2 出问题时才走的分支。
//
// handler_auth_guards_test.go 已经把「密码错怎么算」「PoW/captcha 怎么拦」钉住了。
// 这里补的是另一类:CSRF token / 验证码 / PoW 题目**签不出来**的时候。
//
// 为什么值得单独钉:这三样都是「防线本身」。签不出来时若还照常渲染表单,
// 用户就会看到一个没有 CSRF 隐藏字段、没有验证码图、没有 PoW 输入的登录页 ——
// 页面看着能用,提交却必然失败(死循环),更糟的是万一下游校验也跟着放水,
// 那道闸就等于在这次故障里被临时拆掉了。正确行为是明确报 500。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// setupServer:一个还没有任何管理员、允许 setup 的 server。
func setupGuardServer(t *testing.T) *Server {
	t.Helper()
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true
	return s
}

// -------------------------------------------------------------------------
// /setup 与 /login 的 GET:三样凭据签不出来都要 500
// -------------------------------------------------------------------------

// nth 对应 GET 分支里 randRead 的调用顺序:1=CSRF token,2=验证码答案,
// 3=验证码 nonce,4=PoW challenge_id。难度为 0 时不会走到第 4 次。
func TestAuthPages_CredentialIssueFailureIs500(t *testing.T) {
	cases := []struct {
		name    string
		nth     int
		armPoW  bool
		handler func(*Server) func(http.ResponseWriter, *http.Request)
		target  string
	}{
		{"setup:CSRF 签不出来", 1, false, func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleSetup }, "/setup"},
		{"setup:验证码画不出来", 2, false, func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleSetup }, "/setup"},
		{"setup:PoW 出不了题", 4, true, func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleSetup }, "/setup"},
		{"login:CSRF 签不出来", 1, false, func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleLogin }, "/login"},
		{"login:验证码画不出来", 2, false, func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleLogin }, "/login"},
		{"login:PoW 出不了题", 4, true, func(s *Server) func(http.ResponseWriter, *http.Request) { return s.handleLogin }, "/login"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := setupGuardServer(t)
			if strings.HasPrefix(tc.target, "/login") {
				createTestAdmin(t, s, "root", "AdminPass123!") // 有管理员才不会被弹去 /setup
			}
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			req.RemoteAddr = "198.51.100.7:40000"
			if tc.armPoW {
				armPoWForIP(t, s, clientIP(req))
			}
			stubRandRead(t, tc.nth)

			w := httptest.NewRecorder()
			tc.handler(s)(w, req)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code=%d, 期望 500 —— 签不出凭据却照常渲染了表单(用户会陷入「页面能开、提交必失败」)",
					w.Code)
			}
		})
	}
}

// /login/totp 的 GET 同理:CSRF 签不出来必须 500,不能渲染一个交不上去的表单。
func TestLoginTOTPPage_CSRFIssueFailureIs500(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	enableTOTPDirect(t, s, admin, 1)
	pending := issuePending(t, s, admin.ID, loginTestIP)

	req := httptest.NewRequest(http.MethodGet, "/login/totp", nil)
	req.RemoteAddr = loginTestIP + ":40000"
	req.AddCookie(pending)
	stubRandRead(t, 1)

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
}

// -------------------------------------------------------------------------
// /setup POST:哈希失败不能建出账号
// -------------------------------------------------------------------------

// 首个管理员的密码哈希失败时,绝不能带着空/坏 hash 建号 —— 那个账号任何密码都
// 登不进去,而 web_admins 一非空,setup 这扇门就永久关闭:控制台被锁死,
// Web 侧没有任何补救路径。
func TestSetup_HashFailureCreatesNoAdmin(t *testing.T) {
	s := setupGuardServer(t)
	orig := HashWebPassword
	HashWebPassword = func(string) (string, error) {
		return "$argon2id$broken", errors.New("注入的哈希故障")
	}
	t.Cleanup(func() { HashWebPassword = orig })

	w := httptest.NewRecorder()
	s.handleSetup(w, setupPost(t, s, goodSetupForm()))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q, 期望 200(打回 setup 页重填)", w.Code, trimForLog(w.Body.String()))
	}
	if n := countAdmins(t, s); n != 0 {
		t.Fatalf("哈希失败却建出了 %d 个管理员 —— setup 从此永久关闭", n)
	}
	if hasSessionCookie(w) {
		t.Fatal("没建成账号却颁了会话")
	}
}

// 会话签不出来时也不能就这么算了:账号已经建好(首建是原子的、不回滚),
// 但必须明确报 500 让运维知道「账号建成了、这次没登进去」,而不是给个
// 看起来正常的 302 —— 那会让人以为已经登录,而其实没有任何 cookie。
func TestSetup_SessionIssueFailureIs500(t *testing.T) {
	s := setupGuardServer(t)
	req := setupPost(t, s, goodSetupForm())
	stubRandRead(t, 1) // POST 路径里第一次 randRead 就是 session id

	w := httptest.NewRecorder()
	s.handleSetup(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if hasSessionCookie(w) {
		t.Fatal("签不出会话却写了会话 cookie")
	}
}

// -------------------------------------------------------------------------
// /login POST:pending cookie 签不出来
// -------------------------------------------------------------------------

// 密码对了、账号开了 TOTP,这时 pending cookie 签不出来必须 500。
// 不能退化成「直接颁 session」—— 那等于跳过第二因子;也不能静默 302 到
// /login/totp:那一页没有 pending 就只会把用户弹回 /login,死循环。
func TestLogin_PendingIssueFailureIs500AndNoSession(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	enableTOTPDirect(t, s, admin, 1)

	req := loginPost(t, s, url.Values{"username": {"alice"}, "password": {pw}}, loginTestIP)
	stubRandRead(t, 1) // 密码验证不用随机数,第一次调用就是 pending nonce

	w := httptest.NewRecorder()
	s.handleLogin(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if hasSessionCookie(w) {
		t.Fatal("pending 签不出来却直接颁了会话(第二因子被跳过)")
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("失败却还 302 到了 %q", loc)
	}
}

// -------------------------------------------------------------------------
// AttemptLogin:只有库/argon2 出问题时才走的分支
// -------------------------------------------------------------------------

// 查库失败(不是「用户不存在」)要给出可本地化的错误,而不是当成密码错。
// 当成密码错会累加失败计数 —— 一次 DB 抖动就能替攻击者推进锁定。
func TestAttemptLogin_QueryFailureIsNotBadCredentials(t *testing.T) {
	s := newMeTestServer(t)
	createTestAdmin(t, s, "alice", "AdminPass123!")
	// 把这一行写坏:按用户名查得到行,但扫不出来。
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE web_admins SET created_at='not-a-number'`); err != nil {
		t.Fatalf("注入坏管理员行: %v", err)
	}

	res := AttemptLogin(t.Context(), s.store, s.cfg, "alice", "AdminPass123!", loginTestIP)
	if res.Err == nil {
		t.Fatal("查库失败却登录成功了")
	}
	if errors.Is(res.Err, ErrAuthBadCredentials) {
		t.Fatal("查库失败被当成了密码错(会替攻击者推进账号锁定)")
	}
	var le *locErr
	if !errors.As(res.Err, &le) {
		t.Fatalf("err=%v(%T), 期望可本地化错误 —— 否则英文界面会渲染出中文", res.Err, res.Err)
	}
}

// 成功登录时那次「记录成功」写库失败,不该拦住登录:密码已经验过了,
// 拦下来等于因为审计写不进去就把人挡在门外。
func TestAttemptLogin_RecordSuccessFailureStillLetsYouIn(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	abortSQLiteWrites(t, s, "no_login_success", "web_admins", "UPDATE OF last_login_at", "")

	res := AttemptLogin(t.Context(), s.store, s.cfg, "alice", pw, loginTestIP)
	if res.Err != nil {
		t.Fatalf("记录成功写失败却拦住了登录: %v", res.Err)
	}
	if res.Admin == nil || res.Admin.ID != admin.ID {
		t.Fatalf("返回的管理员不对: %+v", res.Admin)
	}
}

// argon2 闸门被压满时,三条 decoy 分支(用户不存在 / 账号被禁 / 账号被锁)
// 都必须回「暂时不可用」,而不是各自的 401/403 —— 否则响应码差异就是一张
// 用户名与账号状态的枚举表:压满闸门后逐个试,能分出「存在=503」和
// 「不存在=401」。
func TestAttemptLogin_DecoyPathsReport503WhenArgon2IsFull(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	disabled := createTestAdmin(t, s, "disabled", pw)
	locked := createTestAdmin(t, s, "locked", pw)
	createTestAdmin(t, s, "keeper", pw) // floor 守卫:至少留一个启用的 admin
	if err := s.store.SetWebAdminEnabled(t.Context(), disabled.ID, false); err != nil {
		t.Fatalf("禁用: %v", err)
	}
	if err := lockAdminUntil(t, s, locked.ID, nowUnix()+3600); err != nil {
		t.Fatalf("锁定: %v", err)
	}

	stop := saturateArgon2(t, 6*time.Second)
	defer stop()

	for _, username := range []string{"nosuchuser", "disabled", "locked"} {
		t.Run(username, func(t *testing.T) {
			var got bool
			for i := 0; i < 8 && !got; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				res := AttemptLogin(ctx, s.store, s.cfg, username, pw, loginTestIP)
				cancel()
				if errors.Is(res.Err, ErrAuthUnavailable) {
					got = true
				}
			}
			if !got {
				t.Fatal("闸门压满时没回「暂时不可用」—— 响应差异会变成用户名/账号状态枚举表")
			}
		})
	}
	// 被禁账号不该因为这些尝试累加失败计数(它连密码步都进不去)。
	if n := failedLoginsOf(t, s, disabled.ID); n != 0 {
		t.Fatalf("被禁账号被记了 %d 次失败", n)
	}
}

// lockAdminUntil 直接把 locked_until 写到未来,模拟「已被锁定的账号」。
func lockAdminUntil(t *testing.T, s *Server, adminID, until int64) error {
	t.Helper()
	_, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE web_admins SET locked_until=? WHERE id=?`, until, adminID)
	return err
}
