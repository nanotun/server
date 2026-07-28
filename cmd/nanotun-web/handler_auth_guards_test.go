package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
)

// 本文件补的是 /setup、/login、/login/totp 三个**未登录即可访问**的 handler 上,
// 此前没有任何测试碰过的那些分支 —— 全都是「出错的时候」和「被人抢跑的时候」。
//
// 这些路径的共同特征是:正常流程永远走不到,所以肉眼 review 很容易放过;可一旦
// 它们的行为不对,后果都不是"报错难看",而是安全属性直接消失:
//   - 数库出错被当成「库里没有管理员」→ setup 在生产系统上重新开门;
//   - argon2 容量打满被当成「密码错」→ 攻击者只要压满 CPU 就能把合法管理员锁死;
//   - 二次因子那段临界区若只认请求开始时读到的行 → 应急改密/停用斩不断在途登录;
//   - 恢复码「烧掉」与「颁会话」两步任一失败没回滚 → 一码一用被打破,或码白烧。

// -------------------------------------------------------------------------
// 故障注入与 PoW 求解的小工具
// -------------------------------------------------------------------------

// abortSQLiteWrites 用 SQLite 触发器把某张表的某类写操作打成失败,模拟「写库这一步
// 抖了一下」。when 非空时作为 WHEN 条件,用来精确命中事务里的**某一步**(比如只让
// 消费 TOTP 时间步的那条 UPDATE 失败,而账号锁定计数照常能写)。
func abortSQLiteWrites(t *testing.T, s *Server, name, table, op, when string) {
	t.Helper()
	cond := ""
	if when != "" {
		cond = " WHEN " + when
	}
	sql := "CREATE TRIGGER " + name + " BEFORE " + op + " ON " + table + cond +
		" BEGIN SELECT RAISE(ABORT, 'injected: " + name + "'); END"
	if _, err := s.store.DB().ExecContext(t.Context(), sql); err != nil {
		t.Fatalf("装故障触发器 %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = s.store.DB().Exec("DROP TRIGGER IF EXISTS " + name)
	})
}

// armPoWForIP 把某个 IP 的失败计数顶到「服务端开始要求 PoW」那一档,返回当前期望难度。
func armPoWForIP(t *testing.T, s *Server, ip string) int {
	t.Helper()
	for i := 0; i < powFailuresEnable; i++ {
		s.sess.ipFailures.Inc(ip)
	}
	d := ComputeDifficulty(s.sess.ipFailures.Recent(ip))
	if d <= 0 {
		t.Fatalf("失败 %d 次后期望难度仍是 %d —— 自适应 PoW 根本没启用", powFailuresEnable, d)
	}
	return d
}

// solvePoWFields 现场解一道 diff 位的题,返回可直接塞进表单的字段。
// 14 位 ≈ 一万六千次 SHA256,毫秒级;这也是真实浏览器 solver 干的活。
func solvePoWFields(t *testing.T, s *Server, diff int) url.Values {
	t.Helper()
	ch, err := s.sess.IssueChallenge(diff)
	if err != nil {
		t.Fatalf("IssueChallenge(%d): %v", diff, err)
	}
	if !ch.IsRequired() {
		t.Fatalf("难度 %d 竟然不下发题目", diff)
	}
	salt, err := base64.StdEncoding.DecodeString(ch.Salt)
	if err != nil {
		t.Fatalf("salt 不是 base64: %v", err)
	}
	var nonce uint64
	for ; nonce < 50_000_000; nonce++ {
		if powVerify(ch.ChallengeID, salt, ch.Difficulty, nonce) {
			break
		}
	}
	if nonce >= 50_000_000 {
		t.Fatalf("难度 %d 解不出来(算法坏了?)", ch.Difficulty)
	}
	return url.Values{
		"pow_challenge_id": {ch.ChallengeID},
		"pow_salt":         {ch.Salt},
		"pow_difficulty":   {strconv.Itoa(ch.Difficulty)},
		"pow_expires_at":   {strconv.FormatInt(ch.ExpiresAt, 10)},
		"pow_signature":    {ch.Signature},
		"pow_nonce":        {strconv.FormatUint(nonce, 10)},
	}
}

func mergeForm(dst, src url.Values) url.Values {
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func lockedUntilOf(t *testing.T, s *Server, adminID int64) int64 {
	t.Helper()
	a, err := s.store.GetWebAdmin(t.Context(), adminID)
	if err != nil || a == nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	return a.LockedUntil
}

func failedLoginsOf(t *testing.T, s *Server, adminID int64) int64 {
	t.Helper()
	a, err := s.store.GetWebAdmin(t.Context(), adminID)
	if err != nil || a == nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	return a.FailedLogins
}

// sessionRowsOf 数库里这个 admin 名下真实存在的会话条数(cookie 可以骗人,库不会)。
func sessionRowsOf(t *testing.T, s *Server, adminID int64) int {
	t.Helper()
	list, err := s.store.ListWebSessionsByAdmin(t.Context(), adminID)
	if err != nil {
		t.Fatalf("ListWebSessionsByAdmin: %v", err)
	}
	return len(list)
}

// =========================================================================
// /setup
// =========================================================================

// 数不出管理员时,门必须是关着的。
//
// 这条判断是 setup 唯一的准入依据。要是把「读库失败」和「库里没人」混为一谈,
// 那么任何能让这条 SELECT 出错的时刻(磁盘满、文件被替换、库被锁死),都会让一台
// 已经在跑的生产系统重新打开 TOFU 窗口 —— 谁先 POST 谁就是新主人。
func TestSetup_CountFailureClosesTheDoorInsteadOfOpeningIt(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true
	createTestAdmin(t, s, "incumbent", "pw-incumbent-123")
	if err := s.store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, m := range []string{http.MethodGet, http.MethodPost} {
		w := httptest.NewRecorder()
		s.handleSetup(w, httptest.NewRequest(m, "/setup", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("%s: code=%d, 期望 500(读库失败要显式报错,不能装作库是空的)", m, w.Code)
		}
		if strings.Contains(w.Body.String(), "csrf_token") {
			t.Fatalf("%s: 读库失败却渲染出了 setup 表单", m)
		}
	}
}

// 同 IP 攒够失败之后,setup 也要过 PoW —— 且合法用户按新难度重算一遍就能过去。
//
// /setup 是全新部署里唯一的无凭证写库端点,验证码之外还需要 PoW 给自动化抢占加成本。
// 三个子用例分别钉:题目缺字段要拒、拿低难度的旧签名重放要拒、老老实实算完要放行。
func TestSetup_PoWGateEngagesAfterFailuresAndStillLetsHumansIn(t *testing.T) {
	t.Run("缺字段", func(t *testing.T) {
		s := newMeTestServer(t)
		s.cfg.AllowSetup = true
		armPoWForIP(t, s, "198.51.100.9")

		w := httptest.NewRecorder()
		s.handleSetup(w, setupPost(t, s, goodSetupForm()))
		if w.Code == http.StatusFound {
			t.Fatalf("没带 PoW 却建成了(302 → %q)", w.Header().Get("Location"))
		}
		if n := countAdmins(t, s); n != 0 {
			t.Fatalf("建出了 %d 个管理员", n)
		}
		assertAuditAction(t, s, "web.setup.pow_fail")
	})

	t.Run("低难度签名重放", func(t *testing.T) {
		s := newMeTestServer(t)
		s.cfg.AllowSetup = true
		want := armPoWForIP(t, s, "198.51.100.9")
		// 服务端自己签发的题,但难度低于此刻期望值:攻击者攒了一堆廉价旧题再一次性打过来。
		cheap := solvePoWFields(t, s, powMinDifficulty)
		if powMinDifficulty >= want {
			t.Skipf("最低难度(%d)已达期望(%d),本用例无意义", powMinDifficulty, want)
		}

		w := httptest.NewRecorder()
		s.handleSetup(w, setupPost(t, s, mergeForm(goodSetupForm(), cheap)))
		if w.Code == http.StatusFound {
			t.Fatalf("低难度签名被放过了(302 → %q)", w.Header().Get("Location"))
		}
		if n := countAdmins(t, s); n != 0 {
			t.Fatalf("建出了 %d 个管理员", n)
		}
		assertAuditAction(t, s, "web.setup.pow_fail")
	})

	t.Run("算对了就放行", func(t *testing.T) {
		s := newMeTestServer(t)
		s.cfg.AllowSetup = true
		want := armPoWForIP(t, s, "198.51.100.9")

		w := httptest.NewRecorder()
		s.handleSetup(w, setupPost(t, s, mergeForm(goodSetupForm(), solvePoWFields(t, s, want))))
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/" {
			t.Fatalf("code=%d loc=%q body=%q —— 难度抬升后合法用户被永久挡在门外了",
				w.Code, w.Header().Get("Location"), trimForLog(w.Body.String()))
		}
		if adminByName(t, s, "firstadmin") == nil {
			t.Fatal("PoW 过了却没建出管理员")
		}
	})
}

// 建管理员那条 INSERT 失败时,不能留下"半个已初始化的系统"。
func TestSetup_CreateFailureLeavesNothingBehind(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true
	abortSQLiteWrites(t, s, "kill_admin_insert", "web_admins", "INSERT", "")

	w := httptest.NewRecorder()
	s.handleSetup(w, setupPost(t, s, goodSetupForm()))
	if w.Code == http.StatusFound {
		t.Fatalf("写库失败却回了 302 → %q", w.Header().Get("Location"))
	}
	if n := countAdmins(t, s); n != 0 {
		t.Fatalf("建出了 %d 个管理员", n)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == s.sess.cookieName(sessionCookieName) && c.Value != "" {
			t.Fatal("建失败却颁了会话 cookie")
		}
	}
	// 表单要能接着用:retry 页得重新给 CSRF 与验证码,否则用户卡死在这一页。
	var hasCSRF, hasCaptcha bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case s.sess.cookieName(csrfCookieName):
			hasCSRF = true
		case s.sess.cookieName(captchaCookieName):
			hasCaptcha = true
		}
	}
	if !hasCSRF || !hasCaptcha {
		t.Fatalf("retry 页 cookie 缺失: csrf=%v captcha=%v", hasCSRF, hasCaptcha)
	}
}

// 管理员建成了但会话发不出来:要显式 500,不能假装登录成功。
//
// 关键在于**不能**把这次失败渲染成"请重新 setup":此刻表已非空,setup 已经永久
// 关闭,再引导用户走 setup 只会绕圈。500 之后去 /login 用刚设的密码登录才是出路。
func TestSetup_SessionIssueFailureSurfacesAsError(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true
	abortSQLiteWrites(t, s, "kill_session_insert", "web_sessions", "INSERT", "")

	w := httptest.NewRecorder()
	s.handleSetup(w, setupPost(t, s, goodSetupForm()))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
	admin := adminByName(t, s, "firstadmin")
	if admin == nil {
		t.Fatal("管理员应当已经建成(失败发生在颁会话这步)")
	}
	if hasSessionCookie(w) {
		t.Fatal("会话没建成却下发了会话 cookie")
	}
	if n := sessionRowsOf(t, s, admin.ID); n != 0 {
		t.Fatalf("库里有 %d 条会话, 期望 0", n)
	}
}

// 两个人同时抢首个管理员:只能有一个成功,落败方拿 302,不能变成两个管理员。
//
// CountWebAdmins==0 的预检和 INSERT 之间有一段真空,靠 DAL 的原子首建收口。
// 这里让两个请求真并发跑一遍,验证收口在 handler 这一层也接对了(落败方按
// 「系统已初始化」处理,而不是把 ErrSetupClosed 当成 500 或者重试建第二个)。
func TestSetup_ConcurrentRaceCreatesExactlyOneAdmin(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true

	formA := goodSetupForm()
	formA.Set("username", "racer-a")
	formB := goodSetupForm()
	formB.Set("username", "racer-b")
	reqA := setupPost(t, s, formA)
	reqB := setupPost(t, s, formB)

	wA, wB := httptest.NewRecorder(), httptest.NewRecorder()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.handleSetup(wA, reqA) }()
	go func() { defer wg.Done(); s.handleSetup(wB, reqB) }()
	wg.Wait()

	if n := countAdmins(t, s); n != 1 {
		t.Fatalf("并发抢建后有 %d 个管理员, 期望恰好 1 个", n)
	}
	sessions := 0
	for _, w := range []*httptest.ResponseRecorder{wA, wB} {
		if hasSessionCookie(w) {
			sessions++
		}
		if w.Code != http.StatusFound {
			t.Errorf("code=%d body=%q, 两边都该是 302(赢家去 /,落败方去 /login)",
				w.Code, trimForLog(w.Body.String()))
		}
	}
	if sessions > 1 {
		t.Fatalf("%d 个请求都拿到了会话", sessions)
	}
}

// =========================================================================
// /login
// =========================================================================

// 库里还没有管理员时,登录页要把人送去 setup(否则全新部署无从下手)。
func TestLogin_RedirectsToSetupWhileUninitialized(t *testing.T) {
	s := newMeTestServer(t)
	s.cfg.AllowSetup = true

	for _, m := range []string{http.MethodGet, http.MethodPost} {
		w := httptest.NewRecorder()
		s.handleLogin(w, httptest.NewRequest(m, "/login", nil))
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/setup" {
			t.Fatalf("%s: code=%d loc=%q, 期望 302 /setup", m, w.Code, w.Header().Get("Location"))
		}
	}

	// 反面:运维关掉了 setup(首管由 CLI 下发)时不能再往 /setup 引 —— 那边只会 302 回来,
	// 两个 handler 互相踢皮球就是一个死循环。
	s.cfg.AllowSetup = false
	w := httptest.NewRecorder()
	s.handleLogin(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	if w.Code == http.StatusFound && w.Header().Get("Location") == "/setup" {
		t.Fatal("AllowSetup=false 时仍把用户踢向 /setup(与 /setup 的 302 /login 构成死循环)")
	}
}

// 撞库脚本把同 IP 的失败攒起来之后,/login 也要过 PoW;合法用户重算即可通过。
func TestLogin_PoWGateEngagesAfterFailuresAndStillLetsHumansIn(t *testing.T) {
	const pw = "AdminPass123!"

	t.Run("缺字段", func(t *testing.T) {
		s := newMeTestServer(t)
		createTestAdmin(t, s, "alice", pw)
		armPoWForIP(t, s, loginTestIP)

		w := httptest.NewRecorder()
		s.handleLogin(w, loginPost(t, s, url.Values{
			"username": {"alice"}, "password": {pw},
		}, loginTestIP))
		if hasSessionCookie(w) {
			t.Fatal("没带 PoW 却拿到了会话")
		}
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("code=%d, 期望 401 回渲", w.Code)
		}
		assertAuditAction(t, s, "web.login.pow_fail")
	})

	t.Run("低难度签名重放", func(t *testing.T) {
		s := newMeTestServer(t)
		createTestAdmin(t, s, "alice", pw)
		want := armPoWForIP(t, s, loginTestIP)
		if powMinDifficulty >= want {
			t.Skipf("最低难度(%d)已达期望(%d),本用例无意义", powMinDifficulty, want)
		}
		cheap := solvePoWFields(t, s, powMinDifficulty)

		w := httptest.NewRecorder()
		s.handleLogin(w, loginPost(t, s, mergeForm(url.Values{
			"username": {"alice"}, "password": {pw},
		}, cheap), loginTestIP))
		if hasSessionCookie(w) {
			t.Fatal("低难度签名换来了会话")
		}
		assertAuditAction(t, s, "web.login.pow_fail")
	})

	t.Run("算对了就放行", func(t *testing.T) {
		s := newMeTestServer(t)
		createTestAdmin(t, s, "alice", pw)
		want := armPoWForIP(t, s, loginTestIP)

		w := httptest.NewRecorder()
		s.handleLogin(w, loginPost(t, s, mergeForm(url.Values{
			"username": {"alice"}, "password": {pw},
		}, solvePoWFields(t, s, want)), loginTestIP))
		if !hasSessionCookie(w) {
			t.Fatalf("难度抬升后算对了题却登不进来(code=%d body=%q)",
				w.Code, trimForLog(w.Body.String()))
		}
	})
}

// 密码对、但会话建不出来:要 500,不能"看起来登录成功了"。
//
// 若这里静默放过,浏览器手里没有任何 cookie 却被送到 /,中间件再把人踢回 /login,
// 用户看到的是"密码明明是对的却一直登不进去",而日志里什么都没有。
func TestLogin_SessionIssueFailureSurfacesAsError(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	abortSQLiteWrites(t, s, "kill_session_insert", "web_sessions", "INSERT", "")

	w := httptest.NewRecorder()
	s.handleLogin(w, loginPost(t, s, url.Values{
		"username": {"alice"}, "password": {pw},
	}, loginTestIP))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
	if hasSessionCookie(w) {
		t.Fatal("建会话失败却下发了会话 cookie")
	}
	if n := sessionRowsOf(t, s, admin.ID); n != 0 {
		t.Fatalf("库里有 %d 条会话, 期望 0", n)
	}
}

// argon2 排不上号(容量打满 / 请求超时)时:回 503,**不**记失败、**不**锁账号。
//
// 这是一条纯粹的可用性攻击面:验证密码要过全局 argon2 信号量,攻击者只要并发压满
// 这道闸,合法管理员的每次登录都会"验不出来"。若把这种排不上号当成密码错,
// MaxLoginFailures 次之后账号就被锁 —— 攻击者不需要知道任何密码,就能把管理员
// 锁在门外(并且锁的是**真**管理员,他自己重试只会加速锁定)。
//
// 造法:把信号量占满,再用一个短 deadline 的请求去登录 —— 查库很快,卡在 Acquire。
func TestLogin_Argon2CapacityExhaustionReturns503AndNeverLocksTheAccount(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	alice := createTestAdmin(t, s, "alice", pw)
	bob := createTestAdmin(t, s, "bob", pw)
	// 恢复码要过 argon2,必须在压满信号量**之前**准备好。
	_, codes := enableTOTPDirect(t, s, bob, 1)
	pending := issuePending(t, s, bob.ID, loginTestIP)

	stop := saturateArgon2(t, 4*time.Second)
	defer stop()

	// 密码步:排不上号 → 503。
	var got503 bool
	for i := 0; i < 8 && !got503; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		w := httptest.NewRecorder()
		s.handleLogin(w, loginPost(t, s, url.Values{
			"username": {"alice"}, "password": {pw},
		}, loginTestIP).WithContext(ctx))
		cancel()
		if w.Code == http.StatusServiceUnavailable {
			got503 = true
		}
		if hasSessionCookie(w) {
			t.Fatalf("第 %d 次:排不上号却颁了会话", i+1)
		}
	}
	if !got503 {
		t.Fatal("信号量占满时登录没有回 503(要么被当成密码错,要么静默放过)")
	}
	if n := failedLoginsOf(t, s, alice.ID); n != 0 {
		t.Fatalf("argon2 排不上号被记成了 %d 次密码错 —— 压满 CPU 即可锁死合法管理员", n)
	}
	if u := lockedUntilOf(t, s, alice.ID); u > nowUnix() {
		t.Fatalf("账号被锁到 %d —— 容量抖动被放大成了锁定 DoS", u)
	}

	// 恢复码那步同理:比对恢复码也要过同一道闸。
	got503 = false
	for i := 0; i < 8 && !got503; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		w := httptest.NewRecorder()
		s.handleLoginTOTP(w, loginTOTPPost(t, s,
			url.Values{"recovery_code": {codes[0]}}, loginTestIP, pending).WithContext(ctx))
		cancel()
		if w.Code == http.StatusServiceUnavailable {
			got503 = true
		}
		if hasSessionCookie(w) {
			t.Fatalf("第 %d 次:排不上号却颁了会话", i+1)
		}
	}
	if !got503 {
		t.Fatal("信号量占满时恢复码校验没有回 503")
	}
	if n := failedLoginsOf(t, s, bob.ID); n != 0 {
		t.Fatalf("恢复码排不上号被记成了 %d 次失败", n)
	}
	// 码没被判失败,也就不该被烧掉 —— 用户重试还得能用。
	left, err := s.store.ListUnusedRecoveryCodes(t.Context(), bob.ID)
	if err != nil {
		t.Fatalf("ListUnusedRecoveryCodes: %v", err)
	}
	if len(left) != 1 {
		t.Fatalf("剩 %d 条未用恢复码, 期望 1(排不上号不该消耗凭据)", len(left))
	}
}

// saturateArgon2 在 d 时间内把全局 argon2 信号量占满,返回等待收尾的函数。
//
// 占位用的 PHC 是合法但故意"慢"的参数(m=32MiB, t=100, p=1):单次一秒半以上,
// **远长于**下面每次尝试的 200ms deadline。这一点是必须的 —— 信号量的等待队列是
// 先来先服务,占位者一放手排在队首的请求马上就能拿到号;只有让每次占用都远长于
// 请求的等待上限,才能稳定复现"排不上号"。比对必然失败,不涉及任何真实秘密。
func saturateArgon2(t *testing.T, d time.Duration) func() {
	t.Helper()
	// 与 auth.computeArgon2Capacity 同式:NumCPU*2,夹在 [8,64]。
	capacity := runtime.NumCPU() * 2
	if capacity < 8 {
		capacity = 8
	}
	if capacity > 64 {
		capacity = 64
	}
	slow := auth.EncodePSK(make([]byte, 16), make([]byte, 32), 32*1024, 100, 1)
	// 先确认这串参数仍在 DecodePSK 的接受区间内 —— 若哪天参数上下限收紧把它拒了,
	// 占位者会退化成"秒失败 + 疯狂重试",闸门根本压不住,那种失败模式很难看出原因。
	if _, _, _, _, _, err := auth.DecodePSK(slow); err != nil {
		t.Fatalf("占位用的 PHC 不被接受(argon2 参数上下限变了?): %v", err)
	}
	deadline := time.Now().Add(d)
	var wg sync.WaitGroup
	for i := 0; i < capacity; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				_, _ = auth.VerifyPSKLimited(context.Background(), "nope", slow)
			}
		}()
	}
	// 等占位的 goroutine 真的把闸门吃满,再让调用方发起请求。
	time.Sleep(300 * time.Millisecond)
	return wg.Wait
}

// =========================================================================
// /login/totp
// =========================================================================

// GET 页面要渲染出用户名与 next,并且顺延 CSRF —— 否则这一页交不上去。
func TestLoginTOTP_GETRendersFormForPendingAdmin(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	enableTOTPDirect(t, s, admin, 1)

	req := httptest.NewRequest(http.MethodGet, "/login/totp?next=%2Fdevices", nil)
	req.AddCookie(issuePending(t, s, admin.ID, loginTestIP))
	req.RemoteAddr = loginTestIP + ":40000"
	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q, 期望 200", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	if !strings.Contains(body, "alice") {
		t.Error("页面没显示用户名")
	}
	if !strings.Contains(body, "csrf_token") {
		t.Error("页面没有 CSRF 字段 —— 表单交不上去")
	}
	if !strings.Contains(body, "/devices") {
		t.Error("next 没带进表单 —— 二次验证后回不到原页面")
	}
	if hasSessionCookie(w) {
		t.Fatal("GET 渲染页面就颁了会话")
	}
}

// 没有 pending 时的回退也要把 next 带上,并且只带站内路径。
func TestLoginTOTP_MissingPendingKeepsSafeNextOnly(t *testing.T) {
	s := newMeTestServer(t)
	createTestAdmin(t, s, "alice", "AdminPass123!")

	for _, c := range []struct{ next, wantLoc string }{
		{"/devices", "/login?next=%2Fdevices"},
		{"https://evil.example.com/x", "/login"},
		{"", "/login"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/login/totp?next="+url.QueryEscape(c.next), nil)
		req.RemoteAddr = loginTestIP + ":40000"
		w := httptest.NewRecorder()
		s.handleLoginTOTP(w, req)
		if w.Code != http.StatusFound {
			t.Fatalf("next=%q code=%d, 期望 302", c.next, w.Code)
		}
		if loc := w.Header().Get("Location"); loc != c.wantLoc {
			t.Errorf("next=%q → Location=%q, 期望 %q", c.next, loc, c.wantLoc)
		}
	}
}

// 二次因子那段临界区必须认**锁内重读**的行,而不是请求刚进来时的快照。
//
// 攻击模型:攻击者已经拿到密码、手里有一枚 pending,正卡在这段临界区上(并发下
// 完全正常 —— 前面有一把按账号的锁)。管理员这时做应急处置:停用账号 / 关掉 2FA /
// 改密 / 账号刚被锁。如果这段只信请求开始时读到的那一行,处置就是"晚了一步",
// 攻击者照样能在处置**之后**拿到一枚新会话。
//
// 造法:测试先把这把按账号的锁攥在手里,放 handler 进来堵在锁上,此时改库,再放行。
func TestLoginTOTP_ReReadsTheRowInsideTheLock(t *testing.T) {
	const pw = "AdminPass123!"
	newHash, err := HashWebPassword("BrandNewPass456!")
	if err != nil {
		t.Fatalf("HashWebPassword: %v", err)
	}

	cases := []struct {
		name     string
		mutate   func(t *testing.T, s *Server, admin *store.WebAdmin)
		wantCode int
		wantLoc  string
		audit    string
	}{
		{
			name: "账号被停用",
			mutate: func(t *testing.T, s *Server, admin *store.WebAdmin) {
				if err := s.store.SetWebAdminEnabled(t.Context(), admin.ID, false); err != nil {
					t.Errorf("SetWebAdminEnabled: %v", err)
				}
			},
			wantCode: http.StatusFound, wantLoc: "/login",
		},
		{
			name: "2FA 被关掉",
			mutate: func(t *testing.T, s *Server, admin *store.WebAdmin) {
				if err := s.store.DisableWebAdminTOTP(t.Context(), admin.ID); err != nil {
					t.Errorf("DisableWebAdminTOTP: %v", err)
				}
			},
			wantCode: http.StatusFound, wantLoc: "/login",
		},
		{
			name: "应急改密",
			mutate: func(t *testing.T, s *Server, admin *store.WebAdmin) {
				if err := s.store.UpdateWebAdminPasswordHash(t.Context(), admin.ID, newHash); err != nil {
					t.Errorf("UpdateWebAdminPasswordHash: %v", err)
				}
			},
			wantCode: http.StatusFound, wantLoc: "/login",
			audit: "web.totp.pending_stale",
		},
		{
			name: "账号刚被锁",
			mutate: func(t *testing.T, s *Server, admin *store.WebAdmin) {
				if _, err := s.store.DB().ExecContext(t.Context(),
					`UPDATE web_admins SET locked_until=? WHERE id=?`,
					nowUnix()+600, admin.ID); err != nil {
					t.Errorf("锁账号: %v", err)
				}
			},
			// 锁定在这一步是明确展示倒计时的(此时已凭密码 + pending 证明账号存在,
			// 不再泄露存在性),所以是 401 回渲而非 302。
			wantCode: http.StatusUnauthorized,
			audit:    "web.totp.locked",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			admin := createTestAdmin(t, s, "alice", pw)
			secret, _ := enableTOTPDirect(t, s, admin, 1)
			pending := issuePending(t, s, admin.ID, loginTestIP)
			req := loginTOTPPost(t, s, url.Values{"code": {totpCodeFor(t, secret)}},
				loginTestIP, pending)

			// 先把按账号的锁攥住,handler 会堵在 lockTOTPVerify 上 —— 此刻它已经读过旧行。
			unlock := s.lockTOTPVerify(admin.ID)
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				s.handleLoginTOTP(w, req)
			}()
			time.Sleep(150 * time.Millisecond)
			tc.mutate(t, s, admin)
			unlock()
			<-done

			if hasSessionCookie(w) {
				t.Fatalf("处置(%s)之后在途登录仍然拿到了会话", tc.name)
			}
			if w.Code != tc.wantCode {
				t.Errorf("code=%d, 期望 %d(body=%q)", w.Code, tc.wantCode, trimForLog(w.Body.String()))
			}
			if tc.wantLoc != "" && w.Header().Get("Location") != tc.wantLoc {
				t.Errorf("Location=%q, 期望 %q", w.Header().Get("Location"), tc.wantLoc)
			}
			if n := sessionRowsOf(t, s, admin.ID); n != 0 {
				t.Fatalf("库里多出了 %d 条会话", n)
			}
			if tc.audit != "" {
				assertAuditAction(t, s, tc.audit)
			}
		})
	}
}

// 一枚 pending 被两个请求同时用完:只能成一次,而且落败方不许烧掉恢复码。
//
// 两条请求分别用恢复码和 6 位码,于是两边**都能**通过校验 —— 挡住第二次的只有
// pending nonce 的服务端一次性消费。若那道闸失效,截获到 pending 的人就能在窗口内
// 反复完成第二因子;更隐蔽的是落败方顺手把一枚恢复码标记为已用,用户凭据白丢一张。
func TestLoginTOTP_ConcurrentDoubleSubmitCompletesOnlyOnce(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, codes := enableTOTPDirect(t, s, admin, 2)
	pending := issuePending(t, s, admin.ID, loginTestIP)

	reqRecovery := loginTOTPPost(t, s, url.Values{"recovery_code": {codes[0]}}, loginTestIP, pending)
	reqCode := loginTOTPPost(t, s, url.Values{"code": {totpCodeFor(t, secret)}}, loginTestIP, pending)

	// 两个请求都先过 LookupTOTPPending(nonce 尚未被消费),然后一起堵在按账号的锁上。
	unlock := s.lockTOTPVerify(admin.ID)
	wRecovery, wCode := httptest.NewRecorder(), httptest.NewRecorder()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.handleLoginTOTP(wRecovery, reqRecovery) }()
	go func() { defer wg.Done(); s.handleLoginTOTP(wCode, reqCode) }()
	time.Sleep(200 * time.Millisecond)
	unlock()
	wg.Wait()

	won := 0
	for _, w := range []*httptest.ResponseRecorder{wRecovery, wCode} {
		if hasSessionCookie(w) {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d 个请求拿到了会话, 期望恰好 1 个(recovery=%d code=%d)",
			won, wRecovery.Code, wCode.Code)
	}
	if n := sessionRowsOf(t, s, admin.ID); n != 1 {
		t.Fatalf("库里有 %d 条会话, 期望 1", n)
	}
	assertAuditAction(t, s, "web.totp.pending_replay")

	left, err := s.store.ListUnusedRecoveryCodes(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("ListUnusedRecoveryCodes: %v", err)
	}
	wantLeft := 2
	if hasSessionCookie(wRecovery) {
		wantLeft = 1 // 恢复码那条赢了,烧掉一枚是应该的
	}
	if len(left) != wantLeft {
		t.Fatalf("剩 %d 条未用恢复码, 期望 %d(落败方不该烧码)", len(left), wantLeft)
	}
}

// 码验过了、会话却建不出来:清掉 pending 并显式报错。
//
// pending 的 nonce 已经在前一步被消费,若不把 cookie 清掉,用户重试会撞上
// "pending 重放"再被踢回登录页 —— 表现成"输对了码却怎么都进不去"。
func TestLoginTOTP_SessionIssueFailureClearsPending(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	abortSQLiteWrites(t, s, "kill_session_insert", "web_sessions", "INSERT", "")

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s, url.Values{"code": {totpCodeFor(t, secret)}},
		loginTestIP, issuePending(t, s, admin.ID, loginTestIP)))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
	if hasSessionCookie(w) {
		t.Fatal("建会话失败却下发了会话 cookie")
	}
	if c := pendingCookieOf(w); c == nil || c.Value != "" || c.MaxAge >= 0 {
		t.Fatalf("没清掉 pending: %+v", c)
	}
}

// 恢复码"标记已用"失败时,刚发出去的会话要连库带 cookie 一起收回。
//
// 顺序是先发会话再烧码(反过来的话:会话建失败就白烧一枚码)。既然是这个顺序,
// 烧码失败就必须回滚会话 —— 否则出现"会话已发、码还没标记 used"的状态,那枚码
// 可以被再用一次,一码一用当场破功。
func TestLoginTOTP_RecoveryMarkFailureRollsBackTheSession(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	_, codes := enableTOTPDirect(t, s, admin, 1)
	abortSQLiteWrites(t, s, "kill_recovery_update", "web_admin_recovery_codes", "UPDATE", "")

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s, url.Values{"recovery_code": {codes[0]}},
		loginTestIP, issuePending(t, s, admin.ID, loginTestIP)))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d, 期望 401 回渲", w.Code)
	}
	if n := sessionRowsOf(t, s, admin.ID); n != 0 {
		t.Fatalf("库里残留 %d 条会话 —— 烧码失败没有回滚会话", n)
	}
	// 会话 cookie 先发后清,浏览器认的是**最后**那枚:它必须是空值 + 立即过期。
	var last *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == s.sess.cookieName(sessionCookieName) {
			last = c
		}
	}
	if last == nil || last.Value != "" || last.MaxAge >= 0 {
		t.Fatalf("回滚后浏览器手里还留着会话 cookie: %+v", last)
	}
	if c := pendingCookieOf(w); c == nil || c.Value != "" || c.MaxAge >= 0 {
		t.Fatalf("没清掉 pending: %+v", c)
	}
}

// 消费 TOTP 时间步的那条 UPDATE 出错 ≠ 码错:回 503,不记失败,不消费 pending。
//
// 码本身已经验过了,只是"记一下这一步用掉了"这条写库抖了一下。把它当成码错的话,
// 一个正确的码 + 一次 DB 抖动就会推进账号锁定 —— 与 argon2 排不上号同类的放大伤害。
func TestLoginTOTP_StepConsumeDBErrorReturns503NotAFailure(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	// 只打掉"消费时间步"那条 UPDATE;账号锁定计数器那条 UPDATE 照常可写,
	// 这样才能验证"没有被记成失败"是代码的选择,而不是因为写不进去。
	abortSQLiteWrites(t, s, "kill_step_consume", "web_admins", "UPDATE",
		"NEW.totp_last_used_step <> OLD.totp_last_used_step")

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s, url.Values{"code": {totpCodeFor(t, secret)}},
		loginTestIP, issuePending(t, s, admin.ID, loginTestIP)))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code=%d, 期望 503(body=%q)", w.Code, trimForLog(w.Body.String()))
	}
	if hasSessionCookie(w) {
		t.Fatal("消费时间步失败却颁了会话")
	}
	if n := failedLoginsOf(t, s, admin.ID); n != 0 {
		t.Fatalf("被记成了 %d 次失败 —— 正确的码 + 一次 DB 抖动就能推进锁定", n)
	}
	if c := pendingCookieOf(w); c != nil && (c.Value == "" || c.MaxAge < 0) {
		t.Fatal("pending 被清掉了 —— 用户没做错任何事,应当可以直接重试")
	}
	assertAuditAction(t, s, "web.totp.unavailable")
}

// 恢复码列表读不出来时,绝不能当成"校验通过"。
func TestLoginTOTP_RecoveryListFailureIsNeverTreatedAsMatch(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	_, codes := enableTOTPDirect(t, s, admin, 1)
	// 把 SELECT 列表里要读的列改名,让那条查询直接报错。
	if _, err := s.store.DB().ExecContext(t.Context(),
		`ALTER TABLE web_admin_recovery_codes RENAME COLUMN code_hash TO code_hash_gone`); err != nil {
		t.Fatalf("改列名: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s, url.Values{"recovery_code": {codes[0]}},
		loginTestIP, issuePending(t, s, admin.ID, loginTestIP)))

	if hasSessionCookie(w) {
		t.Fatal("读不出恢复码却放行了")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d, 期望 401", w.Code)
	}
	assertAuditAction(t, s, "web.totp.fail")
}

// 恢复码格式不对时在 argon2 之前就拒掉(否则一串垃圾输入也要烧一次哈希)。
func TestLoginTOTP_MalformedRecoveryCodeRejectedBeforeHashing(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	enableTOTPDirect(t, s, admin, 1)

	w := httptest.NewRecorder()
	s.handleLoginTOTP(w, loginTOTPPost(t, s, url.Values{"recovery_code": {"!!!"}},
		loginTestIP, issuePending(t, s, admin.ID, loginTestIP)))
	if hasSessionCookie(w) {
		t.Fatal("畸形恢复码换来了会话")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d, 期望 401", w.Code)
	}
}

// verifyTOTPOrRecovery 的兜底:两边都空 → 明确的 empty_code,而不是"通过"。
//
// handler 在更早的地方就挡掉了空提交,所以这条只能直接调到。留着它是纵深:
// 将来任何新调用方(或者那道前置检查被挪走)都不能把"什么都没填"变成放行。
func TestVerifyTOTPOrRecovery_EmptyInputIsAFailureWithReason(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	enableTOTPDirect(t, s, admin, 1)
	cur, err := s.store.GetWebAdmin(t.Context(), admin.ID)
	if err != nil || cur == nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}

	ok, usedRecovery, id, reason := s.verifyTOTPOrRecovery(t.Context(), cur, "", "")
	if ok || usedRecovery || id != 0 {
		t.Fatalf("空输入被判通过: ok=%v recovery=%v id=%d", ok, usedRecovery, id)
	}
	if reason != "empty_code" {
		t.Errorf("reason=%q, 期望 empty_code(审计要能看出是空提交)", reason)
	}
}

// step-up 的码也是一码一用:同一枚码不能既过登录又过高危二次确认。
//
// 这些 step-up(开关 2FA、重生成恢复码、亮出服务端 QR)与登录共用同一个"已用时间步"
// 计数器。共用的意义:攻击者肩窥到一枚码之后,不能拿它去做另一件事。
func TestVerifyAndConsumeStepUpTOTP_SameCodeCannotBeReused(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	code := totpCodeFor(t, secret)

	if err := s.verifyAndConsumeStepUpTOTP(t.Context(), admin.ID, secret, code); err != nil {
		t.Fatalf("首次应当通过: %v", err)
	}
	err := s.verifyAndConsumeStepUpTOTP(t.Context(), admin.ID, secret, code)
	if err != ErrTOTPMismatch {
		t.Fatalf("err=%v, 期望 ErrTOTPMismatch(重放与码错不做区分)", err)
	}
}

// step-up 里"消费时间步"写库失败,要冒泡成专属哨兵而不是"码错"。
// 调用方据此回 503,不把一次 DB 抖动累加进 step-up 冷却。
func TestVerifyAndConsumeStepUpTOTP_DBErrorIsNotAMismatch(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	secret, _ := enableTOTPDirect(t, s, admin, 1)
	abortSQLiteWrites(t, s, "kill_step_consume", "web_admins", "UPDATE",
		"NEW.totp_last_used_step <> OLD.totp_last_used_step")

	err := s.verifyAndConsumeStepUpTOTP(t.Context(), admin.ID, secret, totpCodeFor(t, secret))
	if err == nil {
		t.Fatal("写库失败却返回了成功")
	}
	if err == ErrTOTPMismatch {
		t.Fatal("DB 抖动被当成了码错 —— 会把正确的码推进 step-up 冷却")
	}
	if !strings.Contains(err.Error(), ErrTOTPStepUnavailable.Error()) {
		t.Fatalf("err=%v, 期望包 ErrTOTPStepUnavailable", err)
	}
}
