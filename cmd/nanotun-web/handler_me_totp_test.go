package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件覆盖管理员自助 2FA 的四个写动作(setup / enable / disable / regen-codes)
// 与那张一次性恢复码页。
//
// TOTP 的原语(码计算、恢复码生成与归一化)在 totp_test.go 里已经测得很细,缺的是
// **编排**:密码 step-up、IP 冷却、时间步消费、启用后吊销旧会话、恢复码一次性。
// 这些都不在原语里,而恰恰是「2FA 开了但没真开」这类问题的所在 —— 比如启用 2FA
// 却不吊销启用**之前**签发的会话,那个可能早已被盗的 cookie 仍然有效,新加的第二
// 因子直接被绕过。

// newMeTestServer 造一个能跑 /me/totp/* 的 Server:这些 handler 自己校验 CSRF、
// 用 stepUpFailures 做冷却、用 credFlash 传恢复码,还要渲染真实模板。
func newMeTestServer(t *testing.T) *Server {
	t.Helper()
	s := newServerQRTestServer(t)
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	s.tmpl = tmpl
	return s
}

// mePost 造一个 CSRF 合法、带 admin 身份的 POST。
// ip 为空时用 httptest 默认;需要隔离 step-up 冷却计数的用例请显式传。
func mePost(t *testing.T, s *Server, admin *store.WebAdmin, path string,
	form url.Values, ip string) *http.Request {

	t.Helper()
	issueW := httptest.NewRecorder()
	tok, err := s.sess.IssueCSRFToken(httptest.NewRequest(http.MethodGet, path, nil), issueW)
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", tok)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", issueW.Header().Get("Set-Cookie"))
	if ip != "" {
		req.RemoteAddr = ip + ":12345"
	}
	return withAdminCtx(req, admin)
}

// totpCodeFor 算出 secret 在当前时间步的 6 位码。
func totpCodeFor(t *testing.T, secret string) string {
	t.Helper()
	return totpCodeForStep(t, secret, 0)
}

// totpCodeForStep 算出偏移 delta 个时间步的码。
//
// 用途:时间步是被消费掉的(防重放),同一枚码不能连用两次。需要「刚验过码、
// 马上再验一次」时,取 delta=+1 —— 它落在 ±1 的时钟容忍窗内、当下即可通过,
// 步号又大于刚消费的那个,不必真的干等 30 秒。
func totpCodeForStep(t *testing.T, secret string, delta int64) string {
	t.Helper()
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		t.Fatalf("decodeTOTPSecret: %v", err)
	}
	step := nowUnix()/int64(totpPeriodSec) + delta
	return paddedDigits(truncatedHOTP(key, uint64(step)), totpDigits)
}

// enrollTOTP 走完整的 setup+enable,返回 secret 与 10 条明文恢复码。
// 后续用例大多需要「已启用 2FA」的起点,这里一次性铺好。
func enrollTOTP(t *testing.T, s *Server, admin *store.WebAdmin, password string) (string, []string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {password}}, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("setup code=%d body=%q, 期望 200", w.Code, trimForLog(w.Body.String()))
	}
	cur, err := s.store.GetWebAdmin(t.Context(), admin.ID)
	if err != nil || cur == nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if cur.TOTPSecret == "" {
		t.Fatalf("setup 之后 secret 仍为空")
	}

	w = httptest.NewRecorder()
	s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {totpCodeFor(t, cur.TOTPSecret)}}, ""))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("enable code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
	}
	codes := popRecoveryCodes(t, s, admin, w.Header().Get("Location"))
	return cur.TOTPSecret, codes
}

// popRecoveryCodes 消费 enable/regen 那个 303 里的一次性 token,取出明文恢复码。
//
// 直接走 credFlash 而不是渲染页面再从 HTML 里抠字符串:后者会把页面上任何长得像
// 恢复码的东西一起捞进来,测试挂了还得先怀疑是不是解析错了。那张页面本身由
// TestMeTOTPCodes_* 单独覆盖。
func popRecoveryCodes(t *testing.T, s *Server, admin *store.WebAdmin, location string) []string {
	t.Helper()
	const prefix = "/me/totp/codes?token="
	if !strings.HasPrefix(location, prefix) {
		t.Fatalf("Location=%q, 期望跳到一次性恢复码页", location)
	}
	payload, err := s.credFlash.Pop(strings.TrimPrefix(location, prefix),
		credentialsFlashKindRecoveryCodes, admin.ID)
	if err != nil {
		t.Fatalf("取一次性恢复码: %v", err)
	}
	return strings.Split(payload.RecoveryCodes, "\n")
}

// =========================================================================
// 完整生命周期
// =========================================================================

// TestMeTOTP_FullLifecycle:开 → 拿恢复码 → 用恢复码关 → 状态回到干净。
//
// 逐段单测容易各自都过、串起来却断:比如 enable 写了 secret 却没写恢复码、
// disable 清了 enabled 标记却把 secret 留在库里(下次 setup 直接复用旧 secret,
// 等于 2FA 没真的解绑)。这条链路把四个动作串起来跑一遍。
func TestMeTOTP_FullLifecycle(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)

	secret, codes := enrollTOTP(t, s, admin, pw)
	if len(codes) != 10 {
		t.Fatalf("恢复码 %d 条, 期望 10 条", len(codes))
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if !cur.TOTPEnabled {
		t.Fatalf("enable 之后 TOTPEnabled 仍为 false")
	}
	if cur.TOTPSecret != secret {
		t.Fatalf("启用的 secret 与 setup 生成的不一致")
	}

	// 用恢复码关闭(而不是 6 位码:enable 刚消费掉当前时间步,同一枚码会被判重放)。
	w := httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
		url.Values{"recovery_code": {codes[0]}}, ""))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("disable code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
	}

	cur, _ = s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.TOTPEnabled {
		t.Errorf("disable 之后 TOTPEnabled 仍为 true")
	}
	// secret 必须一起清掉:留着的话下次 setup 可能复用,旧的 authenticator 条目还能用。
	if cur.TOTPSecret != "" {
		t.Errorf("disable 之后 secret 未清除: %q", cur.TOTPSecret)
	}
	// 恢复码必须全部作废,否则「2FA 已关」的账号上还挂着 9 条能过 step-up 的凭据。
	left, err := s.store.ListUnusedRecoveryCodes(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("ListUnusedRecoveryCodes: %v", err)
	}
	if len(left) != 0 {
		t.Errorf("disable 之后还剩 %d 条恢复码", len(left))
	}
	assertAuditAction(t, s, "totp_enable")
	assertAuditAction(t, s, "totp_disable")
}

// =========================================================================
// setup
// =========================================================================

// TestMeTOTPSetup_RequiresCorrectPassword:绑定新 secret 必须密码 step-up。
//
// 没有这道闸,一个被劫持的(尚未开 2FA 的)会话就能绑定**攻击者自己的**
// authenticator 并领走恢复码 —— 本系统没有「管理员帮别人清 TOTP」的动作,
// 合法管理员会被彻底锁在门外,只能删号重建。
func TestMeTOTPSetup_RequiresCorrectPassword(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)

	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {"WrongPass123!"}}, "10.20.0.1"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("错误密码 code=%d, 期望 401", w.Code)
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.TOTPSecret != "" {
		t.Fatalf("密码错却已经写入 secret")
	}
	if n := s.stepUpFailures.Recent("10.20.0.1"); n != 1 {
		t.Errorf("失败计数 = %d, 期望 1", n)
	}
	if countAudit(t, s, "totp_setup_password_fail") != 1 {
		t.Errorf("密码错误没写审计")
	}
}

// TestMeTOTPSetup_EmptyPasswordIsNotCounted:空密码是误提交,不该吃冷却配额。
//
// 计数的话,连点几下保存就把自己锁进 5 分钟冷却,而这期间连正确密码也用不了。
func TestMeTOTPSetup_EmptyPasswordIsNotCounted(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")

	for _, pw := range []string{"", "   "} {
		w := httptest.NewRecorder()
		s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
			url.Values{"password": {pw}}, "10.21.0.1"))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("空密码 code=%d, 期望 400", w.Code)
		}
	}
	if n := s.stepUpFailures.Recent("10.21.0.1"); n != 0 {
		t.Errorf("空密码计入了失败配额: %d", n)
	}
}

// TestMeTOTPSetup_RejectedWhenAlreadyEnabled:已开 2FA 时不能直接重新 setup。
//
// 允许一键覆盖 = 拿到会话就能把第二因子换成自己的,还不需要旧的码。
// 正确姿势是先 disable(要验码)再 setup。
func TestMeTOTPSetup_RejectedWhenAlreadyEnabled(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	secret, _ := enrollTOTP(t, s, admin, pw)

	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {pw}}, ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("已启用时 setup code=%d, 期望 400", w.Code)
	}
	// secret 必须没被换掉,否则用户手机上的条目当场失效。
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.TOTPSecret != secret {
		t.Fatalf("被拒的 setup 却换掉了 secret")
	}
}

// TestMeTOTPSetup_IPCooldownBlocks:攒够失败次数后直接 429,连正确密码也不放行。
func TestMeTOTPSetup_IPCooldownBlocks(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	const ip = "10.22.0.1"
	for i := 0; i < stepUpMaxFailures; i++ {
		s.stepUpFailures.Inc(ip)
	}

	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {pw}}, ip))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("冷却中 code=%d, 期望 429", w.Code)
	}
	if countAudit(t, s, "totp_setup_locked") != 1 {
		t.Errorf("冷却拦截没写审计")
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.TOTPSecret != "" {
		t.Errorf("冷却中却生成了 secret")
	}
}

// TestMeTOTPSetup_DisabledAccountIsRejected:已停用的账号不能做 step-up 操作。
func TestMeTOTPSetup_DisabledAccountIsRejected(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	if err := s.store.SetWebAdminEnabled(t.Context(), admin.ID, false); err != nil {
		t.Fatalf("SetWebAdminEnabled: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {pw}}, ""))
	if w.Code != http.StatusForbidden {
		t.Fatalf("停用账号 code=%d, 期望 403", w.Code)
	}
}

// =========================================================================
// enable
// =========================================================================

// TestMeTOTPEnable_WrongCodeDoesNotEnable:码错就不能开,且 secret 要留着让用户重试。
func TestMeTOTPEnable_WrongCodeDoesNotEnable(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {pw}}, ""))
	before, _ := s.store.GetWebAdmin(t.Context(), admin.ID)

	w = httptest.NewRecorder()
	s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {"000000"}}, "10.23.0.1"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("错码 code=%d, 期望 400", w.Code)
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.TOTPEnabled {
		t.Fatalf("码错却启用了 2FA")
	}
	// secret 保留:Authenticator 上的码 30 秒一滚,用户重输一次就好,
	// 清掉的话得从头扫码。
	if cur.TOTPSecret != before.TOTPSecret {
		t.Errorf("码错不该清掉 secret")
	}
	if n := s.stepUpFailures.Recent("10.23.0.1"); n != 1 {
		t.Errorf("失败计数 = %d, 期望 1", n)
	}
	if countAudit(t, s, "totp_enable_code_fail") != 1 {
		t.Errorf("错码没写审计")
	}
}

// TestMeTOTPEnable_EmptyCodeIsNotCounted:空码不吃配额。
func TestMeTOTPEnable_EmptyCodeIsNotCounted(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {pw}}, ""))

	w = httptest.NewRecorder()
	s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {"  "}}, "10.24.0.1"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("空码 code=%d, 期望 400", w.Code)
	}
	if n := s.stepUpFailures.Recent("10.24.0.1"); n != 0 {
		t.Errorf("空码计入了失败配额: %d", n)
	}
}

// TestMeTOTPEnable_RequiresSetupFirst:没走 setup(库里无 secret)时不能 enable。
//
// 光看状态码不够 —— 没有这道前置检查,请求会一路走到「拿空 secret 验码」,同样
// 返回 400,但**会记一次 step-up 失败**。用户在 setup 页还没扫码就手快点了确认,
// 点几下就把自己关进 5 分钟冷却,而他一次密码/码都没输错。
func TestMeTOTPEnable_RequiresSetupFirst(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")
	const ip = "10.30.0.1"

	w := httptest.NewRecorder()
	s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {"123456"}}, ip))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("无 secret 时 code=%d, 期望 400", w.Code)
	}
	if n := s.stepUpFailures.Recent(ip); n != 0 {
		t.Errorf("「还没生成密钥」不该计入失败配额, 计数 = %d", n)
	}
	if countAudit(t, s, "totp_enable_code_fail") != 0 {
		t.Errorf("「还没生成密钥」不该记成码错审计")
	}
}

// TestMeTOTPEnable_RevokesSessionsIssuedBeforeTwoFactor:启用 2FA 必须吊销旧会话。
//
// 这是整套 2FA 里最容易漏、漏了又最致命的一条:如果 cookie 在**开 2FA 之前**
// 就被盗了(那时只要密码),开完 2FA 旧 cookie 照样有效 —— 攻击者根本不用碰第二
// 因子,刚加的这层防护形同虚设。与「改密原子吊销」是同一条对称规则。
func TestMeTOTPEnable_RevokesSessionsIssuedBeforeTwoFactor(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)

	// 模拟一个「开 2FA 之前就存在」的会话(可能已被盗)。
	oldW := httptest.NewRecorder()
	if _, err := s.sess.IssueSession(t.Context(), oldW, admin.ID, "10.0.0.9", "old-ua"); err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	oldCookie := oldW.Header().Get("Set-Cookie")
	probe := httptest.NewRequest(http.MethodGet, "/", nil)
	probe.Header.Set("Cookie", oldCookie)
	if _, _, err := s.sess.LookupSession(t.Context(), probe); err != nil {
		t.Fatalf("旧会话本应有效: %v", err)
	}

	enrollTOTP(t, s, admin, pw)

	probe = httptest.NewRequest(http.MethodGet, "/", nil)
	probe.Header.Set("Cookie", oldCookie)
	if _, _, err := s.sess.LookupSession(t.Context(), probe); !errors.Is(err, ErrNoSession) {
		t.Fatalf("启用 2FA 后旧会话仍然有效(err=%v)—— 开 2FA 之前被盗的 cookie 可绕过第二因子", err)
	}
}

// TestMeTOTPEnable_SecretRotatedUnderneathIsConflict:验码与启用之间 secret 被换掉 → 409。
//
// store 层用 CAS 保证「启用的一定是刚验过的那个 secret」。少了这层,并发的两个
// setup 可能让账号启用一个用户手机上并不存在的 secret —— 直接把自己锁死。
func TestMeTOTPEnable_SecretRotatedUnderneathIsConflict(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {pw}}, ""))
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	code := totpCodeFor(t, cur.TOTPSecret)

	// 直接把库里的 secret 换成另一个,模拟并发 setup 抢跑。
	other, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if err := s.store.SetWebAdminTOTPSecret(t.Context(), admin.ID, other); err != nil {
		t.Fatalf("SetWebAdminTOTPSecret: %v", err)
	}

	w = httptest.NewRecorder()
	s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {code}}, ""))
	// 用旧 secret 算的码对新 secret 不成立,拿到 400(码错)即可;
	// 关键是**没有**把 2FA 启用起来。
	if w.Code == http.StatusSeeOther {
		t.Fatalf("secret 已被换掉,不该启用成功")
	}
	cur, _ = s.store.GetWebAdmin(t.Context(), admin.ID)
	if cur.TOTPEnabled {
		t.Fatalf("用过期 secret 的码启用了 2FA")
	}
}

// =========================================================================
// disable
// =========================================================================

// TestMeTOTPDisable_WrongCodeKeepsTOTPOn:码错关不掉。
func TestMeTOTPDisable_WrongCodeKeepsTOTPOn(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	enrollTOTP(t, s, admin, pw)

	w := httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
		url.Values{"code": {"000000"}}, "10.25.0.1"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("错码 code=%d, 期望 400", w.Code)
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if !cur.TOTPEnabled {
		t.Fatalf("码错却关掉了 2FA")
	}
	if n := s.stepUpFailures.Recent("10.25.0.1"); n != 1 {
		t.Errorf("失败计数 = %d, 期望 1", n)
	}
	if countAudit(t, s, "totp_disable_fail") != 1 {
		t.Errorf("关闭失败没写审计")
	}
}

// TestMeTOTPDisable_WrongRecoveryCodeIsRejected:随便编一个格式正确的恢复码也不行。
func TestMeTOTPDisable_WrongRecoveryCodeIsRejected(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	_, codes := enrollTOTP(t, s, admin, pw)

	// 拿一条真码改掉最后一个字符 —— 格式合法但不匹配任何 hash。替换字符要挑一个**与原字符
	// 不同**的:恢复码是 base32,末位本来就有 1/32 的机会正好等于替换字符,那时「伪造码」就是
	// 真码,2FA 真被关掉、返回 303,这条用例会随机翻车(2026-07-29 -race 全量里就中过一次)。
	last := codes[0][len(codes[0])-1]
	repl := "Z"
	if last == 'Z' {
		repl = "Y"
	}
	bogus := codes[0][:len(codes[0])-1] + repl
	w := httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
		url.Values{"recovery_code": {bogus}}, "10.26.0.1"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("伪造恢复码 code=%d, 期望 400", w.Code)
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	if !cur.TOTPEnabled {
		t.Fatalf("伪造恢复码关掉了 2FA")
	}
	// 真码必须仍然可用(没被这次失败尝试误标为已用)。
	left, _ := s.store.ListUnusedRecoveryCodes(t.Context(), admin.ID)
	if len(left) != 10 {
		t.Errorf("失败尝试后剩余恢复码 %d 条, 期望 10 条", len(left))
	}
}

// TestMeTOTPDisable_EmptyInputIsNotCounted:两个字段都空 = 误提交,不吃配额。
func TestMeTOTPDisable_EmptyInputIsNotCounted(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	enrollTOTP(t, s, admin, pw)

	w := httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable", url.Values{}, "10.27.0.1"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("空输入 code=%d, 期望 400", w.Code)
	}
	if n := s.stepUpFailures.Recent("10.27.0.1"); n != 0 {
		t.Errorf("空输入计入了失败配额: %d", n)
	}
}

// TestMeTOTPDisable_RevokesOtherSessions:关闭 2FA 同样要吊销其余会话。
//
// 与启用时那条对称。关 2FA 的常见起因就是「验证器设备丢了 / 怀疑被人动过」,
// 这时候把其它在线会话一起清掉才说得通;留着的话,真出事时这个动作等于没做。
func TestMeTOTPDisable_RevokesOtherSessions(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	_, codes := enrollTOTP(t, s, admin, pw)

	otherW := httptest.NewRecorder()
	if _, err := s.sess.IssueSession(t.Context(), otherW, admin.ID, "10.0.0.9", "other-ua"); err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	otherCookie := otherW.Header().Get("Set-Cookie")

	w := httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
		url.Values{"recovery_code": {codes[0]}}, ""))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("disable code=%d, 期望 303", w.Code)
	}

	probe := httptest.NewRequest(http.MethodGet, "/", nil)
	probe.Header.Set("Cookie", otherCookie)
	if _, _, err := s.sess.LookupSession(t.Context(), probe); !errors.Is(err, ErrNoSession) {
		t.Fatalf("关闭 2FA 后其余会话仍然有效(err=%v)", err)
	}
}

// TestMeTOTPDisable_WhenNotEnabledRedirects:没开过就点关闭 → 温和跳回 /me,不是报错。
func TestMeTOTPDisable_WhenNotEnabledRedirects(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")

	w := httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
		url.Values{"code": {"123456"}}, ""))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("未启用时 code=%d, 期望 303", w.Code)
	}
}

// =========================================================================
// regen-codes
// =========================================================================

// TestMeTOTPRegen_InvalidatesOldCodes:重刷恢复码后,旧码必须立刻失效。
//
// 旧码还能用的话,「我怀疑恢复码泄露了,重新生成一批」这个动作就毫无意义。
func TestMeTOTPRegen_InvalidatesOldCodes(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	secret, oldCodes := enrollTOTP(t, s, admin, pw)

	// enable 刚消费掉当前时间步,同一枚码会被判重放 —— 用下一步的码(在 ±1 容忍窗内)。
	w := httptest.NewRecorder()
	s.handleMeTOTPRegen(w, mePost(t, s, admin, "/me/totp/regen-codes",
		url.Values{"code": {totpCodeForStep(t, secret, 1)}}, ""))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("regen code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
	}
	newCodes := popRecoveryCodes(t, s, admin, w.Header().Get("Location"))
	if len(newCodes) != 10 {
		t.Fatalf("新恢复码 %d 条, 期望 10 条", len(newCodes))
	}

	// 旧码拿去关 2FA 必须失败。
	w = httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
		url.Values{"recovery_code": {oldCodes[0]}}, "10.28.0.1"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("旧恢复码仍然可用(code=%d)", w.Code)
	}
	// 新码则应当可用。
	w = httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
		url.Values{"recovery_code": {newCodes[0]}}, ""))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("新恢复码不可用(code=%d)", w.Code)
	}
	assertAuditAction(t, s, "totp_regen_codes")
}

// TestMeTOTPRegen_RequiresEnabled:没开 2FA 时不能刷恢复码。
//
// 关键场景是「setup 了但还没 enable」:此时库里已经有 secret,能算出**有效**的 6 位码。
// 少了 TOTPEnabled 这道检查,这枚码就能刷出一批恢复码 —— 账号 2FA 明明是关的,却
// 挂着 10 条能过 step-up 的长期凭据,而用户在界面上根本看不到它们的存在。
func TestMeTOTPRegen_RequiresEnabled(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)

	// 完全没配过 2FA。
	w := httptest.NewRecorder()
	s.handleMeTOTPRegen(w, mePost(t, s, admin, "/me/totp/regen-codes",
		url.Values{"code": {"123456"}}, ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未配置时 code=%d, 期望 400", w.Code)
	}

	// setup 过但没 enable:有 secret、码有效,仍然必须拒绝。
	w = httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {pw}}, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("setup code=%d, 期望 200", w.Code)
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	w = httptest.NewRecorder()
	s.handleMeTOTPRegen(w, mePost(t, s, admin, "/me/totp/regen-codes",
		url.Values{"code": {totpCodeFor(t, cur.TOTPSecret)}}, ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("仅 setup 未 enable 时 code=%d, 期望 400", w.Code)
	}
	codes, err := s.store.ListUnusedRecoveryCodes(t.Context(), admin.ID)
	if err != nil {
		t.Fatalf("ListUnusedRecoveryCodes: %v", err)
	}
	if len(codes) != 0 {
		t.Fatalf("2FA 未启用却生成了 %d 条恢复码", len(codes))
	}
}

// TestMeTOTPRegen_WrongCodeKeepsOldCodes:码错时旧恢复码不能被作废。
//
// 作废了的话,一次误输入就把用户手上那批码全废了,而新码又没发出来 —— 账号
// 只剩 authenticator 一条路,设备一丢就彻底进不去。
func TestMeTOTPRegen_WrongCodeKeepsOldCodes(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	admin := createTestAdmin(t, s, "alice", pw)
	_, oldCodes := enrollTOTP(t, s, admin, pw)

	w := httptest.NewRecorder()
	s.handleMeTOTPRegen(w, mePost(t, s, admin, "/me/totp/regen-codes",
		url.Values{"code": {"000000"}}, "10.29.0.1"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("错码 code=%d, 期望 400", w.Code)
	}
	if n := s.stepUpFailures.Recent("10.29.0.1"); n != 1 {
		t.Errorf("失败计数 = %d, 期望 1", n)
	}
	// 旧码仍然可用。
	w = httptest.NewRecorder()
	s.handleMeTOTPDisable(w, mePost(t, s, admin, "/me/totp/disable",
		url.Values{"recovery_code": {oldCodes[0]}}, ""))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("regen 失败后旧恢复码也不能用了(code=%d)", w.Code)
	}
}

// =========================================================================
// 一次性恢复码页
// =========================================================================

// enableAndGetCodesLocation 走到 enable 的 303,返回那条一次性恢复码 URL(不消费)。
func enableAndGetCodesLocation(t *testing.T, s *Server, admin *store.WebAdmin, pw string) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleMeTOTPSetup(w, mePost(t, s, admin, "/me/totp/setup",
		url.Values{"password": {pw}}, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("setup code=%d, 期望 200", w.Code)
	}
	cur, _ := s.store.GetWebAdmin(t.Context(), admin.ID)
	w = httptest.NewRecorder()
	s.handleMeTOTPEnable(w, mePost(t, s, admin, "/me/totp/enable",
		url.Values{"code": {totpCodeFor(t, cur.TOTPSecret)}}, ""))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("enable code=%d, 期望 303", w.Code)
	}
	return w.Header().Get("Location")
}

// TestMeTOTPCodes_TokenIsOneShot:明文码只能被看一次。
//
// 走 PRG 的全部意义就在这:明文码不落 POST 历史、刷新不重发。token 若能重复消费,
// 等于把恢复码挂在一个可分享的 URL 上。
func TestMeTOTPCodes_TokenIsOneShot(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	alice := createTestAdmin(t, s, "alice", pw)
	loc := enableAndGetCodesLocation(t, s, alice, pw)

	w := httptest.NewRecorder()
	s.handleMeTOTPCodesFlash(w, withAdminCtx(httptest.NewRequest(http.MethodGet, loc, nil), alice))
	if w.Code != http.StatusOK {
		t.Fatalf("本人首次 code=%d, 期望 200", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleMeTOTPCodesFlash(w, withAdminCtx(httptest.NewRequest(http.MethodGet, loc, nil), alice))
	if w.Code != http.StatusGone {
		t.Fatalf("重复消费 code=%d, 期望 410", w.Code)
	}
}

// TestMeTOTPCodes_ForeignAdminBurnsToken:别的管理员拿到 token 不但读不到,还会当场把它烧掉。
//
// 烧掉是**有意为之**(防止拿着一个泄漏的 token 反复试 kind/身份做枚举),代价是
// 合法用户回头再点那条链接会看到「已过期」,只能去重刷一批恢复码。这个取舍写在
// credentials_flash.go 的注释里,这里钉住它 —— 免得日后有人觉得「误伤了合法用户」
// 顺手改成「不匹配就直接返回、保留 entry」,那样正好把枚举的门重新打开。
func TestMeTOTPCodes_ForeignAdminBurnsToken(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "AdminPass123!"
	alice := createTestAdmin(t, s, "alice", pw)
	bob := createTestAdmin(t, s, "bob", pw)
	loc := enableAndGetCodesLocation(t, s, alice, pw)

	w := httptest.NewRecorder()
	s.handleMeTOTPCodesFlash(w, withAdminCtx(httptest.NewRequest(http.MethodGet, loc, nil), bob))
	if w.Code != http.StatusGone {
		t.Fatalf("他人 token code=%d, 期望 410", w.Code)
	}
	// alice 随后也读不到了。
	w = httptest.NewRecorder()
	s.handleMeTOTPCodesFlash(w, withAdminCtx(httptest.NewRequest(http.MethodGet, loc, nil), alice))
	if w.Code != http.StatusGone {
		t.Fatalf("被他人试探过的 token 应当已作废, code=%d", w.Code)
	}
}

// TestMeTOTPCodes_BadTokenIsGone:空 / 乱编的 token 一律 410。
func TestMeTOTPCodes_BadTokenIsGone(t *testing.T) {
	s := newMeTestServer(t)
	alice := createTestAdmin(t, s, "alice", "AdminPass123!")

	for _, bad := range []string{"", "?token=", "?token=deadbeef", "?token=%20"} {
		w := httptest.NewRecorder()
		s.handleMeTOTPCodesFlash(w,
			withAdminCtx(httptest.NewRequest(http.MethodGet, "/me/totp/codes"+bad, nil), alice))
		if w.Code != http.StatusGone {
			t.Errorf("token=%q code=%d, 期望 410", bad, w.Code)
		}
	}
}

// =========================================================================
// 方法 / CSRF / 路由
// =========================================================================

// TestMeTOTP_AllWritesRequireCSRF:四个写动作都必须自己校验 CSRF。
//
// 这几个 handler 不完全依赖中间件(setup 之后还要渲染带表单的页面),各自都写了
// 一行 VerifyCSRFToken —— 四行里漏一行,那个动作就能被跨站发起。
func TestMeTOTP_AllWritesRequireCSRF(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")

	for _, c := range []struct {
		path string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"/me/totp/setup", s.handleMeTOTPSetup},
		{"/me/totp/enable", s.handleMeTOTPEnable},
		{"/me/totp/disable", s.handleMeTOTPDisable},
		{"/me/totp/regen-codes", s.handleMeTOTPRegen},
	} {
		// 不带 csrf cookie / token 的裸 POST。
		req := httptest.NewRequest(http.MethodPost, c.path,
			strings.NewReader("password=x&code=123456"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		c.fn(w, withAdminCtx(req, admin))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s 无 CSRF code=%d, 期望 403", c.path, w.Code)
		}
	}
}

// TestMeTOTP_AllWritesRejectGET:GET 不能触发任何 2FA 状态变更。
func TestMeTOTP_AllWritesRejectGET(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")

	for _, c := range []struct {
		path string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"/me/totp/setup", s.handleMeTOTPSetup},
		{"/me/totp/enable", s.handleMeTOTPEnable},
		{"/me/totp/disable", s.handleMeTOTPDisable},
		{"/me/totp/regen-codes", s.handleMeTOTPRegen},
	} {
		w := httptest.NewRecorder()
		c.fn(w, withAdminCtx(httptest.NewRequest(http.MethodGet, c.path, nil), admin))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s code=%d, 期望 405", c.path, w.Code)
		}
	}
	// 反过来:一次性恢复码页只认 GET。
	w := httptest.NewRecorder()
	s.handleMeTOTPCodesFlash(w,
		withAdminCtx(httptest.NewRequest(http.MethodPost, "/me/totp/codes", nil), admin))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /me/totp/codes code=%d, 期望 405", w.Code)
	}
}

// TestMeAction_UnknownVerb:未知动作词一律 404,不能落到某个默认分支上。
func TestMeAction_UnknownVerb(t *testing.T) {
	s := newMeTestServer(t)
	admin := createTestAdmin(t, s, "alice", "AdminPass123!")

	for _, path := range []string{"/me/totp/frobnicate", "/me/passkey/setup", "/me/totp"} {
		w := httptest.NewRecorder()
		s.handleMeAction(w, mePost(t, s, admin, path, nil, ""))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s code=%d, 期望 404", path, w.Code)
		}
	}
}
