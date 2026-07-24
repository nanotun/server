package main

import (
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/nanotun/server/store"
)

// 2026-05-23:每个 admin 自己的"个人账号"页面 + TOTP 自助管理。
//
//   GET  /me                     个人页:基本信息 + TOTP 启用状态 + 活跃会话列表
//   POST /me/totp/setup          启用 TOTP 第一步:生成 secret + 渲染 QR
//   POST /me/totp/enable         启用 TOTP 第二步:校验 6 位码 → enabled=1 + 发恢复码
//   POST /me/totp/disable        关闭 TOTP(必须输当前 6 位码或恢复码)
//   POST /me/totp/regen-codes    重新生成 10 个恢复码(必须输当前 6 位码)
//
// 所有路径都强 CSRF;关闭 / 重置之类的高风险操作要求当前 TOTP 码,避免密码泄露后
// 攻击者一键关 2FA。

// handleMe:GET /me
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	admin := adminFromCtx(r.Context())
	if admin == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// 让模板拿到最新的 totp 状态(adminFromCtx 是 middleware 在请求开始时填的快照,
	// 自助操作后立即 GET /me 时可能落后一拍 — 这里多查一次保正确)。
	cur, err := s.store.GetWebAdmin(r.Context(), admin.ID)
	if err == nil && cur != nil {
		admin = cur
	}

	sessions, _ := s.store.ListWebSessionsByAdmin(r.Context(), admin.ID)
	codesRemaining64, _ := s.store.CountUnusedRecoveryCodes(r.Context(), admin.ID)
	// 模板里跟字面量 4 比较时,html/template 严格要求同类型。统一用 int 进模板,
	// 避免 "incompatible types for comparison" 的运行时 panic。
	codesRemaining := int(codesRemaining64)

	s.renderPage(w, r, "me.html", PageData{
		Title: tr(r, "page.me.title"),
		Admin: admin,
		Flash: flashFromQuery(r), // 第七轮 P2:统一到 helper
		Data: map[string]any{
			"Sessions":            sessions,
			"RecoveryCodesRemain": codesRemaining,
		},
		Nav: NavContext{Active: "me"},
	})
}

// handleMeTOTPSetup:POST /me/totp/setup
//
// 生成新 secret 并写入 web_admins.totp_secret(enabled 暂为 0),渲染扫码 + 确认页。
//
// 关键:即便 admin 已经 enabled=1,重新点击 setup 也允许 —— 但要求先输入当前 6
// 位码确认身份(密码已经过 session 隔了一道,但 setup 会换 secret,等同于关 + 开,
// 必须二次确认)。
func (s *Server) handleMeTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.sess.VerifyCSRFToken(r); err != nil {
		http.Error(w, trErr(r, err), http.StatusForbidden)
		return
	}
	admin := adminFromCtx(r.Context())
	if admin == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// 第十一轮深扫 MED:首次启用 TOTP 也要求**密码 step-up** —— 与 disable/regen(TOTP 码)、
	// server-qr/self-reset(密码)同等级保护。绑定新 secret + 发恢复码是把「第二因子」焊到本账号的
	// 敏感写操作:此前只凭 session+CSRF,未开 2FA 的会话一旦被劫持 / 借用,攻击者即可绑定**自己的**
	// TOTP secret 并领走恢复码,把合法 admin 锁死(本系统无「admin 侧清他人 TOTP」的动作,只能删号重建)。
	// 此刻账号尚无 secret 可验,故 step-up 用**密码**;复用 step-up IP 冷却 + 按 adminID 串行化「读冷却+
	// verify+记账」临界区(与 disable/regen 同款,复用 totpVerifyLocks)。
	//
	// 第十二轮深扫 MED:锁**先于**下面的 GetWebAdmin —— cur 在锁内读到最新 hash/enabled/secret,验密码用它,
	// 抹掉「requireAuth 请求初快照 → step-up 执行」间紧急改密+吊销会话的 TOCTOU 窗口(与 /login/totp 同源)。
	unlock := s.lockTOTPVerify(admin.ID)
	defer unlock()

	// 如果已经 enabled,先要求输入当前 6 位码(走 disable+re-setup 才合理)。
	cur, err := s.store.GetWebAdmin(r.Context(), admin.ID)
	if err != nil || cur == nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryAccountFailed"))
		return
	}
	if !cur.Enabled {
		s.renderError(w, r, http.StatusForbidden, tr(r, "err.stepUpAccountDisabled"))
		return
	}
	if cur.TOTPEnabled {
		// 提示用户先 disable 再 setup,避免一键覆盖造成的安全隐患。
		s.renderError(w, r, http.StatusBadRequest,
			tr(r, "me.totpAlreadyEnabled"))
		return
	}
	ip := clientIP(r)
	if s.stepUpFailures.Recent(ip) >= stepUpMaxFailures {
		s.audit.WriteFromRequest(r, "totp_setup_locked",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", ip, "reason", "ip_cooldown"))
		s.renderError(w, r, http.StatusTooManyRequests, tr(r, "me.totpTooManyAttempts"))
		return
	}
	password := r.FormValue("password")
	if strings.TrimSpace(password) == "" {
		// 空密码不计失败配额(与其它 step-up 空输入一致),回渲提示补填。
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.enrollPasswordRequired"))
		return
	}
	ok, verr := VerifyWebPassword(r.Context(), password, cur.PasswordHash)
	if isVerifyUnavailable(verr) {
		// 第十四轮深扫 MED:容量/ctx 超时非密码错 —— 不计冷却,回 503(与登录对齐)。
		s.renderError(w, r, http.StatusServiceUnavailable, tr(r, "auth.tryAgainLater"))
		return
	}
	if verr != nil || !ok {
		newCount := s.stepUpFailures.Inc(ip)
		s.audit.WriteFromRequest(r, "totp_setup_password_fail",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", ip, "reason", "wrong_password", "fail_count", newCount))
		msg := tr(r, "adminPwd.currentWrong")
		status := http.StatusUnauthorized
		if newCount >= stepUpMaxFailures {
			msg = tr(r, "me.totpTooManyAttempts")
			status = http.StatusTooManyRequests
		}
		s.renderError(w, r, status, msg)
		return
	}
	s.stepUpFailures.Reset(ip)

	secret, err := GenerateTOTPSecret()
	if err != nil {
		// 第四轮深扫 MED(d_err_mask):内部错误详情只进服务端日志,页面回通用文案,不向(已登录但可能是
		// viewer 角色的)用户回显 err.Error()。下同。
		s.renderInternalError(w, r, "me:totp_gen_secret", err)
		return
	}
	if err := s.store.SetWebAdminTOTPSecret(r.Context(), admin.ID, secret); err != nil {
		s.renderInternalError(w, r, "me:totp_save_secret", err)
		return
	}
	host := r.Host
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	account := admin.Username + "@" + host
	uri := BuildOtpauthURI(secret, account)
	png, err := RenderTOTPQRCodePNG(uri)
	if err != nil {
		s.renderInternalError(w, r, "me:totp_render_qr", err)
		return
	}
	s.audit.WriteFromRequest(r, "totp_setup_start", FormatTarget("web_admin", admin.ID), "")

	// QRDataURL 必须用 template.URL 类型 — html/template 默认对 <img src=...>
	// 的 URL context 做 scheme 白名单(http/https/mailto/tel/ftp),"data:" 不在
	// 白名单 → 输出会被替换成 "#ZgotmplZ" 导致图片显示成 broken icon。
	// template.URL 是 "I trust this URL, don't sanitize" 的显式信号。
	// 内容由本进程刚生成的 base64 PNG 构成,无注入风险。
	qrDataURL := template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))

	// 关键:本 handler 是 POST(POST→渲染下一步页面),requireCSRFAndAuth
	// 中间件**只在 GET/HEAD 注入 csrf token 到 ctx**,POST 路径里 ctx 没有
	// token → renderPage 的 fallback csrfTokenFromCtx 返回 ""。结果模板里
	// {{.CSRFToken}} 是空字符串,渲染的第二步 form 的 hidden csrf_token 也是
	// 空,提交 /me/totp/enable 时被 VerifyCSRFToken 拒掉。
	//
	// 在这里显式 EnsureCSRFToken(复用现有 cookie 或新签),写到 PageData.CSRFToken
	// 让模板能拿到正确值。这个模式应当用于所有「POST 之后又渲染含 form 的页面」
	// 的 handler;enable / regen 恢复码页已改走 PRG(POST 只 303,GET /me/totp/codes 才渲染,
	// 见 d_recovery_prg),那条路径由 GET 中间件正常注入 csrf,不受本问题影响。
	tok, _ := s.sess.EnsureCSRFToken(r, w)

	s.renderPage(w, r, "me_totp_setup.html", PageData{
		Title:     tr(r, "page.meTotpSetup.title"),
		Admin:     admin,
		CSRFToken: tok,
		Data: map[string]any{
			"Secret":     secret,
			"OtpauthURI": uri,
			"QRDataURL":  qrDataURL,
			"Account":    account,
		},
		Nav: NavContext{Active: "me"},
	})
}

// handleMeTOTPEnable:POST /me/totp/enable
//
// 校验用户在 setup 页面输入的 6 位码 → 翻 enabled=1 + 生成 10 条恢复码 →
// 渲染一次性展示恢复码的页面(用户必须保存)。
func (s *Server) handleMeTOTPEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.sess.VerifyCSRFToken(r); err != nil {
		http.Error(w, trErr(r, err), http.StatusForbidden)
		return
	}
	admin := adminFromCtx(r.Context())
	if admin == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))

	// 第十二轮深扫 MED:enable 也要 per-IP 冷却 + 按 adminID 串行化(与 disable/regen/setup 同套 stepUpFailures +
	// totpVerifyLocks)。否则被劫持的会话可**无锁定**地暴破这枚 6 位确认码(HMAC 廉价、不过 argon2),成功即启用
	// TOTP 并领走一次性恢复码 → 拿到长期第二因子。锁也让下面 GetWebAdmin 在临界区内读到最新 secret/enabled。
	unlock := s.lockTOTPVerify(admin.ID)
	defer unlock()
	ip := clientIP(r)
	if s.stepUpFailures.Recent(ip) >= stepUpMaxFailures {
		s.audit.WriteFromRequest(r, "totp_enable_locked",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", ip, "reason", "ip_cooldown"))
		s.renderError(w, r, http.StatusTooManyRequests, tr(r, "me.totpTooManyAttempts"))
		return
	}

	cur, err := s.store.GetWebAdmin(r.Context(), admin.ID)
	if err != nil || cur == nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryAccountFailed"))
		return
	}
	if cur.TOTPSecret == "" {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.secretNotGenerated"))
		return
	}
	if cur.TOTPEnabled {
		flashRedirect(w, r, "/me", tr(r, "flash.totpEnabled"), "")
		return
	}
	if code == "" {
		// 空码不计失败配额(与 setup/server-qr 空输入一致,避免误提交自锁),回渲提示补填。
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.totpCodeRequired"))
		return
	}
	// 第七轮深扫 MED:enable 也消费该时间步(与登录共享计数),防止这枚确认码被重放到登录。
	// enable 前 SetWebAdminTOTPSecret 已把 last_used_step 归零,故此处消费不会与旧 secret 的登录抢占。
	if err := s.verifyAndConsumeStepUpTOTP(r.Context(), admin.ID, cur.TOTPSecret, code); err != nil {
		if errors.Is(err, ErrTOTPStepUnavailable) {
			// 第十五轮深扫 MED:消费时间步的 DB 瞬时错误非码错 —— 不计冷却,回 503(与登录对齐)。
			s.renderError(w, r, http.StatusServiceUnavailable, tr(r, "auth.tryAgainLater"))
			return
		}
		newCount := s.stepUpFailures.Inc(ip)
		s.audit.WriteFromRequest(r, "totp_enable_code_fail",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", ip, "reason", "wrong_code", "fail_count", newCount))
		// 不清 secret,让用户能重输一次(Authenticator 显示的码 30s 滚)。
		msg := tr(r, "me.totpCodeWrongCheckTime", trErr(r, err))
		status := http.StatusBadRequest
		if newCount >= stepUpMaxFailures {
			msg = tr(r, "me.totpTooManyAttempts")
			status = http.StatusTooManyRequests
		}
		s.renderError(w, r, status, msg)
		return
	}
	// step-up 全过 → 清 IP 冷却计数(与 disable/regen/server-qr 成功即 Reset 对齐)。
	s.stepUpFailures.Reset(ip)
	plain, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		s.renderInternalError(w, r, "me:totp_gen_recovery", err)
		return
	}
	// 第七轮深扫 MED:把「刚验过码的那个 secret」传给 store 做 CAS —— 若 setup 竞态把 secret
	// 换掉了,enable 命中 0 行返回 ErrNotFound,引导用户重开 setup,而非把错误的 secret 启用锁死账号。
	n, err := s.store.EnableWebAdminTOTP(r.Context(), admin.ID, cur.TOTPSecret, hashes, time.Now().Unix())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderError(w, r, http.StatusConflict, tr(r, "me.totpSetupChanged"))
			return
		}
		s.renderInternalError(w, r, "me:totp_enable", err)
		return
	}
	s.audit.WriteFromRequest(r, "totp_enable",
		FormatTarget("web_admin", admin.ID),
		FormatDetail("recovery_codes", n))

	// 第四轮深扫 MED(d_recovery_prg):不再在本 POST 响应里直接渲染明文码。stash 进一次性 flash(绑定当前
	// admin)后 303 到 GET /me/totp/codes?token=... —— 刷新 / 后退只 GET,不会重发 POST;明文码只在一次 GET
	// 里出现,不落浏览器 POST 历史。stash 失败(crypto/rand 故障,极罕见)时 TOTP 已启用,引导用户去 regen。
	s.redirectRecoveryCodesFlash(w, r, admin, plain, true, "totp_enable")
}

// redirectRecoveryCodesFlash 把明文恢复码 stash 进一次性 flash(绑定当前 admin)并 303 到 GET /me/totp/codes。
// firstTime 区分「启用首发」与「重刷」文案;auditAction 仅用于 stash 失败时的审计打点。
func (s *Server) redirectRecoveryCodesFlash(w http.ResponseWriter, r *http.Request, admin *store.WebAdmin, codes []string, firstTime bool, auditAction string) {
	token, err := s.credFlash.Stash(credentialsFlashPayload{
		Kind:          credentialsFlashKindRecoveryCodes,
		UserID:        admin.ID, // 复用字段承载 admin id,便于排错;真正的绑定由 Stash 的 adminID 参数完成
		Username:      admin.Username,
		RecoveryCodes: strings.Join(codes, "\n"),
		FirstTime:     firstTime,
	}, admin.ID)
	if err != nil {
		s.audit.WriteFromRequest(r, auditAction+"_stash_failed",
			FormatTarget("web_admin", admin.ID), FormatDetail("err", err.Error()))
		s.renderInternalError(w, r, "me:recovery_codes_stash", err)
		return
	}
	http.Redirect(w, r, "/me/totp/codes?token="+token, http.StatusSeeOther)
}

// handleMeTOTPCodesFlash:GET /me/totp/codes?token=... — 一次性消费 flash 里的恢复码明文并渲染。
// token 缺失 / 过期 / 已消费 / 非本人 → 410 Gone(与 credentials 一次性页同语义)。
func (s *Server) handleMeTOTPCodesFlash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	admin := adminFromCtx(r.Context())
	if admin == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	payload, err := s.credFlash.Pop(token, credentialsFlashKindRecoveryCodes, admin.ID)
	if err != nil {
		s.renderError(w, r, http.StatusGone, tr(r, "me.recoveryCodesExpired"))
		return
	}
	title := "page.meTotpCodesRegen.title"
	if payload.FirstTime {
		title = "page.meTotpCodesEnable.title"
	}
	s.renderPage(w, r, "me_totp_codes.html", PageData{
		Title: tr(r, title),
		Admin: admin,
		Data: map[string]any{
			"Codes":     strings.Split(payload.RecoveryCodes, "\n"),
			"FirstTime": payload.FirstTime,
		},
		Nav: NavContext{Active: "me"},
	})
}

// handleMeTOTPDisable:POST /me/totp/disable
//
// 关闭 TOTP 必须当场输入一个有效的 6 位码或恢复码,防止密码泄露 + cookie 劫持
// 一键关 2FA。关闭后清掉所有恢复码 + secret。
func (s *Server) handleMeTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.sess.VerifyCSRFToken(r); err != nil {
		http.Error(w, trErr(r, err), http.StatusForbidden)
		return
	}
	admin := adminFromCtx(r.Context())
	if admin == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// 第九轮深扫 MED:step-up 冷却是「先 Recent() 读计数、晚点才 Inc()」的 check-then-act,
	// 与已在第八轮修掉的 /login/totp 同类竞态 —— 并发请求都在任一 Inc 落地前读到低于阈值的
	// 计数,即可越过「5 次/5min」冷却,对 6 位码提速爆破(劫持会话即可关 2FA)。按 adminID
	// 串行化「读冷却 + verify + 记账」临界区(复用登录用的 totpVerifyLocks),使冷却与 verify
	// 在并发下也按账号顺序生效。
	//
	// 第十四轮深扫 HIGH:GetWebAdmin **移到锁内**,验 TOTP/恢复码用锁内重读的 cur —— 抹掉「锁外读 → verify」
	// 间受害者轮换 2FA(disable→setup→enable)的 TOCTOU:攻击者持旧 secret 的会话可在受害者换成新 secret 后仍
	// 用旧码关掉 2FA。与 setup/enable/server-qr/self-reset 同源(此前 disable/regen 漏改)。停用即拒。
	unlock := s.lockTOTPVerify(admin.ID)
	defer unlock()
	cur, err := s.store.GetWebAdmin(r.Context(), admin.ID)
	if err != nil || cur == nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryAccountFailed"))
		return
	}
	if !cur.Enabled {
		s.renderError(w, r, http.StatusForbidden, tr(r, "err.stepUpAccountDisabled"))
		return
	}
	if !cur.TOTPEnabled {
		flashRedirect(w, r, "/me", tr(r, "flash.totpNotEnabled"), "")
		return
	}
	// 深扫第八轮 MED:关 2FA 是「输一个 6 位码即生效」的敏感操作,此前无任何限流 ——
	// 密码泄露 + cookie 劫持后可对 6 位码无限爆破直到关掉 2FA。复用 step-up 的 IP 冷却
	// (滑窗 5min,5 次锁),与 /server-qr/reveal 同款,失败即计数、锁定即 429、成功清零。
	ip := clientIP(r)
	if s.stepUpFailures.Recent(ip) >= stepUpMaxFailures {
		s.audit.WriteFromRequest(r, "totp_disable_locked",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", ip, "reason", "ip_cooldown"))
		s.renderError(w, r, http.StatusTooManyRequests, tr(r, "me.totpTooManyAttempts"))
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	recovery := strings.TrimSpace(r.FormValue("recovery_code"))
	// 深扫第九轮 LOW:空输入(既没填 TOTP 码也没填恢复码)不计 step-up 失败配额 ——
	// 与 /server-qr 空密码一致(handler_server_qr.go),避免误提交把自己锁进冷却。
	if code == "" && recovery == "" {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.totpCodeRequired"))
		return
	}
	ok, usedRecovery, recoveryID, dreason := s.verifyTOTPOrRecovery(r.Context(), cur, code, recovery)
	if dreason == reasonVerifyUnavailable {
		// 第十四轮深扫 MED:恢复码 argon2 容量/ctx 超时非码错 —— 不计冷却,回 503(与登录对齐)。
		s.renderError(w, r, http.StatusServiceUnavailable, tr(r, "auth.tryAgainLater"))
		return
	}
	if !ok {
		s.stepUpFailures.Inc(ip)
		s.audit.WriteFromRequest(r, "totp_disable_fail",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", ip))
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.totpCodeWrongCloseFail"))
		return
	}
	s.stepUpFailures.Reset(ip)
	if usedRecovery && recoveryID > 0 {
		// disable 路径用了恢复码,标记 used 主要是审计完整,实际马上要全删了。
		_ = s.store.MarkRecoveryCodeUsed(r.Context(), recoveryID, clientIP(r), time.Now().Unix())
	}
	if err := s.store.DisableWebAdminTOTP(r.Context(), admin.ID); err != nil {
		s.renderInternalError(w, r, "me:totp_disable", err)
		return
	}
	s.audit.WriteFromRequest(r, "totp_disable",
		FormatTarget("web_admin", admin.ID),
		FormatDetail("via", choose(usedRecovery, "recovery", "totp")))
	flashRedirect(w, r, "/me", tr(r, "flash.totpDisabled"), "")
}

// handleMeTOTPRegen:POST /me/totp/regen-codes
//
// 重新生成 10 条恢复码(老的全部作废)。要求当前 TOTP 码 — 与 disable 同等级保护,
// 避免他人借机刷出"我已经看见过"的码。
func (s *Server) handleMeTOTPRegen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.sess.VerifyCSRFToken(r); err != nil {
		http.Error(w, trErr(r, err), http.StatusForbidden)
		return
	}
	admin := adminFromCtx(r.Context())
	if admin == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// 第九轮深扫 MED:同 disable —— 按 adminID 串行化「读冷却 + verify + 记账」临界区,
	// 关闭 step-up 冷却的 check-then-act 竞态(见 handleMeTOTPDisable 注释)。
	// 第十四轮深扫 HIGH:GetWebAdmin **移到锁内**,验 TOTP 用锁内重读的 cur —— 抹掉受害者轮换 2FA 时攻击者用
	// 旧 secret 刷新恢复码的 TOCTOU(与 disable 同源;此前漏改)。停用即拒。
	unlock := s.lockTOTPVerify(admin.ID)
	defer unlock()
	cur, err := s.store.GetWebAdmin(r.Context(), admin.ID)
	if err != nil || cur == nil || !cur.TOTPEnabled {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.totpNotEnabledRegen"))
		return
	}
	if !cur.Enabled {
		s.renderError(w, r, http.StatusForbidden, tr(r, "err.stepUpAccountDisabled"))
		return
	}
	// 深扫第八轮 MED:重刷恢复码同样是「输一个 6 位码即作废旧码、刷出新码」的敏感操作,
	// 与 disable 同等防护 —— 复用 step-up IP 冷却,防止劫持会话后爆破 6 位码刷恢复码。
	ip := clientIP(r)
	if s.stepUpFailures.Recent(ip) >= stepUpMaxFailures {
		s.audit.WriteFromRequest(r, "totp_regen_locked",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", ip, "reason", "ip_cooldown"))
		s.renderError(w, r, http.StatusTooManyRequests, tr(r, "me.totpTooManyAttempts"))
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	// 深扫第九轮 LOW:空验证码不计 step-up 失败配额(与 disable / server-qr 一致)。
	if code == "" {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.totpCodeRequired"))
		return
	}
	// 第七轮深扫 MED:regen 消费该时间步(与登录共享计数),防止该码被重放到登录 / 其它 step-up。
	if err := s.verifyAndConsumeStepUpTOTP(r.Context(), admin.ID, cur.TOTPSecret, code); err != nil {
		if errors.Is(err, ErrTOTPStepUnavailable) {
			// 第十五轮深扫 MED:消费时间步的 DB 瞬时错误非码错 —— 不计冷却,回 503(与登录对齐)。
			s.renderError(w, r, http.StatusServiceUnavailable, tr(r, "auth.tryAgainLater"))
			return
		}
		s.stepUpFailures.Inc(ip)
		s.audit.WriteFromRequest(r, "totp_regen_fail",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", ip))
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.totpCodeWrong", trErr(r, err)))
		return
	}
	s.stepUpFailures.Reset(ip)
	plain, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		s.renderInternalError(w, r, "me:totp_regen_gen", err)
		return
	}
	if err := s.store.RegenerateRecoveryCodes(r.Context(), admin.ID, hashes, time.Now().Unix()); err != nil {
		s.renderInternalError(w, r, "me:totp_regen_save", err)
		return
	}
	s.audit.WriteFromRequest(r, "totp_regen_codes",
		FormatTarget("web_admin", admin.ID),
		FormatDetail("count", len(plain)))
	// d_recovery_prg:与 enable 路径一致走 PRG,不在 POST 响应里渲染明文码(重刷路径尤其重要——
	// 刷新重发 POST 会再作废旧码刷新码)。
	s.redirectRecoveryCodesFlash(w, r, admin, plain, false, "totp_regen_codes")
}

// handleMeAction:/me/totp/* dispatcher;只接收 POST。
func (s *Server) handleMeAction(w http.ResponseWriter, r *http.Request) {
	segs := pathSegments(r.URL.Path)
	// segs 形如 ["me", "totp", "setup"]
	if len(segs) < 3 || segs[1] != "totp" {
		s.renderError(w, r, http.StatusNotFound, tr(r, "err.unknownActionVerb", r.URL.Path))
		return
	}
	switch segs[2] {
	case "setup":
		s.handleMeTOTPSetup(w, r)
	case "enable":
		s.handleMeTOTPEnable(w, r)
	case "disable":
		s.handleMeTOTPDisable(w, r)
	case "regen-codes":
		s.handleMeTOTPRegen(w, r)
	case "codes":
		// d_recovery_prg:一次性恢复码展示页(GET,PRG 的 G)。
		s.handleMeTOTPCodesFlash(w, r)
	default:
		s.renderError(w, r, http.StatusNotFound, tr(r, "err.unknownTotpAction", segs[2]))
	}
}

func choose(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// 强制让 store 包可见(避免某些重构后引用消失编译错)。
var _ = store.WebAdmin{}
