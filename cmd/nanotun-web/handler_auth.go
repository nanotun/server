package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nanotun/server/store"
)

// handleSetup:Web 后台首次初始化向导。
// 当 web_admins 表为空时,任何访问都可以进入这条路径创建首位管理员。
// 一旦表非空,这个 handler 直接 302 /login 并不允许再走 setup,防止 attacker
// 在已运行系统上通过它劫持 admin。
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	n, err := s.store.CountWebAdmins(ctx)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.countAccountsFailed")+err.Error())
		return
	}
	if n > 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// setup 页面也需要 CSRF cookie,但因为还没进 requireCSRFAndAuth 中间件,
		// 这里手动签发/复用一个 token 嵌入页面(K4 同 handleLogin)。
		tok, err := s.sess.EnsureCSRFToken(r, w)
		if err != nil {
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.csrfIssueFailed")+err.Error())
			return
		}
		cap, err := s.sess.IssueCaptcha(w)
		if err != nil {
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.captchaGenFailed")+err.Error())
			return
		}
		s.renderPage(w, r, "setup.html", PageData{
			Title:     tr(r, "page.setup.title"),
			CSRFToken: tok,
			Data:      map[string]any{"Captcha": cap},
			Nav:       NavContext{Active: "setup"},
		})
	case http.MethodPost:
		if err := s.sess.VerifyCSRFToken(r); err != nil {
			http.Error(w, trErr(r, err), http.StatusForbidden)
			return
		}
		// 先验 captcha,过了再消耗 password verify;无论 captcha 成功失败都立刻
		// Clear,防止 attacker 拿一对 (cookie, answer) 反复重放。setupRetry 会
		// 自己再签一张新的图。
		if err := s.sess.VerifyCaptcha(r, r.FormValue("captcha")); err != nil {
			s.sess.ClearCaptcha(w)
			s.audit.Write(ctx, nil, "web.setup.captcha_fail",
				FormatTarget("username", strings.TrimSpace(r.FormValue("username"))),
				FormatDetail("ip", clientIP(r), "reason", err.Error()))
			s.setupRetry(w, r, tr(r, "auth.captchaInvalidRefresh"))
			return
		}
		s.sess.ClearCaptcha(w)
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		confirm := r.FormValue("password_confirm")
		if username == "" || len(username) < 3 {
			s.setupRetry(w, r, tr(r, "auth.usernameMin3"))
			return
		}
		if password != confirm {
			s.setupRetry(w, r, tr(r, "auth.passwordMismatch"))
			return
		}
		if err := ValidatePasswordStrength(password); err != nil {
			s.setupRetry(w, r, trErr(r, err))
			return
		}
		hash, err := HashWebPassword(password)
		if err != nil {
			s.setupRetry(w, r, tr(r, "err.hashFailed")+err.Error())
			return
		}
		admin, err := s.store.CreateWebAdmin(ctx, store.NewWebAdmin{
			Username:     username,
			PasswordHash: hash,
			Role:         "admin",
		})
		if err != nil {
			s.setupRetry(w, r, tr(r, "err.createAccountFailed")+err.Error())
			return
		}
		// 直接颁发 session,登入。
		ip := clientIP(r)
		if err := s.sess.IssueSession(ctx, w, admin.ID, ip, r.UserAgent()); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.issueSessionFailed")+err.Error())
			return
		}
		_ = s.store.RecordWebAdminLoginSuccess(ctx, admin.ID, ip)
		s.audit.Write(ctx, admin, "web.setup", FormatTarget("web_admin", admin.ID),
			FormatDetail("username", admin.Username))
		http.Redirect(w, r, "/", http.StatusFound)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) setupRetry(w http.ResponseWriter, r *http.Request, msg string) {
	tok, _ := s.sess.EnsureCSRFToken(r, w)
	// 一定要再签一张新 captcha — POST 路径里旧的已经 Clear 或不可重用,
	// 不重签的话用户在 retry 页看到一张破图 + 提交都 captcha 失败,死循环。
	cap, capErr := s.sess.IssueCaptcha(w)
	data := map[string]any{}
	if capErr == nil {
		data["Captcha"] = cap
	}
	s.renderPage(w, r, "setup.html", PageData{
		Title:     tr(r, "page.setup.title"),
		CSRFToken: tok,
		Flash:     &Flash{Kind: "err", Text: msg},
		Data:      data,
		Nav:       NavContext{Active: "setup"},
	})
}

// handleLogin:
//
//	GET  → 渲染登录页 + 签发 CSRF token;
//	POST → AttemptLogin → 成功颁 session 跳 /,失败重渲染 + 错误提示。
//
// 如果系统未初始化(web_admins 为空),先 302 /setup。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if n, _ := s.store.CountWebAdmins(ctx); n == 0 && s.cfg.AllowSetup {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		tok, err := s.sess.EnsureCSRFToken(r, w)
		if err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "csrf: "+err.Error())
			return
		}
		cap, err := s.sess.IssueCaptcha(w)
		if err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "captcha: "+err.Error())
			return
		}
		// 自适应 PoW:平时(失败 <3 次)difficulty=0 不下发题目,
		// 模板里 hidden field 都留空,JS solver 也跳过。
		// 失败次数变多 → IssueChallenge 给出 14~22-bit 的题。
		ip := clientIP(r)
		powDiff := ComputeDifficulty(s.sess.ipFailures.Recent(ip))
		powCh, err := s.sess.IssueChallenge(powDiff)
		if err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "pow: "+err.Error())
			return
		}
		next := r.URL.Query().Get("next")
		s.renderPage(w, r, "login.html", PageData{
			Title:     tr(r, "page.login.title"),
			CSRFToken: tok,
			Data: map[string]any{
				"Next":    next,
				"Captcha": cap,
				"PoW":     FormatPoWForTemplate(powCh),
			},
			Nav: NavContext{Active: "login"},
		})
	case http.MethodPost:
		if err := s.sess.VerifyCSRFToken(r); err != nil {
			http.Error(w, trErr(r, err), http.StatusForbidden)
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		next := r.FormValue("next")
		ip := clientIP(r)

		// 验证码先于密码 — 让自动化撞库脚本根本走不到 store.GetWebAdmin。
		// 失败一律消耗本张图,retry 时签新的。这里**故意不**把 captcha 错误
		// 和密码错误对外区分,提示统一改成"账号或密码或验证码错误"。
		// 实际 audit 里写清楚 reason=captcha_xxx 便于运维查脚本流量。
		if err := s.sess.VerifyCaptcha(r, r.FormValue("captcha")); err != nil {
			s.sess.ClearCaptcha(w)
			s.sess.ipFailures.Inc(ip)
			s.audit.Write(ctx, nil, "web.login.captcha_fail",
				FormatTarget("username", username),
				FormatDetail("ip", ip, "reason", err.Error()))
			s.loginRetry(w, r, AuthResult{Err: errors.New(tr(r, "auth.captchaInvalidReenter"))},
				username, next)
			return
		}
		// captcha 通过 — 不论后面密码成功/失败都先 Clear,避免一次 captcha
		// 被反复重放试不同密码(那样会让 captcha 退化成只挡第一次)。
		s.sess.ClearCaptcha(w)

		// PoW 校验:只在「此次登录服务端期望要 PoW」时才校验。
		// expectedDiff = ComputeDifficulty(当前 IP 失败数);=0 跳过整段。
		// 注意:VerifyPoWProof 内部还会用 expectedDiff 防御「拿低难度旧签名重放」。
		expectedDiff := ComputeDifficulty(s.sess.ipFailures.Recent(ip))
		if expectedDiff > 0 {
			proof, perr := parsePoWFormFields(r)
			if perr != nil {
				s.sess.ipFailures.Inc(ip)
				s.audit.Write(ctx, nil, "web.login.pow_fail",
					FormatTarget("username", username),
					FormatDetail("ip", ip, "reason", "missing:"+perr.Error()))
				s.loginRetry(w, r, AuthResult{Err: errors.New(tr(r, "auth.securityCheckFailed"))},
					username, next)
				return
			}
			if verr := s.sess.VerifyPoWProof(proof, expectedDiff); verr != nil {
				s.sess.ipFailures.Inc(ip)
				s.audit.Write(ctx, nil, "web.login.pow_fail",
					FormatTarget("username", username),
					FormatDetail("ip", ip, "reason", verr.Error(),
						"expected_difficulty", expectedDiff))
				s.loginRetry(w, r, AuthResult{Err: errors.New(tr(r, "auth.securityCheckFailed"))},
					username, next)
				return
			}
		}

		res := AttemptLogin(ctx, s.store, s.cfg, username, password, ip)
		if res.Err != nil {
			s.sess.ipFailures.Inc(ip)
			s.audit.Write(ctx, nil, "web.login.fail",
				FormatTarget("username", username),
				FormatDetail("ip", ip, "reason", res.Err.Error()))
			s.loginRetry(w, r, res, username, next)
			return
		}
		// TOTP 路径:密码已验证,但 admin 启了 TOTP → 不直接发 session,
		// 用 pending cookie 转场到 /login/totp。这样:
		//   * 密码泄露但没拿到 TOTP 的 attacker 进不了主界面;
		//   * 用户体验上类似一个二次输入页面,正常 60 秒内完成。
		if res.Admin.TOTPEnabled {
			if err := s.sess.IssueTOTPPending(w, res.Admin.ID); err != nil {
				s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.issue2faFailed")+err.Error())
				return
			}
			s.audit.Write(ctx, res.Admin, "web.login.password_ok_await_totp",
				FormatTarget("web_admin", res.Admin.ID),
				FormatDetail("ip", ip))
			// 第十轮深扫 P2:next 走 sanitizeReturnTo 统一(与 mesh toggle 同口),
			// 防 `%5C` / scheme / host 等开放重定向变种。透传到 /login/totp GET
			// 之前先 sanitize 一道,虽然下游 handleLoginTOTP 还会再 sanitize,但
			// 在第一时间剥掉攻击载荷可以避免 hidden field / 中间页 referer 泄露。
			redirectTo := "/login/totp"
			if dest := sanitizeReturnTo(next, ""); dest != "/" {
				redirectTo = "/login/totp?next=" + url.QueryEscape(dest)
			}
			http.Redirect(w, r, redirectTo, http.StatusFound)
			return
		}
		if err := s.sess.IssueSession(ctx, w, res.Admin.ID, ip, r.UserAgent()); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.issueSessionFailed")+err.Error())
			return
		}
		// 成功登录 → 清零 IP 失败计数,下次同 IP 来登录直接无 PoW 体验。
		// TOTP 分支下不在这里清,放到 handleLoginTOTP 成功才算"真登录"。
		s.sess.ipFailures.Reset(ip)
		s.audit.Write(ctx, res.Admin, "web.login.ok",
			FormatTarget("web_admin", res.Admin.ID),
			FormatDetail("ip", ip))
		// 第十轮深扫 P2:登录成功 redirect 用 sanitizeReturnTo,与 mesh toggle / devices
		// set-fixed-vip 同款防御(`%5C` / scheme / host 全拦)。攻击模型:钓鱼站让
		// 受害者带着 next=https://evil/x 完成登录后跳回 evil — 攻击面比 mesh toggle
		// 窄(需有效凭证),但同类逻辑漏洞应该一致清扫。
		dest := sanitizeReturnTo(next, "")
		http.Redirect(w, r, dest, http.StatusFound)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) loginRetry(w http.ResponseWriter, r *http.Request,
	res AuthResult, username, next string) {

	// 登录错误对外文案(多语言):哨兵错误按当前请求语言翻译;非哨兵(captcha/pow
	// 等在创建时已翻好、或后端错误)由 trErr 兜底(携带 LocaleKey 则译,否则原文)。
	msg := trErr(r, res.Err)
	switch {
	case errors.Is(res.Err, ErrAuthLocked):
		if res.LockedUntil > 0 {
			msg = tr(r, "auth.accountLocked", fmtTime(res.LockedUntil))
		} else {
			msg = tr(r, "auth.accountLockedGeneric")
		}
	// **第三轮深扫 P1-A**:`ErrAuthDisabled` 对外文案不能区别于 `ErrAuthBadCredentials`,
	// 否则 attacker 用账号枚举工具能直接定位「用户存在但已禁用」名单 — 部分破坏了
	// `AttemptLogin` 顶部承诺的「不暴露用户存在性」。修法:对外统一 BadCredentials 同
	// 文案,**audit 仍写真实 reason**("账号已被禁用",由 handleLogin 的 `res.Err.Error()`
	// 落 detail.reason),运维内部可见、attacker 不可见,与 captcha_fail 同款设计。
	case errors.Is(res.Err, ErrAuthBadCredentials), errors.Is(res.Err, ErrAuthDisabled):
		msg = tr(r, "auth.badCredentials")
	}
	tok, _ := s.sess.EnsureCSRFToken(r, w)
	// 同 setupRetry 的理由:每次 retry 一定要换 captcha,否则旧 cookie
	// 已被 Clear,新页里 captcha 必然校验不过。
	cap, capErr := s.sess.IssueCaptcha(w)
	// PoW 题目也要按"现在"的失败次数重新出 —— retry 之前那一步通常已经
	// ipFailures.Inc 过了,这里查到的难度会比刚才 GET /login 时高一档。
	// 如果浏览器 JS 这次失败后没有重新算高难度,只会下次 POST 时报 pow_fail,
	// 但页面会以新难度再出一次,用户体验是"按钮按下后等了几秒再次告诉你
	// 错了",可以接受。
	ip := clientIP(r)
	powDiff := ComputeDifficulty(s.sess.ipFailures.Recent(ip))
	powCh, powErr := s.sess.IssueChallenge(powDiff)
	data := map[string]any{"Next": next, "Username": username}
	if capErr == nil {
		data["Captcha"] = cap
	}
	if powErr == nil {
		data["PoW"] = FormatPoWForTemplate(powCh)
	}
	w.WriteHeader(http.StatusUnauthorized)
	s.renderPage(w, r, "login.html", PageData{
		Title:     tr(r, "page.login.title"),
		CSRFToken: tok,
		Flash:     &Flash{Kind: "err", Text: msg},
		Data:      data,
		Nav:       NavContext{Active: "login"},
	})
}

// handleLoginTOTP:密码已验证、TOTP 待输入的第二步页面。
//
//	GET  /login/totp?next=...        渲染输入 6 位码 / 恢复码的表单
//	POST /login/totp                 校验 → IssueSession → 302 next
//
// 不携带 pending cookie / cookie 过期 → 302 /login(让用户重新输密码)。
// pending cookie 只是 short-lived 转场态,登录的"真凭证"仍是密码 + TOTP。
func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	adminID, err := s.sess.LookupTOTPPending(r)
	if err != nil {
		// 没 pending(或已过期 / 篡改)→ 回登录页;不暴露 admin 是否存在等细节。
		// 第十轮 P2:next 走 sanitizeReturnTo 统一防御。
		next := r.URL.Query().Get("next")
		dest := "/login"
		if sane := sanitizeReturnTo(next, ""); sane != "/" {
			dest = "/login?next=" + url.QueryEscape(sane)
		}
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}
	admin, err := s.store.GetWebAdmin(ctx, adminID)
	if err != nil || admin == nil || !admin.Enabled || !admin.TOTPEnabled {
		// pending 签的是合法 adminID,但 admin 被禁 / 被删 / 关了 TOTP → 也回登录。
		s.sess.ClearTOTPPending(w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// 账号锁定同时覆盖密码步与 TOTP 步:TOTP 失败也会累加 failed_logins 并可能
	// 触发锁定(见下面 POST 分支),锁定后即便持有有效 pending cookie 也不放行,
	// 否则拿到密码的 attacker 可在 pending cookie TTL 内无限枚举 6 位 TOTP 码。
	if admin.LockedUntil > 0 && admin.LockedUntil > nowUnix() {
		s.sess.ClearTOTPPending(w)
		s.audit.Write(ctx, admin, "web.totp.locked",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", clientIP(r), "locked_until", admin.LockedUntil))
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		tok, err := s.sess.EnsureCSRFToken(r, w)
		if err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "csrf: "+err.Error())
			return
		}
		s.renderPage(w, r, "login_totp.html", PageData{
			Title:     tr(r, "page.loginTotp.title"),
			CSRFToken: tok,
			Data: map[string]any{
				"Username": admin.Username,
				"Next":     r.URL.Query().Get("next"),
			},
			Nav: NavContext{Active: "login"},
		})
	case http.MethodPost:
		if err := s.sess.VerifyCSRFToken(r); err != nil {
			http.Error(w, trErr(r, err), http.StatusForbidden)
			return
		}
		code := strings.TrimSpace(r.FormValue("code"))
		recoveryCode := strings.TrimSpace(r.FormValue("recovery_code"))
		next := r.FormValue("next")
		ip := clientIP(r)

		// 优先按 6 位 TOTP 码校验;失败再尝试当作恢复码。两种都不行返回 401。
		ok, usedRecovery, recoveryID, verr := s.verifyTOTPOrRecovery(ctx, admin, code, recoveryCode)
		if !ok {
			s.sess.ipFailures.Inc(ip)
			// TOTP/恢复码失败与密码失败共用账号锁定计数器(原子事务),
			// 满 MaxLoginFailures 次即锁定 LockoutSeconds,杜绝 6 位码暴力枚举。
			_, lockedUntil, _ := s.store.RecordWebAdminLoginFailure(ctx, admin.ID,
				s.cfg.MaxLoginFailures, s.cfg.LockoutSeconds)
			s.audit.Write(ctx, admin, "web.totp.fail",
				FormatTarget("web_admin", admin.ID),
				FormatDetail("ip", ip, "reason", verr, "locked_until", lockedUntil))
			if lockedUntil > 0 && lockedUntil > nowUnix() {
				// 已被本次失败锁定:作废 pending,提示回登录页重来。
				s.sess.ClearTOTPPending(w)
				s.loginTOTPRetry(w, r, tr(r, "auth.accountLocked", fmtTime(lockedUntil)), admin.Username, next)
				return
			}
			s.loginTOTPRetry(w, r, tr(r, "auth.totpCodeInvalid"), admin.Username, next)
			return
		}
		// 通过 → 把恢复码标记 used(如有);颁正式 session;清 pending。
		if usedRecovery && recoveryID > 0 {
			if err := s.store.MarkRecoveryCodeUsed(ctx, recoveryID, ip, time.Now().Unix()); err != nil {
				// 这条恢复码可能并发被用了 / DB 抖动 — 拒绝本次登录,让用户重试。
				// 不应该让一个恢复码"看起来用过其实没用过"或者反过来。
				s.loginTOTPRetry(w, r, tr(r, "auth.recoveryCodeError"), admin.Username, next)
				return
			}
			s.audit.Write(ctx, admin, "web.totp.recovery_used",
				FormatTarget("web_admin", admin.ID),
				FormatDetail("ip", ip, "recovery_id", recoveryID))
		}
		if err := s.sess.IssueSession(ctx, w, admin.ID, ip, r.UserAgent()); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.issueSessionFailed")+err.Error())
			return
		}
		s.sess.ClearTOTPPending(w)
		s.sess.ipFailures.Reset(ip)
		_ = s.store.RecordWebAdminLoginSuccess(ctx, admin.ID, ip)
		s.audit.Write(ctx, admin, "web.login.ok",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", ip, "totp", true, "recovery", usedRecovery))
		// 第十轮 P2:TOTP 验证成功 redirect 同款 sanitizeReturnTo。
		dest := sanitizeReturnTo(next, "")
		http.Redirect(w, r, dest, http.StatusFound)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// verifyTOTPOrRecovery 二选一校验,简化 handler 逻辑。
// 返回 (ok, usedRecovery, recoveryID, errReason)。
// errReason 仅用于 audit 写 reason 字段,不展示给用户(避免提示"是 TOTP 错还是
// recovery 错"被用来侧信道枚举)。
func (s *Server) verifyTOTPOrRecovery(ctx context.Context, admin *store.WebAdmin,
	totpCode, recoveryCode string) (ok bool, usedRecovery bool, recoveryID int64, errReason string) {

	if totpCode != "" {
		if err := VerifyTOTP(admin.TOTPSecret, totpCode); err == nil {
			return true, false, 0, ""
		} else {
			errReason = "totp:" + err.Error()
		}
	}
	if recoveryCode != "" {
		norm, err := NormalizeRecoveryCode(recoveryCode)
		if err != nil {
			return false, false, 0, "recovery_format:" + err.Error()
		}
		codes, err := s.store.ListUnusedRecoveryCodes(ctx, admin.ID)
		if err != nil {
			return false, false, 0, "recovery_list:" + err.Error()
		}
		for _, c := range codes {
			match, _ := VerifyWebPassword(norm, c.CodeHash)
			if match {
				return true, true, c.ID, ""
			}
		}
		errReason = "recovery_no_match"
	}
	if errReason == "" {
		errReason = "empty_code"
	}
	return false, false, 0, errReason
}

func (s *Server) loginTOTPRetry(w http.ResponseWriter, r *http.Request,
	msg, username, next string) {
	tok, _ := s.sess.EnsureCSRFToken(r, w)
	w.WriteHeader(http.StatusUnauthorized)
	s.renderPage(w, r, "login_totp.html", PageData{
		Title:     tr(r, "page.loginTotp.title"),
		CSRFToken: tok,
		Flash:     &Flash{Kind: "err", Text: msg},
		Data: map[string]any{
			"Username": username,
			"Next":     next,
		},
		Nav: NavContext{Active: "login"},
	})
}

// handleLogout:仅 POST + CSRF 校验通过时销毁 session 并跳登录页。
//
// 不再容忍 GET:GET 注销意味着任意第三方页面用 <img src="https://console/logout">
// 就能跨站把管理员踢下线(CSRF logout,可反复骚扰 + 打断操作);header 侧边栏的
// 退出按钮本就是带 csrf_token 的 POST 表单(partials/header.html),无需 GET 兜底。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.sess.VerifyCSRFToken(r); err != nil {
		http.Error(w, trErr(r, err), http.StatusForbidden)
		return
	}
	ctx := r.Context()
	// 取一次 admin 信息用于 audit(没登录就跳过)。
	if admin, _, err := s.sess.LookupSession(ctx, r); err == nil && admin != nil {
		s.audit.Write(ctx, admin, "web.logout", FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", clientIP(r)))
	}
	s.sess.DestroySession(ctx, w, r)
	http.Redirect(w, r, "/login", http.StatusFound)
}
