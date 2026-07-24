package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// handleSetup:Web 后台首次初始化向导。
// 当 web_admins 表为空时,任何访问都可以进入这条路径创建首位管理员。
// 一旦表非空,这个 handler 直接 302 /login 并不允许再走 setup,防止 attacker
// 在已运行系统上通过它劫持 admin。
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// M4:setup 向导须显式启用。此前 handleSetup 只看「web_admins 是否为空」，从不查 AllowSetup，
	// 于是即便运维想关闭 setup 也关不掉——全新安装到管理员建成前的 TOFU 窗口里，任何过了验证码的
	// 网络访客都能 POST /setup 抢占管理员。现在 AllowSetup=false 直接 302 /login，setup 彻底关闭
	// （此时首个管理员改由 CLI `nanotun-admin` provisioned）。与 handleLogin 对 AllowSetup 的判定一致。
	if !s.cfg.AllowSetup {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	n, err := s.store.CountWebAdmins(ctx)
	if err != nil {
		s.renderInternalError(w, r, "setup:count_admins", err)
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
			s.renderInternalError(w, r, "setup:csrf_issue", err)
			return
		}
		cap, err := s.sess.IssueCaptcha(w)
		if err != nil {
			s.renderInternalError(w, r, "setup:captcha_gen", err)
			return
		}
		// 第四轮深扫 MED(d_setup_pow):/setup 是 web_admins 为空时的**公开**端点(TOFU 窗口),此前只有
		// captcha 一道闸。补上与 /login 同款的自适应 PoW —— 同 IP 失败累积后下发题目,给自动化抢占首个
		// 管理员的脚本加成本。平时(失败少)difficulty=0 不下发,honest 运维无感。
		ip := clientIP(r)
		powCh, err := s.sess.IssueChallenge(ComputeDifficulty(s.sess.ipFailures.Recent(ip)))
		if err != nil {
			s.renderInternalError(w, r, "setup:pow_issue", err)
			return
		}
		s.renderPage(w, r, "setup.html", PageData{
			Title:     tr(r, "page.setup.title"),
			CSRFToken: tok,
			Data:      map[string]any{"Captcha": cap, "PoW": FormatPoWForTemplate(powCh)},
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
		setupIP := clientIP(r)
		if err := s.sess.VerifyCaptcha(r, r.FormValue("captcha")); err != nil {
			s.sess.ClearCaptcha(w)
			s.sess.ipFailures.Inc(setupIP) // d_setup_pow:公开端点失败计数,驱动自适应 PoW
			s.audit.Write(ctx, nil, "web.setup.captcha_fail",
				FormatTarget("username", strings.TrimSpace(r.FormValue("username"))),
				FormatDetail("ip", setupIP, "reason", err.Error()))
			s.setupRetry(w, r, tr(r, "auth.captchaInvalidRefresh"))
			return
		}
		s.sess.ClearCaptcha(w)
		// d_setup_pow:captcha 过后校验 PoW(仅当当前 IP 失败数已把期望难度顶到 >0 时)。与 /login 同口径:
		// VerifyPoWProof 内部用 expectedDiff 防「低难度旧签名重放」。缺字段 / 校验失败均计一次失败并 retry。
		if expectedDiff := ComputeDifficulty(s.sess.ipFailures.Recent(setupIP)); expectedDiff > 0 {
			proof, perr := parsePoWFormFields(r)
			if perr != nil {
				s.sess.ipFailures.Inc(setupIP)
				s.audit.Write(ctx, nil, "web.setup.pow_fail",
					FormatTarget("username", strings.TrimSpace(r.FormValue("username"))),
					FormatDetail("ip", setupIP, "reason", "missing:"+perr.Error()))
				s.setupRetry(w, r, tr(r, "auth.securityCheckFailed"))
				return
			}
			if verr := s.sess.VerifyPoWProof(proof, expectedDiff); verr != nil {
				s.sess.ipFailures.Inc(setupIP)
				s.audit.Write(ctx, nil, "web.setup.pow_fail",
					FormatTarget("username", strings.TrimSpace(r.FormValue("username"))),
					FormatDetail("ip", setupIP, "reason", verr.Error(), "expected_difficulty", expectedDiff))
				s.setupRetry(w, r, tr(r, "auth.securityCheckFailed"))
				return
			}
		}
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
			logrus.WithError(err).WithField("ctx", "setup:hash_password").Error("[web] internal error")
			s.setupRetry(w, r, tr(r, "err.internalGeneric"))
			return
		}
		// 原子首建:仅当 web_admins 仍为空时插入。防「count==0 检查」与「创建」之间的 TOCTOU —— 两个
		// 并发 POST /setup 都过了上面的 CountWebAdmins==0 判定却各建一个管理员。竞争落败者拿到
		// ErrSetupClosed(表已被抢先建成),按「已初始化」处理:302 /login。
		admin, err := s.store.CreateFirstWebAdmin(ctx, store.NewWebAdmin{
			Username:     username,
			PasswordHash: hash,
			Role:         "admin",
		})
		if errors.Is(err, store.ErrSetupClosed) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if err != nil {
			logrus.WithError(err).WithField("ctx", "setup:create_first_admin").Error("[web] internal error")
			s.setupRetry(w, r, tr(r, "err.internalGeneric"))
			return
		}
		// 直接颁发 session,登入。
		ip := clientIP(r)
		if _, err := s.sess.IssueSession(ctx, w, admin.ID, ip, r.UserAgent()); err != nil {
			s.renderInternalError(w, r, "setup:issue_session", err)
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
	// d_setup_pow:retry 页也按当前 IP 失败数重新下发 PoW 题(与 loginRetry 同理),否则失败一次抬升
	// 难度后,retry 页缺 PoW 字段,合法用户再提交必然 pow_fail 死循环。issue 失败则不带(降级为无 PoW)。
	if powCh, perr := s.sess.IssueChallenge(ComputeDifficulty(s.sess.ipFailures.Recent(clientIP(r)))); perr == nil {
		data["PoW"] = FormatPoWForTemplate(powCh)
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
			s.renderInternalError(w, r, "login:csrf_issue", err)
			return
		}
		cap, err := s.sess.IssueCaptcha(w)
		if err != nil {
			s.renderInternalError(w, r, "login:captcha_gen", err)
			return
		}
		// 自适应 PoW:平时(失败 <3 次)difficulty=0 不下发题目,
		// 模板里 hidden field 都留空,JS solver 也跳过。
		// 失败次数变多 → IssueChallenge 给出 14~22-bit 的题。
		ip := clientIP(r)
		powDiff := ComputeDifficulty(s.sess.ipFailures.Recent(ip))
		powCh, err := s.sess.IssueChallenge(powDiff)
		if err != nil {
			s.renderInternalError(w, r, "login:pow_issue", err)
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

		// 第九轮深扫 LOW:按用户名分桶串行化「读锁定态 + verify + 记账」整段,关闭密码步账号锁定的
		// check-then-act 竞态(见 Server.loginAttemptLocks)。captcha / PoW 已在上方校验完毕,锁只
		// 罩住 AttemptLogin 这段;用闭包 + defer 确保即便 argon2 / DB 路径 panic 也必然解锁。
		res := func() AuthResult {
			unlock := s.lockLoginAttempt(username)
			defer unlock()
			return AttemptLogin(ctx, s.store, s.cfg, username, password, ip)
		}()
		if res.Err != nil {
			// 第十二轮深扫 MED:argon2 容量/ctx 超时(ErrAuthUnavailable)属「暂时不可用」,非用户之过 ——
			// **不**累加 ipFailures(PoW 难度/验证码升级)与账号锁定,回 503 让用户重试,避免容量抖动被放大
			// 成对合法管理员的锁定/难度 DoS。真相仍落 audit 供运维观测。
			if errors.Is(res.Err, ErrAuthUnavailable) {
				s.audit.Write(ctx, nil, "web.login.unavailable",
					FormatTarget("username", username),
					FormatDetail("ip", ip, "reason", "argon2_verify_unavailable"))
				s.renderError(w, r, http.StatusServiceUnavailable, tr(r, "auth.tryAgainLater"))
				return
			}
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
			if err := s.sess.IssueTOTPPending(w, res.Admin.ID, ip, res.Admin.PasswordHash); err != nil {
				s.renderInternalError(w, r, "login:issue_totp_pending", err)
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
		if _, err := s.sess.IssueSession(ctx, w, res.Admin.ID, ip, r.UserAgent()); err != nil {
			s.renderInternalError(w, r, "login:issue_session", err)
			return
		}
		// 成功登录 → 把 IP 失败计数减半(非清零,见 Decay):合法用户自身手误的少量计数会落到阈值下、
		// 几乎无感,而 NAT 共享 IP 下同段攻击者的失败信号不会被一次成功清空。TOTP 分支不在这里衰减,
		// 放到 handleLoginTOTP 成功才算"真登录"。
		s.sess.ipFailures.Decay(ip)
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
	// **第三轮深扫 P1-A**:`ErrAuthDisabled` 对外文案不能区别于 `ErrAuthBadCredentials`,
	// 否则 attacker 用账号枚举工具能直接定位「用户存在但已禁用」名单 — 部分破坏了
	// `AttemptLogin` 顶部承诺的「不暴露用户存在性」。修法:对外统一 BadCredentials 同
	// 文案,**audit 仍写真实 reason**("账号已被禁用",由 handleLogin 的 `res.Err.Error()`
	// 落 detail.reason),运维内部可见、attacker 不可见,与 captcha_fail 同款设计。
	//
	// **第九轮深扫 LOW(账号枚举)**:`ErrAuthLocked` 亦并入本分支。此前锁定态给出区别于「凭证
	// 错误」的专属文案("账号已锁定,请于 X 后重试"),而**不存在**的用户名走 decoy(id=0 永不
	// 锁定)恒返回 ErrAuthBadCredentials —— attacker 用 5 次失败把某用户名锁掉后,凭第 6 次
	// 「锁定 vs 凭证错误」的文案差即可判定该用户名是否存在,构成确定性存在性 oracle,恰与顶部
	// 承诺相悖。修法:**密码步**对外统一 badCredentials,锁定真相仍落 audit(handleLogin 用
	// res.Err.Error() 写 detail.reason)。时序早已由 decoy verify + DecoyWebAdminLoginFailure
	// 抹平。注意:`/login/totp` 步仍显式展示锁定倒计时(handleLoginTOTP)——那一步已凭密码 +
	// pending cookie 证明账号存在,展示锁定不再泄露存在性,反而是必要的可用性反馈。
	case errors.Is(res.Err, ErrAuthLocked),
		errors.Is(res.Err, ErrAuthBadCredentials),
		errors.Is(res.Err, ErrAuthDisabled):
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
// lockTOTPVerify 取(必要时创建)本 adminID 的进程内互斥锁并加锁,返回解锁函数。
// 用于把 /login/totp 的 verify+记账临界区按账号串行化(第八轮深扫 HIGH,见 Server.totpVerifyLocks)。
func (s *Server) lockTOTPVerify(adminID int64) func() {
	m, _ := s.totpVerifyLocks.LoadOrStore(adminID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// lockLoginAttempt 取(按用户名分桶的)/login 密码步互斥锁并加锁,返回解锁函数。
// 用于把 AttemptLogin 的「读锁定态 + verify + 记账」临界区按账号串行化(第九轮深扫 LOW,
// 见 Server.loginAttemptLocks)。归一(ToLower+Trim)与 store 的 CI 用户名查找口径对齐,
// 使同一账号的不同大小写/空白写法落同一桶。桶数固定,内存有界。
func (s *Server) lockLoginAttempt(username string) func() {
	key := strings.ToLower(strings.TrimSpace(username))
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	mu := &s.loginAttemptLocks[h.Sum32()%loginAttemptLockBuckets]
	mu.Lock()
	return mu.Unlock
}

func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	adminID, pendingPwFp, pendingNonce, err := s.sess.LookupTOTPPending(r)
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
	// 第五轮深扫 HIGH:pending 绑定签发时的密码指纹。若期间密码被轮换(UpdateWebAdminPasswordHash),
	// 当前指纹与 pending 里签的不符 → 作废旧 pending、强制回密码步用新密码重来。这样管理员应急改密能
	// 立即斩断「已过密码步、仅差 TOTP」的在途登录,而不必等 5 分钟窗口自然过期。
	if want := passwordFingerprint(admin.PasswordHash); subtle.ConstantTimeCompare(pendingPwFp[:], want[:]) != 1 {
		s.sess.ClearTOTPPending(w)
		s.audit.Write(ctx, admin, "web.totp.pending_stale",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", clientIP(r), "reason", "password_changed"))
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
			s.renderInternalError(w, r, "login_totp:csrf_issue", err)
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

		// 深扫第十轮 MED:空提交(既没填 TOTP 码也没填恢复码)不计入账号锁定计数器,
		// 与 handler_me(disable/regen)、/server-qr 空输入豁免对齐。否则误点提交
		// MaxLoginFailures 次会触发**账号级锁定**(比 step-up IP 冷却更重)。
		if code == "" && recoveryCode == "" {
			s.loginTOTPRetry(w, r, tr(r, "me.totpCodeRequired"), admin.Username, next)
			return
		}

		// 第八轮深扫 HIGH:把「重读锁定 + verify + 记账」整段按账号串行化,关闭并发绕过账号锁定的窗口。
		// 拿到锁后**重新读账号**,让本次判锁看到并发失败已写入的最新 locked_until / failed_logins —— 上面
		// (行 435)基于请求开始时的快照判锁,并发下会被多请求同时越过。web 单进程,进程内互斥即足够。
		unlock := s.lockTOTPVerify(admin.ID)
		defer unlock()
		if fresh, ferr := s.store.GetWebAdmin(ctx, admin.ID); ferr == nil && fresh != nil {
			admin = fresh
		}
		// 第十轮深扫 MED:锁内用**最新**行重验密码指纹 + enabled/TOTP 开关,而非只重读 locked_until。
		// 背景:上面(行 450 快照)基于请求开始时的旧行做过一次指纹/开关校验,但应急改密
		// (UpdateWebAdminPasswordHash + DeleteWebSessionsByAdmin + locked_until 清零)若落在
		// 「行 450 快照读」与下方 IssueSession 之间,本请求仍凭旧指纹通过 460 的检查,且清零的
		// locked_until 反而助其过锁 —— TOTP 用未变的 secret 验过后,会在 DeleteWebSessionsByAdmin
		// **之后**再颁一枚新 session,使「应急改密立即斩断在途登录」失效。锁内用 fresh 行重验即闭合
		// 该 TOCTOU(改密方拿到 totpVerifyLocks 之前或之后,本请求都能看到新指纹并作废 pending)。
		if !admin.Enabled || !admin.TOTPEnabled {
			s.sess.ClearTOTPPending(w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if want := passwordFingerprint(admin.PasswordHash); subtle.ConstantTimeCompare(pendingPwFp[:], want[:]) != 1 {
			s.sess.ClearTOTPPending(w)
			s.audit.Write(ctx, admin, "web.totp.pending_stale",
				FormatTarget("web_admin", admin.ID),
				FormatDetail("ip", ip, "reason", "password_changed"))
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if admin.LockedUntil > 0 && admin.LockedUntil > nowUnix() {
			s.sess.ClearTOTPPending(w)
			s.audit.Write(ctx, admin, "web.totp.locked",
				FormatTarget("web_admin", admin.ID),
				FormatDetail("ip", ip, "locked_until", admin.LockedUntil))
			s.loginTOTPRetry(w, r, tr(r, "auth.accountLocked", fmtTime(admin.LockedUntil)), admin.Username, next)
			return
		}

		// 优先按 6 位 TOTP 码校验;失败再尝试当作恢复码。两种都不行返回 401。
		ok, usedRecovery, recoveryID, verr := s.verifyTOTPOrRecovery(ctx, admin, code, recoveryCode)
		if verr == reasonVerifyUnavailable {
			// 第十四轮深扫 MED:恢复码 argon2 容量/ctx 超时属「暂时不可用」,非码错 —— 不计 ipFailures / 账号锁定,
			// 不消费 pending(用户可重试),回 503(与 AttemptLogin 密码步一致)。
			s.audit.Write(ctx, admin, "web.totp.unavailable",
				FormatTarget("web_admin", admin.ID), FormatDetail("ip", ip))
			s.renderError(w, r, http.StatusServiceUnavailable, tr(r, "auth.tryAgainLater"))
			return
		}
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
		// 第七轮深扫 MED:pending 服务端一次性消费 —— 校验通过、颁 session 前原子标记本 pending nonce。
		// 若该 nonce 已被消费(截获重放 / 完成后二次提交 / 并发双提交),拒绝本次,作废 pending 回登录页。
		// 放在恢复码 mark-used 之前:避免「第二次重放」把一枚恢复码也白白烧掉。
		if !s.sess.MarkPendingConsumed(pendingNonce) {
			s.sess.ClearTOTPPending(w)
			s.audit.Write(ctx, admin, "web.totp.pending_replay",
				FormatTarget("web_admin", admin.ID),
				FormatDetail("ip", ip))
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		// 第十五轮深扫 MED:改「**先颁 session,再** MarkRecoveryCodeUsed」顺序,并在标记失败时回滚 session。
		// 此前是「先标记 used 再 IssueSession」:IssueSession 失败(建 session DB 抖动)会白白**烧掉**一枚恢复码
		// 却拿不到会话。新顺序下——
		//   · IssueSession 失败:恢复码**尚未**标记,用户可用同码重登(pending 已消费,需重走密码步),不浪费码;
		//   · MarkRecoveryCodeUsed 失败:删掉刚建的 session 回滚,保证「一码一用」不被「session 已发但码未烧」破坏。
		// 顺序仍在 MarkPendingConsumed(nonce 一次性)之后,重放保护不变。
		sid, err := s.sess.IssueSession(ctx, w, admin.ID, ip, r.UserAgent())
		if err != nil {
			// 第十七轮深扫 LOW:pending nonce 已在上面 MarkPendingConsumed 消费,IssueSession 又失败 →
			// 清掉 pending cookie,否则浏览器留着一枚死 nonce,用户重试会撞 pending_replay 再跳登录。
			s.sess.ClearTOTPPending(w)
			s.renderInternalError(w, r, "login_totp:issue_session", err)
			return
		}
		if usedRecovery && recoveryID > 0 {
			if merr := s.store.MarkRecoveryCodeUsed(ctx, admin.ID, recoveryID, ip, time.Now().Unix()); merr != nil {
				// 恢复码可能并发被用了 / DB 抖动 —— 回滚刚发的 session(删库 + 清 cookie)并拒绝本次登录,
				// 避免会话已发而恢复码未标记 used(否则该码可被重放,破坏一码一用)。
				// 第十六轮深扫 LOW:一并清 pending cookie —— nonce 已在上面 MarkPendingConsumed 消费,留着死 nonce
				// 只会让重试撞 pending_replay 再跳登录,直接清掉更干净。
				_ = s.store.DeleteWebSession(ctx, sid)
				s.sess.clearSessionCookie(w)
				s.sess.ClearTOTPPending(w)
				s.loginTOTPRetry(w, r, tr(r, "auth.recoveryCodeError"), admin.Username, next)
				return
			}
			s.audit.Write(ctx, admin, "web.totp.recovery_used",
				FormatTarget("web_admin", admin.ID),
				FormatDetail("ip", ip, "recovery_id", recoveryID))
		}
		s.sess.ClearTOTPPending(w)
		// 第七轮深扫 MED:成功登录减半 IP 失败计数(非清零),NAT 共享 IP 下不清空同段攻击者的失败信号。
		s.sess.ipFailures.Decay(ip)
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

// reasonVerifyUnavailable:verifyTOTPOrRecovery 在恢复码 argon2 校验遇容量/ctx 超时(或第十五轮起的
// ConsumeTOTPStep DB 瞬时错误)时冒泡的专属 reason,调用方据此回 503(暂时不可用)而非当作码错计入失败/锁定。
const reasonVerifyUnavailable = "verify_unavailable"

// ErrTOTPStepUnavailable:verifyAndConsumeStepUpTOTP 在 ConsumeTOTPStep 遇 **DB 瞬时错误** 时冒泡的哨兵。
// 第十五轮深扫 MED:step-up 各调用方据此回 503(暂时不可用),**不**累加 stepUpFailures —— 码已 VerifyTOTPStep
// 通过、只是消费写库抖了一下,不该把正确码 + 一次 DB 抖动推进 step-up 冷却(与登录 reasonVerifyUnavailable 对齐)。
var ErrTOTPStepUnavailable = errors.New("totp step consume unavailable")

// verifyTOTPOrRecovery 二选一校验,简化 handler 逻辑。
// 返回 (ok, usedRecovery, recoveryID, errReason)。
// errReason 仅用于 audit 写 reason 字段,不展示给用户(避免提示"是 TOTP 错还是
// recovery 错"被用来侧信道枚举)。
func (s *Server) verifyTOTPOrRecovery(ctx context.Context, admin *store.WebAdmin,
	totpCode, recoveryCode string) (ok bool, usedRecovery bool, recoveryID int64, errReason string) {

	if totpCode != "" {
		step, err := VerifyTOTPStep(admin.TOTPSecret, totpCode)
		if err == nil {
			// 重放保护(0022):原子消费该时间步。同一枚码在其 ~90s 窗口内被重放会命中同一步 →
			// ConsumeTOTPStep 返回 false → 本次登录判为失败(reason=totp_replay,便于审计区分)。
			consumed, cerr := s.store.ConsumeTOTPStep(ctx, admin.ID, step)
			if cerr != nil {
				// 第十五轮深扫 MED:消费时间步的 **DB 瞬时错误** ≠ 码错。码已 VerifyTOTPStep 通过,只是消费写库抖了一下。
				// 若当失败返回,正确码 + 一次 DB 抖动就累加 ipFailures / 账号锁定(与 argon2 容量同类 DoS)。改用
				// reasonVerifyUnavailable 冒泡 → 调用方回 503、不计失败、不消费 pending,用户可重试。无 session 被颁,
				// 无重放旁路(码尚未被消费,重试会重新走完整消费)。
				return false, false, 0, reasonVerifyUnavailable
			}
			if !consumed {
				return false, false, 0, "totp_replay"
			}
			return true, false, 0, ""
		}
		errReason = "totp:" + err.Error()
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
			match, verr := VerifyWebPassword(ctx, norm, c.CodeHash)
			if isVerifyUnavailable(verr) {
				// 第十四轮深扫 MED:argon2 容量/ctx 超时不能当「码不匹配」,否则宿主压力下**合法**恢复码被判失败 +
				// 累加 ipFailures/账号锁定(与登录密码步同类 DoS)。用专属 reason 冒泡,调用方回 503、不计失败。
				return false, false, 0, reasonVerifyUnavailable
			}
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

// verifyAndConsumeStepUpTOTP 校验一枚 6 位 TOTP 码,并在成功时**原子消费**其时间步(与 /login/totp 的
// ConsumeTOTPStep 共用同一 totp_last_used_step 计数器),使该码在其 ~90s skew 窗口内无法被重放到登录或
// 其它 step-up。用于 enable / regen / server-qr reveal 等已登录后的高危二次确认。
//
// 第七轮深扫 MED:此前这些 step-up 走无状态的 VerifyTOTP、不消费步,「刚在 enable / regen / QR-reveal
// 里被输入过的那枚码」在窗口内仍可被拿去 /login/totp(攻击者已握有密码 + 肩窥到码时)。改为与登录共享
// 消费计数即根治:一枚码全局单次可用。
//
// 代价(明确接受):同一 30s 窗口内「登录 + 一次 step-up」若用同一枚码,后者会撞到已消费步而需等下一枚
// 码——这是「一码一用」语义的固有结果,也是多数 2FA 系统的行为。step-up 均为已登录后的低频操作,权衡可接受。
//
// 返回 nil = 校验且消费成功;ErrTOTPMismatch 统一覆盖「码错」与「步已被消费(重放/撞登录)」(不区分,
// 避免侧信道);其它 error 为底层故障。
func (s *Server) verifyAndConsumeStepUpTOTP(ctx context.Context, adminID int64, secret, code string) error {
	step, err := VerifyTOTPStep(secret, code)
	if err != nil {
		return err
	}
	consumed, cerr := s.store.ConsumeTOTPStep(ctx, adminID, step)
	if cerr != nil {
		// 第十五轮深扫 MED:DB 瞬时错误 ≠ 码错。包 ErrTOTPStepUnavailable 让调用方回 503、不累加冷却(见哨兵注释)。
		return fmt.Errorf("%w: %v", ErrTOTPStepUnavailable, cerr)
	}
	if !consumed {
		return ErrTOTPMismatch
	}
	return nil
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
	ctx := r.Context()
	// 第五轮深扫 HIGH:/logout 是**公开路由**(routes.go 直接挂 mux,不过 requireCSRFAndAuth),故
	// ctxKeySessionID 从不会被中间件注入 → csrfBoundID(r) 恒为空串。但退出按钮的 csrf_token 是在**已登录页**
	// 里签发的(绑定当前 session id),用空 boundID 校验必然 mismatch → 恒 403 → DestroySession 永不执行,
	// **登出按钮实际失效**(自第三轮 CSRF 会话绑定起的回归)。修法:校验前先查 session,把其 id 注入 ctx,
	// 让 CSRF 绑定主体与签发时一致;顺带复用这次查询做 audit(去掉原本第二次 LookupSession)。
	// 无 session(已登出 / 无 cookie / 已失效)时保持空绑定,行为不变(此时也无需真正登出)。
	admin, ws, lookupErr := s.sess.LookupSession(ctx, r)
	if lookupErr == nil && ws != nil {
		ctx = context.WithValue(ctx, ctxKeySessionID, ws.ID)
		r = r.WithContext(ctx)
	}
	if err := s.sess.VerifyCSRFToken(r); err != nil {
		http.Error(w, trErr(r, err), http.StatusForbidden)
		return
	}
	if lookupErr == nil && admin != nil {
		s.audit.Write(ctx, admin, "web.logout", FormatTarget("web_admin", admin.ID),
			FormatDetail("ip", clientIP(r)))
	}
	s.sess.DestroySession(ctx, w, r)
	http.Redirect(w, r, "/login", http.StatusFound)
}
