package main

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"net/url"
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
	// 如果已经 enabled,先要求输入当前 6 位码(走 disable+re-setup 才合理)。
	cur, err := s.store.GetWebAdmin(r.Context(), admin.ID)
	if err != nil || cur == nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryAccountFailed"))
		return
	}
	if cur.TOTPEnabled {
		// 提示用户先 disable 再 setup,避免一键覆盖造成的安全隐患。
		s.renderError(w, r, http.StatusBadRequest,
			tr(r, "me.totpAlreadyEnabled"))
		return
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.genSecretFailed")+err.Error())
		return
	}
	if err := s.store.SetWebAdminTOTPSecret(r.Context(), admin.ID, secret); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.saveSecretFailed")+err.Error())
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
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.renderQrFailed")+err.Error())
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
	// 的 handler;handleMeTOTPEnable 渲染恢复码页是个静态展示页(不含再次提交的
	// form,只有 GET 链接回 /me),所以那条路径不受影响。
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
		http.Redirect(w, r, "/me?flash="+url.QueryEscape(tr(r, "flash.totpEnabled")), http.StatusFound)
		return
	}
	if err := VerifyTOTP(cur.TOTPSecret, code); err != nil {
		// 不清 secret,让用户能重输一次(Authenticator 显示的码 30s 滚)。
		s.renderError(w, r, http.StatusBadRequest,
			tr(r, "me.totpCodeWrongCheckTime", trErr(r, err)))
		return
	}
	plain, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.genRecoveryFailed")+err.Error())
		return
	}
	n, err := s.store.EnableWebAdminTOTP(r.Context(), admin.ID, hashes, time.Now().Unix())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.enableFailed")+err.Error())
		return
	}
	s.audit.WriteFromRequest(r, "totp_enable",
		FormatTarget("web_admin", admin.ID),
		FormatDetail("recovery_codes", n))

	// 一次性展示恢复码,刷新就再也看不到了。模板里给"我已保存"按钮 → /me。
	s.renderPage(w, r, "me_totp_codes.html", PageData{
		Title: tr(r, "page.meTotpCodesEnable.title"),
		Admin: admin,
		Data: map[string]any{
			"Codes":     plain,
			"FirstTime": true,
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
	cur, err := s.store.GetWebAdmin(r.Context(), admin.ID)
	if err != nil || cur == nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryAccountFailed"))
		return
	}
	if !cur.TOTPEnabled {
		http.Redirect(w, r, "/me?flash="+url.QueryEscape(tr(r, "flash.totpNotEnabled")), http.StatusFound)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	recovery := strings.TrimSpace(r.FormValue("recovery_code"))
	ok, usedRecovery, recoveryID, _ := s.verifyTOTPOrRecovery(r.Context(), cur, code, recovery)
	if !ok {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.totpCodeWrongCloseFail"))
		return
	}
	if usedRecovery && recoveryID > 0 {
		// disable 路径用了恢复码,标记 used 主要是审计完整,实际马上要全删了。
		_ = s.store.MarkRecoveryCodeUsed(r.Context(), recoveryID, clientIP(r), time.Now().Unix())
	}
	if err := s.store.DisableWebAdminTOTP(r.Context(), admin.ID); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.closeFailed")+err.Error())
		return
	}
	s.audit.WriteFromRequest(r, "totp_disable",
		FormatTarget("web_admin", admin.ID),
		FormatDetail("via", choose(usedRecovery, "recovery", "totp")))
	http.Redirect(w, r, "/me?flash="+url.QueryEscape(tr(r, "flash.totpDisabled")), http.StatusFound)
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
	cur, err := s.store.GetWebAdmin(r.Context(), admin.ID)
	if err != nil || cur == nil || !cur.TOTPEnabled {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.totpNotEnabledRegen"))
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if err := VerifyTOTP(cur.TOTPSecret, code); err != nil {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "me.totpCodeWrong", trErr(r, err)))
		return
	}
	plain, hashes, err := GenerateRecoveryCodes()
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.genRecoveryFailed")+err.Error())
		return
	}
	if err := s.store.RegenerateRecoveryCodes(r.Context(), admin.ID, hashes, time.Now().Unix()); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.saveRecoveryFailed")+err.Error())
		return
	}
	s.audit.WriteFromRequest(r, "totp_regen_codes",
		FormatTarget("web_admin", admin.ID),
		FormatDetail("count", len(plain)))
	s.renderPage(w, r, "me_totp_codes.html", PageData{
		Title: tr(r, "page.meTotpCodesRegen.title"),
		Admin: admin,
		Data: map[string]any{
			"Codes":     plain,
			"FirstTime": false,
		},
		Nav: NavContext{Active: "me"},
	})
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
