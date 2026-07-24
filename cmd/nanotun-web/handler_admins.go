package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nanotun/server/store"
)

// admins handlers — 多 Web 管理员账号管理。
//
//   GET  /admins                  → list
//   GET  /admins/new              → 新建表单
//   POST /admins/new              → 创建
//   POST /admins/{id}/reset-pwd   → 改密
//   POST /admins/{id}/disable
//   POST /admins/{id}/enable
//   POST /admins/{id}/delete
//   POST /admins/{id}/set-role
//   POST /admins/{id}/unlock      → 重置失败计数 / 解锁
//
// 保护:
//   - 最后一个 enabled=admin 不能 disable / delete / 降级为 viewer;
//   - 任何对 admin 自己的 disable / delete 直接拒(避免误操作把自己锁外)。

func (s *Server) handleAdminList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 第四轮深扫 MED(d_viewer_admins):列表页也要 admin 角色。此前只有 /admins/new 与各写操作 gate 了角色,
	// GET /admins 裸奔 —— viewer 能枚举全部管理员账号(用户名、角色、启用/锁定状态、上次登录 IP/时间),
	// 是不必要的信息暴露(viewer 定位是「只读业务视图」,不该看到管理员账户台账)。与其它 /admins 端点对齐。
	if !s.requireAdminRole(w, r) {
		return
	}
	admins, err := s.store.ListWebAdmins(r.Context())
	if err != nil {
		s.renderInternalError(w, r, "admins:list", err)
		return
	}
	s.renderPage(w, r, "admins_list.html", PageData{
		Title: tr(r, "page.admins.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:create/disable/enable/delete/reset-pwd 等 redirect 都写了 flash
		Data:  map[string]any{"Admins": admins},
		Nav:   NavContext{Active: "admins"},
	})
}

func (s *Server) handleAdminNew(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminRole(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.renderPage(w, r, "admin_new.html", PageData{
			Title: tr(r, "page.adminNew.title"),
			Nav:   NavContext{Active: "admins"},
		})
	case http.MethodPost:
		username := strings.TrimSpace(r.FormValue("username"))
		role := strings.TrimSpace(r.FormValue("role"))
		password := r.FormValue("password")
		confirm := r.FormValue("password_confirm")
		if password != confirm {
			s.adminNewRetry(w, r, tr(r, "auth.passwordMismatch"))
			return
		}
		if err := ValidatePasswordStrength(password); err != nil {
			s.adminNewRetry(w, r, trErr(r, err))
			return
		}
		hash, err := HashWebPassword(password)
		if err != nil {
			// 第八轮深扫 LOW:哈希失败是内部错误,详情进日志、页面回通用文案(不外泄 err 原文)。
			s.renderInternalError(w, r, "admin_new:hash_pwd", err)
			return
		}
		me := adminFromCtx(r.Context())
		var createdBy int64
		if me != nil {
			createdBy = me.ID
		}
		newAdmin, err := s.store.CreateWebAdmin(r.Context(), store.NewWebAdmin{
			Username:     username,
			PasswordHash: hash,
			Role:         role,
			CreatedBy:    createdBy,
		})
		if err != nil {
			// 第八轮深扫 LOW:重名 → 友好提示 + 保留表单;其余内部错误 → 详情进日志、页面通用文案。
			if errors.Is(err, store.ErrDuplicate) {
				s.adminNewRetry(w, r, tr(r, "err.usernameTaken", username))
				return
			}
			s.renderInternalError(w, r, "admin_new:create", err)
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_create",
			FormatTarget("web_admin", newAdmin.ID),
			FormatDetail("username", newAdmin.Username, "role", newAdmin.Role))
		// username 是 admin 自由输入;flashRedirect 内部 QueryEscape 并附签名(第三轮 L5)。
		flashRedirect(w, r, "/admins", tr(r, "flash.adminCreated", newAdmin.Username), "")
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) adminNewRetry(w http.ResponseWriter, r *http.Request, msg string) {
	s.renderPage(w, r, "admin_new.html", PageData{
		Title: tr(r, "page.adminNew.title"),
		Flash: &Flash{Kind: "err", Text: msg},
		Nav:   NavContext{Active: "admins"},
	})
}

func (s *Server) handleAdminAction(w http.ResponseWriter, r *http.Request) {
	segs := pathSegments(r.URL.Path) // [admins, id, verb]
	if len(segs) < 3 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.missingAction"))
		return
	}
	id, err := strconv.ParseInt(segs[1], 10, 64)
	if err != nil || id <= 0 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.invalidAdminId"))
		return
	}
	// 2026-07-19 易用性改版:GET /admins/{id}/reset-pwd 渲染独立改密表单页
	//(替代原列表页 JS prompt() 弹窗)。GET 无副作用,CSRF middleware 已短路。
	if r.Method == http.MethodGet && segs[2] == "reset-pwd" {
		if !s.requireAdminRole(w, r) {
			return
		}
		target, err := s.store.GetWebAdmin(r.Context(), id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				s.renderError(w, r, http.StatusNotFound, tr(r, "err.adminNotFound"))
				return
			}
			s.renderInternalError(w, r, "admins:get_reset_pwd", err)
			return
		}
		// 第七轮深扫 MED:改**自己**的密码需 step-up(当前密码 +(若开)TOTP),表单据此多渲两个字段。
		meGet := adminFromCtx(r.Context())
		isSelfGet := meGet != nil && meGet.ID == target.ID
		s.renderPage(w, r, "admin_reset_pwd.html", PageData{
			Title: tr(r, "page.adminPwd.title", target.Username),
			Data: map[string]any{
				"Target":   target,
				"IsSelf":   isSelfGet,
				"SelfTOTP": isSelfGet && target.TOTPEnabled,
			},
			Nav: NavContext{Active: "admins"},
		})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}

	target, err := s.store.GetWebAdmin(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, tr(r, "err.adminNotFound"))
			return
		}
		s.renderInternalError(w, r, "admins:get_action", err)
		return
	}
	me := adminFromCtx(r.Context())
	verb := segs[2]

	// 任何对当前登录管理员自己的危险操作 → 拒绝
	if me != nil && me.ID == target.ID {
		switch verb {
		case "disable", "delete", "set-role":
			s.renderError(w, r, http.StatusBadRequest,
				tr(r, "admins.cannotActOnSelf"))
			return
		}
	}

	switch verb {
	case "reset-pwd":
		isSelf := me != nil && me.ID == target.ID
		// 2026-07-19 易用性:校验失败回渲染表单页 + 错误横幅(而不是甩到错误页
		// 让 admin 按后退键找回输入),与表单页 GET 同模板。
		retryForm := func(msg string) {
			s.renderPage(w, r, "admin_reset_pwd.html", PageData{
				Title: tr(r, "page.adminPwd.title", target.Username),
				Flash: &Flash{Kind: "err", Text: msg},
				Data: map[string]any{
					"Target":   target,
					"IsSelf":   isSelf,
					"SelfTOTP": isSelf && target.TOTPEnabled,
				},
				Nav: NavContext{Active: "admins"},
			})
		}
		// 第七轮深扫 MED:改**自己**的密码要求 step-up —— 先验当前密码,(若已开 TOTP)再验一枚当前 6 位码。
		// 背景:此前只要 requireAdminRole + CSRF,会话被劫持(cookie 失窃 / 未锁屏离开)即可静默改掉自己的
		// 密码 → 持久接管 / 反锁真正的管理员。改**他人**密码属管理操作,已由 requireAdminRole 把关,不在此加。
		// 复用 stepUpFailures(与 QR-reveal / TOTP disable 同套 IP 冷却),防止对当前密码/TOTP 暴破。
		if isSelf {
			// 第九轮深扫 MED:按 adminID 串行化「读冷却 + 密码/TOTP verify + 记账」临界区,关闭
			// step-up 冷却的 check-then-act 竞态(与 handleMeTOTPDisable 同源,复用 totpVerifyLocks)。
			unlock := s.lockTOTPVerify(me.ID)
			defer unlock()
			ip := clientIP(r)
			if s.stepUpFailures.Recent(ip) >= stepUpMaxFailures {
				s.audit.WriteFromRequest(r, "webadmin_reset_pwd_locked",
					FormatTarget("web_admin", id), FormatDetail("ip", ip, "reason", "ip_cooldown"))
				s.renderError(w, r, http.StatusTooManyRequests, tr(r, "me.totpTooManyAttempts"))
				return
			}
			curPwd := r.FormValue("current_password")
			if curPwd == "" {
				retryForm(tr(r, "adminPwd.currentRequired"))
				return
			}
			okCur, verr := VerifyWebPassword(r.Context(), curPwd, me.PasswordHash)
			if verr != nil || !okCur {
				s.stepUpFailures.Inc(ip)
				s.audit.WriteFromRequest(r, "webadmin_reset_pwd_stepup_fail",
					FormatTarget("web_admin", id), FormatDetail("ip", ip, "reason", "wrong_current_password"))
				retryForm(tr(r, "adminPwd.currentWrong"))
				return
			}
			if me.TOTPEnabled {
				code := strings.TrimSpace(r.FormValue("totp_code"))
				if code == "" {
					retryForm(tr(r, "adminPwd.totpRequired"))
					return
				}
				if terr := s.verifyAndConsumeStepUpTOTP(r.Context(), me.ID, me.TOTPSecret, code); terr != nil {
					s.stepUpFailures.Inc(ip)
					s.audit.WriteFromRequest(r, "webadmin_reset_pwd_stepup_fail",
						FormatTarget("web_admin", id), FormatDetail("ip", ip, "reason", "wrong_totp"))
					retryForm(tr(r, "adminPwd.totpWrong"))
					return
				}
			}
			// step-up 全过 → 清 IP 冷却计数(与 QR-reveal / login 成功即 Reset 对齐)。
			s.stepUpFailures.Reset(ip)
		}
		pwd := r.FormValue("password")
		confirm := r.FormValue("password_confirm")
		if pwd != confirm {
			retryForm(tr(r, "auth.passwordMismatch"))
			return
		}
		if err := ValidatePasswordStrength(pwd); err != nil {
			retryForm(trErr(r, err))
			return
		}
		hash, err := HashWebPassword(pwd)
		if err != nil {
			s.renderInternalError(w, r, "admins:hash_pwd", err)
			return
		}
		if err := s.store.UpdateWebAdminPasswordHash(r.Context(), id, hash); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.adminNotFound", "err.pwChangeFailed")
			return
		}
		// 改密后清空该 admin 的所有 session,强制重新登录(防止旧 session 继续用)。
		_, _ = s.store.DeleteWebSessionsByAdmin(r.Context(), id)
		s.audit.WriteFromRequest(r, "webadmin_reset_pwd",
			FormatTarget("web_admin", id), FormatDetail("username", target.Username))
		flashRedirect(w, r, "/admins", tr(r, "flash.adminPwdReset"), "")

	case "disable":
		// 原子 floor 守卫(第四轮深扫 HIGH):ensureNotLastAdmin 只是友好的快速预检(常见单请求场景给清晰文案),
		// 真正**防并发 TOCTOU** 的是 SetWebAdminEnabledEnsuringAdmin —— 它在事务内「先写后验 floor」,两个并发禁用
		// 不同 admin 时后者会拿到 ErrLastAdmin 并回滚,绝不会把系统推入零可登录管理员。
		if target.Role == "admin" {
			if err := s.ensureNotLastAdmin(r); err != nil {
				s.renderError(w, r, http.StatusBadRequest, err.Error())
				return
			}
		}
		if err := s.store.SetWebAdminEnabledEnsuringAdmin(r.Context(), id); err != nil {
			if errors.Is(err, store.ErrLastAdmin) {
				s.renderError(w, r, http.StatusBadRequest, tr(r, "admins.lastAdmin"))
				return
			}
			s.renderStoreWriteErr(w, r, err, "err.adminNotFound", "err.disableFailed")
			return
		}
		_, _ = s.store.DeleteWebSessionsByAdmin(r.Context(), id)
		s.audit.WriteFromRequest(r, "webadmin_disable",
			FormatTarget("web_admin", id), FormatDetail("username", target.Username))
		flashRedirect(w, r, "/admins", tr(r, "flash.adminDisabled"), "")

	case "enable":
		if err := s.store.SetWebAdminEnabled(r.Context(), id, true); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.adminNotFound", "err.enableFailed")
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_enable",
			FormatTarget("web_admin", id), FormatDetail("username", target.Username))
		flashRedirect(w, r, "/admins", tr(r, "flash.adminEnabled"), "")

	case "delete":
		if target.Role == "admin" {
			if err := s.ensureNotLastAdmin(r); err != nil {
				s.renderError(w, r, http.StatusBadRequest, err.Error())
				return
			}
		}
		if err := s.store.DeleteWebAdminEnsuringAdmin(r.Context(), id); err != nil {
			if errors.Is(err, store.ErrLastAdmin) {
				s.renderError(w, r, http.StatusBadRequest, tr(r, "admins.lastAdmin"))
				return
			}
			s.renderStoreWriteErr(w, r, err, "err.adminNotFound", "err.deleteFailed")
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_delete",
			FormatTarget("web_admin", id), FormatDetail("username", target.Username))
		flashRedirect(w, r, "/admins", tr(r, "flash.adminDeleted"), "")

	case "set-role":
		newRole := strings.TrimSpace(r.FormValue("role"))
		// 第九轮深扫 LOW:先在 handler 侧校验角色枚举,非法值回本地化 400 —— 此前直接把
		// store 的内部错误串("store: set web admin role: store: invalid web admin role \"x\"")
		// 经 err.Error() 原样渲染给页面,与本仓其它写路径统一遮蔽内部错误的做法不一致。
		if newRole != "admin" && newRole != "viewer" {
			s.renderError(w, r, http.StatusBadRequest, tr(r, "admins.invalidRole"))
			return
		}
		if target.Role == "admin" && newRole == "viewer" {
			if err := s.ensureNotLastAdmin(r); err != nil {
				s.renderError(w, r, http.StatusBadRequest, err.Error())
				return
			}
		}
		if err := s.store.SetWebAdminRoleEnsuringAdmin(r.Context(), id, newRole); err != nil {
			if errors.Is(err, store.ErrLastAdmin) {
				s.renderError(w, r, http.StatusBadRequest, tr(r, "admins.lastAdmin"))
				return
			}
			// 已在上面挡掉非法角色,走到这里的都是意外内部错误 → 统一遮蔽。
			s.renderInternalError(w, r, "admins:set_role", err)
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_set_role",
			FormatTarget("web_admin", id),
			FormatDetail("username", target.Username, "role", newRole))
		flashRedirect(w, r, "/admins", tr(r, "flash.adminRoleChanged"), "")

	case "unlock":
		if err := s.store.ResetWebAdminLockout(r.Context(), id); err != nil {
			s.renderInternalError(w, r, "admins:unlock", err)
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_unlock",
			FormatTarget("web_admin", id), FormatDetail("username", target.Username))
		flashRedirect(w, r, "/admins", tr(r, "flash.adminUnlocked"), "")

	default:
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.unknownActionVerb", verb))
	}
}

// ensureNotLastAdmin:禁用 / 删除 / 降级 admin 角色前的保护。
func (s *Server) ensureNotLastAdmin(r *http.Request) error {
	n, err := s.store.CountEnabledWebAdminsByRole(r.Context(), "admin")
	if err != nil {
		return err
	}
	if n <= 1 {
		return errors.New(tr(r, "admins.lastAdmin"))
	}
	return nil
}
