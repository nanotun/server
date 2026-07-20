package main

import (
	"errors"
	"net/http"
	"net/url"
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
	admins, err := s.store.ListWebAdmins(r.Context())
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "list admins: "+err.Error())
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
			s.adminNewRetry(w, r, tr(r, "err.hashFailed")+err.Error())
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
			s.adminNewRetry(w, r, tr(r, "err.createFailed")+err.Error())
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_create",
			FormatTarget("web_admin", newAdmin.ID),
			FormatDetail("username", newAdmin.Username, "role", newAdmin.Role))
		// 第三轮深扫 P2-8:username 是 admin 自由输入,需 QueryEscape 防止 `&`/`?` 污染 query。
		http.Redirect(w, r,
			"/admins?flash="+url.QueryEscape(tr(r, "flash.adminCreated", newAdmin.Username)),
			http.StatusSeeOther)
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
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryFailed")+err.Error())
			return
		}
		s.renderPage(w, r, "admin_reset_pwd.html", PageData{
			Title: tr(r, "page.adminPwd.title", target.Username),
			Data:  map[string]any{"Target": target},
			Nav:   NavContext{Active: "admins"},
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
		s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.queryFailed")+err.Error())
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
		// 2026-07-19 易用性:校验失败回渲染表单页 + 错误横幅(而不是甩到错误页
		// 让 admin 按后退键找回输入),与表单页 GET 同模板。
		retryForm := func(msg string) {
			s.renderPage(w, r, "admin_reset_pwd.html", PageData{
				Title: tr(r, "page.adminPwd.title", target.Username),
				Flash: &Flash{Kind: "err", Text: msg},
				Data:  map[string]any{"Target": target},
				Nav:   NavContext{Active: "admins"},
			})
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
			s.renderError(w, r, http.StatusInternalServerError, tr(r, "err.hashFailed")+err.Error())
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
		http.Redirect(w, r, "/admins?flash="+url.QueryEscape(tr(r, "flash.adminPwdReset")), http.StatusSeeOther)

	case "disable":
		if target.Role == "admin" {
			if err := s.ensureNotLastAdmin(r); err != nil {
				s.renderError(w, r, http.StatusBadRequest, err.Error())
				return
			}
		}
		if err := s.store.SetWebAdminEnabled(r.Context(), id, false); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.adminNotFound", "err.disableFailed")
			return
		}
		_, _ = s.store.DeleteWebSessionsByAdmin(r.Context(), id)
		s.audit.WriteFromRequest(r, "webadmin_disable",
			FormatTarget("web_admin", id), FormatDetail("username", target.Username))
		http.Redirect(w, r, "/admins?flash="+url.QueryEscape(tr(r, "flash.adminDisabled")), http.StatusSeeOther)

	case "enable":
		if err := s.store.SetWebAdminEnabled(r.Context(), id, true); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.adminNotFound", "err.enableFailed")
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_enable",
			FormatTarget("web_admin", id), FormatDetail("username", target.Username))
		http.Redirect(w, r, "/admins?flash="+url.QueryEscape(tr(r, "flash.adminEnabled")), http.StatusSeeOther)

	case "delete":
		if target.Role == "admin" {
			if err := s.ensureNotLastAdmin(r); err != nil {
				s.renderError(w, r, http.StatusBadRequest, err.Error())
				return
			}
		}
		if err := s.store.DeleteWebAdmin(r.Context(), id); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.adminNotFound", "err.deleteFailed")
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_delete",
			FormatTarget("web_admin", id), FormatDetail("username", target.Username))
		http.Redirect(w, r, "/admins?flash="+url.QueryEscape(tr(r, "flash.adminDeleted")), http.StatusSeeOther)

	case "set-role":
		newRole := strings.TrimSpace(r.FormValue("role"))
		if target.Role == "admin" && newRole == "viewer" {
			if err := s.ensureNotLastAdmin(r); err != nil {
				s.renderError(w, r, http.StatusBadRequest, err.Error())
				return
			}
		}
		if err := s.store.SetWebAdminRole(r.Context(), id, newRole); err != nil {
			s.renderError(w, r, http.StatusBadRequest, err.Error())
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_set_role",
			FormatTarget("web_admin", id),
			FormatDetail("username", target.Username, "role", newRole))
		http.Redirect(w, r, "/admins?flash="+url.QueryEscape(tr(r, "flash.adminRoleChanged")), http.StatusSeeOther)

	case "unlock":
		if err := s.store.ResetWebAdminLockout(r.Context(), id); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit.WriteFromRequest(r, "webadmin_unlock",
			FormatTarget("web_admin", id), FormatDetail("username", target.Username))
		http.Redirect(w, r, "/admins?flash="+url.QueryEscape(tr(r, "flash.adminUnlocked")), http.StatusSeeOther)

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
