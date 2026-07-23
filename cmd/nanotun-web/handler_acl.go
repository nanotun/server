package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// ACL handlers
//
//   GET  /acl                  → list
//   GET  /acl/new              → 新建表单(下拉 user 列表 + action/proto/port)
//   POST /acl/new              → 创建
//   POST /acl/{id}/delete      → 删除
//
// 改动后,若 cfg.AutoReloadOnACLChange = true,异步通知 nanotund reload。

func (s *Server) handleACLList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pairs, err := s.store.ListACLPairs(r.Context())
	if err != nil {
		s.renderInternalError(w, r, "acl:list", err)
		return
	}
	users, _ := s.store.ListUsers(r.Context())
	uByID := indexUsersByID(users)
	type row struct {
		ID        int64
		Action    string
		SrcName   string
		DstName   string
		Proto     string
		PortRange string
		DstKind   string
		CreatedAt int64
	}
	rs := make([]row, 0, len(pairs))
	for _, p := range pairs {
		rs = append(rs, row{
			ID:        p.ID,
			Action:    p.Action,
			SrcName:   nameOrAny(uByID, p.SrcUserID),
			DstName:   nameOrAny(uByID, p.DstUserID),
			Proto:     p.Proto,
			PortRange: portRangeText(p.DstPortLo, p.DstPortHi),
			DstKind:   p.DstKind,
			CreatedAt: p.CreatedAt,
		})
	}
	s.renderPage(w, r, "acl_list.html", PageData{
		Title: tr(r, "page.acl.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:add/delete redirect 都写 flash
		Data:  map[string]any{"Rows": rs},
		Nav:   NavContext{Active: "acl"},
	})
}

func (s *Server) handleACLNew(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminRole(w, r) {
		return
	}
	users, _ := s.store.ListUsers(r.Context())
	switch r.Method {
	case http.MethodGet:
		s.renderPage(w, r, "acl_new.html", PageData{
			Title: tr(r, "page.aclNew.title"),
			Data:  map[string]any{"Users": users},
			Nav:   NavContext{Active: "acl"},
		})
	case http.MethodPost:
		retry := func(msg string) {
			s.renderPage(w, r, "acl_new.html", PageData{
				Title: tr(r, "page.aclNew.title"),
				Data:  map[string]any{"Users": users},
				Flash: &Flash{Kind: "err", Text: msg},
				Nav:   NavContext{Active: "acl"},
			})
		}
		// 第十轮深扫 P1:此前 ParseInt/Atoi 的错误被 `_` 丢弃,非法输入静默落 0 ——
		// 而 0 在 ACL 语义里是「任意」(任意用户 / 任意端口)。number 输入框挡不住
		// 所有形态("1e3" 等科学计数法多数浏览器放行),curl 更没有约束:一次手滑
		// 就把定向规则静默放大成全网 any 规则。解析失败必须显式报错打回表单。
		srcUserID, errSrc := parseFormInt64Strict(r.FormValue("src_user_id"))
		dstUserID, errDst := parseFormInt64Strict(r.FormValue("dst_user_id"))
		if errSrc != nil || errDst != nil {
			retry(tr(r, "acl.userIdInvalid"))
			return
		}
		action := strings.TrimSpace(r.FormValue("action"))
		proto := strings.ToLower(strings.TrimSpace(r.FormValue("proto")))
		// K(2026-05-23):UX 容错 — UI/CLI/curl 习惯传 "any"/"*" 表示"任意协议",
		// 而 store 用 ""(空串)做语义。统一在 handler 收口转换,避免下游 400。
		if proto == "any" || proto == "*" {
			proto = ""
		}
		lo64, errLo := parseFormInt64Strict(r.FormValue("port_lo"))
		hi64, errHi := parseFormInt64Strict(r.FormValue("port_hi"))
		if errLo != nil || errHi != nil {
			retry(tr(r, "acl.portInvalid"))
			return
		}
		portLo, portHi := int(lo64), int(hi64)
		dstKind := strings.TrimSpace(r.FormValue("dst_kind"))

		pair, err := s.store.AddACLPair(r.Context(), store.NewACLPair{
			SrcUserID: srcUserID,
			DstUserID: dstUserID,
			Action:    action,
			Proto:     proto,
			DstPortLo: portLo,
			DstPortHi: portHi,
			DstKind:   dstKind,
		})
		if err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				retry(tr(r, "acl.duplicate"))
				return
			}
			retry(tr(r, "acl.createFailed") + err.Error())
			return
		}
		s.audit.WriteFromRequest(r, "acl_create", FormatTarget("acl", pair.ID),
			FormatDetail("src", srcUserID, "dst", dstUserID, "action", action,
				"proto", proto, "port_lo", portLo, "port_hi", portHi, "kind", dstKind))
		http.Redirect(w, r,
			"/acl?"+s.aclChangeFlashQuery(r, "flash.aclCreated"),
			http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// parseFormInt64Strict:表单整数字段严格解析。空串视为 0(端口/用户选择器的
// 「任意」语义),其余必须是完整十进制整数 —— 部分可解析("8080x")或科学计数
// 法("1e3")一律报错,不静默截断成意外值。
func parseFormInt64Strict(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	return strconv.ParseInt(raw, 10, 64)
}

func (s *Server) handleACLAction(w http.ResponseWriter, r *http.Request) {
	segs := pathSegments(r.URL.Path) // [acl, id, verb]
	if len(segs) < 3 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.missingAclAction"))
		return
	}
	id, err := strconv.ParseInt(segs[1], 10, 64)
	if err != nil || id <= 0 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.invalidAclId"))
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
	switch segs[2] {
	case "delete":
		if err := s.store.DeleteACLPair(r.Context(), id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				s.renderError(w, r, http.StatusNotFound, tr(r, "err.aclNotFound"))
				return
			}
			s.renderInternalError(w, r, "acl:delete", err)
			return
		}
		s.audit.WriteFromRequest(r, "acl_delete", FormatTarget("acl", id), "")
		http.Redirect(w, r,
			"/acl?"+s.aclChangeFlashQuery(r, "flash.aclDeleted"),
			http.StatusSeeOther)
	default:
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.unknownAction"))
	}
}

// aclChangeFlash:ACL 写操作后的 flash 文案闭环(2026-07-19 易用性改版)。
//
// 原实现:cfg.AutoReloadOnACLChange 时 tryReloadACLBackground 异步 best-effort,
// flash 只说「已创建」,admin 无从得知规则**是否已生效**;auto-reload 关闭时更是
// 全靠 admin 记得手点「重载 ACL」,忘了就是「建了规则但没生效」的暗坑。
// 改成同步 reload(5s 超时)并按三种结果给差异化文案 + 横幅色级:
//   - reload 成功       → ok  「…已重载生效」
//   - reload 失败       → warn「…但自动重载失败,请手动点『重载 ACL』」(DB 已落,不回滚)
//   - auto-reload 关闭  → warn「…请点『重载 ACL』使其生效」
//
// 返回值直接是 redirect 用的 query 片段(flash + flash_kind,已转义)。
func (s *Server) aclChangeFlashQuery(r *http.Request, baseKey string) string {
	base := tr(r, baseKey)
	msg, kind := "", ""
	switch {
	case !s.cfg.AutoReloadOnACLChange || s.control == nil:
		msg, kind = base+tr(r, "flash.aclNeedManualReload"), "warn"
	default:
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if _, err := s.control.ReloadACL(ctx); err != nil {
			logrus.WithError(err).Warn("[web] ACL 变更后同步 reload 失败 — 数据面仍按旧规则运行")
			msg, kind = base+tr(r, "flash.aclReloadFailed"), "warn"
		} else {
			msg, kind = base+tr(r, "flash.aclReloadedOK"), "ok"
		}
	}
	// flashQuery 内部收口 kind 白名单 + QueryEscape + 附签名(第三轮 L5)。
	return flashQuery(msg, kind)
}

// helpers

func indexUsersByID(users []*store.User) map[int64]*store.User {
	out := make(map[int64]*store.User, len(users))
	for _, u := range users {
		out[u.ID] = u
	}
	return out
}

func nameOrAny(idx map[int64]*store.User, id int64) string {
	if id == 0 {
		return "<any>"
	}
	if u, ok := idx[id]; ok {
		return u.Username
	}
	return fmt.Sprintf("uid=%d", id)
}

func portRangeText(lo, hi int) string {
	if lo == 0 && hi == 0 {
		return "*"
	}
	if lo == hi {
		return strconv.Itoa(lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}
