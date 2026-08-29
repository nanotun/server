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

// aclDefaultActionView 是 ACL 列表页顶部「兜底动作」的只读展示。
//
// 为什么要有:一屏 allow 规则在 default=allow 和 default=deny 两种部署下长得
// 一模一样,但语义相反(前者规则只是例外,后者规则才是全部放行来源)。列表页此前
// 不显示这个值,只有 /acl/new 的说明文字提过一句「出厂是 allow」——看列表的人
// 得不到任何提示。
//
// 只读:改这个值是瞬间全网通断,控制台故意不给表单(仅 CLI
// `nanotun-admin setting set acl_default_action`),避免下拉框手滑。
type aclDefaultActionView struct {
	// Action 是数据面实际会用的动作:"allow" / "deny"。Failed 时为空。
	Action string
	// Raw 仅在库里存了个既不是 allow 也不是 deny 的值时非空(如拼成 "deni"),
	// 用于把原始字符串回显给运维——否则他看到 badge 是 deny 却以为自己设的是 allow。
	Raw string
	// Failed 表示读设置本身出错。此时不猜值:allow 和 deny 猜错任何一个方向都是
	// 误导(说 allow 会让人以为网是通的,说 deny 会引发一次无谓的排查)。
	Failed bool
}

// readACLDefaultAction 读取兜底动作,归一化逻辑与数据面
// (cmd/nanotund/acl_runtime.go 的 readSettings)保持一致:
//   - key 不存在      → allow(migration 0003 的 seed 值,也是内置默认)
//   - allow / deny    → 原值(大小写与空白不敏感)
//   - 其它非空值      → deny(fail-closed),并把原值回显
//
// 这里刻意不复用 store.IsAllowed:那个函数有意不读 acl_default_action
// (见其注释),拿它渲染会显示出与数据面相反的结论。
func (s *Server) readACLDefaultAction(ctx context.Context) aclDefaultActionView {
	v, ok, err := s.store.SettingsGet(ctx, "acl_default_action")
	if err != nil {
		logrus.WithError(err).Warn("[acl] failed to read acl_default_action; the list page shows it as unknown")
		return aclDefaultActionView{Failed: true}
	}
	if !ok {
		return aclDefaultActionView{Action: store.ACLAllow}
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case store.ACLAllow:
		return aclDefaultActionView{Action: store.ACLAllow}
	case store.ACLDeny:
		return aclDefaultActionView{Action: store.ACLDeny}
	default:
		return aclDefaultActionView{Action: store.ACLDeny, Raw: v}
	}
}

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
	def := s.readACLDefaultAction(r.Context())
	s.renderPage(w, r, "acl_list.html", PageData{
		Title: tr(r, "page.acl.title"),
		Flash: flashFromQuery(r), // 第七轮 P2:add/delete redirect 都写 flash
		Data: map[string]any{
			"Rows":              rs,
			"DefaultAction":     def.Action,
			"DefaultActionRaw":  def.Raw,
			"DefaultActionFail": def.Failed,
		},
		Nav: NavContext{Active: "acl"},
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
			// 第八轮深扫 LOW:非重复类为内部错误,详情进日志、页面回通用文案(不外泄 err 原文)。
			s.renderInternalError(w, r, "acl_create", err)
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
			logrus.WithError(err).Warn("[web] synchronous reload after the ACL change failed — the data plane still runs the old rules")
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
