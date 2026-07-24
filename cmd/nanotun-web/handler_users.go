package main

import (
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// users handlers
//
// 路由(均需 admin 角色才能写;viewer 只能 GET):
//
//	GET  /users                              → list
//	GET  /users/new                          → 新建表单
//	POST /users/new                          → 创建 → flash + 303 redirect
//	GET  /users/{id}                         → 详情
//	GET  /users/{id}/created                 → P1#2:user create 一次性 PSK + cred QR 展示
//	GET  /users/{id}/reset-psk-result        → P1#2:reset-psk 一次性 PSK + cred QR 展示
//	POST /users/{id}/disable                 → 禁用
//	POST /users/{id}/enable                  → 启用
//	POST /users/{id}/delete                  → 删除
//	POST /users/{id}/reset-psk               → 生成新 PSK → flash + 303 redirect
//	POST /users/{id}/set-admin               → 设置/取消管理员
//
// 0008(2026-05-23):「固定 vIP」改 device 维度,user 上没有该字段了。
// 在 /devices/{id}/set-fixed-vip 配置。
//
// 0013(2026-05-25):profile / credentials 解耦。create + reset-psk 路径都额外
// 渲染一份 nanotun-cred:// QR(含 username + UUID + PSK + ts)。
//
// P1#2(2026-05-26):POST 完成业务后**不再**直接 render 结果页 —— 浏览器刷新 /
// 后退会重新触发 POST,使用户拿到的 PSK 立即被 rotate 失效。改成「flash 暂存 →
// 303 redirect → GET 一次性消费」的 PRG 模式;flash 实现见 credentials_flash.go。
//
// P1#3(2026-05-26):reset-psk 不再手写 RotateUserPSK + 条件 BackfillUserCredentialID,
// 改成调用 store.RotateUserPSKAndEnsureCredential(CLI 同款),保持「PSK rotate
// + UUID backfill」这一关键操作两端字节级一致。

func (s *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// P1#7(2026-05-26):?show_disabled=1(或 ?all=1)展开列表,默认隐藏 disabled。
	// 与 admin CLI `user list --all` 语义对齐;不带参数维持现状(典型场景看活跃账号)。
	showDisabled := userListShowDisabled(r)
	var (
		users []*store.User
		err   error
	)
	if showDisabled {
		users, err = s.store.ListUsersAll(r.Context())
	} else {
		users, err = s.store.ListUsers(r.Context())
	}
	if err != nil {
		s.renderInternalError(w, r, "users:list", err)
		return
	}
	// 2026-07-19 易用性:?q= 按用户名过滤(大小写不敏感 contains)。用户量级
	// 通常几十到几百,内存过滤即可,不必下推 SQL。
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query != "" {
		q := strings.ToLower(query)
		filtered := users[:0]
		for _, u := range users {
			if strings.Contains(strings.ToLower(u.Username), q) {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}
	s.renderPage(w, r, "users_list.html", PageData{
		Title: tr(r, "page.users.title"),
		// 第六轮深扫 P1#1:delete 后 redirect 写了 `?flash=已删除...`,但本 GET
		// 不读 → 横幅永不展示,admin 操作反馈丢失。统一走 flashFromQuery helper。
		Flash: flashFromQuery(r),
		Data: map[string]any{
			"Users":        users,
			"ShowDisabled": showDisabled,
			"Query":        query,
		},
		Nav: NavContext{Active: "users"},
	})
}

// userListShowDisabled 接受 ?show_disabled=1 / ?all=1 / ?show_disabled=true 任一形式,
// 让运维 / 书签 / 控件实现都能凑得上。**只**看到 truthy 字符串才认为开启;空 / 0 / 任何其它
// 都视作关闭(确保「明确请求」才暴露 disabled,符合最小披露原则)。
func userListShowDisabled(r *http.Request) bool {
	q := r.URL.Query()
	for _, k := range []string{"show_disabled", "all"} {
		v := strings.ToLower(strings.TrimSpace(q.Get(k)))
		if v == "1" || v == "true" || v == "yes" || v == "on" {
			return true
		}
	}
	return false
}

func (s *Server) handleUserNew(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminRole(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.renderUserNew(w, r, nil, "")
	case http.MethodPost:
		username := strings.TrimSpace(r.FormValue("username"))
		isAdmin := r.FormValue("is_admin") == "on"
		exitAllowed := r.FormValue("exit_allowed") == "on"

		if username == "" {
			s.renderUserNew(w, r, nil, tr(r, "form.usernameRequired"))
			return
		}
		// 平台白名单:复选框多值收集(2026-07-19,原自由文本 CSV)。全选/全不选 = 不限。
		allowedPlatforms, err := platformsFromForm(r)
		if err != nil {
			// 第十二轮深扫 LOW:平台来自复选框(受控),非法 token 仅可能来自手工构造 POST。回本地化的通用校验
			// 文案,不再把 store 层 err(含 "store: unknown platform ...")原样回显到页面。
			logrus.WithError(err).Warn("[users] platformsFromForm(create) rejected")
			s.renderUserNew(w, r, nil, tr(r, "form.invalidPlatforms"))
			return
		}
		// 自动生成 PSK,创建成功后一次性展示给管理员(不入审计 detail)。
		psk, err := util.GeneratePSK()
		if err != nil {
			// 第八轮深扫 LOW:内部错误详情进服务端日志,页面只回通用文案(不外泄 err 原文)。
			s.renderInternalError(w, r, "user_new:gen_psk", err)
			return
		}
		hash, err := HashPSKForUser(psk)
		if err != nil {
			s.renderInternalError(w, r, "user_new:hash_psk", err)
			return
		}
		// 0013(2026-05-25):新建 user 同步分配 credential_id(UUID v4)+ credential_created_at,
		// 客户端首次扫 credentials show 拿到的 UUID 与本时刻对齐;PSK rotate 后保持 UUID 不变
		// 让 client 端可按 UUID 索引自动覆盖旧 PSK。
		credID := uuid.NewString()
		credNow := time.Now().UTC().Unix()
		u, err := s.store.CreateUser(r.Context(), store.NewUser{
			Username:            username,
			PSKHash:             hash,
			IsAdmin:             isAdmin,
			ExitAllowed:         exitAllowed,
			AllowedPlatforms:    allowedPlatforms,
			CredentialID:        credID,
			CredentialCreatedAt: credNow,
		})
		if err != nil {
			// 第八轮深扫 LOW:重名是可操作的用户级反馈 → 友好提示 + 保留表单;其余为内部错误 → 详情进日志、页面通用文案。
			if errors.Is(err, store.ErrDuplicate) {
				s.renderUserNew(w, r, nil, tr(r, "err.usernameTaken", username))
				return
			}
			s.renderInternalError(w, r, "user_new:create", err)
			return
		}
		// P2#3(2026-05-26):audit action 改成 underscore 风格,与 CLI `user_*` 对齐。
		// 0008:user_create audit 不再带 fixed_vip(creation 时还没设备)。
		s.audit.WriteFromRequest(r, "user_create", FormatTarget("user", u.ID),
			FormatDetail("username", u.Username, "is_admin", u.IsAdmin))

		// P1#2:不再直接 render。把 PSK + credentials QR stash 进一次性 flash,
		// 303 redirect 到 GET /users/{id}/created?token=...;后续刷新只 GET,不再
		// 重复 POST → 不会误建第二个 user。
		//
		// 2026-05-26 wire 扩展:host + server_id 一并写入 credentials QR。
		// 这两个 read 失败不阻断 user_create — 创建已经成功,QR 缺字段比"500 让 admin
		// 重试 user_create 误建第二个 user"代价低。fallback 到空字符串即可。
		advertisedHost, _ := s.store.GetAdvertisedHost(r.Context())
		serverID, _ := s.store.GetServerID(r.Context())
		credURL, credQR := buildCredentialsURLAndQR(u.CredentialID, u.Username, psk, u.CredentialCreatedAt, advertisedHost, serverID)
		token, err := s.credFlash.Stash(credentialsFlashPayload{
			Kind:        credentialsFlashKindUserCreated,
			UserID:      u.ID,
			Username:    u.Username,
			PSK:         psk,
			CredID:      u.CredentialID,
			CredCreated: fmtTime(u.CredentialCreatedAt),
			CredURL:     credURL,
			CredQRImage: credQR,
			Host:        advertisedHost,
			ServerID:    serverID,
		}, currentAdminID(r))
		if err != nil {
			// 第六轮深扫 P1#3:对称 reset-psk 的修法 — 不再 inline 渲染。
			// create 路径有 username unique 兜底(刷新二次 POST 必然失败),但用户已经
			// 创建在 DB 里,admin 看到「创建失败」会误以为没建,反复尝试更糟。改成
			// 500 + audit + 提示「用户已创建,可去重置 PSK 获取凭证」,语义清晰。
			logrus.WithError(err).Error("[web] stash credentials flash (create) 失败 - 拒绝 inline 渲染")
			s.audit.WriteFromRequest(r, "user_create_stash_failed",
				FormatTarget("user", u.ID),
				FormatDetail("username", u.Username, "err", err.Error()))
			_ = psk
			_ = credURL
			_ = credQR
			idStr := strconv.FormatInt(u.ID, 10)
			// 第八轮深扫 LOW:err 详情已于上方 logrus + audit 记录;页面不再回显原始错误串。
			s.renderError(w, r, http.StatusInternalServerError,
				tr(r, "users.createStashFailed", idStr, idStr))
			return
		}
		http.Redirect(w, r,
			"/users/"+strconv.FormatInt(u.ID, 10)+"/created?token="+token,
			http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// platformsFromForm:从复选框组收集平台白名单(2026-07-19,原为自由文本 CSV,
// 用户反馈复选框更直观且不会拼错)。r.Form["platforms"] 多值 join 后仍走
// NormalizePlatformCSV 兜底校验(防手工构造 POST 塞非法 token 把用户锁死)。
//
// 全部勾选折叠为 ""(= 不限):语义上「全平台」就是不限制,且未来新增平台 token 时
// 这类用户自动放行,不会被存死的旧全集 CSV 卡住。全不勾也是 ""(后端没有「全禁」
// 概念,要禁人请用 disable),模板 hint 里已注明。
func platformsFromForm(r *http.Request) (string, error) {
	_ = r.ParseForm() // FormValue 早已隐式调用过,这里显式一次确保 r.Form 就绪
	csv, err := store.NormalizePlatformCSV(strings.Join(r.Form["platforms"], ","))
	if err != nil {
		return "", err
	}
	if csv != "" && len(strings.Split(csv, ",")) == len(store.CanonicalPlatforms) {
		return "", nil
	}
	return csv, nil
}

// platformCheck:user_new / user_detail 模板复选框组的一行(平台名 + 当前是否勾选)。
type platformCheck struct {
	Name    string
	Checked bool
}

// platformChecksFor:按 canonical 顺序生成复选框状态。u == nil(新建表单)或
// 未设白名单 → 全勾(默认不限);否则按 AllowsPlatform 逐个判定。
func platformChecksFor(u *store.User) []platformCheck {
	out := make([]platformCheck, 0, len(store.CanonicalPlatforms))
	for _, p := range store.CanonicalPlatforms {
		out = append(out, platformCheck{Name: p, Checked: u == nil || u.AllowsPlatform(p)})
	}
	return out
}

func (s *Server) renderUserNew(w http.ResponseWriter, r *http.Request,
	form any, errMsg string) {
	var flash *Flash
	if errMsg != "" {
		flash = &Flash{Kind: "err", Text: errMsg}
	}
	// form 参数历史上始终为 nil(错误时不回填表单);Data 现在固定传复选框状态,
	// 新建默认全勾(= 不限)。
	_ = form
	s.renderPage(w, r, "user_new.html", PageData{
		Title: tr(r, "page.userNew.title"),
		Data:  map[string]any{"PlatformChecks": platformChecksFor(nil)},
		Flash: flash,
		Nav:   NavContext{Active: "users"},
	})
}

// handleUserAction:dispatch /users/{id} 与 /users/{id}/{verb}。
func (s *Server) handleUserAction(w http.ResponseWriter, r *http.Request) {
	segs := pathSegments(r.URL.Path) // [users, id, verb?]
	if len(segs) < 2 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.missingUserId"))
		return
	}
	id, err := strconv.ParseInt(segs[1], 10, 64)
	if err != nil || id <= 0 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.invalidUserId", segs[1]))
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, tr(r, "err.userNotFound"))
			return
		}
		// d_err_mask:内部查询错误详情进日志,页面回通用文案。
		s.renderInternalError(w, r, "users:get_user", err)
		return
	}

	if len(segs) == 2 { // /users/{id} 详情
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		devs, _ := s.store.ListDevicesByUser(r.Context(), id)
		// 0013(2026-05-25):凭证元信息(UUID + 上次 rotate 时间)在用户详情上展示;
		// 由于 PSK hash 不可反解,这里**不**渲染 credentials QR —— admin 想下发新 QR
		// 必须走「重置 PSK」,在 user_psk_reset.html 一次性展示。这是「PSK 唯一一次明文
		// 出现机会」原则的延伸。
		s.renderPage(w, r, "user_detail.html", PageData{
			Title: tr(r, "page.userDetail.title", u.Username),
			Flash: flashFromQuery(r), // 第九轮 P2:disable/enable/delete POST redirect 回 detail 时显示横幅;mesh toggle 落 detail 时同样消费
			Data: map[string]any{
				"User":           u,
				"Devices":        devs,
				"CredCreated":    fmtTime(u.CredentialCreatedAt),
				"PlatformChecks": platformChecksFor(u),
			},
			Nav: NavContext{Active: "users"},
		})
		return
	}

	verb := segs[2]

	// P1#2:GET 路径(一次性展示页)在 CSRF / requireAdminRole 校验之前 dispatch,
	// 因为它们用 token 而不是 form 触发,无 side effect。CSRF middleware 已经
	// 把 GET 短路了(VerifyCSRFToken 第一行),requireAdminRole 仍要保留 — viewer
	// 不该看到 PSK,但「已登录」这一层 already 由 routes.requireCSRFAndAuth 提供。
	if r.Method == http.MethodGet {
		switch verb {
		case "created":
			if !s.requireAdminRole(w, r) {
				return
			}
			s.handleUserCreatedFlash(w, r, u)
			return
		case "reset-psk-result":
			if !s.requireAdminRole(w, r) {
				return
			}
			s.handleUserResetPSKResultFlash(w, r, u)
			return
		default:
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	switch verb {
	case "disable":
		if err := s.store.DisableUser(r.Context(), id); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.userNotFound", "err.disableFailed")
			return
		}
		s.audit.WriteFromRequest(r, "user_disable", FormatTarget("user", id),
			FormatDetail("username", u.Username))
		// 第十轮深扫 P2:disable/enable/set-platforms 此前裸 redirect 不带 flash,
		// detail 页的 flashFromQuery 永远读不到横幅 —— 与 delete/reset-psk/kick
		// 的反馈口径不一致(detail 渲染处注释一直声称有横幅)。补上。
		flashRedirect(w, r, "/users/"+segs[1], tr(r, "flash.userDisabled", u.Username), "")
	case "enable":
		if err := s.store.EnableUser(r.Context(), id); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.userNotFound", "err.enableFailed")
			return
		}
		s.audit.WriteFromRequest(r, "user_enable", FormatTarget("user", id),
			FormatDetail("username", u.Username))
		flashRedirect(w, r, "/users/"+segs[1], tr(r, "flash.userEnabled", u.Username), "")
	case "delete":
		if err := s.store.DeleteUser(r.Context(), id); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.userNotFound", "err.deleteFailed")
			return
		}
		s.audit.WriteFromRequest(r, "user_delete", FormatTarget("user", id),
			FormatDetail("username", u.Username))
		// u.Username 是 admin 录入字符串;flashRedirect 内部 QueryEscape + 附签名(第三轮 L5)。
		flashRedirect(w, r, "/users", tr(r, "flash.userDeleted", u.Username), "")
	case "reset-psk":
		// P2#6(2026-05-26):disabled user 不允许 rotate-psk —— 「让账号被踢线但
		// 同时下发新凭证」语义矛盾(rotate 后的 user_invalidate scan 还是会把这条踢
		// 掉,新 PSK 等于发了张废卡;且 admin 无意中放了一个「禁用但仍带新凭证」的
		// 用户,正常运维流程会忘了清理)。先 enable 才能 rotate。
		if u.DisabledAt != 0 {
			s.renderError(w, r, http.StatusConflict,
				tr(r, "users.pskResetUserDisabled", segs[1]))
			return
		}
		psk, err := util.GeneratePSK()
		if err != nil {
			s.renderInternalError(w, r, "users:reset_gen_psk", err)
			return
		}
		hash, err := HashPSKForUser(psk)
		if err != nil {
			s.renderInternalError(w, r, "users:reset_hash_psk", err)
			return
		}
		// P1#3(2026-05-26):走 store 共享 helper,与 CLI 完全一致 —— 内部刷
		// psk_hash + credential_created_at,若 user 是老 row 顺手 backfill UUID v4。
		// 失败显式 500(不再「悄悄返回空 QR」),并写一条 audit;client 看到 error
		// 不会扫到不完整凭证。
		priorCredID := u.CredentialID
		newCredID, _, err := s.store.RotateUserPSKAndEnsureCredential(r.Context(), u, hash)
		if err != nil {
			// 第七轮深扫 P1:`ErrPSKConcurrentRotation` 是 CAS 失败 sentinel —— 别让
			// admin 看到 "store: PSK rotation lost CAS race (snapshot stale)" 这种
			// 实现层文案。改成 409 Conflict + 中文提示「另一管理员已先一步重置,请
			// 刷新页面」;audit action 区分开,运维能用 user_reset_psk_raced 单独
			// 监控并发冲突频率(贴近场景,不混到 user_reset_psk_failed 的通用桶里)。
			if errors.Is(err, store.ErrPSKConcurrentRotation) {
				// 第九轮 P2:detail 统一为 `username=X reason=... via=Y`,via 标识入口
				// (web_reset_psk 区分于 CLI user_reset_psk / credentials_show)。
				s.audit.WriteFromRequest(r, "user_reset_psk_raced",
					FormatTarget("user", id),
					FormatDetail("username", u.Username,
						"reason", "concurrent_rotation_by_peer_admin",
						"via", "web_reset_psk"))
				s.renderError(w, r, http.StatusConflict,
					tr(r, "users.pskResetRaced"))
				return
			}
			s.audit.WriteFromRequest(r, "user_reset_psk_failed",
				FormatTarget("user", id),
				FormatDetail("username", u.Username, "err", err.Error()))
			s.renderInternalError(w, r, "users:rotate_psk", err)
			return
		}
		_ = newCredID

		// 重读用户拿权威 credential_id / credential_created_at;之前的 `u` 在 RotateUserPSK
		// 之后已过期。下面的 credentials URL / QR 渲染必须用最新值,否则客户端扫码会
		// 拿到旧 UUID(老 user 首次 rotate 时)。
		freshU, err := s.store.GetUser(r.Context(), id)
		if err != nil {
			s.renderInternalError(w, r, "users:reread_after_rotate", err)
			return
		}
		// audit:不带明文 PSK / URL;detail = username + credential_id,与 admin CLI
		// 的 "user_reset_psk" / "credentials_rotate_psk" 保留同等追溯字段。
		detail := "username=" + freshU.Username + " credential_id=" + freshU.CredentialID
		if priorCredID == "" {
			detail += " backfilled credential_id=" + freshU.CredentialID
		}
		s.audit.WriteFromRequest(r, "user_reset_psk", FormatTarget("user", id), detail)

		// 2026-05-26 wire 扩展:host + server_id 写入 credentials QR(同 user_create 路径)。
		// read 失败 fallback 到空,不阻断 reset-psk(PSK 已成功 rotate,不能让 QR 渲染失败掀翻流程)。
		advertisedHost, _ := s.store.GetAdvertisedHost(r.Context())
		serverID, _ := s.store.GetServerID(r.Context())
		credURL, credQR := buildCredentialsURLAndQR(freshU.CredentialID, freshU.Username, psk, freshU.CredentialCreatedAt, advertisedHost, serverID)
		token, err := s.credFlash.Stash(credentialsFlashPayload{
			Kind:        credentialsFlashKindUserResetPSK,
			UserID:      freshU.ID,
			Username:    freshU.Username,
			PSK:         psk,
			CredID:      freshU.CredentialID,
			CredCreated: fmtTime(freshU.CredentialCreatedAt),
			CredURL:     credURL,
			CredQRImage: credQR,
			Host:        advertisedHost,
			ServerID:    serverID,
		}, currentAdminID(r))
		if err != nil {
			// 第六轮深扫 P1#3:此前在 Stash 失败时直接 `s.renderUserResetPSK(...)`
			// 把 PSK 渲染在当前 POST 响应里 —— 浏览器刷新会**重复 POST 同一表单**,
			// 重新 rotate 出第三把 PSK,用户刚抄的那把瞬间失效。这条 race 在 reset-psk
			// 路径下后果最严重(create 路径有 username unique 约束兜底),所以本轮
			// 改成 500 + audit + 不渲染 PSK:admin 看到错误页会去 reset-psk-result
			// 或重新发起,不会拿一张「随时被刷新作废」的 QR 给用户。crypto/rand 故障
			// 极罕见(<<1e-9),走 500 比走「看起来正常但实际危险」的退化路径更可解释。
			logrus.WithError(err).Error("[web] stash credentials flash (reset-psk) 失败 - 拒绝 inline 渲染")
			s.audit.WriteFromRequest(r, "user_reset_psk_stash_failed",
				FormatTarget("user", id),
				FormatDetail("username", freshU.Username, "err", err.Error()))
			_ = psk
			_ = credURL
			_ = credQR
			// 第八轮深扫 LOW:err 详情已于上方 logrus + audit 记录;页面不再回显原始错误串。
			s.renderError(w, r, http.StatusInternalServerError,
				tr(r, "users.resetStashFailed"))
			return
		}
		http.Redirect(w, r,
			"/users/"+segs[1]+"/reset-psk-result?token="+token,
			http.StatusSeeOther)
	case "set-platforms":
		// 平台白名单(2026-07-18):空 = 不限。改后自动生效:user_invalidate 周期扫描
		// (默认 10s)会 close(910) 掉不合规在线会话,新登录即时拦截(与 CLI
		// set-platforms 同口径)。2026-07-19 改复选框多值收集,全选/全不选 = 不限。
		csv, err := platformsFromForm(r)
		if err != nil {
			// 第十二轮深扫 LOW:同 create 路径,回本地化通用校验文案,不泄漏 store 层错误串。
			logrus.WithError(err).Warn("[users] platformsFromForm(set-platforms) rejected")
			s.renderError(w, r, http.StatusBadRequest, tr(r, "form.invalidPlatforms"))
			return
		}
		if err := s.store.SetUserAllowedPlatforms(r.Context(), id, csv); err != nil {
			s.renderStoreWriteErr(w, r, err, "err.userNotFound", "err.saveFailed")
			return
		}
		s.audit.WriteFromRequest(r, "user_platforms_set", FormatTarget("user", id),
			FormatDetail("username", u.Username, "allowed_platforms", csv))
		platformsFlash := tr(r, "flash.userPlatformsSet", csv)
		if csv == "" {
			platformsFlash = tr(r, "flash.userPlatformsCleared")
		}
		flashRedirect(w, r, "/users/"+segs[1], platformsFlash, "")
	case "set-max-sessions":
		// 0021:按账号并发会话上限。0=跟随全局;>0=覆盖;-1=该账号不限。
		// 仅对未来登录生效(登录时定格),现役会话不回踢 —— 与 CLI / 全局热更同口径。
		raw := strings.TrimSpace(r.FormValue("max_sessions"))
		n, err := strconv.Atoi(raw)
		if err != nil || n < -1 || n > store.MaxSessionsCap {
			s.renderError(w, r, http.StatusBadRequest, tr(r, "err.badMaxSessions"))
			return
		}
		if err := s.store.SetUserMaxSessions(r.Context(), id, n); err != nil {
			if errors.Is(err, store.ErrInvalid) {
				s.renderError(w, r, http.StatusBadRequest, tr(r, "err.badMaxSessions"))
				return
			}
			s.renderStoreWriteErr(w, r, err, "err.userNotFound", "err.saveFailed")
			return
		}
		s.audit.WriteFromRequest(r, "user_max_sessions_set", FormatTarget("user", id),
			FormatDetail("username", u.Username, "max_sessions", strconv.Itoa(n)))
		flashRedirect(w, r, "/users/"+segs[1], tr(r, "flash.userMaxSessionsSet", n), "")
	// 0008(2026-05-23):user.set-fixed-vip 已移到 device 维度。
	// 老前端表单 POST 到这里会给一个清晰提示,而不是悄悄 404 / 改成 noop。
	case "set-fixed-vip":
		http.Error(w, tr(r, "httpErr.userFixedVipGone"), http.StatusGone)
	default:
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.unknownActionVerb", verb))
	}
}

// handleUserCreatedFlash 处理 GET /users/{id}/created?token=... — 一次性消费
// flash store 里 user create 留下的 PSK + credentials QR payload。
//
// token 缺失 / 已过期 / 已被消费 / 用户 id mismatch → 410 Gone 提示「页面已过期」,
// admin 知道这是预期行为(每次刷新都看到 PSK 反而是 bug)。
func (s *Server) handleUserCreatedFlash(w http.ResponseWriter, r *http.Request, u *store.User) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	payload, err := s.credFlash.Pop(token, credentialsFlashKindUserCreated, currentAdminID(r))
	if err != nil {
		s.renderError(w, r, http.StatusGone,
			tr(r, "users.credExpiredCreate"))
		return
	}
	if payload.UserID != u.ID {
		// token 与 URL user 不匹配 — 可能 admin 把别人的 created token 拼到本 URL,
		// 或浏览器 history 错位。直接当过期处理。
		//
		// 注意顺序(第四轮 P2-b,保留):Pop 已在上面消费掉 token,故此处不泄漏 PSK,且一个 token 只能
		// 被「试」一次 —— 持有 token 但不知归属 {id} 的攻击者无法反复枚举 URL 上的 {id}。这是刻意的
		// 安全不变式(有回归测试 TestHandleUserCreatedFlash_UserIDMismatch 锁定),不要改成「先校验后
		// Pop」:那样 mismatch 不消费 token,反而打开枚举面。
		s.renderError(w, r, http.StatusGone,
			tr(r, "users.credExpiredCreate"))
		return
	}
	s.renderUserCreated(w, r, payload)
}

// handleUserResetPSKResultFlash 处理 GET /users/{id}/reset-psk-result?token=...。
// 与 created 类似,但 kind = credentialsFlashKindUserResetPSK,模板用 user_psk_reset.html。
func (s *Server) handleUserResetPSKResultFlash(w http.ResponseWriter, r *http.Request, u *store.User) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	payload, err := s.credFlash.Pop(token, credentialsFlashKindUserResetPSK, currentAdminID(r))
	if err != nil {
		s.renderError(w, r, http.StatusGone,
			tr(r, "users.credExpiredReset"))
		return
	}
	if payload.UserID != u.ID {
		// 见 handleUserCreatedFlash:Pop 先于 UserID 校验是刻意的安全不变式(消费即防枚举),勿改序。
		s.renderError(w, r, http.StatusGone,
			tr(r, "users.credExpiredShort"))
		return
	}
	s.renderUserResetPSK(w, r, payload)
}

// renderUserCreated / renderUserResetPSK 共用 PageData 构造,保持模板字段命名稳定。
func (s *Server) renderUserCreated(w http.ResponseWriter, r *http.Request, p credentialsFlashPayload) {
	s.renderPage(w, r, "user_created.html", PageData{
		Title: tr(r, "page.userCreated.title"),
		Data: map[string]any{
			"User": map[string]any{
				"ID":           p.UserID,
				"Username":     p.Username,
				"CredentialID": p.CredID,
			},
			"PSK":         p.PSK,
			"CredURL":     p.CredURL,
			"CredQRImage": p.CredQRImage,
			"CredCreated": p.CredCreated,
			// 2026-05-26:模板显示「对应服务器:<Host>」。空串时模板会展示「未指定 —
			// 请到 /settings 设置 advertised_host」,防止 admin 把这种 QR 误以为「不知道
			// 是哪台机器的」直接发给用户。
			"Host": p.Host,
		},
		Nav: NavContext{Active: "users"},
	})
}

func (s *Server) renderUserResetPSK(w http.ResponseWriter, r *http.Request, p credentialsFlashPayload) {
	s.renderPage(w, r, "user_psk_reset.html", PageData{
		Title: tr(r, "page.userPskReset.title"),
		Data: map[string]any{
			"User": map[string]any{
				"ID":           p.UserID,
				"Username":     p.Username,
				"CredentialID": p.CredID,
			},
			"PSK":         p.PSK,
			"CredURL":     p.CredURL,
			"CredQRImage": p.CredQRImage,
			"CredCreated": p.CredCreated,
			"Host":        p.Host,
		},
		Nav: NavContext{Active: "users"},
	})
}

// requireAdminRole 在写操作前确认当前 admin 是 admin 角色;viewer 拒绝。
func (s *Server) requireAdminRole(w http.ResponseWriter, r *http.Request) bool {
	admin := adminFromCtx(r.Context())
	if admin == nil {
		http.Error(w, tr(r, "httpErr.notLoggedIn"), http.StatusUnauthorized)
		return false
	}
	if admin.Role != "admin" {
		http.Error(w, tr(r, "httpErr.viewerForbidden"), http.StatusForbidden)
		return false
	}
	return true
}

// HashPSKForUser:nanotun 数据面 PSK 走 auth.HashPSK,这里转一层是为了让
// 未来若想换算法时只改一处。
func HashPSKForUser(plain string) (string, error) {
	return HashWebPassword(plain) // 同一 argon2id 参数,逻辑一致。
}

// credentialsQRPixels:PNG 边长(像素)。256 与 admin CLI 默认值对齐,Medium 纠错
// 级别下手机摄像头能稳定扫到;更大会让 dataURL base64 体积涨到几 KB,模板渲染慢。
const credentialsQRPixels = 256

// buildCredentialsURLAndQR 把 (credential_id, username, psk, created_at, host, server_id)
// 编成 `nanotun-cred://v1?d=<base64url(json)>` 并渲染 256x256 PNG 二维码,
// 包成 `data:image/png;base64,...` 可直接塞 <img src=...>。
//
// 返回 (url, qrDataURL):
//   - url           = 明文 nanotun-cred:// 字符串,供模板展示「完整 URL」给用户手抄;
//   - qrDataURL     = html/template.URL 类型(显式 trusted),`<img src>` 不会被
//     默认 URL 白名单(http/https/mailto/...)拦成 #ZgotmplZ。
//
// 失败路径(credential_id 为空 / qrcode.Encode error)返回 ("", "") + warn 日志 —
// 让模板能 fall-through 到「凭证未生成」分支(用户老 row 在没 rotate 过的情况下),
// 而不是 500。caller 该分支已经把 PSK 重置成功了,不能让二维码渲染失败掀翻整个流程。
//
// 0013(2026-05-25)新增。与 nanotun-admin/cmd_credentials.go 用同一份 util 包,
// **字节级**一致(两边都跑 Rust 客户端单测,跨语言对齐)。
//
// 2026-05-26 扩展:host + serverID 作为元数据嵌入 wire,client 端 list / picker /
// main view 凭这两个字段区分跨服务器场景。caller 从 store 读 advertised_host / server_id
// 后传入,允许空字符串(server 未配 advertised_host 时 host 为 "")。
func buildCredentialsURLAndQR(credentialID, username, psk string, createdAt int64, host, serverID string) (string, template.URL) {
	if strings.TrimSpace(credentialID) == "" || strings.TrimSpace(psk) == "" {
		return "", ""
	}
	url, err := util.EncodeCredentialsURL(&util.CredentialsSchema{
		Version:   util.CredentialsSchemaVersion,
		ID:        credentialID,
		Username:  username,
		PSK:       psk,
		CreatedAt: createdAt,
		Host:      host,
		ServerID:  serverID,
	})
	if err != nil {
		logrus.WithError(err).Warn("[web] encode credentials url failed; fall back to empty QR")
		return "", ""
	}
	png, err := qrcode.Encode(url, qrcode.Medium, credentialsQRPixels)
	if err != nil {
		logrus.WithError(err).Warn("[web] render credentials QR PNG failed; fall back to URL only")
		return url, ""
	}
	dataURL := template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
	return url, dataURL
}

// 提示:context 这里没用,但导入留着以便后续扩展(audit ctx 等)。
var _ = context.Background
