package main

// handler_server_qr.go — 服务器配置 QR 显示页(2026-05-26 引入)。
//
// 设计目标:让 admin 在 web 后台直接拿到 `nanotun://v2` 服务器 profile QR,无需
// 登 SSH 跑 CLI。但 server profile QR 即使不含 PSK,仍含 REALITY public_key /
// hy2 auth password / hy2 mTLS 客户端证书等敏感字段 —— 泄露后第一层网关层
// 就被绕过(攻击者仍需 PSK 才能完成 nanotun 登录,但 hy2 协议层已经能 reach
// 数据面服务,可被用于扫描 / DDoS / probing)。
//
// 因此即便 admin 已经过密码 + TOTP 登录,显示 QR 仍要求 step-up:再次输入
// 当前 admin 密码,与 GitHub 「sudo mode」/ Stripe API key 显示同款模式。
//
// 安全姿态(用户决策见 commit message 第十一轮记录):
//   • QR 内容:仅服务器 profile(`nanotun://v2`),credentials 走 user 详情页;
//   • Step-up 窗口:单次显示 —— 关闭 / 刷新页面就要重新输密码;
//   • host 来源(2026-05-26 第六轮拆字段后):
//       - dial target = `app_settings.server_dial_host`(`/settings/server-dial-host`
//         配置,strict IPv4/IPv6/RFC1035 hostname,**QR 阻断键**);
//       - display label = `app_settings.advertised_host`(`/settings/advertised-host`
//         配置,可选,客户端 UI 副标题用);
//       原 `public_host` key 已在 migration 0015 改名为 advertised_host,migration
//       0016 引入 server_dial_host 但**不 auto-backfill**(force admin 显式配 dial)。
//   • 锁定:IP 级 5 min cooldown(失败 5 次锁 IP,与主登录隔离);
//   • Audit:全审计(成功 + 失败都入,sibling action 命名)。

import (
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/nanotun/server/store"
)

// 三个 step-up 路径用到的常量。
//
// stepUpMaxFailures:5 次错误就锁 IP。比主登录(cfg.MaxLoginFailures 也是 5)
// 严格不到哪里去,但语义对齐 — admin 主动展示敏感数据,跟登录同等级保护。
//
// 注意:IPFailureTracker 的窗口是 ipFailureWindowSec = 5min(写死在
// ip_failures.go),5 次失败后 Recent(ip) >= 5,handler 检测并拒绝。
const (
	stepUpMaxFailures = 5
)

// handleServerQR 是 GET /server-qr 的密码输入页面。
//
// 已登录用户访问,显示一个 password input 表单 + 警告说明。
// 渲染前检查:
//  1. admin 角色(viewer 不能看);
//  2. server_dial_host 是否已配置(空则提示去 /settings;2026-05-26 第六轮拆字段
//     后阻断键从 advertised_host 切到 dial);advertised_host 始终可选;
//  3. IP 是否在 cooldown(显示「请稍后再试」)。
//
// 用户提交后到 POST /server-qr/reveal,见 handleServerQRReveal。
func (s *Server) handleServerQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	ctx := r.Context()
	// 2026-05-26 第六轮拆字段:GET 入口的"前置 readiness 检查"按 dial host 走
	// (那才是阻断 QR 生成的关键 setting),advertised_host 是可选 label,缺失
	// 不阻塞。模板继续接收两个字段同时展示给 admin 让人一眼分清。
	dialHost, _ := s.store.GetServerDialHost(ctx)
	advertisedHost, _ := s.store.GetAdvertisedHost(ctx)
	ip := clientIP(r)
	locked := s.stepUpFailures.Recent(ip) >= stepUpMaxFailures

	s.renderPage(w, r, "server_qr_password.html", PageData{
		Title: tr(r, "page.serverQrPassword.title"),
		Flash: flashFromQuery(r),
		Data: map[string]any{
			"DialHost":          dialHost,
			"HasDialHost":       dialHost != "",
			"AdvertisedHost":    advertisedHost,
			"HasAdvertisedHost": advertisedHost != "",
			"Locked":            locked,
			"ErrorMsg":          r.URL.Query().Get("err"),
		},
		Nav: NavContext{Active: "dashboard"},
	})
}

// handleServerQRReveal 是 POST /server-qr/reveal — step-up 核心。
//
// 流程:
//  1. CSRF 已由 requireCSRFAndAuth 验证(authed dispatch 在 routes.go);
//  2. admin role 检查(viewer 直接 403);
//  3. IP cooldown 检查 —— 已锁则 audit `server_profile_qr_locked` + 拒;
//  4. server_dial_host 检查 —— 空则 audit `server_profile_qr_no_dial_host` + 拒
//     (2026-05-26 第六轮拆字段:阻断键从 advertised_host 切到 server_dial_host);
//  5. VerifyWebPassword(form.password, admin.PasswordHash):
//     失败 → stepUpFailures.Inc(ip) + audit `server_profile_qr_password_fail`;
//     失败次数恰好触发锁定时,返回页面提示「已锁定 5 分钟」;
//  6. fork `nanotun-admin profile show --dial-host <server_dial_host>
//     [--advertised-host <advertised_host>] --format url`,timeout 20s,捕获
//     stdout(server-level 模式,无位置参 — 见 buildServerProfileQRAndURL 注释
//     P1 修复;第六轮拆字段后 --host 已 deprecated,改为 --dial-host 主 +
//     --advertised-host 可选);
//  7. web 进程内 qrcode.Encode(url, Medium→Low) 自渲 PNG → base64 → inline
//     `server_qr_revealed.html`,同页同时展示 URL 文本(扫码失败兜底,折叠);
//  8. audit `server_profile_qr_show` + audit detail 含 dial_host + advertised_host
//     (不含 PSK / public_key 等敏感字段,只记「这次 admin 看了 QR」)。
//
// 成功后只渲染一次。用户刷新 / 关闭 → 下次访问回到 GET /server-qr,要再次输密码。
func (s *Server) handleServerQRReveal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	ctx := r.Context()
	admin := adminFromCtx(ctx)
	if admin == nil {
		// requireAdminRole 已经拒了未登录,这里 defensive。
		http.Error(w, tr(r, "httpErr.notLoggedIn"), http.StatusUnauthorized)
		return
	}
	ip := clientIP(r)

	// (3) IP cooldown
	if s.stepUpFailures.Recent(ip) >= stepUpMaxFailures {
		s.audit.WriteFromRequest(r, "server_profile_qr_locked",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("username", admin.Username, "reason", "ip_cooldown"))
		s.renderServerQRPasswordPage(w, r, tr(r, "serverQr.tooManyFailures"),
			http.StatusTooManyRequests)
		return
	}

	// (4) server_dial_host 必填(2026-05-26 第六轮拆字段)。
	//
	// 这是客户端 PacketTunnel `tunnelRemoteAddress` 实际拨号目标 —— 老 advertised_host
	// 现在只是展示 label,**不能**当 dial 使用(踩坑现场:用户配 `test-203.0.113.10`
	// 当 label 但被旧路径塞进客户端 dial,iOS NEVPN 拒掉)。本字段空 = server 对外
	// 不可用,拒绝生成 QR + 引导 admin 去 /settings 显式声明。
	//
	// 同时读 advertised_host(纯展示 label,可选),后面一起塞进 profile JSON
	// 的 `advertised_host` 字段;空 = profile omitempty,client UI fallback 展示
	// dial host。
	dialHost, err := s.store.GetServerDialHost(ctx)
	if err != nil {
		s.renderInternalError(w, r, "server_qr:read_dial_host", err)
		return
	}
	if dialHost == "" {
		s.audit.WriteFromRequest(r, "server_profile_qr_no_dial_host",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("username", admin.Username, "reason", "server_dial_host_unset"))
		s.renderServerQRPasswordPage(w, r,
			tr(r, "serverQr.dialHostUnset"),
			http.StatusPreconditionFailed)
		return
	}
	// advertised_host 可选 label,读失败也只 log warn 不阻断 QR 生成
	// (label 缺失客户端会 fallback 展示 dial host)。
	advertisedHost, ahErr := s.store.GetAdvertisedHost(ctx)
	if ahErr != nil {
		logrus.WithError(ahErr).Warn("[server-qr] 读 advertised_host 失败,QR 将不带 label")
		advertisedHost = ""
	}

	// (5) 密码验证
	password := r.FormValue("password")
	if password == "" {
		// 空密码不计入失败计数(还没尝试,避免误操作锁自己)。
		s.renderServerQRPasswordPage(w, r, tr(r, "serverQr.passwordRequired"), http.StatusBadRequest)
		return
	}
	ok, verr := VerifyWebPassword(r.Context(), password, admin.PasswordHash)
	if verr != nil || !ok {
		newCount := s.stepUpFailures.Inc(ip)
		reason := "wrong_password"
		if verr != nil {
			// hash 解析失败属罕见 path,但不应改 reason 让 attacker 区分。
			// log warn 让运维知道,audit detail 用统一 reason。
			logrus.WithError(verr).Warn("[server-qr] VerifyWebPassword 解析失败")
		}
		s.audit.WriteFromRequest(r, "server_profile_qr_password_fail",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("username", admin.Username, "reason", reason, "fail_count", newCount))
		msg := tr(r, "serverQr.passwordWrong")
		status := http.StatusUnauthorized
		if newCount >= stepUpMaxFailures {
			msg = tr(r, "serverQr.passwordWrongLocked")
			status = http.StatusTooManyRequests
		}
		s.renderServerQRPasswordPage(w, r, msg, status)
		return
	}

	// (5b) 第七轮深扫 HIGH:密码通过后,若该 admin 已开启 TOTP,则强制第二因子。
	//
	// 背景:server profile QR 含 REALITY public_key / hy2 auth / hy2 mTLS 客户端证书,
	// 泄露后第一层网关就被绕过。此前 step-up 只验密码 —— 一旦会话 cookie 被劫持 + 密码
	// 泄露(钓鱼 / 复用),攻击者无需持有 TOTP 设备即可 reveal,使 admin 已开的 2FA 在
	// 这条敏感路径上形同虚设。对齐 handler_me 的 disable/regen step-up:密码正确后再验一次
	// **当前 6 位 TOTP 码**。刻意不接受恢复码 —— reveal 是可重复的只读操作,不该消耗珍贵的
	// 一次性恢复码;丢了 TOTP 设备的 admin 应先去 /me 重建 2FA 再来。用 VerifyTOTP 非消费式
	// 校验(与 regen 一致),避免烧掉登录用的 TOTP step 形成自锁式 UX;失败与错误密码同权
	// 计入 IP 冷却配额。admin.TOTPEnabled / TOTPSecret 取自 middleware 请求初的快照(经
	// GetWebAdmin 全列 scan 填充),对这条一次性 step-up 足够新。
	if admin.TOTPEnabled {
		code := strings.TrimSpace(r.FormValue("code"))
		if code == "" {
			// 空码不计失败配额(与空密码一致,避免误提交自锁),回渲提示补填。
			s.renderServerQRPasswordPage(w, r, tr(r, "serverQr.totpRequired"), http.StatusBadRequest)
			return
		}
		if terr := VerifyTOTP(admin.TOTPSecret, code); terr != nil {
			newCount := s.stepUpFailures.Inc(ip)
			s.audit.WriteFromRequest(r, "server_profile_qr_totp_fail",
				FormatTarget("web_admin", admin.ID),
				FormatDetail("username", admin.Username, "reason", "wrong_totp", "fail_count", newCount))
			msg := tr(r, "serverQr.totpWrong")
			status := http.StatusUnauthorized
			if newCount >= stepUpMaxFailures {
				msg = tr(r, "serverQr.totpWrongLocked")
				status = http.StatusTooManyRequests
			}
			s.renderServerQRPasswordPage(w, r, msg, status)
			return
		}
	}

	// step-up 全部因子(密码 + 若启用则 TOTP)验证成功 → 清零本 IP 的失败计数,与登录 /
	// handler_me(disable/regen TOTP)成功即 Reset 一致。否则「几次手误 + 一次成功」的失败
	// 计数会一直累加,穿插几次误操作即可把自己推到 stepUpMaxFailures 冷却阈值(且连累同样用
	// step-up 的 TOTP disable/regen),形成管理员自锁。
	s.stepUpFailures.Reset(ip)

	// (6) fork nanotun-admin profile show
	//
	// 2026-05-26·server_id 链路第五轮 P1 修复:不再传 admin.Username 作为
	// `<username>` 位置参 — 原依赖「web admin 名 == 某 VPN user 名」的巧合(本部署
	// 凑巧成立,其它部署会因 GetUserByUsername 找不到行而 fail)。改走 CLI 的
	// server-level 模式(`profile show` 无位置参):无 user lookup,Hy2 mTLS 证书
	// CN 用合成占位符 "vpnport-server-profile-<rand>"。Hy2 mTLS 鉴权只验签 CA 链
	// 不验 CN,功能上完全等价。
	//
	// 第六轮 P0 follow-up(2026-05-26):buildServerProfileQRAndURL 一次 fork 拿
	// URL 文本,PNG 在 web 进程内由 go-qrcode 自渲。避免「同一次显示里 PNG 和
	// 文本 URL 含不同 cert」的不一致(每次 CLI invocation 都重新签 Hy2 mTLS 客
	// 户端证书,二次 fork 会撞)。也顺便让页面能展示 URL 文本作为扫码失败兜底。
	urlText, png, fork_err := s.buildServerProfileQRAndURL(ctx, dialHost, advertisedHost)
	if fork_err != nil {
		s.audit.WriteFromRequest(r, "server_profile_qr_failed",
			FormatTarget("web_admin", admin.ID),
			FormatDetail("username", admin.Username,
				"dial_host", dialHost, "advertised_host", advertisedHost,
				"reason", "build_failed", "err", fork_err.Error()))
		s.renderError(w, r, http.StatusInternalServerError,
			tr(r, "err.genServerQrFailed")+trErr(r, fork_err))
		return
	}

	// (7) 渲染成功页:inline PNG 作为 data: URL。
	// template.URL 显式信任 — 内容是本进程刚生成的 PNG,无注入风险。
	dataURL := template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))

	// (8) audit 成功 — 不写 hy2 password / reality public_key / 客户端证书 PEM,只记
	// 「看了 QR」+ host + 用户名。host 是 public 数据,但写进 audit 方便事后审计
	// 「这条 QR 链路上的 host 与本次配置一致」。
	s.audit.WriteFromRequest(r, "server_profile_qr_show",
		FormatTarget("web_admin", admin.ID),
		FormatDetail("username", admin.Username,
			"dial_host", dialHost, "advertised_host", advertisedHost))

	// 第十三轮(2026-05-27):server_id 也带给模板展示给 admin。
	// reveal 页面是 admin 看到「即将分发的 QR 内容」的最权威视角,server_id 嵌在
	// QR(nanotun://v2 wire format)里,这里同步展示让 admin 灾备时有据可查。
	serverID, _ := s.store.GetServerID(ctx)

	s.renderPage(w, r, "server_qr_revealed.html", PageData{
		Title: tr(r, "page.serverQrRevealed.title"),
		Data: map[string]any{
			// dial host(真实拨号目标)+ advertised label(展示名) — 模板两个都展示。
			"DialHost":       dialHost,
			"AdvertisedHost": advertisedHost,
			"ServerID":       serverID,
			"QRDataURL":      dataURL,
			// URLText 是 nanotun://v1?d=... 形式,~2.5KB 文本。模板里放
			// <details> 折叠 + <textarea readonly> 展示 + 复制按钮,作为扫码
			// 失败时的兜底。Go html/template 默认对 string 字段做 HTML 转义,
			// 这里 URL 只含 base64url 字符 + 协议头 + `?d=`,无注入风险,但仍
			// 走转义流程(textarea 内文本会被 HTML-escape 是预期行为)。
			"URLText": urlText,
		},
		Nav: NavContext{Active: "dashboard"},
	})
}

// renderServerQRPasswordPage 是失败 / 重试场景下的统一渲染:
// 重渲 server_qr_password.html 含错误提示 + 当前 cooldown 状态。
//
// 注:不走 PRG redirect — step-up 是「在原页面 stay + 给提示」的 UX,
// 跟主登录失败一致,POST 失败重渲 401 + 同页面。
func (s *Server) renderServerQRPasswordPage(w http.ResponseWriter, r *http.Request,
	errMsg string, status int) {

	ctx := r.Context()
	dialHost, _ := s.store.GetServerDialHost(ctx)
	advertisedHost, _ := s.store.GetAdvertisedHost(ctx)
	ip := clientIP(r)
	locked := s.stepUpFailures.Recent(ip) >= stepUpMaxFailures

	w.WriteHeader(status)
	s.renderPage(w, r, "server_qr_password.html", PageData{
		Title: tr(r, "page.serverQrPassword.title"),
		Data: map[string]any{
			"DialHost":          dialHost,
			"HasDialHost":       dialHost != "",
			"AdvertisedHost":    advertisedHost,
			"HasAdvertisedHost": advertisedHost != "",
			"Locked":            locked,
			"ErrorMsg":          errMsg,
		},
		Nav: NavContext{Active: "dashboard"},
	})
}

// serverQRPixels 是本 handler 自渲 PNG 的边长(像素)。
//
// 与 nanotun-admin/cmd_profile_qr.go::defaultQRPNGPixels 保持一致(1024):
// server profile URL 含 Hy2 mTLS 客户端证书 + 私钥 PEM,~2.5 KB,QR 进 v40-L
// (177×177 modules),1024/177 ≈ 5.78 px/module,远高于 zxing / iOS Vision 推荐
// 的 ≥4 px/module 阈值;配合 server_qr_revealed.html 的 width="512" CSS,Retina
// HDPI 屏 1:1 显示,普通屏 2:1 downscale 渲染干净。
const serverQRPixels = 1024

// buildServerProfileQRAndURL 调用 nanotun-admin profile show 拿到 URL 文本,
// 然后在本进程内用 go-qrcode 渲染 PNG。
//
// 一次 fork 拿两份产物的原因(第六轮 P0 follow-up):
//
//	历史实现只 fork 一次拿 PNG。页面想同时显示 URL 文本(扫码失败兜底)就得二次
//	fork 拿 `--format url`。两次 fork 的硬伤:每次 CLI 都会**重新签发** Hy2 mTLS
//	客户端证书(`hy2ClientCertCommonName` 用 rand 8 字节做后缀),PNG 和 URL 文本
//	里嵌的 cert 不一致 —— 用户扫码 vs 复制文本两条路径拿到的客户端 cert 不同,
//	革命服务器审计 / 撤销时会看不到对应关系。
//	解法:一次拿 URL 文本,PNG 由 web 进程自渲(go-qrcode 已 import,credentials QR
//	也走它),两份产物 byte-for-byte 对应同一份证书,语义干净。顺便干掉 tmp file。
//
// 实现选择:fork CLI 而不是 import buildProfile() 函数 —— `nanotun-admin` 是
// `package main`,无法被本包 import。fork 是最稳的复用方式;CLI 已过多轮深扫
// 验证,行为冻结。长期可考虑把 buildProfile / profileSchema 抽到 nanotun/profile/
// 包,届时直接 import 替换本函数即可,UI / handler / 模板 / audit 都不动。
//
// 安全注意:
//   - 调用形式 exec.Command(name, args...) 多参数,不是 shell 拼接,无注入风险;
//   - dialHost 由 setting 写入,setter 已用 ValidateServerDialHost 强校验
//     (IPv4 / IPv6 / RFC1035 合法 hostname 末段含字母);
//   - advertisedHost 由 setting 写入,setter 已用 ValidateAdvertisedHost 校验
//     (无 scheme / path / port / 控制字符,允许任意中文 / emoji label);
//   - URL 含 hy2_pw / hy2 client_cert_pem / hy2 client_key_pem 等敏感字段 —
//     caller(handleServerQRReveal)已强制 step-up password,本函数纯计算不再校验。
//
// 2026-05-26 第六轮拆字段:fork CLI 时传 `--dial-host`(真实拨号目标) + 可选
// `--advertised-host`(展示 label)。两值通过 setting 流入,CLI 端再做一次
// strict validation 兜底(防御性,避免直接调本函数 bypass setting validator)。
func (s *Server) buildServerProfileQRAndURL(ctx context.Context, dialHost, advertisedHost string) (string, []byte, error) {
	binPath := s.cfg.VPNPortAdminPath
	if binPath == "" {
		binPath = "/usr/local/bin/nanotun-admin"
	}
	configPath := s.cfg.ServerConfigPath
	if configPath == "" {
		configPath = "/etc/nanotun/config.toml"
	}

	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	// `--format url` 把 nanotun://v1?d=<base64url(json)> 写到 stdout。
	// 不传 --output → 走 stdout;writeProfile 内部会带 trailing newline,这里
	// TrimSpace 干掉。
	args := []string{
		"--db-path", s.cfg.DBPath,
		"profile", "show",
		"--dial-host", dialHost,
		"--config", configPath,
		"--format", "url",
	}
	if advertisedHost != "" {
		args = append(args, "--advertised-host", advertisedHost)
	}
	cmd := exec.CommandContext(cctx, binPath, args...)
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		logrus.WithError(err).WithField("stderr", stderr.String()).
			WithField("bin", binPath).
			Error("[server-qr] nanotun-admin profile show 失败")
		// 截短 stderr 第一行作为错误信息,避免泄露磁盘路径等。
		firstLine := strings.SplitN(stderr.String(), "\n", 2)[0]
		if len(firstLine) > 120 {
			firstLine = firstLine[:120] + "…"
		}
		if firstLine == "" {
			firstLine = err.Error()
		}
		return "", nil, newLocErr("serverQr.cliFailed", firstLine)
	}

	urlText := strings.TrimSpace(stdout.String())
	if urlText == "" {
		return "", nil, newLocErr("serverQr.cliEmptyURL")
	}

	// 自渲 PNG:先试 Medium 纠错(15% 容量),容量超 → 降级 Low(7% 容量)。
	// 与 cmd_profile_qr.go 的策略对齐,保证 admin 在 web / CLI 两种入口下扫到
	// 的 QR 行为一致(纠错等级、模块数、像素密度都 byte-equal)。
	png, qerr := qrcode.Encode(urlText, qrcode.Medium, serverQRPixels)
	if qerr != nil {
		var lowErr error
		png, lowErr = qrcode.Encode(urlText, qrcode.Low, serverQRPixels)
		if lowErr != nil {
			return urlText, nil, newLocErr("serverQr.pngRenderFailed",
				qerr.Error(), lowErr.Error(), len(urlText))
		}
		logrus.WithField("url_bytes", len(urlText)).
			Warn("[server-qr] PNG 渲染降级到 Low 纠错(URL 超 Medium 容量;扫码可靠度仍够屏幕直显,跨屏拍摄请留意光照与对焦)")
	}

	return urlText, png, nil
}

// =============================================================================
// advertised_host setting POST handler
// =============================================================================

// handleSettingsAdvertisedHostSet — POST /settings/advertised-host
//
// 2026-05-26 改名:原 handleSettingsPublicHostSet / POST /settings/public-host,
// 配 db key 由 public_host → advertised_host 的整体重命名(migration 0015)。
//
// 表单字段:advertised_host(string)。空 = 清除。
// 经 ValidateAdvertisedHost(store/advertised_host.go)校验后落 app_settings。
//
// audit:settings_advertised_host_set,detail 含 old/new(host 是 public 数据,审计
// 里写明白让事后追溯能看「什么时候改过 host」)。
func (s *Server) handleSettingsAdvertisedHostSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	ctx := r.Context()
	newHost := strings.TrimSpace(r.FormValue("advertised_host"))
	if err := store.ValidateAdvertisedHost(newHost); err != nil {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.advertisedHostInvalid")+trErr(r, err))
		return
	}
	old, _ := s.store.GetAdvertisedHost(ctx)
	if err := s.store.SetAdvertisedHost(ctx, newHost); err != nil {
		s.renderInternalError(w, r, "settings:set_advertised_host", err)
		return
	}
	s.audit.WriteFromRequest(r, "settings_advertised_host_set", "",
		FormatDetail("old", old, "new", newHost))
	verb := tr(r, "flash.advertisedHostUpdated")
	if newHost == "" {
		verb = tr(r, "flash.advertisedHostCleared")
	}
	// flashRedirect 内部 QueryEscape + 附签名(第三轮 L5)。
	flashRedirect(w, r, "/settings", verb, "")
}

// =============================================================================
// server_dial_host setting POST handler (2026-05-26 第六轮拆字段新增)
// =============================================================================

// handleSettingsServerDialHostSet — POST /settings/server-dial-host
//
// 拆字段背景:advertised_host 历史上兼任客户端 dial target,踩坑后(用户配
// `test-203.0.113.10` 当 label 但被作为 dial 塞进 PacketTunnel 导致 NEVPN
// `Invalid tunnelRemoteAddress` 隧道挂掉)拆出本独立 setting。
//
// 表单字段:
//   - `server_dial_host`:字符串,空 = 清除;
//   - `skip_probe`:"1" 时**仅跳过 ICMP softfail**,DNS 解析仍必查
//     (适用于云服务商 firewall ban ICMP 的合法 server)。
//
// **三阶段校验**(2026-05-26 第六轮拆字段 + 主动 ping 检测,第十一轮校正 skip 语义):
//
//  1. [store.ValidateServerDialHost] 语法 — IPv4 / IPv6 / RFC1035 域名,拒末段
//     纯数字的伪 hostname。失败 → 400,**与 skip_probe 正交**(skip 不绕过语法)。
//
//  2. [store.ProbeServerDialHost] 可达性(newHost 非空就跑,与 skip_probe 正交):
//     - DNS resolve 失败 → 400(`ErrServerDialHostDNS`,**硬错,任何 skip 都救不回来**);
//     - ICMP ping 0 回包 → skip_probe=1 时入库(audit `_icmp_softfail_skipped`),
//     否则 412(`ErrServerDialHostICMPSoftFail`,软错)+ 提示勾选「跳过 ICMP」;
//     - ctx cancel → 503,**不写 audit**(系统抖动)。
//
//  3. [store.SetServerDialHost] 入库 + 审计。
//
// audit 路径(全部 detail 用 dial_host 键):
//   - `settings_server_dial_host_set`           : 成功(detail.probe = probed_ok/icmp_skipped/cleared)
//   - `_dns_fail`                                : DNS 硬错(skip_probe 也无效)
//   - `_icmp_softfail` / `_icmp_softfail_skipped`: ICMP 软错(skip 与否分开 audit,便于审计)
//   - `_probe_unknown` / `_probe_unknown_skipped`: 未分类 probe 错
//
// **为什么 ICMP 失败是 412 而不是 400**:
//   - 400 语义 = 客户端输入根本不合法;
//   - 412 语义 = 输入合法但前置条件(可达性)未满足;
//   - admin 看到 412 才知道「再勾选一下 skip_probe 就能保存」 — 比 400 的"格式错误"
//     更精准引导。
func (s *Server) handleSettingsServerDialHostSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	ctx := r.Context()
	newHost := strings.TrimSpace(r.FormValue("server_dial_host"))
	skipProbe := r.FormValue("skip_probe") == "1"

	if err := store.ValidateServerDialHost(newHost); err != nil {
		// 第二十四轮 P3-2:语法错时给出「去设置页手改」直链,免去 admin 摸索
		s.renderErrorWithCTA(w, r, http.StatusBadRequest,
			tr(r, "serverQr.dialHostInvalidSyntax", trErr(r, err)),
			"/settings", tr(r, "cta.editInSettings"))
		return
	}

	// 第 11 轮(2026-05-26):skip_probe 语义校正 —— **只跳过 ICMP softfail**,
	// DNS 必查。原实现 `if !skipProbe { probe }` 让勾选 skip_probe 时 DNS 也被跳过,
	// 与 settings.html 文案「DNS 解析失败 → 一定是错地址,无法跳过」直接矛盾。
	// 校正后行为(三种 probe 失败 × 是否 skip):
	//   - DNS fail        : 400,**无视 skip_probe**(地址永远是错的,不可入库)
	//   - ICMP softfail   : skip_probe=1 → 入库,skip_probe=0 → 412
	//   - probe_unknown   : skip_probe=1 → 入库,skip_probe=0 → 412
	//   - ctx cancel      : 503,与 skip_probe 正交(系统抖动,不写 audit)
	// probeOutcome 精确追踪 probe 走了哪条路径,用于成功 audit `detail.probe` + 用户 flash verb。
	// 第十一轮原 probeNote 写法 `skipProbe && newHost != "" → icmp_skipped` 是 **proxy 推断**:
	// 当 admin 勾了 skip_probe 但 probe 实际全通过(如填入真实通的 IP),也会被错标为
	// `icmp_skipped` — 漂移 audit 精度。第十二轮改成在 probe 真正落入 softfail+skip 分支时
	// 才 set,默认 `probed_ok`,literal IP 路径独立标 `probed_literal_ip`(没跑 DNS lookup,
	// 用于校正 verb 文案不要说「DNS 已通过」)。
	probeOutcome := "probed_ok"
	// wasLiteralIP 与 probeOutcome 并存:probeOutcome 在 switch 分支可能被覆盖
	// (如 icmp_softfail_skipped),但 wasLiteralIP 不会 — verb 用它独立判断
	// 「这个保存路径有没有跑过 DNS」,避免 literal IP + skip 时仍写「DNS 已通过」。
	wasLiteralIP := false
	if newHost != "" {
		// 第十三轮(2026-05-27):probe 预算从 10s 调到 **20s**,覆盖多 A/AAAA 域名
		// 串行 ping 最坏场景(DNS 3s + 5 IP × 3s/Count=3 ≈ 18s)。原 10s 在 4+ IP
		// 域名上必触发 parent ctx DeadlineExceeded → 503 假阴性。20s 给运维余地,
		// admin 在浏览器上等 ≤20s 拿真实结果,远好于"看到 503 不知道是地址还是系统"。
		probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		perr := store.ProbeServerDialHost(probeCtx, newHost)
		cancel()
		// literal IP 路径在 ProbeServerDialHost 内部不走 DNS lookup(直接 pingOnce),
		// 用 [store.ParseLiteralIP] 唯一来源(剥 `[]` 再 ParseIP),避免 bracket
		// IPv6 漂移成「域名」。
		if _, ok := store.ParseLiteralIP(newHost); ok {
			probeOutcome = "probed_literal_ip"
			wasLiteralIP = true
		}
		if perr != nil {
			switch {
			case errors.Is(perr, context.Canceled) || errors.Is(perr, context.DeadlineExceeded):
				// ctx 取消(admin 浏览器主动断开 / server shutdown / probe 自己 20s 超时)
				// **不是地址问题**,不写 audit(audit 是"事件",不是"系统抖动")。
				// 返回 503 让 admin 直接重试,UI 友好。
				// 注:probe 20s deadline 在合法 host 上不应触发(第十三轮把 ctx 从 10s
				// 调到 20s 即为兼容 4+ A/AAAA 域名);触发多半是网络异常,与 ICMPSoftFail
				// 区分开。
				s.renderError(w, r, http.StatusServiceUnavailable,
					tr(r, "serverQr.probeInterrupted", perr.Error()))
				return
			case errors.Is(perr, store.ErrServerDialHostDNS):
				// **不可跳过**:DNS 解析失败 = 客户端 100% 连不上,任何 skip_probe
				// 都不能放过。保留 audit 即使 admin 想强行跳过(便于审计追踪误操作)。
				s.audit.WriteFromRequest(r, "settings_server_dial_host_set_dns_fail", "",
					FormatDetail("dial_host", newHost, "err", perr.Error(), "skip_probe", skipProbe))
				// 第二十四轮 P3-2:DNS 硬错给「去设置页改地址」CTA(skip_probe 救不回来)
				s.renderErrorWithCTA(w, r, http.StatusBadRequest,
					tr(r, "serverQr.dnsFailed", trErr(r, perr)),
					"/settings", tr(r, "cta.changeAddrInSettings"))
				return
			case errors.Is(perr, store.ErrServerDialHostICMPSoftFail):
				if skipProbe {
					// admin 明确知道服务器 ban ICMP(AWS / Vultr 安全组默认),
					// 选择强行入库;DNS 解析已通过,客户端实际拨号大概率成功。
					s.audit.WriteFromRequest(r, "settings_server_dial_host_set_icmp_softfail_skipped", "",
						FormatDetail("dial_host", newHost, "err", perr.Error(), "skip_probe", "1"))
					probeOutcome = "icmp_softfail_skipped"
					break // 跳出 switch,继续走保存逻辑
				}
				s.audit.WriteFromRequest(r, "settings_server_dial_host_set_icmp_softfail", "",
					FormatDetail("dial_host", newHost, "err", perr.Error()))
				// 第二十四轮 P3-2:412 ICMP softfail 是 backlog 最强场景 — 默认 banner
				// 一键不勾 skip_probe,云厂商 ban ICMP 时必触发,admin 必须能一键到
				// 设置页勾上 skip_probe 重试。CTA 直接指向 /settings(候选已预填)。
				s.renderErrorWithCTA(w, r, http.StatusPreconditionFailed,
					tr(r, "serverQr.icmpSoftfail", trErr(r, perr)),
					"/settings", tr(r, "cta.skipIcmpInSettings"))
				return
			default:
				// 未分类的 probe 错(理论上不会到):为保险也允许 skip_probe 跳过。
				if skipProbe {
					s.audit.WriteFromRequest(r, "settings_server_dial_host_set_probe_unknown_skipped", "",
						FormatDetail("dial_host", newHost, "err", perr.Error(), "skip_probe", "1"))
					probeOutcome = "probe_unknown_skipped"
					break
				}
				s.audit.WriteFromRequest(r, "settings_server_dial_host_set_probe_unknown", "",
					FormatDetail("dial_host", newHost, "err", perr.Error()))
				// 第二十四轮 P3-2:probe_unknown 同款 CTA(skip_probe 绕过)
				s.renderErrorWithCTA(w, r, http.StatusPreconditionFailed,
					tr(r, "serverQr.probeUnknown", trErr(r, perr)),
					"/settings", tr(r, "cta.skipIcmpInSettings"))
				return
			}
		}
	}

	old, _ := s.store.GetServerDialHost(ctx)
	if err := s.store.SetServerDialHost(ctx, newHost); err != nil {
		s.renderInternalError(w, r, "settings:set_server_dial_host", err)
		return
	}
	auditAction := "settings_server_dial_host_set"
	// 第十二轮(2026-05-27):probeNote 改为读 probeOutcome(精确追踪 probe 实际路径),
	// 而非旧版 `skipProbe && newHost != "" → icmp_skipped` 的 proxy 推断。
	// 路径:
	//   - "cleared"               : newHost="",未跑 probe
	//   - "probed_ok"             : 域名 DNS+ICMP 全通过(默认)
	//   - "probed_literal_ip"     : literal IP,跳过 DNS lookup,ICMP 通过
	//   - "icmp_softfail_skipped" : ICMP 软错 + admin 主动 bypass(双 audit 之一)
	//   - "probe_unknown_skipped" : 未分类 probe 错 + admin 主动 bypass
	// 注意:DNS hard fail 路径已 early return,这里永不出现 dns_*。
	probeNote := probeOutcome
	if newHost == "" {
		probeNote = "cleared"
	}
	s.audit.WriteFromRequest(r, auditAction, "",
		FormatDetail("old", old, "new", newHost, "probe", probeNote))
	verb := tr(r, "flash.dialHostUpdated")
	// 第十三轮(2026-05-27):literal IP + skip 路径 verb 不说「DNS 已通过」
	// (literal IP 在 Probe 内部跳过 DNS lookup,实际未做 DNS 解析)。
	switch probeNote {
	case "cleared":
		verb = tr(r, "flash.dialHostCleared")
	case "icmp_softfail_skipped":
		if wasLiteralIP {
			verb = tr(r, "flash.dialHostUpdatedLiteralIcmpSkipped")
		} else {
			verb = tr(r, "flash.dialHostUpdatedIcmpSkipped")
		}
	case "probe_unknown_skipped":
		verb = tr(r, "flash.dialHostUpdatedProbeUnknownSkipped")
	case "probed_literal_ip":
		verb = tr(r, "flash.dialHostUpdatedLiteralOk")
	case "probed_ok":
		verb = tr(r, "flash.dialHostUpdatedProbedOk")
	}
	// 2026-05-27 第二十二轮:dashboard 顶部红 banner 的「一键确认候选」按钮
	// 会 POST `return_to=/`,期望保存成功后回到 dashboard(banner 自动消失 +
	// QR 卡片立即可用)。原 settings.html 表单**不传** return_to,保留旧的
	// `/settings?flash=...` 行为(用户已经在 settings 页,redirect 自己很顺)。
	// `sanitizeReturnTo` 白名单收敛(详见 handler_misc.go TestSanitizeReturnTo),
	// `javascript:alert` / `//evil.com` 等攻击 payload 一律 fallback `/`,
	// 开放重定向风险已封堵。
	dest := "/settings"
	if rt := strings.TrimSpace(r.FormValue("return_to")); rt != "" {
		dest = sanitizeReturnTo(rt, r.Referer())
	}
	// flashRedirect 内部 QueryEscape + 附签名(第三轮 L5)。
	flashRedirect(w, r, dest, verb, "")
}
