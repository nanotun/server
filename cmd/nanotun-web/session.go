package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// maxConcurrentWebSessionsPerAdmin 是单个 web admin 的并发有效 session 上限(d_relogin_revoke)。
// 登录成功后 IssueSession 会把该 admin 的 session 数封顶到此值(保留最近若干条)。取 10:足够覆盖
// 「笔记本 + 手机 + 平板 + 几个浏览器」的正常多设备使用,又能阻止无界累积。要「一键踢全部」走
// DeleteWebSessionsByAdmin(改密 / 禁用 / 删除路径已用)。
const maxConcurrentWebSessionsPerAdmin = 10

// M2:Web 后台 session cookie 管理。
//
// 设计:
//   - session id = 32 字节随机 → base64url (43 chars,no padding),
//     等价 256-bit unguessable bearer token;
//   - 存 SQLite web_sessions (id, admin_id, expires_at, ip, ua) 持久化;
//   - 同 id 也作为 cookie 的 value;cookie 标签 HttpOnly + Secure + SameSite=Lax;
//   - 每次请求命中 → store.TouchWebSession 滑动延期。
//
// 为什么不用 signed cookie + 无状态?
//   - 持久化让重启不掉登录,运维体验好;
//   - 主动 revoke (admin 改密 / 禁用) 立即生效;
//   - SQLite 写入轻,touch 一次只有几十微秒。

const (
	sessionCookieName = "nanotun-web_session"

	// CSRF token cookie。double-submit cookie 模式:
	//   GET → 服务器从 session 派生一个 token 写 cookie;
	//   POST → 表单内必须有同样的 token,与 cookie 比对一致才通过。
	csrfCookieName = "nanotun-web_csrf"

	// pending2FACookieName(2026-05-23):密码已验证但 TOTP 还没输入的临时态。
	// 短期(5min)签名 cookie,服务端无 state,内容 = adminID|exp|nonce|HMAC。
	// 重启进程后 hmac key 重新生成,所有正在等待的 pending 自动失效 —— 正好就是
	// 我们想要的语义(短期 token 不应该跨进程生命周期)。
	pending2FACookieName = "nanotun-web_pending_2fa"
	pending2FATTLSec     = int64(5 * 60)
)

// SessionService 包装 session 管理操作。零依赖 net/http,handler 用之。
type SessionService struct {
	store        *store.Store
	cfg          Config
	cookieSecure bool

	// pendingHMACKey 用于 TOTP pending cookie 的 HMAC 签名。
	// 进程启动时随机生成,重启后所有 pending cookie 自动失效 — 这正符合"短期
	// 转场 token"的语义。32 字节 → HMAC-SHA256。
	pendingHMACKey []byte

	// captchaHMACKey 用于登录页数字验证码 cookie 的 HMAC 签名。
	// 与 pendingHMACKey 同模式但**独立 key**:不让一种 cookie 的伪造能力
	// 顺路用到另一种。同样进程启动即随机,重启失效全部待提交 captcha
	// (没关系,用户重新刷新登录页就有新的一张图)。
	captchaHMACKey []byte

	// powHMACKey 用于登录页前置 PoW 题目元数据 (challenge_id, salt, ...)
	// 的 HMAC-SHA256 签名,防止客户端伪造低难度题目混过去。独立 key,
	// 进程启动即随机;重启会让所有未提交的旧 challenge 失效 — 配合
	// powUsed 重启清空,旧 challenge 既不能签也不能重放,完整断链。
	powHMACKey []byte

	// csrfHMACKey 用于把 CSRF token **绑定到 session**(第三轮深扫 L1)。此前 CSRF 纯 double-submit
	// (仅校验 cookie==form),token 是无绑定随机串,唯一跨站防线是 SameSite=Lax;同注册域下的
	// cookie-tossing(evil.sub.example 写 Domain=example 的 cookie)或明文兄弟源 MITM 注入 Set-Cookie
	// 可让 cookie==form 自洽而绕过。改为 token = nonce + HMAC(csrfHMACKey, boundID‖nonce),boundID=已登录
	// 的 web session id(未登录 setup/login 阶段为空);校验时用**当前请求**的 boundID 复算签名,攻击者
	// 不知本 key、也无法对受害者的 session id 产生合法签名。独立 key,进程启动即随机。
	csrfHMACKey []byte

	// powUsed 记录已经成功消费过的 challenge_id → expireUnix,用于防重放。
	// 单实例进程内 sync.Map 够用;runPoWGC goroutine 每 60s prune 过期项。
	powUsed sync.Map

	// captchaUsed 记录已**尝试**过的 captcha nonce → expireUnix,做**服务端**一次性消费。
	// ClearCaptcha 只清响应里的 cookie,attacker 攥着截获的 (cookie, answer) 仍可在 5min TTL
	// 内反复重放同一张验证码试不同密码;这里在校验时(答案对错前,见 VerifyCaptcha / L8)就把
	// nonce 记下,再次提交同 nonce 直接拒绝 —— 每张 captcha 只准一次尝试,杜绝同图暴破。
	// 与 powUsed 同套(sync.Map + runPoWGC 每 60s prune 过期项)。
	captchaUsed sync.Map

	// ipFailures 跟踪每个 IP 的滑动窗口失败次数,驱动自适应 PoW 难度。
	// 见 ip_failures.go。
	ipFailures *IPFailureTracker
}

// NewSessionService 构造。listenAddr 上若开启 HTTPS,cookie 加上 Secure 属性。
// 当前 nanotun-web 总是 HTTPS(self-signed 也是),所以默认 true。
//
// pendingHMACKey 启动时随机。失败时 panic — 进程没办法签 pending cookie,
// TOTP 启用了的 admin 将永远登不上,直接拉警报让运维知道。
func NewSessionService(st *store.Store, cfg Config) *SessionService {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("nanotun-web: 无法初始化 pending hmac key: " + err.Error())
	}
	capKey := make([]byte, 32)
	if _, err := rand.Read(capKey); err != nil {
		panic("nanotun-web: 无法初始化 captcha hmac key: " + err.Error())
	}
	powKey := make([]byte, 32)
	if _, err := rand.Read(powKey); err != nil {
		panic("nanotun-web: 无法初始化 pow hmac key: " + err.Error())
	}
	csrfKey := make([]byte, 32)
	if _, err := rand.Read(csrfKey); err != nil {
		panic("nanotun-web: 无法初始化 csrf hmac key: " + err.Error())
	}
	return &SessionService{
		store:          st,
		cfg:            cfg,
		cookieSecure:   true,
		pendingHMACKey: key,
		captchaHMACKey: capKey,
		powHMACKey:     powKey,
		csrfHMACKey:    csrfKey,
		ipFailures:     NewIPFailureTracker(),
	}
}

// IssueSession 创建一条 session 并写 cookie。在成功登录路径调用。
func (s *SessionService) IssueSession(ctx context.Context, w http.ResponseWriter,
	adminID int64, ip, ua string) error {

	sid, err := generateRandomToken(32)
	if err != nil {
		return err
	}
	if err := s.store.CreateWebSession(ctx, store.WebSession{
		ID:        sid,
		AdminID:   adminID,
		ExpiresAt: nowUnix() + s.cfg.SessionTTLSec,
		IP:        ip,
		UserAgent: truncate(ua, 256),
	}); err != nil {
		return err
	}
	// 第四轮深扫 MED(d_relogin_revoke):登录成功即把该 admin 的并发 session 数**封顶**到
	// maxConcurrentWebSessionsPerAdmin,删掉较旧的多余项。防止反复登录无界累积有效 session、给失窃 /
	// 遗留 cookie 一个确定的淘汰路径。best-effort:prune 失败只记日志,不阻断本次登录(会话已建成)。
	if _, perr := s.store.PruneWebSessionsKeepingRecent(ctx, adminID, maxConcurrentWebSessionsPerAdmin); perr != nil {
		logrus.WithError(perr).WithField("admin_id", adminID).Warn("[web] 登录后封顶并发 session 失败(忽略)")
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.SessionTTLSec),
	})
	return nil
}

// LookupSession 从 r.Cookie 取出 session id 并去库里验证。
//
// 返回 (admin, session, nil) 表示有效登录;
// 返回 (nil, nil, ErrNoSession) 表示未登录(无 cookie / cookie 失效 / admin 被删/禁)。
//
// 注意:这里**不**对 ip/ua 做相同性校验,以免移动客户端 / IPv4 跳网 / VPN 出口
// 切换被反复登出。如果需要,可在 Config 加 strict_session_ip 开关。
var ErrNoSession = errors.New("no valid session")

func (s *SessionService) LookupSession(ctx context.Context, r *http.Request) (
	*store.WebAdmin, *store.WebSession, error) {

	ck, err := r.Cookie(sessionCookieName)
	if err != nil || ck.Value == "" {
		return nil, nil, ErrNoSession
	}
	// session id 应该是 43 字符 base64url。明显畸形直接 reject,省一次 DB 查询。
	if len(ck.Value) < 32 || len(ck.Value) > 128 {
		return nil, nil, ErrNoSession
	}
	ws, err := s.store.GetWebSession(ctx, ck.Value)
	if err != nil {
		return nil, nil, ErrNoSession
	}
	a, err := s.store.GetWebAdmin(ctx, ws.AdminID)
	if err != nil || !a.Enabled {
		return nil, nil, ErrNoSession
	}
	// 滑动窗口:每次成功命中都把 expires_at 往后顶 cfg.SessionTTLSec。
	// 容忍写库失败(只是这次没续期),不阻塞请求。
	_ = s.store.TouchWebSession(ctx, ws.ID, s.cfg.SessionTTLSec)
	return a, ws, nil
}

// DestroySession 登出。清 cookie + 删库。
func (s *SessionService) DestroySession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookieName); err == nil && ck.Value != "" {
		_ = s.store.DeleteWebSession(ctx, ck.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	// 同时清掉 pending 2FA cookie(以防 logout 时还有半途的转场态)。
	s.ClearTOTPPending(w)
}

// =========================================================================
// pending 2FA cookie:密码已通过、等待 TOTP 输入的转场态
// =========================================================================
//
// 流程:
//   POST /login   → 密码 OK + admin.TOTPEnabled
//                 → IssueTOTPPending(adminID, w)   // 写 5 分钟签名 cookie
//                 → 302 /login/totp
//   GET  /login/totp → LookupTOTPPending(r) 拿 adminID,渲染输入页面
//   POST /login/totp → LookupTOTPPending + 验 TOTP/recovery code
//                    → IssueSession + ClearTOTPPending + 302 /
//
// 安全属性:
//   - cookie 内容 = adminID(8B big-endian) | exp(8B) | nonce(16B) | HMAC-SHA256(32B);
//     base64url 编码;长度 = ceil(64/3*4) = 88 字符;
//   - HMAC key 每次进程启动随机一次,重启即失效全部 pending → 风险面最小;
//   - exp = now + 5min,过期 cookie 拒绝;
//   - HMAC 用常量时间比对,避免 timing 泄露;
//   - 不与 session cookie 复用 name,避免和登录态混淆。

// pending 载荷布局:adminID(8) | exp(8) | pwFp(8) | nonce(16) = 40;其后拼 HMAC-SHA256(32),总 72,
// base64url ≈ 96 字符。pwFp 是签发时密码指纹(第五轮深扫 HIGH),用于让密码轮换作废在途 pending。
const (
	pendingPwFpLen    = 8
	pendingPayloadLen = 8 + 8 + pendingPwFpLen + 16 // = 40
)

// passwordFingerprint 取 password_hash 的 8 字节指纹,签进 pending 载荷。
//
// 第五轮深扫 HIGH:pending-2FA cookie 原先只绑 adminID|exp|nonce + IP,**不绑密码**。于是「攻击者拿到
// 密码、已过密码步、持有 pending」时,管理员即便应急改密(UpdateWebAdminPasswordHash 会撤销 web_session,
// 但撤不掉在途 pending),攻击者仍能在 5 分钟窗口内用同 IP 提交 TOTP/恢复码,IssueSession 成功 —— 等于
// **不需要新密码**就完成登录,改密作为事件响应手段失效。把签发时的密码指纹绑进(被 HMAC 覆盖的)载荷,
// /login/totp 用**当前**密码指纹比对,不符即作废旧 pending、强制回密码步。SHA256 前 8 字节:单向不可还原
// 出 hash;对本用途只需「密码一变指纹就变」,碰撞无意义。
func passwordFingerprint(hash string) [pendingPwFpLen]byte {
	sum := sha256.Sum256([]byte(hash))
	var fp [pendingPwFpLen]byte
	copy(fp[:], sum[:pendingPwFpLen])
	return fp
}

// pendingMAC 计算 pending-2FA cookie 的 HMAC:签 payload,并把**客户端 IP** 作为附加认证数据(AAD)
// 绑进签名。这样 pending cookie 即便被窃取,从**另一个 IP** 重放时算出的 MAC 与 cookie 内的不符 → 拒,
// 使「拿到密码 + 偷到 pending cookie」的攻击者无法在自己的机器上完成 TOTP 步。payload 定长(32B),其后
// 直接拼 ip 无边界歧义。IP 在 5 分钟窗口内切换(移动网络等)会导致该步失败并回退重新登录,可接受。
func (s *SessionService) pendingMAC(payload []byte, ip string) []byte {
	mac := hmac.New(sha256.New, s.pendingHMACKey)
	mac.Write(payload)
	mac.Write([]byte(ip))
	return mac.Sum(nil)
}

// IssueTOTPPending 写 pending cookie。每次密码验证通过、需要 TOTP 时调用。ip 绑进签名(见 pendingMAC),
// passwordHash 的指纹绑进载荷(见 passwordFingerprint):密码轮换后旧 pending 立即失效。
func (s *SessionService) IssueTOTPPending(w http.ResponseWriter, adminID int64, ip, passwordHash string) error {
	if adminID <= 0 {
		return errors.New("pending2fa: bad admin id")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	exp := nowUnix() + pending2FATTLSec
	var payload [pendingPayloadLen]byte
	binary.BigEndian.PutUint64(payload[0:8], uint64(adminID))
	binary.BigEndian.PutUint64(payload[8:16], uint64(exp))
	fp := passwordFingerprint(passwordHash)
	copy(payload[16:24], fp[:])
	copy(payload[24:40], nonce)

	sig := s.pendingMAC(payload[:], ip)

	full := append(payload[:], sig...) // 40 + 32 = 72 字节
	value := base64.RawURLEncoding.EncodeToString(full)

	http.SetCookie(w, &http.Cookie{
		Name:     pending2FACookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(pending2FATTLSec),
	})
	return nil
}

// LookupTOTPPending 验签 pending cookie,返回 adminID。
// 错误情形:无 cookie / 解码失败 / HMAC 不匹配 / 已过期 → ErrNoPending2FA。
//
// 不抛细分错误是有意的:用户看到的统一信息是"会话过期,请重新登录",避免 attacker
// 通过错误码区分 cookie 内容篡改成功了多少。
var ErrNoPending2FA = errors.New("no valid pending 2fa")

func (s *SessionService) LookupTOTPPending(r *http.Request) (int64, [pendingPwFpLen]byte, error) {
	var zeroFp [pendingPwFpLen]byte
	ck, err := r.Cookie(pending2FACookieName)
	if err != nil || ck.Value == "" {
		return 0, zeroFp, ErrNoPending2FA
	}
	raw, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil || len(raw) != pendingPayloadLen+sha256.Size {
		return 0, zeroFp, ErrNoPending2FA
	}
	payload := raw[:pendingPayloadLen]
	sig := raw[pendingPayloadLen:]

	// 用与签发时相同的客户端 IP 复算 MAC:cookie 被窃后从别的 IP 重放会因 IP 不符而验签失败。
	want := s.pendingMAC(payload, clientIP(r))
	if subtle.ConstantTimeCompare(sig, want) != 1 {
		return 0, zeroFp, ErrNoPending2FA
	}
	adminID := int64(binary.BigEndian.Uint64(payload[0:8]))
	exp := int64(binary.BigEndian.Uint64(payload[8:16]))
	if adminID <= 0 || exp <= nowUnix() {
		return 0, zeroFp, ErrNoPending2FA
	}
	// 返回签发时的密码指纹;调用方在拿到 admin 后与当前密码指纹比对,不符即作废(密码已轮换)。
	var fp [pendingPwFpLen]byte
	copy(fp[:], payload[16:24])
	return adminID, fp, nil
}

// ClearTOTPPending 清 pending cookie。在 TOTP 校验通过后(IssueSession 前后)调用,
// 或者 admin 明显放弃流程(/logout) 时调用。
func (s *SessionService) ClearTOTPPending(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     pending2FACookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// =========================================================================
// CSRF token: double-submit cookie
// =========================================================================

// csrfBoundID 取「CSRF 绑定主体」:已登录请求(requireAuth 已注入 ctxKeySessionID)绑到 web session id;
// 未登录的 setup / login / TOTP 前置页无 session,绑到空串。两处(签发 & 校验)必须用同一来源,
// 保证同一浏览器视图内前后一致。
func csrfBoundID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeySessionID).(string); ok {
		return v
	}
	return ""
}

// csrfSign 生成绑定 boundID 的 CSRF token:`<nonce>.<base64url(HMAC(key, boundID‖0x00‖nonce))>`。
func (s *SessionService) csrfSign(boundID, nonce string) string {
	mac := hmac.New(sha256.New, s.csrfHMACKey)
	mac.Write([]byte(boundID))
	mac.Write([]byte{0})
	mac.Write([]byte(nonce))
	return nonce + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// csrfValidFor 常量时间校验 token 是否是对 boundID 的合法签名。
func (s *SessionService) csrfValidFor(token, boundID string) bool {
	i := strings.IndexByte(token, '.')
	if i <= 0 || i >= len(token)-1 {
		return false
	}
	want := s.csrfSign(boundID, token[:i])
	return subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
}

// IssueCSRFToken 在 GET 渲染表单页时调用:生成绑定当前 boundID 的签名 token,写到一个非 HttpOnly
// cookie(让 JS 也能读),并返回 token 给模板作为 hidden input 的 value。
//
// 模式:**会话绑定**的 double-submit cookie(第三轮深扫 L1)。POST 时既校验 cookie==form,又校验 token
// 是对当前请求 boundID 的合法 HMAC 签名。前者防常规跨站(叠加 SameSite=Lax),后者关掉 cookie-tossing
// (攻击者塞入的自洽 cookie/form 值无法对受害者 session id 产生合法签名)。
//
// K4(2026-05-23):**强制新签**只在没有合法 cookie 时使用。常规渲染请走 EnsureCSRFToken,避免
// 「GET 页面 + 浏览器并发 favicon GET → 二次签发覆盖 → form 里嵌的旧 token 与 cookie 不一致」的经典坑。
func (s *SessionService) IssueCSRFToken(r *http.Request, w http.ResponseWriter) (string, error) {
	nonce, err := generateRandomToken(24) // 32 base64url 字符;+ "." + 43 字符签名 ≈ 76 字符
	if err != nil {
		return "", err
	}
	token := s.csrfSign(csrfBoundID(r), nonce)
	s.writeCSRFCookie(w, token)
	return token, nil
}

// EnsureCSRFToken:有对**当前 boundID** 仍合法的 cookie 就复用,否则新签。**所有渲染表单的 GET handler
// 都应该用这个版本而不是 IssueCSRFToken**。复用保证「同一浏览器视图里 form hidden field 与 cookie 值
// 始终一致」,即便页面加载中触发多次 GET(favicon、redirect 回环)也不会错位。
//
// 关键:登录跨越 pre-auth("")→ authed(session id)边界时,旧 cookie 对新 boundID 签名不再合法,
// 这里会**自动重签**绑到新的 session id,无缝完成绑定切换。
func (s *SessionService) EnsureCSRFToken(r *http.Request, w http.ResponseWriter) (string, error) {
	boundID := csrfBoundID(r)
	if ck, err := r.Cookie(csrfCookieName); err == nil &&
		len(ck.Value) >= 32 && len(ck.Value) <= 256 && s.csrfValidFor(ck.Value, boundID) {
		// 刷新 cookie 的 MaxAge 让有效期顺延,但 value 不变。
		s.writeCSRFCookie(w, ck.Value)
		return ck.Value, nil
	}
	return s.IssueCSRFToken(r, w)
}

func (s *SessionService) writeCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.SessionTTLSec),
	})
}

// VerifyCSRFToken 在 POST/PUT/DELETE handler 第一行调用。
//
// 返回 nil → 通过;否则 handler 应回 403 + 描述。校验两层:
//  1. cookie==form(double-submit,保留);
//  2. form token 是对**当前请求 boundID**(已登录=session id)的合法 HMAC 签名(会话绑定,关 cookie-tossing)。
func (s *SessionService) VerifyCSRFToken(r *http.Request) error {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return nil
	}
	ck, err := r.Cookie(csrfCookieName)
	if err != nil || ck.Value == "" {
		return newLocErr("csrf.missingCookie")
	}
	// 从 form / query 取 token:支持表单 POST(form-urlencoded)+ multipart;不取 header。
	formToken := r.FormValue("csrf_token")
	if formToken == "" {
		formToken = r.Header.Get("X-CSRF-Token") // SPA / htmx 替代路径
	}
	if formToken == "" {
		return newLocErr("csrf.missingToken")
	}
	if !ConstantTimeStringEqual(ck.Value, formToken) {
		return newLocErr("csrf.mismatch")
	}
	if !s.csrfValidFor(formToken, csrfBoundID(r)) {
		return newLocErr("csrf.mismatch")
	}
	return nil
}

// =========================================================================
// helpers
// =========================================================================

func generateRandomToken(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("token length must > 0")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// trustedProxyNets 是启动时(main → setTrustedProxies)固定下来的可信反代前缀集合。
// nil / 空 = 默认安全姿态:完全不信任 X-Forwarded-For。设定后只读,读无需加锁。
var trustedProxyNets []netip.Prefix

// setTrustedProxies 在 Config.Validate 通过后、开始 Serve 之前由 main 调一次。
func setTrustedProxies(nets []netip.Prefix) {
	trustedProxyNets = nets
}

// hostFromAddr 从 "ip:port" / "[ipv6]:port" / 裸 IP 中取出 host 字符串(去端口去括号)。
// 解析不出 host:port 时按裸地址处理(测试里常直接塞裸 IP)。
func hostFromAddr(s string) string {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(s, "[]")
}

// parseHostIP 从 "ip" / "ip:port" / "[ipv6]:port" / "[ipv6]" 中解析出 netip.Addr。
func parseHostIP(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	if a, err := netip.ParseAddr(s); err == nil { // 裸 IP(含裸 IPv6)
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil { // ip:port / [ipv6]:port
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil { // [ipv6] 无端口
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

func ipInTrustedProxy(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range trustedProxyNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP 提取请求的真实客户端 IP。
//
// 默认安全姿态:trustedProxyNets 为空时**完全不信任** X-Forwarded-For —— 直接用
// TCP 直连对端(r.RemoteAddr)。否则任何人都能伪造 XFF 污染审计日志,并把「按 IP
// 限流 / 锁定」变成跨账号 DoS(伪造不同 XFF 绕过锁定,或伪造同一 XFF 锁死他人)。
//
// 仅当运维显式配置了 trusted_proxies(反代自己的 IP/CIDR)且本次直连对端确实落在
// 该集合内时,才解析 XFF:从右往左取第一个「不在可信集合」的 IP 作为真实客户端
// (右侧是最靠近本机的可信反代链,可信反代会把上游追加在右边)。全部可信则退化到
// 最左项;直连对端不可信则忽略 XFF(视为伪造)。
func clientIP(r *http.Request) string {
	direct := hostFromAddr(r.RemoteAddr)
	if len(trustedProxyNets) == 0 {
		return direct
	}
	da, ok := parseHostIP(r.RemoteAddr)
	if !ok || !ipInTrustedProxy(da) {
		// 直连对端不是可信反代 → XFF 不可信,一律用直连 IP。
		return direct
	}
	// 深扫第十轮 MED:聚合**所有** X-Forwarded-For header 值再解析。Header.Get 只返回
	// 第一条,若某跳用 Header.Add 追加真实客户端(而非拼进同一行),右往左扫会漏掉它 →
	// 把限流/审计记到攻击者可控的伪造首值上。Values 拿到全部,按到达顺序拼成一条列表。
	xff := strings.TrimSpace(strings.Join(r.Header.Values("X-Forwarded-For"), ","))
	if xff == "" {
		return direct
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if a, ok := parseHostIP(parts[i]); ok && !ipInTrustedProxy(a) {
			return a.String()
		}
	}
	// XFF 里全是可信反代(或都解析失败):取最左(离真实客户端最近)。
	if a, ok := parseHostIP(parts[0]); ok {
		return a.String()
	}
	return direct
}

func nowUnix() int64 {
	return time.Now().Unix()
}
