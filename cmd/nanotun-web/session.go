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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nanotun/server/store"
)

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

	// powUsed 记录已经成功消费过的 challenge_id → expireUnix,用于防重放。
	// 单实例进程内 sync.Map 够用;runPoWGC goroutine 每 60s prune 过期项。
	powUsed sync.Map

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
	return &SessionService{
		store:          st,
		cfg:            cfg,
		cookieSecure:   true,
		pendingHMACKey: key,
		captchaHMACKey: capKey,
		powHMACKey:     powKey,
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

// pendingPayloadLen = adminID(8) + exp(8) + nonce(16) = 32, HMAC = 32, 总 64。
const pendingPayloadLen = 32

// IssueTOTPPending 写 pending cookie。每次密码验证通过、需要 TOTP 时调用。
func (s *SessionService) IssueTOTPPending(w http.ResponseWriter, adminID int64) error {
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
	copy(payload[16:32], nonce)

	mac := hmac.New(sha256.New, s.pendingHMACKey)
	mac.Write(payload[:])
	sig := mac.Sum(nil)

	full := append(payload[:], sig...) // 32 + 32 = 64 字节
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

func (s *SessionService) LookupTOTPPending(r *http.Request) (int64, error) {
	ck, err := r.Cookie(pending2FACookieName)
	if err != nil || ck.Value == "" {
		return 0, ErrNoPending2FA
	}
	raw, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil || len(raw) != pendingPayloadLen+sha256.Size {
		return 0, ErrNoPending2FA
	}
	payload := raw[:pendingPayloadLen]
	sig := raw[pendingPayloadLen:]

	mac := hmac.New(sha256.New, s.pendingHMACKey)
	mac.Write(payload)
	want := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sig, want) != 1 {
		return 0, ErrNoPending2FA
	}
	adminID := int64(binary.BigEndian.Uint64(payload[0:8]))
	exp := int64(binary.BigEndian.Uint64(payload[8:16]))
	if adminID <= 0 || exp <= nowUnix() {
		return 0, ErrNoPending2FA
	}
	return adminID, nil
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

// IssueCSRFToken 在 GET 渲染表单页时调用:生成 32 字节随机 token,写到一个
// 非 HttpOnly cookie(让 JS 也能读 —— htmx 之类的可选,主要靠模板渲染到 hidden field)。
//
// 同时返回 token 给模板,作为 hidden input 的 value。
//
// 模式:double-submit cookie。POST 时校验 cookie value === form value 即可,
// 不需要服务端 state。前提:cookie SameSite=Lax 让跨站 form post 不带 cookie。
//
// K4(2026-05-23):**强制新签**只在没有合法 cookie 时使用。常规渲染请走
// EnsureCSRFToken,避免「GET 页面 + 浏览器并发 favicon GET → 二次签发覆盖
// → form 里嵌的旧 token 与 cookie 不一致」的经典坑(实测复现:点登录按钮
// 直接 403 "CSRF: token 不匹配")。
func (s *SessionService) IssueCSRFToken(w http.ResponseWriter) (string, error) {
	token, err := generateRandomToken(32)
	if err != nil {
		return "", err
	}
	s.writeCSRFCookie(w, token)
	return token, nil
}

// EnsureCSRFToken:有合法 cookie 就复用,否则新签。**所有渲染表单的 GET handler
// 都应该用这个版本而不是 IssueCSRFToken**。复用保证「同一个浏览器视图里 form
// hidden field 与浏览器 cookie 值始终一致」,即便页面在加载过程中触发了
// 多次 GET(favicon、redirect 回环)也不会被覆盖错位。
//
// 合法 = base64url 字符 + 长度落在 [32,128] 区间(IssueCSRFToken 写的就是 43 字符)。
// 不做更严格的格式校验,因为本身就是不可猜测的随机串,长度即抗碰撞性。
func (s *SessionService) EnsureCSRFToken(r *http.Request, w http.ResponseWriter) (string, error) {
	if ck, err := r.Cookie(csrfCookieName); err == nil &&
		len(ck.Value) >= 32 && len(ck.Value) <= 128 {
		// 刷新 cookie 的 MaxAge 让有效期顺延,但 value 不变。
		s.writeCSRFCookie(w, ck.Value)
		return ck.Value, nil
	}
	return s.IssueCSRFToken(w)
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
// 返回 nil → 通过;否则 handler 应回 403 + 描述。
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

func clientIP(r *http.Request) string {
	// X-Forwarded-For 由前置反代设置;若直接绑公网就只剩 RemoteAddr。
	// 不信任 XFF 是默认安全姿态(otherwise admin 可通过伪造 XFF 把审计搞乱)。
	// 这里 *只* 在 trust_proxy_header=true 时才解析,目前 hardcoded false。
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	// IPv6 RemoteAddr 形如 [::1]:1234,strip 括号。
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

func nowUnix() int64 {
	return time.Now().Unix()
}
