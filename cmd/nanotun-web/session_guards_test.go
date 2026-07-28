package main

// session_guards_test.go(第二十轮)—— session / pending-2FA / CSRF 的失败侧,
// 以及 clientIP 那一串解析辅助函数的边界。
//
// session_test.go 与 session_pending_test.go 已经把正路和「换 IP 重放」「密码轮换
// 作废在途 pending」钉死了。这里补的都是「出错时会不会静默降级」:
//
//   - 四个 HMAC key 生成失败必须 panic。全零 key 等于把 pending-2FA / captcha /
//     PoW / CSRF 的签名能力公开发放 —— 谁都能自己签一张,2FA 与 CSRF 同时失效;
//   - session id / pending nonce 生成失败必须让整个登录失败,不能发出空 token
//     (空 token 会让「未鉴权」被当成「已登录」);
//   - pending cookie 的每种畸形(长度不对、adminID<=0、已过期)都要拒;
//   - clientIP 的解析链在各种奇怪输入下都要落到「直连对端」这个安全默认,
//     不能因为解析失败就返回空串(空 IP 会让按 IP 的限流/锁定整体失效)。

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// stubRandRead 把随机源换成「第 n 次调用起开始报错」。
// 返回 nil 之外还写满缓冲区:真实的 crypto/rand 故障也可能返回半截数据,
// 这样才能验证是那个 err 拦住了流程,而不是靠下游的空值校验兜住。
func stubRandRead(t *testing.T, failFrom int) {
	t.Helper()
	orig := randRead
	calls := 0
	randRead = func(b []byte) (int, error) {
		calls++
		if calls >= failFrom {
			for i := range b {
				b[i] = 0x41
			}
			return len(b), errors.New("注入的随机数故障")
		}
		return orig(b)
	}
	t.Cleanup(func() { randRead = orig })
}

// abortStoreWrites 与 abortSQLiteWrites 同款,但直接吃 *store.Store ——
// 本文件里大多数用例只需要 store 与 SessionService,不必立起整个 Server。
func abortStoreWrites(t *testing.T, st *store.Store, name, table, op, when string) {
	t.Helper()
	cond := ""
	if when != "" {
		cond = " WHEN " + when
	}
	sql := "CREATE TRIGGER " + name + " BEFORE " + op + " ON " + table + cond +
		" BEGIN SELECT RAISE(ABORT, 'injected: " + name + "'); END"
	if _, err := st.DB().ExecContext(t.Context(), sql); err != nil {
		t.Fatalf("装故障触发器 %s: %v", name, err)
	}
	t.Cleanup(func() { _, _ = st.DB().Exec("DROP TRIGGER IF EXISTS " + name) })
}

// pendingReqWith 手工签一张指定 adminID / exp 的 pending cookie。
// 这两段都被 HMAC 覆盖,所以不能靠改 base64 字节来造 —— 那样验签会先失败,
// 就测不到「adminID<=0」「已过期」这两条判断本身了。
func pendingReqWith(t *testing.T, sess *SessionService, adminID, exp int64, ip string) *http.Request {
	t.Helper()
	var payload [pendingPayloadLen]byte
	binary.BigEndian.PutUint64(payload[0:8], uint64(adminID))
	binary.BigEndian.PutUint64(payload[8:16], uint64(exp))
	value := base64.RawURLEncoding.EncodeToString(
		append(payload[:], sess.pendingMAC(payload[:], ip)...))

	r := httptest.NewRequest(http.MethodPost, "/login/totp", nil)
	r.RemoteAddr = ip + ":1234"
	r.AddCookie(&http.Cookie{Name: sess.cookieName(pending2FACookieName), Value: value})
	return r
}

// -------------------------------------------------------------------------
// 四个 HMAC key
// -------------------------------------------------------------------------

// 任何一个 key 生成失败都必须 panic。这是刻意的:全零(或半截)key 意味着
// pending-2FA / captcha / PoW / CSRF 的签名谁都能造 —— 与其带着这种进程继续
// 服务,不如起不来让运维立刻发现。
func TestNewSessionService_KeyFailurePanics(t *testing.T) {
	for _, tc := range []struct {
		nth  int
		want string
	}{
		{1, "pending"},
		{2, "captcha"},
		{3, "pow"},
		{4, "csrf"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			st := newTestStore(t)
			stubRandRead(t, tc.nth)
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("随机数故障却照常构造出了 SessionService(等于用一把可预测的 key 在签名)")
				}
				msg, _ := r.(string)
				if !strings.Contains(msg, tc.want) {
					t.Fatalf("panic 信息没说清是哪把 key: %q", msg)
				}
			}()
			_ = NewSessionService(st, defaultConfig())
		})
	}
}

// -------------------------------------------------------------------------
// IssueSession
// -------------------------------------------------------------------------

func TestIssueSession_TokenFailureIssuesNothing(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	hash, _ := HashWebPassword("strongPass1!aa")
	a, err := st.CreateWebAdmin(t.Context(), store.NewWebAdmin{Username: "z", PasswordHash: hash})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	stubRandRead(t, 1) // service 已构造完,这次失败的就是 session id

	w := httptest.NewRecorder()
	sid, err := sess.IssueSession(t.Context(), w, a.ID, "10.0.0.1", "ua")
	if err == nil {
		t.Fatal("随机数故障却颁出了 session")
	}
	if sid != "" {
		t.Fatalf("失败时还返回了 sid=%q", sid)
	}
	if ck := w.Header().Get("Set-Cookie"); ck != "" {
		t.Fatalf("失败时仍写了 cookie: %q", ck)
	}
}

// 会话封顶(prune)是 best-effort:删不动只该记一行日志,不能让本次登录失败 ——
// 会话已经建成了,这时候报错等于「登录成功但告诉你没成功」。
func TestIssueSession_PruneFailureStillLogsIn(t *testing.T) {
	st := newTestStore(t)
	cfg := defaultConfig()
	cfg.SessionTTLSec = 3600
	sess := NewSessionService(st, cfg)
	hash, _ := HashWebPassword("strongPass1!aa")
	a, err := st.CreateWebAdmin(t.Context(), store.NewWebAdmin{Username: "z", PasswordHash: hash})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	// 先塞满上限,让 prune 真的会去删行;再让删除失败。
	for i := 0; i < maxConcurrentWebSessionsPerAdmin+1; i++ {
		w := httptest.NewRecorder()
		if _, err := sess.IssueSession(t.Context(), w, a.ID, "10.0.0.1", "ua"); err != nil {
			t.Fatalf("第 %d 次颁发: %v", i, err)
		}
	}
	abortStoreWrites(t, st, "no_session_delete", "web_sessions", "DELETE", "")

	w := httptest.NewRecorder()
	sid, err := sess.IssueSession(t.Context(), w, a.ID, "10.0.0.1", "ua")
	if err != nil {
		t.Fatalf("封顶失败不该让登录失败: %v", err)
	}
	if sid == "" || !strings.Contains(w.Header().Get("Set-Cookie"), sessionCookieName) {
		t.Fatal("没写出 session cookie")
	}
	if _, err := st.GetWebSession(t.Context(), sid); err != nil {
		t.Fatalf("会话没落库: %v", err)
	}
}

// -------------------------------------------------------------------------
// pending-2FA cookie
// -------------------------------------------------------------------------

func TestIssueTOTPPending_RefusesBadInput(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())

	for _, id := range []int64{0, -1} {
		w := httptest.NewRecorder()
		if err := sess.IssueTOTPPending(w, id, "10.0.0.1", "hash"); err == nil {
			t.Errorf("adminID=%d 也签出了 pending", id)
		}
		if ck := w.Header().Get("Set-Cookie"); ck != "" {
			t.Errorf("adminID=%d 失败却写了 cookie: %q", id, ck)
		}
	}

	stubRandRead(t, 1)
	w := httptest.NewRecorder()
	if err := sess.IssueTOTPPending(w, 7, "10.0.0.1", "hash"); err == nil {
		t.Fatal("nonce 生成失败却签出了 pending")
	}
	if ck := w.Header().Get("Set-Cookie"); ck != "" {
		t.Fatalf("nonce 失败却写了 cookie: %q", ck)
	}
}

// 畸形 / 过期 / adminID 非法的 pending 一律拒,且错误统一 —— 不能让攻击者从
// 错误差异里推断出「载荷改到哪一位才通过」。
func TestLookupTOTPPending_MalformedCookiesAreRejected(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	const ip = "10.0.0.9"

	// 先拿一张合法的,用来做「只改某一段」的底板。
	w := httptest.NewRecorder()
	if err := sess.IssueTOTPPending(w, 7, ip, "hash"); err != nil {
		t.Fatalf("IssueTOTPPending: %v", err)
	}
	good := w.Result().Cookies()[0].Value

	cases := []struct{ name, value string }{
		{"空值", ""},
		{"不是 base64", "!!!not-base64!!!"},
		{"长度不对(短一截)", good[:len(good)-8]},
		{"长度不对(多一截)", good + "AAAA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/login/totp", nil)
			r.RemoteAddr = ip + ":1234"
			if tc.value != "" {
				r.AddCookie(&http.Cookie{Name: sess.cookieName(pending2FACookieName), Value: tc.value})
			}
			if _, _, _, err := sess.LookupTOTPPending(r); !errors.Is(err, ErrNoPending2FA) {
				t.Fatalf("err=%v, 期望 ErrNoPending2FA", err)
			}
		})
	}

	// adminID<=0 与已过期:这两段都在 HMAC 覆盖范围内,所以要按同样的方式
	// 重新签一张(不能靠改 base64 字节 —— 那样验签就先挂了,测不到这两条判断)。
	t.Run("adminID 为 0", func(t *testing.T) {
		r := pendingReqWith(t, sess, 0, nowUnix()+60, ip)
		if _, _, _, err := sess.LookupTOTPPending(r); !errors.Is(err, ErrNoPending2FA) {
			t.Fatalf("err=%v, 期望 ErrNoPending2FA", err)
		}
	})
	t.Run("已过期", func(t *testing.T) {
		r := pendingReqWith(t, sess, 7, nowUnix()-1, ip)
		if _, _, _, err := sess.LookupTOTPPending(r); !errors.Is(err, ErrNoPending2FA) {
			t.Fatalf("err=%v, 期望 ErrNoPending2FA", err)
		}
	})
}

func TestMarkPendingConsumed_EmptyNonceIsNotAConsumption(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	// 空 nonce 必须直接判否。若返回 true,「找不到 nonce 的畸形 pending」就会被
	// 当成首次消费放行,一次性语义整体失效。
	if sess.MarkPendingConsumed("") {
		t.Fatal("空 nonce 被当成了一次合法消费")
	}
}

// -------------------------------------------------------------------------
// CSRF
// -------------------------------------------------------------------------

// token 的形状是 `<nonce>.<签名>`。缺了点号、点号在头尾,都不该进到签名比对
// (更不该被当成合法)。
func TestCSRFValidFor_MalformedTokenShapes(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	for _, tok := range []string{"", ".", "nodot", ".leading", "trailing.", "a.b.c"} {
		if sess.csrfValidFor(tok, "") {
			t.Errorf("畸形 token %q 被判为合法", tok)
		}
	}
	// 形状对但签名不对(换了一把 key 才可能产生的值)也要拒。
	if sess.csrfValidFor("nonce.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "") {
		t.Error("签名不符的 token 被判为合法")
	}
}

func TestIssueCSRFToken_TokenFailureWritesNoCookie(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	stubRandRead(t, 1)

	w := httptest.NewRecorder()
	tok, err := sess.IssueCSRFToken(httptest.NewRequest(http.MethodGet, "/login", nil), w)
	if err == nil {
		t.Fatal("随机数故障却签出了 CSRF token")
	}
	if tok != "" {
		t.Fatalf("失败时还返回了 token=%q", tok)
	}
	if ck := w.Header().Get("Set-Cookie"); ck != "" {
		t.Fatalf("失败时仍写了 cookie: %q", ck)
	}
}

// -------------------------------------------------------------------------
// 小工具:token 长度、UA 截断、IP 解析
// -------------------------------------------------------------------------

func TestGenerateRandomToken_RejectsNonPositiveLength(t *testing.T) {
	for _, n := range []int{0, -1} {
		if tok, err := generateRandomToken(n); err == nil {
			t.Errorf("n=%d 也生成了 token=%q", n, tok)
		}
	}
}

func TestTruncate_CutsAtLimit(t *testing.T) {
	if got := truncate("abcdef", 3); got != "abc" {
		t.Errorf("truncate 超长: %q", got)
	}
	if got := truncate("ab", 3); got != "ab" {
		t.Errorf("truncate 不该动没超长的: %q", got)
	}
}

func TestHostFromAddr_AndParseHostIP(t *testing.T) {
	hostCases := []struct{ in, want string }{
		{"10.0.0.1:1234", "10.0.0.1"},
		{"[2001:db8::1]:1234", "2001:db8::1"},
		{"10.0.0.1", "10.0.0.1"},         // 没端口:按裸地址处理
		{"[2001:db8::1]", "2001:db8::1"}, // 有括号没端口:括号要剥掉
		{"  10.0.0.1  ", "10.0.0.1"},
	}
	for _, tc := range hostCases {
		if got := hostFromAddr(tc.in); got != tc.want {
			t.Errorf("hostFromAddr(%q) = %q, 期望 %q", tc.in, got, tc.want)
		}
	}

	ipCases := []struct {
		in   string
		want string // "" = 解析不出来
	}{
		{"10.0.0.1", "10.0.0.1"},
		{"10.0.0.1:80", "10.0.0.1"},
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]:80", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"}, // 括号无端口:走最后那条兜底分支
		{"::ffff:10.0.0.1", "10.0.0.1"},  // v4-mapped 要 Unmap,否则前缀匹配对不上
		{"", ""},
		{"   ", ""},
		{"not-an-ip", ""},
		{"10.0.0.1:notaport", ""},
	}
	for _, tc := range ipCases {
		got, ok := parseHostIP(tc.in)
		if tc.want == "" {
			if ok {
				t.Errorf("parseHostIP(%q) 竟然解析成了 %v", tc.in, got)
			}
			continue
		}
		if !ok || got.String() != tc.want {
			t.Errorf("parseHostIP(%q) = (%v, %v), 期望 %q", tc.in, got, ok, tc.want)
		}
	}
}

// 零值地址不能被判成「落在可信反代内」—— 那等于让解析失败的输入拿到反代特权,
// 于是伪造的 XFF 就会被采信。
func TestIPInTrustedProxy_InvalidAddrIsNever(t *testing.T) {
	restore := trustedProxyNets
	trustedProxyNets = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	t.Cleanup(func() { trustedProxyNets = restore })

	if ipInTrustedProxy(netip.Addr{}) {
		t.Fatal("零值地址被判成了可信反代(即使前缀是 0.0.0.0/0 也不该)")
	}
}

// 可信反代场景下 XFF 的几种退化输入都要落回直连对端,不能返回空串 ——
// 空 IP 会让按 IP 的失败计数与锁定全部记到同一个「空」桶里。
func TestClientIP_DegradesToDirectPeer(t *testing.T) {
	restore := trustedProxyNets
	trustedProxyNets = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	t.Cleanup(func() { trustedProxyNets = restore })

	cases := []struct {
		name string
		xff  []string
		want string
	}{
		{"没有 XFF", nil, "127.0.0.1"},
		{"XFF 是空串", []string{""}, "127.0.0.1"},
		{"XFF 全是空白", []string{"   ,  "}, "127.0.0.1"},
		{"XFF 全是垃圾", []string{"junk, alsojunk"}, "127.0.0.1"},
		// 全是可信反代 → 取最左那个(离真实客户端最近)。
		{"XFF 全是可信反代", []string{"127.0.0.9, 127.0.0.8"}, "127.0.0.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "127.0.0.1:5555"
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := clientIP(r); got != tc.want {
				t.Fatalf("clientIP = %q, 期望 %q", got, tc.want)
			}
		})
	}
}
