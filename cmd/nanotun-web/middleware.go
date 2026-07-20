package main

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// M2:中间件层。
//
// 责任拆分:
//   - withCommonHeaders: 安全 headers + 隐藏 server signature;
//   - withRecover: 任何 handler panic 都包成 500,不让 process 倒;
//   - withRequestLog: 一行 access log,便于排错;
//   - requireAuth: 没 session → 302 /login + back;
//   - requireRole: admin / viewer 权限分流;
//   - requireCSRF: 写方法的 CSRF 校验。

// ctxKey 用来在 request context 里挂登录信息。避免直接污染全局。
type ctxKey int

const (
	ctxKeyAdmin ctxKey = iota + 1
	ctxKeySessionID
	ctxKeyCSRFToken
	ctxKeyLang
)

func adminFromCtx(ctx context.Context) *store.WebAdmin {
	if v, ok := ctx.Value(ctxKeyAdmin).(*store.WebAdmin); ok {
		return v
	}
	return nil
}

func csrfTokenFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyCSRFToken).(string); ok {
		return v
	}
	return ""
}

// withCommonHeaders 给每个响应加上安全头。CSP 用最严格策略:
// 自身脚本/样式 + 内联(模板里有少量 inline JS / style)+ 同源资源,
// 拒绝远程 CDN。img-src 放宽到 data: 让 QR / base64 内嵌图片能用。
func withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"img-src 'self' data:; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"font-src 'self' data:; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'")
		next.ServeHTTP(w, r)
	})
}

// withRecover 把 handler panic 包成 500。
func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logrus.WithField("panic", rec).WithField("path", r.URL.Path).Error("[web] panic")
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestCounter 简单的全局请求计数,/metrics 暴露。
var (
	totalRequests  atomic.Uint64
	totalErrors4xx atomic.Uint64
	totalErrors5xx atomic.Uint64
)

// statusRecorder 包一层 ResponseWriter 拿状态码。
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// withRequestLog 打一行 access log。query string 截短,避免 PSK 之类敏感东西
// 被无意写到磁盘(handler 自己不应该把 secret 放 query,但兜底)。
func withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalRequests.Add(1)
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		switch {
		case rec.status >= 500:
			totalErrors5xx.Add(1)
		case rec.status >= 400:
			totalErrors4xx.Add(1)
		}
		logrus.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"status": rec.status,
			"bytes":  rec.bytes,
			"ip":     clientIP(r),
		}).Debug("[web] req")
	})
}

// requireAuth 包装一个 handler,使其只对已登录用户开放。
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admin, ws, err := s.sess.LookupSession(r.Context(), r)
		if err != nil {
			// 未登录:GET 重定向到 /login?next=...,其它方法直接 401。
			if r.Method == http.MethodGet {
				next := r.URL.RequestURI()
				if next == "/" || strings.HasPrefix(next, "/login") {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				http.Redirect(w, r,
					"/login?next="+urlQueryEscape(next), http.StatusFound)
				return
			}
			http.Error(w, tr(r, "httpErr.notLoggedIn"), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyAdmin, admin)
		ctx = context.WithValue(ctx, ctxKeySessionID, ws.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireCSRFAndAuth = requireAuth + 写方法前 CSRF 校验 + 注入 csrf token 到 ctx 给模板用。
func (s *Server) requireCSRFAndAuth(next http.Handler) http.Handler {
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 总是为 GET 准备一个 csrf token,即便不渲染表单也无害(cookie 续期)。
		// K4(2026-05-23):用 EnsureCSRFToken 而不是 IssueCSRFToken — 已有合法
		// cookie 时复用,避免「同一个 view 里浏览器并发触发多次 GET(favicon、
		// 自动 redirect)→ form hidden field 嵌的是旧 token,cookie 已被覆盖
		// 成新值,POST 时一致性校验直接失败」。
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			tok, err := s.sess.EnsureCSRFToken(r, w)
			if err == nil {
				ctx := context.WithValue(r.Context(), ctxKeyCSRFToken, tok)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// 极少失败(rand 错),退化为不带 token 也能继续渲染。
			next.ServeHTTP(w, r)
			return
		}

		if err := s.sess.VerifyCSRFToken(r); err != nil {
			// 2026-05-27 第二十四轮 P3-1:原 `http.Error` 返回纯文本 403,admin 看到
			// 浏览器原生灰底「CSRF: token 不匹配」字符串完全不知发生了什么。改用
			// `renderError` 走 error.html,带原版 header / 主题 / 「返回首页」CTA。
			//
			// 典型触发场景:admin 长时间空闲 → 会话过期 → cookie 里 csrf token 被服务
			// 重新签发 → form 里 hidden field 仍是旧 token → 401 比 403 准确,但因为
			// 历史 admin 可能仍登录(只是 csrf 不匹配),保留 403 + 引导刷新页面更友好。
			s.renderError(w, r, http.StatusForbidden,
				tr(r, "csrf.sessionExpiredWrap", trErr(r, err)))
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// urlQueryEscape 是 net/url.QueryEscape 的极简内联版,避免拉整个 url 包。
func urlQueryEscape(s string) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' || c == '/' || c == ':' {
			out = append(out, c)
			continue
		}
		out = append(out, '%', hex[c>>4], hex[c&0xF])
	}
	return string(out)
}
