package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWithCommonHeaders_CSPNonce 锁死第十一轮深扫 LOW(保留项)的 CSP 硬化不变量:
//   - script-src 不再含 'unsafe-inline';
//   - script-src 带一个 per-request 的 'nonce-<x>';
//   - 该 nonce 与注入到 request context 的值(renderPage 会填进 PageData.Nonce,模板内联
//     <script nonce="{{.Nonce}}"> 用)**逐字一致** —— 否则页面所有内联脚本会被浏览器 CSP 拦;
//   - 每个请求的 nonce 互不相同(不可预测)。
func TestWithCommonHeaders_CSPNonce(t *testing.T) {
	var ctxNonce string
	h := withCommonHeaders(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctxNonce = cspNonceFromCtx(r.Context())
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("缺少 Content-Security-Policy 头")
	}

	// 提取 script-src 指令段。
	var scriptSrc string
	for _, d := range strings.Split(csp, ";") {
		d = strings.TrimSpace(d)
		if strings.HasPrefix(d, "script-src") {
			scriptSrc = d
			break
		}
	}
	if scriptSrc == "" {
		t.Fatalf("CSP 无 script-src 指令: %q", csp)
	}
	if strings.Contains(scriptSrc, "'unsafe-inline'") {
		t.Fatalf("script-src 仍含 'unsafe-inline'(硬化被回退): %q", scriptSrc)
	}
	if ctxNonce == "" {
		t.Fatal("request context 未注入 CSP nonce")
	}
	if !strings.Contains(scriptSrc, "'nonce-"+ctxNonce+"'") {
		t.Fatalf("script-src 的 nonce 与 ctx 注入值不一致\n  script-src=%q\n  ctxNonce=%q", scriptSrc, ctxNonce)
	}

	// 第二个请求应拿到不同的 nonce(每请求随机)。
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))
	nonce2 := ctxNonce
	if strings.Contains(rec2.Header().Get("Content-Security-Policy"), "'nonce-"+nonce2+"'") && nonce2 == "" {
		t.Fatal("第二请求 nonce 为空")
	}
	// 重新读取:ctxNonce 已被第二请求覆盖,直接比较两次响应头里的 nonce 段。
	if extractNonce(t, rec.Header().Get("Content-Security-Policy")) ==
		extractNonce(t, rec2.Header().Get("Content-Security-Policy")) {
		t.Fatal("两次请求的 CSP nonce 相同(应每请求随机)")
	}
}

// extractNonce 从 CSP 头里抠出 script-src 的 'nonce-<x>' 值(测试辅助)。
func extractNonce(t *testing.T, csp string) string {
	t.Helper()
	const marker = "'nonce-"
	i := strings.Index(csp, marker)
	if i < 0 {
		t.Fatalf("CSP 无 nonce: %q", csp)
	}
	rest := csp[i+len(marker):]
	j := strings.Index(rest, "'")
	if j < 0 {
		t.Fatalf("CSP nonce 未闭合: %q", csp)
	}
	return rest[:j]
}
