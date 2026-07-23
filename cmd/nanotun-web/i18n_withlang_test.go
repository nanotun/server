package main

// i18n_withlang_test.go - withLang 剥 ?lang= 重定向的开放重定向防护(第六轮深扫 HIGH)。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithLang_StripLangPreservesLegitPath(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := withLang(next)

	r := httptest.NewRequest(http.MethodGet, "/users/123?lang=en&x=1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 strip-lang redirect, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/users/123?x=1" {
		t.Fatalf("legit path should be preserved with lang stripped, got %q", loc)
	}
}

// 协议相对 path(//evil)必须被净化回落到 "/",不得原样作 Location(开放重定向)。
func TestWithLang_NeutralizesProtocolRelativeRedirect(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := withLang(next)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.URL.Path = "//evil.example/phish" // 模拟请求行 `GET //evil.example/phish?lang=en`
	r.URL.RawQuery = "lang=en"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if strings.HasPrefix(loc, "//") || strings.Contains(loc, "evil.example") {
		t.Fatalf("open redirect NOT neutralized, Location=%q", loc)
	}
	if loc != "/" {
		t.Fatalf("unsafe path should fall back to \"/\", got %q", loc)
	}
}

// 反斜杠 path(/\evil,浏览器可能归一成 //evil)也应被净化。
func TestWithLang_NeutralizesBackslashRedirect(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := withLang(next)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.URL.Path = `/\evil.example/phish`
	r.URL.RawQuery = "lang=zh"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if loc := w.Header().Get("Location"); strings.Contains(loc, "evil.example") {
		t.Fatalf("backslash open redirect NOT neutralized, Location=%q", loc)
	}
}
