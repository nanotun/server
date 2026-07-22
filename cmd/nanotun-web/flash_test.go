package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestFlashFromQuery_RequiresValidSignature 覆盖第三轮深扫 L5:
//   - 无签名 / 伪造签名的 ?flash= 一律不渲染(挡站内钓鱼横幅);
//   - flashRedirect 签发的 flash 能被正确校验并渲染;
//   - flash_kind 被篡改后签名失配 → 丢弃。
func TestFlashFromQuery_RequiresValidSignature(t *testing.T) {
	// 无签名:攻击者手拼的 ?flash= 必须被丢弃。
	r := httptest.NewRequest(http.MethodGet, "/users?flash=Your+key+expired&flash_kind=err", nil)
	if f := flashFromQuery(r); f != nil {
		t.Fatalf("未签名 flash 应被丢弃,got %+v", f)
	}

	// 伪造签名。
	r = httptest.NewRequest(http.MethodGet, "/users?flash=hi&flash_sig=deadbeef", nil)
	if f := flashFromQuery(r); f != nil {
		t.Fatalf("伪造签名 flash 应被丢弃,got %+v", f)
	}

	// 合法签名(经 flashQuery 生成)应渲染。
	qs := flashQuery("操作成功", "ok")
	r = httptest.NewRequest(http.MethodGet, "/users?"+qs, nil)
	f := flashFromQuery(r)
	if f == nil || f.Text != "操作成功" || f.Kind != "ok" {
		t.Fatalf("合法签名 flash 应渲染,got %+v", f)
	}

	// warn 级别签名也应通过且保留 kind。
	qsWarn := flashQuery("重载失败", "warn")
	r = httptest.NewRequest(http.MethodGet, "/routes?"+qsWarn, nil)
	f = flashFromQuery(r)
	if f == nil || f.Kind != "warn" {
		t.Fatalf("warn flash 应渲染并保留 kind,got %+v", f)
	}

	// 篡改 flash_kind(ok→err):签名是按 ok 算的,改成 err 后校验用 err 复算 → 失配 → 丢弃。
	sig := flashSig("操作成功", "ok")
	tampered := "flash=" + url.QueryEscape("操作成功") + "&flash_kind=err&flash_sig=" + sig
	r = httptest.NewRequest(http.MethodGet, "/users?"+tampered, nil)
	if f := flashFromQuery(r); f != nil {
		t.Fatalf("篡改 flash_kind 后应丢弃,got %+v", f)
	}
}
