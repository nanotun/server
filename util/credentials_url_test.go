package util

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestEncodeCredentialsURL_Roundtrip — P2#5(2026-05-26):
//
// 把 5 字段都填非空 / 非零,EncodeCredentialsURL → 拆 prefix → base64url decode →
// json.Unmarshal,确认每个字段字节级回传无误。这是本包的核心约定 — Rust 客户端
// 完全靠这条契约从 server 出来的 QR 反解出原始字段。
func TestEncodeCredentialsURL_Roundtrip(t *testing.T) {
	in := &CredentialsSchema{
		Version:   CredentialsSchemaVersion,
		ID:        "0d4b1c4e-3a2f-4f7e-9c8d-12345678abcd",
		Username:  "alice",
		PSK:       "ALPHA-BRAVO-CHARLIE-DELTA-ECHO",
		CreatedAt: 1716530400,
		Host:      "203.0.113.10",
		ServerID:  "1d2e3f4a-5b6c-4d7e-8f90-abcdef012345",
	}
	url, err := EncodeCredentialsURL(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.HasPrefix(url, CredentialsURLPrefix) {
		t.Fatalf("url 缺 prefix:%q", url)
	}
	payload := strings.TrimPrefix(url, CredentialsURLPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("base64url decode: %v", err)
	}
	var out CredentialsSchema
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json unmarshal: %v\npayload=%q", err, raw)
	}
	if out.Version != in.Version {
		t.Fatalf("version: got=%d want=%d", out.Version, in.Version)
	}
	if out.ID != in.ID {
		t.Fatalf("id: %q vs %q", out.ID, in.ID)
	}
	if out.Username != in.Username {
		t.Fatalf("username: %q vs %q", out.Username, in.Username)
	}
	if out.PSK != in.PSK {
		t.Fatalf("psk: %q vs %q", out.PSK, in.PSK)
	}
	if out.CreatedAt != in.CreatedAt {
		t.Fatalf("created_at: %d vs %d", out.CreatedAt, in.CreatedAt)
	}
	if out.Host != in.Host {
		t.Fatalf("host: %q vs %q", out.Host, in.Host)
	}
	if out.ServerID != in.ServerID {
		t.Fatalf("server_id: %q vs %q", out.ServerID, in.ServerID)
	}
}

// TestEncodeCredentialsURL_EmptyHostServerID — host / server_id 都允许为空字符串
// (server 未设 advertised_host;或 db 跑 0014 migrate 之前),wire format 不应因此 fail,
// 且解出来的 out.Host / out.ServerID 必须等于空字符串(不是 nil / 不是缺失)。
func TestEncodeCredentialsURL_EmptyHostServerID(t *testing.T) {
	in := &CredentialsSchema{
		Version:   CredentialsSchemaVersion,
		ID:        "0d4b1c4e-3a2f-4f7e-9c8d-12345678abcd",
		Username:  "alice",
		PSK:       "ALPHA-BRAVO-CHARLIE-DELTA-ECHO",
		CreatedAt: 1716530400,
	}
	url, err := EncodeCredentialsURL(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	payload := strings.TrimPrefix(url, CredentialsURLPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var out CredentialsSchema
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Host != "" {
		t.Fatalf("空 host 应保持空字符串,got=%q", out.Host)
	}
	if out.ServerID != "" {
		t.Fatalf("空 server_id 应保持空字符串,got=%q", out.ServerID)
	}
}

// TestEncodeCredentialsURL_LongUsernameAndPSK — base64url + JSON 均无内置长度限制,
// 验证「8KB 左右的极端 username / PSK」也能 roundtrip。
//
// 现实上 username 通常 ≤ 64,PSK ~62;但仓库里没有显式检查,要保证 wire format
// 没有「在某个长度临界点出 panic / 截断」的退化行为。
func TestEncodeCredentialsURL_LongUsernameAndPSK(t *testing.T) {
	longUser := strings.Repeat("a", 4096)
	longPSK := strings.Repeat("Z", 4096)
	in := &CredentialsSchema{
		Version:   CredentialsSchemaVersion,
		ID:        "11111111-1111-4111-8111-111111111111",
		Username:  longUser,
		PSK:       longPSK,
		CreatedAt: 9999999999,
	}
	url, err := EncodeCredentialsURL(in)
	if err != nil {
		t.Fatalf("encode long: %v", err)
	}
	payload := strings.TrimPrefix(url, CredentialsURLPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode long: %v", err)
	}
	var out CredentialsSchema
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal long: %v", err)
	}
	if len(out.Username) != 4096 || out.Username != longUser {
		t.Fatalf("username 长度 / 内容失真:got len=%d", len(out.Username))
	}
	if len(out.PSK) != 4096 || out.PSK != longPSK {
		t.Fatalf("psk 长度 / 内容失真:got len=%d", len(out.PSK))
	}
}

// TestEncodeCredentialsURL_NilSchema — defensive contract:nil 必须返回 error,
// 不 panic。caller 在 prod 里有 fallback 路径(handler_users.go::buildCredentialsURLAndQR
// 拿到 err 会渲染空 QR + warn 日志),所以 nil → error 是显式契约。
func TestEncodeCredentialsURL_NilSchema(t *testing.T) {
	_, err := EncodeCredentialsURL(nil)
	if err == nil {
		t.Fatalf("nil schema 应返回 error")
	}
}

// TestDecodeCredentialsURL_RejectInvalidBase64 — 客户端 / 老备份 / 第三方工具
// 偶尔会拼出非法 base64url(`nanotun-cred://v1?d=!!!@@@`),解码方必须明确报错而
// 不是 panic / 拼出垃圾 schema。
//
// 当前 util 包未提供 Decode helper,本测试通过手工拆 prefix + base64 + json 走一遍
// 链路;若未来补 DecodeCredentialsURL,本测试可直接换成 helper 调用。
func TestDecodeCredentialsURL_RejectInvalidBase64(t *testing.T) {
	url := CredentialsURLPrefix + "!!!invalid-base64-payload!!!"
	payload := strings.TrimPrefix(url, CredentialsURLPrefix)
	if _, err := base64.RawURLEncoding.DecodeString(payload); err == nil {
		t.Fatalf("非法 base64url 应被 reject(payload=%q)", payload)
	}
}

// TestDecodeCredentialsURL_RejectInvalidJSON — payload 是合法 base64url 但反解
// 不是合法 JSON(随机字节),json.Unmarshal 必须报错。
func TestDecodeCredentialsURL_RejectInvalidJSON(t *testing.T) {
	garbage := []byte{0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03}
	url := CredentialsURLPrefix + base64.RawURLEncoding.EncodeToString(garbage)
	payload := strings.TrimPrefix(url, CredentialsURLPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode base64 失败:%v", err)
	}
	var out CredentialsSchema
	if err := json.Unmarshal(raw, &out); err == nil {
		t.Fatalf("非 JSON payload 应被 reject")
	}
}
