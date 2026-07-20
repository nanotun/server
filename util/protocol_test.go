package util

import (
	"encoding/json"
	"testing"
)

func TestMarshalConvSaltLiteJSON_DNSv4v6Roundtrip(t *testing.T) {
	assignments := []VirtualIPAssignment{{VirtualIP: "10.200.0.2", Mask: "255.255.0.0", Gateway: "10.200.0.1/16"}}
	v4 := []string{" 223.5.5.5 ", "not-ip", "2001::1"}
	v6 := []string{"bad", "2001:4860:4860::8888"}
	raw, err := MarshalConvSaltLiteJSON(assignments, v4, v6, " lan ", " homepi-1 ")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseConvSaltLiteLinkPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNSServersV4) != 1 || parsed.DNSServersV4[0] != "223.5.5.5" {
		t.Fatalf("v4: %+v", parsed.DNSServersV4)
	}
	if len(parsed.DNSServersV6) != 1 || parsed.DNSServersV6[0] != "2001:4860:4860::8888" {
		t.Fatalf("v6: %+v", parsed.DNSServersV6)
	}
	if parsed.MagicDNSSuffix != "lan" {
		t.Fatalf("magic_dns_suffix: %q (want trimmed \"lan\")", parsed.MagicDNSSuffix)
	}
	if parsed.DeviceName != "homepi-1" {
		t.Fatalf("device_name: %q (want trimmed \"homepi-1\")", parsed.DeviceName)
	}
	eff := ConvSaltEffectiveDNS(parsed)
	if len(eff) != 2 || eff[0] != "223.5.5.5" || eff[1] != "2001:4860:4860::8888" {
		t.Fatalf("effective: %+v", eff)
	}
}

func TestParseConvSaltLite_LegacyDNSField(t *testing.T) {
	raw := []byte(`{"dns_servers":["223.5.5.5","2001:4860:4860::8844"]}`)
	lite, err := ParseConvSaltLiteLinkPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(lite.DNSServersV4) != 1 || lite.DNSServersV4[0] != "223.5.5.5" {
		t.Fatalf("v4: %+v", lite.DNSServersV4)
	}
	if len(lite.DNSServersV6) != 1 {
		t.Fatalf("v6: %+v", lite.DNSServersV6)
	}
}

func TestSanitizeDNSServers_AllInvalid(t *testing.T) {
	if SanitizeDNSServers([]string{"not-an-ip", ""}) != nil {
		t.Fatal("expected nil")
	}
	if SanitizeDNSServersV4([]string{"2001::1"}) != nil {
		t.Fatal("v4 expected nil")
	}
	if SanitizeDNSServersV6([]string{"8.8.8.8"}) != nil {
		t.Fatal("v6 expected nil")
	}
}

func TestMarshalConvSaltLiteJSON_OmitsEmptyDNS(t *testing.T) {
	raw, err := MarshalConvSaltLiteJSON(nil, nil, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["dns_servers_v4"]; ok {
		t.Fatal("expected omit dns_servers_v4")
	}
	if _, ok := m["dns_servers_v6"]; ok {
		t.Fatal("expected omit dns_servers_v6")
	}
	if _, ok := m["magic_dns_suffix"]; ok {
		t.Fatal("expected omit magic_dns_suffix")
	}
	if _, ok := m["device_name"]; ok {
		t.Fatal("expected omit device_name")
	}
}

// 老消息（无 takeover 相关字段）必须能正常解析，新字段为零值。
//
// 同时验证 P3-d:已下架的 "password" 字段不应再有 schema 字段对应,
// 但 encoding/json 默认会忽略 wire 上多出来的 key,所以仍然解析成功。
func TestParseLoginReq_LegacyHasNoTakeoverFields(t *testing.T) {
	raw := []byte(`{"name":"u","password":"p","type":"client","platform":"linux","transport":"hy2"}`)
	req, err := ParseLoginReqLinkPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if req.Purpose != "" || req.TakeoverSessionID != "" || req.TakeoverSecret != "" {
		t.Fatalf("legacy LoginReq should have empty takeover fields, got %+v", req)
	}
}

// P3-d:确保 MarshalLoginReqJSON 不再把 password 字段塞进 wire。
// 老 client 调用 MarshalLoginReqJSON(name, "stale-pw", token,...) 应当看不到 "password" 键。
func TestMarshalLoginReqJSON_DropsPasswordFromWire(t *testing.T) {
	raw, err := MarshalLoginReqJSON("alice", "should-be-dropped", "psk-tok", "client", "linux", "hy2")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["password"]; ok {
		t.Fatalf("wire 上不应再出现 password 字段,got=%s", raw)
	}
	if m["token"] != "psk-tok" {
		t.Fatalf("token 应当正常透传,got=%s", raw)
	}
}

func TestMarshalLoginReqWithDeviceJSON_DropsPasswordFromWire(t *testing.T) {
	raw, err := MarshalLoginReqWithDeviceJSON("alice", "should-be-dropped", "tok", "client", "linux", "hy2",
		"11111111-2222-4333-8444-555555555555", "alice-mac")
	if err != nil {
		t.Fatal(err)
	}
	if json.Valid(raw) == false {
		t.Fatalf("invalid json: %s", raw)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if _, ok := m["password"]; ok {
		t.Fatalf("wire 上不应再出现 password 字段,got=%s", raw)
	}
	if m["device_uuid"] == nil {
		t.Fatalf("device_uuid 应当正常透传,got=%s", raw)
	}
}

// 接管登录的 LoginReq 序列化与解析。
func TestLoginReq_TakeoverRoundtrip(t *testing.T) {
	want := LoginReq{
		Name:              "u",
		Token:             "tok",
		Type:              "client",
		Platform:          "linux",
		Transport:         "hy2",
		Purpose:           PurposeTakeover,
		TakeoverSessionID: "sid-123",
		TakeoverSecret:    "deadbeef",
	}
	raw, err := json.Marshal(&want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseLoginReqLinkPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Purpose != want.Purpose ||
		got.TakeoverSessionID != want.TakeoverSessionID ||
		got.TakeoverSecret != want.TakeoverSecret {
		t.Fatalf("takeover fields mismatch: got %+v want %+v", got, want)
	}
}

// MarshalLoginReqTakeoverJSON 应携带 purpose=takeover 与 takeover_session_id/secret，
// 且与 server handleTakeoverLogin 的解析路径互通（roundtrip）。
func TestMarshalLoginReqTakeoverJSON_RoundtripAndFields(t *testing.T) {
	raw, err := MarshalLoginReqTakeoverJSON(
		"", "", "ignored-token", "client", "linux", LinkTransportWebSocket,
		"sid-xyz", "deadbeef",
	)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"purpose", "takeover_session_id", "takeover_secret"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("takeover LoginReq should contain field %q, got %s", k, string(raw))
		}
	}
	got, err := ParseLoginReqLinkPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Purpose != PurposeTakeover {
		t.Fatalf("purpose: got %q want %q", got.Purpose, PurposeTakeover)
	}
	if got.TakeoverSessionID != "sid-xyz" || got.TakeoverSecret != "deadbeef" {
		t.Fatalf("takeover fields mismatch: %+v", got)
	}
	if got.Transport != LinkTransportWebSocket {
		t.Fatalf("transport: got %q want %q", got.Transport, LinkTransportWebSocket)
	}
}

// 常规登录构造的 LoginReq 不应序列化出空的 takeover 字段。
func TestMarshalLoginReqJSON_PrimaryOmitsTakeoverFields(t *testing.T) {
	raw, err := MarshalLoginReqJSON("u", "p", "", "client", "linux", LinkTransportTCP)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"purpose", "takeover_session_id", "takeover_secret"} {
		if _, ok := m[k]; ok {
			t.Fatalf("primary LoginReq should not contain field %q", k)
		}
	}
}

// 老 LoginResp（无 session_id / takeover_secret）必须能解析。
func TestParseLoginResp_LegacyHasNoSessionFields(t *testing.T) {
	raw := []byte(`{"code":0,"message":"ok","user_id":"u1"}`)
	resp, err := ParseLoginRespLinkPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resp.SessionID != "" || resp.TakeoverSecret != "" {
		t.Fatalf("legacy LoginResp should have empty session fields, got %+v", resp)
	}
}

// 新 LoginResp 包含 session_id / takeover_secret 的 roundtrip。
func TestLoginResp_SessionFieldsRoundtrip(t *testing.T) {
	want := LoginResp{
		Code:           0,
		Message:        "ok",
		UserID:         "u1",
		SessionID:      "sid-abc",
		TakeoverSecret: "ff00aa",
	}
	raw, err := json.Marshal(&want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseLoginRespLinkPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != want.SessionID || got.TakeoverSecret != want.TakeoverSecret {
		t.Fatalf("session fields mismatch: got %+v want %+v", got, want)
	}
}

// 现有 MarshalLoginRespJSON 不带新字段时不应输出 session_id / takeover_secret，保留向后兼容。
func TestMarshalLoginRespJSON_LegacyOmitsSessionFields(t *testing.T) {
	raw, err := MarshalLoginRespJSON(0, "ok", "u1")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"session_id", "takeover_secret"} {
		if _, ok := m[k]; ok {
			t.Fatalf("legacy MarshalLoginRespJSON should not contain field %q", k)
		}
	}
}

func TestTakenOverMsg_Roundtrip(t *testing.T) {
	raw, err := MarshalTakenOverJSON("sid-abc", "hy2")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTakenOverLinkPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.NewSessionID != "sid-abc" || got.NewTransport != "hy2" {
		t.Fatalf("taken over fields mismatch: %+v", got)
	}
}

// 空负载也应被接受（兼容未来可能下发空 TakenOver）。
func TestParseTakenOverLinkPayload_Empty(t *testing.T) {
	got, err := ParseTakenOverLinkPayload(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.NewSessionID != "" || got.NewTransport != "" {
		t.Fatalf("expected zero-value, got %+v", got)
	}
}
