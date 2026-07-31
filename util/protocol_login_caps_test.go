package util

import (
	"encoding/json"
	"strings"
	"testing"
)

// LoginReq 的字段长度上限是**认证前**的闸门:这个函数解析的是任何能连上端口的人送来的
// 第一帧,校验发生在鉴权之前。所以这十二条 `if n > max` 是攻击面上的第一道墙,而它们
// 之前一条都没被执行过 —— 单测只走正常路径,e2e 送的是合法客户端构造的报文。
//
// 坏掉的样子是静默的:某条上限被删掉、或比较号写反,不会有任何东西变红,只是从此
// 允许未认证方塞一个超长字段进来(注释自己写的动机是「64KB 字符串到处搬运」)。
//
// 每条都测两侧:
//   - 恰好等于上限 → 必须**放行**。只测「超长被拒」的话,`>` 改成 `>=` 照样绿,
//     而那会把合法的边界值请求误拒(name 正好 128 字符的用户从此登不上)。
//   - 上限 + 1 → 必须**拒绝**,且错误里点名是哪个字段(运维要靠这行日志认出恶意客户端)。
//
// 逐字段单独一条用例,是为了让「删掉其中一条上限」这种变异被精确抓住 —— 合在一起
// 用一个大 payload 测的话,任一条存活都能让整体报错,十二条互相遮蔽。
func TestParseLoginReqLinkPayload_EnforcesEveryFieldLengthCap(t *testing.T) {
	for _, tc := range []struct {
		field string // 出错信息里应当出现的字段名
		max   int
		set   func(*LoginReq, string)
	}{
		{"name", maxLoginReqName, func(r *LoginReq, s string) { r.Name = s }},
		{"token", maxLoginReqToken, func(r *LoginReq, s string) { r.Token = s }},
		{"takeover_secret", maxLoginReqTakeoverSecret, func(r *LoginReq, s string) { r.TakeoverSecret = s }},
		{"takeover_session_id", maxLoginReqTakeoverSessionID, func(r *LoginReq, s string) { r.TakeoverSessionID = s }},
		{"device_uuid", maxLoginReqDeviceUUID, func(r *LoginReq, s string) { r.DeviceUUID = s }},
		{"device_name", maxLoginReqDeviceName, func(r *LoginReq, s string) { r.DeviceName = s }},
		{"platform", maxLoginReqShortEnum, func(r *LoginReq, s string) { r.Platform = s }},
		{"transport", maxLoginReqShortEnum, func(r *LoginReq, s string) { r.Transport = s }},
		{"purpose", maxLoginReqShortEnum, func(r *LoginReq, s string) { r.Purpose = s }},
		{"pow.cid", maxLoginReqPowCID, func(r *LoginReq, s string) { r.Pow.ChallengeID = s }},
		{"pow.salt", maxLoginReqPowSalt, func(r *LoginReq, s string) { r.Pow.Salt = s }},
		{"pow.signature", maxLoginReqPowSignature, func(r *LoginReq, s string) { r.Pow.Signature = s }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			atCap := LoginReq{}
			tc.set(&atCap, strings.Repeat("x", tc.max))
			raw, err := json.Marshal(atCap)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseLoginReqLinkPayload(raw); err != nil {
				t.Errorf("%s 恰好 %d 字符应放行,却被拒:%v —— 边界值合法请求被误杀", tc.field, tc.max, err)
			}

			tooLong := LoginReq{}
			tc.set(&tooLong, strings.Repeat("x", tc.max+1))
			raw, err = json.Marshal(tooLong)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseLoginReqLinkPayload(raw)
			if err == nil {
				t.Fatalf("%s 长 %d 字符(上限 %d)竟被放行 —— 未认证方可塞超长字段", tc.field, tc.max+1, tc.max)
			}
			if got != nil {
				t.Errorf("%s 被拒时不应同时返回解析结果(调用方可能误用),得到 %+v", tc.field, got)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("%s 的报错未点名字段,运维无从判断是哪一项:%v", tc.field, err)
			}
		})
	}
}

// TestParseLoginReqLinkPayload_RejectsMalformedJSON 非法 JSON 必须报错而不是返回半个对象。
func TestParseLoginReqLinkPayload_RejectsMalformedJSON(t *testing.T) {
	for _, raw := range []string{``, `{`, `{"name":}`, `[]`, `null-ish`} {
		got, err := ParseLoginReqLinkPayload([]byte(raw))
		if err == nil {
			t.Errorf("非法 JSON %q 竟解析成功,得到 %+v", raw, got)
		}
		if got != nil {
			t.Errorf("非法 JSON %q 报错时仍返回了对象 %+v", raw, got)
		}
	}
}

// TestParseTakenOverLinkPayload_EmptyVsMalformed 空负载是合法的(零值),畸形负载不是。
//
// 这两种情况长得很像却必须分开:takeover 通知允许不带 body,但「带了一个坏 body」
// 是协议违例。混为一谈的话,一个被截断的通知会被当成正常的零值通知处理。
func TestParseTakenOverLinkPayload_EmptyVsMalformed(t *testing.T) {
	m, err := ParseTakenOverLinkPayload(nil)
	if err != nil || m == nil {
		t.Fatalf("空负载应返回零值而非报错:m=%v err=%v", m, err)
	}
	if m, err := ParseTakenOverLinkPayload([]byte(`{"reason":`)); err == nil {
		t.Errorf("截断的 JSON 应报错,却返回 %+v", m)
	}
}

// TestParseLinkPayloads_RejectMalformedJSON 另外两个链路负载解析器的畸形输入。
func TestParseLinkPayloads_RejectMalformedJSON(t *testing.T) {
	if r, err := ParseLoginRespLinkPayload([]byte(`{"session_id":`)); err == nil {
		t.Errorf("LoginResp 截断 JSON 应报错,却返回 %+v", r)
	}
	if l, err := ParseConvSaltLiteLinkPayload([]byte(`{"dns_servers":`)); err == nil {
		t.Errorf("ConvSaltLite 截断 JSON 应报错,却返回 %+v", l)
	}
}

// TestConvSaltEffectiveDNS_NilAndEmpty 两种「没有 DNS」的输入都应得到 nil。
//
// 返回 nil 而不是空切片是有讲究的:调用方按 `len(eff) > 0` 决定要不要下发
// resolvectl,空切片和 nil 在这里等价,但返回 `[]string{}` 会让 JSON 序列化出 `[]`
// 而非省略字段。
func TestConvSaltEffectiveDNS_NilAndEmpty(t *testing.T) {
	if got := ConvSaltEffectiveDNS(nil); got != nil {
		t.Errorf("nil lite 应得 nil,得到 %#v", got)
	}
	if got := ConvSaltEffectiveDNS(&ConvSaltLite{}); got != nil {
		t.Errorf("两个 DNS 列表都空时应得 nil,得到 %#v", got)
	}
}

// TestSanitizeDNSServers_EmptyInputAndBlankEntries 空输入与空白项。
//
// 三个 Sanitize 变体各有一条「输入为空直接返回」的短路,以及一条「跳过空串」——
// 后者不是多余的:`net.ParseIP("")` 也返回 nil、同样会被跳过,但空串是配置里最常见的
// 脏数据(尾随逗号、占位行),显式跳过让意图明确。这里把三个变体一起钉住,免得
// 将来有人「简化」掉其中一个的短路而改变返回 nil / 空切片的语义。
func TestSanitizeDNSServers_EmptyInputAndBlankEntries(t *testing.T) {
	for name, fn := range map[string]func([]string) []string{
		"any": SanitizeDNSServers,
		"v4":  SanitizeDNSServersV4,
		"v6":  SanitizeDNSServersV6,
	} {
		if got := fn(nil); got != nil {
			t.Errorf("%s: nil 输入应得 nil,得到 %#v", name, got)
		}
		if got := fn([]string{}); got != nil {
			t.Errorf("%s: 空切片应得 nil,得到 %#v", name, got)
		}
		if got := fn([]string{"", "   ", "\t"}); got != nil {
			t.Errorf("%s: 全是空白项应得 nil,得到 %#v", name, got)
		}
	}

	if got := SanitizeDNSServers([]string{"", "223.5.5.5"}); len(got) != 1 || got[0] != "223.5.5.5" {
		t.Errorf("空串应被跳过而不影响后续项,得到 %#v", got)
	}
}

// TestSplitDNSByIPVersion_SkipsUnparsable 直接测这个包内 helper 自己的契约。
//
// 为什么不通过 ParseConvSaltLiteLinkPayload 间接测:唯一的调用点传进来的是
// `SanitizeDNSServers(...)` 的输出,非法项在那一步就被滤掉了 —— 也就是说
// `ip == nil → continue` 这条经由现有调用链**结构性不可达**。
//
// 那还测它做什么?因为这道防御是给**将来的第二个调用方**准备的:helper 不该假设
// 入参已被清洗过。直接调用它、钉住「非法项跳过而不是 panic 或塞进 v4」这条契约,
// 比留一条永不执行的分支要诚实 —— 也比为了覆盖率去伪造一条不存在的调用路径诚实。
func TestSplitDNSByIPVersion_SkipsUnparsable(t *testing.T) {
	v4, v6 := splitDNSByIPVersion([]string{"223.5.5.5", "dns.example.com", "2001:4860:4860::8844", "10.0.0", ""})
	if len(v4) != 1 || v4[0] != "223.5.5.5" {
		t.Errorf("v4 应只留合法项,得到 %#v", v4)
	}
	if len(v6) != 1 || v6[0] != "2001:4860:4860::8844" {
		t.Errorf("v6 应只留合法项,得到 %#v", v6)
	}
}

// TestParseConvSaltLite_LegacyFieldSplitsByFamily 旧字段 dns_servers 按族拆分。
func TestParseConvSaltLite_LegacyFieldSplitsByFamily(t *testing.T) {
	raw := []byte(`{"dns_servers":["223.5.5.5","dns.example.com","2001:4860:4860::8844","10.0.0"]}`)
	lite, err := ParseConvSaltLiteLinkPayload(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(lite.DNSServersV4) != 1 || lite.DNSServersV4[0] != "223.5.5.5" {
		t.Errorf("v4 应只留合法项,得到 %#v", lite.DNSServersV4)
	}
	if len(lite.DNSServersV6) != 1 || lite.DNSServersV6[0] != "2001:4860:4860::8844" {
		t.Errorf("v6 应只留合法项,得到 %#v", lite.DNSServersV6)
	}
}
