package config

import (
	"strings"
	"testing"
)

// dest 是 REALITY 的伪装落点:握手不通过的连接会被**原样**转发过去,让扫描者看到一个
// 真实的第三方站点。这个字段配错的后果不是「功能不可用」,而是伪装破功 —— 非法客户端
// 拿到的是一个奇怪的 TCP 错误,而不是预期中那个网站的正常响应,主动探测一试就露。
//
// 校验 dest 与其余几项的分支此前都没被走到过。

func TestValidateRealityDest_RejectsWhatWouldBreakTheDisguise(t *testing.T) {
	cases := []struct {
		name    string
		dest    string
		wantErr string
		because string
	}{
		{"域名带端口", "www.microsoft.com:443", "", ""},
		{"IP 带端口", "93.184.216.34:443", "", ""},
		{"IPv6 带端口", "[2606:2800:220:1:248:1893:25c8:1946]:443", "", ""},
		{"端口用服务名", "www.microsoft.com:https", "",
			"net.LookupPort 认得 https,底层 Dial 也认"},
		{"前后空白容忍", "  www.microsoft.com:443  ", "", ""},

		{"空", "", "不能为空", "没有落点,握手失败的连接无处可去"},
		{"只有空白", "   ", "不能为空", ""},
		{"缺端口", "www.microsoft.com", "host:port", "Dial 会直接报 missing port"},
		{"只有端口", ":443", "host 段为空",
			"fallback 落到本机 = 回环,扫描者会看到自己被打回来"},
		{"端口为 0", "www.microsoft.com:0", "越界",
			"Dial 报 unknown port,伪装当场失效"},
		{"端口非数字且不是服务名", "www.microsoft.com:notaport", "port 段非法", ""},
		{"端口超界", "www.microsoft.com:99999", "port", ""},
		{"多个冒号", "a:b:c", "host:port", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRealityDest(tc.dest)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("%q 应通过,却报 %v(%s)", tc.dest, err, tc.because)
				}
				return
			}
			if err == nil {
				t.Fatalf("%q 应报错(含 %q),却通过了 —— %s", tc.dest, tc.wantErr, tc.because)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%q 的错误应提到 %q,实际 %v", tc.dest, tc.wantErr, err)
			}
		})
	}
}

// server_names 与 short_ids 是握手的匹配面。空列表意味着**没有任何客户端能握手成功**,
// 所有连接都会静默回落到 dest —— 服务看上去在跑、端口也通,就是谁都连不上,
// 而且因为回落逻辑本身是正常的,日志里不会有任何异常。
func TestRealityConfig_Validate_HandshakeMatchingListsMustNotBeEmpty(t *testing.T) {
	const seed32 = "2pagi_xOuxmKJQNLl8lQ_Hh8kj7Nt8VUlV_lzGLk5Bg"
	base := func() RealityConfig {
		return RealityConfig{
			ListenAddr:  ":443",
			Dest:        "www.microsoft.com:443",
			PrivateKey:  seed32,
			ServerNames: []string{"www.microsoft.com"},
			ShortIds:    []string{""},
		}
	}

	cases := []struct {
		name    string
		mutate  func(*RealityConfig)
		wantErr string
		because string
	}{
		{"server_names 为空", func(c *RealityConfig) { c.ServerNames = nil }, "server_names 至少一项",
			"没有 SNI 可匹配,所有握手都回落到 dest,表现为「谁都连不上但服务是好的」"},
		{"server_names 含空项", func(c *RealityConfig) { c.ServerNames = []string{"a.com", "  "} },
			"含空项", "空 SNI 匹配不到任何东西,还会挡住排查视线"},
		{"short_ids 为空", func(c *RealityConfig) { c.ShortIds = nil }, "short_ids 至少一项",
			"空列表与「含一个空串」不是一回事:后者表示允许全 0 shortId,前者是谁都不允许"},
		{"short_ids 含空串是允许的", func(c *RealityConfig) { c.ShortIds = []string{""} }, "",
			"这是「允许全 0 shortId」的显式写法"},
		{"short_ids 长度为奇数", func(c *RealityConfig) { c.ShortIds = []string{"aab"} }, "short_ids[0]",
			"截不成整字节"},
		{"short_ids 超过 8 字节", func(c *RealityConfig) { c.ShortIds = []string{strings.Repeat("ab", 9)} },
			"short_ids[0]", ""},
		{"dest 非法会被带上下文报出来", func(c *RealityConfig) { c.Dest = "www.microsoft.com" }, "dest:",
			"错误要指明是哪个字段,否则一堆校验混在一起没法定位"},
		{"private_key 非法", func(c *RealityConfig) { c.PrivateKey = "太短了" }, "private_key:", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("应通过,却报 %v(%s)", err, tc.because)
				}
				return
			}
			if err == nil {
				t.Fatalf("应报错(含 %q),却通过了 —— %s", tc.wantErr, tc.because)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误应提到 %q,实际 %v", tc.wantErr, err)
			}
		})
	}
}

// 私钥与 mldsa seed 都要求「解码后正好 32 字节」,且四种 Base64 变体都得认 —— 运维从
// 不同工具拷出来的 key 编码风格不一样(带不带 padding、用不用 URL 字母表),
// 只认一种的话会出现「明明是同一把钥匙,换个地方拷就起不来」。
func TestDecodeRealityKeys_AcceptAllBase64FlavoursButExactly32Bytes(t *testing.T) {
	// 同一把 32 字节钥匙的四种写法。
	const (
		rawURL = "2pagi_xOuxmKJQNLl8lQ_Hh8kj7Nt8VUlV_lzGLk5Bg"
		stdPad = "2pagi/xOuxmKJQNLl8lQ/Hh8kj7Nt8VUlV/lzGLk5Bg="
	)
	for _, dec := range []struct {
		name string
		fn   func(string) ([]byte, error)
	}{
		{"private_key", DecodeRealityPrivateKey},
		{"mldsa65_seed", DecodeRealityMldsa65Seed},
	} {
		t.Run(dec.name, func(t *testing.T) {
			for _, in := range []string{rawURL, stdPad, "  " + rawURL + "  "} {
				b, err := dec.fn(in)
				if err != nil {
					t.Fatalf("%q 应能解码: %v", in, err)
				}
				if len(b) != 32 {
					t.Fatalf("%q 解出 %d 字节,应为 32", in, len(b))
				}
			}
			for _, bad := range []struct{ in, why string }{
				{"", "空值"},
				{"   ", "只有空白"},
				{"YWJj", "解码只有 3 字节 —— 长度不对的 key 会让握手全部失败"},
				{"这不是base64", "根本解不开"},
				{rawURL + "AAAA", "解码超过 32 字节"},
			} {
				if _, err := dec.fn(bad.in); err == nil {
					t.Errorf("%q 应报错(%s)", bad.in, bad.why)
				}
			}
		})
	}
}

// StrictCheck 的两条错误路径要分得开:未知字段要给出「疑似拼写错误」的指引(这是它
// 存在的理由 —— exit_dns_redirect 拼错过一次,静默失效),而语法/类型错要原样透传,
// 不能被包装成「未知字段」把人往错方向带。
func TestStrictCheck_UnknownFieldVersusPlainParseError(t *testing.T) {
	if err := StrictCheck([]byte("[server]\nlisten_addr = \":8080\"\n")); err != nil {
		t.Fatalf("合法配置应通过: %v", err)
	}

	err := StrictCheck([]byte("[server]\nlisten_addrr = \":8080\"\n"))
	if err == nil {
		t.Fatal("拼错的字段名应被拦下 —— 静默忽略正是这个检查要防的")
	}
	if !strings.Contains(err.Error(), "未知字段") {
		t.Fatalf("未知字段的报错应当点明是拼写问题,实际 %v", err)
	}

	// 类型错:字段名对,值的类型不对。
	err = StrictCheck([]byte("[server]\nlisten_addr = 8080\n"))
	if err == nil {
		t.Fatal("类型错应报错")
	}
	if strings.Contains(err.Error(), "未知字段") {
		t.Fatalf("类型错被包装成了「未知字段」,会让人去查字段名而不是值:%v", err)
	}
}
