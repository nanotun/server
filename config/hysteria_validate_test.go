package config

import (
	"strings"
	"testing"
)

// hy2 的两组校验此前一条都没被测过。它们各自防一件事:
// 凭证校验防「半配」和弱口令 —— hy2 是单密码认证,password 就是全部的门禁;
// 调优校验防「越界值让 server 在重启时 Fatal」—— 这些字段平时没人动,一动就是
// 在排查性能问题的时候,那正是最不希望服务起不来的时刻。

func TestValidateHysteriaCredentials_AllOrNothingAndNoWeakPassword(t *testing.T) {
	const okPW = "0123456789abcdef" // 正好 16 字节
	cases := []struct {
		name    string
		cfg     HysteriaConfig
		wantErr string
		because string
	}{
		{"三项全空 = 不启用 hy2", HysteriaConfig{}, "", ""},
		{"三项配齐", HysteriaConfig{Password: okPW, TLSCertFile: "/c.pem", TLSKeyFile: "/k.pem"}, "", ""},

		{"只配密码", HysteriaConfig{Password: okPW}, "须同时配置",
			"半配起不来监听,而运维会以为 hy2 已经在跑"},
		{"只配证书", HysteriaConfig{TLSCertFile: "/c.pem"}, "须同时配置", ""},
		{"配了密码和证书,漏了私钥", HysteriaConfig{Password: okPW, TLSCertFile: "/c.pem"}, "须同时配置", ""},
		{"空白不算配置", HysteriaConfig{Password: "   ", TLSCertFile: "/c.pem", TLSKeyFile: "/k.pem"}, "须同时配置",
			"只有空白的密码等于没配,不能让它凑数把三项凑齐"},

		{"密码 15 字节", HysteriaConfig{Password: strings.Repeat("a", 15), TLSCertFile: "/c.pem", TLSKeyFile: "/k.pem"},
			"至少 16 字节", "hy2 只有这一道门,短口令等于敞开"},
		{"密码正好 16 字节", HysteriaConfig{Password: okPW, TLSCertFile: "/c.pem", TLSKeyFile: "/k.pem"}, "",
			"边界上应当放行"},
		{"空格凑不出足够长的密码", HysteriaConfig{Password: "      short       ", TLSCertFile: "/c.pem", TLSKeyFile: "/k.pem"},
			"至少 16 字节",
			"这串带空格 18 字节、trim 后只有 5 字节。按未 trim 的长度算就会放过一个 5 字节口令"},

		{"obfs 密码但没配 hy2", HysteriaConfig{ObfsSalamanderPassword: "abcd"}, "须先配齐",
			"混淆是 hy2 之上的一层,单独开没有意义"},
		{"obfs 密码太短", HysteriaConfig{Password: okPW, TLSCertFile: "/c.pem", TLSKeyFile: "/k.pem",
			ObfsSalamanderPassword: "abc"}, "至少 4 字节", "库本身的下限,配短了是启动期报错"},
		{"obfs 密码正好 4 字节", HysteriaConfig{Password: okPW, TLSCertFile: "/c.pem", TLSKeyFile: "/k.pem",
			ObfsSalamanderPassword: "abcd"}, "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			err := cfg.ValidateHysteriaCredentials()
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
				t.Fatalf("错误里应提到 %q,实际 %v", tc.wantErr, err)
			}
		})
	}
}

// HysteriaActive 决定 hy2 到底起不起。它和凭证校验必须自洽:凡是能通过校验且非空的
// 配置,Active 就该为真;凡是 Active 为真的,校验一定得放行过。两者错位的后果是
// 「校验说没配、实际却在监听」或者反过来。
func TestHysteriaActive_AgreesWithCredentialValidation(t *testing.T) {
	const okPW = "0123456789abcdef"
	cases := []struct {
		name       string
		cfg        HysteriaConfig
		wantActive bool
	}{
		{"三项齐 → 启用", HysteriaConfig{Password: okPW, TLSCertFile: "/c.pem", TLSKeyFile: "/k.pem"}, true},
		{"全空 → 不启用", HysteriaConfig{}, false},
		{"只有密码 → 不启用", HysteriaConfig{Password: okPW}, false},
		{"证书是空白 → 不启用", HysteriaConfig{Password: okPW, TLSCertFile: " ", TLSKeyFile: "/k.pem"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if got := cfg.HysteriaActive(); got != tc.wantActive {
				t.Fatalf("HysteriaActive=%v,want %v", got, tc.wantActive)
			}
			if cfg.HysteriaActive() && cfg.ValidateHysteriaCredentials() != nil {
				t.Fatal("判定为启用,凭证校验却不放行 —— server 会带着一份「校验说非法」的配置去监听")
			}
		})
	}
}

func TestValidateHysteriaTuning_ZeroMeansLibraryDefault(t *testing.T) {
	cases := []struct {
		name       string
		cfg        HysteriaConfig
		wantReject bool
		because    string
	}{
		{"全零 = 全用库默认", HysteriaConfig{}, false,
			"没人动过调优字段的配置必须永远通过"},

		{"stream 初始窗口太小", HysteriaConfig{QUICInitialStreamRecvWindow: 1024}, true, ""},
		{"stream 初始窗口恰好 16384", HysteriaConfig{QUICInitialStreamRecvWindow: 16384}, false, "边界放行"},
		{"stream 最大窗口太小", HysteriaConfig{QUICMaxStreamRecvWindow: 1}, true, ""},
		{"conn 初始窗口太小", HysteriaConfig{QUICInitialConnRecvWindow: 1}, true, ""},
		{"conn 最大窗口太小", HysteriaConfig{QUICMaxConnRecvWindow: 1}, true, ""},

		{"空闲超时太短", HysteriaConfig{QUICMaxIdleTimeoutSec: 3}, true,
			"低于 4 秒会让正常连接被反复判死重连"},
		{"空闲超时太长", HysteriaConfig{QUICMaxIdleTimeoutSec: 121}, true, ""},
		{"空闲超时在区间内", HysteriaConfig{QUICMaxIdleTimeoutSec: 30}, false, ""},

		{"并发流太少", HysteriaConfig{QUICMaxIncomingStreams: 7}, true, ""},
		{"并发流恰好 8", HysteriaConfig{QUICMaxIncomingStreams: 8}, false, ""},

		{"上行带宽帽太低", HysteriaConfig{BandwidthMaxTxBps: 1000}, true,
			"低于 64 kbps 的帽子等于把链路掐死"},
		{"下行带宽帽太低", HysteriaConfig{BandwidthMaxRxBps: 1000}, true, ""},

		{"UDP 空闲超时越界但没开 relay", HysteriaConfig{UDPIdleTimeoutSec: 1}, false,
			"没开 UDP 转发时这个字段不生效,不该因此拒绝启动"},
		{"开了 relay 且超时太短", HysteriaConfig{UDPRelayEnabled: true, UDPIdleTimeoutSec: 1}, true, ""},
		{"开了 relay 且超时太长", HysteriaConfig{UDPRelayEnabled: true, UDPIdleTimeoutSec: 601}, true, ""},
		{"开了 relay 且超时为 0", HysteriaConfig{UDPRelayEnabled: true}, false, "0 仍然表示用库默认"},

		{"MTU 太小", HysteriaConfig{MTU: 1199}, true, ""},
		{"MTU 太大", HysteriaConfig{MTU: 9217}, true, ""},
		{"MTU 在区间内", HysteriaConfig{MTU: 1400}, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			err := cfg.ValidateTuning()
			if tc.wantReject != (err != nil) {
				t.Fatalf("err=%v,want reject=%v(%s)", err, tc.wantReject, tc.because)
			}
		})
	}
}
