package config

import (
	"strings"
	"testing"
)

// 这一整个文件的职责是「重启前把会让 server 拒绝启动的配置拦下来」——`config lint`
// 靠它预演启动期的 fail-fast。它本身此前一条语句都没被测过。
//
// 判松和判紧的代价不对称但都很实在:判松,一份能过 lint 的配置在真正重启时 Fatal,
// lint 的全部价值就没了(而运维往往是在维护窗口里才重启,发现时已经停机);判紧,
// 明明能跑的配置被拦在门外。更隐蔽的是「lint 放行、server 也启动、但语义被静默降级」
// 那一类——jump_host 的两个校验防的正是这个。

func TestPoWConfigValidate_ZeroMeansDefaultAndOrderMustHold(t *testing.T) {
	cases := []struct {
		name    string
		cfg     PoWConfig
		wantErr string // 空 = 应通过;否则要求错误里含这个片段
		because string
	}{
		{"全缺省", PoWConfig{}, "",
			"一份没写 [server.pow] 的配置永远该通过,零值一律走默认 8/14/2/22/300"},

		{"合法的一组", PoWConfig{BaseDifficulty: 10, RampDifficulty: 16, AdaptiveCeiling: 20,
			StepPerFailure: 3, TTLSec: 120, FailuresEnable: 2}, "", ""},

		{"base 低于下界", PoWConfig{BaseDifficulty: 3}, "base_difficulty",
			"低于 4 位难度等于没有 PoW,挡不住任何撞库"},
		{"base 高于上界", PoWConfig{BaseDifficulty: 23}, "base_difficulty",
			"22 位已经是 iPhone 算 15 秒,再高就是把正常用户挡在外面"},
		{"ramp 越界", PoWConfig{RampDifficulty: 100}, "ramp_difficulty", ""},
		{"ceiling 越界", PoWConfig{AdaptiveCeiling: 1}, "adaptive_ceiling", ""},
		{"负难度也算越界", PoWConfig{BaseDifficulty: -5}, "base_difficulty",
			"负数不是「未配」,只有 0 才是"},

		{"failures_enable 为负", PoWConfig{FailuresEnable: -1}, "failures_enable", ""},
		{"step_per_failure 为负", PoWConfig{StepPerFailure: -1}, "step_per_failure",
			"负步长意味着失败越多难度越低"},
		{"ttl_sec 为负", PoWConfig{TTLSec: -1}, "ttl_sec", ""},

		{"ramp 低于 base", PoWConfig{BaseDifficulty: 16, RampDifficulty: 10}, "必须 ≥",
			"倒置意味着「失败之后反而更好算」,自适应升级形同虚设"},
		{"ceiling 低于 ramp", PoWConfig{RampDifficulty: 20, AdaptiveCeiling: 10}, "必须 ≥",
			"天花板比 ramp 还低,难度永远升不上去"},
		{"缺省 base 与显式低 ramp 的组合", PoWConfig{RampDifficulty: 5}, "必须 ≥",
			"顺序要在「零值→默认」解析之后比:base 缺省是 8,ramp=5 就是倒置。" +
				"只比显式值的话这份配置会被放过"},
		{"缺省 ceiling 不该误报", PoWConfig{BaseDifficulty: 20, RampDifficulty: 22}, "",
			"ceiling 缺省是 22,等于 ramp 不算倒置"},

		{"越界优先于顺序报错", PoWConfig{BaseDifficulty: 99, RampDifficulty: 10}, "越界",
			"先查区间再查顺序:拿被污染的值去比大小,报出来的顺序错误会把人带偏"},
		{"越界时不该同时抱怨顺序", PoWConfig{BaseDifficulty: 99, RampDifficulty: 10}, "!必须 ≥",
			"base=99 本身就非法,再报一句「ramp 必须 ≥ base(99)」只会让人去改 ramp"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("应通过,却报 %v(%s)", err, tc.because)
				}
				return
			}
			if err == nil {
				t.Fatalf("应报错(含 %q),却通过了 —— %s", tc.wantErr, tc.because)
			}
			if neg, ok := strings.CutPrefix(tc.wantErr, "!"); ok {
				if strings.Contains(err.Error(), neg) {
					t.Fatalf("错误里不该提到 %q(%s),实际 %v", neg, tc.because, err)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误里应提到 %q,实际 %v", tc.wantErr, err)
			}
		})
	}
}

// TLS 证书与私钥是对外 HTTPS/WSS 的同一个开关,半配等于监听起不来。
func TestServerConfigValidateTLSPair_BothOrNeither(t *testing.T) {
	cases := []struct {
		name       string
		cert, key  string
		wantReject bool
	}{
		{"都留空", "", "", false},
		{"都配齐", "/etc/c.pem", "/etc/k.pem", false},
		{"只配证书", "/etc/c.pem", "", true},
		{"只配私钥", "", "/etc/k.pem", true},
		{"私钥只有空白 = 没配", "/etc/c.pem", "   ", true},
		{"证书只有空白 = 没配", "\t\n", "/etc/k.pem", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ServerConfig{TLSCertFile: tc.cert, TLSKeyFile: tc.key}.ValidateTLSPair()
			if tc.wantReject != (err != nil) {
				t.Fatalf("cert=%q key=%q → err=%v,want reject=%v", tc.cert, tc.key, err, tc.wantReject)
			}
		})
	}
}

// jump_host_allowed_ips 的校验防的是「以为开了限制、实际没有」和「以为放行了、实际被自锁」。
//
// 后者尤其阴:runtime 的 sanitizeJumpHostIPv4s 对 CIDR / 主机名 / IPv6 一律静默丢弃,
// 名单被丢空之后退化成只允许 127.0.0.1 —— 运维配的那台跳板机连不上,而日志里什么都没有。
func TestServerConfigValidateJumpHostFirewall_RejectsWhatRuntimeWouldSilentlyDrop(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		ips     []string
		wantErr string
		because string
	}{
		{"没启用就不管", false, nil, "", "关掉时这个字段完全被忽略"},
		{"没启用时非法条目也不管", false, []string{"垃圾"}, "", ""},

		{"启用但名单为空", true, nil, "必须",
			"空名单 + 开 firewall = 「以为开了限制、实际全网开放」"},
		{"启用且名单合法", true, []string{"203.0.113.7", "198.51.100.9"}, "", ""},
		{"空白项被容忍", true, []string{" ", "203.0.113.7", ""}, "",
			"与 runtime skip 空串的行为一致"},

		{"CIDR 被拒", true, []string{"203.0.113.0/24"}, "不是合法 IPv4",
			"runtime 静默丢弃 CIDR。放它过 lint,运维会以为整个网段都放行了"},
		{"主机名被拒", true, []string{"jump.example.com"}, "不是合法 IPv4",
			"同上,而且 DNS 会变,名单不能依赖它"},
		{"IPv6 被拒", true, []string{"2001:db8::1"}, "不是合法 IPv4",
			"ipset 建的是 family inet,v6 进不去"},
		{"混着一个非法项也拒", true, []string{"203.0.113.7", "not-an-ip"}, "不是合法 IPv4",
			"部分非法比全非法更危险:剩下的那些还能连,问题要等到用那台跳板机时才暴露"},
		{"全是空白项", true, []string{"  ", "\t"}, "全是空白",
			"等价于空名单,退化成只允许 127.0.0.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ServerConfig{JumpHostFirewall: tc.enabled, JumpHostAllowedIPs: tc.ips}.ValidateJumpHostFirewall()
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

// protected_ports 里任一条目写错,对应的那些端口就不会被保护 —— 而 hy2 UDP / REALITY
// 恰恰是最容易写错的两项。runtime 对非法条目只 Warn 后跳过,所以这道校验必须在启动前拦住。
func TestServerConfigValidateJumpHostProtectedPorts_AnyBadEntryIsFatal(t *testing.T) {
	cases := []struct {
		name       string
		enabled    bool
		ports      []string
		wantReject bool
		because    string
	}{
		{"没启用就不校验", false, []string{"完全是垃圾"}, false,
			"关掉 firewall 时这个字段被完全忽略"},
		{"列表为空", true, nil, false,
			"清空 = 沿用历史默认「只保护 listen_addr TCP」,是个有意的选择"},

		{"单端口", true, []string{"tcp/8443"}, false, ""},
		{"短横线区间", true, []string{"udp/5000-5002"}, false, ""},
		{"冒号区间", true, []string{"udp/5000:5002"}, false, ""},
		{"大小写不敏感", true, []string{"TCP/8443", "UDP/443"}, false, ""},
		{"空白项容忍", true, []string{" ", "tcp/8443"}, false, ""},

		{"缺斜杠", true, []string{"tcp8443"}, true, ""},
		{"斜杠在开头", true, []string{"/8443"}, true, ""},
		{"斜杠在结尾", true, []string{"tcp/"}, true, ""},
		{"proto 不认识", true, []string{"sctp/8443"}, true,
			"iptables 那条规则会因为 -p sctp 而语义完全不同"},
		{"端口不是数字", true, []string{"tcp/http"}, true, ""},
		{"端口为 0", true, []string{"tcp/0"}, true, ""},
		{"端口超界", true, []string{"tcp/65536"}, true, ""},
		{"结束端口非法", true, []string{"udp/5000-99999"}, true,
			"整条被跳过,那一段 port hopping 全部裸奔"},
		{"混着一个错的也拒", true, []string{"tcp/8443", "udp/oops"}, true,
			"部分保护比完全不保护更误导:iptables 里看得见规则,只是少了几条"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ServerConfig{JumpHostFirewall: tc.enabled, JumpHostProtectedPorts: tc.ports}.
				ValidateJumpHostProtectedPorts()
			if tc.wantReject != (err != nil) {
				t.Fatalf("%v → err=%v,want reject=%v(%s)", tc.ports, err, tc.wantReject, tc.because)
			}
		})
	}
}

// TUN 网段写反族是最容易犯又最难自查的错:两个字段名字只差 _v6,而 CIDR 本身语法都合法,
// 所以只查「是不是合法 CIDR」的校验放它过去,直到启动时撞上「该族无可用网段」才 Fatal。
func TestTUNConfigValidateTUNSubnets_CatchesEmptyAndSwappedFamilies(t *testing.T) {
	cases := []struct {
		name    string
		cfg     TUNConfig
		wantErr string
		because string
	}{
		{"只配 v4", TUNConfig{Subnets: []string{"10.80.0.0/16"}}, "", ""},
		{"只配 v6", TUNConfig{SubnetsV6: []string{"fd00:80::/64"}}, "", ""},
		{"两族都配", TUNConfig{Subnets: []string{"10.80.0.0/16"}, SubnetsV6: []string{"fd00:80::/64"}}, "", ""},

		{"两个都空", TUNConfig{}, "至少配置一项",
			"数据面没有地址池,谁也分不到 vIP"},
		{"两个都只有空白", TUNConfig{Subnets: []string{" "}, SubnetsV6: []string{""}}, "至少配置一项", ""},

		{"v6 段写进了 subnets", TUNConfig{Subnets: []string{"fd00:80::/64"}}, "应放到 [tun].subnets_v6",
			"语法完全合法,只是放错了字段 —— 只查 CIDR 语法的校验抓不住"},
		{"v4 段写进了 subnets_v6", TUNConfig{SubnetsV6: []string{"10.80.0.0/16"}}, "应放到 [tun].subnets", ""},
		{"两边都写反", TUNConfig{Subnets: []string{"fd00:80::/64"}, SubnetsV6: []string{"10.80.0.0/16"}},
			"应放到", "把两个字段整体对调是最常见的写法错误"},

		{"语法错的 CIDR 交给别人报", TUNConfig{Subnets: []string{"这不是CIDR"}, SubnetsV6: []string{"fd00::/64"}}, "",
			"族校验只补「族」这一维,语法由 Config.Validate 的 checkCIDRs 负责,两边都报会刷屏"},
		{"subnets_v6 里语法错的也交给别人报", TUNConfig{Subnets: []string{"10.80.0.0/16"}, SubnetsV6: []string{"也不是CIDR"}}, "", ""},
		{"subnets_v6 里的空白项跳过", TUNConfig{Subnets: []string{"10.80.0.0/16"}, SubnetsV6: []string{"  ", "fd00::/64"}}, "",
			"与 subnets 一侧同口径"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.ValidateTUNSubnets()
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

// smux 的负值字段:三处「不能为负」此前只覆盖了一部分。这些值会被直接喂给 smux 的
// VerifyConfig,越界时**每条连接**都建不起来 —— 数据面整体不可用,而错误只在连接时
// 才出现,启动日志干干净净。
func TestValidateSmux_NegativesAreRejectedBeforeTheyReachSmux(t *testing.T) {
	cases := []struct {
		name       string
		cfg        SmuxConfig
		wantReject bool
		because    string
	}{
		{"全零 = 全用默认", SmuxConfig{}, false, "没配 [smux] 的配置必须永远通过"},

		{"keepalive interval 为负", SmuxConfig{KeepAliveIntervalSec: -1}, true, ""},
		{"keepalive timeout 为负", SmuxConfig{KeepAliveTimeoutSec: -1}, true, ""},
		{"max_stream_buffer 为负", SmuxConfig{MaxStreamBuffer: -1}, true, ""},
		{"max_receive_buffer 为负", SmuxConfig{MaxReceiveBuffer: -1}, true, ""},

		{"interval 不小于 timeout", SmuxConfig{KeepAliveIntervalSec: 30, KeepAliveTimeoutSec: 30}, true,
			"相等也不行:判死逻辑要求 interval 严格小于 timeout,否则永远来不及发下一次心跳"},
		{"interval 小于 timeout", SmuxConfig{KeepAliveIntervalSec: 10, KeepAliveTimeoutSec: 30}, false, ""},
		{"只配了一个不比较", SmuxConfig{KeepAliveIntervalSec: 30}, false, "另一个走默认,不该拿零去比"},

		{"stream buffer 超过 receive buffer", SmuxConfig{MaxStreamBuffer: 1 << 20, MaxReceiveBuffer: 1 << 10}, true, ""},
		{"version 非法", SmuxConfig{Version: 3}, true, ""},
		{"max_frame_size 超过 16 位", SmuxConfig{MaxFrameSize: 65536}, true, "smux 帧长字段就是 16 位"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errs []string
			cfg := tc.cfg
			validateSmux(&cfg, &errs)
			if tc.wantReject != (len(errs) > 0) {
				t.Fatalf("errs=%v,want reject=%v(%s)", errs, tc.wantReject, tc.because)
			}
		})
	}
}
