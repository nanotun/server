package config

import "testing"

func TestConfigValidate(t *testing.T) {
	// 合法基线：应通过。
	good := Config{}
	good.Server.ListenAddr = ":8080"
	good.Server.UploadRate = 0
	good.TUN.Subnets = []string{"10.201.0.0/16"}
	good.TUN.SubnetsV6 = []string{"fd00:200::/64", ""} // 空串应被容忍
	if err := good.Validate(); err != nil {
		t.Fatalf("合法配置不应报错: %v", err)
	}

	cases := []struct {
		name string
		mut  func(c *Config)
	}{
		{"负 upload_rate", func(c *Config) { c.Server.UploadRate = -1 }},
		{"负 download_rate", func(c *Config) { c.Server.DownloadRate = -100 }},
		{"负 exit_forward_rate_bps", func(c *Config) { c.Server.ExitForwardRateBPS = -1 }},
		{"负 kcp upload_rate", func(c *Config) { c.KCP.UploadRate = -1 }},
		{"负 tcp download_rate", func(c *Config) { c.TCP.DownloadRate = -1 }},
		{"非法 subnet CIDR", func(c *Config) { c.TUN.Subnets = []string{"10.0.0.0/24", "garbage"} }},
		{"非法 subnet_v6 CIDR", func(c *Config) { c.TUN.SubnetsV6 = []string{"not-a-cidr"} }},
		{"非法 listen_addr", func(c *Config) { c.Server.ListenAddr = "no-colon" }},
		{"listen_addr 端口越界", func(c *Config) { c.Server.ListenAddr = ":70000" }},
		{"负 per-platform rate", func(c *Config) {
			c.Server.RateLimitByPlatform = map[string]LinkRateLimitPlatform{"linux": {UploadRate: -5}}
		}},
		{"smux version 非法", func(c *Config) { c.Smux = &SmuxConfig{Version: 3} }},
		{"smux max_frame_size 超 65535", func(c *Config) { c.Smux = &SmuxConfig{MaxFrameSize: 70000} }},
		{"smux max_frame_size 负", func(c *Config) { c.Smux = &SmuxConfig{MaxFrameSize: -1} }},
		{"smux stream > receive buffer", func(c *Config) {
			c.Smux = &SmuxConfig{MaxReceiveBuffer: 4096, MaxStreamBuffer: 8192}
		}},
		{"smux interval >= timeout", func(c *Config) {
			c.Smux = &SmuxConfig{KeepAliveIntervalSec: 30, KeepAliveTimeoutSec: 30}
		}},
		{"smux 负 receive buffer", func(c *Config) { c.Smux = &SmuxConfig{MaxReceiveBuffer: -1} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{}
			c.Server.ListenAddr = ":8080"
			c.TUN.Subnets = []string{"10.201.0.0/16"}
			tc.mut(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("%s 应校验失败但通过了", tc.name)
			}
		})
	}

	// MaxSessionsPerUser = -1（显式不限）不应被判为错误。
	ms := Config{}
	ms.Server.ListenAddr = ":8080"
	ms.TUN.Subnets = []string{"10.201.0.0/16"}
	ms.Server.MaxSessionsPerUser = -1
	if err := ms.Validate(); err != nil {
		t.Fatalf("MaxSessionsPerUser=-1 是合法「不限」值,不应报错: %v", err)
	}

	// 合法 smux 配置(含全零值 = 用默认)应通过。
	sm := Config{}
	sm.Server.ListenAddr = ":8080"
	sm.TUN.Subnets = []string{"10.201.0.0/16"}
	sm.Smux = &SmuxConfig{Version: 2, MaxFrameSize: 32768, MaxReceiveBuffer: 4 << 20, MaxStreamBuffer: 1 << 20, KeepAliveIntervalSec: 10, KeepAliveTimeoutSec: 30}
	if err := sm.Validate(); err != nil {
		t.Fatalf("合法 smux 配置不应报错: %v", err)
	}
}

// TestValidateTUNSubnets 第十六轮深扫 MED:两者皆空 → 报错;族错配(v6 in subnets / v4 in subnets_v6)→ 报错;
// 正确分族 + 仅 v4 / 仅 v6 / 空白项容忍 → 通过。
func TestValidateTUNSubnets(t *testing.T) {
	// 两者皆空(含仅空白项)。
	if err := (TUNConfig{}).ValidateTUNSubnets(); err == nil {
		t.Fatal("subnets 与 subnets_v6 皆空应报错")
	}
	if err := (TUNConfig{Subnets: []string{"  "}}).ValidateTUNSubnets(); err == nil {
		t.Fatal("仅空白项等同皆空,应报错")
	}
	// 族错配。
	if err := (TUNConfig{Subnets: []string{"fd00::/64"}}).ValidateTUNSubnets(); err == nil {
		t.Fatal("IPv6 CIDR 放进 subnets 应报错")
	}
	if err := (TUNConfig{SubnetsV6: []string{"10.0.0.0/8"}}).ValidateTUNSubnets(); err == nil {
		t.Fatal("IPv4 CIDR 放进 subnets_v6 应报错")
	}
	// 合法组合。
	for _, c := range []TUNConfig{
		{Subnets: []string{"10.201.0.0/16"}},
		{SubnetsV6: []string{"fd00:201::/64"}},
		{Subnets: []string{"10.201.0.0/16", "  "}, SubnetsV6: []string{"fd00:201::/64"}},
	} {
		if err := c.ValidateTUNSubnets(); err != nil {
			t.Fatalf("合法网段组合不应报错: %+v -> %v", c, err)
		}
	}
}

// TestReality_ValidateListenAddrFormat 第十六轮深扫 MED:REALITY 启用(listen_addr 非空)时 listen_addr 须是
// 合法 host:port;格式非法应报错。
func TestReality_ValidateListenAddrFormat(t *testing.T) {
	base := func(la string) *RealityConfig {
		return &RealityConfig{
			ListenAddr:  la,
			Dest:        "www.microsoft.com:443",
			PrivateKey:  "",
			ServerNames: []string{"www.microsoft.com"},
			ShortIds:    []string{""},
		}
	}
	// 缺冒号 → 报错(且应先于 dest/key 校验命中 listen_addr)。
	if err := base("443").Validate(); err == nil {
		t.Fatal("REALITY listen_addr 缺端口分隔应报错")
	}
	if err := base("0.0.0.0:99999").Validate(); err == nil {
		t.Fatal("REALITY listen_addr 端口越界应报错")
	}
	// 空 listen_addr = 未启用 → 直接放行。
	if err := base("").Validate(); err != nil {
		t.Fatalf("空 listen_addr 应视为未启用直接放行: %v", err)
	}
}
