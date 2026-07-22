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
}
