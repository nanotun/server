package main

// config_guards_test.go(第二十轮)—— 启动期配置校验的拒绝面与兜底面。
//
// Validate 是唯一一道「运维把脚枪对着自己」时的闸门,而它跑在 Listen 之前、
// 没有任何请求上下文:拦不住的错配置会一路带进生产,而且症状往往看起来像功能
// 正常。所以这里逐条钉住那些**看似无害其实关掉了一整道防线**的取值:
//
//   - lockout_seconds=0:locked_until==now,而判定是严格大于 → 账号锁定永不生效;
//   - trusted_proxies 写错一个字:若不 fail-fast,运维会以为开了 XFF 信任,
//     实际所有 IP 都记成反代地址(审计与限流一起失真);
//   - db_path / cert_dir 相对路径:systemd 的 ReadWritePaths 是按绝对路径授权的,
//     相对路径会在运行时才炸,且错误信息离原因很远。
//
// 另外补三个超时字段的兜底:0 值必须被换成默认值而不是原样带进 http.Server ——
// 0 在标准库里的语义是「永不超时」,慢连接就能把连接槽占死。

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidate_RejectsSelfDefeatingValues(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string // 期望错误里出现的字段名
	}{
		{"监听地址为空", func(c *Config) { c.ListenAddr = "  " }, "listen_addr"},
		{"监听地址没端口", func(c *Config) { c.ListenAddr = "0.0.0.0" }, "listen_addr"},
		{"库路径为空", func(c *Config) { c.DBPath = " " }, "db_path"},
		{"库路径是相对路径", func(c *Config) { c.DBPath = "web.db" }, "db_path"},
		{"证书目录为空", func(c *Config) { c.CertDir = "" }, "cert_dir"},
		{"证书目录是相对路径", func(c *Config) { c.CertDir = "certs" }, "cert_dir"},
		{"会话有效期过短", func(c *Config) { c.SessionTTLSec = 59 }, "session_ttl_sec"},
		{"失败上限为 0", func(c *Config) { c.MaxLoginFailures = 0 }, "max_login_failures"},
		{"锁定时长为 0", func(c *Config) { c.LockoutSeconds = 0 }, "lockout_seconds"},
		{"锁定时长为负", func(c *Config) { c.LockoutSeconds = -1 }, "lockout_seconds"},
		{"可信反代写错", func(c *Config) { c.TrustedProxies = []string{"10.0.0.0/33"} }, "trusted_proxies"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validatableConfig()
			tc.mut(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("这份配置本该被拒: %+v", cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, 没点明是 %s 的问题", err, tc.want)
			}
		})
	}
}

// 三个超时字段留 0 时必须落到默认值。0 在 net/http 里的语义是「永不超时」,
// 原样带进去等于把慢连接攻击的闸门拆掉。
func TestConfigValidate_FillsTimeoutDefaults(t *testing.T) {
	cfg := validatableConfig()
	cfg.ReadHeaderTimeout = 0
	cfg.WriteTimeout = 0
	cfg.IdleTimeout = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, tc := range []struct {
		name string
		got  time.Duration
	}{
		{"ReadHeaderTimeout", cfg.ReadHeaderTimeout},
		{"WriteTimeout", cfg.WriteTimeout},
		{"IdleTimeout", cfg.IdleTimeout},
	} {
		if tc.got <= 0 {
			t.Errorf("%s 仍是 %v —— 0 在 net/http 里是「永不超时」", tc.name, tc.got)
		}
	}
}

// 空白条目要被跳过而不是当成错误:CSV 里多打一个逗号是最常见的手误,
// 为此拒绝启动没有意义(而它确实什么也不信任)。
func TestParseTrustedProxies_SkipsBlankEntries(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8", "  ", "", "192.168.1.1"})
	if err != nil {
		t.Fatalf("parseTrustedProxies: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("解析出 %d 条,期望 2(空白条目应被跳过): %v", len(nets), nets)
	}
	// 裸 IP 要当成单主机前缀,不能变成 /8 之类的大网段。
	if nets[1].Bits() != 32 {
		t.Errorf("裸 IPv4 被解析成了 /%d,期望 /32", nets[1].Bits())
	}
}

// 环境变量覆盖:这三个是「装好之后才会去调」的项,漏读会让运维以为改了配置
// 却毫无效果 —— 尤其 ALLOW_SETUP=0,漏读等于 /setup 一直开着。
func TestConfigFromEnv_ReadsLateAddedKnobs(t *testing.T) {
	cfg := validatableConfig()
	cfg.AllowSetup = true
	t.Setenv("NANOTUN_WEB_ALLOW_SETUP", "0")
	t.Setenv("NANOTUN_ADMIN_PATH", "/opt/nanotun/bin/nanotun-admin")
	t.Setenv("NANOTUN_SERVER_CONFIG", "/etc/nanotun/server.toml")

	cfg.applyEnvOverrides()

	if cfg.AllowSetup {
		t.Error("NANOTUN_WEB_ALLOW_SETUP=0 没被读进来 —— /setup 会一直开着")
	}
	if cfg.VPNPortAdminPath != "/opt/nanotun/bin/nanotun-admin" {
		t.Errorf("NANOTUN_ADMIN_PATH 没生效: %q", cfg.VPNPortAdminPath)
	}
	if cfg.ServerConfigPath != "/etc/nanotun/server.toml" {
		t.Errorf("NANOTUN_SERVER_CONFIG 没生效: %q", cfg.ServerConfigPath)
	}
}

// validatableConfig 造一份能通过 Validate 的基线配置,便于逐项弄坏。
func validatableConfig() Config {
	c := defaultConfig()
	c.ListenAddr = "127.0.0.1:7443"
	c.DBPath = "/var/lib/nanotun/web.db"
	c.CertDir = "/var/lib/nanotun/certs"
	if c.SessionTTLSec < 60 {
		c.SessionTTLSec = 3600
	}
	if c.MaxLoginFailures < 1 {
		c.MaxLoginFailures = 5
	}
	if c.LockoutSeconds < 1 {
		c.LockoutSeconds = 900
	}
	return c
}
