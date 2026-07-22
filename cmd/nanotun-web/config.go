// Package main: nanotun-web — nanotun 自托管模式下的 Web 管理后台。
//
// 设计上独立成 binary,与 nanotund 物理隔离:
//   - 数据面 nanotund: 跑 root,持有 TUN/iptables/control socket;
//   - 管理面 nanotun-web: 跑非特权用户(systemd DynamicUser=yes),只持有
//     SQLite 文件 + control socket 读写权限,所有写操作都过 audit_logs;
//   - 接管路径: Web → 直写 SQLite → SIGHUP(或调 /control/reload) → server 拿新 snapshot。
//
// 监听 0.0.0.0:7443,启动时自动生成 self-signed 证书放在 certs_dir,
// 已存在则不覆盖。生产建议在前面套 nginx/caddy 走 Let's Encrypt + mTLS。

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config 是 nanotun-web 的运行时配置。优先级:显式 flag > env > default。
// (env 覆盖默认值;若某项 flag 被显式传入,则在 applyEnvOverrides 之后再复写回来,
// 确保命令行始终压过环境变量 —— 见 main.go 的 flag.Visit / setFlags 复写逻辑。)
//
// 字段命名上保持与 nanotund config 风格一致(snake_case 的 flag,大写 env)。
type Config struct {
	// 监听地址。默认 0.0.0.0:7443。空串视为非法。
	ListenAddr string

	// SQLite 数据库路径。与 nanotund 共享同一文件。
	DBPath string

	// nanotund 的 control socket 路径,用于 /runtime/reload + /runtime/kick。
	ControlSocketPath string

	// 自签证书目录。生成的文件为 cert.pem + key.pem,权限 0600。
	// 已存在 cert.pem + key.pem → 直接复用。
	CertDir string

	// SAN 列表的额外条目(domain 或 IP)。startup 时合并 hostname + 公网检测 +
	// 这里手动写的,然后生成证书。
	ExtraSANs []string

	// session 滑动过期窗口(秒)。每次成功命中 session 都把 expires_at 往后顶。
	SessionTTLSec int64

	// 暴力破解防护:连续失败 N 次后锁 lock_seconds 秒。
	MaxLoginFailures int64
	LockoutSeconds   int64

	// 写操作时是否同步调 nanotund /control/reload?acl(默认 true)。
	// 关闭后管理员需要手动 systemctl reload nanotun 让 ACL 生效。
	AutoReloadOnACLChange bool

	// 启动 setup wizard 的阈值:web_admins 表空时 / true 才进 setup 模式。
	// 当 admin 误删了所有账号,有意保留这个 wizard 入口而不是 fatal。
	AllowSetup bool

	// HTTP read header timeout,防止 Slowloris。默认 10s。
	ReadHeaderTimeout time.Duration
	// 整体写超时,防止下载 + slow client 长占连接。默认 60s。
	WriteTimeout time.Duration
	// keep-alive idle 上限。默认 120s。
	IdleTimeout time.Duration

	// VPNPortAdminPath:nanotun-admin CLI 二进制路径,用于 /server-qr 渲染
	// 服务器 profile QR(2026-05-26 引入)。默认 /usr/local/bin/nanotun-admin。
	//
	// 为什么不抽包直接 import buildProfile?nanotun-admin 是 package main,无法
	// 被 nanotun-web import。短期内 fork CLI 是最稳的复用方式:CLI 已经过
	// 9 轮深扫验证,行为冻结;web 进程只是密码验证 + audit + cooldown 的"门卫"。
	// 长期可考虑把 buildProfile / profileSchema 抽到 nanotun/profile/ 包。
	//
	// 测试时 inject 一个 stub binary path 即可(写个 bash 脚本输出固定 PNG)。
	VPNPortAdminPath string

	// ServerConfigPath:nanotun server 的 config.toml 路径,profile show 需要它
	// 派生 reality / hy2 / gateway 字段。默认 /etc/nanotun/config.toml(install
	// 脚本布局)。
	ServerConfigPath string

	// TrustedProxies:可信前置反代的 IP / CIDR 列表(如 "127.0.0.1", "10.0.0.0/8")。
	//
	// 默认空 = **不信任** X-Forwarded-For,一律用 TCP 直连对端作为客户端 IP(默认安全
	// 姿态)。仅当 nanotun-web 部署在 nginx/caddy/HAProxy 之后时才应配置:填反代自己
	// 的地址,clientIP 才会在「直连对端属于本集合」时解析 XFF 还原真实客户端 IP。
	// 否则任何人都能伪造 XFF,把「按 IP 限流 / 锁定」变成跨账号 DoS 并污染审计日志。
	// 来源:flag -trusted-proxies / env NANOTUN_WEB_TRUSTED_PROXIES(逗号分隔)。
	TrustedProxies []string

	// trustedProxyNets 是 TrustedProxies 在 Validate 阶段解析后的前缀集合(内部用)。
	trustedProxyNets []netip.Prefix

	// MetricsToken 门禁 /metrics 的可选 bearer token。
	//   - 空(默认):/metrics 仅对**环回**对端(127.0.0.1 / ::1)开放,其余来源一律 404
	//     —— 关闭「任意公网访客可读 admin 账号数 / 请求计数」的信息泄漏(此前 /metrics 完全无鉴权)。
	//   - 非空:要求 `Authorization: Bearer <token>`(常量时间比较);匹配即放行(供远程 Prometheus 抓取)。
	// 来源:env NANOTUN_WEB_METRICS_TOKEN。
	MetricsToken string
}

// defaultConfig 返回填好默认值的 Config。
func defaultConfig() Config {
	return Config{
		ListenAddr:            "0.0.0.0:7443",
		DBPath:                "/var/lib/nanotun/nanotun.db",
		ControlSocketPath:     "/run/nanotun/control.sock",
		CertDir:               "/etc/nanotun/certs",
		SessionTTLSec:         12 * 3600, // 12h 滑动窗口
		MaxLoginFailures:      5,
		LockoutSeconds:        15 * 60,
		AutoReloadOnACLChange: true,
		AllowSetup:            true,
		ReadHeaderTimeout:     10 * time.Second,
		WriteTimeout:          60 * time.Second,
		IdleTimeout:           120 * time.Second,
		VPNPortAdminPath:      "/usr/local/bin/nanotun-admin",
		ServerConfigPath:      "/etc/nanotun/config.toml",
	}
}

// applyEnvOverrides 把 NANOTUN_WEB_* 环境变量覆盖到默认值之上。
// 用环境变量而不是 viper / toml,是为了与 nanotund 一致地保留「单一 binary
// 无外部依赖」属性,部署只要一个 systemd unit + 几个 Environment= 即可。
func (c *Config) applyEnvOverrides() {
	if v := strings.TrimSpace(os.Getenv("NANOTUN_WEB_LISTEN")); v != "" {
		c.ListenAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("NANOTUN_WEB_DB")); v != "" {
		c.DBPath = v
	}
	if v := strings.TrimSpace(os.Getenv("NANOTUN_CONTROL_SOCKET")); v != "" {
		c.ControlSocketPath = v
	}
	if v := strings.TrimSpace(os.Getenv("NANOTUN_WEB_CERT_DIR")); v != "" {
		c.CertDir = v
	}
	if v := strings.TrimSpace(os.Getenv("NANOTUN_WEB_EXTRA_SANS")); v != "" {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				c.ExtraSANs = append(c.ExtraSANs, s)
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("NANOTUN_WEB_DISABLE_AUTORELOAD")); v != "" {
		c.AutoReloadOnACLChange = !parseBoolEnv(v, false)
	}
	// M4:setup 向导开关。建好管理员后可设 NANOTUN_WEB_ALLOW_SETUP=0 彻底封堵 /setup 抢占。
	if v := strings.TrimSpace(os.Getenv("NANOTUN_WEB_ALLOW_SETUP")); v != "" {
		c.AllowSetup = parseBoolEnv(v, c.AllowSetup)
	}
	if v := strings.TrimSpace(os.Getenv("NANOTUN_ADMIN_PATH")); v != "" {
		c.VPNPortAdminPath = v
	}
	if v := strings.TrimSpace(os.Getenv("NANOTUN_SERVER_CONFIG")); v != "" {
		c.ServerConfigPath = v
	}
	if v, ok := os.LookupEnv("NANOTUN_WEB_TRUSTED_PROXIES"); ok {
		// env 覆盖(而非追加):显式给了就以 env 为准。支持 none/off 哨兵显式清空。
		c.TrustedProxies = splitTrustedProxies(v)
	}
	if v := strings.TrimSpace(os.Getenv("NANOTUN_WEB_METRICS_TOKEN")); v != "" {
		c.MetricsToken = v
	}
}

// splitCSV 逗号分隔并去空白/空项。
func splitCSV(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// splitTrustedProxies 解析 -trusted-proxies / NANOTUN_WEB_TRUSTED_PROXIES 的 CSV。
// 深扫第十轮 LOW:支持 none/off 哨兵**显式清空**信任集合 —— 运维在 systemd 里设了 env,
// 又想在命令行临时关掉 XFF 信任时,`-trusted-proxies=none` 就能清空(空串会被 flag.Visit
// 判为"仍显式提供了 flag",同样清空)。
func splitTrustedProxies(v string) []string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none", "off":
		return nil
	}
	return splitCSV(v)
}

// parseTrustedProxies 把 CIDR / 裸 IP 列表解析成前缀集合。裸 IP 视作 /32(IPv4)
// 或 /128(IPv6)。任何非法条目立即返回 error(启动期 fail-fast,避免运维以为开了
// XFF 信任实际上因拼错而静默失效)。
func parseTrustedProxies(entries []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, raw := range entries {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted_proxies CIDR %q: %w", raw, err)
			}
			// 深扫第十轮 LOW:拒绝 0.0.0.0/0 与 ::/0 —— 全零前缀等于"信任所有对端",
			// 会让任何直连来源的 X-Forwarded-For 都被采信,彻底打开 XFF 伪造面,
			// 完全违背 trusted_proxies 的收敛意图。这几乎必然是误配,直接 fail-fast。
			if p.Bits() == 0 {
				return nil, fmt.Errorf("invalid trusted_proxies CIDR %q: a zero-length prefix trusts every "+
					"peer and defeats XFF trust; list the reverse proxy's real IP/CIDR instead", raw)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted_proxies IP %q: %w", raw, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// listenAddrIsPublic 判断监听地址是否绑在**非环回**(可被公网 / 局域网访问)地址上。
// 空 host / 0.0.0.0 / :: = 所有网卡(视为公网);127.0.0.1 / ::1 / localhost = 环回。未知形态保守当公网。
func listenAddrIsPublic(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		host = strings.TrimSpace(addr)
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "", "0.0.0.0", "::":
		return true
	case "127.0.0.1", "::1", "localhost":
		return false
	}
	if a, perr := netip.ParseAddr(host); perr == nil {
		return !a.IsLoopback()
	}
	return true
}

func parseBoolEnv(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

// Validate 在 Listen 之前跑一遍合理性检查,把会让运维一脸懵的错误前置成清晰
// 提示。任何返回 error 都让 main fatal。
func (c *Config) Validate() error {
	// 说明(多语言):Config.Validate 只在启动阶段(Listen 之前)跑,无 HTTP 请求
	// 语言上下文,错误直接 main fatal 到运维 stderr / 日志 —— 与 CLI「默认英文」
	// 一致,这里统一用英文,不走 catalog(启动期没有请求语言可翻)。
	if strings.TrimSpace(c.ListenAddr) == "" {
		return errors.New("listen_addr cannot be empty")
	}
	if !strings.Contains(c.ListenAddr, ":") {
		return fmt.Errorf("listen_addr=%q is missing a port number, expected host:port like 0.0.0.0:7443", c.ListenAddr)
	}
	if strings.TrimSpace(c.DBPath) == "" {
		return errors.New("db_path cannot be empty")
	}
	if !filepath.IsAbs(c.DBPath) && c.DBPath != ":memory:" {
		return fmt.Errorf("db_path=%q must be an absolute path (required by systemd ReadWritePaths)", c.DBPath)
	}
	if strings.TrimSpace(c.CertDir) == "" {
		return errors.New("cert_dir cannot be empty")
	}
	if !filepath.IsAbs(c.CertDir) {
		return fmt.Errorf("cert_dir=%q must be an absolute path", c.CertDir)
	}
	if c.SessionTTLSec < 60 {
		return fmt.Errorf("session_ttl_sec=%d is too short (<60s); logins would expire immediately", c.SessionTTLSec)
	}
	// 必须 >= 1。RecordWebAdminLoginFailure 的锁定条件是 `maxFailures > 0 && failed >= maxFailures`,
	// 因此 0 会**彻底关闭**账号级暴力破解锁定(运维若误以为「0=不限次数放行」而设 0,等于放开对
	// 密码 / 6 位 TOTP 的无限枚举)。启动期直接拒,逼运维给一个真实阈值。
	if c.MaxLoginFailures < 1 {
		return fmt.Errorf("max_login_failures=%d must be >= 1; 0 would disable brute-force lockout entirely", c.MaxLoginFailures)
	}
	if c.LockoutSeconds < 0 {
		return fmt.Errorf("lockout_seconds=%d cannot be < 0", c.LockoutSeconds)
	}
	if c.ReadHeaderTimeout <= 0 {
		c.ReadHeaderTimeout = 10 * time.Second
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 60 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 120 * time.Second
	}
	nets, err := parseTrustedProxies(c.TrustedProxies)
	if err != nil {
		return err
	}
	c.trustedProxyNets = nets
	return nil
}
