package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/crypto/curve25519"

	"github.com/nanotun/server/certs"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 与 rust_vpn_client_lib_common::server_profile 对齐的 schema 与默认端口；
// 改这里时务必同步 Rust 一侧（两边都有自家单测保护，不会被无声破坏）。
const (
	profileSchemaVersion    = 1
	profileURLPrefix        = "nanotun://v1?d="
	defaultGatewayTCPPort   = 8080
	defaultRealityTCPPort   = 8443
	defaultHy2UDPPort       = 443
	defaultServerConfigPath = "/etc/nanotun/config.toml"
)

// profileSchemaReality 与 [`server_profile::RealitySection`] 对齐。
//
// 全字段 omitempty：服务端只输出真正能从 config.toml 读到的字段，剩下的让客户端
// 套库内默认（fingerprint=chrome、server_name=www.microsoft.com 等）。
type profileSchemaReality struct {
	Address       string   `json:"address,omitempty"`
	Port          uint16   `json:"port,omitempty"`
	ServerName    string   `json:"server_name,omitempty"`
	PublicKey     string   `json:"public_key,omitempty"`
	ShortID       string   `json:"short_id,omitempty"`
	ShortIDs      []string `json:"short_ids,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	SpiderX       string   `json:"spider_x,omitempty"`
	UsePQ         *bool    `json:"use_pq,omitempty"`
	Mldsa65Verify string   `json:"mldsa65_verify,omitempty"`
}

// profileSchemaHy2 与 [`server_profile::Hy2Section`] 对齐。
//
// `tls_insecure_hint` 用 *bool：dev 自签证书 → true；上 Letsencrypt 后 → 显式 false。
// 用裸 bool + omitempty 时无法表达「显式 false」，会让 production profile 把字段丢掉。
type profileSchemaHy2 struct {
	Address                string `json:"address,omitempty"`
	UDPPort                uint16 `json:"udp_port,omitempty"`
	UDPPorts               string `json:"udp_ports,omitempty"`
	HopIntervalSec         uint64 `json:"hop_interval_sec,omitempty"`
	HopIntervalMinSec      uint64 `json:"hop_interval_min_sec,omitempty"`
	HopIntervalMaxSec      uint64 `json:"hop_interval_max_sec,omitempty"`
	Auth                   string `json:"auth,omitempty"`
	TLSSNI                 string `json:"tls_sni,omitempty"`
	TLSInsecureHint        *bool  `json:"tls_insecure_hint,omitempty"`
	ObfsType               string `json:"obfs_type,omitempty"`
	ObfsSalamanderPassword string `json:"obfs_salamander_password,omitempty"`
	// 2026-07-17:keepalive_ws_tls_port / keepalive_ws_path 已下线不再签发——
	// 独立 WSS 保活被数据面 1s 链路 Ping 覆盖;老客户端 profile 里没有端口就不会起保活任务。
	MTU                   uint16 `json:"mtu,omitempty"`
	QUICMaxIdleTimeoutSec int    `json:"quic_max_idle_timeout_sec,omitempty"`
	// m1i：服务端启用 [hysteria].tls_client_ca_file 时，profile show 临场签发的客户端证书（PEM）。
	// 客户端须用此对证书做 Hy2 QUIC + 保活 WSS mTLS；勿长期落盘，与 PSK 同级敏感。
	ClientCertPEM string `json:"client_cert_pem,omitempty"`
	ClientKeyPEM  string `json:"client_key_pem,omitempty"`
	MTLSRequired  *bool  `json:"mtls_required,omitempty"`
}

// profileSchema 与 Rust [`VpnPortServerProfile`] 完全对齐。`json` tag 不能改。
//
// **2026-05-25 解耦** `Username` / `PSK` 已剥离到 [`credentialsSchema`](cmd_credentials.go),
// 分别通过 `nanotun-admin profile show` 与 `nanotun-admin credentials show` 输出独立 QR。
// 改造目标:profile 可云同步 / 公开传阅(只含服务器配置),credentials 仅本地 Keychain
// 持久化(含敏感 PSK)。两份 QR 客户端各自扫描后,client 在内存里合并出 LoginReq。
//
// **2026-05-26 加 server_id** 与 credentials.id(用户级凭证指纹)对称的「服务器实例指纹」:
//   - 取自 `app_settings.server_id`(`store.GetOrInitServerID` lazy 生成的 UUID v4);
//   - 同一台 nanotun 实例的任何 profile show / web QR 都用同一值,永久不变;
//   - 换 host / 加节点 / rotate REALITY 公钥 都不变 — 客户端可按 server_id 去重 /
//     自动覆盖既有条目,而不是当成另一台陌生服务器添加。
//   - `omitempty`:旧客户端 / 老 server 没该字段时仍可正常 parse(向前/后兼容)。
//
// `Gateway*` 系列字段为 m1h 新增（schema_version 仍为 1，向后兼容）：
//   - GatewayTCPPort 旧字段保留；
//   - GatewayTLS / GatewayWSPath / GatewayTLSSNI 三个空串视作"未配置"，由 omitempty 省略；
//   - GatewayTLSInsecureHint 用 *bool 区分「显式 false」（生产 LE）与「省略」（兼容旧 client）。
type profileSchema struct {
	Version  uint32 `json:"version"`
	ServerID string `json:"server_id,omitempty"`
	Name     string `json:"name,omitempty"`
	// Host 是客户端 dial target(IPv4 / IPv6 / 合法 RFC 1035 hostname)。
	// 入库前由 [store.ValidateServerDialHost] 做 strict 校验,客户端直接拼端口拨号。
	Host string `json:"host"`
	// AdvertisedHost 是 admin 起的展示 label(`prod-jp-1`、`东京一号`),与
	// Host (dial target) **严格分离**(2026-05-26 第六轮拆字段)。客户端 UI
	// 副标题展示,不解析、不连接。空时 omitempty。
	AdvertisedHost         string                `json:"advertised_host,omitempty"`
	GatewayTCPPort         uint16                `json:"gateway_tcp_port,omitempty"`
	GatewayTLS             *bool                 `json:"gateway_tls,omitempty"`
	GatewayWSPath          string                `json:"gateway_ws_path,omitempty"`
	GatewayTLSSNI          string                `json:"gateway_tls_sni,omitempty"`
	GatewayTLSInsecureHint *bool                 `json:"gateway_tls_insecure_hint,omitempty"`
	TransportPreference    []string              `json:"transport_preference,omitempty"`
	Reality                *profileSchemaReality `json:"reality,omitempty"`
	Hy2                    *profileSchemaHy2     `json:"hy2,omitempty"`
	Nodes                  []profileSchemaNode   `json:"nodes,omitempty"`
	Note                   string                `json:"note,omitempty"`
}

// cmdProfile 派发：目前仅 show。
//
// 历史(2026-05-25 移除):P2#14 曾在此挂 `revoke / unrevoke / revocations`
// 用于按 profile_id(pid)吊销已发出的 profile QR。0013 credentials 解耦后
// profile QR 不再包含 PSK,即使被截屏泄露也不能登录,pid 黑名单机制冗余,
// 整条链路连同 wire 字段一并删除。
func cmdProfile(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return errors.New(opts.usage("nanotun-admin profile show [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "show":
		return cmdProfileShow(ctx, st, opts, rest)
	default:
		return newLocErr("cli.unknownSubcommand", "profile", sub)
	}
}

// cmdProfileShow 是「服务器侧导出客户端可直接导入的 profile」的主入口。
//
// 设计：
//   - 公网地址 (`--host`) 没法从 db / config 推得，必填；
//   - **2026-05-25 解耦后** profile 不再含 username + PSK,凭证走独立的
//     `nanotun-admin credentials show <user>` 命令(见 cmd_credentials.go);
//     此处 `<username>` 仅用于校验用户存在 + Hy2 mTLS 客户端证书 CN,**不出现在输出 JSON**;
//   - 其它字段（reality 公钥、hy2 端口/密码 等）默认从 nanotun server `config.toml` 派生，
//     可以用 `--no-reality` / `--no-hy2` 跳过段，或用 `--reality-port` 等显式覆盖。
//   - 输出格式：json（pretty）/ url（nanotun://）/ both；目标：stdout 或 `--output FILE`。
func cmdProfileShow(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("profile show", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	// `--dial-host` 是 2026-05-26 第六轮拆字段新引入的"真实 dial target"flag,
	// 强校验为 IPv4 / IPv6 / RFC1035 合法域名(末段含字母);客户端 PacketTunnel
	// 直接拼端口拨号,容不得 label 字符串。
	// `--host` 保留为 deprecated 别名 + warning,避免破坏现有运维脚本 / docs。
	// 两者填了任意一个都行,二者皆填时优先用 --dial-host(显式 > 隐式)。
	dialHost := fs.String("dial-host", "", opts.T("profile.flag.dialHost"))
	host := fs.String("host", "", opts.T("profile.flag.host"))
	advertisedHostFlag := fs.String("advertised-host", "", opts.T("profile.flag.advertisedHost"))
	configPath := fs.String("config", defaultServerConfigPath, opts.T("profile.flag.config"))
	format := fs.String("format", "json", opts.T("profile.flag.format"))
	output := fs.String("output", "", opts.T("profile.flag.output"))
	// --force:允许覆盖已存在的 --output 目标(含 qr-png)。默认不覆盖(openProfileOutput/writeFileTight
	// 用 O_EXCL / Lstat 拒绝),避免误覆盖含明文 PSK/PEM 的既有产物,并防符号链接跟随写。
	forceOverwrite := fs.Bool("force", false, opts.T("profile.flag.force"))
	nameFlag := fs.String("name", "", opts.T("profile.flag.name"))
	noteFlag := fs.String("note", "", opts.T("profile.flag.note"))
	noReality := fs.Bool("no-reality", false, opts.T("profile.flag.noReality"))
	noHy2 := fs.Bool("no-hy2", false, opts.T("profile.flag.noHy2"))
	noGateway := fs.Bool("no-gateway", false, opts.T("profile.flag.noGateway"))
	withGateway := fs.Bool("with-gateway", false, opts.T("profile.flag.withGateway"))
	gatewayPort := fs.Uint("gateway-port", 0, opts.T("profile.flag.gatewayPort"))
	gatewayPath := fs.String("gateway-path", "", opts.T("profile.flag.gatewayPath"))
	gatewayTLSFlag := fs.String("gateway-tls", "auto", opts.T("profile.flag.gatewayTLS"))
	gatewayTLSSNI := fs.String("gateway-tls-sni", "", opts.T("profile.flag.gatewayTLSSNI"))
	gatewayTLSInsecureFlag := fs.String("gateway-tls-insecure", "auto", opts.T("profile.flag.gatewayTLSInsecure"))
	realityPort := fs.Uint("reality-port", 0, opts.T("profile.flag.realityPort"))
	hy2UDPPort := fs.Uint("hy2-udp-port", 0, opts.T("profile.flag.hy2UDPPort"))
	hy2InsecureFlag := fs.String("hy2-tls-insecure", "true", opts.T("profile.flag.hy2Insecure"))
	noIssueHy2Cert := fs.Bool("no-issue-hy2-client-cert", false, opts.T("profile.flag.noIssueHy2Cert"))
	hy2CertDays := fs.Uint("hy2-client-cert-days", 90, opts.T("profile.flag.hy2CertDays"))
	var nodeFlags stringList
	fs.Var(&nodeFlags, "node", opts.T("profile.flag.node"))

	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New(opts.T("profile.usageTooMany"))
	}
	// --dial-host 优先,--host 作 deprecated 别名(2026-05-26 第六轮拆字段)。
	// 二者均空 → fail。
	effectiveDial := strings.TrimSpace(*dialHost)
	if effectiveDial == "" {
		effectiveDial = strings.TrimSpace(*host)
		if effectiveDial != "" {
			fmt.Fprintln(opts.stderr, opts.T("profile.hostDeprecated"))
		}
	}
	if effectiveDial == "" {
		return errors.New(opts.T("profile.dialHostRequired"))
	}
	// strict 校验:本字段是客户端 PacketTunnel `tunnelRemoteAddress`,
	// 配错(test-203.0.113.10 / 含中文 / 含端口)→ 客户端隧道挂掉。
	if err := store.ValidateServerDialHost(effectiveDial); err != nil {
		return errors.New(opts.T("profile.dialHostInvalid", opts.errText(err)))
	}
	advertisedHost := strings.TrimSpace(*advertisedHostFlag)
	if advertisedHost != "" {
		// label 校验放宽:允许中文 / emoji,只拒 scheme/path/port/控制字符。
		if err := store.ValidateAdvertisedHost(advertisedHost); err != nil {
			return errors.New(opts.T("profile.advertisedHostInvalid", opts.errText(err)))
		}
	}
	if !validFormat(*format) {
		return errors.New(opts.T("profile.formatInvalid", *format))
	}

	// usernameForCertCN 仅供 Hy2 mTLS 客户端证书 CN 占位(`vpnport-<cn>-<8hex>`);
	// Hy2 mTLS 鉴权只验签证书 CA 链,**不**校验 CN — 所以这个值的语义意义只有「让
	// 服务器证书审计日志能区分这张 cert 是哪条 issuance 路径出的」。
	//
	// 两种调用模式:
	//   (a) `profile show <username>` (legacy/per-user) — 校验该 VPN user 存在,
	//       Hy2 cert CN = "vpnport-<username>-<rand>";
	//   (b) `profile show` (server-level, 2026-05-26+) — 不再绑用户,Hy2 cert CN
	//       = "vpnport-server-profile-<rand>"。本路径让 nanotun-web 的「服务器
	//       配置 QR」按钮不再依赖「某个 VPN user 名字 == web admin 名字」的巧合。
	//
	// 输出 profile JSON 在两种模式下**字段一致**(都不带 username);差异仅在
	// 内嵌 Hy2 mTLS 证书的 CN。
	var usernameForCertCN string
	if len(pos) == 1 {
		username := strings.TrimSpace(pos[0])
		if username == "" {
			return errors.New(opts.T("profile.usernameEmpty"))
		}
		user, uerr := st.GetUserByUsername(ctx, username)
		if uerr != nil {
			return opts.notFoundErr(uerr, "user.notFound", username)
		}
		usernameForCertCN = user.Username
	} else {
		// server-level QR:无 user lookup,Hy2 cert CN 用合成占位符。
		usernameForCertCN = "server-profile"
	}

	// 3. 加载 server config（reality / hy2 段；若读不到 + 用户也没显式禁用，给 warn 而不是 fail）
	srvCfg, srvCfgErr := loadServerConfigOptional(*configPath)
	if srvCfgErr != nil {
		fmt.Fprintln(opts.stderr, opts.T("profile.warnReadConfig", *configPath, srvCfgErr.Error()))
	}

	// 4. 组装 profile struct
	insecureHint, err := parseHy2InsecureFlag(*hy2InsecureFlag, srvCfg)
	if err != nil {
		return err
	}
	gwTLS, err := parseGatewayTLSFlag(*gatewayTLSFlag, srvCfg)
	if err != nil {
		return err
	}
	gwInsecure, err := parseGatewayTLSInsecureFlag(*gatewayTLSInsecureFlag, gwTLS)
	if err != nil {
		return err
	}

	// server_id = 服务器实例永久指纹(类比 credentials.id)。lazy 取 / 生成,失败软
	// 降级:profile 仍照常出,只是这次 QR 没 `server_id` 字段 —— 客户端无法做去重 /
	// 自动覆盖,但仍能用。打 warn 让 admin 知道。
	//
	// 失败原因通常是 SQLite 文件被运维误 chmod 成 read-only / WAL 文件丢了 —
	// 此时 user / device 等表也不可写,nanotund 都跑不起来,profile show 不应
	// 因此 fail。
	serverID, sidErr := st.GetOrInitServerID(ctx)
	if sidErr != nil {
		fmt.Fprintln(opts.stderr, opts.T("profile.warnReadServerID", sidErr.Error()))
	}

	bpIn := buildProfileInput{
		// username 仅用于 Hy2 mTLS 客户端证书 CN(见 hy2ClientCertCommonName),
		// **不**会写入 profile JSON 输出(已剥离到 credentials)。
		// server-level QR 模式下是合成占位符 "server-profile"(见 usernameForCertCN 注释)。
		username:               usernameForCertCN,
		serverID:               serverID,
		host:                   effectiveDial,
		advertisedHost:         advertisedHost,
		name:                   *nameFlag,
		note:                   *noteFlag,
		gatewayPort:            uint16(*gatewayPort),
		gatewayWSPath:          strings.TrimSpace(*gatewayPath),
		gatewayTLS:             gwTLS,
		gatewayTLSSNI:          strings.TrimSpace(*gatewayTLSSNI),
		gatewayTLSInsecureHint: gwInsecure,
		noGateway:              *noGateway,
		includeGateway:         *withGateway,
		gatewayTLSFlag:         *gatewayTLSFlag,
		gatewayTLSInsecureFlag: *gatewayTLSInsecureFlag,
		realityPort:            uint16(*realityPort),
		hy2UDPPort:             uint16(*hy2UDPPort),
		hy2InsecureHint:        insecureHint,
		noReality:              *noReality,
		noHy2:                  *noHy2,
		serverCfg:              srvCfg,
		configPath:             *configPath,
		noIssueHy2ClientCert:   *noIssueHy2Cert,
		hy2ClientCertDays:      int(*hy2CertDays),
	}
	var prof *profileSchema
	if len(nodeFlags) > 0 {
		specs := make([]nodeSpec, 0, len(nodeFlags))
		for _, raw := range nodeFlags {
			spec, err := parseNodeSpec(raw)
			if err != nil {
				return errors.New(opts.T("profile.parseNode") + ": " + opts.errText(err))
			}
			specs = append(specs, spec)
		}
		prof, err = buildProfileV2(bpIn, specs)
	} else {
		prof, err = buildProfile(bpIn)
	}
	if err != nil {
		return err
	}

	_ = st // 留 st 引用,方便将来加 "profile_issuance" 审计表;当前 show 路径完全只读。

	return emitProfile(prof, *format, *output, *forceOverwrite, opts)
}

// emitProfile 按 --format 写出 profile；qr / qr-png 编码 nanotun:// URL（非裸 JSON）。
func emitProfile(p *profileSchema, format, outputPath string, force bool, opts *globalOpts) error {
	if opts.json {
		out, closeOut, err := openProfileOutput(outputPath, opts.stdout, force)
		if err != nil {
			return err
		}
		if err := writeJSONCompact(out, p); err != nil {
			return err
		}
		return closeOut()
	}

	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "qr-png":
		if strings.TrimSpace(outputPath) == "" {
			return errors.New(opts.T("profile.qrPngNeedsOutput"))
		}
		url, err := profileToURL(p)
		if err != nil {
			return err
		}
		return writeQRPNG(opts, outputPath, url, force)
	case "qr":
		if strings.TrimSpace(outputPath) != "" {
			fmt.Fprintln(opts.stderr, opts.T("profile.qrIgnoresOutput", outputPath))
		}
		url, err := profileToURL(p)
		if err != nil {
			return err
		}
		fmt.Fprintln(opts.stdout, opts.T("profile.qrScanHint"))
		return writeQRTerminal(opts, opts.stdout, url)
	default:
		out, closeOut, err := openProfileOutput(outputPath, opts.stdout, force)
		if err != nil {
			return err
		}
		if err := writeProfile(out, p, format, false); err != nil {
			return err
		}
		return closeOut()
	}
}

// loadServerConfigOptional 用 [pelletier/go-toml] 加载 nanotun `config.toml`；找不到 / 解析
// 失败一律返回 (nil, err)，由调用方决定是 warn 还是 fail。
func loadServerConfigOptional(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg config.Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// parseHy2InsecureFlag 解释 `--hy2-tls-insecure`：
//   - "true" / "false"：透传；
//   - "auto"：从 server config 启发（`report_tls_insecure_hint=true` ⇒ true；否则 false）；
//   - 其它：报错。
//
// 返回 nil 表示「不写到 profile」（罕见；只有用户显式给 "skip" 才会到这）。
func parseHy2InsecureFlag(s string, cfg *config.Config) (*bool, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "true":
		t := true
		return &t, nil
	case "false":
		f := false
		return &f, nil
	case "auto":
		t := true
		f := false
		if cfg != nil && cfg.Hysteria.ReportTLSInsecureHint {
			return &t, nil
		}
		return &f, nil
	default:
		return nil, newLocErr("profile.hy2InsecureBad", s)
	}
}

type buildProfileInput struct {
	// username 仅供 Hy2 mTLS 客户端证书 CN 使用(hy2ClientCertCommonName),
	// **不**写入 profile JSON 输出。凭证 username 走独立的 credentials QR(cmd_credentials.go)。
	username string
	// serverID = app_settings.server_id 的 lazy-init UUID v4。写到 profile JSON
	// 的 `server_id` 字段;空串视为「不写出」(test fixture / 兼容旧 store 未跑迁移)。
	// 由 cmdProfileShow 在调用 buildProfile/buildProfileV2 前从 store 读出注入。
	serverID string
	// host 是客户端 dial target,strict IPv4/IPv6/RFC1035 hostname。
	// 来自 `--dial-host`(优先)或 `--host`(deprecated 别名),CLI 入口已 strict 校验。
	host string
	// advertisedHost 是 admin 起的展示 label(`prod-jp-1`、`东京一号`、`test-xxx`)。
	// 与 host 严格分离(2026-05-26 第六轮);客户端 UI 副标题展示,不参与连接。
	// 来自 `--advertised-host` flag,空 = 不写入 profile JSON(走 omitempty)。
	advertisedHost         string
	name                   string
	note                   string
	gatewayPort            uint16
	gatewayWSPath          string
	gatewayTLS             *bool
	gatewayTLSSNI          string
	gatewayTLSInsecureHint *bool
	noGateway              bool
	includeGateway         bool
	gatewayTLSFlag         string
	gatewayTLSInsecureFlag string
	realityPort            uint16
	hy2UDPPort             uint16
	hy2InsecureHint        *bool
	noReality              bool
	noHy2                  bool
	serverCfg              *config.Config // 可为 nil
	configPath             string
	noIssueHy2ClientCert   bool
	hy2ClientCertDays      int
}

func buildProfile(in buildProfileInput) (*profileSchema, error) {
	p := &profileSchema{
		Version:        profileSchemaVersion,
		ServerID:       strings.TrimSpace(in.serverID),
		Name:           strings.TrimSpace(in.name),
		Host:           in.host,
		AdvertisedHost: strings.TrimSpace(in.advertisedHost),
		Note:           strings.TrimSpace(in.note),
	}

	if shouldIncludeGateway(in) {
		applyGateway(p, in)
	}

	if !in.noReality {
		r, err := buildReality(in)
		if err != nil {
			return nil, err
		}
		if r != nil {
			p.Reality = r
		}
	}

	if !in.noHy2 {
		h2, err := buildHy2(in)
		if err != nil {
			return nil, err
		}
		if h2 != nil {
			p.Hy2 = h2
		}
	}

	return p, nil
}

// shouldIncludeGateway 决定是否把 gateway_* 写入客户端 profile。
//
// 默认 false：Hy2 / REALITY 数据面不经公网 :8080 WebSocket path，该 path 仅服务端环回使用。
// 开启条件：--with-gateway，或任意显式 gateway 覆盖（--gateway-port / --gateway-path / …），
// 且未被 --no-gateway 否决。
func shouldIncludeGateway(in buildProfileInput) bool {
	if in.noGateway {
		return false
	}
	if in.includeGateway {
		return true
	}
	if in.gatewayPort != 0 || in.gatewayWSPath != "" || in.gatewayTLSSNI != "" {
		return true
	}
	if explicitGatewayProfileFlag(in.gatewayTLSFlag) || explicitGatewayProfileFlag(in.gatewayTLSInsecureFlag) {
		return true
	}
	return false
}

func explicitGatewayProfileFlag(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto", "skip":
		return false
	default:
		return true
	}
}

// applyGateway 把 gateway_* 字段从 (cfg, flag override) 派生到 profile 上（仅 admin / 将来 tcp-ws 客户端）。
//
// 派生规则：
//   - gateway_tcp_port: 用户 --gateway-port > 0 时用之；否则 config 端口；都无则 8080。
//     8080 默认值不写入 JSON（让 profile 更短，反正客户端走库内默认）。
//   - gateway_tls: 由 parseGatewayTLSFlag 决定（已在调用方解析过 auto / true / false）。
//   - gateway_ws_path: 用户 --gateway-path > config [server].vpn_websocket_path。空字符串
//     不写入 JSON；客户端会落到 [`DEFAULT_GATEWAY_WS_PATH`]，所以省略也无害。
//   - gateway_tls_sni: 显式 --gateway-tls-sni；空时不写（客户端 fallback 到 host）。
//   - gateway_tls_insecure_hint: parseGatewayTLSInsecureFlag 决定（auto 关联 gateway_tls）。
func applyGateway(p *profileSchema, in buildProfileInput) {
	port := uint16(0)
	if in.gatewayPort != 0 {
		port = in.gatewayPort
	} else if cfg := in.serverCfg; cfg != nil {
		if cp := portFromListenAddr(cfg.Server.ListenAddr); cp != 0 {
			port = cp
		}
	}
	// 默认 8080 时不写 JSON，客户端用库内默认
	if port != 0 && port != defaultGatewayTCPPort {
		p.GatewayTCPPort = port
	}

	if in.gatewayTLS != nil {
		p.GatewayTLS = in.gatewayTLS
	}

	wsPath := strings.TrimSpace(in.gatewayWSPath)
	if wsPath == "" && in.serverCfg != nil {
		wsPath = strings.TrimSpace(in.serverCfg.Server.VPNWebSocketPath)
	}
	if wsPath != "" {
		if !strings.HasPrefix(wsPath, "/") {
			wsPath = "/" + wsPath
		}
		p.GatewayWSPath = wsPath
	}

	if in.gatewayTLSSNI != "" {
		p.GatewayTLSSNI = in.gatewayTLSSNI
	}
	if in.gatewayTLSInsecureHint != nil {
		p.GatewayTLSInsecureHint = in.gatewayTLSInsecureHint
	}
}

// parseGatewayTLSFlag 解释 `--gateway-tls`：
//   - "true" / "false"：透传。
//   - "auto" / 空 / "skip"：从 config 启发：
//     [server].tls_cert_file 与 tls_key_file 都非空 ⇒ true（必须显式写到 profile，
//     否则客户端默认 plain WS 拨号会撞 TLS server）；
//     都为空 ⇒ nil（plain WS 不写 gateway_tls 字段，让 profile 短一些，
//     与「TLS 关闭时不写 insecure_hint」对齐）。
//   - 其它：报错。
//
// 返回 nil 表示「不写 gateway_tls 字段」；返回 *bool 表示显式写 true / false。
func parseGatewayTLSFlag(s string, cfg *config.Config) (*bool, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "true":
		t := true
		return &t, nil
	case "false":
		f := false
		return &f, nil
	case "", "auto", "skip":
		if cfg == nil {
			return nil, nil
		}
		hasCert := strings.TrimSpace(cfg.Server.TLSCertFile) != "" &&
			strings.TrimSpace(cfg.Server.TLSKeyFile) != ""
		if hasCert {
			t := true
			return &t, nil
		}
		return nil, nil
	default:
		return nil, newLocErr("profile.gatewayTLSBad", s)
	}
}

// parseGatewayTLSInsecureFlag 解释 `--gateway-tls-insecure`：
//   - "true" / "false"：透传。
//   - "auto" / 空：与 gateway_tls 联动 —— TLS 启用且为 dev 自签时默认 true（与 install.sh dev cert
//     行为一致）；TLS 关闭时一律不写（plain WS 没有 TLS hint 概念）。
//   - 其它：报错。
func parseGatewayTLSInsecureFlag(s string, gwTLS *bool) (*bool, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "true":
		t := true
		return &t, nil
	case "false":
		f := false
		return &f, nil
	case "", "auto":
		if gwTLS == nil || !*gwTLS {
			return nil, nil
		}
		t := true
		return &t, nil
	default:
		return nil, newLocErr("profile.gatewayTLSInsecureBad", s)
	}
}

func buildReality(in buildProfileInput) (*profileSchemaReality, error) {
	port := in.realityPort
	var serverName, pubKey, shortID string

	if cfg := in.serverCfg; cfg != nil {
		rc := &cfg.Reality
		if strings.TrimSpace(rc.ListenAddr) != "" {
			if port == 0 {
				if p := portFromListenAddr(rc.ListenAddr); p != 0 {
					port = p
				}
			}
			if len(rc.ServerNames) > 0 {
				serverName = strings.TrimSpace(rc.ServerNames[0])
			}
			if len(rc.ShortIds) > 0 {
				shortID = strings.TrimSpace(rc.ShortIds[0])
			}
			if strings.TrimSpace(rc.PrivateKey) != "" {
				priv, err := config.DecodeRealityPrivateKey(rc.PrivateKey)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", newLocErr("profile.parseRealityPriv").Error(), err)
				}
				pub, err := DeriveRealityPublicKey(priv)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", newLocErr("profile.deriveRealityPub").Error(), err)
				}
				pubKey = base64.StdEncoding.EncodeToString(pub)
			}
		}
	}

	if port == 0 {
		port = defaultRealityTCPPort
	}

	var shortIDs []string
	if cfg := in.serverCfg; cfg != nil && strings.TrimSpace(cfg.Reality.ListenAddr) != "" {
		for _, sid := range cfg.Reality.ShortIds {
			sid = strings.TrimSpace(sid)
			if sid != "" {
				shortIDs = append(shortIDs, sid)
			}
		}
	}

	r := &profileSchemaReality{
		Port:        port,
		ServerName:  serverName,
		PublicKey:   pubKey,
		ShortID:     shortID,
		ShortIDs:    shortIDs,
		Fingerprint: "chrome",
	}
	// 全空（host 为空 + 公钥为空 + ServerName 为空 + ShortID 为空 + 仅默认 port）时不输出 reality 段。
	if r.PublicKey == "" && r.ServerName == "" && r.ShortID == "" && len(r.ShortIDs) == 0 && in.realityPort == 0 {
		return nil, nil
	}
	return r, nil
}

func buildHy2(in buildProfileInput) (*profileSchemaHy2, error) {
	udpPort := in.hy2UDPPort
	var auth, sni, obfsPW string
	var hy2MTU uint16
	var hy2QUICIdle int
	obfsType := "" // 与 Rust 默认一致：留空时 client 视为 "none"

	if cfg := in.serverCfg; cfg != nil {
		hc := &cfg.Hysteria
		if hc.HysteriaActive() {
			if udpPort == 0 {
				if p := portFromListenAddr(hc.ListenAddr); p != 0 {
					udpPort = p
				}
			}
			if hc.MTU > 0 {
				hy2MTU = uint16(hc.MTU)
			}
			if hc.QUICMaxIdleTimeoutSec > 0 {
				hy2QUICIdle = hc.QUICMaxIdleTimeoutSec
			}
			auth = strings.TrimSpace(hc.Password)
			sni = strings.TrimSpace(hc.ReportTLSSNI)
			if pw := strings.TrimSpace(hc.ObfsSalamanderPassword); pw != "" {
				obfsType = "salamander"
				obfsPW = pw
			}
		}
	}

	// 用户没显式禁用 hy2，但 server 也没启用 → 留空 hy2 段
	if udpPort == 0 && auth == "" && obfsPW == "" {
		return nil, nil
	}
	if udpPort == 0 {
		udpPort = defaultHy2UDPPort
	}

	h := &profileSchemaHy2{
		UDPPort:                udpPort,
		Auth:                   auth,
		TLSSNI:                 sni,
		TLSInsecureHint:        in.hy2InsecureHint,
		ObfsType:               obfsType,
		ObfsSalamanderPassword: obfsPW,
		MTU:                    hy2MTU,
		QUICMaxIdleTimeoutSec:  hy2QUICIdle,
	}

	if cfg := in.serverCfg; cfg != nil {
		hc := &cfg.Hysteria
		if pu, err := util.PortUnionStringFromUDPListenAddr(hc.ListenAddr); err == nil && util.UDPPortUnionNeedsHop(pu) {
			h.UDPPorts = pu
		}
		if hc.PortHopIntervalSec >= 5 {
			h.HopIntervalSec = uint64(hc.PortHopIntervalSec)
		}
		if hc.PortHopIntervalMinSec >= 5 && hc.PortHopIntervalMaxSec >= hc.PortHopIntervalMinSec {
			h.HopIntervalMinSec = uint64(hc.PortHopIntervalMinSec)
			h.HopIntervalMaxSec = uint64(hc.PortHopIntervalMaxSec)
		}
		caRel := strings.TrimSpace(hc.TLSClientCAFile)
		if caRel != "" {
			t := true
			h.MTLSRequired = &t
			if !in.noIssueHy2ClientCert {
				if err := attachIssuedHy2ClientCert(h, in, caRel); err != nil {
					return nil, err
				}
			}
		}
	}

	return h, nil
}

// attachIssuedHy2ClientCert 用 [hysteria].tls_client_ca_file 对应的 CA 为当前 profile 签发短期客户端证书。
func attachIssuedHy2ClientCert(h *profileSchemaHy2, in buildProfileInput, caRelPath string) error {
	caCertPath := resolvePathRelativeToConfig(in.configPath, caRelPath)
	caKeyPath := resolvePathRelativeToConfig(in.configPath, certs.ClientCAKeyPath(caRelPath))
	cn, err := hy2ClientCertCommonName(in.username)
	if err != nil {
		return err
	}
	days := in.hy2ClientCertDays
	if days <= 0 {
		days = 90
	}
	issued, err := certs.IssueClientCertFromFiles(caCertPath, caKeyPath, cn, days)
	if err != nil {
		return fmt.Errorf("%s: %w", newLocErr("profile.issueHy2Cert", caCertPath).Error(), err)
	}
	h.ClientCertPEM = issued.CertPEM
	h.ClientKeyPEM = issued.KeyPEM
	return nil
}

func hy2ClientCertCommonName(username string) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("vpnport-%s-%s", username, hex.EncodeToString(b[:])), nil
}

func resolvePathRelativeToConfig(configPath, rel string) string {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return rel
	}
	if filepath.IsAbs(rel) {
		return rel
	}
	base := filepath.Dir(strings.TrimSpace(configPath))
	if base == "" || base == "." {
		return rel
	}
	return filepath.Join(base, rel)
}

// validFormat 限制 --format。
func validFormat(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json", "url", "both", "qr", "qr-png":
		return true
	}
	return false
}

// openProfileOutput 为 profile / credentials 输出选择 writer 及其收尾 closer。
//
//   - path 为空 → 直接写 fallback(stdout),closer 是 no-op(返回 nil)。
//   - path 非空 → 写进内存缓冲;closer 通过 writeFileTight **原子落盘**。
//
// 第三轮深扫 M3 加固:此前 force=true 走 `os.OpenFile(path, O_CREATE|O_WRONLY|O_TRUNC, 0600)`,含两处缺陷——
//   1. 无 O_EXCL / 无 Lstat:path 是符号链接时 open **跟随**它,把明文 PSK / hy2 密码 / mTLS client key
//      写进链接目标(泄密)或截断受害文件;
//   2. 0600 mode 只在**创建**文件时生效,覆盖既有 0644 文件会**保留** 0644 → 密材世界可读;
//   且 closer 里 `_ = f.Sync(); _ = f.Close()` 吞掉刷盘错误,ENOSPC/EIO 下产出截断密材却报成功。
// 改为复用兄弟函数 writeFileTight(CreateTemp O_EXCL + fchmod 0600 + fsync + 原子 rename):force 语义也交给它
// (false=目标存在即拒;true=覆盖但仍经临时文件+rename,不跟随链接),并把落盘错误经 closer 返回值交回调用方。
//
// 调用方约定:先写 writer,再**检查 closer() 返回值**(不要 `defer closeOut()` 把错误丢掉);写失败时直接
// 返回、不调 closer(不产出半截文件)。
func openProfileOutput(path string, fallback io.Writer, force bool) (io.Writer, func() error, error) {
	if strings.TrimSpace(path) == "" {
		return fallback, func() error { return nil }, nil
	}
	buf := &bytes.Buffer{}
	closer := func() error {
		if err := writeFileTight(path, buf.Bytes(), 0o600, force); err != nil {
			return fmt.Errorf("%s: %w", newLocErr("profile.openOutput", path).Error(), err)
		}
		return nil
	}
	return buf, closer, nil
}

func writeProfile(w io.Writer, p *profileSchema, format string, jsonGlobal bool) error {
	// 全局 --json 强制走 compact json，便于脚本管线消费（与其它 CLI 子命令一致）。
	if jsonGlobal {
		return writeJSONCompact(w, p)
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return writeJSONPretty(w, p)
	case "url":
		return writeURL(w, p)
	case "both":
		if err := writeJSONPretty(w, p); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
		return writeURL(w, p)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeJSONPretty(w io.Writer, p *profileSchema) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

func writeJSONCompact(w io.Writer, p *profileSchema) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n")
	return err
}

func writeURL(w io.Writer, p *profileSchema) error {
	url, err := profileToURL(p)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, url+"\n")
	return err
}

// portFromListenAddr 从形如 ":443" / "0.0.0.0:443" / "[::]:443" 的 listen 地址里取出端口。
//
// 解析失败 / 空串一律返回 0；调用方据此 fallback。
func portFromListenAddr(addr string) uint16 {
	if p, err := util.PrimaryPortFromUDPListenAddr(addr); err == nil {
		return p
	}
	s := strings.TrimSpace(addr)
	if s == "" {
		return 0
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return 0
	}
	portStr := strings.SplitN(s[idx+1:], ",", 2)[0]
	if strings.Contains(portStr, "-") {
		portStr = strings.SplitN(portStr, "-", 2)[0]
	}
	n, err := strconv.Atoi(portStr)
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return uint16(n)
}

// DeriveRealityPublicKey 从 32 字节 X25519 私钥派生公钥（curve25519 标量 base mult）。
//
// REALITY 与 Xray 行为一致：private_key 经 X25519 与基点相乘得到 public_key（32 字节）。
// 客户端会对该公钥做 "RawURL Base64 / Base64 / RawStd / Std" 任一 base64 解码再校验 32 字节。
func DeriveRealityPublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, newLocErr("profile.realityPrivLen", len(privateKey))
	}
	pub, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
