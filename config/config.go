package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Duration 是 time.Duration 的 TOML 友好包装。
//
// 背景:pelletier/go-toml/v2 v2.2.4 反序列化 time.Duration 时,**只接受 TOML 整数(纳秒)**,
// 字符串字面量(如 "30s"、"5m")会直接抛 `cannot decode TOML string into ... time.Duration`。
// 这个语义与文档/示例里习惯写的 "30s" 严重背离 —— 我们曾因此在一次部署后整个 nanotun 进程
// 无法启动(systemd 加 RestartPreventExitStatus,需要人工介入)。
//
// Duration 通过实现 encoding.TextUnmarshaler 解决这一坑:
//   - data_plane_ping_interval = "30s"     ✓  走 time.ParseDuration
//   - data_plane_ping_interval = "1h30m"   ✓  走 time.ParseDuration
//   - data_plane_ping_interval = 30000000000  ✓  pelletier 会先 Itoa 再调 UnmarshalText,
//     ParseDuration 失败后再 fallback 到 strconv.ParseInt(纳秒)
//   - data_plane_ping_interval 不写 / 留空      ✓  默认 0
//
// 用法:配置结构体里写 `Foo config.Duration`,使用点写 `time.Duration(cfg.Foo)`。
type Duration time.Duration

// UnmarshalText 让 pelletier/go-toml/v2 能反序列化 "30s" 这种字符串字面量。
// pelletier 在遇到带 TextUnmarshaler 的字段时,无论 TOML 源是字符串还是整数,
// 都会先 Stringify 再调用本方法,所以这里要兼容两种形态。
func (d *Duration) UnmarshalText(text []byte) error {
	s := string(text)
	if v, err := time.ParseDuration(s); err == nil {
		// 深扫第十轮 MED:字符串路径也套用亚毫秒下限。第八轮只在「裸整数」分支拦了
		// `= 30`(30ns),却漏了带单位但依然亚毫秒的 `"30ns"` / `"500us"` —— 它们
		// 走 time.ParseDuration 成功分支直接放行,同样让 ticker 亚毫秒空转刷屏。
		// 这里统一在「任何解析成功」后判正的亚毫秒并拒绝(0 保留=禁用)。
		if err := rejectInvalidInterval(s, v); err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		dur := time.Duration(n)
		// 深扫第八轮 MED:裸整数按纳秒解释(与 time.Duration 语义一致)。但一个正的
		// **亚毫秒**裸整数几乎必然是「忘了带单位」的误配 —— 例如把 ping 间隔写成
		// `data_plane_ping_interval = 30`(本意 30 秒),会被当成 30ns,让 time.Ticker
		// 每 30ns 触发一次 → CPU 空转 + 日志/网络刷屏。这类值直接拒绝并提示补单位,
		// 而不是静默上线一个刷屏配置。0 保留(表示禁用),显式大整数纳秒(如 30000000000
		// = 30s)仍照常接受。
		if err := rejectInvalidInterval(s, dur); err != nil {
			return err
		}
		*d = Duration(dur)
		return nil
	}
	return fmt.Errorf("config: invalid duration %q (expected forms: \"30s\" / \"5m\" / 30000000000)", s)
}

// rejectInvalidInterval 拒绝对「间隔」语义无意义的时长:本项目里所有 Duration 字段
// (目前仅 data_plane_ping_interval)都是「间隔」语义。
//   - 正且 < 1ms:几乎必然是忘带单位的误配(如 `= 30` 本意 30s),会让 ticker 空转刷屏;
//   - 负数(深扫第十一轮 LOW):没有任何间隔含义,当前会被 wss_keepalive 静默当成「禁用」,
//     掩盖 `-1s` 这类打错的符号。显式拒绝,让运维知道要写 0 才是禁用。
//
// 0 表示禁用,保留放行。
func rejectInvalidInterval(raw string, dur time.Duration) error {
	if dur < 0 {
		return fmt.Errorf("config: duration %q parsed as %v — negative intervals are not meaningful; "+
			"use 0 to disable or a positive value (e.g. %q)", raw, dur, "30s")
	}
	if dur > 0 && dur < time.Millisecond {
		return fmt.Errorf("config: duration %q parsed as %v — sub-millisecond intervals are almost "+
			"always a missing-unit typo; use at least 1ms (e.g. %q)", raw, dur, "30s")
	}
	return nil
}

// Config 是服务端的完整配置（从 config.toml 加载）
type Config struct {
	Server   ServerConfig   `toml:"server"`
	Log      LogConfig      `toml:"log"`
	KCP      KCPConfig      `toml:"kcp"`
	TCP      TCPConfig      `toml:"tcp"`
	TUN      TUNConfig      `toml:"tun"`
	Hysteria HysteriaConfig `toml:"hysteria"`
	// Smux 非空且启用 hy2 或 REALITY 时：进程内环回 127.0.0.1:<server 端口> 使用单条 TCP + smux 多路复用（魔法前缀 VPN1）；否则 hy2/REALITY 仍为每流独立 dial。
	Smux   *SmuxConfig   `toml:"smux,omitempty"`
	Simple *SimpleConfig `toml:"simple,omitempty"` // 简单模式：无 WebSocket/TUN，smux 连上后发固定大小数据
	// Reality 可选：与 Xray-core v26.3.27 入站相同栈（github.com/xtls/reality@v0.0.0-20260322125925-9234c772ba8f）。
	// 握手完成后与明文 TCP 一样走 handleVPNLink（登录帧 + TUN）。环回本机 [server].listen_addr：未配 [smux] 时为每连接一次 TCP dial；
	// 若存在 [smux] 且与 hy2/REALITY 任一同时启用，则经环回 smux（单 TCP、首包 VPN1、每会话一条 stream）。参见 [reality]。
	Reality RealityConfig `toml:"reality,omitempty"`

	// 自托管 PSK 模式持久化层与管理后台配置。
	Store StoreConfig `toml:"store"`
	Admin AdminConfig `toml:"admin"`
}

// StoreConfig 控制 SQLite 持久化层的位置。
//
// DBPath 为空时使用默认 "data/nanotun.db"。允许传 ":memory:"（仅测试）。
type StoreConfig struct {
	DBPath string `toml:"db_path"`
}

// AdminConfig 是管理后台 HTTP 服务的占位配置。M0 仅落库不启用，
// 真正的 admin Web UI 在后续里程碑（M2）落地。
type AdminConfig struct {
	Enabled     bool   `toml:"enabled"`
	ListenAddr  string `toml:"listen_addr"`
	TLSCertFile string `toml:"tls_cert_file"`
	TLSKeyFile  string `toml:"tls_key_file"`
}

// HysteriaConfig 进程内 Hysteria 2（QUIC/UDP）。hy2 认证通过后，每个 TCP 代理流访问本机 VPN 端口 [server].listen_addr：
// 若存在 [smux] 且 hy2 已启用，则经环回 smux（单 TCP、首包 VPN1、每流一条 stream）；否则每流单独 dial 环回明文 TCP。
// 与公网直连明文 TCP 客户端共用同一套链路帧与 TUN。
// 当 password、tls_cert_file、tls_key_file 三项均非空时启用 hy2；须同时留空或同时配齐（见 ValidateHysteriaCredentials）。
// 数值型 QUIC/带宽/超时：0 表示使用 hysteria core 默认值（与官方服务端一致）。
type HysteriaConfig struct {
	ListenAddr string `toml:"listen_addr"` // UDP 监听；支持端口并集 :443,8443,5000-5100（Linux 上 iptables REDIRECT 至首端口）
	// PortHopIntervalSec 随 profile 下发给客户端的固定跳跃间隔（秒），≥5；0=默认 30。与 Min/Max 互斥。
	PortHopIntervalSec    int `toml:"port_hop_interval_sec"`
	PortHopIntervalMinSec int `toml:"port_hop_interval_min_sec"`
	PortHopIntervalMaxSec int `toml:"port_hop_interval_max_sec"`
	// PortHopIface 是 Linux iptables PREROUTING REDIRECT 规则的入接口限定(-i <iface>)。
	//
	// 默认空 = 不限定接口,与历史行为一致(任何入接口的 UDP 包,只要匹配 dport 都 REDIRECT
	// 到主端口)。在多网卡 / 多 routing-table / 容器宿主机上,空值会**所有**接口共用同一
	// 套 REDIRECT 规则,常导致:
	//   - 内网管理面网卡上的 UDP 服务被吞;
	//   - docker0 / cni0 上的容器流量错入 hy2;
	//   - 跳板机用 lo 回环测试时被误 redirect。
	//
	// 写明 iface 后(如 "eth0" / "ens3"),规则只匹配该接口的 UDP 包,可安全在多网卡机
	// 上部署。配置该字段不影响客户端配置(hy2 客户端只知道一个 sni + 端口集)。
	PortHopIface string `toml:"port_hop_iface"`
	TLSCertFile  string `toml:"tls_cert_file"`
	TLSKeyFile   string `toml:"tls_key_file"`
	// TLSClientCAFile 非空时启用 mTLS：客户端须提交由该 PEM 根/链签发的证书
	TLSClientCAFile string `toml:"tls_client_ca_file"`
	Password        string `toml:"password"` // 与官方 hysteria client 的 auth 字符串一致（单密码模式）
	// ObfsSalamanderPassword 非空时在 UDP 上启用 Salamander 混淆（与客户端 obfs.salamander.password 一致，至少 4 字节）
	ObfsSalamanderPassword string `toml:"obfs_salamander_password"`

	// QUIC 传输（0 = 默认：流/连接窗口 8MB/20MB、空闲 30s、最大入站流 1024）
	QUICInitialStreamRecvWindow uint64 `toml:"quic_initial_stream_recv_window"`
	QUICMaxStreamRecvWindow     uint64 `toml:"quic_max_stream_recv_window"`
	QUICInitialConnRecvWindow   uint64 `toml:"quic_initial_conn_recv_window"`
	QUICMaxConnRecvWindow       uint64 `toml:"quic_max_conn_recv_window"`
	// QUICMaxIdleTimeoutSec QUIC 连接空闲超时（秒）；hysteria 限制 4～120，0=默认 30
	QUICMaxIdleTimeoutSec       int   `toml:"quic_max_idle_timeout_sec"`
	QUICMaxIncomingStreams      int64 `toml:"quic_max_incoming_streams"`
	QUICDisablePathMTUDiscovery bool  `toml:"quic_disable_path_mtu_discovery"`

	// BandwidthMaxTxBps / BandwidthMaxRxBps：服务端相对「代理目标」方向的上/下行上限（字节/秒），0=不限；非 0 时须 ≥ 65536
	BandwidthMaxTxBps     uint64 `toml:"bandwidth_max_tx_bps"`
	BandwidthMaxRxBps     uint64 `toml:"bandwidth_max_rx_bps"`
	IgnoreClientBandwidth bool   `toml:"ignore_client_bandwidth"` // true 时忽略客户端声明带宽，用服务端拥塞配置

	UDPRelayEnabled   bool `toml:"udp_relay_enabled"`    // false 时 DisableUDP（当前 VPN 场景默认 false）
	UDPIdleTimeoutSec int  `toml:"udp_idle_timeout_sec"` // UDP 中继会话空闲（秒）；0=默认 60；有效 2～600

	ForwardDialTimeoutSec int `toml:"forward_dial_timeout_sec"` // dial 本机 VPN 端口超时（秒），0=15

	// MTU 与官方 hysteria 客户端 `mtu` 一致，随 node_login 下发；0 表示 JSON 省略。进程内 hy2 服务端由 quic-go 默认 InitialPacketSize（通常为 1280）与 path MTU 探测共同决定报文大小。
	MTU int `toml:"mtu"`

	// MasqueradeDir 非空时，未通过 hy2 认证的 HTTP 请求对该目录做静态文件响应（伪装站点）
	MasqueradeDir string `toml:"masquerade_dir"`

	// 2026-07-17:keepalive_ws_listen_addr / keepalive_ws_path 已下线(独立 WSS 保活被
	// 数据面 1s 链路 Ping 完全覆盖);旧配置中的这两个 key 会被 TOML 解码忽略,无需迁移。

	// 供 nanotun-admin 生成客户端 profile 时填入(不影响服务端运行,仅作为元数据)。
	// 不再上报给任何远端控制面;profile 命令读这两项决定客户端 tls.sni / tls.insecure。
	ReportTLSSNI          string `toml:"report_tls_sni"`           // 客户端 tls.sni；空则省略字段
	ReportTLSInsecureHint bool   `toml:"report_tls_insecure_hint"` // 提示客户端可设 tls.insecure
}

// SimpleConfig 简单模式配置（server-simple / client-simple）
type SimpleConfig struct {
	SendSizeMB int `toml:"send_size_mb"` // 服务端每个 stream 发送的字节数（MB），默认 600
}

// SmuxConfig 多路复用配置（与 github.com/xtaci/smux Config 对应，下发给客户端须一致）
type SmuxConfig struct {
	Version              int  `toml:"version"`              // 协议版本 1 或 2
	KeepAliveDisabled    bool `toml:"keepalive_disabled"`   // 是否禁用 keepalive
	KeepAliveIntervalSec int  `toml:"keepalive_interval_s"` // KeepAlive 间隔（秒）
	KeepAliveTimeoutSec  int  `toml:"keepalive_timeout_s"`  // 无数据时关闭 session 超时（秒）
	MaxFrameSize         int  `toml:"max_frame_size"`       // 单帧最大字节
	MaxReceiveBuffer     int  `toml:"max_receive_buffer"`   // 共享接收缓冲大小（smuxbuf）
	MaxStreamBuffer      int  `toml:"max_stream_buffer"`    // 每流缓冲大小（streambuf）
}

// TUNConfig 虚拟网卡配置：从 subnets 中选一个合法网段，只创建一张虚拟网卡
type TUNConfig struct {
	DeviceName        string   `toml:"device_name"`          // 虚拟网卡名称，如 "tun0"；程序启动时先删除该设备（若存在）再创建
	TCPConnlimitPerIP int      `toml:"tcp_connlimit_per_ip"` // 每虚拟 IP 最大并发 TCP 连接（iptables connlimit）；≤0 时按 40
	UDPConnlimitPerIP int      `toml:"udp_connlimit_per_ip"` // 每虚拟 IP 最大并发 UDP 连接；≤0 时按 40
	Subnets           []string `toml:"subnets"`              // VPN IPv4 网段候选列表；仅内网，不与本机网段冲突
	SubnetsV6         []string `toml:"subnets_v6"`           // VPN IPv6 网段候选列表（ULA 段，如 "fd00:200::/64"），可选；为空则不分配 IPv6 虚拟地址
	// DNSServersV4/V6 登录成功后经 ConvSaltLite 下发；无 IPv6 隧道时服务端不附带 dns_servers_v6
	DNSServersV4 []string `toml:"dns_servers_v4,omitempty"`
	DNSServersV6 []string `toml:"dns_servers_v6,omitempty"`
	// 从 TUN 转发出站时按目的端口 DROP（减轻滥用；可能误伤同端口合法服务，可按需 false）
	ForwardBlockBT          bool `toml:"forward_block_bt"`           // TCP+UDP 6881-6889
	ForwardBlockTracker6969 bool `toml:"forward_block_tracker_6969"` // TCP 6969
	ForwardBlockSMTP25      bool `toml:"forward_block_smtp_25"`      // TCP 25
	// ClientIsolate 控制 iptables/ip6tables 是否插入「同 TUN 设备客户端 → 客户端 DROP」规则。
	//
	// 默认 **false** —— 自托管 mesh 模式：同账号 / 同组下的客户端可以直接互访，
	// 任何细粒度策略由应用层 ACL（store/acl.go + util/AclMode）落实，便于实现 LAN-like
	// 协作（远程桌面、SMB、SSH、VoIP 等）。
	//
	// 设为 true 时回到老行为：在 FORWARD 链插入 `-i <tun> -o <tun> -j DROP`，把任何客户端
	// 之间的横向流量统统丢弃；适用于公共出口型部署、企业版「访客网络」等不允许互访的场景。
	//
	// 注意：本开关只影响**进程内**插入的 iptables 规则；如果同时还有外部 systemd
	// `nanotun-tun-isolate.service` 在跑，那是另一套独立机制（参见 cmd/nanotund/tun-isolate.sh），
	// 须各自启停。M0 起 systemd 单元已默认禁用 [Install]，相互不冲突。
	//
	// P2#16 以后 ExitMode 优先,ClientIsolate 仅作为「上一代配置」兼容路径(见 ResolveExitMode)。
	ClientIsolate bool `toml:"client_isolate"`

	// ExitMode(P2#16,2026-05-22):TUN 出口三档开关。比 ClientIsolate 表达更精细的拓扑:
	//
	//   - "mesh"     默认。允许同 TUN 客户端互访(ACCEPT i==o),允许出 WAN(SNAT/MASQUERADE)。
	//                这是"自托管组网工具"的本意:LAN-like 协作 + 偶尔代理出网。
	//                user 级再用 users.exit_allowed + ACL 决定谁能真正出网。
	//
	//   - "isolate"  禁止同 TUN 客户端互访(DROP i==o),仍允许出 WAN。
	//                公共出口型部署、企业版"访客网络"——只让用户用本机做 NAT 出口,
	//                不允许横向移动到别人虚拟 IP。
	//
	//   - "off"      禁止出 WAN(不装 SNAT,FORWARD device→wan DROP),仅允许同 TUN
	//                客户端互访。纯组网模式,把 nanotun 当 Tailscale-like 内网用,
	//                不希望任何流量经本机出公网(合规、计费、防滥用)。
	//
	// 兼容路径:ExitMode 空串 → 查 ClientIsolate:true → "isolate",false → "mesh"。
	// 想要 "off" 必须显式写 `[tun] exit_mode = "off"`。
	//
	// SIGHUP **不可热更**(改 iptables 规则集 + 重建 NAT 表,涉及现有连接;deferred ERROR)。
	ExitMode string `toml:"exit_mode,omitempty"`

	// ExitDNSRedirect(2026-07-03):服务器自出口的 DNS 接管。与「客户端做出口」对齐——
	// 无论客户端配了什么 DNS(常是下发的 8.8.8.8),经本机出网的 :53 查询都在 nat PREROUTING
	// DNAT 到「服务器自己可达的解析器」,使域名从服务器视角解析、解析出的 IP 也从服务器可达。
	// 修「服务器部署在墙内 / 客户端 DNS 从服务器够不着 → 域名解析失败」。仅出口模式(mesh/isolate)生效。
	//
	// 取值:
	//   ""(默认) / "auto"  → 自动探测服务器系统 DNS(/etc/resolv.conf 及 systemd-resolved 上游,
	//                        跳过环回/stub);探到则接管,探不到则跳过(退化为原样透传,无回归)。
	//   "off"              → 关闭接管,客户端 :53 原样转发到它自己选的上游(老行为)。
	//   "<IPv4>"           → 强制 DNAT 到该解析器(如 "223.5.5.5" / "1.1.1.1")。
	//
	// SIGHUP 不可热更(同 ExitMode,涉及 nat 表重建)。
	ExitDNSRedirect string `toml:"exit_dns_redirect,omitempty"`
}

// TUNExitMode 取值常量。
const (
	TUNExitModeMesh    = "mesh"
	TUNExitModeIsolate = "isolate"
	TUNExitModeOff     = "off"
)

// MagicDNSConfig 见 TUNConfig.MagicDNS 字段注释。
//
// 该 section 与 [tun].dns_servers_v4 / v6 兼容:
//   - magic_dns.enabled=false  → 仍按 [tun].dns_servers_* 下发(老行为不变);
//   - magic_dns.enabled=true   → server 起 DNS;客户端 DNSServersV4 = [magic gateway IP] + [tun].dns_servers_v4
//     (magic 排第一,确保 *.<suffix> 优先命中本地解析)。
type MagicDNSConfig struct {
	Enabled bool `toml:"enabled"`

	// DomainSuffix 是 Magic DNS 拦截的域名后缀,默认 "lan"。
	// 查询如 `alice-mac.alice.lan` → server 内查 leases 表 → 返回 vIP A/AAAA。
	// 非该 suffix 域名走 Upstream 转发(若未配置 upstream → SERVFAIL)。
	DomainSuffix string `toml:"domain_suffix,omitempty"`

	// ListenPort 是 DNS UDP 端口。默认 5353(避开系统 53 / cap_net_bind 限制)。
	// 客户端登录时收到的 DNSServersV4 会包含「TUN gateway IP:<此端口>」 —— 客户端解析栈
	// 必须支持非 53 端口;不支持时请改回 53(需 root / setcap cap_net_bind)。
	ListenPort uint16 `toml:"listen_port,omitempty"`

	// UpstreamV4 / UpstreamV6 是非 magic 域名的上游解析器。
	// 留空 → 收到非 magic 查询时回 SERVFAIL(强制 magic-only,防 leak)。
	UpstreamV4 []string `toml:"upstream_v4,omitempty"`
	UpstreamV6 []string `toml:"upstream_v6,omitempty"`
}

// ResolveExitMode 把 cfg 上的 ExitMode + ClientIsolate 翻译成最终生效的三档值。
// 输入**空字符串** → 用 ClientIsolate 退化(向后兼容老配置)。
// 这条逻辑必须在 SetupIptables 之前调一次,把字符串归一为 mesh/isolate/off。
//
// 未知非空值(如拼错的 "lockdown")本应在启动早期被 ValidateExitMode fail-fast 拦下,
// 不会流到这里;万一被绕过(测试 / 未调 Validate),default 分支仍退回兼容路径以免 panic,
// 但生产路径不依赖这个兜底。
func (t *TUNConfig) ResolveExitMode() string {
	switch strings.ToLower(strings.TrimSpace(t.ExitMode)) {
	case TUNExitModeMesh:
		return TUNExitModeMesh
	case TUNExitModeIsolate:
		return TUNExitModeIsolate
	case TUNExitModeOff:
		return TUNExitModeOff
	default:
		if t.ClientIsolate {
			return TUNExitModeIsolate
		}
		return TUNExitModeMesh
	}
}

// ValidateExitMode 在启动早期校验 tun.exit_mode。
//
// 深扫第八轮 MED:此前未知非空值会被 ResolveExitMode 静默退回 mesh(或 isolate),
// 即一个 typo(exit_mode = "lockdow")就能让一个本想「off / isolate」的部署以 mesh
// (跨用户互通)姿态上线 —— 静默 fail-open。这里对非空值强制枚举校验,非法即 fail-fast,
// 把 ClientIsolate 兼容退化严格限定在「exit_mode 留空」这一种情况。
func (t *TUNConfig) ValidateExitMode() error {
	switch strings.ToLower(strings.TrimSpace(t.ExitMode)) {
	case "", TUNExitModeMesh, TUNExitModeIsolate, TUNExitModeOff:
		return nil
	default:
		return fmt.Errorf("config: unknown tun.exit_mode %q (valid: %q / %q / %q, or leave empty)",
			t.ExitMode, TUNExitModeMesh, TUNExitModeIsolate, TUNExitModeOff)
	}
}

// ValidateExitDNSRedirect 在启动早期校验 tun.exit_dns_redirect,是 ValidateExitMode
// 的姊妹校验。
//
// 深扫第九轮 MED:此前该字段没有 fail-fast 校验,而 resolveExitDNSRedirect 对无法识别
// 的值(如把 "off" 拼成 "of")会 Warn 后**静默回退 auto**(自动探测系统 DNS 并接管)。
// 于是「运维想关掉 DNS 接管」的 typo 反而把 DNS 劫持**打开**了 —— 与 exit_mode 同类的
// fail-open-on-typo。这里对非空值强制枚举/IPv4 校验,非法即 fail-fast。
// 合法取值:""(默认) / "auto" / "off" / 合法 IPv4;大小写不敏感(IP 本身无大小写)。
func (t *TUNConfig) ValidateExitDNSRedirect() error {
	raw := strings.TrimSpace(t.ExitDNSRedirect)
	switch strings.ToLower(raw) {
	case "", "auto", "off":
		return nil
	}
	if ip := net.ParseIP(raw); ip != nil && ip.To4() != nil {
		return nil
	}
	return fmt.Errorf("config: invalid tun.exit_dns_redirect %q (valid: empty / \"auto\" / \"off\" / a literal IPv4 such as \"1.1.1.1\")",
		t.ExitDNSRedirect)
}

// LinkRateLimitPlatform 按登录 JSON 的 platform（小写匹配，如 linux、android）覆盖链路限速；某项为 0 表示该方向仍用全局默认（upload_rate/download_rate 及 [kcp] 回退）
type LinkRateLimitPlatform struct {
	UploadRate   int `toml:"upload_rate"`
	DownloadRate int `toml:"download_rate"`
}

// ServerConfig 主 VPN：ListenAddr 上为 HTTP + WebSocket Upgrade；链路帧跑在 WS Binary 上（每帧一条或多段 Write 拼流，见 cmd/nanotund/ws_stream_conn.go）
type ServerConfig struct {
	ListenAddr       string `toml:"listen_addr"`        // 监听，如 :8080（HTTP/WS 共用）
	VPNWebSocketPath string `toml:"vpn_websocket_path"` // WebSocket 路径，须以 / 开头，与客户端一致；空则用内置默认长路径
	Path             string `toml:"path"`               // 已废弃：请使用 vpn_websocket_path
	// TLSCertFile + TLSKeyFile 同时非空时：对外为 HTTPS/WSS（gorilla Upgrade）；环回本机 hy2/REALITY 使用 wss://127.0.0.1（自签时进程内跳过证书校验）
	TLSCertFile  string `toml:"tls_cert_file"`
	TLSKeyFile   string `toml:"tls_key_file"`
	UploadRate   int    `toml:"upload_rate"`   // 链路上行限速（对 Read），字节/秒；0 不限；未设时可回退 [kcp].upload_rate（见 server 启动逻辑）
	DownloadRate int    `toml:"download_rate"` // 链路下行限速（对 Write），字节/秒；0 不限；未设时可回退 [kcp].download_rate

	// ExitForwardRateBPS（exit-node M6 带宽帽）：每个使用出口节点的会话，其经出口转发的公网流量速率上限
	// （字节/秒），0/缺省 = 不限。出口中转占用 server 双倍带宽（A↔server↔出口客户端 D），可比常规链路更严地
	// 单独限速以防滥用。per-session 令牌桶非阻塞判定，超额丢包（fail-closed）。**重启生效**（非 SIGHUP 热更）。
	ExitForwardRateBPS int64 `toml:"exit_forward_rate_bps,omitempty"`
	// key 为 platform 小写字符串，与 LoginReq.platform 对齐（客户端多为 runtime.GOOS）
	RateLimitByPlatform map[string]LinkRateLimitPlatform `toml:"rate_limit_by_platform,omitempty"`
	// JumpHostFirewall 为 true 时（仅 Linux）:按 [server].jump_host_allowed_ips 用固定 ipset 名 + 自定义链限制本机「仅 listen_addr 对应 TCP 端口」入站；进程退出时清理。须安装 ipset、iptables。
	JumpHostFirewall bool `toml:"jump_host_firewall"`

	// JumpHostAllowedIPs:自托管 PSK 模式从配置文件静态注入跳板机 IPv4 名单。
	// **仅在 jump_host_firewall = true 时生效**。SIGHUP 可热更名单(见 cmd/nanotund/reload.go),
	// 但 jump_host_firewall 开关本身需重启才能生效。
	// 127.0.0.1 会被自动加入(本机 hy2 / REALITY 环回连 VPN 端口)。
	// 留空 + 启用 jump_host_firewall 会 Fatal,避免「以为开了限制实际全网开放」陷阱。
	JumpHostAllowedIPs []string `toml:"jump_host_allowed_ips,omitempty"`

	// JumpHostProtectedPorts(C6_full,2026-05-22):明确列出 jump_host_firewall 要保护的
	// 端口/协议清单。每项格式 "proto/port" 或 "proto/start-end":
	//   tcp/8080         单 TCP 端口(WSS gateway)
	//   tcp/8443         REALITY
	//   udp/443          hy2 主端口
	//   udp/5000-5002    hy2 端口跳跃区间
	//
	// 留空 = 退化为「只保护 [server].listen_addr 对应的 TCP 端口」(C6 之前的历史行为,
	// 即 hy2 / REALITY / 保活 wss 全部对全网开放)。强烈建议在自托管部署中明确列出全部
	// VPN 入口,否则跳板机限制只能挡一半门 —— 攻击者可以直接打 hy2 / REALITY 端口绕开。
	//
	// 注:本项变化需 systemctl restart 生效(改 iptables 规则,不是 G6 热更字段)。
	JumpHostProtectedPorts []string `toml:"jump_host_protected_ports,omitempty"`

	// DataPlanePingInterval(G_wss_ping):数据面 WSS 链路 server→client Ping 间隔。
	// 0 / 缺省 = 禁用(向后兼容老客户端,默认行为)。建议生产值 "30s",配合
	// DataPlanePingMissThreshold=3,即 90s 无 Pong 视为僵尸连接,主动 Close + 客户端
	// 重连。Rust 客户端在 1.x 及之后版本支持响应 LinkTypePing,启用前请确认客户端版本。
	//
	// 字段类型用本包的 Duration 包装(不是 time.Duration):pelletier/go-toml/v2 直接解析
	// time.Duration 时不接受 "30s" 字符串。详见 Duration 类型注释。读取时:
	//     interval := time.Duration(cfg.Server.DataPlanePingInterval)
	DataPlanePingInterval Duration `toml:"data_plane_ping_interval,omitempty"`

	// DataPlanePingMissThreshold(G_wss_ping):连续 N 次 Ping 没收到 Pong 视为链路死。
	// 0 / 缺省 = 3。计算公式:client 必须在 N * DataPlanePingInterval 时间内回复任一
	// Pong 才不被判死。设 1 会让正常网络抖动(单包丢)直接断,设过大又拖长检出。
	DataPlanePingMissThreshold int `toml:"data_plane_ping_miss_threshold,omitempty"`

	// MaxSessionsPerUser:同一 userID 最多并发会话数(全局默认值)。新登录超过上限时,
	// 踢掉**最老**的那一/几条,腾位置给新连接。
	//
	// **0 或缺省 = 不限制**(2026-07-20 起;此前缺省是 5)。>0 = 全局上限;-1 = 显式不限
	// (与缺省等价,保留写法兼容)。
	//
	// 账号级覆盖(0021):users.max_sessions 非 0 时优先于本值 —— >0 覆盖(可更松或
	// 更紧),-1 该账号显式不限。用 `nanotun-admin user set-max-sessions` 或 web
	// 用户详情页设置;仅对未来登录生效(登录时定格),现役会话不回踢。
	//
	// 设计权衡:
	//   - 同账号短时间内重复登录(网络抖动后客户端自动重连)不会被踢老的,因为客户端
	//     reconnect 会发 takeover(同 connIDStr,只换 linkConn),不计入新会话计数;
	//   - 同 device_uuid 重登另有无条件互踢(supersede),不受本上限影响;
	//   - 不限制模式下,持有 PSK 的用户理论上可无限并发占 conv_id / vIP;对外提供
	//     服务的部署建议显式配一个数字。
	MaxSessionsPerUser int `toml:"max_sessions_per_user,omitempty"`

	// LoginRateLimitPerMin(2026-06-23):每个源 IP 每分钟允许的登录尝试次数上限
	// (per-IP 令牌桶,进 argon2 verify 之前判定)。
	//
	//   - 0 / 缺省 = **不限制**(关闭 per-IP 登录令牌桶)。**这是默认值**。
	//   - N > 0    = 每 IP 每分钟最多 N 次登录尝试(突发额度固定为内置 loginRLBurst=3);
	//                超出时服务端直接回 429「登录请求过于频繁,请稍后再试」,
	//                **不**进入 argon2 verify。
	//
	// 为什么默认放开:自托管 / 小规模 / 移动端弱网频繁重连场景下,旧的固定 5/min 很容易
	// 误伤正常用户(网络抖动后客户端自动重连、AUTO 协议回退重试都会算尝试)。关掉本项后,
	// 防暴破的主要防线仍是**始终启用的 PoW**(失败难度 ramp)+ argon2id 全局并发 semaphore;
	// per-IP 令牌桶只是「单 IP 短窗口尝试次数」这一层额外兜底,按部署规模需要时再显式调高。
	//
	// 可 SIGHUP 热更:globalLoginIPLimiter 内部用 atomic 持有该值,改后立即对**新建**
	// per-IP entry 生效;切到 0(不限制)立即全量放行(无锁短路)。
	LoginRateLimitPerMin int `toml:"login_rate_limit_per_min,omitempty"`

	// HealthListenAddr: /health readiness probe 监听地址。默认 127.0.0.1:8081,
	// 独立 listener,**不**暴露给公网,k8s/lb/cron 通过本地反代或 ssh forward 拉。
	// 空串关闭 health 端点,1.1.1.1:port 等非环回地址需要运维显式配置(并自负风险:
	// 外部能拿到 TUN/store 就绪状态,辅助攻击者判断后端实例可用性)。
	HealthListenAddr string `toml:"health_listen_addr,omitempty"`

	// UserInvalidateIntervalSec(P0-1):server 周期扫描 users 表,主动踢掉已经被
	// disable / reset-psk / delete 的会话。<=0 或缺省 = 10s。这条扫描跑得越快,
	// admin 改 user 状态的「生效延迟」越短,但也越频繁占用 SQLite IO。10s 是
	// admin 操作期望 + DB 成本的平衡;紧急踢线由 nanotun-admin kick 子命令
	// 触发,不靠这条扫描。
	UserInvalidateIntervalSec int `toml:"user_invalidate_interval_sec,omitempty"`

	// LeaseGCIdleDays(P1#9):server 内置 lease_gc 定时任务的 idle 阈值(天)。
	// 默认 30 天(GcOrphanLeases 只删 manual=0 且对应 device.last_seen_at >
	// 阈值的 lease)。<=0 显式关闭定时回收,回归 admin CLI cron 模型。
	LeaseGCIdleDays int `toml:"lease_gc_idle_days,omitempty"`

	// LeaseGCIntervalHours(P1#9):lease_gc 循环间隔(小时)。默认 24。
	LeaseGCIntervalHours int `toml:"lease_gc_interval_hours,omitempty"`

	// ControlSocketPath(P1#6/7/8):admin <-> server 本地控制 socket(unix domain)。
	// 默认 /run/nanotun/control.sock,空串关闭(不提供 reload/kick/list 等接口)。
	//
	// 安全模型:
	//   - 文件权限 chmod 0600,仅 root 可读写;
	//   - 仅监听 SOCK_STREAM Unix domain,不暴露给网络;
	//   - 不做 auth(假设已经在 server host 上 root 才能访问 socket),
	//     未来若要给 ops 子账户访问,改成 chmod 0660 + chown root:opsteam。
	//
	// 接口:
	//   GET  /status                    返回 JSON {tun_ready, store_ready, conn_count, sessions[]}
	//   POST /reload?what=acl           触发 ACL snapshot 重建(等价 SIGHUP)
	//   POST /kick                      JSON {kind:session|device|user, id} → 主动断会话
	ControlSocketPath string `toml:"control_socket_path,omitempty"`

	// MagicDNS(P2#11,2026-05-22):server 内置 DNS server,把 peer 主机名解析成 vIP。
	// 类比 Tailscale Magic DNS:用户拿到「<device-name>.<user>.<suffix>」就能 ssh / curl 同账号下
	// 其它设备,不必记忆 100.64.0.x。详见 MagicDNSConfig。
	MagicDNS MagicDNSConfig `toml:"magic_dns,omitempty"`

	// PoW(P2#16,2026-05-24):VPN 登录前置 Proof-of-Work 防护配置。
	//
	// 项目决策:**始终启用** PoW(没有 enabled=false 开关)。理由是 server argon2id
	// 单 verify ~10ms,全局并发 semaphore 即使顶到上限单 attacker 也能通过持续 IP 替换
	// 把它打满让正常用户排队;PoW 把这部分 verify-cycle 的成本前置到 client 端 ——
	// 平时 8-bit(~5ms 客户端 CPU)无感,失败 ≥ failures_enable 跳 ramp(14-bit, ~50ms)
	// 然后 step_per_failure=2 阶梯上升,最高 adaptive_ceiling=22-bit。
	//
	// 老客户端兼容:服务端**永远要求** PoW,老客户端不会发 LinkTypePoWChallengeReq
	// 直接发 LoginReq → server 检测到首帧不是 PoWChallengeReq → 关闭连接(Code=412)。
	// 这是「客户端先升级,服务端后启用」的部署顺序要求,详见 PoW 设计文档。
	//
	// 参数热更新:hmac_key 启动随机不暴露,其它字段(难度公式 / ttl)reload 时无影响 ——
	// 老 challenge 在新 hmac_key 下全部失效是预期行为(重启即如此),改公式时同理。
	// 因此 PoW 段不进 reload 路径,改配置必须重启 server。
	Pow PoWConfig `toml:"pow,omitempty"`
}

// PoWConfig 见 ServerConfig.Pow 注释。所有字段缺省时 NewPoWService 用内置默认值,
// 确保「不配也能跑」的开箱即用语义。
type PoWConfig struct {
	// FailuresEnable:IP 失败 < 此值时下发 BaseDifficulty,>= 此值时跳 RampDifficulty。
	// 默认 0 = 从第 1 次登录就要 PoW(用 BaseDifficulty);设 3 = 头 3 次免 ramp(只要 8-bit)。
	// **不**让用户设负值。
	FailuresEnable int `toml:"failures_enable,omitempty"`

	// BaseDifficulty:平时难度。默认 8(~5ms M1 客户端,无感)。下限 4 上限 22。
	BaseDifficulty int `toml:"base_difficulty,omitempty"`

	// RampDifficulty:跳 ramp 之后的起步难度。默认 14(~50ms 客户端,有微觉察)。
	RampDifficulty int `toml:"ramp_difficulty,omitempty"`

	// StepPerFailure:ramp 之后每多一次失败的难度加成。默认 2。
	StepPerFailure int `toml:"step_per_failure,omitempty"`

	// AdaptiveCeiling:难度封顶。默认 22(~10s 客户端 / iPhone 15s),attacker 经济上不划算。
	AdaptiveCeiling int `toml:"adaptive_ceiling,omitempty"`

	// TTLSec:单道 challenge 的有效期(秒)。默认 300(5 分钟)。
	// 设得短一点能减少 powUsed sync.Map 的大小,但移动端弱网下解题 + LoginReq 往返
	// 可能需要 10s+,所以最好 ≥ 60。
	TTLSec int64 `toml:"ttl_sec,omitempty"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level string `toml:"level"`
}

// KCPConfig KCP 协议相关配置
type KCPConfig struct {
	ListenAddr   string `toml:"listen_addr"`
	ClientAddr   string `toml:"client_addr"` // 下发给客户端的 KCP 连接地址:端口
	DataShards   int    `toml:"data_shards"`
	ParityShards int    `toml:"parity_shards"`
	Crypt        string `toml:"crypt"`
	// NoDelay 参数
	NoDelay  int `toml:"nodelay"`  // 0:禁用(默认), 1:启用
	Interval int `toml:"interval"` // 协议内部工作的 interval，单位毫秒，比如 10ms 或 20ms
	Resend   int `toml:"resend"`   // 快速重传模式，0:关闭, 1:快速重传, 2:更激进
	NC       int `toml:"nc"`       // 是否关闭流控，0:不关闭, 1:关闭
	// MTU 和窗口大小
	MTU    int `toml:"mtu"`    // 最大传输单元
	SndWnd int `toml:"sndwnd"` // 发送窗口大小
	RcvWnd int `toml:"rcvwnd"` // 接收窗口大小
	Stream int `toml:"stream"` // 流模式, 0:消息模式, 1:流模式
	// 与 kcp-server-pure 对齐：DSCP、SockBuf、AckNodelay、WriteDelay
	DSCP       int  `toml:"dscp"`        // IP ToS DSCP，如 46
	SockBuf    int  `toml:"sockbuf"`     // UDP socket 读写缓冲（字节），如 4194304
	AckNodelay bool `toml:"acknodelay"`  // ACK 是否无延迟发送（与参考 false 对齐）
	FlushWrite bool `toml:"flush_write"` // 每次写入后是否立即 flush（客户端 KCP 会话生效）
	// 主 VPN server 已改用 [server].upload_rate/download_rate；此处仍为 server-simple 等沿用，且主服务在未配 [server] 限速时可回退读此两项
	UploadRate   int `toml:"upload_rate"`   // 字节/秒，0 不限
	DownloadRate int `toml:"download_rate"` // 字节/秒，0 不限
	// 简单模式（无 WebSocket）：服务端与客户端共用同一 key/salt/conv_id
	ConvID uint32 `toml:"conv_id"` // 简单模式固定会话 id，默认 1
	Salt   string `toml:"salt"`    // 简单模式 base64 盐，与客户端一致
	Key    string `toml:"key"`     // 简单模式 base64 密钥，与客户端一致（不填则服务端随机生成并下发，仅原 server 用）
}

// TCPConfig 数据面走 TCP + 记录层时的监听与参数
type TCPConfig struct {
	ListenAddr         string `toml:"listen_addr"`          // 监听地址，如 :3401
	ClientAddr         string `toml:"client_addr"`          // 下发给客户端的地址:端口；空则取 ListenAddr 端口拼公网占位（同 KCP）
	TokenTTLSeconds    int    `toml:"token_ttl_sec"`        // WS 下发后 TCP 握手 token 有效时间，默认 60
	MaxPlaintextRecord int    `toml:"max_plaintext_record"` // 单条记录明文上限，默认 65519
	Crypt              string `toml:"crypt"`                // 加密方式，与 [kcp].crypt 同名；默认 aes-256-gcm
	UploadRate         int    `toml:"upload_rate"`          // 上传速率限制（字节/秒），0 表示不限制
	DownloadRate       int    `toml:"download_rate"`        // 下载速率限制（字节/秒），0 表示不限制
}
