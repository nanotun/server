package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// ErrServerDialHostDNS 表示 ProbeServerDialHost 阶段 DNS 解析失败。
//
// 这是**硬错**:DNS 解不出来意味着这个字符串根本不是个真实地址,
// 调用方应直接拒保存,不要给 admin "跳过" 选项。典型触发:
//   - 域名拼错(`vpn.exampel.com`);
//   - 域名未在 DNS 注册;
//   - DNS server 异常(此场景偶发,admin 可换网络重试)。
//
// 用 errors.Is(err, ErrServerDialHostDNS) 来判定。
var ErrServerDialHostDNS = errors.New("server_dial_host: DNS 解析失败")

// ErrServerDialHostICMPSoftFail 表示 DNS OK 但 ICMP ping 0 回包。
//
// 这是**软错**:云服务商(AWS / Vultr / Linode 等)安全组默认 ban ICMP echo
// reply 是常见配置,即使服务器**完全合法且对外可用** ping 也不通。硬拒
// 会卡死大量合法用户。
//
// 调用方应:
//   - 默认拒保存,在 UI 上展示"ICMP 不可达"警告 + 提供「跳过 ICMP 检测」勾选;
//   - admin 勾选后传 force=true,跳过本检测直接 SetServerDialHost。
//
// 用 errors.Is(err, ErrServerDialHostICMPSoftFail) 来判定。
var ErrServerDialHostICMPSoftFail = errors.New("server_dial_host: ICMP 不可达(可能服务器 firewall 阻断 ping)")

// ServerDialHostKey 是 app_settings 表里持久化「客户端实际拨号的服务器地址」的 key。
//
// 2026-05-26 第六轮拆字段:此前 `advertised_host`(原 `public_host`)兼任两个角色 ——
//   - admin 起的"展示标签"(`prod-jp-1`、`测试机`、`test-203.0.113.10`);
//   - 客户端 PacketTunnel/NEVPN `tunnelRemoteAddress` 实际拨号目标。
//
// 现场踩坑:admin 把 advertised_host 配成 `test-203.0.113.10` 想做"带前缀的标签",
// 客户端把这个字符串塞进 NEPacketTunnelNetworkSettings → 触发
// `Invalid NETunnelNetworkSettings tunnelRemoteAddress` → 隧道挂掉。
// 字面上 `test-203.0.113.10` 看起来像 hostname,但末段 `.158` 是纯数字,
// RFC 952/3696 明确规定 TLD 不能纯数字 —— 实际 DNS 不可解析。
//
// 拆解后:
//   - `server_dial_host` (本 key):必须是**真实可拨号地址**,strict validation
//     接受 IPv4 / IPv6 / 合法 RFC 1035 hostname(末段必须含字母);
//   - `advertised_host` (相邻 file):放宽为**纯展示 label**,客户端不解析、不连接。
//
// 客户端 profile JSON 的 `host` 字段从这里取(真实 dial),`advertised_host`
// 字段从 advertised_host setting 取(展示 label)。
const ServerDialHostKey = "server_dial_host"

// GetServerDialHost 读 server_dial_host setting。空串表示未配置 —— 调用方应
// fail-fast(本字段是 client 拨号目标,空串 = 服务器对外不可用,直接报错让
// admin 去 /settings 显式声明,不要 silent fallback 到旧 advertised_host)。
//
// DB 错误返回 ("", err),让调用方决定。
func (s *Store) GetServerDialHost(ctx context.Context) (string, error) {
	v, ok, err := s.SettingsGet(ctx, ServerDialHostKey)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	return strings.TrimSpace(v), nil
}

// SetServerDialHost 写 server_dial_host setting。空串视为"清除"。
//
// 入库前必须用 [ValidateServerDialHost] 显式校验(handler/CLI 都已强制),
// 这里只做空白裁剪 + 长度保险栏(防御性,实际 validation 拒掉的不会走到这)。
func (s *Store) SetServerDialHost(ctx context.Context, host string) error {
	host = strings.TrimSpace(host)
	if len(host) > 253 {
		return i18nErr("store.dialHost.setterTooLong",
			fmt.Sprintf("server_dial_host 长度 %d 超过 RFC 1035 上限 253", len(host)), len(host))
	}
	return s.SettingsSet(ctx, ServerDialHostKey, host)
}

// ValidateServerDialHost 是给 handler / CLI 直接调的语义校验。
//
// 三选一接受:
//   - IPv4 字面量(如 "203.0.113.10");
//   - IPv6 字面量,带方括号(如 "[2001:db8::1]")或不带方括号纯文本(`2001:db8::1`);
//   - 合法 RFC 1035 hostname(如 "vpn.example.com"),且**末段必须含至少一个字母字符**。
//
// 末段含字母约束的理由(本轮加的):
//   - RFC 952/3696 明确 TLD label 不能纯数字 —— `test-203.0.113.10` / `1.2.3.4` 这类
//     伪 hostname 实际 DNS 不可解析,客户端塞进 PacketTunnel `tunnelRemoteAddress`
//     会触发 `Invalid NETunnelNetworkSettings tunnelRemoteAddress`;
//   - 纯数字末段的字符串理论上应走 IP path 解析,Go `net.ParseIP` 已能识别 IPv4;
//   - 这条约束就是为了拒掉"带 IP 风格末段但又不是合法 IP"的过渡形态。
//
// 拒绝(同 advertised_host 历史口径,防注入 / 误配):
//   - scheme(`http://` / `wss://`);
//   - path / query / fragment(`/x` / `?y` / `#z`);
//   - 端口号(`:8080`);
//   - 控制字符(`\n` / `\r` / `\t` / NUL);
//   - 长度 > 253。
//
// 空串视为合法(等同"清除"),但调用方在生成 profile QR 前应单独 fail-fast
// (本 key 空了意味着 server 无对外可拨号地址,不应继续 build profile)。
func ValidateServerDialHost(host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return nil
	}
	if len(h) > 253 {
		return i18nErr("store.host.tooLong",
			fmt.Sprintf("长度 %d 超过 RFC 1035 上限 253", len(h)), len(h))
	}
	if strings.ContainsAny(h, "\n\r\t\x00") {
		return i18nErr("store.host.controlChars", "不允许换行 / TAB / NUL 等控制字符")
	}
	lo := strings.ToLower(h)
	if strings.HasPrefix(lo, "http://") || strings.HasPrefix(lo, "https://") ||
		strings.HasPrefix(lo, "ws://") || strings.HasPrefix(lo, "wss://") {
		return i18nErr("store.host.scheme", "请只填裸地址 / 域名,不要带 scheme(如 https://)")
	}
	if strings.ContainsAny(h, "/?#") {
		return i18nErr("store.host.pathChars", "不允许 path / query / fragment 字符(/、?、#)")
	}
	if strings.Contains(h, "]:") {
		return i18nErr("store.host.portBracket", "不允许嵌入端口号 — profile 端口字段与 host 是分开的")
	}

	// (a) IPv4 / IPv6 字面量(含可选 `[]` 包裹的 IPv6)。
	if ip, ok := ParseLiteralIP(h); ok {
		// (a.1) 语法合法但**实际不可拨号**的 IP 类别 — 必须拒。
		// 这条防线在 ping 探活之前:127.0.0.1 在 server 机器上 ping 必然通,
		// 0.0.0.0 / 169.254.x / 多播段等也可能被 kernel routing 处理成假"可达",
		// 让客户端拿到这些字符串后必然连不上。
		//
		// reason 本身含 IP 类别关键词(loopback / link-local / …)+ 中文注解,
		// 作为 %s 参数透传给 web 翻译(技术细节保留中文,首句翻译)。
		if reasonErr := rejectedSpecialIP(ip); reasonErr != nil {
			return i18nErr("store.dialHost.specialIP",
				fmt.Sprintf("%s — 该地址客户端无法对外拨号", reasonErr.Error()), reasonErr)
		}
		return nil
	}

	// (b) host:port 形态(非 IPv6)— 单冒号 + 后段全数字。
	if !strings.HasPrefix(h, "[") {
		if strings.Count(h, ":") == 1 {
			parts := strings.SplitN(h, ":", 2)
			if isAllDigit(parts[1]) {
				return i18nErr("store.host.portColon", "不允许嵌入端口号 — 检测到 host:port 形式")
			}
		}
	}

	// (c) RFC 1035 hostname:每 label 1-63 字节,只含 [A-Za-z0-9-],首尾不为 '-',
	//     且 **末段(TLD)必须含至少一个字母字符**(RFC 952/3696)。
	//     validateRFC1035Hostname 的细分诊断(哪个 label 违规)作为 %s 参数透传。
	if err := validateRFC1035Hostname(h); err != nil {
		// 传 err 对象(而非 err.Error()):若 err 携带 LocaleKey(label 语法诊断),
		// 上层 translate 会按目标语言递归翻译这个 %s 参数;否则退回其 Error()。
		return i18nErr("store.dialHost.notValidHost",
			fmt.Sprintf("不是合法 IPv4 / IPv6 / 域名(末段含字母): %s", err.Error()), err)
	}
	return nil
}

// validateRFC1035Hostname 校验 hostname 的语法形态;返回的 error 仅供 wrap 进
// ValidateServerDialHost 的最终消息,不直接对外暴露。
//
// 规则:
//   - 不能空;
//   - 总长 1-253(已在外层 ValidateServerDialHost 校验,这里再插一道保险);
//   - 拆 '.' 为若干 label,每个 label:
//   - 长度 1-63;
//   - 字符只能是 [A-Za-z0-9-];
//   - 首尾不能是 '-';
//   - 最末 label(rightmost,等同 TLD)必须含至少一个字母字符
//     —— 这条是拒 `test-203.0.113.10` / `1.2.3.4`(虽然 1.2.3.4 走 IPv4 path
//     不到这,但拒纯数字 TLD 是 RFC 952/3696 公认 best practice)。
func validateRFC1035Hostname(s string) error {
	if s == "" {
		return fmt.Errorf("empty")
	}
	if len(s) > 253 {
		return fmt.Errorf("length %d > 253", len(s))
	}
	labels := strings.Split(s, ".")
	for i, lab := range labels {
		if len(lab) == 0 {
			return i18nErr("store.hostlabel.empty",
				fmt.Sprintf("label %d 为空(连续的 '.' 或首尾 '.')", i), i)
		}
		if len(lab) > 63 {
			return i18nErr("store.hostlabel.tooLong",
				fmt.Sprintf("label %d 长度 %d > 63", i, len(lab)), i, len(lab))
		}
		first, last := lab[0], lab[len(lab)-1]
		if first == '-' || last == '-' {
			return i18nErr("store.hostlabel.dashEdge",
				fmt.Sprintf("label %d %q 首尾不能为 '-'", i, lab), i, lab)
		}
		for _, r := range lab {
			if !isHostnameChar(r) {
				return i18nErr("store.hostlabel.badChar",
					fmt.Sprintf("label %d %q 含非法字符 %q", i, lab, r), i, lab, r)
			}
		}
	}
	last := labels[len(labels)-1]
	if !labelHasLetter(last) {
		return i18nErr("store.hostlabel.tldNoLetter",
			fmt.Sprintf("末段 label %q 必须含至少一个字母(拒纯数字 TLD,RFC 952/3696)", last), last)
	}
	return nil
}

// ParseLiteralIP 是 server_dial_host 跨包共享的「字面量 IP 判定」唯一来源。
//
// 行为:接受裸 IPv4 / 裸 IPv6 / **带方括号**的 IPv6(`[2001:db8::1]`),三种
// 都返回 IP + true。其他(域名 / 空串 / 含路径等噪声)返回 `nil, false`。
//
// 2026-05-27 第十三轮抽出:此前 [ValidateServerDialHost] 和 [ProbeServerDialHost]
// 各自实现「剥 [] 再 net.ParseIP」,而 web handler 的 `isLiteralIP` 直接 ParseIP
// **不剥**,导致 `[2001:db8::1]` 在 handler 被错判为非 literal → audit detail.probe
// 漂移、flash verb 写「DNS 已通过」(实际未做 DNS lookup,因为内部 Probe 是按
// literal 处理的)。本 helper 是单一来源,所有 server_dial_host 相关 literal
// 判定都应用它。
func ParseLiteralIP(host string) (net.IP, bool) {
	h := strings.TrimSpace(host)
	if h == "" {
		return nil, false
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return nil, false
	}
	return ip, true
}

// isHostnameChar 检查单字符是否落在 RFC 1035 hostname 允许集合 [A-Za-z0-9-]。
func isHostnameChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-'
}

// labelHasLetter 检查 label 是否含至少一个字母字符 [A-Za-z]。
func labelHasLetter(s string) bool {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// rejectedSpecialIP 检查 IP 是否落在"语法合法但客户端不可对外拨号"的特殊段。
//
// 返回非空 string = 拒,字符串本身是给 admin 看的解释;返回 "" = 通过。
//
// **拒的类别**(IPv4 / IPv6 对齐):
//   - **Unspecified**(0.0.0.0 / ::):语义"任意接口",connect() 在多数 OS 上
//     被转 127.0.0.1,客户端连本机失败;
//   - **Loopback**(127.0.0.0/8 / ::1):客户端连自己 loopback,绝对失败;
//   - **Link-local**(169.254.0.0/16 / fe80::/10):IPv4 link-local 跨网不可达;
//     IPv6 link-local 必须带 zone id(`fe80::1%en0`),不能作 server 公开地址;
//   - **Multicast**(224.0.0.0/4 / ff00::/8):组播,客户端 TCP 拨号不能用;
//   - **Broadcast**(255.255.255.255):限定广播,TCP 不可拨;
//   - **IPv4 兼容/映射**(::/96 头段、::ffff:x.x.x.x 后 32 位 IPv4):这是 IPv6
//     表示 IPv4 的过渡形态,语义上 = IPv4,落 server_dial_host 让客户端"以为是
//     IPv6 端点"反而走错 socket family。net.IP.To4() ≠ nil 这条已覆盖映射段。
//
// **不拒的类别**(刻意放行):
//   - **RFC1918 私网**(10/8 / 172.16-31/12 / 192.168/16):自托管 / 内网部署是
//     合法场景(`vpn.lan`),admin 应自己确认场景;web 端可以走 ProbeServerDialHost
//     的 ping 阶段验证可达性,这里语法层不阻断;
//   - **CGNAT**(100.64/10):ISP 共享段,海外节点偶有这类公网出口 routing 见过,
//     不拒。
//
// 实现:用 net.IP 的标准谓词(IsLoopback / IsLinkLocalUnicast 等),不直接比字符串,
// 这样 IPv4 / IPv6 / 映射形态全自动覆盖。
// 返回值改造(多语言):此前返回裸 string(中文技术细节),被上层当 %s 参数透传
// 到 store.dialHost.specialIP / store.probe.dnsResolvedTo,英文界面下会混出中文。
// 现返回携带 LocaleKey 的 LocalizedError(Error() 仍是原中文,供 CLI/日志/测试),
// 上层 translate 会按目标语言递归翻译;通过返 nil 表示「不拒」。
func rejectedSpecialIP(ip net.IP) error {
	switch {
	case ip.IsUnspecified():
		return i18nErr("store.specialip.unspecified",
			fmt.Sprintf("unspecified address %q(0.0.0.0 / :: 表示任意接口,不是真实端点)", ip.String()), ip.String())
	case ip.IsLoopback():
		return i18nErr("store.specialip.loopback",
			fmt.Sprintf("loopback %q(127.x / ::1,客户端拨到自己机器)", ip.String()), ip.String())
	case ip.IsLinkLocalUnicast():
		return i18nErr("store.specialip.linkLocal",
			fmt.Sprintf("link-local %q(169.254.x / fe80::/10,只在本网段可达)", ip.String()), ip.String())
	case ip.IsLinkLocalMulticast() || ip.IsMulticast():
		return i18nErr("store.specialip.multicast",
			fmt.Sprintf("multicast %q(224.0.0.0/4 / ff00::/8,客户端 TCP 不能拨)", ip.String()), ip.String())
	case ip.IsInterfaceLocalMulticast():
		return i18nErr("store.specialip.ifaceLocalMcast",
			fmt.Sprintf("interface-local multicast %q", ip.String()), ip.String())
	}
	// 限定广播 255.255.255.255 不被 IsMulticast 覆盖,显式拒。
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 {
			return i18nErr("store.specialip.broadcast",
				fmt.Sprintf("broadcast %q(255.255.255.255,TCP 不可拨)", ip.String()), ip.String())
		}
	}
	return nil
}

// CheckResolvedDialIPs 把一批 DNS 解析返回的 IPAddr 跑特殊段黑名单,任一命中即返
// [ErrServerDialHostDNS] 包装的人类可读错误(loopback / unspecified / link-local
// / multicast / 全 1 广播);全部通过返 nil。
//
// **2026-05-27 第十六轮 P1 抽出**:`ProbeServerDialHost` 域名分支在 LookupIPAddr
// 后内联跑这套检查;CLI `setting probe-dial-host --skip-icmp` 第十五轮新加路径
// 直接调 `net.DefaultResolver.LookupIPAddr` 但**漏查**黑名单 — 运维如果遇到 DNS
// 投毒或私网 resolver 把域名解析到 127.0.0.1 等危险 IP,CLI 会假阳性 ✓ 通过。
// 抽 exported helper 让两个路径共享同一份黑名单语义,避免漂移。
//
// 命中"任一即拒"的保守策略:与其落库后让客户端轮询时撞到 unreachable 候选,
// 不如让 admin 配 DNS 时就被打回(与 `ProbeServerDialHost` 原始域名分支同款语义)。
//
// host 仅用于错误信息中显示「域名 %q 解析到 %s」,允许是域名或调用方记的字符串。
func CheckResolvedDialIPs(host string, ips []net.IPAddr) error {
	for _, ipAddr := range ips {
		if reasonErr := rejectedSpecialIP(ipAddr.IP); reasonErr != nil {
			// i18nErrWrap:Error() 与原 `%w` 输出逐字节一致,Unwrap→ErrServerDialHostDNS
			// 让 errors.Is 照常成立;首句(sentinel)经 web trErr 按语言翻译。
			// reasonErr 为动态技术细节(自带 LocaleKey),作参数透传,上层按语言递归翻译。
			return i18nErrWrap("store.probe.dnsResolvedTo",
				fmt.Sprintf("%s: 域名 %q 解析到 %s — %s", ErrServerDialHostDNS.Error(), host, ipAddr.IP, reasonErr.Error()),
				ErrServerDialHostDNS, host, ipAddr.IP.String(), reasonErr)
		}
	}
	return nil
}

// ProbeServerDialHost 在 [ValidateServerDialHost] 语法过关之后,进一步做
// **真实网络可达性检测**。设计为 web handler 在 SetServerDialHost 之前调用,
// 拦截"语法对但实际拨号不通"的字符串(典型如 `test-203.0.113.10`:语法上像
// hostname,RFC1035 校验靠末段含字母这条放行,但 DNS 解不出来,客户端塞进
// PacketTunnel 会爆 `Invalid NETunnelNetworkSettings tunnelRemoteAddress`)。
//
// **两阶段检测**:
//
//  1. **DNS resolve**(必做):
//     - 字面 IPv4 / IPv6:trivially pass;
//     - 域名:`net.DefaultResolver.LookupIPAddr` 3s timeout,至少解出一个 IP;
//     - 失败 → 返回 wrap [ErrServerDialHostDNS] 的 error,**硬错**,调用方必须拒保存。
//
//  2. **ICMP ping**(advisory):
//     - 用 `prometheus-community/pro-bing` 的 **unprivileged UDP "ping"** 模式
//     (`SetPrivileged(false)`),不需要 root / cap_net_raw;
//     - 发 3 个 echo,interval 300ms,总 timeout 3s,任一回包视为通过;
//     - 0 回包 → 返回 wrap [ErrServerDialHostICMPSoftFail] 的 error,**软错**,
//     调用方应给 admin 一个「跳过 ICMP 检测」勾选(因为 AWS / Vultr / Linode
//     安全组默认 ban ICMP 是常见配置,合法 server 也可能 ping 不通)。
//
// **Linux 部署机的 unprivileged UDP ping 前置**:
//
//	sysctl -w net.ipv4.ping_group_range="0 65535"
//
// macOS / FreeBSD 同款 sysctl。如果 sysctl 未配,pro-bing 内部 socket 调用
// 会拿到 EPERM —— 本函数会把这个 errno 也归类为 ICMPSoftFail(因为对 admin
// 来说,环境没配好≠地址非法,不应硬拒)。
//
// **不在 CLI 层调** —— `nanotun-admin` 通常在 admin 笔记本上跑,SSH/scp 改
// server db,网络环境与 server 机器完全不同(笔记本能 ping 通≠server 能 ping
// 通,反之亦然)。CLI 只走 [ValidateServerDialHost] 语法校验,实际可达性由
// web handler 站在 server 机器视角检测。
//
// **ctx 取消语义**:本函数尊重 ctx.Done(),取消后立即停止 ping 并返回 ctx.Err()。
// 不返回包装错误,因为 ctx 取消是调用方主动行为,不是地址问题。
func ProbeServerDialHost(ctx context.Context, host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return nil
	}

	// 2026-05-26 第十轮扫描修:**遍历所有解析返回的 IP**,任一 ping 通即视为可达。
	// 老实现只 ping ips[0],对双栈域名(同时有 A + AAAA)采样不完整 — 若 v4 通
	// v6 不通(或反过来),只 ping 一个的结果对客户端拨号意义有限(客户端拨
	// hostname 时 OS resolver 决定走哪个栈)。任一通 = 整个域名标记可达,符合
	// 「probe 是 advisory check」的语义。全部失败才报 ICMPSoftFail。
	//
	// 字面 IP 路径只有一个 target,行为不变。
	var pingTargets []string
	if ip, ok := ParseLiteralIP(h); ok {
		pingTargets = []string{ip.String()}
	} else {
		naked := h // 域名路径不会含 `[]`,但保留变量名兼容下方错误信息
		dnsCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupIPAddr(dnsCtx, naked)
		if err != nil {
			// **优先识别 ctx 取消**:LookupIPAddr 拿到 ctx 错时会包成 `*net.DNSError`,
			// 但底层 cause 仍是 context.Canceled / DeadlineExceeded。如果不在这里
			// 先解开,handler 会误把"系统抖动"当成"DNS 真实失败"走 400 + audit。
			// 用 parent ctx(不是 dnsCtx)来判断 — dnsCtx 是自己 3s timeout,parent
			// 取消才是 admin 主动断开 / server shutdown 这类需要静默的场景。
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return i18nErrWrap("store.probe.dnsNoResolve",
				fmt.Sprintf("%s: 域名 %q 无法解析为 IP(请确认拼写 / DNS / 网络): %v", ErrServerDialHostDNS.Error(), naked, err),
				ErrServerDialHostDNS, naked, err.Error())
		}
		if len(ips) == 0 {
			return i18nErrWrap("store.probe.dnsNoRecord",
				fmt.Sprintf("%s: 域名 %q 无 A/AAAA 记录", ErrServerDialHostDNS.Error(), naked),
				ErrServerDialHostDNS, naked)
		}
		// 2026-05-26 第八轮扫描修:**DNS 解析结果也走特殊段黑名单**,防止
		// DNS 中毒 / 私网 DNS resolver 把域名解到 loopback / link-local 等
		// 客户端不可拨号的 IP。
		// 2026-05-27 第十六轮 P1:抽出 [CheckResolvedDialIPs] 让 CLI 共享同款语义。
		if err := CheckResolvedDialIPs(naked, ips); err != nil {
			return err
		}
		pingTargets = make([]string, 0, len(ips))
		for _, ipAddr := range ips {
			pingTargets = append(pingTargets, ipAddr.IP.String())
		}
	}

	// 串行 ping 每个 target(双栈通常 ≤ 2 个,串行最多 6s 不致命;并行省 timeout
	// 但要管理 goroutine 生命周期 + Stop() 取消传播,串行简单可靠)。任一通即返
	// nil,记录所有失败原因供 admin 排查。
	var lastErr error
	for _, target := range pingTargets {
		if err := pingOnce(ctx, target); err != nil {
			lastErr = err
			continue
		}
		// 任一 target 通 = 整个域名可达,不再 ping 剩余 target。
		return nil
	}
	// 走到这里 = 所有 target 都 fail,lastErr 必非 nil(pingTargets 非空,
	// 上面的循环至少跑一轮)。
	if lastErr != nil {
		// lastErr 传对象(而非 .Error()):pingOnce 返回携带 LocaleKey 的错误,
		// 上层 translate 按目标语言递归翻译这段 ping 明细。
		return i18nErrWrap("store.probe.icmpAllFailed",
			fmt.Sprintf("%s: 所有 %d 个解析 IP ping 均失败 — 最后一个错: %v", ErrServerDialHostICMPSoftFail.Error(), len(pingTargets), lastErr),
			ErrServerDialHostICMPSoftFail, len(pingTargets), lastErr)
	}
	return nil
}

// pingOnce 跑一次 ICMP probe,封装 pro-bing 的初始化 + 统计判定。
//
// 抽出来让多 IP 遍历能复用,返回 nil = ping 通(≥1 个回包);返回 err 已 wrap
// ErrServerDialHostICMPSoftFail sentinel。尊重 ctx.Done() — 取消时立即 Stop()
// 并返回 ctx.Err()(不带 sentinel,让上层短路到 503 静默路径)。
func pingOnce(ctx context.Context, target string) error {
	pinger, err := probing.NewPinger(target)
	if err != nil {
		return i18nErrWrap("store.ping.newPinger",
			fmt.Sprintf("%s: 初始化 pinger 失败 — %v", ErrServerDialHostICMPSoftFail.Error(), err),
			ErrServerDialHostICMPSoftFail, err.Error())
	}
	pinger.SetPrivileged(false)
	pinger.Count = 3
	pinger.Interval = 300 * time.Millisecond
	pinger.Timeout = 3 * time.Second

	done := make(chan error, 1)
	go func() {
		done <- pinger.Run()
	}()
	select {
	case runErr := <-done:
		if runErr != nil {
			return i18nErrWrap("store.ping.runFail",
				fmt.Sprintf("%s: ping %s 执行失败 — 可能 Linux 需要 `sysctl net.ipv4.ping_group_range=\"0 65535\"` 解锁 unprivileged UDP ping:%v",
					ErrServerDialHostICMPSoftFail.Error(), target, runErr),
				ErrServerDialHostICMPSoftFail, target, runErr.Error())
		}
	case <-ctx.Done():
		pinger.Stop()
		return ctx.Err()
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return i18nErrWrap("store.ping.noReply",
			fmt.Sprintf("%s: ping %s 未收到任何回包(发 %d / 收 0)— 服务器可能离线或 firewall 阻断 ICMP",
				ErrServerDialHostICMPSoftFail.Error(), target, stats.PacketsSent),
			ErrServerDialHostICMPSoftFail, target, stats.PacketsSent)
	}
	return nil
}
