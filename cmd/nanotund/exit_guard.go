package main

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/nanotun/server/config"
)

// 本文件计算「出口路径上要拦掉哪些目的网段」。装规则的部分在 exit_guard_linux.go,这里只做纯计算,
// 便于单测覆盖(不需要 root / 不碰 iptables)。
//
// 要拦的原因见 config.TUNConfig.ExitDenyPrivate 注释:出口模式装的 `-i tun -o wan ACCEPT` + SNAT
// 把「经出网网卡可达的一切」都放行了,其中包括云厂商元数据(169.254.169.254)与服务器自己所处的
// 私网(云上单网卡形态下与出网流量共用一块卡)。

// 链路本地:无条件拦。经隧道访问它们没有任何正当用途,而 169.254.169.254 一条就等于
// 「把服务器的云身份(AWS IMDSv1 的 IAM 凭证 / GCP·Azure 的服务账号 token)交给每个 VPN 用户」。
var (
	linkLocalDenyV4 = netip.MustParsePrefix("169.254.0.0/16")
	linkLocalDenyV6 = netip.MustParsePrefix("fe80::/10")
)

// isPrivateDenyCandidateV4 判断一个 IPv4 前缀是否属于「不该经出口暴露给 VPN 用户」的地址空间。
// 含 RFC1918 三段 + CGNAT 100.64/10(运营商 NAT 段,云上也用来放内部服务)+ 链路本地。
func isPrivateDenyCandidateV4(p netip.Prefix) bool {
	a := p.Addr()
	if !a.Is4() {
		return false
	}
	// 0.0.0.0/0 之类的默认路由必须排除:它是「出网」本身,拦掉等于关掉出口。
	if p.Bits() == 0 {
		return false
	}
	return a.IsPrivate() || a.IsLinkLocalUnicast() || cgnatV4.Contains(a)
}

var cgnatV4 = netip.MustParsePrefix("100.64.0.0/10")

// isPrivateDenyCandidateV6 判断 IPv6 前缀是否属于 ULA(fc00::/7)或链路本地。
func isPrivateDenyCandidateV6(p netip.Prefix) bool {
	a := p.Addr()
	if a.Is4() || a.Is4In6() {
		return false
	}
	if p.Bits() == 0 {
		return false
	}
	return a.IsPrivate() || a.IsLinkLocalUnicast()
}

// parseIPRouteDests 从 `ip [-6] route show dev <iface>` 的输出里取出目的前缀。
//
// 每行首个字段是目的地:可能是 "10.5.0.0/24"、裸地址 "10.5.0.7"(等价 /32),或 "default"。
// 解析不了的行整行跳过 —— 探测失败只会少拦一个网段,绝不能让它阻断启动。
func parseIPRouteDests(out string) []netip.Prefix {
	var dests []netip.Prefix
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		dst := fields[0]
		if dst == "default" || dst == "unreachable" || dst == "blackhole" || dst == "prohibit" {
			continue
		}
		if p, err := netip.ParsePrefix(dst); err == nil {
			dests = append(dests, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(dst); err == nil {
			dests = append(dests, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return dests
}

// computeExitDenyPrefixes 算出最终要装成 DROP 的目的前缀(去重 + 排序,便于日志与单测稳定比对)。
//
//	mode        已归一的档位(auto / link-local / off)
//	candidates  探测到的「出网网卡上 on-link 或经它路由」的前缀(接口地址 + ip route show dev <wan>)
//	meshSubnets 本次生效的 VPN 网段:与之重叠的候选一律剔除,保证永不误伤 mesh / 网关 / MagicDNS
//	v6          选族
//
// link-local 档只回链路本地那一条;off 档回空。
func computeExitDenyPrefixes(mode string, candidates []netip.Prefix, meshSubnets []netip.Prefix, v6 bool) []string {
	if mode == config.TUNExitDenyPrivateOff {
		return nil
	}
	base := linkLocalDenyV4
	if v6 {
		base = linkLocalDenyV6
	}
	out := []netip.Prefix{base}

	if mode == config.TUNExitDenyPrivateAuto {
		for _, c := range candidates {
			c = c.Masked()
			if v6 {
				if !isPrivateDenyCandidateV6(c) {
					continue
				}
			} else if !isPrivateDenyCandidateV4(c) {
				continue
			}
			// 与 VPN 网段重叠的前缀必须放过:mesh 互访、网关自身(MagicDNS)、已批准子网路由
			// 都可能落在里面,拦了就是把自家数据面打断。
			if overlapsAny(c, meshSubnets) {
				continue
			}
			out = append(out, c)
		}
	}
	return dedupSortPrefixes(out)
}

func overlapsAny(p netip.Prefix, others []netip.Prefix) bool {
	for _, o := range others {
		if !o.IsValid() || o.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if p.Overlaps(o) {
			return true
		}
	}
	return false
}

// dedupSortPrefixes 去重并按字符串排序。另外剔除「已被列表里更短前缀包含」的冗余项:
// 探到 10.0.0.0/8 就不必再单独装 10.5.0.0/24,少一条规则少一次匹配。
func dedupSortPrefixes(in []netip.Prefix) []string {
	seen := make(map[string]netip.Prefix, len(in))
	for _, p := range in {
		if p.IsValid() {
			seen[p.String()] = p
		}
	}
	var kept []string
	for s, p := range seen {
		redundant := false
		for s2, p2 := range seen {
			if s == s2 || p2.Bits() >= p.Bits() {
				continue
			}
			if p2.Contains(p.Addr()) {
				redundant = true
				break
			}
		}
		if !redundant {
			kept = append(kept, s)
		}
	}
	sort.Strings(kept)
	return kept
}

// parseMeshPrefixes 把配置里的网段字符串(如 "10.201.0.0/16")解析成前缀,解析不了的跳过。
func parseMeshPrefixes(subnets []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range subnets {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}
