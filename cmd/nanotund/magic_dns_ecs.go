package main

// magic DNS 上游转发的 EDNS Client Subnet(ECS,RFC 7871)注入。
//
// 背景(真机 e2e,2026-08-16):iOS meshOnly 要解除 AAAA 抑制必须给隧道装 v6 默认路由,而 v6
// 默认路由会让 iOS 把隧道 DNS 提升为系统默认解析器 —— 公网域名也经隧道到 magic DNS 转发上游。
// 上游看到的查询源是 server(如新加坡),CDN 域名被调度到 server 附近节点(baidu → 45.113.192.x
// 香港),国内客户端访问绕远。fullTunnel 各平台(macOS 已实测)同病。
//
// 修法:转发前把客户端会话对端 IP 的 /24(v4)// /56(v6)作为 ECS 附进查询,支持 ECS 的上游
//(223.5.5.5 / 8.8.8.8 等)即按客户端所在地调度(e2e 验证:新加坡带 ECS 问 223.5.5.5,baidu
// 恢复 180.101.x 国内节点)。不支持 ECS 的上游忽略该选项,无害。config `ecs_forward` 显式开启。
import (
	"encoding/binary"
	"net"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	ecsOptionCode = 8 // RFC 7871 CLIENT-SUBNET OPT option code
	// SOURCE PREFIX-LENGTH:v4 用 /24、v6 用 /56 —— RFC 7871 隐私建议的常用粒度,
	// 足够 CDN 定位到城市/运营商,又不向上游暴露完整客户端地址。
	ecsV4PrefixLen = 24
	ecsV6PrefixLen = 56
	// 新建 OPT 伪 RR 时声明的 UDP payload size(仅在查询原本没有 OPT 时用到;1232 为
	// DNS Flag Day 2020 推荐值,避免 IPv6 分片)。
	ecsUDPPayloadSize = 1232
)

// hostPartOf 取 "host:port" 的 host;没有 port(或解析失败)时原样返回。
// 与 handleVPNLink 登录路径对 globalLoginIPLimiter 的宽容语义一致。
func hostPartOf(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

// connRemoteHostForClientVIP 返回该客户端 vIP 所属会话底层链路的对端 IP(host)。
// found=false = 未找到会话或会话未记录对端。低频(仅上游转发路径触发),扫 connIDMap 可接受,
// 与 connCreatedAtForClientVIP 同款遍历。
func connRemoteHostForClientVIP(vip netip.Addr) (string, bool) {
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	for _, c := range connIDMap {
		if c == nil || c.takenOver.Load() {
			continue
		}
		for _, a := range c.safeClientIPs() {
			if pa, err := netip.ParseAddr(a.VirtualIP); err == nil && pa == vip {
				return c.remoteIPHost, c.remoteIPHost != ""
			}
		}
	}
	return "", false
}

// ecsCGNATv4:RFC 6598 共享地址空间。客户端从运营商 CGNAT 内网直连 server 时对端是这段,
// 对上游没有定位价值(且可能误导),按「非全球单播」同款跳过。
var ecsCGNATv4 = netip.MustParsePrefix("100.64.0.0/10")

// ecsEligibleClientIP 判断该对端 IP 是否值得作为 ECS 发给上游:必须是全球单播,
// 且不是 RFC1918/ULA 私网、不是 CGNAT。不合格 → 调用方直接跳过注入(转发不带 ECS,与旧行为一致)。
func ecsEligibleClientIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if ip.Is4() && ecsCGNATv4.Contains(ip) {
		return false
	}
	return true
}

// buildECSOptionData 构造 CLIENT-SUBNET 选项的 OPTION-DATA:
// FAMILY(2B) + SOURCE PREFIX-LENGTH(1B) + SCOPE PREFIX-LENGTH(1B,查询必须 0) + 截断到前缀的地址字节。
func buildECSOptionData(ip netip.Addr) []byte {
	ip = ip.Unmap()
	var family uint16
	var prefixLen int
	var addr []byte
	if ip.Is4() {
		family, prefixLen = 1, ecsV4PrefixLen
		a4 := ip.As4()
		addr = a4[:]
	} else {
		family, prefixLen = 2, ecsV6PrefixLen
		a16 := ip.As16()
		addr = a16[:]
	}
	nbytes := (prefixLen + 7) / 8
	data := make([]byte, 4+nbytes)
	binary.BigEndian.PutUint16(data[0:2], family)
	data[2] = byte(prefixLen)
	data[3] = 0
	copy(data[4:], addr[:nbytes])
	// 前缀非整字节时清零末字节尾部位(RFC 7871 要求;当前 24/56 均整字节,防御性保留)。
	if extra := nbytes*8 - prefixLen; extra > 0 {
		data[4+nbytes-1] &= byte(0xff << extra)
	}
	return data
}

// maybeInjectECS 是 forwardMagicDNSToUpstream 的注入入口:任何一步不适用(查不到会话、
// 对端非全球单播、查询已带 ECS、解包失败)都原样返回 query,绝不让 ECS 影响转发本身。
func maybeInjectECS(query []byte, peer *net.UDPAddr) []byte {
	vip, ok := netipAddrFromUDP(peer)
	if !ok {
		return query
	}
	host, found := connRemoteHostForClientVIP(vip)
	if !found {
		return query
	}
	clientIP, err := netip.ParseAddr(host)
	if err != nil || !ecsEligibleClientIP(clientIP) {
		return query
	}
	out, injected := injectECS(query, clientIP)
	if !injected {
		return query
	}
	return out
}

// injectECS 把 clientIP 的 ECS 选项拼进 DNS 查询:已有 OPT → 追加选项;没有 → 新建 OPT 伪 RR。
// 查询自带 ECS 时尊重客户端意图不覆盖(返回 ok=false)。解包/重打包失败同样 ok=false,调用方原样转发。
func injectECS(query []byte, clientIP netip.Addr) ([]byte, bool) {
	var m dnsmessage.Message
	if err := m.Unpack(query); err != nil {
		return nil, false
	}
	opt := dnsmessage.Option{Code: ecsOptionCode, Data: buildECSOptionData(clientIP)}
	patched := false
	for i := range m.Additionals {
		if m.Additionals[i].Header.Type != dnsmessage.TypeOPT {
			continue
		}
		body, isOpt := m.Additionals[i].Body.(*dnsmessage.OPTResource)
		if !isOpt {
			return nil, false
		}
		for _, o := range body.Options {
			if o.Code == ecsOptionCode {
				return nil, false
			}
		}
		body.Options = append(body.Options, opt)
		patched = true
		break
	}
	if !patched {
		m.Additionals = append(m.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(ecsUDPPayloadSize),
			},
			Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{opt}},
		})
	}
	out, err := m.Pack()
	if err != nil {
		return nil, false
	}
	return out, true
}
