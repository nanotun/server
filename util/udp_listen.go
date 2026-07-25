package util

import (
	"fmt"
	"strconv"
	"strings"

	hyutils "github.com/apernet/hysteria/extras/v2/utils"
)

// SplitUDPListenAddr 从 hysteria 风格 UDP listen 地址拆出 host 与端口并集字符串。
//
// 示例：":443,8443,5000-5100" → ("", "443,8443,5000-5100")；
// "0.0.0.0:443" → ("0.0.0.0", "443")；"[::]:443,8443" → ("::", "443,8443")。
func SplitUDPListenAddr(addr string) (host string, portUnion string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", fmt.Errorf("empty udp listen address")
	}
	if strings.HasPrefix(addr, "[") {
		rb := strings.Index(addr, "]")
		if rb < 0 {
			return "", "", fmt.Errorf("invalid ipv6 listen address %q", addr)
		}
		host = addr[1:rb]
		rest := addr[rb+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("expected ]:port in %q", addr)
		}
		portUnion = rest[1:]
		return host, portUnion, nil
	}
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", fmt.Errorf("missing port in udp listen address %q", addr)
	}
	return addr[:i], addr[i+1:], nil
}

// FormatUDPListenAddr 拼回 net.ListenPacket 可用的地址（仅主端口）。
func FormatUDPListenAddr(host string, primaryPort uint16) string {
	p := strconv.FormatUint(uint64(primaryPort), 10)
	if host == "" {
		return ":" + p
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + p
	}
	return host + ":" + p
}

// PrimaryPortFromUDPListenAddr 取端口并集里**书写顺序**的第一个端口（主监听口，真正
// bind 的那个；并集里其余端口由 iptables REDIRECT 折过来）。
//
// 不能直接用 hyutils.ParsePortUnion 的第 0 项：它会把并集升序排序并合并，
// ":8443,443" 解析出来第 0 项是 443 —— 于是主端口变成"最小端口"而不是配置里写的
// 第一个，和本函数名、config.listen_addr 注释、启动日志里的"主端口"三处说法都对不上，
// 且随管理员书写顺序静默改变绑定口。这里按原串取首个 token（"5000-5100,443" → 5000），
// 仍用 hysteria 的解析器校验整体合法性；首 token 解析不出来时回退到旧行为，
// 不让边角写法把服务器卡在启动失败上。
func PrimaryPortFromUDPListenAddr(addr string) (uint16, error) {
	_, portUnion, err := SplitUDPListenAddr(addr)
	if err != nil {
		return 0, err
	}
	pu := hyutils.ParsePortUnion(portUnion)
	if len(pu) == 0 {
		return 0, fmt.Errorf("invalid port union in %q", addr)
	}
	if p, ok := firstWrittenPort(portUnion); ok {
		return p, nil
	}
	return pu[0].Start, nil
}

// firstWrittenPort 从并集串里取书写顺序的第一个端口："8443,443" → 8443、
// "5000-5100,443" → 5000。解析不出合法端口时返回 ok=false，由调用方回退。
func firstWrittenPort(portUnion string) (uint16, bool) {
	head, _, _ := strings.Cut(strings.TrimSpace(portUnion), ",")
	head, _, _ = strings.Cut(strings.TrimSpace(head), "-")
	n, err := strconv.ParseUint(strings.TrimSpace(head), 10, 16)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint16(n), true
}

// PortUnionStringFromUDPListenAddr 返回端口并集子串（无 host），供 profile udp_ports 导出。
func PortUnionStringFromUDPListenAddr(addr string) (string, error) {
	_, portUnion, err := SplitUDPListenAddr(addr)
	return portUnion, err
}

// UDPPortUnionNeedsHop 端口并集是否含多个 distinct 口/段（需客户端 port hopping + 服务端 redirect）。
func UDPPortUnionNeedsHop(portUnion string) bool {
	pu := hyutils.ParsePortUnion(strings.TrimSpace(portUnion))
	if len(pu) == 0 {
		return false
	}
	if len(pu) > 1 {
		return true
	}
	return pu[0].Start != pu[0].End
}
