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

// PrimaryPortFromUDPListenAddr 取端口并集的第一个端口（主监听口）。
func PrimaryPortFromUDPListenAddr(addr string) (uint16, error) {
	_, portUnion, err := SplitUDPListenAddr(addr)
	if err != nil {
		return 0, err
	}
	pu := hyutils.ParsePortUnion(portUnion)
	if len(pu) == 0 {
		return 0, fmt.Errorf("invalid port union in %q", addr)
	}
	return pu[0].Start, nil
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
