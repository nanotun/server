//go:build !linux

package main

import (
	"fmt"
	"net"
)

func GetLocalSubnets() ([]*net.IPNet, error) {
	return nil, nil
}

func GetLocalSubnetsV6() ([]*net.IPNet, error) {
	return nil, nil
}

func SubnetOverlaps(a, b *net.IPNet) bool {
	return false
}

func DeleteExistingTUNs(prefix string, n int) {}

func DeleteExistingTUN(name string) {}

func EnableIPForward() error {
	return fmt.Errorf("ip_forward only supported on Linux")
}

func EnableIPv6Forward() error {
	return fmt.Errorf("ipv6 forwarding only supported on Linux")
}

func GetWAN() (iface, ip string, err error) {
	return "", "", fmt.Errorf("WAN detection only supported on Linux")
}

// hasIPv4DefaultRoute 非 Linux 上恒为 false:该平台不进生产数据面(isProductionLinuxRoot
// 为假,GetWAN 失败只 Warn),返回 false 让调用点走「容忍跳过」那条即可。
func hasIPv4DefaultRoute() bool { return false }

func GetWANv6() (iface, ip string, err error) {
	return "", "", fmt.Errorf("IPv6 WAN detection only supported on Linux")
}

func SetupIptables(deviceName, wanIface, wanIP string, subnets []string, tcpConnlimit, udpConnlimit int, _, _, _ bool, _, _, _ string, _ string, _ int) error {
	return fmt.Errorf("iptables only supported on Linux")
}

func SetupIp6tables(deviceName, wanIface, wanIP string, subnets []string, tcpConnlimit, udpConnlimit int, _, _, _ bool, _, _, _ string, _ string, _ int) error {
	return fmt.Errorf("ip6tables only supported on Linux")
}

func SetupMagicDNSV6Exception(deviceName, gwV6 string, port int) error {
	return fmt.Errorf("ip6tables only supported on Linux")
}
