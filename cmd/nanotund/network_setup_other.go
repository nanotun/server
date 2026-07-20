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

func GetWANv6() (iface, ip string, err error) {
	return "", "", fmt.Errorf("IPv6 WAN detection only supported on Linux")
}

func SetupIptables(deviceName, wanIface, wanIP string, subnets []string, tcpConnlimit, udpConnlimit int, _, _, _ bool, _, _ string, _ string, _ int) error {
	return fmt.Errorf("iptables only supported on Linux")
}

func SetupIp6tables(deviceName, wanIface, wanIP string, subnets []string, tcpConnlimit, udpConnlimit int, _, _, _ bool, _, _ string) error {
	return fmt.Errorf("ip6tables only supported on Linux")
}
