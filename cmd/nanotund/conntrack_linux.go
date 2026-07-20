//go:build linux

package main

import (
	"net"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ReleaseConntrackForIP 删除该源 IP 在 conntrack 中的全部条目，用于虚拟 IP 释放时清理 NAT 残留，
// 使 connlimit 的名额立即回收。同时支持 IPv4 和 IPv6。仅 Linux 有效，需 root 或 CAP_NET_ADMIN。
func ReleaseConntrackForIP(clientIP string) (uint, error) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return 0, nil
	}
	filter := &netlink.ConntrackFilter{}
	if err := filter.AddIP(netlink.ConntrackOrigSrcIP, ip); err != nil {
		return 0, err
	}
	family := netlink.InetFamily(unix.AF_INET)
	if ip.To4() == nil {
		family = netlink.InetFamily(unix.AF_INET6)
	}
	deleted, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, family, filter)
	if err != nil {
		logrus.WithError(err).WithField("clientIP", clientIP).Warn("清理 conntrack 失败")
		return deleted, err
	}
	if deleted > 0 {
		logrus.WithField("clientIP", clientIP).WithField("deleted", deleted).Info("已清理 conntrack 条目")
	}
	return deleted, nil
}
