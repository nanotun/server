//go:build !linux

package main

import (
	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/util"
)

func setupHy2UDPPortHopRedirect(primaryPort uint16, portUnion, iface string) (func(), error) {
	_ = iface
	if util.UDPPortUnionNeedsHop(portUnion) {
		logrus.Warnf("Hy2 端口跳跃：非 Linux 主机，跳过 iptables REDIRECT（主端口 %d；并集 %q）", primaryPort, portUnion)
	}
	return func() {}, nil
}
