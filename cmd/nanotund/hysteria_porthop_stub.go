//go:build !linux

package main

import (
	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/util"
)

func setupHy2UDPPortHopRedirect(primaryPort uint16, portUnion, iface string) (func(), error) {
	_ = iface
	if util.UDPPortUnionNeedsHop(portUnion) {
		logrus.Warnf("Hy2 port hopping: not a Linux host, skipping the iptables REDIRECT (primary port %d; union %q)", primaryPort, portUnion)
	}
	return func() {}, nil
}

// sweepHy2UDPPortHopByComment 在非 Linux 上没有 iptables 可清,恒返回 0。
// 存在的意义只是让 hysteria.go 里跨平台的 sweepHy2PortHopFn 接缝能编译。
func sweepHy2UDPPortHopByComment() int { return 0 }
