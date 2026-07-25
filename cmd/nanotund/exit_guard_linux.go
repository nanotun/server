//go:build linux

package main

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/nanotun/server/config"
	"github.com/sirupsen/logrus"
)

// detectWANPrivatePrefixes 探测「经出网网卡可达的私网前缀」,给 auto 档当候选集。
//
// 两个来源合并:
//  1. 出网网卡自身的地址 —— 云上单网卡形态(AWS/GCP/Azure)内网地址就挂在这块卡上,
//     它的 on-link 网段即整个 VPC 子网;
//  2. `ip route show dev <wan>` —— 覆盖「经出网网关再跳一层」的内网段(VPC peering、
//     机房内部路由),这类地址不在本机 on-link 网段里,只能从路由表看出来。
//
// 任何一步失败都只 Debug 后跳过:探测不到顶多少拦一段,绝不阻断启动。
func detectWANPrivatePrefixes(wanIface string, v6 bool) []netip.Prefix {
	var out []netip.Prefix
	if strings.TrimSpace(wanIface) == "" {
		return nil
	}

	if ifi, err := net.InterfaceByName(wanIface); err == nil {
		addrs, aerr := ifi.Addrs()
		if aerr != nil {
			logrus.WithError(aerr).Debug("[exit-guard] 读出网网卡地址失败,跳过该来源")
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is4() == v6 {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if p := netip.PrefixFrom(addr, ones); p.IsValid() {
				out = append(out, p.Masked())
			}
		}
	} else {
		logrus.WithError(err).Debug("[exit-guard] 找不到出网网卡,跳过接口地址来源")
	}

	args := []string{"route", "show", "dev", wanIface}
	if v6 {
		args = append([]string{"-6"}, args...)
	}
	if raw, err := exec.Command("ip", args...).Output(); err == nil {
		out = append(out, parseIPRouteDests(string(raw))...)
	} else {
		logrus.WithError(err).Debug("[exit-guard] ip route show dev 失败,跳过路由表来源")
	}
	return out
}

// applyExitDenyPrivate 在出口路径上装 DROP,拦掉链路本地 / 私网目的地。
//
// 装两处,各有分工:
//   - FORWARD `-i <tun> -o <wan> -d <prefix> DROP`:拦「借服务器出网访问内网邻居 / 云元数据」。
//     带 `-o <wan>` 限定出网方向,故不影响 tun→tun 互访,也不影响用户态直投的已批准子网路由。
//     off 出口模式下 FORWARD 已有一条全量 device→wan DROP,这里跳过省规则槽。
//   - INPUT `-i <tun> -d <prefix> DROP`:拦「服务器自己挂在私网卡上的地址」——目的是本机地址时
//     走 INPUT 而不是 FORWARD,不装这条的话内部管理面服务照样对 VPN 用户敞开。与出口模式无关,
//     纯组网(off)也要装。MagicDNS 的 INPUT ACCEPT 在本函数之后插入(-I INPUT 1),故排在前面,不受影响。
//
// 规则一律经 withMainComment,由既有 sweep / teardown 统一回收(见 iptables_sweep_linux.go)。
// 返回实际装上的前缀,供调用方打日志 —— 运维必须能一眼看到到底拦了哪些网段。
func applyExitDenyPrivate(bin, deviceName, wanIface, mode string, meshSubnets []string, allowExitWAN bool) ([]string, error) {
	v6 := bin == "ip6tables"
	if mode == config.TUNExitDenyPrivateOff {
		return nil, nil
	}
	var candidates []netip.Prefix
	if mode == config.TUNExitDenyPrivateAuto {
		candidates = detectWANPrivatePrefixes(wanIface, v6)
	}
	prefixes := computeExitDenyPrefixes(mode, candidates, parseMeshPrefixes(meshSubnets), v6)
	if len(prefixes) == 0 {
		return nil, nil
	}

	for _, p := range prefixes {
		if allowExitWAN && strings.TrimSpace(wanIface) != "" {
			if err := iptablesLikeInsertChain(bin, "FORWARD",
				[]string{"-i", deviceName, "-o", wanIface, "-d", p, "-j", "DROP"}); err != nil {
				return nil, fmt.Errorf("%s exit-guard FORWARD -d %s: %w", bin, p, err)
			}
		}
		if err := iptablesLikeInsertChain(bin, "INPUT",
			[]string{"-i", deviceName, "-d", p, "-j", "DROP"}); err != nil {
			return nil, fmt.Errorf("%s exit-guard INPUT -d %s: %w", bin, p, err)
		}
	}
	return prefixes, nil
}

// iptablesLikeInsertChain 若规则不存在则 `-I <chain> 1`,自动带 mainIptComment(幂等)。
func iptablesLikeInsertChain(bin, chain string, ruleArgs []string) error {
	ruleArgs = withMainComment(ruleArgs)
	if exec.Command(bin, append([]string{"-C", chain}, ruleArgs...)...).Run() == nil {
		return nil
	}
	out, err := exec.Command(bin, append([]string{"-I", chain, "1"}, ruleArgs...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s -I %s: %w (%s)", bin, chain, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// logExitDenyPrivate 把生效档位与实际拦掉的前缀打成一行 Info。
// 运维改了 exit_deny_private 或换了云环境后,应当能只看启动日志就知道闸门落在哪。
func logExitDenyPrivate(bin, mode string, prefixes []string) {
	if mode == config.TUNExitDenyPrivateOff {
		logrus.WithField("bin", bin).Warn("[exit-guard] exit_deny_private=off:出口不拦私网/链路本地 —— " +
			"VPN 用户可经本机访问云元数据(169.254.169.254)与服务器所处内网,确认这是本部署想要的")
		return
	}
	if len(prefixes) == 0 {
		return
	}
	logrus.WithFields(logrus.Fields{
		"bin":      bin,
		"mode":     mode,
		"prefixes": strings.Join(prefixes, ","),
	}).Info("[exit-guard] 已拦截出口方向的链路本地/私网目的地(含云元数据地址)")
}
