//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// resolveExitDNSRedirect 把 config 的 exit_dns_redirect 归一成实际要 DNAT 的解析器 IPv4。
//
//	"" / "auto" → 探测本机系统 DNS(detectSystemDNSv4);探不到返回 "" (不接管)
//	"off"       → 返回 "" (不接管)
//	"<IPv4>"    → 校验后原样返回;非法则告警 + 回退 auto 探测
func resolveExitDNSRedirect(setting string) string {
	s := strings.ToLower(strings.TrimSpace(setting))
	switch s {
	case "off":
		return ""
	case "", "auto":
		return detectSystemDNSv4()
	default:
		if ip := net.ParseIP(strings.TrimSpace(setting)); ip != nil && ip.To4() != nil {
			return ip.String()
		}
		logrus.WithField("exit_dns_redirect", setting).Warn(
			"iptables: exit_dns_redirect 不是合法 IPv4,回退 auto 探测系统 DNS")
		return detectSystemDNSv4()
	}
}

// detectSystemDNSv4 读 /etc/resolv.conf 及 systemd-resolved 上游,取第一个非环回 IPv4 nameserver。
// 用于服务器出口 DNS 接管的 DNAT 目标。探不到返回 ""(调用方跳过接管)。
//
// 跳过环回(含 systemd-resolved 的 127.0.0.53 stub):把转发流量 DNAT 到本机 stub 对外部客户端无意义,
// 且 stub 常只监听本地。systemd-resolved 场景真实上游在 /run/systemd/resolve/resolv.conf。
func detectSystemDNSv4() string {
	for _, path := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "nameserver") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			ip := net.ParseIP(fields[1])
			if ip == nil || ip.To4() == nil || ip.IsLoopback() {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

// setupExitDNSRedirect 在 nat PREROUTING 装 DNAT:从 TUN 进来、目的端口 53 的 udp/tcp 查询 → dnsIP:53。
// 幂等(-C 检查),规则带 mainIptComment(随 teardown/sweep 一并清)。dnsIP 为空则 no-op。
func setupExitDNSRedirect(bin, deviceName, dnsIP string) error {
	if dnsIP == "" || deviceName == "" {
		return nil
	}
	for _, proto := range []string{"udp", "tcp"} {
		ruleArgs := withMainComment([]string{
			"-i", deviceName, "-p", proto, "--dport", "53",
			"-j", "DNAT", "--to-destination", dnsIP + ":53",
		})
		check := append([]string{"-t", "nat", "-C", "PREROUTING"}, ruleArgs...)
		if exec.Command(bin, check...).Run() == nil {
			continue
		}
		args := append([]string{"-t", "nat", "-A", "PREROUTING"}, ruleArgs...)
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s nat PREROUTING DNS DNAT: %w (%s)", bin, err, strings.TrimSpace(string(out)))
		}
	}
	logrus.WithFields(logrus.Fields{"bin": bin, "dev": deviceName, "dns": dnsIP}).Info(
		"iptables: 已装出口 DNS 接管(:53 → 本机可达解析器)")
	return nil
}

// setupMagicDNSException 在启用 MagicDNS 时,给「客户端 → TUN 网关 IP:<port>」的 DNS 查询开两处例外:
//  1. nat PREROUTING RETURN:插到链首(-I 1),先于第 6 步出口 DNS 接管的 :53 DNAT。否则发往本机
//     MagicDNS 的查询会被 DNAT 到上游解析器,MagicDNS(只 listen 在 gateway IP)永远收不到,名字解析失败;
//  2. filter INPUT ACCEPT:插到链首,放行到本机 gateway:<port> 的入站。很多发行版 -P INPUT DROP
//     或 ufw 默认拒绝,不放行则 listener 收不到查询(表现为客户端 dig 超时)。
//
// 与 exitMode 无关:即便 off 模式没有 DNAT,INPUT 默认 DROP 仍会挡住 MagicDNS 查询,故两条都要装。
// 规则携带 mainIptComment,随启动 sweep / 退出 teardown 一并清理;幂等(-C 检查)。
// gwV4 为空或 port<=0(未启用 MagicDNS)时 no-op。
//
// 仅在 port == 53 时装:与 magicDNSExtraDNS 的 port==53 约束对齐(见 magic_dns.go)。
// 客户端 OS stub resolver 永远打 :53,非 53 端口时 server 不会给客户端 prepend 网关 DNS,
// 客户端根本不会查网关:<port>;且出口 DNS 接管的 DNAT 硬编码在 :53,非 53 端口上没有 DNAT
// 要绕过。故非 53 端口装这两条纯属死规则(无害但多余),直接跳过并 no-op。
func setupMagicDNSException(bin, deviceName, gwV4 string, port int) error {
	if gwV4 == "" || port != 53 || deviceName == "" {
		return nil
	}
	portStr := strconv.Itoa(port)
	// 1) nat PREROUTING RETURN:必须排在出口 DNS 接管 DNAT 之前 → 用 -I PREROUTING 1。
	for _, proto := range []string{"udp", "tcp"} {
		ruleArgs := withMainComment([]string{
			"-i", deviceName, "-d", gwV4, "-p", proto, "--dport", portStr, "-j", "RETURN",
		})
		check := append([]string{"-t", "nat", "-C", "PREROUTING"}, ruleArgs...)
		if exec.Command(bin, check...).Run() == nil {
			continue
		}
		insert := append([]string{"-t", "nat", "-I", "PREROUTING", "1"}, ruleArgs...)
		if out, err := exec.Command(bin, insert...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s nat PREROUTING MagicDNS RETURN: %w (%s)", bin, err, strings.TrimSpace(string(out)))
		}
	}
	// 2) filter INPUT ACCEPT:放行本机 gateway:<port> 的入站(先于 -P INPUT DROP / ufw)。
	for _, proto := range []string{"udp", "tcp"} {
		ruleArgs := withMainComment([]string{
			"-i", deviceName, "-d", gwV4, "-p", proto, "--dport", portStr, "-j", "ACCEPT",
		})
		check := append([]string{"-C", "INPUT"}, ruleArgs...)
		if exec.Command(bin, check...).Run() == nil {
			continue
		}
		insert := append([]string{"-I", "INPUT", "1"}, ruleArgs...)
		if out, err := exec.Command(bin, insert...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s filter INPUT MagicDNS ACCEPT: %w (%s)", bin, err, strings.TrimSpace(string(out)))
		}
	}
	logrus.WithFields(logrus.Fields{"bin": bin, "dev": deviceName, "gw": gwV4, "port": port}).Info(
		"iptables: 已装 MagicDNS 端口例外(nat PREROUTING RETURN + filter INPUT ACCEPT)")
	return nil
}

// GetLocalSubnets 返回本机所有 IPv4 接口的网段（用于冲突检测）
func GetLocalSubnets() ([]*net.IPNet, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []*net.IPNet
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		out = append(out, ipnet)
	}
	return out, nil
}

// GetLocalSubnetsV6 返回本机所有 IPv6 接口的网段（跳过 link-local），用于冲突检测
func GetLocalSubnetsV6() ([]*net.IPNet, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []*net.IPNet
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.To4() != nil || ipnet.IP.To16() == nil {
			continue
		}
		if ipnet.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ipnet)
	}
	return out, nil
}

// SubnetOverlaps 判断两个网段是否重叠
func SubnetOverlaps(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// DeleteExistingTUNs 删除已存在的虚拟网卡 prefix0..prefix(n-1)（兼容旧逻辑，多设备时用）
func DeleteExistingTUNs(prefix string, n int) {
	for i := 0; i < n; i++ {
		name := prefix + strconv.Itoa(i)
		_ = exec.Command("ip", "link", "delete", name).Run()
	}
	logrus.Infof("已清理虚拟网卡 %s0~%s%d（若存在）", prefix, prefix, n-1)
}

// DeleteExistingTUN 删除指定名称的虚拟网卡（若存在）；程序启动时先删再建
func DeleteExistingTUN(name string) {
	if name == "" {
		return
	}
	_ = exec.Command("ip", "link", "delete", name).Run()
	logrus.Infof("已清理虚拟网卡 %s（若存在）", name)
}

// ensureLooseRPFilter 把 TUN 设备的 rp_filter 设为 loose(2),原因见 SetupIptables 第 0 步。
// best-effort:失败只 Warn 不阻断(容器等场景 sysctl 可能只读;Ubuntu 默认 all=2 时无影响)。
func ensureLooseRPFilter(deviceName string) {
	key := fmt.Sprintf("net.ipv4.conf.%s.rp_filter=2", deviceName)
	if out, err := exec.Command("sysctl", "-w", key).CombinedOutput(); err != nil {
		logrus.WithError(err).WithField("out", strings.TrimSpace(string(out))).
			Warnf("sysctl %s 失败;若发行版 rp_filter 默认 strict,出口回程会被内核丢弃", key)
		return
	}
	logrus.Infof("已设置 %s(出口回程 hairpin 需要 loose 反向路由校验)", key)
}

// EnableIPForward 开启 IPv4 转发
func EnableIPForward() error {
	out, err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl ip_forward: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	logrus.Info("已开启 net.ipv4.ip_forward=1")
	return nil
}

// EnableIPv6Forward 开启 IPv6 转发
func EnableIPv6Forward() error {
	out, err := exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1").CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl ipv6 forwarding: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	logrus.Info("已开启 net.ipv6.conf.all.forwarding=1")
	return nil
}

// GetWAN 返回默认出站接口名和出口 IPv4（用于 NAT）
func GetWAN() (iface string, ip string, err error) {
	out, err := exec.Command("ip", "route", "get", "1.1.1.1").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("ip route get: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				iface = fields[i+1]
			}
			if fields[i] == "src" {
				ip = fields[i+1]
			}
		}
		if iface != "" && ip != "" {
			break
		}
	}
	if iface == "" || ip == "" {
		return "", "", fmt.Errorf("cannot parse WAN from: %s", string(out))
	}
	return iface, ip, nil
}

// GetWANv6 返回默认出站接口名和出口 IPv6 地址（用于 IPv6 NAT/路由）
func GetWANv6() (iface string, ip string, err error) {
	out, err := exec.Command("ip", "-6", "route", "get", "2001:4860:4860::8888").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("ip -6 route get: %w", err)
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" {
				iface = fields[i+1]
			}
			if fields[i] == "src" {
				ip = fields[i+1]
			}
		}
		if iface != "" && ip != "" {
			break
		}
	}
	if iface == "" || ip == "" {
		return "", "", fmt.Errorf("cannot parse IPv6 WAN from: %s", string(out))
	}
	return iface, ip, nil
}

// SetupIptables 配置 FORWARD、connlimit、（可选）隔离、NAT（幂等）。
// deviceName 为虚拟网卡名称（如 tun0），规则按该接口精确匹配。
// clientIsolate=true 时插入「-i <dev> -o <dev> -j DROP」客户端互访阻断规则；
// false（M0 起的 mesh 默认）时跳过这条规则，互访由上层 ACL 决定。
//
// C7: 所有装入的规则统一携带 `-m comment --comment nanotun_main`,启动期先 sweep
// 同 comment 的残留规则(上次进程异常退出留下的),退出期由调用方触发 sweep 撤掉。
// 这样进程崩 / kill -9 / 二进制升级都不会让 iptables 表里积累幽灵规则。
// P2#16:exitMode 三档语义见 config.TUNConfig.ResolveExitMode 注释。
// 老路径(布尔 clientIsolate)统一翻译成 exitMode 后进入,见 SetupIptablesLegacy。
func SetupIptables(deviceName, wanIface, wanIP string, subnets []string, tcpConnlimit, udpConnlimit int, blockBT, blockTracker6969, blockSMTP25 bool, exitMode, exitDNSRedirect string, magicDNSGwV4 string, magicDNSPort int) error {
	if deviceName == "" {
		deviceName = "tun0"
	}

	clientIsolate := exitMode == "isolate"
	allowExitWAN := exitMode != "off"
	logrus.WithFields(logrus.Fields{
		"exit_mode":      exitMode,
		"client_isolate": clientIsolate,
		"allow_exit_wan": allowExitWAN,
	}).Info("iptables: 解析 TUN 出口策略")

	// 启动前 sweep:把上次本进程留下的同 comment 残留全部清掉,保证「重启 = 干净安装」。
	// 不在乎本次和上次的 deviceName / wanIface 是否一致 —— comment 已经精确标记是本进程装的。
	sweepMainIptablesRules("iptables")

	// 0) TUN 设备 rp_filter 置 loose(2)。出口节点回程流量以公网 IP 为源从 TUN hairpin
	// 折返(正向包在用户态直投、内核无出向记录),strict(1) 下反向路由校验会把这些回包
	// 全部静默丢弃 —— 出口功能整体黑洞且 iptables 计数器看不到。内核取
	// max(conf/all, conf/<dev>) 为生效值,只设本设备即可保证 loose,不放松全局策略。
	// Ubuntu 默认 all=2 恰好能用,但不能赌发行版默认值(RHEL 系默认 strict)。
	ensureLooseRPFilter(deviceName)

	// 1) 客户端互访策略
	if clientIsolate {
		// 隔离模式：先清掉可能存在的 mesh ACCEPT，再插入 DROP，避免两条同时存在导致策略混乱
		removeAcceptArgs := withMainComment([]string{"-i", deviceName, "-o", deviceName, "-j", "ACCEPT"})
		for exec.Command("iptables", append([]string{"-C", "FORWARD"}, removeAcceptArgs...)...).Run() == nil {
			if err := exec.Command("iptables", append([]string{"-D", "FORWARD"}, removeAcceptArgs...)...).Run(); err != nil {
				logrus.WithError(err).Warn("iptables: 清理历史 device->device ACCEPT 规则失败")
				break
			}
		}
		if err := iptablesInsertForward([]string{"-i", deviceName, "-o", deviceName, "-j", "DROP"}); err != nil {
			return err
		}
		logrus.Info("iptables: 已添加客户端隔离 (device -> device DROP)")
	} else {
		// mesh 模式：清掉历史 DROP，并主动 ACCEPT 同 TUN 互访。
		// 主动 ACCEPT 是必须的——许多发行版默认 -P FORWARD DROP，或 ufw / firewalld 把转发链
		// 默认压成 DROP；不显式 ACCEPT 的话，去掉旧 DROP 也照样不通，伪装成「mesh 已开但其实不通」。
		removeDropArgs := withMainComment([]string{"-i", deviceName, "-o", deviceName, "-j", "DROP"})
		removed := false
		for exec.Command("iptables", append([]string{"-C", "FORWARD"}, removeDropArgs...)...).Run() == nil {
			if err := exec.Command("iptables", append([]string{"-D", "FORWARD"}, removeDropArgs...)...).Run(); err != nil {
				logrus.WithError(err).Warn("iptables: 清理历史 device->device DROP 规则失败")
				break
			}
			removed = true
		}
		if err := iptablesInsertForward([]string{"-i", deviceName, "-o", deviceName, "-j", "ACCEPT"}); err != nil {
			return err
		}
		if removed {
			logrus.Info("iptables: 已切换到 mesh（清理历史隔离 DROP，并 ACCEPT device <-> device）")
		} else {
			logrus.Info("iptables: 已启用 mesh（ACCEPT device <-> device，同 TUN 客户端互通）")
		}
	}

	// 2) connlimit（幂等），TCP/UDP 分别计数。
	// 必须加 -s <subnet> 只匹配「客户端网段为源」的包:FORWARD 链上还有出口节点回程的
	// hairpin 流量(tun→tun,源是公网 CDN IP;正向 client→exit 在用户态直投、不进内核,
	// conntrack 只见回程单向包)。不加 -s 时 connlimit 按 CDN 源 IP 计数,热门 CDN 边缘
	// 节点(多个域名解析到同一 IP,如 p1-p5.img.cctvpic.com)并发条目 >limit 后该 IP 的
	// 全部 TCP 包(含 SYN-ACK 与既有流数据)被 DROP——表现为经出口的页面加载整体黑洞
	// 数十秒,直到 CDN 侧 FIN 让 conntrack 条目过期(2026-07 tv.cctv.com 卡死根因)。
	for _, pl := range []struct {
		proto string
		limit int
	}{{"tcp", tcpConnlimit}, {"udp", udpConnlimit}} {
		if pl.limit <= 0 {
			continue
		}
		for _, subnet := range subnets {
			if subnet == "" {
				continue
			}
			ruleArgs := withMainComment([]string{"-i", deviceName, "-s", subnet, "-p", pl.proto,
				"-m", "connlimit", "--connlimit-above", strconv.Itoa(pl.limit),
				"--connlimit-saddr", "--connlimit-mask", "32", "-j", "DROP"})
			check := append([]string{"-C", "FORWARD"}, ruleArgs...)
			if exec.Command("iptables", check...).Run() == nil {
				continue
			}
			args := append([]string{"-I", "FORWARD", "1"}, ruleArgs...)
			if err := exec.Command("iptables", args...).Run(); err != nil {
				return fmt.Errorf("iptables connlimit %s: %w", pl.proto, err)
			}
		}
	}
	if tcpConnlimit > 0 || udpConnlimit > 0 {
		logrus.Infof("iptables: 已添加 connlimit TCP=%d/每IP UDP=%d/每IP", tcpConnlimit, udpConnlimit)
	}

	// 3) FORWARD: device <-> WAN
	if allowExitWAN {
		if err := iptablesInsertForward([]string{"-i", deviceName, "-o", wanIface, "-j", "ACCEPT"}); err != nil {
			return err
		}
		if err := iptablesInsertForward([]string{"-i", wanIface, "-o", deviceName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}); err != nil {
			return err
		}
		logrus.Info("iptables: 已添加 FORWARD device <-> WAN")
	} else {
		// P2#16 off 模式:确保不存在 device→wan ACCEPT(可能是上次 mesh 留下来的),
		// 同时显式插入 DROP,让默认 ACCEPT 的发行版也不会泄到 WAN。
		dropToWAN := withMainComment([]string{"-i", deviceName, "-o", wanIface, "-j", "DROP"})
		acceptToWAN := withMainComment([]string{"-i", deviceName, "-o", wanIface, "-j", "ACCEPT"})
		for exec.Command("iptables", append([]string{"-C", "FORWARD"}, acceptToWAN...)...).Run() == nil {
			if err := exec.Command("iptables", append([]string{"-D", "FORWARD"}, acceptToWAN...)...).Run(); err != nil {
				logrus.WithError(err).Warn("iptables(off): 清理历史 device->wan ACCEPT 失败")
				break
			}
		}
		check := append([]string{"-C", "FORWARD"}, dropToWAN...)
		if exec.Command("iptables", check...).Run() != nil {
			args := append([]string{"-I", "FORWARD", "1"}, dropToWAN...)
			if err := exec.Command("iptables", args...).Run(); err != nil {
				return fmt.Errorf("iptables off FORWARD drop: %w", err)
			}
		}
		logrus.Info("iptables: exit_mode=off,已 DROP FORWARD device->WAN(纯组网,无出口)")
	}

	// 4) NAT SNAT：每个可用网段一条（幂等）。off 模式跳过(没出口流量,SNAT 也没意义)。
	if allowExitWAN {
		for _, subnet := range subnets {
			ruleArgs := withMainComment([]string{"-s", subnet, "-o", wanIface, "-j", "SNAT", "--to-source", wanIP})
			check := append([]string{"-t", "nat", "-C", "POSTROUTING"}, ruleArgs...)
			if exec.Command("iptables", check...).Run() == nil {
				continue
			}
			args := append([]string{"-t", "nat", "-A", "POSTROUTING"}, ruleArgs...)
			if err := exec.Command("iptables", args...).Run(); err != nil {
				return fmt.Errorf("iptables NAT -s %s: %w", subnet, err)
			}
		}
		logrus.Infof("iptables: 已添加 NAT SNAT 共 %d 个网段", len(subnets))
	} else {
		logrus.Info("iptables: exit_mode=off,跳过 NAT SNAT(无出口流量)")
	}

	// 5) 出站目的端口 DROP（最后插入 -I FORWARD 1，位于 tun→wan ACCEPT 之前）。
	// off 模式没有出口流量,这些端口黑名单逻辑等于「黑名单上加黑名单」,跳过节省规则槽。
	if allowExitWAN {
		if err := insertTUNForwardPortDrops("iptables", deviceName, blockBT, blockTracker6969, blockSMTP25); err != nil {
			return err
		}
	}

	// 6) 出口 DNS 接管（PREROUTING DNAT :53 → 本机可达解析器）。与「客户端做出口」对齐:
	// 客户端配的 DNS(常是下发的 8.8.8.8)若从服务器网络够不着(墙内部署)则域名解析失败;
	// DNAT 到服务器自己的解析器,使域名从服务器视角解析。off 模式无出口流量,跳过。
	if allowExitWAN {
		if err := setupExitDNSRedirect("iptables", deviceName, resolveExitDNSRedirect(exitDNSRedirect)); err != nil {
			return err
		}
	}

	// 7) MagicDNS 端口例外(启用时)。与 exitMode 无关,须在第 6 步 DNAT 之后调用:
	// 内部用 -I PREROUTING 1 保证 RETURN 排在 DNAT 之前;并 -I INPUT 1 放行本机 gateway:<port>。
	if err := setupMagicDNSException("iptables", deviceName, magicDNSGwV4, magicDNSPort); err != nil {
		return err
	}
	return nil
}

// iptablesInsertForward 若规则不存在则 -I FORWARD 1 ...
//
// 自动追加 mainIptComment,与 sweep / teardown 路径配套(参见 iptables_sweep_linux.go)。
func iptablesInsertForward(ruleArgs []string) error {
	ruleArgs = withMainComment(ruleArgs)
	check := append([]string{"-C", "FORWARD"}, ruleArgs...)
	if exec.Command("iptables", check...).Run() == nil {
		return nil // 已存在
	}
	insert := append([]string{"-I", "FORWARD", "1"}, ruleArgs...)
	out, err := exec.Command("iptables", insert...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables -I FORWARD: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetupIp6tables 配置 IPv6 的 FORWARD、connlimit、（可选）隔离、NAT（幂等）。
// 语义见 SetupIptables;exitMode 也是三档 mesh/isolate/off。
// exitDNSRedirect 参数在 v6 侧暂不使用(DNS 接管走 v4 DNAT 到 v4 解析器,见 SetupIptables 第 6 步;
// 客户端 v6 DNS 查询无 v4 解析器可 DNAT 到,保持原样转发)。留参数是为调用点两个函数签名对齐。
func SetupIp6tables(deviceName, wanIface, wanIP string, subnets []string, tcpConnlimit, udpConnlimit int, blockBT, blockTracker6969, blockSMTP25 bool, exitMode, _ string) error {
	if deviceName == "" {
		deviceName = "tun0"
	}

	clientIsolate := exitMode == "isolate"
	allowExitWAN := exitMode != "off"
	logrus.WithFields(logrus.Fields{
		"exit_mode":      exitMode,
		"client_isolate": clientIsolate,
		"allow_exit_wan": allowExitWAN,
	}).Info("ip6tables: 解析 TUN 出口策略")

	// 启动前 sweep:同上面 SetupIptables。
	sweepMainIptablesRules("ip6tables")

	// 1) 客户端互访策略：语义见 SetupIptables
	if clientIsolate {
		removeAcceptArgs := withMainComment([]string{"-i", deviceName, "-o", deviceName, "-j", "ACCEPT"})
		for exec.Command("ip6tables", append([]string{"-C", "FORWARD"}, removeAcceptArgs...)...).Run() == nil {
			if err := exec.Command("ip6tables", append([]string{"-D", "FORWARD"}, removeAcceptArgs...)...).Run(); err != nil {
				logrus.WithError(err).Warn("ip6tables: 清理历史 device->device ACCEPT 规则失败")
				break
			}
		}
		if err := ip6tablesInsertForward([]string{"-i", deviceName, "-o", deviceName, "-j", "DROP"}); err != nil {
			return err
		}
		logrus.Info("ip6tables: 已添加客户端隔离 (device -> device DROP)")
	} else {
		removeDropArgs := withMainComment([]string{"-i", deviceName, "-o", deviceName, "-j", "DROP"})
		removed := false
		for exec.Command("ip6tables", append([]string{"-C", "FORWARD"}, removeDropArgs...)...).Run() == nil {
			if err := exec.Command("ip6tables", append([]string{"-D", "FORWARD"}, removeDropArgs...)...).Run(); err != nil {
				logrus.WithError(err).Warn("ip6tables: 清理历史 device->device DROP 规则失败")
				break
			}
			removed = true
		}
		if err := ip6tablesInsertForward([]string{"-i", deviceName, "-o", deviceName, "-j", "ACCEPT"}); err != nil {
			return err
		}
		if removed {
			logrus.Info("ip6tables: 已切换到 mesh（清理历史隔离 DROP，并 ACCEPT device <-> device）")
		} else {
			logrus.Info("ip6tables: 已启用 mesh（ACCEPT device <-> device，同 TUN 客户端互通）")
		}
	}

	// 2) connlimit（幂等），IPv6 用 128 位掩码；TCP/UDP 分别计数。
	// -s <subnet> 限定客户端源,原因同 SetupIptables 第 2 步(出口回程 hairpin 按公网源 IP 误限)。
	for _, pl := range []struct {
		proto string
		limit int
	}{{"tcp", tcpConnlimit}, {"udp", udpConnlimit}} {
		if pl.limit <= 0 {
			continue
		}
		for _, subnet := range subnets {
			if subnet == "" {
				continue
			}
			ruleArgs := withMainComment([]string{"-i", deviceName, "-s", subnet, "-p", pl.proto,
				"-m", "connlimit", "--connlimit-above", strconv.Itoa(pl.limit),
				"--connlimit-saddr", "--connlimit-mask", "128", "-j", "DROP"})
			check := append([]string{"-C", "FORWARD"}, ruleArgs...)
			if exec.Command("ip6tables", check...).Run() == nil {
				continue
			}
			args := append([]string{"-I", "FORWARD", "1"}, ruleArgs...)
			if err := exec.Command("ip6tables", args...).Run(); err != nil {
				return fmt.Errorf("ip6tables connlimit %s: %w", pl.proto, err)
			}
		}
	}
	if tcpConnlimit > 0 || udpConnlimit > 0 {
		logrus.Infof("ip6tables: 已添加 connlimit TCP=%d/每IP UDP=%d/每IP", tcpConnlimit, udpConnlimit)
	}

	// 3) FORWARD: device <-> WAN
	if allowExitWAN {
		if err := ip6tablesInsertForward([]string{"-i", deviceName, "-o", wanIface, "-j", "ACCEPT"}); err != nil {
			return err
		}
		if err := ip6tablesInsertForward([]string{"-i", wanIface, "-o", deviceName, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}); err != nil {
			return err
		}
		logrus.Info("ip6tables: 已添加 FORWARD device <-> WAN")
	} else {
		dropToWAN := withMainComment([]string{"-i", deviceName, "-o", wanIface, "-j", "DROP"})
		acceptToWAN := withMainComment([]string{"-i", deviceName, "-o", wanIface, "-j", "ACCEPT"})
		for exec.Command("ip6tables", append([]string{"-C", "FORWARD"}, acceptToWAN...)...).Run() == nil {
			if err := exec.Command("ip6tables", append([]string{"-D", "FORWARD"}, acceptToWAN...)...).Run(); err != nil {
				logrus.WithError(err).Warn("ip6tables(off): 清理历史 device->wan ACCEPT 失败")
				break
			}
		}
		check := append([]string{"-C", "FORWARD"}, dropToWAN...)
		if exec.Command("ip6tables", check...).Run() != nil {
			args := append([]string{"-I", "FORWARD", "1"}, dropToWAN...)
			if err := exec.Command("ip6tables", args...).Run(); err != nil {
				return fmt.Errorf("ip6tables off FORWARD drop: %w", err)
			}
		}
		logrus.Info("ip6tables: exit_mode=off,已 DROP FORWARD device->WAN(纯组网,无出口)")
	}

	// 4) NAT MASQUERADE：IPv6 一般不需要 NAT（全局可路由），但在 ULA 段时仍需 MASQUERADE。
	// off 模式跳过 —— 没出口流量,装了 SNAT 也是死规则。
	if allowExitWAN {
		for _, subnet := range subnets {
			ruleArgs := withMainComment([]string{"-s", subnet, "-o", wanIface, "-j", "MASQUERADE"})
			check := append([]string{"-t", "nat", "-C", "POSTROUTING"}, ruleArgs...)
			if exec.Command("ip6tables", check...).Run() == nil {
				continue
			}
			args := append([]string{"-t", "nat", "-A", "POSTROUTING"}, ruleArgs...)
			if err := exec.Command("ip6tables", args...).Run(); err != nil {
				return fmt.Errorf("ip6tables NAT -s %s: %w", subnet, err)
			}
		}
		logrus.Infof("ip6tables: 已添加 NAT MASQUERADE 共 %d 个网段", len(subnets))
	} else {
		logrus.Info("ip6tables: exit_mode=off,跳过 NAT MASQUERADE(无出口流量)")
	}

	if allowExitWAN {
		if err := insertTUNForwardPortDrops("ip6tables", deviceName, blockBT, blockTracker6969, blockSMTP25); err != nil {
			return err
		}
	}
	return nil
}

// insertTUNForwardPortDrops 从 TUN 转发、目的端口为常见滥用端口时 DROP（幂等）
func insertTUNForwardPortDrops(bin, deviceName string, blockBT, blockTracker6969, blockSMTP25 bool) error {
	if deviceName == "" {
		deviceName = "tun0"
	}
	var rules [][]string
	if blockBT {
		rules = append(rules, []string{"-p", "tcp", "--dport", "6881:6889", "-j", "DROP"})
		rules = append(rules, []string{"-p", "udp", "--dport", "6881:6889", "-j", "DROP"})
	}
	if blockTracker6969 {
		rules = append(rules, []string{"-p", "tcp", "--dport", "6969", "-j", "DROP"})
	}
	if blockSMTP25 {
		rules = append(rules, []string{"-p", "tcp", "--dport", "25", "-j", "DROP"})
	}
	for _, extra := range rules {
		if err := iptablesLikeInsertForward(bin, deviceName, extra); err != nil {
			return err
		}
	}
	if len(rules) > 0 {
		logrus.Infof("%s: 已添加 TUN 出站目的端口 DROP（%d 条）", bin, len(rules))
	}
	return nil
}

func iptablesLikeInsertForward(bin, deviceName string, extra []string) error {
	args := withMainComment(append([]string{"-i", deviceName}, extra...))
	check := append([]string{"-C", "FORWARD"}, args...)
	if exec.Command(bin, check...).Run() == nil {
		return nil
	}
	insert := append([]string{"-I", "FORWARD", "1"}, args...)
	out, err := exec.Command(bin, insert...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s -I FORWARD: %w (%s)", bin, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ip6tablesInsertForward 若规则不存在则 ip6tables -I FORWARD 1 ...
//
// 自动追加 mainIptComment,与 sweep / teardown 路径配套(参见 iptables_sweep_linux.go)。
func ip6tablesInsertForward(ruleArgs []string) error {
	ruleArgs = withMainComment(ruleArgs)
	check := append([]string{"-C", "FORWARD"}, ruleArgs...)
	if exec.Command("ip6tables", check...).Run() == nil {
		return nil
	}
	insert := append([]string{"-I", "FORWARD", "1"}, ruleArgs...)
	out, err := exec.Command("ip6tables", insert...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip6tables -I FORWARD: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
