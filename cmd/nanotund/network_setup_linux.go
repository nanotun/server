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
//	"<IPv4>"    → 校验后原样返回;非法则 fail-safe 到「不接管」("")
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
		// 深扫第十轮 LOW:非法值 fail-safe 到「不接管」("")而非回退 auto 探测。
		// 正常路径 config.ValidateExitDNSRedirect 已在启动期挡掉任何非 ""/auto/off/IPv4
		// 的值(fail-fast),故对合法配置此分支不可达;这里仅作 defense-in-depth —— 万一有
		// 调用方绕过 Validate,也宁可「不启用 DNS 拦截」,不把误配(如 "of" 想写 "off")
		// 静默升级成 auto 接管 DNS。
		logrus.WithField("exit_dns_redirect", setting).Error(
			"iptables: exit_dns_redirect 不是合法 IPv4(应已被启动期校验拦截);按 fail-safe 不接管 DNS")
		return ""
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

// setupMagicDNSException 在启用 MagicDNS 时,给「客户端 → TUN 网关 IP:<port>」的 DNS 查询开例外:
//  1. filter INPUT ACCEPT:插到链首,放行到本机 gateway:<port> 的入站。很多发行版 -P INPUT DROP
//     或 ufw 默认拒绝,不放行则 listener 收不到查询(表现为客户端 dig 超时)。**两族都要**;
//  2. nat PREROUTING RETURN:插到链首(-I 1),先于 SetupIptables 第 6 步出口 DNS 接管的 :53 DNAT。
//     否则发往本机 MagicDNS 的查询会被 DNAT 到上游解析器,MagicDNS(只 listen 在 gateway IP)永远
//     收不到。**仅 v4**:出口 DNS 接管只在 v4 侧装 DNAT(见 SetupIp6tables 注释——客户端的 v6 查询
//     没有 v4 解析器可 DNAT 到),v6 上没有 DNAT 要绕过,装了是死规则。
//
// 与 exitMode 无关:即便 off 模式没有 DNAT,INPUT 默认 DROP 仍会挡住 MagicDNS 查询,故 INPUT 那条照装。
// 规则携带 mainIptComment,随启动 sweep / 退出 teardown 一并清理;幂等(-C 检查)。
// gwAddr 为空或 port<=0(未启用 MagicDNS)时 no-op。
//
// bin 决定地址族("iptables" / "ip6tables"),gwAddr 须与之匹配(v4 点分 / v6 冒号,均不带前缀长度)。
// v6 侧同样必须装:magic DNS 在 v4 与 v6 网关上成对 listen(见 server.go 的 startMagicDNS 调用),
// 而客户端(iOS 仅组网确定如此)会把 mesh ULA 网关一并写进解析器列表 —— v6 少了这条 ACCEPT,ip6tables
// 默认 DROP 的机器(ufw 开着即是)上 socket 明明在 LISTEN、查询也确实到了 tun0,却在进 socket 前就被
// 丢掉:凡是选了 v6 解析器的客户端都静默解不出 AAAA / 4via6,且抓包看着「包已到达」极易误判。
// (2026-08-17 iOS 18.7.9 实测该端把 AAAA 发给了 v4 网关,故 v6 这条是兜底路径,不是唯一路径。)
//
// 仅在 port == 53 时装:与 magicDNSExtraDNS 的 port==53 约束对齐(见 magic_dns.go)。
// 客户端 OS stub resolver 永远打 :53,非 53 端口时 server 不会给客户端 prepend 网关 DNS,
// 客户端根本不会查网关:<port>;且出口 DNS 接管的 DNAT 硬编码在 :53,非 53 端口上没有 DNAT
// 要绕过。故非 53 端口装这些纯属死规则(无害但多余),直接跳过并 no-op。
func setupMagicDNSException(bin, deviceName, gwAddr string, port int) error {
	if gwAddr == "" || port != 53 || deviceName == "" {
		return nil
	}
	portStr := strconv.Itoa(port)
	// 1) nat PREROUTING RETURN:必须排在出口 DNS 接管 DNAT 之前 → 用 -I PREROUTING 1。仅 v4 有该 DNAT。
	if bin != "ip6tables" {
		for _, proto := range []string{"udp", "tcp"} {
			ruleArgs := withMainComment([]string{
				"-i", deviceName, "-d", gwAddr, "-p", proto, "--dport", portStr, "-j", "RETURN",
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
	}
	// 2) filter INPUT ACCEPT:放行本机 gateway:<port> 的入站(先于 -P INPUT DROP / ufw)。
	for _, proto := range []string{"udp", "tcp"} {
		ruleArgs := withMainComment([]string{
			"-i", deviceName, "-d", gwAddr, "-p", proto, "--dport", portStr, "-j", "ACCEPT",
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
	installed := "filter INPUT ACCEPT + nat PREROUTING RETURN"
	if bin == "ip6tables" {
		installed = "filter INPUT ACCEPT(v6 无出口 DNS DNAT,不需 nat RETURN)"
	}
	logrus.WithFields(logrus.Fields{"bin": bin, "dev": deviceName, "gw": gwAddr, "port": port}).Infof(
		"%s: 已装 MagicDNS 端口例外(%s)", bin, installed)
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

// sysctlSet 写一个 `键=值` 形式的 sysctl 项。写失败时**回读一次实际值**,
// 已经是目标值则返回 preset=true、err=nil。
//
// 为什么要回读(2026-08-02 容器化实测):容器里 /proc/sys 是只读挂载,值由 Docker 在
// 创建容器那一刻按 --sysctl 预置。于是 `sysctl -w` 必然 permission denied,而目标状态
// **早就达成了**。不回读的话两类调用方都会误判:
//   - 致命项(ip_forward):转发明明开着,却以 exit 60 退出、容器无限重启,唯一出路是
//     --privileged —— 为一个已经生效的内核参数把整个 /proc/sys 敞开给容器。
//   - best-effort 项(rp_filter / send_redirects):每次启动刷一串 warning,把运维引向
//     一个不存在的故障。更糟的是真出问题时也分辨不出来 —— 两种情况的日志一模一样。
//
// 回读用 `sysctl -n` 而不是直接读 /proc/sys/<path>:后者绕过 PATH,会把这条路径从
// 故障注入测试里摘出去,而这里恰恰是「判错方向就整机不通」的地方,不能失去覆盖。
//
// 语义没有放宽:回读拿不到值、或值对不上,照样返回错误。
func sysctlSet(entry string) (preset bool, err error) {
	out, werr := exec.Command("sysctl", "-w", entry).CombinedOutput()
	if werr == nil {
		return false, nil
	}
	writeErr := fmt.Errorf("%w (%s)", werr, strings.TrimSpace(string(out)))
	key, want, ok := strings.Cut(entry, "=")
	if !ok {
		return false, writeErr
	}
	cur, rerr := exec.Command("sysctl", "-n", key).Output()
	if rerr != nil || strings.TrimSpace(string(cur)) != strings.TrimSpace(want) {
		return false, writeErr
	}
	return true, nil
}

// ensureLooseRPFilter 把 TUN 设备的 rp_filter 设为 loose(2),原因见 SetupIptables 第 0 步。
// best-effort:失败只 Warn 不阻断(容器等场景 sysctl 可能只读;Ubuntu 默认 all=2 时无影响)。
func ensureLooseRPFilter(deviceName string) {
	entry := fmt.Sprintf("net.ipv4.conf.%s.rp_filter=2", deviceName)
	preset, err := sysctlSet(entry)
	switch {
	case err != nil:
		logrus.WithError(err).
			Warnf("sysctl %s 失败;若发行版 rp_filter 默认 strict,出口回程会被内核丢弃", entry)
	case preset:
		logrus.WithField("sysctl", entry).Info(
			"sysctl 写入被拒但该项已经是目标值(容器里 /proc/sys 常为只读,值由外部预置),按已设置处理")
	default:
		logrus.Infof("已设置 %s(出口回程 hairpin 需要 loose 反向路由校验)", entry)
	}
}

// redirectSysctlKeys 返回抑制 ICMP Redirect 需要写的 sysctl 键值对。
// 内核对 send_redirects 取 OR(conf/all, conf/<dev>)（IN_DEV_TX_REDIRECTS），
// 所以只关本设备不够 —— all 仍为 1 时照样发。两个都要写。
func redirectSysctlKeys(deviceName string) []string {
	return []string{
		"net.ipv4.conf.all.send_redirects=0",
		fmt.Sprintf("net.ipv4.conf.%s.send_redirects=0", deviceName),
	}
}

// suppressICMPRedirects 关掉 ICMP Redirect 的发送。
//
// mesh 内 peer 互访天然是 hairpin：客户端 A 的包从 TUN 进来、目的是同一条 TUN 上的
// 客户端 C，内核转发时发现「出接口 == 入接口且下一跳在同一链路」，就给 A 回一条
// ICMP Redirect（New nexthop: C 的 vIP）。这条重定向对客户端毫无用处 —— vIP 只能
// 经隧道到达，A 根本没有直连 C 的路径 —— 但会造成三件事：
//   - 客户端内核缓存一条「dst=C via C」的重定向路由，peer 越多缓存越脏；
//   - ping/traceroute 等工具把它记成错误（`+N errors`），监控与健康检查误报；
//   - 网关向所有客户端广撒重定向，属于路由器加固基线（CIS）明确要求关掉的行为。
//
// best-effort：失败只 Warn 不阻断（容器内 sysctl 可能只读）。
func suppressICMPRedirects(deviceName string) {
	for _, entry := range redirectSysctlKeys(deviceName) {
		preset, err := sysctlSet(entry)
		switch {
		case err != nil:
			logrus.WithError(err).
				Warnf("sysctl %s 失败;mesh peer 互访时网关会向客户端发 ICMP Redirect(功能不受影响,但客户端路由缓存变脏、ping 记为 error)", entry)
		case preset:
			logrus.WithField("sysctl", entry).Info(
				"sysctl 写入被拒但该项已经是目标值(容器里 /proc/sys 常为只读,值由外部预置),按已设置处理")
		default:
			logrus.Infof("已设置 %s(mesh hairpin 转发不再向客户端发 ICMP Redirect)", entry)
		}
	}
}

// connlimitRuleArgs 造一条 per-客户端-IP 并发连接上限的 FORWARD DROP 规则(不含 comment)。
//
// 两个限定缺一不可:
//   - `-s <subnet>`:只按「客户端网段为源」计数。少了它,出口回程 hairpin(源是公网 CDN IP)
//     会按 CDN 源 IP 计数,热门边缘节点并发一超限就把该 IP 的全部 TCP 包连同既有流一起 DROP
//     (2026-07 tv.cctv.com 整站卡死的根因)。
//   - `-o <wanIface>`:只管**出公网**这一段。少了它,同一条规则连 mesh 内部的 tun→tun 流量
//     也一起计数并丢弃 —— 而 xt_connlimit 是按 conntrack **原始方向**的源地址归类的,于是
//     「某客户端公网连接数超标」会连带把它的 peer 互访、子网路由、出口回程全打死。
//     三机实测(2026-07-25):A↔C 的 mesh TCP 握手永远收不到 SYN-ACK(ICMP 却通),
//     且当时 conntrack 表里连一条相关条目都没有(nf_conncount 计数已陈旧)、
//     规则计数器经 nft-compat 层还不自增 —— 现场几乎无法定位。限定出接口后立刻恢复。
//
// wanIface 为空(WAN 探测失败等)时退回不限定出接口的老形态:此时宁可保守限流,也不放空。
func connlimitRuleArgs(deviceName, wanIface, subnet, proto string, limit int, mask string) []string {
	args := []string{"-i", deviceName}
	if strings.TrimSpace(wanIface) != "" {
		args = append(args, "-o", wanIface)
	}
	return append(args, "-s", subnet, "-p", proto,
		"-m", "connlimit", "--connlimit-above", strconv.Itoa(limit),
		"--connlimit-saddr", "--connlimit-mask", mask, "-j", "DROP")
}

// installConnlimitRules 把每网段 × {tcp,udp} 的并发上限规则装进 FORWARD 链首(幂等)。
//
// **调用位置有硬性要求**:必须排在 device→wan ACCEPT 之后。两者都用 `-I FORWARD 1`,
// 后插入的更靠前;先装 connlimit 再装 ACCEPT 的话,ACCEPT 会盖在 connlimit 上方,
// 出公网的包第一条就被放行、永远走不到限流规则 —— 功能整条静默失效,而 `iptables -S`
// 里两条规则一应俱全,看不出任何异常。2026-07-25 三机实测抓到:某客户端并发开 60 条
// 公网 TCP(上限 40)全部建连成功,`iptables -vnL FORWARD` 显示 tun→wan ACCEPT 480 包、
// 两条 connlimit 各 0 包。判据也就在这里:限流规则的计数器长期为 0 即说明被盖住了。
func installConnlimitRules(bin, deviceName, wanIface string, subnets []string, tcpConnlimit, udpConnlimit int, mask string) error {
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
			ruleArgs := withMainComment(connlimitRuleArgs(deviceName, wanIface, subnet, pl.proto, pl.limit, mask))
			check := append([]string{"-C", "FORWARD"}, ruleArgs...)
			if exec.Command(bin, check...).Run() == nil {
				continue
			}
			args := append([]string{"-I", "FORWARD", "1"}, ruleArgs...)
			if err := exec.Command(bin, args...).Run(); err != nil {
				return fmt.Errorf("%s connlimit %s: %w", bin, pl.proto, err)
			}
		}
	}
	if tcpConnlimit > 0 || udpConnlimit > 0 {
		logrus.Infof("%s: 已添加 connlimit TCP=%d/每IP UDP=%d/每IP", bin, tcpConnlimit, udpConnlimit)
	}
	return nil
}

// enableForwardSysctl 把某个转发开关置 1。与 rp_filter 那些 best-effort 项不同,
// 这一项失败是**致命**的:ip_forward=0 意味着一个包都转不出去,出口功能整体不存在。
//
// 写不进去但回读已经是 1 时按已开启处理(容器场景,原因见 sysctlSet)。
// 语义没有放宽:回读不是 1 照样返回错误。
func enableForwardSysctl(key, label string) error {
	preset, err := sysctlSet(key + "=1")
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if preset {
		logrus.WithField("sysctl", key).Info(
			"sysctl 写入被拒但该项已经是 1(容器里 /proc/sys 常为只读,值由外部预置),按已开启处理")
		return nil
	}
	logrus.Infof("已开启 %s=1", key)
	return nil
}

// EnableIPForward 开启 IPv4 转发
func EnableIPForward() error {
	return enableForwardSysctl("net.ipv4.ip_forward", "sysctl ip_forward")
}

// EnableIPv6Forward 开启 IPv6 转发
func EnableIPv6Forward() error {
	return enableForwardSysctl("net.ipv6.conf.all.forwarding", "sysctl ipv6 forwarding")
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

// hasIPv4DefaultRoute 报告本机是否存在 IPv4 默认路由。
//
// 用来把 GetWAN 失败分成两类,分错了后果完全相反:
//   - **有** v4 默认路由却探不到出口 → 真故障,必须 fail-closed 硬退(否则监听起得来、
//     数据面是黑洞)。
//   - **没有** v4 默认路由 → 纯 IPv6 主机(`ip route get 1.1.1.1` 必然 "Network is
//     unreachable")。这类机器没有 v4 出口可 MASQUERADE,也就没有 v4 可泄漏,应当容忍并
//     跳过 v4 iptables、让数据面走 v6,而不是像以前那样崩溃循环起不来。
//
// 命令本身失败按「没有」处理:`ip -4 route show default` 是只读查询,正常 v4 主机上
// GetWAN 早就成功了、根本走不到这里;能走到这里就已经是异常态,此时宁可偏向可用性
// (当作纯 v6 容忍)也不把机器卡死在崩溃循环 —— 反正真有 v4 WAN 的话 GetWAN 不会先失败。
func hasIPv4DefaultRoute() bool {
	out, err := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
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
func SetupIptables(deviceName, wanIface, wanIP string, subnets []string, tcpConnlimit, udpConnlimit int, blockBT, blockTracker6969, blockSMTP25 bool, exitMode, exitDNSRedirect, exitDenyPrivate string, magicDNSGwV4 string, magicDNSPort int) error {
	if deviceName == "" {
		deviceName = "tun0"
	}

	clientIsolate, allowExitWAN := exitModePolicy(exitMode)
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

	// 0.5) 关掉 ICMP Redirect 发送。mesh peer 互访是同一条 TUN 上的 hairpin 转发,
	// 内核默认会给发送方回「改走 <对端 vIP>」的重定向,见 suppressICMPRedirects。
	suppressICMPRedirects(deviceName)

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

	// 2) FORWARD: device <-> WAN
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

	// 3) connlimit（幂等），TCP/UDP 分别计数。必须排在第 2 步之后,见 installConnlimitRules。
	if err := installConnlimitRules("iptables", deviceName, wanIface, subnets, tcpConnlimit, udpConnlimit, "32"); err != nil {
		return err
	}

	// 3.5) 出口方向拦掉链路本地 / 私网目的地(云元数据 + 服务器所处内网)。
	// 必须排在第 2 步的 device→wan ACCEPT **之前**;插入用的是 -I FORWARD 1,后插入=更靠前,故这里的顺序正确。
	if applied, err := applyExitDenyPrivate("iptables", deviceName, wanIface, exitDenyPrivate, subnets, allowExitWAN); err != nil {
		return err
	} else {
		logExitDenyPrivate("iptables", exitDenyPrivate, applied)
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

// SetupIp6tables 配置 IPv6 的 FORWARD、connlimit、（可选）隔离、NAT、MagicDNS 端口例外（幂等）。
// 语义见 SetupIptables;exitMode 也是三档 mesh/isolate/off。
// exitDNSRedirect 参数在 v6 侧暂不使用(DNS 接管走 v4 DNAT 到 v4 解析器,见 SetupIptables 第 6 步;
// 客户端 v6 DNS 查询无 v4 解析器可 DNAT 到,保持原样转发)。留参数是为调用点两个函数签名对齐。
func SetupIp6tables(deviceName, wanIface, wanIP string, subnets []string, tcpConnlimit, udpConnlimit int, blockBT, blockTracker6969, blockSMTP25 bool, exitMode, _, exitDenyPrivate string, magicDNSGwV6 string, magicDNSPort int) error {
	if deviceName == "" {
		deviceName = "tun0"
	}

	clientIsolate, allowExitWAN := exitModePolicy(exitMode)
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

	// 2) FORWARD: device <-> WAN
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

	// 3) connlimit（幂等），IPv6 用 128 位掩码。位置要求同 v4，见 installConnlimitRules。
	if err := installConnlimitRules("ip6tables", deviceName, wanIface, subnets, tcpConnlimit, udpConnlimit, "128"); err != nil {
		return err
	}

	// 3.5) 出口方向拦掉链路本地(fe80::/10)/ ULA 目的地,语义同 v4 侧,见 applyExitDenyPrivate。
	if applied, err := applyExitDenyPrivate("ip6tables", deviceName, wanIface, exitDenyPrivate, subnets, allowExitWAN); err != nil {
		return err
	} else {
		logExitDenyPrivate("ip6tables", exitDenyPrivate, applied)
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

	// 5) MagicDNS 端口例外(启用时)。对齐 SetupIptables 第 7 步 —— magic DNS 在 v4 / v6 网关上成对
	// listen,少了 v6 这条 ACCEPT,ip6tables 默认 DROP 的机器上 v6 查询会在进 socket 前被丢掉
	// (症状:选了 v6 解析器的客户端静默解不出 AAAA / 4via6)。详见 setupMagicDNSException。
	if err := SetupMagicDNSV6Exception(deviceName, magicDNSGwV6, magicDNSPort); err != nil {
		return err
	}
	return nil
}

// SetupMagicDNSV6Exception 只装 v6 侧的 MagicDNS 端口例外,不碰 FORWARD/NAT。
//
// 单独导出是因为它的**前提比整套 ip6tables 更弱**:magic DNS listen 在 mesh 的 ULA 网关上,客户端
// 经隧道即可问到,与本机有没有 v6 出网无关。而 SetupIp6tables 整体依赖 GetWANv6(),纯 v4 出网的机器
// (很常见)上会整块跳过 —— 那条 INPUT ACCEPT 也就跟着丢了。server.go 在那条路径上单独调本函数补装。
func SetupMagicDNSV6Exception(deviceName, gwV6 string, port int) error {
	return setupMagicDNSException("ip6tables", deviceName, gwV6, port)
}

// insertTUNForwardPortDrops 从 TUN 转发、目的端口为常见滥用端口时 DROP（幂等）
func insertTUNForwardPortDrops(bin, deviceName string, blockBT, blockTracker6969, blockSMTP25 bool) error {
	if deviceName == "" {
		deviceName = "tun0"
	}
	rules := tunForwardPortDropRules(blockBT, blockTracker6969, blockSMTP25)
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
