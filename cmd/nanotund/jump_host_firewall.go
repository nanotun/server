package main

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

// 固定资源名（与 listen 端口无关，换端口只改 INPUT 中 --dport 匹配）。
const (
	jumpHostIPSetName = "nanotun_jump_src"
	jumpHostChainName = "NANOTUN_JUMP"
	jumpHostRuleCmt   = "nanotun:jump_fw"
)

// jumpHostPortSpec 描述一个被 jump_host_firewall 保护的端口/段。
//
// C6_full(2026-05-22):之前只能保护单个 TCP 端口(默认 8080 / WSS gateway),
// hy2 UDP / REALITY / 保活 wss 全部对全网开放,跳板机用户只能挡住一半门。
// 现在用一个 spec 列表覆盖多端口 + 多协议(tcp / udp + 单端口 / 端口段)。
//
// 单端口:Port=8080, EndPort=0;
// 端口段:Port=5000, EndPort=5002(适配 hy2 port hopping)。
type jumpHostPortSpec struct {
	Proto   string // "tcp" 或 "udp"
	Port    int    // 起始端口 [1..65535]
	EndPort int    // 0 表示单端口;否则 [Port..EndPort] 闭区间
}

// jumpHostFirewall 按 [server].jump_host_allowed_ips 静态注入的 IPv4 列表限制
// 本机一组 VPN 入口端口入站(Linux:ipset + iptables)。历史上还支持过从
// 旧后端 控制面下发动态白名单,自托管 PSK 化后只保留静态注入路径。
//
// **保护范围**(C6_full 2026-05-22 起):
//   - 由 [server].jump_host_protected_ports 显式列出全部入口,format 见
//     config/config.go ServerConfig.JumpHostProtectedPorts。
//   - 历史行为(留空)= 仅保护 [server].listen_addr 对应 TCP 端口,**强烈不推荐**
//     —— hy2 / REALITY / 保活 wss 全部对全网开放,跳板机限制只挡半边门。
//
// 工作机制:protectedPorts 列表里每个 spec 对应一条 INPUT 跳转规则,
// 命中 ipset 的源 IP 才放行进 NANOTUN_JUMP 自定义链(其中再 ACCEPT / DROP),
// 不在 ipset 的源 IP 直接走 DROP。
//
// 注意:本机制只挡 INPUT,不挡 OUTPUT/FORWARD;TUN 出向 NAT 数据流由
// network_setup_linux.go 单独管理,与本功能无重叠。
type jumpHostFirewall struct {
	enabled        bool
	protectedPorts []jumpHostPortSpec
	mu             sync.Mutex
	installed      bool
	teardownOnce   sync.Once
	nonLinuxLogged uint32
}

// newJumpHostFirewall 兼容老签名:接受单个 TCP 端口(用于 [server].listen_addr 默认值)。
// 新代码应优先用 newJumpHostFirewallWithSpecs 显式列出全部端口。
func newJumpHostFirewall(enabled bool, port int) *jumpHostFirewall {
	return newJumpHostFirewallWithSpecs(enabled, []jumpHostPortSpec{{Proto: "tcp", Port: port}})
}

func newJumpHostFirewallWithSpecs(enabled bool, specs []jumpHostPortSpec) *jumpHostFirewall {
	// 防御性 copy + 过滤无效 spec,避免 ensureInstalledLocked 在 iptables 命令里塞进
	// 非法 --dport(否则整条 INPUT 规则会失败,留 INPUT 空挂)。
	clean := make([]jumpHostPortSpec, 0, len(specs))
	for _, s := range specs {
		if s.Proto != "tcp" && s.Proto != "udp" {
			continue
		}
		if s.Port < 1 || s.Port > 65535 {
			continue
		}
		if s.EndPort < 0 || s.EndPort > 65535 {
			continue
		}
		if s.EndPort > 0 && s.EndPort < s.Port {
			s.EndPort, s.Port = s.Port, s.EndPort
		}
		clean = append(clean, s)
	}
	return &jumpHostFirewall{enabled: enabled, protectedPorts: clean}
}

func (f *jumpHostFirewall) Replace(ips []string) {
	if !f.enabled {
		return
	}
	if runtime.GOOS != "linux" {
		if atomic.CompareAndSwapUint32(&f.nonLinuxLogged, 0, 1) {
			logrus.Warn("[server] jump_host_firewall 仅支持 Linux，已忽略")
		}
		return
	}
	sanitized := ensureLoopbackIPv4Allowlist(ips)
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.ensureInstalledLocked(); err != nil {
		logrus.Errorf("[server] jump_host_firewall 安装失败（已跳过本次刷新，避免误伤端口）: %v", err)
		return
	}
	if out, err := exec.Command("ipset", "flush", jumpHostIPSetName).CombinedOutput(); err != nil {
		logrus.Errorf("[server] ipset flush %s: %v (%s)，尝试回滚防火墙规则", jumpHostIPSetName, err, strings.TrimSpace(string(out)))
		f.rollbackJumpFirewallLocked()
		return
	}
	for _, ip := range sanitized {
		if out, err := exec.Command("ipset", "add", jumpHostIPSetName, ip).CombinedOutput(); err != nil {
			logrus.Errorf("[server] ipset add %s %q: %v (%s)，尝试回滚（避免端口在空 ipset 下被全 DROP）", jumpHostIPSetName, ip, err, strings.TrimSpace(string(out)))
			f.rollbackJumpFirewallLocked()
			return
		}
	}
	f.installed = true
	logrus.WithFields(logrus.Fields{
		"ipset":          jumpHostIPSetName,
		"ip_count":       len(sanitized),
		"protected_spec": describePortSpecs(f.protectedPorts),
	}).Info("[server] jump_host_firewall:已刷新 ipset")
}

func (f *jumpHostFirewall) Teardown() {
	f.teardownOnce.Do(func() { f.teardownImpl() })
}

func (f *jumpHostFirewall) teardownImpl() {
	if !f.enabled {
		return
	}
	if runtime.GOOS != "linux" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.installed {
		return
	}
	f.removeJumpFirewallRulesLocked()
	f.installed = false
	logrus.Info("[server] jump_host_firewall：已清理 ipset/iptables")
}

// rollbackJumpFirewallLocked 在 flush/add 失败时调用：去掉本功能挂上的 INPUT/链/ipset，避免空 ipset 导致该端口被全 DROP。须已持 f.mu。
func (f *jumpHostFirewall) rollbackJumpFirewallLocked() {
	f.removeJumpFirewallRulesLocked()
	f.installed = false
	logrus.Warn("[server] jump_host_firewall：已回滚（本端口不再套用跳板 ipset 限制）")
}

func (f *jumpHostFirewall) removeJumpFirewallRulesLocked() {
	// 删 INPUT 里每个 spec 对应的跳转规则。重复 -C / -D 直到删干净,
	// 防御性循环防止 iptables 同一规则被加多次时只删一次的边缘 case。
	for _, spec := range f.protectedPorts {
		inputRule := f.inputJumpRuleArgsFor(spec)
		for exec.Command("iptables", append([]string{"-C", "INPUT"}, inputRule...)...).Run() == nil {
			_ = exec.Command("iptables", append([]string{"-D", "INPUT"}, inputRule...)...).Run()
		}
	}
	_ = exec.Command("iptables", "-F", jumpHostChainName).Run()
	_ = exec.Command("iptables", "-X", jumpHostChainName).Run()
	_ = exec.Command("ipset", "destroy", jumpHostIPSetName).Run()
}

// inputJumpRuleArgsFor 给单个 spec 生成 iptables INPUT 跳转规则参数。
// 端口段(EndPort>0)用 multiport 或者 --dport range;此处用 -p ... --dport start:end
// 形式,与 iptables 内置 port range 语法对齐(实际是 conntrack/match 的内置 range)。
func (f *jumpHostFirewall) inputJumpRuleArgsFor(spec jumpHostPortSpec) []string {
	dport := fmt.Sprintf("%d", spec.Port)
	if spec.EndPort > 0 && spec.EndPort != spec.Port {
		dport = fmt.Sprintf("%d:%d", spec.Port, spec.EndPort)
	}
	return []string{
		"-p", spec.Proto, "--dport", dport,
		"-m", "comment", "--comment", jumpHostRuleCmt,
		"-j", jumpHostChainName,
	}
}

// describePortSpecs 用于日志:把 specs 序列化成 "tcp/8080,tcp/8443,udp/443,udp/5000:5002"。
func describePortSpecs(specs []jumpHostPortSpec) string {
	parts := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.EndPort > 0 && s.EndPort != s.Port {
			parts = append(parts, fmt.Sprintf("%s/%d:%d", s.Proto, s.Port, s.EndPort))
		} else {
			parts = append(parts, fmt.Sprintf("%s/%d", s.Proto, s.Port))
		}
	}
	return strings.Join(parts, ",")
}

func (f *jumpHostFirewall) ensureInstalledLocked() error {
	if f.installed {
		return nil
	}
	var installOK bool
	defer func() {
		if !installOK {
			f.removeJumpFirewallRulesLocked()
		}
	}()
	if exec.Command("ipset", "list", jumpHostIPSetName).Run() != nil {
		out, err := exec.Command("ipset", "create", jumpHostIPSetName, "hash:ip", "family", "inet", "hashsize", "1024", "maxelem", "65536").CombinedOutput()
		if err != nil {
			return fmt.Errorf("ipset create: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	if exec.Command("iptables", "-L", jumpHostChainName, "-n").Run() != nil {
		out, err := exec.Command("iptables", "-N", jumpHostChainName).CombinedOutput()
		if err != nil {
			return fmt.Errorf("iptables -N %s: %w (%s)", jumpHostChainName, err, strings.TrimSpace(string(out)))
		}
	}
	_ = exec.Command("iptables", "-F", jumpHostChainName).Run()
	chainRuleA := []string{"-A", jumpHostChainName, "-m", "set", "--match-set", jumpHostIPSetName, "src", "-j", "ACCEPT"}
	if out, err := exec.Command("iptables", chainRuleA...).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %v: %w (%s)", chainRuleA, err, strings.TrimSpace(string(out)))
	}
	chainRuleB := []string{"-A", jumpHostChainName, "-j", "DROP"}
	if out, err := exec.Command("iptables", chainRuleB...).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %v: %w (%s)", chainRuleB, err, strings.TrimSpace(string(out)))
	}
	// 给每个 spec 安一条 INPUT 跳转规则。-I INPUT 1 让它们都放到最前,
	// 避免被其它默认 ACCEPT 规则提前命中。
	// 已存在(-C 成功)则不重复 -I,保证幂等。
	for _, spec := range f.protectedPorts {
		inputArgs := f.inputJumpRuleArgsFor(spec)
		if exec.Command("iptables", append([]string{"-C", "INPUT"}, inputArgs...)...).Run() != nil {
			insert := append([]string{"-I", "INPUT", "1"}, inputArgs...)
			if out, err := exec.Command("iptables", insert...).CombinedOutput(); err != nil {
				return fmt.Errorf("iptables %v: %w (%s)", insert, err, strings.TrimSpace(string(out)))
			}
		}
	}
	installOK = true
	// f.installed 仅在 Replace 整次 flush+add 成功后置 true，避免「已挂 INPUT、ipset 仍空」时 Teardown 因 installed=false 不清理。
	return nil
}

// ensureLoopbackIPv4Allowlist 规范化 IPv4；若名单无 127.0.0.1 则自动加入（本机 hy2/REALITY 环回连 VPN 端口）。
// 若全无有效 IPv4，则退化为仅 ["127.0.0.1"]，避免开启限制后环回被挡死。
func ensureLoopbackIPv4Allowlist(in []string) []string {
	const lb = "127.0.0.1"
	out := sanitizeJumpHostIPv4s(in)
	for _, s := range out {
		if s == lb {
			return out
		}
	}
	if len(out) == 0 {
		logrus.Warn("[server] jump_host_firewall：无有效 IPv4，仅加入 127.0.0.1（本机环回）")
		return []string{lb}
	}
	logrus.Warn("[server] jump_host_firewall：名单未含 127.0.0.1，已自动加入（本机 hy2/REALITY 环回）")
	return append([]string{lb}, out...)
}

// parseJumpHostProtectedPorts 把 toml 里的字符串 "tcp/8080" / "udp/5000-5002" 解析成 spec。
//
// 容错策略:
//   - 大小写不敏感,proto 取前缀 tcp/udp,其它一律视为无效项跳过(打 warn 而不是 fatal,
//     这样运维敲错一行不至于让整个 jump_host_firewall 拒服)。
//   - port 区间允许 "start-end" 或 "start:end",end<start 自动交换。
//   - 全列无效 / 列表为空时,返回 nil(调用方应当退化到「仅保护 listen_addr 单端口」)。
func parseJumpHostProtectedPorts(in []string) []jumpHostPortSpec {
	var out []jumpHostPortSpec
	for _, raw := range in {
		s := strings.TrimSpace(strings.ToLower(raw))
		if s == "" {
			continue
		}
		idx := strings.Index(s, "/")
		if idx <= 0 || idx == len(s)-1 {
			logrus.WithField("entry", raw).Warn("[server] jump_host_protected_ports 格式应为 proto/port 或 proto/start-end,跳过")
			continue
		}
		proto := s[:idx]
		portPart := s[idx+1:]
		if proto != "tcp" && proto != "udp" {
			logrus.WithField("entry", raw).Warn("[server] jump_host_protected_ports proto 必须 tcp/udp,跳过")
			continue
		}
		startStr := portPart
		endStr := ""
		if strings.ContainsAny(portPart, "-:") {
			sep := "-"
			if strings.Contains(portPart, ":") {
				sep = ":"
			}
			parts := strings.SplitN(portPart, sep, 2)
			startStr = parts[0]
			endStr = parts[1]
		}
		start, err := strconv.Atoi(startStr)
		if err != nil || start < 1 || start > 65535 {
			logrus.WithField("entry", raw).Warn("[server] jump_host_protected_ports 起始端口非法,跳过")
			continue
		}
		end := 0
		if endStr != "" {
			end, err = strconv.Atoi(endStr)
			if err != nil || end < 1 || end > 65535 {
				logrus.WithField("entry", raw).Warn("[server] jump_host_protected_ports 结束端口非法,跳过")
				continue
			}
		}
		out = append(out, jumpHostPortSpec{Proto: proto, Port: start, EndPort: end})
	}
	return out
}

func sanitizeJumpHostIPv4s(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			continue
		}
		v := ip.To4().String()
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
