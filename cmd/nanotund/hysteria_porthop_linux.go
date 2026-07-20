//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

const hy2PortHopIptComment = "nanotun_hy2_porthop"

// setupHy2UDPPortHopRedirect 将端口并集中除主端口外的 UDP 口 REDIRECT 到 primaryPort（与官方 Hy2 文档一致）。
// 需要 root 或 CAP_NET_ADMIN；失败时返回 error，调用方可选择仅监听主端口继续运行。
//
// 启动前先按 comment(`nanotun_hy2_porthop`) sweep 所有旧规则,避免:
//
//  1. 上次进程被 SIGKILL / panic 后 cleanup 没跑,defer 没执行,残留规则
//     下次启动直接 `-A` 追加 → 同一 dport 出现 N 条规则,匹配几次 REDIRECT
//     行为飘忽;
//
//  2. 端口并集配置发生变更(原来 `:443,8443`,改成 `:443,8443,5000-5100`),
//     旧并集里独有的端口需要被清理才能反映新意图。
//
// 之后用 `-C` 检查后再 `-A`,做到完全幂等。
//
// I3: iface 非空时,在 -p/--dport 之前注入 `-i <iface>`,把规则限定到指定入接口。
// 详见 HysteriaConfig.PortHopIface 的注释。
func setupHy2UDPPortHopRedirect(primaryPort uint16, portUnion, iface string) (func(), error) {
	rules, err := planHy2PortHopDportRules(primaryPort, portUnion)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return func() {}, nil
	}
	primary := strconv.FormatUint(uint64(primaryPort), 10)
	iface = strings.TrimSpace(iface)

	// 启动前 sweep 旧规则(包括本进程上次残留 + 旧端口配置 + 旧 iface 设置)。
	sweptN := sweepHy2UDPPortHopByComment()
	if sweptN > 0 {
		logrus.Infof("Hy2 端口跳跃: 启动前清理了 %d 条残留 PREROUTING REDIRECT 规则(同 comment)", sweptN)
	}

	for _, dport := range rules {
		var ruleArgs []string
		if iface != "" {
			ruleArgs = append(ruleArgs, "-i", iface)
		}
		ruleArgs = append(ruleArgs,
			"-p", "udp", "-m", "udp",
			"--dport", dport,
			"-m", "comment", "--comment", hy2PortHopIptComment,
			"-j", "REDIRECT", "--to-ports", primary,
		)
		// -C 先探:若已存在(理论上 sweep 后不会,但 sweep 失败也别叠加),跳过 -A。
		checkArgs := append([]string{"-t", "nat", "-C", "PREROUTING"}, ruleArgs...)
		if err := exec.Command("iptables", checkArgs...).Run(); err == nil {
			continue
		}
		addArgs := append([]string{"-t", "nat", "-A", "PREROUTING"}, ruleArgs...)
		if out, err := exec.Command("iptables", addArgs...).CombinedOutput(); err != nil {
			teardownHy2UDPPortHopRules(rules, primary, iface)
			return nil, fmt.Errorf("iptables %v: %w (%s)", addArgs, err, strings.TrimSpace(string(out)))
		}
	}
	if iface != "" {
		logrus.Infof("Hy2 端口跳跃：已用 iptables 将接口 %s 上的 UDP %v REDIRECT 到主端口 %s", iface, rules, primary)
	} else {
		logrus.Infof("Hy2 端口跳跃：已用 iptables 将 UDP %v REDIRECT 到主端口 %s (未限定入接口,所有接口生效)", rules, primary)
	}
	return func() { teardownHy2UDPPortHopRules(rules, primary, iface) }, nil
}

func teardownHy2UDPPortHopRules(dports []string, primary, iface string) {
	for i := len(dports) - 1; i >= 0; i-- {
		var args []string
		args = append(args, "-t", "nat", "-D", "PREROUTING")
		if iface != "" {
			args = append(args, "-i", iface)
		}
		args = append(args,
			"-p", "udp", "-m", "udp",
			"--dport", dports[i],
			"-m", "comment", "--comment", hy2PortHopIptComment,
			"-j", "REDIRECT", "--to-ports", primary,
		)
		_ = exec.Command("iptables", args...).Run()
	}
}

// sweepHy2UDPPortHopByComment 扫 PREROUTING 链,按 hy2PortHopIptComment 把所有
// 匹配 comment 的规则都 `-D` 掉。
//
// 为什么用 `iptables-save` + 解析而不是循环 `-D`:`-D` 必须传完整的规则匹配条件,
// 但残留规则可能是上一版本字段顺序不同/不带某些 `-m udp`,精确重建容易丢。
// 直接 grep `iptables-save -t nat` 拿到完整规则文本,把 `-A` 改 `-D` 再喂给 iptables,
// 等价于「按 comment 精确 delete」,无论字段顺序/版本差异都能成功。
func sweepHy2UDPPortHopByComment() int {
	out, err := exec.Command("iptables-save", "-t", "nat").Output()
	if err != nil {
		// iptables-save 不在或 nat 表为空时返回非 0,不阻断启动。
		return 0
	}
	cleaned := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A PREROUTING") {
			continue
		}
		if !strings.Contains(line, hy2PortHopIptComment) {
			continue
		}
		// 把 "-A PREROUTING ..." 改成 "-D PREROUTING ..." 再传给 iptables -t nat。
		delLine := "-D" + strings.TrimPrefix(line, "-A")
		args := append([]string{"-t", "nat"}, strings.Fields(delLine)...)
		if err := exec.Command("iptables", args...).Run(); err == nil {
			cleaned++
		}
	}
	return cleaned
}
