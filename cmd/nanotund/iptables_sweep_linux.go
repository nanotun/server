//go:build linux

package main

import (
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// mainIptComment 是 SetupIptables / SetupIp6tables 安装的所有规则统一携带的 comment。
//
// 用 comment 而不是 chain / 子表来标识:
//   - nanotun 与 ufw / firewalld / docker / 第三方运维脚本共存时,不能贸然 -F 清空
//     FORWARD / POSTROUTING 链(会误伤别人的规则);
//   - 同 comment 的规则可以用 iptables-save 文本匹配 + -D 删除,做到「只清自己装的」;
//   - 与 hy2 端口跳跃 `nanotun_hy2_porthop` 形成对称,运维一眼能看出哪些规则属于 nanotun。
const mainIptComment = "nanotun_main"

// withMainComment 把 `-m comment --comment nanotun_main` 追加到规则参数末尾。
//
// 注意:`-C` 检查也必须带 comment,因为 iptables 把 comment 视为规则匹配条件的一部分;
// 不带 comment 的 -C 检查会找到「同 chain 上无 comment 的同样规则」,误认为已存在。
func withMainComment(args []string) []string {
	return append(args, "-m", "comment", "--comment", mainIptComment)
}

// sweepMainIptablesRules 扫描指定 bin(iptables / ip6tables)的 filter + nat 表,把
// 所有 comment == mainIptComment 的规则用 `-D` 删除。
//
// 解析方式与 sweepHy2UDPPortHopByComment 一致:`iptables-save -t <table>` 输出 "-A
// <chain> ..." 行,改成 "-D <chain> ..." 喂回 iptables。这种做法无视字段顺序差异,
// 对任何版本 iptables 都能精确删除。
//
// 失败仅 Debug 不 Warn,因为 sweep 在「无残留」时也会跑(返回 0 条),嘈杂日志没价值。
// 返回清理掉的规则总数,>0 时调用方可 Info 日志。
func sweepMainIptablesRules(bin string) int {
	tables := []string{"filter", "nat"}
	cleaned := 0
	for _, table := range tables {
		saveCmd := bin + "-save"
		out, err := exec.Command(saveCmd, "-t", table).Output()
		if err != nil {
			// 表为空 / 命令不存在时 -save 也可能非 0,直接跳过该 table。
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "-A ") {
				continue
			}
			if !strings.Contains(line, mainIptComment) {
				continue
			}
			delLine := "-D" + strings.TrimPrefix(line, "-A")
			args := append([]string{"-t", table}, strings.Fields(delLine)...)
			if err := exec.Command(bin, args...).Run(); err == nil {
				cleaned++
			}
		}
	}
	if cleaned > 0 {
		logrus.Infof("%s: sweep %s 共清理 %d 条残留规则", bin, mainIptComment, cleaned)
	}
	return cleaned
}

// teardownMainIptablesRules 退出路径上的总入口:同时清 iptables + ip6tables。
//
// 注册在 main 的 defer 链里(SetupIptables 返回 cleanup func 触发),进程 graceful
// shutdown 时把本进程装的 FORWARD / POSTROUTING / connlimit 等全部撤掉,避免:
//   - nanotun 升级 / 重启短窗口期 FORWARD 链上残留 ACCEPT 让客户端流量短暂不走 NAT;
//   - 服务停了但 connlimit / NAT 规则永远留在内核,排查工具(iptables -L -v -n)
//     看到一大堆 "0 packets" 干扰判断;
//   - 不同 deviceName / WAN iface 在同一台机器切换时旧规则与新规则共存导致路由不预期。
//
// 注意:此函数**不**会 touch 没有 mainIptComment 的规则,因此 ufw / firewalld / docker
// 装的规则完全不受影响。
func teardownMainIptablesRules() {
	_ = sweepMainIptablesRules("iptables")
	_ = sweepMainIptablesRules("ip6tables")
}
