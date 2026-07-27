package main

// 本文件只放「规则内容的纯计算」,不碰 exec:这样策略判断在任何平台都能测,
// 不必依赖 Linux + root。真正装规则的执行侧见 network_setup_linux.go。

// exitModePolicy 把 config 解析出的三档 exit_mode 翻译成两个开关。
//
// v4 / v6 两条装规则路径必须共用同一份翻译。此前两处各手写一遍
// `== "isolate"` / `!= "off"`(network_setup_linux.go 的 SetupIptables 与
// SetupIp6tables),改一处漏一处就会让 IPv6 的出口策略与 IPv4 悄悄劈叉 ——
// 而 v6 泄漏恰恰是最不容易被发现的那种。
//
// 未知取值按 mesh 处理(既不隔离、也不断出口),与 config.ResolveExitMode 的兜底一致:
// 宁可保持连通也不要因为一个 typo 把整个网断掉。
func exitModePolicy(exitMode string) (clientIsolate, allowExitWAN bool) {
	return exitMode == "isolate", exitMode != "off"
}

// tunForwardPortDropRules 按 forward_block_* 开关列出要插进 FORWARD 链的目的端口
// DROP 规则。返回的是规则尾部,`-i <tun>` 前缀与 mainIptComment 由调用方补齐。
func tunForwardPortDropRules(blockBT, blockTracker6969, blockSMTP25 bool) [][]string {
	var rules [][]string
	if blockBT {
		// tcp 与 udp 都要挡:只挡 tcp 的话 uTP / DHT 走 udp 照样能把出口跑满。
		rules = append(rules, []string{"-p", "tcp", "--dport", "6881:6889", "-j", "DROP"})
		rules = append(rules, []string{"-p", "udp", "--dport", "6881:6889", "-j", "DROP"})
	}
	if blockTracker6969 {
		rules = append(rules, []string{"-p", "tcp", "--dport", "6969", "-j", "DROP"})
	}
	if blockSMTP25 {
		// 挡 25 是为了不让出口 IP 被当成垃圾邮件源进黑名单。
		rules = append(rules, []string{"-p", "tcp", "--dport", "25", "-j", "DROP"})
	}
	return rules
}
