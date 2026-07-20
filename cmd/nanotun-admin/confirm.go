package main

import (
	"bufio"
	"fmt"
	"strings"
)

// confirm 在 stdout 上询问用户 yes/no；只有输入 "y" / "yes"（不区分大小写）才返回 true。
//
// 仅供危险子命令调用；--yes / -y 全局 flag 会让所有子命令绕过 confirm 直接执行。
func confirm(opts *globalOpts, prompt string) (bool, error) {
	fmt.Fprintf(opts.stdout, "%s [y/N]: ", prompt)
	r := bufio.NewReader(opts.stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		// EOF / 关闭 stdin 视为不确认（保守）。
		return false, nil //nolint:nilerr
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
