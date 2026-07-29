package main

import (
	"bufio"
	"fmt"
	"strings"
)

// confirm 在 stdout 上询问用户 yes/no；只有输入 "y" / "yes"（不区分大小写）才返回 true。
//
// 仅供危险子命令调用；--yes / -y 全局 flag 会让所有子命令绕过 confirm 直接执行。
//
// 不返回 error:读 stdin 失败(EOF / stdin 被关掉 / 管道断了)一律当作「没确认」——
// 这是这个函数唯一安全的降级方向,把它冒泡成 error 只会让调用方多一条永远走不到的分支。
// 2026-07-30 去掉了那个恒为 nil 的返回值:九个调用点里有五个本来就写 `ok, _ :=` 把它丢了,
// 剩下四个的 `if err != nil { return err }` 是死代码 —— 两种写法并存反而让人以为
// 「取消」和「读不到输入」是两回事。
func confirm(opts *globalOpts, prompt string) bool {
	fmt.Fprintf(opts.stdout, "%s [y/N]: ", prompt)
	r := bufio.NewReader(opts.stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
