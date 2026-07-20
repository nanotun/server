//go:build !linux

package main

// 非 Linux 平台 noop。
//
// _xxx = ... 是为了让 staticcheck 不再报 U1000(unused)。这些符号是 build
// constraint 上的对照面 —— Linux 版有真实实现,但 Linux 版以外不会被任何文件
// 引用。保留对外接口形状,让 cross-platform 编译 link 通过即可。
const mainIptComment = "nanotun_main"

var (
	_ = mainIptComment
	_ = withMainComment
	_ = sweepMainIptablesRules
)

func withMainComment(args []string) []string { return args }
func sweepMainIptablesRules(bin string) int  { return 0 }
func teardownMainIptablesRules()             {}
