package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/config"
)

// 这一族压的是防火墙安装路径上的**故障分支** —— 到 2026-08-01 为止一条都没跑过。
//
// 为什么以前压不到:e2e 在真机上装规则,`iptables` 永远成功,所有 `if err != nil` 都是
// 死路;而单测在 macOS 上连这个文件都不参与编译。于是「装规则失败了怎么办」这件事,
// 从来没有任何东西检查过。
//
// 而这恰恰是不能出错的地方。这些函数在 **root 下改宿主机的网络**,它们的失败有两种
// 处理方式,分错了后果完全不同:
//
//   - **必须中止启动**的:装 FORWARD/NAT/DROP 规则失败。吞掉就等于「日志说启动成功,
//     防火墙其实没装上」。最要命的是 exit_mode=off 那条 device→WAN DROP —— 用户以为
//     买的是纯组网、不出公网,规则装失败却被咽下去的话,流量就这么漏出去了,而且没有
//     任何迹象。
//   - **只能告警继续**的:sysctl(rp_filter / ICMP redirect)、清理历史残留规则。
//     容器里 sysctl 常常只读,这些失败不该让整个服务起不来。
//
// 这条分界线是本文件的主题。它没有类型系统保护 —— 一个 `return err` 改成 `log.Warn`
// (或反过来)在评审里都长得很无辜。
//
// 做法:往 PATH 前面插一个临时目录,放假的 iptables / ip6tables / ip / sysctl。
// **不需要改生产代码** —— 这些命令都是裸名字(`exec.Command("iptables", ...)`),
// 走 PATH 查找。生产代码里加接缝(把 exec.Command 换成可替换的包级变量)本来是另一个
// 选项,但那等于为了测试在生产路径上多一个可变全局,而 PATH 注入什么都不用改。

// fakeNetTools 是一套受控的假命令行工具。
type fakeNetTools struct {
	dir    string
	logPth string
}

// 假工具的行为:
//   - 每次调用把 argv 追加进 $FAKE_LOG,供测试断言「装了哪些规则、顺序如何」;
//   - argv 匹配 $FAKE_FAIL_RE 时以非零退出并往 stderr 写一行(模拟 iptables 报错);
//   - `-C`(检查规则是否存在)默认返回**非零** = 规则不存在 → 生产代码会去装。
//     匹配 $FAKE_EXISTS_RE 时返回 0 = 已存在 → 生产代码应跳过(幂等)。
//   - 匹配 $FAKE_EXISTS_ONCE_RE 的 `-C` 只在**第一次**报告存在,之后报告不存在。
//     这是为了模拟「历史残留规则被成功删掉」:代码形态是 `for -C 成功 { -D }`,
//     恒真会死循环、恒假则循环体一次都不进,只有「一次之后消失」才能走完整条清理路径。
//   - `*-save` 输出 $FAKE_SAVE_OUT,用来喂 sweep 一份假的现有规则集。
//
// 注意 PATH 是**前插**而不是替换:脚本自己要用 grep / basename / md5sum。
const fakeToolScript = `#!/bin/sh
tool=$(basename "$0")
args="$*"
printf '%s %s\n' "$tool" "$args" >> "$FAKE_LOG"

case "$tool" in
  *-save)
    if [ -n "$FAKE_SAVE_OUT" ]; then printf '%s\n' "$FAKE_SAVE_OUT"; fi
    exit 0 ;;
esac

if [ -n "$FAKE_FAIL_RE" ] && printf '%s' "$args" | grep -qE -- "$FAKE_FAIL_RE"; then
  printf 'fake %s: simulated failure\n' "$tool" >&2
  exit 1
fi

# sysctl -n <key>:回读当前值,输出 $FAKE_SYSCTL_READ。放在 FAIL_RE 之后,
# 这样「写失败 + 读也失败」的组合同样能造出来。
if [ "$tool" = sysctl ] && printf '%s' "$args" | grep -qE -- '(^| )-n( |$)'; then
  if [ -n "$FAKE_SYSCTL_READ" ]; then printf '%s\n' "$FAKE_SYSCTL_READ"; fi
  exit 0
fi

if printf '%s' "$args" | grep -qE -- '(^| )-C( |$)'; then
  if [ -n "$FAKE_EXISTS_ONCE_RE" ] && printf '%s' "$args" | grep -qE -- "$FAKE_EXISTS_ONCE_RE"; then
    key=$(printf '%s' "$args" | md5sum | cut -d' ' -f1)
    if [ ! -f "$FAKE_STATE_DIR/once-$key" ]; then
      : > "$FAKE_STATE_DIR/once-$key"
      exit 0
    fi
    exit 1
  fi
  if [ -n "$FAKE_EXISTS_RE" ] && printf '%s' "$args" | grep -qE -- "$FAKE_EXISTS_RE"; then
    exit 0
  fi
  exit 1
fi
exit 0
`

func newFakeNetTools(t *testing.T) *fakeNetTools {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{
		"iptables", "ip6tables", "ip", "sysctl",
		"iptables-save", "ip6tables-save",
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(fakeToolScript), 0o755); err != nil {
			t.Fatalf("写假工具 %s: %v", name, err)
		}
	}
	state := filepath.Join(dir, "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fakeNetTools{dir: dir, logPth: filepath.Join(dir, "calls.log")}
	if err := os.WriteFile(f.logPth, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_LOG", f.logPth)
	t.Setenv("FAKE_STATE_DIR", state)
	t.Setenv("FAKE_FAIL_RE", "")
	t.Setenv("FAKE_EXISTS_RE", "")
	t.Setenv("FAKE_EXISTS_ONCE_RE", "")
	t.Setenv("FAKE_SAVE_OUT", "")
	t.Setenv("FAKE_SYSCTL_READ", "")
	return f
}

func (f *fakeNetTools) failOn(t *testing.T, re string) { t.Helper(); t.Setenv("FAKE_FAIL_RE", re) }

// sysctlReads 指定 `sysctl -n <key>` 的回读结果。
func (f *fakeNetTools) sysctlReads(t *testing.T, v string) {
	t.Helper()
	t.Setenv("FAKE_SYSCTL_READ", v)
}
func (f *fakeNetTools) ruleExists(t *testing.T, re string) {
	t.Helper()
	t.Setenv("FAKE_EXISTS_RE", re)
}
func (f *fakeNetTools) saveOutput(t *testing.T, s string) { t.Helper(); t.Setenv("FAKE_SAVE_OUT", s) }

// ruleExistsOnce 让匹配的规则「第一次查在、删掉后就不在」,用于走完历史残留的清理循环。
func (f *fakeNetTools) ruleExistsOnce(t *testing.T, re string) {
	t.Helper()
	t.Setenv("FAKE_EXISTS_ONCE_RE", re)
}

func (f *fakeNetTools) calls(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(f.logPth)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func (f *fakeNetTools) countMatching(t *testing.T, subs ...string) int {
	t.Helper()
	n := 0
outer:
	for _, c := range f.calls(t) {
		for _, s := range subs {
			if !strings.Contains(c, s) {
				continue outer
			}
		}
		n++
	}
	return n
}

// setupIptablesDefaults 一组「正常部署」的参数,各用例只改自己关心的那一项。
func setupIptablesArgs() (deviceName, wanIface, wanIP string, subnets []string) {
	return "tun0", "eth0", "203.0.113.10", []string{"10.200.0.0/16"}
}

func callSetupIptables(exitMode, denyPrivate string) error {
	dev, wan, ip, subnets := setupIptablesArgs()
	return SetupIptables(dev, wan, ip, subnets, 40, 20, true, true, true,
		exitMode, "off", denyPrivate, "", 0)
}

func callSetupIp6tables(exitMode, denyPrivate string) error {
	dev, wan, _, _ := setupIptablesArgs()
	return SetupIp6tables(dev, wan, "2001:db8::1", []string{"fd00::/64"}, 40, 20,
		true, true, true, exitMode, "", denyPrivate)
}

// TestSetupIptables_RuleInstallFailureAbortsStartup 装规则失败必须中止,且指明是哪一步。
//
// 逐个失败点单独一条用例:合起来测的话,只要有一条仍然返回错误,其余全被遮蔽 ——
// 把某一处的 `return err` 悄悄改成 `logrus.Warn` 就抓不到了。
func TestSetupIptables_RuleInstallFailureAbortsStartup(t *testing.T) {
	for _, tc := range []struct {
		desc       string
		exitMode   string
		failRe     string // 匹配到这条 argv 就让 iptables 失败
		wantErrSub string // 错误里应出现的字样(运维靠它定位是哪一步)
	}{
		{
			desc: "mesh 互访 ACCEPT 装不上", exitMode: config.TUNExitModeMesh,
			failRe: "-I FORWARD 1 -i tun0 -o tun0 -j ACCEPT", wantErrSub: "FORWARD",
		},
		{
			desc: "客户端隔离 DROP 装不上(isolate 的全部意义就在这条)", exitMode: config.TUNExitModeIsolate,
			failRe: "-I FORWARD 1 -i tun0 -o tun0 -j DROP", wantErrSub: "FORWARD",
		},
		{
			desc: "出口 ACCEPT 装不上", exitMode: config.TUNExitModeMesh,
			failRe: "-I FORWARD 1 -i tun0 -o eth0 -j ACCEPT", wantErrSub: "FORWARD",
		},
		{
			// 这条最要紧:off = 用户买的是纯组网。DROP 没装上又不报错,流量就漏到公网了。
			desc: "off 模式的 device→WAN DROP 装不上", exitMode: config.TUNExitModeOff,
			failRe: "-I FORWARD 1 -i tun0 -o eth0 -j DROP", wantErrSub: "off FORWARD drop",
		},
		{
			desc: "connlimit 装不上", exitMode: config.TUNExitModeMesh,
			failRe: "connlimit", wantErrSub: "connlimit",
		},
		{
			desc: "NAT SNAT 装不上(装不上就是客户端出不了网)", exitMode: config.TUNExitModeMesh,
			failRe: "-t nat -A POSTROUTING", wantErrSub: "NAT",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := newFakeNetTools(t)
			f.failOn(t, tc.failRe)

			err := callSetupIptables(tc.exitMode, config.TUNExitDenyPrivateOff)
			if err == nil {
				t.Fatalf("%s —— 却返回 nil。防火墙没装上而启动继续,是静默失败里最坏的一类", tc.desc)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("错误应含 %q 以便定位是哪一步,实得:%v", tc.wantErrSub, err)
			}
		})
	}
}

// TestSetupIptables_SucceedsWhenEveryCommandSucceeds 反面锚点。
//
// 没有这条,一个「永远返回 error」的实现能让上面六条全绿。
func TestSetupIptables_SucceedsWhenEveryCommandSucceeds(t *testing.T) {
	f := newFakeNetTools(t)
	if err := callSetupIptables(config.TUNExitModeMesh, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatalf("所有命令都成功时不应报错:%v", err)
	}
	if n := f.countMatching(t, "iptables", "-I FORWARD 1"); n == 0 {
		t.Error("一条 FORWARD 规则都没装 —— 假工具没被调用到,这批用例其实什么都没测")
	}
	if n := f.countMatching(t, "iptables", "--comment", mainIptComment); n == 0 {
		t.Errorf("装的规则没带 %s comment —— sweep/teardown 将无法回收它们", mainIptComment)
	}
}

// TestSetupIptables_SysctlFailureIsNotFatal sysctl 失败只能告警,不能中止启动。
//
// rp_filter 与 ICMP redirect 都是 best-effort:容器 / 只读 sysctl 的环境下必然失败,
// 若改成致命,这些部署会直接起不来。反过来,把这两处改成 `return err` 在评审里看着
// 也很合理 —— 所以要有断言钉住「就是不能致命」。
func TestSetupIptables_SysctlFailureIsNotFatal(t *testing.T) {
	f := newFakeNetTools(t)
	f.failOn(t, "^-w net\\.ipv4\\.conf\\.")

	if err := callSetupIptables(config.TUNExitModeMesh, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatalf("sysctl 失败不该中止启动(容器里 sysctl 常只读),却返回:%v", err)
	}
	if n := f.countMatching(t, "sysctl", "rp_filter=2"); n == 0 {
		t.Error("压根没尝试设 rp_filter —— 用例没真正走到那一步")
	}
	if n := f.countMatching(t, "sysctl", "send_redirects=0"); n < 2 {
		t.Errorf("send_redirects 应对 all 与本设备各写一次,实际 %d 次", n)
	}
}

// TestSetupIptables_HistoryCleanupFailureIsNotFatal 清理历史残留失败只告警并跳出循环。
//
// 这里同时钉住**循环会终止**:代码形态是 `for -C 成功 { -D }`,如果 -D 失败却不
// break,`-C` 会永远成功 —— 死循环卡在启动路径上,比报错难查得多。
func TestSetupIptables_HistoryCleanupFailureIsNotFatal(t *testing.T) {
	f := newFakeNetTools(t)
	// 让「历史 mesh DROP」看起来一直存在,同时让删除它失败。
	f.ruleExists(t, "-C FORWARD -i tun0 -o tun0 -j DROP")
	f.failOn(t, "-D FORWARD -i tun0 -o tun0 -j DROP")

	if err := callSetupIptables(config.TUNExitModeMesh, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatalf("清理历史规则失败不该中止启动,却返回:%v", err)
	}
	if n := f.countMatching(t, "-D FORWARD -i tun0 -o tun0 -j DROP"); n != 1 {
		t.Errorf("删除失败后应立刻 break,只该尝试一次,实际 %d 次 —— 不 break 就是启动期死循环", n)
	}
}

// TestSetupIptables_IdempotentWhenRulesAlreadyExist 规则已存在时不再重复插入。
//
// `-C` 返回 0 就该跳过。少了这个短路,每次重启都会把同一条规则再插一遍,
// FORWARD 链无限膨胀 —— 而且因为规则确实生效,功能上看不出任何异常。
func TestSetupIptables_IdempotentWhenRulesAlreadyExist(t *testing.T) {
	f := newFakeNetTools(t)
	f.ruleExists(t, ".") // 所有 -C 都说「已存在」
	// 清理历史残留的形态是 `for -C 成功 { -D }`。上一行让 -C 恒真,若 -D 也恒成功,
	// 这个循环就永远转下去 —— 让 -D 失败,循环走 warn+break 退出。
	f.failOn(t, "^-D ")

	if err := callSetupIptables(config.TUNExitModeMesh, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatalf("规则都已存在时应当无事发生:%v", err)
	}
	if n := f.countMatching(t, "-I FORWARD 1"); n != 0 {
		t.Errorf("规则已存在却仍插入了 %d 条 —— 每次重启都会让 FORWARD 链膨胀", n)
	}
	if n := f.countMatching(t, "-t nat -A POSTROUTING"); n != 0 {
		t.Errorf("NAT 规则已存在却仍追加了 %d 条", n)
	}
}

// TestSetupIp6tables_RuleInstallFailureAbortsStartup v6 侧同样不能吞错误。
//
// v6 是独立的一套调用,不能假设「v4 测过了 v6 就没问题」—— 两个函数是各写一遍的。
func TestSetupIp6tables_RuleInstallFailureAbortsStartup(t *testing.T) {
	for _, tc := range []struct{ desc, exitMode, failRe string }{
		{"mesh 互访 ACCEPT 装不上", config.TUNExitModeMesh, "-I FORWARD 1 -i tun0 -o tun0 -j ACCEPT"},
		{"隔离 DROP 装不上", config.TUNExitModeIsolate, "-I FORWARD 1 -i tun0 -o tun0 -j DROP"},
		{"off 模式 device→WAN DROP 装不上", config.TUNExitModeOff, "-I FORWARD 1 -i tun0 -o eth0 -j DROP"},
		{"connlimit 装不上", config.TUNExitModeMesh, "connlimit"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := newFakeNetTools(t)
			f.failOn(t, tc.failRe)
			if err := callSetupIp6tables(tc.exitMode, config.TUNExitDenyPrivateOff); err == nil {
				t.Fatalf("v6 侧 %s —— 却返回 nil", tc.desc)
			}
		})
	}
}

func TestSetupIp6tables_SucceedsWhenEveryCommandSucceeds(t *testing.T) {
	f := newFakeNetTools(t)
	if err := callSetupIp6tables(config.TUNExitModeMesh, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatalf("所有命令成功时不应报错:%v", err)
	}
	if n := f.countMatching(t, "ip6tables", "-I FORWARD 1"); n == 0 {
		t.Error("v6 一条 FORWARD 规则都没装")
	}
	if n := f.countMatching(t, "iptables ", "-I FORWARD"); n != 0 {
		t.Errorf("v6 安装路径调用了 v4 的 iptables %d 次 —— 两族规则串了", n)
	}
}

// TestExitDenyPrivate_InstallFailureAbortsStartup 私网闸门装不上必须中止。
//
// 这道闸拦的是「VPN 用户经服务器访问云元数据(169.254.169.254)和机房内网」。
// 装失败却继续启动,等于把内网对所有 VPN 用户敞开,而启动日志一切正常。
func TestExitDenyPrivate_InstallFailureAbortsStartup(t *testing.T) {
	for _, tc := range []struct{ desc, chain string }{
		{"FORWARD 方向(拦借道出网访问内网邻居)", "-I FORWARD 1 -i tun0 -o eth0 -d 169.254.0.0/16"},
		{"INPUT 方向(拦访问服务器自己的私网地址)", "-I INPUT 1 -i tun0 -d 169.254.0.0/16"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := newFakeNetTools(t)
			f.failOn(t, tc.chain)
			err := callSetupIptables(config.TUNExitModeMesh, config.TUNExitDenyPrivateLinkLocal)
			if err == nil {
				t.Fatalf("私网闸门 %s 装失败却返回 nil —— 内网对 VPN 用户敞开而日志正常", tc.desc)
			}
			if !strings.Contains(err.Error(), "exit-guard") {
				t.Errorf("错误应带 exit-guard 字样,实得:%v", err)
			}
		})
	}
}

// TestExitDenyPrivate_LinkLocalInstallsBothDirections link-local 档要装满两个方向。
//
// 只装 FORWARD 不装 INPUT 是个很容易犯的简化:FORWARD 拦的是「借道出网」,
// 目的地是**服务器本机**的私网地址时走的是 INPUT,漏了这一半,管理面照样敞开。
func TestExitDenyPrivate_LinkLocalInstallsBothDirections(t *testing.T) {
	f := newFakeNetTools(t)
	if err := callSetupIptables(config.TUNExitModeMesh, config.TUNExitDenyPrivateLinkLocal); err != nil {
		t.Fatal(err)
	}
	if n := f.countMatching(t, "-I FORWARD 1", "-d 169.254.0.0/16", "-j DROP"); n == 0 {
		t.Error("缺 FORWARD 方向的链路本地 DROP —— 可借道访问云元数据")
	}
	if n := f.countMatching(t, "-I INPUT 1", "-d 169.254.0.0/16", "-j DROP"); n == 0 {
		t.Error("缺 INPUT 方向的链路本地 DROP —— 服务器自身私网地址仍对 VPN 用户敞开")
	}
}

// TestExitDenyPrivate_OffInstallsNothing off 档就是一条都不装。
func TestExitDenyPrivate_OffInstallsNothing(t *testing.T) {
	f := newFakeNetTools(t)
	if err := callSetupIptables(config.TUNExitModeMesh, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatal(err)
	}
	if n := f.countMatching(t, "-d 169.254.0.0/16"); n != 0 {
		t.Errorf("exit_deny_private=off 却装了 %d 条链路本地规则", n)
	}
}

// TestMagicDNSException_InstallFailureAbortsStartup MagicDNS 例外装不上要中止。
//
// 这两条例外把 MagicDNS 的查询从出口 DNS DNAT 里摘出来。装不上的话客户端的
// *.<suffix> 查询会被 DNAT 到系统解析器 —— 解析不出来,而 MagicDNS 看着是「已启用」。
func TestMagicDNSException_InstallFailureAbortsStartup(t *testing.T) {
	for _, tc := range []struct{ desc, failRe, wantSub string }{
		{"nat PREROUTING RETURN", "-t nat -I PREROUTING 1", "PREROUTING"},
		{"filter INPUT ACCEPT", "-I INPUT 1 -i tun0 -d 10.200.0.1 -p udp", "INPUT"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := newFakeNetTools(t)
			f.failOn(t, tc.failRe)
			err := setupMagicDNSException("iptables", "tun0", "10.200.0.1", 53)
			if err == nil {
				t.Fatalf("MagicDNS 例外 %s 装失败却返回 nil", tc.desc)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("错误应含 %q,实得:%v", tc.wantSub, err)
			}
		})
	}
}

// TestMagicDNSException_SkippedUnlessPort53 只有 :53 才装例外。
func TestMagicDNSException_SkippedUnlessPort53(t *testing.T) {
	for _, tc := range []struct {
		desc, gw, dev string
		port          int
	}{
		{"gateway 为空", "", "tun0", 53},
		{"设备名为空", "10.200.0.1", "", 53},
		{"端口不是 53", "10.200.0.1", "tun0", 5353},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := newFakeNetTools(t)
			if err := setupMagicDNSException("iptables", tc.dev, tc.gw, tc.port); err != nil {
				t.Fatal(err)
			}
			if n := len(f.calls(t)); n != 0 {
				t.Errorf("%s 时不该动 iptables,实际调用了 %d 次", tc.desc, n)
			}
		})
	}
}

// TestSetupExitDNSRedirect_InstallFailureAbortsStartup 出口 DNS 接管装不上要中止。
func TestSetupExitDNSRedirect_InstallFailureAbortsStartup(t *testing.T) {
	f := newFakeNetTools(t)
	f.failOn(t, "-t nat -A PREROUTING")
	err := setupExitDNSRedirect("iptables", "tun0", "8.8.8.8")
	if err == nil {
		t.Fatal("DNS DNAT 装失败却返回 nil")
	}
	if !strings.Contains(err.Error(), "DNS DNAT") {
		t.Errorf("错误应含 DNS DNAT,实得:%v", err)
	}
}

// TestSetupExitDNSRedirect_NoopWhenDisabled dnsIP / 设备名为空时什么都不做。
func TestSetupExitDNSRedirect_NoopWhenDisabled(t *testing.T) {
	for _, tc := range []struct{ desc, dev, dns string }{
		{"dnsIP 为空(解析不到系统 DNS 或配了 off)", "tun0", ""},
		{"设备名为空", "", "8.8.8.8"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := newFakeNetTools(t)
			if err := setupExitDNSRedirect("iptables", tc.dev, tc.dns); err != nil {
				t.Fatal(err)
			}
			if n := len(f.calls(t)); n != 0 {
				t.Errorf("%s 时不该动 iptables,实际 %d 次", tc.desc, n)
			}
		})
	}
}

// TestResolveExitDNSRedirect_FailSafeOnGarbage 非法值退到「不接管」而不是 auto 探测。
//
// 纯函数,不需要假工具。这条是 fail-safe 方向的选择:把 "of"(想写 "off" 的手误)
// 理解成 auto 的话,就是「运维想关掉 DNS 接管,结果反而开了」。
func TestResolveExitDNSRedirect_FailSafeOnGarbage(t *testing.T) {
	for _, bad := range []string{"of", "yes", "1.2.3", "2001:db8::1", "not-an-ip"} {
		if got := resolveExitDNSRedirect(bad); got != "" {
			t.Errorf("非法值 %q 应 fail-safe 到不接管(\"\"),实得 %q", bad, got)
		}
	}
	if got := resolveExitDNSRedirect("off"); got != "" {
		t.Errorf("off 应返回空,实得 %q", got)
	}
	if got := resolveExitDNSRedirect(" 8.8.4.4 "); got != "8.8.4.4" {
		t.Errorf("合法 IPv4 应原样返回(去空白),实得 %q", got)
	}
}

// TestInstallConnlimitRules_SkipsNonPositiveLimitsAndEmptySubnets 上限 ≤0 或空网段时跳过。
func TestInstallConnlimitRules_SkipsNonPositiveLimitsAndEmptySubnets(t *testing.T) {
	f := newFakeNetTools(t)
	if err := installConnlimitRules("iptables", "tun0", "eth0", []string{""}, 0, 0, "32"); err != nil {
		t.Fatal(err)
	}
	if n := f.countMatching(t, "connlimit"); n != 0 {
		t.Errorf("上限为 0 且网段为空时不该装规则,实际 %d 条", n)
	}

	f2 := newFakeNetTools(t)
	if err := installConnlimitRules("iptables", "tun0", "eth0", []string{"10.0.0.0/8", ""}, 5, 0, "32"); err != nil {
		t.Fatal(err)
	}
	if n := f2.countMatching(t, "-I FORWARD 1", "connlimit", "-p tcp"); n != 1 {
		t.Errorf("应只为非空网段装一条 tcp 规则,实际 %d 条", n)
	}
	if n := f2.countMatching(t, "connlimit", "-p udp", "-I FORWARD"); n != 0 {
		t.Errorf("udp 上限为 0 时不该装 udp 规则,实际 %d 条", n)
	}
}

// TestDeleteExistingTUNs_IgnoresFailures 删网卡失败不能中止(网卡本就可能不存在)。
func TestDeleteExistingTUNs_IgnoresFailures(t *testing.T) {
	f := newFakeNetTools(t)
	f.failOn(t, "link delete")
	DeleteExistingTUNs("tun", 3) // 不返回错误,不 panic 即为通过
	if n := f.countMatching(t, "ip link delete"); n != 3 {
		t.Errorf("应对 tun0~tun2 各尝试一次,实际 %d 次", n)
	}

	f2 := newFakeNetTools(t)
	DeleteExistingTUN("")
	if n := len(f2.calls(t)); n != 0 {
		t.Errorf("空名字不该调用 ip,实际 %d 次", n)
	}
}

// TestGetWAN_ReportsErrorWhenRouteLookupFails 探不到出网网卡要如实报错。
//
// 探测失败若被吞成空字符串,后续 NAT 规则会带着空的 -o 装上去 —— 要么 iptables 报错,
// 要么(更糟)规则语义变成「所有出接口」。
func TestGetWAN_ReportsErrorWhenRouteLookupFails(t *testing.T) {
	f := newFakeNetTools(t)
	f.failOn(t, "route get")
	if iface, ip, err := GetWAN(); err == nil {
		t.Errorf("ip route get 失败却返回成功:iface=%q ip=%q", iface, ip)
	}

	f6 := newFakeNetTools(t)
	f6.failOn(t, "route get")
	if iface, ip, err := GetWANv6(); err == nil {
		t.Errorf("v6 侧同样应报错:iface=%q ip=%q", iface, ip)
	}
}

// TestEnableIPForward_ReportsSysctlFailure 开转发失败要报错(这条是致命的)。
//
// 与 rp_filter 不同:ip_forward=0 意味着**一个包都转不出去**,整个出口功能不存在。
// 这不能只告警。
func TestEnableIPForward_ReportsSysctlFailure(t *testing.T) {
	f := newFakeNetTools(t)
	f.failOn(t, "ip_forward=1")
	if err := EnableIPForward(); err == nil {
		t.Fatal("sysctl ip_forward 失败却返回 nil —— 转发没开,出口整体不通而启动继续")
	}

	f6 := newFakeNetTools(t)
	f6.failOn(t, "forwarding=1")
	if err := EnableIPv6Forward(); err == nil {
		t.Fatal("sysctl ipv6 forwarding 失败却返回 nil")
	}
}

// TestEnableIPForward_AcceptsPresetValueWhenSysctlIsReadOnly 写不进去但值已经是 1 时必须放行。
//
// 这是 2026-08-02 容器化时实撞的:Docker 按 --sysctl 在建容器那一刻把 ip_forward 设成 1,
// 之后 /proc/sys 是只读的,于是 `sysctl -w` 恒失败。把它判为致命的话,转发明明开着,
// nanotund 却以 exit 60 退出、容器无限重启,唯一出路是 --privileged —— 为一个已经生效的
// 内核参数敞开整个 /proc/sys。
//
// 一并钉住反向:回读**不是** 1 时照旧报错。放行的只有「目标状态已达成」这一种情况,
// 谁把回读判定写成「读得到就算数」,下面第二组就会红。
func TestEnableIPForward_AcceptsPresetValueWhenSysctlIsReadOnly(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		failRe  string
		read    string
		wantErr bool
	}{
		{"v4 · 写被拒但值已是 1 → 放行", "ip_forward=1", "1", false},
		{"v4 · 写被拒且值仍是 0 → 报错", "ip_forward=1", "0", true},
		{"v4 · 写被拒且读不出值 → 报错", "ip_forward=1", "", true},
		{"v6 · 写被拒但值已是 1 → 放行", "forwarding=1", "1", false},
		{"v6 · 写被拒且值仍是 0 → 报错", "forwarding=1", "0", true},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := newFakeNetTools(t)
			f.failOn(t, tc.failRe)
			f.sysctlReads(t, tc.read)

			var err error
			if strings.HasPrefix(tc.desc, "v6") {
				err = EnableIPv6Forward()
			} else {
				err = EnableIPForward()
			}
			if tc.wantErr && err == nil {
				t.Fatalf("回读为 %q 却当成已开启 —— 转发没开,出口整体不通而启动继续", tc.read)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("值已经是 1 仍报错(%v)—— 容器里 /proc/sys 只读时会无限重启", err)
			}
		})
	}
}

// TestSetupIptables_CleansStaleRulesThenInstallsFresh 历史残留被成功删掉的完整路径。
//
// 前面那条用例压的是「删失败」,这条压「删成功」:切换 isolate → mesh 时,上次留下的
// device→device DROP 必须先被摘掉,再装 ACCEPT。少了这一步,链上同时存在 DROP 和 ACCEPT,
// 谁在前谁生效 —— 表现为「配置改成 mesh 了但客户端还是互访不通」,而 `iptables -S` 里
// ACCEPT 明明在。
func TestSetupIptables_CleansStaleRulesThenInstallsFresh(t *testing.T) {
	f := newFakeNetTools(t)
	// 上次是 isolate 模式,链上留着 device→device DROP;删一次就没了。
	f.ruleExistsOnce(t, "-C FORWARD -i tun0 -o tun0 -j DROP")

	if err := callSetupIptables(config.TUNExitModeMesh, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatalf("切到 mesh 不该报错:%v", err)
	}
	if n := f.countMatching(t, "-D FORWARD -i tun0 -o tun0 -j DROP"); n != 1 {
		t.Errorf("应删掉 1 条历史 DROP,实际 %d 条", n)
	}
	if n := f.countMatching(t, "-I FORWARD 1 -i tun0 -o tun0 -j ACCEPT"); n != 1 {
		t.Errorf("删完历史 DROP 后应装上 mesh ACCEPT,实际 %d 条", n)
	}
}

// TestSetupIptables_OffModeCleansStaleExitAccept off 模式要摘掉上次留下的出网 ACCEPT。
//
// 从 mesh 改成 off 时,若只加 DROP 不摘 ACCEPT,而 ACCEPT 恰好排在前面,流量照样出公网 ——
// 「改成纯组网」这个操作静默无效。
func TestSetupIptables_OffModeCleansStaleExitAccept(t *testing.T) {
	f := newFakeNetTools(t)
	f.ruleExistsOnce(t, "-C FORWARD -i tun0 -o eth0 -j ACCEPT")

	if err := callSetupIptables(config.TUNExitModeOff, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatalf("切到 off 不该报错:%v", err)
	}
	if n := f.countMatching(t, "-D FORWARD -i tun0 -o eth0 -j ACCEPT"); n != 1 {
		t.Errorf("应摘掉 1 条历史出网 ACCEPT,实际 %d 条 —— 不摘的话 off 模式形同虚设", n)
	}
	if n := f.countMatching(t, "-I FORWARD 1 -i tun0 -o eth0 -j DROP"); n != 1 {
		t.Errorf("应装上 off 模式的出网 DROP,实际 %d 条", n)
	}
}

// TestSetupIptables_PropagatesFailureFromEveryDelegatedStep 委托给子函数的步骤同样不能吞错。
//
// 前面按「规则」维度压过失败,这条按「步骤」维度补齐:SetupIptables 后半段把活交给
// insertTUNForwardPortDrops / setupExitDNSRedirect / setupMagicDNSException / applyExitDenyPrivate。
// 这些子函数自己会返回错误(已单独测过),但**调用点有没有把错误往上抛**是另一回事 ——
// 一个 `_ =` 就能让整段静默失效,而子函数的测试全绿。
func TestSetupIptables_PropagatesFailureFromEveryDelegatedStep(t *testing.T) {
	for _, tc := range []struct{ desc, failRe, wantSub string }{
		{"回程 ESTABLISHED ACCEPT", "-I FORWARD 1 -i eth0 -o tun0 -m state", "FORWARD"},
		{"出站端口黑名单", "-I FORWARD 1 -i tun0 -p tcp --dport 6881:6889", "FORWARD"},
		{"出口 DNS DNAT", "-t nat -A PREROUTING", "DNS DNAT"},
		{"MagicDNS 例外", "-t nat -I PREROUTING 1", "PREROUTING"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := newFakeNetTools(t)
			f.failOn(t, tc.failRe)
			dev, wan, ip, subnets := setupIptablesArgs()
			// 这次把 DNS 接管与 MagicDNS 都打开,好走到后半段。
			err := SetupIptables(dev, wan, ip, subnets, 40, 20, true, true, true,
				config.TUNExitModeMesh, "8.8.8.8", config.TUNExitDenyPrivateOff, "10.200.0.1", 53)
			if err == nil {
				t.Fatalf("%s 装失败却返回 nil —— 调用点吞掉了子函数的错误", tc.desc)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("错误应含 %q,实得:%v", tc.wantSub, err)
			}
		})
	}
}

// TestSetupIp6tables_PropagatesFailureFromDelegatedSteps v6 侧的委托步骤同理。
func TestSetupIp6tables_PropagatesFailureFromDelegatedSteps(t *testing.T) {
	for _, tc := range []struct{ desc, denyPrivate, failRe string }{
		{"回程 ESTABLISHED ACCEPT", config.TUNExitDenyPrivateOff, "-I FORWARD 1 -i eth0 -o tun0 -m state"},
		{"NAT SNAT", config.TUNExitDenyPrivateOff, "-t nat -A POSTROUTING"},
		{"出站端口黑名单", config.TUNExitDenyPrivateOff, "-I FORWARD 1 -i tun0 -p tcp --dport 6881:6889"},
		{"私网闸门", config.TUNExitDenyPrivateLinkLocal, "-d fe80::/10"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			f := newFakeNetTools(t)
			f.failOn(t, tc.failRe)
			if err := callSetupIp6tables(config.TUNExitModeMesh, tc.denyPrivate); err == nil {
				t.Fatalf("v6 侧 %s 装失败却返回 nil", tc.desc)
			}
		})
	}
}

// TestSetupIp6tables_CleansStaleRulesThenInstallsFresh v6 的历史清理路径。
func TestSetupIp6tables_CleansStaleRulesThenInstallsFresh(t *testing.T) {
	f := newFakeNetTools(t)
	f.ruleExistsOnce(t, "-C FORWARD -i tun0 -o tun0 -j DROP")

	if err := callSetupIp6tables(config.TUNExitModeMesh, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatal(err)
	}
	if n := f.countMatching(t, "ip6tables", "-D FORWARD -i tun0 -o tun0 -j DROP"); n != 1 {
		t.Errorf("v6 应删掉 1 条历史 DROP,实际 %d 条", n)
	}

	f2 := newFakeNetTools(t)
	f2.ruleExistsOnce(t, "-C FORWARD -i tun0 -o tun0 -j ACCEPT")
	if err := callSetupIp6tables(config.TUNExitModeIsolate, config.TUNExitDenyPrivateOff); err != nil {
		t.Fatal(err)
	}
	if n := f2.countMatching(t, "ip6tables", "-D FORWARD -i tun0 -o tun0 -j ACCEPT"); n != 1 {
		t.Errorf("切 isolate 时应删掉 1 条历史 mesh ACCEPT,实际 %d 条", n)
	}
}

// TestSetupIptables_EmptyDeviceNameFallsBackToTun0 设备名为空时退到 tun0。
//
// 退不了的话规则会带着空的 -i 装上去 —— 语义从「只管这块 TUN」变成「所有入接口」,
// 客户端隔离 DROP 会把整机转发全掐掉。
func TestSetupIptables_EmptyDeviceNameFallsBackToTun0(t *testing.T) {
	f := newFakeNetTools(t)
	if err := SetupIptables("", "eth0", "203.0.113.10", []string{"10.200.0.0/16"}, 40, 20,
		false, false, false, config.TUNExitModeMesh, "off", config.TUNExitDenyPrivateOff, "", 0); err != nil {
		t.Fatal(err)
	}
	if n := f.countMatching(t, "-I FORWARD 1 -i tun0 -o tun0"); n == 0 {
		t.Error("设备名为空时应退到 tun0")
	}
	if n := f.countMatching(t, "-i  "); n != 0 {
		t.Errorf("出现了 -i 后跟空值的规则 %d 条 —— 语义会变成「所有入接口」", n)
	}

	f6 := newFakeNetTools(t)
	if err := SetupIp6tables("", "eth0", "2001:db8::1", []string{"fd00::/64"}, 40, 20,
		false, false, false, config.TUNExitModeMesh, "", config.TUNExitDenyPrivateOff); err != nil {
		t.Fatal(err)
	}
	if n := f6.countMatching(t, "ip6tables", "-I FORWARD 1 -i tun0 -o tun0"); n == 0 {
		t.Error("v6 侧设备名为空时也应退到 tun0")
	}
}

// TestIdempotentSkipsOnDelegatedHelpers 子函数自己的幂等短路。
func TestIdempotentSkipsOnDelegatedHelpers(t *testing.T) {
	t.Run("MagicDNS 例外已存在", func(t *testing.T) {
		f := newFakeNetTools(t)
		f.ruleExists(t, ".")
		if err := setupMagicDNSException("iptables", "tun0", "10.200.0.1", 53); err != nil {
			t.Fatal(err)
		}
		if n := f.countMatching(t, "-I "); n != 0 {
			t.Errorf("规则已存在却仍插入 %d 条", n)
		}
	})
	t.Run("出口 DNS DNAT 已存在", func(t *testing.T) {
		f := newFakeNetTools(t)
		f.ruleExists(t, ".")
		if err := setupExitDNSRedirect("iptables", "tun0", "8.8.8.8"); err != nil {
			t.Fatal(err)
		}
		if n := f.countMatching(t, "-A PREROUTING"); n != 0 {
			t.Errorf("DNAT 已存在却仍追加 %d 条", n)
		}
	})
	t.Run("v6 FORWARD 规则已存在", func(t *testing.T) {
		f := newFakeNetTools(t)
		f.ruleExists(t, ".")
		f.failOn(t, "^-D ") // 同上:让恒真的清理循环有出口
		if err := callSetupIp6tables(config.TUNExitModeMesh, config.TUNExitDenyPrivateOff); err != nil {
			t.Fatal(err)
		}
		if n := f.countMatching(t, "ip6tables", "-I FORWARD 1"); n != 0 {
			t.Errorf("v6 规则已存在却仍插入 %d 条", n)
		}
	})
}

// TestGetWAN_ReportsErrorWhenOutputIsUnparsable 命令成功但输出解析不出网卡/源地址。
//
// 与「命令失败」是两条不同的路径:`ip route get` 在某些容器网络下会成功返回一行
// 没有 dev/src 的输出。吞掉的话后续 NAT 规则会带空 -o 装上去。
func TestGetWAN_ReportsErrorWhenOutputIsUnparsable(t *testing.T) {
	newFakeNetTools(t) // 假 ip 成功退出但不输出任何内容
	if iface, ip, err := GetWAN(); err == nil {
		t.Errorf("输出里没有 dev/src 却返回成功:iface=%q ip=%q", iface, ip)
	}
	if iface, ip, err := GetWANv6(); err == nil {
		t.Errorf("v6 侧同样应报错:iface=%q ip=%q", iface, ip)
	}
}

// TestSweepMainIptablesRules_OnlyDeletesOwnRules sweep 只删自己 comment 的规则。
//
// 这台机器上同时有 ufw / docker / 运维脚本装的规则。sweep 的匹配条件一旦放宽
// (比如改成按 chain 或按 -j DROP 匹配),就会在每次重启时清掉别人的防火墙规则 ——
// 而 nanotun 自己一切正常,故障出在别的服务上,几乎不可能联想到这里。
func TestSweepMainIptablesRules_OnlyDeletesOwnRules(t *testing.T) {
	f := newFakeNetTools(t)
	f.saveOutput(t, strings.Join([]string{
		"*filter",
		":FORWARD ACCEPT [0:0]",
		"-A FORWARD -i tun0 -o eth0 -j ACCEPT -m comment --comment " + mainIptComment,
		"-A FORWARD -i docker0 -o eth0 -j ACCEPT",
		"-A FORWARD -s 10.0.0.0/8 -j DROP -m comment --comment ufw-user-input",
		"-A INPUT -i tun0 -d 169.254.0.0/16 -j DROP -m comment --comment " + mainIptComment,
		"COMMIT",
	}, "\n"))

	cleaned := sweepMainIptablesRules("iptables")

	// filter 与 nat 两张表各喂了同一份输出,故每条 nanotun 规则会被数两次。
	if cleaned == 0 {
		t.Fatal("一条都没清 —— sweep 没解析出自己的规则,重启不再是「干净安装」")
	}
	for _, foreign := range []string{"docker0", "ufw-user-input"} {
		if n := f.countMatching(t, "-D", foreign); n != 0 {
			t.Errorf("删除了别人的规则(%s)%d 次 —— 每次重启都会破坏同机其它服务的防火墙", foreign, n)
		}
	}
	if n := f.countMatching(t, "-D FORWARD", mainIptComment); n == 0 {
		t.Error("没有删除自己带 comment 的 FORWARD 规则")
	}
}
