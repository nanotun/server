package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// 这套 ipset/iptables 编排此前一条语句都没执行过 —— 它只在生产的 Linux 上跑,开发机上
// 没有真 iptables,三机 e2e 也没开 jump_host_firewall。于是「装出来的规则集到底长什么样」
// 从来没人验证过。
//
// 这里验的是规则集的形状和失败时的收尾。两个方向都致命:
//   - 装漏了(比如链尾少一条 DROP、或 INPUT 跳转没插到最前),端口看着受保护实际全网可达;
//   - 装歪了(比如 ipset 空着就把 INPUT 挂上去),连本机环回都被 DROP,机器当场失联。
// 两者都不会报错,iptables -L 看上去也都"有规则"。

// fakeIPT 是一个够用的 ipset/iptables 模型:记录每条命令,并且**维护状态** ——
// 建出来的集合/链才能被 list 到,插进去的规则才能被 -C 查到,删掉之后就查不到了。
//
// 状态是必须的,不是为了逼真:生产代码里有「-C 成功就继续 -D」的删除循环,和
// 「-C 失败才 -I」的幂等插入,一个只会说"成功"的假命令会让前者转不出来、让后者
// 每次都重复插。要验的恰恰就是这两处对返回值的依赖。
type fakeIPT struct {
	mu    sync.Mutex
	calls []string
	// fail:命令行前缀 → 返回的错误。按注册顺序匹配第一个命中的,优先于状态模型。
	fail []struct {
		prefix string
		err    error
	}
	setExists   bool
	chainExists bool
	inputRules  []string // 已挂在 INPUT 上的规则(去掉 -I/-C/-D 前缀后的规则体)
}

var errFakeAbsent = errors.New("不存在")

func (f *fakeIPT) run(name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, line)

	for _, c := range f.fail {
		if strings.HasPrefix(line, c.prefix) {
			return []byte("模拟失败输出"), c.err
		}
	}

	// 规则体:INPUT 之后的部分,用来在 -C/-I/-D 之间对齐同一条规则。
	body := ""
	if i := strings.Index(line, " INPUT "); i >= 0 {
		body = line[i+len(" INPUT "):]
		body = strings.TrimPrefix(body, "1 ")
	}
	idx := func() int {
		for i, r := range f.inputRules {
			if r == body {
				return i
			}
		}
		return -1
	}

	switch {
	case strings.HasPrefix(line, "ipset list"):
		if !f.setExists {
			return nil, errFakeAbsent
		}
	case strings.HasPrefix(line, "ipset create"):
		f.setExists = true
	case strings.HasPrefix(line, "ipset destroy"):
		f.setExists = false
	case strings.HasPrefix(line, "ipset flush"), strings.HasPrefix(line, "ipset add"):
		if !f.setExists {
			return nil, errFakeAbsent
		}
	case strings.HasPrefix(line, "iptables -L"):
		if !f.chainExists {
			return nil, errFakeAbsent
		}
	case strings.HasPrefix(line, "iptables -N"):
		f.chainExists = true
	case strings.HasPrefix(line, "iptables -X"):
		f.chainExists = false
	case strings.HasPrefix(line, "iptables -C INPUT"):
		if idx() < 0 {
			return nil, errFakeAbsent
		}
	case strings.HasPrefix(line, "iptables -I INPUT"):
		f.inputRules = append(f.inputRules, body)
	case strings.HasPrefix(line, "iptables -D INPUT"):
		if i := idx(); i >= 0 {
			f.inputRules = append(f.inputRules[:i], f.inputRules[i+1:]...)
		} else {
			return nil, errFakeAbsent
		}
	}
	return nil, nil
}

// leftovers 返回清理后仍挂在 INPUT 上的规则 —— 服务停掉后还挡着端口的那些。
func (f *fakeIPT) leftovers() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.inputRules...)
}

func (f *fakeIPT) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeIPT) has(sub string) bool {
	for _, c := range f.log() {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func (f *fakeIPT) count(sub string) int {
	n := 0
	for _, c := range f.log() {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

// indexOf 返回第一条包含 sub 的命令下标,没有则 -1。用来断言先后顺序。
func (f *fakeIPT) indexOf(sub string) int {
	for i, c := range f.log() {
		if strings.Contains(c, sub) {
			return i
		}
	}
	return -1
}

// installFakeIPT 接管命令执行并假装自己在 Linux 上。
func installFakeIPT(t *testing.T) *fakeIPT {
	t.Helper()
	f := &fakeIPT{}
	prevExec, prevOS := jumpFWExec, jumpFWOnLinux
	jumpFWExec = f.run
	jumpFWOnLinux = func() bool { return true }
	t.Cleanup(func() { jumpFWExec, jumpFWOnLinux = prevExec, prevOS })
	return f
}

func twoPortFirewall() *jumpHostFirewall {
	return newJumpHostFirewallWithSpecs(true, []jumpHostPortSpec{
		{Proto: "tcp", Port: 8443},
		{Proto: "udp", Port: 5000, EndPort: 5002},
	})
}

// TestJumpFirewall_InstalledRuleSetActuallyRestrictsTheseIPs 验一次成功安装的规则集形状。
func TestJumpFirewall_InstalledRuleSetActuallyRestrictsTheseIPs(t *testing.T) {
	f := installFakeIPT(t)
	fw := twoPortFirewall()

	if err := fw.Replace([]string{"203.0.113.7"}); err != nil {
		t.Fatalf("Replace 应成功: %v", err)
	}

	// 自定义链必须是「命中 ipset 就 ACCEPT,否则 DROP」两条,缺了 DROP 那条,不在名单里的
	// 源会掉回 INPUT 继续往下走 —— 多数机器的 INPUT 默认策略是 ACCEPT,等于没保护。
	accept := f.indexOf("iptables -A " + jumpHostChainName + " -m set --match-set " + jumpHostIPSetName + " src -j ACCEPT")
	drop := f.indexOf("iptables -A " + jumpHostChainName + " -j DROP")
	if accept < 0 {
		t.Fatal("链里没有「命中 ipset → ACCEPT」")
	}
	if drop < 0 {
		t.Fatal("链尾没有兜底 DROP —— 不在名单里的源会掉回 INPUT 走默认策略,多数机器是 ACCEPT")
	}
	if accept > drop {
		t.Fatal("DROP 排在 ACCEPT 前面,名单里的源也会被丢掉")
	}

	// 每个受保护端口都要有 INPUT 跳转,且必须插在第一条:排在别人的 ACCEPT 之后就永远不会被命中。
	for _, want := range []string{
		"iptables -I INPUT 1 -p tcp --dport 8443",
		"iptables -I INPUT 1 -p udp --dport 5000:5002",
	} {
		if !f.has(want) {
			t.Fatalf("没有装 %q —— 这个端口对全网敞开\n实际执行:\n%s",
				want, strings.Join(f.log(), "\n"))
		}
	}

	// 环回必须进 ipset,否则本机 hy2/REALITY 经环回连 VPN 端口会被自己 DROP。
	if !f.has("ipset add " + jumpHostIPSetName + " 127.0.0.1") {
		t.Fatal("127.0.0.1 没进 ipset,本机入口会被自己的规则挡死")
	}
	if !f.has("ipset add " + jumpHostIPSetName + " 203.0.113.7") {
		t.Fatal("配置里的跳板机地址没进 ipset")
	}

	// 顺序:ipset 里先有内容,INPUT 跳转才该生效。反过来的话中间那段时间是空集全 DROP。
	if f.indexOf("iptables -I INPUT 1") > f.indexOf("ipset add") {
		t.Fatal("先挂 INPUT 再灌 ipset —— 中间那个窗口里 ipset 是空的,所有源都被 DROP")
	}
	if !fw.installed {
		t.Fatal("装成功了却没记 installed,Teardown 会因此不清理")
	}
}

// TestJumpFirewall_ReplaceReportsFailureInsteadOfPretendingItWorked 验失败必须回给调用方。
//
// 这是第二十三轮深扫那条 HIGH 的回归钉:此前所有失败分支只打一行红字就 return,于是
// ipset/iptables 不可用(没装、没权限、内核缺模块)时,启动照常继续、reload 照常回报
// "已热更新"。运维看配置以为端口只对跳板机开放,实际对全网敞开。
func TestJumpFirewall_ReplaceReportsFailureInsteadOfPretendingItWorked(t *testing.T) {
	cases := []struct {
		name      string
		failOn    string
		because   string
		wantClean bool // 失败后是否应把已装的东西撤干净
	}{
		{"ipset 建不出来(内核无模块/没权限)", "ipset create",
			"整套机制的地基没了,继续跑等于裸奔", false},
		{"自定义链建不出来", "iptables -N",
			"同上", false},
		{"链内 ACCEPT 规则装不上", "iptables -A " + jumpHostChainName + " -m set",
			"链是空的,所有源都会掉到链尾 DROP —— 包括跳板机自己", false},
		{"链尾 DROP 装不上", "iptables -A " + jumpHostChainName + " -j DROP",
			"只有 ACCEPT 没有 DROP,不在名单里的源会落回 INPUT 走默认策略,等于没保护", false},
		{"INPUT 跳转插不进去", "iptables -I INPUT",
			"端口根本没被接管", false},
		{"ipset flush 失败", "ipset flush",
			"旧名单还在,新名单没生效,实际放行的是一批过期地址", true},
		{"ipset add 失败", "ipset add",
			"名单只灌了一半,漏掉的跳板机连不上", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := installFakeIPT(t)
			f.fail = append(f.fail, struct {
				prefix string
				err    error
			}{tc.failOn, errors.New("boom")})

			fw := twoPortFirewall()
			err := fw.Replace([]string{"203.0.113.7"})
			if err == nil {
				t.Fatalf("%s 失败了,Replace 却回报成功 —— %s", tc.failOn, tc.because)
			}
			if !strings.Contains(err.Error(), "未") {
				t.Errorf("错误文案应当讲清「端口当前未受限」,got %q", err)
			}
			if fw.installed {
				t.Error("失败了还标记 installed,后续 Replace 会跳过重装")
			}

			// 失败之后不能留下半装状态:INPUT 已经跳进一条空链 = 全 DROP。
			if f.has("iptables -I INPUT 1") {
				if !f.has("iptables -D INPUT") && !f.has("iptables -X "+jumpHostChainName) {
					t.Errorf("装了 INPUT 跳转又没清掉 —— 留下「跳进空链」的半装状态,本机也连不上\n%s",
						strings.Join(f.log(), "\n"))
				}
			}
			if tc.wantClean && !f.has("ipset destroy") {
				t.Errorf("回滚没销毁 ipset,空集加已挂的 INPUT 规则 = 该端口全 DROP\n%s",
					strings.Join(f.log(), "\n"))
			}
		})
	}
}

// TestJumpFirewall_RepeatedReplaceDoesNotStackRules 验重复刷新的幂等性。
//
// reload 会反复调 Replace。每次都无条件 -I INPUT 的话,iptables 里会攒出成百上千条
// 同样的规则:内存和匹配开销之外,更麻烦的是 Teardown 只删一遍,残留规则会在服务停掉
// 之后继续挡着那个端口。
func TestJumpFirewall_RepeatedReplaceDoesNotStackRules(t *testing.T) {
	f := installFakeIPT(t)
	fw := twoPortFirewall()

	if err := fw.Replace([]string{"203.0.113.7"}); err != nil {
		t.Fatalf("首次 Replace: %v", err)
	}
	firstInserts := f.count("iptables -I INPUT 1")
	if firstInserts != 2 {
		t.Fatalf("两个受保护端口应插两条 INPUT 规则,实际 %d 条", firstInserts)
	}

	if err := fw.Replace([]string{"203.0.113.7", "198.51.100.9"}); err != nil {
		t.Fatalf("再次 Replace: %v", err)
	}
	if got := f.count("iptables -I INPUT 1"); got != firstInserts {
		t.Fatalf("第二次刷新又插了规则(累计 %d 条)—— reload 几次就攒出一堆重复规则", got)
	}
	// 但名单本身必须真的换掉:先 flush 再 add,否则删掉的地址还留在 ipset 里。
	if f.count("ipset flush") != 2 {
		t.Fatalf("每次刷新都该先 flush,实际 %d 次 —— 不 flush 的话被移除的地址还能连",
			f.count("ipset flush"))
	}
	if !f.has("ipset add " + jumpHostIPSetName + " 198.51.100.9") {
		t.Fatal("新增的地址没进 ipset")
	}
}

// TestJumpFirewall_TeardownRemovesEverythingItAdded 验停机清理。
//
// 留下的规则不会随进程消失。服务停了而 INPUT 还跳进一条已经没人维护的链,那个端口
// 就永久不可达 —— 换个程序来监听也一样连不上,排查起来毫无线索。
func TestJumpFirewall_TeardownRemovesEverythingItAdded(t *testing.T) {
	f := installFakeIPT(t)
	fw := twoPortFirewall()
	if err := fw.Replace([]string{"203.0.113.7"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	fw.Teardown()

	for _, want := range []string{
		"iptables -D INPUT -p tcp --dport 8443",
		"iptables -D INPUT -p udp --dport 5000:5002",
		"iptables -X " + jumpHostChainName,
		"ipset destroy " + jumpHostIPSetName,
	} {
		if !f.has(want) {
			t.Fatalf("Teardown 没执行 %q —— 残留规则会让那个端口在服务停掉后依然不可达\n%s",
				want, strings.Join(f.log(), "\n"))
		}
	}
	if left := f.leftovers(); len(left) != 0 {
		t.Fatalf("清理完 INPUT 上还挂着 %v —— 服务已经停了,这些规则还在挡着端口,"+
			"换个程序来监听也一样连不上", left)
	}
	if fw.installed {
		t.Error("清理完了 installed 还是 true")
	}

	// Teardown 幂等:进程退出路径上可能被多次触发(信号处理 + defer)。
	before := len(f.log())
	fw.Teardown()
	if len(f.log()) != before {
		t.Error("第二次 Teardown 又执行了一遍命令,应当被 once 挡住")
	}
}

// TestJumpFirewall_DoesNothingWhenDisabledOrUnsupported 验两条「什么都不该做」的路径。
//
// 没启用却动了 iptables,是拿用户没要求的规则去改他的防火墙;非 Linux 上盲目执行
// 只会得到一堆 command not found,还可能在装了同名工具的系统上造成意外后果。
// 两者都返回 nil —— 它们不是"应用失败",承诺本来就没做出过。
func TestJumpFirewall_DoesNothingWhenDisabledOrUnsupported(t *testing.T) {
	t.Run("未启用", func(t *testing.T) {
		f := installFakeIPT(t)
		fw := newJumpHostFirewallWithSpecs(false, []jumpHostPortSpec{{Proto: "tcp", Port: 8443}})
		if err := fw.Replace([]string{"203.0.113.7"}); err != nil {
			t.Fatalf("未启用时应静默返回 nil,got %v", err)
		}
		fw.Teardown()
		if n := len(f.log()); n != 0 {
			t.Fatalf("未启用却执行了 %d 条命令:%v", n, f.log())
		}
	})

	t.Run("从没装成功过就 Teardown", func(t *testing.T) {
		// 启动期 Replace 失败(或压根没跑到)之后,进程退出路径照样会调 Teardown。
		// 此时不该去 -X/-destroy 那些自己没建过的东西 —— 同名资源可能是别人留下的,
		// 更常见的是上一代进程正在用,清掉等于把还在服务的那套规则拆了。
		f := installFakeIPT(t)
		fw := twoPortFirewall()
		fw.Teardown()
		if n := len(f.log()); n != 0 {
			t.Fatalf("没装成功过却执行了 %d 条清理命令:%v", n, f.log())
		}
	})

	t.Run("非 Linux", func(t *testing.T) {
		f := installFakeIPT(t)
		jumpFWOnLinux = func() bool { return false }
		fw := twoPortFirewall()
		if err := fw.Replace([]string{"203.0.113.7"}); err != nil {
			t.Fatalf("非 Linux 上应静默返回 nil(已明确告知不支持),got %v", err)
		}
		fw.Teardown()
		if n := len(f.log()); n != 0 {
			t.Fatalf("非 Linux 却执行了 %d 条命令:%v", n, f.log())
		}
	})
}

// TestJumpFirewall_ExistingResourcesAreReused 验重入时不重复创建。
//
// 进程重启后 ipset 和链通常还在(Teardown 不一定跑到,比如 kill -9)。此时无脑
// create 会失败,而失败会被当成"安装失败"→ 整个 Replace 报错 → 启动期直接 Fatal。
func TestJumpFirewall_ExistingResourcesAreReused(t *testing.T) {
	f := installFakeIPT(t)
	// 上一代进程留下的现场:ipset 与自定义链都还在,只有 INPUT 跳转没了。
	f.setExists, f.chainExists = true, true

	fw := twoPortFirewall()
	if err := fw.Replace([]string{"203.0.113.7"}); err != nil {
		t.Fatalf("资源已存在时应复用而不是报错: %v", err)
	}
	if f.has("ipset create") {
		t.Error("ipset 已存在还去 create,重启后必然失败")
	}
	if f.has("iptables -N") {
		t.Error("链已存在还去 -N,重启后必然失败")
	}
	// 但链内规则要重刷:-F 之后重新 -A,否则上一代进程留下的链内容(可能是旧端口/旧集合)会继续生效。
	if !f.has("iptables -F " + jumpHostChainName) {
		t.Error("复用已有链却不先 flush,上一代留下的规则会继续生效")
	}
}

// TestJumpFirewall_RestartWithLeftoverRulesDoesNotDuplicate 验重启后不重复插规则。
//
// 这条和「同一进程里反复 Replace」不是一回事:进程内有 installed 标志兜着,第二次
// Replace 压根不会走到插规则那步。真正需要 -C 探测的是 kill -9 之后 —— 内存里的
// 标志没了,iptables 里的规则还在。每崩一次重启就多插一份,几轮下来 INPUT 顶上
// 攒出几十条同样的规则,而 Teardown 的删除循环只按当前 spec 删,清不干净就永久残留。
func TestJumpFirewall_RestartWithLeftoverRulesDoesNotDuplicate(t *testing.T) {
	f := installFakeIPT(t)
	fw := twoPortFirewall()

	// 上一代进程的现场:集合、链、INPUT 跳转全都还在。
	f.setExists, f.chainExists = true, true
	for _, spec := range fw.protectedPorts {
		f.inputRules = append(f.inputRules, strings.Join(fw.inputJumpRuleArgsFor(spec), " "))
	}

	if err := fw.Replace([]string{"203.0.113.7"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	if n := f.count("iptables -I INPUT"); n != 0 {
		t.Fatalf("规则明明还在,重启后又插了 %d 条 —— 每崩一次多一份,最后清不干净\n%s",
			n, strings.Join(f.log(), "\n"))
	}
	if got := len(f.leftovers()); got != 2 {
		t.Fatalf("INPUT 上应仍是 2 条规则,实际 %d 条", got)
	}
}
