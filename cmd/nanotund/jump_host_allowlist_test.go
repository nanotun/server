package main

import (
	"strings"
	"testing"

	"github.com/nanotun/server/config"
)

// 这两个函数决定 ipset 里最终装哪些源 IP —— 也就是「谁能连到 VPN 入口端口」。
// 它们此前一条语句都没被执行过(单测和三机 e2e 都没有)。
//
// 两个方向的判错都是致命且静默的:漏掉一个该在的地址,那台跳板机连不上而运维只会
// 看到"连接超时";多留一个不该在的,防护形同虚设但日志一切正常。更麻烦的是名单一旦
// 变空,ipset 空集意味着**所有**源都落到链尾的 DROP —— 包括本机环回和跳板机自己,
// 服务器当场失联。

func TestSanitizeJumpHostIPv4s_KeepsOnlyWhatIpsetCanActuallyHold(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		because string
	}{
		{"常规两个地址", []string{"203.0.113.7", "198.51.100.9"},
			[]string{"203.0.113.7", "198.51.100.9"}, "保持配置里的顺序"},

		{"前后空格", []string{"  203.0.113.7  ", "\t198.51.100.9\n"},
			[]string{"203.0.113.7", "198.51.100.9"}, "TOML 里手敲难免带空格,不该因此把跳板机挡在外面"},

		{"空串与纯空白", []string{"", "   ", "203.0.113.7"},
			[]string{"203.0.113.7"}, ""},

		{"重复项去重", []string{"203.0.113.7", "203.0.113.7", "203.0.113.7"},
			[]string{"203.0.113.7"},
			"ipset add 一个已存在的元素会报错,而 Replace 里任一 add 失败就整体回滚 —— " +
				"配置里手滑写重一行,后果是所有端口一起失去保护"},

		{"IPv6 丢掉", []string{"2001:db8::1", "203.0.113.7"},
			[]string{"203.0.113.7"},
			"ipset 建的是 family inet,塞 v6 进去 add 必失败 → 回滚 → 全部端口失去保护。" +
				"宁可这条地址不生效,也不能让整套防护塌掉"},

		{"v4-mapped v6 归一成 v4", []string{"::ffff:203.0.113.7"},
			[]string{"203.0.113.7"},
			"同一个地址的两种写法必须折叠,否则去重失效、ipset 里还会出现奇怪格式"},

		{"CIDR 不接受", []string{"203.0.113.0/24", "203.0.113.7"},
			[]string{"203.0.113.7"},
			"运维很自然会想写网段,但 hash:ip 只吃单个地址 —— 这里静默跳过," +
				"意味着那一整段人都连不上,是这套配置最容易踩的坑"},

		{"主机名不接受", []string{"jump.example.com", "203.0.113.7"},
			[]string{"203.0.113.7"}, "不做 DNS 解析:名单是安全边界,不能随 DNS 变"},

		{"全是垃圾 → 空", []string{"???", "999.1.1.1", ""}, nil,
			"空名单本身不是终态,由 ensureLoopbackIPv4Allowlist 兜底"},

		{"空输入 → 空", nil, nil, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeJumpHostIPv4s(tc.in)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v,want %v(%s)", got, tc.want, tc.because)
			}
		})
	}
}

// ensureLoopbackIPv4Allowlist 在名单里强行保证 127.0.0.1 存在。
//
// 这不是便利性考虑:本机的 hy2 / REALITY 入口是**经环回**去连 VPN 端口的。127.0.0.1
// 不在 ipset 里,这些本地转发就被自己的 INPUT 规则 DROP 掉 —— 表现为「开了 jump_host
// 之后 hy2 客户端全连不上」,而 iptables 看上去完全正常。
func TestEnsureLoopbackIPv4Allowlist_AlwaysLeavesTheLocalDoorOpen(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		because string
	}{
		{"名单里没有环回 → 补在最前", []string{"203.0.113.7"},
			[]string{"127.0.0.1", "203.0.113.7"},
			"本机 hy2/REALITY 是经环回连 VPN 端口的,漏了它等于把自己的入口挡死"},

		{"名单里已有环回 → 保持原样不重复", []string{"203.0.113.7", "127.0.0.1"},
			[]string{"203.0.113.7", "127.0.0.1"},
			"重复 add 会让 Replace 整体回滚"},

		{"环回在中间也算数", []string{"203.0.113.7", "127.0.0.1", "198.51.100.9"},
			[]string{"203.0.113.7", "127.0.0.1", "198.51.100.9"}, ""},

		{"空名单 → 只剩环回", nil, []string{"127.0.0.1"},
			"绝不能返回空:空 ipset 会让所有源都掉进链尾 DROP,机器当场失联"},

		{"全是无效项 → 只剩环回", []string{"2001:db8::1", "垃圾", "10.0.0.0/8"},
			[]string{"127.0.0.1"},
			"同上。这也是「只配了 v6 跳板机」时的实际结果:fail-closed 到只剩本机"},

		{"其它环回地址不算数", []string{"127.0.0.2"},
			[]string{"127.0.0.1", "127.0.0.2"},
			"补的是 127.0.0.1 这个确切地址 —— 环回桥接拨的就是它,同段的别的地址顶不了"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ensureLoopbackIPv4Allowlist(tc.in)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v,want %v(%s)", got, tc.want, tc.because)
			}
			found := false
			for _, s := range got {
				if s == "127.0.0.1" {
					found = true
				}
			}
			if !found {
				t.Fatal("结果里没有 127.0.0.1 —— 这个不变量任何输入下都不许破")
			}
		})
	}
}

// 解析器里「结束端口非法」那条分支此前没走到过。
//
// 它决定的是一整段端口保不保护:"udp/5000-99999" 被整条跳过,意味着 5000 起的
// port hopping range 全部对公网敞开,而配置文件里明明写了要保护它。
func TestParseJumpHostProtectedPorts_BadEndPortDropsTheWholeRange(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []jumpHostPortSpec
	}{
		{"结束端口超界", "udp/5000-99999", nil},
		{"结束端口为 0", "udp/5000-0", nil},
		{"结束端口不是数字", "udp/5000-abc", nil},
		{"结束端口为负", "tcp/5000--1", nil},
		{"合法区间作为对照", "udp/5000-5002",
			[]jumpHostPortSpec{{Proto: "udp", Port: 5000, EndPort: 5002}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseJumpHostProtectedPorts([]string{tc.in})
			if len(got) != len(tc.want) {
				t.Fatalf("%q → %+v,want %+v —— 整条被跳过意味着那段端口对公网敞开",
					tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("[%d] got %+v want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestJumpHostPortSyntax_LintAndRuntimeAcceptTheSameSet 钉住一条跨包不变量。
//
// config 那边的 ValidateJumpHostProtectedPorts 是给 `config lint` 用的语法闸,这边的
// parseJumpHostProtectedPorts 是运行期真正解析。两者必须接受**同一个集合** ——
// 它们分别写了一遍相同的语法规则,而语法规则是最容易改一处忘一处的东西。
//
// 一旦漂移:lint 放行、runtime 静默跳过,那个端口就在运维毫不知情的情况下失去保护。
// 反向漂移(lint 拒、runtime 能认)危害小些,但会让一份能跑的配置过不了检查。
func TestJumpHostPortSyntax_LintAndRuntimeAcceptTheSameSet(t *testing.T) {
	corpus := []string{
		// 合法
		"tcp/8443", "udp/443", "udp/5000-5002", "tcp/9000:9002",
		"TCP/8443", "  udp/443  ", "tcp/1", "tcp/65535",
		// 非法
		"", "   ", "tcp8443", "/8443", "tcp/", "sctp/8443", "icmp/0",
		"tcp/http", "tcp/0", "tcp/65536", "tcp/-1",
		"udp/5000-99999", "udp/5000-0", "udp/5000-abc", "tcp/5000:0",
		"tcp/5000-", "tcp//8443", "8443", "tcp/8443/extra",
	}

	for _, in := range corpus {
		t.Run(strings.ReplaceAll(in, "/", "_"), func(t *testing.T) {
			// 空白项两边都当「跳过」处理,不算分歧。
			if strings.TrimSpace(in) == "" {
				return
			}
			lintRejects := config.ServerConfig{
				JumpHostFirewall:       true,
				JumpHostProtectedPorts: []string{in},
			}.ValidateJumpHostProtectedPorts() != nil

			runtimeSkips := len(parseJumpHostProtectedPorts([]string{in})) == 0

			if lintRejects != runtimeSkips {
				verdict := "lint 放行但运行期会静默跳过 —— 这个端口不会被保护,而 lint 说配置没问题"
				if lintRejects {
					verdict = "lint 拒绝但运行期认得 —— 一份实际能用的配置过不了检查"
				}
				t.Fatalf("%q:两边语法判定不一致(lint 拒=%v,runtime 跳过=%v)\n%s",
					in, lintRejects, runtimeSkips, verdict)
			}
		})
	}
}
