package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/util"
)

// SIGHUP 只能热更一小部分字段,其余改了要么无效、要么会让在跑的连接遭殃。所以 reload 把它们
// 归进 deferred 列表并打 ERROR 日志。
//
// 漏报一个字段的后果不是「少条日志」:运维改完 `upload_rate`、发 SIGHUP、日志里没有任何异常,
// 于是认为限速已经改了 —— 实际要等下次 restart。这类误解会一直持续到某次真的重启,而那时限速
// 突然变化又会被归因到重启本身。
//
// 反方向同样要钉:把「效果不变」的改动误报成 deferred 也在毁掉这个信号 —— 一旦 deferred 里
// 常年有噪声,运维就不再看它了。exit_mode / exit_deny_private / exit_dns_redirect 这几项都有
// 「""/auto 等价、大小写不敏感」的归一化语义,归一化前后必须一致对待。

// TestClassifyDeferredFields_ReportsEveryFieldThatWontTakeEffect 每个不可热更的字段都要报。
func TestClassifyDeferredFields_ReportsEveryFieldThatWontTakeEffect(t *testing.T) {
	cases := []struct {
		field string
		mut   func(c *config.Config)
	}{
		{"server.upload_rate", func(c *config.Config) { c.Server.UploadRate = 5 << 20 }},
		{"server.download_rate", func(c *config.Config) { c.Server.DownloadRate = 5 << 20 }},
		{"server.data_plane_ping_interval", func(c *config.Config) {
			c.Server.DataPlanePingInterval = config.Duration(30 * 1e9)
		}},
		{"tun.exit_mode", func(c *config.Config) { c.TUN.ExitMode = config.TUNExitModeIsolate }},
		{"tun.exit_deny_private", func(c *config.Config) {
			c.TUN.ExitDenyPrivate = config.TUNExitDenyPrivateOff
		}},
		// 下面五项与各自同族的兄弟字段一样只在启动时落链/构建,却一直没进 deferred。
		// 三个端口封堵开关在 server.go 里就是同一次 SetupIptables 调用的相邻实参,
		// 而同一次调用里的 exit_mode / exit_dns_redirect 早就报了。
		{"tun.forward_block_bt", func(c *config.Config) { c.TUN.ForwardBlockBT = !c.TUN.ForwardBlockBT }},
		{"tun.forward_block_tracker_6969", func(c *config.Config) {
			c.TUN.ForwardBlockTracker6969 = !c.TUN.ForwardBlockTracker6969
		}},
		{"tun.forward_block_smtp_25", func(c *config.Config) {
			c.TUN.ForwardBlockSMTP25 = !c.TUN.ForwardBlockSMTP25
		}},
		// 加一个端口 = 运维以为它从此受保护,实际仍对全网敞开到下次重启。
		{"server.jump_host_protected_ports", func(c *config.Config) {
			c.Server.JumpHostProtectedPorts = append(c.Server.JumpHostProtectedPorts, "tcp/9999")
		}},
		// 危险方向是关:为收紧而改 false,却仍在转发任意 UDP。
		{"hysteria.udp_relay_enabled", func(c *config.Config) {
			c.Hysteria.UDPRelayEnabled = !c.Hysteria.UDPRelayEnabled
		}},
		// 这两个是上面三个端口封堵开关在 SetupIptables 里的相邻实参,补那一族时漏了。
		// 典型场景是应急:某客户端把机器打满,当场把上限从 40 收到 5、SIGHUP、日志一切正常,
		// 于是以为摁住了 —— 内核里那条规则仍写着 40。
		{"tun.tcp_connlimit_per_ip", func(c *config.Config) { c.TUN.TCPConnlimitPerIP = 5 }},
		{"tun.udp_connlimit_per_ip", func(c *config.Config) { c.TUN.UDPConnlimitPerIP = 5 }},
		// 「为安全而轮换」的一族:漏报是双向的 —— 旧口令 / 旧 CA 仍然有效(加固没发生),
		// 而照配置文件新签出来的 profile 与客户端证书连不上(在跑的进程还用着旧值)。
		// hysteria.password 与 server.tls_cert_file 早就在名单里,这三个一直漏着。
		{"hysteria.obfs_salamander_password", func(c *config.Config) {
			c.Hysteria.ObfsSalamanderPassword = "rotated-" + c.Hysteria.ObfsSalamanderPassword
		}},
		{"hysteria.tls_client_ca_file", func(c *config.Config) {
			c.Hysteria.TLSClientCAFile = "certs/rotated-client-ca.pem"
		}},
		{"server.vpn_websocket_path", func(c *config.Config) {
			c.Server.VPNWebSocketPath = "/internal/rotated/path"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			old := newReloadCfg()
			nc := newReloadCfg()
			tc.mut(&nc)

			got := classifyDeferredFields(&old, &nc)
			if !slices.Contains(got, tc.field) {
				t.Fatalf("改了 %s 却没进 deferred(got %v)—— 运维会以为 SIGHUP 已经生效", tc.field, got)
			}
			// 只报改动的那一项,不夹带别的。
			if len(got) != 1 {
				t.Errorf("deferred = %v,只改了一项却报了多项 —— 噪声会让这个列表失去意义", got)
			}
		})
	}
}

// TestClassifyDeferredFields_StaysQuietWhenNothingReallyChanged 效果不变的改写不许报。
func TestClassifyDeferredFields_StaysQuietWhenNothingReallyChanged(t *testing.T) {
	cases := []struct {
		name string
		mut  func(oldCfg, newCfg *config.Config)
	}{
		{
			// 两者都归一化到 mesh:一个是显式写、一个是留空取默认。
			name: "exit_mode 空值与显式 mesh 等价",
			mut: func(o, n *config.Config) {
				o.TUN.ExitMode = ""
				n.TUN.ExitMode = "MESH"
			},
		},
		{
			name: "exit_deny_private 空值与 auto 等价",
			mut: func(o, n *config.Config) {
				o.TUN.ExitDenyPrivate = ""
				n.TUN.ExitDenyPrivate = "Auto"
			},
		},
		{
			// 注意这一项的空值归一化到 auto(不是 off),所以 ""→"Auto" 才是等价改写。
			name: "exit_dns_redirect 空值与 auto 等价",
			mut: func(o, n *config.Config) {
				o.TUN.ExitDNSRedirect = ""
				n.TUN.ExitDNSRedirect = "Auto"
			},
		},
		{
			// 留空即取内置默认长路径,与显式写出那条路径完全等价。
			name: "vpn_websocket_path 空值与显式默认路径等价",
			mut: func(o, n *config.Config) {
				o.Server.VPNWebSocketPath = ""
				n.Server.VPNWebSocketPath = util.DefaultVPNWebSocketPath
			},
		},
		{
			// 缺前导斜杠会被补上,补前补后是同一条路径。
			name: "vpn_websocket_path 前导斜杠可省",
			mut: func(o, n *config.Config) {
				o.Server.VPNWebSocketPath = "internal/ws/v1"
				n.Server.VPNWebSocketPath = "/internal/ws/v1"
			},
		},
		{
			// 读取点是 TrimSpace 后用的,首尾空白不改变实际口令。
			name: "obfs_salamander_password 首尾空白不算改动",
			mut: func(o, n *config.Config) {
				o.Hysteria.ObfsSalamanderPassword = "s3cret"
				n.Hysteria.ObfsSalamanderPassword = "  s3cret\t"
			},
		},
		{
			name: "exit_dns_redirect 大小写不敏感",
			mut: func(o, n *config.Config) {
				o.TUN.ExitDNSRedirect = "off"
				n.TUN.ExitDNSRedirect = "OFF"
			},
		},
		// jump_host_protected_ports 的等价改写。解析器大小写不敏感、"-" 与 ":" 同义、
		// end<start 自动交换、非法条目跳过,顺序也不影响落链(每条各自成一条 INPUT 规则)。
		// 这些若被报成 deferred,列表就会常年有噪声。
		{
			name: "protected_ports 大小写不敏感",
			mut: func(o, n *config.Config) {
				o.Server.JumpHostProtectedPorts = []string{"tcp/8080"}
				n.Server.JumpHostProtectedPorts = []string{"TCP/8080"}
			},
		},
		{
			name: "protected_ports 的 - 与 : 等价",
			mut: func(o, n *config.Config) {
				o.Server.JumpHostProtectedPorts = []string{"udp/5000-5002"}
				n.Server.JumpHostProtectedPorts = []string{"udp/5000:5002"}
			},
		},
		{
			name: "protected_ports 区间反写会被自动交换",
			mut: func(o, n *config.Config) {
				o.Server.JumpHostProtectedPorts = []string{"udp/5000-5002"}
				n.Server.JumpHostProtectedPorts = []string{"udp/5002-5000"}
			},
		},
		{
			name: "protected_ports 顺序不影响落链",
			mut: func(o, n *config.Config) {
				o.Server.JumpHostProtectedPorts = []string{"tcp/8080", "udp/443"}
				n.Server.JumpHostProtectedPorts = []string{"udp/443", "tcp/8080"}
			},
		},
		{
			// 非法条目 runtime 本来就跳过,加一条不改变任何落链结果。
			name: "protected_ports 追加一条非法项不改变效果",
			mut: func(o, n *config.Config) {
				o.Server.JumpHostProtectedPorts = []string{"tcp/8080"}
				n.Server.JumpHostProtectedPorts = []string{"tcp/8080", "sctp/99"}
			},
		},
		// connlimit 的 ≤0 一律按 40 落链,所以「没配」与「显式写 40」装出来是同一条规则。
		// 把这种改写报成需要重启,等于告诉运维去做一次毫无必要的重启。
		{
			name: "tcp_connlimit 没配与显式 40 等价",
			mut: func(o, n *config.Config) {
				o.TUN.TCPConnlimitPerIP = 0
				n.TUN.TCPConnlimitPerIP = config.DefaultConnlimitPerIP
			},
		},
		{
			// 负数同样归一到默认值,不是「关闭限制」。
			name: "udp_connlimit 负数与显式 40 等价",
			mut: func(o, n *config.Config) {
				o.TUN.UDPConnlimitPerIP = -1
				n.TUN.UDPConnlimitPerIP = config.DefaultConnlimitPerIP
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := newReloadCfg()
			nc := newReloadCfg()
			tc.mut(&old, &nc)
			if got := classifyDeferredFields(&old, &nc); len(got) != 0 {
				t.Errorf("效果没变却报了 %v —— deferred 里的噪声会让运维不再看它", got)
			}
		})
	}
}

// TestClassifyDeferredFields_NoChangeMeansEmpty 完全没改时列表必须是空的。
func TestClassifyDeferredFields_NoChangeMeansEmpty(t *testing.T) {
	old := newReloadCfg()
	nc := newReloadCfg()
	if got := classifyDeferredFields(&old, &nc); len(got) != 0 {
		t.Fatalf("配置一字未动却报了 %v", got)
	}
}

// TestParseJumpHostProtectedPorts_WarnsAboutEntriesItSilentlySkips 敲错的条目必须留下告警。
//
// 非法条目是「Warn 后跳过」而不是拒服(敲错一行不该让 jump_host_firewall 整个拒启),所以那行
// 告警是运维唯一能发现自己敲错的信号 —— 少了它,`jump_host_protected_ports = ["tcp/8O8O"]`
// (字母 O)会表现成「配置写了、启动没报错、端口却不受保护」。
//
// 这条是补测:把解析拆成 quiet + 打日志的外壳之后,那层外壳很容易被当成纯转发删掉。
func TestParseJumpHostProtectedPorts_WarnsAboutEntriesItSilentlySkips(t *testing.T) {
	hook := &countingLogHook{levels: []logrus.Level{logrus.WarnLevel}}
	logrus.AddHook(hook)
	// logrus 没有 RemoveHook;把等级压到 Panic 让后续用例不受这个 hook 干扰。
	t.Cleanup(func() { hook.mu.Lock(); hook.levels = []logrus.Level{logrus.PanicLevel}; hook.mu.Unlock() })

	specs := parseJumpHostProtectedPorts([]string{
		"tcp/8080",      // 合法,不该告警
		"8080",          // 缺 proto/
		"sctp/99",       // proto 不是 tcp/udp
		"tcp/8O8O",      // 字母 O,起始端口非法
		"udp/500-70000", // 结束端口越界
	})

	// 只有那一条合法的进了 spec。
	if len(specs) != 1 || specs[0].Proto != "tcp" || specs[0].Port != 8080 {
		t.Fatalf("specs = %+v,应当只留下 tcp/8080", specs)
	}
	// 四条非法项各留一条告警。数量断言是为了防「只报第一条就 break」。
	msgs := hook.messages()
	var warned int
	for _, m := range msgs {
		if strings.Contains(m, "jump_host_protected_ports") {
			warned++
		}
	}
	if warned != 4 {
		t.Errorf("jump_host_protected_ports 相关告警 = %d 条,期望 4 条(每个被跳过的条目一条)\n全部日志:%v", warned, msgs)
	}
}
