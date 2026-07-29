package main

import (
	"net/netip"
	"strings"
	"testing"
)

// vIP 分配。这里出错的形状只有一种,但很致命:两台设备拿到同一个地址,或者拿到一个不属于本
// 网段的地址。两者都不报错 —— 数据面表现是「其中一台的流量时通时不通」,查到根因通常要很久。
//
// 既有用例只跑了 IPv4 /24 的顺序分配。下面补的是三类没人测过的:v6 分配整条路径、按主机位夹取
// 迭代上界(第八轮那条 LOW 的回归)、以及池子快满时的容量告警。

// TestAllocClientIP_IPv6 v6 分配从来没有测过 —— 而配了 [tun].subnets_v6 的部署走的就是它。
func TestAllocClientIP_IPv6(t *testing.T) {
	used := map[string]bool{}
	prefix := netip.MustParsePrefix("fd00:80::1/64")

	for _, want := range []string{"fd00:80::2", "fd00:80::3", "fd00:80::4"} {
		cfg, err := AllocClientIP("fd00:80::1/64", used, nil)
		if err != nil {
			t.Fatalf("AllocClientIP(v6): %v", err)
		}
		if cfg.ClientIP != want {
			t.Fatalf("ClientIP = %q,期望 %q", cfg.ClientIP, want)
		}
		// v6 的「掩码」下发的是前缀长度,不是点分十进制 —— 客户端按它配地址。
		if cfg.Mask != "64" {
			t.Errorf("v6 的 Mask 应为前缀长度 %q,got %q", "64", cfg.Mask)
		}
		if cfg.Gateway != "fd00:80::1" {
			t.Errorf("Gateway = %q", cfg.Gateway)
		}
		addr := netip.MustParseAddr(cfg.ClientIP)
		if !prefix.Contains(addr) {
			t.Fatalf("分出的地址 %s 落在配置前缀之外", cfg.ClientIP)
		}
		if addr == prefix.Addr() {
			t.Fatal("不该把网关地址分给客户端")
		}
		used[cfg.ClientIP] = true
	}
}

// TestAllocClientIP_NeverLeavesThePrefix 第八轮那条 LOW 的回归。
//
// v6 的候选地址是直接往最后两字节写 i 算出来的。前缀长于 /112 时,byte14 属于**网络位** ——
// 迭代上界若仍按固定的 65534 走,i 一过 255 就把网络位覆写掉,生成的地址落在配置前缀之外。
// 客户端拿着这样的地址,报文出不去也回不来,而 server 侧没有任何错误。
//
// 这条修完(按主机位夹取上界 + prefix.Contains 兜底)之后一直没有回归测试。
func TestAllocClientIP_NeverLeavesThePrefix(t *testing.T) {
	// limit 是这一档要取多少个地址。小前缀直接分光(这才是第八轮那条修复真正改变行为的地方 ——
	// 只有主机位少于 16 时,固定上界才会把 i 溢进网络位);大池子只抽查前几百个:分配器是线性
	// 扫描,把 65534 个全取出来是 O(n²),跑几分钟还没完,而它的行为本来就不受那条修复影响。
	for _, tc := range []struct {
		cidr  string
		limit int
	}{
		{"fd00:80::1/64", 400},  // 常见:主机位远超 16,上界封顶 65534;400 个足以跨过 byte15 边界
		{"fd00:80::1/112", 400}, // 恰好 16 位主机位
		{"fd00:80::1/120", 300}, // 长于 /112:byte14 是网络位,只有 8 位主机位 → 会分光
		{"fd00:80::1/126", 10},  // 极小前缀 → 会分光
		{"10.0.0.1/24", 300},    // 会分光
		{"10.0.0.1/8", 400},     // 主机位 24,上界要被夹到 16 位
		{"10.0.0.1/30", 10},     // 会分光
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			cidr := tc.cidr
			prefix := netip.MustParsePrefix(cidr)
			used := map[string]bool{}
			for n := 0; n < tc.limit; n++ {
				cfg, err := AllocClientIP(cidr, used, nil)
				if err != nil {
					break // 池满 —— 正常终止
				}
				addr := netip.MustParseAddr(cfg.ClientIP).Unmap()
				if !prefix.Contains(addr) {
					t.Fatalf("第 %d 次分配给出 %s,落在 %s 之外 —— 客户端拿到它就是报文出不去也回不来",
						n+1, cfg.ClientIP, cidr)
				}
				if addr == prefix.Addr().Unmap() {
					t.Fatalf("第 %d 次分配给出了网关地址 %s", n+1, cfg.ClientIP)
				}
				if used[cfg.ClientIP] {
					t.Fatalf("同一个地址 %s 被分了两次 —— 两台设备会同时用它", cfg.ClientIP)
				}
				used[cfg.ClientIP] = true
			}
			if len(used) == 0 {
				t.Fatalf("%s 一个地址都分不出来", cidr)
			}
		})
	}
}

// TestAllocClientIP_TinyPrefixesRunOutInsteadOfImprovising 小到没有可用主机位的前缀。
//
// /31 与 /32(v6 的 /127、/128)没有可分配的客户端地址。此时必须**报池满**,而不是硬凑一个 ——
// 凑出来的只能是网关自己或前缀外的地址,两种都会让那个客户端彻底不通,而登录是成功的。
func TestAllocClientIP_TinyPrefixesRunOutInsteadOfImprovising(t *testing.T) {
	for _, cidr := range []string{"10.0.0.1/31", "10.0.0.1/32", "fd00::1/127", "fd00::1/128"} {
		t.Run(cidr, func(t *testing.T) {
			cfg, err := AllocClientIP(cidr, map[string]bool{}, nil)
			if err == nil {
				t.Fatalf("%s 没有可用主机位,应报池满,却分出了 %q", cidr, cfg.ClientIP)
			}
			if !strings.Contains(err.Error(), "subnet full") {
				t.Errorf("错误应说明是池满,got %v", err)
			}
		})
	}
}

// TestAllocClientIP_SkipsTheGatewayWhereverItSits 网关不在 .1 的部署。
//
// 扫描从主机位 2 开始,所以网关恰好落在 .2 时必须跳过它。跳不过就是把网关地址分给客户端:
// 与 server 冲突、该客户端整条路由断掉。
func TestAllocClientIP_SkipsTheGatewayWhereverItSits(t *testing.T) {
	cfg, err := AllocClientIP("10.9.0.2/24", map[string]bool{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientIP == "10.9.0.2" {
		t.Fatal("把网关地址分给了客户端 —— 它会和 server 网关撞车,整条路由断掉")
	}
	if cfg.ClientIP != "10.9.0.3" {
		t.Errorf("应跳过网关取下一个,got %q", cfg.ClientIP)
	}
}

// TestAllocClientIP_HonoursTheExcludeSet exclude 是「本机自己的地址」那一类,分给客户端会撞车。
func TestAllocClientIP_HonoursTheExcludeSet(t *testing.T) {
	got, err := AllocClientIP("10.0.0.1/24", map[string]bool{"10.0.0.2": true},
		map[string]bool{"10.0.0.3": true, "10.0.0.4": true})
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientIP != "10.0.0.5" {
		t.Errorf("used 与 exclude 都要避开,got %q(期望 10.0.0.5)", got.ClientIP)
	}
}

// TestAllocClientIP_WarnsBeforeThePoolIsGone 容量告警。
//
// 池子满了才发现,意味着一批客户端已经登不进来。告警的意义是在「将爆未爆」时给运维留出扩容
// 或回收僵死 lease 的时间,所以它必须在**成功**分配的路径上打 —— 等到失败才说就晚了。
func TestAllocClientIP_WarnsBeforeThePoolIsGone(t *testing.T) {
	// /29 → 主机位 3 → 上界 6,占掉 5 个后下一次成功分配就跨过 90%。
	used := map[string]bool{}
	prefix := "10.0.0.1/29"
	var last string
	for {
		cfg, err := AllocClientIP(prefix, used, nil)
		if err != nil {
			break
		}
		last = cfg.ClientIP
		used[cfg.ClientIP] = true
	}
	if len(used) == 0 {
		t.Fatal("/29 应至少能分出几个地址")
	}
	// 这里不断言日志本身(logrus 全局),只钉住「快满时仍然照常分配、不提前拒绝」——
	// 告警是提示,不是闸门;提前拒绝会让还有余量的池子白白登不进人。
	if last == "" {
		t.Fatal("池子接近满时仍应正常分配")
	}
	addr := netip.MustParseAddr(last)
	if !netip.MustParsePrefix(prefix).Contains(addr) {
		t.Fatalf("最后分出的 %s 不在前缀内", last)
	}
}

// TestAllocClientIP_V4MappedGatewayReportsInsteadOfPanicking 网关写成 v4-mapped 形态。
//
// 这是一个真缺陷的回归:`::ffff:10.0.0.1/24` 能过 [tun].subnets 的校验(地址解析出来是 v4),
// 而分配器里 gatewayAddr 做了 Unmap、networkAddr 没做 —— 于是走 v4 分支却对 16 字节形态的
// 地址调 As4(),**直接 panic**。发作时机是第一个客户端登录,不是启动,所以配置检查也看不出来。
//
// 修法两侧:分配器把 networkAddr 一并 Unmap(报错好过崩),配置校验直接拒掉这种写法
// (见 config.ValidateTUNSubnets —— 真正该拦的地方)。
func TestAllocClientIP_V4MappedGatewayReportsInsteadOfPanicking(t *testing.T) {
	// 不许 panic:这行本身就是断言。
	cfg, err := AllocClientIP("::ffff:10.0.0.1/24", map[string]bool{}, nil)
	if err == nil {
		// 万一将来改成能分:分出来的必须是 v4、且不是网关。
		addr, perr := netip.ParseAddr(cfg.ClientIP)
		if perr != nil || !addr.Unmap().Is4() {
			t.Fatalf("若要支持这种写法,分出的必须是 v4 地址,got %q", cfg.ClientIP)
		}
		if cfg.ClientIP == cfg.Gateway {
			t.Error("不该把网关分给客户端")
		}
		return
	}
	if !strings.Contains(err.Error(), "地址族不一致") {
		t.Errorf("应明确报族不一致,而不是含糊的池满 / 崩溃,got %v", err)
	}
}

// TestLogrusWarnPoolFull_DoesNotPanicOnZeroTotal 告警函数自己不许炸。
// total=0 时算百分比会得到 Inf/NaN;它跑在分配成功的热路径上,panic 等于一次登录带走整进程。
func TestLogrusWarnPoolFull_DoesNotPanicOnZeroTotal(t *testing.T) {
	logrusWarnPoolFull("10.0.0.1/24", 5, 0)
	logrusWarnPoolFull("", 0, 0)
}

// mustAllocN 连续分配 n 个地址,返回它们(便于其它用例复用)。
func mustAllocN(t *testing.T, cidr string, n int) []string {
	t.Helper()
	used := map[string]bool{}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		cfg, err := AllocClientIP(cidr, used, nil)
		if err != nil {
			t.Fatalf("第 %d 次分配失败: %v", i+1, err)
		}
		used[cfg.ClientIP] = true
		out = append(out, cfg.ClientIP)
	}
	return out
}

// TestAllocClientIP_CrossesByteBoundaries /16 上分到第 300 个,要正确进位到第三字节。
// 算术写错(只加最后一个字节)会在第 254 个之后开始重复发地址 —— 两台设备同一个 vIP。
func TestAllocClientIP_CrossesByteBoundaries(t *testing.T) {
	got := mustAllocN(t, "10.7.0.1/16", 300)
	seen := map[string]bool{}
	for _, ip := range got {
		if seen[ip] {
			t.Fatalf("地址 %s 被分了两次 —— 跨字节进位算错了", ip)
		}
		seen[ip] = true
	}
	if want := "10.7.1.45"; got[299] != want {
		t.Errorf("第 300 个地址 = %s,期望 %s(从 network+2 起数,第 300 个是 network+301,应已进位到第三字节)", got[299], want)
	}
	if !strings.HasPrefix(got[254], "10.7.1.") {
		t.Errorf("第 255 个之后应进入 10.7.1.x,got %s", got[254])
	}
}
