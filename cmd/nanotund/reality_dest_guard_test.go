package main

// reality_dest_guard_test.go —— REALITY 的 dest 够不够得着,得有人查一次。
//
// REALITY 的每一条入站连接,进门第一件事就是 dial dest(third_party/xtls-reality/tls.go
// 的 Server():`target, err := config.DialContext(ctx, config.Type, config.Dest)`,dial 不通
// 就 conn.Close() 直接返回)—— 这发生在任何客户端认证**之前**。所以 dest 不可达时,
// 所有客户端都连不上,合法的也一样。
//
// 而现场看不出任何异常:端口在听(装机的状态自检照样打「✓ 监听中:8443/tcp(REALITY)」)、
// 进程健康、配置没错。那句 "failed to dial dest" 是每连接错误,不进日志 —— 实测把出站到
// www.microsoft.com:443 阻断之后,openssl 握手拿到的是 "no peer certificate available",
// 而 journalctl 里一个字都没有。更糊的是 hy2(443/udp)不依赖 dest、照常能用,于是症状
// 变成「有的客户端能连、有的连不上」,取决于它挑了哪条传输。
//
// 触发场景都很实在:出站只放行少数目的地的机器、被上游 IP 段封的机房、dest 站点抽风。
// 修不了运行时那条不打日志的决定(每连接错误打日志会被扫描器刷爆),但可以让人有办法查:
// 环境自检主动探一次 —— 装之前探模板的默认值,装之后探 config.toml 里的实际值。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreflight_ChecksRealityDestReachable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../..", "scripts/preflight.sh"))
	if err != nil {
		t.Fatalf("读 preflight.sh: %v", err)
	}
	body := string(raw)

	if !strings.Contains(body, "REALITY dest 连不上") {
		t.Fatal("环境自检没有探 REALITY 的 dest —— " +
			"它不可达时所有客户端都连不上,而端口照样在听、日志里一个字都没有,没有别的地方能发现这件事")
	}
	// 装之后要读实际配置(dest 是可以改的),装之前也得探一次 —— 装完才发现连不上就晚了。
	if !strings.Contains(body, `sec == "[reality]"`) {
		t.Error("没有段感知地读 [reality] 的 dest —— 顶层或别的段里也可能有同名键,读错了等于探了个别的地址")
	}
	if !strings.Contains(body, "装机模板的默认值") {
		t.Error("机器还没装时没有回落到模板默认值 —— " +
			"这正是最该提前发现的时机:装之前就知道这台机器够不着 dest")
	}
	// 报错要说清「为什么所有客户端都连不上」和「怎么改」,否则人只会以为是网络抖动。
	for _, c := range []struct{ needle, why string }{
		{"在认证之前关掉", "得说清这发生在认证之前 —— 否则人会以为只影响没认证的探测流量"},
		{"端口照样在听", "得点破「看起来一切正常」这件事,不然人不会怀疑到这儿"},
		{"server_names", "改 dest 就得同时改 server_names,只说一个会改出个更难查的状态"},
	} {
		if !strings.Contains(body, c.needle) {
			t.Errorf("dest 检查的提示里没有 %q —— %s", c.needle, c.why)
		}
	}
}
