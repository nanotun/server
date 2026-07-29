package main

import (
	"slices"
	"testing"

	"github.com/nanotun/server/config"
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
			name: "exit_dns_redirect 大小写不敏感",
			mut: func(o, n *config.Config) {
				o.TUN.ExitDNSRedirect = "off"
				n.TUN.ExitDNSRedirect = "OFF"
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
