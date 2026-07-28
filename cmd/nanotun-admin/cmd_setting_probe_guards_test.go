package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// probe-dial-host 的价值全在**结果分类**上:运维照着它的结论决定要不要
// `setting set server_dial_host`。分类错一次就是「验证通过了、客户端连不上」。
//
// 这里把 DNS 与 ICMP 两个外部依赖换成假实现(见 cmd_setting.go 的 probeLookupIPAddr /
// probeDialHost)。真去查网络会让用例随宿主网络红绿漂移,而要验的分支与网络无关。

// runProbe 直接调 cmdSettingProbeDialHost —— 顶层 main.go 会在打开 DB 之前把
// probe-dial-host 短路掉(它零 DB 依赖),这里同口径,不摆一个用不上的库。
func runProbe(t *testing.T, args ...string) (error, string) {
	t.Helper()
	stdout := &bytes.Buffer{}
	opts := &globalOpts{lang: langZH, stdout: stdout, stderr: &bytes.Buffer{}}
	err := cmdSettingProbeDialHost(t.Context(), opts, args)
	return err, stdout.String()
}

func stubLookup(t *testing.T, fn func(ctx context.Context, host string) ([]net.IPAddr, error)) {
	t.Helper()
	orig := probeLookupIPAddr
	probeLookupIPAddr = fn
	t.Cleanup(func() { probeLookupIPAddr = orig })
}

func stubProbe(t *testing.T, fn func(ctx context.Context, host string) error) {
	t.Helper()
	orig := probeDialHost
	probeDialHost = fn
	t.Cleanup(func() { probeDialHost = orig })
}

func TestCmdSettingProbeDialHost_SkipICMPClassifiesDNSResults(t *testing.T) {
	t.Run("解析成功要列出解到的 IP", func(t *testing.T) {
		// 列出 IP 是这条命令的主要产出:运维靠它确认域名指向的是自己那台机器,
		// 而不是某个还没换 DNS 的旧 IP。
		stubLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("203.0.113.10")},
				{IP: net.ParseIP("2001:db8::10")},
			}, nil
		})
		err, stdout := runProbe(t, "vpn.example.com", "--skip-icmp")
		if err != nil {
			t.Fatalf("解析成功却报错: %v (%q)", err, stdout)
		}
		for _, want := range []string{"203.0.113.10", "2001:db8::10"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("没列出解到的 %s: %q", want, stdout)
			}
		}
	})

	t.Run("解析成功但零条记录要当失败", func(t *testing.T) {
		// resolver 返回空列表(某些 CDN / split-horizon DNS 的表现)时若报通过,
		// 运维会照着去 set,server 起来才发现连不上。
		stubLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
			return nil, nil
		})
		err, stdout := runProbe(t, "vpn.example.com", "--skip-icmp")
		if err == nil {
			t.Fatalf("零记录却报通过: %q", stdout)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("失败了却什么都不说")
		}
	})

	t.Run("DNS 报错时原因要透出来", func(t *testing.T) {
		stubLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
			return nil, errors.New("SERVFAIL from 10.0.0.1")
		})
		err, stdout := runProbe(t, "vpn.example.com", "--skip-icmp")
		if err == nil {
			t.Fatal("DNS 失败却报通过")
		}
		// resolver 的原始错误(SERVFAIL / timeout / NXDOMAIN)决定运维下一步查什么,
		// 吞掉它只剩一句「DNS 失败」等于让人重新自己 dig。
		if !strings.Contains(stdout, "SERVFAIL") {
			t.Errorf("DNS 原始错误被吞了: %q", stdout)
		}
	})

	t.Run("解到不可拨的特殊地址要拒", func(t *testing.T) {
		// --skip-icmp 只跳过 ICMP,不跳过地址黑名单:DNS 投毒或内网 resolver 把域名
		// 解到 127.0.0.1 时若报通过,运维会把一个「客户端永远连不上自己」的 host 设上去。
		for _, ip := range []string{
			"127.0.0.1",       // 客户端拨到自己
			"::1",             //
			"0.0.0.0",         // 任意接口,不是端点
			"169.254.1.1",     // 只在本网段可达
			"224.0.0.1",       // 组播,TCP 拨不了
			"255.255.255.255", // 广播
		} {
			stubLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(ip)}}, nil
			})
			err, stdout := runProbe(t, "vpn.example.com", "--skip-icmp")
			if err == nil {
				t.Errorf("解到 %s 却报通过: %q", ip, stdout)
			}
		}
	})

	t.Run("解到私网地址是放行的", func(t *testing.T) {
		// RFC1918 不在黑名单里,这是**有意**的:自建/局域网部署的 server 就在
		// 10.x / 192.168.x 上,拒掉会让这类部署没法用域名。
		stubLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.5")}}, nil
		})
		if err, stdout := runProbe(t, "vpn.lan", "--skip-icmp"); err != nil {
			t.Fatalf("局域网部署的私网地址被拒了: %v (%q)", err, stdout)
		}
	})

	t.Run("字面 IP 不走 DNS", func(t *testing.T) {
		// 传字面 IP 时压根不该拨 resolver —— 拨了就是在没有 DNS 的机房里白等一个超时。
		called := false
		stubLookup(t, func(context.Context, string) ([]net.IPAddr, error) {
			called = true
			return nil, errors.New("resolver 不该被调用")
		})
		if err, stdout := runProbe(t, "203.0.113.10", "--skip-icmp"); err != nil {
			t.Fatalf("字面 IP 应直接通过: %v (%q)", err, stdout)
		}
		if called {
			t.Error("字面 IP 也去查了 DNS")
		}
	})
}

func TestCmdSettingProbeDialHost_FullProbeClassifiesFailures(t *testing.T) {
	t.Run("全通过", func(t *testing.T) {
		stubProbe(t, func(context.Context, string) error { return nil })
		err, stdout := runProbe(t, "vpn.example.com")
		if err != nil {
			t.Fatalf("探测通过却报错: %v", err)
		}
		if strings.TrimSpace(stdout) == "" {
			t.Error("通过了却什么都不说 —— 运维无从判断到底跑了没有")
		}
	})

	// 三类失败必须能从输出里区分开,因为处置完全不同:
	//   DNS 不通 → 去改 DNS 记录;
	//   ICMP 不通 → 大概率是安全组 ban 了 ICMP,可以照常 set(软失败);
	//   其它 → 真出问题了,得看原始错误。
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"DNS 失败", fmt.Errorf("lookup failed: %w", store.ErrServerDialHostDNS)},
		{"ICMP 软失败", fmt.Errorf("no reply: %w", store.ErrServerDialHostICMPSoftFail)},
		{"其它错误", errors.New("raw socket: operation not permitted")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubProbe(t, func(context.Context, string) error { return tc.err })
			err, stdout := runProbe(t, "vpn.example.com")
			if err == nil {
				t.Fatalf("%s 却报通过: %q", tc.name, stdout)
			}
			// 返回的必须是原始 error(而不是被换成一句自造的),调用方与脚本
			// 才能用 errors.Is 继续分类。
			if !errors.Is(err, tc.err) {
				t.Errorf("返回的 error 被换掉了: %v", err)
			}
			if strings.TrimSpace(stdout) == "" {
				t.Errorf("%s 时 stdout 空白", tc.name)
			}
		})
	}

	t.Run("--timeout 会传给探测", func(t *testing.T) {
		// 超时值不生效的话,默认 20s 会让 CI / 脚本里的批量校验拖很久。
		var gotDeadline bool
		stubProbe(t, func(ctx context.Context, _ string) error {
			_, gotDeadline = ctx.Deadline()
			return nil
		})
		if err, _ := runProbe(t, "vpn.example.com", "--timeout", "1s"); err != nil {
			t.Fatal(err)
		}
		if !gotDeadline {
			t.Error("探测拿到的 ctx 没有 deadline —— --timeout 没生效")
		}
	})
}

// cmdSetting 里也留了一条 probe-dial-host 分支(main.go 平时会在打开 DB 前把它短路掉)。
// 两条路必须同语义,否则「哪条路进来的」会决定校验严不严 —— 这种分叉最难查。
func TestCmdSetting_ProbeSubcommandMatchesTheShortCircuit(t *testing.T) {
	db := newInitializedDB(t, t.TempDir(), "set-probe-dispatch.db")
	stubProbe(t, func(context.Context, string) error { return nil })

	st := openStoreForTest(t, db)
	defer st.Close()
	stdout := &bytes.Buffer{}
	opts := &globalOpts{lang: langZH, stdout: stdout, stderr: &bytes.Buffer{}}
	if err := cmdSetting(t.Context(), st, opts, []string{"probe-dial-host", "vpn.example.com"}); err != nil {
		t.Fatalf("走 cmdSetting 派发时失败了: %v (%q)", err, stdout)
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Error("走这条路时什么都不打")
	}
}
