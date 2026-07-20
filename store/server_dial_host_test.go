package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateServerDialHost_Accept(t *testing.T) {
	cases := []string{
		"", // 空 = 清除,合法
		// 公网 / 普通 IP — 不在特殊段。
		"203.0.113.10", // IPv4 普通公网
		"8.8.8.8",      // Google DNS
		"1.1.1.1",      // Cloudflare DNS
		// RFC 1918 私网 — 自托管 / 内网部署是合法场景,语法层放行。
		// admin 可在 web 端通过 ProbeServerDialHost 自检实际可达性。
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"vpn.example.com", // 合法 hostname,末段 com 含字母
		"a.b.example.org",
		"example.com",
		"localhost",                 // 单 label 含字母 OK(语法层不解析,Probe 阶段才会发现)
		"2001:db8::1",               // IPv6 doc 段不带括号
		"[2001:db8::1]",             // IPv6 doc 段带括号
		"vpn-prod-jp-1.example.com", // label 含 -,首尾非 -
		"01.example.com",            // label 首字符数字 OK,末段含字母
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if err := ValidateServerDialHost(c); err != nil {
				t.Errorf("应接受 %q, 但被拒: %v", c, err)
			}
		})
	}
}

func TestValidateServerDialHost_Reject(t *testing.T) {
	cases := []struct {
		input  string
		reason string // 期待错误信息片段(子串匹配)
	}{
		// 本轮核心案例:用户实际配的伪 hostname,末段 .158 纯数字 TLD。
		{"test-203.0.113.10", "末段"},
		// 末段纯数字 TLD 的更多变体。
		{"foo.123", "末段"},
		{"prod-jp-1.5.6.7", "末段"},
		// scheme / path / port / control char
		{"https://vpn.example.com", "scheme"},
		{"http://1.2.3.4", "scheme"},
		{"vpn.example.com/path", "path"},
		{"vpn.example.com?q=1", "path"},
		{"vpn.example.com:8080", "端口"},
		{"[::1]:443", "端口"},
		{"bad\nhost", "控制字符"},
		// label 首尾 -
		{"-leading-dash.com", "首尾不能为 '-'"},
		{"trailing-.com", "首尾不能为 '-'"},
		// 空 label / 连续点
		{"foo..bar", "label 1 为空"},
		{".leading.dot", "label 0 为空"},
		// 长度
		{strings.Repeat("a", 254), "长度"},
		// 非法字符(中文)
		{"测试.example.com", "非法字符"},
		// 单 label 全数字(不是合法 IPv4 也不是合法 hostname)
		{"12345", "末段"},
		// 特殊 IP 黑名单(2026-05-26 第七轮加):语法合法但客户端不可拨号。
		// 这条防线在 ping 探活之前 — 127.0.0.1 在 server 机器上 ping 必然通,
		// 让客户端拿到也连不上自己 loopback。
		{"0.0.0.0", "unspecified"},
		{"::", "unspecified"},
		{"127.0.0.1", "loopback"},
		{"127.1.2.3", "loopback"},
		{"::1", "loopback"},
		{"169.254.169.254", "link-local"}, // AWS metadata 服务地址,典型踩点
		{"169.254.1.1", "link-local"},
		{"fe80::1", "link-local"},
		{"[fe80::1234]", "link-local"},
		{"224.0.0.1", "multicast"},
		{"239.255.255.255", "multicast"},
		{"ff02::1", "multicast"},
		{"255.255.255.255", "broadcast"},
		// IPv4-mapped IPv6 形态走 net.IP.To4 把它当 IPv4 看,落到对应黑名单上。
		{"[::ffff:127.0.0.1]", "loopback"},
		{"[::ffff:0.0.0.0]", "unspecified"},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			err := ValidateServerDialHost(c.input)
			if err == nil {
				t.Fatalf("应拒 %q,但通过", c.input)
			}
			if !strings.Contains(err.Error(), c.reason) {
				t.Errorf("错误信息应含 %q,实际: %v", c.reason, err)
			}
		})
	}
}

// TestParseLiteralIP: 2026-05-27 第十三轮抽出的跨包 helper 的回归锁。
//
// 关键不变量(server_dial_host 单一来源):
//   - 裸 IPv4 / 裸 IPv6 / **方括号 IPv6** 三种 literal 都返回 IP + true;
//   - 域名 / 空串 / scheme / 含路径噪声 → nil + false;
//   - 与 ValidateServerDialHost / ProbeServerDialHost 内部判定行为完全一致
//     (第十三轮之前 web handler 直接 ParseIP 不剥 `[]` → `[2001:db8::1]` 错判
//     为非 literal → audit/verb 漂移)。
func TestParseLiteralIP(t *testing.T) {
	type tc struct {
		input string
		ok    bool
	}
	cases := []tc{
		// literal IPv4
		{"203.0.113.10", true},
		{"203.0.113.42", true},
		// 裸 IPv6
		{"2001:db8::1", true},
		{"::1", true},
		// 方括号 IPv6(handler 用户输入实际形态)
		{"[2001:db8::1]", true},
		{"[::1]", true},
		// 域名 / 看似 IP 实非 IP
		{"vpn.example.com", false},
		{"test-203.0.113.10", false}, // 末段纯数字伪 hostname,语法非 IP
		{"localhost", false},
		// 噪声 / 空
		{"", false},
		{"   ", false},
		{"203.0.113.10:8080", false}, // 含端口
		{"http://1.2.3.4", false},    // 含 scheme
		{"[2001:db8::1", false},      // 不闭合方括号
		{"2001:db8::1]", false},      // 不开放方括号
		{"[not-an-ip]", false},       // 方括号包域名
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			ip, ok := ParseLiteralIP(c.input)
			if ok != c.ok {
				t.Errorf("ParseLiteralIP(%q) ok = %v, want %v(ip=%v)", c.input, ok, c.ok, ip)
			}
			if ok && ip == nil {
				t.Errorf("ParseLiteralIP(%q) 返回 ok=true 但 ip=nil", c.input)
			}
		})
	}
}

func TestServerDialHostRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "dial_host_test.db")
	st, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// 默认空
	v, err := st.GetServerDialHost(ctx)
	if err != nil || v != "" {
		t.Fatalf("expect empty default, got %q err=%v", v, err)
	}

	// set + read back(SetServerDialHost 内部 TrimSpace)
	if err := st.SetServerDialHost(ctx, "  203.0.113.10  "); err != nil {
		t.Fatal(err)
	}
	v, err = st.GetServerDialHost(ctx)
	if err != nil || v != "203.0.113.10" {
		t.Fatalf("expect trimmed IP, got %q err=%v", v, err)
	}

	// 清除
	if err := st.SetServerDialHost(ctx, ""); err != nil {
		t.Fatal(err)
	}
	v, _ = st.GetServerDialHost(ctx)
	if v != "" {
		t.Fatalf("expect empty after clear, got %q", v)
	}
}

// TestProbeServerDialHost_EmptyPass: 空串视为"清除",可达性无意义,直接通过。
func TestProbeServerDialHost_EmptyPass(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ProbeServerDialHost(ctx, ""); err != nil {
		t.Errorf("空串应通过,实际拒: %v", err)
	}
	if err := ProbeServerDialHost(ctx, "   "); err != nil {
		t.Errorf("纯空白应通过,实际拒: %v", err)
	}
}

// TestProbeServerDialHost_DNSFail: 不可解析的域名应硬错(ErrServerDialHostDNS)。
//
// 使用 RFC 2606 保留的 .invalid TLD —— 任何符合 standards 的 resolver 都不会解析,
// 不会触碰真实 DNS server,测试在离线 / sandbox 环境也稳定可重复。
func TestProbeServerDialHost_DNSFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := ProbeServerDialHost(ctx, "this-host-definitely-does-not-exist.invalid")
	if err == nil {
		t.Fatal("应拒不可解析域名,但通过")
	}
	if !errors.Is(err, ErrServerDialHostDNS) {
		t.Errorf("应是 ErrServerDialHostDNS,实际: %v", err)
	}
}

// TestProbeServerDialHost_LiteralIPSkipsDNS: 字面 IP 不走 DNS,直接进 ping 阶段。
//
// 用 192.0.2.x(RFC 5737 TEST-NET-1,公网 unroutable),DNS 跳过 ✓,ping
// 必然 0 回包(因为这个段保留为文档示例,真实路由表里走 blackhole)。
// 期待返回 ErrServerDialHostICMPSoftFail —— 这就是软错的语义:
// **DNS 无法解析**(本例: 字面 IP 不走 DNS)和**地址不可达**(本例: 文档示例段)
// 是两种语义,前者一定是错,后者可能只是 firewall。
//
// 注意:CI / 沙箱环境如果连 unprivileged UDP socket 都开不了,
// 我们也接受 wrap 了 ErrServerDialHostICMPSoftFail 的初始化失败 —— 同样归类为
// "ICMP 软失败",admin 端表现一致。
func TestProbeServerDialHost_LiteralIPSkipsDNS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := ProbeServerDialHost(ctx, "192.0.2.1")
	if err == nil {
		t.Skip("192.0.2.1 居然 ping 通了?跳过(可能在特殊网络环境),不视为失败")
	}
	if errors.Is(err, ErrServerDialHostDNS) {
		t.Errorf("字面 IP 不应走 DNS path,实际错: %v", err)
	}
	if !errors.Is(err, ErrServerDialHostICMPSoftFail) {
		t.Errorf("文档示例段 ping 不通,应是 ICMPSoftFail,实际: %v", err)
	}
}

// TestProbeServerDialHost_ContextCancel: ctx 取消后立即返回,不留挂起 goroutine。
//
// 这是个保护栏:web handler 客户端断开 / 整个进程关停时,probe 不应继续跑完
// 3 秒的 ICMP timeout。验证 ctx.Done() 优先于 ping 完成。
func TestProbeServerDialHost_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ProbeServerDialHost(ctx, "192.0.2.1")
	if err == nil {
		t.Fatal("ctx 已 cancel,应返回 ctx.Err(),不是 nil")
	}

	if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrServerDialHostICMPSoftFail) {
		t.Errorf("应是 context.Canceled 或 ICMPSoftFail(若 ping 极快完成在 cancel 之前),实际: %v", err)
	}
}

// TestProbeServerDialHost_LongLabelStillProbes: ValidateServerDialHost 已拒
// 长度 > 253 的字符串,所以 Probe 不会被传入这种 case;但万一上游漏校,
// Probe 仍应优雅返回(DNS resolve 失败 → 硬错),不 panic。
func TestProbeServerDialHost_LongLabelGraceful(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	long := strings.Repeat("a", 100) + ".invalid"
	err := ProbeServerDialHost(ctx, long)
	if err == nil {
		t.Fatal("超长 .invalid 域名应拒(DNS 无法解析)")
	}
	if !errors.Is(err, ErrServerDialHostDNS) {
		t.Errorf("应是 ErrServerDialHostDNS,实际: %v", err)
	}
}

// TestProbeServerDialHost_DomainResolvesToLoopback: 域名 resolve 到 loopback 也拒。
//
// 2026-05-26 第八轮扫描修:防 DNS 中毒 / 私网 DNS 把域名解到 127.0.0.1 / ::1
// 这类客户端不可拨号的特殊段。如果不查,probe ping 通本机 → 看起来合法 → 落库,
// 客户端连自己 loopback 必失败。
//
// 测试 case 完美利用 stdlib + /etc/hosts:`localhost` 在所有 Unix/macOS 都映射
// 到 127.0.0.1 / ::1(全是 loopback 黑名单段),验证 LookupIPAddr 之后的二次
// 黑名单 check 真的生效。
func TestProbeServerDialHost_DomainResolvesToLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := ProbeServerDialHost(ctx, "localhost")
	if err == nil {
		t.Fatal("localhost 应被拒(/etc/hosts 解到 127.0.0.1 / ::1,落 loopback 黑名单)")
	}
	if !errors.Is(err, ErrServerDialHostDNS) {
		t.Errorf("应是 ErrServerDialHostDNS(DNS 结果不可用归类),实际: %v", err)
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("错误消息应含 'loopback' 关键词以引导 admin,实际: %v", err)
	}
}
