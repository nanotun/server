package main

// cmd_setting_test.go(2026-05-26·server_id 链路第五轮 P2-1):
// `setting set` 拒绝 system-managed key 的回归保护。
//
// 现状:运维若误打 `setting set server_id ""`,SettingsSet 会成功落空串 →
// 客户端去重 / 自动覆盖语义破灭(下次扫码视为新 server,产生"重影")。
// 改造后入口加一道 systemManagedSettingKeys map 守门,拒掉就报错 + hint。
//
// 单测覆盖:
//   - server_id / schema_version 必须被拒;
//   - 拒错信息必须含 hint(让运维知道为什么 + 该走哪条路径);
//   - 普通业务 key(如 setup_completed)继续允许 → 不能"误伤"。

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSettingSet_RejectsSystemManagedKeys(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "guard.db")
	// runCLI 内 runWithStore 会 Open + Migrate,无需先 init。

	for _, tc := range []struct {
		key      string
		hintWord string // 拒错信息必含的关键词
	}{
		{"server_id", "永久指纹"},
		{"schema_version", "Migrate"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			c, _, stderr := runCLI(t, db, "", "setting", "set", tc.key, "anything")
			if c == 0 {
				t.Fatalf("setting set %q 应被拒,但通过了", tc.key)
			}
			if !strings.Contains(stderr, "拒绝写入") {
				t.Errorf("error 应含 \"拒绝写入\";got: %s", stderr)
			}
			if !strings.Contains(stderr, tc.hintWord) {
				t.Errorf("error 应含 hint 关键词 %q;got: %s", tc.hintWord, stderr)
			}
		})
	}
}

// TestSettingSet_AllowsNormalKeys:守门不能误伤普通 app_settings key。
//
// 选 setup_completed 做样本:它是 init 后就存在的标准 key,且没有特殊语义守
// 护(rate / advertised_host 各自有专用 CLI / 校验,不在 setting set 路径)。
func TestSettingSet_AllowsNormalKeys(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "ok.db")

	c, stdout, stderr := runCLI(t, db, "", "setting", "set", "setup_completed", "1")
	if c != 0 {
		t.Fatalf("setting set setup_completed 应允许;code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stdout, "已写入") {
		t.Errorf("成功路径应输出 \"已写入\" 提示;got stdout: %s", stdout)
	}

	// 验证真的写进去了。
	c, stdout, _ = runCLI(t, db, "", "setting", "get", "setup_completed")
	if c != 0 {
		t.Fatalf("get setup_completed: code=%d", c)
	}
	if strings.TrimSpace(stdout) != "1" {
		t.Errorf("get setup_completed 应返回 1;got %q", stdout)
	}
}

// TestSettingSet_ValidatedKey_AdvertisedHost_RejectsInvalid:2026-05-26·server_id 链路
// 第五轮 P2 follow-up — `setting set` 对 validatedSettingKeys 里的 key(目前是
// `advertised_host`)先过 store.ValidateAdvertisedHost,非法值拒掉且**不落库**。
//
// 历史问题:Web 端 POST /settings/advertised-host 有 ValidateAdvertisedHost 守门,但 CLI
// raw `setting set advertised_host "..."` 绕过校验 → ops 误打非法值能直接落库,后续
// server-QR / 公网 host 解析撞下游 fail。Fix 后两条入口校验对齐。
//
// 2026-05-26 改名:public_host → advertised_host(migration 0015),test 同步重命名,
// 语义不变。
//
// 覆盖几类典型非法 host 形态(与 web 端 TestSettingsAdvertisedHostSet_Invalid 同款):
//   - 带 scheme
//   - 带端口
//   - 带 path
//   - 换行注入
//
// 关键不变量:任何一类非法值都不能落到 app_settings.advertised_host(防御性 read-back)。
func TestSettingSet_ValidatedKey_AdvertisedHost_RejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "validated.db")

	cases := []struct {
		name string
		host string
	}{
		{"scheme http", "http://vpn.example.com"},
		{"with port", "vpn.example.com:8080"},
		{"has path", "vpn.example.com/x"},
		{"newline injection", "vpn.example.com\nINJECT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, stderr := runCLI(t, db, "", "setting", "set", "advertised_host", tc.host)
			if c == 0 {
				t.Fatalf("非法 host %q 应被拒,但通过了", tc.host)
			}
			if !strings.Contains(stderr, "校验失败") {
				t.Errorf("拒错信息应含 \"校验失败\";got: %s", stderr)
			}
			// 落地确认:不应有任何值。
			c, stdout, _ := runCLI(t, db, "", "setting", "get", "advertised_host")
			if c == 0 {
				// advertised_host 还没设置过应返回 not found(非零退出),意外通过说明值落库了。
				t.Errorf("非法 host 后 advertised_host 竟然能 get 到 %q,说明 raw 落库了", stdout)
			}
		})
	}
}

// TestSettingSet_ValidatedKey_AdvertisedHost_AcceptsValid:合法值正常落库 — 不能"误伤"。
func TestSettingSet_ValidatedKey_AdvertisedHost_AcceptsValid(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "valid.db")

	c, stdout, stderr := runCLI(t, db, "", "setting", "set", "advertised_host", "203.0.113.10")
	if c != 0 {
		t.Fatalf("合法 IPv4 应通过;code=%d stderr=%s", c, stderr)
	}
	if !strings.Contains(stdout, "已写入") {
		t.Errorf("成功 stdout 应含 \"已写入\";got: %s", stdout)
	}

	c, stdout, _ = runCLI(t, db, "", "setting", "get", "advertised_host")
	if c != 0 {
		t.Fatalf("get advertised_host: code=%d", c)
	}
	if strings.TrimSpace(stdout) != "203.0.113.10" {
		t.Errorf("get 应返回 203.0.113.10;got %q", stdout)
	}

	// 再写一次域名形式,确保 validator 不只接 IP。
	c, _, stderr = runCLI(t, db, "", "setting", "set", "advertised_host", "vpn.example.com")
	if c != 0 {
		t.Fatalf("合法域名应通过;stderr=%s", stderr)
	}
}

// TestSettingSet_ValidatedKey_ServerDialHost_RejectsInvalid:2026-05-26 第六轮拆字段。
//
// `server_dial_host` 是 client PacketTunnel 实际拨号目标,strict IPv4/IPv6/RFC1035
// hostname 校验。CLI raw `setting set server_dial_host ...` 必须走 validator —— 否则
// ops 误打 `test-203.0.113.10`(末段纯数字,DNS 不可解析)能直接落库,生成的 server-QR
// 客户端导入后会触发 `Invalid NETunnelNetworkSettings tunnelRemoteAddress` 隧道挂掉。
func TestSettingSet_ValidatedKey_ServerDialHost_RejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "dialhost_validated.db")

	cases := []struct {
		name string
		host string
	}{
		// 核心案例:用户实际配的伪 hostname,末段 .158 是纯数字 TLD,DNS 不可解析。
		{"末段纯数字 TLD (用户实际踩坑)", "test-203.0.113.10"},
		// 类似末段纯数字的变体。
		{"末段纯数字 1.2.3.4 风格但非 IPv4", "foo.5.6.7"},
		// scheme / path / port:沿用 advertised_host 同款拒绝集合。
		{"带 scheme", "https://vpn.example.com"},
		{"带 port", "vpn.example.com:8080"},
		{"带 path", "vpn.example.com/x"},
		// label 字符不合法(中文 hostname 不是合法 RFC1035)。
		{"中文 hostname", "测试.example.com"},
		// 2026-05-26 第七轮加特殊 IP 黑名单(rejectedSpecialIP):语法合法但客户端
		// 不可对外拨号。这条防线在 ping 探活前 — 比如 127.0.0.1 在 server 机器
		// 上 ping 必然通,落库后客户端拿到这个值连自己 loopback 必失败。
		{"loopback IPv4 (127.0.0.1)", "127.0.0.1"},
		{"loopback IPv6 (::1)", "::1"},
		{"unspecified (0.0.0.0)", "0.0.0.0"},
		{"link-local IPv4 (AWS metadata 169.254.169.254)", "169.254.169.254"},
		{"multicast (239.0.0.1)", "239.0.0.1"},
		{"broadcast (255.255.255.255)", "255.255.255.255"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, stderr := runCLI(t, db, "", "setting", "set", "server_dial_host", tc.host)
			if c == 0 {
				t.Fatalf("非法 dial host %q 应被拒,但通过了", tc.host)
			}
			if !strings.Contains(stderr, "校验失败") {
				t.Errorf("拒错信息应含 \"校验失败\";got: %s", stderr)
			}
			c, stdout, _ := runCLI(t, db, "", "setting", "get", "server_dial_host")
			if c == 0 {
				t.Errorf("非法 dial host 后 server_dial_host 竟能 get 到 %q,说明 raw 落库了", stdout)
			}
		})
	}
}

// TestSettingSet_ValidatedKey_ServerDialHost_AcceptsValid:合法 dial host 正常落库。
//
// 2026-05-26 第七轮加特殊 IP 黑名单后,127.0.0.1 / ::1(loopback)、0.0.0.0(unspecified)、
// 169.254.x(link-local)、224.0.0.0/4 / ff00::/8(multicast)、255.255.255.255(broadcast)
// 这些"语法合法但客户端拨号必定失败"的 IP 段全部走 reject 路径(见
// TestSettingSet_ValidatedKey_ServerDialHost_RejectsInvalid),不再 accept。
// 这里只列**真正公网可路由**的 IPv4 / IPv6 + RFC1918 私网(自托管场景合法)。
func TestSettingSet_ValidatedKey_ServerDialHost_AcceptsValid(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "dialhost_valid.db")

	for _, val := range []string{
		"203.0.113.10",    // 公网 IPv4
		"8.8.8.8",         // Google DNS
		"vpn.example.com", // 合法 RFC1035 域名
		"[2001:db8::1]",   // IPv6 doc 段(不在特殊黑名单)
		"192.168.1.100",   // RFC1918 私网(自托管场景合法)
		"10.0.0.5",        // RFC1918 私网
	} {
		c, _, stderr := runCLI(t, db, "", "setting", "set", "server_dial_host", val)
		if c != 0 {
			t.Fatalf("合法 dial host %q 应通过;stderr=%s", val, stderr)
		}
	}
}

// TestSettingProbeDialHost_SyntaxErrorRejected(2026-05-27 第十五轮 backlog#3):
// `setting probe-dial-host` 在跑 DNS/ICMP 之前先做语法校验,拼写错应直接退出且不
// 触网。回归点:运维误打 `setting probe-dial-host http://x.com` 不应卡在 DNS
// 阶段(网络环境差时可能 ≥ 3s),应**立即**抛 syntax error。
func TestSettingProbeDialHost_SyntaxErrorRejected(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "probe_syntax.db")
	for _, bad := range []string{
		"http://vpn.example.com", // 含 scheme
		"vpn.example.com:8080",   // 含 port
		"vpn..example.com",       // 双点(RFC1035 不允许)
		"127.0.0.1",              // loopback(rejectedSpecialIP)
		"0.0.0.0",                // unspecified
		"169.254.10.5",           // link-local
	} {
		c, stdout, stderr := runCLI(t, db, "", "setting", "probe-dial-host", bad)
		if c == 0 {
			t.Errorf("非法 host %q 应被拒;stdout=%s", bad, stdout)
		}
		if !strings.Contains(stdout, "✗ 语法校验失败") {
			t.Errorf("应输出语法失败前缀;bad=%q stdout=%s stderr=%s", bad, stdout, stderr)
		}
	}
}

// TestSettingProbeDialHost_LiteralIP_SkipICMP:字面 IP + --skip-icmp = 跳过 DNS
// + 跳过 ICMP,纯语法校验过即成功。这条路径不触网,稳定可测。
func TestSettingProbeDialHost_LiteralIP_SkipICMP(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "probe_literal_skip.db")
	c, stdout, stderr := runCLI(t, db, "", "setting", "probe-dial-host",
		"203.0.113.10", "--skip-icmp")
	if c != 0 {
		t.Fatalf("字面 IP + --skip-icmp 应通过;stderr=%s stdout=%s", stderr, stdout)
	}
	if !strings.Contains(stdout, "字面 IP") {
		t.Errorf("应明示「字面 IP」语义;stdout=%s", stdout)
	}
}

// TestSettingProbeDialHost_Usage:无参 / 多参的 usage 提示。
func TestSettingProbeDialHost_Usage(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "probe_usage.db")
	c, _, stderr := runCLI(t, db, "", "setting", "probe-dial-host")
	if c == 0 {
		t.Fatal("无参应失败")
	}
	// runCLI 固定 --lang zh:usage 前缀翻成「用法: 」,命令语法部分保持不变。
	if !strings.Contains(stderr, "nanotun-admin setting probe-dial-host") {
		t.Errorf("应输出 usage;stderr=%s", stderr)
	}
}

// TestSettingProbeDialHost_SkipICMP_RejectsDNSToLoopback(2026-05-27 第十六轮 P1):
// `--skip-icmp` 路径 DNS 解析返回特殊段 IP(如 loopback)必须拒。
//
// **回归点**:第十五轮新加 --skip-icmp 路径直接调 net.DefaultResolver 但漏跑
// rejectedSpecialIP 黑名单 → 运维如果遇到 DNS 投毒(把 vpn.example.com 解到
// 127.0.0.1)→ CLI 假阳性 ✓ 通过 → 误 setting set → server QR 给客户端的
// dial host 是 loopback → 客户端连不上自己 loopback。
//
// 用 `localhost` 做样本:OS resolver 在所有平台都把它解到 127.0.0.1 / ::1,
// 不需要 mock DNS,稳定可测。
func TestSettingProbeDialHost_SkipICMP_RejectsDNSToLoopback(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "probe_skip_loopback.db")
	// `localhost` 语法合法(末段 RFC1035 含字母,不是 IP 字面量,
	// 不走 rejectedSpecialIP 的字面量路径),但 DNS 必解到 127.0.0.1/::1。
	c, stdout, _ := runCLI(t, db, "", "setting", "probe-dial-host",
		"localhost", "--skip-icmp")
	if c == 0 {
		t.Fatalf("localhost --skip-icmp 应被 DNS 解析后黑名单拒;stdout=%s", stdout)
	}
	if !strings.Contains(stdout, "DNS 解析到特殊段 IP") {
		t.Errorf("应输出黑名单拒绝前缀;stdout=%s", stdout)
	}
}
