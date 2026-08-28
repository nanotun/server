package main

// cmd_profile_guards_test.go(第二十二轮)—— `profile show` 的拒绝面与派生边角。
//
// profile 是**客户端唯一的拨号说明书**:端口、REALITY 公钥、Hy2 密码、mTLS 证书全在里面。
// 它的失败模式有个共同特征 —— 全都**静默**:字段派生错了照样能出一份格式漂亮的 JSON /
// 二维码,运维扫码分发完,几天后才收到「连不上」的反馈,而那时已经无从判断是哪一环。
//
// 所以这里的断言几乎都不看错误文案,而看:该拒绝的有没有拒绝、该有的字段有没有,
// 以及**软降级的那几处有没有真的把警告说出来**(它们是唯一的现场线索)。

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/config"
)

// =========================================================================
// 测试用小工具
// =========================================================================

// brokenWriter 在前 okWrites 次写入之后一律报错,用来把 emit / write 那一层的
// 「写到一半失败」路径逼出来 —— 真实现场是 --output 落在满盘 / EIO 的挂载点上。
type brokenWriter struct {
	okWrites int
	n        int
}

func (w *brokenWriter) Write(p []byte) (int, error) {
	w.n++
	if w.n > w.okWrites {
		return 0, errors.New("盘写不进去了")
	}
	return len(p), nil
}

// newProfileOpts 造一份直接调用内部函数用的 opts(不经 runRoot)。
func newProfileOpts(stdout, stderr *strings.Builder) *globalOpts {
	return &globalOpts{lang: "zh", stdout: stdout, stderr: stderr, stdin: strings.NewReader("")}
}

// =========================================================================
// 用法与入参校验
// =========================================================================

func TestCmdProfile_UsageGuards(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	const goodHost = "203.0.113.10"

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"不给子命令", []string{"profile"}},
		{"未知子命令", []string{"profile", "revoke"}},
		{"未知 flag", []string{"profile", "show", "--bogus", "--dial-host", goodHost}},
		{"多余的位置参数", []string{"profile", "show", "alice", "bob", "--dial-host", goodHost}},
		{"一个 host 都不给", []string{"profile", "show"}},
		{"用户名是空白", []string{"profile", "show", "   ", "--dial-host", goodHost}},
		{"--format 不认识", []string{"profile", "show", "--dial-host", goodHost, "--format", "yaml"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := runCLI(t, db, "", append(tc.args, "--config", cfg)...)
			if code != 2 {
				t.Fatalf("code=%d, 期望 2(用法错误)", code)
			}
		})
	}
}

// dial host 是客户端 PacketTunnel 的 tunnelRemoteAddress:写成带端口 / 带 scheme /
// 带中文的东西,客户端起隧道时直接失败,而 profile 本身看着完全正常。
func TestCmdProfileShow_HostFieldsAreValidatedNotJustCopied(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "p.db")
	cfg := writeFixtureConfig(t, dir)

	t.Run("dial host", func(t *testing.T) {
		for _, bad := range []string{
			"203.0.113.10:443",     // 带端口:客户端会再拼一次端口
			"https://vpn.test",     // 带 scheme
			"vpn.example.com/path", // 带 path
			"服务器.测试",               // 非 RFC1035
			"-leading-dash.test",
		} {
			code, _, _ := runCLI(t, db, "", "profile", "show", "--config", cfg, "--dial-host", bad)
			if code != 2 {
				t.Errorf("--dial-host %q 被放过了(code=%d)—— 客户端隧道会直接起不来", bad, code)
			}
		}
	})

	// advertised host 只是 UI 上的展示名,校验故意放宽(中文可以),但仍不许带
	// scheme / path / 端口 —— 那些会让客户端把它当成可拨号地址。
	t.Run("advertised host", func(t *testing.T) {
		code, _, _ := runCLI(t, db, "", "profile", "show", "--config", cfg,
			"--dial-host", "203.0.113.10", "--advertised-host", "https://vpn.test/x")
		if code != 2 {
			t.Errorf("带 scheme 的 --advertised-host 被放过了(code=%d)", code)
		}
		code, stdout, stderr := runCLI(t, db, "", "profile", "show", "--config", cfg,
			"--dial-host", "203.0.113.10", "--advertised-host", "香港节点")
		if code != 0 {
			t.Fatalf("中文展示名被误拒: code=%d stderr=%s", code, stderr)
		}
		if p := parseProfileJSON(t, stdout); p.AdvertisedHost != "香港节点" {
			t.Errorf("advertised_host=%q, 期望「香港节点」", p.AdvertisedHost)
		}
	})
}

// 端口 flag 是 flag.Uint 再强转 uint16:越界值会**静默截断**(70000 → 4464、
// 65536 → 0 被当「未设」回退默认)。脚本因此发出错误端口且毫无提示。
func TestCmdProfileShow_OutOfRangePortsAreRejectedNotTruncated(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "p.db")
	cfg := writeFixtureConfig(t, dir)

	for _, flagName := range []string{"--gateway-port", "--reality-port", "--hy2-udp-port"} {
		for _, val := range []string{"65536", "70000"} {
			code, stdout, _ := runCLI(t, db, "", "profile", "show", "--config", cfg,
				"--dial-host", "203.0.113.10", flagName, val)
			if code != 2 {
				t.Errorf("%s=%s 被放过了(code=%d, stdout=%q)—— 会静默截断成另一个端口",
					flagName, val, code, trimForProfileLog(stdout))
			}
		}
	}
	// 边界值 65535 必须能用,别把加固做过头。
	code, stdout, stderr := runCLI(t, db, "", "profile", "show", "--config", cfg,
		"--dial-host", "203.0.113.10", "--reality-port", "65535")
	if code != 0 {
		t.Fatalf("65535 被误拒: code=%d stderr=%s", code, stderr)
	}
	if p := parseProfileJSON(t, stdout); p.Reality == nil || p.Reality.Port != 65535 {
		t.Errorf("reality.port 没落到 65535: %+v", p.Reality)
	}
}

// --host 是 --dial-host 的历史别名:必须继续能用(运维脚本还在用),但要出 deprecation
// 提示;两个都给时以显式的 --dial-host 为准。
func TestCmdProfileShow_LegacyHostAliasStillWorksAndWarns(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "p.db")
	cfg := writeFixtureConfig(t, dir)

	code, stdout, stderr := runCLI(t, db, "", "profile", "show", "--config", cfg,
		"--host", "203.0.113.10")
	if code != 0 {
		t.Fatalf("--host 别名失效了: code=%d stderr=%s", code, stderr)
	}
	if p := parseProfileJSON(t, stdout); p.Host != "203.0.113.10" {
		t.Errorf("host=%q", p.Host)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Error("用了已废弃的 --host 却一句提示都没有 —— 将来真移除时运维毫无准备")
	}

	code, stdout, stderr = runCLI(t, db, "", "profile", "show", "--config", cfg,
		"--host", "198.51.100.1", "--dial-host", "203.0.113.10")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if p := parseProfileJSON(t, stdout); p.Host != "203.0.113.10" {
		t.Errorf("host=%q —— 显式的 --dial-host 应压过别名", p.Host)
	}
}

// =========================================================================
// 软降级的两处:必须把警告说出来
// =========================================================================

// config.toml 读不到 / 解析不了时,profile 仍然出 —— 但那份 profile 缺 REALITY 公钥和
// Hy2 密码,客户端一定连不上。这时候唯一能救运维的就是 stderr 上那句警告。
func TestCmdProfileShow_UnreadableConfigWarnsLoudlyAndDropsTransportSections(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "p.db")

	t.Run("文件不存在", func(t *testing.T) {
		code, stdout, stderr := runCLI(t, db, "", "profile", "show",
			"--dial-host", "203.0.113.10", "--config", filepath.Join(dir, "nope.toml"))
		if code != 0 {
			t.Fatalf("config 读不到不该让命令失败: code=%d stderr=%s", code, stderr)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Fatal("config 读不到却静默出了一份没有传输层的 profile")
		}
		p := parseProfileJSON(t, stdout)
		if p.Reality != nil || p.Hy2 != nil {
			t.Errorf("没有 config 却凭空造出了传输层: reality=%+v hy2=%+v", p.Reality, p.Hy2)
		}
	})

	t.Run("TOML 语法坏了", func(t *testing.T) {
		bad := filepath.Join(dir, "broken.toml")
		if err := os.WriteFile(bad, []byte("[hysteria\npassword = "), 0o600); err != nil {
			t.Fatalf("写坏配置: %v", err)
		}
		code, _, stderr := runCLI(t, db, "", "profile", "show",
			"--dial-host", "203.0.113.10", "--config", bad)
		if code != 0 {
			t.Fatalf("code=%d stderr=%s", code, stderr)
		}
		if !strings.Contains(stderr, bad) {
			t.Errorf("警告里没说清是哪份配置解析失败: %q", stderr)
		}
	})
}

// server_id 是客户端「同一台服务器的新 QR 覆盖旧 QR」的依据。读不出来时 profile 照出,
// 但必须警告 —— 否则客户端会把这份 profile 当成一台**新服务器**,列表里出现重复条目。
func TestCmdProfileShow_ServerIDReadFailureWarnsButStillEmits(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "p.db")
	cfg := writeFixtureConfig(t, dir)

	// 把 server_id 的值改成 NULL:SettingsGet 往 string 里扫会失败,于是这是一次
	// **真·读故障**(而不是「没设过」),正是要验的那条软降级。schema 里 value 是
	// NOT NULL,所以先把表重建成不带该约束的样子 —— 现场对应的是磁盘位翻转 / 库被
	// 外部工具改坏这类情形。
	st := openStoreForTest(t, db)
	for _, stmt := range []string{
		`CREATE TABLE app_settings_relaxed (key TEXT PRIMARY KEY, value TEXT)`,
		`INSERT INTO app_settings_relaxed(key, value) SELECT key, value FROM app_settings`,
		`DROP TABLE app_settings`,
		`ALTER TABLE app_settings_relaxed RENAME TO app_settings`,
		`UPDATE app_settings SET value = NULL WHERE key = 'server_id'`,
	} {
		if _, err := st.DB().ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("弄坏 server_id(%s): %v", stmt, err)
		}
	}
	_ = st.Close()

	code, stdout, stderr := runCLI(t, db, "", "profile", "show",
		"--dial-host", "203.0.113.10", "--config", cfg)
	if code != 0 {
		t.Fatalf("server_id 读不出来不该让命令失败: code=%d stderr=%s", code, stderr)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Fatal("server_id 读失败却静默出了一份没有 server_id 的 profile —— 客户端会把它当成另一台服务器")
	}
	if p := parseProfileJSON(t, stdout); p.ServerID != "" {
		t.Errorf("server_id=%q, 读失败时应留空而不是编一个", p.ServerID)
	}
}

// =========================================================================
// 三个 tri-state flag 的解析
// =========================================================================

func TestParseTriStateProfileFlags(t *testing.T) {
	// auto 的语义是「跟着服务端配置走」,这才是默认值的意义所在:
	// 已上正规证书的部署不该签出「跳过 TLS 校验」的 profile。
	t.Run("hy2 insecure", func(t *testing.T) {
		hintOn := &config.Config{}
		hintOn.Hysteria.ReportTLSInsecureHint = true

		for _, tc := range []struct {
			in   string
			cfg  *config.Config
			want *bool
		}{
			{"true", nil, boolPtr(true)},
			{"TRUE", nil, boolPtr(true)},
			{"false", hintOn, boolPtr(false)}, // 显式压过 config
			{" auto ", hintOn, boolPtr(true)},
			{"auto", &config.Config{}, boolPtr(false)},
			{"auto", nil, boolPtr(false)}, // 读不到 config 时 fail-closed
		} {
			got, err := parseHy2InsecureFlag(tc.in, tc.cfg)
			if err != nil {
				t.Fatalf("parseHy2InsecureFlag(%q): %v", tc.in, err)
			}
			if got == nil || *got != *tc.want {
				t.Errorf("parseHy2InsecureFlag(%q, cfg=%v) = %v, 期望 %v", tc.in, tc.cfg != nil, deref(got), *tc.want)
			}
		}
		if _, err := parseHy2InsecureFlag("maybe", nil); err == nil {
			t.Error("认不出的取值却没报错 —— 拼错的 flag 会被当成某个默认值悄悄生效")
		}
	})

	t.Run("gateway tls", func(t *testing.T) {
		withCert := &config.Config{}
		withCert.Server.TLSCertFile = "/tmp/c.pem"
		withCert.Server.TLSKeyFile = "/tmp/k.pem"
		// 只有 cert 没有 key 不算开了 TLS。
		halfCert := &config.Config{}
		halfCert.Server.TLSCertFile = "/tmp/c.pem"

		for _, tc := range []struct {
			in   string
			cfg  *config.Config
			want *bool // nil = 不写该字段
		}{
			{"true", nil, boolPtr(true)},
			{"false", withCert, boolPtr(false)},
			{"auto", withCert, boolPtr(true)},
			{"auto", halfCert, nil},
			{"", &config.Config{}, nil},
			{"skip", nil, nil},
		} {
			got, err := parseGatewayTLSFlag(tc.in, tc.cfg)
			if err != nil {
				t.Fatalf("parseGatewayTLSFlag(%q): %v", tc.in, err)
			}
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Errorf("parseGatewayTLSFlag(%q) = %v, 期望 %v", tc.in, deref(got), deref(tc.want))
			}
		}
		if _, err := parseGatewayTLSFlag("yes", nil); err == nil {
			t.Error("认不出的取值却没报错")
		}
	})

	t.Run("gateway tls insecure", func(t *testing.T) {
		for _, tc := range []struct {
			in    string
			gwTLS *bool
			want  *bool
		}{
			{"true", nil, boolPtr(true)},
			{"false", boolPtr(true), boolPtr(false)},
			{"auto", boolPtr(true), boolPtr(true)},
			{"auto", boolPtr(false), nil}, // TLS 关着就没有 hint 可言
			{"", nil, nil},
		} {
			got, err := parseGatewayTLSInsecureFlag(tc.in, tc.gwTLS)
			if err != nil {
				t.Fatalf("parseGatewayTLSInsecureFlag(%q): %v", tc.in, err)
			}
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Errorf("parseGatewayTLSInsecureFlag(%q, gwTLS=%v) = %v, 期望 %v",
					tc.in, deref(tc.gwTLS), deref(got), deref(tc.want))
			}
		}
		if _, err := parseGatewayTLSInsecureFlag("nope", nil); err == nil {
			t.Error("认不出的取值却没报错")
		}
	})

	// 三个都要能从 CLI 那一层把错误顶出来,而不是被当成默认值悄悄放过。
	t.Run("坏取值经 CLI 也要失败", func(t *testing.T) {
		dir := t.TempDir()
		db := newInitializedDB(t, dir, "p.db")
		cfg := writeFixtureConfig(t, dir)
		for _, f := range []string{"--hy2-tls-insecure", "--gateway-tls", "--gateway-tls-insecure"} {
			code, stdout, _ := runCLI(t, db, "", "profile", "show", "--config", cfg,
				"--dial-host", "203.0.113.10", f, "sure")
			if code == 0 {
				t.Errorf("%s=sure 却成功了: %s", f, trimForProfileLog(stdout))
			}
		}
	})
}

// gateway_* 默认不写进客户端 profile(数据面不走公网 :8080),但只要运维显式碰过任一
// gateway flag 就该写出来 —— 否则「我明明设了 --gateway-tls」的设置凭空消失。
func TestShouldIncludeGateway_ExplicitFlagsOptIn(t *testing.T) {
	base := buildProfileInput{host: "203.0.113.10"}

	if shouldIncludeGateway(base) {
		t.Error("什么都没给却写出了 gateway 段")
	}
	for name, in := range map[string]buildProfileInput{
		"--with-gateway":         {includeGateway: true},
		"--gateway-port":         {gatewayPort: 9090},
		"--gateway-path":         {gatewayWSPath: "/ws"},
		"--gateway-tls-sni":      {gatewayTLSSNI: "gw.example.com"},
		"--gateway-tls":          {gatewayTLSFlag: "true"},
		"--gateway-tls-insecure": {gatewayTLSInsecureFlag: "false"},
	} {
		if !shouldIncludeGateway(in) {
			t.Errorf("显式给了 %s 却没写出 gateway 段 —— 运维的设置凭空消失", name)
		}
	}
	// auto / skip / 空 都算「没碰过」。
	for _, v := range []string{"", "auto", "AUTO", " skip "} {
		if explicitGatewayProfileFlag(v) {
			t.Errorf("%q 被当成显式设置了", v)
		}
	}
	// --no-gateway 一票否决,连 --with-gateway 都压得住。
	if shouldIncludeGateway(buildProfileInput{noGateway: true, includeGateway: true, gatewayPort: 9090}) {
		t.Error("--no-gateway 没能否决其它 gateway flag")
	}
}

// =========================================================================
// REALITY / Hy2 段的派生
// =========================================================================

// config 里的密钥材料坏了必须**整条失败**。软降级成「没有 reality 段」会更糟:
// 客户端会退到 Hy2 单通道,而运维以为 REALITY 一直在用。
func TestBuildReality_BrokenKeyMaterialFailsLoudly(t *testing.T) {
	mk := func(priv, seed string) buildProfileInput {
		cfg := &config.Config{}
		cfg.Reality.ListenAddr = ":8443"
		cfg.Reality.ServerNames = []string{"www.microsoft.com"}
		cfg.Reality.ShortIds = []string{"abcd1234"}
		cfg.Reality.PrivateKey = priv
		cfg.Reality.Mldsa65SeedBase64 = seed
		return buildProfileInput{host: "203.0.113.10", serverCfg: cfg}
	}

	t.Run("private_key 解不开", func(t *testing.T) {
		if _, err := buildReality(mk("not-base64-at-all!!", "")); err == nil {
			t.Fatal("坏 private_key 却派生出了 reality 段")
		}
		// 长度不对(解得开但不是 32 字节)同样要拒。
		short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
		if _, err := buildReality(mk(short, "")); err == nil {
			t.Fatal("16 字节私钥却派生出了 reality 段")
		}
	})

	t.Run("mldsa seed 解不开", func(t *testing.T) {
		in := mk(realityPrivateKeyB64, "###not-base64###")
		if _, err := buildReality(in); err == nil {
			t.Fatal("坏 mldsa65 seed 却派生出了 reality 段 —— 抗量子那层会白开且无任何报错")
		}
	})

	// 错误必须一路顶到 buildProfile / buildProfileV2,不能在中间被吞。
	t.Run("错误顶到 buildProfile", func(t *testing.T) {
		in := mk("not-base64-at-all!!", "")
		if _, err := buildProfile(in); err == nil {
			t.Error("buildProfile 吞掉了 reality 的错误")
		}
		if _, err := buildProfileV2(in, []nodeSpec{{Host: "198.51.100.1"}}); err == nil {
			t.Error("buildProfileV2 吞掉了 reality 的错误")
		}
	})
}

// Hy2 段的端口来源有三层(flag > config > 默认 443)。中间那层解析不出来时必须落到
// 默认值,而不是留个 0 —— udp_port=0 的 profile 客户端拨不出去。
func TestBuildHy2_PortAndHopDerivation(t *testing.T) {
	t.Run("config 端口解不出来就落默认 443", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Hysteria.ListenAddr = "" // 解析不出端口
		cfg.Hysteria.Password = "hello"
		cfg.Hysteria.TLSCertFile = "/tmp/c.pem"
		cfg.Hysteria.TLSKeyFile = "/tmp/k.pem"

		h, err := buildHy2(buildProfileInput{host: "203.0.113.10", serverCfg: cfg})
		if err != nil {
			t.Fatalf("buildHy2: %v", err)
		}
		if h == nil {
			t.Fatal("配了密码却没有 hy2 段")
		}
		if h.UDPPort != defaultHy2UDPPort {
			t.Errorf("udp_port=%d, 期望落到默认 %d —— 0 端口客户端拨不出去", h.UDPPort, defaultHy2UDPPort)
		}
	})

	t.Run("随机跳端口区间要成对写出", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Hysteria.ListenAddr = ":443,8443"
		cfg.Hysteria.Password = "hello"
		cfg.Hysteria.TLSCertFile = "/tmp/c.pem"
		cfg.Hysteria.TLSKeyFile = "/tmp/k.pem"
		cfg.Hysteria.PortHopIntervalMinSec = 10
		cfg.Hysteria.PortHopIntervalMaxSec = 40

		h, err := buildHy2(buildProfileInput{host: "203.0.113.10", serverCfg: cfg})
		if err != nil {
			t.Fatalf("buildHy2: %v", err)
		}
		if h.HopIntervalMinSec != 10 || h.HopIntervalMaxSec != 40 {
			t.Errorf("跳端口区间 = [%d,%d], 期望 [10,40]", h.HopIntervalMinSec, h.HopIntervalMaxSec)
		}
		if h.UDPPorts == "" {
			t.Error("多端口监听却没写出 udp_ports —— 客户端不会跳端口,配了等于没配")
		}
	})

	t.Run("min>max 的区间不写出", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Hysteria.ListenAddr = ":443"
		cfg.Hysteria.Password = "hello"
		cfg.Hysteria.TLSCertFile = "/tmp/c.pem"
		cfg.Hysteria.TLSKeyFile = "/tmp/k.pem"
		cfg.Hysteria.PortHopIntervalMinSec = 40
		cfg.Hysteria.PortHopIntervalMaxSec = 10

		h, err := buildHy2(buildProfileInput{host: "203.0.113.10", serverCfg: cfg})
		if err != nil {
			t.Fatalf("buildHy2: %v", err)
		}
		if h.HopIntervalMinSec != 0 || h.HopIntervalMaxSec != 0 {
			t.Errorf("min>max 的区间被写了出来 [%d,%d] —— 客户端行为未定义",
				h.HopIntervalMinSec, h.HopIntervalMaxSec)
		}
	})

	t.Run("server 没开 hy2 就不写 hy2 段", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Hysteria.ListenAddr = ":443" // 有监听地址但没密码/证书 → 未启用
		h, err := buildHy2(buildProfileInput{host: "203.0.113.10", serverCfg: cfg})
		if err != nil {
			t.Fatalf("buildHy2: %v", err)
		}
		if h != nil {
			t.Errorf("server 没启用 hy2 却写出了 hy2 段: %+v", h)
		}
	})
}

// mTLS 客户端证书是**签发**出来的,不是抄的:签不出来就必须失败。
// 悄悄给出一份没有 client_cert_pem 的 profile,客户端会在 QUIC 握手时被服务端拒,
// 报的是「TLS 握手失败」这类和真因毫无关系的错。
func TestAttachIssuedHy2ClientCert_FailuresAreFatal(t *testing.T) {
	t.Run("CA 文件不存在", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.toml")
		cfg := &config.Config{}
		cfg.Hysteria.ListenAddr = ":443"
		cfg.Hysteria.Password = "hello"
		cfg.Hysteria.TLSCertFile = "/tmp/c.pem"
		cfg.Hysteria.TLSKeyFile = "/tmp/k.pem"
		cfg.Hysteria.TLSClientCAFile = "certs/missing-ca.pem"

		in := buildProfileInput{
			host: "203.0.113.10", username: "alice",
			serverCfg: cfg, configPath: cfgPath, hy2ClientCertDays: 90,
		}
		_, err := buildHy2(in)
		if err == nil {
			t.Fatal("CA 不存在却照样出了 hy2 段 —— 客户端会在握手期被拒,报的错和真因无关")
		}
		if !strings.Contains(err.Error(), "missing-ca.pem") {
			t.Errorf("错误里没提是哪个 CA 找不到: %v", err)
		}
		// 错误要一路顶到 buildProfile。
		if _, err := buildProfile(in); err == nil {
			t.Error("buildProfile 吞掉了签证书的错误")
		}
	})

	t.Run("--no-issue-hy2-client-cert 时只标记不签发", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := writeFixtureConfigWithMTLS(t, dir)
		in := buildProfileInput{
			host: "203.0.113.10", username: "alice",
			serverCfg: loadFixtureConfig(t, cfgPath), configPath: cfgPath,
			noIssueHy2ClientCert: true,
		}
		h, err := buildHy2(in)
		if err != nil {
			t.Fatalf("buildHy2: %v", err)
		}
		if h.MTLSRequired == nil || !*h.MTLSRequired {
			t.Error("服务端要求 mTLS 却没在 profile 里标出来 —— 客户端不知道要带证书")
		}
		if h.ClientCertPEM != "" || h.ClientKeyPEM != "" {
			t.Error("说了不签发却还是塞了证书进去")
		}
	})

	t.Run("有效期为 0 时落到默认值", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := writeFixtureConfigWithMTLS(t, dir)
		in := buildProfileInput{
			host: "203.0.113.10", username: "alice",
			serverCfg: loadFixtureConfig(t, cfgPath), configPath: cfgPath,
			hy2ClientCertDays: 0,
		}
		h, err := buildHy2(in)
		if err != nil {
			t.Fatalf("buildHy2: %v", err)
		}
		if h.ClientCertPEM == "" {
			t.Fatal("没签出客户端证书")
		}
		notAfter := certNotAfter(t, h.ClientCertPEM)
		days := time.Until(notAfter).Hours() / 24
		// 绑常量而不是写死数字:这里要保的是「0 不能原样用」(那样签出的证书当场就是
		// 过期的),而不是某个具体天数。fixture CA 与默认值同为一百年,故应当基本贴合。
		if want := float64(defaultHy2ClientCertDays); days < want*0.9 || days > want*1.01 {
			t.Errorf("证书有效期 %.0f 天,期望落到默认的 %.0f 天 —— 0 天的证书当场就是过期的", days, want)
		}
	})

	t.Run("取不到随机数时整条失败", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := writeFixtureConfigWithMTLS(t, dir)
		orig := profileRandRead
		profileRandRead = func([]byte) (int, error) { return 0, errors.New("熵池干了") }
		t.Cleanup(func() { profileRandRead = orig })

		in := buildProfileInput{
			host: "203.0.113.10", username: "alice",
			serverCfg: loadFixtureConfig(t, cfgPath), configPath: cfgPath,
			hy2ClientCertDays: 90,
		}
		if _, err := buildHy2(in); err == nil {
			t.Fatal("随机数取不到却照样签了证书 —— CN 后缀会退化成固定值,吊销时分不清该吊哪张")
		}
	})
}

// 装机脚本签出的自签证书,有效期必须 ≥ defaultHy2ClientCertDays。
//
// 这是一条跨文件的不变量,而在此之前它只靠两边的注释互相提醒。certs.IssueClientCert 会把
// 叶子夹到 CA 的 NotAfter 以内,所以 scripts/ensure-server-assets.sh 里的 -days 一旦小于这里
// 的默认值,profile 里的客户端证书就被静默截短 —— 签发照常成功、二维码照常能扫,只是寿命悄悄
// 变成了 CA 的剩余寿命。
//
// 加这条的直接起因:客户端证书的默认值一路放到了一百年,而同一个脚本里 [server] / [hysteria]
// 的服务端自签证书一直停在 3650 天,期间没有任何测试碰过它 —— shell 那侧本来就没有单测,
// 从 Go 这边读一遍脚本是唯一能把这条约束变成断言的办法。
func TestEnsureServerAssetsScript_SelfSignedDaysCoversClientCertDefault(t *testing.T) {
	const script = "../../scripts/ensure-server-assets.sh"
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("读 %s: %v", script, err)
	}
	body := string(raw)

	m := regexp.MustCompile(`(?m)^SELF_SIGNED_DAYS=(\d+)$`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s 里找不到 SELF_SIGNED_DAYS=<天数> —— 要么改名了,要么有效期又被写回各个 openssl "+
			"调用里。后者会让几处 -days 各自漂移,而漂移的那处只在到期那天现形", script)
	}
	got, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("SELF_SIGNED_DAYS=%q 不是数字", m[1])
	}
	if got < defaultHy2ClientCertDays {
		t.Errorf("SELF_SIGNED_DAYS=%d < defaultHy2ClientCertDays=%d —— 客户端 CA 比叶子短,"+
			"profile 里的证书会被静默夹到 CA 的到期日", got, defaultHy2ClientCertDays)
	}

	// 每个 openssl 的 -days 都得走这个变量。留一处写死的数字就等于留一处不受本测试保护的
	// 有效期,而它恰好是上次漏掉的那种。
	for i, ln := range strings.Split(body, "\n") {
		if !strings.Contains(ln, "-days") || strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		if !strings.Contains(ln, `-days "$SELF_SIGNED_DAYS"`) {
			t.Errorf("%s:%d 的 -days 没走 SELF_SIGNED_DAYS:%s", script, i+1, strings.TrimSpace(ln))
		}
	}
}

func TestResolvePathRelativeToConfig(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configPath string
		rel        string
		want       string
	}{
		{"空的相对路径不拼到 config 目录上", "/etc/nanotun/config.toml", "  ", ""},
		{"绝对路径不动", "/etc/nanotun/config.toml", "/opt/ca.pem", "/opt/ca.pem"},
		{"相对 config 目录", "/etc/nanotun/config.toml", "certs/ca.pem", "/etc/nanotun/certs/ca.pem"},
		{"config 路径没有目录部分", "config.toml", "certs/ca.pem", "certs/ca.pem"},
		{"config 路径为空", "", "certs/ca.pem", "certs/ca.pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolvePathRelativeToConfig(tc.configPath, tc.rel); got != tc.want {
				t.Errorf("= %q, 期望 %q", got, tc.want)
			}
		})
	}
}

// =========================================================================
// 多入口(--node)
// =========================================================================

func TestParseNodeSpec_Guards(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"空", "   "},
		{"段里没有等号", "id=hk,香港"},
		{"不认识的键", "id=hk,region=asia,host=1.2.3.4"},
		{"只给了 id 没给 host", "id=hk,name=香港"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseNodeSpec(tc.raw); err == nil {
				t.Fatalf("parseNodeSpec(%q) 却成功了", tc.raw)
			}
		})
	}

	t.Run("裸字符串当 host", func(t *testing.T) {
		got, err := parseNodeSpec(" hk.example.com ")
		if err != nil {
			t.Fatalf("parseNodeSpec: %v", err)
		}
		if got.Host != "hk.example.com" || got.ID != "" {
			t.Errorf("= %+v", got)
		}
	})

	t.Run("键值对形式 + 空段跳过", func(t *testing.T) {
		got, err := parseNodeSpec("id=hk,,name=香港, host=1.2.3.4 ")
		if err != nil {
			t.Fatalf("parseNodeSpec: %v", err)
		}
		if got.ID != "hk" || got.Name != "香港" || got.Host != "1.2.3.4" {
			t.Errorf("= %+v", got)
		}
	})

	t.Run("stringList 累积重复 flag", func(t *testing.T) {
		var l stringList
		_ = l.Set("a")
		_ = l.Set("b")
		if l.String() != "a,b" {
			t.Errorf("stringList.String() = %q", l.String())
		}
	})
}

func TestBuildProfileV2_Guards(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeFixtureConfig(t, dir)
	base := buildProfileInput{
		host: "203.0.113.10", username: "alice",
		serverCfg: loadFixtureConfig(t, cfgPath), configPath: cfgPath,
	}

	t.Run("一个入口都没有", func(t *testing.T) {
		if _, err := buildProfileV2(base, nil); err == nil {
			t.Fatal("零入口的 v2 profile 却造出来了 —— 客户端没有任何可拨号的地址")
		}
	})

	t.Run("入口 id 撞车", func(t *testing.T) {
		_, err := buildProfileV2(base, []nodeSpec{
			{ID: "hk", Host: "1.2.3.4"},
			{ID: "hk", Host: "5.6.7.8"},
		})
		if err == nil {
			t.Fatal("重复的入口 id 被放过 —— 客户端按 id 索引,第二个会静默覆盖第一个")
		}
	})

	t.Run("入口 host 空", func(t *testing.T) {
		if _, err := buildProfileV2(base, []nodeSpec{{ID: "hk", Host: "   "}}); err == nil {
			t.Fatal("空 host 的入口被放过")
		}
	})

	t.Run("两种传输都造不出来", func(t *testing.T) {
		bare := buildProfileInput{host: "203.0.113.10", serverCfg: &config.Config{}}
		if _, err := buildProfileV2(bare, []nodeSpec{{Host: "1.2.3.4"}}); err == nil {
			t.Fatal("REALITY / Hy2 都造不出来却照样出了 v2 profile(每个入口都是空壳)")
		}
	})

	t.Run("正常路径:入口地址成对写出、端口字段清掉", func(t *testing.T) {
		p, err := buildProfileV2(base, []nodeSpec{
			{ID: "hk", Name: "香港", Host: "198.51.100.1"},
			{ID: "v6", Host: "2001:db8::1"},
		})
		if err != nil {
			t.Fatalf("buildProfileV2: %v", err)
		}
		if p.Version != profileSchemaVersionV2 {
			t.Errorf("version=%d", p.Version)
		}
		if len(p.Nodes) != 2 {
			t.Fatalf("入口数 %d", len(p.Nodes))
		}
		if got := p.Nodes[0].Reality.Address; got != "198.51.100.1:8443" {
			t.Errorf("v4 入口地址 = %q", got)
		}
		// IPv6 必须带方括号,否则是个歧义且非法的 dial 目标。
		if got := p.Nodes[1].Reality.Address; got != "[2001:db8::1]:8443" {
			t.Errorf("v6 入口地址 = %q —— 裸拼冒号的话客户端连不上", got)
		}
		for i, n := range p.Nodes {
			if n.Reality.Port != 0 || n.Hy2.UDPPort != 0 || n.Hy2.UDPPorts != "" {
				t.Errorf("第 %d 个入口同时留了 address 和 port 字段,白占体积: %+v", i, n)
			}
		}
		if profileURLPrefixFor(p) != profileURLPrefixV2 {
			t.Errorf("v2 profile 的 URL 前缀不对: %q", profileURLPrefixFor(p))
		}
	})

	t.Run("--node 参数坏了经 CLI 也要失败", func(t *testing.T) {
		db := newInitializedDB(t, dir, "v2.db")
		code, stdout, _ := runCLI(t, db, "", "profile", "show", "--config", cfgPath,
			"--dial-host", "203.0.113.10", "--node", "region=asia")
		if code == 0 {
			t.Errorf("坏 --node 却成功了: %s", trimForProfileLog(stdout))
		}
	})
}

func TestHy2DialAddress_PrefersPortUnion(t *testing.T) {
	// 端口并集要整段拼上去(客户端据此跳端口);没有并集时才用单端口,单端口为 0 时落默认。
	for _, tc := range []struct {
		name string
		h    profileSchemaHy2
		host string
		want string
	}{
		{"并集优先", profileSchemaHy2{UDPPort: 443, UDPPorts: "443,8443"}, "1.2.3.4", "1.2.3.4:443,8443"},
		{"单端口", profileSchemaHy2{UDPPort: 8443}, "1.2.3.4", "1.2.3.4:8443"},
		{"端口为 0 落默认", profileSchemaHy2{}, "1.2.3.4", "1.2.3.4:443"},
		{"v6 加方括号", profileSchemaHy2{UDPPorts: "443,8443"}, "2001:db8::1", "[2001:db8::1]:443,8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.h
			if got := hy2DialAddress(tc.host, &h); got != tc.want {
				t.Errorf("= %q, 期望 %q", got, tc.want)
			}
		})
	}

	// 入口 host 为空时不该把 address 写成一个只有端口的残缺串。
	// 这里的 8443 是**输入**,不是默认值:断言的是「入口 host 为空时这一段一个字都别动」,
	// 所以期望值必须等于上面设进去的那个数,与 defaultRealityTCPPort 无关。
	// (2026-08-28 把默认端口改成 443 时,这一行一度被误当成回落断言改掉,于是它开始
	//  验证一件相反的事 —— 「空 host 时把端口改成默认值」。)
	r := &profileSchemaReality{Port: 8443}
	attachEntryAddresses("  ", r, nil)
	if r.Address != "" || r.Port != 8443 {
		t.Errorf("空入口 host 却动了 reality 段: %+v", r)
	}
	// reality 端口为 0 时也要落默认,别拼出 "1.2.3.4:0"。
	r2 := &profileSchemaReality{}
	attachEntryAddresses("1.2.3.4", r2, nil)
	if r2.Address != "1.2.3.4:443" {
		t.Errorf("reality 入口地址 = %q", r2.Address)
	}
}

// =========================================================================
// 输出层
// =========================================================================

func TestWriteProfile_FormatsAndWriteFailures(t *testing.T) {
	p := &profileSchema{Version: 1, Host: "203.0.113.10", Name: "n"}

	t.Run("不认识的格式要报错", func(t *testing.T) {
		var sb strings.Builder
		if err := writeProfile(&sb, p, "toml", false); err == nil {
			t.Fatal("不支持的格式却写出来了")
		}
	})

	t.Run("全局 json 压过 format", func(t *testing.T) {
		var sb strings.Builder
		if err := writeProfile(&sb, p, "url", true); err != nil {
			t.Fatalf("writeProfile: %v", err)
		}
		if strings.Contains(sb.String(), "nanotun://") {
			t.Errorf("--json 之下还是出了 URL: %q", sb.String())
		}
		if !strings.Contains(sb.String(), `"host":"203.0.113.10"`) {
			t.Errorf("--json 之下不是 compact JSON: %q", sb.String())
		}
	})

	// both 分三次写(JSON、换行、URL),任一次失败都必须往上报,不能只写出半份。
	t.Run("both 的每一步写失败都要上报", func(t *testing.T) {
		for okWrites := 0; okWrites < 3; okWrites++ {
			w := &brokenWriter{okWrites: okWrites}
			if err := writeProfile(w, p, "both", false); err == nil {
				t.Errorf("前 %d 次写成功之后失败,却被当成写完了", okWrites)
			}
		}
	})

	t.Run("compact json 写失败要上报", func(t *testing.T) {
		if err := writeJSONCompact(&brokenWriter{}, p); err == nil {
			t.Error("第一次写就失败却报成功")
		}
		// 第一次写 body 成功、写尾换行失败。
		if err := writeJSONCompact(&brokenWriter{okWrites: 1}, p); err == nil {
			t.Error("尾换行写失败被吞了")
		}
	})
}

func TestEmitProfile_Guards(t *testing.T) {
	p := &profileSchema{Version: 1, Host: "203.0.113.10"}

	t.Run("qr-png 缺 --output", func(t *testing.T) {
		var out, errb strings.Builder
		opts := newProfileOpts(&out, &errb)
		if err := emitProfile(p, "qr-png", "  ", false, opts); err == nil {
			t.Fatal("qr-png 不给 --output 却成功了")
		} else if !isUsageErr(err) {
			t.Errorf("应判为用法错误(exit 2),实际 %v", err)
		}
	})

	t.Run("qr 忽略 --output 时要提醒", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "ignored.png")
		var out, errb strings.Builder
		opts := newProfileOpts(&out, &errb)
		if err := emitProfile(p, "qr", target, false, opts); err != nil {
			t.Fatalf("emitProfile: %v", err)
		}
		if !strings.Contains(errb.String(), target) {
			t.Errorf("没提醒 --output 被忽略: %q", errb.String())
		}
		if _, err := os.Stat(target); err == nil {
			t.Error("说是忽略却真写了文件")
		}
	})

	t.Run("stdout 写不进去要上报", func(t *testing.T) {
		var errb strings.Builder
		// --json 路径:compact JSON 直接写 stdout。
		opts := &globalOpts{lang: "zh", json: true, stdout: &brokenWriter{}, stderr: &errb}
		if err := emitProfile(p, "json", "", false, opts); err == nil {
			t.Error("--json 路径把 stdout 的写失败吞了 —— 运维会以为 profile 已经拿到手")
		}
		// 默认路径同理。
		opts2 := newProfileOpts(&strings.Builder{}, &errb)
		opts2.stdout = &brokenWriter{}
		if err := emitProfile(p, "json", "", false, opts2); err == nil {
			t.Error("默认路径把 stdout 的写失败吞了")
		}
	})

	t.Run("不认识的格式落到默认分支后仍要报错", func(t *testing.T) {
		var out, errb strings.Builder
		opts := newProfileOpts(&out, &errb)
		// 正常 CLI 路径上 --format 已被 validFormat 挡住;这里直接调 emitProfile,
		// 确认最里层也不会把未知格式当成 json 悄悄放过。
		if err := emitProfile(p, "toml", "", false, opts); err == nil {
			t.Fatal("未知格式在最里层被当成默认格式放过了")
		}
	})
}

// --output 落在不存在的目录 / 已有文件上时的行为:前者报错,后者默认拒绝覆盖。
// 覆盖那条尤其要紧 —— 目标文件里可能是另一个用户的 mTLS 私钥。
func TestCmdProfileShow_OutputTargetGuards(t *testing.T) {
	dir := t.TempDir()
	db := newInitializedDB(t, dir, "p.db")
	cfg := writeFixtureConfig(t, dir)
	run := func(extra ...string) (int, string) {
		args := append([]string{"profile", "show", "--config", cfg, "--dial-host", "203.0.113.10"}, extra...)
		code, _, stderr := runCLI(t, db, "", args...)
		return code, stderr
	}

	t.Run("目录不存在", func(t *testing.T) {
		if code, _ := run("--output", filepath.Join(dir, "nope", "p.json")); code == 0 {
			t.Fatal("写到不存在的目录却成功了")
		}
	})

	t.Run("默认拒绝覆盖", func(t *testing.T) {
		target := filepath.Join(dir, "p.json")
		if code, stderr := run("--output", target); code != 0 {
			t.Fatalf("首次写入失败: %s", stderr)
		}
		fi, err := os.Stat(target)
		if err != nil {
			t.Fatalf("产物不存在: %v", err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("产物权限 %o,期望 600 —— 里面有 Hy2 密码和 mTLS 私钥", perm)
		}
		if code, stderr := run("--output", target); code == 0 {
			t.Fatal("已存在的产物被默默覆盖了")
		} else if !strings.Contains(stderr, target) {
			t.Errorf("没说清是哪个文件: %q", stderr)
		}
		if code, stderr := run("--output", target, "--force"); code != 0 {
			t.Fatalf("--force 之下仍失败: %s", stderr)
		}
	})
}

// writeFileTight 是所有含密产物的落盘口。它的两条安全承诺:
// 不覆盖既有文件(no-clobber 走 link(2),原子),以及从创建那一刻起就是 0600。
func TestWriteFileTight_Guards(t *testing.T) {
	dir := t.TempDir()

	t.Run("已存在即拒", func(t *testing.T) {
		p := filepath.Join(dir, "taken")
		if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := writeFileTight(p, []byte("new"), 0o600, false); err == nil {
			t.Fatal("覆盖了既有文件")
		}
		if body, _ := os.ReadFile(p); string(body) != "old" {
			t.Errorf("原文件被改了: %q", body)
		}
		// 拒绝之后不能在目录里留临时文件。
		assertNoTempResidue(t, dir, "taken")
	})

	t.Run("force 覆盖并收紧权限", func(t *testing.T) {
		p := filepath.Join(dir, "loose")
		if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := writeFileTight(p, []byte("new"), 0o600, true); err != nil {
			t.Fatalf("writeFileTight: %v", err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("覆盖既有 0644 文件后权限 %o —— 密材世界可读", fi.Mode().Perm())
		}
		if body, _ := os.ReadFile(p); string(body) != "new" {
			t.Errorf("内容没换成新的: %q", body)
		}
	})

	t.Run("目录不存在时不留残骸", func(t *testing.T) {
		missing := filepath.Join(dir, "no-such-dir")
		if err := writeFileTight(filepath.Join(missing, "x"), []byte("d"), 0o600, false); err == nil {
			t.Fatal("父目录不存在却写成功了")
		}
		if _, err := os.Stat(missing); err == nil {
			t.Error("顺手把目录建出来了 —— 打错路径时会在盘上散落空目录")
		}
	})

	// 路径本身不合法(中间某一段是个普通文件)时,Lstat 报的不是 NotExist ——
	// 这类错误必须原样上报,不能被当成「目标不存在,可以写」而继续往下走。
	t.Run("路径中间夹了个文件", func(t *testing.T) {
		blocker := filepath.Join(dir, "not-a-dir")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeFileTight(filepath.Join(blocker, "x"), []byte("d"), 0o600, false); err == nil {
			t.Fatal("路径中间是个普通文件却写成功了")
		}
	})

	// force=true 走 rename:目标是个非空目录时 rename 会失败,此时必须报错并清掉临时文件,
	// 不能在目录里留下一份含密的 .tmp-*。
	t.Run("force 覆盖目录时报错且不留残骸", func(t *testing.T) {
		sub := filepath.Join(dir, "as-dir")
		if err := os.MkdirAll(filepath.Join(sub, "inner"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeFileTight(sub, []byte("d"), 0o600, true); err == nil {
			t.Fatal("把非空目录当文件覆盖却成功了")
		}
		assertNoTempResidue(t, dir, "as-dir")
	})

	t.Run("目标是符号链接时不跟随", func(t *testing.T) {
		victim := filepath.Join(dir, "victim")
		if err := os.WriteFile(victim, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link")
		if err := os.Symlink(victim, link); err != nil {
			t.Skipf("造不出符号链接: %v", err)
		}
		// force=false:Lstat 看到链接就该拒。
		if err := writeFileTight(link, []byte("attack"), 0o600, false); err == nil {
			t.Fatal("目标是符号链接却照写 —— 明文密材会被写进链接指向的文件")
		}
		// force=true:rename 替换链接本身,不能经它写到 victim。
		if err := writeFileTight(link, []byte("attack"), 0o600, true); err != nil {
			t.Fatalf("writeFileTight(force): %v", err)
		}
		if body, _ := os.ReadFile(victim); string(body) != "secret" {
			t.Errorf("经符号链接改写了受害文件: %q", body)
		}
	})
}

// 终端二维码这条路上,「装不下」必须是一个明确的错误。
// qrterminal 内部编码失败时**不输出任何东西也不报错**,运维只会看到一片空白。
func TestWriteQRTerminal_OverflowIsAnErrorNotBlankOutput(t *testing.T) {
	var out, errb strings.Builder
	opts := newProfileOpts(&out, &errb)

	huge := strings.Repeat("A", qrLowMaxURLBytes+1)
	if err := writeQRTerminal(opts, &out, huge); err == nil {
		t.Fatal("超长 URL 却没报错 —— 运维只会看到一片空白")
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Errorf("失败路径还是吐了点东西出来: %q", trimForProfileLog(out.String()))
	}

	// 落在 Medium 装不下、Low 装得下的区间时要降级并明说,而不是静默降级。
	out.Reset()
	if err := writeQRTerminal(opts, &out, qrByteModePayload(2400)); err != nil {
		t.Fatalf("2400 字节应能降级到 Low: %v", err)
	}
	if !strings.Contains(out.String(), "2400") {
		t.Errorf("降级到低纠错级别却没说 —— 扫码失败时无从判断原因: %q", trimForProfileLog(out.String()))
	}
}

// qrByteModePayload 造一段长度精确为 n 的载荷,内容强制 go-qrcode 走 Byte 模式。
//
// 不能用 strings.Repeat("A", n):全大写字母落进 QR 的 Alphanumeric 模式,每字符只占
// 5.5 bit,2400 个 'A' 轻松塞进 v40-M —— 于是「Medium 装不下才降级 Low」那条分支
// 根本不会触发。掺进小写就只能走 Byte 模式(8 bit/字符),容量口径才与真实 profile
// URL(base64url,含大小写)一致。
func qrByteModePayload(n int) string {
	const unit = "aB9-_"
	return strings.Repeat(unit, n/len(unit)+1)[:n]
}

func TestWriteQRPNG_OverflowAndDowngrade(t *testing.T) {
	dir := t.TempDir()
	var out, errb strings.Builder
	opts := newProfileOpts(&out, &errb)

	t.Run("装不下就明确报错", func(t *testing.T) {
		p := filepath.Join(dir, "huge.png")
		if err := writeQRPNG(opts, p, strings.Repeat("A", qrLowMaxURLBytes+1), false); err == nil {
			t.Fatal("超长 URL 却出了 PNG")
		}
		if _, err := os.Stat(p); err == nil {
			t.Error("失败路径留下了半份 PNG")
		}
	})

	t.Run("降级到 Low 时要写进 stderr", func(t *testing.T) {
		errb.Reset()
		p := filepath.Join(dir, "big.png")
		if err := writeQRPNG(opts, p, qrByteModePayload(2400), false); err != nil {
			t.Fatalf("writeQRPNG: %v", err)
		}
		if !strings.Contains(errb.String(), "2400") {
			t.Errorf("降级了却没进 stderr —— 这条是事后审计「这次 QR 降级了」的唯一线索: %q", errb.String())
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("PNG 不存在: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("PNG 权限 %o —— 里面编码着明文 profile", fi.Mode().Perm())
		}
	})
}

func TestPortFromListenAddr_FallbackParsing(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint16
	}{
		{":443", 443},
		{"0.0.0.0:8443", 8443},
		{"[::]:443,8443", 443},
		{":5000-5100,443", 5000},
		{"", 0},
		{"443", 0},        // 没有冒号,拿不出端口
		{":0", 0},         // 0 端口视作「未设」
		{":70000", 0},     // 越界
		{":abc", 0},       // 解析不出
		{":443,bad", 443}, // 并集整体不合法时退回按书写顺序取首个
		{":5000-5100,bad", 5000},
	} {
		if got := portFromListenAddr(tc.in); got != tc.want {
			t.Errorf("portFromListenAddr(%q) = %d, 期望 %d", tc.in, got, tc.want)
		}
	}
}

// =========================================================================
// 辅助
// =========================================================================

func boolPtr(v bool) *bool { return &v }

func deref(p *bool) any {
	if p == nil {
		return "nil"
	}
	return *p
}

func trimForProfileLog(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

// loadFixtureConfig 把 fixture config.toml 读成 *config.Config,供直接调用
// buildHy2 / buildReality 的测试用(不经 CLI)。
func loadFixtureConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := loadServerConfigOptional(path)
	if err != nil {
		t.Fatalf("loadServerConfigOptional(%s): %v", path, err)
	}
	return cfg
}

// certNotAfter 从 PEM 里取出证书的到期时间。
func certNotAfter(t *testing.T, certPEM string) time.Time {
	t.Helper()
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		t.Fatalf("客户端证书不是合法 PEM: %q", trimForProfileLog(certPEM))
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("解析客户端证书: %v", err)
	}
	return c.NotAfter
}

// assertNoTempResidue 确认目录里没有 writeFileTight 留下的临时文件。
func assertNoTempResidue(t *testing.T, dir, base string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "."+base+".tmp-") {
			t.Errorf("留下了临时文件 %s —— 里面是明文密材", e.Name())
		}
	}
}
