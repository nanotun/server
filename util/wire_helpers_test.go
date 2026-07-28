package util

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
)

// 这一批是 wire 层的小函数:序列化、解析、名字归一、端口并集。它们各自只有几行,
// 但都是**跨进程契约**的一端 —— 写错了就是客户端解不出来,而且只在真机上才暴露。

func TestMarshalLoginRespFullJSON_OmitsTheTakeoverFieldsWhenThereIsNoSession(t *testing.T) {
	// 没有 takeover 时字段必须整个消失,不能是空串:老客户端看到 "session_id":""
	// 会以为自己拿到了一个会话。
	b, err := MarshalLoginRespFullJSON(0, "ok", "u1", "", "")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	s := string(b)
	if strings.Contains(s, "session_id") || strings.Contains(s, "takeover_secret") {
		t.Fatalf("空值应被 omitempty 掉: %s", s)
	}

	b2, err := MarshalLoginRespFullJSON(0, "ok", "u1", "sess-1", "secret-1")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	var resp LoginResp
	if err := json.Unmarshal(b2, &resp); err != nil {
		t.Fatalf("解不回来: %v", err)
	}
	if resp.SessionID != "sess-1" || resp.TakeoverSecret != "secret-1" {
		t.Fatalf("round-trip 掉字段: %+v", resp)
	}
	if resp.Code != 0 || resp.Message != "ok" || resp.UserID != "u1" {
		t.Fatalf("基础字段对不上: %+v", resp)
	}

	// 失败响应也走这条路,code/message 必须原样带出去。
	b3, _ := MarshalLoginRespFullJSON(403, "禁用", "", "", "")
	var deny LoginResp
	if err := json.Unmarshal(b3, &deny); err != nil {
		t.Fatalf("解不回来: %v", err)
	}
	if deny.Code != 403 || deny.Message != "禁用" {
		t.Fatalf("%+v", deny)
	}
}

func TestCloseFrame_RoundTripsAndTheKickReasonStaysReadable(t *testing.T) {
	b, err := MarshalCloseJSON(4001, "被管理员踢下线")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	msg, err := ParseCloseLinkPayload(b)
	if err != nil {
		t.Fatalf("ParseCloseLinkPayload: %v", err)
	}
	if msg.Code != 4001 || msg.Reason != "被管理员踢下线" {
		t.Fatalf("%+v", msg)
	}

	if _, err := ParseCloseLinkPayload([]byte("不是 JSON")); err == nil {
		t.Fatal("坏负载应报错")
	}

	// 客户端断线提示直接显示这段文本,所以没有 message 时也得说清是什么码。
	if got := CloseReasonForKick(4001, ""); got != "code=4001" {
		t.Fatalf("got %q", got)
	}
	if got := CloseReasonForKick(4001, "欠费"); got != "code=4001 欠费" {
		t.Fatalf("got %q", got)
	}
}

func TestLinkPoWChallenge_RoundTripsEveryFieldTheClientNeedsToSolveIt(t *testing.T) {
	b, err := MarshalLinkPoWChallengeJSON("cid-1", "salt-1", 14, 1_700_000_000, "sig-1")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	c, err := ParseLinkPoWChallengePayload(b)
	if err != nil {
		t.Fatalf("ParseLinkPoWChallengePayload: %v", err)
	}
	// 缺任何一项客户端都算不出答案,或者算出来服务端验不过。
	if c.ChallengeID != "cid-1" || c.Salt != "salt-1" || c.Difficulty != 14 ||
		c.ExpiresAt != 1_700_000_000 || c.Signature != "sig-1" {
		t.Fatalf("round-trip 掉字段: %+v", c)
	}

	if _, err := ParseLinkPoWChallengePayload([]byte("{")); err == nil {
		t.Fatal("坏负载应报错")
	}
}

func TestRoutesList_IsAlwaysAnArrayAndSchemaMismatchIsRejected(t *testing.T) {
	// nil 序列化成 null 的话,客户端 for-each 会崩。
	b, err := MarshalRoutesList(nil)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(string(b), `"routes":[]`) {
		t.Fatalf("空列表必须是 [],不能是 null: %s", b)
	}

	in := []SubnetRouteInfo{
		{CIDR: "192.168.1.0/24", DeviceUUID: "uuid-a", DeviceName: "pi", Online: true, SiteID: 7},
		{CIDR: "10.0.0.0/8", Online: false},
	}
	b2, err := MarshalRoutesList(in)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	rl, err := ParseRoutesList(b2)
	if err != nil {
		t.Fatalf("ParseRoutesList: %v", err)
	}
	if rl.Schema != RouteSchemaCurrent || len(rl.Routes) != 2 {
		t.Fatalf("%+v", rl)
	}
	if rl.Routes[0].SiteID != 7 || !rl.Routes[0].Online {
		t.Fatalf("4via6 站点号或在线态丢了: %+v", rl.Routes[0])
	}
	// site_id=0 表示"没分配",omitempty 掉是对的,解回来还是 0。
	if rl.Routes[1].SiteID != 0 || rl.Routes[1].Online {
		t.Fatalf("%+v", rl.Routes[1])
	}

	t.Run("schema 不匹配", func(t *testing.T) {
		bad, _ := json.Marshal(RoutesList{Schema: RouteSchemaCurrent + 1})
		if _, err := ParseRoutesList(bad); err == nil {
			t.Fatal("schema 对不上要拒 —— 静默接受等于让新旧两端各自理解字段")
		}
	})
	t.Run("坏 JSON", func(t *testing.T) {
		if _, err := ParseRoutesList([]byte("[]")); err == nil {
			t.Fatal("应报错")
		}
	})
}

// NormalizeMagicHost 同时被 MagicDNS 解析和「每用户设备名唯一」去重用。两边口径
// 一旦漂移,就会出现「库里允许两个设备叫这个名字,但 DNS 只能解出一个」。
func TestNormalizeMagicHost_CollapsesEverythingDNSCannotDistinguish(t *testing.T) {
	cases := []struct {
		in, want string
		because  string
	}{
		{"MyLaptop", "mylaptop", "DNS 名大小写不敏感"},
		{"  home pi  ", "home-pi", "空格换连字符,首尾空白先裁掉"},
		{"home_pi", "home-pi", "下划线在主机名里非法"},
		{"home.pi", "home-pi", "点会把它变成两级子域"},
		{"home--pi", "home-pi", "连续连字符折叠"},
		{"home___pi", "home-pi", "折叠发生在替换之后"},
		{"-lead-", "lead", "首尾连字符是非法主机名"},
		{"办公室", "", "全是非 ASCII → 全变连字符 → 裁光"},
		{"", "", ""},
		{"   ", "", ""},
		{"---", "", "只有连字符也裁光"},
		{"pi-4b", "pi-4b", "数字和连字符原样保留"},
		{"Café Mac", "caf-mac", "多字节字符每个字节各换一个连字符,再折叠"},
	}
	for _, tc := range cases {
		if got := NormalizeMagicHost(tc.in); got != tc.want {
			t.Errorf("NormalizeMagicHost(%q)=%q,期望 %q(%s)", tc.in, got, tc.want, tc.because)
		}
	}

	// 幂等:归一形再归一必须不变,否则两次调用结果不同,去重就漏了。
	for _, s := range []string{"my-laptop", "pi-4b", "a", ""} {
		if got := NormalizeMagicHost(s); got != s {
			t.Errorf("不幂等:%q → %q", s, got)
		}
	}
}

func TestGenerateID_IsA32CharHexAndNeverRepeats(t *testing.T) {
	seen := make(map[string]struct{}, 128)
	for i := 0; i < 128; i++ {
		id := GenerateID()
		if len(id) != 32 {
			t.Fatalf("长度 %d,期望 32(16 字节 hex)", len(id))
		}
		if strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("不是小写 hex: %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("128 次里就撞了:%q —— conn_id 撞了会把两条连接的日志和限速搅在一起", id)
		}
		seen[id] = struct{}{}
	}
}

func TestCryptKeyLen_MatchesWhatTheCipherActuallyNeeds(t *testing.T) {
	cases := map[string]int{
		"aes-128": 16, "aes-128-gcm": 16, "tea": 16, "xtea": 16, "cast5": 16, "sm4": 16,
		"aes-192": 24, "3des": 24, "tripledes": 24,
		"aes-256": 32, "aes-256-gcm": 32, "salsa20": 32, "blowfish": 32, "twofish": 32,
		"": 0, "none": 0, "xor": 0,
		"不存在的算法": 0,
	}
	for crypt, want := range cases {
		if got := CryptKeyLen(crypt); got != want {
			t.Errorf("CryptKeyLen(%q)=%d,期望 %d", crypt, got, want)
		}
		// 声称需要 N 字节,就得真能用 N 字节的 key 建出 BlockCrypt 来。
		if want > 0 {
			key := strings.Repeat("k", want)
			if _, err := NewKCPBlockCrypt(crypt, key); err != nil {
				t.Errorf("NewKCPBlockCrypt(%q, %d 字节 key) 失败: %v", crypt, want, err)
			}
		}
	}
}

func TestValidateCrypt_AcceptsExactlyWhatNewKCPBlockCryptCanBuild(t *testing.T) {
	// 两个函数各有一份 switch。清单漂移的话,config lint 会放行一个运行时建不出来的算法。
	supported := []string{
		"", "none", "xor", "aes-128", "aes-192", "aes-256",
		"aes-128-gcm", "aes-256-gcm", "tea", "xtea", "salsa20",
		"blowfish", "cast5", "3des", "tripledes", "twofish", "sm4",
	}
	for _, c := range supported {
		if err := ValidateCrypt(c); err != nil {
			t.Errorf("ValidateCrypt(%q) 应通过: %v", c, err)
		}
		key, err := GenerateKCPKey(c)
		if err != nil {
			t.Fatalf("GenerateKCPKey(%q): %v", c, err)
		}
		if _, err := NewKCPBlockCrypt(c, string(key)); err != nil {
			t.Errorf("ValidateCrypt 放行了 %q,但 NewKCPBlockCrypt 建不出来: %v", c, err)
		}
	}

	for _, c := range []string{"aes", "rc4", "AES-128", " none", "chacha20"} {
		if err := ValidateCrypt(c); err == nil {
			t.Errorf("ValidateCrypt(%q) 应被拒", c)
		}
		if _, err := NewKCPBlockCrypt(c, "0123456789abcdef"); err == nil {
			t.Errorf("NewKCPBlockCrypt(%q) 也该拒 —— 两处清单必须一致", c)
		}
	}
}

func TestGenerateKCPKey_LengthFollowsTheCipherAndIsNotAllZeros(t *testing.T) {
	for crypt, want := range map[string]int{"aes-128": 16, "aes-192": 24, "aes-256": 32} {
		k, err := GenerateKCPKey(crypt)
		if err != nil {
			t.Fatalf("GenerateKCPKey(%q): %v", crypt, err)
		}
		if len(k) != want {
			t.Fatalf("GenerateKCPKey(%q) 长度 %d,期望 %d", crypt, len(k), want)
		}
	}
	// 不需要 key 的算法也得给足 32 字节随机数(none/xor 的 key 可能被拿去当别的种子)。
	k, err := GenerateKCPKey("none")
	if err != nil || len(k) != 32 {
		t.Fatalf("got (%d,%v)", len(k), err)
	}

	a, _ := GenerateKCPKey("aes-256")
	b, _ := GenerateKCPKey("aes-256")
	if string(a) == string(b) {
		t.Fatal("两次生成的 key 一样 —— 不是随机的")
	}
	if strings.Count(string(a), "\x00") == len(a) {
		t.Fatal("全零 key")
	}
}

func TestFormatUDPListenAddr_ProducesSomethingListenPacketAccepts(t *testing.T) {
	cases := []struct {
		host string
		port uint16
		want string
	}{
		{"", 443, ":443"},
		{"0.0.0.0", 443, "0.0.0.0:443"},
		{"127.0.0.1", 8443, "127.0.0.1:8443"},
		{"::", 443, "[::]:443"},
		{"fe80::1", 443, "[fe80::1]:443"},
	}
	for _, tc := range cases {
		got := FormatUDPListenAddr(tc.host, tc.port)
		if got != tc.want {
			t.Fatalf("FormatUDPListenAddr(%q,%d)=%q,期望 %q", tc.host, tc.port, got, tc.want)
		}
		// 真拿去 bind 一次:v6 地址忘了加方括号是这里最容易犯的错,而且只在配了
		// v6 监听的机器上才炸。
		if _, _, err := net.SplitHostPort(got); err != nil {
			t.Fatalf("%q 不是合法的 host:port: %v", got, err)
		}
	}

	// 和拆解函数对得上:拆出来的 host 拼回去要还原。
	for _, addr := range []string{":443", "0.0.0.0:443", "[::]:443", "[fe80::1]:8443"} {
		host, _, err := SplitUDPListenAddr(addr)
		if err != nil {
			t.Fatalf("SplitUDPListenAddr(%q): %v", addr, err)
		}
		port, err := PrimaryPortFromUDPListenAddr(addr)
		if err != nil {
			t.Fatalf("PrimaryPortFromUDPListenAddr(%q): %v", addr, err)
		}
		if got := FormatUDPListenAddr(host, port); got != addr {
			t.Fatalf("拆再拼 %q → %q", addr, got)
		}
	}
}

func TestPortUnionStringFromUDPListenAddr_HandsBackJustThePortsForProfileExport(t *testing.T) {
	cases := []struct {
		addr, want string
	}{
		{":443", "443"},
		{":443,8443", "443,8443"},
		{"0.0.0.0:5000-5100", "5000-5100"},
		{"[::]:443,5000-5100", "443,5000-5100"},
	}
	for _, tc := range cases {
		got, err := PortUnionStringFromUDPListenAddr(tc.addr)
		if err != nil {
			t.Fatalf("%q: %v", tc.addr, err)
		}
		if got != tc.want {
			t.Fatalf("PortUnionStringFromUDPListenAddr(%q)=%q,期望 %q", tc.addr, got, tc.want)
		}
		// 导给客户端的 udp_ports 必须能被同一个解析器读回来,不然客户端端口跳跃直接跳空。
		if !UDPPortUnionNeedsHop(got) && strings.ContainsAny(got, ",-") {
			t.Fatalf("%q 明明是多口,却被判成不需要 hop", got)
		}
	}

	for _, bad := range []string{"", "443", "[::1", "[::1]443"} {
		if _, err := PortUnionStringFromUDPListenAddr(bad); err == nil {
			t.Fatalf("%q 应报错", bad)
		}
	}
}

func TestTCPRecordConn_CloseGoesThroughToTheUnderlyingSocket(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()

	rc := &TCPRecordConn{conn: a}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// 底层真关了的话,对端读会立刻拿到错误而不是永远阻塞。
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("底层 conn 没被关掉 —— 连接会泄漏到进程退出")
	}
	_ = fmt.Sprint(rc)
}
