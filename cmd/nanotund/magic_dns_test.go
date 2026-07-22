package main

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
)

func newMagicDNSCfg(enabled bool) *config.Config {
	c := &config.Config{}
	c.Server.MagicDNS.Enabled = enabled
	return c
}

// helpers ------------------------------------------------------------

func buildDNSQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               0x4242,
		RecursionDesired: true,
		Response:         false,
	})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  n,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parseDNSResponse(t *testing.T, raw []byte) (dnsmessage.Header, []dnsmessage.Resource) {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	return msg.Header, msg.Answers
}

// 把 handleMagicDNSPacket 放到一对环回 UDP 上跑,readback 客户端收到的响应。
func runOneMagicDNSQuery(t *testing.T, gw *gatewayState, r magicDNSResolved, query []byte) []byte {
	t.Helper()
	// Server 端 conn(handleMagicDNSPacket 用它 WriteToUDP);Client 端 conn 模拟"客户端"读响应。
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cliAddr := cli.LocalAddr().(*net.UDPAddr)

	handleMagicDNSPacket(t.Context(), gw, srv, cliAddr, query, r)

	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	return buf[:n]
}

func newMagicDNSGateway(t *testing.T) *gatewayState {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "magic.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return &gatewayState{store: st, cfg: &config.Config{}}
}

func seedDevice(t *testing.T, st *store.Store, username, deviceName, vipV4, vipV6 string) {
	t.Helper()
	ctx := t.Context()
	u, err := st.CreateUser(ctx, store.NewUser{Username: username, PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := st.UpsertDevice(ctx, u.ID, "uuid-"+username, deviceName, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertLease(ctx, d.ID, vipV4, vipV6, false); err != nil {
		t.Fatal(err)
	}
}

// tests --------------------------------------------------------------

// TestMagicNameDeniedByMeshOff 锁住「组网 OFF 时跨用户 magic 名 NXDOMAIN」的口径(2026-07-19):
//   - mesh OFF + 跨用户 → 拦;同用户 → 放;
//   - 目标 user 不存在 / 查询方 vIP 无归属 → fail-open 放行(交正常路径处理);
//   - mesh ON → 一律放行。
func TestMagicNameDeniedByMeshOff(t *testing.T) {
	ctx := t.Context()
	gw := newMagicDNSGateway(t)

	alice, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.store.CreateUser(ctx, store.NewUser{Username: "bob", PSKHash: "h"}); err != nil {
		t.Fatal(err)
	}

	// 查询方 = alice 的设备 vIP(与数据面同一张归属表)。
	aliceVIP := netip.MustParseAddr("10.99.0.2")
	registerVIPOwners([]netip.Addr{aliceVIP}, alice.ID, 1)
	t.Cleanup(func() { unregisterVIPOwners([]netip.Addr{aliceVIP}, 1) })

	// 快照替换为 mesh OFF;结束后恢复原快照,不污染其它测试。
	oldSnap := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(oldSnap) })
	aclCurrent.Store(&aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: false})

	alicePeer := &net.UDPAddr{IP: net.ParseIP("10.99.0.2"), Port: 5555}
	strangerPeer := &net.UDPAddr{IP: net.ParseIP("10.99.0.77"), Port: 5555} // 无归属

	if !magicNameDeniedByMeshOff(ctx, gw, alicePeer, "pi.bob.lan", "lan") {
		t.Error("mesh OFF + 跨用户(alice 查 bob 的名)应被拦")
	}
	if magicNameDeniedByMeshOff(ctx, gw, alicePeer, "mac.alice.lan", "lan") {
		t.Error("mesh OFF + 同用户应放行")
	}
	if magicNameDeniedByMeshOff(ctx, gw, alicePeer, "x.nobody.lan", "lan") {
		t.Error("目标 user 不存在应 fail-open 放行(交正常路径回 NXDOMAIN)")
	}
	if magicNameDeniedByMeshOff(ctx, gw, strangerPeer, "pi.bob.lan", "lan") {
		t.Error("查询方 vIP 无归属应 fail-open 放行")
	}

	aclCurrent.Store(&aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: true})
	if magicNameDeniedByMeshOff(ctx, gw, alicePeer, "pi.bob.lan", "lan") {
		t.Error("mesh ON 时不应拦任何名字")
	}
}

func TestParseMagicHostname(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		suffix   string
		wantHost string
		wantUser string
		wantOK   bool
	}{
		{"正常", "mac.alice.lan", "lan", "mac", "alice", true},
		{"段数=2(缺 user)", "alice.lan", "lan", "", "", false},
		{"段数=4", "a.b.c.lan", "lan", "", "", false},
		{"空 host", ".alice.lan", "lan", "", "", false},
		{"自定义 suffix", "phone.bob.internal", "internal", "phone", "bob", true},
		{"等于 suffix", "lan", "lan", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, u, ok := parseMagicHostname(c.in, c.suffix)
			if ok != c.wantOK || h != c.wantHost || u != c.wantUser {
				t.Fatalf("got (%q,%q,%v), want (%q,%q,%v)",
					h, u, ok, c.wantHost, c.wantUser, c.wantOK)
			}
		})
	}
}

func TestNormalizeMagicHost(t *testing.T) {
	cases := map[string]string{
		"Alice's MacBook":  "alice-s-macbook",
		"  TRIM space  ":   "trim-space",
		"weird_underscore": "weird-underscore",
		"中文设备":             "", // 多字节字符全被替换成 -,折叠 + trim 后归零
		"---a---b---":      "a-b",
		"":                 "",
	}
	for in, want := range cases {
		if got := normalizeMagicHost(in); got != want {
			t.Errorf("normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMagicDNS_AnswersAForLeasedDevice(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "alice", "Alice MacBook", "100.64.0.5", "")
	r := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	r.suffix = "lan"

	q := buildDNSQuery(t, "alice-macbook.alice.lan", dnsmessage.TypeA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, answers := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v, want success", hdr.RCode)
	}
	if hdr.ID != 0x4242 {
		t.Fatalf("ID 不应被改写,got %#x", hdr.ID)
	}
	if len(answers) != 1 {
		t.Fatalf("expected 1 A answer, got %d", len(answers))
	}
	a, ok := answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer 不是 AResource: %T", answers[0].Body)
	}
	if got := netip.AddrFrom4(a.A).String(); got != "100.64.0.5" {
		t.Fatalf("vIP = %q, want 100.64.0.5", got)
	}
}

func TestMagicDNS_UnknownNameReturnsNXDOMAIN(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "alice", "mac", "100.64.0.5", "")
	r := magicDNSResolved{suffix: "lan", port: 5353}

	q := buildDNSQuery(t, "ghost.alice.lan", dnsmessage.TypeA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, _ := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("rcode = %v, want NXDOMAIN", hdr.RCode)
	}
}

// TestMagicDNS_MagicHostHTTPSReturnsNODATA：mesh 内网主机存在时，其 **HTTPS(非 A/AAAA)** 查询应本地回 NODATA
// （NOERROR + 0 answer），**不**外发公网上游（防内网名泄漏 + 防 NXDOMAIN 负缓存污染同名 A/AAAA）。这里 gateway 未配
// upstream —— 若实现误走 forward 路径会得到 SERVFAIL，据此反证「没外发、就地作答」。
func TestMagicDNS_MagicHostHTTPSReturnsNODATA(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "alice", "mac", "100.64.0.5", "")
	r := magicDNSResolved{suffix: "lan", port: 5353} // 无 upstream

	q := buildDNSQuery(t, "mac.alice.lan", dnsmessage.TypeHTTPS)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, answers := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("存在的 mesh 主机 HTTPS 应回 NODATA(NOERROR), got rcode=%v", hdr.RCode)
	}
	if hdr.ID != 0x4242 {
		t.Fatalf("ID 不应被改写, got %#x", hdr.ID)
	}
	if len(answers) != 0 {
		t.Fatalf("NODATA 应 0 answer, got %d", len(answers))
	}
}

// TestMagicDNS_MagicHostUnknownHTTPSReturnsNXDOMAIN：mesh 后缀但主机不存在时，非 A/AAAA 查询回 NXDOMAIN（本地作答，
// 不外发上游）。同样用「无 upstream 却不 SERVFAIL」反证没走 forward。
func TestMagicDNS_MagicHostUnknownHTTPSReturnsNXDOMAIN(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "alice", "mac", "100.64.0.5", "")
	r := magicDNSResolved{suffix: "lan", port: 5353} // 无 upstream

	q := buildDNSQuery(t, "ghost.alice.lan", dnsmessage.TypeHTTPS)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, _ := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("不存在的 mesh 主机 HTTPS 应回 NXDOMAIN, got rcode=%v", hdr.RCode)
	}
}

func TestMagicDNS_NonMagicNoUpstreamServfail(t *testing.T) {
	gw := newMagicDNSGateway(t)
	r := magicDNSResolved{suffix: "lan", port: 5353}

	q := buildDNSQuery(t, "google.com", dnsmessage.TypeA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, _ := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode = %v, want SERVFAIL", hdr.RCode)
	}
}

func TestMagicDNS_AAAAForDeviceWithIPv6Only(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "bob", "phone", "", "fd00:200::42")
	r := magicDNSResolved{suffix: "lan", port: 5353}

	q := buildDNSQuery(t, "phone.bob.lan", dnsmessage.TypeAAAA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, answers := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v, want success", hdr.RCode)
	}
	if len(answers) != 1 {
		t.Fatalf("expected 1 AAAA answer, got %d", len(answers))
	}
	aaaa, ok := answers[0].Body.(*dnsmessage.AAAAResource)
	if !ok {
		t.Fatalf("answer 不是 AAAAResource: %T", answers[0].Body)
	}
	got := netip.AddrFrom16(aaaa.AAAA).String()
	if !strings.EqualFold(got, "fd00:200::42") {
		t.Fatalf("vIP = %q, want fd00:200::42", got)
	}
}

func TestMagicDNSExtraDNS_GatedByEnabled(t *testing.T) {
	gw := &gatewayState{cfg: newMagicDNSCfg(false)}
	if got := magicDNSExtraDNS(gw, "100.64.0.1"); got != "" {
		t.Fatalf("disabled 不应返回 extra DNS,got %q", got)
	}
	gw.cfg = newMagicDNSCfg(true)
	if got := magicDNSExtraDNS(gw, "100.64.0.1"); got != "100.64.0.1" {
		t.Fatalf("enabled+ip 应返回 ip,got %q", got)
	}
	if got := magicDNSExtraDNS(gw, "  "); got != "" {
		t.Fatalf("空 ip 应返回空,got %q", got)
	}
	if got := magicDNSExtraDNS(gw, "not-an-ip"); got != "" {
		t.Fatalf("非法 ip 应返回空,got %q", got)
	}
}

// A1 修复:listen_port != 53 时,magicDNSExtraDNS 必须返回空(避免把客户端 DNS
// 指到一个查不到任何东西的 IP)。这里 reset 一下 once,然后跑两遍,确认行为稳定。
func TestMagicDNSExtraDNS_NonStandardPortSkipsPrepend(t *testing.T) {
	cfg := newMagicDNSCfg(true)
	cfg.Server.MagicDNS.ListenPort = 5353
	gw := &gatewayState{cfg: cfg}
	if got := magicDNSExtraDNS(gw, "100.64.0.1"); got != "" {
		t.Fatalf("non-standard port 应跳过 prepend,got %q", got)
	}
	// 再调一次走 once 已 Do 过的分支,仍应返回空。
	if got := magicDNSExtraDNS(gw, "100.64.0.1"); got != "" {
		t.Fatalf("第二次调用仍应跳过 prepend,got %q", got)
	}
}

func TestMagicDNSExtraDNS_DefaultPortIs53(t *testing.T) {
	// ListenPort 留 0,经 resolveMagicDNSConfig 后应等于 53,然后 prepend 生效。
	gw := &gatewayState{cfg: newMagicDNSCfg(true)}
	if got := magicDNSExtraDNS(gw, "100.64.0.1"); got != "100.64.0.1" {
		t.Fatalf("port 默认 = 53 时应 prepend,got %q", got)
	}
}

func TestResolveMagicDNSConfig_PortDefault53(t *testing.T) {
	r := resolveMagicDNSConfig(config.MagicDNSConfig{Enabled: true})
	if r.port != 53 {
		t.Fatalf("默认 port = %d, want 53", r.port)
	}
}

// F1:in-flight 上限触顶时新 query 走 drop 计数,不阻塞;
// 不验证 UDP 真实读循环(那需要起真 socket),直接验证 semaphore 行为。
func TestMagicDNSInflight_DropOnSaturation(t *testing.T) {
	// 先把信号量灌满 cap。
	for i := 0; i < magicDNSInflightCap; i++ {
		magicDNSInflight <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < magicDNSInflightCap; i++ {
			<-magicDNSInflight
		}
	})

	before := magicDNSInflightDropCount.Load()
	// 模拟主 read loop 的非阻塞 send:select default → 计数 + drop。
	select {
	case magicDNSInflight <- struct{}{}:
		t.Fatal("信号量已满,应进 default 分支 drop")
	default:
		magicDNSInflightDropCount.Add(1)
	}
	if got := magicDNSInflightDropCount.Load(); got != before+1 {
		t.Fatalf("drop count 未自增, before=%d after=%d", before, got)
	}
}

// 每客户端在途上限：单个客户端最多占 magicDNSPerClientCap 个位，超出丢它自己的；关键是**不影响别的客户端**
// （公平隔离）——验证「一个用户猛刷拖垮所有人」的老缺陷已被修掉。
func TestMagicDNS_PerClientCapIsolatesClients(t *testing.T) {
	clientA := netip.MustParseAddr("100.64.0.5")
	clientB := netip.MustParseAddr("100.64.0.6")

	dropBefore := magicDNSPerClientDropCount.Load()

	// clientA 占满自己的每客户端上限。
	releases := make([]func(), 0, magicDNSPerClientCap)
	for i := 0; i < magicDNSPerClientCap; i++ {
		rel, ok := tryAcquireMagicDNSSlot(clientA, true)
		if !ok {
			t.Fatalf("clientA 第 %d 个应成功（未到上限）", i)
		}
		releases = append(releases, rel)
	}
	t.Cleanup(func() {
		for _, r := range releases {
			r()
		}
	})

	// clientA 再来一个 → 超自己上限 → 拒绝 + per-client drop +1。
	if _, ok := tryAcquireMagicDNSSlot(clientA, true); ok {
		t.Fatal("clientA 超每客户端上限应被拒")
	}
	if got := magicDNSPerClientDropCount.Load(); got != dropBefore+1 {
		t.Fatalf("per-client drop 应 +1，before=%d after=%d", dropBefore, got)
	}

	// 关键断言：clientB 不受 clientA 刷满的影响，仍能拿到位（公平隔离）。
	relB, ok := tryAcquireMagicDNSSlot(clientB, true)
	if !ok {
		t.Fatal("clientB 应不受 clientA 占满影响，仍能获得位")
	}
	relB()
}

// ————————————————————— SR-VIA6：MagicDNS 4via6 解析 —————————————————————

func TestParseVia6Hostname(t *testing.T) {
	cases := []struct {
		in, suffix, wantV4 string
		wantSite           uint16
		wantOK             bool
	}{
		{"192-168-1-10via7.lan", "lan", "192.168.1.10", 7, true},         // Tailscale 式：<v4-dashed>via<siteID>
		{"10-0-5-20via123.internal", "internal", "10.0.5.20", 123, true}, // 另一后缀
		{"192-168-1-10-via-7.lan", "lan", "192.168.1.10", 7, true},       // 可读变体 -via-
		{"mac.alice.lan", "lan", "", 0, false},                           // 多段：普通设备查询，非 4via6
		{"192-168-1-10.homerouter.alice.lan", "lan", "", 0, false},       // 旧式 <v4>.<dev>.<user> 不再支持（多段）
		{"a-b-c-dvia7.lan", "lan", "", 0, false},                         // 首段非合法 v4
		{"192-168-1-10via0.lan", "lan", "", 0, false},                    // siteID 0 非法（AUTOINCREMENT 从 1 起）
		{"192-168-1-10via.lan", "lan", "", 0, false},                     // 缺 siteID
		{"via7.lan", "lan", "", 0, false},                                // 缺 v4
	}
	for _, c := range cases {
		v4, site, ok := parseVia6Hostname(c.in, c.suffix)
		if ok != c.wantOK {
			t.Fatalf("%s: ok=%v want %v", c.in, ok, c.wantOK)
		}
		if ok && (v4.String() != c.wantV4 || site != c.wantSite) {
			t.Fatalf("%s: got (%s, site=%d) want (%s, site=%d)", c.in, v4, site, c.wantV4, c.wantSite)
		}
	}
}

// 端到端：AAAA 查询 <v4-dashed>.<宣告方设备>.<user>.<suffix> → 返回 encode4via6(siteID, v4)。
func TestMagicDNS_Answers4via6ForAdvertiserSite(t *testing.T) {
	gw := newMagicDNSGateway(t)
	ctx := t.Context()
	u, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := gw.store.UpsertDevice(ctx, u.ID, "uuid-alice", "homerouter", "test")
	if err != nil {
		t.Fatal(err)
	}
	// 模拟 approve 后 rebuild 给宣告方分配了 siteID。
	sid, err := gw.store.GetOrAssignSiteID(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	// P3：MagicDNS 现在校验目标 v4 ∈ 宣告方已批准网段，故装一条 homerouter 宣告的 192.168.1.0/24 快照。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", d.ID)})

	r := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	r.suffix = "lan"

	q := buildDNSQuery(t, fmt.Sprintf("192-168-1-10via%d.lan", sid), dnsmessage.TypeAAAA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, answers := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v, want success", hdr.RCode)
	}
	if len(answers) != 1 {
		t.Fatalf("expected 1 AAAA answer, got %d", len(answers))
	}
	aaaa, ok := answers[0].Body.(*dnsmessage.AAAAResource)
	if !ok {
		t.Fatalf("answer 不是 AAAAResource: %T", answers[0].Body)
	}
	want, wok := encode4via6(sid, netip.MustParseAddr("192.168.1.10"))
	if !wok {
		t.Fatal("encode4via6 失败")
	}
	if got := netip.AddrFrom16(aaaa.AAAA); got != want {
		t.Fatalf("4via6 AAAA = %q, want %q", got, want)
	}
}

// P3：目标 v4 不在宣告方已批准网段内 → NameError（不返回数据面会 not-advertised 丢弃的 4via6）。
func TestMagicDNS_4via6OutsideAdvertisedNameError(t *testing.T) {
	gw := newMagicDNSGateway(t)
	ctx := t.Context()
	u, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := gw.store.UpsertDevice(ctx, u.ID, "uuid-alice", "homerouter", "test")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := gw.store.GetOrAssignSiteID(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	// homerouter 只宣告 192.168.1.0/24。
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", d.ID)})
	r := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	r.suffix = "lan"

	// 查 10.0.0.5（不在 192.168.1.0/24）→ NameError。
	q := buildDNSQuery(t, fmt.Sprintf("10-0-0-5via%d.lan", sid), dnsmessage.TypeAAAA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, _ := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("目标 v4 不在宣告网段应 NameError, got %v", hdr.RCode)
	}
}

// 未分配的 siteID 做 4via6 查询 → DeviceIDBySiteID 查不到 → NameError。
func TestMagicDNS_4via6UnknownSiteNameError(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "alice", "laptop", "100.64.0.5", "") // 普通设备，从未分配 siteID
	r := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	r.suffix = "lan"

	q := buildDNSQuery(t, "192-168-1-10via9999.lan", dnsmessage.TypeAAAA) // siteID 9999 未分配
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, _ := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("未分配 siteID 的 4via6 查询应 NameError, got %v", hdr.RCode)
	}
}
