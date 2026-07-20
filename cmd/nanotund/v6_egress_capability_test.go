package main

// server 自身 v6 出网能力相关单测：
//   - isUsableV6EgressSrc（路由级探测源地址判据：GUA 且非 2001:db8::/32 文档段）
//   - shouldStripAAAAForServerSelf（server 自出口 MagicDNS 剥 AAAA 纯决策）
//   - dnsV6ServersForClient（无 v6 出网时下发 DNS 的公网 v6 解析器剔除）
//   - v6SetupRetry 补装钩子（失败保留、成功撤钩）
//   - handleMagicDNSPacket 的 server 自出口 AAAA strip 分支（端到端，含 mesh AAAA 不受影响的反证）

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// withServerV6EgressState 临时设置 server v6 出网探测状态，测试结束恢复。
func withServerV6EgressState(t *testing.T, known, has bool) {
	t.Helper()
	prevKnown := serverV6EgressKnown.Swap(known)
	prevHas := serverV6EgressHas.Swap(has)
	t.Cleanup(func() {
		serverV6EgressKnown.Store(prevKnown)
		serverV6EgressHas.Store(prevHas)
	})
}

func TestIsUsableV6EgressSrc(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"2001:19f0:4400:2af6::1", true}, // 真 GUA
		{"2600:3c0e::1", true},           // 真 GUA
		{"2001:db8:1::5", false},         // RFC3849 文档段（家用路由器假 v6 实测段）→ 不算
		{"fd00:200::3", false},           // ULA
		{"fe80::1", false},               // link-local
		{"::1", false},                   // loopback
		{"::ffff:1.2.3.4", false},        // v4-mapped
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.addr)
		if got := isUsableV6EgressSrc(a); got != c.want {
			t.Errorf("isUsableV6EgressSrc(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestShouldStripAAAAForServerSelf(t *testing.T) {
	cases := []struct {
		qtype dnsmessage.Type
		known bool
		has   bool
		want  bool
	}{
		{dnsmessage.TypeAAAA, true, false, true},   // 已探明无 v6 + AAAA → 剥
		{dnsmessage.TypeAAAA, true, true, false},   // 有 v6 → 不剥
		{dnsmessage.TypeAAAA, false, false, false}, // 未探明 → 保守不剥
		{dnsmessage.TypeA, true, false, false},     // 非 AAAA → 不剥
	}
	for _, c := range cases {
		if got := shouldStripAAAAForServerSelf(c.qtype, c.known, c.has); got != c.want {
			t.Errorf("shouldStripAAAAForServerSelf(%v,known=%v,has=%v) = %v, want %v",
				c.qtype, c.known, c.has, got, c.want)
		}
	}
}

func TestDnsV6ServersForClient(t *testing.T) {
	in := []string{"2001:4860:4860::8888", "fd00:200::53", "2606:4700:4700::1111"}

	t.Run("无v6出网剔除公网解析器保留ULA", func(t *testing.T) {
		withServerV6EgressState(t, true, false)
		got := dnsV6ServersForClient(in)
		if len(got) != 1 || got[0] != "fd00:200::53" {
			t.Fatalf("应只剩 ULA 解析器, got %v", got)
		}
	})
	t.Run("无v6出网且全为公网解析器返回nil", func(t *testing.T) {
		withServerV6EgressState(t, true, false)
		if got := dnsV6ServersForClient([]string{"2001:4860:4860::8888"}); got != nil {
			t.Fatalf("全公网 + 无 v6 应返回 nil, got %v", got)
		}
	})
	t.Run("有v6出网原样返回", func(t *testing.T) {
		withServerV6EgressState(t, true, true)
		got := dnsV6ServersForClient(in)
		if len(got) != len(in) {
			t.Fatalf("有 v6 应原样返回, got %v", got)
		}
	})
	t.Run("未探明原样返回", func(t *testing.T) {
		withServerV6EgressState(t, false, false)
		got := dnsV6ServersForClient(in)
		if len(got) != len(in) {
			t.Fatalf("未探明应保守原样返回, got %v", got)
		}
	})
}

func TestV6SetupRetryHook(t *testing.T) {
	// 保存/恢复全局钩子，避免污染其它测试。
	v6SetupRetryMu.Lock()
	prev := v6SetupRetryFn
	v6SetupRetryMu.Unlock()
	t.Cleanup(func() {
		v6SetupRetryMu.Lock()
		v6SetupRetryFn = prev
		v6SetupRetryMu.Unlock()
	})

	calls := 0
	ok := false
	armV6SetupRetry(func() bool {
		calls++
		return ok
	})

	// 失败 → 钩子保留（下轮再试）。
	runV6SetupRetryIfArmed()
	if calls != 1 {
		t.Fatalf("第一次应调用钩子, calls=%d", calls)
	}
	runV6SetupRetryIfArmed()
	if calls != 2 {
		t.Fatalf("失败后钩子应保留并再次调用, calls=%d", calls)
	}

	// 成功 → 撤钩，之后不再调用。
	ok = true
	runV6SetupRetryIfArmed()
	if calls != 3 {
		t.Fatalf("第三次应调用钩子, calls=%d", calls)
	}
	runV6SetupRetryIfArmed()
	if calls != 3 {
		t.Fatalf("成功后应撤钩不再调用, calls=%d", calls)
	}
}

// TestMagicDNS_ServerSelfNoV6StripsAAAA：server 自出口（会话未绑 peer 出口）+ 已探明无 v6 出网时，公网名的
// AAAA 查询应就地回 NODATA（NOERROR/0 answer）。gateway 未配 upstream —— 若实现误走 forward 路径会得到
// SERVFAIL，据此反证「在 upstream 之前就被 strip 分支拦下」。
func TestMagicDNS_ServerSelfNoV6StripsAAAA(t *testing.T) {
	withServerV6EgressState(t, true, false)
	gw := newMagicDNSGateway(t)
	r := magicDNSResolved{suffix: "lan", port: 5353} // 无 upstream

	stripBefore := magicDNSServerAAAAStripCount.Load()
	q := buildDNSQuery(t, "example.com", dnsmessage.TypeAAAA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, answers := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("应回 NODATA(NOERROR), got rcode=%v", hdr.RCode)
	}
	if hdr.ID != 0x4242 {
		t.Fatalf("ID 不应被改写, got %#x", hdr.ID)
	}
	if len(answers) != 0 {
		t.Fatalf("NODATA 应 0 answer, got %d", len(answers))
	}
	if got := magicDNSServerAAAAStripCount.Load(); got != stripBefore+1 {
		t.Fatalf("server strip 计数应 +1, before=%d after=%d", stripBefore, got)
	}
}

// TestMagicDNS_ServerSelfHasV6NotStripped：有 v6 出网时 AAAA 不剥，照走 upstream 路径（无 upstream → SERVFAIL）。
func TestMagicDNS_ServerSelfHasV6NotStripped(t *testing.T) {
	withServerV6EgressState(t, true, true)
	gw := newMagicDNSGateway(t)
	r := magicDNSResolved{suffix: "lan", port: 5353}

	stripBefore := magicDNSServerAAAAStripCount.Load()
	q := buildDNSQuery(t, "example.com", dnsmessage.TypeAAAA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, _ := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("有 v6 不应剥, 无 upstream 应 SERVFAIL, got rcode=%v", hdr.RCode)
	}
	if got := magicDNSServerAAAAStripCount.Load(); got != stripBefore {
		t.Fatalf("strip 计数不应变化, before=%d after=%d", stripBefore, got)
	}
}

// TestMagicDNS_ServerSelfNoV6ADoesNotStrip：无 v6 出网时 A 查询不受影响（照走 upstream → 无 upstream SERVFAIL）。
func TestMagicDNS_ServerSelfNoV6ADoesNotStrip(t *testing.T) {
	withServerV6EgressState(t, true, false)
	gw := newMagicDNSGateway(t)
	r := magicDNSResolved{suffix: "lan", port: 5353}

	q := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, _ := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("A 查询不应被剥, 无 upstream 应 SERVFAIL, got rcode=%v", hdr.RCode)
	}
}

// TestMagicDNS_ServerSelfNoV6MeshAAAAUnaffected：无 v6 出网时 mesh 名（vIP AAAA）不受剥离影响——
// magic 分支在 strip 之前作答（mesh v6 vIP 是 ULA 段内部互访，与公网 v6 出网能力无关）。
func TestMagicDNS_ServerSelfNoV6MeshAAAAUnaffected(t *testing.T) {
	withServerV6EgressState(t, true, false)
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "bob", "phone", "", "fd00:200::42")
	r := magicDNSResolved{suffix: "lan", port: 5353}

	q := buildDNSQuery(t, "phone.bob.lan", dnsmessage.TypeAAAA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, answers := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("mesh AAAA 应正常作答, got rcode=%v", hdr.RCode)
	}
	if len(answers) != 1 {
		t.Fatalf("mesh AAAA 应有 1 answer, got %d", len(answers))
	}
}
