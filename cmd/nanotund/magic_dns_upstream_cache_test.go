package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// resetUpstreamDNSCacheForTest 清空 server 本地上游应答缓存（全局，测试间隔离）。singleflight.Group 在每次
// Do 完成后自动忘记 key，无需重置。由 newMagicDNSGateway 统一调用。
func resetUpstreamDNSCacheForTest(t *testing.T) {
	t.Helper()
	upstreamDNSCacheMu.Lock()
	upstreamDNSCache = make(map[string]upstreamDNSCacheEntry)
	upstreamDNSCacheLastSweep = time.Time{}
	upstreamDNSCacheMu.Unlock()
}

// key 的地理维度：同名同类型的查询，只要 ECS 网段不同就必须是不同的 key —— 否则缓存会把 A 地区的
// 上游答案发给 B 地区的使用方，正是 ECS 要修的那个病被缓存重新引入。
func TestUpstreamDNSCacheKey_SeparatesByECSScope(t *testing.T) {
	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("www.baidu.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	cq := upstreamDNSCacheKey("123.146.195.0/24", q, 1232, false)
	sg := upstreamDNSCacheKey("13.212.0.0/24", q, 1232, false)
	if cq == sg {
		t.Fatalf("不同 ECS 网段必须是不同 key,got 同一个 %q", cq)
	}
	// 同网段同问题必须稳定命中同一 key（否则缓存永远不命中，等于没做）。
	if again := upstreamDNSCacheKey("123.146.195.0/24", q, 1232, false); again != cq {
		t.Fatalf("同输入应得同 key: %q vs %q", cq, again)
	}
}

// key 还必须区分「影响应答形态」的 EDNS 参数：缓冲区大小决定上游裁剪后的应答长度，DO 位决定有无 DNSSEC 记录。
// 混用会把超出对方缓冲区的大包发过去（被丢），或给要验签的使用方一份没有 RRSIG 的答案。
func TestUpstreamDNSCacheKey_SeparatesByEDNSBufferAndDOBit(t *testing.T) {
	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	base := upstreamDNSCacheKey("", q, 1232, false)
	if k := upstreamDNSCacheKey("", q, 4096, false); k == base {
		t.Fatal("EDNS 缓冲区不同必须换 key")
	}
	if k := upstreamDNSCacheKey("", q, 1232, true); k == base {
		t.Fatal("DO 位不同必须换 key")
	}
}

// 自带 ECS 的查询不可缓存：那份答案取决于客户端给的网段，而 key 只反映我们注入的网段。
func TestUpstreamDNSCacheKeyFor_RefusesQueriesCarryingTheirOwnECS(t *testing.T) {
	plain := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
	if _, ok := upstreamDNSCacheKeyFor(plain, "1.2.3.0/24"); !ok {
		t.Fatal("普通查询应可缓存")
	}
	withECS, injected := injectECS(plain, netip.MustParseAddr("203.0.113.7"))
	if !injected {
		t.Fatal("injectECS 应成功,测试前提不成立")
	}
	if _, ok := upstreamDNSCacheKeyFor(withECS, "1.2.3.0/24"); ok {
		t.Fatal("查询自带 ECS 时必须判为不可缓存")
	}
}

// 解不开 / 无 question 的查询同样不可缓存（调用方据此走原路径，行为与加缓存前一致）。
func TestUpstreamDNSCacheKeyFor_RefusesUnparsableQueries(t *testing.T) {
	for name, q := range map[string][]byte{
		"空报文":    {},
		"截断头":    {0x42},
		"只有头无问题": {0x42, 0x42, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0},
	} {
		if _, ok := upstreamDNSCacheKeyFor(q, ""); ok {
			t.Fatalf("%s 应判为不可缓存", name)
		}
	}
}

// SERVFAIL / REFUSED 这类软失败不进缓存：缓存下来会把一次上游抖动放大成一段时间的硬失败。
func TestBuildUpstreamDNSCacheEntry_SkipsSoftFailures(t *testing.T) {
	for _, rc := range []dnsmessage.RCode{
		dnsmessage.RCodeServerFailure,
		dnsmessage.RCodeRefused,
		dnsmessage.RCodeNotImplemented,
	} {
		if _, ok := buildUpstreamDNSCacheEntry(dnsAnswer(t, rc)); ok {
			t.Fatalf("rcode=%v 不该进缓存", rc)
		}
	}
	// NOERROR / NXDOMAIN 是确定性答复,必须可缓存。
	if _, ok := buildUpstreamDNSCacheEntry(buildDNSResponseA(t, "example.com", 60, "203.0.113.5")); !ok {
		t.Fatal("NOERROR 有答复应可缓存")
	}
	if _, ok := buildUpstreamDNSCacheEntry(dnsAnswer(t, dnsmessage.RCodeNameError)); !ok {
		t.Fatal("NXDOMAIN 应可缓存(负缓存)")
	}
}

// 正缓存 TTL 必须夹在 [min,max]:上游给 1s 不能让缓存 1s 就失效(等于没缓存),给 30 天也不能一直不收敛。
func TestBuildUpstreamDNSCacheEntry_ClampsTTLIntoRange(t *testing.T) {
	tiny, ok := buildUpstreamDNSCacheEntry(buildDNSResponseA(t, "a.example.com", 1, "203.0.113.5"))
	if !ok {
		t.Fatal("应可缓存")
	}
	if d := time.Until(tiny.expires); d < upstreamDNSCacheMinTTL-time.Second {
		t.Fatalf("TTL=1s 应被抬到 min(%v),实际剩余 %v", upstreamDNSCacheMinTTL, d)
	}
	huge, ok := buildUpstreamDNSCacheEntry(buildDNSResponseA(t, "b.example.com", 86400*30, "203.0.113.5"))
	if !ok {
		t.Fatal("应可缓存")
	}
	if d := time.Until(huge.expires); d > upstreamDNSCacheMaxTTL+time.Second {
		t.Fatalf("超大 TTL 应被压到 max(%v),实际剩余 %v", upstreamDNSCacheMaxTTL, d)
	}
}

// 命中时把 TTL 钳到「本条缓存的剩余寿命」：否则一条 TTL=300 的应答在缓存里躺了 299s 后仍宣称 300s，
// 使用方侧的实际有效期被放大到近两倍。
func TestUpstreamDNSCacheServeTTL_ShrinksWithRemainingLifetime(t *testing.T) {
	e := upstreamDNSCacheEntry{expires: time.Now().Add(42 * time.Second)}
	if got := upstreamDNSCacheServeTTL(e, false); got > 42 || got < 41 {
		t.Fatalf("应约等于剩余寿命 42s,got %d", got)
	}
	// 早期竞速窗口内取更小值。
	if got := upstreamDNSCacheServeTTL(e, true); got != magicDNSEarlyClampTTL {
		t.Fatalf("早期窗口应钳到 %d,got %d", magicDNSEarlyClampTTL, got)
	}
	// 已到期/即将到期时不能回 0（0 会让使用方完全不缓存、每次都回源）。
	stale := upstreamDNSCacheEntry{expires: time.Now().Add(-time.Minute)}
	if got := upstreamDNSCacheServeTTL(stale, false); got != 1 {
		t.Fatalf("剩余不足 1s 应回 1,got %d", got)
	}
}

// 条目上限：到顶且没有可清理的过期项时，本次不缓存（宁可放弃一次加速，也不无界占内存）。
func TestUpstreamDNSCachePut_StopsAtTheEntryCap(t *testing.T) {
	resetUpstreamDNSCacheForTest(t)
	t.Cleanup(func() { resetUpstreamDNSCacheForTest(t) })
	live := upstreamDNSCacheEntry{raw: []byte{0}, expires: time.Now().Add(time.Hour)}
	upstreamDNSCacheMu.Lock()
	for i := 0; i < upstreamDNSCacheMaxEntries; i++ {
		upstreamDNSCache["k"+string(rune(i%1000))+string(rune(i/1000))] = live
	}
	n := len(upstreamDNSCache)
	upstreamDNSCacheMu.Unlock()
	if n < upstreamDNSCacheMaxEntries {
		t.Skipf("造满缓存失败(key 碰撞),实际 %d 条,跳过", n)
	}
	upstreamDNSCachePut("overflow-key", live)
	if _, ok := upstreamDNSCacheGet("overflow-key"); ok {
		t.Fatal("到顶后不应再写入新条目")
	}
}

// 过期条目当未命中（不在读锁下删，交给惰性清扫）。
func TestUpstreamDNSCacheGet_TreatsExpiredAsMiss(t *testing.T) {
	resetUpstreamDNSCacheForTest(t)
	t.Cleanup(func() { resetUpstreamDNSCacheForTest(t) })
	upstreamDNSCachePut("expired", upstreamDNSCacheEntry{raw: []byte{0}, expires: time.Now().Add(-time.Second)})
	if _, ok := upstreamDNSCacheGet("expired"); ok {
		t.Fatal("过期条目必须当未命中")
	}
}

// ecsScopeForPeer 与实际注入共用 ecsClientIPForPeer：查不到会话时返回 ""（一个自洽的隔离维度值），
// 而不是 panic 或半个前缀。
func TestECSScopeForPeer_EmptyWhenNoSession(t *testing.T) {
	peer := &net.UDPAddr{IP: net.ParseIP("10.201.0.99"), Port: 5353}
	if got := ecsScopeForPeer(peer); got != "" {
		t.Fatalf("查不到会话应回空串,got %q", got)
	}
}

// 端到端：第二次同样的查询必须由缓存作答 —— 不再回源上游（这就是本轮要的加速），且应答对使用方仍合法
// （txn id 回带、答案不丢），TTL 收敛到缓存剩余寿命而非原样的大 TTL。
func TestForwardMagicDNSToUpstream_SecondIdenticalQueryIsServedFromCache(t *testing.T) {
	const upstreamTTL = 3600
	resetConnByDeviceForTest(t)
	resetUpstreamDNSCacheForTest(t)
	t.Cleanup(func() { resetUpstreamDNSCacheForTest(t) })

	up, hits := startFakeUpstream(t, func(query []byte) [][]byte {
		return [][]byte{buildDNSResponseATTL(t, dnsQueryName(t, query), upstreamTTL, "93.184.216.34")}
	})
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	peer := cli.LocalAddr().(*net.UDPAddr)
	// 会话年龄跨过早期竞速窗口，排除 magicDNSEarlyClampTTL 干扰，让 TTL 差异只由缓存造成。
	registerFreshClientConn(t, peer.IP.String(), magicDNSEarlyClampWindow+time.Second)

	r := magicDNSResolved{upstream: []string{up}}
	query := buildDNSQuery(t, "cached.example.com", dnsmessage.TypeA)

	forwardMagicDNSToUpstream(t.Context(), srv, peer, query, r)
	firstTTL := readbackFirstAnswerTTL(t, cli)
	if hits.Load() != 1 {
		t.Fatalf("第一次应回源一次,实际 %d", hits.Load())
	}
	if firstTTL != upstreamTTL {
		t.Fatalf("第一次应原样透传上游 TTL,got %d want %d", firstTTL, upstreamTTL)
	}

	beforeHit := magicDNSUpstreamCacheHitCount.Load()
	forwardMagicDNSToUpstream(t.Context(), srv, peer, query, r)
	secondTTL := readbackFirstAnswerTTL(t, cli)
	if got := hits.Load(); got != 1 {
		t.Fatalf("第二次必须由缓存作答、不再回源,上游却被查了 %d 次", got)
	}
	if magicDNSUpstreamCacheHitCount.Load() != beforeHit+1 {
		t.Error("命中缓存却没记 magicDNSUpstreamCacheHitCount")
	}
	if secondTTL == 0 || secondTTL > upstreamDNSCacheMaxTTLSeconds() {
		t.Fatalf("命中应把 TTL 收敛到缓存剩余寿命(≤%d),got %d", upstreamDNSCacheMaxTTLSeconds(), secondTTL)
	}
}

// upstreamDNSCacheMaxTTLSeconds 把 upstreamDNSCacheMaxTTL 换成秒，供断言用。
func upstreamDNSCacheMaxTTLSeconds() uint32 {
	return uint32(upstreamDNSCacheMaxTTL / time.Second)
}
