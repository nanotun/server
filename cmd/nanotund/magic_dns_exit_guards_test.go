package main

// 经出口解析这条链路的拒绝面 —— 重点是**共享缓存的投毒面**。
//
// exitDNSCache 是按 (出口 deviceID, qtype, 归一 qname) 分键的**全局**表:同一出口上所有客户端
// 共享一条缓存项。所以「一份被投毒的应答被写进去」的影响不是一次查询,而是该出口上所有人
// 在 TTL 内都拿到那个错答案。这条链路上有三道相关的闸:
//
//   1. 出口回包必须与在途查询完整匹配(Response 位 + TXID + question),不只 TXID —— 受损或
//      恶意出口能回一份 TXID 相符、question 是另一个域名的合法应答;
//   2. 截获路径只收「查询被投递到的那条出口会话」的包 —— src=:53 是攻击者可控的,不足为凭;
//   3. 就地改写(buildRawDNSResponseFor)前必须确认 question 段线格等长 —— 否则覆写会越过
//      question 末尾写进答复区,把污染直接吐给客户端。
//
// 另一半是 fail-closed 的方向:已绑定出口的会话,只要出口不可用就必须回 SERVFAIL,**绝不**
// 回退 server 本地上游。回退看着更可用,实际是把 server 地理的答案灌进客户端 OS 缓存 ——
// 而那个会话的公网流量本就被数据面丢弃,换出口之后这些答案还在继续误导它。

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/util"
)

// ------------------------------------------------------ 报文构造/解析的边界

// TestParseIPv4UDPForReturn_Boundaries 钉住回包解析的边界。判宽了会把非 DNS 流量当应答处理;
// 判窄了(比如不认带 IP 选项的头)会让一部分真应答被当普通包写进 TUN —— 客户端收到一个
// 源地址是伪装 resolver 的包,而等待者一直等到超时。
func TestParseIPv4UDPForReturn_Boundaries(t *testing.T) {
	good, ok := buildIPv4UDP(netip.MustParseAddr("10.0.0.1"), 40000,
		netip.MustParseAddr("8.8.8.8"), 53, []byte("hello"))
	if !ok {
		t.Fatal("前置条件:构包应当成功")
	}
	if _, _, sp, dp, pl, ok := parseIPv4UDPForReturn(good); !ok || sp != 40000 || dp != 53 || string(pl) != "hello" {
		t.Fatalf("合法包应解析出 (40000,53,\"hello\"), got (%d,%d,%q,ok=%v)", sp, dp, pl, ok)
	}

	t.Run("带 IP 选项的头(IHL>5)也要认", func(t *testing.T) {
		// 真实网络里 IHL=6 的包不常见但合法。按固定 20 字节偏移解析的实现会在这里取错端口。
		withOpts := make([]byte, 0, len(good)+4)
		withOpts = append(withOpts, good[:20]...)
		withOpts = append(withOpts, 0, 0, 0, 0) // 4 字节 NOP 选项
		withOpts = append(withOpts, good[20:]...)
		withOpts[0] = 0x46 // IHL=6
		binary.BigEndian.PutUint16(withOpts[2:4], uint16(len(withOpts)))
		if _, _, sp, dp, pl, ok := parseIPv4UDPForReturn(withOpts); !ok || sp != 40000 || dp != 53 || string(pl) != "hello" {
			t.Fatalf("IHL=6 的包应按选项长度取偏移, got (%d,%d,%q,ok=%v)", sp, dp, pl, ok)
		}
	})

	shorten := func(n int) []byte { return good[:n] }
	bad := map[string][]byte{
		"空包":           {},
		"不足 20 字节":     shorten(19),
		"版本号不是 4":      func() []byte { c := append([]byte(nil), good...); c[0] = 0x65; return c }(),
		"IHL 小于 5":     func() []byte { c := append([]byte(nil), good...); c[0] = 0x44; return c }(),
		"IHL 超出实际长度":   func() []byte { c := append([]byte(nil), good...); c[0] = 0x4f; return c }(),
		"协议不是 UDP":     func() []byte { c := append([]byte(nil), good...); c[9] = 6; return c }(),
		"UDP 长度小于 8":   func() []byte { c := append([]byte(nil), good...); binary.BigEndian.PutUint16(c[24:26], 7); return c }(),
		"UDP 长度超出实际字节": func() []byte { c := append([]byte(nil), good...); binary.BigEndian.PutUint16(c[24:26], 9999); return c }(),
		"UDP 头被截断":     shorten(24),
	}
	for name, pkt := range bad {
		t.Run(name, func(t *testing.T) {
			if _, _, _, _, _, ok := parseIPv4UDPForReturn(pkt); ok {
				t.Fatal("这种形状必须 ok=false")
			}
		})
	}
}

// TestBuildIPv4UDP_Refusals 非 v4 地址与超长载荷都要拒。超长那条尤其要紧:构出一个
// total length 字段回绕的包会被对端当成截断包或另一个长度,行为不可预期。
func TestBuildIPv4UDP_Refusals(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.1")
	v6 := netip.MustParseAddr("fd00::1")

	if _, ok := buildIPv4UDP(v6, 1, v4, 53, nil); ok {
		t.Fatal("源是 v6 应拒")
	}
	if _, ok := buildIPv4UDP(v4, 1, v6, 53, nil); ok {
		t.Fatal("目的是 v6 应拒")
	}
	if _, ok := buildIPv4UDP(v4, 1, v4, 53, make([]byte, 0xffff-28+1)); ok {
		t.Fatal("载荷超过 IPv4 总长上限应拒(否则 total length 字段回绕)")
	}
	// 边界:正好到上限要放行(判成 >= 会把最大包也拒掉)。
	if _, ok := buildIPv4UDP(v4, 1, v4, 53, make([]byte, 0xffff-28)); !ok {
		t.Fatal("正好 0xffff-28 的载荷应当放行")
	}
}

// ------------------------------------------------------ 就地改写的越界防护

// mkRawResp 造一份「question 是 name/qtype、答复区有 n 条 A 记录」的应答字节。
func mkRawResp(t *testing.T, qid uint16, name string, qtype dnsmessage.Type, ttl uint32, answers int) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: qid, Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < answers; i++ {
		if err := b.AResource(
			dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
			dnsmessage.AResource{A: [4]byte{1, 2, 3, byte(i + 1)}},
		); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// mkRawRespTTLs 同 mkRawResp,但每条答复各给一个 TTL —— 验「取最小」必须让它们不相等。
func mkRawRespTTLs(t *testing.T, qid uint16, name string, qtype dnsmessage.Type, ttls []uint32) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: qid, Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for i, ttl := range ttls {
		if err := b.AResource(
			dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
			dnsmessage.AResource{A: [4]byte{1, 2, 3, byte(i + 1)}},
		); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestDNSQuestionEnd_Boundaries 钉住 question 段末尾偏移的计算。这个函数错一个字节,
// buildRawDNSResponseFor 的原位覆写就会切进答复区 —— 客户端拿到一份 question 正确、
// 答案被踩坏的应答,而它看起来完全合法。
func TestDNSQuestionEnd_Boundaries(t *testing.T) {
	raw := mkRawResp(t, 1, "example.com.", dnsmessage.TypeA, 60, 1)
	// "example.com." 线格 = 7+1 + 3+1 + 1(根) = 13,加 12 头 + 4 (qtype/qclass) = 29。
	if got, ok := dnsQuestionEnd(raw); !ok || got != 29 {
		t.Fatalf("dnsQuestionEnd = %d(ok=%v), want 29", got, ok)
	}

	bad := map[string][]byte{
		"不足 12 字节的头": raw[:11],
		"qname 没有结束就到包尾": func() []byte {
			c := append([]byte(nil), raw[:20]...) // 截在标签中间
			return c
		}(),
		// 压缩指针这条要**够长**才有区分力:短包里去掉这道检查后,0xc0 会被当成长度 192、
		// 一步跨过包尾,照样落到「越界」那条 return false —— 两种实现结果相同,用例就白写了。
		// 这里给一个 220 字节的包,并让指针跳到的位置(12+1+192=205)恰好是 0 字节:
		// 缺了这道检查的实现会把它当合法根标签,返回一个 210 的**假**偏移。
		"question 段里有压缩指针": func() []byte {
			c := make([]byte, 220)
			copy(c, raw[:12])
			c[12], c[13] = 0xc0, 0x0c // 指向偏移 12 的压缩指针
			return c
		}(),
		"qtype/qclass 被截断": raw[:27],
	}
	for name, pkt := range bad {
		t.Run(name, func(t *testing.T) {
			if _, ok := dnsQuestionEnd(pkt); ok {
				t.Fatal("这种形状必须 ok=false —— 放过去会让后续原位覆写越界")
			}
		})
	}
}

// TestBuildRawDNSResponseFor_RewritesOnlyHeaderAndQuestion 钉住就地改写的三件事:
// txn id 换成当前查询的、question 段**逐字节**回显当前查询的(0x20 校验要看这个)、
// 答复区一个字节都不许动。
func TestBuildRawDNSResponseFor_RewritesOnlyHeaderAndQuestion(t *testing.T) {
	// 缓存里存的是一份 qid=0x1111、question 全小写的应答。
	cached := mkRawResp(t, 0x1111, "example.com.", dnsmessage.TypeHTTPS, 60, 2)
	// 当前查询用另一个 qid,且 question 做了 0x20 大小写随机化。
	query := buildDNSQueryFull(t, "ExAmPlE.CoM", dnsmessage.TypeHTTPS, dnsmessage.ClassINET)

	out := buildRawDNSResponseFor(query, 0x9999, cached)
	if out == nil {
		t.Fatal("等长的 question 应当改写成功")
	}
	if got := binary.BigEndian.Uint16(out[0:2]); got != 0x9999 {
		t.Fatalf("txn id = %#x, want 0x9999", got)
	}
	qEnd, ok := dnsQuestionEnd(query)
	if !ok {
		t.Fatal("查询的 question 段应当可解析")
	}
	// 0x20 校验是**大小写敏感的逐字节比对** —— 客户端只认自己发出去的那串字节。
	if string(out[12:qEnd]) != string(query[12:qEnd]) {
		t.Fatalf("question 段必须逐字节回显当前查询(0x20 校验),got %q want %q",
			out[12:qEnd], query[12:qEnd])
	}
	// 答复区必须原封不动。
	if string(out[qEnd:]) != string(cached[qEnd:]) {
		t.Fatal("答复区被改动了 —— 改写只该碰 header 的 id 与 question 段")
	}
	// 原缓存项不能被就地修改(它是共享的,多个 goroutine 并发读)。
	if binary.BigEndian.Uint16(cached[0:2]) != 0x1111 {
		t.Fatal("缓存里的原始应答被就地改了 —— 那是全 egress 共享的只读数据")
	}
}

// TestBuildRawDNSResponseFor_RefusesLengthMismatch 钉住那道越界防护:缓存项的 question
// 段与当前查询**线格不等长**时必须放弃(返回 nil → 调用方回 SERVFAIL),不能原位覆写。
//
// 这种缓存项确实构造得出来:摄取侧(parseRawDNSMeta)只跳过 question、不强制它与查询匹配,
// 所以一个坏/恶意出口回一份 question 是另一个域名的合法应答,照样会以本查询的 key 落缓存。
func TestBuildRawDNSResponseFor_RefusesLengthMismatch(t *testing.T) {
	query := buildDNSQueryFull(t, "example.com", dnsmessage.TypeHTTPS, dnsmessage.ClassINET)

	for name, cached := range map[string][]byte{
		"缓存项的 question 更短":  mkRawResp(t, 1, "a.io.", dnsmessage.TypeHTTPS, 60, 1),
		"缓存项的 question 更长":  mkRawResp(t, 1, "much.longer.example.com.", dnsmessage.TypeHTTPS, 60, 1),
		"缓存项短到装不下 question": mkRawResp(t, 1, "example.com.", dnsmessage.TypeHTTPS, 60, 0)[:14],
	} {
		t.Run(name, func(t *testing.T) {
			if out := buildRawDNSResponseFor(query, 7, cached); out != nil {
				t.Fatal("question 段不等长时必须返回 nil —— 原位覆写会越过 question 末尾踩进答复区")
			}
		})
	}

	// 查询本身解析不出 question 时也放弃。
	if out := buildRawDNSResponseFor([]byte{0x01, 0x02}, 7, mkRawResp(t, 1, "example.com.", dnsmessage.TypeA, 60, 1)); out != nil {
		t.Fatal("查询解析不出 question 时应返回 nil")
	}
}

// ------------------------------------------------------ 缓存的收纳规则

// withCleanExitDNSCache 清空共享缓存并在用完后还原 —— 这张表是包级全局的,不隔离会串味。
func withCleanExitDNSCache(t *testing.T) {
	t.Helper()
	exitDNSCacheMu.Lock()
	prev := exitDNSCache
	exitDNSCache = make(map[string]exitDNSCacheEntry)
	prevSweep := exitDNSCacheLastSweep
	exitDNSCacheMu.Unlock()
	t.Cleanup(func() {
		exitDNSCacheMu.Lock()
		exitDNSCache = prev
		exitDNSCacheLastSweep = prevSweep
		exitDNSCacheMu.Unlock()
	})
}

// TestExitDNSCachePut_SweepsExpiredAndRefusesWhenFull 钉住缓存的两条自保规则:
// 清扫过期项、满了就放弃缓存(而不是无界增长或踢掉有效项)。
//
// 「满了就放弃」这条方向要紧:这张表是全局的,无界增长的代价是 server 内存;而放弃一次
// 缓存只是少一次加速,下一条查询照样能经出口解析。
func TestExitDNSCachePut_SweepsExpiredAndRefusesWhenFull(t *testing.T) {
	withCleanExitDNSCache(t)

	// 塞满上限,全部都是**未过期**的项 → 清扫扫不掉任何东西 → 新项必须被放弃。
	fresh := exitDNSCacheEntry{rcode: dnsmessage.RCodeSuccess, expires: time.Now().Add(time.Hour)}
	for i := 0; i < exitDNSCacheMaxEntries; i++ {
		exitDNSCachePut(exitDNSCacheKey(int64(i), dnsmessage.TypeA, "x.example.com"), fresh)
	}
	exitDNSCacheMu.RLock()
	n := len(exitDNSCache)
	exitDNSCacheMu.RUnlock()
	if n != exitDNSCacheMaxEntries {
		t.Fatalf("前置条件:应正好装满 %d 条, got %d", exitDNSCacheMaxEntries, n)
	}

	overflowKey := exitDNSCacheKey(999999, dnsmessage.TypeA, "overflow.example.com")
	exitDNSCachePut(overflowKey, fresh)
	if _, hit := exitDNSCacheGet(overflowKey); hit {
		t.Fatal("满且无可清理时应放弃本次缓存,而不是继续增长")
	}
	exitDNSCacheMu.RLock()
	n = len(exitDNSCache)
	exitDNSCacheMu.RUnlock()
	if n > exitDNSCacheMaxEntries {
		t.Fatalf("条数超过上限(%d > %d)—— 无界增长", n, exitDNSCacheMaxEntries)
	}

	// 现在让表里全是过期项:下一次 put 的清扫应当腾出空间,新项进得来。
	exitDNSCacheMu.Lock()
	for k := range exitDNSCache {
		exitDNSCache[k] = exitDNSCacheEntry{expires: time.Now().Add(-time.Minute)}
	}
	exitDNSCacheLastSweep = time.Time{} // 强制这次 put 走清扫
	exitDNSCacheMu.Unlock()

	exitDNSCachePut(overflowKey, fresh)
	if _, hit := exitDNSCacheGet(overflowKey); !hit {
		t.Fatal("清扫掉过期项之后新项应当进得来,否则缓存会永久卡死在满状态")
	}
}

// TestExitDNSCacheGet_ExpiredCountsAsMiss 过期项当未命中 —— 返回它等于把一份过期答案
// 当权威结果回给客户端,而且因为不删,会一直返回到被覆盖为止。
func TestExitDNSCacheGet_ExpiredCountsAsMiss(t *testing.T) {
	withCleanExitDNSCache(t)
	key := exitDNSCacheKey(1, dnsmessage.TypeA, "stale.example.com")
	exitDNSCachePut(key, exitDNSCacheEntry{
		rcode: dnsmessage.RCodeSuccess, expires: time.Now().Add(-time.Second),
	})
	if _, hit := exitDNSCacheGet(key); hit {
		t.Fatal("已过期的项必须算未命中")
	}
	if _, hit := exitDNSCacheGet("从来没写过的 key"); hit {
		t.Fatal("没写过的 key 不该命中")
	}
}

// TestParseExitDNSResult_SkipsOtherRRsAndTakesMinTTL 钉住两件事:CNAME 之类的 RR 要跳过
// 而不是让整份应答解析失败,以及 TTL 取答复区**最小值**。
//
// 前者:真实的 CDN 应答几乎都是 CNAME 链 + A,把 CNAME 当解析失败等于「经出口解析对大部分
// 站点都失败」,然后 fail-closed 回 SERVFAIL —— 一个只在真实网络里才暴露的故障。
// 后者:取最大值会让短 TTL 的记录被缓存超期,那正是 DNS 轮转失效的经典原因。
func TestParseExitDNSResult_SkipsOtherRRsAndTakesMinTTL(t *testing.T) {
	name := dnsmessage.MustNewName("www.example.com.")
	cname := dnsmessage.MustNewName("cdn.example.net.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{
			{ // CNAME:必须跳过,不能当失败
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 900},
				Body:   &dnsmessage.CNAMEResource{CNAME: cname},
			},
			// TTL 刻意排成「最小值落在第二条 A 上」:同类型里有两条、且最小值不在 AAAA 上,
			// 这样 A 分支与 AAAA 分支各自的取最小比较都必须正确才能得到 45 —— 只放一条 A
			// 的话,A 分支写成取最大也照样会被后面 AAAA 分支的取最小掩盖过去。
			{
				Header: dnsmessage.ResourceHeader{Name: cname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: cname, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 45},
				Body:   &dnsmessage.AResource{A: [4]byte{1, 1, 1, 2}},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: cname, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 90},
				Body:   &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 15: 1}},
			},
		},
	}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	addrs, rcode, ttl, ok := parseExitDNSResult(raw)
	if !ok {
		t.Fatal("含 CNAME 的应答必须能解析 —— 真实 CDN 应答基本都是 CNAME 链 + A")
	}
	if rcode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v", rcode)
	}
	if len(addrs) != 3 {
		t.Fatalf("应抽出 3 个地址(2×A + AAAA), got %v", addrs)
	}
	if ttl != 45 {
		t.Fatalf("TTL 应取答复区最小值 45, got %d —— 取大了会让短 TTL 的记录被缓存超期", ttl)
	}

	// 坏报文:解析不出就是 ok=false(调用方据此 fail-closed,不缓存)。
	for _, junk := range [][]byte{nil, {}, {0xff, 0xee}, raw[:len(raw)-3]} {
		if _, _, _, ok := parseExitDNSResult(junk); ok {
			t.Fatalf("坏应答应 ok=false: %v", junk)
		}
	}
}

// TestParseRawDNSMeta_MinTTLAcrossAnyType 中继路径只抽 rcode 与最小 TTL,不解 rdata ——
// 所以它必须对 HTTPS/SVCB 这类本模块不认识的类型也工作。认不出就 ok=false 的话,
// HTTPS 中继会退化成「一律 SERVFAIL」。
func TestParseRawDNSMeta_MinTTLAcrossAnyType(t *testing.T) {
	// 用 A 记录冒充「任意类型」:parseRawDNSMeta 走的是 SkipAnswer,不看类型。
	raw := mkRawResp(t, 1, "example.com.", dnsmessage.TypeHTTPS, 120, 0)
	rcode, ttl, ok := parseRawDNSMeta(raw)
	if !ok {
		t.Fatal("0 answer 的应答也要能解析")
	}
	if rcode != dnsmessage.RCodeSuccess || ttl != 0 {
		t.Fatalf("NODATA 应给 (Success, ttl=0), got (%v,%d)", rcode, ttl)
	}
	// ttl=0 会被 buildRawExitDNSCacheEntry 归到负缓存 —— 钉住这条联动。
	e := buildRawExitDNSCacheEntry(raw, rcode, ttl)
	if d := time.Until(e.expires); d > exitDNSCacheNegTTL+time.Second {
		t.Fatalf("NODATA 应走负缓存 TTL(≤%v), got %v", exitDNSCacheNegTTL, d)
	}

	// 多条答复且 TTL **各不相同** —— 都给同一个值的话,取最大与取最小的实现结果一样,
	// 这条断言就废了。最小值刻意放中间,顺带排除「取最后一条」这种写法。
	multi := mkRawRespTTLs(t, 1, "example.com.", dnsmessage.TypeHTTPS, []uint32{300, 45, 90})
	if _, ttl, ok := parseRawDNSMeta(multi); !ok || ttl != 45 {
		t.Fatalf("多条答复应取最小 TTL 45, got %d(ok=%v)", ttl, ok)
	}
	for _, junk := range [][]byte{nil, {0x01}} {
		if _, _, ok := parseRawDNSMeta(junk); ok {
			t.Fatal("坏应答应 ok=false")
		}
	}
}

// TestBuildRawExitDNSCacheEntry_TTLClamp 原始应答缓存项的 TTL 夹取,与 A/AAAA 版同规则。
// 上界防的是「一份错答案被记很久」,下界防的是「TTL=1 的记录把缓存变成摆设」。
func TestBuildRawExitDNSCacheEntry_TTLClamp(t *testing.T) {
	raw := mkRawResp(t, 1, "example.com.", dnsmessage.TypeHTTPS, 1, 1)
	for _, tc := range []struct {
		name  string
		rcode dnsmessage.RCode
		ttl   uint32
		want  time.Duration
	}{
		{"上游 TTL 过小 → 夹到下界", dnsmessage.RCodeSuccess, 1, exitDNSCacheMinTTL},
		{"上游 TTL 过大 → 夹到上界", dnsmessage.RCodeSuccess, 86400, exitDNSCacheMaxTTL},
		{"NXDOMAIN → 负缓存", dnsmessage.RCodeNameError, 3600, exitDNSCacheNegTTL},
		{"Success 但 ttl=0(NODATA) → 负缓存", dnsmessage.RCodeSuccess, 0, exitDNSCacheNegTTL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := buildRawExitDNSCacheEntry(raw, tc.rcode, tc.ttl)
			d := time.Until(e.expires)
			if d > tc.want+time.Second || d < tc.want-time.Second {
				t.Fatalf("到期时长 = %v, want ≈%v", d, tc.want)
			}
			if e.rcode != tc.rcode {
				t.Fatalf("rcode 应原样保留, got %v", e.rcode)
			}
		})
	}
}

// ------------------------------------------------------ fail-closed 方向

// exitDNSUDPPair 起一对环回 UDP:srv 供被测代码写应答,cli 当「客户端」读。
func exitDNSUDPPair(t *testing.T) (*net.UDPConn, *net.UDPAddr, func() (dnsmessage.Header, bool)) {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	read := func() (dnsmessage.Header, bool) {
		_ = cli.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1500)
		n, _, err := cli.ReadFromUDP(buf)
		if err != nil {
			return dnsmessage.Header{}, false
		}
		var p dnsmessage.Parser
		hdr, perr := p.Start(buf[:n])
		if perr != nil {
			return dnsmessage.Header{}, false
		}
		return hdr, true
	}
	return srv, cli.LocalAddr().(*net.UDPAddr), read
}

// registerFailClosedConn 造一条「选了出口但兑现不了」的会话(egressDeviceID = 哨兵),
// 并把 peer 的 vIP 登记到它名下,好让 exitDeviceForClientVIP 找得到。
func registerFailClosedConn(t *testing.T, vip string, egress int64) {
	t.Helper()
	c := &Connection{userID: "u1", connIDStr: "fc-" + vip}
	c.egressDeviceID.Store(egress)
	ips := []util.VirtualIPAssignment{{VirtualIP: vip}}
	c.clientIPs.Store(&ips)
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, c.connIDStr)
		connIDMapMu.Unlock()
	})
}

// TestTryResolvePublicViaExit_FailClosedSentinelIsServfail 钉住那个哨兵的处置:
// egressDeviceID = egressFailClosed(选了出口但未批准 / 已撤销 / isolate 拒绝)时,
// 必须回 SERVFAIL 且返回 true,**不能**回退 server 本地上游。
//
// 回退看着更可用,实际是把 server 地理的答案灌进客户端 OS 缓存 —— 而这个会话的公网流量
// 本就被数据面就地丢弃,那些答案在它换出口之后还会继续误导它。这条与数据面的 fail-closed
// 必须同向。
func TestTryResolvePublicViaExit_FailClosedSentinelIsServfail(t *testing.T) {
	resetConnByDeviceForTest(t)
	srv, peer, read := exitDNSUDPPair(t)
	registerFailClosedConn(t, peer.IP.String(), egressFailClosed)

	query := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
	_, q, _ := parseDNSQueryKey(query)

	before := magicDNSExitServfailCount.Load()
	if !tryResolvePublicViaExit(srv, peer, query, q, 0x1234) {
		t.Fatal("兑现不了的出口必须由本函数负责作答(返回 true),不能回退 server 本地上游")
	}
	hdr, got := read()
	if !got {
		t.Fatal("应当收到一帧应答")
	}
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode = %v, want SERVFAIL", hdr.RCode)
	}
	if hdr.ID != 0x1234 {
		t.Fatalf("应答的 txn id = %#x, want 0x1234", hdr.ID)
	}
	if magicDNSExitServfailCount.Load() != before+1 {
		t.Fatal("应记 magicDNSExitServfailCount")
	}
}

// TestTryRelayPublicViaExit_FailClosedSentinelIsServfail HTTPS/SVCB 中继路径同款。
// 只堵 A/AAAA 不堵 HTTPS 等于没堵 —— HTTPS RR 里的 ipv4hint/ipv6hint 与 A/AAAA 同病,
// 一样会被 server 地理的答案污染。
func TestTryRelayPublicViaExit_FailClosedSentinelIsServfail(t *testing.T) {
	resetConnByDeviceForTest(t)
	srv, peer, read := exitDNSUDPPair(t)
	registerFailClosedConn(t, peer.IP.String(), egressFailClosed)

	query := buildDNSQueryFull(t, "example.com", dnsmessage.TypeHTTPS, dnsmessage.ClassINET)
	_, q, _ := parseDNSQueryKey(query)

	if !tryRelayPublicViaExit(srv, peer, query, q, 0x4321) {
		t.Fatal("兑现不了的出口在中继路径上同样要就地 SERVFAIL")
	}
	hdr, got := read()
	if !got {
		t.Fatal("应当收到一帧应答")
	}
	if hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("rcode = %v, want SERVFAIL", hdr.RCode)
	}
}

// TestTryResolvePublicViaExit_EntryGuardsFallThrough 三条「不该由这条路径负责」的入口:
// 参数不全、peer 地址取不出、以及**未选出口**。它们都必须返回 false 让调用方走 server
// 本地上游 —— 返 true 而不作答会让客户端干等到超时。
func TestTryResolvePublicViaExit_EntryGuardsFallThrough(t *testing.T) {
	resetConnByDeviceForTest(t)
	srv, peer, _ := exitDNSUDPPair(t)
	query := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
	_, q, _ := parseDNSQueryKey(query)

	for name, call := range map[string]func() bool{
		"conn 为 nil":   func() bool { return tryResolvePublicViaExit(nil, peer, query, q, 1) },
		"peer 为 nil":   func() bool { return tryResolvePublicViaExit(srv, nil, query, q, 1) },
		"空查询":          func() bool { return tryResolvePublicViaExit(srv, peer, nil, q, 1) },
		"peer 的 IP 为空": func() bool { return tryResolvePublicViaExit(srv, &net.UDPAddr{}, query, q, 1) },
		"未选 peer 出口":   func() bool { return tryResolvePublicViaExit(srv, peer, query, q, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if call() {
				t.Fatal("这条路径不该接管,必须返回 false 让调用方走 server 本地上游")
			}
		})
	}

	// 中继路径同样的四条。
	for name, call := range map[string]func() bool{
		"conn 为 nil": func() bool { return tryRelayPublicViaExit(nil, peer, query, q, 1) },
		"peer 为 nil": func() bool { return tryRelayPublicViaExit(srv, nil, query, q, 1) },
		"空查询":        func() bool { return tryRelayPublicViaExit(srv, peer, nil, q, 1) },
		"未选 peer 出口": func() bool { return tryRelayPublicViaExit(srv, peer, query, q, 1) },
	} {
		t.Run("中继/"+name, func(t *testing.T) {
			if call() {
				t.Fatal("中继路径也不该接管")
			}
		})
	}
}

// ------------------------------------------------------ 截获路径的拒收面

// TestInterceptExitDNSResponse_RejectionPaths 钉住截获路径逐层拒收的形状。
//
// 这些包能到这里,说明发送方已经是一条**通过认证的会话** —— 所以「src=:53 就当出口应答」
// 是不够的:任一已认证会话都能伪造 src=:53 并撞关联端口,把自己的答案塞进另一个用户的
// 在途查询里。真正把关的是「必须来自查询被投递到的那条出口会话」+「TXID 相符」。
func TestInterceptExitDNSResponse_RejectionPaths(t *testing.T) {
	setServerGatewayAddrs("10.201.0.1/16", "")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })
	gwV4 := netip.MustParseAddr("10.201.0.1")
	exitConn := &Connection{userID: "u1", connIDStr: "exit"}

	// 在途查询:登记一个等待者,占住一个关联端口。
	ch := make(chan []byte, 1)
	port, ok := registerExitDNSWaiter(ch, exitConn, 0xbeef, true)
	if !ok {
		t.Fatal("登记等待者失败")
	}
	t.Cleanup(func() { unregisterExitDNSWaiter(port) })

	mkResp := func(t *testing.T, srcPort, dstPort uint16, dst netip.Addr, qid uint16) []byte {
		t.Helper()
		body := make([]byte, 12)
		binary.BigEndian.PutUint16(body[0:2], qid)
		body[2] = 0x80 // QR=1
		pkt, ok := buildIPv4UDP(netip.MustParseAddr("8.8.8.8"), srcPort, dst, dstPort, body)
		if !ok {
			t.Fatal("构包失败")
		}
		return pkt
	}

	t.Run("源端口不是 53", func(t *testing.T) {
		if interceptExitDNSResponseIfPending(exitConn, mkResp(t, 5353, port, gwV4, 0xbeef)) {
			t.Fatal("非 :53 的回包不该被当出口 DNS 应答")
		}
	})
	t.Run("目的端口不在关联端口区间", func(t *testing.T) {
		if interceptExitDNSResponseIfPending(exitConn, mkResp(t, 53, exitDNSPortLo-1, gwV4, 0xbeef)) {
			t.Fatal("区间外的端口不该被截获 —— 那是普通流量,截了就等于把客户端的包吞掉")
		}
	})
	t.Run("目的不是 server 的 v4 网关", func(t *testing.T) {
		if interceptExitDNSResponseIfPending(exitConn, mkResp(t, 53, port, netip.MustParseAddr("10.201.9.9"), 0xbeef)) {
			t.Fatal("目的不是网关地址的包不该被截获")
		}
	})
	t.Run("那个端口上没有等待者", func(t *testing.T) {
		free := port + 1
		if free > exitDNSPortHi {
			free = port - 1
		}
		if interceptExitDNSResponseIfPending(exitConn, mkResp(t, 53, free, gwV4, 0xbeef)) {
			t.Fatal("没有在途查询的端口不该被截获")
		}
	})
	t.Run("来自别的会话", func(t *testing.T) {
		other := &Connection{userID: "u2", connIDStr: "other"}
		before := exitDNSForeignConnRejectCount.Load()
		if interceptExitDNSResponseIfPending(other, mkResp(t, 53, port, gwV4, 0xbeef)) {
			t.Fatal("别的会话即便伪造 src=:53 并撞中端口也必须被拒 —— 否则是跨用户缓存投毒")
		}
		if exitDNSForeignConnRejectCount.Load() != before+1 {
			t.Fatal("应记 exitDNSForeignConnRejectCount")
		}
		// 关键:拒收**不能**消费掉等待者,否则攻击者一发包就能让真应答无处可去(DoS)。
		if _, waiting := peekExitDNSWaiter(port); !waiting {
			t.Fatal("拒收不该摘除等待者 —— 那样一个伪造包就能掐掉一次真解析")
		}
	})
	t.Run("TXID 不符", func(t *testing.T) {
		if interceptExitDNSResponseIfPending(exitConn, mkResp(t, 53, port, gwV4, 0xdead)) {
			t.Fatal("TXID 不符必须拒")
		}
		if _, waiting := peekExitDNSWaiter(port); !waiting {
			t.Fatal("TXID 不符的拒收同样不该摘除等待者")
		}
	})
	t.Run("UDP 载荷短到没有 TXID", func(t *testing.T) {
		pkt, ok := buildIPv4UDP(netip.MustParseAddr("8.8.8.8"), 53, gwV4, port, []byte{1, 2, 3})
		if !ok {
			t.Fatal("构包失败")
		}
		if interceptExitDNSResponseIfPending(exitConn, pkt) {
			t.Fatal("不足 12 字节的载荷判不出 TXID,必须拒")
		}
	})

	// 反面对照:正主的应答必须收下并交到等待者手里 —— 否则上面全部「拒收」可以由一个
	// 「一律返回 false」的实现满足。
	t.Run("正主的应答收下", func(t *testing.T) {
		if !interceptExitDNSResponseIfPending(exitConn, mkResp(t, 53, port, gwV4, 0xbeef)) {
			t.Fatal("来自正主、TXID 相符的应答必须被截获")
		}
		select {
		case got := <-ch:
			if len(got) < 12 || binary.BigEndian.Uint16(got[0:2]) != 0xbeef {
				t.Fatalf("交给等待者的载荷不对: %v", got)
			}
		default:
			t.Fatal("应答没有交到等待者手里")
		}
		// 一次性:收下之后等待者要被摘除,防重复投递。
		if _, waiting := peekExitDNSWaiter(port); waiting {
			t.Fatal("收下之后必须摘除等待者(一次性),否则会重复投递")
		}
	})
}

// peekExitDNSWaiter 查某关联端口上是否还挂着等待者(只读,给测试用)。
func peekExitDNSWaiter(port uint16) (*exitDNSWaiter, bool) {
	exitDNSMu.Lock()
	defer exitDNSMu.Unlock()
	w, ok := exitDNSWaiters[port]
	return w, ok
}

// TestUnregisterExitDNSWaiter_Idempotent 摘除要幂等:截获路径可能已经先摘过一次,
// resolveExitDNS 的 defer 还会再摘一次。不幂等的话 in-flight 计数会被减两次 →
// 归零后热路径的快速返回判据失效(或者更糟,变成负数)。
func TestUnregisterExitDNSWaiter_Idempotent(t *testing.T) {
	ch := make(chan []byte, 1)
	port, ok := registerExitDNSWaiter(ch, nil, 0, false)
	if !ok {
		t.Fatal("登记失败")
	}
	before := exitDNSInflight.Load()
	unregisterExitDNSWaiter(port)
	after := exitDNSInflight.Load()
	if after != before-1 {
		t.Fatalf("第一次摘除应把 in-flight 减 1(%d → %d)", before, after)
	}
	unregisterExitDNSWaiter(port)
	if got := exitDNSInflight.Load(); got != after {
		t.Fatalf("重复摘除不该再减(%d → %d)—— 双减会让 in-flight 归零甚至变负", after, got)
	}
}

// TestInterceptExitDNSResponse_ZeroInflightFastPath in-flight 为 0 时立刻返回 false,
// 不去解析报文。这是数据面每个包都要过的判据,顺带确认它不会误吞普通流量。
func TestInterceptExitDNSResponse_ZeroInflightFastPath(t *testing.T) {
	if exitDNSInflight.Load() != 0 {
		t.Skip("有其它用例的在途查询未收尾,跳过(本条只验零在途的快速路径)")
	}
	if interceptExitDNSResponseIfPending(&Connection{}, []byte{0x45, 0x00}) {
		t.Fatal("零在途时必须直接返回 false")
	}
}
