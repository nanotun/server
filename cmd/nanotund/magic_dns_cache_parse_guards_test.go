package main

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// 经出口回来的 DNS 应答的解析与缓存元信息。
//
// 这两个函数的输出直接决定缓存里放什么、放多久。三类错法各有各的现场表现:
//   - 截断 / 畸形应答被当成「成功解析出 0 个地址」→ 缓存一条空答案,该域名在整个 TTL 内解析不出
//     任何地址,而下次查询根本不会回源(缓存命中);
//   - 取的不是**最小** TTL → 缓存活得比上游任一条记录都久,CDN 换 IP 后客户端连着老地址打;
//   - rcode 丢了 → NXDOMAIN 被当成成功的空答案缓存下来,客户端拿到 NOERROR/0 而不是「域名不存在」,
//     很多解析器会因此不去查 AAAA / 不走下一个 search domain。

// dnsAnswer 构造一份带若干 A/AAAA/CNAME 记录的应答字节。
func dnsAnswer(t *testing.T, rcode dnsmessage.RCode, recs ...dnsmessage.Resource) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: 0x4242, Response: true, RCode: rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	q := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		switch body := r.Body.(type) {
		case *dnsmessage.AResource:
			if err := b.AResource(r.Header, *body); err != nil {
				t.Fatal(err)
			}
		case *dnsmessage.AAAAResource:
			if err := b.AAAAResource(r.Header, *body); err != nil {
				t.Fatal(err)
			}
		case *dnsmessage.CNAMEResource:
			if err := b.CNAMEResource(r.Header, *body); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("未支持的记录类型 %T", r.Body)
		}
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func aRec(ttl uint32, ip string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName("example.com."), Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()},
	}
}

func aaaaRec(ttl uint32, ip string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName("example.com."), Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(ip).As16()},
	}
}

func cnameRec(ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name: dnsmessage.MustNewName("example.com."), Class: dnsmessage.ClassINET, TTL: ttl,
		},
		Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("cdn.example.net.")},
	}
}

// TestParseExitDNSResult_TakesTheShortestTTLAndSkipsWhatItCannotUse 取最小 TTL、跳过其它类型。
//
// 最小 TTL 是缓存能活多久的上限。取成最大值(或某一条的值)就会让缓存活得比上游最短的那条记录更久
// —— CDN 换了 IP,客户端还在往老地址打,而排障时看上游 TTL 一切正常。CNAME 这类记录要跳过但**不能
// 因此判解析失败**:真实的 CDN 应答几乎都是 CNAME 链 + 末端 A,判失败就等于出口解析路径永远不命中。
func TestParseExitDNSResult_TakesTheShortestTTLAndSkipsWhatItCannotUse(t *testing.T) {
	t.Run("多条记录取最小 TTL", func(t *testing.T) {
		raw := dnsAnswer(t, dnsmessage.RCodeSuccess,
			aRec(300, "93.184.216.34"), aRec(60, "93.184.216.35"), aaaaRec(120, "2606:2800:220::1"))
		addrs, rcode, ttl, ok := parseExitDNSResult(raw)
		if !ok {
			t.Fatal("解析失败")
		}
		if rcode != dnsmessage.RCodeSuccess {
			t.Errorf("rcode=%v", rcode)
		}
		if ttl != 60 {
			t.Errorf("TTL=%d,期望最小的 60 —— 取大了会让缓存活过 CDN 换 IP", ttl)
		}
		if len(addrs) != 3 {
			t.Errorf("抽出 %d 个地址,期望 3(两族都要)", len(addrs))
		}
	})

	t.Run("最短的那条是 AAAA", func(t *testing.T) {
		// A/AAAA 两个分支各有一份「取最小」的实现,只测其中一个等于只钉住一半:
		// 双栈站点的 AAAA 常配更短 TTL(v6 出口切换更频繁),漏掉这半边的表现正是「v6 换了地址还在打老的」。
		raw := dnsAnswer(t, dnsmessage.RCodeSuccess,
			aRec(300, "93.184.216.34"), aaaaRec(30, "2606:2800:220::1"))
		_, _, ttl, ok := parseExitDNSResult(raw)
		if !ok {
			t.Fatal("解析失败")
		}
		if ttl != 30 {
			t.Errorf("TTL=%d,期望 AAAA 那条的 30 —— AAAA 分支没参与取最小,v6 地址换了还在打老的", ttl)
		}
	})

	t.Run("CNAME 链跳过但不算失败", func(t *testing.T) {
		raw := dnsAnswer(t, dnsmessage.RCodeSuccess, cnameRec(3600), aRec(45, "93.184.216.34"))
		addrs, _, ttl, ok := parseExitDNSResult(raw)
		if !ok {
			t.Fatal("含 CNAME 的应答被判解析失败 —— 真实 CDN 应答几乎都是 CNAME 链,出口解析会永不命中")
		}
		if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("93.184.216.34") {
			t.Errorf("抽出的地址不对: %v", addrs)
		}
		if ttl != 45 {
			t.Errorf("TTL=%d,期望 45(只看 A/AAAA 的 TTL,不该被 CNAME 的 3600 带偏)", ttl)
		}
	})

	t.Run("NXDOMAIN 的 rcode 必须带回去", func(t *testing.T) {
		raw := dnsAnswer(t, dnsmessage.RCodeNameError)
		_, rcode, _, ok := parseExitDNSResult(raw)
		if !ok {
			t.Fatal("否定应答不是解析失败,它是一个有效答案")
		}
		if rcode != dnsmessage.RCodeNameError {
			t.Errorf("rcode=%v,期望 NXDOMAIN —— 丢了它就会把「域名不存在」缓存成「成功但没有地址」", rcode)
		}
	})

	t.Run("NODATA:成功但零地址", func(t *testing.T) {
		raw := dnsAnswer(t, dnsmessage.RCodeSuccess)
		addrs, rcode, _, ok := parseExitDNSResult(raw)
		if !ok || rcode != dnsmessage.RCodeSuccess || len(addrs) != 0 {
			t.Errorf("NODATA 应答解析成 (%v,%v,%d 个地址)", ok, rcode, len(addrs))
		}
	})

	t.Run("畸形字节判失败", func(t *testing.T) {
		for _, name := range []string{"空", "半个头", "只有头"} {
			var raw []byte
			switch name {
			case "半个头":
				raw = []byte{0x42, 0x42, 0x81}
			case "只有头":
				raw = []byte{0x42, 0x42, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0} // 声明有 1 问 1 答,实际没有
			}
			if _, _, _, ok := parseExitDNSResult(raw); ok {
				t.Errorf("%s 的应答被判解析成功 —— 会把一条空答案缓存进去,整个 TTL 内该域名解析不出地址", name)
			}
		}
	})
}

// TestParseRawDNSMeta_OnlyNeedsRcodeAndShortestTTL HTTPS/SVCB 那条路只要元信息。
//
// 这条路缓存的是**原始字节**(本模块不解析 HTTPS/SVCB 的 rdata),所以只需要 rcode 与最小 TTL。
// 但「不解析 rdata」不等于「不校验」:畸形应答仍必须判失败,否则会把一份解不开的字节连同一个
// 凭空的 TTL 缓存下来,后续命中缓存的客户端全都收到那份坏应答。
func TestParseRawDNSMeta_OnlyNeedsRcodeAndShortestTTL(t *testing.T) {
	t.Run("取最小 TTL", func(t *testing.T) {
		raw := dnsAnswer(t, dnsmessage.RCodeSuccess, cnameRec(600), aRec(30, "93.184.216.34"))
		rcode, ttl, ok := parseRawDNSMeta(raw)
		if !ok {
			t.Fatal("解析失败")
		}
		if rcode != dnsmessage.RCodeSuccess {
			t.Errorf("rcode=%v", rcode)
		}
		if ttl != 30 {
			t.Errorf("TTL=%d,期望最小的 30 —— 这里连 CNAME 的 TTL 也要一起算,因为缓存的是整份原始应答", ttl)
		}
	})

	t.Run("零 answer 时 TTL 为 0", func(t *testing.T) {
		rcode, ttl, ok := parseRawDNSMeta(dnsAnswer(t, dnsmessage.RCodeSuccess))
		if !ok || rcode != dnsmessage.RCodeSuccess || ttl != 0 {
			t.Errorf("NODATA 元信息解析成 (%v,%v,%d) —— 期望 TTL=0 好让上层归成负缓存", ok, rcode, ttl)
		}
	})

	t.Run("否定应答的 rcode 要带回", func(t *testing.T) {
		rcode, _, ok := parseRawDNSMeta(dnsAnswer(t, dnsmessage.RCodeNameError))
		if !ok || rcode != dnsmessage.RCodeNameError {
			t.Errorf("解析成 (%v,%v),期望 NXDOMAIN", ok, rcode)
		}
	})

	t.Run("畸形字节判失败", func(t *testing.T) {
		if _, _, ok := parseRawDNSMeta(nil); ok {
			t.Error("空字节被判解析成功")
		}
		if _, _, ok := parseRawDNSMeta([]byte{0x42, 0x42, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}); ok {
			t.Error("声明有答复实际没有的应答被判解析成功 —— 那份解不开的字节会连同凭空 TTL 一起缓存")
		}
	})
}
