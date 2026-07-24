package main

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func buildDNSReplyMsg(t *testing.T, id uint16, name string, qType dnsmessage.Type) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, Response: true},
		Questions: []dnsmessage.Question{{
			Name: n, Type: qType, Class: dnsmessage.ClassINET,
		}},
	}
	b, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack reply: %v", err)
	}
	return b
}

// TestDNSReplyMatches 第十六轮深扫 MED:上游 DNS 应答须 TXID + question 双校验,拒收伪造/迟到包。
func TestDNSReplyMatches(t *testing.T) {
	// buildDNSQueryID 会自行追加 "."。
	query := buildDNSQueryID(t, "example.com", dnsmessage.TypeA, 0x1234)
	wantID, wantQ, ok := parseDNSQueryKey(query)
	if !ok {
		t.Fatal("parseDNSQueryKey 应成功")
	}

	// 正确应答:同 ID + 同 question。
	good := buildDNSReplyMsg(t, 0x1234, "example.com.", dnsmessage.TypeA)
	if !dnsReplyMatches(good, wantID, wantQ) {
		t.Fatal("匹配的应答应被接受")
	}

	// TXID 不符 → 拒。
	badID := buildDNSReplyMsg(t, 0x9999, "example.com.", dnsmessage.TypeA)
	if dnsReplyMatches(badID, wantID, wantQ) {
		t.Fatal("TXID 不符的应答应被拒")
	}

	// 名称不符 → 拒。
	badName := buildDNSReplyMsg(t, 0x1234, "attacker.com.", dnsmessage.TypeA)
	if dnsReplyMatches(badName, wantID, wantQ) {
		t.Fatal("question 名称不符的应答应被拒")
	}

	// type 不符(AAAA vs A)→ 拒。
	badType := buildDNSReplyMsg(t, 0x1234, "example.com.", dnsmessage.TypeAAAA)
	if dnsReplyMatches(badType, wantID, wantQ) {
		t.Fatal("question type 不符的应答应被拒")
	}

	// 名称大小写不敏感 → 接受。
	upper := buildDNSReplyMsg(t, 0x1234, "Example.COM.", dnsmessage.TypeA)
	if !dnsReplyMatches(upper, wantID, wantQ) {
		t.Fatal("名称大小写不敏感,应接受")
	}

	// 非 Response 位(把 query 当 reply)→ 拒。
	if dnsReplyMatches(query, wantID, wantQ) {
		t.Fatal("未置 Response 位的报文不应被当作合法应答")
	}
}

// TestIsMeshCIDRAddr 第十六轮深扫 MED:mesh 网段(TUN CIDR)内地址应被识别,用于 exit 转发的 fail-closed。
func TestIsMeshCIDRAddr(t *testing.T) {
	setServerGatewayAddrs("10.201.0.1/16", "fd00:201::1/64")
	t.Cleanup(func() { setServerGatewayAddrs("", "") })

	cases := []struct {
		addr string
		want bool
	}{
		{"10.201.5.5", true}, // mesh v4 段内
		{"10.201.255.254", true},
		{"10.202.0.1", false},    // 段外
		{"8.8.8.8", false},       // 公网
		{"fd00:201::abcd", true}, // mesh v6 段内
		{"fd00:202::1", false},   // v6 段外
		{"2001:4860:4860::8888", false},
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.addr)
		if got := isMeshCIDRAddr(a); got != c.want {
			t.Errorf("isMeshCIDRAddr(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
}
