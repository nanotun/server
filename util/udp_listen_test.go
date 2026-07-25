package util

import "testing"

func TestSplitUDPListenAddrPortUnion(t *testing.T) {
	host, pu, err := SplitUDPListenAddr(":443,8443,5000-5100")
	if err != nil {
		t.Fatal(err)
	}
	if host != "" || pu != "443,8443,5000-5100" {
		t.Fatalf("got host=%q pu=%q", host, pu)
	}
	if !UDPPortUnionNeedsHop(pu) {
		t.Fatal("expected hop")
	}
	p, err := PrimaryPortFromUDPListenAddr(":443,8443")
	if err != nil || p != 443 {
		t.Fatalf("primary=%d err=%v", p, err)
	}
}

// TestPrimaryPortFollowsWrittenOrder:主端口取配置里写的第一个,不受 hysteria
// 解析器升序排序影响。之前直接用 ParsePortUnion()[0] 时 ":8443,443" 会绑到 443,
// 与"首端口"的说法相反,且端口写法一换绑定口就静默变。
func TestPrimaryPortFollowsWrittenOrder(t *testing.T) {
	cases := []struct {
		addr string
		want uint16
	}{
		{":443,8443", 443},
		{":8443,443", 8443},
		{"0.0.0.0:60205,53953", 60205},
		{":5000-5100,443", 5000},
		{"[::]:9443,443", 9443},
		{":443", 443},
	}
	for _, c := range cases {
		got, err := PrimaryPortFromUDPListenAddr(c.addr)
		if err != nil {
			t.Errorf("%s: err=%v", c.addr, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: primary=%d want %d", c.addr, got, c.want)
		}
	}

	if _, err := PrimaryPortFromUDPListenAddr(":notaport"); err == nil {
		t.Error("非法并集应当报错")
	}
}
