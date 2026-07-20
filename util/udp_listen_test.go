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
