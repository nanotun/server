package util

import (
	"encoding/json"
	"testing"
)

func TestNormalizeExitAdvertisedCIDR(t *testing.T) {
	// 出口语境：0/0 与 ::/0 必须被接受（普通语境会被拒）。
	for _, in := range []string{"0.0.0.0/0", "::/0"} {
		got, err := NormalizeExitAdvertisedCIDR(in)
		if err != nil {
			t.Fatalf("NormalizeExitAdvertisedCIDR(%q) 应接受，却报错: %v", in, err)
		}
		if !IsExitDefaultRoute(got) {
			t.Fatalf("NormalizeExitAdvertisedCIDR(%q) = %q，应为出口全网路由", in, got)
		}
	}
	// 普通语境仍拒 /0。
	if _, err := NormalizeAdvertisedCIDR("0.0.0.0/0"); err == nil {
		t.Fatal("NormalizeAdvertisedCIDR(0.0.0.0/0) 应拒绝 /0")
	}
	// 带主机位应被 mask 化。
	got, err := NormalizeExitAdvertisedCIDR("10.1.2.3/24")
	if err != nil || got != "10.1.2.0/24" {
		t.Fatalf("mask 化失败: got=%q err=%v", got, err)
	}
	// 非法 CIDR 仍报错。
	if _, err := NormalizeExitAdvertisedCIDR("not-a-cidr"); err == nil {
		t.Fatal("非法 CIDR 应报错")
	}
}

func TestRouteAdvertiseExitRoundtrip(t *testing.T) {
	// Exit 标志应能随 JSON 往返（且 omitempty 在 false 时不出现）。
	ra := RouteAdvertise{Schema: RouteSchemaCurrent, Routes: []string{"0.0.0.0/0"}, Exit: true}
	b, err := json.Marshal(ra)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRouteAdvertise(b)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Exit || len(parsed.Routes) != 1 || parsed.Routes[0] != "0.0.0.0/0" {
		t.Fatalf("Exit 往返失败: %+v", parsed)
	}
}

func TestEgressSelectRoundtrip(t *testing.T) {
	// 选具体出口设备。
	b, err := MarshalEgressSelect("11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatal(err)
	}
	es, err := ParseEgressSelect(b)
	if err != nil {
		t.Fatal(err)
	}
	if es.Egress != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("egress 往返失败: %q", es.Egress)
	}
	if IsDefaultEgress(es.Egress) {
		t.Fatal("具体设备 UUID 不应判为默认出口")
	}
	// 默认出口判定：空 / "server" / 大小写。
	for _, d := range []string{"", "server", "SERVER", "  ", " server "} {
		if !IsDefaultEgress(d) {
			t.Fatalf("IsDefaultEgress(%q) 应为 true", d)
		}
	}
}

func TestEgressSelectAckRoundtrip(t *testing.T) {
	ack := EgressSelectAck{Accepted: false, Reason: "not_approved"}
	b, err := MarshalEgressSelectAck(ack)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEgressSelectAck(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Accepted || got.Reason != "not_approved" || got.Schema != RouteSchemaCurrent {
		t.Fatalf("ack 往返失败: %+v", got)
	}
}
