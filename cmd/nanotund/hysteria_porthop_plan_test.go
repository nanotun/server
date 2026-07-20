package main

import (
	"reflect"
	"testing"
)

func TestPlanHy2PortHopDportRules(t *testing.T) {
	rules, err := planHy2PortHopDportRules(443, "443,8443,5000-5100")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"5000:5100", "8443"} // 按 PortUnion 规范化后的区间顺序
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules=%v want %v", rules, want)
	}
}

func TestPlanHy2PortHopDportRules_SinglePort(t *testing.T) {
	rules, err := planHy2PortHopDportRules(443, "443")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected no redirect rules, got %v", rules)
	}
}

func TestPlanHy2PortHopDportRules_InvalidUnion(t *testing.T) {
	if _, err := planHy2PortHopDportRules(443, "bad-port"); err == nil {
		t.Fatal("expected error for invalid port union")
	}
}
