package main

import (
	"testing"

	"github.com/nanotun/server/store"
)

// TestCountIsolateBlockedApprovals:出口设备按 device 去重(同一台设备的 0.0.0.0/0 与 ::/0
// 是一台出口,不是两台),子网路由按条计。数字直接进 WARN 文案,报错等于误导管理员。
func TestCountIsolateBlockedApprovals(t *testing.T) {
	routes := []store.SubnetRoute{
		{DeviceID: 31, CIDR: "0.0.0.0/0"},
		{DeviceID: 31, CIDR: "::/0"},
		{DeviceID: 31, CIDR: "192.168.88.0/24"},
		{DeviceID: 42, CIDR: "::/0"},
		{DeviceID: 42, CIDR: "10.9.0.0/24"},
	}
	exits, subnets := countIsolateBlockedApprovals(routes)
	if exits != 2 {
		t.Errorf("出口设备数 = %d, want 2(31 与 42 各算一台)", exits)
	}
	if subnets != 2 {
		t.Errorf("子网路由数 = %d, want 2", subnets)
	}

	if e, s := countIsolateBlockedApprovals(nil); e != 0 || s != 0 {
		t.Errorf("空表应为 0/0,got %d/%d", e, s)
	}
}
