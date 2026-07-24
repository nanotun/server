package store

import (
	"testing"
)

// TestDeleteDevice_CleansOrphanPortForwards 第十六轮深扫 HIGH:删设备时同事务清掉引用其 UUID 的 port_forwards,
// 否则残留孤儿转发行会被后来注册同一(客户端自选)UUID 的账号静默继承公网入口。
func TestDeleteDevice_CleansOrphanPortForwards(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "pfu", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.UpsertDevice(ctx, u.ID, "UUID-PF-1", "dev", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertLease(ctx, d.ID, "10.201.0.9", "", false); err != nil {
		t.Fatal(err)
	}
	pf, err := s.CreatePortForward(ctx, PortForward{
		PublicPort: 18080, Proto: "tcp", TargetDeviceUUID: "UUID-PF-1",
		TargetIP: "10.201.0.9", TargetPort: 80, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreatePortForward: %v", err)
	}

	if err := s.DeleteDevice(ctx, d.ID); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	// 引用该设备 UUID 的转发行必须已随设备一并删除(不留孤儿)。
	if _, err := s.GetPortForward(ctx, pf.ID); err != ErrNotFound {
		t.Fatalf("删设备后引用其 UUID 的 port_forward 应被清掉(ErrNotFound), got %v", err)
	}
}

// TestDeleteUser_CleansOrphanPortForwards 同理:删用户级联删其设备,并清掉这些设备 UUID 引用的 port_forwards。
func TestDeleteUser_CleansOrphanPortForwards(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "pfu2", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.UpsertDevice(ctx, u.ID, "UUID-PF-2", "dev", "linux")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertLease(ctx, d.ID, "10.201.0.10", "", false); err != nil {
		t.Fatal(err)
	}
	pf, err := s.CreatePortForward(ctx, PortForward{
		PublicPort: 18081, Proto: "tcp", TargetDeviceUUID: "uuid-pf-2", // 小写:验证 LOWER() 匹配
		TargetIP: "10.201.0.10", TargetPort: 80, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreatePortForward: %v", err)
	}

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := s.GetPortForward(ctx, pf.ID); err != ErrNotFound {
		t.Fatalf("删用户后其设备 UUID 引用的 port_forward 应被清掉(ErrNotFound), got %v", err)
	}
}

// TestSetDeviceFixedVIP_KeepSentinel 第十六轮深扫 MED:KeepFixedVIP 只改指定族,另一族保持不变;
// 空串仍表示清除。验证事务内读当前值填充「不改动的族」。
func TestSetDeviceFixedVIP_KeepSentinel(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "keepu", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.UpsertDevice(ctx, u.ID, "uuid-keep", "dev", "linux")
	if err != nil {
		t.Fatal(err)
	}
	// 先设两族。
	if err := s.SetDeviceFixedVIP(ctx, d.ID, "10.201.0.5", "fd00:201::5", false); err != nil {
		t.Fatalf("initial set: %v", err)
	}
	// 只改 v4,v6 传 Keep → v6 应保持不变。
	if err := s.SetDeviceFixedVIP(ctx, d.ID, "10.201.0.6", KeepFixedVIP, false); err != nil {
		t.Fatalf("keep-v6 set: %v", err)
	}
	got, _ := s.GetDevice(ctx, d.ID)
	if got.FixedVIPv4 != "10.201.0.6" {
		t.Fatalf("v4 应更新为 10.201.0.6, got %q", got.FixedVIPv4)
	}
	if got.FixedVIPv6 != "fd00:201::5" {
		t.Fatalf("v6 传 Keep 应保持 fd00:201::5, got %q", got.FixedVIPv6)
	}
	// 只清 v6(传空串),v4 传 Keep → v4 保持,v6 清空。
	if err := s.SetDeviceFixedVIP(ctx, d.ID, KeepFixedVIP, "", false); err != nil {
		t.Fatalf("clear-v6 set: %v", err)
	}
	got, _ = s.GetDevice(ctx, d.ID)
	if got.FixedVIPv4 != "10.201.0.6" {
		t.Fatalf("v4 传 Keep 应保持 10.201.0.6, got %q", got.FixedVIPv4)
	}
	if got.FixedVIPv6 != "" {
		t.Fatalf("v6 传空串应清除, got %q", got.FixedVIPv6)
	}
}
