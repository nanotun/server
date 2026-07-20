package store

import (
	"errors"
	"testing"
)

func TestPortForwards_CRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	pf, err := s.CreatePortForward(ctx, PortForward{
		PublicPort:       2222,
		Proto:            "tcp",
		TargetDeviceUUID: "D2B65929-90C5-4382-A964-67C2009CD425", // 混大小写：应被归一为小写
		TargetIP:         "10.201.0.6",
		TargetPort:       22,
		Enabled:          true,
		Comment:          "ssh 到节点",
	})
	if err != nil {
		t.Fatalf("CreatePortForward: %v", err)
	}
	if pf.ID == 0 || pf.PublicPort != 2222 || pf.TargetPort != 22 {
		t.Fatalf("bad row: %+v", pf)
	}
	if pf.TargetDeviceUUID != "d2b65929-90c5-4382-a964-67c2009cd425" {
		t.Fatalf("uuid 未归一小写: %q", pf.TargetDeviceUUID)
	}
	if !pf.Enabled {
		t.Fatalf("enabled 应为 true")
	}

	got, err := s.GetPortForward(ctx, pf.ID)
	if err != nil {
		t.Fatalf("GetPortForward: %v", err)
	}
	if got.TargetIP != "10.201.0.6" || got.Comment != "ssh 到节点" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// 停用 → ListEnabled 不含它。
	if err := s.SetPortForwardEnabled(ctx, pf.ID, false); err != nil {
		t.Fatalf("SetPortForwardEnabled: %v", err)
	}
	enabled, err := s.ListEnabledPortForwards(ctx)
	if err != nil {
		t.Fatalf("ListEnabledPortForwards: %v", err)
	}
	for _, e := range enabled {
		if e.ID == pf.ID {
			t.Fatalf("停用后不应出现在 ListEnabled")
		}
	}
	// 全量 List 仍含它。
	all, err := s.ListPortForwards(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("ListPortForwards: n=%d err=%v", len(all), err)
	}

	// 删除 → 再查 ErrNotFound。
	if err := s.DeletePortForward(ctx, pf.ID); err != nil {
		t.Fatalf("DeletePortForward: %v", err)
	}
	if _, err := s.GetPortForward(ctx, pf.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后 Get 应 ErrNotFound, 得 %v", err)
	}
	if err := s.DeletePortForward(ctx, pf.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("重复删除应 ErrNotFound, 得 %v", err)
	}
}

func TestPortForwards_DuplicatePublicPort(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	base := PortForward{PublicPort: 3333, TargetDeviceUUID: "uuid-a", TargetIP: "10.201.0.6", TargetPort: 80}
	if _, err := s.CreatePortForward(ctx, base); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// 同 public_port 再建 → ErrDuplicate（UNIQUE 约束）。
	dup := base
	dup.TargetDeviceUUID = "uuid-b"
	dup.TargetIP = "10.201.0.7"
	if _, err := s.CreatePortForward(ctx, dup); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate public_port 应 ErrDuplicate, 得 %v", err)
	}
}

func TestPortForwards_RejectsBadInput(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	cases := []struct {
		name string
		pf   PortForward
	}{
		{"public_port=0", PortForward{PublicPort: 0, TargetDeviceUUID: "u", TargetIP: "1.2.3.4", TargetPort: 80}},
		{"public_port>65535", PortForward{PublicPort: 70000, TargetDeviceUUID: "u", TargetIP: "1.2.3.4", TargetPort: 80}},
		{"target_port=0", PortForward{PublicPort: 5000, TargetDeviceUUID: "u", TargetIP: "1.2.3.4", TargetPort: 0}},
		{"empty uuid", PortForward{PublicPort: 5001, TargetDeviceUUID: "", TargetIP: "1.2.3.4", TargetPort: 80}},
		{"empty ip", PortForward{PublicPort: 5002, TargetDeviceUUID: "u", TargetIP: "", TargetPort: 80}},
		{"udp proto", PortForward{PublicPort: 5003, Proto: "udp", TargetDeviceUUID: "u", TargetIP: "1.2.3.4", TargetPort: 80}},
	}
	for _, tc := range cases {
		if _, err := s.CreatePortForward(ctx, tc.pf); err == nil {
			t.Fatalf("%s: 期望报错，却成功", tc.name)
		}
	}
}

func TestPortForwards_ProtoDefaultsTCP(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	pf, err := s.CreatePortForward(ctx, PortForward{
		PublicPort: 4444, TargetDeviceUUID: "u", TargetIP: "10.201.0.6", TargetPort: 443,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if pf.Proto != "tcp" {
		t.Fatalf("proto 空应默认 tcp, 得 %q", pf.Proto)
	}
}
