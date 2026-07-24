package store

import (
	"errors"
	"testing"
)

// TestMeshCIDRs_RoundTrip 覆盖 SetMeshCIDRs / GetMeshCIDRs 的写读、清除与「去空白项」语义,
// 以及未设置时返回 (nil,nil)(调用方据此跳过批准期重叠检查)。
func TestMeshCIDRs_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	// 未设置:GetMeshCIDRs 返回 (nil,nil),不报错。
	got, err := s.GetMeshCIDRs(ctx)
	if err != nil {
		t.Fatalf("GetMeshCIDRs (unset): %v", err)
	}
	if got != nil {
		t.Fatalf("GetMeshCIDRs (unset) = %v, want nil", got)
	}

	// 写入两个族,读回一致。
	if err := s.SetMeshCIDRs(ctx, []string{"10.201.0.1/16", "fd00::1/64"}); err != nil {
		t.Fatalf("SetMeshCIDRs: %v", err)
	}
	got, err = s.GetMeshCIDRs(ctx)
	if err != nil {
		t.Fatalf("GetMeshCIDRs: %v", err)
	}
	if len(got) != 2 || got[0] != "10.201.0.1/16" || got[1] != "fd00::1/64" {
		t.Fatalf("GetMeshCIDRs = %v, want [10.201.0.1/16 fd00::1/64]", got)
	}

	// 覆盖写(仅 v4,v6 段下线)——不追加,应完整替换。
	if err := s.SetMeshCIDRs(ctx, []string{"10.201.0.1/16"}); err != nil {
		t.Fatalf("SetMeshCIDRs overwrite: %v", err)
	}
	got, err = s.GetMeshCIDRs(ctx)
	if err != nil {
		t.Fatalf("GetMeshCIDRs after overwrite: %v", err)
	}
	if len(got) != 1 || got[0] != "10.201.0.1/16" {
		t.Fatalf("GetMeshCIDRs after overwrite = %v, want [10.201.0.1/16]", got)
	}

	// 空切片 = 清除:落空串,读回 (nil,nil)。
	if err := s.SetMeshCIDRs(ctx, nil); err != nil {
		t.Fatalf("SetMeshCIDRs clear: %v", err)
	}
	got, err = s.GetMeshCIDRs(ctx)
	if err != nil {
		t.Fatalf("GetMeshCIDRs after clear: %v", err)
	}
	if got != nil {
		t.Fatalf("GetMeshCIDRs after clear = %v, want nil", got)
	}
}

// TestMeshCIDRs_SettingsSetBlocked 确认 mesh_cidrs 是系统托管键:通用 SettingsSet 必须拒改(纵深防御),
// 只能经 SetMeshCIDRs 专用写路径(server 启动)落库。
func TestMeshCIDRs_SettingsSetBlocked(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	if err := s.SettingsSet(ctx, MeshCIDRsKey, "10.0.0.0/8"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("SettingsSet(mesh_cidrs) err = %v, want ErrInvalid (system-managed)", err)
	}
	// 确认没写进去。
	if v, ok, err := s.SettingsGet(ctx, MeshCIDRsKey); err != nil || ok {
		t.Fatalf("SettingsGet(mesh_cidrs) = (%q,%v,%v), want unset", v, ok, err)
	}
}
