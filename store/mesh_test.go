package store

import "testing"

// TestGetMeshEnabled_DefaultsTrueWhenUnset:0008 部署前的老库没有 mesh_enabled
// setting,GetMeshEnabled 必须返回 (true, nil) 而不是误把 mesh 关掉。
func TestGetMeshEnabled_DefaultsTrueWhenUnset(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	on, err := s.GetMeshEnabled(ctx)
	if err != nil {
		t.Fatalf("GetMeshEnabled err: %v", err)
	}
	if !on {
		t.Fatalf("默认值应为 true (key 不存在等价于 mesh on), got false")
	}
}

func TestSetAndGetMeshEnabled_Roundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	if err := s.SetMeshEnabled(ctx, false); err != nil {
		t.Fatalf("SetMeshEnabled(false): %v", err)
	}
	on, err := s.GetMeshEnabled(ctx)
	if err != nil {
		t.Fatalf("GetMeshEnabled err: %v", err)
	}
	if on {
		t.Fatalf("写入 false 后应为 false, got true")
	}

	if err := s.SetMeshEnabled(ctx, true); err != nil {
		t.Fatalf("SetMeshEnabled(true): %v", err)
	}
	on, err = s.GetMeshEnabled(ctx)
	if err != nil {
		t.Fatalf("GetMeshEnabled err: %v", err)
	}
	if !on {
		t.Fatalf("写入 true 后应为 true, got false")
	}
}

// TestParseMeshEnabled_AcceptsCommonForms:确认 setting value 各种常见写法都被
// 正确归一,坏数据兜底默认 true(永远不要意外把整网关闭)。
func TestParseMeshEnabled_AcceptsCommonForms(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"true", true}, {"True", true}, {"TRUE", true},
		{"1", true}, {"yes", true}, {"on", true},
		{"  on ", true},
		{"false", false}, {"False", false}, {"FALSE", false},
		{"0", false}, {"no", false}, {"off", false},
		{"  off  ", false},
		{"", true},           // 空串 = 默认 on
		{"garbage", true},    // 不认识 = 默认 on
		{"yes please", true}, // ParseBool 也认不出 → 默认 on
		{"f", false},         // strconv.ParseBool 接受 f / F
		{"T", true},
	}
	for _, c := range cases {
		got := parseMeshEnabled(c.in)
		if got != c.want {
			t.Errorf("parseMeshEnabled(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestSetMeshEnabled_PersistedAsCanonicalString:确保我们写入的是规范化的 "true"/"false",
// 让 admin CLI / 直接 SELECT 看到的值也是稳定的(而不是 "1"/"yes")。
func TestSetMeshEnabled_PersistedAsCanonicalString(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	if err := s.SetMeshEnabled(ctx, true); err != nil {
		t.Fatalf("SetMeshEnabled: %v", err)
	}
	v, ok, err := s.SettingsGet(ctx, MeshEnabledKey)
	if err != nil || !ok {
		t.Fatalf("SettingsGet: err=%v ok=%v", err, ok)
	}
	if v != "true" {
		t.Errorf("persisted value = %q, want %q", v, "true")
	}

	if err := s.SetMeshEnabled(ctx, false); err != nil {
		t.Fatalf("SetMeshEnabled: %v", err)
	}
	v, _, _ = s.SettingsGet(ctx, MeshEnabledKey)
	if v != "false" {
		t.Errorf("persisted value = %q, want %q", v, "false")
	}
}
