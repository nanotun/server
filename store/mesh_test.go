package store

import (
	"strconv"
	"strings"
	"testing"
)

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
		// 深扫第十一轮 MED:带空白的 f/F/t/T 之前会因 ParseBool(未 TrimSpace) 失败落到默认 true,
		// 与 ValidateMeshEnabledSetting(用 TrimSpace)不一致。修复后应正确去空白解析。
		{" f ", false}, {"\tF\t", false}, {" t ", true},
	}
	for _, c := range cases {
		got := parseMeshEnabled(c.in)
		if got != c.want {
			t.Errorf("parseMeshEnabled(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestMeshEnabled_ValidateParseParity:任何通过写校验(ValidateMeshEnabledSetting)的值,
// 读路径 parseMeshEnabled 都必须解析成与校验时一致的布尔 —— 否则会出现「写进去以为关了、
// 读出来却是开」的静默不一致(深扫第十一轮 MED 修复的正是带空白的 " f " 这类)。
func TestMeshEnabled_ValidateParseParity(t *testing.T) {
	vals := []string{
		"true", "false", "1", "0", "t", "f", "T", "F",
		"  true ", " false ", " f ", "\tF\t", " t ", "TRUE", "FALSE",
	}
	for _, v := range vals {
		if err := ValidateMeshEnabledSetting(v); err != nil {
			// 校验拒绝的值不在本测试关注范围(读路径怎么兜底都行)。
			continue
		}
		want, perr := strconv.ParseBool(strings.TrimSpace(v))
		if perr != nil {
			t.Fatalf("Validate 放行了 %q 但 ParseBool(TrimSpace) 仍失败 —— 校验器与解析器口径不一致", v)
		}
		if got := parseMeshEnabled(v); got != want {
			t.Errorf("parseMeshEnabled(%q) = %v, 但通过写校验的值应解析为 %v", v, got, want)
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
