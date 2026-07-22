package store

import (
	"errors"
	"testing"
)

// TestSetRateDefaults_BurstBounds 验证 burst 区间校验:0 放行(= 用默认),区间内放行,区间外拒(ErrInvalid),
// 与 CLI 写路径 ValidateRateBurstSetting 对齐,消除「写得进却被运行期 effectiveBurst 静默夹住」的不一致。
func TestSetRateDefaults_BurstBounds(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	cases := []struct {
		name    string
		burst   int64
		wantErr bool
	}{
		{"zero-ok", 0, false},
		{"min-ok", RateBurstBytesMin, false},
		{"max-ok", RateBurstBytesMax, false},
		{"below-min", RateBurstBytesMin - 1, true},
		{"above-max", RateBurstBytesMax + 1, true},
	}
	for _, tc := range cases {
		err := s.SetRateDefaults(ctx, RateDefaults{UploadBPS: 0, DownloadBPS: 0, BurstBytes: tc.burst})
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: 期望拒绝 burst=%d,却成功", tc.name, tc.burst)
			} else if !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: 期望 ErrInvalid,got %v", tc.name, err)
			}
		} else if err != nil {
			t.Errorf("%s: 期望放行 burst=%d,got %v", tc.name, tc.burst, err)
		}
	}
}

// TestSettingsSet_RejectsReservedKeys 验证 DAL 纵深守卫:server_id / schema_version 不得经通用 SettingsSet 写入;
// 普通 key 正常写入。
func TestSettingsSet_RejectsReservedKeys(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	for _, k := range []string{ServerIDKey, "schema_version"} {
		if err := s.SettingsSet(ctx, k, "x"); err == nil {
			t.Errorf("SettingsSet(%q) 应被拒绝", k)
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("SettingsSet(%q) 期望 ErrInvalid,got %v", k, err)
		}
	}
	// 普通 key 应正常写入 + 读回。
	if err := s.SettingsSet(ctx, "some_custom_key", "v1"); err != nil {
		t.Fatalf("普通 key 写入不应失败: %v", err)
	}
	v, ok, err := s.SettingsGet(ctx, "some_custom_key")
	if err != nil || !ok || v != "v1" {
		t.Fatalf("回读普通 key 失败: v=%q ok=%v err=%v", v, ok, err)
	}
	// 守卫不得破坏 server_id 的专用初始化路径(ensureServerID 走 INSERT OR IGNORE,不经 SettingsSet)。
	if id, err := s.GetServerID(ctx); err != nil || id == "" {
		t.Fatalf("server_id 应已由 Migrate 初始化: id=%q err=%v", id, err)
	}
}

// TestDevicesFixedVIPEmptyStringNotUnique 验证 0023 迁移后:两台 device 都存空串 fixed_vip 不再撞唯一索引
// (空串已归一为 NULL / 被排除出唯一性判定),而两台存**相同非空** fixed_vip 仍冲突。
func TestDevicesFixedVIPEmptyStringNotUnique(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "carol", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d1, err := s.UpsertDevice(ctx, u.ID, "uuid-1", "m1", "linux")
	if err != nil {
		t.Fatal(err)
	}
	d2, err := s.UpsertDevice(ctx, u.ID, "uuid-2", "m2", "linux")
	if err != nil {
		t.Fatal(err)
	}
	// 直接写空串(绕过 nullableString),两台都空串:重建索引后不应冲突。
	if _, err := s.DB().ExecContext(ctx, `UPDATE devices SET fixed_vip_v4='' WHERE id=?`, d1.ID); err != nil {
		t.Fatalf("d1 空串写入应成功: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx, `UPDATE devices SET fixed_vip_v4='' WHERE id=?`, d2.ID); err != nil {
		t.Fatalf("d2 空串写入不应撞唯一索引: %v", err)
	}
	// 相同非空值仍应冲突。
	if err := s.SetDeviceFixedVIP(ctx, d1.ID, "10.5.5.5", ""); err != nil {
		t.Fatalf("d1 设固定 vip 应成功: %v", err)
	}
	if err := s.SetDeviceFixedVIP(ctx, d2.ID, "10.5.5.5", ""); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("d2 设相同固定 vip 应 ErrDuplicate,got %v", err)
	}
}
