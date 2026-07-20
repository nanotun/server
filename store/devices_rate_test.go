package store

import (
	"context"
	"errors"
	"testing"
)

// TestSetDeviceRateLimit_RoundTrip:0011 起 device 持久化 per-device 限速。
// 写入 → 读回 → 改 → 读回 → 清(传 0,0)→ 读回 = 0。覆盖正常分支。
func TestSetDeviceRateLimit_RoundTrip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	u, err := st.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	d, err := st.UpsertDevice(ctx, u.ID, "a1b2c3d4-1111-4111-8111-000000000001", "phone", "ios")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	if d.RateUploadBPS != 0 || d.RateDownloadBPS != 0 {
		t.Fatalf("new device: want 0/0 got %d/%d", d.RateUploadBPS, d.RateDownloadBPS)
	}

	// 设置 5 MiB/s 上 / 10 MiB/s 下
	const up = 5 * 1024 * 1024
	const down = 10 * 1024 * 1024
	if err := st.SetDeviceRateLimit(ctx, d.ID, up, down); err != nil {
		t.Fatalf("set rate: %v", err)
	}
	got, err := st.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if got.RateUploadBPS != up || got.RateDownloadBPS != down {
		t.Errorf("after set: want %d/%d got %d/%d", up, down, got.RateUploadBPS, got.RateDownloadBPS)
	}

	// 单向改:只压上行,下行保留
	if err := st.SetDeviceRateLimit(ctx, d.ID, 1024, down); err != nil {
		t.Fatalf("set rate (asymmetric): %v", err)
	}
	got, _ = st.GetDevice(ctx, d.ID)
	if got.RateUploadBPS != 1024 || got.RateDownloadBPS != down {
		t.Errorf("asymmetric set: want 1024/%d got %d/%d", down, got.RateUploadBPS, got.RateDownloadBPS)
	}

	// 清:0/0 表示「跟随全局默认」
	if err := st.SetDeviceRateLimit(ctx, d.ID, 0, 0); err != nil {
		t.Fatalf("clear: %v", err)
	}
	got, _ = st.GetDevice(ctx, d.ID)
	if got.RateUploadBPS != 0 || got.RateDownloadBPS != 0 {
		t.Errorf("after clear: want 0/0 got %d/%d", got.RateUploadBPS, got.RateDownloadBPS)
	}
}

// TestSetDeviceRateLimit_Invalid:负数 → ErrInvalid。
func TestSetDeviceRateLimit_Invalid(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	u, _ := st.CreateUser(ctx, NewUser{Username: "u", PSKHash: "h"})
	d, _ := st.UpsertDevice(ctx, u.ID, "a1b2c3d4-1111-4111-8111-000000000002", "x", "linux")

	for _, tc := range []struct {
		name     string
		up, down int64
	}{
		{"negative_up", -1, 0},
		{"negative_down", 0, -1},
		{"both_negative", -10, -20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := st.SetDeviceRateLimit(ctx, d.ID, tc.up, tc.down)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("want ErrInvalid, got %v", err)
			}
		})
	}
}

// TestSetDeviceRateLimit_NotFound:未知 device id → ErrNotFound。
func TestSetDeviceRateLimit_NotFound(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	err := st.SetDeviceRateLimit(ctx, 99999, 1024, 1024)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

// TestSetDeviceRateLimit_ListAllDevicesIncluded:0011 migration 改了 deviceSelectSQL,
// ListAllDevices / ListDevicesByUser 也要正确带出 rate_*_bps,否则 web 列表展示会丢字段。
func TestSetDeviceRateLimit_ListAllDevicesIncluded(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	u, _ := st.CreateUser(ctx, NewUser{Username: "u", PSKHash: "h"})
	d, _ := st.UpsertDevice(ctx, u.ID, "a1b2c3d4-1111-4111-8111-000000000003", "x", "linux")
	_ = st.SetDeviceRateLimit(ctx, d.ID, 2048, 4096)

	all, err := st.ListAllDevices(ctx)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("want 1 device, got %d", len(all))
	}
	if all[0].RateUploadBPS != 2048 || all[0].RateDownloadBPS != 4096 {
		t.Errorf("ListAllDevices missing rate fields: %+v", all[0])
	}

	byUser, _ := st.ListDevicesByUser(ctx, u.ID)
	if len(byUser) != 1 || byUser[0].RateUploadBPS != 2048 {
		t.Errorf("ListDevicesByUser missing rate fields: %+v", byUser)
	}
}
