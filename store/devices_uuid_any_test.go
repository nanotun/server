package store

import (
	"errors"
	"testing"
)

// TestGetDeviceByUUIDAny 覆盖 FRP 端口转发运行时按 UUID 解析设备的路径：
//   - 找得到（大小写归一）；
//   - 找不到 → ErrNotFound；
//   - 同一 UUID 分属两个 user 时，按 last_seen_at 倒序取最近活跃的一条（行为确定）。
func TestGetDeviceByUUIDAny(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u1, err := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser alice: %v", err)
	}
	uuid := "D2B65929-90C5-4382-A964-67C2009CD425" // 混大小写：写入按小写归一
	d1, err := s.UpsertDevice(ctx, u1.ID, uuid, "alice-mbp", "macos")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	// 大小写不敏感命中。
	got, err := s.GetDeviceByUUIDAny(ctx, uuid)
	if err != nil {
		t.Fatalf("GetDeviceByUUIDAny: %v", err)
	}
	if got.ID != d1.ID {
		t.Fatalf("命中错误设备: got id=%d want %d", got.ID, d1.ID)
	}

	// 未注册 UUID → ErrNotFound。
	if _, err := s.GetDeviceByUUIDAny(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("未注册应 ErrNotFound, 得 %v", err)
	}

	// 同一 UUID 分属两个 user：取 last_seen_at 更大的（此处 u2 后写，last_seen 更新）→ 确定性。
	u2, err := s.CreateUser(ctx, NewUser{Username: "bob", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser bob: %v", err)
	}
	d2, err := s.UpsertDevice(ctx, u2.ID, uuid, "bob-pc", "windows")
	if err != nil {
		t.Fatalf("UpsertDevice bob: %v", err)
	}
	if err := s.TouchDevice(ctx, d2.ID); err != nil {
		t.Fatalf("TouchDevice: %v", err)
	}
	got2, err := s.GetDeviceByUUIDAny(ctx, uuid)
	if err != nil {
		t.Fatalf("GetDeviceByUUIDAny(dup): %v", err)
	}
	if got2.ID != d2.ID {
		t.Fatalf("同 UUID 多 user 应取最近活跃(d2=%d), 得 %d", d2.ID, got2.ID)
	}
}
