package store

import (
	"errors"
	"testing"
)

// TestGetDeviceByUUIDAny 覆盖 FRP 端口转发运行时按 UUID 解析设备的路径：
//   - 找得到（大小写归一）；
//   - 找不到 → ErrNotFound；
//   - 同一 UUID 分属两个 user 时 → ErrAmbiguousDevice(第六轮深扫 HIGH:fail-closed,防跨租户劫持)。
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

	// 同一 UUID 分属两个 user:跨租户碰撞 → fail-closed 返回 ErrAmbiguousDevice(而非静默取一条)。
	// 这样 FRP 转发对歧义 UUID 直接不建立,攻击者无法用「注册同名 UUID + 保持更近活跃」劫持他人转发。
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
	if _, err := s.GetDeviceByUUIDAny(ctx, uuid); !errors.Is(err, ErrAmbiguousDevice) {
		t.Fatalf("同 UUID 多 user 应 fail-closed ErrAmbiguousDevice, 得 %v", err)
	}
	_ = d2
}
