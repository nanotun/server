package store

import (
	"errors"
	"testing"
)

func TestVia6Sites_AssignIdempotentAndLookup(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	dev1 := mustCreateDevice(t, s, u.ID, "dev1")
	dev2 := mustCreateDevice(t, s, u.ID, "dev2")

	// 首次分配 → 得一个 >=1 的 site_id。
	sid1, err := s.GetOrAssignSiteID(ctx, dev1)
	if err != nil {
		t.Fatalf("GetOrAssignSiteID(dev1): %v", err)
	}
	if sid1 == 0 {
		t.Fatal("site_id 不应为 0(AUTOINCREMENT 从 1 起)")
	}
	// 幂等:同 device 再调返回同值。
	sid1b, err := s.GetOrAssignSiteID(ctx, dev1)
	if err != nil {
		t.Fatalf("GetOrAssignSiteID(dev1) 二次: %v", err)
	}
	if sid1b != sid1 {
		t.Fatalf("同 device 分配不幂等: %d vs %d", sid1, sid1b)
	}
	// 另一 device → 不同 site_id。
	sid2, err := s.GetOrAssignSiteID(ctx, dev2)
	if err != nil {
		t.Fatalf("GetOrAssignSiteID(dev2): %v", err)
	}
	if sid2 == sid1 {
		t.Fatalf("不同 device 得到相同 site_id: %d", sid2)
	}

	// 反查 site_id → device_id。
	if got, err := s.DeviceIDBySiteID(ctx, sid1); err != nil || got != dev1 {
		t.Fatalf("DeviceIDBySiteID(%d) = (%d,%v), 期望 (%d,nil)", sid1, got, err, dev1)
	}
	if got, err := s.DeviceIDBySiteID(ctx, sid2); err != nil || got != dev2 {
		t.Fatalf("DeviceIDBySiteID(%d) = (%d,%v), 期望 (%d,nil)", sid2, got, err, dev2)
	}
	// 未分配的 site_id → ErrNotFound。
	if _, err := s.DeviceIDBySiteID(ctx, 60000); !errors.Is(err, ErrNotFound) {
		t.Fatalf("未分配 site_id 反查应 ErrNotFound, 得 %v", err)
	}

	// ListVia6Sites 覆盖两条映射。
	m, err := s.ListVia6Sites(ctx)
	if err != nil {
		t.Fatalf("ListVia6Sites: %v", err)
	}
	if m[dev1] != sid1 || m[dev2] != sid2 {
		t.Fatalf("ListVia6Sites 不符: %v (期望 dev1=%d dev2=%d)", m, sid1, sid2)
	}
}

func TestVia6Sites_BadDeviceID(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetOrAssignSiteID(t.Context(), 0); err == nil {
		t.Fatal("device_id=0 应报错")
	}
}

// TestVia6Sites_OverflowRollsBackPoisonedRow 钉住深扫第八/十轮 LOW 的回归:site_id 越过
// uint16 上限时,刚 INSERT 的那条脏行绝不能落库(第十轮已从「先 commit 再 DELETE」改成
// 真事务 Rollback)—— 否则该 device 会被永久钉死(下次 GetOrAssignSiteID 走 siteIDByDevice
// 命中脏行,同样越界报错)。
//
// 手法:直接把 AUTOINCREMENT 计数器(sqlite_sequence)顶到 70000,下一条插入拿到
// 70001 > 65535,触发溢出分支。
func TestVia6Sites_OverflowRollsBackPoisonedRow(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "bob", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	dev := mustCreateDevice(t, s, u.ID, "dev-overflow")

	// 把 via6_sites 的 AUTOINCREMENT seq 顶到 70000(> 65535)。空表时先清残留再写入。
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sqlite_sequence WHERE name='via6_sites'`); err != nil {
		t.Fatalf("clear sqlite_sequence: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO sqlite_sequence(name, seq) VALUES('via6_sites', 70000)`); err != nil {
		t.Fatalf("seed sqlite_sequence: %v", err)
	}

	// 下一条 INSERT → site_id=70001 → 溢出 → 报错。
	if _, err := s.GetOrAssignSiteID(ctx, dev); err == nil {
		t.Fatal("site_id 越界应报错")
	}

	// 关键断言:脏行已被回滚删除,device 回到「未分配」状态。
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM via6_sites WHERE device_id=?`, dev).Scan(&n); err != nil {
		t.Fatalf("count via6_sites: %v", err)
	}
	if n != 0 {
		t.Fatalf("溢出后应无残留脏行,却有 %d 条", n)
	}
	// siteIDByDevice 也应报「未分配」而不是命中脏行再次越界。
	if _, err := s.siteIDByDevice(ctx, dev); !errors.Is(err, ErrNotFound) {
		t.Fatalf("溢出回滚后 siteIDByDevice 应 ErrNotFound, 得 %v", err)
	}
}
