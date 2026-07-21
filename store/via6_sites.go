package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// 4via6 站点 ID 的 store API（SR-VIA6）。表结构见 migrations/0017_via6_sites.sql。
//
// 语义:
//   - 每个「子网路由器(宣告方)设备」= 一个站点,分配一个稳定的 16 位 site_id;
//   - site_id 用 AUTOINCREMENT,删除不复用 → 跨重启稳定,绝不把旧站点的 4via6 地址错映射到新设备;
//   - 数据面收到 4via6 v6 包 → 解出 site_id → DeviceIDBySiteID 反查宣告方设备 → 投递。

// GetOrAssignSiteID 返回 device 的 4via6 site_id;尚未分配则分配一个(AUTOINCREMENT)。
// 幂等:同一 device 多次调用返回同一 site_id。site_id 保证落在 1..65535(uint16);超界报错(站点数超上限)。
func (s *Store) GetOrAssignSiteID(ctx context.Context, deviceID int64) (uint16, error) {
	if deviceID <= 0 {
		return 0, errors.New("store: bad device_id")
	}
	// 先查已有(热路径:绝大多数调用命中)。
	if sid, err := s.siteIDByDevice(ctx, deviceID); err == nil {
		return sid, nil
	} else if !errors.Is(err, ErrNotFound) {
		return 0, err
	}
	// 分配一条新记录。
	//
	// 深扫第十轮 LOW:改成**真事务**。旧实现是「INSERT 自动提交 → 若越界再 DELETE」,
	// 两步之间崩溃会把越界脏行永久留在表里(siteIDByDevice 命中它继续报错,device 被钉死)。
	// 现在在同一事务里 INSERT + 查 LastInsertId,越界直接 Rollback —— 越界脏行**从不提交**,
	// 彻底消除崩溃窗口。AUTOINCREMENT 的 sqlite_sequence 递增也随事务回滚,行为保持「已达上限」。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: assign site_id (begin): %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 提交后为 no-op;各错误分支的兜底回滚。

	res, err := tx.ExecContext(ctx,
		`INSERT INTO via6_sites(device_id, created_at) VALUES(?,?)`,
		deviceID, nowUnix())
	if err != nil {
		// 并发窗口:可能刚被另一路径插入(device_id UNIQUE 冲突)→ 先回滚本事务再查一次取既有值。
		_ = tx.Rollback()
		if sid, e2 := s.siteIDByDevice(ctx, deviceID); e2 == nil {
			return sid, nil
		}
		return 0, fmt.Errorf("store: assign site_id: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: assign site_id (lastid): %w", err)
	}
	if id <= 0 || id > 65535 {
		// 越界:直接 return,defer Rollback 撤销这条脏行(不落库)。
		return 0, i18nErr("store.via6.siteIDOverflow",
			fmt.Sprintf("store: site_id %d 超出 uint16 范围(4via6 站点数已达上限)", id), id)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: assign site_id (commit): %w", err)
	}
	return uint16(id), nil
}

// siteIDByDevice 查 device 已分配的 site_id;无则 ErrNotFound。
func (s *Store) siteIDByDevice(ctx context.Context, deviceID int64) (uint16, error) {
	var sid int64
	err := s.db.QueryRowContext(ctx,
		`SELECT site_id FROM via6_sites WHERE device_id=?`, deviceID).Scan(&sid)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	// 读路径与插入路径同一道界检查:手工改库 / AUTOINCREMENT 超过 65535 后,
	// 直接截断成 uint16 会把两个站点映射到同一 4via6 地址段 —— 宁可报错。
	if sid <= 0 || sid > 65535 {
		return 0, i18nErr("store.via6.siteIDOverflow",
			fmt.Sprintf("store: site_id %d 超出 uint16 范围(4via6 站点数已达上限)", sid), sid)
	}
	return uint16(sid), nil
}

// SiteIDByDevice 只读查 device 已分配的 4via6 site_id;未分配返回 ErrNotFound(MagicDNS 4via6 解析用,**绝不**主动分配
// ——普通非宣告方设备不该有 site_id,查不到即表示该设备不是子网路由器,4via6 主机名解析失败)。
func (s *Store) SiteIDByDevice(ctx context.Context, deviceID int64) (uint16, error) {
	return s.siteIDByDevice(ctx, deviceID)
}

// DeviceIDBySiteID 反查 site_id → device_id(数据面按 4via6 site_id 找宣告方设备用)。未分配返回 ErrNotFound。
func (s *Store) DeviceIDBySiteID(ctx context.Context, siteID uint16) (int64, error) {
	var dev int64
	err := s.db.QueryRowContext(ctx,
		`SELECT device_id FROM via6_sites WHERE site_id=?`, int64(siteID)).Scan(&dev)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return dev, nil
}

// ListVia6Sites 列出全部 device_id → site_id 映射(供数据面路由表重建 / routes-list 下发)。
func (s *Store) ListVia6Sites(ctx context.Context) (map[int64]uint16, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id, site_id FROM via6_sites`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int64]uint16)
	for rows.Next() {
		var dev, sid int64
		if err := rows.Scan(&dev, &sid); err != nil {
			return nil, err
		}
		// 与 siteIDByDevice 同口径:越界行跳过(不让一行脏数据废掉整张路由表),
		// 该站点等价「未分配」,数据面解析不到即投递失败,fail-closed。
		if sid <= 0 || sid > 65535 {
			continue
		}
		out[dev] = uint16(sid)
	}
	return out, rows.Err()
}
