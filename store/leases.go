package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Lease 表示一台设备的 vIP 持久化分配。
//
// 一台设备至多保留一个 v4 + 一个 v6 vIP；Manual=true 表示由管理员手动指定，
// AllocOrLeaseVIP 不会自动改写。
type Lease struct {
	ID         int64
	DeviceID   int64
	VIPv4      string
	VIPv6      string
	Manual     bool
	AssignedAt int64
}

// GetLeaseByDevice 查询某台设备的现有租约。无租约时返回 ErrNotFound。
func (s *Store) GetLeaseByDevice(ctx context.Context, deviceID int64) (*Lease, error) {
	row := s.db.QueryRowContext(ctx, leaseSelectSQL+` WHERE device_id=?`, deviceID)
	l, err := s.scanLeaseCols(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return l, err
}

// UpsertLease 写入或更新租约：保留 manual 标记，刷新 v4 / v6 / assigned_at。
//
// 调用方传入空字符串视为「该协议下无 vIP」，并在数据库里存为 NULL（受唯一索引约束）。
func (s *Store) UpsertLease(ctx context.Context, deviceID int64, vipV4, vipV6 string, manual bool) (*Lease, error) {
	now := nowUnix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO leases(device_id, vip_v4, vip_v6, manual, assigned_at)
		 VALUES(?,?,?,?,?)
		 ON CONFLICT(device_id) DO UPDATE SET
		   vip_v4=excluded.vip_v4,
		   vip_v6=excluded.vip_v6,
		   manual=excluded.manual,
		   assigned_at=excluded.assigned_at`,
		deviceID, nullableString(vipV4), nullableString(vipV6), boolToInt(manual), now,
	)
	if err != nil {
		// idx_leases_vip_v4 / _v6 UNIQUE 冲突意味着「这个 vIP 已经被另一台设备持有」。
		// 之前直接 %w 透传 modernc.org/sqlite 的内部错误,调用方无法区分这种业务级冲突
		// 与「IO 错误」「Disk 满」等系统错误,结果是 cmd/nanotund/alloc_lease.go 用 Warn 吞掉,
		// 数据面双重占用同一个 vIP -> 路由黑洞。
		//
		// 现在显式归一化为 ErrDuplicate,让调用方 errors.Is 后拒登/重新分配。
		if isUniqueConstraintErr(err) {
			return nil, i18nErrWrap("store.lease.vipConflict",
				fmt.Sprintf("store: upsert lease vIP 冲突 (device=%d v4=%q v6=%q): %s", deviceID, vipV4, vipV6, ErrDuplicate.Error()),
				ErrDuplicate, deviceID, vipV4, vipV6, ErrDuplicate.Error())
		}
		return nil, fmt.Errorf("store: upsert lease: %w", err)
	}
	return s.GetLeaseByDevice(ctx, deviceID)
}

// DeleteLease 删除一台设备的租约（在管理员手动释放时调用）。
//
// 若该 device_id 当前没有租约,返回 ErrNotFound —— 让 admin CLI 能区分
// 「真的删除成功」与「传错 device_id / 已经释放过」。否则误操作会无声成功。
func (s *Store) DeleteLease(ctx context.Context, deviceID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM leases WHERE device_id=?`, deviceID)
	if err != nil {
		return fmt.Errorf("store: delete lease: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AllUsedVIPs 返回当前已被任何租约占用的 vIP 集合，按 v4 / v6 分开。
//
// AllocOrLeaseVIP 在为新设备分配地址时把它们传给 server.AllocClientIP 作为 used 集。
func (s *Store) AllUsedVIPs(ctx context.Context) (v4 map[string]bool, v6 map[string]bool, err error) {
	v4 = map[string]bool{}
	v6 = map[string]bool{}

	rows, err := s.db.QueryContext(ctx, `SELECT vip_v4, vip_v6 FROM leases`)
	if err != nil {
		return nil, nil, fmt.Errorf("store: list leases: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s4, s6 sql.NullString
		if err := rows.Scan(&s4, &s6); err != nil {
			return nil, nil, err
		}
		if s4.Valid && s4.String != "" {
			v4[s4.String] = true
		}
		if s6.Valid && s6.String != "" {
			v6[s6.String] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// 0008(2026-05-23):固定 vIP 已从 users 表迁到 devices 表。这里也跟着改 —
	// 任何 device.fixed_vip_* 都必须从「可用 vIP 集合」里排除,即便该 device 还没拿到
	// lease 也算占用(否则 admin 钉的 fixed_vip 会被自动分配给别人,登录时撞 UNIQUE 失败)。
	drows, err := s.db.QueryContext(ctx, `SELECT COALESCE(fixed_vip_v4,''), COALESCE(fixed_vip_v6,'') FROM devices`)
	if err != nil {
		return nil, nil, fmt.Errorf("store: list device fixed vip: %w", err)
	}
	defer drows.Close()
	for drows.Next() {
		var f4, f6 string
		if err := drows.Scan(&f4, &f6); err != nil {
			return nil, nil, err
		}
		if f4 != "" {
			v4[f4] = true
		}
		if f6 != "" {
			v6[f6] = true
		}
	}
	return v4, v6, drows.Err()
}

// GcOrphanLeases 删除所有「设备已长期失联」的非手动 lease,释放占用的 vIP。
//
// 触发条件(全部满足):
//   - leases.manual = 0(手动指定的固定 vIP 永远不自动回收,留给管理员处理);
//   - devices.last_seen_at + idle.Seconds() < now;
//   - 同时清理 users.fixed_vip_v4/fixed_vip_v6 ? **不**清。fixed_vip 是用户级
//     长期绑定,与设备活跃度无关,只能管理员手工 unset。
//
// 设备行本身**不**删除:
//   - 同 UUID 重新上线时(如客户端重启)仍可命中老 device 行,新分配的 vIP
//     按 sticky 策略可能给老 IP(因为 lease 已删,需重新分配);
//   - 即使重装后 UUID 变了,老 device 留下也只是空记录,无 lease 占资源;
//   - admin 命令 `device delete` 提供显式删除路径。
//
// 返回被删的 lease 个数。idle <= 0 时直接 no-op(防止误用 idle=0 把所有 lease 全删)。
func (s *Store) GcOrphanLeases(ctx context.Context, idle int64) (int64, error) {
	if idle <= 0 {
		return 0, i18nErr("store.lease.gcIdlePositive", "store: GcOrphanLeases idle 必须 > 0 秒")
	}
	cutoff := nowUnix() - idle
	// GC 守卫(纵深防御):除了 manual=0,再显式排除「lease 的 vip 正是该 device 的 fixed_vip」的行。
	// 正常路径下 SetDeviceFixedVIP 已在同一事务里把 fixed_vip 与 leases.manual 同步,manual=1 本就挡住回收;
	// 但历史行 / 老迁移 / 外部直接写库可能造成 manual 漂移成 0 而 fixed_vip 仍在 —— 只靠 manual 会把管理员手钉的
	// 固定地址当空闲回收,设备再上线拿不回固定 vIP。这里以 fixed_vip 实值兜底,任何与 fixed_vip 匹配的 lease 永不回收。
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM leases
		WHERE manual = 0
		  AND device_id IN (
		      SELECT id FROM devices WHERE last_seen_at < ?
		  )
		  AND id NOT IN (
		      SELECT l.id FROM leases l
		      JOIN devices d ON d.id = l.device_id
		      WHERE (COALESCE(d.fixed_vip_v4,'') <> '' AND d.fixed_vip_v4 = l.vip_v4)
		         OR (COALESCE(d.fixed_vip_v6,'') <> '' AND d.fixed_vip_v6 = l.vip_v6)
		  )`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: gc orphan leases: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

const leaseSelectSQL = `SELECT id, device_id, COALESCE(vip_v4,''), COALESCE(vip_v6,''), manual, assigned_at FROM leases`

func (s *Store) scanLeaseCols(sc rowScanner) (*Lease, error) {
	var l Lease
	var manual int64
	if err := sc.Scan(&l.ID, &l.DeviceID, &l.VIPv4, &l.VIPv6, &manual, &l.AssignedAt); err != nil {
		return nil, err
	}
	l.Manual = manual != 0
	return &l, nil
}
