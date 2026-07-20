package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// P2#12 subnet route advertise store API。
//
// 业务语义:
//   - 客户端上报 → UpsertAdvertisedRoute(device_id, cidr) 写 (pending, advertised_at=now);
//     如果同 (device, cidr) 已存在,仅更新 advertised_at,**不**回退 approved 状态;
//   - admin 审批 → SetRouteStatus(id 或 (device, cidr), approved/rejected, reason);
//   - 客户端撤回(advertise 一条空列表) → DeleteAdvertisedRoutesForDevice 删未 approved 的,
//     已 approved 的保留(避免短暂网络抖动导致 approved 状态丢失);
//   - admin 删除某条 → DeleteRoute(id);
//
// 列出:
//   - ListRoutesByDevice / ListRoutesByStatus / ListAllRoutes(分页用 limit/offset)。

// Status 取值常量(与 util.RouteStatus* 对齐,store 这边再定义一份避免 import cycle)。
const (
	RouteStatusPending  = "pending"
	RouteStatusApproved = "approved"
	RouteStatusRejected = "rejected"
)

// SubnetRoute 是一行 subnet_routes 表。
type SubnetRoute struct {
	ID           int64
	DeviceID     int64
	CIDR         string
	Status       string
	AdvertisedAt int64
	ApprovedAt   int64
	Reason       string
}

// UpsertAdvertisedRoute 客户端上报路径用。已存在 → 仅 advertised_at = now;
// 不存在 → 新建一条 status=pending。
//
// 返回当前行(可能是 pending 也可能是已 approved 的旧行)。
func (s *Store) UpsertAdvertisedRoute(ctx context.Context, deviceID int64, cidr string) (*SubnetRoute, error) {
	cidr = strings.TrimSpace(cidr)
	if deviceID <= 0 || cidr == "" {
		return nil, errors.New("store: bad device_id/cidr")
	}
	now := nowUnix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO subnet_routes(device_id, cidr, status, advertised_at)
		 VALUES(?,?, 'pending', ?)
		 ON CONFLICT(device_id, cidr) DO UPDATE SET advertised_at = excluded.advertised_at`,
		deviceID, cidr, now,
	)
	if err != nil {
		return nil, fmt.Errorf("store: upsert route: %w", err)
	}
	return s.GetRouteByDeviceCIDR(ctx, deviceID, cidr)
}

// GetRouteByDeviceCIDR 单行查询。
func (s *Store) GetRouteByDeviceCIDR(ctx context.Context, deviceID int64, cidr string) (*SubnetRoute, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, device_id, cidr, status, advertised_at, approved_at, reason
		 FROM subnet_routes WHERE device_id=? AND cidr=?`,
		deviceID, cidr)
	var r SubnetRoute
	if err := row.Scan(&r.ID, &r.DeviceID, &r.CIDR, &r.Status, &r.AdvertisedAt, &r.ApprovedAt, &r.Reason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

// SetRouteStatus 把一条 (device, cidr) 路由审批为 approved / rejected。
// status 必须是 approved/rejected/pending 之一,其它返回 error。
// reason 仅在 rejected 时记录,其它情况下被清空。
func (s *Store) SetRouteStatus(ctx context.Context, deviceID int64, cidr, status, reason string) error {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case RouteStatusPending, RouteStatusApproved, RouteStatusRejected:
	default:
		return fmt.Errorf("store: bad status %q", status)
	}
	if status != RouteStatusRejected {
		reason = ""
	}
	now := nowUnix()
	var approvedAt int64
	if status == RouteStatusApproved {
		approvedAt = now
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE subnet_routes SET status=?, approved_at=?, reason=? WHERE device_id=? AND cidr=?`,
		status, approvedAt, reason, deviceID, cidr)
	if err != nil {
		return fmt.Errorf("store: set route status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteRoute 删除单行(admin 显式删,审批已通过的也能删)。
func (s *Store) DeleteRoute(ctx context.Context, deviceID int64, cidr string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM subnet_routes WHERE device_id=? AND cidr=?`, deviceID, cidr)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAdvertisedRoutesForDevice 在客户端发空 advertise 时调用:
// 只删 status='pending' 的条目;approved/rejected 保留(由 admin 显式管理)。
// 返回删除条数(可用于 audit / debug)。
func (s *Store) DeleteAdvertisedRoutesForDevice(ctx context.Context, deviceID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM subnet_routes WHERE device_id=? AND status='pending'`,
		deviceID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListRoutesByDevice 列出某 device 下所有 route。
func (s *Store) ListRoutesByDevice(ctx context.Context, deviceID int64) ([]SubnetRoute, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, device_id, cidr, status, advertised_at, approved_at, COALESCE(reason,'')
		 FROM subnet_routes WHERE device_id=? ORDER BY cidr ASC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoutes(rows)
}

// ListRoutesByStatus 按状态列出(admin 看 pending 队列用)。
func (s *Store) ListRoutesByStatus(ctx context.Context, status string) ([]SubnetRoute, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, device_id, cidr, status, advertised_at, approved_at, COALESCE(reason,'')
		 FROM subnet_routes WHERE status=? ORDER BY advertised_at DESC, id DESC`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoutes(rows)
}

// ListAllRoutes 列全表(typical 路由数百行内,不分页)。
func (s *Store) ListAllRoutes(ctx context.Context) ([]SubnetRoute, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, device_id, cidr, status, advertised_at, approved_at, COALESCE(reason,'')
		 FROM subnet_routes ORDER BY device_id ASC, cidr ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoutes(rows)
}

func scanRoutes(rows *sql.Rows) ([]SubnetRoute, error) {
	var out []SubnetRoute
	for rows.Next() {
		var r SubnetRoute
		if err := rows.Scan(&r.ID, &r.DeviceID, &r.CIDR, &r.Status, &r.AdvertisedAt, &r.ApprovedAt, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
