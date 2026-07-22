package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// FRP 式反向端口转发映射的 store API（schema v18，见 migrations/0018_port_forwards.sql）。
//
// 语义：外部公网访问 server 的 PublicPort（TCP），由 server 转发到 mesh 节点自身端口（node 目标：
// TargetIP = 设备 vIP）或其 LAN 后设备（LAN 目标：TargetIP 在该设备已批准宣告网段内）。映射由 web 后台
// 增删；server 端口转发管理器按 enabled 行启停监听（见 cmd/nanotund/port_forward.go），改动经 control-socket
// /reload?what=portforward 实时生效。

// PortForward 是一行 port_forwards 表。
type PortForward struct {
	ID               int64
	PublicPort       int
	Proto            string
	TargetDeviceUUID string
	TargetIP         string
	TargetPort       int
	Enabled          bool
	Comment          string
	CreatedAt        int64
}

const portForwardSelectSQL = `SELECT id, public_port, proto, target_device_uuid, target_ip, target_port, enabled, COALESCE(comment,''), created_at FROM port_forwards`

// CreatePortForward 新增一条映射。public_port 冲突 → ErrDuplicate；端口越界 / 空目标 / 非 tcp → error。
func (s *Store) CreatePortForward(ctx context.Context, pf PortForward) (*PortForward, error) {
	proto := strings.ToLower(strings.TrimSpace(pf.Proto))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" {
		return nil, fmt.Errorf("store: unsupported proto %q (only tcp for now)", proto)
	}
	if pf.PublicPort <= 0 || pf.PublicPort > 65535 || pf.TargetPort <= 0 || pf.TargetPort > 65535 {
		return nil, errors.New("store: port out of range (1..65535)")
	}
	uuid := strings.ToLower(strings.TrimSpace(pf.TargetDeviceUUID))
	ip := strings.TrimSpace(pf.TargetIP)
	if uuid == "" || ip == "" {
		return nil, errors.New("store: empty target_device_uuid/target_ip")
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO port_forwards(public_port, proto, target_device_uuid, target_ip, target_port, enabled, comment, created_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		pf.PublicPort, proto, uuid, ip, pf.TargetPort, boolToInt(pf.Enabled), strings.TrimSpace(pf.Comment), nowUnix())
	if err != nil {
		if isUniqueConstraintErr(err) {
			// i18nErrWrap:Error() 与原 `%w` 输出逐字节一致(%v == %w 的 .Error()),
			// 且 Unwrap→ErrDuplicate 让 errors.Is(err, ErrDuplicate) 照常成立。
			return nil, i18nErrWrap("store.pf.portOccupied",
				fmt.Sprintf("store: public_port %d 已被占用: %v", pf.PublicPort, ErrDuplicate),
				ErrDuplicate, pf.PublicPort)
		}
		return nil, fmt.Errorf("store: create port_forward: %w", err)
	}
	// 显式检查 LastInsertId 错误:此前忽略 err,若驱动返回 (0, err) 会用 id=0 去 GetPortForward,
	// 撞出 ErrNotFound —— 把「插入其实成功了但拿不到 rowid」误报成「没找到」,调用方无从区分。
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: port_forward last insert id: %w", err)
	}
	return s.GetPortForward(ctx, id)
}

// GetPortForward 按 id 单行查询。无 → ErrNotFound。
func (s *Store) GetPortForward(ctx context.Context, id int64) (*PortForward, error) {
	row := s.db.QueryRowContext(ctx, portForwardSelectSQL+` WHERE id=?`, id)
	return s.scanPortForwardRow(row)
}

// DeletePortForward 删除一条映射。不存在 → ErrNotFound。
func (s *Store) DeletePortForward(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM port_forwards WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPortForwardEnabled 启用/停用一条映射。不存在 → ErrNotFound。
func (s *Store) SetPortForwardEnabled(ctx context.Context, id int64, enabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE port_forwards SET enabled=? WHERE id=?`, boolToInt(enabled), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPortForwards 列全表（按 public_port 升序）。
func (s *Store) ListPortForwards(ctx context.Context) ([]PortForward, error) {
	rows, err := s.db.QueryContext(ctx, portForwardSelectSQL+` ORDER BY public_port ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPortForwards(rows)
}

// ListEnabledPortForwards 仅列 enabled=1（供 server 端口转发管理器启监听）。
func (s *Store) ListEnabledPortForwards(ctx context.Context) ([]PortForward, error) {
	rows, err := s.db.QueryContext(ctx, portForwardSelectSQL+` WHERE enabled=1 ORDER BY public_port ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPortForwards(rows)
}

func (s *Store) scanPortForwardRow(row *sql.Row) (*PortForward, error) {
	var pf PortForward
	var enabled int
	if err := row.Scan(&pf.ID, &pf.PublicPort, &pf.Proto, &pf.TargetDeviceUUID, &pf.TargetIP, &pf.TargetPort, &enabled, &pf.Comment, &pf.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	pf.Enabled = enabled != 0
	return &pf, nil
}

func scanPortForwards(rows *sql.Rows) ([]PortForward, error) {
	var out []PortForward
	for rows.Next() {
		var pf PortForward
		var enabled int
		if err := rows.Scan(&pf.ID, &pf.PublicPort, &pf.Proto, &pf.TargetDeviceUUID, &pf.TargetIP, &pf.TargetPort, &enabled, &pf.Comment, &pf.CreatedAt); err != nil {
			return nil, err
		}
		pf.Enabled = enabled != 0
		out = append(out, pf)
	}
	return out, rows.Err()
}
