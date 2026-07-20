package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ACLAction 列出当前支持的动作。
const (
	ACLAllow = "allow"
	ACLDeny  = "deny"
)

// ACL dst_kind 取值。
const (
	// ACLDstKindUser:规则匹配「dst 是某 user 的 vIP」流量(默认,与 v1 行为一致)。
	ACLDstKindUser = "user"
	// ACLDstKindExit:规则匹配「dst 不在任何 user 的 vIP 上,即出口公网」流量。
	// dst_user_id 必须为 NULL(0);proto / port 仍可以叠加。
	ACLDstKindExit = "exit"
)

// ACLPair 描述一条扩展后的 ACL 规则(schema v3)。
//
// SrcUserID / DstUserID 为 0 时表示通配。
//
// Proto:空串 = 任意协议;否则取 "tcp" / "udp" / "icmp" / "icmpv6"。
// DstPortLo / DstPortHi:闭区间;同时为 0 表示「任意端口」。
//
//	单端口:DstPortLo == DstPortHi。
//
// DstKind:取值见 ACLDstKindUser / ACLDstKindExit。
type ACLPair struct {
	ID        int64
	SrcUserID int64
	DstUserID int64
	Action    string
	Proto     string
	DstPortLo int
	DstPortHi int
	DstKind   string
	CreatedAt int64
}

// NewACLPair 描述新规则的可选字段。零值合理,等价于 v1 的 (src,dst,action)。
type NewACLPair struct {
	SrcUserID int64
	DstUserID int64
	Action    string
	Proto     string
	DstPortLo int
	DstPortHi int
	DstKind   string
}

// AddACLPair 写入一条 ACL 规则。重复的唯一键组合会被 UNIQUE 索引拦截。
//
// 兼容老调用(只有 src/dst/action 三参的旧形态)由 AddACLPairBasic 提供。
func (s *Store) AddACLPair(ctx context.Context, in NewACLPair) (*ACLPair, error) {
	if in.Action == "" {
		in.Action = ACLAllow
	}
	if in.Action != ACLAllow && in.Action != ACLDeny {
		return nil, fmt.Errorf("store: invalid acl action %q", in.Action)
	}
	if in.DstKind == "" {
		in.DstKind = ACLDstKindUser
	}
	if in.DstKind != ACLDstKindUser && in.DstKind != ACLDstKindExit {
		return nil, fmt.Errorf("store: invalid acl dst_kind %q", in.DstKind)
	}
	if in.DstKind == ACLDstKindExit && in.DstUserID != 0 {
		return nil, fmt.Errorf("store: acl dst_kind=exit must not pin dst_user_id")
	}
	switch in.Proto {
	case "", "tcp", "udp", "icmp", "icmpv6":
	default:
		return nil, fmt.Errorf("store: invalid acl proto %q", in.Proto)
	}
	if in.DstPortLo < 0 || in.DstPortLo > 65535 || in.DstPortHi < 0 || in.DstPortHi > 65535 {
		return nil, fmt.Errorf("store: acl port out of range")
	}
	if in.DstPortLo == 0 && in.DstPortHi != 0 {
		in.DstPortLo = in.DstPortHi
	}
	if in.DstPortHi == 0 && in.DstPortLo != 0 {
		in.DstPortHi = in.DstPortLo
	}
	if in.DstPortLo > in.DstPortHi {
		return nil, fmt.Errorf("store: acl port range lo>hi")
	}
	// port 范围只对 tcp/udp 有意义;icmp 不带端口,proto='' 也只允许全 0(避免歧义)。
	if (in.DstPortLo != 0 || in.DstPortHi != 0) && in.Proto != "tcp" && in.Proto != "udp" {
		return nil, fmt.Errorf("store: acl port range only valid for tcp/udp")
	}
	now := nowUnix()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO acl_pairs(src_user_id, dst_user_id, action, proto, dst_port_lo, dst_port_hi, dst_kind, created_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		nullableInt(in.SrcUserID), nullableInt(in.DstUserID), in.Action,
		in.Proto, in.DstPortLo, in.DstPortHi, in.DstKind, now,
	)
	if err != nil {
		return nil, fmt.Errorf("store: add acl: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: acl last insert id: %w", err)
	}
	return s.GetACLPair(ctx, id)
}

// AddACLPairBasic 是 v1 三参 helper,保留给 CLI / 测试少代码迁移用。
func (s *Store) AddACLPairBasic(ctx context.Context, src, dst int64, action string) (*ACLPair, error) {
	return s.AddACLPair(ctx, NewACLPair{SrcUserID: src, DstUserID: dst, Action: action})
}

// GetACLPair 按主键取一条规则。
func (s *Store) GetACLPair(ctx context.Context, id int64) (*ACLPair, error) {
	row := s.db.QueryRowContext(ctx, aclSelectSQL+` WHERE id=?`, id)
	a, err := s.scanACLCols(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// ListACLPairs 返回所有 ACL 规则，按 id 升序。
func (s *Store) ListACLPairs(ctx context.Context) ([]*ACLPair, error) {
	rows, err := s.db.QueryContext(ctx, aclSelectSQL+` ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list acl: %w", err)
	}
	defer rows.Close()
	var out []*ACLPair
	for rows.Next() {
		a, err := s.scanACLCols(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteACLPair 删除一条 ACL 规则。
func (s *Store) DeleteACLPair(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM acl_pairs WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: delete acl: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// IsAllowed 判断 src→dst 是否被允许。
//
// M0 规则（朴素实现）：
//   - 同一 user 内部默认放行；
//   - 否则若有任意 (src, dst) 的 deny 规则，拒绝；
//   - 否则若有任意 (src, dst) 的 allow 规则，放行；
//   - 否则若 ACL 规则集为空（用户没启用 ACL），全部放行；
//   - 其它情况一律拒绝（默认 deny）。
//
// 数据面已接入(P0-1, 2026-05-22):cmd/nanotund/acl_runtime.go 在启动 / SIGHUP 时
// `ListACLPairs` 一次,构建 in-memory snapshot;TUN demux 路径(`tunDemuxToLink` /
// `LinkTypeIPPacket`)按 srcUserID(连接来源)+ dstUserID(目的 vIP 反查)按规则裁决,
// 命中 deny 直接 drop,不入 TUN。本函数(IsAllowed)是带 SQLite 直查的"次选 / 后台校验"
// 路径,适合 admin CLI / 一次性核对场景,不要在 per-packet 热路径调用 —— 走 snapshot。
//
// 新增 / 删除规则后,需要 `kill -HUP $(pidof nanotund)` 或 `systemctl reload`
// 让运行中进程把内存 snapshot 替换,**未 reload 不影响已建立连接的 packet routing**。
func (s *Store) IsAllowed(ctx context.Context, srcUserID, dstUserID int64) (bool, error) {
	if srcUserID == dstUserID {
		return true, nil
	}

	var hasAnyRule int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM acl_pairs`).Scan(&hasAnyRule); err != nil {
		return false, fmt.Errorf("store: count acl: %w", err)
	}
	if hasAnyRule == 0 {
		return true, nil
	}

	var denyN int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM acl_pairs WHERE action='deny' AND
		  (src_user_id=? OR src_user_id IS NULL) AND (dst_user_id=? OR dst_user_id IS NULL)`,
		srcUserID, dstUserID,
	).Scan(&denyN); err != nil {
		return false, fmt.Errorf("store: query acl deny: %w", err)
	}
	if denyN > 0 {
		return false, nil
	}

	var allowN int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM acl_pairs WHERE action='allow' AND
		  (src_user_id=? OR src_user_id IS NULL) AND (dst_user_id=? OR dst_user_id IS NULL)`,
		srcUserID, dstUserID,
	).Scan(&allowN); err != nil {
		return false, fmt.Errorf("store: query acl allow: %w", err)
	}
	return allowN > 0, nil
}

const aclSelectSQL = `SELECT id, COALESCE(src_user_id,0), COALESCE(dst_user_id,0), action,
	proto, dst_port_lo, dst_port_hi, dst_kind, created_at FROM acl_pairs`

func (s *Store) scanACLCols(sc rowScanner) (*ACLPair, error) {
	var a ACLPair
	if err := sc.Scan(&a.ID, &a.SrcUserID, &a.DstUserID, &a.Action,
		&a.Proto, &a.DstPortLo, &a.DstPortHi, &a.DstKind, &a.CreatedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

func nullableInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
