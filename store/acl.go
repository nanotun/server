package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ACLAction 列出当前支持的动作。
const (
	ACLAllow = "allow"
	ACLDeny  = "deny"
)

// ValidateACLDefaultActionSetting 校验 acl_default_action 的写入值:大小写/空白不敏感,
// 必须是 "allow" 或 "deny"。用于 CLI `setting set acl_default_action` 的 write 路径兜底,
// 防止拼错(如 "deni")落库后被数据面读取时按 fail-closed 兜到 deny(见 acl_runtime.go),
// 运维却以为设成了别的值。
func ValidateACLDefaultActionSetting(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ACLAllow, ACLDeny:
		return nil
	}
	return fmt.Errorf("acl_default_action must be %q or %q, got %q", ACLAllow, ACLDeny, v)
}

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
		// 深扫第八轮 MED:UNIQUE 冲突归一化为 ErrDuplicate,与 users / leases 等 DAL 一致。
		// 否则同一条 (src,dst,proto,port,kind) 规则重复添加时向上抛裸驱动错误,web 侧只能
		// 渲染成通用 500(而非「规则已存在」的可读提示)。
		if isUniqueConstraintErr(err) {
			return nil, ErrDuplicate
		}
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
//
// ⚠️ 深扫第十二轮 LOW —— 语义边界(切勿在生产判定路径复用):本函数**不代表**真实数据面
// ACL 裁决。它有意采用固定的「规则集非空且无命中 → deny」朴素默认,**不读取**
// app_settings.acl_default_action(其 seed 默认恰是 allow),也**不考虑** proto / port /
// dst_kind(user/exit)等 ACL v2 维度。真实裁决只在 cmd/nanotund/acl_runtime.go 的
// snapshot 路径,那里按 acl_default_action + 逐条 proto/port/exit 规则做 deny-first。
// 本函数仅供「用户对」粗判 / 单测。若未来需要「与数据面一致的后台核对」,应改为复用
// acl_runtime 的 evaluate 逻辑,而不是在这里塞一个 acl_default_action 分支(会与既有
// 单测的 default-deny 语义冲突)。
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
	// created_at 用一个宽松的容器接,别的列照旧严格。
	//
	// 它只用来显示,不参与任何放行判断(acl_runtime 拿到规则后根本不读这个字段)。而
	// SQLite 是动态类型:列声明成 INTEGER 也拦不住外部工具往里写字符串。此前一个歪了的
	// 时间戳会让整条 ListACLPairs 失败,后果不成比例 —— 数据面在启动期拒绝上线(拒绝
	// 本身是对的,ACL 装不全就不该以放行姿态开门),而理由是一列它根本不看的元数据;
	// 更糟的是 `acl ls` 走同一个 scan,于是人既看不到是哪条坏了、也没有 CLI 能删它,
	// 只剩手改数据库这一条路 —— 而那正是文档反复劝阻的事。
	//
	// 现在:时间戳读不懂就当 0(列表里显示为空),规则本身照常装载、照常生效。action /
	// proto / 端口这些真正决定放行的列仍然严格 —— 它们歪了就该整条拒绝。
	var createdAt any
	if err := sc.Scan(&a.ID, &a.SrcUserID, &a.DstUserID, &a.Action,
		&a.Proto, &a.DstPortLo, &a.DstPortHi, &a.DstKind, &createdAt); err != nil {
		return nil, err
	}
	a.CreatedAt = CoerceUnixSeconds(createdAt)
	return &a, nil
}

// CoerceUnixSeconds 把 SQLite 里一列时间戳可能是的几种东西折成 unix 秒;认不出来就是 0。
//
// 我们自己写的永远是整数,字符串只会来自外部写入(手改库、第三方脚本、从别处导回来的
// 备份)。既然认得出来就顺手认了,认不出也不该因此丢掉整行 —— 时间戳是给人看的,
// 不参与任何判断。导出是因为 nanotun-admin 的列表查询自带 JOIN、不走这里的 scan,
// 两边得是同一套宽容度,否则「服务起得来但 acl ls 看不见」这种错位又会回来。
func CoerceUnixSeconds(v any) int64 {
	switch t := v.(type) {
	case nil:
		return 0
	case int64:
		return t
	case float64:
		return int64(t)
	case []byte:
		return CoerceUnixSeconds(string(t))
	case time.Time:
		return t.Unix()
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
		// SQLite 的 datetime() 默认吐这个形状,且是 UTC。
		for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339} {
			if ts, err := time.Parse(layout, s); err == nil {
				return ts.Unix()
			}
		}
		return 0
	default:
		return 0
	}
}

func nullableInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
