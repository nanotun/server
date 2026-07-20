package store

import (
	"context"
	"fmt"
)

// AuditLog 一条审计记录。actor / action / target 都是非空字符串,detail 可空。
// 设计为 append-only 风格,不提供 Update,只 Insert + 按时间查询。
type AuditLog struct {
	ID     int64
	Actor  string
	Action string
	Target string
	Detail string
	At     int64
}

// Audit 写一条审计日志。失败仅返回 error 让调用方决定是否打 logrus.Warn,
// **不**让审计 IO 影响业务路径(典型用法是 `_ = st.Audit(ctx, ...)`,审计丢一条
// 比让登录卡 5s 等 DB 更重要)。
//
// 常见 action 命名(供调用方对齐,store 不强制枚举):
//
// 两种风格**有意区分**(2026-05-26 第三轮深扫澄清):
//
//   - **dot 风格 `xx.yy.zz`** —— runtime / server 自发事件,**保留 hierarchy 语义**,
//     `nanotun-admin audit list --action-prefix login.fail` 能一次抓所有失败子分类。
//
//   - "login.success" / "login.takeover"
//
//   - "login.fail.user_not_found" / "login.fail.bad_psk" / "login.fail.ratelimit"
//
//   - "login.takeover.fail.<reason>"
//
//   - "kick.received" / "kick.applied"
//
//   - "lease.allocated" / "lease.released" / "lease.gc"
//
//   - "acl.drop.agg" / "acl.drop"
//
//   - **underscore 风格 `xx_yy`** —— admin 主动 CRUD 类事件,无需 hierarchy,
//     调用方为 CLI / Web Console。
//
//   - "user_create" / "user_disable" / "user_delete" / "user_reset_psk"
//
//   - "user_reset_psk_failed" / "user_reset_psk_raced"(第六/七轮新增,见下方备注)
//
//   - "user_create_stash_failed" / "user_reset_psk_stash_failed"(PRG flash 暂存失败)
//
//   - "credentials_rotate_psk" / "credentials_show"
//
//   - "device_create" / "device_set_rate"
//
//   - "totp_setup_start" / "totp_enable" / "totp_disable"
//
//   - "recovery_regenerate"
//
//   - "mesh_toggle" / "mesh_toggle_fail"
//
//   - "settings_rate_default_set" / "settings_advertised_host_set" /
//     "settings_server_dial_host_set"(+ `_dns_fail` / `_icmp_softfail` /
//     `_icmp_softfail_skipped` / `_probe_unknown` / `_probe_unknown_skipped`
//     失败 sibling,2026-05-26 第六轮起 ping probe 上线;第十一轮加 `_skipped`
//     后缀区分 admin 主动 bypass 的 ICMP 软错入库路径,便于事后追踪)
//
//   - "server_profile_qr_show" / "server_profile_qr_password_fail" /
//     "server_profile_qr_locked" / "server_profile_qr_no_dial_host" /
//     "server_profile_qr_failed"(2026-05-26 第十一轮新增 sibling 簇,详见下方备注;
//     第六轮拆字段把 `_no_advertised_host` 改名为 `_no_dial_host`,阻断键从展示
//     label 切到真实 dial target)
//
// 备注(第八轮深扫):`user_reset_psk_*` 三个 sibling 是「同一动作的不同结局」,
// 运维诊断时可批量过滤:`--action-prefix user_reset_psk` 拿到 4 条变体,然后用
// 后缀(空 = 成功 / `_raced` = CAS 并发 / `_failed` = DB/hash 故障 /
// `_stash_failed` = PSK 已落库但 QR 通道异常)定位根因。
// `_raced` 走 Web 路径时 actor 是 `web:<username>`,CLI 路径时是 `admin-cli`。
//
// 备注(第十一轮 2026-05-26):`server_profile_qr_*` 五兄弟在 web 后台「显示服务器
// QR」step-up 路径上,对应五种结局。`--action-prefix server_profile_qr` 一键看全:
//   - 空后缀 `_show`     :step-up 通过,QR 已渲染到屏(success)
//   - `_password_fail`   :当前 admin 密码错(含 fail_count 递增计数,关联 IP cooldown)
//   - `_locked`          :当前 IP 已在 5 min cooldown 内,拒服务
//   - `_no_dial_host`        :app_settings.server_dial_host 未配置 / 空,前置条件不满足
//     (第六轮拆字段:阻断键从原 advertised_host 切到 dial,
//     确保客户端 PacketTunnel 拿到的是真实可拨号地址)
//   - `_failed`              :fork `nanotun-admin profile show` CLI 子进程返非零,通常是
//     CLI 不存在 / config.toml 不可读 / disk 满
//
// audit 的 detail 都用 `key=value, key=value` 格式(见 FormatDetail),含
// `username=<admin>`,可选 `dial_host=<dial>` / `advertised_host=<label>` / `reason=<short>` /
// `fail_count=<n>`,
// **绝不**写 PSK / password / private_key 等敏感字段。
//
// 不要为「统一」把 dot 改成 underscore —— 会丢掉 `--action-prefix` 一键过滤的能力,
// admin 排错时只能逐 verb 写一长串过滤,得不偿失。新增 runtime action 时维持 dot,
// 新增 CRUD action 时维持 underscore。
func (s *Store) Audit(ctx context.Context, actor, action, target, detail string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store: Audit on nil store")
	}
	if actor == "" || action == "" {
		return i18nErr("store.audit.missingActorAction", "store: Audit 缺 actor / action")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs(actor, action, target, detail, at) VALUES(?,?,?,?,?)`,
		actor, action, target, detail, nowUnix(),
	)
	if err != nil {
		return fmt.Errorf("store: audit insert: %w", err)
	}
	return nil
}

// PruneAuditBefore 删除 at < cutoffUnix 的所有审计行,返回删除的行数。
//
// P2-16: 长跑生产环境单台 nanotun 每天可写入数千到数十万条 audit(登录失败 / kick /
// reload / takeover / acl drop / ...),不做截尾的话 audit_logs + WAL 几个月会撑满
// 几 GB,sqlite 全表扫描时延也跟着退化。periodic prune 在后台跑,保留 N 天数据。
//
// 实现细节:
//   - DELETE + index on at:O(rows-to-delete),不会全表扫;
//   - 一次性 DELETE 可能锁表 100ms~秒级,要在调用方控制为业务低峰期或拆 batch;
//   - 此函数本身不做 batch,调用方 cli 端按需。生产 goroutine 实现见 server。
func (s *Store) PruneAuditBefore(ctx context.Context, cutoffUnix int64) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("store: PruneAuditBefore on nil store")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE at < ?`, cutoffUnix)
	if err != nil {
		return 0, fmt.Errorf("store: prune audit: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CountAudit 返回 audit_logs 表当前总行数,供监控用(配合 PruneAuditBefore 后日志报表)。
// SQLite COUNT(*) 在 ~百万行下走 idx_audit_at 扫描,几十毫秒级。
func (s *Store) CountAudit(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("store: CountAudit on nil store")
	}
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// QueryAudit 按时间区间(>= startAt AND < endAt)拉审计记录。limit 上限 10000
// 防止误用 LIMIT 0 把整表都取出来撑爆内存(生产 audit 表可能数百万条)。
func (s *Store) QueryAudit(ctx context.Context, startAt, endAt int64, limit int) ([]AuditLog, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, actor, action, target, COALESCE(detail,''), at
		  FROM audit_logs
		 WHERE at >= ? AND at < ?
		 ORDER BY at DESC, id DESC
		 LIMIT ?`,
		startAt, endAt, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditLog
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.At); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// QueryAuditByAction 同 QueryAudit,额外按 action 精确过滤。
//
// P2#3(2026-05-26)新增。当 admin CLI `audit list --action <action>` 指定时,
// 把过滤下推到 SQL,让 LIMIT 在过滤后生效(避免「先取 N 条 → client 过滤 → 剩 0
// 条」的反直觉)。
//
// 没有专属索引;audit_logs 已有 idx_audit_at,SQLite 走 idx_audit_at + filter
// action 即可,在百万行表上几十毫秒级。如果未来 action 过滤变热可加 idx_audit_action,
// 但这是 admin CLI ad-hoc 查询,优先简洁。
func (s *Store) QueryAuditByAction(ctx context.Context, startAt, endAt int64, action string, limit int) ([]AuditLog, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, actor, action, target, COALESCE(detail,''), at
		  FROM audit_logs
		 WHERE at >= ? AND at < ? AND action = ?
		 ORDER BY at DESC, id DESC
		 LIMIT ?`,
		startAt, endAt, action, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditLog
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.Target, &a.Detail, &a.At); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
