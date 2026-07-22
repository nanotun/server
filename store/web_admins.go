package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// M2:nanotun-web 后台账号 / 会话 DAL。
//
// 表结构见 migrations/0007_web_admins.sql。这里集中所有 web 后台需要的数据库
// 访问点,避免 nanotun-web 直接拼 SQL —— 留出未来加索引 / 改 schema 时的统一
// 修改面。
//
// 失败模式约定与其它 DAL 一致:UNIQUE 冲突 → ErrDuplicate;不存在 → ErrNotFound。

// WebAdmin 一行 web_admins。PasswordHash 是 argon2id PHC,绝不输出到日志。
//
// TOTPSecret(0009 引入):base32 编码的 TOTP 共享密钥,明文存。
//   - TOTPEnabled=0 且 TOTPSecret="" → 该 admin 没启用过 TOTP;
//   - TOTPEnabled=0 但 TOTPSecret!="" → 启用流程中途(setup 生成了 secret 但未点
//     "确认"),下次 setup 会覆盖,登录路径忽略;
//   - TOTPEnabled=1 → 登录必须输入 6 位 TOTP 码(或恢复码)。
type WebAdmin struct {
	ID            int64
	Username      string
	PasswordHash  string
	Role          string
	Enabled       bool
	CreatedAt     int64
	CreatedBy     int64 // 0 = NULL(setup 首位 或 SQL 手工)
	LastLoginAt   int64
	LastLoginIP   string
	FailedLogins  int64
	LockedUntil   int64
	TOTPSecret    string
	TOTPEnabled   bool
	TOTPEnabledAt int64
	// TOTPLastUsedStep(0022):最近一次成功 TOTP 登录消费的时间步 T=(unix/period)。用于重放保护
	// (见 ConsumeTOTPStep)。0 = 从未用过。
	TOTPLastUsedStep int64
}

// NewWebAdmin 创建新 Web 管理员的入参。Username + PasswordHash 必填。
type NewWebAdmin struct {
	Username     string
	PasswordHash string
	Role         string // 空 → "admin"
	CreatedBy    int64  // 0 → NULL
}

// CreateWebAdmin 写入一行 web_admins。Username UNIQUE 冲突归一化为 ErrDuplicate。
func (s *Store) CreateWebAdmin(ctx context.Context, in NewWebAdmin) (*WebAdmin, error) {
	if strings.TrimSpace(in.Username) == "" {
		return nil, errors.New("store: empty web admin username")
	}
	if strings.TrimSpace(in.PasswordHash) == "" {
		return nil, errors.New("store: empty web admin password_hash")
	}
	role := strings.TrimSpace(in.Role)
	if role == "" {
		role = "admin"
	}
	if role != "admin" && role != "viewer" {
		return nil, fmt.Errorf("store: invalid web admin role %q", in.Role)
	}
	createdBy := nullableInt(in.CreatedBy)

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO web_admins(username, password_hash, role, enabled, created_at, created_by)
		 VALUES(?,?,?,1,?,?)`,
		in.Username, in.PasswordHash, role, nowUnix(), createdBy,
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return nil, fmt.Errorf("store: create web admin username=%q: %w", in.Username, ErrDuplicate)
		}
		return nil, fmt.Errorf("store: create web admin: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: web admin last insert id: %w", err)
	}
	return s.GetWebAdmin(ctx, id)
}

// GetWebAdmin 按主键取。
func (s *Store) GetWebAdmin(ctx context.Context, id int64) (*WebAdmin, error) {
	return s.scanWebAdminRow(s.db.QueryRowContext(ctx, webAdminSelectSQL+` WHERE id=?`, id))
}

// GetWebAdminByUsername 按用户名取(登录路径用)。
func (s *Store) GetWebAdminByUsername(ctx context.Context, username string) (*WebAdmin, error) {
	return s.scanWebAdminRow(s.db.QueryRowContext(ctx, webAdminSelectSQL+` WHERE username=?`, username))
}

// ListWebAdmins 列全部(含禁用),按 id 升序。
func (s *Store) ListWebAdmins(ctx context.Context) ([]*WebAdmin, error) {
	rows, err := s.db.QueryContext(ctx, webAdminSelectSQL+` ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list web admins: %w", err)
	}
	defer rows.Close()
	var out []*WebAdmin
	for rows.Next() {
		a, err := s.scanWebAdminCols(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountWebAdmins 返回 web_admins 行数(setup 流程用:0 → 进入首位创建向导)。
func (s *Store) CountWebAdmins(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM web_admins`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count web admins: %w", err)
	}
	return n, nil
}

// CountEnabledWebAdminsByRole 给保护性删除/降级用:最后一个 admin 不能被删 / 降级,
// 否则 Web 端会出现「无人可登录」的死局。
func (s *Store) CountEnabledWebAdminsByRole(ctx context.Context, role string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM web_admins WHERE role=? AND enabled=1`,
		role).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count web admins by role: %w", err)
	}
	return n, nil
}

// UpdateWebAdminPasswordHash 改密(或 reset)。
func (s *Store) UpdateWebAdminPasswordHash(ctx context.Context, id int64, pwdHash string) error {
	if strings.TrimSpace(pwdHash) == "" {
		return errors.New("store: empty password_hash")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE web_admins SET password_hash=?, failed_logins=0, locked_until=0 WHERE id=?`,
		pwdHash, id)
	if err != nil {
		return fmt.Errorf("store: update web admin password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetWebAdminRole 修改角色。
func (s *Store) SetWebAdminRole(ctx context.Context, id int64, role string) error {
	role = strings.TrimSpace(role)
	if role != "admin" && role != "viewer" {
		return fmt.Errorf("store: invalid web admin role %q", role)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE web_admins SET role=? WHERE id=?`, role, id)
	if err != nil {
		return fmt.Errorf("store: set web admin role: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetWebAdminEnabled 启/停用。disable 同时不会自动 revoke 该 admin 的活跃 session;
// 调用方应单独跑 DeleteWebSessionsByAdmin(id) 配合。
func (s *Store) SetWebAdminEnabled(ctx context.Context, id int64, enabled bool) error {
	v := int64(0)
	if enabled {
		v = 1
	}
	res, err := s.db.ExecContext(ctx, `UPDATE web_admins SET enabled=? WHERE id=?`, v, id)
	if err != nil {
		return fmt.Errorf("store: set web admin enabled: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteWebAdmin 物理删除。CASCADE 会一起删 web_sessions。
func (s *Store) DeleteWebAdmin(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM web_admins WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: delete web admin: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordWebAdminLoginSuccess 登录成功后调用:更新 last_login + 清失败计数。
func (s *Store) RecordWebAdminLoginSuccess(ctx context.Context, id int64, ip string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE web_admins
		    SET last_login_at=?, last_login_ip=?, failed_logins=0, locked_until=0
		  WHERE id=?`,
		nowUnix(), ip, id)
	if err != nil {
		return fmt.Errorf("store: record web admin login success: %w", err)
	}
	return nil
}

// RecordWebAdminLoginFailure 失败计数 +1;到阈值时返回 locked_until 让上层提示。
// 返回 (newFailedLogins, newLockedUntil)。
func (s *Store) RecordWebAdminLoginFailure(ctx context.Context, id int64,
	maxFailures int64, lockSeconds int64) (int64, int64, error) {

	now := nowUnix()
	// 用条件 UPDATE 单语句完成「+1 并按阈值设 locked_until」,避免 SELECT-then-UPDATE 的
	// race(同一 admin 并发多端口爆破时计数会丢)。SQLite 不支持 CASE in UPDATE 同时取
	// 新值,所以分两步:先 +1,再 SELECT,但用同一事务保证一致性。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("store: begin tx record web admin failure: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`UPDATE web_admins SET failed_logins = failed_logins + 1 WHERE id=?`, id); err != nil {
		return 0, 0, fmt.Errorf("store: incr web admin failed_logins: %w", err)
	}
	var failed int64
	if err := tx.QueryRowContext(ctx,
		`SELECT failed_logins FROM web_admins WHERE id=?`, id).Scan(&failed); err != nil {
		// 深扫第八轮 LOW:未知 admin id 时 UPDATE 影响 0 行(无错),SELECT 返回
		// sql.ErrNoRows。归一化为 ErrNotFound,与其余 DAL 一致(上层可 errors.Is 判定),
		// 而不是把裸 sql.ErrNoRows 包成一条读失败错误。
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, ErrNotFound
		}
		return 0, 0, fmt.Errorf("store: read web admin failed_logins: %w", err)
	}
	var lockUntil int64
	if maxFailures > 0 && failed >= maxFailures {
		lockUntil = now + lockSeconds
		if _, err := tx.ExecContext(ctx,
			`UPDATE web_admins SET locked_until=? WHERE id=?`, lockUntil, id); err != nil {
			return 0, 0, fmt.Errorf("store: set web admin locked_until: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("store: commit web admin failure record: %w", err)
	}
	return failed, lockUntil, nil
}

// ResetWebAdminLockout admin 手动解锁。
func (s *Store) ResetWebAdminLockout(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE web_admins SET failed_logins=0, locked_until=0 WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: reset web admin lockout: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const webAdminSelectSQL = `SELECT
	id, username, password_hash, role, enabled,
	created_at, COALESCE(created_by,0),
	last_login_at, last_login_ip,
	failed_logins, locked_until,
	totp_secret, totp_enabled, totp_enabled_at,
	COALESCE(totp_last_used_step,0)
FROM web_admins`

func (s *Store) scanWebAdminRow(row *sql.Row) (*WebAdmin, error) {
	a, err := s.scanWebAdminCols(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func (s *Store) scanWebAdminCols(sc rowScanner) (*WebAdmin, error) {
	var a WebAdmin
	var enabled, totpEnabled int64
	if err := sc.Scan(
		&a.ID, &a.Username, &a.PasswordHash, &a.Role, &enabled,
		&a.CreatedAt, &a.CreatedBy,
		&a.LastLoginAt, &a.LastLoginIP,
		&a.FailedLogins, &a.LockedUntil,
		&a.TOTPSecret, &totpEnabled, &a.TOTPEnabledAt,
		&a.TOTPLastUsedStep,
	); err != nil {
		return nil, err
	}
	a.Enabled = enabled != 0
	a.TOTPEnabled = totpEnabled != 0
	return &a, nil
}

// =========================================================================
// web_sessions
// =========================================================================

// WebSession 一条 web 登录会话。
type WebSession struct {
	ID         string
	AdminID    int64
	CreatedAt  int64
	LastSeenAt int64
	ExpiresAt  int64
	IP         string
	UserAgent  string
}

// CreateWebSession 写入会话。id 由调用方生成(crypto/rand),保证全局唯一。
func (s *Store) CreateWebSession(ctx context.Context, in WebSession) error {
	if strings.TrimSpace(in.ID) == "" {
		return errors.New("store: empty web session id")
	}
	if in.AdminID <= 0 {
		return errors.New("store: bad admin id")
	}
	now := nowUnix()
	if in.CreatedAt == 0 {
		in.CreatedAt = now
	}
	if in.LastSeenAt == 0 {
		in.LastSeenAt = now
	}
	if in.ExpiresAt == 0 {
		return errors.New("store: empty expires_at")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO web_sessions(id, admin_id, created_at, last_seen_at, expires_at, ip, user_agent)
		 VALUES(?,?,?,?,?,?,?)`,
		in.ID, in.AdminID, in.CreatedAt, in.LastSeenAt, in.ExpiresAt, in.IP, in.UserAgent)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("store: create web session id=%q: %w", in.ID, ErrDuplicate)
		}
		return fmt.Errorf("store: create web session: %w", err)
	}
	return nil
}

// WebSessionAbsoluteMaxAge 是 web 会话的**绝对**生命周期上限(自 created_at 起,单位秒)。
//
// M5:滑动过期(TouchWebSession 每次请求把 expires_at 顺延)保证「活跃即不掉线」,但单有滑动窗口会让
// 一枚被窃 cookie 只要持续被使用就**永不**失效(除非管理员显式 DeleteWebSessionsByAdmin)。这里补一个
// 硬顶:无论多活跃,会话自创建起超过本时长即判过期,强制重新登录(密码 [+ TOTP])。取 30 天——远大于
// 默认 12h 滑动窗口,正常用户几乎无感,却给失窃 token 一个确定的止损期限。
const WebSessionAbsoluteMaxAge int64 = 30 * 24 * 60 * 60

// GetWebSession 取一条 session;滑动过期或超过绝对生命周期上限均返回 ErrNotFound(由上层让客户端重新登录)。
func (s *Store) GetWebSession(ctx context.Context, id string) (*WebSession, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, admin_id, created_at, last_seen_at, expires_at, ip, user_agent
		   FROM web_sessions WHERE id=?`, id)
	var ws WebSession
	if err := row.Scan(&ws.ID, &ws.AdminID, &ws.CreatedAt, &ws.LastSeenAt,
		&ws.ExpiresAt, &ws.IP, &ws.UserAgent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get web session: %w", err)
	}
	now := nowUnix()
	if ws.ExpiresAt > 0 && ws.ExpiresAt <= now {
		return nil, ErrNotFound // 滑动窗口过期
	}
	// M5:绝对生命周期上限。命中后 LookupSession 会把请求当未登录处理,不再 TouchWebSession 续期,
	// 该行 expires_at 停止顺延,最终被 session GC 清掉。
	if ws.CreatedAt > 0 && now-ws.CreatedAt >= WebSessionAbsoluteMaxAge {
		return nil, ErrNotFound
	}
	return &ws, nil
}

// TouchWebSession 刷新 last_seen_at,顺便延长 expires_at(滑动过期窗口)。
// extendBy <=0 时只刷新 last_seen,不改 expires。
func (s *Store) TouchWebSession(ctx context.Context, id string, extendBy int64) error {
	now := nowUnix()
	// 深扫第八轮 LOW:检查 RowsAffected —— touch 一个不存在(已过期被 GC / 已 logout)
	// 的 session id 应显式返回 ErrNotFound,而不是静默成功。上层据此可提前把请求当未登录
	// 处理,不会误以为滑动续期成功。
	var res sql.Result
	var err error
	if extendBy > 0 {
		res, err = s.db.ExecContext(ctx,
			`UPDATE web_sessions SET last_seen_at=?, expires_at=? WHERE id=?`,
			now, now+extendBy, id)
	} else {
		res, err = s.db.ExecContext(ctx,
			`UPDATE web_sessions SET last_seen_at=? WHERE id=?`, now, id)
	}
	if err != nil {
		return fmt.Errorf("store: touch web session: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteWebSession 主动 revoke 一条(logout)。
func (s *Store) DeleteWebSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: delete web session: %w", err)
	}
	return nil
}

// DeleteWebSessionsByAdmin 撤销该 admin 全部 session(改密 / 禁用 / 删除时调用)。
// 返回删除条数。
func (s *Store) DeleteWebSessionsByAdmin(ctx context.Context, adminID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE admin_id=?`, adminID)
	if err != nil {
		return 0, fmt.Errorf("store: delete web sessions by admin: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PruneExpiredWebSessions 后台 GC 调用。
func (s *Store) PruneExpiredWebSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires_at <= ?`, nowUnix())
	if err != nil {
		return 0, fmt.Errorf("store: prune web sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListWebSessionsByAdmin admin 自己看自己当前活跃设备用。
func (s *Store) ListWebSessionsByAdmin(ctx context.Context, adminID int64) ([]*WebSession, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, admin_id, created_at, last_seen_at, expires_at, ip, user_agent
		   FROM web_sessions WHERE admin_id=? AND expires_at > ?
		   ORDER BY last_seen_at DESC`,
		adminID, nowUnix())
	if err != nil {
		return nil, fmt.Errorf("store: list web sessions: %w", err)
	}
	defer rows.Close()
	var out []*WebSession
	for rows.Next() {
		var ws WebSession
		if err := rows.Scan(&ws.ID, &ws.AdminID, &ws.CreatedAt, &ws.LastSeenAt,
			&ws.ExpiresAt, &ws.IP, &ws.UserAgent); err != nil {
			return nil, err
		}
		out = append(out, &ws)
	}
	return out, rows.Err()
}
