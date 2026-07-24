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

// webAdminUsernameExistsCI 判断是否已存在大小写不敏感同名的 web admin(排除 excludeID;create 传 0)。
func (s *Store) webAdminUsernameExistsCI(ctx context.Context, username string, excludeID int64) (bool, error) {
	var dummy int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM web_admins WHERE username = ? COLLATE NOCASE AND id != ? LIMIT 1`,
		username, excludeID).Scan(&dummy)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: web admin username ci check: %w", err)
	}
	return true, nil
}

// CreateWebAdmin 写入一行 web_admins。Username UNIQUE 冲突归一化为 ErrDuplicate。
func (s *Store) CreateWebAdmin(ctx context.Context, in NewWebAdmin) (*WebAdmin, error) {
	// 第四轮深扫 MED(store #4/#15):裁剪首尾空白 + 大小写不敏感去重(见 users.CreateUser 同款说明)。
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" {
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
	if exists, err := s.webAdminUsernameExistsCI(ctx, in.Username, 0); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("store: create web admin username=%q (case-insensitive match): %w", in.Username, ErrDuplicate)
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

// CreateFirstWebAdmin 原子创建**首位** web 管理员:仅当 web_admins 表当前为空时才插入。
//
// 修 setup TOCTOU:handleSetup 此前「先 CountWebAdmins()==0、后 CreateWebAdmin()」两步分离,两个并发
// POST /setup 可能都过了 count==0 判定,各自建出一个管理员(攻击者借此在 TOFU 窗口抢占/多建 admin)。
// 这里用单条 `INSERT ... SELECT ... WHERE NOT EXISTS` —— SQLite 对写是串行化的,该语句是原子的:只有
// 一个请求真正插入(RowsAffected=1),其余拿到 RowsAffected=0 → 返回 ErrSetupClosed,由 handler 302 /login。
func (s *Store) CreateFirstWebAdmin(ctx context.Context, in NewWebAdmin) (*WebAdmin, error) {
	// 首位管理员:表为空(NOT EXISTS 守门),无需 CI 去重,只裁剪首尾空白。
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" {
		return nil, errors.New("store: empty web admin username")
	}
	if strings.TrimSpace(in.PasswordHash) == "" {
		return nil, errors.New("store: empty web admin password_hash")
	}
	// 第五轮深扫 MED:首位管理员**强制** admin 角色,忽略入参里显式传的 "viewer"。setup 表空后就永久关闭
	// (NOT EXISTS 守门),若首位是 viewer 则无人能提权 / 建 admin —— 整个控制台被永久锁成只读。web setup
	// handler 本就硬编码 "admin",这里在 DAL 兜底,堵住任何绕过 handler 直接调本函数造出 viewer 首管的路径。
	const role = "admin"
	createdBy := nullableInt(in.CreatedBy)

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO web_admins(username, password_hash, role, enabled, created_at, created_by)
		 SELECT ?,?,?,1,?,?
		 WHERE NOT EXISTS (SELECT 1 FROM web_admins)`,
		in.Username, in.PasswordHash, role, nowUnix(), createdBy,
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return nil, fmt.Errorf("store: create first web admin username=%q: %w", in.Username, ErrDuplicate)
		}
		return nil, fmt.Errorf("store: create first web admin: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: first web admin rows affected: %w", err)
	}
	if n == 0 {
		return nil, ErrSetupClosed
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: first web admin last insert id: %w", err)
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

// UpdateWebAdminPasswordHash 改密(或 reset)。**原子撤销**该 admin 的全部现存 web_session。
//
// 第四轮深扫 MED(store #7):此前改密与「撤销旧 session」是两步分离(handler 改密后再单独调
// DeleteWebSessionsByAdmin)。两步之间若进程崩溃 / 出错,旧密码时代签发的 cookie 仍然有效 —— 改密无法
// 真正把攻击者踢下线。现在把 UPDATE + DELETE web_sessions 收进同一事务,改密即刻、原子地失效所有旧会话。
func (s *Store) UpdateWebAdminPasswordHash(ctx context.Context, id int64, pwdHash string) error {
	if strings.TrimSpace(pwdHash) == "" {
		return errors.New("store: empty password_hash")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx update web admin password: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE web_admins SET password_hash=?, failed_logins=0, locked_until=0 WHERE id=?`,
		pwdHash, id)
	if err != nil {
		return fmt.Errorf("store: update web admin password: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE admin_id=?`, id); err != nil {
		return fmt.Errorf("store: revoke sessions on password change: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit update web admin password: %w", err)
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

// mutateWebAdminEnsuringAdmin 在**单个事务**里执行 mutate(禁用 / 删除 / 改角色),提交前确认系统仍存在
// ≥1 个「enabled 且 role=admin」的账号;不足则回滚并返回 ErrLastAdmin(第四轮深扫 HIGH,修 last-admin TOCTOU)。
//
// 关键点:mutate 里第一条语句必须是**写**(UPDATE/DELETE),事务因此以取写锁起手 —— 并发的同类事务会被
// SQLite 单写者串行化(靠 busy_timeout 等待,而非读快照升级),故两个并发禁用不同 admin 时,后者在前者提交后
// 才跑自己的写 + floor 校验,看到计数已降到 0 → 回滚拒绝。write-then-read 也规避了 DEFERRED 事务「读后升级写」
// 撞 BUSY_SNAPSHOT。mutate 返回 rowsAffected==0 → ErrNotFound(目标不存在)。
func (s *Store) mutateWebAdminEnsuringAdmin(ctx context.Context, what string, mutate func(*sql.Tx) (sql.Result, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin %s tx: %w", what, err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := mutate(tx)
	if err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	var enabledAdmins int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM web_admins WHERE role='admin' AND enabled=1`).Scan(&enabledAdmins); err != nil {
		return fmt.Errorf("store: %s count enabled admins: %w", what, err)
	}
	if enabledAdmins == 0 {
		// defer Rollback 撤销本次 mutate —— 绝不允许把系统推入「零可登录管理员」。
		return ErrLastAdmin
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit %s: %w", what, err)
	}
	return nil
}

// SetWebAdminEnabledEnsuringAdmin 禁用(enabled=false)一个账号,但保证不会禁掉最后一个 enabled admin,
// 并在**同一事务**里撤销该 admin 的全部 web_session(第四轮深扫 MED,store #7:禁用与踢线原子化,
// 消除「已禁用但旧 cookie 仍可用」的窗口)。仅用于 disable 语义;enable 继续用 SetWebAdminEnabled。
func (s *Store) SetWebAdminEnabledEnsuringAdmin(ctx context.Context, id int64) error {
	return s.mutateWebAdminEnsuringAdmin(ctx, "disable web admin", func(tx *sql.Tx) (sql.Result, error) {
		res, err := tx.ExecContext(ctx, `UPDATE web_admins SET enabled=0 WHERE id=?`, id)
		if err != nil {
			return res, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			if _, derr := tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE admin_id=?`, id); derr != nil {
				return res, derr
			}
		}
		return res, nil
	})
}

// DeleteWebAdminEnsuringAdmin 删除账号,但保证不会删掉最后一个 enabled admin。CASCADE 一并删其 web_sessions。
func (s *Store) DeleteWebAdminEnsuringAdmin(ctx context.Context, id int64) error {
	return s.mutateWebAdminEnsuringAdmin(ctx, "delete web admin", func(tx *sql.Tx) (sql.Result, error) {
		return tx.ExecContext(ctx, `DELETE FROM web_admins WHERE id=?`, id)
	})
}

// SetWebAdminRoleEnsuringAdmin 改角色,但保证降级(admin→viewer)不会把最后一个 enabled admin 降没。
// 升级(→admin)天然满足 floor(计数只增),同一路径无害。
func (s *Store) SetWebAdminRoleEnsuringAdmin(ctx context.Context, id int64, role string) error {
	role = strings.TrimSpace(role)
	if role != "admin" && role != "viewer" {
		return fmt.Errorf("store: invalid web admin role %q", role)
	}
	return s.mutateWebAdminEnsuringAdmin(ctx, "set web admin role", func(tx *sql.Tx) (sql.Result, error) {
		return tx.ExecContext(ctx, `UPDATE web_admins SET role=? WHERE id=?`, role, id)
	})
}

// RecordWebAdminLoginSuccess 登录成功后调用:更新 last_login + 清失败计数(含衰减用的 last_failure_at)。
func (s *Store) RecordWebAdminLoginSuccess(ctx context.Context, id int64, ip string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE web_admins
		    SET last_login_at=?, last_login_ip=?, failed_logins=0, locked_until=0, last_failure_at=0
		  WHERE id=?`,
		nowUnix(), ip, id)
	if err != nil {
		return fmt.Errorf("store: record web admin login success: %w", err)
	}
	// 第四轮深扫 LOW:未知 id → 0 行,此前静默返回 nil(看似「成功记录了成功」)。归一化为 ErrNotFound,
	// 与其余 DAL 一致;调用方(AttemptLogin 成功路径)本就把此错吞进日志、不拦登录,行为不变但更诚实。
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordWebAdminLoginFailure 失败计数 +1;到阈值时返回 locked_until 让上层提示。
// 返回 (newFailedLogins, newLockedUntil)。
//
// 滑动窗口衰减(第三轮深扫 M1):lockSeconds 同时作为「失败聚合窗口」。若距上次失败已超过该窗口,
// 计数先衰减归零再 +1 —— 关键是消除「锁定窗口一过、单次失败就重新锁满整个窗口」的永久 DoS:
// 此前 failed_logins 只增不减,窗口过后它仍 ≥ 阈值,任意 1 次失败即重锁,只知用户名的攻击者能永久
// 封住账号。改后攻击者必须在一个窗口内重新累积满 max_failures 次失败才能再次锁定。
func (s *Store) RecordWebAdminLoginFailure(ctx context.Context, id int64,
	maxFailures int64, lockSeconds int64) (int64, int64, error) {

	now := nowUnix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("store: begin tx record web admin failure: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 单条**写优先**的 UPDATE 完成「衰减判定 + 计数 +1 + 记录本次失败时刻」:
	//   - last_failure_at>0 且 now-last_failure_at>window(=lockSeconds)→ 视为陈旧,计数重置为 1;
	//   - 否则 failed_logins+1。
	// 用 CASE 在同一语句内原子完成,既避免 SELECT-then-UPDATE 丢计数的 race,又保持事务以写(而非读快照)
	// 起手,规避 modernc DEFERRED 事务「读后升级写」撞 SQLITE_BUSY_SNAPSHOT(该错不受 busy_timeout 重试)。
	// window<=0(lockSeconds=0,即不锁)时 `now-last_failure_at>0` 几乎恒真 → 每次都重置为 1,与「不累积/不锁」
	// 语义一致,无害。
	if _, err := tx.ExecContext(ctx,
		`UPDATE web_admins
		    SET failed_logins = CASE
		            WHEN last_failure_at > 0 AND (? - last_failure_at) > ? THEN 1
		            ELSE failed_logins + 1
		        END,
		        last_failure_at = ?
		  WHERE id=?`,
		now, lockSeconds, now, id); err != nil {
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

// DecoyWebAdminLoginFailure 是 [RecordWebAdminLoginFailure] 的**等时空跑**(timing decoy)。
//
// 第八轮深扫 LOW(用户名枚举旁路):登录失败里只有「账号存在且密码错」这一支会跑 RecordWebAdminLoginFailure
// (一次写事务),而「用户不存在 / 已禁用 / 已锁定」三支在 decoy argon2 之后直接返回、**完全不碰 DB**。argon2
// (~几十 ms)虽是主耗时且已对齐,但那一次写事务的 tx begin/commit + 语句编译开销仍构成可测的分支差 →
// 攻击者据此区分「用户名是否存在」。这里让早退分支也跑一遍同形状的写事务,抹平该差。
//
// 绑到 id=0(web_admins 主键自增恒为正,永不命中真实行)→ UPDATE 影响 0 行、SELECT 落空,**无任何副作用**,
// 但仍走完整 BeginTx + 同款 UPDATE/SELECT + Commit,对齐提交路径开销。最贵且已对齐的仍是 argon2 decoy;
// 此处进一步抹平 DB 侧残余。best-effort:任何错误静默忽略(它不承载业务语义,只为吃掉等价耗时)。
func (s *Store) DecoyWebAdminLoginFailure(ctx context.Context) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer func() { _ = tx.Commit() }()
	now := nowUnix()
	_, _ = tx.ExecContext(ctx,
		`UPDATE web_admins
		    SET failed_logins = CASE
		            WHEN last_failure_at > 0 AND (? - last_failure_at) > ? THEN 1
		            ELSE failed_logins + 1
		        END,
		        last_failure_at = ?
		  WHERE id=?`,
		now, int64(0), now, int64(0))
	var failed int64
	_ = tx.QueryRowContext(ctx,
		`SELECT failed_logins FROM web_admins WHERE id=?`, int64(0)).Scan(&failed)
}

// ResetWebAdminLockout admin 手动解锁。
func (s *Store) ResetWebAdminLockout(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE web_admins SET failed_logins=0, locked_until=0, last_failure_at=0 WHERE id=?`, id)
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
	// M5 补全:绝对生命周期守卫。此前 Touch 只按 id 更新,若一条 session 已超过 created_at+MaxAge
	// 却因某种时序被再次 Touch,expires_at 会被继续顺延、把绝对上限「续」没了(与 GetWebSession 的绝对
	// 上限判定相互矛盾)。加 WHERE 条件:已过绝对上限的行不再被 Touch(RowsAffected=0 → ErrNotFound,
	// 与 GetWebSession 命中绝对上限时的语义一致);顺延 expires_at 时也用 MIN 夹住不超过绝对截止点。
	absDeadlineClause := `(created_at <= 0 OR ? - created_at < ?)`
	var res sql.Result
	var err error
	if extendBy > 0 {
		res, err = s.db.ExecContext(ctx,
			`UPDATE web_sessions
			    SET last_seen_at=?,
			        expires_at=CASE WHEN created_at > 0 THEN MIN(?, created_at + ?) ELSE ? END
			  WHERE id=? AND `+absDeadlineClause,
			now, now+extendBy, WebSessionAbsoluteMaxAge, now+extendBy, id, now, WebSessionAbsoluteMaxAge)
	} else {
		res, err = s.db.ExecContext(ctx,
			`UPDATE web_sessions SET last_seen_at=? WHERE id=? AND `+absDeadlineClause,
			now, id, now, WebSessionAbsoluteMaxAge)
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
//
// 第四轮深扫 LOW:**有意**幂等——不校验 RowsAffected。logout 一个已过期 / 已被 GC / 不存在的 session
// 应当照常成功(用户点了「退出」,目标就是「这个 cookie 不再有效」,已经不在了即达成),报 ErrNotFound
// 只会让 handler 对着已登出的用户弹错误页,是更差的体验。故此处刻意不改为 ErrNotFound。
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

// PruneWebSessionsKeepingRecent 把某 admin 的活跃 session 数**封顶**到 keep 条,删掉较旧的多余项,
// 返回删除条数(第四轮深扫 MED,d_relogin_revoke)。
//
// 动机:此前每次成功登录都无条件新增一条 session,从不回收旧的 —— 一个 admin 反复登录会**无界累积**
// 有效 session。任何一条被窃 / 遗留在旧设备的 cookie 只要还在滑动窗口内就一直有效,徒增失窃面且无从
// 收敛。登录成功后调用本函数,只保留最近 keep 条(按 created_at 新→旧,并列时用 id 兜底稳定排序),
// 把并发会话数钉在上限内,给旧 token 一个确定的淘汰路径。keep<=0 视为 1(至少留住刚建的这条)。
//
// 选择「封顶」而非「登录即踢掉其它所有会话」:后者会把 admin 在其它设备的正常登录一并踢下线,体验差;
// 封顶在限制累积的同时保留合理的多设备并发。真正要「一键踢所有」的场景走 DeleteWebSessionsByAdmin。
func (s *Store) PruneWebSessionsKeepingRecent(ctx context.Context, adminID int64, keep int) (int64, error) {
	if adminID <= 0 {
		return 0, errors.New("store: bad admin id")
	}
	if keep <= 0 {
		keep = 1
	}
	// 子查询选出「按 created_at 新→旧的前 keep 条」的 id,删掉不在其中的本 admin 会话。
	// created_at 并列时以 id 二级排序,保证 OFFSET 边界确定、不会漏删/多删。
	//
	// 第十五轮深扫 MED:keep-set 子查询额外**排除已过期 / 已超绝对上限**的 session(与 GetWebSession /
	// PruneExpiredWebSessions 同判定)。此前 keep-set 只按 created_at 取前 keep 条,不看有效性 —— 一条较新但已
	// 过期(或越 30 天绝对上限)的死会话会占住 keep 名额、被本函数「保护」不删,反而挤掉一条**仍有效**的较旧会话
	// (违背「封顶有效并发」的本意);且死行滞留到后台 GC 才清。改为只在有效会话里取最近 keep 条,其余(超额有效 +
	// 全部失效)一并删除:cap 精确作用于有效会话,顺带即时回收死行。刚建的会话 created_at=now、expires_at 在未来,
	// 必在有效集且最新 → 永远被保留。
	now := nowUnix()
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM web_sessions
		  WHERE admin_id = ?
		    AND id NOT IN (
		        SELECT id FROM web_sessions
		         WHERE admin_id = ?
		           AND expires_at > ?
		           AND NOT (created_at > 0 AND ? - created_at >= ?)
		         ORDER BY created_at DESC, id DESC
		         LIMIT ?
		    )`,
		adminID, adminID, now, now, WebSessionAbsoluteMaxAge, keep)
	if err != nil {
		return 0, fmt.Errorf("store: prune web sessions keeping recent: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PruneExpiredWebSessions 后台 GC 调用。
//
// M5 补全:除滑动窗口过期(expires_at <= now)外,也回收**已超过绝对生命周期上限**的 session
// (created_at + MaxAge <= now)。此前只删 expires_at 过期的行 —— 一条刚被续期(expires_at 仍在未来)
// 但已越过 30 天绝对上限的 session 会在库里滞留到其滑动窗口自然过期为止(GetWebSession 已拒绝使用它,
// 但行不清理,占空间也误导 List)。两条件取并集,过期与超龄都清。
func (s *Store) PruneExpiredWebSessions(ctx context.Context) (int64, error) {
	now := nowUnix()
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM web_sessions
		  WHERE expires_at <= ?
		     OR (created_at > 0 AND ? - created_at >= ?)`,
		now, now, WebSessionAbsoluteMaxAge)
	if err != nil {
		return 0, fmt.Errorf("store: prune web sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListWebSessionsByAdmin admin 自己看自己当前活跃设备用。
//
// M5 补全:除滑动窗口未过期(expires_at > now)外,也排除**已越过绝对生命周期上限**的 session,
// 与 GetWebSession 的判定一致 —— 否则一条已超龄、GetWebSession 已当未登录处理的 session 仍会在
// 「当前活跃设备」列表里显示为在线,误导 admin(以为还能用 / 还需手动 revoke)。
func (s *Store) ListWebSessionsByAdmin(ctx context.Context, adminID int64) ([]*WebSession, error) {
	now := nowUnix()
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, admin_id, created_at, last_seen_at, expires_at, ip, user_agent
		   FROM web_sessions
		  WHERE admin_id=? AND expires_at > ?
		    AND (created_at <= 0 OR ? - created_at < ?)
		   ORDER BY last_seen_at DESC`,
		adminID, now, now, WebSessionAbsoluteMaxAge)
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
