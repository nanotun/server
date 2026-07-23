package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// M2 + 0009:web 后台 admin TOTP 二步验证相关的 DAL。
//
// 表 web_admins 增了 totp_secret/totp_enabled/totp_enabled_at 三列;新表
// web_admin_recovery_codes 存储一次性恢复码的 argon2id 哈希。
//
// 调用关系:nanotun-web 的 handler_me.go / handler_auth.go 全部走这一层,不直接
// 拼 SQL。失败语义:不存在 = ErrNotFound;其它写错 = 原 SQL error 包一层。

// ConsumeTOTPStep 原子「消费」一次成功登录用到的 TOTP 时间步 step,做重放保护(0022)。
//
// 语义:仅当 step **严格大于**当前记录的 totp_last_used_step 时才更新并返回 (true, nil);否则(同一枚码
// 重放会匹配到同一步或更早步)命中 0 行、返回 (false, nil),调用方应把本次登录判为失败。id 不存在同样 (false,nil)
// (但登录路径此时 admin 必然存在)。条件 UPDATE 在单条语句里完成,天然抗并发双重放。
func (s *Store) ConsumeTOTPStep(ctx context.Context, id int64, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE web_admins SET totp_last_used_step=? WHERE id=? AND totp_last_used_step < ?`,
		step, id, step)
	if err != nil {
		return false, fmt.Errorf("store: consume totp step: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetWebAdminTOTPSecret 把 secret 写到 web_admins.totp_secret,但不修改
// totp_enabled —— 这是 setup 第一步:生成 secret 给用户扫码,用户输入正确 6 位
// 码"确认绑定"后才会 ConfirmEnable 翻转 enabled=1。中途取消 / 离开页面留下的
// 半成品 secret 会被下次 setup 覆盖,登录路径只看 enabled,不影响。
//
// 同时清空 totp_enabled_at(虽然 enabled 还是 0,这里冗余清一下,保证 setup
// 重做时审计字段从零开始)。
func (s *Store) SetWebAdminTOTPSecret(ctx context.Context, id int64, secretBase32 string) error {
	if secretBase32 == "" {
		return errors.New("store: empty totp secret")
	}
	// 一并清 totp_last_used_step:写入的是**新** secret,其重放步计数器应从零开始。否则「禁用→立即
	// 用新 secret 重新绑定」若落在同一 30s 时间步内,ConsumeTOTPStep 会因残留的旧 step 把新 secret 的
	// 首次登录判为重放而拒绝(需干等一个时间步)。新凭据 = 新计数器。
	res, err := s.db.ExecContext(ctx,
		`UPDATE web_admins
		    SET totp_secret=?, totp_enabled=0, totp_enabled_at=0, totp_last_used_step=0
		  WHERE id=?`,
		secretBase32, id)
	if err != nil {
		return fmt.Errorf("store: set totp secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnableWebAdminTOTP 翻转 enabled=1 + 记录 enabled_at。
// 调用前 handler 必须已经 1) 校验当前 totp_secret 与用户输入的 6 位码匹配,
// 2) 准备好 10 个恢复码的 hash 列表。这两步在一个事务里做,避免"启用了 TOTP
// 但没生成恢复码"或者"恢复码生成了但 enabled 没翻"的部分成功。
//
// 实现:开事务 → UPDATE web_admins → 删旧 recovery_codes(以防 setup 重做)
// → INSERT 新一批 recovery_codes → 提交。
//
// 返回插入的恢复码条数(应当等于 len(codeHashes))。
func (s *Store) EnableWebAdminTOTP(ctx context.Context, id int64,
	codeHashes []string, now int64) (int, error) {

	if len(codeHashes) == 0 {
		return 0, errors.New("store: empty recovery code hashes")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin tx enable totp: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE web_admins
		    SET totp_enabled=1, totp_enabled_at=?
		  WHERE id=? AND totp_secret <> ''`, now, id)
	if err != nil {
		return 0, fmt.Errorf("store: enable totp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// 要么 id 不存在,要么没设置过 totp_secret(setup 没走完)。
		return 0, ErrNotFound
	}

	// 清掉旧恢复码 — 如果是 disable 再 enable 的场景,旧码必须全部作废。
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM web_admin_recovery_codes WHERE admin_id=?`, id); err != nil {
		return 0, fmt.Errorf("store: clear old recovery codes: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO web_admin_recovery_codes(admin_id, code_hash, created_at)
		 VALUES(?,?,?)`)
	if err != nil {
		return 0, fmt.Errorf("store: prepare insert recovery code: %w", err)
	}
	defer stmt.Close()
	for _, h := range codeHashes {
		if _, err := stmt.ExecContext(ctx, id, h, now); err != nil {
			return 0, fmt.Errorf("store: insert recovery code: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit enable totp: %w", err)
	}
	return len(codeHashes), nil
}

// DisableWebAdminTOTP 关闭 TOTP:清空 secret + enabled=0 + 删除所有恢复码。
// 调用前 handler 必须验证当前 TOTP 码或恢复码,避免攻击者拿密码就能一键关 2FA。
//
// 不同于 enable,这里允许 admin 不存在时静默成功(idempotent disable),减少
// "已经禁用还按一次按钮就报错"的体验问题 — 改用 ErrNotFound 只在 admin 行不存
// 在时返回。
func (s *Store) DisableWebAdminTOTP(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx disable totp: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 同时清 totp_last_used_step:disable 作废当前 secret,重放步计数器也应归零,保证将来重新绑定
	// (新 secret)时从干净状态开始(见 SetWebAdminTOTPSecret 同款注释)。
	res, err := tx.ExecContext(ctx,
		`UPDATE web_admins
		    SET totp_secret='', totp_enabled=0, totp_enabled_at=0, totp_last_used_step=0
		  WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: disable totp: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM web_admin_recovery_codes WHERE admin_id=?`, id); err != nil {
		return fmt.Errorf("store: delete recovery codes: %w", err)
	}
	return tx.Commit()
}

// =========================================================================
// recovery codes
// =========================================================================

// WebAdminRecoveryCode 一行 web_admin_recovery_codes(校验 / 列表用)。
// 明文恢复码不在数据库里,只在 EnableWebAdminTOTP 时由调用方暂时持有。
type WebAdminRecoveryCode struct {
	ID        int64
	AdminID   int64
	CodeHash  string
	UsedAt    int64
	UsedIP    string
	CreatedAt int64
}

// ListUnusedRecoveryCodes 列出该 admin 当前未使用的恢复码(供登录 / disable 时
// 校验)。返回按 id 升序;数量 ≤ 10 (创建时就是这个数)。
func (s *Store) ListUnusedRecoveryCodes(ctx context.Context, adminID int64) ([]*WebAdminRecoveryCode, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, admin_id, code_hash, used_at, used_ip, created_at
		   FROM web_admin_recovery_codes
		  WHERE admin_id=? AND used_at=0
		  ORDER BY id ASC`, adminID)
	if err != nil {
		return nil, fmt.Errorf("store: list recovery codes: %w", err)
	}
	defer rows.Close()
	var out []*WebAdminRecoveryCode
	for rows.Next() {
		var c WebAdminRecoveryCode
		if err := rows.Scan(&c.ID, &c.AdminID, &c.CodeHash, &c.UsedAt, &c.UsedIP, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// MarkRecoveryCodeUsed 标记一条恢复码已使用。返回 ErrNotFound 表示该 id 不存在
// 或并发已被另一处使用(used_at 已 != 0)— 调用方该把这次"使用"视为失败,
// 让用户再输一次。
//
// 关键:用 WHERE used_at=0 这个条件保证并发场景下只有第一个调用成功 — sqlite
// 的单条 UPDATE ... WHERE 是原子的,即便连接池已放大到 MaxOpenConns=4、多请求
// 真并发也只会有一条 UPDATE 命中 used_at=0(其余 RowsAffected=0 → ErrNotFound),
// 不出双花。不依赖任何「单连接串行」假设。
func (s *Store) MarkRecoveryCodeUsed(ctx context.Context, codeID int64, ip string, now int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE web_admin_recovery_codes
		    SET used_at=?, used_ip=?
		  WHERE id=? AND used_at=0`, now, ip, codeID)
	if err != nil {
		return fmt.Errorf("store: mark recovery code used: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountUnusedRecoveryCodes 给 UI 显示"还剩 N 个恢复码可用"用。
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, adminID int64) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM web_admin_recovery_codes WHERE admin_id=? AND used_at=0`,
		adminID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count recovery codes: %w", err)
	}
	return n, nil
}

// RegenerateRecoveryCodes 清空现有恢复码并写入新一批。
// 与 EnableWebAdminTOTP 类似走事务,保证"老码删了但新码没写"不会发生。
// 不修改 totp_enabled / totp_secret(只换码),所以可以在任何启用了 TOTP 的
// admin 上调用。
func (s *Store) RegenerateRecoveryCodes(ctx context.Context, adminID int64,
	codeHashes []string, now int64) error {

	if len(codeHashes) == 0 {
		return errors.New("store: empty recovery code hashes")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx regen recovery: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// **写优先**:先 DELETE(取写锁,规避 DEFERRED 事务读后升级写撞 BUSY_SNAPSHOT),再在同一 tx 内校验前置条件。
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM web_admin_recovery_codes WHERE admin_id=?`, adminID); err != nil {
		return fmt.Errorf("store: clear recovery codes: %w", err)
	}

	// 第四轮深扫 MED(store #8):校验目标 admin **存在**且 **totp_enabled=1**,再写新码。
	//   - 不存在:此前 INSERT 会因 FK 抛一条晦涩的约束错;归一化为 ErrNotFound,与其余 DAL 一致。
	//   - 未启用 TOTP:恢复码是「TOTP 丢失时的兜底」,给一个没开 TOTP 的账号塞恢复码是无意义的孤儿数据
	//     (且可能被误当成「已有第二因子」)。要求先启用 TOTP,契合本函数「只换码不改 enabled」的语义。
	var totpEnabled int64
	if err := tx.QueryRowContext(ctx,
		`SELECT totp_enabled FROM web_admins WHERE id=?`, adminID).Scan(&totpEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("store: check totp_enabled for regen: %w", err)
	}
	if totpEnabled == 0 {
		return fmt.Errorf("store: refuse to regenerate recovery codes: admin_id=%d has TOTP disabled: %w",
			adminID, ErrInvalid)
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO web_admin_recovery_codes(admin_id, code_hash, created_at)
		 VALUES(?,?,?)`)
	if err != nil {
		return fmt.Errorf("store: prepare insert recovery code: %w", err)
	}
	defer stmt.Close()
	for _, h := range codeHashes {
		if _, err := stmt.ExecContext(ctx, adminID, h, now); err != nil {
			return fmt.Errorf("store: insert recovery code: %w", err)
		}
	}
	return tx.Commit()
}
