package store

// users_helper.go(2026-05-25):「profile / credentials 解耦」(0013)的高阶工具,
// 由 CLI(nanotun-admin)与 Web(nanotun-web)两边共用,避免「PSK rotate + 老 user
// credential_id backfill」的逻辑被两套实现各自维护、悄悄漂移。
//
// 历史:这两段最早以包外函数 / Web 手写的形式分散在 CLI 和 web handler 内,各自
// 实现略不同(条件 backfill / 出错只 warn 不 audit)给 admin 制造静默失败。统一
// 上移到 store 层后:
//
//   1. 行为单点:PSK rotate(CAS 守门) + BackfillUserCredentialID 永远成对调用,
//      顺序固定;
//   2. 错误归一化:caller 只要看到 err != nil,就一定是「PSK 或 credential_id 没
//      成功持久化」,可以放心 abort;ErrPSKConcurrentRotation 是 CAS race sentinel,
//      caller 可专门做友好 UI 提示;
//   3. 调用方接口:CLI / Web / 未来 SDK 都可以拿 *Store + *User 直接调。
//
// **承诺**:credential_id 一旦写入,生命周期内不再改变 —— 这是 client 端按 UUID
// 索引、新 QR 自动覆盖旧 PSK 的根基。CAS rotate 只动 psk_hash + credential_created_at。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrPSKConcurrentRotation 表示:本次 rotate 时拿的 user snapshot 已经过期 ——
// `u.PSKHash`(CAS base)与 DB 当下的 psk_hash 不一致,说明在 caller GetUser 之后
// 和 RotateUserPSKAndEnsureCredential 调用之前,另一次 rotate 已经先一步落库。
//
// 触发条件:两个 admin(CLI 或 Web,任意组合)在毫秒级内对同一 user 同时 reset-psk —
// 各自 GetUser 都看到 old hash,各自生成本地新 PSK 调 rotate。没 CAS 时**双双成功**,
// 后写者的 hash 留 DB,前写者却拿本地 plain 渲染了张「客户端扫了登不上」的 QR。
// 引入 CAS(WHERE psk_hash = expectedOldHash)后,失败者立即收到这个 sentinel,
// caller 据此拒绝展示 QR、提示「请刷新页面」。
//
// 第六轮深扫 P1#2 引入(原 reload-compare 方案在 SQLite 上无效已修正)。
var ErrPSKConcurrentRotation = errors.New("store: PSK rotation lost CAS race (snapshot stale)")

// RotateUserPSKAndEnsureCredential 是「PSK 变化时」的统一入口。
//
//	new_hash → users.psk_hash
//	now      → users.credential_created_at
//	(若空) 新 UUID v4 → users.credential_id
//
// 返回 (credentialID, createdAt) 给 caller 构造 credentials QR;两者保证非空 / >0。
//
// 失败语义:
//   - RotateUserPSK 失败:psk_hash / credential_created_at 没变更,直接返回 err;
//   - RotateUserPSK 成功 + BackfillUserCredentialID 失败:已经 rotate 的 PSK 无法
//     回滚(SQLite 无 BEGIN/COMMIT 包裹这两条 UPDATE),返回 err。Caller 视为
//     「PSK 已 rotate 但 credential_id 仍空」的半成功状态:
//     · CLI / Web admin 看到 error 不该展示 QR(避免引导用户扫到不完整凭证);
//     · 下次 credentials show 命中老 user 分支会再次 backfill(幂等)。
//     这种语义比「悄悄忽略 backfill 失败」可解释得多。
func (s *Store) RotateUserPSKAndEnsureCredential(
	ctx context.Context, u *User, pskHash string,
) (credentialID string, createdAt int64, err error) {
	if u == nil {
		return "", 0, fmt.Errorf("store: RotateUserPSKAndEnsureCredential: nil user")
	}
	if u.PSKHash == "" {
		// 见下方历史注释:空 psk_hash 不退回无 CAS 路径,显式报错。
		return "", 0, fmt.Errorf("store: refusing CAS-less rotate: user_id=%d has empty psk_hash "+
			"(check DB integrity / migration)", u.ID)
	}
	if pskHash == "" {
		return "", 0, errors.New("store: empty psk_hash")
	}
	now := time.Now().UTC().Unix()

	// 第四轮深扫 MED(store #9):把「CAS rotate + backfill credential_id」收进**同一事务**,消除此前
	// 「rotate 成功、backfill 失败 → PSK 已变但 credential_id 仍空」的半成功态(会让客户端 QR 生成失败,
	// 需靠下次 credentials show 自愈)。事务以 CAS UPDATE(**写**)起手,规避 DEFERRED 事务读后升级写撞
	// BUSY_SNAPSHOT;且 SQLite 单写者串行化让并发 rotate / EnsureUserCredentialID 天然序列化——本 tx 持写锁
	// 期间无人能插进来 backfill,故不再需要旧版那套「backfill race → 重读」的兜底分支。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, fmt.Errorf("store: rotate psk begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// CAS:仅当 DB 当前 psk_hash 仍等于 caller snapshot(u.PSKHash)时才改。0 行 = row 不存在或已被他人改写
	// (stale view race)→ ErrPSKConcurrentRotation,caller 拒绝展示可能过期的 QR。
	res, err := tx.ExecContext(ctx,
		`UPDATE users SET psk_hash=?, credential_created_at=? WHERE id=? AND psk_hash=?`,
		pskHash, now, u.ID, u.PSKHash)
	if err != nil {
		return "", 0, fmt.Errorf("store: rotate psk (cas): %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", 0, ErrPSKConcurrentRotation
	}

	// 事务内重读 credential_id(权威值:含本 tx 之前已提交的任何 backfill)。空 → 生成并写入;非空 → 复用,
	// 保证 credential_id 一经写入生命周期不变。createdAt 取 DB 值以与 UUID 同源。
	var curCredID string
	var curCredTS int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(credential_id,''), COALESCE(credential_created_at,0) FROM users WHERE id=?`,
		u.ID).Scan(&curCredID, &curCredTS); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", 0, ErrNotFound
		}
		return "", 0, fmt.Errorf("store: read credential_id in rotate tx: %w", err)
	}
	if curCredID == "" {
		curCredID = uuid.NewString()
		curCredTS = now
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET credential_id=?, credential_created_at=? WHERE id=?`,
			curCredID, curCredTS, u.ID); err != nil {
			if isUniqueConstraintErr(err) {
				return "", 0, fmt.Errorf("store: backfill credential_id (user_id=%d): %w", u.ID, ErrDuplicate)
			}
			return "", 0, fmt.Errorf("store: backfill credential_id: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", 0, fmt.Errorf("store: rotate psk commit: %w", err)
	}
	return curCredID, curCredTS, nil
}

// EnsureUserCredentialID 是「PSK 没变,但需要 credentials QR」的入口。
//
//   - 已有 credential_id → 直接返回 (u.CredentialID, u.CredentialCreatedAt);
//   - 老 user(credential_id IS NULL):
//     生成新 UUID v4;createdAt 优先 u.CredentialCreatedAt,其次 u.CreatedAt
//     (user create 时刻,PSK 大概也是那时候设的),最后 fallback time.Now()。
//     Backfill 失败时不重试(unique violation 极罕见,UUID v4 122 bit 熵 ≈ 5e36)。
func (s *Store) EnsureUserCredentialID(
	ctx context.Context, u *User,
) (credentialID string, createdAt int64, err error) {
	if u == nil {
		return "", 0, fmt.Errorf("store: EnsureUserCredentialID: nil user")
	}
	if u.CredentialID != "" {
		ts := u.CredentialCreatedAt
		if ts == 0 {
			ts = u.CreatedAt
		}
		if ts == 0 {
			ts = time.Now().UTC().Unix()
		}
		return u.CredentialID, ts, nil
	}
	newID := uuid.NewString()
	ts := u.CredentialCreatedAt
	if ts == 0 {
		ts = u.CreatedAt
	}
	if ts == 0 {
		ts = time.Now().UTC().Unix()
	}
	wrote, err := s.BackfillUserCredentialID(ctx, u.ID, newID, ts)
	if err != nil {
		return "", 0, err
	}
	if !wrote {
		// 极罕见 race:并发进程刚 backfill;重读拿权威值。
		reloaded, err := s.GetUser(ctx, u.ID)
		if err != nil {
			return "", 0, err
		}
		if reloaded.CredentialID == "" {
			return "", 0, fmt.Errorf("store: backfill credential_id raced but row still empty (user_id=%d)", u.ID)
		}
		return reloaded.CredentialID, reloaded.CredentialCreatedAt, nil
	}
	return newID, ts, nil
}
