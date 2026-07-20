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
	now := time.Now().UTC().Unix()
	// 第六轮深扫 P1#2:用 CAS(`WHERE id=? AND psk_hash=?`)替代无条件 UPDATE。
	//
	// CAS base 取 `u.PSKHash` —— caller 传进来的 user snapshot 上的 hash。
	// 两个 admin 同时 reset-psk:
	//   - A: GetUser → u.PSKHash="h_orig" → CAS old=h_orig new=h_A → ok(影响 1 行)
	//   - B: GetUser → u.PSKHash="h_orig" → CAS old=h_orig new=h_B → 0 行(A 已改)
	//     B 收 ErrPSKConcurrentRotation,caller 拒绝下发 h_B 的 QR。
	// SQLite 单 writer 串行也满足此语义(A 的 UPDATE 已 commit,B 的 WHERE 守门生效)。
	//
	// **第七轮深扫 P1**:`u.PSKHash == ""` 不再退回无条件 rotate。
	// 生产里:0001 migration `psk_hash TEXT NOT NULL` + CreateUser/Web/CLI create 都
	// 强制非空,理论永不发生。一旦真发生(手工改库 / migration 出错),静默退回无
	// CAS 路径会重现 P1#2 的双赢家无效 QR 行为 —— 用 "silently 退化到 race-vulnerable"
	// 换 "比 panic 好" 不值。改成显式 error:caller 看到失败 → 排查 DB 状态。
	if u.PSKHash == "" {
		return "", 0, fmt.Errorf("store: refusing CAS-less rotate: user_id=%d has empty psk_hash "+
			"(check DB integrity / migration)", u.ID)
	}
	wrote, rerr := s.RotateUserPSKCAS(ctx, u.ID, pskHash, u.PSKHash, now)
	if rerr != nil {
		return "", 0, rerr
	}
	if !wrote {
		return "", 0, ErrPSKConcurrentRotation
	}
	credentialID = u.CredentialID
	if credentialID == "" {
		// **第三轮深扫 P1-B → 第七轮深扫 P1·注释更新**:
		//
		// CAS 落地之前(P1-B 时代)这里防的是「两个 admin 同时 reset-psk 同一老 user」
		// → 两边各自生成不同 UUID 调 BackfillUserCredentialID → 后写者拿 wrote=false。
		// CAS 之后这条 race **在本函数里不会再触发** —— 多 worker 同时 reset-psk 已经
		// 在 CAS 阶段(`RotateUserPSKCAS`)被序列化,只有 1 个 winner 进 backfill。
		//
		// 那么 `!wrote` 分支什么时候会触发?
		//   1. **rotate × EnsureUserCredentialID 交叉**:本函数刚 CAS 成功还没 backfill
		//      期间,另一个进程的 `credentials show`(EnsureUserCredentialID 入口,不走
		//      CAS)先一步把 credential_id backfill 了 → 我们看到 wrote=false。
		//   2. 数据修复脚本 / 手工 INSERT credential_id 抢先(极罕见运维场景)。
		// 两种情况下 helper 必须重读 DB 拿权威 UUID,而不是吐自生未入库 UUID(否则
		// CLI/Web 拿这条 QR 给客户端 → UUID 与 server 不匹配 → 反复换卡)。
		credentialID = uuid.NewString()
		wrote, berr := s.BackfillUserCredentialID(ctx, u.ID, credentialID, now)
		if berr != nil {
			return "", 0, berr
		}
		if !wrote {
			reloaded, gerr := s.GetUser(ctx, u.ID)
			if gerr != nil {
				return "", 0, gerr
			}
			if reloaded.CredentialID == "" {
				return "", 0, fmt.Errorf("store: backfill credential_id raced but row still empty (user_id=%d)", u.ID)
			}
			// CAS 之后 winner 的 PSK rotate 不会被 peer 覆盖,但 credential_created_at
			// 仍以 DB reload 为准:winner 的 rotate 写了 now,但若 EnsureUserCredentialID
			// 在 winner 写完 PSK 之后、本 backfill 之前先 backfill,它带的 createdAt
			// 是它 own 时钟读数(略早),DB 里就是那个 — 取 reloaded.CredentialCreatedAt
			// 而非 now,保证 UUID 与时间戳同源。
			return reloaded.CredentialID, reloaded.CredentialCreatedAt, nil
		}
	}
	return credentialID, now, nil
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
