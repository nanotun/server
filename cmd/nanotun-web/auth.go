package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
)

// M2:Web 管理后台密码 hash 与验证。
//
// 与 nanotun 数据面的 auth.HashPSK / VerifyPSK 使用同一格式 + 同一 argon2id
// 参数(memory=64MB, time=2, p=4),代码上直接复用 auth.HashPSK / VerifyPSK,
// 避免维护两套独立但几乎一样的实现。理由:
//   * 算法/参数一旦不一致,未来 admin reset psk 时会 silent fall back 到旧参,
//     重启后突然 verify 失败,debug 成本高;
//   * 同样的实现意味着同样经过 P0-2 / E1 的 DoS 防护(全局 argon2 semaphore),
//     登录爆破的 RAM 消耗封顶。

// HashWebPassword 与 auth.HashPSK 等价,仅为可读性保留独立名字。
func HashWebPassword(plaintext string) (string, error) {
	return auth.HashPSK(plaintext)
}

// VerifyWebPassword 与 auth.VerifyPSK 等价。
//
// 注意:这里没有复用 *auth.Verifier 是因为它要求 store.User,而 web_admins
// 是单独表;但 VerifyPSK 本身仅需要 PHC 字符串,可直接用。
func VerifyWebPassword(plaintext, encoded string) (bool, error) {
	return auth.VerifyPSK(plaintext, encoded)
}

// ValidatePasswordStrength 在 setup / create / reset 时给一道基础门槛。
//
// 不上 zxcvbn 之类的强密度检测,理由:nanotun-web 是给运维管理员用的,
// 实际威胁是字典 / 撞库,而不是同事记不住的复杂密码。argon2id 已经让暴力
// 破解成本很高;再加一道 rate limit + 锁定,P1 防护够用。
const (
	minPasswordLen = 12
	maxPasswordLen = 256
)

// ValidatePasswordStrength 拒绝弱密码。错误信息直接给用户看(zh-CN)。
func ValidatePasswordStrength(p string) error {
	if len(p) < minPasswordLen {
		return newLocErr("auth.pwTooShort", minPasswordLen, len(p))
	}
	if len(p) > maxPasswordLen {
		return newLocErr("auth.pwTooLong", maxPasswordLen)
	}
	if strings.ContainsAny(p, "\n\r\t\x00") {
		return newLocErr("auth.pwBadChars")
	}
	// 必含两类字符以上(数字 + 字母 + 符号任二)。避免 "aaaaaaaaaaaa" 这种全同字符。
	classes := 0
	hasDigit, hasLetter, hasSym := false, false, false
	for _, r := range p {
		switch {
		case r >= '0' && r <= '9':
			if !hasDigit {
				classes++
				hasDigit = true
			}
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			if !hasLetter {
				classes++
				hasLetter = true
			}
		default:
			if !hasSym {
				classes++
				hasSym = true
			}
		}
	}
	if classes < 2 {
		return newLocErr("auth.pwTooFewClasses")
	}
	return nil
}

// =========================================================================
// 登录尝试 → store.WebAdmin 路径
// =========================================================================

// AuthResult 是登录尝试的归一化结果。便于 handler 直接 switch。
type AuthResult struct {
	Admin       *store.WebAdmin
	Err         error
	LockedUntil int64 // 0 表示未锁定
}

// 错误集合,导出供 handler 文案匹配。
var (
	ErrAuthBadCredentials = errors.New("用户名或密码错误")
	ErrAuthLocked         = errors.New("账号已暂时锁定")
	ErrAuthDisabled       = errors.New("账号已被禁用")
)

// AttemptLogin 是登录的统一入口。
//
// 流程:
//  1. 查 web_admins → 不存在 → decoy verify(等时间)+ ErrAuthBadCredentials;
//  2. enabled=0 → ErrAuthDisabled(不计入失败计数,避免被禁用户被反复锁 admin 的解锁路径);
//  3. locked_until > now → ErrAuthLocked + 透出 locked_until 给 UI 显示;
//  4. argon2id verify 不匹配 → 计数 + 可能锁定 → ErrAuthBadCredentials;
//  5. 匹配 → RecordSuccess + 返回 admin。
//
// 关键安全属性:
//   - 用户名不存在 / 密码错都返回同一条 ErrAuthBadCredentials,不告诉 attacker
//     用户名是否有效;
//   - 不存在路径仍跑 decoy argon2,timing 与真实 verify 对齐;
//   - 失败计数 / 锁定靠 RecordWebAdminLoginFailure 原子事务,不在内存里维护
//     可丢失的 counter。
func AttemptLogin(ctx context.Context, st *store.Store, cfg Config,
	username, password, ip string) AuthResult {

	a, err := st.GetWebAdminByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			_, _ = VerifyWebPassword(password, decoyWebHash())
			return AuthResult{Err: ErrAuthBadCredentials}
		}
		return AuthResult{Err: fmt.Errorf("查询用户失败: %w", err)}
	}
	if !a.Enabled {
		_, _ = VerifyWebPassword(password, decoyWebHash())
		return AuthResult{Admin: a, Err: ErrAuthDisabled}
	}
	if a.LockedUntil > 0 && a.LockedUntil > nowUnix() {
		_, _ = VerifyWebPassword(password, decoyWebHash())
		return AuthResult{Admin: a, Err: ErrAuthLocked, LockedUntil: a.LockedUntil}
	}

	ok, verr := VerifyWebPassword(password, a.PasswordHash)
	if verr != nil || !ok {
		_, lockUntil, _ := st.RecordWebAdminLoginFailure(ctx, a.ID,
			cfg.MaxLoginFailures, cfg.LockoutSeconds)
		// lockUntil > 0 时把"刚刚被锁"也透给 UI,让用户知道为什么 5 次后突然不响应了
		return AuthResult{Admin: a, Err: ErrAuthBadCredentials, LockedUntil: lockUntil}
	}
	if err := st.RecordWebAdminLoginSuccess(ctx, a.ID, ip); err != nil {
		// 成功路径里 record 失败不应该拦登录(已经验证通过,只是审计写库出问题)。
		// 这里直接放过,让登录 OK,RecordSuccess 失败会在 logrus 体现。
		_ = err
	}
	return AuthResult{Admin: a}
}

// =========================================================================
// decoy hash:登录 timing 防护
// =========================================================================

// decoyWebHashCached 在首次需要时生成一次 unguessable password 的 PHC,后续复用。
// 与 nanotun/auth.runDecoyVerify 同思路。
var decoyWebHashCached string

func decoyWebHash() string {
	if decoyWebHashCached != "" {
		return decoyWebHashCached
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// rand 都炸了,这进程也不该继续提供服务 —— 但 verify 路径不该 panic。
		// 退化:返回一个常量 hash,timing 仍走 argon2,无安全意义(decoy 不需要保密)。
		decoyWebHashCached = fallbackDecoy()
		return decoyWebHashCached
	}
	plain := base64.RawStdEncoding.EncodeToString(raw[:])
	h, err := auth.HashPSK(plain)
	if err != nil {
		decoyWebHashCached = fallbackDecoy()
		return decoyWebHashCached
	}
	decoyWebHashCached = h
	return decoyWebHashCached
}

// fallbackDecoy 在 crypto/rand 失败时使用。生成一次性硬编码 salt+hash。
// 这只是兜底,生产中走不到。
func fallbackDecoy() string {
	const salt = "0123456789abcdef"
	hash := argon2.IDKey([]byte("decoy-fallback"), []byte(salt), 2, 64*1024, 4, 32)
	return auth.EncodePSK([]byte(salt), hash, 64*1024, 2, 4)
}

// ConstantTimeStringEqual 暴露给 csrf / session id 比较用。
func ConstantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		// 长度不等仍跑一次比较,避免长度泄露 timing。
		_ = subtle.ConstantTimeCompare([]byte(a), []byte(a))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
