package main

import (
	"context"
	"crypto/subtle"
	"errors"
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

// VerifyWebPassword 与 auth.VerifyPSK 等价,但**经全局 argon2 semaphore 限流**(auth.VerifyPSKLimited)。
//
// 注意:这里没有复用 *auth.Verifier 是因为它要求 store.User,而 web_admins 是单独表;但 VerifyPSKLimited
// 仅需要 PHC 字符串,可直接用。第四轮深扫 HIGH:此前直接调 VerifyPSK 绕过了信号量,web 登录 / decoy / 恢复码
// 校验可并发起大量 64MB argon2 把宿主 OOM;改走 VerifyPSKLimited 后与 VPN 登录共用同一并发天花板。
//
// ctx 取消 / 容量耗尽时返回 (false, err);调用方(AttemptLogin 等)对 err 的既有处理是「按验证失败/记一次失败」,
// 语义安全(不会误判为验证通过)。
func VerifyWebPassword(ctx context.Context, plaintext, encoded string) (bool, error) {
	return auth.VerifyPSKLimited(ctx, plaintext, encoded)
}

// isVerifyUnavailable 报告 err 是否为 argon2 verify **暂时不可用**(容量耗尽 / ctx 超时,auth.ErrVerifyUnavailable)。
// 第十四轮深扫 MED:供各 step-up / 登录 / 恢复码 handler 统一判定「非密码错 → 不计失败配额 → 回 503」,
// 避免每个 handler 都 import auth 包。
func isVerifyUnavailable(err error) bool { return errors.Is(err, auth.ErrVerifyUnavailable) }

// VerifyWebPasswordOrDecoy 同 VerifyWebPassword,但在**同一次** argon2 slot 内完成「真实 verify + 畸形 hash 的
// decoy」(auth.VerifyPSKLimitedOrDecoy)。第十二轮深扫 MED:合并 decoy 到单次 Acquire,消除「畸形 hash 的第二次
// Acquire 高并发下被跳过 → 时序泄漏 hash 损坏」的窗口。容量/ctx 超时返回的 err 会 errors.Is(auth.ErrVerifyUnavailable)。
func VerifyWebPasswordOrDecoy(ctx context.Context, plaintext, encoded, decoy string) (bool, error) {
	return auth.VerifyPSKLimitedOrDecoy(ctx, plaintext, encoded, decoy)
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
	// ErrAuthUnavailable:argon2 verify 因容量/ctx 超时未能执行(auth.ErrVerifyUnavailable)。第十二轮深扫 MED:
	// 属「暂时不可用」而非「密码错」——handler 据此**不**累加 ipFailures / 账号锁定,回 503 让用户重试。
	ErrAuthUnavailable = errors.New("登录暂时不可用,请稍后重试")
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
			// 第十四轮深扫 MED:decoy 遇 argon2 容量/ctx 超时,统一回 ErrAuthUnavailable(503),与「已存在用户」
			// 路径同款 —— 消除「已存在=503 vs 不存在/禁用/锁定=401」的用户名/状态枚举 oracle(round-12 只把已存在
			// 路径改成 503,漏了这三条 decoy 分支)。非容量错才走原「等时序 decoy 写事务 + 统一 badCredentials」。
			if _, derr := VerifyWebPassword(ctx, password, decoyWebHash()); isVerifyUnavailable(derr) {
				return AuthResult{Err: ErrAuthUnavailable}
			}
			// 第八轮深扫 LOW:与「密码错」分支一样跑一次等价写事务,抹平「不存在→零 DB」的时序差(枚举旁路)。
			st.DecoyWebAdminLoginFailure(ctx)
			return AuthResult{Err: ErrAuthBadCredentials}
		}
		// 深扫第八轮 LOW:此前返回内联中文 fmt.Errorf,trErr 既非哨兵也无 LocaleKey,
		// 英文 UI 下会原样渲染中文。改用可本地化错误(err.queryFailed 两套 catalog 都有)。
		return AuthResult{Err: newLocErr("err.queryFailed")}
	}
	if !a.Enabled {
		if _, derr := VerifyWebPassword(ctx, password, decoyWebHash()); isVerifyUnavailable(derr) {
			return AuthResult{Admin: a, Err: ErrAuthUnavailable}
		}
		// 禁用账号故意不累加失败计数(见下),但跑 decoy 写事务对齐时序,避免「存在且禁用」被时序识别。
		st.DecoyWebAdminLoginFailure(ctx)
		return AuthResult{Admin: a, Err: ErrAuthDisabled}
	}
	if a.LockedUntil > 0 && a.LockedUntil > nowUnix() {
		if _, derr := VerifyWebPassword(ctx, password, decoyWebHash()); isVerifyUnavailable(derr) {
			return AuthResult{Admin: a, Err: ErrAuthUnavailable}
		}
		st.DecoyWebAdminLoginFailure(ctx)
		return AuthResult{Admin: a, Err: ErrAuthLocked, LockedUntil: a.LockedUntil}
	}

	// 第四轮深扫 MED:存储 password_hash 畸形(手改库 / 老迁移 / 损坏)时,VerifyPSK 在 DecodePSK 阶段就
	// 快速返错(**不跑 argon2**),时序明显快于正常「密码错」路径 → 泄漏「此账号 hash 异常」。
	// 第十二轮深扫 MED:decoy 合并进**同一次** argon2 slot(VerifyWebPasswordOrDecoy),消除「畸形 hash 的
	// 第二次 Acquire 高并发下被跳过 → 时序泄漏」窗口(与 VPN 侧 auth.VerifyLogin 单 slot 内跑 decoy 对齐)。
	ok, verr := VerifyWebPasswordOrDecoy(ctx, password, a.PasswordHash, decoyWebHash())
	if errors.Is(verr, auth.ErrVerifyUnavailable) {
		// 第十二轮深扫 MED:argon2 容量/ctx 超时属「暂时不可用」,非密码错 —— **不**累加账号锁定计数
		// (handler 也会跳过 ipFailures.Inc 并回 503),避免容量抖动被放大成对合法管理员的锁定 DoS。
		return AuthResult{Admin: a, Err: ErrAuthUnavailable}
	}
	if verr != nil || !ok {
		_, lockUntil, _ := st.RecordWebAdminLoginFailure(ctx, a.ID,
			cfg.MaxLoginFailures, cfg.LockoutSeconds)
		// lockUntil > 0 时把"刚刚被锁"也透给 UI,让用户知道为什么 5 次后突然不响应了
		return AuthResult{Admin: a, Err: ErrAuthBadCredentials, LockedUntil: lockUntil}
	}
	// TOTP 账号:密码只是登录的第一步,**绝不能**在这里 RecordWebAdminLoginSuccess ——
	// 那会把 failed_logins/locked_until 清零,让 attacker 每次重发正确密码就把 TOTP 步
	// 累积起来的失败计数抹掉,6 位码锁定形同虚设(H1)。计数器复位统一交给
	// handleLoginTOTP 里「TOTP 全程通过」后的 RecordWebAdminLoginSuccess。
	// 非 TOTP 账号:密码正确即登录完成,照常复位 + 记录 last_login。
	if !a.TOTPEnabled {
		if err := st.RecordWebAdminLoginSuccess(ctx, a.ID, ip); err != nil {
			// 成功路径里 record 失败不应该拦登录(已经验证通过,只是审计写库出问题)。
			// 这里直接放过,让登录 OK,RecordSuccess 失败会在 logrus 体现。
			_ = err
		}
	}
	return AuthResult{Admin: a}
}

// =========================================================================
// decoy hash:登录 timing 防护
// =========================================================================

// decoyWebHashCached 是一段**固定**的合法 PHC,用于登录 timing 防护:让「用户不存在」分支也跑一次等价
// 耗时的 argon2id,避免通过响应时延枚举管理员用户名。
//
// 用固定构造(fallbackDecoy，不依赖运行时 crypto/rand)在包初始化时算一次:
//   - 天然**无数据竞争**——此前用惰性写 `decoyWebHashCached string` 存在良性 data race(go test -race 报警);
//   - 也不会像「sync.Once + 随机生成」那样一旦首次 entropy 抖动失败就永久退化为无 timing 防护
//     (与 nanotun/auth 侧把 decoy 改成固定值同一思路)。
//
// decoy 不保护任何真实秘密,只需触发等价耗时的 argon2 计算,故固定盐无碍。
var decoyWebHashCached = fallbackDecoy()

func decoyWebHash() string {
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
//
// 第四轮深扫 LOW:此前手写「长度不等就 ConstantTimeCompare(a, a)」的分支其实是**多余且误导**的——
// 它拿 a 和自己比,恒返回 1(被丢弃),耗时还随 len(a) 变化,并没有真正掩盖长度差。crypto/subtle 的
// ConstantTimeCompare 本身已保证:长度不匹配立即返回 0,且耗时只与输入长度有关、与内容无关(这正是
// 恒定时间比较对「长度非机密」的标准约定;session/CSRF token 均为定长,长度本就不是秘密)。直接委托它,
// 语义等价而更清晰。
func ConstantTimeStringEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
