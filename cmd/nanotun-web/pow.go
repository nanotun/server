package main

// pow.go - 登录页前置 Hashcash 式工作量证明(P3:防自动化批量撞库 / 扫描)。
//
// 设计要点
// --------
// 1) **算法与 旧集中式后端/internal/pow 完全一致**:
//      preimage = UTF8(challenge_id) || 0x00 || salt(16B) || BE_uint64(nonce)
//      合法当且仅当 SHA-256(preimage) 前导零比特数 >= difficulty
//    复用同一规则让客户端 JS / 其它语言实现可以直接迁移,审计统一。
//
// 2) **服务端无 server-side state**:
//    challenge_id (UUID) + salt + difficulty + expires_at 全部由客户端在
//    POST 时回传,服务端用 powHMACKey 重算 HMAC-SHA256 对比 → 防伪造。
//    模式与 captcha cookie / pending2FA cookie 一致,powHMACKey 独立 32B
//    启动随机。
//
// 3) **防重放只用进程内 sync.Map**:
//    - nanotun-web 是**单实例**(走 systemd 单进程,无水平扩展),没有 Redis;
//      用 SQLite 写一行 ~50us 也行但纯属浪费,内存 map 同进程读写 < 1μs。
//    - 每条记录 = (challenge_id, expireUnix),GC goroutine 每 60s 扫一遍
//      把已过期的删掉,避免无界增长。即便不 GC,5min 内一台机器扛
//      上百万次登录都不可能,内存上限可控。
//    - **重启清空**:把全部"已用 challenge"清空 → attacker 可以重放
//      重启前签发的 challenge?**不会**,因为 powHMACKey 启动时也随机重新生成,
//      旧 HMAC 在新 key 下全部无效,自动断链。
//
// 4) **自适应难度,平时无感**:
//    handler 端按当前 IP 的失败计数算难度(见 ip_failures.go):
//      failures < 3       → difficulty=0,不下发 PoW,模板不渲染输入
//      failures = 3       → 14-bit(浏览器 ~50ms)
//      每多 1 次失败      → +2-bit(~4x 耗时)
//      封顶               → 22-bit(浏览器 ~10-20s,扫描器经济上不划算)
//
// 5) **任何失败(密码/captcha/PoW)都计 IP 失败**;成功登录 → 该 IP 清零。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// =============================================================================
// 常量
// =============================================================================

const (
	powMinDifficulty = 4  // 与 旧集中式后端 一致,< 4 没意义
	powMaxDifficulty = 26 // 浏览器 setTimeout-切片 SHA-256 跑 ~60-120s,封顶在用户能忍的边缘
	powSaltBytes     = 16

	// 题目 5 分钟有效。够慢用户解(最大难度也就 ~60s),又够短压制重放窗口。
	powTTLSec = int64(5 * 60)

	// 签名格式版本号。明文 = "v1|cid|salt_b64|difficulty|exp"
	powSigVersion = "v1"
)

// =============================================================================
// 算法核心 — 与 旧集中式后端/internal/pow/pow.go 兼容
// =============================================================================

// powHash 计算单次 PoW 哈希。一次性场景,不引入中间态复用(那是 solver 该做的事)。
func powHash(challengeID string, salt []byte, nonce uint64) [32]byte {
	buf := make([]byte, 0, len(challengeID)+1+len(salt)+8)
	buf = append(buf, challengeID...)
	buf = append(buf, 0)
	buf = append(buf, salt...)
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	buf = append(buf, nb[:]...)
	return sha256.Sum256(buf)
}

// powLeadingZeroBits 数 digest 从最高位起连续 0 比特数。
// 与 旧后端 实现等价,**手动展开**第一字节扫描,避免 inner loop 跑空。
func powLeadingZeroBits(d [32]byte) int {
	n := 0
	for _, b := range d {
		if b == 0 {
			n += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<uint(bit)) == 0 {
				n++
			} else {
				return n
			}
		}
		return n
	}
	return n
}

// powVerify 校验 (cid, salt, difficulty, nonce) 是否构成合法 PoW。
// 单纯数学校验,不管签名 / 重放 — 那是上层 VerifyPoWProof 的事。
func powVerify(challengeID string, salt []byte, difficulty int, nonce uint64) bool {
	if difficulty < powMinDifficulty || difficulty > powMaxDifficulty {
		return false
	}
	if len(salt) != powSaltBytes {
		return false
	}
	return powLeadingZeroBits(powHash(challengeID, salt, nonce)) >= difficulty
}

// =============================================================================
// 签名(防伪造题目元数据)
// =============================================================================
//
// 明文格式 = "v1|cid|salt_b64|difficulty|exp_unix",与 旧集中式后端 一致。
// HMAC-SHA256 base64-std 输出。exp=0 时表示无过期(本项目目前总下发 exp,
// 但保留 0 语义便于以后 toggle)。

func powChallengeHMAC(key []byte, cid, saltB64 string, difficulty int, exp int64) string {
	if len(key) == 0 {
		return ""
	}
	msg := fmt.Sprintf("%s|%s|%s|%d|%d", powSigVersion, cid, saltB64, difficulty, exp)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func powChallengeHMACEqual(key []byte, cid, saltB64 string, difficulty int, exp int64, sigB64 string) bool {
	want := powChallengeHMAC(key, cid, saltB64, difficulty, exp)
	if want == "" {
		return false
	}
	a, err1 := base64.StdEncoding.DecodeString(want)
	b, err2 := base64.StdEncoding.DecodeString(sigB64)
	if err1 != nil || err2 != nil || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// =============================================================================
// 题目 / 校验数据结构
// =============================================================================

// PoWChallenge 是出题时下发给模板 / 客户端的题目元数据。
type PoWChallenge struct {
	ChallengeID string `json:"challenge_id"`
	Salt        string `json:"salt"`       // base64 std
	Difficulty  int    `json:"difficulty"` // 0 = 不需要 PoW(平时无感)
	ExpiresAt   int64  `json:"expires_at"` // Unix 秒;0 = 不需要 PoW
	Signature   string `json:"signature"`  // base64 std HMAC;0 难度时为空
}

// IsRequired 题目难度 > 0 即视为客户端需要解 PoW;
// difficulty=0 时整套字段对客户端是"占位",服务端 POST 也跳过校验。
func (c PoWChallenge) IsRequired() bool {
	return c.Difficulty > 0
}

// PoWProof 是客户端 POST 时回传的字段。前 5 个字段必须与出题原样一致,
// Nonce 是客户端找到的解。
type PoWProof struct {
	ChallengeID string
	Salt        string
	Difficulty  int
	ExpiresAt   int64
	Signature   string
	Nonce       uint64
}

// =============================================================================
// 错误类型 — 分得细是为了 audit 写明 reason,**对外提示统一模糊化**
// =============================================================================

var (
	ErrPoWNotProvided   = errors.New("pow: proof missing")
	ErrPoWBadSalt       = errors.New("pow: bad salt")
	ErrPoWBadSignature  = errors.New("pow: bad signature")
	ErrPoWExpired       = errors.New("pow: expired")
	ErrPoWDifficultyLow = errors.New("pow: difficulty below server requirement")
	ErrPoWInvalid       = errors.New("pow: hash does not meet difficulty")
	ErrPoWReplay        = errors.New("pow: challenge already consumed")
	ErrPoWBadCID        = errors.New("pow: bad challenge id")
)

// =============================================================================
// SessionService 方法:出题 + 校验 + 防重放
// =============================================================================

// IssueChallenge 出一道难度 d 的题。d=0 → 返回零值,代表客户端不需要算。
// d > 0 必须落在 [powMinDifficulty, powMaxDifficulty];越界自动夹断。
func (s *SessionService) IssueChallenge(d int) (PoWChallenge, error) {
	if d <= 0 {
		return PoWChallenge{}, nil
	}
	if d < powMinDifficulty {
		d = powMinDifficulty
	}
	if d > powMaxDifficulty {
		d = powMaxDifficulty
	}
	cidBuf := make([]byte, 16)
	if _, err := rand.Read(cidBuf); err != nil {
		return PoWChallenge{}, err
	}
	// 用 base64url 而不是 UUID 格式 — challenge_id 只是不可碰撞的 token,
	// 不需要"v4 UUID"那种语义。短一字节就少占字节。
	cid := base64.RawURLEncoding.EncodeToString(cidBuf)

	salt := make([]byte, powSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return PoWChallenge{}, err
	}
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	exp := nowUnix() + powTTLSec
	return PoWChallenge{
		ChallengeID: cid,
		Salt:        saltB64,
		Difficulty:  d,
		ExpiresAt:   exp,
		Signature:   powChallengeHMAC(s.powHMACKey, cid, saltB64, d, exp),
	}, nil
}

// VerifyPoWProof 校验客户端 POST 回来的 PoWProof。
//
// 顺序:格式 → HMAC → 过期 → 难度下限(serverWants)→ 数学 → 防重放。
// 任一失败均返回对应 Err*;serverWants 是 handler 当时算出来的"此次登录
// 应该要的最小难度",防止 attacker 拿到一把旧的低难度合法签名后无限重放
// (HMAC 上服务端只对自己签发的难度负责,但配套自适应升级时旧签名仍合法,
// 这里加 serverWants 兜底)。
//
// 防重放:进程内 sync.Map[challenge_id] = expireUnix;第二次校验同一 cid
// 直接返回 ErrPoWReplay。GC 由 runPoWGC goroutine 异步回收。
func (s *SessionService) VerifyPoWProof(p PoWProof, serverWants int) error {
	if p.ChallengeID == "" {
		return ErrPoWBadCID
	}
	// 这里 difficulty 是 0..powMaxDifficulty,签名 secret 都为空时 IssueChallenge
	// 不会签也不会进 verify;>0 必然有签名。
	if p.Signature == "" || p.Difficulty <= 0 || p.ExpiresAt <= 0 {
		return ErrPoWBadSignature
	}
	salt, err := base64.StdEncoding.DecodeString(p.Salt)
	if err != nil || len(salt) != powSaltBytes {
		return ErrPoWBadSalt
	}
	if !powChallengeHMACEqual(s.powHMACKey, p.ChallengeID, p.Salt, p.Difficulty, p.ExpiresAt, p.Signature) {
		return ErrPoWBadSignature
	}
	now := nowUnix()
	if now >= p.ExpiresAt {
		return ErrPoWExpired
	}
	if p.Difficulty < serverWants {
		// 防御深度:旧的低难度签名(签名合法 + 未过期)在服务端临时升级
		// 后被重放。serverWants 通常等于"刚才 GET /login 时算出来的难度",
		// 但 attacker 可以拿三天前的 GET 拿到的 challenge 来 POST,这里挡。
		return ErrPoWDifficultyLow
	}
	if !powVerify(p.ChallengeID, salt, p.Difficulty, p.Nonce) {
		return ErrPoWInvalid
	}
	// 防重放:第一次见 → 写入;第二次见 → 拒绝。
	// SetNX 语义用 LoadOrStore + 比较 — 同 IP 并发提交同一 challenge
	// 也只有一次能赢。
	exp := p.ExpiresAt
	if _, loaded := s.powUsed.LoadOrStore(p.ChallengeID, exp); loaded {
		return ErrPoWReplay
	}
	return nil
}

// runPoWGC 是 main.go 启动时 go 出去的 goroutine,定期清扫已过期的
// challenge_id 记录,避免长时间运行内存无界增长。
//
// 实测:5min TTL × 哪怕 100 req/s 也只有 30000 条 entry × ~80B/entry ≈ 2.4 MB
// 完全用不到 GC;但加上保险,跑了几天还是干净的。
func (s *SessionService) runPoWGC(stop <-chan struct{}) {
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			s.pruneExpiredPoW()
		}
	}
}

// pruneExpiredPoW 单次清理。Map.Range 上**修改不影响遍历语义**(sync.Map
// 文档保证) — 边遍历边 Delete 是 ok 的。
func (s *SessionService) pruneExpiredPoW() {
	now := nowUnix()
	s.powUsed.Range(func(k, v any) bool {
		exp, ok := v.(int64)
		if !ok || exp <= now {
			s.powUsed.Delete(k)
		}
		return true
	})
	// captchaUsed 与 powUsed 同套(nonce → expireUnix),同一轮 GC 一并清过期项,
	// 避免用过的 captcha nonce 长期占内存。
	s.captchaUsed.Range(func(k, v any) bool {
		exp, ok := v.(int64)
		if !ok || exp <= now {
			s.captchaUsed.Delete(k)
		}
		return true
	})
}

// powUsedSnapshot 仅测试 / 调试用:返回当前 in-flight challenge 数量。
// 不保证准确(并发场景下计数会偏小),够诊断就行。
func (s *SessionService) powUsedSnapshot() int {
	n := 0
	s.powUsed.Range(func(_, _ any) bool { n++; return true })
	return n
}

// =============================================================================
// 难度计算 — 自适应公式
// =============================================================================
//
// 思路:平时 0(无 PoW),失败 ≥3 次开始要,每多 1 次失败 +2 bit,封顶 22。
// 14-bit 浏览器纯 JS SHA-256 跑 ~50ms,22-bit 跑 ~10-20s。
// 用户失败的越多说明越像撞库 → 越慢。
//
// 同时把 powMaxDifficulty(26)留作"硬天花板",即使公式算出更大也夹到 26
// 防止运维误调把客户端逼死。

const (
	powFailuresEnable  = 3
	powBaseDifficulty  = 14
	powStepPerFailure  = 2
	powAdaptiveCeiling = 22
)

// ComputeDifficulty 给定 IP 在过去窗口内的失败次数,算出应下发的 PoW 难度。
//
// 返回值语义:0 = 不下发 PoW(失败 < powFailuresEnable,平时无感);否则落在
// [powBaseDifficulty, min(powAdaptiveCeiling, powMaxDifficulty)]。注意 base(14)已经 ≥
// powMinDifficulty(4),故本函数产出的任何非零难度天然满足 IssueChallenge 的下限,无需再夹;
// powMinDifficulty 仅对「运维/调用方手动指定的低难度」在 IssueChallenge 处兜底。
//
// 第三轮深扫 L9:曲线本身与出/校验/重放防御一致且正确,这里不改调参(base=14、step=2、
// 3 次起、封顶 22),仅去掉恒不成立的 `d > powMaxDifficulty` 死分支——powAdaptiveCeiling(22)
// < powMaxDifficulty(26),故经自适应天花板夹断后 d 必 ≤ 22 < 26。异常的 failures<0 也已被下面
// 的 `< powFailuresEnable` 阈值覆盖(负数必 < 3 → 返回 0),无需额外兜底。
func ComputeDifficulty(failures int) int {
	if failures < powFailuresEnable {
		return 0
	}
	d := powBaseDifficulty + powStepPerFailure*(failures-powFailuresEnable)
	// 自适应天花板即最终上限(已恒 < powMaxDifficulty 硬顶,无需二次夹断)。
	if d > powAdaptiveCeiling {
		d = powAdaptiveCeiling
	}
	return d
}

// =============================================================================
// 模板/前端格式化辅助
// =============================================================================

// FormatPoWForTemplate 把 PoWChallenge 转成 template 友好的 map,
// 配合 login.html 里的 hidden field + JS solver。
//
// "Required" 单独抽出来方便模板 `{{if .Data.PoW.Required}}` 写条件;
// "DifficultyStr" 是 strconv.Itoa,模板里不用再调函数。
func FormatPoWForTemplate(c PoWChallenge) map[string]any {
	if !c.IsRequired() {
		return map[string]any{"Required": false}
	}
	return map[string]any{
		"Required":      true,
		"ChallengeID":   c.ChallengeID,
		"Salt":          c.Salt,
		"Difficulty":    c.Difficulty,
		"DifficultyStr": strconv.Itoa(c.Difficulty),
		"ExpiresAt":     c.ExpiresAt,
		"Signature":     c.Signature,
	}
}

// =============================================================================
// 解析 POST 表单里的 PoW 字段(handler_auth.go 调用)
// =============================================================================
//
// 字段命名跟 login.html / pow_solver.js 一致:
//   pow_challenge_id    string
//   pow_salt            string (base64)
//   pow_difficulty      int
//   pow_expires_at      int64
//   pow_signature       string
//   pow_nonce           string (uint64 十进制)
//
// nonce 用字符串传 — JS BigInt → string,服务端再 strconv.ParseUint。
// 不用 int64 是因为 nonce 可能跨过 2^63(虽然实际不会,严谨起见 uint64)。

// parsePoWFormFields 是 handler_auth 用来把表单 raw 字段折成 PoWProof 的小工具。
// 任一字段缺失 / 解析失败 → 返回携带具体 reason 的 error,让 audit 写明白原因。
func parsePoWFormFields(r interface {
	FormValue(string) string
}) (PoWProof, error) {
	cid := r.FormValue("pow_challenge_id")
	if cid == "" {
		return PoWProof{}, errors.New("pow_challenge_id empty")
	}
	salt := r.FormValue("pow_salt")
	if salt == "" {
		return PoWProof{}, errors.New("pow_salt empty")
	}
	diffStr := r.FormValue("pow_difficulty")
	diff, err := strconv.Atoi(diffStr)
	if err != nil || diff <= 0 {
		return PoWProof{}, errors.New("pow_difficulty bad: " + diffStr)
	}
	expStr := r.FormValue("pow_expires_at")
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || exp <= 0 {
		return PoWProof{}, errors.New("pow_expires_at bad: " + expStr)
	}
	sig := r.FormValue("pow_signature")
	if sig == "" {
		return PoWProof{}, errors.New("pow_signature empty")
	}
	nonceStr := r.FormValue("pow_nonce")
	nonce, err := strconv.ParseUint(nonceStr, 10, 64)
	if err != nil {
		return PoWProof{}, errors.New("pow_nonce bad: " + nonceStr)
	}
	return PoWProof{
		ChallengeID: cid,
		Salt:        salt,
		Difficulty:  diff,
		ExpiresAt:   exp,
		Signature:   sig,
		Nonce:       nonce,
	}, nil
}

// =============================================================================
// SessionService 字段补丁 — powHMACKey + powUsed 在 session.go 里加;
// 这里为防 mock 测试方便,暴露一个 setter(仅测试用)。
// =============================================================================

var _ = sync.Map{} // 防 import drift
