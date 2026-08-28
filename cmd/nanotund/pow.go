package main

// pow.go - VPN 登录前置 PoW(SHA-256 前导零比特)防护。
//
// 设计要点 — 与 `nanotun-web/pow.go` / `rust_vpn_client_lib_common/src/pow.rs` /
// 旧集中式后端/internal/pow` 算法完全一致(三处独立实现 + 一处 Rust 客户端,
// 算法字段命名都对齐):
//
//   preimage = UTF8(challenge_id) || 0x00 || salt(16B) || BE_uint64(nonce)
//   合法 ⇔ SHA-256(preimage) 前导零比特数 ≥ difficulty
//
// 跟 nanotun-web 的区别:
//
//   1) **协议层**:nanotun-web 是 HTML 表单上下文(handler 解 r.FormValue),nanotun 走
//      链路帧 JSON,所以这里不需要 parsePoWFormFields,直接读 LoginReq.Pow 子结构;
//   2) **failures_enable 默认 0**:nanotun-web 默认头 2 次 IP 失败免 PoW(网页用户体验
//      优先),nanotun 设计阶段决定 **永远要 PoW**(failures < 3 用 base_difficulty=8,
//      ~5ms 客户端无感),保证 server argon2 永不被 attacker 无 PoW 直接消耗;
//   3) **base_difficulty=8 / ramp_difficulty=14**:nanotun-web 只有一档基础难度 14,
//      nanotun 拆两档 — 平时 8(对正常用户无感),失败 ≥ 3 跳到 14;
//   4) **HMAC key 强制启动随机,不暴露配置**:不开放 [server.pow].salt_hmac_key_b64,
//      因为 key 持久化 + sync.Map 重启清空 = 旧签名可重放;启动随机 + 重启即失效是
//      invariant,不能被运维错误配置破坏;
//   5) **包名 main**:跟 server/ 其它 .go 一致(server 不是单独 package,直接编进
//      nanotun binary main 包)。
//
// 防重放:进程内 sync.Map[challenge_id] = expireUnix,LoadOrStore 原子操作;数学
// 校验通过后才 store(失败的 nonce 不消耗 challenge,让 attacker 算错 nonce 时
// 仍需重做 PoW)。每 60s GC 一次过期 entry。重启清空 — 配合 HMAC key 启动随机
// 重新生成,旧 challenge 在新 key 下全部失效,自动断链,不需要持久化。

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/config"
)

// =============================================================================
// 常量
// =============================================================================

const (
	// 难度边界别名到 config 包的单一事实来源(config.PoWMinDifficulty/PoWMaxDifficulty)。
	// 语义不变:4=与旧集中式后端 / rust_vpn_client_lib_common 一致下界;22-bit 在 M1 ~10s /
	// iPhone ~15s / 低端 Android ~30s 封顶。`nanotun-admin config lint` 的 PoWConfig.Validate
	// 也据此边界预演本文件 NewPoWService 的 fail-fast,三处永不漂移。
	powMinDifficulty = config.PoWMinDifficulty
	powMaxDifficulty = config.PoWMaxDifficulty
	powSaltBytes     = 16

	// 签名格式版本号。明文 = "v1|cid|salt_b64|difficulty|exp"。
	powSigVersion = "v1"
)

// =============================================================================
// 算法核心 — 与 旧集中式后端/internal/pow/pow.go / nanotun-web/pow.go 兼容
// =============================================================================

// powHash 计算单次 PoW 哈希。
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
// 与 旧后端 / nanotun-web 实现等价。
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

// PoWChallenge 出题时下发给客户端的题目元数据。
// JSON wire 跟 util.LinkPoWChallenge 一一对应(都用 snake_case)。
type PoWChallenge struct {
	ChallengeID string `json:"challenge_id"`
	Salt        string `json:"salt"`       // base64 std,16B
	Difficulty  int    `json:"difficulty"` // [powMinDifficulty, powMaxDifficulty]
	ExpiresAt   int64  `json:"expires_at"` // Unix 秒
	Signature   string `json:"signature"`  // base64 std HMAC
}

// PoWProof 客户端在 LoginReq.pow 字段中回填的解题答案。
// 前 5 字段必须与出题原样一致;Nonce 是客户端找到的解。
type PoWProof struct {
	ChallengeID string
	Salt        string
	Difficulty  int
	ExpiresAt   int64
	Signature   string
	Nonce       uint64
}

// =============================================================================
// 错误类型 — 分得细是为了 audit 写明 reason;**对外 close code 统一 412**,
// 不让 attacker 通过响应区分内部失败原因。
// =============================================================================

var (
	ErrPoWBadCID        = errors.New("pow: bad challenge id")
	ErrPoWBadSalt       = errors.New("pow: bad salt")
	ErrPoWBadSignature  = errors.New("pow: bad signature")
	ErrPoWExpired       = errors.New("pow: expired")
	ErrPoWDifficultyLow = errors.New("pow: difficulty below server requirement")
	ErrPoWInvalid       = errors.New("pow: hash does not meet difficulty")
	ErrPoWReplay        = errors.New("pow: challenge already consumed")
)

// =============================================================================
// PoWService
// =============================================================================

// PoWService 出题 + 校验 + 防重放。**进程级单例**,启动时初始化(随机 HMAC key)。
//
// 字段 (难度计算公式 / TTL) 来自 [server.pow] 配置,初始化时拷贝进结构体,后续
// 不变(reload 不动 PoW 段,因为 HMAC key 重启即失效,无法热更新公式而保持
// 题目兼容)。
type PoWService struct {
	// 进程级 HMAC key,启动时 crypto/rand 32B,**永不持久化**。
	// 重启即失效 + sync.Map 清空,旧 challenge 自动作废,attacker 无法跨重启重放。
	hmacKey []byte

	// powUsed 防重放:LoadOrStore(cid, expireUnix) 原子。
	// runGC 每 60s 扫一遍删除已过期的 entry,sync.Map 文档保证边遍历边 Delete 安全。
	powUsed sync.Map // map[string]int64

	// 配置参数(初始化后只读)
	failuresEnable  int   // 失败次数 < 此值时用 baseDifficulty(默认 0:从第 1 次就要 PoW)
	baseDifficulty  int   // 平时难度(默认 8,~5ms 客户端无感)
	rampDifficulty  int   // 失败 ≥ failuresEnable 时跳到的难度(默认 14)
	stepPerFailure  int   // ramp 后每多一次失败 +N bit(默认 2)
	adaptiveCeiling int   // 难度封顶(默认 22)
	ttlSec          int64 // 题目有效期秒(默认 300)

	// 失败计数器(IP 滑动窗口),由 ipFailureTracker 维护;PoWService 不直接管。
	failures *IPFailureTracker

	// =============== Prometheus metrics(P1-2)===============
	// 全部 atomic.Uint64,无锁;Range 读 sync.Map 算 powUsed size 时偶有微开销,
	// 但 metrics scrape ~30s 一次,可忽略。
	//
	// 设计:不暴露 per-IP 维度(高基数),只暴露聚合 counter。
	issuedTotal        atomic.Uint64 // IssueChallenge 成功次数
	issuedRampedTotal  atomic.Uint64 // 其中难度高于 base 的次数(该 IP 已进 ramp)
	verifySuccessTotal atomic.Uint64 // VerifyPoWProof 返回 nil 次数
	// 失败分原因:每个 ErrPoW* 对应一个 counter,便于运维分析 attack pattern。
	verifyFailBadCID        atomic.Uint64
	verifyFailBadSignature  atomic.Uint64
	verifyFailBadSalt       atomic.Uint64
	verifyFailExpired       atomic.Uint64
	verifyFailDifficultyLow atomic.Uint64
	verifyFailInvalid       atomic.Uint64
	verifyFailReplay        atomic.Uint64
}

// NewPoWService 构造一个新 PoW 服务实例。
// hmacKeyOverride 仅供测试注入固定 key;生产路径传 nil → 启动随机 32B。
func NewPoWService(
	hmacKeyOverride []byte,
	failures *IPFailureTracker,
	failuresEnable, baseDifficulty, rampDifficulty, stepPerFailure, adaptiveCeiling int,
	ttlSec int64,
) (*PoWService, error) {
	key := hmacKeyOverride
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := powRandRead(key); err != nil {
			return nil, fmt.Errorf("pow: failed to generate the HMAC key: %w", err)
		}
	}
	if failures == nil {
		failures = NewIPFailureTracker()
	}
	// 取值守卫,三种语义(第四轮深扫 LOW,e_pow_cfg):
	//   - **零值 / 未配置** → 用业务推荐默认(8/14/2/22/300),跟 config.go 注释承诺"开箱即用"对齐;
	//   - **显式非法值**(负数 / 正但越出 [powMinDifficulty, powMaxDifficulty] / 顺序倒置)→ **fail-fast 返回
	//     error**,由 main 走 util.FatalExit(ExitConfigSemantic) 拒绝启动;
	//   - 不再"静默夹断":之前把 base_difficulty=40 悄悄夹到 26、ramp=2 夹到 base、ceiling<ramp 抬到 ramp,
	//     运维以为按自己写的难度在跑,实际是被改写过的值 —— 安全参数被静默篡改比直接报错更危险。
	//
	// 历史:round-3 deep scan 修过「零值被误当非法夹到 4 导致 PoW 近乎失效」;本轮把剩下的"非法即夹断"
	// 也改成"非法即报错",零值→默认的语义保持不变。
	var perrs []string
	// failures_enable 也要走「==0 视作未配 → 用默认」,和下面每一个难度字段一致。
	//
	// 它以前是唯一没有零值默认的字段,而 ComputeDifficulty 的判据是 `failures < failuresEnable`:
	// 取 0 时这个条件恒假,于是**永远走 ramp 分支**,baseDifficulty 完全不可达。后果是参考部署
	// (没有 [server.pow] 段 → 全零)实际跑出来的曲线和文档承诺的整体错位一档:
	//   实际  failures=0→14, 3→20, 4→22(封顶)
	//   承诺  failures=0→8,  3→14, 4→16, 7→22
	// 也就是说:每次正常登录都在付 14-bit 而不是设计的 8-bit(多 64 倍哈希),而**普通用户连输错
	// 4 次密码就撞上 22-bit 封顶**(注释自己写的是「~10s 客户端 / iPhone 15s」),而设计上要 7 次。
	//
	// 「从第 1 次失败就 ramp」并没有因此失去表达方式 —— 那正是 failures_enable=1:
	// failures=0 时 0<1 走 base,第 1 次失败后进 ramp。
	if failuresEnable == 0 {
		failuresEnable = config.PoWDefaultFailuresEnable // 头 3 次(含 0 次失败)只要 base_difficulty
	} else if failuresEnable < 0 {
		perrs = append(perrs, fmt.Sprintf("[server.pow].failures_enable=%d must not be negative (0=use the default 3; 1=ramp from the very first failure)", failuresEnable))
	}
	// 各难度字段:==0 视作未配 → 用默认;其余(含负数)必须落在 [powMinDifficulty, powMaxDifficulty]。
	if baseDifficulty == 0 {
		baseDifficulty = config.PoWDefaultBaseDifficulty // ~5ms M1 客户端
	} else if baseDifficulty < powMinDifficulty || baseDifficulty > powMaxDifficulty {
		perrs = append(perrs, fmt.Sprintf("[server.pow].base_difficulty=%d is out of range (must be %d..%d; 0=use the default 8)",
			baseDifficulty, powMinDifficulty, powMaxDifficulty))
	}
	if rampDifficulty == 0 {
		rampDifficulty = config.PoWDefaultRampDifficulty // ~50ms 跳档
	} else if rampDifficulty < powMinDifficulty || rampDifficulty > powMaxDifficulty {
		perrs = append(perrs, fmt.Sprintf("[server.pow].ramp_difficulty=%d is out of range (must be %d..%d; 0=use the default 14)",
			rampDifficulty, powMinDifficulty, powMaxDifficulty))
	}
	if stepPerFailure == 0 {
		stepPerFailure = config.PoWDefaultStepPerFailure
	} else if stepPerFailure < 0 {
		perrs = append(perrs, fmt.Sprintf("[server.pow].step_per_failure=%d must not be negative (0=use the default 2)", stepPerFailure))
	}
	if adaptiveCeiling == 0 {
		adaptiveCeiling = config.PoWDefaultAdaptiveCeiling // ~10s 封顶
	} else if adaptiveCeiling < powMinDifficulty || adaptiveCeiling > powMaxDifficulty {
		perrs = append(perrs, fmt.Sprintf("[server.pow].adaptive_ceiling=%d is out of range (must be %d..%d; 0=use the default 22)",
			adaptiveCeiling, powMinDifficulty, powMaxDifficulty))
	}
	if ttlSec == 0 {
		ttlSec = config.PoWDefaultTTLSec
	} else if ttlSec < 0 {
		perrs = append(perrs, fmt.Sprintf("[server.pow].ttl_sec=%d must not be negative (0=use the default 300)", ttlSec))
	}
	// 区间错误先行返回,避免用被污染的值再做顺序校验产生二次误导。
	if len(perrs) > 0 {
		return nil, fmt.Errorf("pow: invalid configuration:\n  - %s", strings.Join(perrs, "\n  - "))
	}
	// 顺序约束(在已解析出的值上):base ≤ ramp ≤ ceiling。倒置意味着"失败后难度反而更低",
	// 让自适应升级失效 —— 同样 fail-fast 而非悄悄抬高。
	if rampDifficulty < baseDifficulty {
		perrs = append(perrs, fmt.Sprintf("[server.pow].ramp_difficulty(%d) must be >= base_difficulty(%d)",
			rampDifficulty, baseDifficulty))
	}
	if adaptiveCeiling < rampDifficulty {
		perrs = append(perrs, fmt.Sprintf("[server.pow].adaptive_ceiling(%d) must be >= ramp_difficulty(%d)",
			adaptiveCeiling, rampDifficulty))
	}
	if len(perrs) > 0 {
		return nil, fmt.Errorf("pow: invalid configuration:\n  - %s", strings.Join(perrs, "\n  - "))
	}
	return &PoWService{
		hmacKey:         key,
		failuresEnable:  failuresEnable,
		baseDifficulty:  baseDifficulty,
		rampDifficulty:  rampDifficulty,
		stepPerFailure:  stepPerFailure,
		adaptiveCeiling: adaptiveCeiling,
		ttlSec:          ttlSec,
		failures:        failures,
	}, nil
}

// ComputeDifficulty 根据 IP 当前失败次数算应下发的难度。
//
// 公式:
//
//	failures <  failuresEnable        → baseDifficulty   (平时,~5ms)
//	failures >= failuresEnable        → ramp + step * (failures - failuresEnable),封顶 adaptiveCeiling
//
// 默认值下(failuresEnable=3 / base=8 / ramp=14 / step=2 / ceiling=22):
// 这张表**整体依赖 failuresEnable 的默认值**;它曾经漏了零值默认,于是全表向上错位一档
// 而没人看得出来(详见 NewPoWService 里那段)。改这里的默认值必须同时改这张表。
//
//	failures=0  → 8-bit (~5ms 客户端无感)
//	failures=3  → 14-bit(~50ms 触发警觉)
//	failures=4  → 16-bit
//	failures=5  → 18-bit
//	failures=6  → 20-bit
//	failures=7+ → 22-bit(封顶,~10s 客户端,经济上 attacker 不划算)
func (s *PoWService) ComputeDifficulty(failures int) int {
	if failures < 0 {
		failures = 0
	}
	if failures < s.failuresEnable {
		return s.baseDifficulty
	}
	d := s.rampDifficulty + s.stepPerFailure*(failures-s.failuresEnable)
	if d > s.adaptiveCeiling {
		d = s.adaptiveCeiling
	}
	if d > powMaxDifficulty {
		d = powMaxDifficulty
	}
	if d < powMinDifficulty {
		d = powMinDifficulty
	}
	return d
}

// powRandRead 是 crypto/rand.Read 的间接层,只为可测性(生产行为不变)。与 takeoverSecretRandRead /
// hy2TokenRandRead 同一手法:熵源故障是走到「出题失败 → 拒绝这条连接」那条分支的唯一方式,而那条分支
// 的正确性(不能放一个没题的连接进登录,也不能给出一道 salt 全零的题)只有注入故障才验得到。
var powRandRead = rand.Read

// IssueChallenge 出一道难度 d 的题。d 会被自动夹到 [powMinDifficulty, powMaxDifficulty]。
func (s *PoWService) IssueChallenge(d int) (PoWChallenge, error) {
	if d < powMinDifficulty {
		d = powMinDifficulty
	}
	if d > powMaxDifficulty {
		d = powMaxDifficulty
	}
	cidBuf := make([]byte, 16)
	if _, err := powRandRead(cidBuf); err != nil {
		return PoWChallenge{}, fmt.Errorf("pow: failed to generate challenge_id: %w", err)
	}
	cid := base64.RawURLEncoding.EncodeToString(cidBuf)

	salt := make([]byte, powSaltBytes)
	if _, err := powRandRead(salt); err != nil {
		return PoWChallenge{}, fmt.Errorf("pow: failed to generate the salt: %w", err)
	}
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	exp := time.Now().Unix() + s.ttlSec
	s.issuedTotal.Add(1)
	// 按档分计:难度高于 base 说明这个 IP 已经进了 ramp。
	//
	// 自适应难度是登录侧唯一「按 IP 累进」的防爆破闸门,而在此之前它**在生产里完全不可观测**:
	// 既没有日志也没有指标,已有的 pow_ip_failures_tracked 只说「跟踪了几个 IP」,不说难度有没有涨。
	// 于是两件事都看不见:真被爆破时运维判断不了闸门在不在起作用;而 ComputeDifficulty 一旦回归
	// (本轮修的那个默认值缺陷就是一例)也不会留下任何痕迹。
	//
	// 口径说明:ramp_difficulty == base_difficulty 时(合法配置,ramp ≥ base)进 ramp 的出题会被
	// 记成 base —— 这种配置本身就放弃了分档,不额外区分。
	if d > s.baseDifficulty {
		s.issuedRampedTotal.Add(1)
	}
	return PoWChallenge{
		ChallengeID: cid,
		Salt:        saltB64,
		Difficulty:  d,
		ExpiresAt:   exp,
		Signature:   powChallengeHMAC(s.hmacKey, cid, saltB64, d, exp),
	}, nil
}

// VerifyPoWProof 校验客户端 LoginReq.pow 回传的 PoWProof。
//
// 顺序: 格式 → HMAC → 过期 → 难度下限(serverWants)→ 数学 → 防重放。
//
// 注意防重放只在「数学验证通过」后才 store cid → attacker 算错 nonce 提交不消耗
// challenge(他还得继续算 PoW,server 端只多了一次 SHA256 验证,可忽略)。
// 数学通过后 LoadOrStore 原子 → 防止并发提交同 cid 都通过。
func (s *PoWService) VerifyPoWProof(p PoWProof, serverWants int) error {
	if p.ChallengeID == "" {
		s.verifyFailBadCID.Add(1)
		return ErrPoWBadCID
	}
	if p.Signature == "" || p.Difficulty <= 0 || p.ExpiresAt <= 0 {
		s.verifyFailBadSignature.Add(1)
		return ErrPoWBadSignature
	}
	salt, err := base64.StdEncoding.DecodeString(p.Salt)
	if err != nil || len(salt) != powSaltBytes {
		s.verifyFailBadSalt.Add(1)
		return ErrPoWBadSalt
	}
	if !powChallengeHMACEqual(s.hmacKey, p.ChallengeID, p.Salt, p.Difficulty, p.ExpiresAt, p.Signature) {
		s.verifyFailBadSignature.Add(1)
		return ErrPoWBadSignature
	}
	now := time.Now().Unix()
	if now >= p.ExpiresAt {
		s.verifyFailExpired.Add(1)
		return ErrPoWExpired
	}
	if p.Difficulty < serverWants {
		// 防御深度: attacker 拿别人 IP 的低难度合法签名 challenge 来高难度 IP 上消费。
		// HMAC 上 server 只对签名合法负责,这里 serverWants 跟当前 IP 失败次数对齐,挡跨 IP 借题。
		s.verifyFailDifficultyLow.Add(1)
		return ErrPoWDifficultyLow
	}
	if !powVerify(p.ChallengeID, salt, p.Difficulty, p.Nonce) {
		s.verifyFailInvalid.Add(1)
		return ErrPoWInvalid
	}
	// 防重放: 第一次见 → store cid + exp;第二次见 → ErrPoWReplay。
	// LoadOrStore 原子,同 cid 并发也只第一个赢。
	if _, loaded := s.powUsed.LoadOrStore(p.ChallengeID, p.ExpiresAt); loaded {
		s.verifyFailReplay.Add(1)
		return ErrPoWReplay
	}
	s.verifySuccessTotal.Add(1)
	return nil
}

// MetricsSnapshot 快照所有 PoW 计数器 + 防重放表大小,metrics.go scrape 时一次性
// 读出,避免每个 metric 独立读多次造成快照不一致。
type PoWMetricsSnapshot struct {
	Issued        uint64
	IssuedRamped  uint64 // 其中难度高于 base 的部分:自适应闸门是否正在起作用的唯一信号
	VerifySuccess uint64
	FailBadCID    uint64
	FailBadSig    uint64
	FailBadSalt   uint64
	FailExpired   uint64
	FailDiffLow   uint64
	FailInvalid   uint64
	FailReplay    uint64

	// 当前活跃防重放表大小(O(n) Range,但 scrape 频率低,可接受)。
	UsedTableSize int
	// 当前 IP 失败计数表大小(per-IP 累积失败)。
	IPFailuresTracked int
}

func (s *PoWService) MetricsSnapshot() PoWMetricsSnapshot {
	if s == nil {
		return PoWMetricsSnapshot{}
	}
	ipFails := 0
	if s.failures != nil {
		ipFails = s.failures.Size()
	}
	return PoWMetricsSnapshot{
		Issued:            s.issuedTotal.Load(),
		IssuedRamped:      s.issuedRampedTotal.Load(),
		VerifySuccess:     s.verifySuccessTotal.Load(),
		FailBadCID:        s.verifyFailBadCID.Load(),
		FailBadSig:        s.verifyFailBadSignature.Load(),
		FailBadSalt:       s.verifyFailBadSalt.Load(),
		FailExpired:       s.verifyFailExpired.Load(),
		FailDiffLow:       s.verifyFailDifficultyLow.Load(),
		FailInvalid:       s.verifyFailInvalid.Load(),
		FailReplay:        s.verifyFailReplay.Load(),
		UsedTableSize:     s.powUsedCount(),
		IPFailuresTracked: ipFails,
	}
}

// powGCInterval 是 RunGC 的清扫周期。用 var 只为让守卫测试把它调到毫秒级 —— 否则「到点真的清了」
// 这条断言要等一分钟。生产不改这个值。
var powGCInterval = 60 * time.Second

// RunGC 是 main 入口启动的 goroutine,定期清扫过期 challenge_id 跟 stale IP 失败记录。
// stop 关闭时退出。
func (s *PoWService) RunGC(stop <-chan struct{}) {
	tick := time.NewTicker(powGCInterval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			s.pruneExpired()
			if s.failures != nil {
				s.failures.Prune()
			}
		}
	}
}

// pruneExpired 单次清理已过期的防重放 entry。
// sync.Map.Range 边遍历边 Delete 是安全的(stdlib 文档保证)。
func (s *PoWService) pruneExpired() {
	now := time.Now().Unix()
	removed := 0
	s.powUsed.Range(func(k, v any) bool {
		exp, ok := v.(int64)
		if !ok || exp <= now {
			s.powUsed.Delete(k)
			removed++
		}
		return true
	})
	if removed > 0 {
		logrus.WithField("removed", removed).Debug("[pow] GC removed expired challenges")
	}
}

// powUsedCount 调试 / metrics 用 — 当前活跃 challenge 防重放表大小。
func (s *PoWService) powUsedCount() int {
	n := 0
	s.powUsed.Range(func(_, _ any) bool { n++; return true })
	return n
}
