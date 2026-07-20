// Package auth 实现 nanotun 的 PSK 登录认证。
//
// 自托管模式下 nanotun 不再向 旧集中式后端 调用 SessionAcquire 来换取 user_id，
// 而是用「用户名 + 预共享密钥（PSK）」做本地校验。PSK 以 argon2id 哈希形式存盘
// （见 PHC 风格的 EncodePSK / DecodePSK），登录时在内存里逐字节比对。
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sync/semaphore"

	"github.com/nanotun/server/store"
)

// argon2Sema 限制全局并发 argon2id verify 数量。
//
// 单次 verify 占 64MB RAM(argonMemory) + 数十 ms CPU(argonTime=2, argonThreads=4)。
// 没有这道闸门,恶意客户端只需要并发 N 个 LoginReq 就能让进程在 argon2 阶段 alloc
// 64GB RAM,触发 OOM kill 整个 nanotund 倒下。
//
// 容量挑选:
//   - argonThreads=4 让单次 verify 实际并行占用 ~4 cores;
//   - 设 NumCPU * 2 让 CPU/RAM 都还有些 headroom 给数据面 / TUN read / WS write;
//   - 兜底下限 8 防止小核心机型(1c2g VPS)算出来 cap=2 把生产堵死;
//   - 上限 64 防止超大机型把 RAM 全压在登录上,Web 数据面会饿。
//
// 真正受益:N 个并发登录排队过 verify,而不是同时占 N * 64MB。被拒登也会跑 decoy verify,
// 同样走这条闸门,保证 timing 防护与容量防护一致。
var argon2Sema = semaphore.NewWeighted(int64(computeArgon2Capacity()))

func computeArgon2Capacity() int {
	n := runtime.NumCPU() * 2
	if n < 8 {
		n = 8
	}
	if n > 64 {
		n = 64
	}
	return n
}

// argon2id 参数：与 OWASP 2024 推荐值对齐的中庸偏稳健档位。
// 调整时务必同步更新 EncodePSK 输出的 m=/t=/p= 字段，避免老库无法 verify。
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16

	// DecodePSK 接受 hash / salt 的最小字节数：分别防御
	//   * 空 hash 撞 ConstantTimeCompare(empty, empty) == 1 的 verify bypass
	//   * 短盐让破解者复用 rainbow table
	minHashBytes = 16
	minSaltBytes = 8

	// DecodePSK 接受 argon2id 参数的上限：防止管理员 / 迁移脚本写入超大 m=
	// 让验证路径 OOM。m=1GB 比 OWASP 推荐高 16 倍，是「显然不正常」的兜底门槛。
	maxArgonMemoryKiB uint32 = 1 * 1024 * 1024 // 1 GiB in KiB
	maxArgonTime      uint32 = 100
	maxArgonThreads   uint8  = 64
)

// HashPSK 接受明文 PSK，返回 PHC 风格编码后的字符串：
//
//	argon2id$v=19$m=65536,t=2,p=4$<base64-salt>$<base64-hash>
//
// 该编码同时包含算法参数与盐，验证时无需读取额外配置。
func HashPSK(plaintext string) (string, error) {
	if plaintext == "" {
		return "", errors.New("auth: empty psk")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read salt: %w", err)
	}
	hash := argon2.IDKey([]byte(plaintext), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return EncodePSK(salt, hash, argonMemory, argonTime, argonThreads), nil
}

// EncodePSK 把 (salt, hash, params) 拼成 PHC 编码。导出以便测试。
func EncodePSK(salt, hash []byte, memory uint32, time uint32, threads uint8) string {
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

// VerifyPSK 用恒定时间比较给定明文与已编码的 hash。
//
// encoded 必须是 HashPSK / EncodePSK 产出的格式；任何字段格式错误都会返回 error。
// 明文匹配时返回 (true, nil)，不匹配返回 (false, nil)；编码本身不合法时返回 error。
//
// 安全不变量（DecodePSK 已经校验过，这里 redundant 一次防御未来重构）：
//   - len(hash) >= minHashBytes —— 防 ConstantTimeCompare(empty, empty)=1 的 verify bypass
//   - len(salt) >= minSaltBytes
//   - argon 参数在合理上限内 —— 防 OOM
func VerifyPSK(plaintext, encoded string) (bool, error) {
	salt, hash, mem, t, p, err := DecodePSK(encoded)
	if err != nil {
		return false, err
	}
	if len(hash) < minHashBytes || len(salt) < minSaltBytes {
		return false, fmt.Errorf("auth: psk encoding too short (hash=%d salt=%d)", len(hash), len(salt))
	}
	cand := argon2.IDKey([]byte(plaintext), salt, t, mem, p, uint32(len(hash)))
	return subtle.ConstantTimeCompare(cand, hash) == 1, nil
}

// DecodePSK 解析 EncodePSK 写出的 PHC 字符串。导出供测试与 admin 后台诊断使用。
func DecodePSK(encoded string) (salt, hash []byte, memory, time uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: invalid psk encoding: parts=%d", len(parts))
	}
	if parts[0] != "argon2id" {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: unsupported algo %q", parts[0])
	}
	if !strings.HasPrefix(parts[1], "v=") {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: bad version field %q", parts[1])
	}
	ver, err := strconv.Atoi(parts[1][2:])
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: parse version: %w", err)
	}
	if ver != argon2.Version {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: argon2 version mismatch: got %d want %d", ver, argon2.Version)
	}

	memory, time, threads, err = parseArgonParams(parts[2])
	if err != nil {
		return nil, nil, 0, 0, 0, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: decode salt: %w", err)
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: decode hash: %w", err)
	}
	// 长度兜底（防 verify bypass）+ 参数上限兜底（防 OOM）。
	// 这两类畸形条目通常是「管理员手抖 / 老迁移脚本 / 第三方导入」产生的；
	// 让 DecodePSK 直接拒掉,verify 永远走 error 路径(被上层映射到 ErrBadPSK)。
	if len(hash) < minHashBytes {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: hash too short: %d (min %d)", len(hash), minHashBytes)
	}
	if len(salt) < minSaltBytes {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: salt too short: %d (min %d)", len(salt), minSaltBytes)
	}
	if memory > maxArgonMemoryKiB {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: argon m=%d KiB exceeds cap %d", memory, maxArgonMemoryKiB)
	}
	if time > maxArgonTime {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: argon t=%d exceeds cap %d", time, maxArgonTime)
	}
	if threads > maxArgonThreads {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: argon p=%d exceeds cap %d", threads, maxArgonThreads)
	}
	return salt, hash, memory, time, threads, nil
}

func parseArgonParams(s string) (memory, time uint32, threads uint8, err error) {
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return 0, 0, 0, fmt.Errorf("auth: bad param %q", kv)
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, 0, 0, fmt.Errorf("auth: bad param %s: %w", kv, err)
		}
		switch k {
		case "m":
			memory = uint32(n)
		case "t":
			time = uint32(n)
		case "p":
			threads = uint8(n)
		default:
			return 0, 0, 0, fmt.Errorf("auth: unknown param %s", k)
		}
	}
	if memory == 0 || time == 0 || threads == 0 {
		return 0, 0, 0, errors.New("auth: missing argon param")
	}
	return memory, time, threads, nil
}

// 错误集合（导出给上层判断登录拒绝原因，便于打日志）
var (
	ErrUnknownUser  = errors.New("auth: unknown user")
	ErrBadPSK       = errors.New("auth: bad psk")
	ErrUserDisabled = errors.New("auth: user disabled")
)

// Verifier 把 store.User 的 PSK 校验封成一个无状态服务。
//
// 上层（server.handleVPNLink）传入 store 实例后，可在登录帧到来时调用
// VerifyLogin(username, plaintextPSK) 直接拿到 *store.User。
type Verifier struct {
	store *store.Store
}

// NewVerifier 构造一个 Verifier，store 不能为 nil。
func NewVerifier(s *store.Store) *Verifier {
	if s == nil {
		panic("auth: nil store")
	}
	return &Verifier{store: s}
}

// VerifyLogin 验证 (username, plaintextPSK) 并返回对应的 user。
//
// 失败原因：
//   - ErrUnknownUser：用户名不存在；
//   - ErrUserDisabled：用户已被禁用；
//   - ErrBadPSK：PSK 不匹配；
//   - 其它 error：数据库故障 / 编码异常。
//
// **时序防护**：用户名不存在 / 已禁用时仍会跑一次完整 argon2id 哈希（用 decoy hash），
// 让响应时延与「用户名存在但密码错」的路径在数量级上一致，避免攻击者通过对比响应
// 时间枚举用户名。这是常规防御性补丁；攻击者拿到「用户名存在」信息后仍要面对 PSK
// 暴力破解（argon2id 64MB / 2 iter），但减少信息泄露总是好事。
func (v *Verifier) VerifyLogin(ctx context.Context, username, plaintext string) (*store.User, error) {
	if v == nil || v.store == nil {
		return nil, errors.New("auth: nil verifier")
	}
	// 关键 DoS 防御(P0-2 / E1):并发 argon2id 单次 64MB / 2 iter,1000 个并发登录 = 64GB
	// RAM 直接 OOM。这里用全局 weighted semaphore 把同时进行中的 verify(含真实 + decoy)
	// 个数封顶。capacity 在 init 里按 NumCPU 推导,详见 argon2Sema 定义。
	//
	// Acquire 失败的两种情况:
	//   - ctx 取消(连接断开 / 5s timeout 到):返回 ErrServerError 的 wrapper,客户端
	//     看到 CodeServerError → "服务器内部错误,请稍后再试",运维 / 监控通过日志计数定位。
	//   - 上下文压根没截止时间:这里不会发生(authenticateLogin 用 5s WithTimeout)。
	if err := argon2Sema.Acquire(ctx, 1); err != nil {
		return nil, fmt.Errorf("auth: argon2 capacity exhausted: %w", err)
	}
	defer argon2Sema.Release(1)

	u, err := v.store.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			runDecoyVerify(plaintext)
			return nil, ErrUnknownUser
		}
		return nil, err
	}
	if u.DisabledAt != 0 {
		runDecoyVerify(plaintext)
		return nil, ErrUserDisabled
	}
	ok, err := VerifyPSK(plaintext, u.PSKHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrBadPSK
	}
	return u, nil
}

// decoyHash 是用「不可能正确」的明文预先生成的 PHC 字符串，用于在用户不存在 / 已禁用
// 分支里跑一次完整的 argon2id 计算，让响应时延向「用户存在但密码错」对齐。
//
// 只在首次需要时按 argon2id 默认参数生成；进程生命期内复用。如果生成失败（极罕见，
// 一般是 crypto/rand 失败），decoy 路径退化为不耗时 —— 此时整个进程的 entropy 都
// 出问题了，更紧迫的事是别让 takeover secret / PSK 生成等地方继续跑（其它路径已
// 各自处理 crypto/rand 失败）。
var (
	decoyHash     string
	decoyHashOnce sync.Once
)

func runDecoyVerify(plaintext string) {
	decoyHashOnce.Do(func() {
		// 任意 32 字节随机 plaintext，不需要保密 —— 我们仅用它的 hash 形态来跑 verify。
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return
		}
		h, err := HashPSK(base64.RawStdEncoding.EncodeToString(raw[:]))
		if err != nil {
			return
		}
		decoyHash = h
	})
	if decoyHash == "" {
		return
	}
	_, _ = VerifyPSK(plaintext, decoyHash)
}
