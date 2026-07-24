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

	// 上限(防 DoS):VerifyPSK 用 argon2.IDKey(..., keyLen=uint32(len(hash))) 申请**等于 hash 长度**的输出
	// 缓冲。若某条 PHC 的 base64 hash 段是几 MB 的巨串(管理员手抖 / 老迁移脚本 / 恶意导入 / DB 被写坏),
	// keyLen 就变成几 MB,单次 verify 即分配巨额内存 → OOM / 放大攻击。真实 argon2 hash 是 16~64B、salt 16B,
	// 给到 1KiB 已远超任何合法值;超长即判畸形,DecodePSK 直接拒掉,verify 走 error 路径(上层映射 ErrBadPSK)。
	maxHashBytes = 1024
	maxSaltBytes = 1024

	// DecodePSK 接受 argon2id 参数的上限：防止管理员 / 迁移脚本写入超大 m= 让验证路径 OOM。
	//
	// 第十六轮深扫 MED:上限从 1 GiB 收到 256 MiB。nanotun **唯一**的哈希产出方是 HashPSK,恒用 argonMemory=64 MiB
	// (见常量),线上任何合法条目都是 64 MiB,不会触及此上限;而 verify 路径每次按 m= 申请等量内存,1 GiB 的上限
	// 意味着一条手改 / 恶意导入 / DB 损坏的 m=1048576 PHC 会让**每次**登录尝试吃 ~1 GiB,配合 argon2Sema 容量
	// (最多 64)即 64 GiB → OOM(与超长 hash 同类放大 DoS)。256 MiB = 标准档 4×,给「未来调强 argonMemory」留足
	// 余量,又把单次 verify 的内存钉在远低于 OOM 的水位。收紧只会拒掉「显然异常」的条目,不影响任何 nanotun 自产哈希。
	maxArgonMemoryKiB uint32 = 256 * 1024 // 256 MiB in KiB
	maxArgonTime      uint32 = 100
	maxArgonThreads   uint8  = 64

	// argon2id 参数**下限**(第四轮深扫 MED):此前只兜上限 + 非零,一条 m=8,t=1,p=1 的 PHC 能通过校验并被
	// verify —— 这种「合法但极弱」的哈希几乎瞬间可暴力破解,等于把 PSK 保护降级。设下限拒掉明显偏弱的参数。
	// 取值刻意保守:nanotun 自产哈希恒为 m=65536(64 MiB)/t=2/p=4,远高于这些下限,不会误伤任何合法条目;
	// 只挡「手改 / 恶意导入 / 老工具」写进来的弱参数。
	minArgonMemoryKiB uint32 = 8 * 1024 // 8 MiB;低于此视为不安全的弱 argon2
	minArgonTime      uint32 = 1
	minArgonThreads   uint8  = 1

	// maxPSKPlaintextBytes 第十六轮深扫 LOW:HashPSK 接受的明文上限(见 HashPSK 注释)。合法 PSK 至多几十字符,
	// 1024 字节是「显然异常」的兜底,拒掉误传整文件 / 恶意超长 --psk。
	maxPSKPlaintextBytes = 1024
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
	// 第十六轮深扫 LOW:PSK 明文长度上限。argon2.IDKey 的耗时与内存由 m/t/p 决定、与明文长度无关,但巨型明文
	// (管理员脚本误传整文件 / 恶意 --psk)仍会在进入 argon2 前吃内存并放大每次 verify 的拷贝。合法 PSK 至多几十
	// 字符,给到 1024 字节已远超任何真实用法;超长直接拒。VerifyPSK 侧不设明文上限(登录明文由协议层帧长约束,
	// 且拒绝会变成对错误密码的可探测差异),只在**产生**哈希这一侧收口。
	if len(plaintext) > maxPSKPlaintextBytes {
		return "", fmt.Errorf("auth: psk too long: %d bytes (max %d)", len(plaintext), maxPSKPlaintextBytes)
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
	// 冗余上限防御(DecodePSK 已拒;此处再兜一次防未来重构绕过 DecodePSK 直接调 VerifyPSK):超长 hash 会让
	// 下面 argon2.IDKey 的 keyLen 变巨大 → OOM。
	if len(hash) > maxHashBytes || len(salt) > maxSaltBytes {
		return false, fmt.Errorf("auth: psk encoding too long (hash=%d salt=%d)", len(hash), len(salt))
	}
	cand := argon2.IDKey([]byte(plaintext), salt, t, mem, p, uint32(len(hash)))
	return subtle.ConstantTimeCompare(cand, hash) == 1, nil
}

// VerifyPSKLimited 是 VerifyPSK 的**并发受限**版本:先取全局 argon2 semaphore(与 Verifier.VerifyLogin 同一把,
// 见 argon2Sema)再跑 argon2id,把整个进程「同时进行中的 argon2 verify」数封顶。
//
// 第四轮深扫 HIGH:nanotun-web 后台登录 / decoy / TOTP 恢复码校验此前直接调 VerifyPSK,**绕过**了信号量,
// 每次 argon2 申请 ~64MB;并发 web 登录(尤其恢复码路径单次最多 10 次 verify)可把宿主 RAM 打爆。让 web
// 侧改走本函数即与 VPN 登录共用同一 DoS 天花板。
//
// ctx 取消 / 无 deadline 导致 Acquire 失败时返回 (false, 非 nil err) —— 调用方应视为「暂时不可用」而非「密码错误」。
func VerifyPSKLimited(ctx context.Context, plaintext, encoded string) (bool, error) {
	if err := argon2Sema.Acquire(ctx, 1); err != nil {
		return false, fmt.Errorf("%w: argon2 capacity/ctx: %v", ErrVerifyUnavailable, err)
	}
	defer argon2Sema.Release(1)
	return VerifyPSK(plaintext, encoded)
}

// ErrVerifyUnavailable 表示 argon2 verify 因**容量耗尽 / ctx 取消**(排队超时、连接断开)而**未能执行**,
// 语义是「暂时不可用」而非「密码错误」。第十二轮深扫 MED:调用方应据此**避免**把它计入登录失败 / 账号锁定,
// 否则并发把 argon2Sema 打满即可让合法管理员被「超时=失败」放大成锁定 DoS。
var ErrVerifyUnavailable = errors.New("auth: psk verify temporarily unavailable")

// VerifyPSKLimitedOrDecoy 在**同一次** semaphore 持有内完成「真实 verify +(必要时)decoy」:
// 若 encoded 畸形(DecodePSK 在跑 argon2 **之前**就返回错误,响应明显偏快),就地对 decoyEncoded 跑一次
// 等价 argon2 烧掉耗时,使「存储 hash 损坏」无法凭响应时延与「密码错误」区分。返回真实 verify 的 (ok, err)。
//
// 第十二轮深扫 MED:此前 web 侧畸形 hash 的 decoy 是**另起**一次 VerifyPSKLimited(第二次 Acquire),高并发下
// 第二次 Acquire 可能超时被跳过 → decoy 不跑 → 时序泄漏「此账号 hash 异常」。合并到单次 Acquire 内即无此窗口。
// Acquire 失败(容量/ctx)→ 返回 (false, ErrVerifyUnavailable wrapper),不跑 decoy(整体已超时,时序无意义)。
func VerifyPSKLimitedOrDecoy(ctx context.Context, plaintext, encoded, decoyEncoded string) (bool, error) {
	if err := argon2Sema.Acquire(ctx, 1); err != nil {
		return false, fmt.Errorf("%w: argon2 capacity/ctx: %v", ErrVerifyUnavailable, err)
	}
	defer argon2Sema.Release(1)
	ok, err := VerifyPSK(plaintext, encoded)
	if err != nil {
		// 存储 hash 畸形:上面在 DecodePSK 阶段就返回、没跑 argon2。就地在同一 slot 内烧一次等价 argon2。
		_, _ = VerifyPSK(plaintext, decoyEncoded)
	}
	return ok, err
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

	// 第四轮深扫 HIGH:在**解码前**先按编码后长度封顶。base64 解码会一次性分配 ~3/4·len(输入) 的字节,
	// 若 parts[3]/parts[4] 是几 MB 的巨串(手改 / 恶意导入 / DB 写坏),即便随后被 max*Bytes 拒掉,解码那一下
	// 已经把大内存 alloc 出来了(放大攻击 / GC 压力)。EncodedLen(maxXxxBytes) 是合法值对应的最大编码长度,
	// 超过它直接判畸形、根本不解码,把分配钉在上限内。
	if len(parts[3]) > base64.RawStdEncoding.EncodedLen(maxSaltBytes) {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: salt b64 too long: %d chars", len(parts[3]))
	}
	if len(parts[4]) > base64.RawStdEncoding.EncodedLen(maxHashBytes) {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: hash b64 too long: %d chars", len(parts[4]))
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
	if len(hash) > maxHashBytes {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: hash too long: %d (max %d)", len(hash), maxHashBytes)
	}
	if len(salt) < minSaltBytes {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: salt too short: %d (min %d)", len(salt), minSaltBytes)
	}
	if len(salt) > maxSaltBytes {
		return nil, nil, 0, 0, 0, fmt.Errorf("auth: salt too long: %d (max %d)", len(salt), maxSaltBytes)
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
	// 第十六轮深扫 LOW:拒绝重复键(如 "m=65536,m=8")。此前重复键静默后者覆盖前者 —— 一条 PHC 可写
	// "m=<强>,m=<弱>" 让人肉/日志审计以为强档,实际按弱档 verify(把强参数「藏」在被覆盖的前一项里)。
	// 三个键各只允许出现一次。
	var seenM, seenT, seenP bool
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return 0, 0, 0, fmt.Errorf("auth: bad param %q", kv)
		}
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 0 {
			return 0, 0, 0, fmt.Errorf("auth: bad param %s: %w", kv, perr)
		}
		// 关键:**在**转成 uint32/uint8 **之前**按上限校验。否则大整数(如 m=2^32+65536)在
		// uint32(n)/uint8(n) 处**回绕**成一个看似正常的小值,绕过 DecodePSK 里事后的 maxArgon* 上限
		// 兜底(如回绕到 m=65536),让畸形条目照跑 verify。以 int 域比较,不受回绕影响。
		switch k {
		case "m":
			if seenM {
				return 0, 0, 0, errors.New("auth: duplicate argon param m")
			}
			seenM = true
			if n > int(maxArgonMemoryKiB) {
				return 0, 0, 0, fmt.Errorf("auth: argon m=%d exceeds cap %d", n, maxArgonMemoryKiB)
			}
			memory = uint32(n)
		case "t":
			if seenT {
				return 0, 0, 0, errors.New("auth: duplicate argon param t")
			}
			seenT = true
			if n > int(maxArgonTime) {
				return 0, 0, 0, fmt.Errorf("auth: argon t=%d exceeds cap %d", n, maxArgonTime)
			}
			time = uint32(n)
		case "p":
			if seenP {
				return 0, 0, 0, errors.New("auth: duplicate argon param p")
			}
			seenP = true
			if n > int(maxArgonThreads) {
				return 0, 0, 0, fmt.Errorf("auth: argon p=%d exceeds cap %d", n, maxArgonThreads)
			}
			threads = uint8(n)
		default:
			return 0, 0, 0, fmt.Errorf("auth: unknown param %s", k)
		}
	}
	if memory == 0 || time == 0 || threads == 0 {
		return 0, 0, 0, errors.New("auth: missing argon param")
	}
	// 参数**下限**(第四轮深扫 MED):拒掉「合法但极弱」的 argon 参数(见 minArgon* 说明)。放在 max 校验之后、
	// 返回之前统一判定。nanotun 自产哈希恒高于这些下限,不会误伤。
	if memory < minArgonMemoryKiB {
		return 0, 0, 0, fmt.Errorf("auth: argon m=%d below floor %d KiB", memory, minArgonMemoryKiB)
	}
	if time < minArgonTime {
		return 0, 0, 0, fmt.Errorf("auth: argon t=%d below floor %d", time, minArgonTime)
	}
	if threads < minArgonThreads {
		return 0, 0, 0, fmt.Errorf("auth: argon p=%d below floor %d", threads, minArgonThreads)
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
		// 第十四轮深扫 LOW(API 一致性):与 VerifyPSKLimited/OrDecoy 一样用 ErrVerifyUnavailable 包裹容量/ctx
		// 超时,让调用方可 errors.Is 统一识别「暂时不可用」而非当作认证失败。VPN 侧 authenticateLogin 目前把
		// 非哨兵错归到 CodeServerError(不计失败),语义已一致;此处补上可判定的哨兵不改变现有映射。
		return nil, fmt.Errorf("%w: argon2 capacity/ctx: %v", ErrVerifyUnavailable, err)
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
	// **先验 PSK,再判 disabled**(反枚举):此前 disabled 在 PSK 之前短路返回 ErrUserDisabled,于是不知道 PSK 的
	// 攻击者只要用户名对上就能得知「该账号存在且被禁用」。改成:只有**证明了知道 PSK** 的调用方才可能收到
	// ErrUserDisabled;错 PSK / 禁用+错 PSK / 不存在 一律 ErrBadPSK / ErrUnknownUser,无法据此区分账号是否存在/禁用。
	ok, verr := VerifyPSK(plaintext, u.PSKHash)
	if verr != nil {
		// 存储 PSKHash 畸形(手改 / 老迁移 / DB 损坏):VerifyPSK 在 DecodePSK 阶段**不跑 argon2** 立即返错,
		// 时序快于正常「密码错」路径,且原先经上层 default 分支回 CodeServerError(500),等于泄漏「此账号 hash 异常」。
		// 补跑一次 decoy 对齐耗时,并统一按 ErrBadPSK 处理 —— 对客户端与「密码错」完全不可区分。
		runDecoyVerify(plaintext)
		return nil, ErrBadPSK
	}
	if !ok {
		return nil, ErrBadPSK
	}
	if u.DisabledAt != 0 {
		return nil, ErrUserDisabled
	}
	return u, nil
}

// decoyHash 是一段**固定**的合法 PHC 字符串，用于在用户不存在 / 已禁用分支里跑一次完整的 argon2id
// 计算，让响应时延向「用户存在但密码错」的路径对齐（时序防护）。
//
// 为什么用固定值而非运行时随机生成：decoy 不保护任何真实秘密——它只需触发一次等价耗时的 argon2id.IDKey。
// 固定构造不依赖 crypto/rand，进程内**恒可用**。这修复了此前「用 sync.Once 惰性生成，一旦首次因 entropy
// 故障失败，decoy 便**永久**退化为即时返回、时序防护对整个进程生命期彻底失效」的问题（sync.Once 不会重试）。
// argon2id 的耗时与盐 / 明文内容无关（内存/迭代量由 m,t,p 决定），故固定盐不影响时延对齐；salt≥minSaltBytes、
// hash=32B≥minHashBytes、参数在 maxArgon* 上限内，均满足 VerifyPSK/DecodePSK 的不变量。全零 hash 与真实
// argon2 输出几乎必然不等，比较结果恒为「不匹配」，符合 decoy 语义。
var decoyHash = EncodePSK(
	[]byte("nanotun/decoy-salt-v1!!"), // 23B，> minSaltBytes(8)；内容任意、无需保密
	make([]byte, argonKeyLen),         // 32B「哈希」占位，仅供 ConstantTimeCompare
	argonMemory, argonTime, argonThreads,
)

func runDecoyVerify(plaintext string) {
	_, _ = VerifyPSK(plaintext, decoyHash)
}
