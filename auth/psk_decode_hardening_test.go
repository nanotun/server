package auth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// DecodePSK 解析的是**来自数据库**的字符串。库里的值理论上只由 HashPSK 产出,但实际会
// 被手改、被老迁移脚本写坏、被第三方导入工具塞进来、被损坏的磁盘改掉几个字节。
// 这些拒绝分支之前一条都没被执行过 —— 已有用例走的都是合法编码或整体畸形(parts != 5),
// 恰好都在第一个检查就返回了,后面每一条都被它遮住。
//
// 逐条分开测的理由和登录报文长度闸门一样:合在一起用一个「全都坏」的串测,任何一条
// 存活都能让整体报错,十几条互相遮蔽。

// 一份合法编码,各测试按需替换其中一段。
const goodPSKEncoding = "argon2id$v=19$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestDecodePSK_RejectsMalformedHeader(t *testing.T) {
	for _, tc := range []struct {
		desc, encoded, wantSubstr string
	}{
		{
			"算法名不是 argon2id(argon2i 抗 GPU 弱得多,不能当成同一档接受)",
			"argon2i$v=19$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"unsupported algo",
		},
		{
			"版本段缺 v= 前缀",
			"argon2id$19$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"bad version field",
		},
		{
			"版本号不是数字",
			"argon2id$v=abc$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"parse version",
		},
		{
			"版本号不是当前 argon2 版本(不同版本的 KDF 输出不可互换)",
			"argon2id$v=18$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"version mismatch",
		},
		{
			"salt 段不是合法 base64",
			"argon2id$v=19$m=65536,t=2,p=4$!!!!not-base64!!!!$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"decode salt",
		},
		{
			"hash 段不是合法 base64",
			"argon2id$v=19$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$!!!!not-base64!!!!",
			"decode hash",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, _, _, _, _, err := DecodePSK(tc.encoded)
			if err == nil {
				t.Fatalf("畸形编码被接受了 —— 这条 PHC 会被拿去 verify")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("错误应点明是哪一段坏了(期望含 %q),实得:%v", tc.wantSubstr, err)
			}
			// 任何畸形都不能验成功:VerifyPSK 必须走 error 路径而不是返回 true。
			ok, verr := VerifyPSK("any-plaintext", tc.encoded)
			if ok {
				t.Error("畸形编码竟验证通过 —— verify bypass")
			}
			if verr == nil {
				t.Error("VerifyPSK 对畸形编码应返回 error")
			}
		})
	}
}

// TestDecodePSK_AcceptsTheGoodEncoding 反面锚点:上面那批的「好」版本必须能解开。
//
// 没有这条的话,一个「DecodePSK 永远报错」的实现能让上面十几条断言全绿。
func TestDecodePSK_AcceptsTheGoodEncoding(t *testing.T) {
	salt, hash, mem, tt, p, err := DecodePSK(goodPSKEncoding)
	if err != nil {
		t.Fatalf("合法编码被拒:%v", err)
	}
	if len(salt) != 16 || len(hash) != 32 {
		t.Errorf("解出的 salt/hash 长度不对:salt=%d hash=%d", len(salt), len(hash))
	}
	if mem != 65536 || tt != 2 || p != 4 {
		t.Errorf("解出的参数不对:m=%d t=%d p=%d", mem, tt, p)
	}
}

// TestParseArgonParams_RejectsMalformedAndWeakParams 参数段的每一条拒绝理由。
//
// 其中「低于下限」那条是这里唯一挡**安全降级**的:m=1024(1 MiB)是合法的 argon2 参数,
// 解得开、验得过,只是弱到可以暴力破解。能写库的攻击者把 m 改小就等于把 PSK 保护摘掉,
// 而一切照常工作 —— 没有任何报错。
func TestParseArgonParams_RejectsMalformedAndWeakParams(t *testing.T) {
	enc := func(params string) string {
		return "argon2id$v=19$" + params + "$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	for _, tc := range []struct {
		desc, params, wantSubstr string
	}{
		{"某项没有等号", "m65536,t=2,p=4", "bad param"},
		{"值不是数字", "m=abc,t=2,p=4", "bad param"},
		{"值为负数", "m=-1,t=2,p=4", "bad param"},
		{"出现不认识的键", "m=65536,t=2,p=4,x=1", "unknown param"},
		{"缺 p", "m=65536,t=2", "missing argon param"},
		{"缺 t", "m=65536,p=4", "missing argon param"},
		{"缺 m", "t=2,p=4", "missing argon param"},
		{"m 显式为 0", "m=0,t=2,p=4", "missing argon param"},
		{"m 低于下限(合法但弱到可暴破 —— 安全降级且不报错)", "m=1024,t=2,p=4", "below floor"},
		// 上限侧:每次 verify 按 m= 申请等量内存,一条 m=8GiB 的条目配合信号量容量就是 OOM。
		// 这里走 DecodePSK 而不是 VerifyPSK —— 后者会真的按这个 m 去跑 argon2。
		{"m 超上限", "m=8388608,t=2,p=4", "exceeds cap"},
		{"t 超上限", "m=65536,t=1000,p=4", "exceeds cap"},
		{"p 超上限", "m=65536,t=2,p=128", "exceeds cap"},
		// 整数回绕:这些值转成 uint32/uint8 后看着正常(m=65536、t=2、p=1),
		// 必须在 int 域就拒掉,否则事后的上限兜底看到的是回绕后的小值。
		{"m 回绕后看似正常", "m=4295032832,t=2,p=4", "exceeds cap"},
		{"t 回绕后看似正常", "m=65536,t=4294967298,p=4", "exceeds cap"},
		{"p 回绕后看似正常", "m=65536,t=2,p=257", "exceeds cap"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, _, _, _, _, err := DecodePSK(enc(tc.params))
			if err == nil {
				t.Fatal("畸形/过弱参数被接受")
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("错误应含 %q,实得:%v", tc.wantSubstr, err)
			}
		})
	}

	// 边界:恰好等于下限必须放行。只测「低于下限被拒」的话,`<` 写成 `<=` 抓不到,
	// 而那会把恰好合规的条目误判成弱参数、让对应用户彻底登不上。
	_, _, mem, _, _, err := DecodePSK(enc("m=8192,t=2,p=4"))
	if err != nil {
		t.Fatalf("m 恰好等于下限 8192 应放行,却被拒:%v", err)
	}
	if mem != 8192 {
		t.Errorf("解出的 m=%d,期望 8192", mem)
	}
}

// TestDecodePSK_RejectsOversizedHashAndSalt 超长 hash / salt 段在**解码前**就被拒。
//
// 走 DecodePSK 而不是 VerifyPSK:这条防线的意义正是「根本不解码」——base64 解码会一次性
// 分配约 3/4 输入长度的内存,几 MB 的巨串即便随后被拒,那一下分配已经发生了。
func TestDecodePSK_RejectsOversizedHashAndSalt(t *testing.T) {
	big := strings.Repeat("A", 8000) // 远超 EncodedLen(1024)=1366

	if _, _, _, _, _, err := DecodePSK("argon2id$v=19$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$" + big); err == nil {
		t.Error("超长 hash 段被接受")
	} else if !strings.Contains(err.Error(), "too long") {
		t.Errorf("超长 hash 的错误应说明过长,实得:%v", err)
	}

	if _, _, _, _, _, err := DecodePSK("argon2id$v=19$m=65536,t=2,p=4$" + big + "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Error("超长 salt 段被接受")
	} else if !strings.Contains(err.Error(), "too long") {
		t.Errorf("超长 salt 的错误应说明过长,实得:%v", err)
	}
}

// TestParseArgonParams_TimeAndThreadFloorsAreCurrentlyUnreachable 记录一处**结构性死分支**。
//
// parseArgonParams 末尾有三条下限校验(m/t/p),但 minArgonTime 与 minArgonThreads 都等于 1,
// 而在它们之前已有 `if memory == 0 || time == 0 || threads == 0` 把零值拒掉了 ——
// 「t < 1」等价于「t == 0」,永远轮不到。所以那两条现在**执行不到**,不是没测,是不可达。
//
// 不为它们伪造覆盖(做不到,除非改常量);改成在这里立一个绊线:哪天有人把下限提到 1 以上,
// 这两条就变成可达且承重的,那时必须补用例。让绊线失败,好过让两条新生效的安全校验无人验证。
func TestParseArgonParams_TimeAndThreadFloorsAreCurrentlyUnreachable(t *testing.T) {
	if minArgonTime > 1 || minArgonThreads > 1 {
		t.Fatalf("minArgonTime=%d minArgonThreads=%d 已提高到 1 以上:"+
			"这两条下限校验不再被零值检查遮蔽,已成为可达的安全校验,请补上对应用例并删掉本绊线",
			minArgonTime, minArgonThreads)
	}
}

// TestClampArgon2Capacity_HonoursFloorAndCeiling 信号量容量的上下限。
//
// 下限挡的是小机型:1 核算出 cap=2,两个并发登录就把后面的全堵在队列里,
// 表现为「登录偶发超时」而不是任何错误。上限挡的是大机型:128 核算出 256,
// 每个 slot 64 MiB,登录能吃掉 16 GiB 把数据面饿死。
func TestClampArgon2Capacity_HonoursFloorAndCeiling(t *testing.T) {
	for _, tc := range []struct{ cpus, want int }{
		{1, 8},    // 2 → 抬到下限
		{3, 8},    // 6 → 抬到下限
		{4, 8},    // 8 → 恰好等于下限
		{5, 10},   // 10 → 原样
		{32, 64},  // 64 → 恰好等于上限
		{33, 64},  // 66 → 压到上限
		{128, 64}, // 256 → 压到上限
	} {
		if got := clampArgon2Capacity(tc.cpus); got != tc.want {
			t.Errorf("%d 核应得容量 %d,实得 %d", tc.cpus, tc.want, got)
		}
	}
}

// TestNewVerifier_PanicsOnNilStore 构造期就要炸,而不是留一个用起来才 nil-deref 的对象。
func TestNewVerifier_PanicsOnNilStore(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewVerifier(nil) 没有 panic —— 会留下一个用起来才崩的 Verifier")
		}
	}()
	_ = NewVerifier(nil)
}

// TestVerifyLogin_NilReceiverOrStoreReturnsError 零值 Verifier 返回错误而不是 panic。
//
// 和上面那条不冲突:构造期拒绝是主防线,这里是「有人绕过 NewVerifier 直接造零值」时
// 的兜底 —— 登录路径上 panic 会带走整个进程。
func TestVerifyLogin_NilReceiverOrStoreReturnsError(t *testing.T) {
	var nilV *Verifier
	if _, err := nilV.VerifyLogin(context.Background(), "u", "p"); err == nil {
		t.Error("nil receiver 应返回错误")
	}
	if _, err := (&Verifier{}).VerifyLogin(context.Background(), "u", "p"); err == nil {
		t.Error("store 为 nil 的 Verifier 应返回错误")
	}
}

func newTestVerifier(t *testing.T) (*Verifier, *store.Store, context.Context) {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "psk.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return NewVerifier(st), st, ctx
}

// TestVerifyLogin_CancelledContextIsNotAFailedPassword 容量/ctx 失败必须可判定为「暂时不可用」。
//
// 这条的要害不在于返回了 error,而在于**返回的是哪个 error**:调用方按
// errors.Is(err, ErrVerifyUnavailable) 决定要不要把这次计入登录失败。判错了就是
// 「把信号量打满 → 合法用户被记失败 → 触发锁定」的放大 DoS。
func TestVerifyLogin_CancelledContextIsNotAFailedPassword(t *testing.T) {
	v, _, _ := newTestVerifier(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := v.VerifyLogin(ctx, "alice", "whatever")
	if err == nil {
		t.Fatal("ctx 已取消却仍完成了 verify")
	}
	if !errors.Is(err, ErrVerifyUnavailable) {
		t.Errorf("应是可判定的「暂时不可用」哨兵,实得 %v —— 调用方会把它当成密码错误计入锁定", err)
	}
	if errors.Is(err, ErrBadPSK) || errors.Is(err, ErrUnknownUser) {
		t.Errorf("不可归类为认证失败:%v", err)
	}
}

// TestVerifyLogin_CorruptStoredHashLooksExactlyLikeAWrongPassword 库里的 hash 坏了要装作密码错。
//
// 两件事必须同时成立:
//   - 返回 ErrBadPSK,而不是把「这个账号的 hash 异常」透给客户端(原先走 500);
//   - 仍然跑一次 decoy argon2,否则响应明显快于正常的「密码错」—— DecodePSK 阶段就返回了,
//     根本没碰 argon2。时序上的这个洞足以枚举出哪些账号的 hash 是坏的。
func TestVerifyLogin_CorruptStoredHashLooksExactlyLikeAWrongPassword(t *testing.T) {
	v, st, ctx := newTestVerifier(t)

	good, err := HashPSK("correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "healthy", PSKHash: good}); err != nil {
		t.Fatal(err)
	}
	// 手改 / 老迁移 / DB 损坏的样子:结构还在,hash 段不是合法 base64。
	if _, err := st.CreateUser(ctx, store.NewUser{
		Username: "corrupt",
		PSKHash:  "argon2id$v=19$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$!!!!corrupted!!!!",
	}); err != nil {
		t.Fatal(err)
	}

	_, err = v.VerifyLogin(ctx, "corrupt", "any-password")
	if !errors.Is(err, ErrBadPSK) {
		t.Fatalf("坏 hash 应与密码错误不可区分(ErrBadPSK),实得 %v", err)
	}

	// 时序对齐:坏 hash 这条路径必须真的烧掉一次 argon2。拿「密码错」那条当基准,
	// 不卡绝对阈值(CI 抖动大),只要求同一数量级 —— 不跑 decoy 的话这里会快上百倍。
	base := timeVerifyLogin(t, v, ctx, "healthy", "wrong-password")
	corrupt := timeVerifyLogin(t, v, ctx, "corrupt", "any-password")
	if corrupt*3 < base {
		t.Errorf("坏 hash 路径耗时 %v,远快于密码错的 %v —— decoy 没跑,可据此枚举 hash 异常的账号",
			corrupt, base)
	}
}

// TestVerifyLogin_DatabaseFailureIsNotAnUnknownUser 库挂了要如实上报,不能伪装成「用户不存在」。
//
// GetUserByUsername 只有 ErrNotFound 才走 ErrUnknownUser 分支,其余错误原样返回。
// 混为一谈有两个后果:运维在日志里看到的是一片「未知用户」而不是数据库故障,查错方向全歪;
// 用户被告知账号不存在,而账号其实好好的。
func TestVerifyLogin_DatabaseFailureIsNotAnUnknownUser(t *testing.T) {
	v, st, ctx := newTestVerifier(t)
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: goodPSKEncoding}); err != nil {
		t.Fatal(err)
	}
	// 关掉库来制造一个非 ErrNotFound 的故障。
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := v.VerifyLogin(ctx, "alice", "whatever")
	if err == nil {
		t.Fatal("库已关闭却登录成功")
	}
	if errors.Is(err, ErrUnknownUser) {
		t.Errorf("数据库故障被伪装成「用户不存在」:%v", err)
	}
	if errors.Is(err, ErrBadPSK) {
		t.Errorf("数据库故障被伪装成「密码错误」:%v", err)
	}
}

func timeVerifyLogin(t *testing.T, v *Verifier, ctx context.Context, user, pass string) time.Duration {
	t.Helper()
	start := time.Now()
	_, _ = v.VerifyLogin(ctx, user, pass)
	return time.Since(start)
}
