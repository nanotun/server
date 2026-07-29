package main

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// PoW 是登录之前唯一的抗滥用闸门:没有它,爆破 PSK 的成本就只是网络往返。
//
// 这个文件盯两件事:
//
//   - **七道拒绝理由各自的边界。** 少一道就是闸门被绕开,而且悄无声息:不查过期 → 一道题永久有效;
//     不查重放 → 一道题算一次能用无限次,PoW 形同虚设;签名不查 → 客户端自己给自己出 4-bit 的题。
//   - **顺序,以及「算错 nonce 不许烧掉题目」。** 顺序错了,attacker 能用「服务端报的是哪个错」
//     反推出题目元数据的有效性;而如果错 nonce 会消耗 challenge,那么拿到别人 cid 的人可以反复
//     提交垃圾把对方的题烧光 —— 闸门本身成了拒绝服务的工具。
//
// 既有 pow 用例走的是完整链路(pow_e2e_test.go)与配置校验,单元级的拒绝矩阵此前没有。

func newPoWTestService(t *testing.T) *PoWService {
	t.Helper()
	svc, err := NewPoWService([]byte("pow-test-hmac-key-0123456789abcd"), nil, 3, 8, 14, 2, 22, 300)
	if err != nil {
		t.Fatalf("NewPoWService: %v", err)
	}
	return svc
}

// minePoW 老实算一个满足难度的 nonce。默认难度 8 位大约几百次哈希,可忽略。
func minePoW(t *testing.T, cid string, salt []byte, difficulty int) uint64 {
	t.Helper()
	for n := uint64(0); n < 1<<26; n++ {
		if powLeadingZeroBits(powHash(cid, salt, n)) >= difficulty {
			return n
		}
	}
	t.Fatalf("难度 %d 没算出 nonce", difficulty)
	return 0
}

// solve 把一道题解成一份合法 proof。
func solve(t *testing.T, svc *PoWService, ch PoWChallenge) PoWProof {
	t.Helper()
	salt, err := base64.StdEncoding.DecodeString(ch.Salt)
	if err != nil {
		t.Fatalf("题目里的 salt 不是合法 base64: %v", err)
	}
	return PoWProof{
		ChallengeID: ch.ChallengeID,
		Salt:        ch.Salt,
		Difficulty:  ch.Difficulty,
		ExpiresAt:   ch.ExpiresAt,
		Signature:   ch.Signature,
		Nonce:       minePoW(t, ch.ChallengeID, salt, ch.Difficulty),
	}
}

func issueAndSolve(t *testing.T, svc *PoWService, d int) PoWProof {
	t.Helper()
	ch, err := svc.IssueChallenge(d)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	return solve(t, svc, ch)
}

func TestVerifyPoWProof_AcceptsARealProofExactlyOnce(t *testing.T) {
	svc := newPoWTestService(t)
	p := issueAndSolve(t, svc, 8)

	if err := svc.VerifyPoWProof(p, 8); err != nil {
		t.Fatalf("老实算出来的 proof 被拒了: %v —— 合法客户端会登不进来", err)
	}
	if snap := svc.MetricsSnapshot(); snap.VerifySuccess != 1 {
		t.Fatalf("成功计数应为 1,实际 %d", snap.VerifySuccess)
	}

	// 同一份 proof 再交一次:必须按重放拒掉。不拒就等于「算一次能用无限次」。
	if err := svc.VerifyPoWProof(p, 8); !errors.Is(err, ErrPoWReplay) {
		t.Fatalf("同一道题被消费两次,want ErrPoWReplay, got %v", err)
	}
	if snap := svc.MetricsSnapshot(); snap.FailReplay != 1 || snap.VerifySuccess != 1 {
		t.Fatalf("重放应只加 FailReplay: %+v", snap)
	}
}

// 每种拒绝都要落到**自己**那个哨兵错误和**自己**那个计数器上。
//
// 计数器串了不影响放行判断,但运维在 metrics 上看到的攻击特征就是错的 —— 一片 bad_signature
// 里混着实际是 expired 的请求,排障方向从一开始就偏了。
func TestVerifyPoWProof_EveryRejectionHasItsOwnReasonAndCounter(t *testing.T) {
	type counterOf func(PoWMetricsSnapshot) uint64
	badCID := func(s PoWMetricsSnapshot) uint64 { return s.FailBadCID }
	badSig := func(s PoWMetricsSnapshot) uint64 { return s.FailBadSig }
	badSalt := func(s PoWMetricsSnapshot) uint64 { return s.FailBadSalt }
	expired := func(s PoWMetricsSnapshot) uint64 { return s.FailExpired }
	diffLow := func(s PoWMetricsSnapshot) uint64 { return s.FailDiffLow }
	invalid := func(s PoWMetricsSnapshot) uint64 { return s.FailInvalid }

	cases := []struct {
		name    string
		tweak   func(t *testing.T, svc *PoWService, p *PoWProof)
		wants   int
		wantErr error
		counter counterOf
	}{
		{
			name:    "没有 challenge_id",
			tweak:   func(_ *testing.T, _ *PoWService, p *PoWProof) { p.ChallengeID = "" },
			wantErr: ErrPoWBadCID, counter: badCID,
		},
		{
			name:    "没有签名",
			tweak:   func(_ *testing.T, _ *PoWService, p *PoWProof) { p.Signature = "" },
			wantErr: ErrPoWBadSignature, counter: badSig,
		},
		{
			name:    "难度声明为 0",
			tweak:   func(_ *testing.T, _ *PoWService, p *PoWProof) { p.Difficulty = 0 },
			wantErr: ErrPoWBadSignature, counter: badSig,
		},
		{
			name:    "过期时间为 0",
			tweak:   func(_ *testing.T, _ *PoWService, p *PoWProof) { p.ExpiresAt = 0 },
			wantErr: ErrPoWBadSignature, counter: badSig,
		},
		{
			name:    "salt 不是合法 base64",
			tweak:   func(_ *testing.T, _ *PoWService, p *PoWProof) { p.Salt = "不是-base64!!" },
			wantErr: ErrPoWBadSalt, counter: badSalt,
		},
		{
			// 缺字段与 salt 同时不合法。入口那道「签名/难度/过期时间为空」的闸门单看结果是冗余的
			// (伪造者过不了后面的 HMAC,同样得 ErrPoWBadSignature、同样记 FailBadSig);它唯一不
			// 冗余的地方是**顺序** —— 缺字段要在解 salt 之前就被拦下。这条钉住那个顺序,否则拆掉
			// 入口闸门看不出任何差别。
			name: "字段缺失优先于 salt 解析被拦下",
			tweak: func(_ *testing.T, _ *PoWService, p *PoWProof) {
				p.Signature = ""
				p.Salt = "不是-base64!!"
			},
			wantErr: ErrPoWBadSignature, counter: badSig,
		},
		{
			name: "salt 长度不对",
			tweak: func(_ *testing.T, _ *PoWService, p *PoWProof) {
				p.Salt = base64.StdEncoding.EncodeToString([]byte("short"))
			},
			wantErr: ErrPoWBadSalt, counter: badSalt,
		},
		{
			name:    "签名被改过",
			tweak:   func(_ *testing.T, _ *PoWService, p *PoWProof) { p.Signature = flipLastB64Byte(p.Signature) },
			wantErr: ErrPoWBadSignature, counter: badSig,
		},
		{
			name: "自己把难度改低(签名不再对得上)",
			tweak: func(_ *testing.T, _ *PoWService, p *PoWProof) {
				p.Difficulty = powMinDifficulty // 想少算几轮
			},
			wantErr: ErrPoWBadSignature, counter: badSig,
		},
		{
			name: "题目已过期(签名是真的)",
			tweak: func(t *testing.T, svc *PoWService, p *PoWProof) {
				p.ExpiresAt = time.Now().Unix() - 1
				p.Signature = powChallengeHMAC(svc.hmacKey, p.ChallengeID, p.Salt, p.Difficulty, p.ExpiresAt)
			},
			wantErr: ErrPoWExpired, counter: expired,
		},
		{
			name:    "难度低于本 IP 当前要求(跨 IP 借低难度的题)",
			tweak:   func(_ *testing.T, _ *PoWService, _ *PoWProof) {},
			wants:   14,
			wantErr: ErrPoWDifficultyLow, counter: diffLow,
		},
		{
			name:    "nonce 不满足难度",
			tweak:   func(_ *testing.T, _ *PoWService, p *PoWProof) { p.Nonce++ },
			wantErr: ErrPoWInvalid, counter: invalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newPoWTestService(t)
			p := issueAndSolve(t, svc, 8)
			tc.tweak(t, svc, &p)

			wants := tc.wants
			if wants == 0 {
				wants = 8
			}
			err := svc.VerifyPoWProof(p, wants)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
			snap := svc.MetricsSnapshot()
			if got := tc.counter(snap); got != 1 {
				t.Fatalf("对应的失败计数应为 1,实际 %d(整份快照 %+v)", got, snap)
			}
			// 其它原因的计数一个都不许动,否则 metrics 上的攻击特征就是错的。
			total := snap.FailBadCID + snap.FailBadSig + snap.FailBadSalt +
				snap.FailExpired + snap.FailDiffLow + snap.FailInvalid + snap.FailReplay
			if total != 1 {
				t.Fatalf("只该有一个失败计数 +1,实际总和 %d: %+v", total, snap)
			}
			if snap.VerifySuccess != 0 {
				t.Fatal("被拒的 proof 不该计入成功")
			}
		})
	}
}

// 校验顺序不是实现细节:它决定了服务端的错误码能泄漏多少题目元数据。
func TestVerifyPoWProof_ChecksSignatureBeforeAnythingItCouldLeak(t *testing.T) {
	svc := newPoWTestService(t)

	t.Run("签名假 + 已过期 → 必须先报签名", func(t *testing.T) {
		p := issueAndSolve(t, svc, 8)
		p.ExpiresAt = time.Now().Unix() - 1
		p.Signature = flipLastB64Byte(p.Signature)
		if err := svc.VerifyPoWProof(p, 8); !errors.Is(err, ErrPoWBadSignature) {
			t.Fatalf("want ErrPoWBadSignature, got %v —— 先报过期就等于告诉对方「这个签名是真的」", err)
		}
	})

	t.Run("签名真但已过期 + 难度不够 → 必须先报过期", func(t *testing.T) {
		p := issueAndSolve(t, svc, 8)
		p.ExpiresAt = time.Now().Unix() - 1
		p.Signature = powChallengeHMAC(svc.hmacKey, p.ChallengeID, p.Salt, p.Difficulty, p.ExpiresAt)
		if err := svc.VerifyPoWProof(p, 22); !errors.Is(err, ErrPoWExpired) {
			t.Fatalf("want ErrPoWExpired, got %v", err)
		}
	})
}

// 算错 nonce 不许消耗掉这道题。
//
// 防重放表是在**数学校验通过之后**才写的。反过来的话,拿到别人 challenge_id 的人只要反复提交
// 垃圾 nonce 就能把对方的题一道道烧掉 —— 抗滥用的闸门自己变成了拒绝服务的入口。
func TestVerifyPoWProof_AWrongNonceDoesNotBurnTheChallenge(t *testing.T) {
	svc := newPoWTestService(t)
	good := issueAndSolve(t, svc, 8)

	bad := good
	bad.Nonce = good.Nonce + 1
	if err := svc.VerifyPoWProof(bad, 8); !errors.Is(err, ErrPoWInvalid) {
		t.Fatalf("want ErrPoWInvalid, got %v", err)
	}
	if n := svc.MetricsSnapshot().UsedTableSize; n != 0 {
		t.Fatalf("算错的提交不该占用防重放表,实际有 %d 条 —— 别人能靠垃圾提交烧掉这道题", n)
	}
	if err := svc.VerifyPoWProof(good, 8); err != nil {
		t.Fatalf("同一道题的正确答案应当仍被接受: %v", err)
	}
}

func TestComputeDifficulty_RampsWithFailuresAndStopsAtTheCeiling(t *testing.T) {
	svc := newPoWTestService(t) // enable=3 base=8 ramp=14 step=2 ceil=22
	cases := map[int]int{
		-5: 8,  // 负数当 0
		0:  8,  // 平时
		2:  8,  // 还没到阈值
		3:  14, // 到阈值,跳到 ramp
		4:  16,
		5:  18,
		6:  20,
		7:  22, // 封顶
		99: 22, // 再多也不超过 ceiling
	}
	for failures, want := range cases {
		if got := svc.ComputeDifficulty(failures); got != want {
			t.Errorf("failures=%d: want %d, got %d", failures, want, got)
		}
	}
}

func TestIssueChallenge_ClampsTheDifficultyAndNeverRepeatsItself(t *testing.T) {
	svc := newPoWTestService(t)

	for _, tc := range []struct{ ask, want int }{
		{0, powMinDifficulty},
		{-3, powMinDifficulty},
		{powMinDifficulty - 1, powMinDifficulty},
		{powMaxDifficulty + 10, powMaxDifficulty},
		{10, 10},
	} {
		ch, err := svc.IssueChallenge(tc.ask)
		if err != nil {
			t.Fatalf("IssueChallenge(%d): %v", tc.ask, err)
		}
		if ch.Difficulty != tc.want {
			t.Errorf("要 %d 应夹到 %d,实际 %d", tc.ask, tc.want, ch.Difficulty)
		}
		// 自己签的题自己必须认,否则客户端算完了也交不上来。
		if !powChallengeHMACEqual(svc.hmacKey, ch.ChallengeID, ch.Salt, ch.Difficulty, ch.ExpiresAt, ch.Signature) {
			t.Error("签发的题目自己验不过")
		}
	}

	a, _ := svc.IssueChallenge(8)
	b, _ := svc.IssueChallenge(8)
	if a.ChallengeID == b.ChallengeID {
		t.Fatal("两道题的 challenge_id 相同 —— 防重放表会把第二个客户端误判成重放")
	}
	if a.Salt == b.Salt {
		t.Fatal("两道题的 salt 相同 —— 算过一次的结果可以直接复用到下一道题")
	}
	if a.ExpiresAt <= time.Now().Unix() {
		t.Fatal("签发即过期")
	}
}

func TestPoWVerify_RejectsOutOfRangeDifficultyAndWrongSaltLength(t *testing.T) {
	salt := make([]byte, powSaltBytes)
	cid := "cid-boundary"
	nonce := minePoW(t, cid, salt, powMinDifficulty)

	if !powVerify(cid, salt, powMinDifficulty, nonce) {
		t.Fatal("最低难度的合法解应当通过")
	}
	if powVerify(cid, salt, powMinDifficulty-1, nonce) {
		t.Fatal("难度低于下限时必须拒绝 —— 否则客户端可以自称 0 难度白嫖")
	}
	if powVerify(cid, salt, powMaxDifficulty+1, nonce) {
		t.Fatal("难度高于上限时必须拒绝")
	}
	if powVerify(cid, make([]byte, powSaltBytes-1), powMinDifficulty, nonce) {
		t.Fatal("salt 长度不对时必须拒绝")
	}
}

// 空 HMAC key 时签名比较必须为 false。
//
// powChallengeHMAC 在 key 为空时返回空串,如果 Equal 不单独挡住这种情况,「两个空串相等」
// 就会让任何伪造签名通过 —— 一个没配好 key 的实例等于完全没有 PoW。
func TestPoWChallengeHMACEqual_TreatsAMissingKeyAsFailure(t *testing.T) {
	if powChallengeHMACEqual(nil, "cid", "c2FsdA==", 8, 1<<40, "") {
		t.Fatal("key 为空时不许通过 —— 那等于任何人都能自己出题")
	}
	if powChallengeHMACEqual([]byte{}, "cid", "c2FsdA==", 8, 1<<40, "AAAA") {
		t.Fatal("key 为空时不许通过")
	}

	key := []byte("k")
	sig := powChallengeHMAC(key, "cid", "c2FsdA==", 8, 1<<40)
	if !powChallengeHMACEqual(key, "cid", "c2FsdA==", 8, 1<<40, sig) {
		t.Fatal("自签自验应当通过")
	}
	if powChallengeHMACEqual(key, "cid", "c2FsdA==", 8, 1<<40, "!!! 不是 base64") {
		t.Fatal("签名不是合法 base64 时应当拒绝")
	}
	if powChallengeHMACEqual(key, "cid", "c2FsdA==", 8, 1<<40, base64.StdEncoding.EncodeToString([]byte("短"))) {
		t.Fatal("长度不等的签名应当拒绝")
	}
	// 元数据任一位变了签名就不该成立(这是「客户端自己改难度」的唯一防线)。
	if powChallengeHMACEqual(key, "cid", "c2FsdA==", 9, 1<<40, sig) {
		t.Fatal("难度变了签名却仍成立")
	}
	if powChallengeHMACEqual(key, "cid2", "c2FsdA==", 8, 1<<40, sig) {
		t.Fatal("challenge_id 变了签名却仍成立")
	}
}

func TestPoWLeadingZeroBits_CountsAcrossByteBoundaries(t *testing.T) {
	var d [32]byte
	if got := powLeadingZeroBits(d); got != 256 {
		t.Fatalf("全零应是 256 位,实际 %d", got)
	}
	d[0] = 0x80
	if got := powLeadingZeroBits(d); got != 0 {
		t.Fatalf("最高位为 1 应是 0,实际 %d", got)
	}
	d[0] = 0x01
	if got := powLeadingZeroBits(d); got != 7 {
		t.Fatalf("0x01 应是 7,实际 %d", got)
	}
	d[0], d[1] = 0x00, 0x0f
	if got := powLeadingZeroBits(d); got != 12 {
		t.Fatalf("0x00 0x0f 应是 12(跨字节),实际 %d", got)
	}
}

// 过期的防重放条目要被清掉(否则表只增不减,长跑就是内存泄漏);没过期的一条都不许丢
// (丢了就等于把用过的题重新放开)。
func TestPruneExpired_DropsTheExpiredAndKeepsTheRest(t *testing.T) {
	svc := newPoWTestService(t)
	now := time.Now().Unix()
	svc.powUsed.Store("已过期", now-1)
	svc.powUsed.Store("正好到点", now)
	svc.powUsed.Store("还有效", now+3600)
	svc.powUsed.Store("类型不对", "这不是 int64")

	svc.pruneExpired()

	if _, ok := svc.powUsed.Load("还有效"); !ok {
		t.Fatal("未过期的条目被清掉了 —— 用过的题会被重新放开")
	}
	for _, k := range []string{"已过期", "正好到点", "类型不对"} {
		if _, ok := svc.powUsed.Load(k); ok {
			t.Fatalf("%q 应当被清掉", k)
		}
	}
	if n := svc.MetricsSnapshot().UsedTableSize; n != 1 {
		t.Fatalf("清理后应只剩 1 条,实际 %d", n)
	}
}

func TestRunGC_StopsWhenTold(t *testing.T) {
	svc := newPoWTestService(t)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { svc.RunGC(stop); close(done) }()
	close(stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("关掉 stop 之后 GC goroutine 没退出")
	}
}

func TestMetricsSnapshot_NilServiceIsZeroNotAPanic(t *testing.T) {
	var svc *PoWService
	if snap := svc.MetricsSnapshot(); snap != (PoWMetricsSnapshot{}) {
		t.Fatalf("nil service 应返回零值快照,实际 %+v", snap)
	}
}

// flipLastB64Byte 把一段 base64 的最后一个字节改掉,得到「长度一样但内容不同」的签名 ——
// 长度不同会先被长度检查挡掉,测不到真正的比较逻辑。
func flipLastB64Byte(sig string) string {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(raw) == 0 {
		return "AAAA"
	}
	raw[len(raw)-1] ^= 0xff
	return base64.StdEncoding.EncodeToString(raw)
}
