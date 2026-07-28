package main

// crypto_guards_test.go(第二十轮)—— PoW / captcha / TOTP 三套「无服务端状态、
// 全靠 HMAC 自证」的机制的失败侧。
//
// 这三套的共同风险是同一个:签名/随机数出问题时如果不是硬失败,而是降级成
// 「放行」,那道闸就等于不存在。所以这里逐条钉住:
//
//   - 随机数拿不到时,PoW 题目 / captcha / TOTP secret / 恢复码一律不许产出
//     (半截随机数意味着可预测的题目、可算出的 6 位码);
//   - 空 key 不能签出「空签名」再被当成合法(空==空 会让任何伪造题目都通过);
//   - 证明里的每一段畸形都要给出对应的拒绝原因,便于审计写清 reason;
//   - GC 要真的按周期清掉过期项,而不只是「收到 stop 会退出」。

import (
	"encoding/base64"
	"errors"
	"image"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// -------------------------------------------------------------------------
// PoW:签名与证明校验
// -------------------------------------------------------------------------

// 空 key 必须签不出东西,而且校验端要把「签不出」当作不合法。否则
// powChallengeHMAC 两边都返回 "",空签名的伪造题目就会被判成自洽。
func TestPoWChallengeHMAC_EmptyKeyNeverValidates(t *testing.T) {
	if sig := powChallengeHMAC(nil, "cid", "salt", 14, 999); sig != "" {
		t.Fatalf("空 key 竟签出了 %q", sig)
	}
	if powChallengeHMACEqual(nil, "cid", "salt", 14, 999, "") {
		t.Fatal("空 key + 空签名被判成了合法(任何伪造题目都能过)")
	}
}

// 签名字段不是合法 base64 时要拒。这条容易被写成「解不出来就跳过比对」,
// 那等于任何乱码签名都放行。
func TestPoWChallengeHMAC_UnparsableSignatureIsRejected(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	good := powChallengeHMAC(key, "cid", "c2FsdA==", 14, 999)
	if !powChallengeHMACEqual(key, "cid", "c2FsdA==", 14, 999, good) {
		t.Fatal("自己签的都验不过")
	}
	for _, bad := range []string{"", "!!!!", "not base64 at all"} {
		if powChallengeHMACEqual(key, "cid", "c2FsdA==", 14, 999, bad) {
			t.Errorf("签名 %q 被判为合法", bad)
		}
	}
}

// 随机数故障时不许产出题目:半截随机的 challenge_id / salt 意味着攻击者可以
// 预先算好解,PoW 就白做了。
func TestIssueChallenge_RandFailureIssuesNothing(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	for _, nth := range []int{1, 2} { // 1=challenge_id,2=salt
		stubRandRead(t, nth)
		c, err := sess.IssueChallenge(14)
		if err == nil {
			t.Fatalf("第 %d 次随机数故障却出了题: %+v", nth, c)
		}
		if c.ChallengeID != "" || c.Salt != "" || c.Signature != "" {
			t.Fatalf("失败时还带出了题面: %+v", c)
		}
	}
}

// 证明里每一段畸形都要落到对应的错误上 —— audit 靠这个 reason 才能区分
// 「客户端实现坏了」和「有人在伪造题目」。
func TestVerifyPoWProof_MalformedProofsMapToReasons(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	good, err := sess.IssueChallenge(powMinDifficulty)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	base := PoWProof{
		ChallengeID: good.ChallengeID, Salt: good.Salt,
		Difficulty: good.Difficulty, ExpiresAt: good.ExpiresAt,
		Signature: good.Signature,
	}

	cases := []struct {
		name string
		mut  func(p *PoWProof)
		want error
	}{
		{"缺 challenge_id", func(p *PoWProof) { p.ChallengeID = "" }, ErrPoWBadCID},
		{"缺签名", func(p *PoWProof) { p.Signature = "" }, ErrPoWBadSignature},
		{"难度为 0", func(p *PoWProof) { p.Difficulty = 0 }, ErrPoWBadSignature},
		{"没有过期时间", func(p *PoWProof) { p.ExpiresAt = 0 }, ErrPoWBadSignature},
		{"salt 不是 base64", func(p *PoWProof) { p.Salt = "!!!" }, ErrPoWBadSalt},
		{"salt 长度不对", func(p *PoWProof) {
			p.Salt = base64.StdEncoding.EncodeToString([]byte("short"))
		}, ErrPoWBadSalt},
		{"签名对不上", func(p *PoWProof) { p.ChallengeID += "x" }, ErrPoWBadSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mut(&p)
			if err := sess.VerifyPoWProof(p, powMinDifficulty); !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, 期望 %v", err, tc.want)
			}
		})
	}
}

// 难度越界要被夹断而不是照用:出题时给个 1 或 999,不能真下发一道
// 「秒解」或「永远解不完」的题。
func TestIssueChallenge_ClampsDifficulty(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	for _, tc := range []struct{ in, want int }{
		{1, powMinDifficulty},
		{999, powMaxDifficulty},
	} {
		c, err := sess.IssueChallenge(tc.in)
		if err != nil {
			t.Fatalf("IssueChallenge(%d): %v", tc.in, err)
		}
		if c.Difficulty != tc.want {
			t.Errorf("难度 %d 被下发成 %d, 期望夹到 %d", tc.in, c.Difficulty, tc.want)
		}
	}
}

// GC 要真的周期性清掉过期项。只验「收到 stop 会退出」的话,一个从不清扫的
// GC 也能过测 —— 而那正是内存无界增长的样子。
func TestRunPoWGC_TickReallyPrunes(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	orig := powGCInterval
	powGCInterval = 5 * time.Millisecond
	t.Cleanup(func() { powGCInterval = orig })

	sess.powUsed.Store("expired-cid", nowUnix()-1)
	sess.powUsed.Store("live-cid", nowUnix()+3600)
	sess.captchaUsed.Store("expired-nonce", nowUnix()-1)
	sess.pendingUsed.Store("expired-pending", nowUnix()-1)

	// step-up 计数器挂在 Server 上、由 main 作为 extra 传进来:它跟 PoW 共用这一个
	// ticker,漏掉的话冷却窗口会越积越长(用户被无限期挡在 step-up 外面)。
	stepUp := NewIPFailureTracker()
	const staleIP = "10.9.9.9"
	stepUp.Inc(staleIP)
	backdateIPFailure(t, stepUp, staleIP)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { sess.runPoWGC(stop, stepUp); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, still := sess.powUsed.Load("expired-cid"); !still {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("GC 收到 stop 之后没退出")
	}

	if _, still := sess.powUsed.Load("expired-cid"); still {
		t.Error("过期的 challenge 没被清掉")
	}
	if _, still := sess.captchaUsed.Load("expired-nonce"); still {
		t.Error("过期的 captcha nonce 没被清掉")
	}
	if _, still := sess.pendingUsed.Load("expired-pending"); still {
		t.Error("过期的 pending nonce 没被清掉")
	}
	if _, still := stepUp.m.Load(staleIP); still {
		t.Error("step-up 的陈旧计数没被清掉 —— 冷却窗口会越积越长,把用户无限期挡在 step-up 外面")
	}
	// 没过期的不能被顺手清掉 —— 那会让防重放出现窗口。
	if _, ok := sess.powUsed.Load("live-cid"); !ok {
		t.Error("还没过期的 challenge 被清掉了(防重放出现窗口)")
	}
}

// -------------------------------------------------------------------------
// captcha
// -------------------------------------------------------------------------

// 随机数故障时不许出图:答案抽不出来、nonce 抽不出来,都不能写 cookie —— 一张
// 「答案可预测」的验证码比没有验证码更糟(它会让人以为这道闸还在)。
func TestIssueCaptcha_RandFailureIssuesNothing(t *testing.T) {
	st := newTestStore(t)
	sess := NewSessionService(st, defaultConfig())
	for _, nth := range []int{1, 2} { // 1=答案,2=nonce
		stubRandRead(t, nth)
		w := httptest.NewRecorder()
		c, err := sess.IssueCaptcha(w)
		if err == nil {
			t.Fatalf("第 %d 次随机数故障却出了图", nth)
		}
		if c.DataURL != "" {
			t.Fatalf("失败时还给出了图片")
		}
		if ck := w.Header().Get("Set-Cookie"); ck != "" {
			t.Fatalf("失败时仍写了 cookie: %q", ck)
		}
	}
}

func TestRandomDigits_RejectsBadCount(t *testing.T) {
	for _, n := range []int{0, -1, 17} {
		if got, err := randomDigits(n); err == nil {
			t.Errorf("n=%d 也生成了 %q", n, got)
		}
	}
}

// cookie 的每种畸形都要判不合法。这里特别要盯「长度对但签名不对」——
// 那正是有人在自己伪造 captcha cookie 的样子。
func TestDecodeCaptchaCookie_RejectsMalformed(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := []byte("0123456789abcdef")
	good := encodeCaptchaCookie(key, "1234", nonce, nowUnix()+60)

	if _, _, _, ok := decodeCaptchaCookie(key, []byte(good)); !ok {
		t.Fatal("自己编的 cookie 都解不出来")
	}
	for _, tc := range []struct{ name, val string }{
		{"空值", ""},
		{"不是 base64", "!!!!"},
		{"短一截", good[:len(good)-8]},
		{"长一截", good + "AAAA"},
	} {
		if _, _, _, ok := decodeCaptchaCookie(key, []byte(tc.val)); ok {
			t.Errorf("%s 竟被解成了合法 cookie", tc.name)
		}
	}
	// 换一把 key 解同一串:签名对不上,必须拒。
	other := []byte("ffffffffffffffffffffffffffffffff")
	if _, _, _, ok := decodeCaptchaCookie(other, []byte(good)); ok {
		t.Error("用别的 key 也能解开(等于签名没起作用)")
	}
}

// nonce 长度写错是程序 bug,不是用户输入 —— 必须当场 panic,而不是编出一张
// 长度不对、之后到处解不开的 cookie。
func TestEncodeCaptchaCookie_PanicsOnBadNonce(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nonce 长度不对却照样编出了 cookie")
		}
	}()
	_ = encodeCaptchaCookie([]byte("k"), "1234", []byte("short"), nowUnix())
}

// 画图那几段本身不涉安全,但 drawLine 的方向判断只在「从右往左」时才走到,
// 而真实调用永远从左往右 —— 留个直调用例免得改到那两行没人发现。
func TestDrawLine_HandlesBothDirections(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 10, 10))
	drawLine(img, 8, 8, 1, 1, colLine) // 右下 → 左上,sx/sy 都是 -1
	if _, _, _, a := img.At(1, 1).RGBA(); a == 0 {
		t.Error("反向画线没画到终点")
	}
	// 越界的端点不能 panic(inBounds 兜底)。
	drawLine(img, -5, -5, 20, 20, colLine)
}

func TestNormalizeAnswer_KeepsOnlyDigits(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{" 1 2 3 4 ", "1234"},
		{"1-2-3-4", "1234"},
		{"abc", ""},
		{"", ""},
	} {
		if got := normalizeAnswer(tc.in); got != tc.want {
			t.Errorf("normalizeAnswer(%q) = %q, 期望 %q", tc.in, got, tc.want)
		}
	}
}

// -------------------------------------------------------------------------
// TOTP
// -------------------------------------------------------------------------

// secret 抽不出来必须报错。这条尤其不能兜底成伪随机:弱 secret 意味着
// 攻击者能自己算出这个账号所有时间步的 6 位码,2FA 直接失效。
func TestGenerateTOTPSecret_RandFailureIsAnError(t *testing.T) {
	stubRandRead(t, 1)
	if got, err := GenerateTOTPSecret(); err == nil {
		t.Fatalf("随机数故障却生成了 secret=%q", got)
	}
}

// 恢复码的两种失败:随机数和哈希。任一失败都必须整体放弃 —— 不能返回一份
// 「前几条能用、后几条丢了」的列表(用户抄下的码与库里存的对不上就锁死了)。
func TestGenerateRecoveryCodes_FailuresYieldNothing(t *testing.T) {
	t.Run("随机数故障", func(t *testing.T) {
		stubRandRead(t, 1)
		plain, hashes, err := GenerateRecoveryCodes()
		if err == nil {
			t.Fatal("随机数故障却生成了恢复码")
		}
		if plain != nil || hashes != nil {
			t.Fatalf("失败时还带出了 %d 条明文 / %d 条哈希", len(plain), len(hashes))
		}
	})

	t.Run("哈希故障", func(t *testing.T) {
		orig := HashWebPassword
		HashWebPassword = func(string) (string, error) {
			// 同时给个非空 hash:这样若错误被忽略,落库的就是一条谁都能匹配的
			// 假哈希,而不是被下游的空值校验挡住 —— 后者会掩盖真正的问题。
			return "$argon2id$broken", errors.New("注入的哈希故障")
		}
		t.Cleanup(func() { HashWebPassword = orig })

		plain, hashes, err := GenerateRecoveryCodes()
		if err == nil {
			t.Fatal("哈希故障却生成了恢复码")
		}
		if plain != nil || hashes != nil {
			t.Fatalf("失败时还带出了 %d 条明文 / %d 条哈希", len(plain), len(hashes))
		}
	})
}

// 库里的 secret 被手改坏时,校验必须报错而不是「解不出来就当匹配」。
func TestVerifyTOTPStep_BadSecretIsRejected(t *testing.T) {
	for _, tc := range []struct{ name, secret string }{
		{"不是 base32", "这不是 base32"},
		{"太短(不足 80 bit)", "AAAAAAAA"}, // 8 字符 base32 = 5 字节
		{"空", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyTOTPStep(tc.secret, "123456"); err == nil {
				t.Fatal("坏 secret 却校验通过了")
			}
			if err := VerifyTOTP(tc.secret, "123456"); err == nil {
				t.Fatal("坏 secret 却校验通过了(无状态版本)")
			}
		})
	}
}

func TestNormalizeRecoveryCode_RejectsWrongLength(t *testing.T) {
	// 正常输入:大小写、空格、横线都要容错成同一个形态。
	for _, in := range []string{"abcd-2345", "ABCD2345", " abcd 2345 ", "a b c d 2 3 4 5"} {
		got, err := NormalizeRecoveryCode(in)
		if err != nil {
			t.Fatalf("NormalizeRecoveryCode(%q): %v", in, err)
		}
		if got != "ABCD-2345" {
			t.Errorf("NormalizeRecoveryCode(%q) = %q", in, got)
		}
	}
	for _, in := range []string{"", "abcd", "abcd-23456", "0189-0189"} { // 0/1/8/9 不在 base32 字母表
		if got, err := NormalizeRecoveryCode(in); err == nil {
			t.Errorf("NormalizeRecoveryCode(%q) = %q, 期望报错", in, got)
		}
	}
}

func TestBuildOtpauthURI_CarriesExplicitParams(t *testing.T) {
	uri := BuildOtpauthURI("ABCDEFGH", "root@vpn.example.com")
	// 显式带上算法/位数/周期:少数旧 app 的默认值不一致,不写就会算出错码。
	for _, want := range []string{"secret=ABCDEFGH", "algorithm=SHA1", "digits=6", "period=30", "issuer=nanotun"} {
		if !strings.Contains(uri, want) {
			t.Errorf("otpauth URI 缺 %q: %s", want, uri)
		}
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("URI 前缀不对: %s", uri)
	}
}

// -------------------------------------------------------------------------
// IP 失败计数
// -------------------------------------------------------------------------

// 空 IP 在各处都要是「无操作」:clientIP 理论上不会返回空,但一旦返回了,
// 空串不能变成一个所有请求共用的计数桶(那会让一个人的失败锁住所有人)。
func TestIPFailureTracker_EmptyIPIsANoop(t *testing.T) {
	tr := NewIPFailureTracker()
	if n := tr.Inc(""); n != 0 {
		t.Errorf("Inc(\"\") = %d, 期望 0", n)
	}
	if n := tr.Recent(""); n != 0 {
		t.Errorf("Recent(\"\") = %d, 期望 0", n)
	}
	tr.Reset("") // 不能 panic
	tr.Decay("") // 不能 panic
	if n := tr.Recent("1.2.3.4"); n != 0 {
		t.Errorf("空 IP 的操作串到别的 IP 上了: %d", n)
	}
}

// 窗口过期后计数要惰性归零:Recent 读到的是 0,再 Inc 也要从 1 起算 ——
// 否则几小时前的失败会一直压着难度,合法管理员长期被要求解 PoW。
func TestIPFailureTracker_WindowExpiryResetsLazily(t *testing.T) {
	tr := NewIPFailureTracker()
	const ip = "203.0.113.7"
	for i := 0; i < 5; i++ {
		tr.Inc(ip)
	}
	if n := tr.Recent(ip); n != 5 {
		t.Fatalf("Recent = %d, 期望 5", n)
	}
	ageOutIPFailure(t, tr, ip)

	if n := tr.Recent(ip); n != 0 {
		t.Fatalf("过窗后 Recent = %d, 期望惰性归零", n)
	}
	// 归零后再失败一次:必须从 1 起算,而不是接着 5 往上。
	ageOutIPFailure(t, tr, ip)
	if n := tr.Inc(ip); n != 1 {
		t.Fatalf("过窗后 Inc = %d, 期望 1", n)
	}
}

// Decay 是登录成功时用的:窗口内减半(保留「这个 IP 近期在被爆破」的信号),
// 过窗则直接归零。写成清零会让 NAT 后一个人的成功登录替同 IP 的攻击者免掉 PoW。
func TestIPFailureTracker_DecayHalvesOrResets(t *testing.T) {
	tr := NewIPFailureTracker()
	const ip = "203.0.113.8"
	for i := 0; i < 7; i++ {
		tr.Inc(ip)
	}
	tr.Decay(ip)
	if n := tr.Recent(ip); n != 3 {
		t.Fatalf("Decay 后 = %d, 期望 3(7 减半向下取整)", n)
	}

	ageOutIPFailure(t, tr, ip)
	tr.Decay(ip)
	if n := tr.Recent(ip); n != 0 {
		t.Fatalf("过窗 Decay 后 = %d, 期望 0", n)
	}

	// Reset 是「彻底清零」那条路径(改密等场景),与 Decay 不同。
	for i := 0; i < 4; i++ {
		tr.Inc(ip)
	}
	tr.Reset(ip)
	if n := tr.Recent(ip); n != 0 {
		t.Fatalf("Reset 后 = %d, 期望 0", n)
	}
}

// ageOutIPFailure 把某 IP 的 lastFail 推到窗口之外,模拟「很久没再失败」。
func ageOutIPFailure(t *testing.T, tr *IPFailureTracker, ip string) {
	t.Helper()
	v, ok := tr.m.Load(ip)
	if !ok {
		t.Fatalf("IP %s 不在表里", ip)
	}
	rec := v.(*ipFailureRecord)
	rec.mu.Lock()
	rec.lastFail = nowUnix() - ipFailureWindowSec - 1
	rec.mu.Unlock()
}

// 触顶时必须驱逐旧条目让新 IP 仍被追踪,而不是放弃追踪 ——
// 后者会让攻击者先用大量源 IP 灌满表,之后用真实攻击 IP 永久免 PoW。
func TestIPFailureTracker_EvictsRatherThanGivingUp(t *testing.T) {
	tr := NewIPFailureTracker()
	// 直接把 size 顶到上限(灌一万多个真 IP 太慢),再看新 IP 有没有被追踪。
	tr.size.Store(maxTrackedIPs)
	tr.m.Store("10.0.0.1", &ipFailureRecord{count: 1, lastFail: nowUnix()})

	if n := tr.Inc("198.51.100.9"); n != 1 {
		t.Fatalf("触顶时新 IP 的失败没被计入(Inc = %d)—— 灌满表即可免 PoW", n)
	}
	if n := tr.Recent("198.51.100.9"); n != 1 {
		t.Fatalf("触顶时新 IP 没进表(Recent = %d)", n)
	}
}

// -------------------------------------------------------------------------
// 登录失败计数与 HTTP 无关的那一层
// -------------------------------------------------------------------------

func TestComputeDifficulty_CurveShape(t *testing.T) {
	for _, tc := range []struct{ failures, want int }{
		{-1, 0}, {0, 0}, {2, 0},
		{powFailuresEnable, powBaseDifficulty},
		{powFailuresEnable + 1, powBaseDifficulty + powStepPerFailure},
		{100, powAdaptiveCeiling}, // 封顶,不能把客户端逼死
	} {
		if got := ComputeDifficulty(tc.failures); got != tc.want {
			t.Errorf("ComputeDifficulty(%d) = %d, 期望 %d", tc.failures, got, tc.want)
		}
	}
}

func TestParsePoWFormFields_ReportsWhichFieldIsBad(t *testing.T) {
	full := map[string]string{
		"pow_challenge_id": "cid", "pow_salt": "c2FsdA==",
		"pow_difficulty": "14", "pow_expires_at": "999",
		"pow_signature": "sig", "pow_nonce": "42",
	}
	if _, err := parsePoWFormFields(fakeForm(full)); err != nil {
		t.Fatalf("完整字段却解析失败: %v", err)
	}
	// 逐个字段弄坏:错误信息里必须点出是哪个字段,audit 才写得清原因。
	for field, bad := range map[string]string{
		"pow_challenge_id": "", "pow_salt": "",
		"pow_difficulty": "0", "pow_expires_at": "-1",
		"pow_signature": "", "pow_nonce": "not-a-number",
	} {
		m := map[string]string{}
		for k, v := range full {
			m[k] = v
		}
		m[field] = bad
		got, err := parsePoWFormFields(fakeForm(m))
		if err == nil {
			t.Errorf("%s=%q 却解析成功了: %+v", field, bad, got)
			continue
		}
		if !strings.Contains(err.Error(), field) {
			t.Errorf("%s=%q 的报错没点明字段: %v", field, bad, err)
		}
	}
}

// fakeForm 只实现 parsePoWFormFields 需要的那一个方法,省得造完整请求。
type fakeForm map[string]string

func (f fakeForm) FormValue(k string) string { return f[k] }

// backdateIPFailure 把某个 IP 的最后失败时间推到「陈旧」之外,好让 Prune 认得出它。
func backdateIPFailure(t *testing.T, tr *IPFailureTracker, ip string) {
	t.Helper()
	v, ok := tr.m.Load(ip)
	if !ok {
		t.Fatalf("%s 没进计数表", ip)
	}
	rec := v.(*ipFailureRecord)
	rec.mu.Lock()
	rec.lastFail = nowUnix() - 10*ipFailureWindowSec
	rec.mu.Unlock()
}
