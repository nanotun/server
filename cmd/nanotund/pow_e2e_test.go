package main

// pow_e2e_test.go - PoW 防护端到端集成测试。
//
// 跟 psk_login_integration_test.go 的「正常通过」路径互补,本文件专门验证
// **attacker 行为**:老客户端首帧不发 PoWChallengeReq、状态机违规、签名篡改、
// nonce 不满足难度等场景下 server 必须拒登。这是 P2#16 PoW 防护最核心的不变量,
// 任何重构必须保持这些测试绿色。

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// newPoWTestGateway 是本文件的共用 helper:开 SQLite + 建 alice 用户 + 返回 gw。
func newPoWTestGateway(t *testing.T) *gatewayState {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "pow_e2e.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	pskHash, errH := auth.HashPSK("hunter2")
	if errH != nil {
		t.Fatalf("HashPSK: %v", errH)
	}
	if _, errU := st.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: pskHash, ExitAllowed: true}); errU != nil {
		t.Fatalf("CreateUser: %v", errU)
	}
	return &gatewayState{
		cfg:          &config.Config{},
		store:        st,
		authVerifier: auth.NewVerifier(st),
	}
}

// startHandlePipe 起一对 net.Pipe,server 端跑 handleVPNLink;返回 client 端 + done chan。
func startHandlePipe(t *testing.T, gw *gatewayState) (net.Conn, chan struct{}) {
	t.Helper()
	serverEnd, clientEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleVPNLink(serverEnd, gw)
	}()
	t.Cleanup(func() {
		_ = clientEnd.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Logf("[警告] handleVPNLink 3s 内未退出 — server 可能挂在 read 上,raw.Close 兜底应能解")
		}
	})
	return clientEnd, done
}

// TestPoWE2E_OldClientFirstFrameLoginReq:**老客户端 / 任何首帧非 PoWChallengeReq 的连接静默断开**。
//
// server 不写 LoginResp、不写 Close 帧,直接 raw.Close — 这是反指纹设计(不给
// 扫描器送响应)。客户端表现:read 立刻得 EOF。
func TestPoWE2E_OldClientFirstFrameLoginReq(t *testing.T) {
	resetServerGlobals(t)
	gw := newPoWTestGateway(t)
	clientEnd, _ := startHandlePipe(t, gw)

	// 模拟老客户端:直接发 LoginReq(无 PoW 字段)。
	body, _ := util.MarshalLoginReqWithDeviceJSON(
		"alice", "", "hunter2",
		"client", "darwin", "tcp",
		"11111111-2222-4333-8444-555555555555", "MacBook",
	)
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 2*time.Second); err != nil {
		// net.Pipe 半双工特性下 server 端 raw.Close() 后 client.Write 会立刻 errClosed —
		// 这是合法行为(等价于 attacker 在网络上观察到 FIN,无 LoginResp 返回)。
		// 校验错误类型确认是 close 而非别的 IO 故障。
		if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
			t.Fatalf("write 错误类型非预期 (应为 ErrClosedPipe/ErrClosed/EOF): %v", err)
		}
		return
	}
	// server 没回任何帧 → client read 应得 EOF / err。
	// SetReadDeadline 在 net.Pipe 已被对端 Close 后会自己报 ErrClosedPipe,这同样
	// 表明 server 已经断开。
	if err := clientEnd.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
			return
		}
		t.Fatalf("SetReadDeadline 错误类型非预期: %v", err)
	}
	buf := make([]byte, 16)
	_, err := clientEnd.Read(buf)
	if err == nil {
		t.Fatalf("期望读到 EOF/err(server 静默断),实际 read 成功 — 反指纹设计破坏")
	}
	// 强断言:必须是 server 主动 close 类的错误,不能是 timeout / 其它 IO 错。
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read 错误类型非预期 (应为 EOF/ErrClosedPipe/ErrClosed): %v", err)
	}
}

// TestPoWE2E_DoubleChallengeReq:**状态机违规 — 单连接二次出题被拒**。
//
// PoW 协议是「一次性」状态机:首帧 PoWChallengeReq → 第二帧必须是 LoginReq。
// 客户端如果在拿到 PoWChallenge 后又发一次 PoWChallengeReq,server 必须 close 412,
// 防止 attacker 在一条连接里反复刷 challenge 抠 server CPU。
func TestPoWE2E_DoubleChallengeReq(t *testing.T) {
	resetServerGlobals(t)
	gw := newPoWTestGateway(t)
	clientEnd, _ := startHandlePipe(t, gw)

	// 第一次:正常拿 challenge。
	_ = runClientPoWHandshake(t, clientEnd)

	// 第二次:再发 PoWChallengeReq(预期 server close 412)。
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypePoWChallengeReq, nil, 2*time.Second); err != nil {
		t.Fatalf("write 二次 PoWChallengeReq: %v", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if err != nil {
		t.Fatalf("read close frame: %v", err)
	}
	if typ != util.LinkTypeClose {
		t.Fatalf("typ=%d want LinkTypeClose(状态机违规应回 Close)", typ)
	}
	msg, errP := util.ParseCloseLinkPayload(payload)
	if errP != nil {
		t.Fatalf("ParseCloseLinkPayload: %v", errP)
	}
	if msg.Code != util.CodePowFailed {
		t.Fatalf("Close.Code=%d want %d (CodePowFailed)", msg.Code, util.CodePowFailed)
	}
}

// TestPoWE2E_TamperedSignature:**HMAC 签名被篡改的 PoW 被拒**。
//
// attacker 拿到合法 challenge 后改 signature 字段 → server 验签必失败 → close 412。
// 这是 HMAC 防伪造的核心保证。
func TestPoWE2E_TamperedSignature(t *testing.T) {
	resetServerGlobals(t)
	gw := newPoWTestGateway(t)
	clientEnd, _ := startHandlePipe(t, gw)

	pow := runClientPoWHandshake(t, clientEnd)
	// 篡改 signature(任何修改都会让 HMAC 验签失败)。
	pow.Signature = "AAAA" + pow.Signature[4:]

	body, _ := marshalLoginReqWithPoW(
		"alice", "hunter2",
		"client", "darwin", "tcp",
		"11111111-2222-4333-8444-555555555555", "MacBook",
		pow,
	)
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 2*time.Second); err != nil {
		t.Fatalf("write LoginReq: %v", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if err != nil {
		t.Fatalf("read close: %v", err)
	}
	if typ != util.LinkTypeClose {
		t.Fatalf("typ=%d want LinkTypeClose", typ)
	}
	msg, _ := util.ParseCloseLinkPayload(payload)
	if msg.Code != util.CodePowFailed {
		t.Fatalf("Close.Code=%d want %d", msg.Code, util.CodePowFailed)
	}
}

// TestPoWE2E_BadNonce:**nonce 不满足难度的 PoW 被拒**。
//
// HMAC 签名对的情况下,server 还要做数学校验(SHA256 前导零比特数 ≥ difficulty)。
// 客户端如果填错 nonce(比如 0),数学必然失败 → close 412。
func TestPoWE2E_BadNonce(t *testing.T) {
	resetServerGlobals(t)
	gw := newPoWTestGateway(t)
	clientEnd, _ := startHandlePipe(t, gw)

	pow := runClientPoWHandshake(t, clientEnd)
	pow.Nonce = 0 // 难度 8-bit,nonce=0 极不可能满足。

	body, _ := marshalLoginReqWithPoW(
		"alice", "hunter2",
		"client", "darwin", "tcp",
		"11111111-2222-4333-8444-555555555555", "MacBook",
		pow,
	)
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 2*time.Second); err != nil {
		t.Fatalf("write LoginReq: %v", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if err != nil {
		t.Fatalf("read close: %v", err)
	}
	if typ != util.LinkTypeClose {
		t.Fatalf("typ=%d want LinkTypeClose", typ)
	}
	msg, _ := util.ParseCloseLinkPayload(payload)
	if msg.Code != util.CodePowFailed {
		t.Fatalf("Close.Code=%d want %d", msg.Code, util.CodePowFailed)
	}
}

// TestPoWE2E_PSKFailureIncrementsDifficulty:**PSK 失败 → IP failures 升 → 下次 PoW 难度跟着升**。
//
// 这是 PoW 自适应难度的核心:正常用户偶尔输错密码不会被升难度(failures_enable=0
// 时所有失败都计数,但失败次数 < failures_enable 时仍发 base);**故意拿一个**
// 高 failures_enable 的测试 gw 验证升降路径行为正确(单元级别)。
//
// 本测试用 PoWService 直接调 ComputeDifficulty 验证公式,不走完整 handleVPNLink
// 路径(那个跑起来慢,这种纯算法用单测验证最经济)。
func TestPoWE2E_PSKFailureIncrementsDifficulty(t *testing.T) {
	tracker := NewIPFailureTracker()
	svc, err := NewPoWService(nil, tracker, 3, 8, 14, 2, 22, 300)
	if err != nil {
		t.Fatalf("NewPoWService: %v", err)
	}

	cases := []struct {
		failures int
		want     int
		desc     string
	}{
		{0, 8, "无失败 → base=8"},
		{2, 8, "失败<failures_enable(3) → 仍 base=8"},
		{3, 14, "失败=failures_enable → ramp=14"},
		{4, 16, "ramp+1 步 → 14+2=16"},
		{5, 18, "ramp+2 步 → 18"},
		{10, 22, "封顶 adaptive_ceiling=22"},
	}
	for _, c := range cases {
		got := svc.ComputeDifficulty(c.failures)
		if got != c.want {
			t.Errorf("%s: ComputeDifficulty(%d)=%d, want %d", c.desc, c.failures, got, c.want)
		}
	}

	// 验证 MarkFailure / MarkSuccess 影响 Count。
	// MarkSuccess 行为(P2-4):减半而非清零,NAT 后合法用户登录不再让 attacker
	// 的失败计数全清。验证 5 失败连续 MarkSuccess 后逐步衰减 5→2→1→0。
	const ip = "1.2.3.4"
	if n := tracker.Count(ip); n != 0 {
		t.Fatalf("初始 Count=%d, want 0", n)
	}
	for i := 0; i < 5; i++ {
		tracker.MarkFailure(ip)
	}
	if n := tracker.Count(ip); n != 5 {
		t.Fatalf("MarkFailure ×5 后 Count=%d, want 5", n)
	}
	if d := svc.ComputeDifficulty(tracker.Count(ip)); d != 18 {
		t.Fatalf("升档难度=%d, want 18", d)
	}
	// 第一次 MarkSuccess:5 → 2(取整除)。在 failuresEnable=3 的配置下,
	// 2 < 3 已经回到 base 难度,合法用户体验立刻恢复。
	tracker.MarkSuccess(ip)
	if n := tracker.Count(ip); n != 2 {
		t.Fatalf("MarkSuccess #1 后 Count=%d, want 2 (5/2)", n)
	}
	if d := svc.ComputeDifficulty(tracker.Count(ip)); d != 8 {
		t.Fatalf("MarkSuccess #1 后难度=%d, want 8 (failures=2<failuresEnable=3 → base)", d)
	}
	// 第二次:2 → 1。
	tracker.MarkSuccess(ip)
	if n := tracker.Count(ip); n != 1 {
		t.Fatalf("MarkSuccess #2 后 Count=%d, want 1 (2/2)", n)
	}
	// 第三次:1 → 0(<=1 直接 delete)。
	tracker.MarkSuccess(ip)
	if n := tracker.Count(ip); n != 0 {
		t.Fatalf("MarkSuccess #3 后 Count=%d, want 0", n)
	}
	if d := svc.ComputeDifficulty(tracker.Count(ip)); d != 8 {
		t.Fatalf("Success 清零后难度=%d, want 8 (base)", d)
	}

	// 关键反向验证:NAT 边界场景 — 高失败次数 IP 不会被一次 MarkSuccess 全清回 base。
	// 制造 7 次失败(→ 应该触顶 22),一次 MarkSuccess 后失败=3 → 难度 14(rampDifficulty)
	// 而不是 8(base),attacker 在 NAT 后仍能感受到难度升高,无法被合法用户"洗白"。
	const ipNAT = "10.0.0.1"
	for i := 0; i < 7; i++ {
		tracker.MarkFailure(ipNAT)
	}
	if n := tracker.Count(ipNAT); n != 7 {
		t.Fatalf("NAT 场景 MarkFailure ×7 后 Count=%d, want 7", n)
	}
	if d := svc.ComputeDifficulty(tracker.Count(ipNAT)); d != 22 {
		t.Fatalf("NAT 场景 7 失败难度=%d, want 22 (封顶)", d)
	}
	tracker.MarkSuccess(ipNAT)
	if n := tracker.Count(ipNAT); n != 3 {
		t.Fatalf("NAT MarkSuccess 后 Count=%d, want 3 (7/2)", n)
	}
	if d := svc.ComputeDifficulty(tracker.Count(ipNAT)); d != 14 {
		t.Fatalf("NAT MarkSuccess 后难度=%d, want 14 (ramp, 仍升档)", d)
	}
}

// TestPoWE2E_ChallengeReplayBlocked:**单元层 — 同一 challenge 提交两次,第二次防重放命中**。
//
// 同一连接里状态机不允许二次 LoginReq(server 走完一次 LoginReq 就进数据面或退出);
// 防重放真正测的是跨连接 — 两条 net.Pipe,A 拿到 challenge 但跳过 LoginReq 直接退出,
// B 用同一份 challenge 提交 → 第二次 PoWService.VerifyPoWProof 命中 powUsed。
//
// 但 challenge 是 server 给每条连接独立 IssueChallenge 出的,A 跟 B 拿到的 cid 不同;
// 要复用 challenge 需要 attacker 自己控制题目缓存。本测试直接调 PoWService 单元层
// 验证 powUsed sync.Map 防重放语义。跨连接的 e2e replay 见
// TestPoWE2E_CrossConnReplayBlocked。
func TestPoWE2E_ChallengeReplayBlocked(t *testing.T) {
	svc, err := NewPoWService(nil, nil, 0, 8, 14, 2, 22, 300)
	if err != nil {
		t.Fatalf("NewPoWService: %v", err)
	}
	ch, errIssue := svc.IssueChallenge(8)
	if errIssue != nil {
		t.Fatalf("IssueChallenge: %v", errIssue)
	}
	// 解 nonce(同包内复用 powVerify)。
	saltBytes, _ := testB64Std.DecodeString(ch.Salt)
	var nonce uint64
	for ; nonce < (1 << 32); nonce++ {
		if powVerify(ch.ChallengeID, saltBytes, ch.Difficulty, nonce) {
			break
		}
	}
	proof := PoWProof{
		ChallengeID: ch.ChallengeID,
		Salt:        ch.Salt,
		Difficulty:  ch.Difficulty,
		ExpiresAt:   ch.ExpiresAt,
		Signature:   ch.Signature,
		Nonce:       nonce,
	}
	// 第一次:通过。
	if errV := svc.VerifyPoWProof(proof, 8); errV != nil {
		t.Fatalf("第一次 VerifyPoWProof: %v", errV)
	}
	// 第二次:同 challenge_id 必拒。
	errV2 := svc.VerifyPoWProof(proof, 8)
	if errV2 != ErrPoWReplay {
		t.Fatalf("第二次 VerifyPoWProof=%v, want ErrPoWReplay", errV2)
	}
}

// TestPoWE2E_PreLoginIdleDeadline:**WS 握手后不发任何帧,30s 内被断**。
//
// 防御 attacker 完成 WS 握手后挂着不发任何帧的廉价 DoS。原本是 30s,测试里手
// 工把 handleVPNLink 的 raw.SetDeadline 行为通过短时间验证 — 但 30s 太长会拖慢
// CI,这里直接验证 SetDeadline 被调到 raw 上(行为间接验证:client 不发帧,
// server 端读应在 deadline 触发后失败,server 走 cleanup 路径退出)。
//
// 由于 net.Pipe 不支持 SetDeadline,本测试在 net.Pipe 路径下只验证 handleVPNLink
// 没在 deadline 设置阶段 panic 即可(SetDeadline 返回 err 被 handleVPNLink 容错处理)。
// 真正的 deadline 行为在生产 TCP / WSS conn 上才生效,需要单独的 net.Listen 测试。
//
// 这里用一个简易的 TCP loopback 验证:server 端 SetDeadline 30s 但我们把 deadline
// 临时改成短值需要改 handleVPNLink 签名 — 暂不做,只断言 SetDeadline 错误不影响
// 主流程(net.Pipe 实测确实如此)。
func TestPoWE2E_PreLoginIdleDeadline_Smoke(t *testing.T) {
	resetServerGlobals(t)
	gw := newPoWTestGateway(t)
	clientEnd, done := startHandlePipe(t, gw)

	// 客户端不发任何帧,但主动 Close 模拟「连了一下就跑」。
	_ = clientEnd.Close()
	// server 端 handleVPNLink 应该在 raw read EOF 后干净退出(此时 SetDeadline
	// 路径不应阻塞 — net.Pipe 不支持 deadline,handleVPNLink 容错继续读)。
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleVPNLink 5s 内未退出 — pre-login deadline 容错路径可能 stuck")
	}
}

// TestPoWE2E_CrossConnReplayBlocked:**跨连接 challenge replay 攻击场景**。
//
// 攻击者拿一次合法 challenge(包含 cid + nonce + 签名),然后在新连接上**跳过**
// server 出的新 challenge,直接把老的 PoW 信息塞进 LoginReq.Pow → server 端
// 已把该 cid Store 进 powUsed,VerifyPoWProof 在 LoadOrStore 阶段命中 → 拒 412。
//
// 这是端到端测试,跟单元层 TestPoWE2E_ChallengeReplayBlocked 互补 ——
// 单元层只测 VerifyPoWProof 的语义,这里测真实 handleVPNLink + server.go 状态机
// 在拿到 replay PoW 后会走 close 412 而不是登录成功。
func TestPoWE2E_CrossConnReplayBlocked(t *testing.T) {
	resetServerGlobals(t)
	gw := newPoWTestGateway(t)

	// 关键:两条连接必须共享同一个 powService,否则 hmacKey / powUsed 都不一致,
	// 不构成 replay。startHandlePipe 内部 handleVPNLink 都用同一个 gw,所以
	// effectivePoWService() 返回同一实例(生产路径走 gw.powService,测试走 lazy)。
	clientA, doneA := startHandlePipe(t, gw)

	// A 路径:正常拿 challenge + 解 nonce + 发 LoginReq → 成功登录(server 把 cid
	// Store 到 powUsed),记下 pow 信息后立刻断开。
	powA := runClientPoWHandshake(t, clientA)
	loginBody, errLM := marshalLoginReqWithPoW(
		"alice", "hunter2",
		"client", "darwin", "tcp",
		"22222222-3333-4444-8555-666666666666", "MacBookA",
		powA,
	)
	if errLM != nil {
		t.Fatalf("marshalLoginReqWithPoW: %v", errLM)
	}
	if err := writeLinkFrameWithDeadline(clientA, util.LinkTypeLoginReq, loginBody, 2*time.Second); err != nil {
		t.Fatalf("A write LoginReq: %v", err)
	}
	// A 读 LoginResp 确认登录成功(同时 server 已把 cid Store 进 powUsed)。
	typ, payload, errR := readLinkFrameWithDeadline(clientA, 2*time.Second)
	if errR != nil {
		t.Fatalf("A read LoginResp: %v", errR)
	}
	if typ != util.LinkTypeLoginResp {
		t.Fatalf("A 期望 LoginResp(2), 实际 typ=%d", typ)
	}
	var resp struct {
		Code int `json:"code"`
	}
	if errJ := json.Unmarshal(payload, &resp); errJ != nil {
		t.Fatalf("A LoginResp 解析: %v", errJ)
	}
	if resp.Code != 0 {
		t.Fatalf("A 期望登录成功 code=0, 实际 code=%d", resp.Code)
	}
	// A 干完活,关链路让 server 端 cleanup。
	_ = clientA.Close()
	<-doneA

	// B 路径:新连接,正常发 PoWChallengeReq 拿到新 challenge(我们故意丢弃);
	// 然后把 A 的 powA 信息塞进 LoginReq.Pow → server 应拒 412 (replay)。
	clientB, _ := startHandlePipe(t, gw)
	// 必须先发 PoWChallengeReq 才能让 server 进入下一状态(状态机第一步)。
	if err := writeLinkFrameWithDeadline(clientB, util.LinkTypePoWChallengeReq, nil, 2*time.Second); err != nil {
		t.Fatalf("B write PoWChallengeReq: %v", err)
	}
	// 读掉 server 出的新 challenge(不解,直接丢)。
	typB, _, errRB := readLinkFrameWithDeadline(clientB, 2*time.Second)
	if errRB != nil {
		t.Fatalf("B read challenge: %v", errRB)
	}
	if typB != util.LinkTypePoWChallenge {
		t.Fatalf("B 期望 LinkTypePoWChallenge(18), 实际 typ=%d", typB)
	}
	// 现在用 A 的 PoW 信息构造 LoginReq → server 验签 cid 在 powUsed → ErrPoWReplay。
	replayBody, _ := marshalLoginReqWithPoW(
		"alice", "hunter2",
		"client", "darwin", "tcp",
		"33333333-4444-5555-8666-777777777777", "MacBookB-replay",
		powA, // 关键:用 A 的 PoW
	)
	if err := writeLinkFrameWithDeadline(clientB, util.LinkTypeLoginReq, replayBody, 2*time.Second); err != nil {
		t.Fatalf("B write replay LoginReq: %v", err)
	}
	// server 应回 LinkTypeClose code=412。
	typC, payloadC, errC := readLinkFrameWithDeadline(clientB, 2*time.Second)
	if errC != nil {
		t.Fatalf("B read close frame: %v", errC)
	}
	if typC != util.LinkTypeClose {
		t.Fatalf("B 期望 LinkTypeClose(7), 实际 typ=%d", typC)
	}
	// CloseMsg 是 JSON {"code":412,"reason":"pow failed"}。
	var closeMsg struct {
		Code int `json:"code"`
	}
	if errJ := json.Unmarshal(payloadC, &closeMsg); errJ != nil {
		t.Fatalf("B Close 解析: %v", errJ)
	}
	if closeMsg.Code != util.CodePowFailed {
		t.Fatalf("B 期望 code=412 (CodePowFailed), 实际 code=%d", closeMsg.Code)
	}
}

// TestPoWE2E_ParseFailureUniformResponse:**parse failure 路径与其它 PoW 失败 wire 同形**(反指纹)。
//
// PoW handshake 通过后,attacker 故意发恶意 JSON 作为 LoginReq。
// round-3 scan 之前的实现这条路径发 LinkTypeLoginResp(2) + Code=1,跟其它 PoW
// 失败发的 LinkTypeClose(7) + Code=412 wire 形态不同 — attacker 据此分辨"PoW 通过
// 但 JSON 解析错"这个状态。修复后:统一发 LinkTypeClose + Code=412 + reason=""
// (同其它 PoW 失败完全一致)+ MarkFailure(IP)。
func TestPoWE2E_ParseFailureUniformResponse(t *testing.T) {
	resetServerGlobals(t)
	gw := newPoWTestGateway(t)
	clientEnd, _ := startHandlePipe(t, gw)

	// 1. 正常跑 PoW handshake(通过)。
	_ = runClientPoWHandshake(t, clientEnd)

	// 2. 故意发完全不合法的 JSON 作为 LoginReq。
	malformed := []byte(`{not-json-at-all`)
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, malformed, 2*time.Second); err != nil {
		t.Fatalf("write malformed LoginReq: %v", err)
	}

	// 3. server 必须回 LinkTypeClose(7) + code=412,**不是** LinkTypeLoginResp(2)。
	typ, payload, errR := readLinkFrameWithDeadline(clientEnd, 2*time.Second)
	if errR != nil {
		t.Fatalf("read close: %v", errR)
	}
	if typ != util.LinkTypeClose {
		t.Fatalf("反指纹失败:期望 LinkTypeClose(7),实际 typ=%d(可能是历史的 LoginResp=2 路径未修复)", typ)
	}
	var msg struct {
		Code   int    `json:"code"`
		Reason string `json:"reason"`
	}
	if errJ := json.Unmarshal(payload, &msg); errJ != nil {
		t.Fatalf("解析 close 帧: %v", errJ)
	}
	if msg.Code != util.CodePowFailed {
		t.Fatalf("期望 code=412(CodePowFailed),实际 code=%d", msg.Code)
	}
	if msg.Reason != "" {
		t.Fatalf("反指纹:reason 应为空,实际 %q(round-2 已统一)", msg.Reason)
	}
}

// 留个 sentinel 让 file-level go vet 找得到这个文件没有 nil-import 残留。
var _ = json.Marshal
