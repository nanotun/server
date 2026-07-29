package main

// 登录握手路径上「熵源故障」的三条分支。
//
// 这三条分支平时永远不跑,但它们决定了熵源坏掉时 server 是**拒绝**还是**放行**。放行的后果
// 比拒绝严重得多,而且都不报错:
//
//   - 出题失败时若继续往下走,客户端拿到的是一道 salt/challenge_id 为零值的题 —— 全部客户端
//     算的是同一道题,重放防护(按 challenge_id 去重)也随之失效;
//   - connIDStr 生成失败(空串)时若照常注册,所有这类会话都以 "" 为键挤在 connIDMap 的同一格,
//     后来的顶掉先来的:两台机器都以为自己在线,数据面 demux 只认得一条,另一条静默黑洞。
//
// 出题难度的夹取同理:难度是**写进链路帧给客户端算**的,超出协议窗口([powMinDifficulty,
// powMaxDifficulty])客户端要么算到超时、要么一次就过 —— 前者是全站登不进来,后者是防护形同未做。

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

var errEntropyGone = errors.New("熵源故障")

// failEntropy 让本用例期间的指定熵源恒失败。
func failEntropy(t *testing.T, which *func([]byte) (int, error)) {
	t.Helper()
	prev := *which
	*which = func([]byte) (int, error) { return 0, errEntropyGone }
	t.Cleanup(func() { *which = prev })
}

// readCloseFrame 读一帧并要求它是 Close,返回 code 与 reason。
func readCloseFrame(t *testing.T, c net.Conn) (int, string) {
	t.Helper()
	typ, payload, err := readLinkFrameWithDeadline(c, 10*time.Second)
	if err != nil {
		t.Fatalf("等 Close 帧: %v", err)
	}
	if typ != util.LinkTypeClose {
		t.Fatalf("typ=%d,期望 Close(%d)", typ, util.LinkTypeClose)
	}
	var msg struct {
		Code   int    `json:"code"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(payload, &msg); err != nil {
		t.Fatalf("解析 Close body %q: %v", payload, err)
	}
	return msg.Code, msg.Reason
}

// TestHandleVPNLink_ChallengeEntropyFailureRefusesTheConnection
// 出题时熵源坏掉 → 必须回 500 并断开,不能带着一道零值的题往下走。
func TestHandleVPNLink_ChallengeEntropyFailureRefusesTheConnection(t *testing.T) {
	env := newStormEnv(t, 1)
	// 先把 lazy fallback 建出来:它的构造也要熵(HMAC key),而构造失败是 Fatal —— 那会连
	// 测试进程一起带走,验不到本用例要验的东西。生产里这只在启动期发生一次。
	_ = env.gw.effectivePoWService()
	failEntropy(t, &powRandRead)

	serverEnd, clientEnd := net.Pipe()
	defer func() { _ = clientEnd.Close() }()
	goHandleVPNLink(&stormConn{Conn: serverEnd, remote: stormAddr(1)}, env.gw)

	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypePoWChallengeReq, nil, 10*time.Second); err != nil {
		t.Fatalf("发 PoWChallengeReq: %v", err)
	}

	code, reason := readCloseFrame(t, clientEnd)
	if code != util.CodeServerError {
		t.Errorf("出题失败应回 %d(服务端错误),got %d —— 回 PoW 相关码会让客户端一直重试同一条死路",
			util.CodeServerError, code)
	}
	// 反指纹:内部失败细节不上 wire(见 writeCloseAndReturn 注释)。
	if reason != "" {
		t.Errorf("Close 的 reason 应留空,got %q", reason)
	}
	// 绝不能有 PoWChallenge 帧先漏出去。
	if typ, _, err := readLinkFrameWithDeadline(clientEnd, 500*time.Millisecond); err == nil {
		t.Errorf("Close 之后还收到一帧 typ=%d —— 出题失败时不该有任何题下发", typ)
	}
}

// TestHandleVPNLink_SessionIDEntropyFailureRejectsBeforeRegistering
// PoW 都过了,却在生成 connIDStr 时熵源坏掉 → 必须回 500 且**不注册**会话、不分配 vIP。
//
// 这条是本文件里最要紧的:空 connIDStr 若被注册,connIDMap 的键就是 "",第二条同样情况的
// 会话会把第一条顶掉,而两边客户端都收到了成功的 LoginResp。
func TestHandleVPNLink_SessionIDEntropyFailureRejectsBeforeRegistering(t *testing.T) {
	env := newStormEnv(t, 1)
	u := env.users[0]

	beforeConns := activeConnCount()
	failEntropy(t, &util.IDRandRead)

	serverEnd, clientEnd := net.Pipe()
	defer func() { _ = clientEnd.Close() }()
	goHandleVPNLink(&stormConn{Conn: serverEnd, remote: stormAddr(2)}, env.gw)

	pow, err := stormPoW(clientEnd)
	if err != nil {
		t.Fatalf("PoW 握手: %v", err)
	}
	body, err := marshalLoginReqWithPoW(u.name, u.psk, "client", "linux", "tcp",
		"11111111-2222-3333-4444-555555555555", "entropy-probe", pow)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 10*time.Second); err != nil {
		t.Fatalf("发 LoginReq: %v", err)
	}

	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 20*time.Second)
	if err != nil {
		t.Fatalf("等 LoginResp: %v", err)
	}
	if typ != util.LinkTypeLoginResp {
		t.Fatalf("typ=%d,期望 LoginResp", typ)
	}
	var resp util.LoginResp
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != util.CodeServerError {
		t.Fatalf("connIDStr 生成失败应回 %d,got code=%d msg=%q —— "+
			"放行会让所有这类会话以空串为键挤在 connIDMap 同一格里互相顶掉",
			util.CodeServerError, resp.Code, resp.Message)
	}

	// 不许留下任何会话痕迹(尤其是键为 "" 的那一条)。
	deadline := time.Now().Add(5 * time.Second)
	for {
		connIDMapMu.RLock()
		_, blank := connIDMap[""]
		n := len(connIDMap)
		connIDMapMu.RUnlock()
		if blank {
			t.Fatal("connIDMap 里出现了键为空串的会话 —— 第二条同样的连接会把它顶掉,两边都以为自己在线")
		}
		if n == beforeConns {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("被拒的连接留下了会话:connIDMap 从 %d 变成 %d", beforeConns, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func activeConnCount() int {
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	return len(connIDMap)
}

// TestHandleVPNLink_UnwritableChallengeIsNotChargedToTheClientsIPBudget
// 题算出来了但写不出去(客户端半途走了)→ 只是收摊,不能给这个 IP 记一次 PoW 失败。
//
// 记了的后果:下一次真正的登录会被按「失败 ≥ failures_enable」拉到 ramp 难度,而这个 IP 什么
// 都没做错 —— NAT 后一个人反复闪断,同出口的所有人跟着变难。
func TestHandleVPNLink_UnwritableChallengeIsNotChargedToTheClientsIPBudget(t *testing.T) {
	env := newStormEnv(t, 1)
	svc := env.gw.effectivePoWService()
	remote := stormAddr(3)
	ipHost, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		t.Fatal(err)
	}
	before := svc.failures.Count(ipHost)

	serverEnd, clientEnd := net.Pipe()
	// 这条要**等 handler 真的退出**再断言:记账发生在写失败之后,查得太早的话不管有没有记都还没发生
	// (这条变异第一版就是这么逃掉的),所以自己拿一个 done 等它。
	done := make(chan struct{})
	vpnLinkHandlers.Add(1)
	go func() {
		defer vpnLinkHandlers.Done()
		defer close(done)
		handleVPNLink(&stormConn{Conn: serverEnd, remote: remote}, env.gw)
	}()

	// net.Pipe 是同步的:这一帧写完说明 server 已经读走了,它下一步就是写 challenge。
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypePoWChallengeReq, nil, 10*time.Second); err != nil {
		t.Fatalf("发 PoWChallengeReq: %v", err)
	}
	_ = clientEnd.Close() // 此刻走人 → server 写 challenge 必然失败

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("写 challenge 失败后 handler 没退出")
	}
	if got := svc.failures.Count(ipHost); got != before {
		t.Errorf("写 challenge 失败被记成了 %d 次 IP 失败(原 %d)—— 那会把下一次登录的难度拉到 ramp 档,"+
			"而这个 IP 只是断线", got, before)
	}
}

// TestComputeDifficulty_NeverLeavesTheProtocolWindow
// 难度必须落在 [powMinDifficulty, powMaxDifficulty]:它要写进链路帧给客户端算。
// 越上界 → 客户端算到超时,表现为「全站登不进来」;越下界 → 一次就过,防护形同未做。
// 越界字段进不来 NewPoWService(它对 base/ramp/ceiling 做 fail-fast,见那里的注释),所以这里
// 直接拿结构体构造 —— 要钉的正是「不管字段怎么来的,ComputeDifficulty 自己绝不吐出窗口外的难度」
// 这条最后防线:它每条连接都跑一次,而难度一旦出窗,客户端那侧只会表现成登不进来。
func TestComputeDifficulty_NeverLeavesTheProtocolWindow(t *testing.T) {
	tooHigh := &PoWService{
		failuresEnable:  1,
		baseDifficulty:  8,
		rampDifficulty:  powMaxDifficulty + 10,
		stepPerFailure:  5,
		adaptiveCeiling: powMaxDifficulty + 50,
	}
	if d := tooHigh.ComputeDifficulty(100); d > powMaxDifficulty {
		t.Errorf("难度 %d 越过协议上界 %d —— 客户端会算到超时,现象是所有人都登不进来", d, powMaxDifficulty)
	}

	// 反方向:ramp 档被压到下界以下,也必须抬回来。
	tooLow := &PoWService{
		failuresEnable:  1,
		baseDifficulty:  powMinDifficulty,
		rampDifficulty:  -5,
		stepPerFailure:  0,
		adaptiveCeiling: -1,
	}
	if d := tooLow.ComputeDifficulty(100); d < powMinDifficulty {
		t.Errorf("难度 %d 低于协议下界 %d —— 一次就能算出来,PoW 等于没做", d, powMinDifficulty)
	}
}

// TestNewPoWService_EntropyFailureIsAnErrorNotAZeroKey
// HMAC key 生成失败必须报错。退回全零 key 的后果是签名可离线伪造:attacker 自己签一道
// 难度 1 的题,server 验签通过 → PoW 整层被绕过,而日志里一切正常。
func TestNewPoWService_EntropyFailureIsAnErrorNotAZeroKey(t *testing.T) {
	failEntropy(t, &powRandRead)
	if svc, err := NewPoWService(nil, nil, 0, 8, 14, 2, 22, 300); err == nil {
		t.Fatalf("熵源故障却建出了服务(svc=%v)—— 全零 HMAC key 让 challenge 签名可被离线伪造", svc)
	}
}

// TestIssueChallenge_EntropyFailureYieldsNoChallengeAtAll
// 出题的两处熵源(challenge_id、salt)任一失败都不能给出半成品:zero 值的 challenge_id
// 会让防重放表把所有客户端并成一格,zero salt 则让所有人算同一道题。
func TestIssueChallenge_EntropyFailureYieldsNoChallengeAtAll(t *testing.T) {
	svc, err := NewPoWService(nil, nil, 0, 8, 14, 2, 22, 300)
	if err != nil {
		t.Fatal(err)
	}
	// 只让第 n 次调用失败(n=1 打在 challenge_id 上,n=2 打在 salt 上),其余照常给随机数。
	// 「第 n 次起全都失败」是不行的:那样 n=1 时 salt 也失败,是 salt 那道检查把错误报了出来 ——
	// challenge_id 自己那道检查有没有在,断言看不出来(实测这条变异就是这么逃掉的)。
	for _, failAt := range []int{1, 2} {
		calls := 0
		prev := powRandRead
		powRandRead = func(b []byte) (int, error) {
			calls++
			if calls == failAt {
				return 0, errEntropyGone
			}
			return prev(b)
		}
		ch, err := svc.IssueChallenge(12)
		powRandRead = prev
		if err == nil {
			t.Errorf("第 %d 处熵源失败却出题成功了: %+v", failAt, ch)
			continue
		}
		if ch.ChallengeID != "" || ch.Salt != "" {
			t.Errorf("第 %d 处失败时返回了半成品的题: %+v", failAt, ch)
		}
	}
}
