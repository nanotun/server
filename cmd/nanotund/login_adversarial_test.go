package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 恶意客户端视角:把握手序列里每一步换成扫描器 / 攻击者会干的事,断言防线的**实际**反应。
//
// 为什么单开这一档 —— 到目前为止所有走 handleVPNLink 的测试(psk_login / login_storm /
// pow_e2e)扮的都是**守规矩的客户端**:每一帧格式对、顺序对、PoW 现算现用。可这台机器
// 挂在公网上,第一个连上来的往往是扫描器:首帧就是垃圾、声明一个巨大的帧体、把抓到的
// PoW 原样重放、自造一道题、发半条 JSON。这些路径全在认证之前,平时一个正常客户端永远
// 走不到,而它们一旦有洞就是远程可利用的。
//
// 这些防线代码和注释里都写着(pre-login 4KB 上限、首帧状态机、PoW 一次性消费、失败统一
// 回 close 412 反指纹),但从没人拿这样的流量真撞过一遍。这一档就是来撞的。
//
// 用 net.Pipe 直连 handleVPNLink,复用 psk_login_integration_test.go 的脚手架
// (runClientPoWHandshake / marshalLoginReqWithPoW / read+writeLinkFrameWithDeadline)。

// newAdversarialGateway 起一台预置了 alice/hunter2 的 gateway,返回它和自己的 store
// (审计断言要用)。一台 gateway 可以被 dialLink 拨上多条连接 —— 这正是「同一台服务器、
// 多条并发连接」的真实形态。
func newAdversarialGateway(t *testing.T) (*gatewayState, *store.Store) {
	t.Helper()
	ctx := t.Context()

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "adv.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	hash, err := auth.HashPSK("hunter2")
	if err != nil {
		t.Fatalf("HashPSK: %v", err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: hash, ExitAllowed: true}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return &gatewayState{cfg: &config.Config{}, store: st, authVerifier: auth.NewVerifier(st)}, st
}

// dialLink 往 gw 上拨一条 net.Pipe 连接,server 端进 handleVPNLink。
// 返回客户端这头和「server 已退出」信号。
func dialLink(t *testing.T, gw *gatewayState) (clientEnd net.Conn, serverDone <-chan struct{}) {
	t.Helper()
	srvEnd, cliEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleVPNLink(srvEnd, gw)
	}()
	t.Cleanup(func() { _ = cliEnd.Close() })
	return cliEnd, done
}

// newAdversarialLink 是「起一台 gw + 拨一条连接」的常用组合。
func newAdversarialLink(t *testing.T) (clientEnd net.Conn, serverDone <-chan struct{}) {
	t.Helper()
	gw, _ := newAdversarialGateway(t)
	return dialLink(t, gw)
}

// expectServerGone 断言 server 侧 handleVPNLink 在 d 内退出(连接被服务端断掉)。
func expectServerGone(t *testing.T, serverDone <-chan struct{}, d time.Duration, what string) {
	t.Helper()
	select {
	case <-serverDone:
	case <-time.After(d):
		t.Fatalf("%s:handleVPNLink 没在 %s 内退出(连接没被断掉)", what, d)
	}
}

// expectClose412 断言客户端读到的下一帧是 LinkTypeClose 且 code=412(CodePowFailed)。
// PoW 相关的失败——重放 / 伪造签名 / 错 nonce / LoginReq 解析失败——刻意都走这一个出口
// (server.go:2937 反指纹注释),attacker 在 wire 上分辨不出自己错在哪一步。
func expectClose412(t *testing.T, clientEnd net.Conn, what string) {
	t.Helper()
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second)
	if err != nil {
		t.Fatalf("%s:期望收到 close 帧,却读失败:%v", what, err)
	}
	if typ != util.LinkTypeClose {
		t.Fatalf("%s:帧类型=%d,期望 LinkTypeClose(%d)", what, typ, util.LinkTypeClose)
	}
	msg, err := util.ParseCloseLinkPayload(payload)
	if err != nil {
		t.Fatalf("%s:close 帧解析失败:%v\n%s", what, err, payload)
	}
	if msg.Code != util.CodePowFailed {
		t.Fatalf("%s:close code=%d,期望 %d(CodePowFailed)", what, msg.Code, util.CodePowFailed)
	}
}

// TestAdversarial_FirstFrameNotPoWChallengeReq:首帧不是 PoWChallengeReq 一律静默断开。
//
// 状态机第一步(server.go:2865)硬性要求首帧 == PoWChallengeReq。老客户端发 LoginReq、
// 扫描器发 IP 包 / 垃圾类型,全落进 default 分支:**不回任何帧**,直接断。断言两点——
// 连接被断掉、且服务端一个字节都没回(不给扫描器留指纹)。
func TestAdversarial_FirstFrameNotPoWChallengeReq(t *testing.T) {
	cases := []struct {
		name string
		typ  byte
		body []byte
	}{
		{"首帧直接发 LoginReq(跳过 PoW)", util.LinkTypeLoginReq, []byte(`{"name":"alice","token":"hunter2"}`)},
		{"首帧发 IP 包(装成已登录)", util.LinkTypeIPPacket, []byte{0x45, 0, 0, 20}},
		{"首帧发未定义的类型", 0xFE, []byte("scan")},
		{"首帧发 LoginResp(装服务端)", util.LinkTypeLoginResp, []byte(`{"code":0}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetServerGlobals(t)
			clientEnd, serverDone := newAdversarialLink(t)

			if err := writeLinkFrameWithDeadline(clientEnd, tc.typ, tc.body, 2*time.Second); err != nil {
				t.Fatalf("写首帧:%v", err)
			}
			// 服务端应当无声断开:这里读到的必须是 EOF / 连接错,而不是任何一帧。
			if typ, _, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second); err == nil {
				t.Fatalf("期望连接被静默断开,却收到一帧 typ=%d(服务端不该回话)", typ)
			}
			expectServerGone(t, serverDone, 3*time.Second, tc.name)
		})
	}
}

// TestAdversarial_OversizedPreLoginFrame:登录前声明一个超过 4KB 的帧体,应在分配内存前就被拒。
//
// 帧体长度是 2 字节前缀,物理上限 64KB;登录前更被压到 MaxPreLoginFrameBody=4KB
// (server.go:2850 的 I5)。攻击者声明一个大帧、诱导服务端 make([]byte, L) 撑内存,是经典
// 手法。这里直接在线上写一个前缀 = 5000 的裸帧:readLinkFrameLimited 读到长度就判超限、
// 立刻报错,**不会**走到那句 make。断言服务端读一眼长度就断开。
func TestAdversarial_OversizedPreLoginFrame(t *testing.T) {
	resetServerGlobals(t)
	clientEnd, serverDone := newAdversarialLink(t)

	// 声明 5000 字节(> 4096),但一个字节的 body 都不打算真发 —— 撑内存的攻击本就靠
	// 「声明得大、发得少」。前缀被服务端读走(io.ReadFull(lb) 消费 2 字节)后即判超限。
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], 5000)
	_ = clientEnd.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientEnd.Write(prefix[:]); err != nil {
		t.Fatalf("写超大帧长度前缀:%v", err)
	}
	_ = clientEnd.SetWriteDeadline(time.Time{})

	if typ, _, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second); err == nil {
		t.Fatalf("期望超大帧被拒后断开,却收到一帧 typ=%d", typ)
	}
	expectServerGone(t, serverDone, 3*time.Second, "超大 pre-login 帧")
}

// TestAdversarial_PoWReplayAcrossConnections:抓到一份用过的 PoW,换条连接原样重放 → close 412。
//
// PoW 挑战由服务端签发、一次性消费(powUsed map,pow.go:458)。攻击者抓一份别人算好的 PoW
// 重投,是绕过工作量证明最省事的想法。这里让连接 A 正常用掉一份 PoW,再让连接 B 携带同一份
// 去登录:VerifyPoWProof 签名过得去(确是服务端签的),但 challenge_id 已在表里 → replay → 412。
// 关键断言:B **建不成第二个会话**,收到的是 close 412。
func TestAdversarial_PoWReplayAcrossConnections(t *testing.T) {
	resetServerGlobals(t)
	gw, st := newAdversarialGateway(t) // 一台服务器,下面两条连接都打向它

	// 连接 A:正常握手 + 登录成功,把这份 PoW「用掉」。
	connA, doneA := dialLink(t, gw)
	powA := runClientPoWHandshake(t, connA)
	bodyA, _ := marshalLoginReqWithPoW("alice", "hunter2", "c", "linux", "tcp",
		"11111111-2222-4333-8444-555555555555", "A", powA)
	if err := writeLinkFrameWithDeadline(connA, util.LinkTypeLoginReq, bodyA, 2*time.Second); err != nil {
		t.Fatalf("A 写 LoginReq:%v", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(connA, 3*time.Second)
	if err != nil {
		t.Fatalf("A 读 LoginResp:%v", err)
	}
	if typ != util.LinkTypeLoginResp {
		t.Fatalf("A 首帧 typ=%d,期望 LoginResp", typ)
	}
	var respA util.LoginResp
	_ = json.Unmarshal(payload, &respA)
	if respA.Code != util.CodeOK {
		t.Fatalf("A 登录应成功,却 code=%d(%s)", respA.Code, respA.Message)
	}
	_ = connA.Close()
	<-doneA

	// 连接 B:状态机仍强制先发 PoWChallengeReq,读回新题后**丢掉**,改投 A 用过的那份。
	connB, doneB := dialLink(t, gw)
	if err := writeLinkFrameWithDeadline(connB, util.LinkTypePoWChallengeReq, nil, 2*time.Second); err != nil {
		t.Fatalf("B 写 PoWChallengeReq:%v", err)
	}
	if _, _, err := readLinkFrameWithDeadline(connB, 3*time.Second); err != nil {
		t.Fatalf("B 读新挑战:%v", err)
	}
	bodyB, _ := marshalLoginReqWithPoW("alice", "hunter2", "c", "linux", "tcp",
		"99999999-2222-4333-8444-555555555555", "B", powA) // ← 重放 A 的 PoW
	if err := writeLinkFrameWithDeadline(connB, util.LinkTypeLoginReq, bodyB, 2*time.Second); err != nil {
		t.Fatalf("B 写 LoginReq(重放):%v", err)
	}
	expectClose412(t, connB, "PoW 跨连接重放")
	expectServerGone(t, doneB, 3*time.Second, "PoW 跨连接重放")

	// 反假绿的关键一步:光看 412 不够 —— 新题没解也会回 412。查审计,确认 B 的失败原因
	// 确实是「challenge 已被消费」(重放),而不是碰巧被别的关卡拦下。ErrPoWReplay 的
	// 文案由 server.go:2972 原样写进 detail。
	logs, err := st.QueryAudit(t.Context(), 0, time.Now().Add(time.Hour).Unix(), 100)
	if err != nil {
		t.Fatalf("查审计:%v", err)
	}
	var sawReplay bool
	for _, l := range logs {
		if strings.Contains(l.Detail, "already consumed") {
			sawReplay = true
			break
		}
	}
	if !sawReplay {
		t.Fatalf("审计里没有 replay 记录 —— B 的 412 可能来自别的原因(假绿)。审计:%+v", logs)
	}
}

// TestAdversarial_ForgedPoW:不问服务端要题,自造一道 PoW → 签名对不上 → close 412。
//
// 挑战用服务端 HMAC key 签名(pow.go:376)。攻击者若想跳过「先要题」,只能自己编一个
// challenge_id + signature。HMAC 校验第一关就拦下。断言:自造 PoW 一律 412。
func TestAdversarial_ForgedPoW(t *testing.T) {
	resetServerGlobals(t)
	clientEnd, serverDone := newAdversarialLink(t)

	// 首帧仍按状态机要求发 PoWChallengeReq,读回真题后无视它,提交自造的一份。
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypePoWChallengeReq, nil, 2*time.Second); err != nil {
		t.Fatalf("写 PoWChallengeReq:%v", err)
	}
	if _, _, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second); err != nil {
		t.Fatalf("读挑战:%v", err)
	}
	forged := util.LoginReqPoW{
		ChallengeID: "deadbeefdeadbeef",
		Salt:        base64.StdEncoding.EncodeToString(make([]byte, powSaltBytes)),
		Difficulty:  8,
		ExpiresAt:   time.Now().Add(5 * time.Minute).Unix(),
		Signature:   base64.StdEncoding.EncodeToString([]byte("not-a-real-hmac")),
		Nonce:       0,
	}
	body, _ := marshalLoginReqWithPoW("alice", "hunter2", "c", "linux", "tcp",
		"11111111-2222-4333-8444-555555555555", "forge", forged)
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 2*time.Second); err != nil {
		t.Fatalf("写自造 PoW 的 LoginReq:%v", err)
	}
	expectClose412(t, clientEnd, "自造 PoW")
	expectServerGone(t, serverDone, 3*time.Second, "自造 PoW")
}

// TestAdversarial_WrongNonce:拿到真题,但提交一个不满足难度的 nonce → 数学校验挂 → close 412.
//
// 签名有效(确是服务端的题),但 nonce 没做够工作量。这一路验的是「拿了题不干活」也过不去。
func TestAdversarial_WrongNonce(t *testing.T) {
	resetServerGlobals(t)
	clientEnd, serverDone := newAdversarialLink(t)

	pow := runClientPoWHandshake(t, clientEnd)
	pow.Nonce = 0 // 覆盖成几乎必然不满足前导零比特要求的解
	body, _ := marshalLoginReqWithPoW("alice", "hunter2", "c", "linux", "tcp",
		"11111111-2222-4333-8444-555555555555", "badnonce", pow)
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 2*time.Second); err != nil {
		t.Fatalf("写错 nonce 的 LoginReq:%v", err)
	}
	expectClose412(t, clientEnd, "错误 nonce")
	expectServerGone(t, serverDone, 3*time.Second, "错误 nonce")
}

// TestAdversarial_GarbageLoginReqJSON:PoW 帧位置发半条 JSON → 解析失败也回 close 412。
//
// LoginReq 的 JSON 里裹着 PoW;body 是垃圾时,ParseLoginReqLinkPayload 在验 PoW 之前就挂
// (server.go:2935)。这一路刻意与 PoW 失败**回同样的 close 412**(反指纹),让攻击者分辨不出
// 自己卡在解析还是卡在 PoW。断言 code 一致即验证了这条反指纹性质。
func TestAdversarial_GarbageLoginReqJSON(t *testing.T) {
	resetServerGlobals(t)
	clientEnd, serverDone := newAdversarialLink(t)

	// 先按状态机发 PoWChallengeReq、读回题(才走得到解析 LoginReq 那一步)。
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypePoWChallengeReq, nil, 2*time.Second); err != nil {
		t.Fatalf("写 PoWChallengeReq:%v", err)
	}
	if _, _, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second); err != nil {
		t.Fatalf("读挑战:%v", err)
	}
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, []byte("{{{ not json at all"), 2*time.Second); err != nil {
		t.Fatalf("写垃圾 LoginReq:%v", err)
	}
	expectClose412(t, clientEnd, "垃圾 LoginReq JSON")
	expectServerGone(t, serverDone, 3*time.Second, "垃圾 LoginReq JSON")
}

// TestAdversarial_PreLoginIdleTimeout:连上来一言不发,应被 pre-login 空闲超时踢掉。
//
// 完成传输层握手后挂着不发任何帧,是最省事的 slowloris 式 DoS —— 每条连接吃一个
// goroutine + 一个 fd,攒够了就拖垮服务。handleVPNLink 起手就设了 preLoginIdleTimeout
// 这道闸(server.go),生产 30s。这里把它压到 300ms 来验:静默连接确实会被服务端断掉,
// 且是超时踢的(不是我们自己关的)。
//
// 这道防线此前零覆盖 —— 万一重构时把那句 SetDeadline 丢了,没有任何测试会红,而后果
// 正是它要挡的那种挂死连接。
func TestAdversarial_PreLoginIdleTimeout(t *testing.T) {
	resetServerGlobals(t)

	prev := preLoginIdleTimeout
	preLoginIdleTimeout = 300 * time.Millisecond
	t.Cleanup(func() { preLoginIdleTimeout = prev })

	clientEnd, serverDone := newAdversarialLink(t)
	_ = clientEnd // 故意什么都不发,就挂着

	// 超时是 300ms,给足余量到 3s:服务端到点应主动断开,handleVPNLink 随之返回。
	expectServerGone(t, serverDone, 3*time.Second, "pre-login 空闲超时")
}
