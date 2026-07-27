package main

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 本文件补 handleTakeoverLogin 的授权边界。
//
// 接管是整个服务里唯一「不走完整登录也能拿到一条在线会话」的入口:客户端热切换传输
// (hy2 ↔ wss)时不重新分配 vIP、不重建会话身份,只把底层链路换掉。凭证是
// (session_id, takeover_secret) + PSK 三件套。三道门任何一道判松,攻击者拿一半凭证
// 就能接管别人的会话;判紧则合法客户端每次弱网切换都掉线。
//
// e2e 只走成功路径(客户端库自己发起热切换),所有拒绝分支在真实流量里都不出现,
// 因此这些用例是纯增量,不与三机回归重叠。

// takeoverFailWireMsgWant 是所有失败分支对**线路**统一回的泛化文案。
//
// server.go 里那个 const 在函数体内,包外/包内都取不到,只能照抄。抄一份反而正好:
// 它一旦被改回「各分支各说各话」,这里就红 —— 而那正是要防的 oracle(持某 sid 的攻击者
// 靠区分 "session not found" / "secret mismatch" / "already taken over" 就能反推该 sid
// 是否在线、secret 是否命中)。
const takeoverFailWireMsgWant = "takeover failed"

const (
	takeoverTestSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	takeoverTestIPHost = "203.0.113.77"
	victimPSK          = "victim-psk-correct"
	attackerPSK        = "attacker-psk-correct"
)

type takeoverFixture struct {
	gw      *gatewayState
	st      *store.Store
	tracker *IPFailureTracker
	oldConn *Connection
	sid     string
}

// newTakeoverFixture 造一条「victim 的在线会话」+ 一个独立的 attacker 账号。
// 每个子测试都要一份新的:tracker 和 audit_logs 都是累计量,共用会串台。
func newTakeoverFixture(t *testing.T) *takeoverFixture {
	t.Helper()
	resetServerGlobals(t)
	gw, st := newPSKGateway(t)
	ctx := t.Context()

	tracker := NewIPFailureTracker()
	pow, err := NewPoWService(nil, tracker, 0, 8, 14, 2, 22, 300)
	if err != nil {
		t.Fatalf("NewPoWService: %v", err)
	}
	gw.powService = pow

	for _, u := range []struct{ name, psk string }{{"victim", victimPSK}, {"attacker", attackerPSK}} {
		hash, herr := auth.HashPSK(u.psk)
		if herr != nil {
			t.Fatalf("HashPSK(%s): %v", u.name, herr)
		}
		if _, cerr := st.CreateUser(ctx, store.NewUser{Username: u.name, PSKHash: hash}); cerr != nil {
			t.Fatalf("CreateUser(%s): %v", u.name, cerr)
		}
	}

	sid := "takeover-guard-sid"
	oldConn := &Connection{
		connIDStr:      sid,
		userID:         storeUserID(t, st, "victim"),
		linkConn:       &routeFakeConn{}, // 缓冲写:给老链路的 TakenOver 通知不阻塞
		takeoverSecret: takeoverTestSecret,
		tunnelDone:     make(chan struct{}),
	}
	ips := []util.VirtualIPAssignment{{
		VirtualIP: "10.203.0.9",
		Mask:      "255.255.0.0",
		Gateway:   "10.203.0.1/16",
		TunChan:   make(chan *util.TunPacket, 4),
	}}
	oldConn.clientIPs.Store(&ips)

	connIDMapMu.Lock()
	connIDMap[sid] = oldConn
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		if cur, ok := connIDMap[sid]; ok && cur == oldConn {
			delete(connIDMap, sid)
		}
		connIDMapMu.Unlock()
	})

	return &takeoverFixture{gw: gw, st: st, tracker: tracker, oldConn: oldConn, sid: sid}
}

func storeUserID(t *testing.T, st *store.Store, username string) string {
	t.Helper()
	u, err := st.GetUserByUsername(t.Context(), username)
	if err != nil {
		t.Fatalf("GetUserByUsername(%s): %v", username, err)
	}
	return userIDFromStoreID(u.ID)
}

// runTakeover 在后台跑 handleTakeoverLogin,读回它写给客户端的那一帧,再等它退出。
func runTakeover(t *testing.T, fx *takeoverFixture, req *util.LoginReq) *util.LoginResp {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTakeoverLogin(serverConn, fx.gw, req, "test-remote", takeoverTestIPHost)
	}()
	resp := readResp(t, clientConn)
	awaitDone(t, done)
	return resp
}

// auditActions 取本次测试写下的全部审计动作名。
func auditActions(t *testing.T, st *store.Store) []string {
	t.Helper()
	logs, err := st.QueryAudit(t.Context(), 0, time.Now().Unix()+60, 1000)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	out := make([]string, 0, len(logs))
	for _, l := range logs {
		out = append(out, l.Action)
	}
	return out
}

func hasAction(actions []string, want string) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}

// TestHandleTakeoverLogin_EveryRejectionLooksIdenticalOnTheWire 一次压三条不变量:
//
//  1. **线路上无 oracle**:八条拒绝分支回给客户端的 message 必须逐字相同,且不回 user_id。
//     真实原因只进服务端 audit_logs。
//  2. **审计记得清**:每条分支写下自己那条 reason —— 运维排障和事后取证只有这一个来源,
//     写错了 reason 等于没写。
//  3. **PoW 惩罚只打攻击者**:枚举 sid / 试 secret / 试 PSK / 跨用户接管要抬高该 IP 的下次
//     PoW 难度;而空 session_id、重复接管、被 supersede 这些是合法客户端在弱网下也会发的,
//     惩罚它们等于让掉线用户越掉越难连回来。
func TestHandleTakeoverLogin_EveryRejectionLooksIdenticalOnTheWire(t *testing.T) {
	cases := []struct {
		name string
		// arrange 在发请求前改 oldConn 的状态;req 造这次接管请求。
		arrange     func(fx *takeoverFixture)
		req         func(fx *takeoverFixture) *util.LoginReq
		wantReason  string
		wantPenalty bool
		because     string
	}{
		{
			name: "session_id 为空",
			req: func(fx *takeoverFixture) *util.LoginReq {
				return &util.LoginReq{Purpose: util.PurposeTakeover, TakeoverSecret: takeoverTestSecret, Transport: "hy2"}
			},
			wantReason:  "empty_session_id",
			wantPenalty: false,
			because:     "客户端 bug 也会发,不该让正常用户的 IP 被抬难度",
		},
		{
			name: "枚举不存在的 session_id",
			req: func(fx *takeoverFixture) *util.LoginReq {
				return makeTakeoverReq("no-such-sid-deadbeef", takeoverTestSecret, "hy2")
			},
			wantReason:  "session_not_found",
			wantPenalty: true,
			because:     "拿 sid 撞库探测哪些会话在线,是典型攻击前戏",
		},
		{
			name:    "会话已被接管过",
			arrange: func(fx *takeoverFixture) { fx.oldConn.takenOver.Store(true) },
			req: func(fx *takeoverFixture) *util.LoginReq {
				return makeTakeoverReq(fx.sid, takeoverTestSecret, "hy2")
			},
			wantReason:  "already_taken_over",
			wantPenalty: false,
			because:     "弱网下客户端重发接管很常见,是多发竞态不是攻击",
		},
		{
			name:    "会话已被同设备新登录 supersede",
			arrange: func(fx *takeoverFixture) { fx.oldConn.superseded.Store(true) },
			req: func(fx *takeoverFixture) *util.LoginReq {
				return makeTakeoverReq(fx.sid, takeoverTestSecret, "hy2")
			},
			wantReason:  "session_superseded",
			wantPenalty: false,
			because:     "正在被回收的会话不能接管,但这是良性竞态",
		},
		{
			name: "secret 传空串",
			req: func(fx *takeoverFixture) *util.LoginReq {
				return makeTakeoverReq(fx.sid, "", "hy2")
			},
			wantReason:  "empty_secret",
			wantPenalty: true,
			because:     "试空串是冲着 ConstantTimeCompare(\"\",\"\")==1 去的 bypass 尝试",
		},
		{
			name: "secret 不对",
			req: func(fx *takeoverFixture) *util.LoginReq {
				return makeTakeoverReq(fx.sid, strings.Repeat("f", 64), "hy2")
			},
			wantReason:  "secret_mismatch",
			wantPenalty: true,
			because:     "试错 secret",
		},
		{
			name: "有 sid+secret 但不知道 PSK",
			req: func(fx *takeoverFixture) *util.LoginReq {
				r := makeTakeoverReq(fx.sid, takeoverTestSecret, "hy2")
				r.Name, r.Token = "victim", "wrong-psk"
				return r
			},
			wantReason:  "psk_verify_fail",
			wantPenalty: true,
			because:     "这正是 PSK 二次校验存在的理由:从内存/抓包/日志里捞到 sid+secret 的人不该能接管",
		},
		{
			name: "拿自己的 PSK 去接管别人的会话",
			req: func(fx *takeoverFixture) *util.LoginReq {
				r := makeTakeoverReq(fx.sid, takeoverTestSecret, "hy2")
				r.Name, r.Token = "attacker", attackerPSK
				return r
			},
			wantReason:  "user_mismatch",
			wantPenalty: true,
			because:     "PSK 验的是「你是谁」,还得验「这条会话是不是你的」,否则有账号的人就能横向接管",
		},
	}

	var wireMsgs []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTakeoverFixture(t)
			if tc.arrange != nil {
				tc.arrange(fx)
			}

			resp := runTakeover(t, fx, tc.req(fx))

			if resp.Code == 0 {
				t.Fatalf("接管必须被拒(%s),却回了 code=0", tc.because)
			}
			if resp.Message != takeoverFailWireMsgWant {
				t.Fatalf("失败文案必须是统一的 %q,got %q —— 分支特异的文案就是 oracle",
					takeoverFailWireMsgWant, resp.Message)
			}
			if resp.UserID != "" {
				t.Fatalf("失败响应不该回 user_id,got %q", resp.UserID)
			}
			wireMsgs = append(wireMsgs, resp.Message)

			actions := auditActions(t, fx.st)
			wantAction := "login.takeover.fail." + tc.wantReason
			if !hasAction(actions, wantAction) {
				t.Fatalf("审计应记 %q,实际只有 %v", wantAction, actions)
			}
			if hasAction(actions, "login.takeover") {
				t.Fatalf("接管被拒却写了成功审计,actions=%v", actions)
			}

			got := fx.tracker.Count(takeoverTestIPHost)
			if tc.wantPenalty && got == 0 {
				t.Fatalf("应给 %s 记一次失败抬 PoW 难度(%s),计数仍是 0", takeoverTestIPHost, tc.because)
			}
			if !tc.wantPenalty && got != 0 {
				t.Fatalf("不该惩罚这条分支(%s),%s 的失败计数却成了 %d", tc.because, takeoverTestIPHost, got)
			}

			// 无论走哪条拒绝分支,连表都必须还指着老会话 —— 换了就等于接管成功了。
			connIDMapMu.RLock()
			cur := connIDMap[fx.sid]
			connIDMapMu.RUnlock()
			if tc.wantReason != "session_not_found" && tc.wantReason != "empty_session_id" && cur != fx.oldConn {
				t.Fatalf("拒绝接管后 connIDMap[sid] 应仍是 oldConn,却成了 %p", cur)
			}
			connectionsMu.RLock()
			n := len(connections)
			connectionsMu.RUnlock()
			if n != 0 {
				t.Fatalf("拒绝接管不该在 connections 里留下 newConn,残留 %d 条", n)
			}
		})
	}

	for i, m := range wireMsgs {
		if m != wireMsgs[0] {
			t.Fatalf("第 %d 条分支的线路文案与第 0 条不同(%q vs %q)", i, m, wireMsgs[0])
		}
	}
}

// TestHandleTakeoverLogin_RejectsWhenCleanupWonTheRaceForTakeoverMu 覆盖锁内 TOCTOU 复验。
//
// 「connIDMap 查到 oldConn」与「拿到 oldConn.takeoverMu」之间有一扇窗口:老链路可能刚断,
// cleanupConnection 抢先拿到锁跑完「!takenOver」分支 —— 它已经把 oldConn 摘出连表**并把 vIP
// 还回了空闲池**。此时若照常接管,新会话继承的是一批已回收的地址:TunChan 已关、ip2Channel
// 已注销,下行直接黑洞;更糟的是那些 vIP 可能已被分给另一台设备,变成双分配。
//
// 用「测试先持锁」把这条竞态钉成确定序:handler 必然阻塞在 Lock 上,此时替换连表,再放锁。
func TestHandleTakeoverLogin_RejectsWhenCleanupWonTheRaceForTakeoverMu(t *testing.T) {
	fx := newTakeoverFixture(t)
	intruder := &Connection{connIDStr: fx.sid, connID: 4242}

	fx.oldConn.takeoverMu.Lock()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		handleTakeoverLogin(serverConn, fx.gw,
			makeTakeoverReq(fx.sid, takeoverTestSecret, "hy2"), "test-remote", takeoverTestIPHost)
	}()

	<-started
	// handler 在阻塞前只做一次 map 读(微秒级),50ms 是四个数量级的余量。真滑出去了也不会
	// 静默通过:下面按 session_cleaned 断言 audit,落到别的分支会直接红。
	time.Sleep(50 * time.Millisecond)
	connIDMapMu.Lock()
	connIDMap[fx.sid] = intruder
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		if cur, ok := connIDMap[fx.sid]; ok && cur == intruder {
			delete(connIDMap, fx.sid)
		}
		connIDMapMu.Unlock()
	})
	fx.oldConn.takeoverMu.Unlock()

	if resp := readResp(t, clientConn); resp.Code == 0 || resp.Message != takeoverFailWireMsgWant {
		t.Fatalf("清理抢先时必须拒绝接管,got %+v", resp)
	}
	awaitDone(t, done)

	if !hasAction(auditActions(t, fx.st), "login.takeover.fail.session_cleaned") {
		t.Fatalf("应记 session_cleaned,实际 %v", auditActions(t, fx.st))
	}
	if fx.oldConn.takenOver.Load() {
		t.Fatal("拒绝接管却把 oldConn 标成了 takenOver —— 它的 cleanup 会因此跳过 vIP 回收")
	}
	if fx.tracker.Count(takeoverTestIPHost) != 0 {
		t.Fatal("断网重连撞上清理是良性竞态,不该抬这个 IP 的 PoW 难度")
	}
}

// TestHandleTakeoverLogin_RejectsWhenOldConnDiesDuringArgon2 覆盖 argon2 窗口之后的复验。
//
// secret 校验通过后代码**故意放锁**再跑 PSK verify:argon2 要数十 ms 且受全局信号量排队,
// 持锁跑它会把 victim 的 cleanupConnection 钉死整个时长,攻击者对同一 sid 猛发错 PSK 就是
// 一次针对该会话的局部 DoS。代价是 oldConn 在这段无锁期里可能被清理/接管/supersede,
// 全靠重加锁后的复验兜住。
//
// 用注入钩子停在窗口正中,而不是 sleep 去猜 argon2 跑多久 —— 机器一快就滑出窗口,
// 测试会静默变成 already_taken_over 那条路径的重复用例。
func TestHandleTakeoverLogin_RejectsWhenOldConnDiesDuringArgon2(t *testing.T) {
	fx := newTakeoverFixture(t)

	takeoverArgon2WindowHookForTest = func() {
		// 窗口正中:锁是放开的,模拟一次并发接管抢先过户。
		fx.oldConn.takeoverMu.Lock()
		fx.oldConn.takenOver.Store(true)
		fx.oldConn.takeoverMu.Unlock()
	}
	t.Cleanup(func() { takeoverArgon2WindowHookForTest = nil })

	req := makeTakeoverReq(fx.sid, takeoverTestSecret, "hy2")
	req.Name, req.Token = "victim", victimPSK

	resp := runTakeover(t, fx, req)
	if resp.Code == 0 || resp.Message != takeoverFailWireMsgWant {
		t.Fatalf("argon2 期间 oldConn 已被接管,必须拒绝,got %+v", resp)
	}
	if !hasAction(auditActions(t, fx.st), "login.takeover.fail.session_gone_after_verify") {
		t.Fatalf("应记 session_gone_after_verify,实际 %v", auditActions(t, fx.st))
	}
	connectionsMu.RLock()
	n := len(connections)
	connectionsMu.RUnlock()
	if n != 0 {
		t.Fatalf("放弃接管后不该有 newConn 残留,connections 还有 %d 条", n)
	}
	if fx.tracker.Count(takeoverTestIPHost) != 0 {
		t.Fatal("PSK 是对的,只是会话没了,不该按攻击者惩罚")
	}
}

// deadLinkConn 写满 okFrames 帧后开始报错。util.WriteLinkFrame 一帧一次 Write,
// 无限速器时 rateLimitedConn 是直通,所以「第几次 Write」就是「第几帧」。
type deadLinkConn struct {
	mu       sync.Mutex
	okFrames int
	writes   int
}

func (c *deadLinkConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes > c.okFrames {
		return 0, errors.New("链路已断")
	}
	return len(p), nil
}

func (c *deadLinkConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *deadLinkConn) Close() error                     { return nil }
func (c *deadLinkConn) LocalAddr() net.Addr              { return deadLinkAddr{} }
func (c *deadLinkConn) RemoteAddr() net.Addr             { return deadLinkAddr{} }
func (c *deadLinkConn) SetDeadline(time.Time) error      { return nil }
func (c *deadLinkConn) SetReadDeadline(time.Time) error  { return nil }
func (c *deadLinkConn) SetWriteDeadline(time.Time) error { return nil }

type deadLinkAddr struct{}

func (deadLinkAddr) Network() string { return "pipe" }
func (deadLinkAddr) String() string  { return "dead-link" }

// TestHandleTakeoverLogin_RollsBackWhenNewLinkDiesMidHandshake 覆盖握手两次写的失败回滚。
//
// 校验全过之后、连表切换之前,还要往新链路写 LoginResp 和 ConvSalt。新客户端此刻掉线是
// 常事(接管本来就常因链路变差才发起)。这两次写失败必须干净收场:newConn 已经在
// connections 表里占了一个 conv_id,漏回滚就是一条谁也清理不到的僵尸;而老会话此时还完好,
// 绝不能被标成 takenOver —— 那会让它自己的 cleanup 跳过 vIP 与 SessionRelease 回收。
func TestHandleTakeoverLogin_RollsBackWhenNewLinkDiesMidHandshake(t *testing.T) {
	for _, tc := range []struct {
		name     string
		okFrames int
	}{
		{"LoginResp 就写不出去", 0},
		{"LoginResp 写成了,ConvSalt 写不出去", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newTakeoverFixture(t)
			req := makeTakeoverReq(fx.sid, takeoverTestSecret, "hy2")
			req.Name, req.Token = "victim", victimPSK

			done := make(chan struct{})
			go func() {
				defer close(done)
				handleTakeoverLogin(&deadLinkConn{okFrames: tc.okFrames}, fx.gw, req,
					"test-remote", takeoverTestIPHost)
			}()
			awaitDone(t, done)

			connectionsMu.RLock()
			n := len(connections)
			connectionsMu.RUnlock()
			if n != 0 {
				t.Fatalf("握手写失败必须回滚 newConn 的占位,connections 仍有 %d 条(僵尸会话)", n)
			}
			if fx.oldConn.takenOver.Load() {
				t.Fatal("接管没完成却把老会话标成 takenOver,它的 vIP 与 session 名额将永久泄漏")
			}
			connIDMapMu.RLock()
			cur := connIDMap[fx.sid]
			connIDMapMu.RUnlock()
			if cur != fx.oldConn {
				t.Fatalf("连表应仍指向老会话,却成了 %p", cur)
			}
			if fx.tracker.Count(takeoverTestIPHost) != 0 {
				t.Fatal("凭证全对,只是新链路断了,不该按攻击者惩罚")
			}
		})
	}
}
