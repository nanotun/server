package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 本文件补 handleVPNLink 的拒绝分支。
//
// 登录主入口有四道闸:PoW 出题限速(per-IP + 全局)、per-IP 登录限速、PSK 认证、vIP 分配。
// e2e 走的是「合法客户端一次登录成功」,四道闸一道都不会响,所以这些分支在三机回归里
// 是纯空白。它们判错的后果又都是静默的:枚举 oracle 不会报错、限速失灵不会报错、
// 地址泄漏也不会报错,只会在某天池子耗尽时表现为「新用户连不上」。

// loginGateEnv 一套能跑完整登录握手的最小服务端。
type loginGateEnv struct {
	gw *gatewayState
	st *store.Store
}

func newLoginGateEnv(t *testing.T) *loginGateEnv {
	t.Helper()
	resetServerGlobals(t)
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "gate.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	hash, err := auth.HashPSK("right-psk")
	if err != nil {
		t.Fatalf("HashPSK: %v", err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{Username: "known", PSKHash: hash}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return &loginGateEnv{
		gw: &gatewayState{cfg: &config.Config{}, store: st, authVerifier: auth.NewVerifier(st)},
		st: st,
	}
}

// loginOnce 完整跑一遍「PoW 握手 → LoginReq → 读首帧回应」,返回服务端回的那一帧。
// remote 为 nil 时用 net.Pipe 自带的 "pipe" 地址。
func loginOnce(t *testing.T, env *loginGateEnv, remote net.Addr, name, psk string) (byte, []byte) {
	t.Helper()
	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()

	var srv net.Conn = serverEnd
	if remote != nil {
		srv = &stormConn{Conn: serverEnd, remote: remote}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleVPNLink(srv, env.gw)
	}()

	pow := runClientPoWHandshake(t, clientEnd)
	body, err := marshalLoginReqWithPoW(name, psk, "c", "linux", "tcp", "", "", pow)
	if err != nil {
		t.Fatalf("marshalLoginReqWithPoW: %v", err)
	}
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 3*time.Second); err != nil {
		t.Fatalf("写 LoginReq: %v", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second)
	if err != nil {
		t.Fatalf("读服务端回应: %v", err)
	}
	_ = clientEnd.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleVPNLink 未在 3s 内退出")
	}
	return typ, payload
}

func mustLoginResp(t *testing.T, typ byte, payload []byte) util.LoginResp {
	t.Helper()
	if typ != util.LinkTypeLoginResp {
		t.Fatalf("期望 LoginResp(%d),got %d", util.LinkTypeLoginResp, typ)
	}
	var r util.LoginResp
	if err := json.Unmarshal(payload, &r); err != nil {
		t.Fatalf("解 LoginResp: %v\n%s", err, payload)
	}
	return r
}

// TestHandleVPNLink_UnknownUserAndBadPSKAreIndistinguishable 锁死反枚举。
//
// 「这个用户名存不存在」是攻击者最想要的第一手情报:拿到有效用户名列表,后面的
// 撞库、社工、定向钓鱼才有目标。服务端内部当然要分得清(审计要能区分是有人在猜
// 用户名还是在撞某个账号的密码),但线路上必须一个字都不能差 —— code、message
// 全都一样,连帧类型都一样。
func TestHandleVPNLink_UnknownUserAndBadPSKAreIndistinguishable(t *testing.T) {
	env := newLoginGateEnv(t)

	typA, payA := loginOnce(t, env, stormAddr(1), "known", "wrong-psk")
	respA := mustLoginResp(t, typA, payA)

	typB, payB := loginOnce(t, env, stormAddr(2), "no-such-user", "whatever")
	respB := mustLoginResp(t, typB, payB)

	if respA.Code == 0 || respB.Code == 0 {
		t.Fatalf("两次都该失败,got %+v / %+v", respA, respB)
	}
	if respA.Code != respB.Code {
		t.Fatalf("「密码错」与「查无此人」的 code 不同(%d vs %d)—— 这就是用户名枚举 oracle",
			respA.Code, respB.Code)
	}
	if respA.Message != respB.Message {
		t.Fatalf("两者文案不同(%q vs %q)—— 同样是枚举 oracle", respA.Message, respB.Message)
	}
	if respA.UserID != "" || respB.UserID != "" {
		t.Fatalf("失败响应不该带 user_id: %q / %q", respA.UserID, respB.UserID)
	}

	// 服务端这边反过来必须分得清,否则运维看不出「有人在猜用户名」还是「在撞某个账号」。
	actions := auditActions(t, env.st)
	if !hasAction(actions, "login.fail.user_not_found") {
		t.Fatalf("审计应能区分出 user_not_found,实际 %v", actions)
	}
	if !hasAction(actions, "login.fail.bad_psk") {
		t.Fatalf("审计应能区分出 bad_psk,实际 %v", actions)
	}
}

// TestHandleVPNLink_PerIPLoginRateLimitKicksIn 覆盖 per-IP 登录闸门。
//
// PoW 挡的是「廉价灌包」,挡不住肯付出算力的撞库者 —— 解一道 8 bit 的题只要几毫秒。
// 真正给暴力破解设上限的是这道闸。它失灵不会有任何症状,直到有人把某个账号撞开。
//
// 限速值默认 0(不限),由 config 的 login_rate_limit_per_min 打开;测试里直接拨上去。
func TestHandleVPNLink_PerIPLoginRateLimitKicksIn(t *testing.T) {
	env := newLoginGateEnv(t)

	// 拨到 1/min 而不是 60/min:桶的补速是 rate/60 每秒,而一次完整登录(PoW + argon2)
	// 在 -race 下要一秒上下。配 60/min 就成了「补一个用一个」,测试永远撞不到限速,
	// 表现为随机超时的假失败。1/min 下 60 秒才补一个,burst 用完就是用完。
	globalLoginIPLimiter.SetRatePerMin(1)
	t.Cleanup(func() { globalLoginIPLimiter.SetRatePerMin(0) })

	attacker := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 51000}
	var limited util.LoginResp
	attempts := 0
	for i := 0; i < loginRLBurst+2; i++ {
		attempts++
		resp := badLogin(t, env, attacker)
		if resp.Code == 429 {
			limited = resp
			break
		}
	}
	if limited.Code != 429 {
		t.Fatalf("同一 IP 连撞 %d 次仍未被限速 —— 暴力破解没有上限了", attempts)
	}
	if limited.Message == "" {
		t.Fatal("429 应带一条可读文案,否则客户端只能表现为「无故失败」")
	}

	// 限速本身要留痕:事后按 IP 关联扫描/爆破行为,只有这一条记录。
	if !hasAction(auditActions(t, env.st), "login.fail.ratelimit") {
		t.Fatalf("429 应写 login.fail.ratelimit 审计,实际 %v", auditActions(t, env.st))
	}

	// 另一个来源不该被连坐 —— 限速是 per-IP 的,做成全局就等于给了攻击者一个
	// 「灌满桶把所有人挡在门外」的 DoS 开关。
	other := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 51000}
	if resp := badLogin(t, env, other); resp.Code == 429 {
		t.Fatal("换个来源 IP 也被 429,限速被做成全局的了")
	}
}

// badLogin 从指定来源打一次注定失败的登录,只关心服务端回的那条 LoginResp。
func badLogin(t *testing.T, env *loginGateEnv, remote net.Addr) util.LoginResp {
	t.Helper()
	typ, payload := loginOnce(t, env, remote, "known", "wrong-psk")
	return mustLoginResp(t, typ, payload)
}

// TestHandleVPNLink_GlobalPoWIssueGateClosesWithoutFingerprint 覆盖跨 IP 的全局出题闸。
//
// per-IP 那道闸对「一人一 IP」的僵尸网络没用,全局闸才是最后一道。被它挡下时服务端
// 必须:① 不再出题(出题的代价不在算 HMAC,在 sync.Map 的跨 IP 写竞争,会拖慢正常用户);
// ② 回一个和其它 PoW 失败**完全一样**的 close,不给攻击者反指纹信号去分辨自己撞到了哪道闸;
// ③ 把计数打进那个 Prometheus 指标 —— 它平时恒为 0,一旦 >0 就是遭遇跨 IP 攻击的唯一信号,
// 不加就等于这场攻击在监控上完全隐形。
func TestHandleVPNLink_GlobalPoWIssueGateClosesWithoutFingerprint(t *testing.T) {
	env := newLoginGateEnv(t)

	prev := globalPoWIssueLimiter
	globalPoWIssueLimiter = rate.NewLimiter(0, 0) // 一道题也不许出
	globalPoWGlobalLimitedTotal.Store(0)
	t.Cleanup(func() {
		globalPoWIssueLimiter = prev
		globalPoWGlobalLimitedTotal.Store(0)
	})

	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleVPNLink(&stormConn{Conn: serverEnd, remote: stormAddr(7)}, env.gw)
	}()

	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypePoWChallengeReq, nil, 3*time.Second); err != nil {
		t.Fatalf("写 PoWChallengeReq: %v", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second)
	if err != nil {
		t.Fatalf("读服务端回应: %v", err)
	}
	if typ == util.LinkTypePoWChallenge {
		t.Fatal("全局闸已关,服务端仍然出了题")
	}
	if typ != util.LinkTypeClose {
		t.Fatalf("期望 Close 帧(与其它 PoW 失败同形),got typ=%d", typ)
	}
	cl, err := util.ParseCloseLinkPayload(payload)
	if err != nil {
		t.Fatalf("解 Close: %v", err)
	}
	if cl.Code != util.CodePowFailed {
		t.Fatalf("Close code 应与其它 PoW 失败一致(%d),got %d —— 不同 code 就是反指纹信号",
			util.CodePowFailed, cl.Code)
	}
	if cl.Reason != "" {
		t.Fatalf("reason 必须留空,不能告诉攻击者他撞的是哪道闸,got %q", cl.Reason)
	}
	awaitDone(t, done)

	if got := globalPoWGlobalLimitedTotal.Load(); got == 0 {
		t.Fatal("全局出题被拒却没有计数,跨 IP 攻击在监控上完全隐形")
	}
}

// panicOnReadConn 首次 Read 就 panic,模拟底层库(WS / QUIC 封装)在这条连接上炸掉。
type panicOnReadConn struct{ net.Conn }

func (c *panicOnReadConn) Read([]byte) (int, error) { panic("模拟底层库在这条连接上炸了") }

// TestHandleVPNLink_PanicOnOneConnectionDoesNotKillTheDaemon 覆盖 per-connection panic 隔离。
//
// 一条连接把整个 nanotund 带走,等于任何一个能触发该 panic 的客户端都握有一键停服的开关 ——
// 所有在线用户一起掉线。recover 在这里不是「吞错误」,是把爆炸半径限制在一条连接内。
func TestHandleVPNLink_PanicOnOneConnectionDoesNotKillTheDaemon(t *testing.T) {
	env := newLoginGateEnv(t)

	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 这一层 recover 是测试自己的安全网:handleVPNLink 若不兜住 panic,它会穿到这里,
		// 而不是直接把整个 test binary 带走 —— 那样只会看到一堆无关测试莫名其妙全挂。
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic 穿透了 handleVPNLink:%v —— 一条坏连接就能停掉整个服务", r)
			}
		}()
		handleVPNLink(&panicOnReadConn{Conn: &stormConn{Conn: serverEnd, remote: stormAddr(8)}}, env.gw)
	}()
	awaitDone(t, done)

	// 进程还活着:同一个 gateway 上后续登录照常。
	typ, payload := loginOnce(t, env, stormAddr(9), "known", "right-psk")
	if resp := mustLoginResp(t, typ, payload); resp.Code != 0 {
		t.Fatalf("崩过一条连接之后,正常登录也不通了:%+v", resp)
	}
}

// TestHandleVPNLink_VIPExhaustionFailsLoudlyAndLeaksNothing 覆盖 vIP 池耗尽。
//
// 两条不变量:
//
//  1. **要出声**。分配不到地址必须回一条明确的 CodeServerError,而不是静默关连接 ——
//     客户端分不清「被拒登」和「网抖」就会无限重连,把耗尽的池子锤得更死。
//  2. **不能漏**。分配失败路径要把已经占下的地址原样吐回去。这里漏一个不会有任何报错,
//     只是池子悄悄少一格,攒够了就是「新用户连不上,重启才好」。
//
// 用 /30 把池子缩到两个地址,几次登录就能撞到底。
func TestHandleVPNLink_VIPExhaustionFailsLoudlyAndLeaksNothing(t *testing.T) {
	env := newLoginGateEnv(t)

	prevTUN, prevGW, prevGW6 := sharedTUN, sharedTUNGateway, sharedTUNGatewayV6
	dev := newStormTUN()
	sharedTUN = dev
	sharedTUNGateway = "10.97.0.1/30"
	sharedTUNGatewayV6 = ""
	t.Cleanup(func() {
		_ = dev.Close()
		sharedTUN, sharedTUNGateway, sharedTUNGatewayV6 = prevTUN, prevGW, prevGW6
	})
	startStormDemux(t)

	// 每条成功的会话都要留着客户端不关,否则 cleanup 会把地址还回池子,永远撞不到底。
	var live []net.Conn
	t.Cleanup(func() {
		for _, c := range live {
			_ = c.Close()
		}
	})

	var exhausted *util.LoginResp
	for i := 0; i < 6 && exhausted == nil; i++ {
		serverEnd, clientEnd := net.Pipe()
		goHandleVPNLink(&stormConn{Conn: serverEnd, remote: stormAddr(20 + i)}, env.gw)

		pow := runClientPoWHandshake(t, clientEnd)
		body, err := marshalLoginReqWithPoW("known", "right-psk", "c", "linux", "tcp", "", "", pow)
		if err != nil {
			t.Fatalf("marshalLoginReqWithPoW: %v", err)
		}
		if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 3*time.Second); err != nil {
			t.Fatalf("第 %d 次写 LoginReq: %v", i, err)
		}
		typ, payload, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second)
		if err != nil {
			t.Fatalf("第 %d 次读回应: %v", i, err)
		}
		resp := mustLoginResp(t, typ, payload)
		if resp.Code == 0 {
			live = append(live, clientEnd)
			// 成功的话还要把 ConvSalt 读掉,不然服务端阻塞在写上,占着地址不进稳态。
			if _, _, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second); err != nil {
				t.Fatalf("第 %d 次读 ConvSalt: %v", i, err)
			}
			continue
		}
		_ = clientEnd.Close()
		exhausted = &resp
	}

	if exhausted == nil {
		t.Fatal("/30 的池子撞了 6 次还没耗尽,分配器可能在往前缀外发地址")
	}
	if exhausted.Code != util.CodeServerError {
		t.Fatalf("地址耗尽应回 CodeServerError(%d),got %d(%q)",
			util.CodeServerError, exhausted.Code, exhausted.Message)
	}
	if exhausted.Message == "" {
		t.Fatal("耗尽时必须带文案,否则客户端只能当成网抖然后无限重连")
	}

	clientIPUsedMu.Lock()
	used := len(clientIPUsed)
	clientIPUsedMu.Unlock()
	if used != len(live) {
		t.Fatalf("在线会话 %d 个,却占着 %d 个地址 —— 分配失败路径漏还了 %d 个",
			len(live), used, used-len(live))
	}
}

// TestHandleVPNLink_NonIPRemoteStillAllocates 覆盖「拿不到客户端 IP」的兜底。
//
// localIPsForVPNAllocation 从 RemoteAddr 推客户端地址,而 net.Pipe / Unix socket /
// 某些代理封装给出的根本不是 IP。此时分配循环的入参会是空集合,不兜底就是一个会话
// 拿不到任何 vIP —— 登录看似成功,数据面全黑。
func TestHandleVPNLink_NonIPRemoteStillAllocates(t *testing.T) {
	env := newLoginGateEnv(t)

	prevTUN, prevGW, prevGW6 := sharedTUN, sharedTUNGateway, sharedTUNGatewayV6
	dev := newStormTUN()
	sharedTUN = dev
	sharedTUNGateway = "10.96.0.1/24"
	sharedTUNGatewayV6 = ""
	t.Cleanup(func() {
		_ = dev.Close()
		sharedTUN, sharedTUNGateway, sharedTUNGatewayV6 = prevTUN, prevGW, prevGW6
	})
	startStormDemux(t)

	serverEnd, clientEnd := net.Pipe() // RemoteAddr() = "pipe",不是 IP
	defer clientEnd.Close()
	goHandleVPNLink(serverEnd, env.gw)

	pow := runClientPoWHandshake(t, clientEnd)
	body, err := marshalLoginReqWithPoW("known", "right-psk", "c", "linux", "tcp", "", "", pow)
	if err != nil {
		t.Fatalf("marshalLoginReqWithPoW: %v", err)
	}
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 3*time.Second); err != nil {
		t.Fatalf("写 LoginReq: %v", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second)
	if err != nil {
		t.Fatalf("读 LoginResp: %v", err)
	}
	if resp := mustLoginResp(t, typ, payload); resp.Code != 0 {
		t.Fatalf("非 IP 型 remote 也该能登录成功,got %+v", resp)
	}

	typ2, payload2, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second)
	if err != nil {
		t.Fatalf("读 ConvSalt: %v", err)
	}
	if typ2 != util.LinkTypeConvSaltMsg {
		t.Fatalf("期望 ConvSaltMsg,got %d", typ2)
	}
	salt, err := util.ParseConvSaltLiteLinkPayload(payload2)
	if err != nil {
		t.Fatalf("解 ConvSalt: %v", err)
	}
	if len(salt.VirtualIPAssignments) != 1 {
		t.Fatalf("应兜底分到 1 个 vIP,实际 %d 个 —— 会话会拿不到地址,数据面全黑",
			len(salt.VirtualIPAssignments))
	}
	if got := salt.VirtualIPAssignments[0].VirtualIP; got == "" {
		t.Fatal("分到了一个空 vIP")
	} else if !isInPrefix(t, got, sharedTUNGateway) {
		t.Fatalf("分到的 vIP %q 落在配置前缀 %s 之外", got, sharedTUNGateway)
	}
}

// TestLocalIPsForVPNAllocation_AlwaysReturnsExactlyOne 把一个隐含前提变成可检查的断言。
//
// 分配路径里有一段「部分分配失败就把已占地址逐个还回去」的回滚循环。变异测试发现它
// **今天走不到**:本函数无论拿到什么地址都只返回一个元素,于是分配循环只跑一轮 ——
// 要么成功(没什么可回滚),要么第一轮就 break(assignments 还是空的)。那段回滚是给
// 「一条连接要多个 vIP」的未来形态留的保险,不是死代码,但现在确实空转。
//
// 所以钉在这里:哪天有人让本函数返回两个地址(双栈、多归属),这条会先红,提醒回去
// 把那段回滚真正测掉 —— 否则它会以「一直在那儿、从没被执行过」的姿态第一次上生产。
func TestLocalIPsForVPNAllocation_AlwaysReturnsExactlyOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		conn net.Conn
	}{
		{"IPv4 TCP 地址", &stormConn{remote: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 443}}},
		{"IPv6 TCP 地址", &stormConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443}}},
		{"非 IP 型(管道/Unix socket)", &stormConn{remote: pipeAddr{}}},
		{"RemoteAddr 返回 nil", &stormConn{remote: nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := localIPsForVPNAllocation(tc.conn)
			if len(got) != 1 {
				t.Fatalf("返回了 %d 个地址(%v);分配路径的回滚循环从没在真实调用下跑过,"+
					"改成多地址前必须先给它补测", len(got), got)
			}
		})
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func isInPrefix(t *testing.T, ip, gatewayCIDR string) bool {
	t.Helper()
	_, network, err := net.ParseCIDR(gatewayCIDR)
	if err != nil {
		t.Fatalf("解析 %q: %v", gatewayCIDR, err)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("%q 不是 IP", ip)
	}
	return network.Contains(parsed)
}
