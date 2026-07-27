package main

// 并发登录风暴与规模测试。
//
// 三机 e2e 只有两个客户端会话,结构上摸不到并发问题;而登录热路径恰恰是全仓库
// 锁最密的地方 —— connIDMapMu 写锁内做 supersede/evict,connectionsMu + clientIPUsedMu
// 内做 vIP 分配(且锁内还会读 SQLite),外加 vipOwner 的 copy-on-write。
//
// 这里用 net.Pipe 直接打 handleVPNLink:不需要真 TUN、不需要真监听端口,却完整跑
// 「PoW → 认证 → device upsert → supersede → vIP 分配 → lease 落库」整条链路,
// 因而可以配合 -race 检出竞态。跑法:
//
//	go test ./cmd/nanotund/ -run 'Storm|Scale' -race -count=1
//	NT_STORM_N=200 go test ./cmd/nanotund/ -run Storm -race -count=1   # 加压
//
// 最核心的不变量只有一条:**任何时刻都不允许两个活着的会话持有同一个 vIP**。
// 一旦破了,数据面 demux 会把包投给错误的会话,表现为随机的连接串台/黑洞,
// 且没有任何错误日志 —— 属于最难从现象倒推的那类故障。

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// ── 测试规模 ────────────────────────────────────────────────────────────────

// stormN 是并发度,可用 NT_STORM_N 覆盖。默认取一个能在几秒内跑完、又足以撞开
// 竞态窗口的值;CI 上想加压直接调环境变量,不用改代码。
func stormN(def int) int {
	if v := os.Getenv("NT_STORM_N"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// ── 假 TUN ──────────────────────────────────────────────────────────────────

// stormTUN 只为把 sharedTUN 置为非 nil —— 登录路径靠 `sharedTUN != nil` 这个门槛
// 决定要不要分配 vIP(server.go:3101)。数据面读写在本测试里用不到。
type stormTUN struct {
	closeOnce sync.Once
	closed    chan struct{}
	events    chan tun.Event
}

func newStormTUN() *stormTUN {
	return &stormTUN{closed: make(chan struct{}), events: make(chan tun.Event)}
}

func (t *stormTUN) File() *os.File                               { return nil }
func (t *stormTUN) Read(_ [][]byte, _ []int, _ int) (int, error) { <-t.closed; return 0, net.ErrClosed }
func (t *stormTUN) Write(bufs [][]byte, _ int) (int, error)      { return len(bufs), nil }
func (t *stormTUN) MTU() (int, error)                            { return 1420, nil }
func (t *stormTUN) Name() (string, error)                        { return "storm0", nil }
func (t *stormTUN) Events() <-chan tun.Event                     { return t.events }
func (t *stormTUN) BatchSize() int                               { return 1 }
func (t *stormTUN) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

// ── 带自定义来源地址的 conn ─────────────────────────────────────────────────

// stormConn 覆写 RemoteAddr,让每个模拟客户端有各自的来源 IP。
//
// 这不是为了好看:PoW 出题限速是 per-IP 的(burst=10、平均 1/s,见 pow_limiter.go),
// 而 net.Pipe 的 RemoteAddr 恒为 "pipe" —— 不覆写的话几十个并发登录会先被反滥用层
// 挡在门外,根本打不到会话层,测出来的「都成功了」是假绿。真实的登录风暴也确实
// 来自不同 IP,所以这样更贴近被测场景。
type stormConn struct {
	net.Conn
	remote net.Addr
}

func (c *stormConn) RemoteAddr() net.Addr { return c.remote }

func stormAddr(i int) net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 99, byte(i/250), byte(i%250+1)), Port: 40000 + i%20000}
}

// ── 环境搭建 ────────────────────────────────────────────────────────────────

// stormArgon* 是 auth.DecodePSK 允许的**最低合法档位**(见 minArgonMemoryKiB=8MiB、
// minArgonTime=1、minArgonThreads=1)。再低会被拒为「不安全的弱 argon2」。
const (
	stormArgonMemKiB  uint32 = 8 * 1024
	stormArgonTime    uint32 = 1
	stormArgonThreads uint8  = 1
)

// stormPSKHash 用**允许范围内最轻的 argon2 参数**产出 PSK 哈希。
//
// 生产参数是 m=64MiB/t=2,单次 verify 就要 64MB;并发几十上百次登录会瞬间吃掉
// 几个 GB 并把耗时拉到分钟级 —— 那测的就成了 argon2 本身,而不是并发正确性。
// VerifyPSK 是从 PHC 串里读 m/t/p 的(auth.DecodePSK),所以预置轻参数哈希能让
// 登录逻辑**一步不少地照常走**,只是算得快。argon2 强度另有 auth 包单测覆盖。
func stormPSKHash(psk string) string {
	salt := []byte("nanotun-storm-16")
	h := argon2.IDKey([]byte(psk), salt, stormArgonTime, stormArgonMemKiB, stormArgonThreads, 32)
	return auth.EncodePSK(salt, h, stormArgonMemKiB, stormArgonTime, stormArgonThreads)
}

type stormEnv struct {
	gw    *gatewayState
	st    *store.Store
	users []storeUserRef
}

type storeUserRef struct {
	name string
	psk  string
	id   int64
}

// newStormEnv 起一套「能真正分配 vIP」的最小 server 状态。
func newStormEnv(t *testing.T, userCount int) *stormEnv {
	t.Helper()
	resetServerGlobals(t)
	resetStormCounters()

	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "storm.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	users := make([]storeUserRef, 0, userCount)
	for i := 0; i < userCount; i++ {
		name := fmt.Sprintf("storm%d", i)
		psk := fmt.Sprintf("psk-%d", i)
		u, err := st.CreateUser(ctx, store.NewUser{
			Username:    name,
			PSKHash:     stormPSKHash(psk),
			ExitAllowed: true,
		})
		if err != nil {
			t.Fatalf("CreateUser %s: %v", name, err)
		}
		users = append(users, storeUserRef{name: name, psk: psk, id: u.ID})
	}

	// 打开 vIP 分配这条路径。/16 给足地址,避免测试因地址耗尽失败而掩盖真正的竞态。
	prevTUN, prevGW, prevGW6 := sharedTUN, sharedTUNGateway, sharedTUNGatewayV6
	dev := newStormTUN()
	sharedTUN = dev
	sharedTUNGateway = "10.90.0.1/16"
	sharedTUNGatewayV6 = ""
	t.Cleanup(func() {
		_ = dev.Close()
		sharedTUN, sharedTUNGateway, sharedTUNGatewayV6 = prevTUN, prevGW, prevGW6
	})

	startStormDemux(t)

	return &stormEnv{
		gw: &gatewayState{
			cfg:          &config.Config{},
			store:        st,
			authVerifier: auth.NewVerifier(st),
		},
		st:    st,
		users: users,
	}
}

func resetStormCounters() {
	safeRLConnNilCount.Store(0)
	sessionSupersedeCount.Store(0)
}

// startStormDemux 跑一份最小 demux:只处理 TunChan 的注册/注销。
//
// 必须有人消费 registerTunReadChan —— vIP 分配路径会 sendRegisterActionAwait 并
// **等回执**(server.go:667),没有消费者就直接死锁在登录中间,现象是测试整体超时,
// 很容易被误判成「服务端卡住了」。生产里这活儿由 main() 里的 demux goroutine 干。
func startStormDemux(t *testing.T) {
	t.Helper()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ip2Channel := make(map[netip.Addr]chan *util.TunPacket)
		for {
			select {
			case <-stop:
				return
			case <-globalContext.Done():
				return
			case action := <-registerTunReadChan:
				applyTunChanRegisterAction(ip2Channel, action)
				action.success <- struct{}{}
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})
}

// ── 客户端侧 ────────────────────────────────────────────────────────────────

type stormSession struct {
	conn net.Conn // 客户端一侧;Close 即触发服务端 cleanup
	vips []string
	// sessionID / takeoverSecret 用于后续发起 takeover 登录(热切换链路)。
	sessionID      string
	takeoverSecret string
}

// stormPoW 是 runClientPoWHandshake 的**返回 error** 版本。
// 并发 goroutine 里不能调 t.Fatalf(行为未定义),所以不能直接复用那个 helper。
func stormPoW(c net.Conn) (util.LoginReqPoW, error) {
	var zero util.LoginReqPoW
	if err := writeLinkFrameWithDeadline(c, util.LinkTypePoWChallengeReq, nil, 10*time.Second); err != nil {
		return zero, fmt.Errorf("write PoWChallengeReq: %w", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(c, 10*time.Second)
	if err != nil {
		return zero, fmt.Errorf("read PoWChallenge: %w", err)
	}
	if typ != util.LinkTypePoWChallenge {
		return zero, fmt.Errorf("首帧 typ=%d,期望 PoWChallenge(%d)", typ, util.LinkTypePoWChallenge)
	}
	ch, err := util.ParseLinkPoWChallengePayload(payload)
	if err != nil {
		return zero, fmt.Errorf("解析 PoWChallenge: %w", err)
	}
	saltBytes, err := base64StdDecode(ch.Salt)
	if err != nil {
		return zero, fmt.Errorf("解 salt: %w", err)
	}
	var nonce uint64
	for ; nonce < (1 << 32); nonce++ {
		if powVerify(ch.ChallengeID, saltBytes, ch.Difficulty, nonce) {
			break
		}
	}
	return util.LoginReqPoW{
		ChallengeID: ch.ChallengeID,
		Salt:        ch.Salt,
		Difficulty:  ch.Difficulty,
		ExpiresAt:   ch.ExpiresAt,
		Signature:   ch.Signature,
		Nonce:       nonce,
	}, nil
}

// stormLogin 完整跑一次客户端登录,返回拿到的 vIP 列表。
// 返回的 session 持有客户端 conn:调用方 Close 之前会话一直在线。
func stormLogin(gw *gatewayState, srcIdx int, user, psk, deviceUUID, deviceName string) (*stormSession, error) {
	serverEnd, clientEnd := net.Pipe()
	go handleVPNLink(&stormConn{Conn: serverEnd, remote: stormAddr(srcIdx)}, gw)

	pow, err := stormPoW(clientEnd)
	if err != nil {
		_ = clientEnd.Close()
		return nil, err
	}
	body, err := marshalLoginReqWithPoW(user, psk, "client", "linux", "tcp", deviceUUID, deviceName, pow)
	if err != nil {
		_ = clientEnd.Close()
		return nil, err
	}
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 10*time.Second); err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("write LoginReq: %w", err)
	}

	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 20*time.Second)
	if err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("read LoginResp: %w", err)
	}
	if typ != util.LinkTypeLoginResp {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("typ=%d,期望 LoginResp", typ)
	}
	var resp util.LoginResp
	if err := json.Unmarshal(payload, &resp); err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("解析 LoginResp: %w", err)
	}
	if resp.Code != 0 {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("登录被拒:code=%d msg=%q", resp.Code, resp.Message)
	}

	typ2, payload2, err := readLinkFrameWithDeadline(clientEnd, 20*time.Second)
	if err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("read ConvSalt: %w", err)
	}
	if typ2 != util.LinkTypeConvSaltMsg {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("typ=%d,期望 ConvSaltMsg", typ2)
	}
	salt, err := util.ParseConvSaltLiteLinkPayload(payload2)
	if err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("解析 ConvSalt: %w", err)
	}
	vips := make([]string, 0, len(salt.VirtualIPAssignments))
	for _, a := range salt.VirtualIPAssignments {
		vips = append(vips, a.VirtualIP)
	}
	return &stormSession{
		conn:           clientEnd,
		vips:           vips,
		sessionID:      resp.SessionID,
		takeoverSecret: resp.TakeoverSecret,
	}, nil
}

// stormTakeover 用已有会话的 session_id + secret 发起一次接管登录(客户端换链路的热切换)。
// 返回接管后的新链路;老链路会被服务端关掉。
func stormTakeover(gw *gatewayState, srcIdx int, user, psk string, old *stormSession) (*stormSession, error) {
	serverEnd, clientEnd := net.Pipe()
	go handleVPNLink(&stormConn{Conn: serverEnd, remote: stormAddr(srcIdx)}, gw)

	pow, err := stormPoW(clientEnd)
	if err != nil {
		_ = clientEnd.Close()
		return nil, err
	}
	req := util.LoginReq{
		Name:              user,
		Token:             psk,
		Type:              "client",
		Platform:          "linux",
		Transport:         "tcp",
		Purpose:           util.PurposeTakeover,
		TakeoverSessionID: old.sessionID,
		TakeoverSecret:    old.takeoverSecret,
		Pow:               pow,
	}
	body, err := json.Marshal(req)
	if err != nil {
		_ = clientEnd.Close()
		return nil, err
	}
	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypeLoginReq, body, 10*time.Second); err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("write takeover LoginReq: %w", err)
	}
	typ, payload, err := readLinkFrameWithDeadline(clientEnd, 20*time.Second)
	if err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("read takeover LoginResp: %w", err)
	}
	if typ != util.LinkTypeLoginResp {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("typ=%d,期望 LoginResp", typ)
	}
	var resp util.LoginResp
	if err := json.Unmarshal(payload, &resp); err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("解析 takeover LoginResp: %w", err)
	}
	if resp.Code != 0 {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("接管被拒:code=%d msg=%q", resp.Code, resp.Message)
	}

	// 必须接着把 ConvSaltLite 读掉。net.Pipe 无缓冲且同步:不读的话服务端那次写会一直
	// 阻塞到超时,然后**回滚整个接管**(日志里是「下发 ConvSaltLite 失败,回滚」)。
	// 漏了这一步,接管看似成功、实则老连接原封不动 —— 基于它的断言会全部假绿。
	typ2, payload2, err := readLinkFrameWithDeadline(clientEnd, 20*time.Second)
	if err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("read takeover ConvSalt: %w", err)
	}
	if typ2 != util.LinkTypeConvSaltMsg {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("typ=%d,期望 ConvSaltMsg", typ2)
	}
	salt, err := util.ParseConvSaltLiteLinkPayload(payload2)
	if err != nil {
		_ = clientEnd.Close()
		return nil, fmt.Errorf("解析 takeover ConvSalt: %w", err)
	}
	vips := make([]string, 0, len(salt.VirtualIPAssignments))
	for _, a := range salt.VirtualIPAssignments {
		vips = append(vips, a.VirtualIP)
	}
	if len(vips) == 0 {
		vips = old.vips // 接管沿用老 vIP;下发为空时退回调用方已知的值
	}
	return &stormSession{
		conn:           clientEnd,
		vips:           vips,
		sessionID:      resp.SessionID,
		takeoverSecret: resp.TakeoverSecret,
	}, nil
}

// ── 断言辅助 ────────────────────────────────────────────────────────────────

func liveConnCount() int {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()
	return len(connections)
}

func usedVIPCount() int {
	clientIPUsedMu.Lock()
	defer clientIPUsedMu.Unlock()
	return len(clientIPUsed)
}

func liveConnsForDevice(deviceID int64) int {
	connIDMapMu.RLock()
	defer connIDMapMu.RUnlock()
	return len(connByDevice[deviceID])
}

// waitFor 轮询等待条件成立,用于等异步 cleanup 收敛。
// 失败时返回 false,由调用方给出带上下文的错误信息。
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func closeAll(sessions []*stormSession) {
	for _, s := range sessions {
		if s != nil && s.conn != nil {
			_ = s.conn.Close()
		}
	}
}

// ── 测试 1:不同设备并发登录 ────────────────────────────────────────────────

// TestLoginStorm_DistinctDevicesGetDistinctVIPs 是本文件的主测试。
//
// N 个不同设备**同时**登录,验证核心不变量:每个会话都拿到 vIP,且两两不重复。
// vIP 分配路径上有一处已知的 TOCTOU 处理(锁外读 dbReservedVIPs、锁内再刷一次,
// server.go:3085-3093),这个测试就是冲着那扇窗口去的。
func TestLoginStorm_DistinctDevicesGetDistinctVIPs(t *testing.T) {
	env := newStormEnv(t, 4)
	n := stormN(48)

	sessions := make([]*stormSession, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := env.users[i%len(env.users)]
			// 同时起跑,把竞态窗口撑到最大。逐个登录几乎撞不上任何窗口。
			<-start
			sessions[i], errs[i] = stormLogin(env.gw, i, u.name, u.psk,
				stormUUID(i), fmt.Sprintf("dev-%d", i))
		}(i)
	}
	close(start)
	wg.Wait()
	defer closeAll(sessions)

	failed := 0
	for i, err := range errs {
		if err != nil {
			failed++
			if failed <= 5 {
				t.Errorf("第 %d 个登录失败: %v", i, err)
			}
		}
	}
	if failed > 0 {
		t.Fatalf("%d/%d 个并发登录失败", failed, n)
	}

	// 核心不变量:vIP 两两不重复。
	owner := make(map[string]int, n)
	for i, s := range sessions {
		if len(s.vips) == 0 {
			t.Errorf("第 %d 个会话没拿到 vIP", i)
			continue
		}
		for _, vip := range s.vips {
			if prev, dup := owner[vip]; dup {
				t.Errorf("vIP 重复分配:%s 同时被会话 %d 和 %d 持有 —— 数据面会把包投给错误的会话", vip, prev, i)
				continue
			}
			owner[vip] = i
		}
	}

	if got := liveConnCount(); got != n {
		t.Errorf("在线连接数 = %d,期望 %d", got, n)
	}
	if got := usedVIPCount(); got != len(owner) {
		t.Errorf("clientIPUsed 条目数 = %d,期望 %d(与实际下发的 vIP 数一致)", got, len(owner))
	}

	// lease 必须每设备一条且 vIP 不重复 —— 重复会撞 UNIQUE,说明分配阶段漏算了已占用集。
	assertLeasesDistinct(t, env, n)

	// 这里没有观测者在并发扫连接,所以窗口不该被撞到;真撞到说明有别的路径在
	// 登录期间读了连接。数值本身不代表故障(见 TestScale_StatusUnderLoginChurn 的说明),
	// 但在这个场景下意外出现值得看一眼。
	if got := safeRLConnNilCount.Load(); got != 0 {
		t.Logf("注意:无并发观测者的场景下仍撞到 rlConn 未就绪窗口 %d 次", got)
	}
}

// ── 测试 2:同一设备并发重登(supersede 路径) ───────────────────────────────

// TestLoginStorm_SameDeviceSupersedeConverges 压 supersede 这条路径。
//
// 同一个 device_uuid 被 N 个连接同时登录 —— 真实场景是客户端在弱网下疯狂重连。
// 服务端的设计是「新登录踢掉同设备的旧会话」,并等旧会话 cleanup 完成(最多 5s)
// 以便复用同一个 vIP(supersede.go:1-43)。并发下要保证的是:最终只剩一条活连接,
// 且不留下泄漏的 vIP。
func TestLoginStorm_SameDeviceSupersedeConverges(t *testing.T) {
	env := newStormEnv(t, 1)
	n := stormN(12)
	u := env.users[0]
	uuid := stormUUID(9999)

	sessions := make([]*stormSession, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			sessions[i], errs[i] = stormLogin(env.gw, i, u.name, u.psk, uuid, "same-device")
		}(i)
	}
	close(start)
	wg.Wait()

	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		}
	}
	if ok == 0 {
		t.Fatalf("同设备并发登录全部失败,至少应有一个成功;errs[0]=%v", errs[0])
	}
	t.Logf("同设备并发登录 %d 次,成功 %d 次,supersede 计数 %d", n, ok, sessionSupersedeCount.Load())

	// 被踢的连接由服务端关闭,其 cleanup 是异步的;等收敛。
	if !waitFor(10*time.Second, func() bool { return liveConnsForDevice(deviceIDOf(t, env, u.id, uuid)) <= 1 }) {
		t.Errorf("同设备活连接数收敛失败:仍有 %d 条,期望 <= 1", liveConnsForDevice(deviceIDOf(t, env, u.id, uuid)))
	}

	closeAll(sessions)

	// 全部断开后不能留下任何被占用的 vIP:留下就是永久泄漏,该地址再也分不出去。
	if !waitFor(10*time.Second, func() bool { return usedVIPCount() == 0 && liveConnCount() == 0 }) {
		t.Errorf("断开后未回收干净:连接 %d 条、占用 vIP %d 个,期望都为 0",
			liveConnCount(), usedVIPCount())
	}
}

// ── 测试 3:反复登录/断开不泄漏 ────────────────────────────────────────────

// TestLoginStorm_ChurnDoesNotLeak 反复做「一批登录 → 全断开」,验证每轮都能回到零。
//
// 单次登录登出不泄漏很容易,泄漏往往只在并发 + 反复的组合下才显形(比如
// unregisterVIPOwners 的 ownerConnID 守卫若失效,老会话的 cleanup 会误删新会话
// 刚注册的映射,acl_runtime.go:990-998)。
func TestLoginStorm_ChurnDoesNotLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("churn 测试较慢,-short 下跳过")
	}
	env := newStormEnv(t, 2)
	perRound := stormN(16)
	rounds := 4

	goroutineBaseline := runtime.NumGoroutine()

	for r := 0; r < rounds; r++ {
		sessions := make([]*stormSession, perRound)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < perRound; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				u := env.users[i%len(env.users)]
				<-start
				s, err := stormLogin(env.gw, i, u.name, u.psk, stormUUID(r*1000+i), fmt.Sprintf("churn-%d-%d", r, i))
				if err == nil {
					sessions[i] = s
				}
			}(i)
		}
		close(start)
		wg.Wait()

		closeAll(sessions)
		if !waitFor(15*time.Second, func() bool { return liveConnCount() == 0 && usedVIPCount() == 0 }) {
			t.Fatalf("第 %d 轮结束后未回到零:连接 %d 条、占用 vIP %d 个",
				r, liveConnCount(), usedVIPCount())
		}
	}

	// goroutine 泄漏:每轮都起了 perRound 个 handleVPNLink,全断开后应当都退出。
	// 给一点余量,GC 与 runtime 内部 goroutine 会有正常波动。
	if !waitFor(10*time.Second, func() bool { return runtime.NumGoroutine() < goroutineBaseline+perRound/2 }) {
		t.Errorf("疑似 goroutine 泄漏:基线 %d,当前 %d(跑了 %d 轮 × %d 个会话)",
			goroutineBaseline, runtime.NumGoroutine(), rounds, perRound)
	}
}

// ── 辅助 ────────────────────────────────────────────────────────────────────

// stormUUID 造合法的 RFC 4122 v4 UUID —— authenticatePSK 会严格校验版本位,
// 不合法会被当成「没提供 device_uuid」静默降级(于是 supersede/lease 全都测不到)。
func stormUUID(i int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i)
}

func deviceIDOf(t *testing.T, env *stormEnv, userID int64, uuid string) int64 {
	t.Helper()
	dev, err := env.st.GetDeviceByUUID(t.Context(), userID, uuid)
	if err != nil {
		t.Fatalf("GetDeviceByUUID(%d, %s): %v", userID, uuid, err)
	}
	return dev.ID
}

// assertLeasesDistinct 逐用户列设备、逐设备取 lease,校验落库的 vIP 两两不重复。
//
// lease 表对 vIP 有 UNIQUE 约束,真撞上会在 persistDeviceLease 阶段拒登;这里额外
// 核一遍是为了覆盖「内存分配已经重复、只是还没走到落库」的中间态。
func assertLeasesDistinct(t *testing.T, env *stormEnv, wantCount int) {
	t.Helper()
	seen := make(map[string]int64, wantCount)
	total := 0
	for _, u := range env.users {
		devs, err := env.st.ListDevicesByUser(t.Context(), u.id)
		if err != nil {
			t.Fatalf("ListDevicesByUser(%d): %v", u.id, err)
		}
		for _, d := range devs {
			l, err := env.st.GetLeaseByDevice(t.Context(), d.ID)
			if err != nil {
				continue // 没租约的设备跳过(不该有,数量断言会兜住)
			}
			total++
			if l.VIPv4 == "" {
				continue
			}
			if prev, dup := seen[l.VIPv4]; dup {
				t.Errorf("lease 里 vIP 重复:%s 同时属于 device %d 和 %d", l.VIPv4, prev, d.ID)
				continue
			}
			seen[l.VIPv4] = d.ID
		}
	}
	if total != wantCount {
		t.Errorf("落库的 lease 条数 = %d,期望 %d", total, wantCount)
	}
}
