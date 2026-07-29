package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// 接管(takeover)的语义是「换底层链路,保业务身份」。凡是**没有**随之过户的状态,都会在客户端
// 一次热切换后悄悄丢掉 —— 而热切换是弱网下的常规动作,用户完全感知不到发生过。
//
// 这类丢失全都不报错,方向还各不相同:限速丢了是「人工降速被解除」(安全方向错),出口意图丢了是
// 「自动恢复失效」(可用性方向错),宣告网段集丢了是「per-CIDR 收窄退回布尔放行」(权限放宽)。

// takeoverReq 造一条合法的接管请求。
func takeoverReq(fx *takeoverFixture, username, psk string) *util.LoginReq {
	return &util.LoginReq{
		Name:              username,
		Token:             psk,
		Purpose:           util.PurposeTakeover,
		TakeoverSessionID: fx.sid,
		TakeoverSecret:    takeoverTestSecret,
		Platform:          "linux",
	}
}

// runTakeoverOK 跑一次**成功**的接管。与 runTakeover(为拒绝路径写的)不同:成功的接管不会返回 ——
// handler 会一路进到数据面隧道并阻塞在读上。所以这里读完回应就放它继续跑,收尾时关掉链路让它退出。
func runTakeoverOK(t *testing.T, fx *takeoverFixture, req *util.LoginReq) *util.LoginResp {
	t.Helper()
	// 老链路的 tunnel 已经退出 —— 这是接管的常态(老链路先断,客户端才来接管)。不这么置的话
	// handler 会在「等老 demux 停止消费共享 TunChan」那一步干等 5s + 3s:那道等待有它自己的
	// 意义(两个 demux 抢同一条下行队列会丢包),但不该让这一组用例每条都为它付 8 秒。
	select {
	case <-fx.oldConn.tunnelDone:
	default:
		close(fx.oldConn.tunnelDone)
	}
	resp, _ := startTakeoverOK(t, fx, req)
	return resp
}

// runTakeoverOKWithSalt 同 runTakeoverOK,另外把紧随 LoginResp 的 ConvSalt 解出来 ——
// 接管下发的 DNS 列表就在里面(登录路径有 dualStackLogin 做同样的事)。
func runTakeoverOKWithSalt(t *testing.T, fx *takeoverFixture, req *util.LoginReq) (*util.LoginResp, *util.ConvSaltLite) {
	t.Helper()
	select {
	case <-fx.oldConn.tunnelDone:
	default:
		close(fx.oldConn.tunnelDone)
	}
	return startTakeoverOK(t, fx, req)
}

// startTakeoverOK 与 runTakeoverOK 相同,但**不动** oldConn.tunnelDone ——
// 「老链路迟迟不退出」那组用例要验的正是那段等待本身。
// 第二个返回值是紧随 LoginResp 的 ConvSalt(code != 0 时为 nil)。
func startTakeoverOK(t *testing.T, fx *takeoverFixture, req *util.LoginReq) (*util.LoginResp, *util.ConvSaltLite) {
	t.Helper()
	// 接管成功后 handler 会 defer cleanupConnection,而清理要往 registerTunReadChan 投递并**等确认**。
	// 没有消费者的话它永远卡在那里 —— 表现就是「关掉链路 handler 也不退出」。
	withTestGlobalContext(t)
	startStormDemux(t)

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTakeoverLogin(serverConn, fx.gw, req, "test-remote", takeoverTestIPHost)
	}()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("关掉链路后接管 handler 仍没退出")
		}
	})
	resp := readResp(t, clientConn)
	// net.Pipe 无缓冲:LoginResp 之后紧跟的 ConvSalt 没人读的话 handler 就卡在写上,
	// 后面的 connIDMap 注册压根跑不到。先把它读出来(顺带给调用方),再起读者一路吸干,
	// 直到链路被 cleanup 关掉。
	var salt *util.ConvSaltLite
	if resp != nil && resp.Code == 0 {
		typ, payload, err := readLinkFrameWithDeadline(clientConn, 15*time.Second)
		if err != nil {
			t.Fatalf("读 ConvSalt: %v", err)
		}
		if typ != util.LinkTypeConvSaltMsg {
			t.Fatalf("LoginResp 之后应是 ConvSalt,got typ=%d", typ)
		}
		var cs util.ConvSaltLite
		if err := json.Unmarshal(payload, &cs); err != nil {
			t.Fatalf("解 ConvSalt: %v", err)
		}
		salt = &cs
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := clientConn.Read(buf); err != nil {
				return
			}
		}
	}()
	return resp, salt
}

// currentConnForSID 取接管后 connIDMap 里那条**新**连接。注册与写回应是两个步骤,给它一个有界窗口。
func currentConnForSID(t *testing.T, sid string, old *Connection) *Connection {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		connIDMapMu.Lock()
		cur := connIDMap[sid]
		connIDMapMu.Unlock()
		if cur == nil {
			t.Fatal("接管后 connIDMap 里没有连接了 —— 会话凭空消失,客户端会一直重连")
		}
		if cur != old {
			return cur
		}
		if time.Now().After(deadline) {
			t.Fatal("connIDMap 还指着老连接 —— 接管没生效")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestTakeover_DeviceRateLimitFollowsTheSession 限速必须随接管过户,且以库里最新值为准。
//
// 两种坏法方向相反,都真实发生过:不继承 → 换链路即解除限速(人工降速形同虚设);继承旧快照而
// 不看库里最新值 → 管理员在老链路期间刚下调的限速被「复活」成旧值,表现是「降速了,但客户端
// 重连一下就恢复原速」,而后台显示的是新值。
func TestTakeover_DeviceRateLimitFollowsTheSession(t *testing.T) {
	fx := newTakeoverFixture(t)
	ctx := t.Context()

	u, err := fx.st.GetUserByUsername(ctx, "victim")
	if err != nil {
		t.Fatalf("取用户: %v", err)
	}
	const uuid = "22222222-3333-4444-8555-000000000001"
	dev, err := fx.st.UpsertDevice(ctx, u.ID, uuid, "victim-dev", "")
	if err != nil {
		t.Fatalf("建设备: %v", err)
	}
	// 老链路带的是「宽松」的旧快照。
	fx.oldConn.deviceID = dev.ID
	fx.oldConn.deviceUUID = uuid
	fx.oldConn.deviceRateUpBPS = 100_000_000
	fx.oldConn.deviceRateDownBPS = 100_000_000

	// 管理员在老链路还活着的时候把这台设备降速了。
	if err := fx.st.SetDeviceRateLimit(ctx, dev.ID, 1_000_000, 2_000_000); err != nil {
		t.Skipf("这套 store 不支持按设备设限速,跳过: %v", err)
	}

	req := takeoverReq(fx, "victim", victimPSK)
	req.DeviceUUID = uuid
	resp := runTakeoverOK(t, fx, req)
	if resp.Code != 0 {
		t.Fatalf("合法接管应成功: %+v", resp)
	}

	newConn := currentConnForSID(t, fx.sid, fx.oldConn)
	if newConn.deviceRateUpBPS == 100_000_000 || newConn.deviceRateDownBPS == 100_000_000 {
		t.Errorf("接管后限速回到了老链路的旧快照(up=%d down=%d)—— 管理员刚下调的限速被一次热切换解除了",
			newConn.deviceRateUpBPS, newConn.deviceRateDownBPS)
	}
	if newConn.deviceRateUpBPS != 1_000_000 || newConn.deviceRateDownBPS != 2_000_000 {
		t.Errorf("接管后限速 = up %d / down %d,期望库里最新的 1000000 / 2000000",
			newConn.deviceRateUpBPS, newConn.deviceRateDownBPS)
	}
	if newConn.deviceID != dev.ID {
		t.Errorf("设备身份没随接管过户:deviceID = %d,期望 %d", newConn.deviceID, dev.ID)
	}
}

// TestTakeover_InheritsTheDeviceIdentityWhenTheLookupComesUpEmpty 查不到设备时沿用老链路的身份。
//
// 认不出设备就把身份清空的后果:这条会话之后的 supersede 匹配、按设备踢线、按设备限速全都对不上号 ——
// 它变成了一个「没有设备」的幽灵会话,而客户端侧一切正常。
func TestTakeover_InheritsTheDeviceIdentityWhenTheLookupComesUpEmpty(t *testing.T) {
	fx := newTakeoverFixture(t)
	const uuid = "22222222-3333-4444-8555-000000000002"
	fx.oldConn.deviceUUID = uuid
	fx.oldConn.deviceID = 4242

	// 请求里不带 device_uuid → 认证阶段拿不到 Device。
	resp := runTakeoverOK(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("合法接管应成功: %+v", resp)
	}

	newConn := currentConnForSID(t, fx.sid, fx.oldConn)
	if newConn.deviceUUID != uuid {
		t.Errorf("认不出设备时应沿用老链路的 device_uuid,got %q —— 否则这条会话变成认不出设备的幽灵,"+
			"按设备踢线 / 限速 / supersede 全都对不上号", newConn.deviceUUID)
	}
	if newConn.deviceID != 4242 {
		t.Errorf("deviceID 也该沿用,got %d", newConn.deviceID)
	}
}

// TestTakeover_CarriesOverTheEgressIntentAndAdvertisedRoutes 出口意图与宣告网段集必须过户。
//
// 热切换不会让客户端重发 EgressSelect / RouteAdvertise,所以这些状态只能靠继承。
//   - 出口意图丢了:「出口撤销后又批回来」的自动恢复失效,用户干等到自己重连;
//   - 宣告 CIDR 集丢了:per-CIDR 门控退回布尔放行 —— 权限被放宽,这个方向更糟;
//   - 两个批准位丢了:合法转发者被误判成「未批准」,它的回程流量被反源欺骗检查丢掉。
func TestTakeover_CarriesOverTheEgressIntentAndAdvertisedRoutes(t *testing.T) {
	fx := newTakeoverFixture(t)

	fx.oldConn.desiredExitDeviceID.Store(int64(77))
	fx.oldConn.desiredExitUUID.Store("33333333-4444-5555-8666-000000000003")
	routes := []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}
	fx.oldConn.advertisedRoutes.Store(&routes)
	fx.oldConn.advertisedExitApproved.Store(true)
	fx.oldConn.advertisedSubnetApproved.Store(true)

	resp := runTakeoverOK(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("合法接管应成功: %+v", resp)
	}
	newConn := currentConnForSID(t, fx.sid, fx.oldConn)

	if got := newConn.desiredExitDeviceID.Load(); got != 77 {
		t.Errorf("出口意图没过户(got %d)—— 「撤销后又批回来」的自动恢复会在一次热切换后失效", got)
	}
	if got, _ := newConn.desiredExitUUID.Load().(string); got != "33333333-4444-5555-8666-000000000003" {
		t.Errorf("出口 UUID 没过户,got %q", got)
	}
	if got := newConn.advertisedRoutes.Load(); got == nil || len(*got) != 1 {
		t.Error("宣告网段集没过户 —— per-CIDR 门控退回布尔放行,权限被放宽")
	}
	if !newConn.advertisedExitApproved.Load() || !newConn.advertisedSubnetApproved.Load() {
		t.Error("两个批准位没过户 —— 合法转发者被误判成未批准,回程流量被反源欺骗检查丢掉")
	}
}

// TestTakeover_InheritsTheVirtualIPsUnchanged vIP 必须原样继承。
//
// 换一个地址等于让客户端的整套路由、ACL 归属、端口转发目标全部失效;而不继承(空集)则是
// 「登录成功但数据面全黑」。两者客户端侧都只表现为「突然不通了」。
func TestTakeover_InheritsTheVirtualIPsUnchanged(t *testing.T) {
	fx := newTakeoverFixture(t)
	oldIPs := fx.oldConn.safeClientIPs()
	if len(oldIPs) == 0 {
		t.Fatal("fixture 应当带 vIP")
	}

	resp := runTakeoverOK(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("合法接管应成功: %+v", resp)
	}
	newConn := currentConnForSID(t, fx.sid, fx.oldConn)

	newIPs := newConn.safeClientIPs()
	if len(newIPs) != len(oldIPs) {
		t.Fatalf("接管后 vIP 数量 %d,期望 %d —— 数据面会整体黑掉", len(newIPs), len(oldIPs))
	}
	for i := range oldIPs {
		if newIPs[i].VirtualIP != oldIPs[i].VirtualIP {
			t.Errorf("第 %d 个 vIP 变成了 %s(原 %s)—— 客户端整套路由 / ACL 归属 / 端口转发目标全部失效",
				i+1, newIPs[i].VirtualIP, oldIPs[i].VirtualIP)
		}
		if newIPs[i].TunChan != oldIPs[i].TunChan {
			t.Errorf("第 %d 个 vIP 的下行通道被换掉了 —— 老通道里在途的包再也发不出去", i+1)
		}
	}
}

// TestTakeover_RotatesTheSecretSoTheOldOneCannotBeReplayed secret 是一次性的。
//
// 不轮换的话,任何拿到过一次 secret 的人可以反复接管同一个会话 —— 每次都把合法客户端踢下线。
func TestTakeover_RotatesTheSecretSoTheOldOneCannotBeReplayed(t *testing.T) {
	fx := newTakeoverFixture(t)

	resp := runTakeoverOK(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("首次接管应成功: %+v", resp)
	}
	if resp.TakeoverSecret == "" {
		t.Fatal("成功的接管必须下发新 secret,否则客户端下次没法再接管自己")
	}
	if resp.TakeoverSecret == takeoverTestSecret {
		t.Fatal("secret 没轮换 —— 拿到过一次的人可以反复接管,每次都把合法客户端踢下线")
	}

	// 拿旧 secret 再来一次:必须失败。
	second := runTakeover(t, fx, takeoverReq(fx, "victim", victimPSK))
	if second.Code == 0 {
		t.Fatal("旧 secret 仍能接管 —— 一次性语义没落实")
	}
}

// TestTakeover_RefusesRatherThanReuseTheOldSecretWhenEntropyFails 熵源故障时保守拒绝。
//
// 生成不出新 secret 时有两条路:拒掉这次接管(客户端退回一次普通重连,代价是几秒),或者退回旧
// secret 继续。后者看着「更可用」,实际是把一次性语义悄悄取消了 —— 旧 secret 已经在线路上用过
// 一次,谁截到过它就能反复接管这个会话,每次都把合法客户端踢下线。所以这里必须选前者。
func TestTakeover_RefusesRatherThanReuseTheOldSecretWhenEntropyFails(t *testing.T) {
	fx := newTakeoverFixture(t)

	prev := takeoverSecretRandRead
	takeoverSecretRandRead = func([]byte) (int, error) { return 0, errNoEntropy }
	t.Cleanup(func() { takeoverSecretRandRead = prev })

	resp := runTakeover(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code == 0 {
		t.Fatal("生成不出新 secret 时必须拒绝接管,而不是退回旧 secret 继续")
	}
	if resp.TakeoverSecret != "" {
		t.Errorf("拒绝时不许下发任何 secret,got %q", resp.TakeoverSecret)
	}
	// 老会话必须原封不动:没被接管、也没被顶掉。
	if fx.oldConn.takenOver.Load() {
		t.Error("接管被拒了,老连接却已标记成被接管 —— 会话凭空作废")
	}
	connIDMapMu.Lock()
	cur := connIDMap[fx.sid]
	connIDMapMu.Unlock()
	if cur != fx.oldConn {
		t.Error("接管被拒后 connIDMap 应仍指向老连接")
	}
}

var errNoEntropy = errors.New("熵源故障")

// TestTakeover_AuditsTheHandoverEvenWhenNothingElseChanges 接管必须留审计。
// 它是「换了条链路继续用同一个会话」——事后追查「这个会话当时在谁手里」只有这一条线索。
func TestTakeover_AuditsTheHandoverEvenWhenNothingElseChanges(t *testing.T) {
	fx := newTakeoverFixture(t)
	resp := runTakeoverOK(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("合法接管应成功: %+v", resp)
	}
	if !hasAction(auditActions(t, fx.st), "login.takeover") {
		t.Error("成功的接管没写审计 —— 事后追查「这个会话当时在谁手里」就没了唯一线索")
	}
}
