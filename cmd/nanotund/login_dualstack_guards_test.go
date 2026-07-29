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

// 登录里的双栈分配与「撞号必须拒登」。
//
// 这两块都属于「不报错的坏」:v6 分配整段此前从未跑过 —— 配了 subnets_v6 的部署里,每个客户端
// 都要经过它,而它悄悄不给地址的话,登录成功、v4 通、v6 静默全黑;撞号那条更糟,两台设备带着
// 同一个 vIP 上线,数据面成路由黑洞,而两边看起来都在线。

// dualStackLogin 起一条完整登录,返回 LoginResp 与紧随其后的 ConvSalt(code!=0 时后者为 nil)。
// 会话保持在线不关,由 t.Cleanup 收尾 —— 关早了 vIP 会被还回池子。
type dualStackResult struct {
	resp util.LoginResp
	salt *util.ConvSaltLite
}

func dualStackLogin(t *testing.T, env *loginGateEnv, remote net.Addr, name, psk, deviceUUID string) dualStackResult {
	t.Helper()
	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = clientEnd.Close() })

	var srv net.Conn = serverEnd
	if remote != nil {
		srv = &stormConn{Conn: serverEnd, remote: remote}
	}
	go handleVPNLink(srv, env.gw)

	pow := runClientPoWHandshake(t, clientEnd)
	body, err := marshalLoginReqWithPoW(name, psk, "c", "linux", "tcp", deviceUUID, "dev", pow)
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
	resp := mustLoginResp(t, typ, payload)
	out := dualStackResult{resp: resp}
	if resp.Code != 0 {
		return out
	}
	typ2, payload2, err := readLinkFrameWithDeadline(clientEnd, 3*time.Second)
	if err != nil {
		t.Fatalf("读 ConvSalt: %v", err)
	}
	if typ2 != util.LinkTypeConvSaltMsg {
		t.Fatalf("第二帧应是 ConvSalt,got %d", typ2)
	}
	var salt util.ConvSaltLite
	if err := json.Unmarshal(payload2, &salt); err != nil {
		t.Fatalf("解 ConvSalt: %v", err)
	}
	out.salt = &salt
	return out
}

// withDualStackTUN 把共享 TUN 与两族网关置好,收尾还原。
func withDualStackTUN(t *testing.T, gw4, gw6 string) {
	t.Helper()
	prevTUN, prevGW, prevGW6 := sharedTUN, sharedTUNGateway, sharedTUNGatewayV6
	dev := newStormTUN()
	sharedTUN = dev
	sharedTUNGateway = gw4
	sharedTUNGatewayV6 = gw6
	t.Cleanup(func() {
		_ = dev.Close()
		sharedTUN, sharedTUNGateway, sharedTUNGatewayV6 = prevTUN, prevGW, prevGW6
	})
	startStormDemux(t)
}

// TestLogin_HandsOutBothFamiliesWhenBothAreConfigured 配了 subnets_v6 就必须真的下发 v6 地址。
//
// 这整段此前一行未跑过。少下发 v6 的表现是「登录成功、v4 通、v6 什么都不通」——客户端不会报错,
// 用户只会觉得某些站点打不开。
func TestLogin_HandsOutBothFamiliesWhenBothAreConfigured(t *testing.T) {
	env := newLoginGateEnv(t)
	withDualStackTUN(t, "10.98.0.1/24", "fd00:98::1/64")
	env.gw.cfg.TUN.DNSServersV4 = []string{"1.1.1.1"}
	env.gw.cfg.TUN.DNSServersV6 = []string{"fd00:98::53"}

	got := dualStackLogin(t, env, stormAddr(40), "known", "right-psk",
		"11111111-2222-4333-8444-000000000040")
	if got.resp.Code != 0 {
		t.Fatalf("登录应成功: %+v", got.resp)
	}

	var haveV4, haveV6 bool
	for _, a := range got.salt.VirtualIPAssignments {
		addr, err := netip.ParseAddr(a.VirtualIP)
		if err != nil {
			t.Fatalf("下发的地址解析不了: %q", a.VirtualIP)
		}
		if addr.Unmap().Is4() {
			haveV4 = true
			if !netip.MustParsePrefix("10.98.0.1/24").Contains(addr.Unmap()) {
				t.Errorf("v4 地址 %s 不在配置网段内", a.VirtualIP)
			}
		} else {
			haveV6 = true
			if !netip.MustParsePrefix("fd00:98::1/64").Contains(addr) {
				t.Errorf("v6 地址 %s 不在配置网段内", a.VirtualIP)
			}
			if a.Mask != "64" {
				t.Errorf("v6 下发的前缀长度 = %q,期望 64", a.Mask)
			}
		}
	}
	if !haveV4 {
		t.Error("没下发 v4 地址")
	}
	if !haveV6 {
		t.Error("配了 subnets_v6 却没下发 v6 地址 —— 登录看着成功,客户端 v6 全黑")
	}
	// v6 解析器只在配了 v6 网关时才下发:没有 v6 地址却给 v6 DNS,客户端每次 v6 查询都白等一轮超时。
	if len(got.salt.DNSServersV6) == 0 {
		t.Error("配了 v6 网关就该下发 v6 解析器")
	}
}

// TestLogin_WithoutAV6GatewayNoV6IsPromised 没配 v6 网段时,既不该给 v6 地址,也不该给 v6 解析器。
// 给了就是让客户端对着一个不存在的 v6 通路发查询,每次都白等超时才回落 v4。
func TestLogin_WithoutAV6GatewayNoV6IsPromised(t *testing.T) {
	env := newLoginGateEnv(t)
	withDualStackTUN(t, "10.99.0.1/24", "")
	env.gw.cfg.TUN.DNSServersV6 = []string{"2606:4700:4700::1111"}

	got := dualStackLogin(t, env, stormAddr(41), "known", "right-psk",
		"11111111-2222-4333-8444-000000000041")
	if got.resp.Code != 0 {
		t.Fatalf("登录应成功: %+v", got.resp)
	}
	for _, a := range got.salt.VirtualIPAssignments {
		if addr, err := netip.ParseAddr(a.VirtualIP); err == nil && !addr.Unmap().Is4() {
			t.Errorf("没配 v6 网段却下发了 v6 地址 %s", a.VirtualIP)
		}
	}
	if len(got.salt.DNSServersV6) != 0 {
		t.Errorf("没配 v6 网段却下发了 v6 解析器 %v —— 客户端每次 v6 查询都要白等一轮超时",
			got.salt.DNSServersV6)
	}
}

// TestLogin_AnExhaustedV6PoolStillLetsV4Through v6 池耗尽是**降级**而不是拒登。
//
// v6 地址不是必需品:拿不到就只用 v4,连接照常可用。这里若改成拒登,一个 v6 网段配小了就会
// 把所有人挡在门外 —— 而运维完全看不出跟 v6 有关。用 /127(没有可分配主机位)造耗尽。
func TestLogin_AnExhaustedV6PoolStillLetsV4Through(t *testing.T) {
	env := newLoginGateEnv(t)
	withDualStackTUN(t, "10.100.0.1/24", "fd00:100::1/127")

	got := dualStackLogin(t, env, stormAddr(42), "known", "right-psk",
		"11111111-2222-4333-8444-000000000042")
	if got.resp.Code != 0 {
		t.Fatalf("v6 分不到地址不该拒登(v6 是可选的),got %+v", got.resp)
	}
	var haveV4, haveV6 bool
	for _, a := range got.salt.VirtualIPAssignments {
		if addr, err := netip.ParseAddr(a.VirtualIP); err == nil && addr.Unmap().Is4() {
			haveV4 = true
		} else {
			haveV6 = true
		}
	}
	if !haveV4 {
		t.Error("v6 分配失败时 v4 仍必须下发")
	}
	if haveV6 {
		t.Error("/127 没有可分配主机位,却下发了 v6 地址")
	}
}

// TestLogin_ReusesTheLeasedAddressAcrossReconnects 同一台设备重连应拿回同一个地址。
//
// 拿不回来不算「报错」,但每次重连换地址会让服务端下发的 ACL / 端口转发目标全部对不上号,
// 而且小网段上很快把地址烧光(每台设备每次重连烧一个,旧的要等 lease gc)。
func TestLogin_ReusesTheLeasedAddressAcrossReconnects(t *testing.T) {
	env := newLoginGateEnv(t)
	withDualStackTUN(t, "10.101.0.1/24", "fd00:101::1/64")
	const uuid = "11111111-2222-4333-8444-000000000043"

	first := dualStackLogin(t, env, stormAddr(43), "known", "right-psk", uuid)
	if first.resp.Code != 0 {
		t.Fatalf("首次登录应成功: %+v", first.resp)
	}
	firstIPs := map[string]bool{}
	for _, a := range first.salt.VirtualIPAssignments {
		firstIPs[a.VirtualIP] = true
	}
	if len(firstIPs) == 0 {
		t.Fatal("首次登录没拿到任何地址")
	}

	// 让第一条会话彻底下线,地址回到池子,但 leases 里还记着它。
	if err := waitLeasePersisted(t, env, uuid); err != nil {
		t.Fatalf("等 lease 落库: %v", err)
	}

	second := dualStackLogin(t, env, stormAddr(44), "known", "right-psk", uuid)
	if second.resp.Code != 0 {
		t.Fatalf("重连应成功: %+v", second.resp)
	}
	for _, a := range second.salt.VirtualIPAssignments {
		if !firstIPs[a.VirtualIP] {
			t.Errorf("重连拿到了新地址 %s(首次是 %v)—— 每次重连烧一个地址,ACL / 端口转发目标也跟着错位",
				a.VirtualIP, keysOf(firstIPs))
		}
	}
}

// TestLogin_RefusesWhenTheAddressIsAlreadyLeasedToAnotherDevice 撞号必须拒登。
//
// 这是最后一道防线。前面几道都在库里:`set-fixed-vip` 不带 --force 时会因跨表守卫直接拒绝,
// 带 --force 时会主动把别的设备占着该地址的 lease 释放掉 —— 所以正常走 API 根本造不出撞号。
// 但分配路径仍有一个它自己看不破的盲点:「把本设备自己的地址从已用集里剔除」时,没法区分
// 「我的 fixed」和「别人的活 lease」,两者是同一个字符串。真出现这种错位(库里有别人的离线
// lease 而分配没算到)时,唯一还能拦住的就是写 lease 时的 UNIQUE 索引。
//
// 所以这里绕过 API 直接写库,把那个错位状态造出来,验证最后这道确实会拒登 —— 放过去就是两台
// 设备带同一个 vIP 上线,回程包发给谁全看运气。
func TestLogin_RefusesWhenTheAddressIsAlreadyLeasedToAnotherDevice(t *testing.T) {
	env := newLoginGateEnv(t)
	withDualStackTUN(t, "10.102.0.1/24", "")
	ctx := t.Context()

	const contested = "10.102.0.77"
	uA := "11111111-2222-4333-8444-00000000004a"
	devA, err := env.st.UpsertDevice(ctx, 1, uA, "A", "")
	if err != nil {
		t.Fatalf("建设备 A: %v", err)
	}
	uB := "11111111-2222-4333-8444-00000000004b"
	devB, err := env.st.UpsertDevice(ctx, 1, uB, "B", "")
	if err != nil {
		t.Fatalf("建设备 B: %v", err)
	}
	// 先钉 B 的 fixed(此刻还没有冲突的 lease,跨表守卫放行),再直接写库给 A 造一条同址 lease。
	// 顺序反过来的话 --force 会把 A 的 lease 释放掉,错位状态就造不出来了。
	if err := env.st.SetDeviceFixedVIP(ctx, devB.ID, contested, "", false); err != nil {
		t.Fatalf("给 B 钉 fixed: %v", err)
	}
	if _, err := env.st.DB().ExecContext(ctx,
		`INSERT INTO leases(device_id, vip_v4, manual, assigned_at) VALUES(?,?,0,?)`,
		devA.ID, contested, time.Now().Unix()); err != nil {
		t.Fatalf("直接写库造 A 的 lease: %v", err)
	}

	got := dualStackLogin(t, env, stormAddr(45), "known", "right-psk", uB)
	if got.resp.Code == 0 {
		// 也允许分配路径提前避开这个地址 —— 那同样安全,只是没走到最后这道。
		for _, a := range got.salt.VirtualIPAssignments {
			if a.VirtualIP == contested {
				t.Fatalf("B 拿到了 A 已持有的地址 %s 还登录成功 —— 两台设备同一个 vIP,回程包发给谁全看运气",
					contested)
			}
		}
		return
	}
	if got.resp.Message == "" {
		t.Error("拒登要带文案,否则客户端分不清是拒登还是网抖,只会无限重连")
	}
	// 拒登之后不许把这个地址记成「已占用」——记了就是永久漏一格。释放走的是 defer cleanupConnection,
	// 相对这里是异步的,所以给它一个有界的窗口。
	deadline := time.Now().Add(5 * time.Second)
	for {
		clientIPUsedMu.Lock()
		stillUsed := clientIPUsed[contested]
		clientIPUsedMu.Unlock()
		if !stillUsed {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("拒登后 %s 仍被算作占用 —— 池子永久少一格,攒够了就是「新用户连不上,重启才好」", contested)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestLogin_NeverHandsOutAPinnedAddressThatWouldBreakTheClient 手钉的偏好地址也要过可用性筛。
//
// 自动分配从主机位 2 起扫,天然避开网关 / 网络 / 广播;而「直接采用偏好 vIP」这条快路没有那层
// 过滤。管理员把 fixed_vip 钉成网关地址(打错一位就会,10.0.0.1 vs 10.0.0.10),网段检查会通过、
// 内存 used 里也没有 —— 客户端于是拿到网关地址,与 server 撞车、整条路由断,而登录是成功的。
// 两族都要挡,这里连 v6 一起钉住(v6 那侧的过滤此前没有任何断言覆盖)。
func TestLogin_NeverHandsOutAPinnedAddressThatWouldBreakTheClient(t *testing.T) {
	for _, tc := range []struct {
		name      string
		gw4, gw6  string
		fixV4     string
		fixV6     string
		forbidden []string
		uuid      string
	}{
		{
			name: "钉成 v4 网关地址", gw4: "10.104.0.1/24", gw6: "",
			fixV4: "10.104.0.1", forbidden: []string{"10.104.0.1"},
			uuid: "44444444-5555-4666-8777-000000000104",
		},
		{
			name: "钉成 v4 定向广播地址", gw4: "10.105.0.1/24", gw6: "",
			fixV4: "10.105.0.255", forbidden: []string{"10.105.0.255"},
			uuid: "44444444-5555-4666-8777-000000000105",
		},
		{
			name: "钉成 v6 网关地址", gw4: "10.106.0.1/24", gw6: "fd00:106::1/64",
			fixV6: "fd00:106::1", forbidden: []string{"fd00:106::1"},
			uuid: "44444444-5555-4666-8777-000000000106",
		},
		{
			name: "钉成落在网段外的 v6", gw4: "10.107.0.1/24", gw6: "fd00:107::1/64",
			fixV6: "fd00:999::9", forbidden: []string{"fd00:999::9"},
			uuid: "44444444-5555-4666-8777-000000000107",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newLoginGateEnv(t)
			withDualStackTUN(t, tc.gw4, tc.gw6)
			ctx := t.Context()

			dev, err := env.st.UpsertDevice(ctx, 1, tc.uuid, "pinned", "")
			if err != nil {
				t.Fatalf("建设备: %v", err)
			}
			if err := env.st.SetDeviceFixedVIP(ctx, dev.ID, tc.fixV4, tc.fixV6, true); err != nil {
				t.Fatalf("钉 fixed_vip: %v", err)
			}

			got := dualStackLogin(t, env, stormAddr(50), "known", "right-psk", tc.uuid)
			if got.resp.Code != 0 {
				t.Fatalf("钉错地址不该让登录失败(应改为自动分配一个可用的): %+v", got.resp)
			}
			for _, a := range got.salt.VirtualIPAssignments {
				for _, bad := range tc.forbidden {
					if a.VirtualIP == bad {
						t.Fatalf("客户端拿到了 %s —— 这个地址用不了(网关会与 server 撞车、"+
							"广播地址部分内核直接丢弃、网段外的根本不通),而登录是成功的", bad)
					}
				}
			}
		})
	}
}

// TestLogin_AppliesTheRateLimitAtHandshakeTime 限速在握手时就要挂上。
//
// 挂晚了或没挂上,这条会话就是不限速的 —— 而后台、审计、/status 全都显示它受限。
// 这里只钉住「配了限速的登录仍然成功且拿到地址」,速率本身的准确性由 rate 包自己的用例负责。
func TestLogin_AppliesTheRateLimitAtHandshakeTime(t *testing.T) {
	env := newLoginGateEnv(t)
	withDualStackTUN(t, "10.103.0.1/24", "")
	ctx := t.Context()

	// 给用户挂上带宽上限:走 effectiveLinkRates → 建 limiter 那两条分支。
	if err := env.st.SetUserBandwidth(ctx, 1, 1_000_000, 2_000_000); err != nil {
		t.Skipf("这套 store 不支持按用户设带宽,跳过: %v", err)
	}

	got := dualStackLogin(t, env, stormAddr(46), "known", "right-psk",
		"11111111-2222-4333-8444-000000000046")
	if got.resp.Code != 0 {
		t.Fatalf("配了限速的登录仍应成功: %+v", got.resp)
	}
	if len(got.salt.VirtualIPAssignments) == 0 {
		t.Error("限速会话也必须拿到地址")
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// waitLeasePersisted 等到该设备的 lease 真的落库(登录路径是异步写的)。
func waitLeasePersisted(t *testing.T, env *loginGateEnv, uuid string) error {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		dev, err := env.st.GetDeviceByUUIDAny(t.Context(), uuid)
		if err == nil && dev != nil {
			lease, err := env.st.GetLeaseByDevice(t.Context(), dev.ID)
			if err == nil && lease != nil && (lease.VIPv4 != "" || lease.VIPv6 != "") {
				return nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errLeaseNotPersisted
}

var errLeaseNotPersisted = errors.New("lease 一直没落库")
