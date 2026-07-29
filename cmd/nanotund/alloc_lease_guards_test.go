package main

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// vIP 的「偏好」与「已占用」两侧。
//
// 分配一个地址要同时回答两个问题:这台设备**应该**拿哪个(管理员手钉的 fixed > 它上次的 lease >
// 随便分一个),以及哪些地址**不能**拿(在线会话占的 + 库里离线 lease 占的)。两边任一处算错,
// 结果都是同一个:两台设备拿到同一个 vIP。表现是其中一台时通时不通,而登录、审计、后台全部正常。
//
// 这一组补的是尚无断言的失败路径 —— 全都是「查不到就退回上一档」而不是「查不到就当没占用」。

func newLeaseGateway(t *testing.T) *gatewayState {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "lease.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return &gatewayState{store: st}
}

// mkLeaseDevice 建用户 + 设备,可选给 fixed vIP 与历史 lease。
func mkLeaseDevice(t *testing.T, gw *gatewayState, username, uuid, fixedV4, fixedV6, leaseV4, leaseV6 string) *store.Device {
	t.Helper()
	u, err := gw.store.CreateUser(t.Context(), store.NewUser{Username: username, PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	dev, err := gw.store.UpsertDevice(t.Context(), u.ID, uuid, "dev", "")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if fixedV4 != "" || fixedV6 != "" {
		if err := gw.store.SetDeviceFixedVIP(t.Context(), dev.ID, fixedV4, fixedV6, true); err != nil {
			t.Fatalf("SetDeviceFixedVIP: %v", err)
		}
	}
	if leaseV4 != "" || leaseV6 != "" {
		if _, err := gw.store.UpsertLease(t.Context(), dev.ID, leaseV4, leaseV6, false); err != nil {
			t.Fatalf("UpsertLease: %v", err)
		}
	}
	fresh, err := gw.store.GetDeviceByUUIDAny(t.Context(), uuid)
	if err != nil || fresh == nil {
		t.Fatalf("回读设备: %v", err)
	}
	return fresh
}

// TestPreferredLeasedVIPs_FixedBeatsLeaseAndNeitherIsInvented 偏好的优先级与降级。
func TestPreferredLeasedVIPs_FixedBeatsLeaseAndNeitherIsInvented(t *testing.T) {
	t.Run("缺任何一环时不给偏好", func(t *testing.T) {
		gw := newLeaseGateway(t)
		dev := mkLeaseDevice(t, gw, "u1", "aaaaaaaa-0000-4000-8000-000000000001", "", "", "10.0.0.9", "")
		for name, args := range map[string]struct {
			gw  *gatewayState
			res *loginAuthResult
		}{
			"gw 为空":    {nil, &loginAuthResult{Device: dev}},
			"没有 store": {&gatewayState{}, &loginAuthResult{Device: dev}},
			"res 为空":   {gw, nil},
			"res 没有设备": {gw, &loginAuthResult{}},
		} {
			v4, v6 := preferredLeasedVIPs(args.gw, args.res)
			if v4 != "" || v6 != "" {
				t.Errorf("%s:不该给出偏好,got (%q,%q)", name, v4, v6)
			}
		}
	})

	t.Run("有 fixed 时以 fixed 为准", func(t *testing.T) {
		gw := newLeaseGateway(t)
		// fixed 与 lease 故意不同:这正是 `set-fixed-vip --force` 之后的形状。
		dev := mkLeaseDevice(t, gw, "u2", "aaaaaaaa-0000-4000-8000-000000000002",
			"10.0.0.50", "fd00::50", "10.0.0.9", "fd00::9")
		v4, v6 := preferredLeasedVIPs(gw, &loginAuthResult{Device: dev})
		if v4 != "10.0.0.50" || v6 != "fd00::50" {
			t.Errorf("fixed 应优先于历史 lease,got (%q,%q)", v4, v6)
		}
	})

	t.Run("没有 fixed 就用上次的 lease", func(t *testing.T) {
		gw := newLeaseGateway(t)
		dev := mkLeaseDevice(t, gw, "u3", "aaaaaaaa-0000-4000-8000-000000000003",
			"", "", "10.0.0.9", "fd00::9")
		v4, v6 := preferredLeasedVIPs(gw, &loginAuthResult{Device: dev})
		if v4 != "10.0.0.9" || v6 != "fd00::9" {
			t.Errorf("应复用上次 lease,got (%q,%q)", v4, v6)
		}
	})

	t.Run("只钉了一族时另一族退回 lease", func(t *testing.T) {
		gw := newLeaseGateway(t)
		dev := mkLeaseDevice(t, gw, "u4", "aaaaaaaa-0000-4000-8000-000000000004",
			"10.0.0.50", "", "10.0.0.9", "fd00::9")
		v4, v6 := preferredLeasedVIPs(gw, &loginAuthResult{Device: dev})
		if v4 != "10.0.0.50" {
			t.Errorf("v4 应用 fixed,got %q", v4)
		}
		if v6 != "fd00::9" {
			t.Errorf("v6 没钉 fixed,应退回 lease,got %q", v6)
		}
	})

	t.Run("lease 查不动时仍然给出 fixed", func(t *testing.T) {
		gw := newLeaseGateway(t)
		dev := mkLeaseDevice(t, gw, "u5", "aaaaaaaa-0000-4000-8000-000000000005",
			"10.0.0.50", "fd00::50", "", "")
		if _, err := gw.store.DB().ExecContext(t.Context(),
			`ALTER TABLE leases RENAME TO leases_gone`); err != nil {
			t.Fatalf("藏表: %v", err)
		}
		v4, v6 := preferredLeasedVIPs(gw, &loginAuthResult{Device: dev})
		if v4 != "10.0.0.50" || v6 != "fd00::50" {
			t.Errorf("lease 表读不动时管理员手钉的地址不该跟着丢,got (%q,%q)", v4, v6)
		}
	})
}

// TestPreferredVIPUsable_RejectsTheAddressesThatWouldBreakTheClient 偏好地址的可用性过滤。
//
// 自动分配路径从主机位 2 起扫,天然避开网关 / 网络 / 广播地址;而「直接采用偏好 vIP」这条快路
// 没有那层过滤 —— 管理员把 fixed_vip 手钉成 10.0.0.1(网关)或 10.0.0.255(广播),网段检查
// 会通过、used 里也没有,于是客户端拿到一个用不了的地址:前者与 server 网关撞车、整条路由断,
// 后者部分内核直接丢弃以广播地址为源的报文。两条都是修过的缺陷。
func TestPreferredVIPUsable_RejectsTheAddressesThatWouldBreakTheClient(t *testing.T) {
	const cidr = "10.0.0.1/24"
	used := map[string]bool{"10.0.0.7": true}

	for _, tc := range []struct {
		name string
		vip  string
		want bool
	}{
		{"正常地址", "10.0.0.20", true},
		{"空串", "", false},
		{"已被占用", "10.0.0.7", false},
		{"网关地址", "10.0.0.1", false},
		{"网络地址", "10.0.0.0", false},
		{"定向广播地址", "10.0.0.255", false},
		{"网段外", "10.0.1.20", false},
		{"根本不是 IP", "不是地址", false},
		{"另一族", "fd00::20", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := preferredVIPUsable(cidr, tc.vip, used); got != tc.want {
				t.Errorf("preferredVIPUsable(%q) = %v,期望 %v", tc.vip, got, tc.want)
			}
		})
	}

	t.Run("网段本身不合法时一律不可用", func(t *testing.T) {
		if preferredVIPUsable("不是网段", "10.0.0.20", nil) {
			t.Error("解析不了的网段不该放行任何偏好地址")
		}
	})

	// v6 侧:没有广播概念,但网关 / 网络地址同样要挡。
	t.Run("v6 的网关与网络地址", func(t *testing.T) {
		const v6cidr = "fd00:80::1/64"
		if preferredVIPUsable(v6cidr, "fd00:80::1", nil) {
			t.Error("v6 网关地址不该放行")
		}
		if preferredVIPUsable(v6cidr, "fd00:80::", nil) {
			t.Error("v6 网络地址不该放行")
		}
		if !preferredVIPUsable(v6cidr, "fd00:80::20", nil) {
			t.Error("正常 v6 地址应放行")
		}
	})
}

// TestIPv4DirectedBroadcast_RespectsRFC3021 /31 与 /32 没有广播地址(RFC 3021)。
// 硬算一个出来会把点对点网段里那个**合法可用**的地址当广播挡掉 —— 于是一台设备永远分不到地址。
func TestIPv4DirectedBroadcast_RespectsRFC3021(t *testing.T) {
	for _, tc := range []struct {
		cidr  string
		want  string
		wantK bool
	}{
		{"10.0.0.1/24", "10.0.0.255", true},
		{"10.0.0.1/16", "10.0.255.255", true},
		{"10.0.0.1/30", "10.0.0.3", true},
		{"10.0.0.1/31", "", false}, // RFC 3021:点对点,无广播
		{"10.0.0.1/32", "", false},
		{"fd00::1/64", "", false}, // v6 没有广播
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			got, ok := ipv4DirectedBroadcast(netip.MustParsePrefix(tc.cidr))
			if ok != tc.wantK {
				t.Fatalf("ok = %v,期望 %v", ok, tc.wantK)
			}
			if ok && got.String() != tc.want {
				t.Errorf("广播地址 = %s,期望 %s", got, tc.want)
			}
		})
	}
}

// TestDBReservedVIPs_FallsBackToMemoryOnlyWhenTheTableIsGone 库里的已占用集。
//
// 读不到 leases 表时返回空集(登录退化成只看内存 used)。这是有意的取舍:宁可有小概率撞上一个
// 离线设备的 lease(写 lease 时会撞 UNIQUE、那条路径会拒登),也不要让所有人因为一次库故障登不进来。
func TestDBReservedVIPs_FallsBackToMemoryOnlyWhenTheTableIsGone(t *testing.T) {
	gw := newLeaseGateway(t)
	mkLeaseDevice(t, gw, "u1", "aaaaaaaa-0000-4000-8000-00000000000a", "", "", "10.0.0.9", "fd00::9")
	mkLeaseDevice(t, gw, "u2", "aaaaaaaa-0000-4000-8000-00000000000b", "", "", "10.0.0.10", "fd00::10")

	v4, v6 := dbReservedVIPs(gw, nil, nil)
	if !v4["10.0.0.9"] || !v4["10.0.0.10"] {
		t.Fatalf("库里两条 lease 都该算已占用,got %v", v4)
	}
	if !v6["fd00::9"] {
		t.Fatalf("v6 lease 也该算已占用,got %v", v6)
	}

	// except:本设备自己的地址不该被当成别人占用,否则它复用不到自己的地址。
	v4, v6 = dbReservedVIPs(gw, []string{"10.0.0.9", ""}, []string{"fd00::9"})
	if v4["10.0.0.9"] {
		t.Error("本设备自己的 v4 应从已占用集里剔除 —— 否则它拿不回自己的地址")
	}
	if v6["fd00::9"] {
		t.Error("本设备自己的 v6 应被剔除")
	}
	if !v4["10.0.0.10"] {
		t.Error("别人的地址仍要算已占用")
	}

	// 没有 store / 没有 gateway → 空集,不炸。
	if a, b := dbReservedVIPs(nil, nil, nil); a != nil || b != nil {
		t.Error("gw 为空应返回空集")
	}
	if a, b := dbReservedVIPs(&gatewayState{}, nil, nil); a != nil || b != nil {
		t.Error("没有 store 应返回空集")
	}

	// 表读不动 → 空集(登录照常放行,只是退化到仅看内存)。
	if _, err := gw.store.DB().ExecContext(t.Context(),
		`ALTER TABLE leases RENAME TO leases_gone`); err != nil {
		t.Fatalf("藏表: %v", err)
	}
	if a, b := dbReservedVIPs(gw, nil, nil); a != nil || b != nil {
		t.Error("读不到 leases 表时应退回空集,让登录继续(不是拒绝所有人登录)")
	}
}

// TestDeviceReservedVIPExceptions_CoversBothFixedAndLease 第十九轮那条 MED 的回归。
//
// 这里必须同时返回 fixed **和** 当前 lease。只返回 fixed 的后果很隐蔽:当两者不同(比如
// `set-fixed-vip --force` 撞上仍在线的旧持有者、或 fixed 掉出了网段),本设备自己的 lease
// 会被当成「别人占用」——它既复用不到、也回收不了,于是拿到第三个地址,fixed 与新 lease 并存,
// 同一台设备白占两个 vIP。小前缀上这就是实打实地烧地址。
func TestDeviceReservedVIPExceptions_CoversBothFixedAndLease(t *testing.T) {
	gw := newLeaseGateway(t)
	dev := mkLeaseDevice(t, gw, "u1", "aaaaaaaa-0000-4000-8000-00000000000c",
		"10.0.0.50", "fd00::50", "10.0.0.9", "fd00::9")

	v4s, v6s := deviceReservedVIPExceptions(gw, &loginAuthResult{Device: dev})
	if !containsStr(v4s, "10.0.0.50") || !containsStr(v4s, "10.0.0.9") {
		t.Errorf("fixed 与当前 lease 都要在 except 里,got %v", v4s)
	}
	if !containsStr(v6s, "fd00::50") || !containsStr(v6s, "fd00::9") {
		t.Errorf("v6 侧同理,got %v", v6s)
	}

	// 查库失败时退回 fixed 部分,不阻断登录。
	if _, err := gw.store.DB().ExecContext(t.Context(),
		`ALTER TABLE leases RENAME TO leases_gone`); err != nil {
		t.Fatalf("藏表: %v", err)
	}
	v4s, v6s = deviceReservedVIPExceptions(gw, &loginAuthResult{Device: dev})
	if !containsStr(v4s, "10.0.0.50") || !containsStr(v6s, "fd00::50") {
		t.Errorf("lease 读不动时至少要保住 fixed,got %v / %v", v4s, v6s)
	}

	// 缺环时返回空,不炸。
	if a, b := deviceReservedVIPExceptions(nil, nil); a != nil || b != nil {
		t.Error("gw 与 res 为空应返回空")
	}
	if a, b := deviceReservedVIPExceptions(gw, &loginAuthResult{}); a != nil || b != nil {
		t.Error("没有设备时应返回空")
	}
}

// TestPersistDeviceLease_TellsRefusalApartFromMereFailure 落 lease 的两类错误。
//
// 撞 vIP UNIQUE 必须回错让调用方**拒登**:同一个地址被两台设备持有,数据面就是路由黑洞,
// 而这说明 alloc 那侧漏算了库里的离线 lease。其它 DB 故障只记 warn 并放行:lease 存不下
// 只影响「下次登录能不能拿回同一个地址」,不值得把人挡在门外。
//
// 混在一起处理的两种坏法方向相反:都当致命 → 一次库抖动让所有人登不进;都当无害 →
// 两台设备带着同一个 vIP 上线。
func TestPersistDeviceLease_TellsRefusalApartFromMereFailure(t *testing.T) {
	t.Run("撞 UNIQUE 时回错(调用方据此拒登)", func(t *testing.T) {
		gw := newLeaseGateway(t)
		// 另一台设备已经持有 10.0.0.9。
		mkLeaseDevice(t, gw, "holder", "aaaaaaaa-0000-4000-8000-00000000000d", "", "", "10.0.0.9", "")
		newDev := mkLeaseDevice(t, gw, "newcomer", "aaaaaaaa-0000-4000-8000-00000000000e", "", "", "", "")

		err := persistDeviceLease(gw, &loginAuthResult{Device: newDev},
			[]util.VirtualIPAssignment{{VirtualIP: "10.0.0.9"}})
		if err == nil {
			t.Fatal("撞了别人的 vIP 必须回错 —— 放过去就是两台设备同一个地址,数据面黑洞")
		}
		if !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("应是 store.ErrDuplicate(调用方据此拒登),got %v", err)
		}
	})

	t.Run("其它 DB 故障只 warn 并放行", func(t *testing.T) {
		gw := newLeaseGateway(t)
		dev := mkLeaseDevice(t, gw, "u1", "aaaaaaaa-0000-4000-8000-00000000000f", "", "", "", "")
		if _, err := gw.store.DB().ExecContext(t.Context(),
			`ALTER TABLE leases RENAME TO leases_gone`); err != nil {
			t.Fatalf("藏表: %v", err)
		}
		if err := persistDeviceLease(gw, &loginAuthResult{Device: dev},
			[]util.VirtualIPAssignment{{VirtualIP: "10.0.0.9"}}); err != nil {
			t.Errorf("非冲突类故障应放行登录(仅 warn),got %v", err)
		}
	})

	t.Run("没有可落的东西时是无害 noop", func(t *testing.T) {
		gw := newLeaseGateway(t)
		dev := mkLeaseDevice(t, gw, "u1", "aaaaaaaa-0000-4000-8000-000000000010", "", "", "", "")
		for name, as := range map[string][]util.VirtualIPAssignment{
			"空列表":     nil,
			"只有空地址":   {{VirtualIP: ""}},
			"地址解析不出来": {{VirtualIP: "不是地址"}},
		} {
			if err := persistDeviceLease(gw, &loginAuthResult{Device: dev}, as); err != nil {
				t.Errorf("%s:应是 noop,got %v", name, err)
			}
		}
		if err := persistDeviceLease(nil, nil, nil); err != nil {
			t.Errorf("缺环时应是 noop,got %v", err)
		}
	})

	t.Run("地址等于 fixed 时标成 manual", func(t *testing.T) {
		gw := newLeaseGateway(t)
		dev := mkLeaseDevice(t, gw, "u1", "aaaaaaaa-0000-4000-8000-000000000011",
			"10.0.0.50", "", "", "")
		if err := persistDeviceLease(gw, &loginAuthResult{Device: dev},
			[]util.VirtualIPAssignment{{VirtualIP: "10.0.0.50"}}); err != nil {
			t.Fatalf("落 lease: %v", err)
		}
		lease, err := gw.store.GetLeaseByDevice(t.Context(), dev.ID)
		if err != nil || lease == nil {
			t.Fatalf("回读 lease: %v", err)
		}
		if !lease.Manual {
			t.Error("地址来自管理员手钉的 fixed_vip,lease 应标 manual —— " +
				"否则 lease gc 会把它当自动分配的回收掉")
		}
	})
}

// TestMergeUsedVIPs_DoesNotTouchItsInputs 合并已占用集不许改动入参。
// 改动了就是把「库里离线占用」写进了「在线会话占用」那张全局表 —— 那些地址从此永不回收。
func TestMergeUsedVIPs_DoesNotTouchItsInputs(t *testing.T) {
	a := map[string]bool{"10.0.0.2": true}
	b := map[string]bool{"10.0.0.3": true}
	out := mergeUsedVIPs(a, b)
	if !out["10.0.0.2"] || !out["10.0.0.3"] {
		t.Fatalf("并集应含两侧,got %v", out)
	}
	if len(a) != 1 || len(b) != 1 {
		t.Error("不许改动入参 —— 把库里的离线占用写进内存表,那些地址从此永不回收")
	}
	if got := mergeUsedVIPs(nil, nil); len(got) != 0 {
		t.Errorf("两侧皆空应得空集,got %v", got)
	}
}

func TestIsIPv4_AcceptsMappedFormToo(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"10.0.0.2", true},
		{"::ffff:10.0.0.2", true}, // v4-mapped 仍算 v4:否则它会被当 v6 lease 落进错误的列
		{"fd00::2", false},
		{"", false},
		{"不是地址", false},
	} {
		if got := isIPv4(tc.in); got != tc.want {
			t.Errorf("isIPv4(%q) = %v,期望 %v", tc.in, got, tc.want)
		}
	}
}

// TestSameSubnetAndGatewayAddr_FailClosedOnGarbage 两个小工具的坏输入。
func TestSameSubnetAndGatewayAddr_FailClosedOnGarbage(t *testing.T) {
	if sameSubnet("不是网段", "10.0.0.2") {
		t.Error("网段解析不了应回 false")
	}
	if sameSubnet("10.0.0.1/24", "不是地址") {
		t.Error("地址解析不了应回 false")
	}
	if !sameSubnet("10.0.0.1/24", "10.0.0.2") {
		t.Error("同网段应回 true")
	}
	if got := gatewayAddrFromCIDR("10.0.0.1/24"); got != "10.0.0.1" {
		t.Errorf("gatewayAddrFromCIDR = %q", got)
	}
	// 解析失败时原样返回,让调用方还能往下走(最坏只是日志字段不规范)。
	if got := gatewayAddrFromCIDR("garbage"); got != "garbage" {
		t.Errorf("解析失败应原样返回,got %q", got)
	}
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
