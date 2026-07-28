package main

// 路由宣告帧的拒绝面与两个「豁免闸」。
//
// handleRouteAdvertiseFrame 在这个包里是少见的「一帧改一堆会话状态」的函数:除了往库里写
// pending 路由,它还翻五个会话级标志,其中两个是**源地址伪装豁免闸**
// (advertisedExitApproved / advertisedSubnetApproved)—— 打开后该会话就能以非自身 vIP 的
// 源地址发包(出口 NAT / LAN 回程要用)。这类标志判错不会报错:
//
//   - 该清的没清:一个已经撤回声明的会话继续保有伪装豁免,且数据面仍把发往其网段的包投给它;
//   - 该保守的没保守:DB 查不动时把豁免闸当「已批准」打开,等于凭一次抖动放开源地址校验。
//
// 所以这里钉的是「入口拒绝」+「撤回必须彻底」+「查不动时闸门怎么动」三类。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// awaitExitsBroadcast 等「撤回出口」触发的那条 `go broadcastExitsList` 落地。
//
// 两个作用。一是断言:出口撤回后必须**立刻**重算并推给所有 exit_allowed 会话,否则它们下拉里
// 那台已经不转发的出口要留到下次上下线才消失,期间选中它就是黑洞。二是同步:那条 goroutine 会读
// gatewayInstance,不等它就在 t.Cleanup 里把值改回去,是一个真实的 data race(-race 下必挂)。
// 收到帧即证明读已完成 —— fake 的写在它自己的锁里,和这里的读构成 happens-before。
func awaitExitsBroadcast(t *testing.T, watcher *routeFakeConn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(watcher.bytes()) > 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("等不到出口列表广播 —— 已撤回的出口会一直留在别人的下拉里,直到它下线")
}

// registerExitsWatcher 挂一条只用来收广播的 exit_allowed 会话。它**不是**宣告方,所以它的
// fake 上只会出现广播帧,不会混进宣告方那条同步回的 route status 帧。
func registerExitsWatcher(t *testing.T) *routeFakeConn {
	t.Helper()
	fake := &routeFakeConn{}
	const sid = "exits-watcher"
	w := &Connection{userID: "watcher", connIDStr: sid, linkConn: fake, exitAllowed: true}
	connIDMapMu.Lock()
	connIDMap[sid] = w
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, sid)
		connIDMapMu.Unlock()
	})
	return fake
}

// exitAdvertiseFrame 造一帧 Exit=true 的宣告(MarshalRouteAdvertise 不带 Exit 字段)。
func exitAdvertiseFrame(t *testing.T, routes []string) []byte {
	t.Helper()
	body, err := json.Marshal(util.RouteAdvertise{
		Schema: util.RouteSchemaCurrent, Routes: routes, Exit: true,
	})
	if err != nil {
		t.Fatalf("marshal exit advertise: %v", err)
	}
	return body
}

// newAdvConn 造一条已登录、带 deviceID 的会话。
func newAdvConn(deviceID int64) *Connection {
	return &Connection{userID: "u1", connIDStr: "adv", deviceID: deviceID, linkConn: &routeFakeConn{}}
}

// relaxRouteStatusNotNull 重建 subnet_routes、去掉 status 的 NOT NULL,但**保留**
// UNIQUE(device_id, cidr) —— UpsertAdvertisedRoute 的 ON CONFLICT 依赖它,丢了约束就
// 变成「upsert 也失败」,那就分不清拦下测试的是哪一步了。
func relaxRouteStatusNotNull(t *testing.T, st *store.Store) {
	t.Helper()
	for _, stmt := range []string{
		`CREATE TABLE subnet_routes_relaxed (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL,
			cidr TEXT NOT NULL,
			status TEXT,
			advertised_at INTEGER NOT NULL DEFAULT 0,
			approved_at INTEGER NOT NULL DEFAULT 0,
			reason TEXT NOT NULL DEFAULT '',
			UNIQUE(device_id, cidr))`,
		`INSERT INTO subnet_routes_relaxed(id, device_id, cidr, status, advertised_at, approved_at, reason)
		 SELECT id, device_id, cidr, status, advertised_at, approved_at, reason FROM subnet_routes`,
		`DROP TABLE subnet_routes`,
		`ALTER TABLE subnet_routes_relaxed RENAME TO subnet_routes`,
	} {
		if _, err := st.DB().ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("放宽 subnet_routes.status 约束: %v", err)
		}
	}
}

// countRoutes 数某设备名下的路由条数。
func countRoutes(t *testing.T, st *store.Store, deviceID int64) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM subnet_routes WHERE device_id=?`, deviceID).Scan(&n); err != nil {
		t.Fatalf("数路由: %v", err)
	}
	return n
}

// TestHandleRouteAdvertiseFrame_EntryGuards 三条入口拒绝:空会话、没有 store、帧解析不出。
// 前两条只要求不 panic 且不计数;第三条要计 failed,否则「客户端发的帧一直被丢」在 /status
// 上完全看不出来。
func TestHandleRouteAdvertiseFrame_EntryGuards(t *testing.T) {
	ctx := context.Background()

	t.Run("空会话", func(t *testing.T) {
		before := routeAdvFailed.Load() + routeAdvRejected.Load() + routeAdvAnonymous.Load()
		handleRouteAdvertiseFrame(ctx, nil, []byte(`{"schema":1}`))
		if after := routeAdvFailed.Load() + routeAdvRejected.Load() + routeAdvAnonymous.Load(); after != before {
			t.Fatal("空会话不该记任何计数")
		}
	})

	t.Run("没有 store", func(t *testing.T) {
		prev := gatewayInstance
		t.Cleanup(func() { gatewayInstance = prev })
		gatewayInstance = &gatewayState{}
		body, _ := util.MarshalRouteAdvertise([]string{"192.168.1.0/24"})
		handleRouteAdvertiseFrame(ctx, newAdvConn(7), body) // 不该 panic
	})

	t.Run("帧解析不出要计 failed", func(t *testing.T) {
		gw := newRouteTestGateway(t)
		prev := gatewayInstance
		gatewayInstance = gw
		t.Cleanup(func() { gatewayInstance = prev })
		_, devID := mustCreateUserAndDevice(t, gw, "parsefail")

		for _, bad := range [][]byte{
			[]byte(`not json`),
			[]byte(`{"schema":99,"routes":["192.168.1.0/24"]}`), // schema 不认
		} {
			before := routeAdvFailed.Load()
			handleRouteAdvertiseFrame(ctx, newAdvConn(devID), bad)
			if routeAdvFailed.Load() != before+1 {
				t.Fatalf("解析失败应记 routeAdvFailed: %q", bad)
			}
		}
		if n := countRoutes(t, gw.store, devID); n != 0 {
			t.Fatalf("解析失败不该往库里写任何东西, got %d 条", n)
		}
	})
}

// TestHandleRouteAdvertiseFrame_WithdrawalClearsExemptionGatesEvenIfDBFails 钉住「撤回必须彻底」。
//
// 空 routes = 客户端撤回所有 pending 声明。除了库里那几行,更要紧的是把会话上的五个标志清掉:
// 两个「在跑」标(数据面据此决定还投不投给它)+ 两个伪装豁免闸 + 当前宣告 CIDR 集。
// 漏清任何一个,都会留下一个「已经不做出口 / 不做子网路由器,却还享有相应特权」的会话。
//
// 第二半更要紧:**即使删库那步失败,标志也必须清**。撤回是客户端单方面的事实(它已经撤了 NAT),
// 服务端删不掉 pending 行只是账面不一致;要是因此不清标志,数据面会继续把包投给一个不再转发的
// 会话 —— 一次 DB 抖动换来一个持续黑洞。
func TestHandleRouteAdvertiseFrame_WithdrawalClearsExemptionGatesEvenIfDBFails(t *testing.T) {
	ctx := context.Background()

	for _, breakDB := range []bool{false, true} {
		name := "正常撤回"
		if breakDB {
			name = "删库失败也要清标志"
		}
		t.Run(name, func(t *testing.T) {
			gw := newRouteTestGateway(t)
			prev := gatewayInstance
			gatewayInstance = gw
			t.Cleanup(func() { gatewayInstance = prev })
			_, devID := mustCreateUserAndDevice(t, gw, "withdraw")

			c := newAdvConn(devID)
			// 模拟一个「既在跑出口、又在跑子网路由器、两个豁免闸都开着」的会话。
			c.advertisedExit.Store(true)
			c.advertisedExitV6.Store(true)
			c.advertisedSubnetRoutes.Store(true)
			c.advertisedExitApproved.Store(true)
			c.advertisedSubnetApproved.Store(true)
			set := []netip.Prefix{netip.MustParsePrefix("192.168.9.0/24")}
			c.advertisedRoutes.Store(&set)

			if breakDB {
				if _, err := gw.store.DB().ExecContext(ctx,
					`ALTER TABLE subnet_routes RENAME TO subnet_routes_gone`); err != nil {
					t.Fatalf("藏掉 subnet_routes: %v", err)
				}
			}
			beforeFailed := routeAdvFailed.Load()
			watcher := registerExitsWatcher(t)

			body, _ := util.MarshalRouteAdvertise(nil)
			handleRouteAdvertiseFrame(ctx, c, body)
			// 即使删库失败也必须广播:撤回是客户端单方面的事实,账面删不掉不是别人下拉里
			// 留着一台黑洞出口的理由。
			awaitExitsBroadcast(t, watcher)

			if breakDB && routeAdvFailed.Load() != beforeFailed+1 {
				t.Fatal("删 pending 失败应记 routeAdvFailed(否则运维看不到账面不一致)")
			}
			if c.advertisedExit.Load() {
				t.Fatal("撤回后 advertisedExit 必须清 —— 否则它仍被当在跑出口,转发过去即黑洞")
			}
			if c.advertisedExitV6.Load() {
				t.Fatal("撤回后 advertisedExitV6 必须清,残留 true 会让数据面误判它有 v6 出网")
			}
			if c.advertisedSubnetRoutes.Load() {
				t.Fatal("撤回后 advertisedSubnetRoutes 必须清")
			}
			if c.advertisedExitApproved.Load() {
				t.Fatal("撤回后出口伪装豁免闸必须关 —— 否则它仍能以非自身 vIP 作源发包")
			}
			if c.advertisedSubnetApproved.Load() {
				t.Fatal("撤回后子网伪装豁免闸必须关")
			}
			if got := c.advertisedRoutes.Load(); got != nil && len(*got) != 0 {
				t.Fatalf("撤回后当前宣告集必须清空, got %v", *got)
			}
		})
	}
}

// TestHandleRouteAdvertiseFrame_TruncatesOverMaxRoutes 单帧超过 RouteAdvertiseMaxRoutes 就截断。
// 不截断的话,一个反复发大帧的客户端能把 forwardPacketToSubnetRoute 的每包 Contains 扫描成本
// 拖到任意大 —— 那是发往**它已批准网段**的流量的延迟,受害者不是它自己。
func TestHandleRouteAdvertiseFrame_TruncatesOverMaxRoutes(t *testing.T) {
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "toomany")

	routes := make([]string, 0, RouteAdvertiseMaxRoutes+6)
	for i := 0; i < RouteAdvertiseMaxRoutes+6; i++ {
		routes = append(routes, fmt.Sprintf("10.%d.0.0/24", i))
	}
	body, _ := util.MarshalRouteAdvertise(routes)
	c := newAdvConn(devID)
	handleRouteAdvertiseFrame(context.Background(), c, body)

	if n := countRoutes(t, gw.store, devID); n != RouteAdvertiseMaxRoutes {
		t.Fatalf("应只收前 %d 条, got %d", RouteAdvertiseMaxRoutes, n)
	}
	set := c.advertisedRoutes.Load()
	if set == nil || len(*set) != RouteAdvertiseMaxRoutes {
		t.Fatalf("当前宣告集也应被截断到 %d, got %v", RouteAdvertiseMaxRoutes, set)
	}
}

// TestHandleRouteAdvertiseFrame_RejectsMeshOverlap 钉住那条 2026-07-26 三机实测的坑:
// 宣告与 server 自身 mesh 网段交叠的网段,必须在入口就拒,不写 pending。
//
// 写进去的后果不是「不生效」那么简单 —— rebuildSubnetRouteTable 早就会把它挡在转发表外,
// 但它照旧出现在 `route list` 里、admin 还能 approve 并看到「approved」。一个「批了却永远
// 不通」的状态比直接报错难查得多:双方都以为配好了。
func TestHandleRouteAdvertiseFrame_RejectsMeshOverlap(t *testing.T) {
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	setServerGatewayAddrs("10.201.0.1/16", "fd00:200::1/64")
	t.Cleanup(func() { serverGatewayAddrs.Store(nil) })
	_, devID := mustCreateUserAndDevice(t, gw, "overlap")

	beforeRejected := routeAdvRejected.Load()
	// 一帧里混着「与 mesh 网段交叠」和「正常 LAN 段」:前者拒、后者收,证明不是一刀切。
	body, _ := util.MarshalRouteAdvertise([]string{"10.201.0.0/16", "192.168.50.0/24"})
	c := newAdvConn(devID)
	handleRouteAdvertiseFrame(context.Background(), c, body)

	if routeAdvRejected.Load() != beforeRejected+1 {
		t.Fatal("与 mesh 网段交叠的宣告应记 routeAdvRejected")
	}
	rows, err := gw.store.ListRoutesByDevice(context.Background(), devID)
	if err != nil {
		t.Fatalf("列路由: %v", err)
	}
	for _, r := range rows {
		if r.CIDR == "10.201.0.0/16" {
			t.Fatal("交叠网段不该落库 —— 落库后 admin 能批准它,而它永远不会生效")
		}
	}
	if len(rows) != 1 || rows[0].CIDR != "192.168.50.0/24" {
		t.Fatalf("同帧里的正常网段仍应收下, got %+v", rows)
	}
	// 当前宣告集里也不该有它(否则 per-CIDR 门控会放行发往 mesh 网段的包)。
	if set := c.advertisedRoutes.Load(); set != nil {
		for _, p := range *set {
			if p.String() == "10.201.0.0/16" {
				t.Fatal("交叠网段不该进当前宣告集")
			}
		}
	}
}

// TestHandleRouteAdvertiseFrame_UpsertFailureStillTracksAdvertisedSet 钉住一条**故意**的设计:
// 当前宣告集按「归一后的内容」收集,**独立于 DB upsert 成败**。
//
// 反过来写(upsert 成功才计入)会造成可用性回归:upsert 瞬时失败时,一条此前已批准、仍在转发表里
// 的网段会被 per-CIDR 门控当成「已不宣告」而丢包。客户端 NAT 限定的是它自己发的网段,与服务端
// 持久化成不成功无关。
func TestHandleRouteAdvertiseFrame_UpsertFailureStillTracksAdvertisedSet(t *testing.T) {
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "upsertfail")

	if _, err := gw.store.DB().ExecContext(context.Background(),
		`ALTER TABLE subnet_routes RENAME TO subnet_routes_gone`); err != nil {
		t.Fatalf("藏掉 subnet_routes: %v", err)
	}
	beforeFailed := routeAdvFailed.Load()
	beforeAccepted := routeAdvAccepted.Load()

	c := newAdvConn(devID)
	body, _ := util.MarshalRouteAdvertise([]string{"192.168.60.0/24"})
	handleRouteAdvertiseFrame(context.Background(), c, body)

	if routeAdvFailed.Load() != beforeFailed+1 {
		t.Fatal("upsert 失败应记 routeAdvFailed")
	}
	if routeAdvAccepted.Load() != beforeAccepted {
		t.Fatal("upsert 失败不该记 accepted")
	}
	if !c.advertisedSubnetRoutes.Load() {
		t.Fatal("upsert 失败仍应认它「在跑子网路由器」—— 否则一次 DB 抖动会让已批准网段的流量被丢")
	}
	set := c.advertisedRoutes.Load()
	if set == nil || len(*set) != 1 || (*set)[0].String() != "192.168.60.0/24" {
		t.Fatalf("当前宣告集应按归一内容收下,与 DB 无关, got %v", set)
	}
}

// TestHandleRouteAdvertiseFrame_ExitApprovalGateWhenDBUnreadable 钉住出口伪装豁免闸在
// 「查不动」时怎么动:**保留上次已知值**,既不擅自打开,也不因一次抖动误清。
//
// 误清的代价是出口的 LAN 回程流量(非自身 vIP 作源)被丢 —— 一次 DB 抖动换一段连接中断;
// 擅自打开的代价是放开源地址校验。代码选的是「保留」,与下面子网侧
// `subnetRouteTableLoaded()` 那条同一个哲学。
//
// 构造:给同设备塞一行 status=NULL 的路由 —— ListRoutesByDevice 扫它会报错(q=false),
// 而 UpsertAdvertisedRoute 只回读自己刚写的那一行,不受影响。这样才能把「查不动」
// 单独隔离出来,不然破表会连 upsert 一起打掉,根本走不到闸门那一步。
func TestHandleRouteAdvertiseFrame_ExitApprovalGateWhenDBUnreadable(t *testing.T) {
	ctx := context.Background()

	for _, prevGate := range []bool{false, true} {
		t.Run(fmt.Sprintf("闸门原值=%v", prevGate), func(t *testing.T) {
			gw := newRouteTestGateway(t)
			prev := gatewayInstance
			gatewayInstance = gw
			t.Cleanup(func() { gatewayInstance = prev })
			_, devID := mustCreateUserAndDevice(t, gw, "exitq")

			relaxRouteStatusNotNull(t, gw.store)
			if _, err := gw.store.DB().ExecContext(ctx,
				`INSERT INTO subnet_routes(device_id, cidr, status) VALUES(?,?,NULL)`,
				devID, "192.168.77.0/24"); err != nil {
				t.Fatalf("塞坏行: %v", err)
			}

			c := newAdvConn(devID)
			c.advertisedExitApproved.Store(prevGate)
			handleRouteAdvertiseFrame(ctx, c, exitAdvertiseFrame(t, []string{"0.0.0.0/0", "::/0"}))

			// 出口声明本身应当被收下(exit 语境才允许 /0,顺带覆盖 exit 归一那条分支)。
			if !c.advertisedExit.Load() {
				t.Fatal("带 /0 的 exit 帧应打上「在跑出口」标")
			}
			if !c.advertisedExitV6.Load() {
				t.Fatal("帧里含 ::/0 应置 advertisedExitV6")
			}
			if got := c.advertisedExitApproved.Load(); got != prevGate {
				t.Fatalf("查不动时豁免闸应保留上次已知值 %v, got %v —— "+
					"擅自打开是放开源校验,擅自关闭会丢掉出口的 LAN 回程流量", prevGate, got)
			}
		})
	}
}

// TestHandleRouteAdvertiseFrame_ExitFrameRejectsDefaultRouteWhenNotExitFrame 对照:
// 同样的 0.0.0.0/0,不带 Exit=true 就必须被拒 —— 否则任意设备都能自称全网代理。
func TestHandleRouteAdvertiseFrame_NonExitFrameRejectsDefaultRoute(t *testing.T) {
	gw := newRouteTestGateway(t)
	prev := gatewayInstance
	gatewayInstance = gw
	t.Cleanup(func() { gatewayInstance = prev })
	_, devID := mustCreateUserAndDevice(t, gw, "fakeexit")

	beforeRejected := routeAdvRejected.Load()
	body, _ := util.MarshalRouteAdvertise([]string{"0.0.0.0/0"}) // Exit 字段缺省 = false
	c := newAdvConn(devID)
	handleRouteAdvertiseFrame(context.Background(), c, body)

	if routeAdvRejected.Load() != beforeRejected+1 {
		t.Fatal("非 exit 帧里的 0.0.0.0/0 应被拒")
	}
	if c.advertisedExit.Load() {
		t.Fatal("非 exit 帧不该打上「在跑出口」标")
	}
	if n := countRoutes(t, gw.store, devID); n != 0 {
		t.Fatalf("被拒的 /0 不该落库, got %d 条", n)
	}
}

// TestHandleRouteAdvertiseFrame_SubnetApprovalGateNeedsLoadedTable 钉住子网侧豁免闸:
// 生效表还没加载(启动早期 / rebuild 之间)时不改写闸门,保留上次已知值,避免瞬时误清。
func TestHandleRouteAdvertiseFrame_SubnetApprovalGateNeedsLoadedTable(t *testing.T) {
	ctx := context.Background()

	t.Run("表未加载时不动闸门", func(t *testing.T) {
		gw := newRouteTestGateway(t)
		prev := gatewayInstance
		gatewayInstance = gw
		t.Cleanup(func() { gatewayInstance = prev })
		_, devID := mustCreateUserAndDevice(t, gw, "notloaded")

		prevTbl := subnetRouteTable.Load()
		subnetRouteTable.Store(nil)
		t.Cleanup(func() { subnetRouteTable.Store(prevTbl) })

		c := newAdvConn(devID)
		c.advertisedSubnetApproved.Store(true) // 上次已知:已批准
		body, _ := util.MarshalRouteAdvertise([]string{"192.168.70.0/24"})
		handleRouteAdvertiseFrame(ctx, c, body)

		if !c.advertisedSubnetApproved.Load() {
			t.Fatal("生效表未加载时不该清豁免闸 —— 那会在启动窗口里丢掉宣告方的 LAN 回程流量")
		}
	})

	t.Run("表已加载且不在表里就关闸门", func(t *testing.T) {
		gw := newRouteTestGateway(t)
		prev := gatewayInstance
		gatewayInstance = gw
		t.Cleanup(func() { gatewayInstance = prev })
		_, devID := mustCreateUserAndDevice(t, gw, "loadedmiss")

		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("172.16.0.0/24", devID+999)})

		c := newAdvConn(devID)
		c.advertisedSubnetApproved.Store(true)
		body, _ := util.MarshalRouteAdvertise([]string{"192.168.71.0/24"})
		handleRouteAdvertiseFrame(ctx, c, body)

		if c.advertisedSubnetApproved.Load() {
			t.Fatal("表已加载且本设备不在其中 → 未获批准,豁免闸必须关")
		}
	})

	t.Run("在表里就开闸门", func(t *testing.T) {
		gw := newRouteTestGateway(t)
		prev := gatewayInstance
		gatewayInstance = gw
		t.Cleanup(func() { gatewayInstance = prev })
		_, devID := mustCreateUserAndDevice(t, gw, "loadedhit")

		setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.72.0/24", devID)})

		c := newAdvConn(devID)
		body, _ := util.MarshalRouteAdvertise([]string{"192.168.72.0/24"})
		handleRouteAdvertiseFrame(ctx, c, body)

		if !c.advertisedSubnetApproved.Load() {
			t.Fatal("已批准宣告方应开豁免闸,否则它的 LAN 回程包会被当源伪装丢掉")
		}
	})
}
