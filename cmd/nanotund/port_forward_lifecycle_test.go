package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 端口转发管理器把「DB 里的一行映射」变成「一个真实的公网监听 + 一条到目标的 TCP 隧道」。
// 它出错的方式基本都是静默的:监听没起来但状态显示正常、目标 vIP 漂移后还在拨旧地址、
// reload 之后旧监听没停干净。这一组测试用真实 listener 跑完整生命周期。

// pfTestUUID:store 要求映射必须带一个非空的 target_device_uuid。LAN 目标的解析
// 不看它(直接用配置 IP),所以这里给一个固定值即可。
const pfTestUUID = "eeeeeeee-0000-4000-8000-0000000000ee"

// pfEnv 一套端口转发测试环境:真库 + 假命令接缝 + 归位的全局单例。
type pfEnv struct {
	t    *testing.T
	st   *store.Store
	gw   *gatewayState
	m    *portForwardManager
	fake *fakePF
	ctx  context.Context
}

func newPFEnv(t *testing.T) *pfEnv {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "pf.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// globalContext 是进程级的,测试里默认为 nil —— startEntry 与 resolveDeviceVIP
	// 都拿它派生子 ctx,不给就会 panic。
	prevGlobal := globalContext
	globalContext = ctx
	t.Cleanup(func() { globalContext = prevGlobal })

	fake := newFakePF(t)
	// 防火墙删除一律「没有更多匹配」,避免 delFirewallRuleAll 空转 8 次。
	fake.failOn("iptables -D", "", errors.New("no match"))
	fake.failOn("ip6tables -D", "", errors.New("no match"))

	gw := &gatewayState{store: st}
	m := &portForwardManager{
		gw:       gw,
		tunDev:   "nanotun0",
		meshV4:   netip.MustParsePrefix("10.80.0.0/16"),
		meshV6:   netip.MustParsePrefix("fd00:80::/64"),
		active:   map[int]*portForwardEntry{},
		routeRef: map[string]int{},
		status:   map[int]*portForwardStatus{},
		vipCache: map[string]vipCacheEntry{},
	}

	// 全局单例与 frp 表都是进程级的,测完必须还原,否则会污染同包其它测试。
	prevMgr := portForwardMgr.Load()
	prevTbl := frpTargetTable.Load()
	prevReply := frpLANReplyTable.Load()
	portForwardMgr.Store(m)
	t.Cleanup(func() {
		m.stopAll()
		portForwardMgr.Store(prevMgr)
		frpTargetTable.Store(prevTbl)
		frpLANReplyTable.Store(prevReply)
	})

	return &pfEnv{t: t, st: st, gw: gw, m: m, fake: fake, ctx: ctx}
}

// mkPF 往库里写一条启用的映射。
func (e *pfEnv) mkPF(publicPort int, uuid, targetIP string, targetPort int) store.PortForward {
	e.t.Helper()
	pf, err := e.st.CreatePortForward(e.ctx, store.PortForward{
		PublicPort:       publicPort,
		Proto:            "tcp",
		TargetDeviceUUID: uuid,
		TargetIP:         targetIP,
		TargetPort:       targetPort,
		Enabled:          true,
	})
	if err != nil {
		e.t.Fatalf("CreatePortForward(:%d): %v", publicPort, err)
	}
	return *pf
}

// mkDevice 建一台设备,可选地给它一个 lease vIP。
func (e *pfEnv) mkDevice(username, uuid, leaseV4, leaseV6 string) *store.Device {
	e.t.Helper()
	u, err := e.st.CreateUser(e.ctx, store.NewUser{Username: username, PSKHash: "h"})
	if err != nil {
		e.t.Fatalf("CreateUser: %v", err)
	}
	dev, err := e.st.UpsertDevice(e.ctx, u.ID, uuid, "dev", "")
	if err != nil {
		e.t.Fatalf("UpsertDevice: %v", err)
	}
	if leaseV4 != "" || leaseV6 != "" {
		if _, err := e.st.UpsertLease(e.ctx, dev.ID, leaseV4, leaseV6, false); err != nil {
			e.t.Fatalf("UpsertLease: %v", err)
		}
	}
	return dev
}

// freePort 拿一个当前空闲的端口号(拿到后立刻释放,给被测代码去绑)。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("探测空闲端口: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func (e *pfEnv) statusOf(port int) portForwardStatus {
	e.t.Helper()
	for _, st := range portForwardStatusSnapshot() {
		if st.PublicPort == port {
			return st
		}
	}
	e.t.Fatalf("端口 %d 没有运行态快照 —— web 后台会显示成一片空白", port)
	return portForwardStatus{}
}

func TestPortForwardReload_ConvergesListenersToWhatTheDBSays(t *testing.T) {
	e := newPFEnv(t)
	port := freePort(t)

	// 一条 LAN 目标映射:reload 之后应该真的在监听,并装上主机路由。
	pf := e.mkPF(port, pfTestUUID, "192.168.1.50", 22)
	e.m.reload(e.ctx)

	if n := len(e.m.active); n != 1 {
		t.Fatalf("应有 1 条活跃监听,got %d", n)
	}
	if st := e.statusOf(port); st.State != pfStateListening {
		t.Fatalf("状态应为 listening,got %q(err=%q)", st.State, st.Err)
	}
	// 端口真的被占住了 —— 状态说 listening 但实际没绑上是最坏的情况。
	if ln, err := net.Listen("tcp", ":"+strconv.Itoa(port)); err == nil {
		_ = ln.Close()
		t.Fatal("状态显示 listening,端口却还能被别人绑上 —— 说明监听根本没建立")
	}
	if e.fake.countWith("route add 192.168.1.50/32") != 1 {
		t.Fatalf("LAN 目标应装主机路由,实际命令 %v", e.fake.got())
	}
	if e.fake.countWith("iptables -I INPUT 1") == 0 {
		t.Fatal("应自动放行公网端口")
	}

	// 把映射禁用掉,reload 之后监听要收干净。
	if err := e.st.SetPortForwardEnabled(e.ctx, pf.ID, false); err != nil {
		t.Fatalf("SetPortForwardEnabled: %v", err)
	}
	e.m.reload(e.ctx)
	if n := len(e.m.active); n != 0 {
		t.Fatalf("禁用后不该还有活跃监听,got %d", n)
	}
	if len(portForwardStatusSnapshot()) != 0 {
		t.Fatal("已删的映射不该还挂着运行态 —— web 会一直显示一条不存在的映射")
	}
	if e.fake.countWith("route del 192.168.1.50/32") != 1 {
		t.Fatalf("停掉时应删主机路由,实际命令 %v", e.fake.got())
	}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("停掉之后端口应被释放,却还占着: %v", err)
	}
	_ = ln.Close()
}

// 改目标不改公网端口,是最容易出错的一种变更:必须停掉旧的再起新的,
// 而不是「端口没变就什么都不做」——后者会让流量继续打到旧目标。
func TestPortForwardReload_RestartsWhenTargetChangesButPortDoesNot(t *testing.T) {
	e := newPFEnv(t)
	port := freePort(t)
	e.mkPF(port, pfTestUUID, "192.168.1.50", 22)
	e.m.reload(e.ctx)

	first := e.m.active[port]
	if first == nil {
		t.Fatal("预置:应有活跃监听")
	}

	// 直接改库里的目标 IP。
	if _, err := e.st.DB().ExecContext(e.ctx,
		`UPDATE port_forwards SET target_ip=? WHERE public_port=?`, "192.168.1.99", port); err != nil {
		t.Fatalf("改目标: %v", err)
	}
	e.m.reload(e.ctx)

	second := e.m.active[port]
	if second == nil {
		t.Fatal("改完目标之后监听应当还在")
	}
	if second == first {
		t.Fatal("目标变了却复用了旧 entry —— 流量还会打到旧目标那台机器上")
	}
	if second.pf.TargetIP != "192.168.1.99" {
		t.Fatalf("新 entry 的目标是 %q,应为 192.168.1.99", second.pf.TargetIP)
	}
	// 旧目标的路由要撤、新目标的要装。
	if e.fake.countWith("route del 192.168.1.50/32") != 1 {
		t.Fatalf("旧 LAN 目标的主机路由没撤,命令:%v", e.fake.got())
	}
	if e.fake.countWith("route add 192.168.1.99/32") != 1 {
		t.Fatalf("新 LAN 目标的主机路由没装,命令:%v", e.fake.got())
	}

	// 只改注释这类无关字段不该重启监听(会瞬断在途连接)。
	before := e.m.active[port]
	e.m.reload(e.ctx)
	if e.m.active[port] != before {
		t.Fatal("配置没实质变化时重启了监听 —— 每次 reload 都会瞬断所有在途连接")
	}
}

func TestPortForwardStartEntry_ReportsBindFailureInsteadOfPretending(t *testing.T) {
	e := newPFEnv(t)

	t.Run("端口被别人占了", func(t *testing.T) {
		port := freePort(t)
		blocker, err := net.Listen("tcp", ":"+strconv.Itoa(port))
		if err != nil {
			t.Skipf("拿不到端口做冲突: %v", err)
		}
		defer blocker.Close()

		pf := e.mkPF(port, pfTestUUID, "192.168.1.60", 22)
		e.m.startEntry(pf)

		if _, ok := e.m.active[port]; ok {
			t.Fatal("绑不上的映射不该进 active —— 计数会骗人")
		}
		st := e.statusOf(port)
		if st.State != pfStateBindFailed {
			t.Fatalf("状态应为 bind_failed,got %q", st.State)
		}
		if st.Err == "" {
			t.Fatal("失败态应带上原因,否则运维只看到一个 bind_failed 不知道是端口占用还是权限")
		}
		// 绑失败要把刚装的主机路由撤掉,不留垃圾。
		if e.fake.countWith("route del 192.168.1.60/32") != 1 {
			t.Fatalf("绑定失败应回滚主机路由,命令:%v", e.fake.got())
		}
	})

	t.Run("target_ip 根本不合法", func(t *testing.T) {
		port := freePort(t)
		pf := store.PortForward{PublicPort: port, Proto: "tcp", TargetIP: "不是IP", TargetPort: 22, Enabled: true}
		e.m.startEntry(pf)
		st := e.statusOf(port)
		if st.State != pfStateBindFailed {
			t.Fatalf("状态应为 bind_failed,got %q", st.State)
		}
		if _, ok := e.m.active[port]; ok {
			t.Fatal("不该起监听")
		}
	})

	t.Run("路由装不上时监听照起但标降级", func(t *testing.T) {
		e2 := newPFEnv(t)
		e2.fake.failOn("ip route add", "Cannot find device", errors.New("exit status 1"))
		port := freePort(t)
		pf := e2.mkPF(port, pfTestUUID, "192.168.1.70", 22)
		e2.m.startEntry(pf)

		if _, ok := e2.m.active[port]; !ok {
			t.Fatal("路由装不上不该阻断监听 —— 其它映射和已有连接不受影响")
		}
		st := e2.statusOf(port)
		if st.State != pfStateRouteFailed {
			t.Fatalf("应标成 route_degraded 让运维看得见,got %q", st.State)
		}
		if st.Err == "" {
			t.Fatal("降级态要说明原因")
		}
	})
}

// 精确路由表决定「从 TUN 读回来的 LAN 目标包投给哪台设备」。建错了不是不通,
// 而是**投给了另一台同网段的设备** —— 跨设备串流,且两边都不会报错。
func TestRebuildFRPTargetTable_OnlyMapsLANTargetsToTheDeviceThatWasChosen(t *testing.T) {
	e := newPFEnv(t)
	devA := e.mkDevice("alice", "aaaaaaaa-0000-4000-8000-000000000001", "10.80.0.11", "")
	devB := e.mkDevice("bob", "bbbbbbbb-0000-4000-8000-000000000002", "10.80.0.12", "")

	rows := []store.PortForward{
		// LAN 目标,指定 devA。
		{PublicPort: 1001, Proto: "tcp", TargetDeviceUUID: devA.DeviceUUID, TargetIP: "192.168.1.50", TargetPort: 22},
		// node 目标(mesh vIP):走正常 vIP demux,不该进表。
		{PublicPort: 1002, Proto: "tcp", TargetDeviceUUID: devB.DeviceUUID, TargetIP: "10.80.0.12", TargetPort: 80},
		// UUID 解析不出设备:跳过,让它回落到按子网猜。
		{PublicPort: 1003, Proto: "tcp", TargetDeviceUUID: "cccccccc-0000-4000-8000-00000000dead", TargetIP: "192.168.1.51", TargetPort: 22},
		// 同一 LAN IP 指向另一台设备(歧义):保留先见者。
		{PublicPort: 1004, Proto: "tcp", TargetDeviceUUID: devB.DeviceUUID, TargetIP: "192.168.1.50", TargetPort: 443},
		// 协议留空 = 历史行,应按 tcp 处理。
		{PublicPort: 1005, Proto: "", TargetDeviceUUID: devA.DeviceUUID, TargetIP: "192.168.1.52", TargetPort: 8080},
	}
	e.m.rebuildFRPTargetTable(e.ctx, rows)

	if dev, ok := lookupFRPTarget(netip.MustParseAddr("192.168.1.50")); !ok || dev != devA.ID {
		t.Fatalf("192.168.1.50 应精确指向先见的 devA(%d),got dev=%d ok=%v —— "+
			"歧义时不确定性地二选一,会让同一份配置在不同进程上把流量投给不同设备", devA.ID, dev, ok)
	}
	if _, ok := lookupFRPTarget(netip.MustParseAddr("10.80.0.12")); ok {
		t.Fatal("mesh vIP 不该进精确表 —— 它走正常 vIP demux,进表反而会压过正确的投递")
	}
	if _, ok := lookupFRPTarget(netip.MustParseAddr("192.168.1.51")); ok {
		t.Fatal("UUID 解析不出设备的那条应跳过,让包回落到按子网猜")
	}
	if _, ok := lookupFRPTarget(netip.MustParseAddr("192.168.1.99")); ok {
		t.Fatal("没配过的地址不该命中")
	}

	// 回程放行表:只放行「这条映射的目标端点」这一个四元组。
	tcpFrom := func(port uint16, proto string) pktTuple {
		return pktTuple{hasL4Ports: true, srcPort: port, proto: proto}
	}
	src := netip.MustParseAddr("192.168.1.50")
	if !frpLANReplyFromDevice(devA.ID, src, tcpFrom(22, "tcp")) {
		t.Fatal("目标端点的回程应放行,不放行的话 LAN 目标从加固那版起彻底不通")
	}
	if frpLANReplyFromDevice(devB.ID, src, tcpFrom(22, "tcp")) {
		t.Fatal("换一台设备发同样的回程包就该判伪造 —— 否则任何设备都能冒充这个端点")
	}
	if frpLANReplyFromDevice(devA.ID, src, tcpFrom(23, "tcp")) {
		t.Fatal("端口不同就不是那条映射的端点 —— 按 IP 放行等于把这台机器所有端口都开了")
	}
	if frpLANReplyFromDevice(devA.ID, src, tcpFrom(22, "udp")) {
		t.Fatal("协议要严格比对")
	}
	if frpLANReplyFromDevice(0, src, tcpFrom(22, "tcp")) {
		t.Fatal("匿名会话(deviceID<=0)无从确认是不是被指定的宣告方,一律不放行")
	}
	if frpLANReplyFromDevice(devA.ID, src, pktTuple{proto: "tcp"}) {
		t.Fatal("拿不到 L4 端口(分片等)时不能放行 —— 端口是这道闸的全部精度")
	}
	// 协议留空的历史行按 tcp 认。
	if !frpLANReplyFromDevice(devA.ID, netip.MustParseAddr("192.168.1.52"), tcpFrom(8080, "tcp")) {
		t.Fatal("proto 留空的历史行应按 tcp 处理")
	}

	// 重建成空表要把旧表覆盖掉,不能留下已删映射的放行。
	e.m.rebuildFRPTargetTable(e.ctx, nil)
	if _, ok := lookupFRPTarget(netip.MustParseAddr("192.168.1.50")); ok {
		t.Fatal("映射全删之后精确表应清空 —— 残留等于给已删的映射继续放行")
	}
	if frpLANReplyFromDevice(devA.ID, src, tcpFrom(22, "tcp")) {
		t.Fatal("回程放行表也应一并清空")
	}
}

// node 目标的 vIP 会随 lease 漂移,而 vIP 回收后会被分配给别的设备。
// 拨一个陈旧的 vIP 意味着把流量送进**现在归属另一个人**的会话里。
func TestResolveDialTarget_NeverDialsAStaleVIP(t *testing.T) {
	e := newPFEnv(t)
	dev := e.mkDevice("alice", "aaaaaaaa-0000-4000-8000-000000000001", "10.80.0.11", "fd00:80::11")

	t.Run("LAN 目标直接用配置的 IP", func(t *testing.T) {
		pf := store.PortForward{TargetDeviceUUID: dev.DeviceUUID, TargetIP: "192.168.1.50", TargetPort: 22}
		got, ok := e.m.resolveDialTarget(pf)
		if !ok || got != "192.168.1.50:22" {
			t.Fatalf("got (%q,%v),want 192.168.1.50:22", got, ok)
		}
	})

	t.Run("node 目标改拨设备当前 vIP", func(t *testing.T) {
		// 配置里存的是一个过期的 vIP,设备现在的 lease 是 10.80.0.11。
		pf := store.PortForward{TargetDeviceUUID: dev.DeviceUUID, TargetIP: "10.80.0.99", TargetPort: 80}
		got, ok := e.m.resolveDialTarget(pf)
		if !ok {
			t.Fatal("设备有 lease,应能解析出目标")
		}
		if got != "10.80.0.11:80" {
			t.Fatalf("应拨设备当前 vIP 10.80.0.11:80,got %q —— "+
				"拨配置里那个陈旧 vIP 会把流量送进现在归属别人的会话", got)
		}
	})

	t.Run("v6 目标按族取对应地址", func(t *testing.T) {
		pf := store.PortForward{TargetDeviceUUID: dev.DeviceUUID, TargetIP: "fd00:80::99", TargetPort: 80}
		got, ok := e.m.resolveDialTarget(pf)
		if !ok || got != "[fd00:80::11]:80" {
			t.Fatalf("got (%q,%v),want [fd00:80::11]:80", got, ok)
		}
	})

	t.Run("设备不存在就丢掉", func(t *testing.T) {
		pf := store.PortForward{TargetDeviceUUID: "dddddddd-0000-4000-8000-00000000dead",
			TargetIP: "10.80.0.99", TargetPort: 80}
		if got, ok := e.m.resolveDialTarget(pf); ok {
			t.Fatalf("设备已删应 fail-close,却要去拨 %q", got)
		}
	})

	t.Run("设备没有该地址族的 vIP 也丢掉", func(t *testing.T) {
		noV6 := e.mkDevice("carol", "cccccccc-0000-4000-8000-000000000003", "10.80.0.13", "")
		pf := store.PortForward{TargetDeviceUUID: noV6.DeviceUUID, TargetIP: "fd00:80::99", TargetPort: 80}
		if got, ok := e.m.resolveDialTarget(pf); ok {
			t.Fatalf("该设备没有 v6 vIP,应 fail-close,却要去拨 %q", got)
		}
	})

	t.Run("target_ip 非法", func(t *testing.T) {
		pf := store.PortForward{TargetDeviceUUID: dev.DeviceUUID, TargetIP: "垃圾", TargetPort: 80}
		if _, ok := e.m.resolveDialTarget(pf); ok {
			t.Fatal("解析不出地址就该 fail-close")
		}
	})
}

// lease 是设备实际拿到的地址,fixed_vip 是管理员的意图。两者不一致时(fixed 地址
// 不可用被迫分了别的)必须拨 lease,否则拨到一个设备根本不在的地址上。
func TestResolveDeviceVIP_PrefersTheLeaseOverAdminIntent(t *testing.T) {
	e := newPFEnv(t)
	u, err := e.st.CreateUser(e.ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	const uuid = "aaaaaaaa-0000-4000-8000-000000000001"
	dev, err := e.st.UpsertDevice(e.ctx, u.ID, uuid, "dev", "")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if err := e.st.SetDeviceFixedVIP(e.ctx, dev.ID, "10.80.0.7", "", true); err != nil {
		t.Fatalf("SetDeviceFixedVIP: %v", err)
	}

	// 只有 fixed、没有 lease:用 fixed 兜底。
	v4, _, ok := e.m.resolveDeviceVIP(uuid)
	if !ok || v4 != "10.80.0.7" {
		t.Fatalf("没有 lease 时应回落 fixed,got (%q,%v)", v4, ok)
	}

	// 分了一个和 fixed 不同的 lease:必须改用 lease。
	e.m.vipCache = map[string]vipCacheEntry{} // 绕过 2s 缓存
	if _, err := e.st.UpsertLease(e.ctx, dev.ID, "10.80.0.42", "", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	v4, _, ok = e.m.resolveDeviceVIP(uuid)
	if !ok || v4 != "10.80.0.42" {
		t.Fatalf("有 lease 时应拨 lease(设备实际所在),got %q —— "+
			"拨 fixed 会打到一个设备根本不在的地址上", v4)
	}

	// 缓存生效:改了库但缓存没过期时仍返回旧值(这是有意的短缓存)。
	if _, err := e.st.UpsertLease(e.ctx, dev.ID, "10.80.0.43", "", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	v4, _, _ = e.m.resolveDeviceVIP(uuid)
	if v4 != "10.80.0.42" {
		t.Fatalf("2 秒内应命中缓存挡住重复查库,got %q", v4)
	}

	if _, _, ok := e.m.resolveDeviceVIP(""); ok {
		t.Fatal("空 UUID 应解析失败")
	}
	if _, _, ok := e.m.resolveDeviceVIP("ffffffff-0000-4000-8000-00000000dead"); ok {
		t.Fatal("未注册的 UUID 应解析失败")
	}
	// UUID 大小写不该影响解析 —— 配置里手抄的 UUID 大小写不一定统一。
	e.m.vipCache = map[string]vipCacheEntry{}
	if _, _, ok := e.m.resolveDeviceVIP(strings.ToUpper(uuid)); !ok {
		t.Fatal("UUID 应大小写不敏感")
	}
}

// 转发本身:数据要双向通、半关要能传下去(否则像 HTTP 这种「发完请求关写端等响应」
// 的协议会一直挂着)、目标拨不通要立刻关掉入站连接而不是让客户端干等。
func TestHandlePortForwardConn_PipesBothDirectionsAndPropagatesHalfClose(t *testing.T) {
	t.Run("双向转发与半关", func(t *testing.T) {
		// 目标端:读完客户端发来的全部内容(靠对端半关得知结束),再回一段。
		target, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("起目标监听: %v", err)
		}
		defer target.Close()

		serverDone := make(chan []byte, 1)
		go func() {
			c, err := target.Accept()
			if err != nil {
				serverDone <- nil
				return
			}
			defer c.Close()
			b, _ := io.ReadAll(c) // 依赖上行半关才会返回
			_, _ = c.Write([]byte("pong:" + string(b)))
			serverDone <- b
		}()

		inClient, inServer := net.Pipe()
		defer inClient.Close()

		go handlePortForwardConn(t.Context(), inServer, target.Addr().String())

		if _, err := inClient.Write([]byte("ping")); err != nil {
			t.Fatalf("写入: %v", err)
		}
		// 客户端半关上行。net.Pipe 没有 CloseWrite,直接关整条 —— 转发侧应把
		// 上行结束传递给目标。
		_ = inClient.Close()

		select {
		case got := <-serverDone:
			if string(got) != "ping" {
				t.Fatalf("目标收到 %q,应为 ping —— 上行没通,或者半关没传下去导致 ReadAll 挂住", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("目标一直没读完 —— 上行半关没有传递到目标,像 HTTP 这类协议会永久挂起")
		}
	})

	t.Run("下行也要通", func(t *testing.T) {
		target, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("起目标监听: %v", err)
		}
		defer target.Close()
		go func() {
			c, err := target.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("hello-from-target"))
			_ = c.Close()
		}()

		inClient, inServer := net.Pipe()
		defer inClient.Close()
		go handlePortForwardConn(t.Context(), inServer, target.Addr().String())

		_ = inClient.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		n, err := inClient.Read(buf)
		if err != nil {
			t.Fatalf("读下行: %v", err)
		}
		if string(buf[:n]) != "hello-from-target" {
			t.Fatalf("下行内容不对: %q", buf[:n])
		}
	})

	t.Run("目标拨不通时立刻关掉入站连接", func(t *testing.T) {
		// 拿一个刚释放的端口 = 基本确定拨不通。
		dead := "127.0.0.1:" + strconv.Itoa(freePort(t))
		inClient, inServer := net.Pipe()
		defer inClient.Close()

		done := make(chan struct{})
		go func() { defer close(done); handlePortForwardConn(t.Context(), inServer, dead) }()

		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("拨号失败后应立刻返回并关闭入站连接,不能让客户端干等")
		}
		_ = inClient.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := inClient.Read(make([]byte, 1)); err == nil {
			t.Fatal("入站连接应已被关闭")
		}
	})

	t.Run("ctx 取消时两端一起断", func(t *testing.T) {
		target, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("起目标监听: %v", err)
		}
		defer target.Close()
		accepted := make(chan net.Conn, 1)
		go func() {
			c, err := target.Accept()
			if err == nil {
				accepted <- c
			}
		}()

		ctx, cancel := context.WithCancel(t.Context())
		inClient, inServer := net.Pipe()
		defer inClient.Close()
		done := make(chan struct{})
		go func() { defer close(done); handlePortForwardConn(ctx, inServer, target.Addr().String()) }()

		select {
		case c := <-accepted:
			defer c.Close()
		case <-time.After(5 * time.Second):
			t.Fatal("目标端没等到连接")
		}

		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("ctx 取消后转发应立刻收尾 —— 否则停映射 / 关服时这些连接会拖住 shutdown")
		}
	})
}

// 并发闸是唯一挡「大量半开连接耗尽 fd 和 goroutine」的东西。它满了之后新连接必须
// 被立刻关掉,而不是排队等着 —— 排队本身就是资源占用。
func TestAcceptPortForward_ClosesConnectionsOverTheConcurrencyCap(t *testing.T) {
	e := newPFEnv(t)
	dev := e.mkDevice("alice", "aaaaaaaa-0000-4000-8000-000000000001", "10.80.0.11", "")

	// 一个永远挂着的目标,让占用的连接不会自己释放。
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起目标监听: %v", err)
	}
	defer target.Close()
	var held []net.Conn
	var heldMu sync.Mutex
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			heldMu.Lock()
			held = append(held, c)
			heldMu.Unlock()
		}
	}()
	t.Cleanup(func() {
		heldMu.Lock()
		defer heldMu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})

	targetPort := target.Addr().(*net.TCPAddr).Port
	pf := store.PortForward{
		PublicPort: freePort(t), Proto: "tcp",
		TargetDeviceUUID: dev.DeviceUUID,
		TargetIP:         "192.168.1.50", // LAN 目标 → resolveDialTarget 直接用它
		TargetPort:       targetPort,
	}
	// 让 LAN 目标指向本地回环,这样拨号真能成功。
	pf.TargetIP = "127.0.0.1"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起公网监听: %v", err)
	}
	pubAddr := ln.Addr().String()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// 容量 1 的闸:第二条并发连接必须被立刻关掉。
	sem := make(chan struct{}, 1)
	go acceptPortForward(ctx, ln, e.m, pf, sem)

	first, err := net.Dial("tcp", pubAddr)
	if err != nil {
		t.Fatalf("第一条连接: %v", err)
	}
	defer first.Close()
	// 等它真正占住闸。
	deadline := time.Now().Add(5 * time.Second)
	for len(sem) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(sem) == 0 {
		t.Fatal("第一条连接没占住并发闸")
	}

	second, err := net.Dial("tcp", pubAddr)
	if err != nil {
		t.Fatalf("第二条连接应能建立 TCP(随后被服务端关掉): %v", err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("超过上限的连接应被立刻关掉 —— 让它挂着等于闸没起作用")
	}

	// 关 ctx 之后 accept 循环要退出,listener 被关。
	cancel()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", pubAddr); err != nil {
			return // 端口已关,符合预期
		} else {
			_ = c.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("ctx 取消后监听应被关闭")
}

// 解析不出目标时必须 fail-close(关连接),绝不能盲拨一个陈旧地址。
func TestAcceptPortForward_FailsClosedWhenTargetCannotBeResolved(t *testing.T) {
	e := newPFEnv(t)
	pf := store.PortForward{
		PublicPort:       1234,
		Proto:            "tcp",
		TargetDeviceUUID: "dddddddd-0000-4000-8000-00000000dead", // 设备不存在
		TargetIP:         "10.80.0.99",                           // mesh 内 → 走 UUID 解析
		TargetPort:       80,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("起监听: %v", err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go acceptPortForward(ctx, ln, e.m, pf, make(chan struct{}, 4))

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("连接: %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("目标设备已删,应关掉连接而不是盲拨配置里那个陈旧 vIP")
	}
}

func TestPortForwardManagerSingleton_NoOpsWhenDisabled(t *testing.T) {
	prev := portForwardMgr.Load()
	portForwardMgr.Store(nil)
	t.Cleanup(func() { portForwardMgr.Store(prev) })

	if n := reloadPortForwards(t.Context()); n != 0 {
		t.Fatalf("未启用时 reload 应回 0,got %d", n)
	}
	if s := portForwardStatusSnapshot(); s != nil {
		t.Fatalf("未启用时状态快照应为 nil,got %v", s)
	}
	if _, ok := lookupFRPTarget(netip.MustParseAddr("192.168.1.1")); ok {
		frpTargetTable.Store(nil)
		if _, ok := lookupFRPTarget(netip.MustParseAddr("192.168.1.1")); ok {
			t.Fatal("精确表未构建时不该命中")
		}
	}

	// store 为 nil 时启动器直接 no-op,返回一个可安全调用的 cleanup。
	cleanup := startPortForwardManager(nil, "nanotun0")
	if cleanup == nil {
		t.Fatal("即便未启用也要返回可调用的 cleanup")
	}
	cleanup()
	cleanup = startPortForwardManager(&gatewayState{}, "nanotun0")
	cleanup()
}

// reload 通过 control-socket 触发时,调用方(web)只给 5 秒就放弃了。DB 写已经提交,
// 服务端必须把监听收敛到最新态 —— 沿用会被取消的 ctx 会发布一张残缺的精确表。
func TestReloadPortForwards_SurvivesCallerCancellation(t *testing.T) {
	e := newPFEnv(t)
	dev := e.mkDevice("alice", "aaaaaaaa-0000-4000-8000-000000000001", "10.80.0.11", "")
	port := freePort(t)
	e.mkPF(port, dev.DeviceUUID, "192.168.1.50", 22)

	// 调用方已经放弃了。
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if n := reloadPortForwards(ctx); n != 1 {
		t.Fatalf("调用方取消后仍应收敛到 1 条活跃监听,got %d", n)
	}
	if _, ok := lookupFRPTarget(netip.MustParseAddr("192.168.1.50")); !ok {
		t.Fatal("精确表也必须建全 —— 残缺的表会让部分 LAN 目标退回按子网猜测,投给错误的设备")
	}
}
