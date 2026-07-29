package main

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/util"
)

// 第 45 轮的零散闸门。它们分布在四个文件里,共同点是「坏掉之后没有任何错误路径会响」:
// 一条被接管的僵尸会话继续替真会话回答出口归属、保活按 0 次阈值把所有健康连接判死、
// 限速表只增不减、监控面板上 TUN 永远显示没起来。

// TestExitDeviceForClientVIP_IgnoresASessionThatWasAlreadyTakenOver 被接管的会话不再代表这个 vIP。
//
// 接管是「换链路保身份」:老连接对象会在 connIDMap 里短暂留着(直到清理跑完),但它的链路已经关了。
// 按 vIP 反查出口时若把它算进来,公网 DNS 会按**老会话**的出口绑定去找出口连接 —— 找不到就 SERVFAIL,
// 找到旧的就把查询发给一条死链路。现象是热切换后几秒内公网域名随机解析失败,而会话本身是好的。
func TestExitDeviceForClientVIP_IgnoresASessionThatWasAlreadyTakenOver(t *testing.T) {
	resetServerGlobals(t)
	const vip = "10.203.7.9"

	stale := &Connection{connIDStr: "stale-sid", createdAt: time.Now().Add(-time.Hour)}
	stale.egressDeviceID.Store(77)
	ips := []util.VirtualIPAssignment{{VirtualIP: vip}}
	stale.clientIPs.Store(&ips)
	stale.takenOver.Store(true)

	connIDMapMu.Lock()
	connIDMap["stale-sid"] = stale
	connIDMapMu.Unlock()

	if got := exitDeviceForClientVIP(netip.MustParseAddr(vip)); got != 0 {
		t.Errorf("按 vIP 查出口拿到了已被接管会话的绑定(device=%d)—— 出口查询会发给一条已经关掉的链路", got)
	}
	if _, found := connCreatedAtForClientVIP(netip.MustParseAddr(vip)); found {
		t.Error("已被接管的会话还在回答「这个 vIP 属于我、我是什么时候上线的」—— TTL 钳制会按一条僵尸会话的时刻算")
	}
}

// TestActiveDeviceIDsSnapshot_LeavesOutSessionsWithoutADevice 没有设备身份的会话不进这份名单。
//
// 这份快照的用途是「GC 前把在线设备的 last_seen_at 刷新一遍」。老客户端 / 没上报 device_uuid 的会话
// deviceID 是 0,混进去就是拿 0 号设备去刷库 —— 白跑一次写,还会让「在线设备数」这类由它派生的判断多算一台。
func TestActiveDeviceIDsSnapshot_LeavesOutSessionsWithoutADevice(t *testing.T) {
	resetServerGlobals(t)

	connIDMapMu.Lock()
	connIDMap["with-device"] = &Connection{connIDStr: "with-device", deviceID: 7}
	connIDMap["no-device"] = &Connection{connIDStr: "no-device"} // 未上报 device_uuid
	connIDMapMu.Unlock()

	got := activeDeviceIDsSnapshot()
	if len(got) != 1 || got[0] != 7 {
		t.Fatalf("活跃设备快照 = %v,期望只有 [7] —— 0 号「设备」被算了进来", got)
	}
}

// TestStartWSSDataPlaneKeepalive_FallsBackToTheDefaultMissThreshold 阈值缺省(0)时要用默认值,不能当 0 次用。
//
// 判活窗口 = missThreshold × interval。阈值真取 0 的话窗口也是 0:第一个 Ping 之后**任何**连接都满足
// 「距上次 Pong 已超过 0」,于是每条连接在一个 interval 后被当成僵尸关掉。配置里只填了 interval、
// 没填 miss_threshold 就是这个组合 —— 全站客户端以 interval 为周期集体掉线重连。
func TestStartWSSDataPlaneKeepalive_FallsBackToTheDefaultMissThreshold(t *testing.T) {
	rec := newRWCRecorder()
	c := &Connection{linkConn: rec}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 客户端一直准点回 Pong —— 这是一条完全健康的连接。
	go func() {
		tk := time.NewTicker(2 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				c.lastPongAtNano.Store(time.Now().UnixNano())
			}
		}
	}()

	go startWSSDataPlaneKeepalive(ctx, c, rec, "test", 20*time.Millisecond, 0)

	// 10 个 interval:阈值若真按 0 用,第 1 个 Ping 之后就该被关掉了。
	time.Sleep(200 * time.Millisecond)
	if rec.closed.Load() {
		t.Fatal("阈值填 0 时把一条按时回 Pong 的健康连接判成了僵尸 —— 全站客户端会以 ping 间隔为周期集体掉线")
	}
	if rec.frameCount(util.LinkTypePing) == 0 {
		t.Fatal("一个 Ping 都没发,保活没在跑,上面的断言等于没测")
	}
}

// TestWritePrometheusMetrics_ReportsTunReadyOnceTheDeviceIsUp TUN 起来之后 tun_ready 必须翻成 1。
//
// 这个 gauge 是给告警用的(「TUN 没起」直接呼人)。恒为 0 的话它每天都在误报,值班几次之后就把这条
// 告警静音了 —— 于是真出事那次也没人看。
func TestWritePrometheusMetrics_ReportsTunReadyOnceTheDeviceIsUp(t *testing.T) {
	// 整行匹配:HELP 那行本身就写着 "nanotun_tun_ready 1=TUN device is up",
	// 用子串找 "nanotun_tun_ready 1" 会永远命中它,断言等于没写。
	var before bytes.Buffer
	writePrometheusMetrics(&before, nil)
	if !strings.Contains(before.String(), "\nnanotun_tun_ready 0\n") {
		t.Fatalf("TUN 未起时应报 0:\n%s", before.String())
	}

	prev := sharedTUN
	dev := newStormTUN()
	sharedTUN = dev
	t.Cleanup(func() {
		sharedTUN = prev
		_ = dev.Close()
	})

	var after bytes.Buffer
	writePrometheusMetrics(&after, nil)
	if !strings.Contains(after.String(), "\nnanotun_tun_ready 1\n") {
		t.Errorf("TUN 已经起来了,tun_ready 还是 0 —— 这条告警从此长鸣,真出事时没人再看:\n%s", after.String())
	}
}

// TestPoWIPLimiter_ForgetsIPsThatStoppedComing 限速表要能忘掉不再来的 IP。
//
// 每个来申请出题的 IP 都会在表里占一个 entry。只增不删的话,一次扫段(几万个源 IP 各来一次)之后
// 这张表就再也不会缩小 —— 内存被一批再也不会回来的 IP 永久占着,而且每次摊销 GC 都要扫过它们。
func TestPoWIPLimiter_ForgetsIPsThatStoppedComing(t *testing.T) {
	l := &powIPLimiter{limits: make(map[string]*powIPEntry)}

	if ok, _ := l.AllowChallenge("198.51.100.7:1234"); !ok {
		t.Fatal("第一次申请出题就被拒了")
	}
	// 让这个 IP 看起来已经很久没来过(超过 GC 的存活窗口)。
	l.mu.Lock()
	l.limits["198.51.100.7"].lastSeen = time.Now().Add(-2 * powIPRLGCTTL)
	l.mu.Unlock()

	// 摊销 GC 是每 N 次调用跑一遍,凑够次数(用另一个 IP,免得顺手刷新了上面那条)。
	for i := 0; i < powIPRLGCEveryNCall; i++ {
		l.AllowChallenge("203.0.113.9:5678")
	}

	l.mu.Lock()
	_, stillThere := l.limits["198.51.100.7"]
	l.mu.Unlock()
	if stillThere {
		t.Error("早就不再来的 IP 仍占着限速表 —— 一次全网扫段之后这张表就再也不会缩小")
	}
}
