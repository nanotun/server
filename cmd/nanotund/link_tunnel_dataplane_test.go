package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/util"
)

// 本文件补 runLinkTunnel 的帧分发与数据面执法链。
//
// 这里是「已认证客户端能对服务端做什么」的全部边界:每一个入向帧都先过一串检查
// —— 报文合法性、尾随字节裁剪、超长丢弃、源地址反欺骗、身份反解、出口闸、ACL、
// 自指目的丢弃 —— 才可能落到 TUN。链条上任何一环判松,后果都是静默的:多转发一个
// 包不会报错,只是某个客户端能冒充别人、或能绕过出口权限上公网。
//
// 单测这边此前整个 switch 一条都没走过(e2e 覆盖的是「合法客户端发正常包」那一条线),
// 所有拒绝分支都是空白。

// ── 造包 ────────────────────────────────────────────────────────────────────

// ipv4UDP 造一份 IPv4+UDP 报文:20B IP 头 + 8B UDP 头 + body 字节负载。
// total_len 如实填写;trailing > 0 时在合法报文**之后**追加垃圾字节,用来验裁剪。
func ipv4UDP(src, dst string, dstPort uint16, body, trailing int) []byte {
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	total := 20 + 8 + body
	p := make([]byte, total+trailing)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	p[8] = 64   // TTL
	p[9] = 0x11 // UDP
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+body))
	for i := 28; i < total; i++ {
		p[i] = 0xAA // 真实负载
	}
	for i := total; i < total+trailing; i++ {
		p[i] = 0xEE // 尾随垃圾,不该被转发
	}
	return p
}

// ── 脚手架 ──────────────────────────────────────────────────────────────────

const (
	harnessVIP    = "10.80.0.5"
	harnessRemote = "198.51.100.7:41234"
)

type linkHarness struct {
	t      *testing.T
	client net.Conn
	conn   *Connection
	done   chan struct{}
}

// newLinkHarness 把 runLinkTunnel 架在一对 net.Pipe 上,客户端一侧可以任意灌帧。
func newLinkHarness(t *testing.T, remote string, tweak func(c *Connection)) *linkHarness {
	t.Helper()
	resetServerGlobals(t)
	drainTunWrites()
	t.Cleanup(func() { drainTunWrites() })

	c := &Connection{
		connIDStr:   "link-dp-sid",
		userID:      "u1",
		connID:      9001,
		tunnelDone:  make(chan struct{}),
		exitAllowed: true,
	}
	ips := []util.VirtualIPAssignment{{
		VirtualIP: harnessVIP,
		Mask:      "255.255.0.0",
		Gateway:   "10.80.0.1/16",
		TunChan:   make(chan *util.TunPacket, 8),
	}}
	c.clientIPs.Store(&ips)
	if tweak != nil {
		tweak(c)
	}

	serverEnd, clientEnd := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runLinkTunnel(ctx, serverEnd, c, remote)
	}()
	t.Cleanup(func() {
		_ = clientEnd.Close()
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("runLinkTunnel 未在 3s 内退出")
		}
	})
	return &linkHarness{t: t, client: clientEnd, conn: c, done: done}
}

func (h *linkHarness) send(typ byte, payload []byte) {
	h.t.Helper()
	if err := writeLinkFrameWithDeadline(h.client, typ, payload, 3*time.Second); err != nil {
		h.t.Fatalf("写 typ=%d 帧: %v", typ, err)
	}
}

// barrier 发一帧 Ping 并等 Pong 回来。
//
// net.Pipe 无缓冲 + readLoop 串行处理,所以「收到 Pong」严格意味着在它之前发的每一帧
// 都已经处理完。计数器断言靠这个同步,不靠 sleep —— sleep 在 -race 下必然抖。
func (h *linkHarness) barrier() {
	h.t.Helper()
	h.send(util.LinkTypePing, []byte("barrier"))
	typ, _, err := readLinkFrameWithDeadline(h.client, 3*time.Second)
	if err != nil {
		h.t.Fatalf("等 Pong: %v", err)
	}
	if typ != util.LinkTypePong {
		h.t.Fatalf("期望 Pong(%d),got %d", util.LinkTypePong, typ)
	}
}

// poolShapedTunPacket 造一个与生产同形的在途包。
//
// 队列里的包最终会被 demux 或 drainAndCloseTunChan **归还池子**,所以塞进去的 Buf 必须是池子那种
// tunBufSize 的切片。塞一条 4 字节(或 nil)的进去,池子里就混进了一个短 buffer,之后任何一次 Get
// 拿到它都只能装下那么多 —— 现象是毫无关系的另一个用例收到一个被截断的包(实测:出口 DNS 那组
// 用例报「注入出口的查询包异常」,而它们与本文件八竿子打不着)。
func poolShapedTunPacket(payload []byte) *util.TunPacket {
	buf := tunReadBufPool.Get().([]byte)
	n := copy(buf, payload)
	return &util.TunPacket{Buf: buf, N: n}
}

// drainTunWrites 抽干 tunWriteChan 并返回抽到的包。它是包级全局,测试之间会串台。
func drainTunWrites() [][]byte {
	var out [][]byte
	for {
		select {
		case p := <-tunWriteChan:
			out = append(out, p)
		default:
			return out
		}
	}
}

// ── 用例 ────────────────────────────────────────────────────────────────────

// TestRunLinkTunnel_TrimsTrailingBytesBeforeForwarding 验尾随字节裁剪。
//
// IP 头声明总长 N,客户端却在后面多塞了一截。不裁掉的话这些字节会跟着报文一路进
// server TUN 或投给 mesh 对端 —— 一条谁都不检查的隐蔽信道(下游 ACL、源校验、NAT
// 只看头部字段,对尾巴一无所知)。
func TestRunLinkTunnel_TrimsTrailingBytesBeforeForwarding(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)

	const body, trailing = 12, 64
	pkt := ipv4UDP(harnessVIP, "8.8.8.8", 53, body, trailing)
	h.send(util.LinkTypeIPPacket, pkt)
	h.barrier()

	got := drainTunWrites()
	if len(got) != 1 {
		t.Fatalf("应转发 1 个包,实际 %d 个", len(got))
	}
	wantLen := 20 + 8 + body
	if len(got[0]) != wantLen {
		t.Fatalf("转发出去 %d 字节,应被裁到 %d —— 多出来的是没人检查的夹带内容",
			len(got[0]), wantLen)
	}
	if bytes.Contains(got[0], []byte{0xEE, 0xEE, 0xEE, 0xEE}) {
		t.Fatal("尾随垃圾字节被一起转发了")
	}
}

// TestRunLinkTunnel_OversizePacketIsDroppedNotTruncated 验超长帧丢弃。
//
// 链路层单帧上限是 64KB,而 TUN 侧 buffer 只有 2048。下游是 copy(pkt, payload) ——
// 不在这里拦住,超长包会被**静默截断**成半截:长度字段与实际不符、校验和全错,
// 却照样写进 server TUN 或投给 mesh 对端。丢弃并计数,比转发一个残包好。
func TestRunLinkTunnel_OversizePacketIsDroppedNotTruncated(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)

	before := tunOversizeDropCount.Load()
	// body 撑到总长 > tunBufSize;头里的 total_len 如实填写,所以裁剪那步不会缩短它。
	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "8.8.8.8", 53, tunBufSize, 0))
	h.barrier()

	if got := tunOversizeDropCount.Load(); got != before+1 {
		t.Fatalf("超长包丢弃计数 %d → %d,应 +1", before, got)
	}
	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("超长包不该进 TUN,却转发了 %d 个(必然是被截断的残包)", n)
	}

	// 反面:正常大小的包照样通行,证明上面不是「什么都丢」。
	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "8.8.8.8", 53, 16, 0))
	h.barrier()
	if n := len(drainTunWrites()); n != 1 {
		t.Fatalf("正常包应转发 1 个,实际 %d 个", n)
	}
}

// TestRunLinkTunnel_SpoofedSourceIsDroppedAndClassified 验源地址反欺骗与它的分类。
//
// 普通会话只能以自己的 vIP 作源。放松这条,一个已认证的低权限用户就能以别人的 vIP
// 发包 —— 对端看到的来源是受害者,ACL 也按受害者的身份判,等于横向冒充。
//
// 分类同样重要:全隧道客户端的不对称回程(公网扫描打到它自己的公网 IP,回包拐进隧道)
// 在这里长得跟冒充一模一样,但它是常态噪声。两者混在一个计数器里,真冒充的信号就被
// 扫描噪声淹掉了,告警只能整个关掉。
func TestRunLinkTunnel_SpoofedSourceIsDroppedAndClassified(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)

	// 另一台在线设备的 vIP —— 登记进归属表,冒充判定才认得出来。
	victim := netip.MustParseAddr("10.80.0.99")
	registerVIPOwners([]netip.Addr{victim}, 2, 7777)

	spoofBefore := srcSpoofDropCount.Load()
	ownBefore := srcOwnPublicDropCount.Load()

	h.send(util.LinkTypeIPPacket, ipv4UDP(victim.String(), "8.8.8.8", 53, 8, 0))
	h.barrier()
	if got := srcSpoofDropCount.Load(); got != spoofBefore+1 {
		t.Fatalf("冒充他人 vIP 的计数 %d → %d,应 +1", spoofBefore, got)
	}
	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("冒充包被转发了 %d 个", n)
	}

	// 源恰是本链路对端自己的公网 IP:同样丢,但要记在另一个计数器上。
	h.send(util.LinkTypeIPPacket, ipv4UDP("198.51.100.7", "8.8.8.8", 53, 8, 0))
	h.barrier()
	if got := srcOwnPublicDropCount.Load(); got != ownBefore+1 {
		t.Fatalf("「自己公网 IP 的不对称回程」计数 %d → %d,应 +1", ownBefore, got)
	}
	if got := srcSpoofDropCount.Load(); got != spoofBefore+1 {
		t.Fatalf("不对称回程被记成了真冒充(冒充计数涨到 %d)—— 告警会被扫描噪声淹掉", got)
	}
	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("不对称回程包也不该进 TUN,却转发了 %d 个", n)
	}
}

// TestRunLinkTunnel_BrokenUserIDFailsClosed 验身份反解的 fail-closed。
//
// userID 解不出来意味着后面所有 per-user 判定(子网路由 ACL、出口闸、ACL 执法)都失去
// 依据。此时唯一安全的选择是丢包:放行等于让一个身份不明的会话拿到「无规则匹配」
// 的默认待遇,而多数部署的默认是 allow。
func TestRunLinkTunnel_BrokenUserIDFailsClosed(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, func(c *Connection) {
		c.userID = "身份损坏" // 非 "u<id>" 形态,parseUserIDStr 解出 0
	})

	before := aclMalformedUserDropCount.Load()
	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "8.8.8.8", 53, 8, 0))
	h.barrier()

	if got := aclMalformedUserDropCount.Load(); got != before+1 {
		t.Fatalf("身份损坏丢包计数 %d → %d,应 +1", before, got)
	}
	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("身份解不出还转发了 %d 个包 —— 后面每一层 per-user 判定都是瞎判的", n)
	}
}

// TestRunLinkTunnel_ExitGateDropIsAttributable 验 user 级出口闸,以及它的归因。
//
// exit_allowed=false 的用户不能用 VPN 出公网。这道闸排在 ACL **之前**:不能指望管理员
// 一定配了出口相关的 ACL 规则,没配也必须默认拒。
//
// 丢包还要能归因:审计聚合里「ACL 规则丢的」和「出口闸丢的」是两回事,管理员看到
// 用户连不上时,得能一眼分清是自己写的规则拦的,还是这个账号压根没开出口权限。
func TestRunLinkTunnel_ExitGateDropIsAttributable(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, func(c *Connection) { c.exitAllowed = false })

	clearACLDropBuckets()
	before := exitGateDropCount.Load()

	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "8.8.8.8", 53, 8, 0))
	h.barrier()

	if got := exitGateDropCount.Load(); got != before+1 {
		t.Fatalf("出口闸丢包计数 %d → %d,应 +1", before, got)
	}
	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("没有出口权限的会话仍然出了 %d 个包上公网", n)
	}
	if !hasACLDropKind("exit_gate") {
		t.Fatal("出口闸丢包没进审计聚合的 exit_gate 桶,管理员分不清是规则拦的还是没权限")
	}

	// 反面:打另一台在线设备的 vIP 不该被出口闸拦 —— 那是 mesh 互通,不是出公网。
	// 没有出口权限的用户照样要能访问同一 mesh 内的对端和 server 本机服务(比如 MagicDNS)。
	peer := netip.MustParseAddr("10.80.0.99")
	registerVIPOwners([]netip.Addr{peer}, 2, 7777)
	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, peer.String(), 53, 8, 0))
	h.barrier()
	if got := exitGateDropCount.Load(); got != before+1 {
		t.Fatalf("打网段内地址也被出口闸拦了(计数涨到 %d)", got)
	}
}

func clearACLDropBuckets() {
	aclDropAggBuckets.Range(func(k, _ any) bool {
		aclDropAggBuckets.Delete(k)
		return true
	})
	aclDropAuditBucketCount.Store(0)
}

func hasACLDropKind(kind string) bool {
	found := false
	aclDropAggBuckets.Range(func(k, _ any) bool {
		if key, ok := k.(aclDropBucketKey); ok && key.kind == kind {
			found = true
			return false
		}
		return true
	})
	return found
}

// TestRunLinkTunnel_PingEchoIsCapped 验 Pong 回显的体积上限。
//
// 回 Pong 时要先拿 linkWrMu,而踢线、supersede、keepalive 判死都得拿到同一把锁才能
// Close 这条链路。客户端发一个 64KB 的 Ping 再停止读取,Pong 就永远写不出去 ——
// 锁被顶死,这个已认证会话的 vIP 和会话配额谁也回收不了,管理员踢都踢不动。
// 截断回显对合法客户端无损(Ping 载荷本来就是小 seq+nonce)。
func TestRunLinkTunnel_PingEchoIsCapped(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)

	huge := bytes.Repeat([]byte{0x5A}, 8192)
	h.send(util.LinkTypePing, huge)
	typ, echo, err := readLinkFrameWithDeadline(h.client, 3*time.Second)
	if err != nil {
		t.Fatalf("读 Pong: %v", err)
	}
	if typ != util.LinkTypePong {
		t.Fatalf("期望 Pong,got %d", typ)
	}
	if len(echo) > linkPingPongMaxEcho {
		t.Fatalf("Pong 回显 %d 字节,超过上限 %d —— 停读的客户端能借它把 linkWrMu 顶死",
			len(echo), linkPingPongMaxEcho)
	}
	if !bytes.Equal(echo, huge[:linkPingPongMaxEcho]) {
		t.Fatal("回显内容应是原载荷的前缀截断")
	}
}

// TestRunLinkTunnel_PongRefreshesLiveness 验 Pong 会刷新判活时间戳。
//
// 服务端主动心跳靠这个时间戳判僵尸连接。不刷新的话,一条明明在正常回 Pong 的链路会被
// 判死主动断开,表现为「网络好好的却每隔几十秒掉一次线」。
func TestRunLinkTunnel_PongRefreshesLiveness(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)
	h.conn.lastPongAtNano.Store(0)

	h.send(util.LinkTypePong, []byte("pong"))
	h.barrier()

	if h.conn.lastPongAtNano.Load() == 0 {
		t.Fatal("收到 Pong 却没刷新判活时间戳,健康链路会被误判成僵尸")
	}
}

// TestRunLinkTunnel_UnknownFrameTypeIsIgnoredNotFatal 验未知帧类型的向前兼容。
//
// 新版客户端引入新帧类型时,老服务端会收到不认识的 typ。此时断链等于「客户端一升级
// 就集体掉线」,而且这个坑要等到灰度上线才暴露。忽略并继续是唯一可用的语义。
func TestRunLinkTunnel_UnknownFrameTypeIsIgnoredNotFatal(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)

	h.send(0xF7, []byte("来自未来版本的帧"))
	h.barrier() // 链路还活着才回得了 Pong

	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "8.8.8.8", 53, 8, 0))
	h.barrier()
	if n := len(drainTunWrites()); n != 1 {
		t.Fatalf("未知帧之后数据面应照常工作,却只转发了 %d 个包", n)
	}
}

// TestRunLinkTunnel_CloseFrameShutsDownCleanly 验 Close 帧的收尾。
//
// 客户端主动说再见时,服务端要取消 tunnel ctx、关链路、等 demux goroutine 退出后才返回。
// 少了 wg.Wait,demux 会继续消费已经过户或即将回收的 TunChan;少了 cancel,限速器上
// 阻塞的 WaitN 不会醒,goroutine 泄漏。
func TestRunLinkTunnel_CloseFrameShutsDownCleanly(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)

	h.send(util.LinkTypeClose, nil)
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("收到 Close 帧后 runLinkTunnel 没退出")
	}
	select {
	case <-h.conn.tunnelDone:
	default:
		t.Fatal("退出了却没关 tunnelDone —— 等它的接管/清理逻辑会一直挂着")
	}
}

// gatedWriteConn 把下行写卡在一个由测试控制的闸门上,用来观察「谁还没退出」。
// 故意不实现 SetWriteDeadline:demux 的 watchdog 只会去调它,调不到就停在闸门上,
// 正是这里想要的状态。
type gatedWriteConn struct {
	rd      net.Conn
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (c *gatedWriteConn) Read(p []byte) (int, error) { return c.rd.Read(p) }
func (c *gatedWriteConn) Close() error               { return c.rd.Close() }
func (c *gatedWriteConn) Write([]byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.gate
	return 0, errors.New("链路已关")
}

// TestRunLinkTunnel_CloseWaitsForDemuxToActuallyStop 验收尾时必须等 demux 真正退出。
//
// runLinkTunnel 返回后,调用方紧接着就会跑 cleanupConnection 回收 vIP 和 TunChan,
// 接管路径还会把同一批 TunChan **过户**给新链路。此时若旧 demux 还活着,它会继续从
// 那些 channel 里取包往已经作废的链路写 —— 新旧两个 demux 抢同一个 TunChan,下行包
// 被随机分给死链路而丢失。所以 wg.Wait 不是礼貌,是过户的前置条件。
//
// 链路有两个出口 —— 客户端好好说再见(Close 帧)和直接断开(读出错)—— 两条都要等,
// 而且后者才是常态。做法:把下行写卡在闸门上让 demux 确定地停在半路,再触发退出;
// 有 wg.Wait 时 runLinkTunnel 必须还在等,放开闸门后才允许返回。
func TestRunLinkTunnel_ShutdownWaitsForDemuxToActuallyStop(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trigger func(t *testing.T, client net.Conn)
	}{
		{"客户端发 Close 帧", func(t *testing.T, client net.Conn) {
			if err := writeLinkFrameWithDeadline(client, util.LinkTypeClose, nil, 3*time.Second); err != nil {
				t.Fatalf("发 Close 帧: %v", err)
			}
		}},
		{"客户端直接断开", func(t *testing.T, client net.Conn) {
			_ = client.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetServerGlobals(t)
			drainTunWrites()
			t.Cleanup(func() { drainTunWrites() })

			tunCh := make(chan *util.TunPacket, 4)
			c := &Connection{
				connIDStr:   "link-dp-gated",
				userID:      "u1",
				connID:      9002,
				tunnelDone:  make(chan struct{}),
				exitAllowed: true,
			}
			ips := []util.VirtualIPAssignment{{VirtualIP: harnessVIP, TunChan: tunCh}}
			c.clientIPs.Store(&ips)

			serverEnd, clientEnd := net.Pipe()
			defer clientEnd.Close()
			gated := &gatedWriteConn{rd: serverEnd, gate: make(chan struct{}), entered: make(chan struct{})}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				runLinkTunnel(ctx, gated, c, harnessRemote)
			}()

			// 让 demux 取一个下行包并卡在写上。
			tunCh <- poolShapedTunPacket([]byte{0x45, 0, 0, 20})
			select {
			case <-gated.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("demux 没有取走下行包(它可能根本没起来)")
			}

			tc.trigger(t, clientEnd)

			select {
			case <-done:
				t.Fatal("demux 还卡在下行写上,runLinkTunnel 就返回了 —— " +
					"调用方会立刻回收/过户 TunChan,而旧 demux 仍在从里面取包")
			case <-time.After(300 * time.Millisecond):
			}

			close(gated.gate) // 放行:demux 的写返回错误,循环退出
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("demux 已退出,runLinkTunnel 却没跟着返回")
			}
		})
	}
}

// TestRunLinkTunnel_DemuxWriteFailureTearsDownTheWholeTunnel 验下行写失败要拖垮整条隧道。
//
// 下行写真的失败(含 5s 写超时)意味着这条链路已经不可用。若只让出错的那个 vIP 的 demux
// 退出、readLoop 继续跑,客户端看到的是「连接还在,上行也通,下行全没了」—— 一个不会
// 报错也不会重连的黑洞,只能等用户手动重启。正确做法是整条拆掉,逼客户端用新链路重协商。
func TestRunLinkTunnel_DemuxWriteFailureTearsDownTheWholeTunnel(t *testing.T) {
	resetServerGlobals(t)
	drainTunWrites()
	t.Cleanup(func() { drainTunWrites() })

	tunCh := make(chan *util.TunPacket, 4)
	c := &Connection{
		connIDStr:   "link-dp-deadwrite",
		userID:      "u1",
		connID:      9003,
		tunnelDone:  make(chan struct{}),
		exitAllowed: true,
	}
	ips := []util.VirtualIPAssignment{{VirtualIP: harnessVIP, TunChan: tunCh}}
	c.clientIPs.Store(&ips)

	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	// 闸门直接开着:第一次下行写立刻返错。
	dead := &gatedWriteConn{rd: serverEnd, gate: make(chan struct{}), entered: make(chan struct{})}
	close(dead.gate)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runLinkTunnel(ctx, dead, c, harnessRemote)
	}()

	tunCh <- poolShapedTunPacket([]byte{0x45, 0, 0, 20})

	// 没人发 Close、客户端也没断开;readLoop 应当被 demux 的收尾(cancel + rw.Close)逼退。
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("下行写失败了,隧道却还立着 —— 客户端会停在「上行通、下行黑洞」的状态里")
	}
}

// TestRunLinkTunnel_SelfReferentialInternalDstIsDropped 验自指内网目的的 fail-closed。
//
// 会话自己就是某内网网段的宣告方,却往那个网段发包:子网转发会把包交回本链路(不能投给
// 自己),而 server 上这类目的没有本地投递语义。放它落进 TUN,内核 FORWARD+MASQUERADE
// 会把私网目的推向 WAN 上行口 —— 内网地址在运营商那边注定被丢,但在此之前它已经明文
// 出现在公网链路上了。
func TestRunLinkTunnel_SelfReferentialInternalDstIsDropped(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, func(c *Connection) {
		c.deviceID = 42
		c.advertisedSubnetApproved.Store(true)
	})

	prev := subnetRouteTable.Load()
	tbl := []subnetRouteEntry{{prefix: netip.MustParsePrefix("192.168.7.0/24"), deviceID: 42}}
	subnetRouteTable.Store(&tbl)
	t.Cleanup(func() { subnetRouteTable.Store(prev) })

	before := subnetRouteDroppedSelfRefEgress.Load()
	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "192.168.7.9", 53, 8, 0))
	h.barrier()

	if got := subnetRouteDroppedSelfRefEgress.Load(); got != before+1 {
		t.Fatalf("自指内网目的丢包计数 %d → %d,应 +1", before, got)
	}
	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("私网目的落进了 TUN(%d 个)—— 会被 MASQUERADE 推上公网上行口", n)
	}
}

// TestRunLinkTunnel_MalformedPacketIsDroppedAtTheDoor 验畸形报文进不了 TUN。
//
// 后面每一层(裁剪、源校验、ACL、出口闸)都从固定偏移读 IP 头字段,报文不合法就等于
// 都在读垃圾。这条不变量由两层独立兜着:门口的 ValidIPPacket,以及 ACL 对「解不出
// tuple」的 fail-closed。拆掉任意一层这个用例都还是绿的 —— 这正是纵深防御该有的样子,
// 想看门本身的边界(IHL 撒谎、总长越界、短包越界读)去 util 那边的 IPPacketTotalLen 用例,
// 那里每一个边界都钉死了。这里钉的是端到端的结果:不管哪一层拦,反正到不了 TUN。
func TestRunLinkTunnel_MalformedPacketIsDroppedAtTheDoor(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)

	for _, bad := range [][]byte{
		{},                                   // 空载荷
		{0x45, 0x00},                         // 短到没有完整 IP 头
		{0x50, 0x00, 0x00, 0x14, 0, 0, 0, 0}, // version=5,既非 v4 也非 v6
		func() []byte { // IHL 声明 60 字节头,总长却只有 24
			p := ipv4UDP(harnessVIP, "8.8.8.8", 53, 0, 0)
			p[0] = 0x4F
			return p
		}(),
	} {
		h.send(util.LinkTypeIPPacket, bad)
	}
	h.barrier()

	if n := len(drainTunWrites()); n != 0 {
		t.Fatalf("畸形报文进了 TUN(%d 个)—— 下游每一层都在从错误偏移读字段", n)
	}
}

// TestRunLinkTunnel_PongWriteFailureEndsTheSession 验 Pong 写不出去就结束会话。
//
// 写失败说明链路已经不通。此时若继续 readLoop,这个会话会一直挂在 connections 表里占着
// vIP 和会话配额,而它其实早就没法回话了。
func TestRunLinkTunnel_PongWriteFailureEndsTheSession(t *testing.T) {
	resetServerGlobals(t)
	drainTunWrites()
	t.Cleanup(func() { drainTunWrites() })

	c := &Connection{
		connIDStr:   "link-dp-pongfail",
		userID:      "u1",
		connID:      9004,
		tunnelDone:  make(chan struct{}),
		exitAllowed: true,
	}
	ips := []util.VirtualIPAssignment{{VirtualIP: harnessVIP}}
	c.clientIPs.Store(&ips)

	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	dead := &gatedWriteConn{rd: serverEnd, gate: make(chan struct{}), entered: make(chan struct{})}
	close(dead.gate) // 所有写立刻返错

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runLinkTunnel(ctx, dead, c, harnessRemote)
	}()

	if err := writeLinkFrameWithDeadline(clientEnd, util.LinkTypePing, []byte("hi"), 3*time.Second); err != nil {
		t.Fatalf("发 Ping: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Pong 写失败后会话还在跑,vIP 与会话配额被一条哑链路占着")
	}
}

// TestRunLinkTunnel_ControlFramesDoNotDisturbTheDataPath 验控制帧与 IP 帧互不干扰。
//
// 子网宣告与出口选择这两类控制帧走的是同一条 readLoop。它们的处理是 best-effort ——
// 参数再离谱也只能记日志,不能让这条链路断掉或让后续 IP 帧停摆。
func TestRunLinkTunnel_ControlFramesDoNotDisturbTheDataPath(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)

	h.send(util.LinkTypeRouteAdvertise, []byte(`{"routes":["不是CIDR"]}`))
	h.send(util.LinkTypeEgressSelect, []byte(`{"device_id":"乱填"}`))
	h.barrier()

	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "8.8.8.8", 53, 8, 0))
	h.barrier()
	if n := len(drainTunWrites()); n != 1 {
		t.Fatalf("控制帧之后数据面应照常,却转发了 %d 个包", n)
	}
}

// TestRunLinkTunnel_KeepaliveStartsOnlyWhenConfigured 验服务端主动心跳的启停条件。
//
// 判死僵尸连接全靠它。配了间隔却没起来,断电/断网的客户端会一直占着 vIP 直到 TCP 自己
// 超时(可能几十分钟);没配却起来了,则是给所有会话平白加了一份周期性写负担。
func TestRunLinkTunnel_KeepaliveStartsOnlyWhenConfigured(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		wantPing bool
	}{
		{"配了间隔 → 起心跳", 20 * time.Millisecond, true},
		{"间隔为 0 → 不起", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := gatewayInstance
			cfg := &config.Config{}
			cfg.Server.DataPlanePingInterval = config.Duration(tc.interval)
			cfg.Server.DataPlanePingMissThreshold = 0 // 走默认阈值那条分支
			gatewayInstance = &gatewayState{cfg: cfg}
			t.Cleanup(func() {
				// 初始出口/路由列表那两发推送是 fire-and-forget(用 context.Background、不进 wg),
				// 会活过 runLinkTunnel 的返回,而它们要读 gatewayInstance。两者各自在自己的广播锁
				// 里读,所以还原全局前先抢同一把锁 —— 在途的推送要么已落地,要么排在还原之后,
				// 不留竞态。直接写回去的话,竞态是测试自己造的,不是被测代码的问题。
				routesBroadcastMu.Lock()
				exitsBroadcastMu.Lock()
				gatewayInstance = prev
				exitsBroadcastMu.Unlock()
				routesBroadcastMu.Unlock()
			})

			h := newLinkHarness(t, harnessRemote, nil)

			deadline := 800 * time.Millisecond
			if !tc.wantPing {
				deadline = 200 * time.Millisecond
			}
			typ, _, err := readLinkFrameWithDeadline(h.client, deadline)
			gotPing := err == nil && typ == util.LinkTypePing

			if tc.wantPing && !gotPing {
				t.Fatalf("配了 %v 的心跳间隔却没收到服务端 Ping(err=%v, typ=%d)—— "+
					"断网的客户端要占着 vIP 直到 TCP 超时", tc.interval, err, typ)
			}
			if !tc.wantPing && gotPing {
				t.Fatal("间隔为 0 时不该有服务端主动心跳")
			}
		})
	}
}

// TestRunLinkTunnel_TunWriteChanFullDropsInsteadOfBlocking 验下行拥塞时的非阻塞投递。
//
// tunWriteChan 是**全进程共享**的一条队列。这里若写成阻塞投递,TUN 写一慢,所有客户端的
// readLoop 会一起停在这行 —— 一个慢消费者把全服务的数据面顶停。宁可丢包并计数。
func TestRunLinkTunnel_TunWriteChanFullDropsInsteadOfBlocking(t *testing.T) {
	h := newLinkHarness(t, harnessRemote, nil)

	// 把共享队列灌满,模拟 TUN 侧消费不过来。
	filled := 0
	for {
		select {
		case tunWriteChan <- []byte{0x45}:
			filled++
		default:
		}
		if len(tunWriteChan) == cap(tunWriteChan) {
			break
		}
		if filled > cap(tunWriteChan)+16 {
			t.Fatalf("灌了 %d 个仍没灌满 cap=%d 的队列", filled, cap(tunWriteChan))
		}
	}
	t.Cleanup(func() { drainTunWrites() })

	before := tunWriteDropCount.Load()
	h.send(util.LinkTypeIPPacket, ipv4UDP(harnessVIP, "8.8.8.8", 53, 8, 0))
	// 队列满时 readLoop 必须立刻回到下一帧;barrier 能返回本身就证明它没阻塞在投递上。
	h.barrier()

	if got := tunWriteDropCount.Load(); got != before+1 {
		t.Fatalf("队列满时的丢包计数 %d → %d,应 +1", before, got)
	}
}
