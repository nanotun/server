package main

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/store"
)

// 本文件补 handleMagicDNSPacket 的分支与上游转发链路。三机 e2e 只走「解析得到 vIP」这条主干,
// 报文畸形 / 非 INET class / 非 A/AAAA 类型 / 隔离与 ACL 拒答 / 上游反投毒 这些分支在真实流量里
// 几乎不出现,却正是 DNS 这层的攻击面所在。

// ---------------------------------------------------------------- helpers

// runMagicDNSQueryRaw 与 runOneMagicDNSQuery 同构,区别是允许「本就不该有回包」的用例:
// 返回 (响应, 是否收到)。等待窗口由调用方给,不该有回包的用例给短一点。
func runMagicDNSQueryRaw(t *testing.T, gw *gatewayState, r magicDNSResolved, query []byte, wait time.Duration) ([]byte, bool) {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	handleMagicDNSPacket(t.Context(), gw, srv, cli.LocalAddr().(*net.UDPAddr), query, r)

	_ = cli.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

// mustRCode 跑一次查询并断言回包的 rcode。
func mustRCode(t *testing.T, gw *gatewayState, r magicDNSResolved, query []byte, want dnsmessage.RCode) dnsmessage.Header {
	t.Helper()
	resp, ok := runMagicDNSQueryRaw(t, gw, r, query, 2*time.Second)
	if !ok {
		t.Fatal("期望有回包,实际超时")
	}
	hdr, _ := parseDNSResponse(t, resp)
	if hdr.RCode != want {
		t.Fatalf("rcode = %v, want %v", hdr.RCode, want)
	}
	return hdr
}

// buildDNSQueryFull 是 buildDNSQuery 的加强版,可指定 class(测非 INET 分支)。
func buildDNSQueryFull(t *testing.T, name string, qtype dnsmessage.Type, class dnsmessage.Class) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: class}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// buildReply 按 query 造一份「合法匹配」的应答,带一条 A 记录。
// 不吃 testing.TB —— 假上游的 goroutine 里会调它,那里不能 t.Fatal。
func buildReply(query []byte, ip string, ttl uint32) ([]byte, error) {
	id, q, ok := parseDNSQueryKey(query)
	if !ok {
		return nil, fmt.Errorf("查询报文解析不出 key")
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return nil, fmt.Errorf("需要一个 IPv4:%q", ip)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeSuccess})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if err := b.AResource(
		dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
		dnsmessage.AResource{A: a.As4()},
	); err != nil {
		return nil, err
	}
	return b.Finish()
}

// buildSpoofReply 造一份 TXID 差 1、其余与真应答一模一样的伪造包 —— 只有校验 TXID 才能识破。
func buildSpoofReply(query []byte, ip string) ([]byte, error) {
	id, q, ok := parseDNSQueryKey(query)
	if !ok {
		return nil, fmt.Errorf("查询报文解析不出 key")
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return nil, fmt.Errorf("需要一个 IPv4:%q", ip)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id + 1, Response: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if err := b.AResource(
		dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
		dnsmessage.AResource{A: a.As4()},
	); err != nil {
		return nil, err
	}
	return b.Finish()
}

// mustReply 是 buildReply 的主 goroutine 包装。
func mustReply(t *testing.T, query []byte, ip string, ttl uint32) []byte {
	t.Helper()
	raw, err := buildReply(query, ip, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// startFakeUpstream 起一个假上游 resolver。每收到一个查询就把 reply(query) 返回的若干包**按序**发回,
// 返回 nil 表示装死(用于测超时 / 全上游不可用)。返回 "host:port" 与收到的查询计数。
func startFakeUpstream(t *testing.T, reply func(query []byte) [][]byte) (string, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}

	var hits atomic.Int32
	done := make(chan struct{})
	// cleanup 是 LIFO:先关 conn 让读循环退出,再等它真的退出。顺序反了会死锁。
	t.Cleanup(func() { <-done })
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, peer, err := pc.ReadFromUDP(buf)
			if err != nil {
				return // conn 已关
			}
			hits.Add(1)
			for _, p := range reply(append([]byte(nil), buf[:n]...)) {
				_, _ = pc.WriteToUDP(p, peer)
			}
		}
	}()
	return pc.LocalAddr().String(), &hits
}

// withACLSnapshotForTest 换掉全局 ACL 快照,测试结束还原,避免污染同包其它用例。
func withACLSnapshotForTest(t *testing.T, snap *aclSnapshot) {
	t.Helper()
	old := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(old) })
	aclCurrent.Store(snap)
}

// meshOnAllowAll 是「组网开着、ACL 不拦」的基线快照。不显式装它的话,
// 用例会读到上一个用例遗留的全局状态,断言就不作数了。
func meshOnAllowAll() *aclSnapshot {
	return &aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: true}
}

// withVIPOwnerForTest 把 vIP 登记进全局归属表(与数据面同一张),测试结束摘除。
func withVIPOwnerForTest(t *testing.T, ip string, userID int64, connID uint32) {
	t.Helper()
	a := netip.MustParseAddr(ip)
	registerVIPOwners([]netip.Addr{a}, userID, connID)
	t.Cleanup(func() { unregisterVIPOwners([]netip.Addr{a}, connID) })
}

// withIsolateForTest 打开 exit_mode=isolate 的运行时开关,测试结束还原。
func withIsolateForTest(t *testing.T) {
	t.Helper()
	old := clientIsolateMode.Load()
	t.Cleanup(func() { clientIsolateMode.Store(old) })
	clientIsolateMode.Store(true)
}

// ------------------------------------------------------- 报文本身的健壮性

// 截断到解析不出 header 的报文:静默丢弃,一个字节都不回。
// 反面(回一帧 FormatError)会让 server 变成放大器 —— 攻击者伪造源 IP 就能拿它打反射。
func TestMagicDNS_TruncatedQueryIsDroppedWithoutReply(t *testing.T) {
	gw := newMagicDNSGateway(t)
	r := magicDNSResolved{suffix: "lan", port: 5353}

	before := magicDNSMalformedCount.Load()
	if _, ok := runMagicDNSQueryRaw(t, gw, r, []byte{0x42, 0x42, 0x01}, 300*time.Millisecond); ok {
		t.Fatal("解析不出 header 的报文不该有任何回包")
	}
	if got := magicDNSMalformedCount.Load(); got != before+1 {
		t.Fatalf("malformed 计数 %d → %d,应 +1", before, got)
	}
}

// header 合法但没有 question section → FormatError,TXID 原样回带。
func TestMagicDNS_HeaderWithoutQuestionIsFormatError(t *testing.T) {
	gw := newMagicDNSGateway(t)
	r := magicDNSResolved{suffix: "lan", port: 5353}

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242})
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	before := magicDNSMalformedCount.Load()
	hdr := mustRCode(t, gw, r, raw, dnsmessage.RCodeFormatError)
	if hdr.ID != 0x4242 {
		t.Fatalf("TXID 应原样回带,got %#x", hdr.ID)
	}
	if got := magicDNSMalformedCount.Load(); got != before+1 {
		t.Fatalf("malformed 计数 %d → %d,应 +1", before, got)
	}
}

// class 不是 INET(如 CHAOS)→ NOTIMP。CHAOS 的 version.bind / hostname.bind 是常见指纹探测,
// 不能顺着 A/AAAA 主干往下跑。
func TestMagicDNS_NonINETClassIsNotImplemented(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "alice", "mac", "100.64.0.5", "")
	withACLSnapshotForTest(t, meshOnAllowAll())
	r := magicDNSResolved{suffix: "lan", port: 5353}

	q := buildDNSQueryFull(t, "version.bind", dnsmessage.TypeA, dnsmessage.ClassCHAOS)
	mustRCode(t, gw, r, q, dnsmessage.RCodeNotImplemented)
}

// -------------------------------------------- 非 A/AAAA 查询落在 mesh 名上

// mesh OFF + 跨用户 + 非 A/AAAA(这里用 TXT)→ 与 A/AAAA 同口径 NXDOMAIN。
// 若这条分支漏了,换个 qtype 就能绕过 mesh-off 探出对端主机的存在性。
func TestMagicDNS_NonAddrQueryOnMagicNameHonoursMeshOff(t *testing.T) {
	ctx := t.Context()
	gw := newMagicDNSGateway(t)
	alice, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	seedDevice(t, gw.store, "bob", "pi", "100.64.0.9", "")

	withVIPOwnerForTest(t, "127.0.0.1", alice.ID, 1)
	withACLSnapshotForTest(t, &aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: false})
	r := magicDNSResolved{suffix: "lan", port: 5353}

	before := magicDNSMeshOffNXCount.Load()
	mustRCode(t, gw, r, buildDNSQuery(t, "pi.bob.lan", dnsmessage.TypeTXT), dnsmessage.RCodeNameError)
	if got := magicDNSMeshOffNXCount.Load(); got != before+1 {
		t.Fatalf("mesh_off_nxdomain 计数 %d → %d,应 +1", before, got)
	}
}

// mesh ON 但 ACL 判定 alice→bob 完全不可达 → 非 A/AAAA 也 NXDOMAIN(同上,堵换 qtype 的探测)。
func TestMagicDNS_NonAddrQueryOnMagicNameHonoursACL(t *testing.T) {
	ctx := t.Context()
	gw := newMagicDNSGateway(t)
	alice, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	seedDevice(t, gw.store, "bob", "pi", "100.64.0.9", "")

	withVIPOwnerForTest(t, "127.0.0.1", alice.ID, 1)
	// 白名单模型且无任何 allow 例外 → aclAllows(alice,bob)=false。
	withACLSnapshotForTest(t, &aclSnapshot{defaultAction: store.ACLDeny, meshEnabled: true})
	r := magicDNSResolved{suffix: "lan", port: 5353}

	before := magicDNSACLNXCount.Load()
	mustRCode(t, gw, r, buildDNSQuery(t, "pi.bob.lan", dnsmessage.TypeTXT), dnsmessage.RCodeNameError)
	if got := magicDNSACLNXCount.Load(); got != before+1 {
		t.Fatalf("acl_nxdomain 计数 %d → %d,应 +1", before, got)
	}
}

// 非 mesh 名的非 A/AAAA 查询:没配上游 → NOTIMP(不能假装成功,也不能挂着不回)。
func TestMagicDNS_NonAddrQueryOnPublicNameWithoutUpstreamIsNotImplemented(t *testing.T) {
	gw := newMagicDNSGateway(t)
	withACLSnapshotForTest(t, meshOnAllowAll())
	r := magicDNSResolved{suffix: "lan", port: 5353}

	mustRCode(t, gw, r, buildDNSQuery(t, "example.com", dnsmessage.TypeMX), dnsmessage.RCodeNotImplemented)
}

// 非 mesh 名的非 A/AAAA 查询:配了上游 → 转发,并把上游应答带回客户端。
func TestMagicDNS_NonAddrQueryOnPublicNameForwardsUpstream(t *testing.T) {
	gw := newMagicDNSGateway(t)
	withACLSnapshotForTest(t, meshOnAllowAll())
	up, hits := startFakeUpstream(t, func(q []byte) [][]byte {
		raw, err := buildReply(q, "203.0.113.7", 300)
		if err != nil {
			return nil
		}
		return [][]byte{raw}
	})
	r := magicDNSResolved{suffix: "lan", port: 5353, upstream: []string{up}}

	resp, ok := runMagicDNSQueryRaw(t, gw, r, buildDNSQuery(t, "example.com", dnsmessage.TypeMX), 3*time.Second)
	if !ok {
		t.Fatal("应把上游应答转回客户端")
	}
	hdr, answers := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 {
		t.Fatalf("上游应答未原样转回: rcode=%v answers=%d", hdr.RCode, len(answers))
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("上游收到 %d 次查询,应为 1", got)
	}
}

// -------------------------------------------------- A/AAAA 主干上的拒答分支

// mesh OFF + 跨用户 A 查询 → NXDOMAIN(数据面必丢,解析层对齐,不给「解析成功却连不上」)。
func TestMagicDNS_AddrQueryCrossUserMeshOffIsNXDOMAIN(t *testing.T) {
	ctx := t.Context()
	gw := newMagicDNSGateway(t)
	alice, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	seedDevice(t, gw.store, "bob", "pi", "100.64.0.9", "")

	withVIPOwnerForTest(t, "127.0.0.1", alice.ID, 1)
	withACLSnapshotForTest(t, &aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: false})
	r := magicDNSResolved{suffix: "lan", port: 5353}

	mustRCode(t, gw, r, buildDNSQuery(t, "pi.bob.lan", dnsmessage.TypeA), dnsmessage.RCodeNameError)
}

// mesh ON + ACL 不可达 → A 查询 NXDOMAIN;反证:同一 gateway 上 alice 查自己的设备照常作答。
// 反证很关键 —— 只断言「拒答」的话,把整个 magic 分支删成无条件 NXDOMAIN 也能过。
func TestMagicDNS_AddrQueryACLDeniedIsNXDOMAINButSelfStillResolves(t *testing.T) {
	ctx := t.Context()
	gw := newMagicDNSGateway(t)
	alice, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := gw.store.UpsertDevice(ctx, alice.ID, "uuid-alice", "mac", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.store.UpsertLease(ctx, d.ID, "100.64.0.5", "", false); err != nil {
		t.Fatal(err)
	}
	seedDevice(t, gw.store, "bob", "pi", "100.64.0.9", "")

	withVIPOwnerForTest(t, "127.0.0.1", alice.ID, 1)
	withACLSnapshotForTest(t, &aclSnapshot{defaultAction: store.ACLDeny, meshEnabled: true})
	r := magicDNSResolved{suffix: "lan", port: 5353}

	mustRCode(t, gw, r, buildDNSQuery(t, "pi.bob.lan", dnsmessage.TypeA), dnsmessage.RCodeNameError)
	// 同用户不受 ACL 影响(aclAllows 对 src==dst 直接放行)。
	mustRCode(t, gw, r, buildDNSQuery(t, "mac.alice.lan", dnsmessage.TypeA), dnsmessage.RCodeSuccess)
}

// 段数不对的 magic 名(a.b.c.lan)→ NXDOMAIN,且绝不能漏到公网上游去(内网命名泄漏)。
func TestMagicDNS_MalformedMagicNameIsNXDOMAINAndNeverLeaksUpstream(t *testing.T) {
	gw := newMagicDNSGateway(t)
	withACLSnapshotForTest(t, meshOnAllowAll())
	up, hits := startFakeUpstream(t, func(q []byte) [][]byte {
		raw, err := buildReply(q, "203.0.113.7", 300)
		if err != nil {
			return nil
		}
		return [][]byte{raw}
	})
	r := magicDNSResolved{suffix: "lan", port: 5353, upstream: []string{up}}

	mustRCode(t, gw, r, buildDNSQuery(t, "a.b.c.lan", dnsmessage.TypeA), dnsmessage.RCodeNameError)
	if got := hits.Load(); got != 0 {
		t.Fatalf("mesh 名不得外发公网上游,上游却收到 %d 次查询", got)
	}
}

// isolate 下:别人的设备名一律 NXDOMAIN,自己的名字照常解析。
// 后半段是反证 —— 少了它,「isolate 时把整条 magic 路径短路成 NXDOMAIN」这种过度实现也能过。
func TestMagicDNS_IsolateHidesPeersButNotSelf(t *testing.T) {
	ctx := t.Context()
	gw := newMagicDNSGateway(t)
	alice, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := gw.store.UpsertDevice(ctx, alice.ID, "uuid-alice", "mac", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.store.UpsertLease(ctx, d.ID, "100.64.0.5", "", false); err != nil {
		t.Fatal(err)
	}
	seedDevice(t, gw.store, "bob", "pi", "100.64.0.9", "")

	// 查询方 = alice 的会话 conn 1;它自己的 vIP 也挂在 conn 1 上,bob 的挂在 conn 2。
	withVIPOwnerForTest(t, "127.0.0.1", alice.ID, 1)
	withVIPOwnerForTest(t, "100.64.0.5", alice.ID, 1)
	withVIPOwnerForTest(t, "100.64.0.9", 999, 2)
	withACLSnapshotForTest(t, meshOnAllowAll())
	withIsolateForTest(t)
	r := magicDNSResolved{suffix: "lan", port: 5353}

	mustRCode(t, gw, r, buildDNSQuery(t, "pi.bob.lan", dnsmessage.TypeA), dnsmessage.RCodeNameError)
	mustRCode(t, gw, r, buildDNSQuery(t, "mac.alice.lan", dnsmessage.TypeA), dnsmessage.RCodeSuccess)
}

// isolate 下 4via6 名同样拒答:它指向别人背后的内网主机,整条路径在 isolate 下必然黑洞。
func TestMagicDNS_Isolate4via6IsNXDOMAIN(t *testing.T) {
	ctx := t.Context()
	gw := newMagicDNSGateway(t)
	u, err := gw.store.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := gw.store.UpsertDevice(ctx, u.ID, "uuid-alice", "homerouter", "test")
	if err != nil {
		t.Fatal(err)
	}
	sid, err := gw.store.GetOrAssignSiteID(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", d.ID)})

	withVIPOwnerForTest(t, "127.0.0.1", u.ID, 1)
	withACLSnapshotForTest(t, meshOnAllowAll())
	withIsolateForTest(t)
	r := magicDNSResolved{suffix: "lan", port: 5353}

	q := buildDNSQuery(t, fmt.Sprintf("192-168-1-10via%d.lan", sid), dnsmessage.TypeAAAA)
	mustRCode(t, gw, r, q, dnsmessage.RCodeNameError)
}

// 公网名 + 配了上游 → 转发(A/AAAA 主干末端)。
func TestMagicDNS_PublicAddrQueryForwardsUpstream(t *testing.T) {
	gw := newMagicDNSGateway(t)
	withACLSnapshotForTest(t, meshOnAllowAll())
	up, hits := startFakeUpstream(t, func(q []byte) [][]byte {
		raw, err := buildReply(q, "203.0.113.9", 300)
		if err != nil {
			return nil
		}
		return [][]byte{raw}
	})
	r := magicDNSResolved{suffix: "lan", port: 5353, upstream: []string{up}}

	resp, ok := runMagicDNSQueryRaw(t, gw, r, buildDNSQuery(t, "example.com", dnsmessage.TypeA), 3*time.Second)
	if !ok {
		t.Fatal("应把上游应答转回客户端")
	}
	_, answers := parseDNSResponse(t, resp)
	if len(answers) != 1 {
		t.Fatalf("answers=%d,want 1", len(answers))
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("上游收到 %d 次查询,应为 1", got)
	}
}

// ------------------------------------------------------------ 上游转发链路

// 所有上游都不可达 → SERVFAIL,且 TXID 原样回带(客户端要靠它对上号)。
// 「逐个 upstream 试过去」的循环也在这里走到。
func TestForwardMagicDNSToUpstream_AllUpstreamsDeadIsServfail(t *testing.T) {
	gw := newMagicDNSGateway(t)
	withACLSnapshotForTest(t, meshOnAllowAll())
	// 两个都装死:第二个用来证明「第一个失败后会继续试下一个」。
	dead1, hits1 := startFakeUpstream(t, func([]byte) [][]byte { return nil })
	dead2, hits2 := startFakeUpstream(t, func([]byte) [][]byte { return nil })
	r := magicDNSResolved{suffix: "lan", port: 5353, upstream: []string{dead1, dead2}}

	before := magicDNSServfailCount.Load()
	hdr := mustRCode(t, gw, r, buildDNSQuery(t, "example.com", dnsmessage.TypeA), dnsmessage.RCodeServerFailure)
	if hdr.ID != 0x4242 {
		t.Fatalf("SERVFAIL 也要回带原 TXID,got %#x", hdr.ID)
	}
	if hits1.Load() != 1 || hits2.Load() != 1 {
		t.Fatalf("两个上游都该被试一次,实际 %d / %d", hits1.Load(), hits2.Load())
	}
	if got := magicDNSServfailCount.Load(); got != before+1 {
		t.Fatalf("servfail 计数 %d → %d,应 +1", before, got)
	}
}

// 第一个上游装死、第二个能答 → 要 fail-over 到第二个,而不是直接 SERVFAIL。
func TestForwardMagicDNSToUpstream_FallsOverToNextUpstream(t *testing.T) {
	gw := newMagicDNSGateway(t)
	withACLSnapshotForTest(t, meshOnAllowAll())
	dead, _ := startFakeUpstream(t, func([]byte) [][]byte { return nil })
	live, liveHits := startFakeUpstream(t, func(q []byte) [][]byte {
		raw, err := buildReply(q, "203.0.113.11", 60)
		if err != nil {
			return nil
		}
		return [][]byte{raw}
	})
	r := magicDNSResolved{suffix: "lan", port: 5353, upstream: []string{dead, live}}

	resp, ok := runMagicDNSQueryRaw(t, gw, r, buildDNSQuery(t, "example.com", dnsmessage.TypeA), 5*time.Second)
	if !ok {
		t.Fatal("第二个上游能答,不该落到没有回包")
	}
	hdr, answers := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 {
		t.Fatalf("应拿到第二个上游的答案: rcode=%v answers=%d", hdr.RCode, len(answers))
	}
	if got := liveHits.Load(); got != 1 {
		t.Fatalf("第二个上游被查 %d 次,应为 1", got)
	}
}

// dialAndQueryUDP 的反投毒:抢在真应答前到达的伪造包(TXID 不符)必须被丢掉,继续等真应答。
// 这是 off-path 盲注的最基本防线,少了它 server 的自解析会被污染。
func TestDialAndQueryUDP_DropsSpoofedReplyAndWaitsForTheRealOne(t *testing.T) {
	const realIP = "198.51.100.20"
	up, _ := startFakeUpstream(t, func(q []byte) [][]byte {
		bad, err1 := buildSpoofReply(q, "6.6.6.6")
		good, err2 := buildReply(q, realIP, 300)
		if err1 != nil || err2 != nil {
			return nil
		}
		return [][]byte{bad, good} // 伪造包先到
	})

	resp, err := dialAndQueryUDP(t.Context(), up, buildDNSQuery(t, "example.com", dnsmessage.TypeA), 3*time.Second)
	if err != nil {
		t.Fatalf("应拿到真应答: %v", err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("answers=%d,want 1", len(msg.Answers))
	}
	a, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer 类型不对: %T", msg.Answers[0].Body)
	}
	if got := netip.AddrFrom4(a.A).String(); got != realIP {
		t.Fatalf("拿到 %s —— 伪造应答被当成了真的", got)
	}
}

// 只有伪造包、真应答永不到达 → 必须等到 deadline 后报错,不能把伪造包当答案。
func TestDialAndQueryUDP_TimesOutWhenOnlySpoofedRepliesArrive(t *testing.T) {
	up, _ := startFakeUpstream(t, func(q []byte) [][]byte {
		bad, err := buildSpoofReply(q, "6.6.6.6")
		if err != nil {
			return nil
		}
		return [][]byte{bad}
	})

	start := time.Now()
	if _, err := dialAndQueryUDP(t.Context(), up, buildDNSQuery(t, "example.com", dnsmessage.TypeA), 400*time.Millisecond); err == nil {
		t.Fatal("只有伪造包时必须超时失败,不能返回伪造应答")
	}
	if el := time.Since(start); el < 300*time.Millisecond {
		t.Fatalf("提前 %v 就返回了,说明没等到 deadline", el)
	}
}

// 上游地址非法 → dial 阶段就失败。
func TestDialAndQueryUDP_BadAddressFails(t *testing.T) {
	if _, err := dialAndQueryUDP(t.Context(), "127.0.0.1:not-a-port",
		buildDNSQuery(t, "example.com", dnsmessage.TypeA), time.Second); err == nil {
		t.Fatal("非法上游地址应报错")
	}
}

// ----------------------------------------------------------------- TTL 钳制

func TestClampDNSResponseTTLs_ClampsOnlyWhatExceedsTheCap(t *testing.T) {
	q := buildDNSQuery(t, "example.com", dnsmessage.TypeA)

	t.Run("超上限被钳短", func(t *testing.T) {
		out, changed := clampDNSResponseTTLs(mustReply(t, q, "203.0.113.5", 3600), 2)
		if !changed {
			t.Fatal("3600 > 2,应判为有改动")
		}
		var m dnsmessage.Message
		if err := m.Unpack(out); err != nil {
			t.Fatal(err)
		}
		if m.Answers[0].Header.TTL != 2 {
			t.Fatalf("TTL=%d,want 2", m.Answers[0].Header.TTL)
		}
	})

	t.Run("未超上限不重打包", func(t *testing.T) {
		raw := mustReply(t, q, "203.0.113.5", 1)
		out, changed := clampDNSResponseTTLs(raw, 2)
		if changed {
			t.Fatal("1 <= 2,不该判为有改动")
		}
		if &out[0] != &raw[0] {
			t.Fatal("无改动时应原样返回同一份 buffer")
		}
	})

	t.Run("坏报文 fail-safe 原样返回", func(t *testing.T) {
		raw := []byte{0x00, 0x01, 0x02}
		out, changed := clampDNSResponseTTLs(raw, 2)
		if changed {
			t.Fatal("坏报文不该被判为有改动")
		}
		if len(out) != len(raw) {
			t.Fatal("坏报文必须原样返回,宁可不钳也不能弄坏应答")
		}
	})
}
