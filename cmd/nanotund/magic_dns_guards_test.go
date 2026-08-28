package main

// MagicDNS 的四个「静默判错」面。
//
// DNS 这层的特点是**判错几乎不会报错**:它只是回一个不同的地址,或者对一个存在的名字说
// 不存在。客户端拿到什么就用什么,运维那头看到的只有「网怪怪的」。这里钉四类:
//
//   1. 反投毒判据(dnsReplyMatches / parseDNSQueryKey)—— 放松一格就等于接受 off-path
//      伪造应答,把错误地址回给客户端且进缓存;
//   2. 名字 → 地址的**确定性**(lookupMagicHost 的重名设备取最小 ID)—— 判错的表现是
//      「同一个名字有时连到这台、有时连到那台」,随上下线漂移,最难查的一种;
//   3. 启动守卫(startMagicDNS)—— 判错的表现是运维以为 magic_dns 生效了,实际 listener
//      压根没起来 / 起在客户端打不到的端口上;
//   4. 上游地址归一(resolveMagicDNSConfig)—— 少一个 :53 或少一对方括号,所有公网名
//      静默变 SERVFAIL。

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
)

// ------------------------------------------------------ 反投毒判据

// TestDNSReplyMatches_RejectsEverythingThatIsNotThisAnswer 直测那道叠加在内核 5-tuple
// 过滤之上的 DNS 层校验。
//
// 每一条都对应一种真实的伪造/串味形态:少了任何一项,一个 on-path(或能伪 upstream 源地址)
// 的攻击者就能在真应答之前抢注一包 —— server 会把它当权威答案回给客户端,且下一跳缓存也吃下去。
func TestDNSReplyMatches_RejectsEverythingThatIsNotThisAnswer(t *testing.T) {
	query := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
	wantID, wantQ, ok := parseDNSQueryKey(query)
	if !ok {
		t.Fatal("前置条件:查询报文应当解析出 key")
	}

	good, err := buildReply(query, "93.184.216.34", 300)
	if err != nil {
		t.Fatalf("造合法应答: %v", err)
	}
	if !dnsReplyMatches(good, wantID, wantQ) {
		t.Fatal("前置条件不成立:合法应答必须被接受,否则下面的「拒绝」证明不了任何事")
	}

	mkReply := func(t *testing.T, id uint16, response bool, name string, qtype dnsmessage.Type, class dnsmessage.Class) []byte {
		t.Helper()
		n, err := dnsmessage.NewName(name)
		if err != nil {
			t.Fatal(err)
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: response})
		if err := b.StartQuestions(); err != nil {
			t.Fatal(err)
		}
		if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: class}); err != nil {
			t.Fatal(err)
		}
		raw, err := b.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	t.Run("TXID 差一位就拒", func(t *testing.T) {
		spoof, err := buildSpoofReply(query, "1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		if dnsReplyMatches(spoof, wantID, wantQ) {
			t.Fatal("TXID 不符必须拒 —— 这是盲注最基本的那道门")
		}
	})

	t.Run("Response 位没置位就拒", func(t *testing.T) {
		// 一个「查询」形状的包不能当应答收下:否则攻击者把自己的查询回灌给 server 就能污染。
		q := mkReply(t, wantID, false, "example.com.", dnsmessage.TypeA, dnsmessage.ClassINET)
		if dnsReplyMatches(q, wantID, wantQ) {
			t.Fatal("QR=0 的报文不是应答,必须拒")
		}
	})

	t.Run("换了个名字就拒", func(t *testing.T) {
		other := mkReply(t, wantID, true, "evil.com.", dnsmessage.TypeA, dnsmessage.ClassINET)
		if dnsReplyMatches(other, wantID, wantQ) {
			t.Fatal("question 名不符必须拒 —— 否则猜中 TXID 就能塞任意名字的答案")
		}
	})

	t.Run("同名不同 qtype 就拒", func(t *testing.T) {
		// 迟到的旧应答典型形态:同名同 TXID(TXID 会复用)但问的是 AAAA。
		other := mkReply(t, wantID, true, "example.com.", dnsmessage.TypeAAAA, dnsmessage.ClassINET)
		if dnsReplyMatches(other, wantID, wantQ) {
			t.Fatal("qtype 不符必须拒")
		}
	})

	t.Run("同名不同 class 就拒", func(t *testing.T) {
		other := mkReply(t, wantID, true, "example.com.", dnsmessage.TypeA, dnsmessage.ClassCHAOS)
		if dnsReplyMatches(other, wantID, wantQ) {
			t.Fatal("class 不符必须拒")
		}
	})

	t.Run("大小写不同要接受", func(t *testing.T) {
		// 0x20 编码 / 上游随机化大小写是常见做法,按字节比会把**合法**应答全部丢掉,
		// 表现为该上游一律超时 —— 反方向的坑,同样要钉。
		mixed := mkReply(t, wantID, true, "ExAmPlE.CoM.", dnsmessage.TypeA, dnsmessage.ClassINET)
		if !dnsReplyMatches(mixed, wantID, wantQ) {
			t.Fatal("名称比较必须大小写不敏感,否则做 0x20 随机化的上游全部失效")
		}
	})

	t.Run("解析不出的应答就拒", func(t *testing.T) {
		for _, junk := range [][]byte{nil, {}, {0x42}, good[:6]} {
			if dnsReplyMatches(junk, wantID, wantQ) {
				t.Fatalf("解析不出的报文必须拒: %v", junk)
			}
		}
	})

	t.Run("应答里没有 question 就拒", func(t *testing.T) {
		// 只有 header、question 段为空的应答:名字对不上号,无从判断它答的是谁。
		hdrOnly := buildMagicDNSStatusBytes(wantID, dnsmessage.RCodeSuccess, dnsmessage.Question{})
		if hdrOnly == nil {
			t.Fatal("造 header-only 应答失败")
		}
		if dnsReplyMatches(hdrOnly, wantID, wantQ) {
			t.Fatal("查询有 question 而应答没有 → 必须拒")
		}
	})

	t.Run("查询本身没有 question 时只校验 TXID", func(t *testing.T) {
		// 这是**放宽**的一格,但它是有意的:查询无 question 时无从比对名字,只能退到 TXID。
		var emptyQ dnsmessage.Question
		hdrOnly := buildMagicDNSStatusBytes(wantID, dnsmessage.RCodeSuccess, dnsmessage.Question{})
		if !dnsReplyMatches(hdrOnly, wantID, emptyQ) {
			t.Fatal("wantQ 名长为 0 时应只按 TXID 判定")
		}
		if dnsReplyMatches(hdrOnly, wantID+1, emptyQ) {
			t.Fatal("即便退到只校验 TXID,TXID 也必须对")
		}
	})
}

// TestParseDNSQueryKey_Shapes 钉住取 key 的三种形态。第三种(ok=false)会让 dialAndQueryUDP
// 退回「收第一包即返回」—— 所以它必须只在报文**真的解析不出**时发生,不能被正常查询误触。
func TestParseDNSQueryKey_Shapes(t *testing.T) {
	t.Run("正常查询", func(t *testing.T) {
		id, q, ok := parseDNSQueryKey(buildDNSQuery(t, "a.example.com", dnsmessage.TypeAAAA))
		if !ok {
			t.Fatal("正常查询必须解析出 key,否则反投毒校验整条被绕过")
		}
		if id != 0x4242 {
			t.Fatalf("TXID = %#x, want 0x4242", id)
		}
		if got := q.Name.String(); got != "a.example.com." {
			t.Fatalf("question 名 = %q", got)
		}
		if q.Type != dnsmessage.TypeAAAA {
			t.Fatalf("qtype = %v", q.Type)
		}
	})

	t.Run("只有 header 没 question", func(t *testing.T) {
		raw := buildMagicDNSStatusBytes(0x1234, dnsmessage.RCodeSuccess, dnsmessage.Question{})
		id, q, ok := parseDNSQueryKey(raw)
		if !ok {
			t.Fatal("header 合法就该 ok=true(退化成只校验 TXID),不该整个放弃校验")
		}
		if id != 0x1234 {
			t.Fatalf("TXID = %#x", id)
		}
		if q.Name.Length != 0 {
			t.Fatal("无 question 时名长应为 0")
		}
	})

	t.Run("header 都解析不出", func(t *testing.T) {
		for _, junk := range [][]byte{nil, {}, {1, 2, 3}} {
			if _, _, ok := parseDNSQueryKey(junk); ok {
				t.Fatalf("坏报文应 ok=false: %v", junk)
			}
		}
	})
}

// ------------------------------------------------------ 名字→地址的确定性

// seedDeviceNamed 造 (user, device, lease) 并返回 device ID。与 seedDevice 的区别是可以
// 给同一个 user 造**多台**设备(seedDevice 的 uuid 按 username 派生,重名会 upsert 同一台)。
func seedDeviceNamed(t *testing.T, st *store.Store, userID int64, uuid, deviceName, v4, v6 string) int64 {
	t.Helper()
	ctx := t.Context()
	d, err := st.UpsertDevice(ctx, userID, uuid, deviceName, "test")
	if err != nil {
		t.Fatalf("建设备 %s: %v", deviceName, err)
	}
	if v4 != "" || v6 != "" {
		if _, err := st.UpsertLease(ctx, d.ID, v4, v6, false); err != nil {
			t.Fatalf("发租约 %s: %v", deviceName, err)
		}
	}
	return d.ID
}

func mustUser(t *testing.T, st *store.Store, name string) int64 {
	t.Helper()
	u, err := st.CreateUser(t.Context(), store.NewUser{Username: name, PSKHash: "h"})
	if err != nil {
		t.Fatalf("建用户 %s: %v", name, err)
	}
	return u.ID
}

// TestLookupMagicHost_DuplicateNamesResolveDeterministically 钉住重名设备的裁决:
// 取 **device_id 最小**(最早登记)的那台。
//
// 这条的价值不在「哪台赢」,而在「每次都是同一台赢」。存量库里可能存在唯一性约束生效前登记的
// 重名设备;若实现依赖 ListDevicesByUser 的返回顺序(按 last_seen),胜出者就随两台设备的上下线
// 漂移 —— 同一个名字今天连到 A、明天连到 B,而且两边都「解析成功」。这种错路由没有任何报错。
func TestLookupMagicHost_DuplicateNamesResolveDeterministically(t *testing.T) {
	gw := newMagicDNSGateway(t)
	ctx := t.Context()
	uid := mustUser(t, gw.store, "alice")

	// 必须**直写 SQL** 才造得出重名:UpsertDevice 那个 chokepoint 会给撞名的设备自动
	// 追加 "-1" 去重(走它的话两台设备根本不同名,下面的裁决压根不会被触发)。
	// 这也正是这段代码要服务的真实场景 —— 唯一性强制生效**之前**登记的存量重名设备。
	insertDupe := func(uuid, name, vip string, lastSeen int64) int64 {
		t.Helper()
		res, err := gw.store.DB().ExecContext(ctx,
			`INSERT INTO devices(user_id, device_uuid, device_name, platform, last_seen_at, created_at)
			 VALUES(?,?,?,'test',?,0)`, uid, uuid, name, lastSeen)
		if err != nil {
			t.Fatalf("直写设备 %s: %v", name, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("取 device id: %v", err)
		}
		if _, err := gw.store.UpsertLease(ctx, id, vip, "", false); err != nil {
			t.Fatalf("发租约 %s: %v", name, err)
		}
		return id
	}

	// 两台归一后同名(空格 / 下划线 / 大小写都归一成 "my-box")。让**后**登记的那台
	// last_seen 更新 —— ListDevicesByUser 是 ORDER BY last_seen_at DESC,所以任何
	// 「取遍历顺序第一个」的实现都会选中它,且这个选择随两台机器的上下线来回漂移。
	firstID := insertDupe("uuid-dupe-a", "My Box", "100.64.0.11", 1000)
	secondID := insertDupe("uuid-dupe-b", "my_BOX", "100.64.0.22", 9000)
	if firstID >= secondID {
		t.Fatalf("前置条件:先登记的 ID 应更小(%d < %d)", firstID, secondID)
	}
	// 前置条件:两台都在,且「更新鲜」的那台排在前面 —— 否则下面证明不了裁决在起作用。
	devices, err := gw.store.ListDevicesByUser(ctx, uid)
	if err != nil {
		t.Fatalf("列设备: %v", err)
	}
	if len(devices) != 2 || devices[0].ID != secondID {
		t.Fatalf("前置条件不成立:应有两台同名设备且 ID 较大的排在前, got %+v", devices)
	}

	for i := 0; i < 5; i++ {
		addrs, ok := lookupMagicHost(t.Context(), gw.store, "alice", "my-box")
		if !ok || len(addrs) == 0 {
			t.Fatal("应当解析得到地址")
		}
		if got := addrs[0].String(); got != "100.64.0.11" {
			t.Fatalf("重名时必须恒定选最早登记的那台(100.64.0.11), got %s —— "+
				"随 last_seen 漂移会让同一个名字时而连到另一台机器,且两边都「解析成功」", got)
		}
	}
}

// TestLookupMagicHost_RefusalPaths 钉住几条「查不到就说查不到」:用户不存在、设备名不匹配、
// 有设备但没有租约、租约里的 vIP 字符串坏掉。
//
// 这几条都必须返回 ok=false(→ 上层 NXDOMAIN)。返回一个空地址集而 ok=true 的话,
// 上层会拼一个「NOERROR 但没有答案」的响应 —— 客户端会认为这个名字存在只是暂时没地址,
// 于是不去查 AAAA 也不重试,表现成一个自己不会恢复的解析失败。
func TestLookupMagicHost_RefusalPaths(t *testing.T) {
	gw := newMagicDNSGateway(t)
	uid := mustUser(t, gw.store, "alice")
	ctx := t.Context()

	t.Run("store 为 nil", func(t *testing.T) {
		if _, ok := lookupMagicHost(ctx, nil, "alice", "box"); ok {
			t.Fatal("nil store 应 ok=false")
		}
	})

	t.Run("用户不存在", func(t *testing.T) {
		if _, ok := lookupMagicHost(ctx, gw.store, "nosuchuser", "box"); ok {
			t.Fatal("用户不存在应 ok=false")
		}
	})

	t.Run("设备名不匹配", func(t *testing.T) {
		seedDeviceNamed(t, gw.store, uid, "uuid-lap", "laptop", "100.64.0.31", "")
		if _, ok := lookupMagicHost(ctx, gw.store, "alice", "desktop"); ok {
			t.Fatal("名字不匹配应 ok=false")
		}
	})

	t.Run("有设备但没有租约", func(t *testing.T) {
		seedDeviceNamed(t, gw.store, uid, "uuid-nolease", "nolease", "", "")
		if _, ok := lookupMagicHost(ctx, gw.store, "alice", "nolease"); ok {
			t.Fatal("没有租约就是「现在没地址」,应 ok=false → NXDOMAIN")
		}
	})

	t.Run("租约里的 vIP 字符串坏掉", func(t *testing.T) {
		devID := seedDeviceNamed(t, gw.store, uid, "uuid-bad", "badlease", "", "")
		// 直写库塞一个解析不出的 vIP:正常写路径不会产生这种值,只有手抠 / 坏迁移会。
		if _, err := gw.store.DB().ExecContext(ctx,
			`INSERT INTO leases(device_id, vip_v4, vip_v6, manual, assigned_at)
			 VALUES(?,?,?,0,0)`, devID, "not-an-ip", ""); err != nil {
			t.Fatalf("塞坏租约: %v", err)
		}
		if _, ok := lookupMagicHost(ctx, gw.store, "alice", "badlease"); ok {
			t.Fatal("vIP 解析不出时应 ok=false,不能回一个空答案集")
		}
	})
}

// TestLookupMagicHost_NormalizesBothSides 钉住归一是**双向**的:查询里的标签和库里的
// device_name 都要归一后再比。只归一一侧的话,「Alice 的 MacBook」这类带空格/大写的
// 设备名永远解析不到 —— 而用户在 UI 上看到的就是这个名字。
func TestLookupMagicHost_NormalizesBothSides(t *testing.T) {
	gw := newMagicDNSGateway(t)
	uid := mustUser(t, gw.store, "bob")
	seedDeviceNamed(t, gw.store, uid, "uuid-mb", "Bob's Mac_Book", "100.64.0.44", "")

	for _, query := range []string{"bob-s-mac-book", "BOB-S-MAC-BOOK", "Bob-s-Mac-Book"} {
		addrs, ok := lookupMagicHost(t.Context(), gw.store, "bob", query)
		if !ok || len(addrs) == 0 || addrs[0].String() != "100.64.0.44" {
			t.Fatalf("查询 %q 应解析到 100.64.0.44, got %v (ok=%v)", query, addrs, ok)
		}
	}
}

// ------------------------------------------------------ 启动守卫

// freeUDPPort 拿一个当下空闲的 UDP 端口(拿完即释放)。有竞态,但对单机测试够用。
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// magicDNSGatewayOn 造一个启用了 MagicDNS 的 gateway,监听端口由调用方给。
func magicDNSGatewayOn(t *testing.T, port int) *gatewayState {
	t.Helper()
	gw := newMagicDNSGateway(t)
	gw.cfg = &config.Config{}
	gw.cfg.Server.MagicDNS = config.MagicDNSConfig{
		Enabled:      true,
		DomainSuffix: "lan",
		ListenPort:   uint16(port),
	}
	return gw
}

// TestStartMagicDNS_NoOpPaths 钉住四条 no-op:每一条都必须返回一个**可调用**的 cleanup
// (main 里是 defer 无条件调的,返回 nil 会 panic 在关机路径上,那是最难查的一类崩溃)。
func TestStartMagicDNS_NoOpPaths(t *testing.T) {
	port := freeUDPPort(t)

	cases := map[string]func(t *testing.T) (*gatewayState, string){
		"gw 为 nil": func(t *testing.T) (*gatewayState, string) {
			return nil, "127.0.0.1"
		},
		"store 为 nil": func(t *testing.T) (*gatewayState, string) {
			return &gatewayState{cfg: &config.Config{}}, "127.0.0.1"
		},
		"cfg 为 nil": func(t *testing.T) (*gatewayState, string) {
			gw := newMagicDNSGateway(t)
			gw.cfg = nil
			return gw, "127.0.0.1"
		},
		"未启用": func(t *testing.T) (*gatewayState, string) {
			// 端口要显式给成下面探测用的那个:留空会走默认 53,而「绑 53 需要 root」
			// 会让「其实起了 listener」的实现**碰巧**也失败 —— 那样这条用例就废了。
			gw := magicDNSGatewayOn(t, port)
			gw.cfg.Server.MagicDNS.Enabled = false
			return gw, "127.0.0.1"
		},
		"listen_addr 为空(TUN 未就绪)": func(t *testing.T) (*gatewayState, string) {
			return magicDNSGatewayOn(t, port), ""
		},
		"listen_addr 不是合法 IP": func(t *testing.T) (*gatewayState, string) {
			// 典型误配:把网卡名 / 带前缀的 CIDR 填进去。必须跳过启动而不是 panic,
			// 也不能把它当 0.0.0.0 那样起在**所有**网卡上(那会把内网 DNS 暴露到公网)。
			return magicDNSGatewayOn(t, port), "tun0"
		},
	}

	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			gw, addr := mk(t)
			cleanup := startMagicDNS(gw, addr)
			if cleanup == nil {
				t.Fatal("cleanup 不能是 nil —— main 在关机路径上无条件 defer 调它")
			}
			// 「返回了 cleanup」证不了「没起 listener」。真正的断言是端口此刻仍然空着:
			// 少了这一步,一个「非法 listen_addr 照样绑」的实现也能过 —— 而 addr.IP=nil
			// 会被 ListenUDP 当成 0.0.0.0,把本该只在 TUN 上听的内网 DNS 摆到所有网卡,
			// 包括公网口。
			probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
			if err != nil {
				t.Fatalf("端口 %d 已被占用 —— 这条路径其实起了 listener: %v", port, err)
			}
			_ = probe.Close()
			cleanup()
			cleanup() // 幂等:关机路径重复调不该炸
		})
	}
}

// TestStartMagicDNS_ListenFailureIsNotFatal 端口被占时不能崩,只跳过启动。
// 这条对应「53 已经被 systemd-resolved 占着」这个极常见的现场。
func TestStartMagicDNS_ListenFailureIsNotFatal(t *testing.T) {
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.LocalAddr().(*net.UDPAddr).Port

	gw := magicDNSGatewayOn(t, port)
	cleanup := startMagicDNS(gw, "127.0.0.1")
	if cleanup == nil {
		t.Fatal("失败时也要返回可调用的 cleanup")
	}
	cleanup()
}

// TestStartMagicDNS_ServesAndStops 走一遍真实链路:真起 UDP listener → 真发一个查询 →
// 拿到 vIP → cleanup 之后 listener 关闭、读循环退出。
//
// 这条是本文件唯一同时穿过 startMagicDNS / runMagicDNSLoop / tryAcquireMagicDNSSlot /
// handleMagicDNSPacket 的用例。前面那些 no-op 用例只证明「不该起的时候没起」,证不了
// 「该起的时候真能答」—— 少了这条,一个「一律 return no-op」的实现能通过上面全部断言。
func TestStartMagicDNS_ServesAndStops(t *testing.T) {
	withTestGlobalContext(t)
	port := freeUDPPort(t)
	gw := magicDNSGatewayOn(t, port)
	seedDevice(t, gw.store, "alice", "laptop", "100.64.0.7", "")
	withACLSnapshotForTest(t, meshOnAllowAll())

	cleanup := startMagicDNS(gw, "127.0.0.1")
	t.Cleanup(cleanup)

	cli, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	query := buildDNSQuery(t, "laptop.alice.lan", dnsmessage.TypeA)
	if _, err := cli.Write(query); err != nil {
		t.Fatalf("发查询: %v", err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("读应答: %v —— listener 没起来,或读循环没在跑", err)
	}
	hdr, answers := parseDNSResponse(t, buf[:n])
	if hdr.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 {
		t.Fatalf("rcode=%v answers=%d, want success/1", hdr.RCode, len(answers))
	}
	a, ok := answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("answer 类型 = %T", answers[0].Body)
	}
	if got := netip.AddrFrom4(a.A).String(); got != "100.64.0.7" {
		t.Fatalf("A = %s, want 100.64.0.7", got)
	}

	// cleanup 关 socket → 读循环拿到 net.ErrClosed 退出。之后再发查询就该没人应答。
	cleanup()
	if _, err := cli.Write(query); err != nil {
		t.Fatalf("二次发查询: %v", err)
	}
	_ = cli.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	if n, err := cli.Read(buf); err == nil {
		t.Fatalf("cleanup 之后仍收到 %d 字节应答 —— socket 没关,关机路径漏了一个 listener", n)
	}
}

// ------------------------------------------------------ 配置归一

// TestResolveMagicDNSConfig_UpstreamNormalization 钉住上游地址的补全规则。
//
// 少补一个 :53 或少一对方括号,dialAndQueryUDP 会在 DialContext 那步失败 → 所有公网名
// 一律 SERVFAIL。而配置文件里写 "8.8.8.8"(不带端口)是最自然的写法,所以这条补全是必须的。
func TestResolveMagicDNSConfig_UpstreamNormalization(t *testing.T) {
	got := resolveMagicDNSConfig(config.MagicDNSConfig{
		UpstreamV4: []string{"8.8.8.8", " 1.1.1.1 ", "9.9.9.9:5353", "", "   "},
		UpstreamV6: []string{"2001:4860:4860::8888", "[2606:4700:4700::1111]:5353", " ", "[2620:fe::fe]"},
	})
	want := []string{
		"8.8.8.8:53",
		"1.1.1.1:53",
		"9.9.9.9:5353", // 已带端口 → 原样
		"[2001:4860:4860::8888]:53",
		"[2606:4700:4700::1111]:5353", // 已带 "]:" → 原样
		"[2620:fe::fe]:53",            // 带方括号但无端口 → 只补端口,不再套一层括号
	}
	if len(got.upstream) != len(want) {
		t.Fatalf("上游条数 = %d(%v), want %d", len(got.upstream), got.upstream, len(want))
	}
	for i := range want {
		if got.upstream[i] != want[i] {
			t.Fatalf("upstream[%d] = %q, want %q", i, got.upstream[i], want[i])
		}
	}
	// 每一条都必须能被 net.SplitHostPort 接受 —— 这才是 DialContext 真正的要求。
	for _, up := range got.upstream {
		if _, _, err := net.SplitHostPort(up); err != nil {
			t.Fatalf("归一结果 %q 不是合法 host:port: %v", up, err)
		}
	}
}

// TestResolveMagicDNSConfig_SuffixAndPortDefaults suffix 的去空白/去点/小写 + 端口默认 53。
// 默认端口这一条有历史:曾经默认 5353,而客户端 stub resolver 永远打 :53 —— 于是
// server 在一个客户端打不到的端口上空跑 listener,运维以为生效了。
func TestResolveMagicDNSConfig_SuffixAndPortDefaults(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		// 空 / 全空白 / 只有一个点 → 回落到默认后缀。默认值 2026-08-28 从 lan 改成 nanotun
		// (lan 恰在装机脚本的保留域告警清单里,旧默认会触发自己的告警)。
		{"", "nanotun"}, {"  ", "nanotun"}, {".", "nanotun"},
		{"LAN", "lan"}, {" .Corp.Internal. ", "corp.internal"},
	} {
		if got := resolveMagicDNSConfig(config.MagicDNSConfig{DomainSuffix: tc.in}).suffix; got != tc.want {
			t.Fatalf("suffix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := resolveMagicDNSConfig(config.MagicDNSConfig{}).port; got != 53 {
		t.Fatalf("默认端口 = %d, want 53(客户端 stub resolver 只打 53)", got)
	}
	if got := resolveMagicDNSConfig(config.MagicDNSConfig{ListenPort: 5353}).port; got != 5353 {
		t.Fatalf("显式端口应保留, got %d", got)
	}
}

// TestMagicDNSSuffixForClient_GatedLikeExtraDNS 钉住下发 suffix 的条件与 prepend gateway DNS
// **严格一致**:只有「启用 + 端口 53」才下发。
//
// 两者不一致的后果:客户端(尤其 mac meshOnly)把 *.suffix 强制走隧道 DNS,而隧道里那个
// DNS 其实没有 prepend、根本不在 53 上 —— 该 suffix 下的所有名字直接解析不了,且客户端
// 不会回退到系统 DNS。比「suffix 没下发」严重得多。
func TestMagicDNSSuffixForClient_GatedLikeExtraDNS(t *testing.T) {
	mk := func(enabled bool, port uint16, suffix string) *gatewayState {
		gw := &gatewayState{cfg: &config.Config{}}
		gw.cfg.Server.MagicDNS = config.MagicDNSConfig{Enabled: enabled, ListenPort: port, DomainSuffix: suffix}
		return gw
	}

	if got := magicDNSSuffixForClient(nil); got != "" {
		t.Fatalf("gw 为 nil 应返回空, got %q", got)
	}
	if got := magicDNSSuffixForClient(&gatewayState{}); got != "" {
		t.Fatalf("cfg 为 nil 应返回空, got %q", got)
	}
	if got := magicDNSSuffixForClient(mk(false, 53, "lan")); got != "" {
		t.Fatalf("未启用应返回空, got %q", got)
	}
	if got := magicDNSSuffixForClient(mk(true, 5353, "lan")); got != "" {
		t.Fatalf("非 53 端口不下发 suffix, got %q —— 与 magicDNSExtraDNS 的 prepend 条件必须一致", got)
	}
	if got := magicDNSSuffixForClient(mk(true, 0, " .Corp. ")); got != "corp" {
		t.Fatalf("启用 + 默认 53 应下发归一后的 suffix, got %q", got)
	}
	// 两个函数的门控必须同时开同时关:抽样一致性检查。
	for _, port := range []uint16{0, 53, 5353} {
		gw := mk(true, port, "lan")
		hasExtra := magicDNSExtraDNS(gw, "10.201.0.1") != ""
		hasSuffix := magicDNSSuffixForClient(gw) != ""
		if hasExtra != hasSuffix {
			t.Fatalf("port=%d 时 prepend=%v 而 suffix=%v —— 两者必须同进同退", port, hasExtra, hasSuffix)
		}
	}
}

// ------------------------------------------------------ 上游转发的边角

// TestForwardMagicDNSToUpstream_UnparsableQueryStaysSilent 全上游失败 + 查询报文本身解析不出
// header → 一个字节都不回。
//
// 这条是反放大器的:攻击者伪造源 IP 灌畸形查询,若 server 还回 SERVFAIL,它就成了反射放大点。
func TestForwardMagicDNSToUpstream_UnparsableQueryStaysSilent(t *testing.T) {
	dead, _ := startFakeUpstream(t, func([]byte) [][]byte { return nil }) // 装死
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	before := magicDNSServfailCount.Load()
	forwardMagicDNSToUpstream(t.Context(), srv, cli.LocalAddr().(*net.UDPAddr),
		[]byte{0x01, 0x02}, magicDNSResolved{upstream: []string{dead}})

	if magicDNSServfailCount.Load() != before+1 {
		t.Fatal("全上游失败应记 servfail 计数(哪怕不回包,运维也得看得见)")
	}
	_ = cli.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 1500)
	if n, _, err := cli.ReadFromUDP(buf); err == nil {
		t.Fatalf("解析不出 header 的查询不该有任何回包,收到 %d 字节 —— server 成了反射放大点", n)
	}
}

// TestClampDNSResponseTTLs_AllSectionsButNotOPT 钳 TTL 要覆盖 Answer/Authority/Additional
// 三段,但**跳过 OPT 伪 RR** —— OPT 的 TTL 字段根本不是 TTL,而是扩展 rcode + flags,
// 改它等于篡改 EDNS 协商结果(典型后果:DO 位被抹掉、扩展 rcode 变成另一个错误码)。
func TestClampDNSResponseTTLs_AllSectionsButNotOPT(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	root := dnsmessage.MustNewName(".")
	const bigTTL = 86400
	// OPT 的 TTL 位放一个「看起来像大 TTL」的值:被误钳的话这里会变。
	const optTTL = 0x8000_0000 >> 1

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1, Response: true},
		Questions: []dnsmessage.Question{
			{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: bigTTL},
			Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
		}},
		Authorities: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: bigTTL},
			Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns1.example.com.")},
		}},
		Additionals: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: bigTTL},
				Body:   &dnsmessage.AResource{A: [4]byte{5, 6, 7, 8}},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: root, Type: dnsmessage.TypeOPT, Class: 4096, TTL: optTTL},
				Body:   &dnsmessage.OPTResource{},
			},
		},
	}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	const capTTL = 30
	out, changed := clampDNSResponseTTLs(raw, capTTL)
	if !changed {
		t.Fatal("三段都超上限,应报告有改动")
	}
	var got dnsmessage.Message
	if err := got.Unpack(out); err != nil {
		t.Fatalf("钳完之后解析不出来了: %v", err)
	}
	for _, sec := range []struct {
		what string
		rrs  []dnsmessage.Resource
	}{
		{"Answer", got.Answers}, {"Authority", got.Authorities},
	} {
		for _, rr := range sec.rrs {
			if rr.Header.TTL != capTTL {
				t.Fatalf("%s 段的 TTL = %d, want %d", sec.what, rr.Header.TTL, capTTL)
			}
		}
	}
	for _, rr := range got.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			if rr.Header.TTL != optTTL {
				t.Fatalf("OPT 的 TTL 字段被改了(%d → %d)—— 那不是 TTL,是扩展 rcode/flags",
					uint32(optTTL), rr.Header.TTL)
			}
			continue
		}
		if rr.Header.TTL != capTTL {
			t.Fatalf("Additional 段的 TTL = %d, want %d", rr.Header.TTL, capTTL)
		}
	}

	// 都在上限之内 → 原样返回、报告无改动(不重打包,避免无谓地改变字节)。
	small := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 2, Response: true},
		Questions: msg.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10},
			Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
		}},
	}
	sraw, err := small.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if out, changed := clampDNSResponseTTLs(sraw, capTTL); changed || !bytes.Equal(out, sraw) {
		t.Fatal("TTL 都在上限内时应原样返回且报告无改动")
	}

	// 解析不出的应答:原样返回,不能因为钳不动就把它弄坏或丢掉(fail-safe)。
	junk := []byte{0xde, 0xad}
	if out, changed := clampDNSResponseTTLs(junk, capTTL); changed || !bytes.Equal(out, junk) {
		t.Fatal("解析不出的应答应原样返回")
	}
}

// ------------------------------------------------------ 换 qtype 探存在性

// TestMagicHostExists_IsolateHidesExistenceForOtherPeers 钉住 isolate 下的信息面一致性:
// A/AAAA 被拦了,换一个 qtype(如 MX)也不能从「NODATA vs NXDOMAIN」的区别里探出
// 对端设备是否存在。
//
// 这条容易漏,因为 A/AAAA 那条路径的 isolate 判定与这条是两处代码。漏了的后果是
// 一个能用任意 qtype 遍历的设备名探测器 —— isolate 承诺的「互相看不见」就只剩一半。
func TestMagicHostExists_IsolateHidesExistenceForOtherPeers(t *testing.T) {
	gw := newMagicDNSGateway(t)
	seedDevice(t, gw.store, "alice", "laptop", "100.64.0.5", "")
	seedDevice(t, gw.store, "bob", "desktop", "100.64.0.6", "")
	// 两台设备各自登记归属,但**不是**同一个会话(connID 不同)。
	withVIPOwnerForTest(t, "100.64.0.5", 1, 101)
	withVIPOwnerForTest(t, "100.64.0.6", 2, 102)
	alice := &net.UDPAddr{IP: net.ParseIP("100.64.0.5"), Port: 5353}

	// 非 isolate:别人的名字「存在」是可见的(NODATA 语义)。
	if !magicHostExists(t.Context(), gw, alice, "desktop.bob.lan", "lan") {
		t.Fatal("前置条件:非 isolate 下应当认为对端名字存在")
	}

	withIsolateForTest(t)
	if magicHostExists(t.Context(), gw, alice, "desktop.bob.lan", "lan") {
		t.Fatal("isolate 下别人的名字连「存在与否」都不该答 —— " +
			"否则换个 qtype 就能从 NODATA/NXDOMAIN 的区别里遍历出所有设备名")
	}
	// 自查本机名照常:isolate 不该把自己也藏起来。
	if !magicHostExists(t.Context(), gw, alice, "laptop.alice.lan", "lan") {
		t.Fatal("isolate 下自查本机名仍应可见")
	}
}

// TestMagicHostExists_RefusalPaths 无 store / 名字非法 / 站点不存在 → 一律「不存在」。
func TestMagicHostExists_RefusalPaths(t *testing.T) {
	gw := newMagicDNSGateway(t)
	ctx := t.Context()

	if magicHostExists(ctx, nil, nil, "x.y.lan", "lan") {
		t.Fatal("gw 为 nil 应返回 false")
	}
	if magicHostExists(ctx, &gatewayState{}, nil, "x.y.lan", "lan") {
		t.Fatal("store 为 nil 应返回 false")
	}
	for _, name := range []string{"lan", "toomany.labels.here.lan", "nosuchhost.nosuchuser.lan"} {
		if magicHostExists(ctx, gw, nil, name, "lan") {
			t.Fatalf("%q 不该被认为存在", name)
		}
	}
	// 未分配的 siteID:4via6 形状的名字也要走同样的「查不到就是不存在」。
	if magicHostExists(ctx, gw, nil, "192-168-1-5via9999.lan", "lan") {
		t.Fatal("未分配的 siteID 不该被认为存在")
	}
}

// TestLookupVia6Addr_RefusalPaths 钉住 4via6 解析的三道拒绝。第三道(v4 不在已批准宣告
// 网段内)是关键:漏了它,用户会拿到一个「解析成功但数据面必丢」的地址 —— 正是这一层
// 想避免的「域名通了、连接超时」。
func TestLookupVia6Addr_RefusalPaths(t *testing.T) {
	gw := newMagicDNSGateway(t)
	ctx := t.Context()
	uid := mustUser(t, gw.store, "alice")
	devID := seedDeviceNamed(t, gw.store, uid, "uuid-router", "homerouter", "", "")
	sid, err := gw.store.GetOrAssignSiteID(ctx, devID)
	if err != nil {
		t.Fatalf("分配 siteID: %v", err)
	}
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", devID)})

	if _, ok := lookupVia6Addr(ctx, nil, sid, netip.MustParseAddr("192.168.1.10")); ok {
		t.Fatal("store 为 nil 应 ok=false")
	}
	if _, ok := lookupVia6Addr(ctx, gw.store, sid+9999, netip.MustParseAddr("192.168.1.10")); ok {
		t.Fatal("未分配的 siteID 应 ok=false")
	}
	if _, ok := lookupVia6Addr(ctx, gw.store, sid, netip.MustParseAddr("10.0.0.5")); ok {
		t.Fatal("目标 v4 不在宣告方已批准网段内应 ok=false —— " +
			"否则解析出的 4via6 地址在数据面必被 not-advertised 丢弃,表现成「解析成功却连不上」")
	}
	// 反面:在网段内的必须解析得出,否则上面三条可以由一个「一律 false」的实现满足。
	addr, ok := lookupVia6Addr(ctx, gw.store, sid, netip.MustParseAddr("192.168.1.10"))
	if !ok {
		t.Fatal("宣告网段内的目标应解析得到 4via6 地址")
	}
	want, wok := encode4via6(sid, netip.MustParseAddr("192.168.1.10"))
	if !wok || addr != want {
		t.Fatalf("4via6 地址 = %v, want %v", addr, want)
	}
}

// TestIsMagicDomain_Boundaries suffix 判定的边界。判宽了会把公网名当 magic 名(那个域下的
// 所有名字对客户端就地失效);判窄了会把 magic 名漏给公网上游(内部设备名泄漏给上游 DNS)。
func TestIsMagicDomain_Boundaries(t *testing.T) {
	cases := []struct {
		name, suffix string
		want         bool
	}{
		{"laptop.alice.lan", "lan", true},
		{"a.b.c.lan", "lan", true},
		{"lan", "lan", false},    // 查根域本身不算 magic
		{"notlan", "lan", false}, // 必须是「.lan」结尾,不是「以 lan 结尾」
		{"lan.example.com", "lan", false},
		{"example.com", "lan", false},
		{"x.corp.internal", "corp.internal", true},
		{"corp.internal", "corp.internal", false},
		{"", "lan", false},
		{"laptop.alice.lan", "", false}, // 没配 suffix 时一律不算
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s|%s", tc.name, tc.suffix), func(t *testing.T) {
			if got := isMagicDomain(tc.name, tc.suffix); got != tc.want {
				t.Fatalf("isMagicDomain(%q, %q) = %v, want %v", tc.name, tc.suffix, got, tc.want)
			}
		})
	}
}
