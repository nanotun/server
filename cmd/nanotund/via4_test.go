package main

// SR-VIA4（DNS46+NAT46）单测：池分配 / 返程标记编解码 / SIIT 翻译（含校验和、MSS 钳制、ICMP echo）/
// 数据面端到端（出向翻译投宣告方、返程反译投回发起方）/ DNS A 合成 / routes-list 池条目。

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// setVia4ForTest 装一份 via4 运行态并在用例结束后还原。
func setVia4ForTest(t *testing.T, pool string) *via4Table {
	t.Helper()
	prev := via4State.Load()
	p := netip.MustParsePrefix(pool).Masked()
	tbl := &via4Table{
		pool:   p,
		byKey:  make(map[via4Key]*via4Mapping),
		byPool: make(map[netip.Addr]*via4Mapping),
		cursor: p.Addr(),
	}
	via4State.Store(tbl)
	t.Cleanup(func() { via4State.Store(prev) })
	return tbl
}

// mkV4UDP 造一个 v4 UDP 包（无选项头 + 8 字节 UDP 头 + payload），校验和按规范算好。
func mkV4UDP(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	l4 := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)
	binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
	copy(l4[8:], payload)
	s4, d4 := src.As4(), dst.As4()
	writeL4ChecksumV4(l4, 17, s4, d4)
	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:20]))
	copy(pkt[20:], l4)
	return pkt
}

// verifyL4V6 校验 v6 包内 L4 校验和是否自洽（重算应得 0 差；这里直接重算比对字段值）。
func verifyL4V6(t *testing.T, pkt []byte) {
	t.Helper()
	nextHdr := pkt[6]
	var src, dst [16]byte
	copy(src[:], pkt[8:24])
	copy(dst[:], pkt[24:40])
	l4 := append([]byte(nil), pkt[40:]...)
	off := l4ChecksumOffset(nextHdr)
	got := binary.BigEndian.Uint16(l4[off : off+2])
	writeL4ChecksumV6(l4, nextHdr, src, dst)
	want := binary.BigEndian.Uint16(l4[off : off+2])
	if got != want {
		t.Fatalf("v6 L4 校验和不自洽: got %#04x want %#04x", got, want)
	}
}

// verifyL4V4 校验 v4 包内 L4 校验和 + 头校验和自洽。
func verifyL4V4(t *testing.T, pkt []byte) {
	t.Helper()
	ihl := int(pkt[0]&0x0f) * 4
	hdr := append([]byte(nil), pkt[:ihl]...)
	gotH := binary.BigEndian.Uint16(hdr[10:12])
	hdr[10], hdr[11] = 0, 0
	if wantH := ipv4HeaderChecksum(hdr); gotH != wantH {
		t.Fatalf("v4 头校验和不自洽: got %#04x want %#04x", gotH, wantH)
	}
	proto := pkt[9]
	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	l4 := append([]byte(nil), pkt[ihl:]...)
	off := l4ChecksumOffset(proto)
	got := binary.BigEndian.Uint16(l4[off : off+2])
	writeL4ChecksumV4(l4, proto, src, dst)
	want := binary.BigEndian.Uint16(l4[off : off+2])
	if got != want {
		t.Fatalf("v4 L4 校验和不自洽: got %#04x want %#04x", got, want)
	}
}

// ---- 返程标记编解码 ----

func TestVia4ReturnMarkerRoundTrip(t *testing.T) {
	client := netip.MustParseAddr("10.201.0.28")
	addr, ok := encodeVia4Return(client)
	if !ok {
		t.Fatal("encodeVia4Return 失败")
	}
	if !via6Prefix.Contains(addr) {
		t.Fatalf("返程标记地址必须落在 via6Prefix 内（客户端已装的 /64 路由要覆盖它）: %s", addr)
	}
	got, ok := decodeVia4Return(addr)
	if !ok || got != client {
		t.Fatalf("decodeVia4Return = (%s, %v), want (%s, true)", got, ok, client)
	}
	// 真 4via6 地址（reserved==0）不得被误识别为返程标记。
	real46, _ := encode4via6(7, netip.MustParseAddr("192.168.1.10"))
	if _, ok := decodeVia4Return(real46); ok {
		t.Fatal("真 4via6 地址被误识别为返程标记")
	}
	// 返程标记地址误入站点路由时 decode4via6 必须得 siteID=0（无效站点 → NoSite 丢弃，不误投）。
	if sid, _, ok := decode4via6(addr); ok && sid != 0 {
		t.Fatalf("返程标记被 decode4via6 解出非零 siteID=%d（可能误路由到站点）", sid)
	}
}

// ---- 池分配 ----

func TestVia4PoolAllocate(t *testing.T) {
	tbl := setVia4ForTest(t, "100.100.0.0/24")
	k1 := via4Key{siteID: 1, v4: netip.MustParseAddr("192.168.1.10")}
	k2 := via4Key{siteID: 2, v4: netip.MustParseAddr("192.168.1.10")} // 同 v4 不同站点 = 不同映射

	a1, ok := via4LookupOrAllocate(k1.siteID, k1.v4)
	if !ok || !tbl.pool.Contains(a1) {
		t.Fatalf("首次分配失败: %s ok=%v", a1, ok)
	}
	if a1 == tbl.pool.Addr() {
		t.Fatal("不应分配网络地址")
	}
	// 幂等：同 key 再查得同地址。
	if a1b, _ := via4LookupOrAllocate(k1.siteID, k1.v4); a1b != a1 {
		t.Fatalf("同 key 重复分配得到不同地址: %s vs %s", a1b, a1)
	}
	a2, _ := via4LookupOrAllocate(k2.siteID, k2.v4)
	if a2 == a1 {
		t.Fatal("不同 key 分到了同一池地址")
	}
	// 双向反查。
	if key, ok := tbl.via4PoolToKey(a1); !ok || key != k1 {
		t.Fatalf("via4PoolToKey(%s) = %+v ok=%v", a1, key, ok)
	}
	if p, ok := tbl.via4KeyToPool(k2); !ok || p != a2 {
		t.Fatalf("via4KeyToPool(%+v) = %s ok=%v", k2, p, ok)
	}
}

// 池满 → 驱逐 lastUsed 最旧的映射复用地址（/30 只有 .1 .2 两个可用地址）。
func TestVia4PoolExhaustionEvictsOldest(t *testing.T) {
	tbl := setVia4ForTest(t, "100.100.0.0/30")
	mk := func(sid uint16) netip.Addr {
		a, ok := via4LookupOrAllocate(sid, netip.MustParseAddr("192.168.1.10"))
		if !ok {
			t.Fatalf("site %d 分配失败", sid)
		}
		return a
	}
	a1 := mk(1)
	a2 := mk(2)
	if a1 == a2 {
		t.Fatal("两个 key 分到同一地址")
	}
	// 触发第二个映射 touch，让 site1 成为最旧。
	if _, ok := tbl.via4PoolToKey(a2); !ok {
		t.Fatal("touch site2 失败")
	}
	before := via4EvictCount.Load()
	a3 := mk(3) // 池满 → 驱逐 site1
	if via4EvictCount.Load() != before+1 {
		t.Fatal("池满应驱逐一条")
	}
	if a3 != a1 {
		t.Fatalf("应复用被驱逐的地址 %s，得到 %s", a1, a3)
	}
	if _, ok := tbl.via4KeyToPool(via4Key{siteID: 1, v4: netip.MustParseAddr("192.168.1.10")}); ok {
		t.Fatal("被驱逐的映射不应再可查")
	}
	if _, ok := tbl.via4KeyToPool(via4Key{siteID: 2, v4: netip.MustParseAddr("192.168.1.10")}); !ok {
		t.Fatal("较新的映射不应被驱逐")
	}
}

// ---- SIIT 翻译 ----

func TestTranslateVia4RoundTripUDP(t *testing.T) {
	client := netip.MustParseAddr("10.201.0.28")
	poolAddr := netip.MustParseAddr("100.100.0.7")
	target := netip.MustParseAddr("192.168.1.10")
	key := via4Key{siteID: 7, v4: target}

	v4pkt := mkV4UDP(client, poolAddr, 5555, 8080, []byte("hello via4"))
	v6pkt, ok := translateVia4ToV6(v4pkt, key, client)
	if !ok {
		t.Fatal("出向翻译失败")
	}
	if v6pkt[0]>>4 != 6 || v6pkt[6] != 17 {
		t.Fatalf("v6 头异常: ver=%d nextHdr=%d", v6pkt[0]>>4, v6pkt[6])
	}
	if v6pkt[7] != 63 {
		t.Fatalf("HopLimit 应为 TTL-1=63, got %d", v6pkt[7])
	}
	wantSrc, _ := encodeVia4Return(client)
	wantDst, _ := encode4via6(key.siteID, target)
	gotSrc, _ := netip.AddrFromSlice(v6pkt[8:24])
	gotDst, _ := netip.AddrFromSlice(v6pkt[24:40])
	if gotSrc != wantSrc || gotDst != wantDst {
		t.Fatalf("v6 地址错: src=%s dst=%s", gotSrc, gotDst)
	}
	if sp := binary.BigEndian.Uint16(v6pkt[40:42]); sp != 5555 {
		t.Fatalf("源端口未保留: %d", sp)
	}
	if string(v6pkt[48:]) != "hello via4" {
		t.Fatalf("payload 未保留: %q", v6pkt[48:])
	}
	verifyL4V6(t, v6pkt)

	// 返程：宣告方 netstack 惯例对调 src/dst（src=目标 4via6，dst=返程标记），端口对调。
	tbl := setVia4ForTest(t, "100.100.0.0/24")
	tbl.byKey[key] = &via4Mapping{key: key, pool: poolAddr}
	tbl.byPool[poolAddr] = tbl.byKey[key]

	reply := make([]byte, len(v6pkt))
	copy(reply, v6pkt)
	copy(reply[8:24], v6pkt[24:40]) // src = 4via6
	copy(reply[24:40], v6pkt[8:24]) // dst = 返程标记
	binary.BigEndian.PutUint16(reply[40:42], 8080)
	binary.BigEndian.PutUint16(reply[42:44], 5555)
	var rs, rd [16]byte
	copy(rs[:], reply[8:24])
	copy(rd[:], reply[24:40])
	l4 := reply[40:]
	writeL4ChecksumV6(l4, 17, rs, rd)

	back, ok := translateVia4ToV4(reply, tbl, client)
	if !ok {
		t.Fatal("返程翻译失败")
	}
	gotS := netip.AddrFrom4([4]byte(back[12:16]))
	gotD := netip.AddrFrom4([4]byte(back[16:20]))
	if gotS != poolAddr || gotD != client {
		t.Fatalf("返程 v4 地址错: src=%s dst=%s, want %s→%s", gotS, gotD, poolAddr, client)
	}
	if back[8] != 62 {
		t.Fatalf("返程 TTL 应为 63-1=62, got %d", back[8])
	}
	if string(back[28:]) != "hello via4" {
		t.Fatalf("返程 payload 未保留: %q", back[28:])
	}
	verifyL4V4(t, back)
}

func TestTranslateVia4TCPMSSClamp(t *testing.T) {
	client := netip.MustParseAddr("10.201.0.28")
	target := netip.MustParseAddr("192.168.1.10")
	key := via4Key{siteID: 7, v4: target}

	// SYN 段：20 字节 TCP 头 + 4 字节 MSS 选项（mss=1460）。
	l4 := make([]byte, 24)
	binary.BigEndian.PutUint16(l4[0:2], 5555)
	binary.BigEndian.PutUint16(l4[2:4], 80)
	l4[12] = 6 << 4 // data offset 24 字节
	l4[13] = 0x02   // SYN
	l4[20], l4[21] = 2, 4
	binary.BigEndian.PutUint16(l4[22:24], 1460)
	s4 := client.As4()
	d4 := netip.MustParseAddr("100.100.0.7").As4()
	writeL4ChecksumV4(l4, 6, s4, d4)

	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:20]))
	copy(pkt[20:], l4)

	v6pkt, ok := translateVia4ToV6(pkt, key, client)
	if !ok {
		t.Fatal("翻译失败")
	}
	if mss := binary.BigEndian.Uint16(v6pkt[40+22 : 40+24]); mss != via4MSSCeiling {
		t.Fatalf("MSS 应被钳到 %d, got %d", via4MSSCeiling, mss)
	}
	verifyL4V6(t, v6pkt)
}

func TestTranslateVia4ICMPEcho(t *testing.T) {
	client := netip.MustParseAddr("10.201.0.28")
	target := netip.MustParseAddr("192.168.1.10")
	key := via4Key{siteID: 7, v4: target}

	// ICMPv4 echo request。
	l4 := make([]byte, 12)
	l4[0] = 8 // echo request
	binary.BigEndian.PutUint16(l4[4:6], 0x1234)
	writeL4ChecksumV4(l4, 1, client.As4(), netip.MustParseAddr("100.100.0.7").As4())

	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 1
	s4 := client.As4()
	d4 := netip.MustParseAddr("100.100.0.7").As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:20]))
	copy(pkt[20:], l4)

	v6pkt, ok := translateVia4ToV6(pkt, key, client)
	if !ok {
		t.Fatal("ICMP echo 翻译失败")
	}
	if v6pkt[6] != 58 || v6pkt[40] != 128 {
		t.Fatalf("应翻成 ICMPv6 echo request(type 128), nextHdr=%d type=%d", v6pkt[6], v6pkt[40])
	}
	verifyL4V6(t, v6pkt)

	// 其它 ICMP 类型（如 dest unreachable type=3）不翻译。
	pkt[20] = 3
	if _, ok := translateVia4ToV6(pkt, key, client); ok {
		t.Fatal("非 echo 的 ICMP 不应翻译")
	}
}

func TestTranslateVia4RejectsFragmentsAndOversize(t *testing.T) {
	client := netip.MustParseAddr("10.201.0.28")
	key := via4Key{siteID: 7, v4: netip.MustParseAddr("192.168.1.10")}
	pkt := mkV4UDP(client, netip.MustParseAddr("100.100.0.7"), 1, 2, []byte("x"))

	// MF 分片。
	frag := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint16(frag[6:8], 0x2000)
	if _, ok := translateVia4ToV6(frag, key, client); ok {
		t.Fatal("分片包不应翻译")
	}
	// 超长（> via4MaxV4Len，翻成 v6 会超客户端 mesh MTU）。
	big := mkV4UDP(client, netip.MustParseAddr("100.100.0.7"), 1, 2, make([]byte, via4MaxV4Len))
	if _, ok := translateVia4ToV6(big, key, client); ok {
		t.Fatal("超长包不应翻译")
	}
	// TTL=1。
	ttl1 := append([]byte(nil), pkt...)
	ttl1[8] = 1
	if _, ok := translateVia4ToV6(ttl1, key, client); ok {
		t.Fatal("TTL≤1 不应翻译")
	}
}

// ---- 数据面端到端 ----

// 出向：发起方 v4 → 池地址 → via4DataPlane 翻译成 4via6 v6 → 投递宣告方 TunChan；
// 返程：宣告方 v6（src=4via6，dst=返程标记）→ 反译回 v4 → 进 tunWriteChan（TUN hairpin 投回发起方）。
func TestVia4DataPlaneEndToEnd(t *testing.T) {
	resetConnByDeviceForTest(t)
	tbl := setVia4ForTest(t, "100.100.0.0/24")
	target := netip.MustParseAddr("192.168.1.10")
	const sid = uint16(7)

	poolAddr, ok := via4LookupOrAllocate(sid, target)
	if !ok {
		t.Fatal("池分配失败")
	}
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)})
	setVia6SiteTableForTest(t, map[uint16]int64{sid: 77})
	advCh := addAdvertiserConnU(t, 77, "adv1", "10.201.0.9", "u2")

	// 换掉全局 tunWriteChan，捕获返程注入。
	prevWrite := tunWriteChan
	tunWriteChan = make(chan []byte, 8)
	t.Cleanup(func() { tunWriteChan = prevWrite })

	client := netip.MustParseAddr("10.201.0.28")
	a := &Connection{userID: "u1", connIDStr: "a", deviceID: 11}

	// 出向。
	out := mkV4UDP(client, poolAddr, 5555, 8080, []byte("ping"))
	if !via4DataPlane(a, 1, out) {
		t.Fatal("池地址流量应归 via4 处理")
	}
	var v6pkt []byte
	select {
	case got := <-advCh:
		v6pkt = append([]byte(nil), got.Buf[:got.N]...)
	default:
		t.Fatal("翻译后的 v6 包未投递到宣告方会话")
	}
	// 截断守卫:收到的必须是完整 v6 翻译(≥40B 头)。历史事故:别的用例把字面量短切片
	// 当 Buf 归还进 tunReadBufPool,毒化后 deliverIPPacketToConn 的 copy 把 52B 翻译截成
	// 池里旧 len —— 在这里表现为收到自己包的前 20 字节,直接 slice panic,毫无线索。
	if len(v6pkt) < 48 {
		t.Fatalf("收到截断包(len=%d hex=%x):怀疑 tunReadBufPool 被短 Buf 毒化,见 poolShapedTunPacket 注释", len(v6pkt), v6pkt)
	}
	wantDst, _ := encode4via6(sid, target)
	if gotDst, _ := netip.AddrFromSlice(v6pkt[24:40]); gotDst != wantDst {
		t.Fatalf("v6 dst = %s, want %s", gotDst, wantDst)
	}
	verifyL4V6(t, v6pkt)

	// 返程（对调地址与端口，重算校验和）。
	reply := make([]byte, len(v6pkt))
	copy(reply, v6pkt)
	copy(reply[8:24], v6pkt[24:40])
	copy(reply[24:40], v6pkt[8:24])
	binary.BigEndian.PutUint16(reply[40:42], 8080)
	binary.BigEndian.PutUint16(reply[42:44], 5555)
	var rs, rd [16]byte
	copy(rs[:], reply[8:24])
	copy(rd[:], reply[24:40])
	writeL4ChecksumV6(reply[40:], 17, rs, rd)

	adv := &Connection{userID: "u2", connIDStr: "adv1", deviceID: 77}
	if !via4DataPlane(adv, 2, reply) {
		t.Fatal("返程标记流量应归 via4 处理")
	}
	select {
	case v4back := <-tunWriteChan:
		gotS := netip.AddrFrom4([4]byte(v4back[12:16]))
		gotD := netip.AddrFrom4([4]byte(v4back[16:20]))
		if gotS != poolAddr || gotD != client {
			t.Fatalf("返程 v4 = %s→%s, want %s→%s", gotS, gotD, poolAddr, client)
		}
		verifyL4V4(t, v4back)
	default:
		t.Fatal("返程 v4 包未进 tunWriteChan")
	}
	_ = tbl
}

// 池段 dst 但映射不存在（被驱逐 / 陈旧 DNS）→ 归 via4 处理但丢弃，绝不漏到出口路径。
func TestVia4DataPlaneNoMappingDrops(t *testing.T) {
	setVia4ForTest(t, "100.100.0.0/24")
	client := netip.MustParseAddr("10.201.0.28")
	a := &Connection{userID: "u1", connIDStr: "a"}
	before := via4DropNoMapping.Load()
	pkt := mkV4UDP(client, netip.MustParseAddr("100.100.0.99"), 1, 2, []byte("x"))
	if !via4DataPlane(a, 1, pkt) {
		t.Fatal("池段 dst 即使无映射也必须归 via4 处理（丢弃），不能漏到出口路径")
	}
	if via4DropNoMapping.Load() != before+1 {
		t.Fatal("应计 via4DropNoMapping")
	}
}

// via4 关闭（state=nil）→ 完全旁路。
func TestVia4DataPlaneDisabledPassthrough(t *testing.T) {
	prev := via4State.Load()
	via4State.Store(nil)
	t.Cleanup(func() { via4State.Store(prev) })
	a := &Connection{userID: "u1"}
	pkt := mkV4UDP(netip.MustParseAddr("10.201.0.28"), netip.MustParseAddr("100.100.0.7"), 1, 2, []byte("x"))
	if via4DataPlane(a, 1, pkt) {
		t.Fatal("via4 关闭时不应拦截任何流量")
	}
}

// ---- DNS A 合成 ----

// via4 启用时，via 名的 A 查询应合成池 v4；AAAA 行为不变（仍返回 4via6 v6）。
func TestMagicDNS_Via4SynthesizesA(t *testing.T) {
	tbl := setVia4ForTest(t, "100.100.0.0/24")
	gw := newMagicDNSGateway(t)
	ctx := t.Context()
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
	r := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	r.suffix = "lan"

	// A 查询 → 恰好 1 条 A，地址在池内，且映射已登记。
	qA := buildDNSQuery(t, fmt.Sprintf("192-168-1-10via%d.lan", sid), dnsmessage.TypeA)
	respA := runOneMagicDNSQuery(t, gw, r, qA)
	hdrA, answersA := parseDNSResponse(t, respA)
	if hdrA.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("A rcode = %v", hdrA.RCode)
	}
	if len(answersA) != 1 {
		t.Fatalf("A 应答应恰 1 条, got %d", len(answersA))
	}
	ar, ok := answersA[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("应答不是 AResource: %T", answersA[0].Body)
	}
	poolAddr := netip.AddrFrom4(ar.A)
	if !tbl.pool.Contains(poolAddr) {
		t.Fatalf("合成 A %s 不在池内 %s", poolAddr, tbl.pool)
	}
	if key, ok := tbl.via4PoolToKey(poolAddr); !ok || key.siteID != sid || key.v4 != netip.MustParseAddr("192.168.1.10") {
		t.Fatalf("映射未登记或不符: %+v ok=%v", key, ok)
	}
	// 幂等：再查一次 A 得同一池地址。
	respA2 := runOneMagicDNSQuery(t, gw, r, qA)
	_, answersA2 := parseDNSResponse(t, respA2)
	if ar2 := answersA2[0].Body.(*dnsmessage.AResource); netip.AddrFrom4(ar2.A) != poolAddr {
		t.Fatalf("同名重复 A 查询应得同一池地址: %s vs %s", netip.AddrFrom4(ar2.A), poolAddr)
	}

	// AAAA 不受影响。
	qAAAA := buildDNSQuery(t, fmt.Sprintf("192-168-1-10via%d.lan", sid), dnsmessage.TypeAAAA)
	respAAAA := runOneMagicDNSQuery(t, gw, r, qAAAA)
	_, answersAAAA := parseDNSResponse(t, respAAAA)
	if len(answersAAAA) != 1 {
		t.Fatalf("AAAA 应答应恰 1 条, got %d", len(answersAAAA))
	}
	if _, ok := answersAAAA[0].Body.(*dnsmessage.AAAAResource); !ok {
		t.Fatalf("AAAA 应答类型错: %T", answersAAAA[0].Body)
	}
}

// via4 关闭时 A 查询维持老行为：NOERROR / 0 answer。
func TestMagicDNS_Via4DisabledEmptyA(t *testing.T) {
	prev := via4State.Load()
	via4State.Store(nil)
	t.Cleanup(func() { via4State.Store(prev) })

	gw := newMagicDNSGateway(t)
	ctx := t.Context()
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
	r := resolveMagicDNSConfig(gw.cfg.Server.MagicDNS)
	r.suffix = "lan"

	q := buildDNSQuery(t, fmt.Sprintf("192-168-1-10via%d.lan", sid), dnsmessage.TypeA)
	resp := runOneMagicDNSQuery(t, gw, r, q)
	hdr, answers := parseDNSResponse(t, resp)
	if hdr.RCode != dnsmessage.RCodeSuccess || len(answers) != 0 {
		t.Fatalf("via4 关闭时 A 查询应 NOERROR/0 answer, got rcode=%v answers=%d", hdr.RCode, len(answers))
	}
}

// ---- routes-list 池条目 ----

// via4 启用且有子网路由 → buildRoutesList 追加池网段合成条目（无 UUID、Online=true、SiteID=0）。
func TestBuildRoutesListAppendsVia4Pool(t *testing.T) {
	resetConnByDeviceForTest(t)
	setVia4ForTest(t, "100.100.0.0/16")
	setSubnetRouteTableForTest(t, []subnetRouteEntry{mkEntry("192.168.1.0/24", 77)})

	routes := buildRoutesList(t.Context())
	var poolEntry *util.SubnetRouteInfo
	for i := range routes {
		if routes[i].CIDR == "100.100.0.0/16" {
			poolEntry = &routes[i]
		}
	}
	if poolEntry == nil {
		t.Fatalf("routes-list 应含池条目, got %+v", routes)
	}
	if poolEntry.DeviceUUID != "" || !poolEntry.Online || poolEntry.SiteID != 0 {
		t.Fatalf("池条目形态错: %+v", poolEntry)
	}

	// via4 关闭 → 不追加。
	via4State.Store(nil)
	for _, r := range buildRoutesList(t.Context()) {
		if r.CIDR == "100.100.0.0/16" {
			t.Fatal("via4 关闭时不应下发池条目")
		}
	}
}
