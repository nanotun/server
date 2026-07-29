package main

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/util"
)

// 选了出口的会话查公网域名,一律不许回落到 server 本地上游。
//
// 这是 2026-07-17 起改成 fail-closed 的那条规矩,原因在 magic_dns_exit.go 文件头:server 与出口通常
// 隔着半个地球,CDN 按「谁来问」就近调度 —— 用 server 的地理答案填客户端 OS 缓存,拿到的边缘节点
// 对出口是烂路由甚至不可达(实测经重庆出口约 27% 连接失败),而缓存要等 TTL 到期才自己好。
// 更糟的是此刻数据面本就在丢这些包,「解析得出、连不上」纯属把故障拖长。
//
// 出口侧的判定(tryResolvePublicViaExit)自己有一组用例,但**调用点有没有真的到此为止**没人验过 ——
// 少一个 return,判定再对也白搭:SERVFAIL 照发,紧接着又向本地上游发一份查询,客户端(先到先用)
// 很可能采信后到的那份 server 地理答案,于是 fail-closed 形同虚设。所以这条测在 handleMagicDNSPacket
// 这一层验,观测量是「本地上游一次都没被问过」。

// TestMagicDNS_AnExitBoundSessionNeverFallsBackToTheLocalUpstream 出口不可兑现时回 SERVFAIL,且绝不问本地上游。
func TestMagicDNS_AnExitBoundSessionNeverFallsBackToTheLocalUpstream(t *testing.T) {
	gw := newMagicDNSGateway(t)
	withACLSnapshotForTest(t, meshOnAllowAll())

	// 本地上游:一问就答一个 server 地理的地址。这条测的核心就是它**不该**被问到。
	up, hits := startFakeUpstream(t, func(query []byte) [][]byte {
		return [][]byte{mustReply(t, query, "93.184.216.34", 3600)}
	})

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
	peer := cli.LocalAddr().(*net.UDPAddr)

	// 使用方会话:vIP == peer.IP(让 exitDeviceForClientVIP 命中),出口已 fail-closed
	// (被撤销 / 未批准 / isolate 拒绝都会落到这个哨兵)。
	client := &Connection{connIDStr: "client-failclosed"}
	client.egressDeviceID.Store(egressFailClosed)
	cips := []util.VirtualIPAssignment{{VirtualIP: peer.IP.String()}}
	client.clientIPs.Store(&cips)
	connIDMapMu.Lock()
	connIDMap[client.connIDStr] = client
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, client.connIDStr)
		connIDMapMu.Unlock()
	})

	query := buildDNSQuery(t, "example.com", dnsmessage.TypeA)
	handleMagicDNSPacket(t.Context(), gw, srv, peer, query,
		magicDNSResolved{suffix: "lan", port: 53, upstream: []string{up}})

	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("客户端没收到任何响应: %v", err)
	}
	h, ans := parseDNSResponse(t, buf[:n])
	if h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("出口兑现不了时应回 SERVFAIL(让客户端 stub 自己重试),got rcode=%v answers=%v", h.RCode, ans)
	}
	// 关键断言:哪怕已经回过 SERVFAIL,也不许再向本地上游补一份查询。
	if got := hits.Load(); got != 0 {
		t.Fatalf("本地上游被问了 %d 次 —— 绑定出口的会话拿到 server 地理的答案后会把它缓存住,"+
			"经出口访问那些边缘节点是烂路由甚至不通,而故障要等 TTL 到期才自己好", got)
	}
}
