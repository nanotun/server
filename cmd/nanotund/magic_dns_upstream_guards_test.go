package main

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/nanotun/server/util"
)

// 上游转发这一段有两件事必须成立,而两件都只在特定时机才可观测。
//
// 一是**会话早期的 TTL 钳制**。客户端刚连上来的一两秒里,mesh 路由 / iptables 规则可能还没就位,
// 此时它发出的公网查询由 server 本地上游解析,拿到的答案反映的是「还没配好」那一刻的可达性。
// CDN 的 A 记录 TTL 常是几百到几千秒 —— 客户端 OS 会把这个答案连同它的 TTL 一起缓存下来,
// 于是「刚连上时打不开某站」这件事会持续到 TTL 过期,而那时链路早就正常了。钳短 TTL 让它几秒后
// 自动重查。漏掉这一步的现象正是最难查的那种:只在刚连上的窗口里出问题,复现时又已经好了。
//
// 二是**上游应答的反投毒校验**。UDP 上任何能伪造 upstream 源地址的人(on-path、或同网段)都能在
// 真应答之前抢注一包。只按 5-tuple 收包挡不住这个,所以还要看 DNS 层:Response 位、TXID、question
// 三样都得对。收了一包错答,污染的是 server 给所有客户端的答案。

// buildDNSResponseATTL 造一份 question 与给定名字相符、带指定 TTL 的 A 应答。
func buildDNSResponseATTL(t *testing.T, fqdn string, ttl uint32, ip string) []byte {
	t.Helper()
	n, err := dnsmessage.NewName(fqdn)
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, Response: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	var a4 [4]byte
	copy(a4[:], net.ParseIP(ip).To4())
	if err := b.AResource(
		dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
		dnsmessage.AResource{A: a4},
	); err != nil {
		t.Fatal(err)
	}
	raw, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// registerFreshClientConn 挂一条「刚注册」的会话,让 peer 的 vIP 能反查到它。
func registerFreshClientConn(t *testing.T, vip string, age time.Duration) {
	t.Helper()
	c := &Connection{connIDStr: "fresh-" + vip, userID: "1", createdAt: time.Now().Add(-age)}
	ips := []util.VirtualIPAssignment{{VirtualIP: vip}}
	c.clientIPs.Store(&ips)
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connIDMapMu.Unlock()
	t.Cleanup(func() {
		connIDMapMu.Lock()
		delete(connIDMap, c.connIDStr)
		connIDMapMu.Unlock()
	})
}

// TestForwardMagicDNSToUpstream_ClampsTTLOnlyInTheEarlyWindow 早期窗口内钳短 TTL,之后原样透传。
func TestForwardMagicDNSToUpstream_ClampsTTLOnlyInTheEarlyWindow(t *testing.T) {
	const upstreamTTL = 3600

	cases := []struct {
		name     string
		age      time.Duration
		wantMax  uint32
		clampCnt bool
	}{
		{
			name:     "刚连上:必须钳短",
			age:      0,
			wantMax:  magicDNSEarlyClampTTL,
			clampCnt: true,
		},
		{
			name:    "早期窗口已过:原样透传",
			age:     magicDNSEarlyClampWindow + time.Second,
			wantMax: upstreamTTL,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetConnByDeviceForTest(t)
			// 两个子测试用同一个 (cdn.example.com, A)：不清上游应答缓存，第二个子测试会命中第一个留下的条目
			// → 不再回源、且 TTL 被钳到「缓存剩余寿命」，本测想验的「新鲜应答是否原样透传」就测不到了。
			resetUpstreamDNSCacheForTest(t)
			up, _ := startFakeUpstream(t, func(query []byte) [][]byte {
				return [][]byte{buildDNSResponseATTL(t, dnsQueryName(t, query), upstreamTTL, "93.184.216.34")}
			})

			srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			peer := cli.LocalAddr().(*net.UDPAddr)
			registerFreshClientConn(t, peer.IP.String(), tc.age)

			before := magicDNSEarlyClampCount.Load()
			query := buildDNSQuery(t, "cdn.example.com", dnsmessage.TypeA)
			forwardMagicDNSToUpstream(t.Context(), srv, peer, query, magicDNSResolved{upstream: []string{up}})

			ttl := readbackFirstAnswerTTL(t, cli)
			if ttl > tc.wantMax {
				t.Fatalf("回给客户端的 TTL = %d,上限应是 %d —— 客户端会把这个答案缓存到那么久", ttl, tc.wantMax)
			}
			if tc.clampCnt && magicDNSEarlyClampCount.Load() == before {
				t.Error("钳了却没记 magicDNSEarlyClampCount")
			}
			if !tc.clampCnt && ttl != upstreamTTL {
				t.Errorf("窗口外不该动 TTL,got %d want %d", ttl, upstreamTTL)
			}
		})
	}
}

// TestForwardMagicDNSToUpstream_RefusesAPoisonedFirstReply 抢注的错答必须被丢掉。
func TestForwardMagicDNSToUpstream_RefusesAPoisonedFirstReply(t *testing.T) {
	resetConnByDeviceForTest(t)
	// 假上游先回一包「TXID 相符但 question 是另一个域名」的应答,再回正确的那份。
	up, _ := startFakeUpstream(t, func(query []byte) [][]byte {
		return [][]byte{
			buildDNSResponseATTL(t, "evil.example.com.", 300, "6.6.6.6"),
			buildDNSResponseATTL(t, dnsQueryName(t, query), 300, "93.184.216.34"),
		}
	})

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	peer := cli.LocalAddr().(*net.UDPAddr)

	query := buildDNSQuery(t, "cdn.example.com", dnsmessage.TypeA)
	forwardMagicDNSToUpstream(t.Context(), srv, peer, query, magicDNSResolved{upstream: []string{up}})

	_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatal("客户端什么都没收到")
	}
	var p dnsmessage.Parser
	if _, err := p.Start(buf[:n]); err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}
	if got := q.Name.String(); got != "cdn.example.com." {
		t.Fatalf("回给客户端的应答 question 是 %q —— 抢注的错答被当成了正主,server 给所有客户端的答案都被污染", got)
	}
}

// TestDialAndQueryUDP_StillWorksForAnUnparsableQuery 查询本身解析不出 key 时不能因此变成不可用。
//
// 这道校验的前提是「能从查询里取出 TXID + question」。取不出(客户端发了畸形/非标准报文)时若直接
// 判失败,这类查询就永远拿不到答案 —— 而它们此前是能工作的(收第一包即返回)。安全加固不该顺手
// 砍掉一条既有的可用路径。
func TestDialAndQueryUDP_StillWorksForAnUnparsableQuery(t *testing.T) {
	up, _ := startFakeUpstream(t, func([]byte) [][]byte {
		return [][]byte{[]byte("whatever-bytes")}
	})

	// 连 12 字节 header 都不完整:parseDNSQueryKey 取不出 key(有 header 无 question 的仍会按 TXID 校验)。
	resp, err := dialAndQueryUDP(t.Context(), up, []byte{0x12, 0x34, 0x01}, time.Second)
	if err != nil {
		t.Fatalf("解析不出 key 的查询应退回旧行为(收第一包即返回),got err=%v", err)
	}
	if len(resp) == 0 {
		t.Fatal("返回了空应答")
	}
}

// TestRunMagicDNSLoop_SurvivesReadErrorsAndStopsOnClose 读循环的三种退出/继续条件。
//
// 这条循环是 MagicDNS 的唯一入口:它退早了,整台 server 的 mesh 名字解析就停了(而进程还活着,
// 监控上一切正常);它退不掉,shutdown 会被一个 2 秒的读超时反复拖住。
func TestRunMagicDNSLoop_SurvivesReadErrorsAndStopsOnClose(t *testing.T) {
	t.Run("空转一个读超时之后仍照常服务", func(t *testing.T) {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		go func() {
			defer close(done)
			runMagicDNSLoop(ctx, newMagicDNSGateway(t), conn, magicDNSResolved{suffix: "lan", port: 53})
		}()

		// 读 deadline 是 2s,它每 2s 触发一次、只用来回头看一眼 ctx。把这一拍当成致命错误退出的话,
		// 整台 server 的 mesh 名字解析在空闲两秒后就停了 —— 而进程还活着,监控上一切正常。
		time.Sleep(2300 * time.Millisecond)

		client, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if _, err := client.Write(buildDNSQuery(t, "nobody.lan", dnsmessage.TypeA)); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := client.Read(make([]byte, 512)); err != nil {
			t.Fatalf("空闲两秒(一次读超时)之后就不再作答: %v —— MagicDNS 停摆而进程仍在跑", err)
		}

		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("ctx 取消后没退出 —— shutdown 会被读超时反复拖住")
		}
	})

	t.Run("连接关闭即退出", func(t *testing.T) {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			runMagicDNSLoop(context.Background(), newMagicDNSGateway(t), conn, magicDNSResolved{suffix: "nanotun.net", port: 53})
		}()
		time.Sleep(30 * time.Millisecond)
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("socket 已关却还在循环 —— 它会一直空转")
		}
	})
}

// readbackFirstAnswerTTL 读一帧应答并返回第一条 answer 的 TTL。
func readbackFirstAnswerTTL(t *testing.T, c *net.UDPConn) uint32 {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("没收到上游转发回来的应答: %v", err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		t.Fatalf("应答解不开: %v", err)
	}
	if len(m.Answers) == 0 {
		t.Fatal("应答里没有 answer")
	}
	return m.Answers[0].Header.TTL
}

// dnsQueryName 取查询里第一个 question 的 FQDN。
func dnsQueryName(t *testing.T, query []byte) string {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}
	return q.Name.String()
}
