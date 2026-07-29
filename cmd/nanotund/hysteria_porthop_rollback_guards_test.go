package main

// hy2 启动的后半段失败时,**端口跳跃的 iptables 规则必须撤掉**。
//
// 已有用例钉住了「失败时把 UDP 端口还回去」,但端口跳跃比端口更麻醿:那是一组 PREROUTING REDIRECT
// 规则,把一整段 dport 打到主端口上。启动失败时若只关 socket 不撤规则,进程退出后机器上留着一段
// 「REDIRECT 到没人监听的端口」——那段端口的入包被内核吞掉,而 nanotun 根本没起来。
// 下次启动的幂等 sweep 会清掉它,但那可能是几小时之后的事,期间只表现为「换端口就连不上」。
//
// 真安装要写 iptables(非 Linux 是 no-op 桩、Linux 要 root),所以这里从 setupHy2PortHopFn 那个
// 接缝注入,只观察「装了几次 / 撤了几次」。

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// hopSpy 替换端口跳跃的安装步骤,记账安装与撤销次数。
type hopSpy struct {
	installs atomic.Int32
	undos    atomic.Int32
	failWith error
}

func (h *hopSpy) install(t *testing.T) {
	t.Helper()
	prev := setupHy2PortHopFn
	setupHy2PortHopFn = func(uint16, string, string) (func(), error) {
		h.installs.Add(1)
		if h.failWith != nil {
			return nil, h.failWith
		}
		return func() { h.undos.Add(1) }, nil
	}
	t.Cleanup(func() { setupHy2PortHopFn = prev })
}

// hopUnionAddr 给一个「需要端口跳跃」的 listen_addr:主端口 + 一段并集。
func hopUnionAddr(primary int) string {
	return fmt.Sprintf("127.0.0.1:%d,%d-%d", primary, primary+1, primary+3)
}

// TestStartEmbeddedHysteria_RollsBackThePortHopRulesWhenStartupFailsLater
// 装了跳跃规则之后 hy2 才启动失败 → 规则必须原路撤掉,端口也要还回去。
func TestStartEmbeddedHysteria_RollsBackThePortHopRulesWhenStartupFailsLater(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	spy := &hopSpy{}
	spy.install(t)

	port := pickFreeUDPPort(t)
	cfg := testHysteriaConfig(t, hopUnionAddr(port), "0123456789abcdef", certFile, keyFile)
	// 让**装完跳跃规则之后**的那一步失败(CA 文件存在但不是 PEM)。
	badCA := dir + "/not-a-pem.crt"
	if err := os.WriteFile(badCA, []byte("这不是 PEM"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Hysteria.TLSClientCAFile = badCA

	srv, gotPort, cleanup, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
	if err == nil {
		if srv != nil {
			_ = srv.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("CA 不是 PEM 却启动成功了")
	}
	if srv != nil || gotPort != 0 || cleanup != nil {
		t.Errorf("失败时不能返回半成品(srv=%v port=%d cleanup==nil:%v)", srv, gotPort, cleanup == nil)
	}
	if spy.installs.Load() != 1 {
		t.Fatalf("端口并集配了却没装跳跃规则(装了 %d 次)—— 那这条用例什么都没验到", spy.installs.Load())
	}
	if n := spy.undos.Load(); n != 1 {
		t.Errorf("启动失败后撤销了 %d 次跳跃规则,应为 1 —— 残留规则会把那段端口 REDIRECT 到没人监听的端口,"+
			"表现成「换端口就连不上」,而 nanotun 根本没起来", n)
	}
	probe, perr := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if perr != nil {
		t.Fatalf("失败路径没关掉已绑的 UDP 端口 %d: %v", port, perr)
	}
	_ = probe.Close()
}

// TestStartEmbeddedHysteria_PortHopFailureReleasesThePortAndSaysSo
// 跳跃规则本身装不上(典型:没有 CAP_NET_ADMIN)→ 先绑上的 UDP 端口必须还回去,错误里要点出是端口跳跃。
//
// 不还端口的后果:main 在这里 Fatal,socket 还攥在退出中的进程里;systemd 立刻拉起的新实例撞上
// 「address already in use」,于是排查方向被带到「端口被谁占了」,而真正的原因是缺权限。
func TestStartEmbeddedHysteria_PortHopFailureReleasesThePortAndSaysSo(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	spy := &hopSpy{failWith: fmt.Errorf("iptables: 权限不足")}
	spy.install(t)

	port := pickFreeUDPPort(t)
	cfg := testHysteriaConfig(t, hopUnionAddr(port), "0123456789abcdef", certFile, keyFile)

	srv, gotPort, cleanup, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
	if err == nil {
		if srv != nil {
			_ = srv.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("装不上跳跃规则却启动成功了 —— 客户端会按并集里的端口发包,那些包没人接")
	}
	if !containsAll(err.Error(), "端口跳跃", "权限") {
		t.Errorf("错误没点出是端口跳跃装不上: %v", err)
	}
	if srv != nil || gotPort != 0 || cleanup != nil {
		t.Errorf("失败时不能返回半成品(srv=%v port=%d cleanup==nil:%v)", srv, gotPort, cleanup == nil)
	}
	if spy.undos.Load() != 0 {
		t.Errorf("安装自己失败了,不该再调撤销(它返回的 cleanup 是 nil)")
	}
	probe, perr := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if perr != nil {
		t.Fatalf("跳跃规则装不上时没关掉已绑的 UDP 端口 %d: %v —— "+
			"systemd 拉起的新实例会撞上「端口已被占用」,把排查带偏", port, perr)
	}
	_ = probe.Close()
}

// TestStartEmbeddedHysteria_ObfsInitFailureUnwindsThePortAndTheRules
// 混淆器初始化失败也要把端口和跳跃规则原路还回去。
//
// 上面两条钉的是「配置构造失败」和「装规则本身失败」,这里补混淆器这一处。触发条件(obfs 密码
// 短于库下限)在配置校验里**已经拦过一遍**,所以正常部署走不到;它是两套限值分头写死之后的兜底
// —— 库升级把下限改了而我们的校验没跟着改时,这条路就是现场唯一会走的路。
//
// 资源回收这件事跟触发原因无关:漏一处,机器上就留下一段「REDIRECT 到没人监听的端口」加一个攥在
// 退出中进程里的 UDP socket,下一个实例撞上「端口已被占用」。
//
// (再往后那处 —— hy2 建服务失败 —— 进程内构造不出来:库会拒的每个维度 ValidateTuning 都在函数
// 开头先拒了一遍,连一个能穿过前者、被后者拒掉的取值都不存在。)
func TestStartEmbeddedHysteria_ObfsInitFailureUnwindsThePortAndTheRules(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	spy := &hopSpy{}
	spy.install(t)

	port := pickFreeUDPPort(t)
	cfg := testHysteriaConfig(t, hopUnionAddr(port), "0123456789abcdef", certFile, keyFile)
	cfg.Hysteria.ObfsSalamanderPassword = "ab" // 短于库下限

	srv, gotPort, cleanup, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
	if err == nil {
		if srv != nil {
			_ = srv.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("混淆器初始化不了却启动成功了 —— 客户端会带混淆发包,服务端按明文收,谁都连不上")
	}
	if srv != nil || gotPort != 0 || cleanup != nil {
		t.Errorf("失败时不能返回半成品(srv=%v port=%d cleanup==nil:%v)", srv, gotPort, cleanup == nil)
	}
	if spy.installs.Load() != 1 {
		t.Fatalf("跳跃规则装了 %d 次,应为 1 —— 失败点排在装规则之前,这条用例什么都没验到", spy.installs.Load())
	}
	if n := spy.undos.Load(); n != 1 {
		t.Errorf("启动失败后撤销了 %d 次跳跃规则,应为 1 —— 残留规则把那段端口 REDIRECT 到没人监听的端口", n)
	}
	probe, perr := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if perr != nil {
		t.Fatalf("失败路径没关掉已绑的 UDP 端口 %d: %v", port, perr)
	}
	_ = probe.Close()
}

// TestStartEmbeddedHysteria_RefusesAListenAddrWhosePortsCannotBeParsed 端口写错必须拒启,不能悄悄换个端口听。
//
// listen_addr 的端口位允许写并集("443"、"8443,443"、"5000-5100,443"),所以它不是简单的整数解析 ——
// 拆 host:port 那一步对 "443x" 之类是**放过**的,只有并集解析才认得出来。这道闸没拦住的话主端口会落成 0,
// 而 0 交给内核就是「随便给个临时端口」:hy2 于是在一个谁都不知道的高位端口上监听,node_login 上报的
// 也是那个号,而客户端配的是 443 —— 服务端日志一片正常,所有 hy2 客户端连不上,现场看起来像被墙。
func TestStartEmbeddedHysteria_RefusesAListenAddrWhosePortsCannotBeParsed(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestHy2ServerTLS(t, dir)
	spy := &hopSpy{}
	spy.install(t)

	// ":0" 不在此列 —— 它是**刻意**支持的(让内核挑口,实际端口由第二个返回值上报给 node_login)。
	for _, addr := range []string{"127.0.0.1:44e3", "127.0.0.1:,", "127.0.0.1:-"} {
		t.Run(addr, func(t *testing.T) {
			cfg := testHysteriaConfig(t, addr, "0123456789abcdef", certFile, keyFile)
			srv, gotPort, cleanup, err := startEmbeddedHysteria(&cfg, "", "ws://127.0.0.1:8080/vpn", nil, nil)
			if err == nil {
				if srv != nil {
					_ = srv.Close()
				}
				if cleanup != nil {
					cleanup()
				}
				t.Fatalf("listen_addr=%q 的端口位解析不出来,却启动成功了(端口 %d)—— 客户端按配置里的端口发包,"+
					"那些包没人接,而服务端日志一切正常", addr, gotPort)
			}
			if srv != nil || gotPort != 0 || cleanup != nil {
				t.Errorf("失败时不能返回半成品(srv=%v port=%d cleanup==nil:%v)", srv, gotPort, cleanup == nil)
			}
			if spy.installs.Load() != 0 {
				t.Errorf("端口都还没定下来就装了跳跃规则(%d 次)", spy.installs.Load())
			}
		})
	}
}

// TestVPNHybridOutbound_UDPHandsOutARealSocket 开了 udp_relay 时 UDP 出口要真给一个可用 socket。
//
// 这条 outbound 只在 config.udp_relay_enabled=true 时装上(nanotun 默认关,开了等于把 hy2 当通用
// UDP 代理)。它必须真的绑一个本地 UDP socket:返回 nil 而不报错的话,hy2 会拿着 nil 往下走 ——
// 表现是客户端的 UDP 会话建起来就静默黑洞,而服务端日志上什么都没有。
func TestVPNHybridOutbound_UDPHandsOutARealSocket(t *testing.T) {
	ob := &vpnHybridOutbound{}
	conn, err := ob.UDP("8.8.8.8:53")
	if err != nil {
		t.Fatalf("开了 udp_relay 却给不出 UDP socket: %v", err)
	}
	if conn == nil {
		t.Fatal("返回了 nil socket 且不报错 —— hy2 会拿着它往下走,客户端 UDP 静默黑洞")
	}
	defer func() { _ = conn.Close() }()

	// 真发一包给自己起的监听,证明这不是个空壳。
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := conn.WriteTo([]byte("ping"), peer.LocalAddr().String()); err != nil {
		t.Fatalf("拿到的 socket 发不出包: %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	n, _, err := peer.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("对端没收到包(n=%d err=%v)", n, err)
	}
}
