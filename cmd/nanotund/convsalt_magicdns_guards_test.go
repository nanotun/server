package main

import (
	"testing"

	"github.com/nanotun/server/config"
)

// 开了 Magic DNS 之后,ConvSalt 里必须把网关 IP **顶到** DNS 列表最前面。
//
// 客户端拿到的是一串裸 IP,按顺序配进 TUN 的 resolver。网关不在第一位(或压根没下发)时,
// `*.lan` 这类只有 server 认得的名字会先被公共 DNS 答成 NXDOMAIN —— 客户端拿到否定答案就
// 不再往后问了。表现是「magic_dns = true、服务端 53 上确实在听、日志一切正常,客户端就是解析不了
// 内网名字」,而运维从两侧任何一处都看不出问题在哪。
//
// 登录和接管两条路径各自拼一次这份列表,所以两侧都要钉住:漏了接管那侧的话,平时能用,
// 客户端一断线重连(弱网下家常便饭)内网名字就集体失效。

// enableMagicDNSOnPort53 打开 Magic DNS(默认端口 = 53),收尾还原。
func enableMagicDNSOnPort53(t *testing.T, gw *gatewayState, suffix string) {
	t.Helper()
	prev := gw.cfg.Server.MagicDNS
	gw.cfg.Server.MagicDNS = config.MagicDNSConfig{Enabled: true, DomainSuffix: suffix}
	t.Cleanup(func() { gw.cfg.Server.MagicDNS = prev })
}

// TestLogin_PutsTheMagicDNSGatewayFirstInTheDNSList 登录路径:网关 IP 必须是头号解析器。
func TestLogin_PutsTheMagicDNSGatewayFirstInTheDNSList(t *testing.T) {
	env := newLoginGateEnv(t)
	withDualStackTUN(t, "10.108.0.1/24", "")
	env.gw.cfg.TUN.DNSServersV4 = []string{"1.1.1.1", "8.8.8.8"}
	enableMagicDNSOnPort53(t, env.gw, "lan")

	got := dualStackLogin(t, env, stormAddr(52), "known", "right-psk",
		"55555555-6666-4777-8888-000000000108")
	if got.resp.Code != 0 {
		t.Fatalf("登录应成功: %+v", got.resp)
	}
	assertMagicDNSFirst(t, got.salt.DNSServersV4, "10.108.0.1", []string{"1.1.1.1", "8.8.8.8"})
	if got.salt.MagicDNSSuffix != "lan" {
		t.Errorf("下发的 domain_suffix = %q,期望 lan —— 客户端不知道哪些名字该走隧道", got.salt.MagicDNSSuffix)
	}
}

// TestTakeover_PutsTheMagicDNSGatewayFirstInTheDNSList 接管路径同样要给,否则重连一次内网名字就失效。
//
// 顺带钉住 v6 解析器:接管是**重新拼**一份 DNS 列表(不是把老会话那份抄过来),漏掉哪一族,
// 客户端热切换之后那一族的解析就整体不见了。
func TestTakeover_PutsTheMagicDNSGatewayFirstInTheDNSList(t *testing.T) {
	fx := newTakeoverFixture(t)
	prevGW, prevGW6 := sharedTUNGateway, sharedTUNGatewayV6
	sharedTUNGateway = "10.109.0.1/24"
	sharedTUNGatewayV6 = "fd00:109::1/64"
	t.Cleanup(func() { sharedTUNGateway, sharedTUNGatewayV6 = prevGW, prevGW6 })
	fx.gw.cfg.TUN.DNSServersV4 = []string{"1.1.1.1"}
	fx.gw.cfg.TUN.DNSServersV6 = []string{"fd00:109::53"}
	enableMagicDNSOnPort53(t, fx.gw, "lan")

	resp, salt := runTakeoverOKWithSalt(t, fx, takeoverReq(fx, "victim", victimPSK))
	if resp.Code != 0 {
		t.Fatalf("合法接管应成功: %+v", resp)
	}
	assertMagicDNSFirst(t, salt.DNSServersV4, "10.109.0.1", []string{"1.1.1.1"})
	if salt.MagicDNSSuffix != "lan" {
		t.Errorf("接管下发的 domain_suffix = %q,期望 lan", salt.MagicDNSSuffix)
	}
	// 配了 v6 网关就必须一起下发 v6 解析器:漏了的话客户端热切换之后 v6 侧的解析全黑,
	// 而它自己看不出跟这次重连有关。
	if len(salt.DNSServersV6) == 0 {
		t.Error("配了 v6 网关,接管却没下发 v6 解析器 —— 热切换之后客户端 v6 解析整体失效")
	}
}

// TestLogin_LeavesTheDNSListAloneWhenMagicDNSListensOffPort53 非 53 端口时**不能** prepend。
//
// 客户端 OS stub resolver 只会打 :53。把网关顶到第一位却没人在 :53 上答,客户端每次解析都要
// 先白等一轮超时才回落到真正能用的上游 —— 全网 DNS 慢一大截,而 magic 名字照样解析不了。
// 这条路径的正确行为是干脆不给,由运维自己接转发器。
func TestLogin_LeavesTheDNSListAloneWhenMagicDNSListensOffPort53(t *testing.T) {
	env := newLoginGateEnv(t)
	withDualStackTUN(t, "10.110.0.1/24", "")
	env.gw.cfg.TUN.DNSServersV4 = []string{"1.1.1.1"}
	enableMagicDNSOnPort53(t, env.gw, "lan")
	env.gw.cfg.Server.MagicDNS.ListenPort = 5353

	got := dualStackLogin(t, env, stormAddr(53), "known", "right-psk",
		"55555555-6666-4777-8888-000000000110")
	if got.resp.Code != 0 {
		t.Fatalf("登录应成功: %+v", got.resp)
	}
	for _, s := range got.salt.DNSServersV4 {
		if s == "10.110.0.1" {
			t.Fatalf("Magic DNS 听在 5353 却把网关下发成解析器(%v)—— 客户端 stub 只打 :53,"+
				"每次解析都白等一轮超时才回落上游", got.salt.DNSServersV4)
		}
	}
	if got.salt.MagicDNSSuffix != "" {
		t.Errorf("非 53 端口不该下发 domain_suffix(客户端会把这些名字强行送进一个没人应答的解析器),got %q",
			got.salt.MagicDNSSuffix)
	}
}

func assertMagicDNSFirst(t *testing.T, got []string, gatewayIP string, keep []string) {
	t.Helper()
	if len(got) == 0 {
		t.Fatalf("开了 Magic DNS 却没下发任何 v4 解析器")
	}
	if got[0] != gatewayIP {
		t.Fatalf("头号解析器 = %q,期望网关 %q(全列表 %v)—— 公共 DNS 先答 NXDOMAIN,客户端就不再问 server 了",
			got[0], gatewayIP, got)
	}
	// 原有上游不能被顶掉:只留网关的话,客户端解析不了任何公网域名。
	for _, want := range keep {
		found := false
		for _, s := range got {
			if s == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("prepend 把原有上游 %s 顶掉了(现在是 %v)—— 客户端只剩网关一个解析器", want, got)
		}
	}
}
