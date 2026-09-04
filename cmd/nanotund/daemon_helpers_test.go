package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/config"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// ---- 环回桥接的地址推导 ----
//
// hy2 与 REALITY 握手完成后都要拨回本机 VPN 数据面。这个 URL 算错了,两个入口
// 会在握手成功之后才断 —— 客户端看到的是"连上了又掉",最难查的那类故障。

func TestLoopbackVPNWebSocketURL_AlwaysDialsBackTo127001(t *testing.T) {
	cases := []struct {
		name       string
		listenAddr string
		wsPath     string
		useTLS     bool
		want       string
	}{
		{"通配监听", ":8080", "/vpn", false, "ws://127.0.0.1:8080/vpn"},
		{"绑定所有网卡", "0.0.0.0:9000", "/vpn", false, "ws://127.0.0.1:9000/vpn"},
		{"只绑环回", "127.0.0.1:7000", "/vpn", false, "ws://127.0.0.1:7000/vpn"},
		{"绑公网 IP 也从环回拨回来", "203.0.113.9:8443", "/vpn", false, "ws://127.0.0.1:8443/vpn"},
		{"开了 TLS 就用 wss", ":8443", "/vpn", true, "wss://127.0.0.1:8443/vpn"},
		{"路径漏了斜杠自动补", ":8080", "vpn", false, "ws://127.0.0.1:8080/vpn"},
		{"路径为空用默认", ":8080", "  ", false, "ws://127.0.0.1:8080" + util.DefaultVPNWebSocketPath},
		{"监听地址为空回落默认端口", "", "/vpn", false, "ws://127.0.0.1:8080/vpn"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := loopbackVPNWebSocketURL(tc.listenAddr, tc.wsPath, tc.useTLS); got != tc.want {
				t.Fatalf("got %q,want %q", got, tc.want)
			}
		})
	}
}

// 环回 wss 用的 TLS 配置:证书是自签的、SAN 里没有 127.0.0.1,所以必须跳过校验;
// 但版本下限不能一起放掉。
func TestLoopbackVPNWebSocketDialTLS_SkipsVerifyButKeepsTheVersionFloor(t *testing.T) {
	c := loopbackVPNWebSocketDialTLS()
	if !c.InsecureSkipVerify {
		t.Fatal("环回自签证书没有 127.0.0.1 SAN,不跳过校验的话 hy2/REALITY 全断")
	}
	if c.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion=%x,不该低于 TLS 1.2", c.MinVersion)
	}
}

func TestServerVPNDataPlaneTLSActive_NeedsBothHalvesOfThePair(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.ServerConfig
		want bool
	}{
		{"nil", nil, false},
		{"都没配", &config.ServerConfig{}, false},
		{"只有证书", &config.ServerConfig{TLSCertFile: "a.crt"}, false},
		{"只有私钥", &config.ServerConfig{TLSKeyFile: "a.key"}, false},
		{"只有空白也不算", &config.ServerConfig{TLSCertFile: "  ", TLSKeyFile: "  "}, false},
		{"成对才算", &config.ServerConfig{TLSCertFile: "a.crt", TLSKeyFile: "a.key"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverVPNDataPlaneTLSActive(tc.cfg); got != tc.want {
				t.Fatalf("got %v want %v —— 判错会让环回用错 ws/wss scheme,握手直接失败", got, tc.want)
			}
		})
	}
}

// ---- smux 配置合成 ----

func TestBuildSmuxConfigFrom_FallsBackToDefaultsRatherThanShippingAnInvalidConfig(t *testing.T) {
	dc := buildSmuxConfigFrom(nil)
	if dc == nil {
		t.Fatal("nil 配置应回默认")
	}

	t.Run("零值项保留默认", func(t *testing.T) {
		got := buildSmuxConfigFrom(&config.SmuxConfig{})
		if got.Version != dc.Version || got.MaxFrameSize != dc.MaxFrameSize ||
			got.MaxReceiveBuffer != dc.MaxReceiveBuffer || got.MaxStreamBuffer != dc.MaxStreamBuffer ||
			got.KeepAliveInterval != dc.KeepAliveInterval || got.KeepAliveTimeout != dc.KeepAliveTimeout {
			t.Fatalf("没配的项被改了: %+v", got)
		}
	})

	t.Run("配了就用配的", func(t *testing.T) {
		got := buildSmuxConfigFrom(&config.SmuxConfig{
			Version:              2,
			KeepAliveIntervalSec: 5,
			KeepAliveTimeoutSec:  20,
			MaxFrameSize:         16384,
			MaxReceiveBuffer:     8 << 20,
			MaxStreamBuffer:      1 << 20,
		})
		if got.Version != 2 || got.KeepAliveInterval != 5*time.Second ||
			got.KeepAliveTimeout != 20*time.Second || got.MaxFrameSize != 16384 ||
			got.MaxReceiveBuffer != 8<<20 || got.MaxStreamBuffer != 1<<20 {
			t.Fatalf("配置没传下去: %+v", got)
		}
	})

	t.Run("不认识的版本号忽略", func(t *testing.T) {
		got := buildSmuxConfigFrom(&config.SmuxConfig{Version: 9})
		if got.Version != dc.Version {
			t.Fatalf("version=9 不该被采纳,got %d", got.Version)
		}
	})

	t.Run("关 keepalive 的开关要传下去", func(t *testing.T) {
		got := buildSmuxConfigFrom(&config.SmuxConfig{KeepAliveDisabled: true})
		if !got.KeepAliveDisabled {
			t.Fatal("KeepAliveDisabled 没传下去")
		}
	})

	// 「用户值 + 默认值」的混合可能违反 smux 的跨字段约束。这时宁可整体回退默认,
	// 也不能让每条连接静默 VerifyConfig 失败 —— 那是整个数据面不可用。
	t.Run("跨字段冲突时整体回退默认", func(t *testing.T) {
		got := buildSmuxConfigFrom(&config.SmuxConfig{MaxStreamBuffer: dc.MaxReceiveBuffer * 4})
		if got.MaxStreamBuffer != dc.MaxStreamBuffer || got.MaxReceiveBuffer != dc.MaxReceiveBuffer {
			t.Fatalf("非法组合应整体回退默认,got stream=%d recv=%d", got.MaxStreamBuffer, got.MaxReceiveBuffer)
		}
	})
}

// ---- REALITY 配置 ----

func TestBuildRealityTLSConfig_MirrorsWhatTheDisguiseNeeds(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	t.Run("正常配置逐项落到 reality.Config", func(t *testing.T) {
		rc, err := buildRealityTLSConfig(&config.RealityConfig{
			PrivateKey:    key,
			Dest:          "  www.microsoft.com:443  ",
			Type:          "  tcp  ",
			Xver:          1,
			ServerNames:   []string{"www.microsoft.com", "  ", "cdn.example.com"},
			ShortIds:      []string{"0123456789abcdef"},
			MaxTimeDiffMs: 60000,
			Show:          true,
		})
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if rc.Dest != "www.microsoft.com:443" {
			t.Fatalf("dest 应去空白,got %q", rc.Dest)
		}
		if rc.Type != "tcp" {
			t.Fatalf("type 应去空白,got %q", rc.Type)
		}
		if rc.Xver != 1 || !rc.Show {
			t.Fatalf("xver/show 没传对: xver=%d show=%v", rc.Xver, rc.Show)
		}
		if len(rc.ServerNames) != 2 || !rc.ServerNames["www.microsoft.com"] {
			t.Fatalf("server_names 应去掉空项,got %v", rc.ServerNames)
		}
		if len(rc.ShortIds) != 1 {
			t.Fatalf("short_ids 数量不对: %v", rc.ShortIds)
		}
		if rc.MaxTimeDiff != 60*time.Second {
			t.Fatalf("max_time_diff 应按毫秒换算,got %v", rc.MaxTimeDiff)
		}
		if !rc.SessionTicketsDisabled {
			t.Fatal("session ticket 必须关 —— 开着会在握手里留下可指纹的复用痕迹")
		}
		// dest 拨号必须带超时:没超时的话,一个被黑洞的 dest 会把并发槽位全攥死,
		// 整个 REALITY 监听僵死。
		if rc.DialContext == nil {
			t.Fatal("DialContext 为空 = 用零值 Dialer,拨 dest 没有超时")
		}
	})

	t.Run("type 为空时补 tcp", func(t *testing.T) {
		rc, err := buildRealityTLSConfig(&config.RealityConfig{PrivateKey: key, Dest: "a.com:443"})
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if rc.Type != "tcp" {
			t.Fatalf("type 应默认 tcp,got %q", rc.Type)
		}
		if rc.MaxTimeDiff != 0 {
			t.Fatalf("没配 max_time_diff 时不该设,got %v", rc.MaxTimeDiff)
		}
	})

	t.Run("私钥不合法要报错", func(t *testing.T) {
		if _, err := buildRealityTLSConfig(&config.RealityConfig{PrivateKey: "不是 base64"}); err == nil {
			t.Fatal("私钥解不出来应报错,不能带着零值密钥启动")
		}
	})

	t.Run("short_id 不合法要报错", func(t *testing.T) {
		_, err := buildRealityTLSConfig(&config.RealityConfig{PrivateKey: key, ShortIds: []string{"不是十六进制"}})
		if err == nil {
			t.Fatal("非法 short_id 应报错 —— 静默丢弃会让对应客户端全部连不上")
		}
	})

	t.Run("mldsa65 种子", func(t *testing.T) {
		seed := base64.StdEncoding.EncodeToString(make([]byte, 32))
		rc, err := buildRealityTLSConfig(&config.RealityConfig{PrivateKey: key, Mldsa65SeedBase64: seed})
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(rc.Mldsa65Key) == 0 {
			t.Fatal("配了种子就该派生出后量子签名密钥")
		}

		if _, err := buildRealityTLSConfig(&config.RealityConfig{
			PrivateKey: key, Mldsa65SeedBase64: "短了",
		}); err == nil {
			t.Fatal("种子不合法应报错")
		}
	})
}

func TestDecodeMldsa65SeedBase64_Needs32BytesAndSaysSoWhenItIsNot(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	out, err := decodeMldsa65SeedBase64(good)
	if err != nil {
		t.Fatalf("32 字节种子应通过: %v", err)
	}
	if string(out[:]) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("解出来的内容不对: %q", out[:])
	}

	for _, bad := range []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := decodeMldsa65SeedBase64(bad); err == nil {
			t.Fatalf("%q 应被拒", bad)
		} else if !strings.Contains(err.Error(), "mldsa65_seed_base64") {
			t.Fatalf("错误里该点名是哪个配置项: %v", err)
		}
	}
}

// bridge 的核心不变量:任一侧断了必须把另一侧也关掉。漏关的话 localhost 上会攒下
// 一堆 ESTABLISHED,是这类 TLS 实现最常见的泄漏。
func TestBridgeRealityToPlainVPN_ClosingOneSideTearsDownTheOther(t *testing.T) {
	t.Run("环回拨不通时立刻关掉客户端连接", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()

		done := make(chan struct{})
		go func() {
			defer close(done)
			// 指向没人监听的端口:拨号必失败。
			bridgeRealityToPlainVPN(server, "127.0.0.1:1", "/vpn", nil, nil)
		}()

		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("拨号失败后 bridge 没有返回")
		}
		// 客户端侧应当读到 EOF 而不是永远挂着。
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Fatal("环回拨不通时必须关掉客户端连接,否则它会一直 ESTABLISHED 挂着")
		}
	})

	t.Run("有 pool 但 OpenStream 失败时同样关掉", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()

		done := make(chan struct{})
		go func() {
			defer close(done)
			bridgeRealityToPlainVPN(server, "127.0.0.1:1", "/vpn", &loopbackSmuxPool{}, nil)
		}()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatal("OpenStream 失败后 bridge 没有返回")
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Fatal("OpenStream 失败也要关掉客户端连接")
		}
	})
}

// ---- 握手截止时间 ----
//
// 这层是 Slow-loris 的第一道闸:攻击者建一堆 TCP 却不发 ClientHello,占满握手
// goroutine。Accept 出来的 conn 必须自带 deadline。

func TestHandshakeDeadlineListener_StampsEveryAcceptedConn(t *testing.T) {
	t.Run("timeout<=0 时原样返回,不做无谓包装", func(t *testing.T) {
		base := &fakeListener{}
		if got := newHandshakeDeadlineListener(base, 0); got != net.Listener(base) {
			t.Fatal("不设超时就该原样返回")
		}
		if got := newHandshakeDeadlineListener(base, -time.Second); got != net.Listener(base) {
			t.Fatal("负超时同样原样返回")
		}
	})

	t.Run("Accept 出来的连接带上了 deadline", func(t *testing.T) {
		c := &deadlineRecordingConn{}
		ln := newHandshakeDeadlineListener(&fakeListener{conn: c}, 15*time.Second)
		got, err := ln.Accept()
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if got != net.Conn(c) {
			t.Fatal("应当把底层 conn 原样交出去")
		}
		if c.deadline.IsZero() {
			t.Fatal("Accept 返回前必须套上握手 deadline —— 少了这层,不发 ClientHello 的连接会一直占着 goroutine")
		}
		if d := time.Until(c.deadline); d <= 0 || d > 16*time.Second {
			t.Fatalf("deadline 距现在 %v,不在预期区间", d)
		}
	})

	t.Run("Accept 出错时原样透传", func(t *testing.T) {
		want := errors.New("listener 关了")
		ln := newHandshakeDeadlineListener(&fakeListener{err: want}, time.Second)
		if _, err := ln.Accept(); !errors.Is(err, want) {
			t.Fatalf("错误应原样透传,got %v", err)
		}
	})
}

type fakeListener struct {
	conn net.Conn
	err  error
}

func (l *fakeListener) Accept() (net.Conn, error) {
	if l.err != nil {
		return nil, l.err
	}
	return l.conn, nil
}
func (l *fakeListener) Close() error   { return nil }
func (l *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

type deadlineRecordingConn struct {
	net.Conn
	deadline time.Time
}

func (c *deadlineRecordingConn) SetDeadline(t time.Time) error { c.deadline = t; return nil }

// ---- 限速连接的 deadline 透传 ----

func TestRateLimitedConn_ForwardsDeadlinesToTheUnderlyingConn(t *testing.T) {
	inner := &deadlineTrackingRWC{}
	c := newRateLimitedConn(inner, nil, nil, context.Background())

	want := time.Now().Add(time.Minute)
	if err := c.SetReadDeadline(want); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if !inner.read.Equal(want) {
		t.Fatalf("read deadline 没传到底层: %v", inner.read)
	}
	if err := c.SetWriteDeadline(want); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if !inner.write.Equal(want) {
		t.Fatalf("write deadline 没传到底层: %v", inner.write)
	}

	// 底层不支持 deadline(如 smux stream 的某些包装)时静默成功,不能报错把链路打断。
	plain := newRateLimitedConn(&plainRWC{}, nil, nil, context.Background())
	if err := plain.SetReadDeadline(want); err != nil {
		t.Fatalf("底层不支持时应静默成功,got %v", err)
	}
	if err := plain.SetWriteDeadline(want); err != nil {
		t.Fatalf("底层不支持时应静默成功,got %v", err)
	}
}

type plainRWC struct{}

func (plainRWC) Read([]byte) (int, error)    { return 0, io.EOF }
func (plainRWC) Write(p []byte) (int, error) { return len(p), nil }
func (plainRWC) Close() error                { return nil }

type deadlineTrackingRWC struct {
	plainRWC
	read  time.Time
	write time.Time
}

func (c *deadlineTrackingRWC) SetReadDeadline(t time.Time) error  { c.read = t; return nil }
func (c *deadlineTrackingRWC) SetWriteDeadline(t time.Time) error { c.write = t; return nil }

// ---- PoW / IP 失败记录的定期清扫 ----
//
// 这两张表都由公网请求驱动增长。GC 不工作就是一条稳定的内存泄漏路径。

func TestIPFailureTracker_PruneDropsWhatFellOutOfTheWindow(t *testing.T) {
	tr := NewIPFailureTracker()
	tr.MarkFailure("203.0.113.1")
	tr.MarkFailure("203.0.113.2")
	if tr.Size() != 2 {
		t.Fatalf("Size=%d,期望 2", tr.Size())
	}

	// 窗口内:什么都不该掉。
	tr.Prune()
	if tr.Size() != 2 {
		t.Fatalf("窗口内的记录被误删了,Size=%d", tr.Size())
	}

	// 把时间推到窗口之外。
	tr.pruneLocked(time.Now().Add(2 * ipFailureWindow))
	if tr.Size() != 0 {
		t.Fatalf("过窗口的记录没清掉,Size=%d —— 这张表由公网请求驱动增长,不清就是泄漏", tr.Size())
	}
}

func TestPoWService_GCRemovesExpiredReplayEntriesAndStopsOnSignal(t *testing.T) {
	svc, err := NewPoWService(make([]byte, 32), NewIPFailureTracker(), 1, 8, 14, 2, 22, 300)
	if err != nil {
		t.Fatalf("NewPoWService: %v", err)
	}

	now := time.Now().Unix()
	svc.powUsed.Store("expired", now-10)
	svc.powUsed.Store("live", now+3600)
	svc.powUsed.Store("坏类型", "不是 int64")

	svc.pruneExpired()

	if _, ok := svc.powUsed.Load("expired"); ok {
		t.Fatal("过期的防重放条目没被清掉")
	}
	if _, ok := svc.powUsed.Load("坏类型"); ok {
		t.Fatal("类型不对的条目也该清掉,不然它永远赖在表里")
	}
	if _, ok := svc.powUsed.Load("live"); !ok {
		t.Fatal("没过期的条目被误删了 —— 删掉等于放开了重放窗口")
	}

	// RunGC 是常驻 goroutine,stop 一关必须退出,否则进程停不下来。
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { defer close(done); svc.RunGC(stop) }()
	close(stop)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stop 关闭后 RunGC 没退出")
	}
}

func TestPowIPLimiter_GCDropsIdleBuckets(t *testing.T) {
	l := &powIPLimiter{limits: make(map[string]*powIPEntry)}
	now := time.Now()
	l.limits["fresh"] = &powIPEntry{lastSeen: now}
	l.limits["stale"] = &powIPEntry{lastSeen: now.Add(-2 * powIPRLGCTTL)}

	if n := l.CountForTest(); n != 2 {
		t.Fatalf("CountForTest=%d,期望 2", n)
	}
	l.forceGCLocked(now)
	if _, ok := l.limits["stale"]; ok {
		t.Fatal("长期没动静的桶该清掉 —— 每个来过的 IP 占一个 entry,不清就是泄漏")
	}
	if _, ok := l.limits["fresh"]; !ok {
		t.Fatal("活跃的桶被误删了,那个 IP 的限速状态就重置了")
	}
	if n := l.CountForTest(); n != 1 {
		t.Fatalf("CountForTest=%d,期望 1", n)
	}
}

// ---- 零散纯函数 ----

func TestParseMeshPrefixes_SkipsWhatItCannotParse(t *testing.T) {
	got := parseMeshPrefixes([]string{
		"  10.201.0.0/16  ",
		"这不是网段",
		"fd7a:115c::/48",
		"",
		"10.0.0.5/8", // 带主机位:应被 Masked 归一
	})
	if len(got) != 3 {
		t.Fatalf("解出 %d 条,期望 3(非法的跳过): %v", len(got), got)
	}
	if got[0] != netip.MustParsePrefix("10.201.0.0/16") {
		t.Fatalf("第一条不对: %v", got[0])
	}
	if got[2] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("带主机位的前缀应被归一成 10.0.0.0/8,got %v —— 不归一会让后续 Contains 判断出错", got[2])
	}
	if parseMeshPrefixes(nil) != nil {
		t.Fatal("空输入应返回 nil")
	}
}

func TestDedupExitsByUUID_KeepsTheOnlineOneAndDropsPlaceholders(t *testing.T) {
	in := []util.ExitInfo{
		{DeviceUUID: "uuid-a", DeviceName: "a-离线", Online: false},
		{DeviceUUID: "", DeviceName: "占位", Online: true},
		{DeviceUUID: "uuid-b", DeviceName: "b", Online: true},
		{DeviceUUID: "uuid-a", DeviceName: "a-在线", Online: true},
		{DeviceUUID: "uuid-b", DeviceName: "b-离线", Online: false},
	}
	got := dedupExitsByUUID(in)

	if len(got) != 2 {
		t.Fatalf("去重后 %d 条,期望 2: %+v", len(got), got)
	}
	if got[0].DeviceUUID != "uuid-a" || got[1].DeviceUUID != "uuid-b" {
		t.Fatalf("应保持首次出现顺序: %+v", got)
	}
	if got[0].DeviceName != "a-在线" || !got[0].Online {
		t.Fatalf("同 uuid 有在线的就该用在线那条(下拉里选到离线项 = 选了也连不上): %+v", got[0])
	}
	if got[1].DeviceName != "b" {
		t.Fatalf("已经是在线的不该被后来的离线条覆盖: %+v", got[1])
	}
	for _, e := range got {
		if e.DeviceUUID == "" {
			t.Fatal("空 uuid 是历史脏数据,选了也无法绑定,必须丢弃")
		}
	}
}

func TestSameSubnet_ReturnsFalseOnAnythingItCannotParse(t *testing.T) {
	cases := []struct {
		cidr, ip string
		want     bool
	}{
		{"100.64.0.1/24", "100.64.0.9", true},
		{"100.64.0.1/24", "100.64.1.9", false},
		{"100.64.0.1/24", "不是地址", false},
		{"不是网段", "100.64.0.9", false},
		{"", "", false},
		{"fd7a:115c::/48", "fd7a:115c::5", true},
	}
	for _, tc := range cases {
		if got := sameSubnet(tc.cidr, tc.ip); got != tc.want {
			t.Errorf("sameSubnet(%q,%q)=%v want %v", tc.cidr, tc.ip, got, tc.want)
		}
	}
}

// 4via6 前缀在 nanotund 与 util 里必须是同一个值:宣告校验拿它把这段挡在可宣告集
// 之外,编解码拿它构造地址。两处漂移会让 4via6 地址落进用户可宣告的网段。
func TestVia6Prefix_IsTheSameValueTheAdvertiseGuardUses(t *testing.T) {
	if Via6Prefix() != util.Via6Prefix {
		t.Fatalf("nanotund 用 %v,util 用 %v —— 两处必须同值", Via6Prefix(), util.Via6Prefix)
	}
	if Via6Prefix().Bits() != 64 {
		t.Fatalf("4via6 前缀应为 /64,got %v", Via6Prefix())
	}
	// 编出来的地址必须落在这个前缀里。
	addr, ok := encode4via6(7, netip.MustParseAddr("192.168.1.5"))
	if !ok {
		t.Fatal("encode4via6 失败")
	}
	if !Via6Prefix().Contains(addr) {
		t.Fatalf("编出来的 %v 不在前缀 %v 内", addr, Via6Prefix())
	}
}

// 这两个只打日志的辅助函数,存在的意义是"不崩"。
func TestLogOnlyHelpers_DoNotPanicOnEdgeInputs(t *testing.T) {
	logrusWarnPoolFull("100.64.0.0/24", 230, 254)

	logMeshSubnetMoved(nil, "10.0.0.1", "")                         // 首次部署:没有上次可比
	logMeshSubnetMoved([]string{"10.0.0.1"}, "10.0.0.1", "")        // 没变
	logMeshSubnetMoved([]string{"10.0.0.1"}, "10.9.9.1", "fd00::1") // 变了
	logMeshSubnetMoved([]string{"  ", ""}, "10.9.9.1", "")          // 全是空白
}

func TestLoginAuthError_CarriesTheMessageClientsWillSee(t *testing.T) {
	e := &loginAuthError{code: 7, message: "认证失败"}
	if e.Error() != "认证失败" {
		t.Fatalf("Error() 应返回给客户端的文案,got %q", e.Error())
	}
	// 它要能当 error 用(调用方会 errors.As 出来取 code)。
	var err error = e
	var target *loginAuthError
	if !errors.As(err, &target) || target.code != 7 {
		t.Fatalf("errors.As 取不出 code: %+v", target)
	}
}

func TestParseListenPort_HappyPathsDoNotKillTheProcess(t *testing.T) {
	if got := parseListenPort(":8080", ":9999"); got != 8080 {
		t.Fatalf("got %d want 8080", got)
	}
	if got := parseListenPort("", ":9999"); got != 9999 {
		t.Fatalf("空值应回落默认,got %d", got)
	}
	if got := parseListenPort("0.0.0.0:443", ":9999"); got != 443 {
		t.Fatalf("got %d want 443", got)
	}
	// 放行的几种写法都不该退进程。
	for _, ok := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "127.0.0.1:8080"} {
		validateVPNListenAddr(ok)
	}
}

func TestIsProductionLinuxRoot_OnlyTrueOnLinuxAsRoot(t *testing.T) {
	// 这个判断决定了启动期 TUN/iptables 失败是 Fatal 还是 Warn。开发机上必须是
	// false,否则联调和单测跑不起来。
	got := isProductionLinuxRoot()
	if runtime.GOOS == "linux" {
		if got != (os.Geteuid() == 0) {
			t.Fatalf("Linux 上应等价于 euid==0,got %v", got)
		}
	} else if got {
		t.Fatal("非 Linux 上必须为 false —— 否则 macOS 开发机一启动就 Fatal")
	}
}

// ---- 后台常驻任务的启动闸 ----
//
// 这些 start* 都在 main 里被无条件调用,拿到的 gw 可能还没接上 store(早退路径 /
// 单测)。它们必须静默跳过而不是空指针。

func TestBackgroundLoopStarters_AreNoOpsWithoutAStore(t *testing.T) {
	if f := startAuditGC(nil); f == nil {
		t.Fatal("startAuditGC(nil) 应返回可调用的 stop")
	} else {
		f()
	}
	for name, start := range map[string]func() func(){
		"aclDropAuditFlusher": func() func() { return startACLDropAuditFlusher(nil, time.Second) },
		"aclDropAuditFlusher/无 store": func() func() {
			return startACLDropAuditFlusher(&gatewayState{}, time.Second)
		},
		"leaseGC":         func() func() { return startLeaseGCLoop(nil, 1, 1, 0) },
		"leaseGC/无 store": func() func() { return startLeaseGCLoop(&gatewayState{}, 1, 1, 0) },
		"userInvalidate":  func() func() { return startUserInvalidationLoop(nil, time.Second) },
		"userInvalidate/无 store": func() func() {
			return startUserInvalidationLoop(&gatewayState{}, time.Second)
		},
		"magicDNS":         func() func() { return startMagicDNS(nil, "10.0.0.1:53") },
		"magicDNS/无 store": func() func() { return startMagicDNS(&gatewayState{}, "10.0.0.1:53") },
	} {
		t.Run(name, func(t *testing.T) {
			stop := start()
			if stop == nil {
				t.Fatal("应返回可调用的 stop,而不是 nil")
			}
			stop()
		})
	}
}

// lease GC 的开关语义:idle_days<=0 是「显式关闭」,不是「用默认值」。
// 弄反了会让运维以为关掉了,实际每天照删租约。
func TestStartLeaseGCLoop_NonPositiveIdleDaysMeansOffNotDefault(t *testing.T) {
	st := newDaemonTestStore(t)
	gw := &gatewayState{store: st}

	prevCtx, prevCancel := globalContext, globalContextCancel
	ctx, cancel := context.WithCancel(t.Context())
	globalContext, globalContextCancel = ctx, cancel
	t.Cleanup(func() {
		cancel()
		globalContext, globalContextCancel = prevCtx, prevCancel
	})

	for _, idle := range []int{0, -1} {
		stop := startLeaseGCLoop(gw, idle, 1, 0)
		if stop == nil {
			t.Fatal("应返回可调用的 stop")
		}
		stop()
	}
}

func TestStartMagicDNS_StaysOffUnlessExplicitlyEnabled(t *testing.T) {
	st := newDaemonTestStore(t)

	t.Run("配置里没打开", func(t *testing.T) {
		gw := &gatewayState{store: st, cfg: &config.Config{}}
		stop := startMagicDNS(gw, "127.0.0.1:0")
		if stop == nil {
			t.Fatal("应返回可调用的 stop")
		}
		stop()
	})

	t.Run("打开了但拿不到监听地址", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Server.MagicDNS.Enabled = true
		gw := &gatewayState{store: st, cfg: cfg}
		// TUN gateway 未就绪 → listenAddr 为空,必须跳过而不是绑一个错的地址。
		stop := startMagicDNS(gw, "")
		if stop == nil {
			t.Fatal("应返回可调用的 stop")
		}
		stop()
	})
}

// isolate 模式下已批准的中继会被挡住,启动期要提醒运维。没有 store / 没开 isolate
// 时必须安静退出。
func TestWarnIsolateBlocksApprovedRelays_QuietWhenThereIsNothingToSay(t *testing.T) {
	ctx := t.Context()
	warnIsolateBlocksApprovedRelays(ctx, nil)
	warnIsolateBlocksApprovedRelays(ctx, &gatewayState{})

	st := newDaemonTestStore(t)
	gw := &gatewayState{store: st}

	// isolate 没开 → 不查 DB 直接返回。
	prev := clientIsolateMode.Load()
	clientIsolateMode.Store(false)
	t.Cleanup(func() { clientIsolateMode.Store(prev) })
	warnIsolateBlocksApprovedRelays(ctx, gw)

	// isolate 开着但库里没有已批准路由 → 也不该报警。
	clientIsolateMode.Store(true)
	warnIsolateBlocksApprovedRelays(ctx, gw)
}

func TestInitAuthBackend_OpensTheStoreAndHandsBackACleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	dbPath := filepath.Join(t.TempDir(), "auth.db")
	cfg := &config.Config{}
	cfg.Store.DBPath = dbPath
	gw := &gatewayState{cfg: cfg}

	cleanup, err := initAuthBackend(ctx, gw)
	if err != nil {
		t.Fatalf("initAuthBackend: %v", err)
	}
	if gw.store == nil || gw.authVerifier == nil {
		t.Fatal("store 与 verifier 都要挂到 gw 上,少一个登录路径就会空指针")
	}
	// 迁移必须跑过 —— 否则第一条登录才发现表不存在。
	if _, err := gw.store.ListUsersAll(ctx); err != nil {
		t.Fatalf("库没迁移好: %v", err)
	}
	cancel()
	cleanup()

	t.Run("路径不可用时报错而不是带着半个 store 继续", func(t *testing.T) {
		// 拿一个普通文件当目录用:父目录建不出来,库自然打不开。
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		bad := &config.Config{}
		bad.Store.DBPath = filepath.Join(blocker, "x.db")
		g := &gatewayState{cfg: bad}
		if _, err := initAuthBackend(t.Context(), g); err == nil {
			t.Fatal("打不开库应报错 —— 带着 nil store 继续跑,第一条登录就空指针")
		}
		if g.authVerifier != nil {
			t.Fatal("失败路径不该留下半挂的 verifier")
		}
	})
}

func newDaemonTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "d.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return st
}
