package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/config"
)

// TestLoadConfig_RefusesToStartOnABadConfigInsteadOfDegrading 配置错误必须在启动期报出来。
//
// 这几条错误路径的共同点是:放过去以后症状全都出现在**别处**。负速率会让限速器行为怪异、非法
// CIDR 会让某一族地址池静默为空(表现是「某些客户端登录成功但不通」)、拼错的字段会被静默忽略
// (表现是「我明明配了却没生效」)。所以这里的每一条都必须带着「哪一项不对」返回,而不是回一份
// 半对的配置继续启动。
func TestLoadConfig_RefusesToStartOnABadConfigInsteadOfDegrading(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("文件不存在", func(t *testing.T) {
		if _, err := loadConfig(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
			t.Fatal("读不到配置文件必须报错 —— 静默用零值配置启动会绑到意外端口、不加载任何网段")
		}
	})

	t.Run("TOML 语法错", func(t *testing.T) {
		_, err := loadConfig(write(t, "[server\nlisten_addr = \":8443\"\n"))
		if err == nil {
			t.Fatal("TOML 解析失败必须报错")
		}
	})

	t.Run("语义校验不过", func(t *testing.T) {
		// 合法 TOML,但网段是非法 CIDR:放过去的话该族地址池静默为空,
		// 表现是「客户端登录成功却拿不到地址」,与配置文件毫无关联线索。
		_, err := loadConfig(write(t, `
[server]
listen_addr = "127.0.0.1:8443"
[tun]
subnets = ["不是网段"]
`))
		if err == nil {
			t.Fatal("非法网段必须在启动期报错,而不是让该族地址池静默为空")
		}
		if !strings.Contains(err.Error(), "语义校验") {
			t.Errorf("报错应说明是语义校验未通过,got %v", err)
		}
	})

	t.Run("未知字段默认只告警不拦", func(t *testing.T) {
		// 拼错的字段是最常见的运维失误。默认放行(只 WARN)是有意的取舍:一份带无害笔误的配置
		// 不该让服务起不来。要严格就设环境变量 —— 下一条用例验的就是那个开关。
		cfg, err := loadConfig(write(t, `
[server]
listen_addr = "127.0.0.1:8443"
listen_addrr = "typo"
[tun]
subnets = ["10.200.0.0/24"]
`))
		if err != nil {
			t.Fatalf("默认模式下未知字段只该告警,got %v", err)
		}
		if cfg.Server.ListenAddr != "127.0.0.1:8443" {
			t.Errorf("已知字段应正常解析,got %q", cfg.Server.ListenAddr)
		}
	})

	t.Run("strict 模式下未知字段直接拦", func(t *testing.T) {
		t.Setenv(config.StrictEnvVar, "1")
		_, err := loadConfig(write(t, `
[server]
listen_addr = "127.0.0.1:8443"
listen_addrr = "typo"
[tun]
subnets = ["10.200.0.0/24"]
`))
		if err == nil {
			t.Fatal("strict 模式必须拒掉未知字段 —— 开这个开关的人要的就是「配错了别让我上线」")
		}
		if !strings.Contains(err.Error(), config.StrictEnvVar) {
			t.Errorf("报错应告诉运维怎么降级成 WARN(提到 %s),got %v", config.StrictEnvVar, err)
		}
	})

	t.Run("正常配置照常返回", func(t *testing.T) {
		cfg, err := loadConfig(write(t, `
[server]
listen_addr = "127.0.0.1:8443"
[tun]
subnets = ["10.200.0.0/24"]
subnets_v6 = ["fd00:200::/64"]
`))
		if err != nil {
			t.Fatalf("合法配置不该报错: %v", err)
		}
		if len(cfg.TUN.Subnets) != 1 || len(cfg.TUN.SubnetsV6) != 1 {
			t.Errorf("两族网段都该读进来,got %v / %v", cfg.TUN.Subnets, cfg.TUN.SubnetsV6)
		}
		if cfg.Server.VPNWebSocketPath == "" {
			t.Error("VPN WebSocket 路径应被补上默认值 —— 空路径会让客户端连不上")
		}
	})
}

// TestCleanupConnection_TellsEveryoneTheExitIsGone 出口宣告方下线要广播。
//
// 不广播的后果不是「列表过期」这么轻:别的用户下拉里仍列着这个已经下线的出口,选中它之后流量
// 发给一个不存在的会话 —— 客户端侧表现为「选了出口就完全不通」,而服务端一切正常。列表只在
// 「有人连入 / admin 改配置」时重算,所以下线这一刻不主动广播,陈旧状态能挂很久。
func TestCleanupConnection_TellsEveryoneTheExitIsGone(t *testing.T) {
	resetServerGlobals(t)
	withTestGlobalContext(t)
	watcher := registerExitsWatcher(t)

	// 一条「真在跑出口」的会话下线。
	c := &Connection{
		userID:      "u-exit",
		connIDStr:   "exit-advertiser",
		linkConn:    &routeFakeConn{},
		cleanupDone: make(chan struct{}),
	}
	c.advertisedExit.Store(true)
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connByUserAddLocked(c)
	connIDMapMu.Unlock()

	cleanupConnection(c)

	awaitExitsBroadcast(t, watcher)

	// 顺带钉住索引确实被摘干净了:留着就是「已下线的会话仍被算作在线出口」。
	connIDMapMu.Lock()
	_, still := connIDMap[c.connIDStr]
	connIDMapMu.Unlock()
	if still {
		t.Error("下线的会话仍留在 connIDMap 里")
	}
}

// TestCleanupConnection_DoesNotBroadcastForAnOrdinaryClient 普通客户端下线不该触发广播。
//
// 每个普通客户端下线都广播一次出口列表,等于把「有人断线」放大成一次全员推送 —— 大规模部署下
// 这是自己给自己造的风暴。门控是「只有真在跑出口 / 已批准的子网宣告方」才广播。
func TestCleanupConnection_DoesNotBroadcastForAnOrdinaryClient(t *testing.T) {
	resetServerGlobals(t)
	withTestGlobalContext(t)
	watcher := registerExitsWatcher(t)

	c := &Connection{
		userID:      "u-plain",
		connIDStr:   "plain-client",
		linkConn:    &routeFakeConn{},
		cleanupDone: make(chan struct{}),
	}
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connByUserAddLocked(c)
	connIDMapMu.Unlock()

	cleanupConnection(c)

	// 给可能的广播留出足够窗口(广播是异步 goroutine),再确认确实没有。
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(watcher.bytes()) > 0 {
			t.Fatal("普通客户端下线也广播出口列表 —— 大规模部署下每次断线都放大成一次全员推送")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestCleanupConnection_IsSafeOnNilAndSignalsCompletion nil 与完成信号。
//
// cleanupDone 是 supersede 等待的那个信号(它等的不是隧道退出,而是「vIP 真的还回去了」)。
// 不 close 就是后来的会话永远等不到、抢不到同一个 vIP;而 nil 入参在关停竞态里确实会出现,
// 在这里 panic 等于一次断线带走整个进程。
func TestCleanupConnection_IsSafeOnNilAndSignalsCompletion(t *testing.T) {
	resetServerGlobals(t)
	withTestGlobalContext(t)

	cleanupConnection(nil) // 不许 panic

	c := &Connection{userID: "u", connIDStr: "sig", cleanupDone: make(chan struct{})}
	connIDMapMu.Lock()
	connIDMap[c.connIDStr] = c
	connIDMapMu.Unlock()
	cleanupConnection(c)

	select {
	case <-c.cleanupDone:
	default:
		t.Fatal("cleanupDone 没被 close —— 等它的 supersede 会永远抢不到这个会话的 vIP")
	}

	// 再清一次:必须幂等(重入 close 会 panic 在关停路径上)。
	cleanupConnection(c)
}
