package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Web 通过一个 unix socket 指挥 nanotund。这层薄客户端的每个方法都有三种结局:
// 连不上、连上了但对端说失败、连上了但回了看不懂的东西。三种都必须区分得出来 ——
// 全都当成成功的话,页面会显示"已生效"而数据面还是老样子。

func TestControlClient_DistinguishesUnreachableFromRefusedFromGarbage(t *testing.T) {
	okJSON := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}
	}

	type call struct {
		name string
		fn   func(c *controlClient) (int, error)
		path string
		good string
		want int
	}
	calls := []call{
		{"ReloadACL", func(c *controlClient) (int, error) { return c.ReloadACL(t.Context()) },
			"/reload", `{"ok":true,"rules":7}`, 7},
		{"ReloadRoutes", func(c *controlClient) (int, error) { return c.ReloadRoutes(t.Context()) },
			"/reload", `{"ok":true,"routes":3}`, 3},
		{"ReloadExits", func(c *controlClient) (int, error) { return c.ReloadExits(t.Context()) },
			"/reload", `{"ok":true,"rebound_to_server":2}`, 2},
		{"ReloadPortForwards", func(c *controlClient) (int, error) { return c.ReloadPortForwards(t.Context()) },
			"/reload", `{"ok":true,"active":5}`, 5},
	}

	for _, tc := range calls {
		t.Run(tc.name+"/正常", func(t *testing.T) {
			fc := newFakeControl(t, map[string]http.HandlerFunc{tc.path: okJSON(tc.good)})
			n, err := tc.fn(fc.client)
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if n != tc.want {
				t.Fatalf("计数 = %d,期望 %d —— 这个数字会显示在页面上", n, tc.want)
			}
		})

		t.Run(tc.name+"/对端说失败", func(t *testing.T) {
			fc := newFakeControl(t, map[string]http.HandlerFunc{tc.path: okJSON(`{"ok":false}`)})
			if _, err := tc.fn(fc.client); err == nil {
				t.Fatal("ok=false 必须当成失败 —— 否则页面显示已生效,数据面其实没动")
			}
		})

		t.Run(tc.name+"/回了看不懂的东西", func(t *testing.T) {
			fc := newFakeControl(t, map[string]http.HandlerFunc{
				tc.path: func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte("这不是 JSON"))
				}})
			_, err := tc.fn(fc.client)
			if err == nil {
				t.Fatal("解析不了的响应应报错")
			}
			if !strings.Contains(err.Error(), "parse") {
				t.Fatalf("错误里该说明是解析问题,方便区分「连不上」和「协议对不上」: %v", err)
			}
		})

		t.Run(tc.name+"/socket 连不上", func(t *testing.T) {
			c := newControlClient("/tmp/绝对不存在的控制面.sock")
			if _, err := tc.fn(c); err == nil {
				t.Fatal("连不上应报错")
			}
		})

		t.Run(tc.name+"/未配置控制面", func(t *testing.T) {
			var c *controlClient
			if _, err := tc.fn(c); err == nil {
				t.Fatal("没配控制面时应报错而不是空指针")
			}
		})
	}
}

// 老版本 server 没有 /sysmon/counters,客户端要能自动退回 /status。
// 退回时 uptime 必须是 -1(未知)而不是 0,前端据此显示 "—"。
func TestSysmonCounters_FallsBackToStatusOnOldServers(t *testing.T) {
	t.Run("新 server 直接用轻量端点", func(t *testing.T) {
		fc := newFakeControl(t, map[string]http.HandlerFunc{
			"/sysmon/counters": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"ts_ms":1700000000000,"uptime_seconds":42,"vpn_bytes_up":10,"vpn_bytes_down":20}`))
			}})
		got, err := fc.client.SysmonCounters(t.Context())
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if got.UptimeSeconds != 42 || got.VPNBytesUp != 10 || got.VPNBytesDown != 20 {
			t.Fatalf("字段没读对: %+v", got)
		}
		if fc.sawPath("/status") {
			t.Fatal("新端点能用就不该再打 /status —— 后者在会话多时要几毫秒")
		}
	})

	t.Run("老 server 退回 /status", func(t *testing.T) {
		fc := newFakeControl(t, map[string]http.HandlerFunc{
			"/status": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"vpn_bytes_up":111,"vpn_bytes_down":222}`))
			}})
		got, err := fc.client.SysmonCounters(t.Context())
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if got.VPNBytesUp != 111 || got.VPNBytesDown != 222 {
			t.Fatalf("退回路径没读到字节数: %+v", got)
		}
		if got.UptimeSeconds != -1 {
			t.Fatalf("uptime=%d,退回路径必须标 -1(未知);写 0 会被前端显示成「刚启动」",
				got.UptimeSeconds)
		}
		if got.TimestampMS <= 0 {
			t.Fatal("老 server 没有 ts_ms,应当用本地时间补上,否则前端算不了速率")
		}
	})

	t.Run("退回路径也解析不了", func(t *testing.T) {
		fc := newFakeControl(t, map[string]http.HandlerFunc{
			"/status": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("垃圾"))
			}})
		if _, err := fc.client.SysmonCounters(t.Context()); err == nil {
			t.Fatal("应报错")
		}
	})
}

func TestRateConfig_FallsBackToStatusOnOldServers(t *testing.T) {
	t.Run("新端点", func(t *testing.T) {
		fc := newFakeControl(t, map[string]http.HandlerFunc{
			"/rate/config": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"settings_up_bps":100,"settings_down_bps":200,` +
					`"settings_burst_bytes":300,"toml_up_bps":400,"toml_down_bps":500,` +
					`"effective_burst_bytes":600}`))
			}})
		got, err := fc.client.RateConfig(t.Context())
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if got.SettingsUpBPS != 100 || got.SettingsDownBPS != 200 || got.SettingsBurst != 300 ||
			got.TomlUpBPS != 400 || got.TomlDownBPS != 500 || got.EffectiveBurst != 600 {
			t.Fatalf("字段没读对: %+v", got)
		}
	})

	t.Run("老 server 从 /status 里挖", func(t *testing.T) {
		fc := newFakeControl(t, map[string]http.HandlerFunc{
			"/status": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"rate_config":{"settings_up_bps":11,"settings_down_bps":22,` +
					`"settings_burst_bytes":33,"toml_up_bps":44,"toml_down_bps":55,` +
					`"effective_burst_bytes":66}}`))
			}})
		got, err := fc.client.RateConfig(t.Context())
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if got.SettingsUpBPS != 11 || got.EffectiveBurst != 66 {
			t.Fatalf("退回路径字段没读对: %+v", got)
		}
	})

	t.Run("两条路都不通", func(t *testing.T) {
		c := newControlClient("/tmp/绝对不存在的控制面.sock")
		if _, err := c.RateConfig(t.Context()); err == nil {
			t.Fatal("应报错")
		}
	})

	t.Run("退回路径解析失败", func(t *testing.T) {
		fc := newFakeControl(t, map[string]http.HandlerFunc{
			"/status": func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("垃圾"))
			}})
		if _, err := fc.client.RateConfig(t.Context()); err == nil {
			t.Fatal("应报错")
		}
	})
}

// 这几个 best-effort 通知是「写库已经成功了,顺手告诉数据面一声」。它们绝不能
// 因为控制面不可用而 panic 或者阻塞用户操作 —— 页面已经返回给用户了。
func TestBackgroundNotifiers_SurviveAnUnreachableControlPlane(t *testing.T) {
	dead := newControlClient("/tmp/绝对不存在的控制面.sock")

	t.Run("控制面连不上", func(t *testing.T) {
		tryReloadACLBackground(dead)
		tryReloadRoutesBackground(dead)
		tryReloadExitsBackground(dead)
		notifyRouteChangeBackground(dead, "10.0.0.0/24")
		notifyRouteChangeBackground(dead, "0.0.0.0/0")
		// 后台 goroutine 自带 5s 超时;这里只要主流程没挂就算过。
		time.Sleep(100 * time.Millisecond)
	})

	t.Run("压根没配控制面", func(t *testing.T) {
		tryReloadRoutesBackground(nil)
		tryReloadExitsBackground(nil)
		notifyRouteChangeBackground(nil, "10.0.0.0/24")
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("控制面正常时确实发了通知", func(t *testing.T) {
		fc := newFakeControl(t, controlOK())
		tryReloadACLBackground(fc.client)
		if !waitForControlPath(t, fc, "/reload") {
			t.Fatalf("没有通知到控制面,收到的是: %v", fc.requests())
		}
	})

	// 出口路由和普通子网走不同的重载目标:混了的话,批准一个出口不会刷新客户端下拉。
	t.Run("出口路由与子网路由分流", func(t *testing.T) {
		fc := newFakeControl(t, controlOK())
		notifyRouteChangeBackground(fc.client, "0.0.0.0/0")
		if !waitForControlQuery(t, fc, "what=exits") {
			t.Fatalf("出口路由应触发 exits 重算,收到的是: %v", fc.requests())
		}

		fc2 := newFakeControl(t, controlOK())
		notifyRouteChangeBackground(fc2.client, "192.168.5.0/24")
		if !waitForControlQuery(t, fc2, "what=routes") {
			t.Fatalf("子网路由应触发 routes 重建,收到的是: %v", fc2.requests())
		}
	})
}

// waitForControlQuery 等后台 goroutine 把带某段 query 的请求发到控制面。
func waitForControlQuery(t *testing.T, fc *fakeControl, want string) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range fc.requests() {
			if strings.Contains(r, want) {
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
