package main

// control_client_guards_test.go(第二十轮)—— 控制面客户端在「对端答非所问」时的行为。
//
// control_client_test.go 已经覆盖了正常应答与 HTTP 错误码。这里补的是应答体本身
// 不可解析的情形(server 版本对不上、被中间件塞了 HTML 错误页、socket 串了别的服务)。
//
// 为什么要逐个方法钉一遍:这些方法的返回值会被 Web 侧当成「数据面的事实」——
// 重载了几条规则、踢了几个会话、端口有没有监听上。解析失败若被当成零值成功,
// 页面就会理直气壮地显示「已重载 0 条规则」「监听中」,把一次协议不兼容
// 伪装成一次正常操作,运维完全无从察觉。

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// garbageControl:所有路径都回 200 + 一段不是 JSON 的内容(典型场景:socket 后面
// 其实是别的服务,或被反代插了 HTML 错误页)。
func garbageControl(t *testing.T) *controlClient {
	t.Helper()
	garbage := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>not json at all</html>"))
	}
	routes := map[string]http.HandlerFunc{}
	for _, p := range []string{
		"/reload", "/kick", "/rate/refresh", "/users/rate/refresh",
		"/portforward/status", "/rate/config", "/sysmon/counters", "/status",
	} {
		routes[p] = garbage
	}
	return newFakeControl(t, routes).client
}

func TestControlClient_UnparsableRepliesAreErrors(t *testing.T) {
	c := garbageControl(t)
	ctx := t.Context()

	cases := []struct {
		name string
		call func() error
	}{
		{"reload acl", func() error { _, err := c.ReloadACL(ctx); return err }},
		{"reload routes", func() error { _, err := c.ReloadRoutes(ctx); return err }},
		{"reload exits", func() error { _, err := c.ReloadExits(ctx); return err }},
		{"reload port-forwards", func() error { _, err := c.ReloadPortForwards(ctx); return err }},
		{"portforward status", func() error { _, err := c.PortForwardStatus(ctx); return err }},
		{"rate config", func() error { _, err := c.RateConfig(ctx); return err }},
		{"sysmon counters", func() error { _, err := c.SysmonCounters(ctx); return err }},
		{"kick", func() error { _, err := c.Kick(ctx, KickReq{Kind: "user", ID: "1"}); return err }},
		{"rate refresh", func() error { _, err := c.RateRefresh(ctx, 0); return err }},
		{"device sessions", func() error { _, err := c.DeviceSessions(ctx, 1); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("对端回了一段非 JSON,却被当成成功(页面会显示一个编出来的结果)")
			}
		})
	}
}

// server 明确回 ok=false 时不能当成功 —— 那是数据面自己说「我没做成」。
func TestControlClient_ExplicitNotOKIsAnError(t *testing.T) {
	notOK := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"rules":0,"routes":0,"exits":0}`))
	}
	c := newFakeControl(t, map[string]http.HandlerFunc{"/reload": notOK}).client
	ctx := t.Context()

	for name, call := range map[string]func() error{
		"acl":    func() error { _, err := c.ReloadACL(ctx); return err },
		"routes": func() error { _, err := c.ReloadRoutes(ctx); return err },
		"exits":  func() error { _, err := c.ReloadExits(ctx); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("%s: server 回了 ok=false 却被当成重载成功", name)
		}
	}
}

// 没配 control socket 时(构造 Server 的某条路径没装 client)要给一句
// 「控制面不可用」,而不是解引用 panic —— 后者会把整个 Web 后台带下线。
func TestControlClient_NilReceiverSaysUnavailable(t *testing.T) {
	var c *controlClient
	if _, err := c.ReloadACL(t.Context()); err == nil {
		t.Fatal("nil client 却报告重载成功")
	} else if !strings.Contains(err.Error(), "control socket") {
		t.Fatalf("err=%v, 期望说明是控制面没配置", err)
	}
	// 异步的那几个入口对 nil 要直接跳过,不能起一个必然 panic 的 goroutine。
	tryReloadPortForwardsBackground(nil)
	tryReloadACLBackground(nil)
	tryReloadRoutesBackground(nil)
}

// 请求体编不出 JSON、方法名非法时要在发出前就失败。这两条在生产里走不到
// (调用方都传结构体、方法名是常量),但它们是 do() 的守卫:一旦哪天有人
// 把用户输入拼进方法或路径,这里是唯一会拦住的地方。
func TestControlClientDo_RefusesUnsendableRequests(t *testing.T) {
	c := newFakeControl(t, controlOK()).client

	if _, _, err := c.do(t.Context(), http.MethodPost, "/kick", func() {}); err == nil {
		t.Error("编不成 JSON 的请求体却被发了出去")
	}
	if _, _, err := c.do(t.Context(), "BAD METHOD", "/kick", nil); err == nil {
		t.Error("非法的方法名却被发了出去")
	}
}

// 拨不通 socket 时的错误要是可本地化的:这条错会经 renderError 冒泡到浏览器,
// 裸英文/中文混排在另一种语言的界面里很难看,也不便于运维搜索。
func TestControlClientDo_DialFailureIsLocalizable(t *testing.T) {
	c := newControlClient("/nonexistent/nanotun-control.sock")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	_, _, err := c.do(ctx, http.MethodPost, "/reload", nil)
	if err == nil {
		t.Fatal("socket 不存在却拨通了")
	}
	var le *locErr
	if !errors.As(err, &le) {
		t.Fatalf("err=%v(%T), 期望可本地化错误", err, err)
	}
}

// 后台 best-effort 通知失败时只能记日志,不能把失败吞成「已通知」也不能 panic。
// 这里断言的是「确实去敲了数据面」——异步 goroutine 里的失败分支跑到了。
func TestBackgroundNotifiers_SurviveBrokenControl(t *testing.T) {
	fc := newFakeControl(t, controlBroken())
	tryReloadPortForwardsBackground(fc.client)
	waitForControlHits(t, fc, "/reload", 1)

	fc2 := newFakeControl(t, controlBroken())
	tryRateRefreshBackground(fc2.client, 7)
	waitForControlHits(t, fc2, "/rate/refresh", 1)
}
