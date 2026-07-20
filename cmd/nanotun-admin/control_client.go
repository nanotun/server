package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// P1#6/7/8:admin <-> server 控制面 client
//
// admin CLI 通过 unix socket 与 server 通信。server 端实现见
// nanotun/server/control_socket.go。
//
// 路径优先级:
//   1. --control-socket=PATH 命令行 flag
//   2. NANOTUN_CONTROL_SOCKET 环境变量
//   3. 默认 /run/nanotun/control.sock

const defaultControlSocketPath = "/run/nanotun/control.sock"

func resolveControlSocketPath(override string) string {
	if override != "" {
		return override
	}
	if v := strings.TrimSpace(os.Getenv("NANOTUN_CONTROL_SOCKET")); v != "" {
		return v
	}
	return defaultControlSocketPath
}

// newControlHTTPClient 返回一个经 unix socket 转发的 http.Client。
// 任何 URL 的 host 都会被忽略,实际请求发到指定 socket 上。
func newControlHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// notifyExitsChanged best-effort 通知**运行中的 server** 复核/重算出口(POST /reload?what=exits):
//   - 撤销出口(exit revoke / route reject|delete 0/0) → server 即时把绑定它的会话踢回 server 自出口 + 通知客户端;
//   - 新批准/变更(exit designate / route approve 0/0) → server 即时把可选出口列表推给客户端下拉。
//
// best-effort:server 没在跑 / socket 不可达只打一行提示,**不让 admin 命令失败** —— DB 改动已落地,
// 即便没即时通知,也会在「客户端重连 / 下次任意出口上下线」时自然收敛。
func notifyExitsChanged(opts *globalOpts) {
	cli := newControlHTTPClient(resolveControlSocketPath(opts.controlSocket))
	if _, err := controlDo(cli, "POST", "/reload?what=exits", nil); err != nil {
		fmt.Fprintln(opts.stderr, opts.T("control.notifyExitsFail", err.Error()))
	}
}

// notifyRoutesChanged best-effort 通知**运行中的 server** 重建「已批准子网路由表」(POST /reload?what=routes):
// admin approve/reject/delete 了**非 0/0**的子网路由(具体 CIDR)后调用,让 server 即时把改动反映进 per-packet
// 最长前缀匹配的数据源。
//
// best-effort:server 没在跑 / socket 不可达只打一行提示,**不让 admin 命令失败** —— DB 改动已落地,
// 即便没即时通知,也会在 server 下次启动 / 下次任意 /reload?what=routes 时收敛。
func notifyRoutesChanged(opts *globalOpts) {
	cli := newControlHTTPClient(resolveControlSocketPath(opts.controlSocket))
	if _, err := controlDo(cli, "POST", "/reload?what=routes", nil); err != nil {
		fmt.Fprintln(opts.stderr, opts.T("control.notifyRoutesFail", err.Error()))
	}
}

// StatusOptions(R7, 2026-05-26):跟 nanotun-web/control_client.go 的同名结构
// 对齐,让 admin CLI / web 用同一套 pattern 表达「拉 /status 分页」意图。
//
// 之前 admin CLI 直接 controlDo(cli, "GET", path, nil) 拼字符串,web 用 functional
// options;两者协议一致(都打到同一个 server 端点)但代码风格漂移,加 server 端
// query 时容易只改一处忘另一处。统一后,任何 /status 调用都走 StatusOptions →
// buildStatusURL → controlDo,只读 server side 协议变化只动 buildStatusURL。
type StatusOptions struct {
	Limit  int
	Offset int
}

type StatusOption func(*StatusOptions)

func WithLimit(n int) StatusOption  { return func(o *StatusOptions) { o.Limit = n } }
func WithOffset(n int) StatusOption { return func(o *StatusOptions) { o.Offset = n } }

// controlStatusDo:封装 GET /status 带可选分页 opts。
//
// 调用方写起来跟 web 一致 — `controlStatusDo(cli, WithLimit(10))`,
// 无需关心 query 拼装。S5(2026-05-26):cmdConnection 改用本 helper,
// 不再有 functional options 跟 path 字符串拼接两套写法并存。
func controlStatusDo(client *http.Client, opts ...StatusOption) ([]byte, error) {
	cfg := StatusOptions{}
	for _, o := range opts {
		o(&cfg)
	}
	return controlDo(client, "GET", buildStatusPath(cfg.Limit, cfg.Offset), nil)
}

// controlDo 发送 HTTP 请求到 control socket,返回解析好的 JSON / 原始 body。
//
// 失败模式:
//   - socket 不存在 → 提示 server 未运行 / 路径未匹配;
//   - 非 2xx → 把 body 当成 error message 透传给用户。
func controlDo(client *http.Client, method, path string, body any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, "http://unix"+path, reqBody)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", newLocErr("control.socketReqFail").Error(), err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return out, newLocErr("control.serverReturned", resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return out, nil
}
