package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func ageFromUnix(ts int64) string {
	if ts <= 0 {
		return "-"
	}
	d := time.Since(time.Unix(ts, 0)).Round(time.Second)
	if d < 0 {
		return "-"
	}
	return d.String()
}

// P1#6/7/8:admin CLI 控制面命令(reload / kick / connection list)

// cmdReload:`nanotun-admin reload [acl]`
//
// 通过 control socket 触发 server 端 ACL snapshot 重建。当前唯一支持 target 是 acl;
// 后续可扩 log_level / dns_cache 等。
func cmdReload(_ context.Context, _ any, opts *globalOpts, args []string) error {
	what := "acl"
	if len(args) > 0 {
		what = args[0]
	}
	cli := newControlHTTPClient(resolveControlSocketPath(opts.controlSocket))
	out, err := controlDo(cli, "POST", "/reload?what="+what, nil)
	if err != nil {
		return err
	}
	if opts.json {
		fmt.Fprintln(opts.stdout, string(out))
		return nil
	}
	var resp struct {
		OK    bool   `json:"ok"`
		What  string `json:"what"`
		Rules int    `json:"rules"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		fmt.Fprintln(opts.stdout, string(out))
		return nil
	}
	fmt.Fprintln(opts.stdout, opts.T("control.reloaded", resp.What, resp.Rules))
	return nil
}

// cmdKick:`nanotun-admin kick <session|device|user> <id> [--reason TEXT]`
//
// 通过 control socket 让 server 立刻断开指定会话(同时给客户端发 LinkTypeClose
// 以便它 UI 能区分「被踢」与「网络异常」)。
func cmdKick(_ context.Context, _ any, opts *globalOpts, args []string) error {
	if len(args) < 2 {
		return usageError(opts.usage("nanotun-admin kick <session|device|user> <id> [--reason TEXT]"))
	}
	kind, id := args[0], args[1]
	reason := ""
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--reason":
			if i+1 >= len(args) {
				return errors.New(opts.T("control.reasonNeedsArg"))
			}
			reason = args[i+1]
			i++
		default:
			return newLocErr("cli.unknownFlag", args[i])
		}
	}
	body := map[string]any{"kind": kind, "id": id}
	if reason != "" {
		body["reason"] = reason
	}
	cli := newControlHTTPClient(resolveControlSocketPath(opts.controlSocket))
	out, err := controlDo(cli, "POST", "/kick", body)
	if err != nil {
		return err
	}
	if opts.json {
		fmt.Fprintln(opts.stdout, string(out))
		return nil
	}
	var resp struct {
		OK      bool     `json:"ok"`
		Kicked  int      `json:"kicked"`
		ConnIDs []string `json:"conn_ids"`
		Reason  string   `json:"reason"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		fmt.Fprintln(opts.stdout, string(out))
		return nil
	}
	fmt.Fprintln(opts.stdout, opts.T("control.kicked", resp.Kicked, resp.Reason))
	for _, c := range resp.ConnIDs {
		fmt.Fprintf(opts.stdout, "  conn_id=%s\n", c)
	}
	return nil
}

// cmdConnection:`nanotun-admin connection list` / `conn list`
//
// 通过 control socket 拉当前所有在线会话信息;比 SQLite 直读更准(SQLite 只能
// 看到 lease,看不到 active session)。
//
// R6(2026-05-26):支持 --limit / --offset 透传 server 端分页。
//
//	nanotun-admin conn list                  ← 全量(N 大时刷屏)
//	nanotun-admin conn list --limit 10       ← 最新 10 条(server 按 created_at DESC)
//	nanotun-admin conn list --limit 10 --offset 10  ← 第 2 页
//
// S5(2026-05-26):走 controlStatusDo helper(R7 加的 functional options),
// 跟 web client 一套 pattern;原 buildStatusPath + controlDo 直拼路径退役。
func cmdConnection(opts *globalOpts, args []string) int {
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	limit, offset, rest, perr := parseLimitOffsetArgs(args)
	if perr != nil {
		fmt.Fprintln(opts.stderr, opts.errText(perr))
		return 2
	}
	if len(rest) > 0 {
		fmt.Fprintln(opts.stderr, opts.T("cli.unexpectedArgs", fmt.Sprint(rest)))
		return 2
	}
	// 第十二轮深扫 MED:先校验 verb,再拨控制 socket。否则 `connection <bogus>` 会先执行 controlStatusDo,
	// 在 server 不可达时返回 dial 错误(exit 1)、掩盖「未知子命令」本应的 exit 2 —— 退出码随服务端可达性漂移。
	switch sub {
	case "list", "ls", "status":
		// 合法 verb,继续拨号。
	default:
		fmt.Fprintln(opts.stderr, opts.T("cli.unknownSubcommand", "connection", sub))
		return 2
	}
	cli := newControlHTTPClient(resolveControlSocketPath(opts.controlSocket))
	out, err := controlStatusDo(cli, WithLimit(limit), WithOffset(offset))
	if err != nil {
		fmt.Fprintln(opts.stderr, opts.errText(err))
		return 1
	}
	switch sub {
	case "list", "ls":
		if perr := printConnectionList(opts, out); perr != nil {
			fmt.Fprintln(opts.stderr, opts.errText(perr))
			return 1
		}
		return 0
	case "status":
		fmt.Fprintln(opts.stdout, string(out))
		return 0
	default:
		fmt.Fprintln(opts.stderr, opts.T("cli.unknownSubcommand", "connection", sub))
		return 2
	}
}

// parseLimitOffsetArgs(R6, 2026-05-26):提取 --limit N --offset M flag。
//
// 返回 (limit, offset, 剩余非 flag args, error)。
// limit / offset <=0 时按未传处理(返回 0,server 端走全量路径)。
//
// S3(2026-05-26):同时支持 `--limit N`(双 token)与 `--limit=N`(单 token)
// 两种 unix CLI 习惯写法。前者方便脚本拼装,后者方便交互输入。
func parseLimitOffsetArgs(args []string) (limit, offset int, rest []string, err error) {
	rest = make([]string, 0, len(args))
	// extractValue 从「双 token (--flag VALUE)」或「单 token (--flag=VALUE)」拿到 value。
	// 调用前 token 必须是 --flag 或 --flag=...;返回 (value, 消费的额外 token 数, err)。
	extractValue := func(token, flagName string, i int) (string, int, error) {
		// --flag=VALUE 形式:value 已在 token 里,跳过 0 个额外 token。
		if eq := strings.IndexByte(token, '='); eq > 0 {
			return token[eq+1:], 0, nil
		}
		// --flag VALUE 形式:value 是下一个 token,跳过 1 个额外 token。
		if i+1 >= len(args) {
			return "", 0, newLocErr("control.flagNeedsArg", flagName)
		}
		return args[i+1], 1, nil
	}

	for i := 0; i < len(args); i++ {
		tok := args[i]
		switch {
		case tok == "--limit" || strings.HasPrefix(tok, "--limit="):
			val, skip, perr := extractValue(tok, "--limit", i)
			if perr != nil {
				return 0, 0, nil, perr
			}
			v, perr := strconv.Atoi(val)
			if perr != nil || v < 0 {
				return 0, 0, nil, newLocErr("control.limitNonNeg", val)
			}
			limit = v
			i += skip
		case tok == "--offset" || strings.HasPrefix(tok, "--offset="):
			val, skip, perr := extractValue(tok, "--offset", i)
			if perr != nil {
				return 0, 0, nil, perr
			}
			v, perr := strconv.Atoi(val)
			if perr != nil || v < 0 {
				return 0, 0, nil, newLocErr("control.offsetNonNeg", val)
			}
			offset = v
			i += skip
		default:
			rest = append(rest, tok)
		}
	}
	return limit, offset, rest, nil
}

// buildStatusPath(R6, 2026-05-26):根据 limit/offset 构造 /status 路径。
// 等价于 web 端 controlClient.Status() 的 functional options 写法,只是 CLI
// 用纯字符串拼接(避免额外依赖 net/url),不解析。
func buildStatusPath(limit, offset int) string {
	if limit <= 0 && offset <= 0 {
		return "/status"
	}
	if limit > 0 && offset > 0 {
		return fmt.Sprintf("/status?limit=%d&offset=%d", limit, offset)
	}
	if limit > 0 {
		return fmt.Sprintf("/status?limit=%d", limit)
	}
	// offset > 0 && limit == 0:server 会 400(Q2 强校验)。这里也提早 hint。
	return fmt.Sprintf("/status?offset=%d", offset)
}

func printConnectionList(opts *globalOpts, body []byte) error {
	var resp struct {
		OK            bool   `json:"ok"`
		ConnCount     int    `json:"conn_count"`
		ServerVersion string `json:"server_version"`
		Uptime        string `json:"uptime"`
		Sessions      []struct {
			ConnID      string   `json:"conn_id"`
			UserID      string   `json:"user_id"`
			VIPs        []string `json:"vips"`
			CreatedAt   int64    `json:"created_at"`
			ExitAllowed bool     `json:"exit_allowed"`
			BWUpBPS     int64    `json:"bw_up_bps"`
			BWDownBPS   int64    `json:"bw_down_bps"`
		} `json:"sessions"`
		ACLDropTotal  uint64 `json:"acl_drop_total"`
		ACLExitDrops  uint64 `json:"acl_exit_drops"`
		ExitGateDrops uint64 `json:"exit_gate_drops"`
		UserKickTotal uint64 `json:"user_invalidate_kicks"`
		LeaseGCTotal  uint64 `json:"lease_gc_total"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode status: %w", err)
	}
	if opts.json {
		fmt.Fprintln(opts.stdout, string(body))
		return nil
	}
	fmt.Fprintln(opts.stdout, opts.T("status.serverLine", resp.ServerVersion, resp.Uptime))
	fmt.Fprintln(opts.stdout, opts.T("status.countersLine",
		resp.ConnCount, resp.ACLDropTotal, resp.ACLExitDrops, resp.UserKickTotal, resp.LeaseGCTotal))
	t := newTable(opts.stdout, "CONN_ID", "USER", "VIPS", "EXIT", "UP_BPS", "DOWN_BPS", "AGE")
	for _, s := range resp.Sessions {
		exit := "yes"
		if !s.ExitAllowed {
			exit = "no"
		}
		t.row(
			s.ConnID,
			s.UserID,
			joinStrings(s.VIPs, ","),
			exit,
			bpsOrDash(s.BWUpBPS),
			bpsOrDash(s.BWDownBPS),
			ageFromUnix(s.CreatedAt),
		)
	}
	return t.flush()
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return "-"
	}
	out := ss[0]
	for _, s := range ss[1:] {
		out += sep + s
	}
	return out
}

func bpsOrDash(n int64) string {
	if n <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", n)
}
