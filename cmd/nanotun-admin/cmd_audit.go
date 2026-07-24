package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nanotun/server/store"
)

// cmdAudit 是 audit 子命令的入口,分发到 list。设计上 audit_logs 是 append-only,
// 不提供 admin CLI 删除路径(运维需要清理时直接走 SQLite,且应当备份)。
func cmdAudit(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return usageError(opts.usage("nanotun-admin audit <list> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return cmdAuditList(ctx, st, opts, rest)
	default:
		return newLocErr("cli.unknownSubcommand", "audit", sub)
	}
}

// cmdAuditList 列出最近的审计日志。
//
// --since 默认 24h,--limit 默认 100(server.go audit 量不大,日志主要给排查
// 「为什么这个 device 突然踢线」「谁 takeover 了谁」用,100 条几乎覆盖一天)。
// 上限走 store.QueryAudit 内部的 10000(避免误用 LIMIT 0)。
func cmdAuditList(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	since := fs.Duration("since", 24*time.Hour, opts.T("audit.flag.since"))
	limit := fs.Int("limit", 100, opts.T("audit.flag.limit"))
	// P2#3(2026-05-26):新增 --action 精确过滤,运维排查时对单一 action(如
	// `user_reset_psk` / `login.fail.bad_psk`)能直接拿到结果。**精确匹配**(不是
	// 前缀)— 想要 prefix 匹配请走 SQL 直查或 future --action-prefix flag。
	action := fs.String("action", "", opts.T("audit.flag.action"))
	if err := fs.Parse(args); err != nil {
		// 第十五轮深扫 MED:flag 解析错误(未知 flag / 非法取值 / -h)属**用法错误** → exit 2,与顶层 dispatch /
		// parseInterspersed / 其它 usageError 一致(此前经 runWithStore 恒 exit 1)。
		return usageErrorWrap(err.Error(), err)
	}
	if fs.NArg() != 0 {
		// 第十五轮深扫 LOW:多余位置参数属用法错误 → exit 2。
		return usageError(opts.T("audit.noPositional", fmt.Sprint(fs.Args())))
	}
	if *since <= 0 {
		return errors.New(opts.T("audit.sinceMustPositive"))
	}
	endAt := time.Now().Unix()
	startAt := endAt - int64(since.Seconds())
	// 当 --action 不为空时,把过滤下推到 store(让 LIMIT 在过滤后的结果集生效,
	// 避免「先取前 100 条 → 再 client-side 过滤 → 实际剩 3 条」的反直觉行为)。
	var (
		logs []store.AuditLog
		err  error
	)
	if strings.TrimSpace(*action) != "" {
		logs, err = st.QueryAuditByAction(ctx, startAt, endAt, strings.TrimSpace(*action), *limit)
	} else {
		logs, err = st.QueryAudit(ctx, startAt, endAt, *limit)
	}
	if err != nil {
		return fmt.Errorf("query audit: %w", err)
	}
	if opts.json {
		return json.NewEncoder(opts.stdout).Encode(logs)
	}
	tw := tabwriter.NewWriter(opts.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "AT\tACTOR\tACTION\tTARGET\tDETAIL")
	for _, l := range logs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			time.Unix(l.At, 0).UTC().Format("2006-01-02T15:04:05Z"),
			l.Actor, l.Action, l.Target, l.Detail,
		)
	}
	return tw.Flush()
}
