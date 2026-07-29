package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/nanotun/server/store"
)

func cmdACL(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return usageError(opts.usage("nanotun-admin acl <list|allow|deny|del> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "ls":
		return cmdACLList(ctx, st, opts, rest)
	case "allow":
		return cmdACLAddPair(ctx, st, opts, rest, store.ACLAllow)
	case "deny":
		return cmdACLAddPair(ctx, st, opts, rest, store.ACLDeny)
	case "del", "delete", "rm":
		return cmdACLDelete(ctx, st, opts, rest)
	default:
		return newLocErr("cli.unknownSubcommand", "acl", sub)
	}
}

func cmdACLList(ctx context.Context, st *store.Store, opts *globalOpts, _ []string) error {
	rows, err := st.DB().QueryContext(ctx, `
		SELECT a.id, a.action, a.proto, a.dst_port_lo, a.dst_port_hi, a.dst_kind, a.created_at,
		       a.src_user_id, COALESCE(us.username, ''),
		       a.dst_user_id, COALESCE(ud.username, '')
		  FROM acl_pairs a
		  LEFT JOIN users us ON us.id = a.src_user_id
		  LEFT JOIN users ud ON ud.id = a.dst_user_id
		 ORDER BY a.id ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var out []aclPairView
	for rows.Next() {
		var r aclPairView
		var srcID, dstID *int64
		if err := rows.Scan(&r.ID, &r.Action, &r.Proto, &r.DstPortLo, &r.DstPortHi, &r.DstKind, &r.CreatedAt, &srcID, &r.SrcUsername, &dstID, &r.DstUsername); err != nil {
			return err
		}
		if srcID != nil {
			r.SrcUserID = *srcID
		}
		if dstID != nil {
			r.DstUserID = *dstID
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if opts.json {
		return printJSON(opts.stdout, out)
	}
	t := newTable(opts.stdout, "ID", "ACTION", "SRC", "DST", "KIND", "PROTO", "PORT", "CREATED_AT")
	for _, r := range out {
		dstCell := formatACLEnd(r.DstUserID, r.DstUsername)
		if r.DstKind == store.ACLDstKindExit {
			dstCell = "<exit>"
		}
		t.row(r.ID, r.Action, formatACLEnd(r.SrcUserID, r.SrcUsername), dstCell, r.DstKind, formatACLProto(r.Proto), formatACLPort(r.DstPortLo, r.DstPortHi), fmtTimeUnix(r.CreatedAt))
	}
	return t.flush()
}

// aclPairView 是 acl 一族 --json 的统一形状。
//
// 2026-07-30:此前 `acl allow/deny --json` 打的是裸 store.ACLPair(没有 json tag,于是键是
// Go 风格的 ID/Action/DstPortLo),而 `acl list --json` 是手写的 snake_case。脚本按 list 的键
// 去读 add 的输出全是零值 —— jq 取不到就是 null,而 CI 里 null 往下走通常不报错,只是把一条
// 「刚建好的规则」当成空的往后传。同一命令族两套形状没有任何理由,统一到 list 那套。
type aclPairView struct {
	ID          int64  `json:"id"`
	Action      string `json:"action"`
	Proto       string `json:"proto,omitempty"`
	DstPortLo   int    `json:"dst_port_lo,omitempty"`
	DstPortHi   int    `json:"dst_port_hi,omitempty"`
	DstKind     string `json:"dst_kind"`
	CreatedAt   int64  `json:"created_at"`
	SrcUserID   int64  `json:"src_user_id,omitempty"`
	SrcUsername string `json:"src_username,omitempty"`
	DstUserID   int64  `json:"dst_user_id,omitempty"`
	DstUsername string `json:"dst_username,omitempty"`
}

// viewFromACLPair 由刚落库的规则拼视图。srcRaw/dstRaw 是命令行原样的两端(用户名或 `*`),
// 通配一端在 list 那侧是 JOIN 不上的空串,这里同样留空。
func viewFromACLPair(p *store.ACLPair, srcRaw, dstRaw string) aclPairView {
	v := aclPairView{
		ID: p.ID, Action: p.Action, Proto: p.Proto,
		DstPortLo: p.DstPortLo, DstPortHi: p.DstPortHi,
		DstKind: p.DstKind, CreatedAt: p.CreatedAt,
		SrcUserID: p.SrcUserID, DstUserID: p.DstUserID,
	}
	if srcRaw != "*" {
		v.SrcUsername = srcRaw
	}
	if dstRaw != "*" {
		v.DstUsername = dstRaw
	}
	return v
}

func formatACLProto(p string) string {
	if p == "" {
		return "*"
	}
	return p
}

func formatACLPort(lo, hi int) string {
	if lo == 0 && hi == 0 {
		return "*"
	}
	if lo == hi {
		return fmt.Sprintf("%d", lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

func formatACLEnd(id int64, username string) string {
	if id == 0 {
		return "*"
	}
	if username == "" {
		return fmt.Sprintf("#%d", id)
	}
	return fmt.Sprintf("%s(#%d)", username, id)
}

// cmdACLAddPair 处理 `acl allow|deny <src_user> <dst_user> [flags]`。
//
// flags(ACL v2):
//
//	--proto <tcp|udp|icmp|icmpv6>     默认 ''(任意)
//	--port  <N>                       单端口
//	--port-range <LO-HI>              端口范围(闭)
//	--exit                            规则匹配「dst 不是任何 vIP 的出口流量」
//	                                  此时 <dst_user> 必须传 `*`
//
// 不带任何 flag 时退化为 v1 的「src 用户 → dst 用户,任意 proto/端口」规则。
func cmdACLAddPair(ctx context.Context, st *store.Store, opts *globalOpts, args []string, action string) error {
	flags, positional, err := splitACLAddFlags(args)
	if err != nil {
		return err
	}
	if len(positional) != 2 {
		return usageError(opts.usage(fmt.Sprintf("nanotun-admin acl %s <src_user|*> <dst_user|*> [--proto X --port N --port-range LO-HI --exit]", action)))
	}
	src, err := resolveUserOrWildcard(ctx, st, opts, positional[0])
	if err != nil {
		return err
	}
	dstRaw := positional[1]
	dstKind := store.ACLDstKindUser
	if flags.exit {
		if dstRaw != "*" {
			// 第十六轮深扫 LOW:`--exit` 要求 dst 传 `*` 属**用法错误** → exit 2(与本仓 usageError 约定一致;
			// 此前 errors.New 恒 exit 1)。
			return usageError(opts.T("acl.exitRequiresWildcard"))
		}
		dstKind = store.ACLDstKindExit
	}
	dst, err := resolveUserOrWildcard(ctx, st, opts, dstRaw)
	if err != nil {
		return err
	}
	pair, err := st.AddACLPair(ctx, store.NewACLPair{
		SrcUserID: src,
		DstUserID: dst,
		Action:    action,
		Proto:     flags.proto,
		DstPortLo: flags.portLo,
		DstPortHi: flags.portHi,
		DstKind:   dstKind,
	})
	if err != nil {
		return err
	}
	// 与 web(acl_add)对等的审计:ACL 变更直接影响数据面放行/拦截,须可归因。
	_ = st.Audit(ctx, "admin-cli", "acl_add",
		fmt.Sprintf("acl:%d", pair.ID),
		fmt.Sprintf("action=%s src=%s dst=%s kind=%s proto=%s port=%s",
			pair.Action, positional[0], dstRaw, pair.DstKind,
			formatACLProto(pair.Proto), formatACLPort(pair.DstPortLo, pair.DstPortHi)))
	// 第二十二轮:此前 --json 在这里直接 return,把后面的**通知 server + reload 提示 + 缺回程告警**
	// 一并跳过了 —— 脚本化加规则(CI / 编排工具)于是拿到一条「已创建」的 JSON,而数据面的 ACL
	// snapshot 从没刷过,规则静默不生效;同一文件里的 acl del 反倒一直通知,两条路口径相反。
	// 这些输出全在 stderr,不会污染 --json 的机器可读 stdout,没有理由分叉。
	if opts.json {
		if err := printJSON(opts.stdout, viewFromACLPair(pair, positional[0], dstRaw)); err != nil {
			return err
		}
	} else {
		dstCell := formatACLEnd(pair.DstUserID, dstRaw)
		if pair.DstKind == store.ACLDstKindExit {
			dstCell = "<exit>"
		}
		fmt.Fprintln(opts.stdout, opts.T("acl.added",
			pair.ID,
			formatACLEnd(pair.SrcUserID, positional[0]), dstCell,
			pair.DstKind, formatACLProto(pair.Proto), formatACLPort(pair.DstPortLo, pair.DstPortHi),
			pair.Action,
		))
	}
	// 落库 ≠ 生效:数据面读的是内存里的 ACL snapshot。不通知就只是往列表里摆了一条没有约束力的规则。
	if notifyACLChanged(opts) {
		fmt.Fprintln(opts.stderr, opts.T("acl.reloaded"))
	} else {
		fmt.Fprintln(opts.stderr, opts.T("acl.reloadHint"))
	}
	warnAllowNeedsReverse(ctx, st, opts, pair, positional[0], dstRaw)
	return nil
}

// warnAllowNeedsReverse:默认动作是 deny 时,单加一条 `allow A B` **不足以**让 A 和 B 通 ——
// ACL 按包判、无连接状态,回程包在数据面是独立的 B→A,还得有自己的 allow。
//
// 2026-07-26 三机实测:acl_default_action=deny + 只有 `allow testcli u4` 时,A→C 的 ping
// 全丢、acl_drop_total 持续涨;补上 `allow u4 testcli` 后立刻通。命令本身打的是
// 「已新增 ACL 规则 #16 … (allow)」,看不出还缺一半,管理员会以为 ACL 坏了或规则没生效
// (跟 acl 落库不通知那次的观感一样,只是这次卡在语义而不是通知)。
//
// 只在真会踩的组合上吼:action=allow、两端都是具体用户(带 * 的通配本身就覆盖了回程)、
// 默认动作为 deny、且当前确实没有覆盖回程的 allow。exit 规则不涉及回程方向,跳过。
func warnAllowNeedsReverse(ctx context.Context, st *store.Store, opts *globalOpts, pair *store.ACLPair, srcRaw, dstRaw string) {
	if pair.Action != "allow" || pair.DstKind != store.ACLDstKindUser {
		return
	}
	if srcRaw == "*" || dstRaw == "*" {
		return
	}
	if v, ok, err := st.SettingsGet(ctx, "acl_default_action"); err != nil || !ok || v != "deny" {
		return
	}
	rules, err := st.ListACLPairs(ctx)
	if err != nil {
		return
	}
	for _, r := range rules {
		if r.Action != "allow" || r.DstKind != store.ACLDstKindUser {
			continue
		}
		// 覆盖回程 = src 侧能匹配原 dst、dst 侧能匹配原 src(0 表示通配 *)。
		srcOK := r.SrcUserID == pair.DstUserID || r.SrcUserID == 0
		dstOK := r.DstUserID == pair.SrcUserID || r.DstUserID == 0
		if srcOK && dstOK {
			return
		}
	}
	fmt.Fprintln(opts.stderr, opts.T("acl.allowNeedsReverse", dstRaw, srcRaw))
}

type aclAddFlags struct {
	proto  string
	portLo int
	portHi int
	exit   bool
}

func splitACLAddFlags(args []string) (aclAddFlags, []string, error) {
	var f aclAddFlags
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--proto":
			if i+1 >= len(args) {
				return f, nil, newLocErr("acl.protoNeedsArg")
			}
			f.proto = args[i+1]
			i++
		case len(a) > len("--proto=") && a[:len("--proto=")] == "--proto=":
			f.proto = a[len("--proto="):]
		case a == "--port":
			if i+1 >= len(args) {
				return f, nil, newLocErr("acl.portNeedsArg")
			}
			n, perr := parseInt64(args[i+1])
			if perr != nil {
				return f, nil, newLocErr("acl.portInvalid", args[i+1], perr.Error())
			}
			f.portLo = int(n)
			f.portHi = int(n)
			i++
		case a == "--port-range":
			if i+1 >= len(args) {
				return f, nil, newLocErr("acl.portRangeNeedsArg")
			}
			lo, hi, perr := parsePortRange(args[i+1])
			if perr != nil {
				return f, nil, perr
			}
			f.portLo, f.portHi = lo, hi
			i++
		case a == "--exit":
			f.exit = true
		default:
			positional = append(positional, a)
		}
	}
	return f, positional, nil
}

func parsePortRange(s string) (int, int, error) {
	dash := -1
	for i, c := range s {
		if c == '-' {
			dash = i
			break
		}
	}
	if dash <= 0 || dash == len(s)-1 {
		return 0, 0, newLocErr("acl.portRangeForm", s)
	}
	lo, err := parseInt64(s[:dash])
	if err != nil {
		return 0, 0, newLocErr("acl.portRangeLoInvalid", s[:dash], err.Error())
	}
	hi, err := parseInt64(s[dash+1:])
	if err != nil {
		return 0, 0, newLocErr("acl.portRangeHiInvalid", s[dash+1:], err.Error())
	}
	if lo > hi {
		return 0, 0, newLocErr("acl.portRangeLoGtHi", s)
	}
	return int(lo), int(hi), nil
}

// resolveUserOrWildcard 把命令行里的 src/dst 参数转成 store ID。
//   - "*" 表示通配（NULL 写入），返回 0；
//   - 否则按 username 查找。
func resolveUserOrWildcard(ctx context.Context, st *store.Store, opts *globalOpts, raw string) (int64, error) {
	if raw == "*" {
		return 0, nil
	}
	u, err := st.GetUserByUsername(ctx, raw)
	if err != nil {
		return 0, opts.notFoundErr(err, "user.notFound", raw)
	}
	return u.ID, nil
}

func cmdACLDelete(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) != 1 {
		return usageError(opts.usage("nanotun-admin acl del <id>"))
	}
	id, err := parseInt64(args[0])
	if err != nil {
		// 第十六轮深扫 LOW:非法 <id> 参数属用法错误 → exit 2(与 acl del 缺参 / 顶层 dispatch 一致)。
		return usageErrorWrap(fmt.Sprintf("%s: %v", opts.T("cli.invalidACLID", args[0]), err), err)
	}
	if err := st.DeleteACLPair(ctx, id); err != nil {
		// 深扫第十轮 LOW:本地化 ErrNotFound(与 route 各 verb 同款,此前裸抛 store 英文错误)。
		if errors.Is(err, store.ErrNotFound) {
			return errors.New(opts.T("acl.notFound", id))
		}
		return err
	}
	// 与 web(acl_delete)对等的审计。
	_ = st.Audit(ctx, "admin-cli", "acl_delete",
		fmt.Sprintf("acl:%d", id), "")
	fmt.Fprintln(opts.stdout, opts.T("acl.deleted", id))
	// 删除同样要刷 snapshot:否则被删掉的 deny 规则还会继续拦流量(而列表里已经没有它了,
	// 排障时无从下手)。
	if notifyACLChanged(opts) {
		fmt.Fprintln(opts.stderr, opts.T("acl.reloaded"))
	} else {
		fmt.Fprintln(opts.stderr, opts.T("acl.reloadHint"))
	}
	return nil
}
