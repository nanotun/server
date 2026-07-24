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

	type row struct {
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
	var out []row
	for rows.Next() {
		var r row
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
			return errors.New(opts.T("acl.exitRequiresWildcard"))
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
	if opts.json {
		return printJSON(opts.stdout, pair)
	}
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
	fmt.Fprintln(opts.stderr, opts.T("acl.reloadHint"))
	return nil
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
		return fmt.Errorf("%s: %w", opts.T("cli.invalidACLID", args[0]), err)
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
	return nil
}
