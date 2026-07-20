package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// P2#12 admin CLI:subnet_routes 表的列 / 审批 / 删除。
//
// 用法:
//   nanotun-admin route list [--user <username>] [--device <device_id>] [--status pending|approved|rejected]
//   nanotun-admin route approve <device_id> <cidr>
//   nanotun-admin route reject  <device_id> <cidr> [--reason "..."]
//   nanotun-admin route delete  <device_id> <cidr>
//
// 不直接读写客户端,也不会主动推 status 帧(那是 server 端职责);admin 改了
// 状态之后,客户端会在下一次 advertise 或 server 主动 push 时拿到更新。

func cmdRoute(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return errors.New(opts.usage("nanotun-admin route <list|approve|reject|delete> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "ls":
		return cmdRouteList(ctx, st, opts, rest)
	case "approve":
		return cmdRouteApprove(ctx, st, opts, rest)
	case "reject":
		return cmdRouteReject(ctx, st, opts, rest)
	case "delete", "rm":
		return cmdRouteDelete(ctx, st, opts, rest)
	default:
		return newLocErr("cli.unknownSubcommand", "route", sub)
	}
}

func cmdRouteList(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("route list", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	username := fs.String("user", "", opts.T("route.flag.user"))
	deviceID := fs.Int64("device", 0, opts.T("route.flag.device"))
	status := fs.String("status", "", opts.T("route.flag.status"))
	if err := fs.Parse(args); err != nil {
		return err
	}

	var rows []store.SubnetRoute
	var err error
	switch {
	case *deviceID > 0:
		rows, err = st.ListRoutesByDevice(ctx, *deviceID)
	case strings.TrimSpace(*status) != "":
		rows, err = st.ListRoutesByStatus(ctx, *status)
	default:
		rows, err = st.ListAllRoutes(ctx)
	}
	if err != nil {
		return err
	}

	if *username != "" {
		u, err := st.GetUserByUsername(ctx, *username)
		if err != nil {
			return err
		}
		devs, err := st.ListDevicesByUser(ctx, u.ID)
		if err != nil {
			return err
		}
		owned := make(map[int64]struct{}, len(devs))
		for _, d := range devs {
			owned[d.ID] = struct{}{}
		}
		filtered := rows[:0]
		for _, r := range rows {
			if _, ok := owned[r.DeviceID]; ok {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}

	if opts.json {
		return printJSON(opts.stdout, rows)
	}
	t := newTable(opts.stdout, "ID", "DEVICE_ID", "CIDR", "STATUS", "ADV_AT", "APPR_AT", "REASON")
	for _, r := range rows {
		t.row(r.ID, r.DeviceID, r.CIDR, r.Status, fmtTimeUnix(r.AdvertisedAt), fmtTimeUnix(r.ApprovedAt), dashIfEmpty(r.Reason))
	}
	return t.flush()
}

func cmdRouteApprove(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("route approve", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	force := fs.Bool("force", false, opts.T("route.flag.force"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	deviceID, cidr, err := parseRouteTarget(opts, pos)
	if err != nil {
		return fmt.Errorf("%s: %w", opts.usage("nanotun-admin route approve <device_id> <cidr> [--force]"), err)
	}
	// 出口默认路由与 exit designate 同口径的平台闸口(第十五轮深扫):route approve
	// 是逐条批 0/0 的**旁门**,漏掉它等于闸口只焊了一半。--force 语义同 designate。
	// fail-closed:GetDevice 出错时拒绝而非放行(设备不存在时路由行也早被级联删了)。
	if util.IsExitDefaultRoute(cidr) && !*force {
		d, gerr := st.GetDevice(ctx, deviceID)
		if gerr != nil {
			return fmt.Errorf("get device %d: %w", deviceID, gerr)
		}
		if !store.IsExitCapablePlatform(d.Platform) {
			return errors.New(opts.T("exit.platformUnsupported", dashIfEmpty(d.Platform)))
		}
		// owner 禁用检查与 exit designate 同口径:禁用用户的设备是死出口,批了会挂进
		// 所有客户端下拉。--force 越过。
		if owner, oerr := st.GetUser(ctx, d.UserID); oerr != nil {
			return fmt.Errorf("get device owner %d: %w", d.UserID, oerr)
		} else if owner.DisabledAt != 0 {
			return errors.New(opts.T("exit.ownerDisabled", owner.Username))
		}
	}
	if err := st.SetRouteStatus(ctx, deviceID, cidr, util.RouteStatusApproved, ""); err != nil {
		return err
	}
	// 与 web(route_approve)对等的审计。
	_ = st.Audit(ctx, "admin-cli", "route_approve",
		fmt.Sprintf("route:%d/%s", deviceID, cidr), "cidr="+cidr)
	fmt.Fprintln(opts.stdout, opts.T("route.approved", deviceID, cidr))
	// 出口默认路由(0.0.0.0/0 / ::/0)的数据面已落地(exit-node M2):approved 后该 device 在线时,
	// 选它当出口的会话公网流量会真正经它转发。非出口的任意 CIDR subnet route 数据面仍待补。
	if util.IsExitDefaultRoute(cidr) {
		fmt.Fprintln(opts.stderr, opts.T("route.approveExitHint"))
		notifyExitsChanged(opts) // 即时把新批准的出口推给客户端下拉。best-effort。
	} else {
		fmt.Fprintln(opts.stderr, opts.T("route.approveSubnetHint"))
		notifyRoutesChanged(opts) // 即时重建 server 的已批准子网路由表。best-effort。
	}
	return nil
}

func cmdRouteReject(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("route reject", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	reason := fs.String("reason", "", opts.T("route.flag.reason"))
	force := fs.Bool("force", false, opts.T("route.flag.rejectForce"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	deviceID, cidr, err := parseRouteTarget(opts, pos)
	if err != nil {
		return fmt.Errorf("%s: %w", opts.usage("nanotun-admin route reject <device_id> <cidr> [--reason ...] [--force]"), err)
	}
	// 深扫第八轮 MED:与 web(handler_routes.go reject 仅限 pending)对齐 —— reject 只作用于
	// 待审批声明。此前 CLI 无守卫,`route reject` 会把一条 **已 approved** 的路由静默降级为
	// rejected,等于绕过 revoke 路径的一次隐式撤销(web 侧已堵住,CLI 却是缺口)。这里先查
	// 当前状态,非 pending 且未加 --force 直接报错,提示改用 `route delete` 显式撤销。
	if !*force {
		cur, gerr := st.GetRouteByDeviceCIDR(ctx, deviceID, cidr)
		if gerr != nil {
			return gerr
		}
		if cur.Status != util.RouteStatusPending {
			return errors.New(opts.T("route.notPending", deviceID, cidr, cur.Status))
		}
	}
	if err := st.SetRouteStatus(ctx, deviceID, cidr, util.RouteStatusRejected, *reason); err != nil {
		return err
	}
	// 与 web(route_reject)对等的审计。
	_ = st.Audit(ctx, "admin-cli", "route_reject",
		fmt.Sprintf("route:%d/%s", deviceID, cidr),
		fmt.Sprintf("cidr=%s reason=%s", cidr, *reason))
	fmt.Fprintln(opts.stdout, opts.T("route.rejected", deviceID, cidr, *reason))
	if util.IsExitDefaultRoute(cidr) {
		notifyExitsChanged(opts) // 撤销出口 → 即时把绑定它的会话踢回 server + 刷新下拉。best-effort。
	} else {
		notifyRoutesChanged(opts) // 拒绝子网路由 → 即时从 server 的已批准子网路由表移除。best-effort。
	}
	return nil
}

func cmdRouteDelete(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	deviceID, cidr, err := parseRouteTarget(opts, args)
	if err != nil {
		return fmt.Errorf("%s: %w", opts.usage("nanotun-admin route delete <device_id> <cidr>"), err)
	}
	if !opts.yes {
		ok, err := confirm(opts, opts.T("route.confirmDelete", deviceID, cidr))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
			return nil
		}
	}
	if err := st.DeleteRoute(ctx, deviceID, cidr); err != nil {
		return err
	}
	// 与 web(route_delete)对等的审计。
	_ = st.Audit(ctx, "admin-cli", "route_delete",
		fmt.Sprintf("route:%d/%s", deviceID, cidr), "cidr="+cidr)
	fmt.Fprintln(opts.stdout, opts.T("route.deleted", deviceID, cidr))
	if util.IsExitDefaultRoute(cidr) {
		notifyExitsChanged(opts) // 删出口路由 → 即时把绑定它的会话踢回 server + 刷新下拉。best-effort。
	} else {
		notifyRoutesChanged(opts) // 删子网路由 → 即时从 server 的已批准子网路由表移除。best-effort。
	}
	return nil
}

func parseRouteTarget(opts *globalOpts, args []string) (int64, string, error) {
	if len(args) != 2 {
		return 0, "", newLocErr("route.needTwoArgs")
	}
	id, err := parseInt64(args[0])
	if err != nil {
		return 0, "", fmt.Errorf("%s: %w", opts.T("cli.invalidDeviceID", args[0]), err)
	}
	// 用出口语境归一器（允许 0.0.0.0/0 与 ::/0）：出口节点（exit-node）正是靠 admin 批准 device 的 /0
	// 路由来生效；用非出口归一器会把 /0 一律拒掉，导致**根本无法批准出口**。approve/reject/delete 共用
	// 本函数——客户端能 advertise 的 cidr（含 exit 的 /0），admin 都得能按同一字面量引用来审批/拒绝/删除。
	cidr, err := util.NormalizeExitAdvertisedCIDR(args[1])
	if err != nil {
		return 0, "", err
	}
	return id, cidr, nil
}
