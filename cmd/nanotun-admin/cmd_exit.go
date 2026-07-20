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

// nanotun-admin exit —— 把一台设备「一键指定为公网出口节点」。
//
// 出口节点是**基础设施**,身份/地址应当稳定(详见 docs/DESIGN_EXIT_NODE.md):
//   - device UUID 是审批(approve)与客户端 EgressSelect 选择的**稳定键** —— UUID 一变,该出口对所有
//     已选它的客户端就「失踪」(saved 选择静默回落 server 自出口),且需 admin 重新审批。
//   - 固定 vIP 让出口在 mesh 内有稳定地址(便于 ACL 例外 / 监控 / 出口上跑服务)。注意出口**数据面按 device
//     转发,不按 vIP**,故固定 vIP 是基础设施卫生/未来留量,不是出网必要条件;UUID 稳定才是必需。
//
// 本命令把原先分散的 `route approve <id> 0/0` + `route approve <id> ::/0` + `device set-fixed-vip` 合成
// 一条**原子流程**,避免漏步。
//
// 用法:
//
//	nanotun-admin exit designate <device_id> [--v4 IP] [--v6 IP] [--no-vip] [--force]
//	    批准该 device 的 0.0.0.0/0 + ::/0(数据面已落地),并钉死固定 vIP。
//	    --v4/--v6 不给 → 默认钉死该 device **当前 lease** 的 vIP(把现有地址焊死);给则用指定值;
//	    空串 → 不动该地址族;--no-vip → 只批准出口路由不碰 vIP;--force → 跳过 vIP 冲突检查。
//	nanotun-admin exit list [--json]
//	    列出所有出口(有 approved 0/0 或 ::/0 的 device)及其固定 vIP。
//	nanotun-admin exit revoke <device_id> [--clear-vip] [--yes]
//	    撤销出口:删除该 device 的 0.0.0.0/0 + ::/0 approved 路由;--clear-vip 同时清掉固定 vIP。
func cmdExit(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return errors.New(opts.usage("nanotun-admin exit <designate|list|revoke> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "designate", "set":
		return cmdExitDesignate(ctx, st, opts, rest)
	case "list", "ls":
		return cmdExitList(ctx, st, opts, rest)
	case "revoke", "unset":
		return cmdExitRevoke(ctx, st, opts, rest)
	default:
		return newLocErr("cli.unknownSubcommand", "exit", sub)
	}
}

// exitIsReadOnly: exit list 只读;designate/revoke 写 subnet_routes / devices。
func exitIsReadOnly(rest []string) bool {
	if len(rest) == 0 {
		return true
	}
	switch rest[0] {
	case "list", "ls":
		return true
	default:
		return false
	}
}

// exitVIPAutoSentinel:--v4/--v6 的默认占位,表示「钉死当前 lease 的 vIP」(区别于显式空串「不动」)。
const exitVIPAutoSentinel = "<auto>"

func cmdExitDesignate(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("exit designate", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	v4 := fs.String("v4", exitVIPAutoSentinel, opts.T("exit.flag.v4"))
	v6 := fs.String("v6", exitVIPAutoSentinel, opts.T("exit.flag.v6"))
	noVip := fs.Bool("no-vip", false, opts.T("exit.flag.noVip"))
	force := fs.Bool("force", false, opts.T("exit.flag.force"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(opts.usage("nanotun-admin exit designate <device_id> [--v4 IP] [--v6 IP] [--no-vip] [--force]"))
	}
	id, err := parseInt64(pos[0])
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("cli.invalidDeviceID", pos[0]), err)
	}
	d, err := st.GetDevice(ctx, id)
	if err != nil {
		return fmt.Errorf("get device %d: %w", id, err)
	}

	// 平台闸口(与 web /routes/exit/designate 同口径):iOS/Android 只有用户态 VPN
	// 隧道、无内核 NAT,批了也只是焊一纸批准。CLI 保留 --force 逃生口 —— 平台 token
	// 异常(legacy 空值 / 新平台未入白名单)时运维可显式越过;web 端无此后门。
	if !store.IsExitCapablePlatform(d.Platform) && !*force {
		return errors.New(opts.T("exit.platformUnsupported", dashIfEmpty(d.Platform)))
	}

	// 禁用用户的设备连不上 server:批了就是死出口挂进所有客户端下拉(buildExitsList
	// 连离线出口一起推)。与 web /routes/exit/designate 同口径拦截;--force 保留逃生口。
	if owner, oerr := st.GetUser(ctx, d.UserID); oerr != nil {
		return fmt.Errorf("get device owner %d: %w", d.UserID, oerr)
	} else if owner.DisabledAt != 0 && !*force {
		return errors.New(opts.T("exit.ownerDisabled", owner.Username))
	}

	// 1) 批准 0.0.0.0/0 + ::/0：upsert(创建 pending,幂等) 再 approve —— 即便该设备尚未 advertise 出口
	//    也能**预先焊死**,设备之后跑 --exit-node 连上即已批准。
	for _, cidr := range []string{util.ExitDefaultRouteV4, util.ExitDefaultRouteV6} {
		if _, err := st.UpsertAdvertisedRoute(ctx, id, cidr); err != nil {
			return fmt.Errorf("upsert route %s: %w", cidr, err)
		}
		if err := st.SetRouteStatus(ctx, id, cidr, util.RouteStatusApproved, ""); err != nil {
			return fmt.Errorf("approve route %s: %w", cidr, err)
		}
	}

	// 2) 钉死固定 vIP（默认把当前 lease 焊死；--v4/--v6 指定；--no-vip 跳过）。
	pinnedV4, pinnedV6 := d.FixedVIPv4, d.FixedVIPv6
	if !*noVip {
		var lease *store.Lease
		if *v4 == exitVIPAutoSentinel || *v6 == exitVIPAutoSentinel {
			if l, lerr := st.GetLeaseByDevice(ctx, id); lerr == nil {
				lease = l
			}
		}
		newV4 := d.FixedVIPv4
		switch *v4 {
		case exitVIPAutoSentinel:
			if lease != nil && lease.VIPv4 != "" {
				newV4 = lease.VIPv4
			}
		case "":
			// 显式空串:不动 v4。
		default:
			newV4 = strings.TrimSpace(*v4)
		}
		newV6 := d.FixedVIPv6
		switch *v6 {
		case exitVIPAutoSentinel:
			if lease != nil && lease.VIPv6 != "" {
				newV6 = lease.VIPv6
			}
		case "":
		default:
			newV6 = strings.TrimSpace(*v6)
		}
		// 冲突检查（仅对真的变了的值；--force 跳过）。
		if newV4 != d.FixedVIPv4 {
			if c, cerr := findFixedVIPConflict(ctx, st, opts, newV4, id); cerr != nil {
				return cerr
			} else if c != "" && !*force {
				return errors.New(opts.T("exit.conflictV4", newV4, c))
			}
		}
		if newV6 != d.FixedVIPv6 {
			if c, cerr := findFixedVIPConflict(ctx, st, opts, newV6, id); cerr != nil {
				return cerr
			} else if c != "" && !*force {
				return errors.New(opts.T("exit.conflictV6", newV6, c))
			}
		}
		if newV4 != d.FixedVIPv4 || newV6 != d.FixedVIPv6 {
			if err := st.SetDeviceFixedVIP(ctx, id, newV4, newV6); err != nil {
				return fmt.Errorf("set fixed vip: %w", err)
			}
		}
		pinnedV4, pinnedV6 = newV4, newV6
		if pinnedV4 == "" && pinnedV6 == "" {
			fmt.Fprintln(opts.stderr, opts.T("exit.warnNoVIP"))
		}
	}

	_ = st.Audit(ctx, "admin-cli", "exit_designate",
		fmt.Sprintf("device:%d", id),
		fmt.Sprintf("uuid=%s fixed_v4=%s fixed_v6=%s", d.DeviceUUID, pinnedV4, pinnedV6))

	fmt.Fprintln(opts.stdout, opts.T("exit.designated",
		id, d.DeviceUUID, dashIfEmpty(d.DeviceName),
		util.ExitDefaultRouteV4, util.ExitDefaultRouteV6,
		dashIfEmpty(pinnedV4), dashIfEmpty(pinnedV6)))
	fmt.Fprintln(opts.stderr, opts.T("exit.designatedHint"))
	// 即时通知 server 重算/推送出口列表(新批准的出口立刻进客户端下拉)。best-effort。
	notifyExitsChanged(opts)
	return nil
}

func cmdExitList(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	rows, err := st.ListRoutesByStatus(ctx, util.RouteStatusApproved)
	if err != nil {
		return err
	}
	type exitRow struct {
		DeviceID   int64  `json:"device_id"`
		DeviceUUID string `json:"device_uuid"`
		DeviceName string `json:"device_name"`
		HasV4Exit  bool   `json:"has_v4_exit"`
		HasV6Exit  bool   `json:"has_v6_exit"`
		FixedVIPv4 string `json:"fixed_vip_v4"`
		FixedVIPv6 string `json:"fixed_vip_v6"`
	}
	byDev := map[int64]*exitRow{}
	order := make([]int64, 0)
	for _, r := range rows {
		if !util.IsExitDefaultRoute(r.CIDR) {
			continue
		}
		er, ok := byDev[r.DeviceID]
		if !ok {
			er = &exitRow{DeviceID: r.DeviceID}
			byDev[r.DeviceID] = er
			order = append(order, r.DeviceID)
		}
		switch r.CIDR {
		case util.ExitDefaultRouteV4:
			er.HasV4Exit = true
		case util.ExitDefaultRouteV6:
			er.HasV6Exit = true
		}
	}
	out := make([]exitRow, 0, len(order))
	for _, id := range order {
		er := byDev[id]
		if d, derr := st.GetDevice(ctx, id); derr == nil && d != nil {
			er.DeviceUUID = d.DeviceUUID
			er.DeviceName = d.DisplayName() // alias(0020):展示名优先管理员别名
			er.FixedVIPv4 = d.FixedVIPv4
			er.FixedVIPv6 = d.FixedVIPv6
		}
		out = append(out, *er)
	}
	if opts.json {
		return printJSON(opts.stdout, out)
	}
	t := newTable(opts.stdout, "DEVICE_ID", "UUID", "NAME", "V4_EXIT", "V6_EXIT", "FIXED_V4", "FIXED_V6")
	for _, e := range out {
		t.row(e.DeviceID, e.DeviceUUID, dashIfEmpty(e.DeviceName),
			exitMark(e.HasV4Exit), exitMark(e.HasV6Exit),
			dashIfEmpty(e.FixedVIPv4), dashIfEmpty(e.FixedVIPv6))
	}
	return t.flush()
}

func cmdExitRevoke(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("exit revoke", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	clearVip := fs.Bool("clear-vip", false, opts.T("exit.flag.clearVip"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(opts.usage("nanotun-admin exit revoke <device_id> [--clear-vip] [--yes]"))
	}
	id, err := parseInt64(pos[0])
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("cli.invalidDeviceID", pos[0]), err)
	}
	d, err := st.GetDevice(ctx, id)
	if err != nil {
		return fmt.Errorf("get device %d: %w", id, err)
	}
	if !opts.yes {
		ok, cerr := confirm(opts, opts.T("exit.confirmRevoke", id, d.DeviceUUID))
		if cerr != nil {
			return cerr
		}
		if !ok {
			fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
			return nil
		}
	}
	removed := make([]string, 0, 2)
	for _, cidr := range []string{util.ExitDefaultRouteV4, util.ExitDefaultRouteV6} {
		err := st.DeleteRoute(ctx, id, cidr)
		switch {
		case err == nil:
			removed = append(removed, cidr)
		case errors.Is(err, store.ErrNotFound):
			// 本就没有该出口路由,跳过。
		default:
			return fmt.Errorf("delete route %s: %w", cidr, err)
		}
	}
	if *clearVip {
		if err := st.SetDeviceFixedVIP(ctx, id, "", ""); err != nil {
			return fmt.Errorf("clear fixed vip: %w", err)
		}
	}
	_ = st.Audit(ctx, "admin-cli", "exit_revoke",
		fmt.Sprintf("device:%d", id),
		fmt.Sprintf("uuid=%s removed=%v clear_vip=%v", d.DeviceUUID, removed, *clearVip))
	fmt.Fprintln(opts.stdout, opts.T("exit.revoked",
		id, d.DeviceUUID, fmt.Sprintf("%v", removed), *clearVip))
	// 即时通知 server:把正绑定该出口的在线会话踢回 server 自出口 + 刷新下拉。best-effort。
	notifyExitsChanged(opts)
	return nil
}

func exitMark(b bool) string {
	if b {
		return "✓"
	}
	return "-"
}
