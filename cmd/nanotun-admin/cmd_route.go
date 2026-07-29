package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
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
		return usageError(opts.usage("nanotun-admin route <list|approve|reject|delete> [...]"))
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
		// 第十五轮深扫 MED:flag 解析错误属用法错误 → exit 2(与 dispatch / parseInterspersed 一致)。
		return usageErrorWrap(err.Error(), err)
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
			return opts.notFoundErr(err, "user.notFound", *username)
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
		return usageErrorWrap(opts.usage("nanotun-admin route approve <device_id> <cidr> [--force]"), err)
	}
	// 出口默认路由与 exit designate 同口径的平台闸口(第十五轮深扫):route approve
	// 是逐条批 0/0 的**旁门**,漏掉它等于闸口只焊了一半。--force 语义同 designate。
	// fail-closed:GetDevice 出错时拒绝而非放行(设备不存在时路由行也早被级联删了)。
	if util.IsExitDefaultRoute(cidr) && !*force {
		d, gerr := st.GetDevice(ctx, deviceID)
		if gerr != nil {
			return opts.notFoundErr(gerr, "device.notFound", deviceID)
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
	// 第十八轮深扫 MED:批准期拒绝与 server 自身 mesh 网段交叠的**具体**子网路由(0/0 / ::/0 出口是特例,不检查
	// —— 它按 IsExitDefaultRoute 交给出口路径、不进子网路由表)。交叠会让发往「当前离线的 mesh 地址」的包被子网
	// 路由中继进宣告方 LAN(跨信任域泄漏)。mesh 网段快照由 server 启动落库(mesh_cidrs);读不到(server 从未跑
	// 过 / 老库)则跳过本检查,由数据面 rebuild 兜底。--force 不越过——重叠是**配置错误**而非策略权衡。
	if !util.IsExitDefaultRoute(cidr) {
		meshCIDRs, merr := st.GetMeshCIDRs(ctx)
		if merr != nil {
			return fmt.Errorf("get mesh cidrs: %w", merr)
		}
		if util.CIDROverlapsAny(cidr, meshCIDRs) {
			return errors.New(opts.T("route.overlapsMesh", cidr))
		}
	}
	if err := st.SetRouteStatus(ctx, deviceID, cidr, util.RouteStatusApproved, ""); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.New(opts.T("route.notFound", deviceID, cidr))
		}
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
		warnDuplicateApprovedCIDR(ctx, st, opts, deviceID, cidr)
		warnOverlappingApprovedCIDR(ctx, st, opts, deviceID, cidr)
		notifyRoutesChanged(opts) // 即时重建 server 的已批准子网路由表。best-effort。
	}
	return nil
}

// warnDuplicateApprovedCIDR 在「同一 CIDR 已被批给另一台设备」时告警。
//
// 数据面对此有确定性 tiebreak(lookupSubnetRoute:最长前缀优先,同长度取**最小 deviceID**),所以行为是
// 可预期的、不需要再定语义 —— 但 admin 侧此前没有任何提示:较小 deviceID 静默胜出,另一台宣告方成为死重
// (它身后的 LAN 经 mesh 完全不可达),而 admin 以为两台都在服务、甚至以为做到了冗余/负载分担。
//
// 只告警不阻断:为计划中的路由器替换而让两条同时 approved 一段时间是合理操作。只比**完全相同**的 CIDR ——
// 不同掩码长度的交叠由最长前缀匹配定义得很清楚,那是有意行为,不该噪扰。
func warnDuplicateApprovedCIDR(ctx context.Context, st *store.Store, opts *globalOpts, deviceID int64, cidr string) {
	routes, err := st.ListRoutesByStatus(ctx, util.RouteStatusApproved)
	if err != nil {
		return // best-effort:查不到就不提示,绝不影响 approve 本身
	}
	others := make([]int64, 0, 2)
	for _, r := range routes {
		if r.DeviceID != deviceID && r.CIDR == cidr {
			others = append(others, r.DeviceID)
		}
	}
	if len(others) == 0 {
		return
	}
	sort.Slice(others, func(i, j int) bool { return others[i] < others[j] })
	// 胜出者 = 所有持有该 CIDR 的设备里 deviceID 最小的那个(与 lookupSubnetRoute 同口径)。
	winner := deviceID
	if others[0] < winner {
		winner = others[0]
	}
	strs := make([]string, 0, len(others))
	for _, d := range others {
		strs = append(strs, strconv.FormatInt(d, 10))
	}
	fmt.Fprintln(opts.stderr, opts.T("route.duplicateCIDR", cidr, strings.Join(strs, ", "), winner))
}

// warnOverlappingApprovedCIDR 在「批准的网段与另一台设备已批准的网段**交叠但掩码不同**」时告警。
//
// 与 warnDuplicateApprovedCIDR 分开:那条只比完全相同的 CIDR,理由是「不同掩码的交叠由最长前缀匹配
// 定义得很清楚,是有意行为」。定义清楚归定义清楚,后果不轻 —— 2026-07-26 三机实测:C 宣告一条嵌套在
// A 已批准的 172.20.10.0/24 里的 172.20.10.0/25,admin 照着 route list 批准之后,A 身后那台真实主机
// (172.20.10.10)对**所有请求方**当场失联:最长前缀选中 C,而 C 身后根本没有这个网段 —— 请求方是 C
// 自己时命中自指分支被丢,是第三方时投给 C 后无处可去。route list 里两条都是 approved、看不出谁盖了谁。
//
// 也就是说,任何允许宣告路由的客户端都能靠一条更长掩码悄悄截走别人网段里的一段。同样只告警不阻断
// (把某个 /32 专门指给另一台网关是合理用法),但要把「谁在这段地址上胜出」当场说清楚。
func warnOverlappingApprovedCIDR(ctx context.Context, st *store.Store, opts *globalOpts, deviceID int64, cidr string) {
	newPfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return
	}
	routes, err := st.ListRoutesByStatus(ctx, util.RouteStatusApproved)
	if err != nil {
		return // best-effort
	}
	for _, r := range routes {
		if r.DeviceID == deviceID || r.CIDR == cidr {
			continue // 同设备内部交叠无歧义;完全相同交给 warnDuplicateApprovedCIDR
		}
		oldPfx, perr := netip.ParsePrefix(strings.TrimSpace(r.CIDR))
		if perr != nil || !oldPfx.Overlaps(newPfx) {
			continue
		}
		// 交叠地址上按最长前缀定胜负(同长度已被上面的 r.CIDR == cidr 排除,不会走到平手)。
		winner, winnerCIDR, loserCIDR := deviceID, cidr, r.CIDR
		if oldPfx.Bits() > newPfx.Bits() {
			winner, winnerCIDR, loserCIDR = r.DeviceID, r.CIDR, cidr
		}
		fmt.Fprintln(opts.stderr, opts.T("route.overlapCIDR",
			cidr, r.DeviceID, r.CIDR, winnerCIDR, winner, loserCIDR))
	}
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
		return usageErrorWrap(opts.usage("nanotun-admin route reject <device_id> <cidr> [--reason ...] [--force]"), err)
	}
	// 深扫第八轮 MED:与 web(handler_routes.go reject 仅限 pending)对齐 —— reject 只作用于
	// 待审批声明。此前 CLI 无守卫,`route reject` 会把一条 **已 approved** 的路由静默降级为
	// rejected,等于绕过 revoke 路径的一次隐式撤销(web 侧已堵住,CLI 却是缺口)。这里先查
	// 当前状态,非 pending 且未加 --force 直接报错,提示改用 `route delete` 显式撤销。
	if !*force {
		cur, gerr := st.GetRouteByDeviceCIDR(ctx, deviceID, cidr)
		if gerr != nil {
			// 深扫第九轮 LOW:本地化 ErrNotFound(此前裸抛 store 英文错误,和 CLI 其它
			// 路径「默认英文可翻」的口径不一致)。
			if errors.Is(gerr, store.ErrNotFound) {
				return errors.New(opts.T("route.notFound", deviceID, cidr))
			}
			return gerr
		}
		if cur.Status != util.RouteStatusPending {
			return errors.New(opts.T("route.notPending", deviceID, cidr, cur.Status))
		}
	}
	if err := st.SetRouteStatus(ctx, deviceID, cidr, util.RouteStatusRejected, *reason); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.New(opts.T("route.notFound", deviceID, cidr))
		}
		return err
	}
	// 与 web(route_reject)对等的审计。
	_ = st.Audit(ctx, "admin-cli", "route_reject",
		fmt.Sprintf("route:%d/%s", deviceID, cidr),
		fmt.Sprintf("cidr=%s reason=%s", cidr, *reason))
	fmt.Fprintln(opts.stdout, opts.T("route.rejected", deviceID, cidr, *reason))
	if util.IsExitDefaultRoute(cidr) {
		warnExitStillApprovedOtherFamily(ctx, st, opts, deviceID, cidr)
		notifyExitsChanged(opts) // 撤销出口 → 即时把绑定它的会话踢回 server + 刷新下拉。best-effort。
	} else {
		notifyRoutesChanged(opts) // 拒绝子网路由 → 即时从 server 的已批准子网路由表移除。best-effort。
	}
	return nil
}

func cmdRouteDelete(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	deviceID, cidr, err := parseRouteTarget(opts, args)
	if err != nil {
		return usageErrorWrap(opts.usage("nanotun-admin route delete <device_id> <cidr>"), err)
	}
	if !opts.yes {
		if !confirm(opts, opts.T("route.confirmDelete", deviceID, cidr)) {
			fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
			return nil
		}
	}
	if err := st.DeleteRoute(ctx, deviceID, cidr); err != nil {
		// 深扫第十轮 LOW:与 approve/reject 同款本地化(此前 delete 裸抛 store 英文错误)。
		if errors.Is(err, store.ErrNotFound) {
			return errors.New(opts.T("route.notFound", deviceID, cidr))
		}
		return err
	}
	// 与 web(route_delete)对等的审计。
	_ = st.Audit(ctx, "admin-cli", "route_delete",
		fmt.Sprintf("route:%d/%s", deviceID, cidr), "cidr="+cidr)
	fmt.Fprintln(opts.stdout, opts.T("route.deleted", deviceID, cidr))
	if util.IsExitDefaultRoute(cidr) {
		warnExitStillApprovedOtherFamily(ctx, st, opts, deviceID, cidr)
		notifyExitsChanged(opts) // 删出口路由 → 即时把绑定它的会话踢回 server + 刷新下拉。best-effort。
	} else {
		notifyRoutesChanged(opts) // 删子网路由 → 即时从 server 的已批准子网路由表移除。best-effort。
	}
	return nil
}

// warnExitStillApprovedOtherFamily 在**按族**撤掉一条出口默认路由(0.0.0.0/0 或 ::/0)后,检查该 device 是否
// 另一族仍被批准;若仍被批准就响亮告警 —— 因为出口绑定是**按 device**判定的(见 resolveApprovedExitDeviceID):
// 只要还剩一族 approved,这台机器就仍是合法出口,连 **IPv4** 流量也照样经它出网。
//
// 2026-07-25 三机实测(A 经 C 出口)坐实:只撤 C 的 0.0.0.0/0、留着 ::/0,A 的 v4 出网 IP 仍是 C 的公网 IP。
// route 子命令把两族显示成两行、也允许单独删一行,天然暗示了一个「并不存在」的粒度;此前还完全静默。
// 不改成硬失败:按族操作对「先撤 v4 再撤 v6」这类分步流程仍有意义,故只保证操作者不被静默误导,并指路
// `exit revoke`(一次撤两族 + 可清 fixed vIP)。
func warnExitStillApprovedOtherFamily(ctx context.Context, st *store.Store, opts *globalOpts, deviceID int64, cidr string) {
	rows, err := st.ListRoutesByDevice(ctx, deviceID)
	if err != nil {
		return // best-effort:告警不该让撤销命令失败
	}
	for _, r := range rows {
		if r.Status != util.RouteStatusApproved || !util.IsExitDefaultRoute(r.CIDR) || r.CIDR == cidr {
			continue
		}
		fmt.Fprintln(opts.stderr, opts.T("route.exitOtherFamilyStillApproved", deviceID, r.CIDR))
		return
	}
}

func parseRouteTarget(opts *globalOpts, args []string) (int64, string, error) {
	if len(args) != 2 {
		return 0, "", newLocErr("route.needTwoArgs")
	}
	id, err := parseInt64(args[0])
	if err != nil {
		return 0, "", usageErrorWrap(fmt.Sprintf("%s: %v", opts.T("cli.invalidDeviceID", args[0]), err), err)
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
