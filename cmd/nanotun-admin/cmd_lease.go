package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"time"

	"github.com/nanotun/server/store"
)

func cmdLease(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return usageError(opts.usage("nanotun-admin lease <list|release|set|gc> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "ls":
		return cmdLeaseList(ctx, st, opts, rest)
	case "release", "rm":
		return cmdLeaseRelease(ctx, st, opts, rest)
	case "set":
		return cmdLeaseSet(ctx, st, opts, rest)
	case "gc":
		return cmdLeaseGc(ctx, st, opts, rest)
	default:
		return newLocErr("cli.unknownSubcommand", "lease", sub)
	}
}

// cmdLeaseGc 回收 idle 时间超过阈值的非手动 lease。典型场景:用户重装 / 换设备
// 导致 device_uuid 变化,旧 device 还在但永远不再上线,占据的 vIP 永久泄漏。
// 默认 idle=30d 比较保守,推荐部署后 cron 每天跑一次。--dry-run 先看会删多少。
func cmdLeaseGc(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("lease gc", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	idle := fs.Duration("idle", 30*24*time.Hour, opts.T("lease.flag.idle"))
	dry := fs.Bool("dry-run", false, opts.T("lease.flag.dryRun"))
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	if *idle <= 0 {
		return usageError(opts.T("lease.idleMustPositive"))
	}
	// 第二十轮深扫 MED:预览 / 确认的计数走 CountOrphanLeases —— 与 GcOrphanLeases 的删除谓词**完全一致**
	// (含「vip==该 device fixed_vip 的行永不回收」)。此前这里内联一条只查 manual+idle 的 COUNT,漏了 fixed_vip
	// 保留 → 显示的数比实删偏大,运维据此误判。
	if *dry {
		n, err := st.CountOrphanLeases(ctx, int64(idle.Seconds()))
		if err != nil {
			return err
		}
		fmt.Fprintln(opts.stdout, opts.T("lease.gcDryRun", n, (*idle).String()))
		return nil
	}
	// 第十四轮深扫 MED:非 --dry-run 的 gc 会批量删除孤儿 lease、释放粘性 vIP,属破坏性操作。与 restore /
	// vacuum / user delete 等一致要求二次确认(--yes / -y 跳过供 cron/脚本)。先算将删多少条,给运维决策依据。
	if !opts.yes {
		n, err := st.CountOrphanLeases(ctx, int64(idle.Seconds()))
		if err != nil {
			return err
		}
		ok, _ := confirm(opts, opts.T("lease.confirmGc", n, (*idle).String()))
		if !ok {
			fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
			return nil
		}
	}
	n, err := st.GcOrphanLeases(ctx, int64(idle.Seconds()))
	if err != nil {
		return err
	}
	fmt.Fprintln(opts.stdout, opts.T("lease.gcDone", n, (*idle).String()))
	return nil
}

func cmdLeaseList(ctx context.Context, st *store.Store, opts *globalOpts, _ []string) error {
	rows, err := st.DB().QueryContext(ctx, `
		SELECT l.id, l.device_id, COALESCE(l.vip_v4,''), COALESCE(l.vip_v6,''),
		       l.manual, l.assigned_at,
		       d.device_uuid, d.user_id, u.username
		  FROM leases l
		  JOIN devices d ON d.id = l.device_id
		  JOIN users   u ON u.id = d.user_id
		 ORDER BY l.id ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var out []leaseView
	for rows.Next() {
		var r leaseView
		var manual int64
		if err := rows.Scan(&r.ID, &r.DeviceID, &r.VIPv4, &r.VIPv6, &manual, &r.AssignedAt,
			&r.DeviceUUID, &r.UserID, &r.Username); err != nil {
			return err
		}
		r.Manual = manual != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if opts.json {
		return printJSON(opts.stdout, out)
	}
	t := newTable(opts.stdout, "ID", "USERNAME", "DEVICE", "VIP_V4", "VIP_V6", "MANUAL", "ASSIGNED_AT")
	for _, r := range out {
		t.row(r.ID, r.Username, r.DeviceUUID, dashIfEmpty(r.VIPv4), dashIfEmpty(r.VIPv6), fmtBool(r.Manual), fmtTimeUnix(r.AssignedAt))
	}
	return t.flush()
}

// leaseView 是 lease 一族 --json 的统一形状(与 aclPairView 同一批统一,原因见那里)。
type leaseView struct {
	ID         int64  `json:"id"`
	DeviceID   int64  `json:"device_id"`
	VIPv4      string `json:"vip_v4,omitempty"`
	VIPv6      string `json:"vip_v6,omitempty"`
	Manual     bool   `json:"manual"`
	AssignedAt int64  `json:"assigned_at"`
	DeviceUUID string `json:"device_uuid"`
	UserID     int64  `json:"user_id"`
	Username   string `json:"username"`
}

// viewFromLease 由刚写入的租约拼视图。device/username 这几列 list 那侧是 JOIN 出来的,
// 这里补一次查询让两条命令的形状一致 —— 查不动时留空而**不**报错:租约已经落库了,
// 为了一个展示字段把命令判成失败,调用方会去重试一个其实已经成功的写操作。
func viewFromLease(ctx context.Context, st *store.Store, l *store.Lease, dev *store.Device) leaseView {
	v := leaseView{
		ID: l.ID, DeviceID: l.DeviceID,
		VIPv4: l.VIPv4, VIPv6: l.VIPv6,
		Manual: l.Manual, AssignedAt: l.AssignedAt,
	}
	if dev != nil {
		v.DeviceUUID, v.UserID = dev.DeviceUUID, dev.UserID
		if u, err := st.GetUser(ctx, dev.UserID); err == nil {
			v.Username = u.Username
		}
	}
	return v
}

func cmdLeaseRelease(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) != 1 {
		return usageError(opts.usage("nanotun-admin lease release <device_id>"))
	}
	id, err := parseInt64(args[0])
	if err != nil {
		return usageErrorWrap(fmt.Sprintf("%s: %v", opts.T("cli.invalidDeviceID", args[0]), err), err)
	}
	if err := st.DeleteLease(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.New(opts.T("lease.noLease", id))
		}
		return err
	}
	// 与其它破坏性 CLI 操作对齐的审计:释放 lease 会让该设备下次登录换 vIP。
	_ = st.Audit(ctx, "admin-cli", "lease_release",
		fmt.Sprintf("device:%d", id), "")
	fmt.Fprintln(opts.stdout, opts.T("lease.released", id))
	return nil
}

func cmdLeaseSet(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("lease set", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	v4 := fs.String("v4", "", opts.T("lease.flag.v4"))
	v6 := fs.String("v6", "", opts.T("lease.flag.v6"))
	manual := fs.Bool("manual", true, opts.T("lease.flag.manual"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(opts.usage("nanotun-admin lease set <device_id> [--v4 IP] [--v6 IP] [--manual=false]"))
	}
	deviceID, err := parseInt64(pos[0])
	if err != nil {
		return usageErrorWrap(fmt.Sprintf("%s: %v", opts.T("cli.invalidDeviceID", pos[0]), err), err)
	}
	dev, err := st.GetDevice(ctx, deviceID)
	if err != nil {
		return opts.notFoundErr(err, "device.notFound", deviceID)
	}
	if *v4 == "" && *v6 == "" {
		return errors.New(opts.T("lease.needV4OrV6"))
	}
	// 深扫第八轮 MED:此前 --v4/--v6 未经任何校验直接进 UpsertLease(store 只归一化
	// UNIQUE 冲突,不验格式/地址族)。`lease set 5 --v4 fe80::1` 或 `--v4 notanip` 会把
	// 垃圾写进 vip_v4,设备下次登录收到即黑洞。与 device set-fixed-vip 同口径严格校验:
	// v4 必须是 IPv4、v6 必须是纯 IPv6(排除 IPv4-mapped)。
	if *v4 != "" {
		if a, aerr := netip.ParseAddr(*v4); aerr != nil || !a.Unmap().Is4() {
			return errors.New(opts.T("lease.badV4", *v4))
		}
	}
	if *v6 != "" {
		if a, aerr := netip.ParseAddr(*v6); aerr != nil || !a.Is6() || a.Is4In6() {
			return errors.New(opts.T("lease.badV6", *v6))
		}
	}
	// 第七轮深扫 MED:命令行未指定的族保留 lease 现值(UpsertLease 的 ON CONFLICT 无条件覆盖两族,只传 --v4
	// 时 vip_v6 被写成 NULL,静默抹掉设备已有 sticky v6,反之亦然)。
	// 第十四轮深扫 LOW:把「读现值 + 保留 + 写」下沉到 UpsertManualLeasePreservingEmpty 的**单事务**内
	// (COALESCE(excluded, 现值)),消除此前「先 GetLeaseByDevice 读、再 UpsertLease 写」的非原子 RMW ——
	// 读写之间设备恰好登录被分配另一族时,旧写会把刚分配的族又抹掉。整条释放用 `lease release`。
	// 钉住的地址若登录路径用不上(掉出 mesh 网段 / 是网关·网络·广播这类保留地址),设备下次登录
	// 会被静默改走自动分配 —— 而这里只会回一句「已分配」。与 device set-fixed-vip 同口径当场提示。
	warnPinnedVIPsUnusable(ctx, st, opts, []pinnedVIPField{
		{changed: *v4 != "", field: "vip_v4", val: *v4},
		{changed: *v6 != "", field: "vip_v6", val: *v6},
	})
	l, err := st.UpsertManualLeasePreservingEmpty(ctx, deviceID, *v4, *v6, *manual)
	if err != nil {
		return err
	}
	// 审计:手工改 lease 直接影响设备下次登录拿到的 vIP。
	_ = st.Audit(ctx, "admin-cli", "lease_set",
		fmt.Sprintf("device:%d", deviceID),
		fmt.Sprintf("v4=%s v6=%s manual=%v", l.VIPv4, l.VIPv6, l.Manual))
	if opts.json {
		return printJSON(opts.stdout, viewFromLease(ctx, st, l, dev))
	}
	fmt.Fprintln(opts.stdout, opts.T("lease.assigned",
		deviceID, dashIfEmpty(l.VIPv4), dashIfEmpty(l.VIPv6), fmtBool(l.Manual)))
	return nil
}
