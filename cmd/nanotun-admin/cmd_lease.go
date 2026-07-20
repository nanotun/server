package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/nanotun/server/store"
)

func cmdLease(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return errors.New(opts.usage("nanotun-admin lease <list|release|set|gc> [...]"))
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
		return errors.New(opts.T("lease.idleMustPositive"))
	}
	if *dry {
		var n int64
		cutoff := time.Now().Add(-*idle).Unix()
		row := st.DB().QueryRowContext(ctx, `
			SELECT COUNT(*) FROM leases l
			 WHERE l.manual = 0
			   AND l.device_id IN (SELECT id FROM devices WHERE last_seen_at < ?)`, cutoff)
		if err := row.Scan(&n); err != nil {
			return err
		}
		fmt.Fprintln(opts.stdout, opts.T("lease.gcDryRun", n, (*idle).String()))
		return nil
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

	type row struct {
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
	var out []row
	for rows.Next() {
		var r row
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

func cmdLeaseRelease(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) != 1 {
		return errors.New(opts.usage("nanotun-admin lease release <device_id>"))
	}
	id, err := parseInt64(args[0])
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("cli.invalidDeviceID", args[0]), err)
	}
	if err := st.DeleteLease(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.New(opts.T("lease.noLease", id))
		}
		return err
	}
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
		return errors.New(opts.usage("nanotun-admin lease set <device_id> [--v4 IP] [--v6 IP] [--manual=false]"))
	}
	deviceID, err := parseInt64(pos[0])
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("cli.invalidDeviceID", pos[0]), err)
	}
	if _, err := st.GetDevice(ctx, deviceID); err != nil {
		return err
	}
	if *v4 == "" && *v6 == "" {
		return errors.New("at least one of --v4 / --v6 must be provided")
	}
	l, err := st.UpsertLease(ctx, deviceID, *v4, *v6, *manual)
	if err != nil {
		return err
	}
	if opts.json {
		return printJSON(opts.stdout, l)
	}
	fmt.Fprintln(opts.stdout, opts.T("lease.assigned",
		deviceID, dashIfEmpty(l.VIPv4), dashIfEmpty(l.VIPv6), fmtBool(l.Manual)))
	return nil
}
