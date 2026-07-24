package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strings"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

func cmdDevice(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return usageError(opts.usage("nanotun-admin device <create|list|delete|set-fixed-vip|set-rate|set-alias> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdDeviceCreate(ctx, st, opts, rest)
	case "list", "ls":
		return cmdDeviceList(ctx, st, opts, rest)
	case "delete", "rm":
		return cmdDeviceDelete(ctx, st, opts, rest)
	case "set-fixed-vip":
		return cmdDeviceSetFixedVIP(ctx, st, opts, rest)
	case "set-rate":
		return cmdDeviceSetRate(ctx, st, opts, rest)
	case "set-alias":
		return cmdDeviceSetAlias(ctx, st, opts, rest)
	default:
		return newLocErr("cli.unknownSubcommand", "device", sub)
	}
}

// cmdDeviceCreate 用**指定 UUID 预创建**一行设备(在设备首次登录前)。
//
// 平时设备行是首登自动 upsert 的;预创建让运维能「先配后连」:先建好已知 UUID 的设备 → `exit designate` 预批准为
// 出口 + 钉固定 vIP → 把同一 UUID 写进出口机 /etc/nanotun/device_id → 它一连上即为已批准、固定地址的出口。
// 对「出口=基础设施,身份可预编排/可复现(重建机器写回同一 UUID 即同一出口)」尤其有用(详见 docs/DESIGN_EXIT_NODE.md M8)。
// 幂等:UUID 已存在则视为更新(刷新 name/platform),不报错。
//
// 用法:
//
//	nanotun-admin device create <username> --uuid <uuidv4> [--name N] [--platform linux|windows|macos|router|ios|android]
func cmdDeviceCreate(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("device create", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	uuidFlag := fs.String("uuid", "", opts.T("device.flag.uuid"))
	name := fs.String("name", "", opts.T("device.flag.name"))
	platform := fs.String("platform", "linux", opts.T("device.flag.platform"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(opts.usage("nanotun-admin device create <username> --uuid <uuidv4> [--name N] [--platform P]"))
	}
	username := pos[0]
	uuidNorm := util.NormalizeDeviceUUID(*uuidFlag)
	if !util.IsValidUUIDv4(uuidNorm) {
		return errors.New(opts.T("device.badUUID", *uuidFlag))
	}
	// 平台入口校验(第十四轮深扫):预创建的头号用途就是配套 exit designate「先配后连」,
	// 而 designate 有平台闸口 —— 这里放进一个非 canonical token(旧文档还写着 darwin!)
	// 会让下游 designate 直接被拦。复用登录白名单的归一/校验,拼错当场报错。
	platNorm, perr := store.NormalizePlatformCSV(*platform)
	if perr != nil || strings.Contains(platNorm, ",") {
		return errors.New(opts.T("device.badPlatform", *platform))
	}
	if platNorm == "" {
		platNorm = "linux" // flag 默认值;显式传空串也回落 linux
	}
	u, err := st.GetUserByUsername(ctx, username)
	if err != nil {
		return opts.notFoundErr(err, "user.notFound", username)
	}
	existed := false
	if d, gerr := st.GetDeviceByUUID(ctx, u.ID, uuidNorm); gerr == nil && d != nil {
		existed = true
	}
	dev, err := st.UpsertDevice(ctx, u.ID, uuidNorm, *name, platNorm)
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("device.precreateFail"), err)
	}
	_ = st.Audit(ctx, "admin-cli", "device_create",
		fmt.Sprintf("device:%d", dev.ID),
		fmt.Sprintf("user=%s uuid=%s name=%s platform=%s", username, uuidNorm, *name, platNorm))
	verb := opts.T("device.createdVerb.new")
	if existed {
		verb = opts.T("device.createdVerb.existed")
	}
	fmt.Fprintln(opts.stdout, opts.T("device.createdLine",
		verb, dev.ID, username, dev.DeviceUUID, dashIfEmpty(dev.DeviceName), dev.Platform))
	fmt.Fprintln(opts.stderr, opts.T("device.createdHint", dev.ID))
	return nil
}

func cmdDeviceList(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("device list", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	username := fs.String("user", "", opts.T("device.flag.user"))
	effective := fs.Bool("effective", false, opts.T("device.flag.effective"))
	if err := fs.Parse(args); err != nil {
		return err
	}

	var devs []*store.Device
	if *username != "" {
		u, err := st.GetUserByUsername(ctx, *username)
		if err != nil {
			return opts.notFoundErr(err, "user.notFound", *username)
		}
		devs, err = st.ListDevicesByUser(ctx, u.ID)
		if err != nil {
			return err
		}
	} else {
		// 全量:0008 后 store 有 ListAllDevices 直接走它,免去 "for user in users:
		// list devices for user" 的 N+1 查询。
		all, err := st.ListAllDevices(ctx)
		if err != nil {
			return err
		}
		devs = all
	}

	if opts.json {
		return printJSON(opts.stdout, devs)
	}

	// --effective:把 device 维度的 raw 值,叠加 app_settings 默认 + (通过 control sock 拿)toml 默认,
	// 取 min 后显示。user 级 bandwidth 也要一并取 min — 走 DB 读 user 表。
	// 失败时退化为 raw 值(警告 stderr),不阻塞展示。
	var defaults store.RateDefaults
	var tomlUp, tomlDown int64
	if *effective {
		var err error
		defaults, err = st.GetRateDefaults(ctx)
		if err != nil {
			fmt.Fprintln(opts.stderr, opts.T("device.warnReadSettings", err.Error()))
		}
		// toml 默认从 server /status 拉 rate_config(server 没起就走 0/0)。
		if cfg, cerr := fetchRateConfigFromControl(opts); cerr == nil {
			tomlUp, tomlDown = cfg.TomlUpBPS, cfg.TomlDownBPS
		} else {
			fmt.Fprintln(opts.stderr, opts.T("device.warnReadStatus", cerr.Error()))
		}
	}

	t := newTable(opts.stdout, "ID", "USER_ID", "DEVICE_UUID", "NAME", "ALIAS", "PLATFORM",
		"FIXED_V4", "FIXED_V6", "RATE_UP", "RATE_DOWN", "LAST_SEEN")
	for _, d := range devs {
		upBPS, downBPS := d.RateUploadBPS, d.RateDownloadBPS
		if *effective {
			// 取 min(device, settings, toml, user)。0 = 不在该层强制,minPos 跳过。
			upBPS = minPos64(upBPS, defaults.UploadBPS, tomlUp)
			downBPS = minPos64(downBPS, defaults.DownloadBPS, tomlDown)
			// user-level 也取 min
			if u, err := st.GetUser(ctx, d.UserID); err == nil && u != nil {
				upBPS = minPos64(upBPS, u.BandwidthUpBPS)
				downBPS = minPos64(downBPS, u.BandwidthDownBPS)
			}
		}
		t.row(d.ID, d.UserID, d.DeviceUUID,
			dashIfEmpty(d.DeviceName), dashIfEmpty(d.Alias), dashIfEmpty(d.Platform),
			dashIfEmpty(d.FixedVIPv4), dashIfEmpty(d.FixedVIPv6),
			bytesPerSecondHuman(upBPS), bytesPerSecondHuman(downBPS),
			fmtTimeUnix(d.LastSeenAt))
	}
	return t.flush()
}

// minPos64:把 0 当 +∞,选所有非零参数中的 min。全 0 返回 0。
// 与 server/effectiveLinkRates 同语义,在 CLI 包内独立一份避免跨包 import。
func minPos64(vs ...int64) int64 {
	var out int64
	for _, v := range vs {
		if v <= 0 {
			continue
		}
		if out == 0 || v < out {
			out = v
		}
	}
	return out
}

// fetchRateConfigFromControl:CLI 端拉 /status 提取 rate_config 字段。
// device list --effective 用,其它命令暂时没需要。
type cliRateConfig struct {
	TomlUpBPS   int64 `json:"toml_up_bps"`
	TomlDownBPS int64 `json:"toml_down_bps"`
}

func fetchRateConfigFromControl(opts *globalOpts) (cliRateConfig, error) {
	cli := newControlHTTPClient(resolveControlSocketPath(opts.controlSocket))
	body, err := controlDo(cli, "GET", "/status", nil)
	if err != nil {
		return cliRateConfig{}, err
	}
	var raw struct {
		RateConfig cliRateConfig `json:"rate_config"`
	}
	if jerr := json.Unmarshal(body, &raw); jerr != nil {
		return cliRateConfig{}, fmt.Errorf("parse /status: %w", jerr)
	}
	return raw.RateConfig, nil
}

// cmdDeviceSetAlias 设置/清除设备别名(0020,管理员展示名)。
//
// alias 只影响展示与下发(exits-list / routes-list / web·CLI 列表),**不改**客户端上报的
// device_name(每次登录仍照常刷新),也不影响 MagicDNS 主机名。空串 = 清除、回落上报名。
//
// 用法:
//
//	nanotun-admin device set-alias <device_id> <alias>   设置
//	nanotun-admin device set-alias <device_id> ''        清除
func cmdDeviceSetAlias(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) != 2 {
		return usageError(opts.usage("nanotun-admin device set-alias <device_id> <alias|''>"))
	}
	id, err := parseInt64(args[0])
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("cli.invalidDeviceID", args[0]), err)
	}
	d, err := st.GetDevice(ctx, id)
	if err != nil {
		return opts.notFoundErr(err, "device.notFound", id)
	}
	alias := strings.TrimSpace(args[1])
	if err := st.SetDeviceAlias(ctx, id, alias); err != nil {
		return err
	}
	_ = st.Audit(ctx, "admin-cli", "device_set_alias",
		fmt.Sprintf("device:%d", id),
		fmt.Sprintf("uuid=%s old=%q new=%q", d.DeviceUUID, d.Alias, alias))
	if alias == "" {
		fmt.Fprintln(opts.stdout, opts.T("device.aliasCleared", id, dashIfEmpty(d.DeviceName)))
	} else {
		fmt.Fprintln(opts.stdout, opts.T("device.aliasSet", id, alias))
	}
	// 出口/子网列表里的展示名变了:通知 server 重算并广播,客户端下拉即时换名。best-effort。
	notifyExitsChanged(opts)
	return nil
}

func cmdDeviceDelete(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) != 1 {
		return usageError(opts.usage("nanotun-admin device delete <device_id>"))
	}
	id, err := parseInt64(args[0])
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("cli.invalidDeviceID", args[0]), err)
	}
	d, err := st.GetDevice(ctx, id)
	if err != nil {
		return opts.notFoundErr(err, "device.notFound", id)
	}
	if !opts.yes {
		ok, err := confirm(opts, opts.T("device.confirmDelete", d.ID, d.DeviceUUID))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
			return nil
		}
	}
	if err := st.DeleteDevice(ctx, id); err != nil {
		return err
	}
	// 与 web(device_delete)对等的审计:删设备级联清 lease / 路由声明,须可归因。
	_ = st.Audit(ctx, "admin-cli", "device_delete",
		fmt.Sprintf("device:%d", id),
		fmt.Sprintf("uuid=%s user_id=%d", d.DeviceUUID, d.UserID))
	fmt.Fprintln(opts.stdout, opts.T("device.deleted", id))
	// 删设备会级联清掉它的 lease / 出口 / 子网路由声明 / 4via6 siteID（via6_sites ON DELETE CASCADE）。通知运行中的
	// server 重算出口与重建「已批准子网路由表」并广播 routes-list，否则数据面快照（subnetRouteTable/via6SiteTable）
	// 与客户端可用列表会陈旧到下次 reload/重启——该设备网段在使用方侧黑洞、siteID→device 映射悬空。best-effort，
	// 与 route reject/delete 同口径（cmd_route.go）。
	notifyExitsChanged(opts)
	notifyRoutesChanged(opts)
	return nil
}

// cmdDeviceSetFixedVIP 给指定 device 钉死(或清除)固定 vIP。
//
// 0008(2026-05-23)起取代 `user set-fixed-vip` — 因为协议层 device_uuid 强制
// RFC 4122 v4,「(user, device) 这台机器每次拿同一个 vIP」是更自然的 fixed 语义。
//
// 用法:
//
//	nanotun-admin device set-fixed-vip <device_id> --v4 100.64.0.42
//	nanotun-admin device set-fixed-vip <device_id> --v4 ""          # 清除 IPv4 fixed
//	nanotun-admin device set-fixed-vip <device_id> --v4 ... --v6 ...
//	nanotun-admin device set-fixed-vip <device_id> --v4 ... --force # 跳过冲突检查
//
// 不指定 --v4/--v6 时该字段保持不变(用 "<keep>" sentinel 区分「不传」vs「传空串清除」)。
func cmdDeviceSetFixedVIP(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("device set-fixed-vip", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	v4 := fs.String("v4", "<keep>", opts.T("device.flag.fixedV4"))
	v6 := fs.String("v6", "<keep>", opts.T("device.flag.fixedV6"))
	force := fs.Bool("force", false, opts.T("device.flag.fixedForce"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(opts.usage("nanotun-admin device set-fixed-vip <device_id> [--v4 IP] [--v6 IP] [--force]"))
	}
	id, err := parseInt64(pos[0])
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("cli.invalidDeviceID", pos[0]), err)
	}
	d, err := st.GetDevice(ctx, id)
	if err != nil {
		return opts.notFoundErr(err, "device.notFound", id)
	}
	newV4 := d.FixedVIPv4
	if *v4 != "<keep>" {
		newV4 = *v4
	}
	newV6 := d.FixedVIPv6
	if *v6 != "<keep>" {
		newV6 = *v6
	}
	// 地址族校验(空串 = 清除,豁免):--v4 必须是 IPv4,--v6 必须是 IPv6。
	// ParseAddr 两族都收,不查族会把 IPv6 字面量写进 fixed_vip_v4(反之亦然),
	// 分配时静默失效。与 web 端 set-fixed-vip 同口径。
	// 第七轮深扫 HIGH:校验通过后立即规范化为 netip.Addr.String()(小写 / 压缩),让下面的冲突预检、
	// audit 记录与 store 落库处在同一文本域。store.SetDeviceFixedVIP 也会再规范化一次(纵深),但这里
	// 先做能让 findFixedVIPConflict 的字符串比较与最终存储一致,避免「预检说无冲突、落库才 ErrDuplicate」。
	if newV4 != "" {
		a, aerr := netip.ParseAddr(newV4)
		if aerr != nil || !a.Unmap().Is4() {
			return errors.New(opts.T("device.badFixedV4", newV4))
		}
		newV4 = a.String()
	}
	if newV6 != "" {
		a, aerr := netip.ParseAddr(newV6)
		if aerr != nil || !a.Is6() || a.Is4In6() {
			return errors.New(opts.T("device.badFixedV6", newV6))
		}
		newV6 = a.String()
	}
	// 仅在「真的变了」时才查冲突,避免 noop 触发全表扫描。
	if newV4 != d.FixedVIPv4 {
		if conflict, err := findFixedVIPConflict(ctx, st, opts, newV4, d.ID); err != nil {
			return err
		} else if conflict != "" {
			if !*force {
				return errors.New(opts.T("device.fixedConflictV4", newV4, conflict))
			}
			fmt.Fprintln(opts.stderr, opts.T("device.forceOverrideV4", conflict))
		}
	}
	if newV6 != d.FixedVIPv6 {
		if conflict, err := findFixedVIPConflict(ctx, st, opts, newV6, d.ID); err != nil {
			return err
		} else if conflict != "" {
			if !*force {
				return errors.New(opts.T("device.fixedConflictV6", newV6, conflict))
			}
			fmt.Fprintln(opts.stderr, opts.T("device.forceOverrideV6", conflict))
		}
	}
	oldV4, oldV6 := d.FixedVIPv4, d.FixedVIPv6
	// --force 传到 store 层:让它在跨表 lease 冲突时释放他设备占用后再钉(而非 ErrDuplicate 拒绝),
	// 与 CLI 侧「--force 跳过预检」的语义一致(见 SetDeviceFixedVIP)。
	if err := st.SetDeviceFixedVIP(ctx, d.ID, newV4, newV6, *force); err != nil {
		return err
	}
	_ = st.Audit(ctx, "admin-cli", "device_set_fixed_vip",
		fmt.Sprintf("device:%d", d.ID),
		fmt.Sprintf("uuid=%s old_v4=%s new_v4=%s old_v6=%s new_v6=%s",
			d.DeviceUUID, oldV4, newV4, oldV6, newV6))
	fmt.Fprintln(opts.stdout, opts.T("device.fixedUpdated",
		d.ID, d.DeviceUUID, dashIfEmpty(newV4), dashIfEmpty(newV6)))
	return nil
}

// cmdDeviceSetRate(0011, 2026-05-23):per-device 带宽限速。
//
// 用法:
//
//	nanotun-admin device set-rate <id> --up-mibs 5 --down-mibs 10
//	nanotun-admin device set-rate <id> --up-bps 5242880          # 精确到字节
//	nanotun-admin device set-rate <id> --up-mibs 0               # 单方向清(沿用全局默认)
//	nanotun-admin device set-rate <id> --no-refresh              # 只改 DB,不推送给 active conn
//
// 不传 --up-* / --down-* 表示「保持该方向当前值不变」(用 errRateUnset sentinel 区分);
// 传 0 表示「清掉该层 cap」(回退全局默认 → toml)。设计目的:CLI 想「只改上行」时
// 不必先 list 出当前下行值再原样传一次。
func cmdDeviceSetRate(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("device set-rate", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	upMibs := fs.String("up-mibs", "", opts.T("device.flag.rateUpMibs"))
	upBps := fs.String("up-bps", "", opts.T("device.flag.rateUpBps"))
	downMibs := fs.String("down-mibs", "", opts.T("device.flag.rateDownMibs"))
	downBps := fs.String("down-bps", "", opts.T("device.flag.rateDownBps"))
	noRefresh := fs.Bool("no-refresh", false, opts.T("setting.rate.flagNoRefresh"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(opts.usage("nanotun-admin device set-rate <device_id> [--up-mibs N|--up-bps N] [--down-mibs N|--down-bps N] [--no-refresh]"))
	}
	id, err := parseInt64(pos[0])
	if err != nil {
		return fmt.Errorf("%s: %w", opts.T("cli.invalidDeviceID", pos[0]), err)
	}
	d, err := st.GetDevice(ctx, id)
	if err != nil {
		return opts.notFoundErr(err, "device.notFound", id)
	}

	oldUp, oldDown := d.RateUploadBPS, d.RateDownloadBPS
	newUp := d.RateUploadBPS
	if v, perr := parseRateFlag(*upMibs, *upBps); perr == nil {
		newUp = v
	} else if !errors.Is(perr, errRateUnset) {
		return perr
	}
	newDown := d.RateDownloadBPS
	if v, perr := parseRateFlag(*downMibs, *downBps); perr == nil {
		newDown = v
	} else if !errors.Is(perr, errRateUnset) {
		return perr
	}

	if err := st.SetDeviceRateLimit(ctx, d.ID, newUp, newDown); err != nil {
		return err
	}
	// audit 写入 admin CLI 的 actor 已经在 store 层补不了(没有"who"上下文),这里
	// 直接用 "admin-cli" 作为 actor,detail 带 device_uuid + old → new 便于追溯。
	_ = st.Audit(ctx, "admin-cli", "device_rate_set",
		fmt.Sprintf("device:%d", d.ID),
		fmt.Sprintf("uuid=%s old_up_bps=%d new_up_bps=%d old_down_bps=%d new_down_bps=%d",
			d.DeviceUUID, oldUp, newUp, oldDown, newDown))

	fmt.Fprintln(opts.stdout, opts.T("device.rateUpdated",
		d.ID, bytesPerSecondHuman(newUp), bytesPerSecondHuman(newDown)))

	if !*noRefresh {
		// control sock 调一下,给 active conn 热更 limiter。失败仅 warn:db 已写入,
		// 下次客户端重连一定生效;active conn 那条没刷上只是少一次效果。
		if err := pushRateRefresh(opts, d.ID); err != nil {
			fmt.Fprintln(opts.stderr, opts.T("setting.rate.refreshWarn", err.Error()))
		}
	}
	return nil
}

// pushRateRefresh:调 control sock POST /rate/refresh?device_id=X。device_id==0 全量。
// 给 device set-rate / setting rate 子命令复用。
func pushRateRefresh(opts *globalOpts, deviceID int64) error {
	cli := newControlHTTPClient(resolveControlSocketPath(opts.controlSocket))
	path := "/rate/refresh"
	if deviceID > 0 {
		path = fmt.Sprintf("/rate/refresh?device_id=%d", deviceID)
	}
	_, err := controlDo(cli, "POST", path, nil)
	return err
}

// findFixedVIPConflict 检查 candidate vIP 是否已被其它持有者占用(0008 device 维度版)。
//
// 检查目标:
//  1. 非本 device 的其它 device.fixed_vip_v4 / fixed_vip_v6
//  2. 非本 device 的 lease.vip_v4 / vip_v6
//
// 本 device 自己的 fixed-vip / lease 不算撞 —— 把现有 fixed-vip 再「设成自己已经在用
// 的值」是 noop 而非冲突;把 fixed-vip 设成自己 device 已有 lease(从 pool 拿到的 IP)
// 是 admin 常见操作(钉死现有 IP)。
//
// 返回值:
//   - candidate == "" 永远返回 "",nil(清除 fixed-vip 不需要检查)
//   - candidate 非合法 IP → 返回 error
//   - 撞了 → 返回人类可读描述(admin 看着决定是否 --force)
//   - 没撞 → 返回 "",nil
//
// ownerDeviceID == 0 表示「新设备/无所属」,等价于「全部都算外部」,适合插入新行前
// (虽然 0008 后已经没有"创建用户时钉 vIP"路径,这里留这个语义只是为了完备性 / 未来
// 可能新增的 device pre-create 入口)。
func findFixedVIPConflict(ctx context.Context, st *store.Store, opts *globalOpts, candidate string, ownerDeviceID int64) (string, error) {
	if candidate == "" {
		return "", nil
	}
	if _, err := netip.ParseAddr(candidate); err != nil {
		return "", fmt.Errorf("%s: %w", opts.T("device.badIP", candidate), err)
	}
	devs, err := st.ListAllDevices(ctx)
	if err != nil {
		return "", fmt.Errorf("list all devices: %w", err)
	}
	for _, d := range devs {
		if d.ID == ownerDeviceID {
			continue
		}
		if d.FixedVIPv4 == candidate {
			return opts.T("device.conflict.fixedV4", d.ID, d.UserID, d.DeviceName, candidate), nil
		}
		if d.FixedVIPv6 == candidate {
			return opts.T("device.conflict.fixedV6", d.ID, d.UserID, d.DeviceName, candidate), nil
		}
		lease, err := st.GetLeaseByDevice(ctx, d.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("get lease for device %d: %w", d.ID, err)
		}
		if lease.VIPv4 == candidate {
			return opts.T("device.conflict.leaseV4", d.ID, d.UserID, d.DeviceUUID, candidate), nil
		}
		if lease.VIPv6 == candidate {
			return opts.T("device.conflict.leaseV6", d.ID, d.UserID, d.DeviceUUID, candidate), nil
		}
	}
	return "", nil
}
