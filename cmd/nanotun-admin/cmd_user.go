package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

func cmdUser(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return usageError(opts.usage("nanotun-admin user <create|list|show|disable|enable|delete|reset-psk|set-bandwidth|set-platforms|set-max-sessions> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdUserCreate(ctx, st, opts, rest)
	case "list", "ls":
		return cmdUserList(ctx, st, opts, rest)
	case "show":
		return cmdUserShow(ctx, st, opts, rest)
	case "disable":
		return cmdUserSetDisabled(ctx, st, opts, rest, true)
	case "enable":
		return cmdUserSetDisabled(ctx, st, opts, rest, false)
	case "delete", "rm":
		return cmdUserDelete(ctx, st, opts, rest)
	case "reset-psk":
		return cmdUserResetPSK(ctx, st, opts, rest)
	case "set-bandwidth":
		return cmdUserSetBandwidth(ctx, st, opts, rest)
	case "set-platforms":
		return cmdUserSetPlatforms(ctx, st, opts, rest)
	case "set-max-sessions":
		return cmdUserSetMaxSessions(ctx, st, opts, rest)
	case "set-fixed-vip":
		// 0008(2026-05-23):fixed_vip 已迁到 devices 表;用户级 set-fixed-vip 不再存在。
		// 给出明确迁移提示,避免老脚本失败时一头雾水。
		return errors.New(opts.T("user.setFixedVIPDeprecated"))
	default:
		return newLocErr("cli.unknownSubcommand", "user", sub)
	}
}

// cmdUserSetBandwidth(0012, 2026-05-23):改 user 级带宽 quota(订阅维度的硬 cap)。
//
// 与 device set-rate 关系:device 是「这台机器」cap,user 是「这个账号所有 device」cap,
// effectiveLinkRates 最终取 min。改 user 之后会广播到该 user 所有 active conn。
//
// 用法:
//
//	nanotun-admin user set-bandwidth <username> --up-mibs 100 --down-mibs 200
//	nanotun-admin user set-bandwidth <username> --up-mibs 0     # 单方向清(=不限)
//	nanotun-admin user set-bandwidth <username> --no-refresh    # 只改 DB
func cmdUserSetBandwidth(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("user set-bandwidth", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	upMibs := fs.String("up-mibs", "", opts.T("user.flag.upMibs"))
	upBps := fs.String("up-bps", "", opts.T("user.flag.upBps"))
	downMibs := fs.String("down-mibs", "", opts.T("user.flag.downMibs"))
	downBps := fs.String("down-bps", "", opts.T("user.flag.downBps"))
	noRefresh := fs.Bool("no-refresh", false, opts.T("setting.rate.flagNoRefresh"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(opts.usage("nanotun-admin user set-bandwidth <username> [--up-mibs N|--up-bps N] [--down-mibs N|--down-bps N] [--no-refresh]"))
	}
	u, err := st.GetUserByUsername(ctx, pos[0])
	if err != nil {
		return opts.notFoundErr(err, "user.notFound", pos[0])
	}
	oldUp, oldDown := u.BandwidthUpBPS, u.BandwidthDownBPS
	newUp := oldUp
	if v, perr := parseRateFlag(*upMibs, *upBps); perr == nil {
		newUp = v
	} else if !errors.Is(perr, errRateUnset) {
		return perr
	}
	newDown := oldDown
	if v, perr := parseRateFlag(*downMibs, *downBps); perr == nil {
		newDown = v
	} else if !errors.Is(perr, errRateUnset) {
		return perr
	}
	if err := st.SetUserBandwidth(ctx, u.ID, newUp, newDown); err != nil {
		return err
	}
	_ = st.Audit(ctx, "admin-cli", "user_bandwidth_set",
		fmt.Sprintf("user:%d", u.ID),
		fmt.Sprintf("username=%s old_up_bps=%d new_up_bps=%d old_down_bps=%d new_down_bps=%d",
			u.Username, oldUp, newUp, oldDown, newDown))
	fmt.Fprintln(opts.stdout, opts.T("user.bandwidthUpdated",
		u.Username, bytesPerSecondHuman(newUp), bytesPerSecondHuman(newDown)))

	if !*noRefresh {
		if err := pushUserRateRefresh(opts, u.ID); err != nil {
			fmt.Fprintln(opts.stderr, opts.T("user.refreshWarn", err.Error()))
		}
	}
	return nil
}

// cmdUserSetMaxSessions(0021):改按账号的并发会话上限。
//
// 用法:
//
//	nanotun-admin user set-max-sessions <username> 5    # 该账号最多 5 个并发会话(覆盖全局)
//	nanotun-admin user set-max-sessions <username> 0    # 跟随全局 [server].max_sessions_per_user
//	nanotun-admin user set-max-sessions <username> -1   # 该账号显式不限(即便全局有上限)
//
// 仅对未来登录生效(登录时定格到 Connection);现役会话不回踢。
// 全局缺省 0 = 不限制 —— 不设账号级也不设全局时完全放开。
func cmdUserSetMaxSessions(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) != 2 {
		return usageError(opts.usage("nanotun-admin user set-max-sessions <username> <n>   # n: >0 覆盖全局; 0 跟随全局; -1 该账号不限"))
	}
	u, err := st.GetUserByUsername(ctx, args[0])
	if err != nil {
		return opts.notFoundErr(err, "user.notFound", args[0])
	}
	n64, err := parseInt64(args[1])
	if err != nil || n64 < -1 || n64 > store.MaxSessionsCap {
		return errors.New(opts.T("user.badMaxSessions", args[1]))
	}
	n := int(n64)
	if err := st.SetUserMaxSessions(ctx, u.ID, n); err != nil {
		return err
	}
	_ = st.Audit(ctx, "admin-cli", "user_max_sessions_set",
		fmt.Sprintf("user:%d", u.ID),
		fmt.Sprintf("username=%s max_sessions=%d", u.Username, n))
	fmt.Fprintln(opts.stdout, opts.T("user.maxSessionsUpdated", u.Username, formatMaxSessions(opts, n)))
	return nil
}

// formatMaxSessions:把 0/-1/N 翻成人类可读短文案(CLI 成功提示 / show 共用)。
func formatMaxSessions(opts *globalOpts, n int) string {
	switch {
	case n > 0:
		return opts.T("user.maxSessions.override", n)
	case n < 0:
		return opts.T("user.maxSessions.unlimited")
	default:
		return opts.T("user.maxSessions.followGlobal")
	}
}

// cmdUserSetPlatforms(2026-07-18):改用户「可登录平台白名单」(见 store.User.AllowedPlatforms)。
//
// 用法:
//
//	nanotun-admin user set-platforms <username> macos,ios   # 只允许 macOS / iOS
//	nanotun-admin user set-platforms <username> ""          # 清空 = 恢复不限
//	nanotun-admin user set-platforms <username>             # 省略 csv 亦为清空
//
// 归一走 store.NormalizePlatformCSV:拼错的 token 直接报错,避免把用户锁死在门外。
// **自动生效**:改完不用手动踢线 —— server 的 user_invalidate 周期扫描(默认 10s)
// 会 close(910) 掉不合规的在线会话(只踢平台不合规的那条,同 user 其它端不受影响),
// 新登录在 authenticatePSK 即时拦截。
func cmdUserSetPlatforms(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return usageError(opts.usage(`nanotun-admin user set-platforms <username> ["macos,ios,android,windows,linux,router"]   # 留空=不限`))
	}
	u, err := st.GetUserByUsername(ctx, args[0])
	if err != nil {
		return opts.notFoundErr(err, "user.notFound", args[0])
	}
	raw := ""
	if len(args) == 2 {
		raw = args[1]
	}
	csv, err := store.NormalizePlatformCSV(raw)
	if err != nil {
		return err
	}
	if err := st.SetUserAllowedPlatforms(ctx, u.ID, csv); err != nil {
		return err
	}
	_ = st.Audit(ctx, "admin-cli", "user_platforms_set",
		fmt.Sprintf("user:%d", u.ID),
		fmt.Sprintf("username=%s allowed_platforms=%q", u.Username, csv))
	if csv == "" {
		fmt.Fprintln(opts.stdout, opts.T("user.platformsCleared", u.Username))
	} else {
		fmt.Fprintln(opts.stdout, opts.T("user.platformsUpdated", u.Username, csv))
	}
	return nil
}

// pushUserRateRefresh:调 control sock POST /users/rate/refresh?user_id=X。
// 给 user set-bandwidth 用,跟 pushRateRefresh(device 维度) 对称。
func pushUserRateRefresh(opts *globalOpts, userID int64) error {
	cli := newControlHTTPClient(resolveControlSocketPath(opts.controlSocket))
	path := fmt.Sprintf("/users/rate/refresh?user_id=%d", userID)
	_, err := controlDo(cli, "POST", path, nil)
	return err
}

// cmdUserCreate:创建一个 PSK 用户。0008 起不再接受 fixed-vip-* 标志 —— 用户创建时
// 还没有 device,无处落地 fixed vIP。流程改为:用户创建后让他登录一次自动 upsert
// device,再用 `nanotun-admin device set-fixed-vip <device_id>` 给该 device 钉 IP。
func cmdUserCreate(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("user create", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	psk := fs.String("psk", "", opts.T("user.flag.createPSK"))
	isAdmin := fs.Bool("admin", false, opts.T("user.flag.admin"))
	exitAllowed := fs.Bool("exit-allowed", true, opts.T("user.flag.exitAllowed"))
	platforms := fs.String("platforms", "", opts.T("user.flag.platforms"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(opts.usage("nanotun-admin user create <username> [--psk PLAIN] [--admin] [--exit-allowed=false] [--platforms macos,ios,...]"))
	}
	username := strings.TrimSpace(pos[0])
	if username == "" {
		return errors.New(opts.T("profile.usernameEmpty"))
	}
	// 空 = 不限;非空则校验每个 token 合法(拼错直接报错,防把用户锁死在门外)。
	allowedPlatforms, err := store.NormalizePlatformCSV(*platforms)
	if err != nil {
		return err
	}

	if *psk != "" {
		opts.warnPSKOnArgv()
	}
	plain := *psk
	autogen := false
	if plain == "" {
		gen, err := util.GeneratePSK()
		if err != nil {
			return err
		}
		plain = gen
		autogen = true
	}
	hash, err := auth.HashPSK(plain)
	if err != nil {
		return err
	}
	// 0013(2026-05-25):新建 user 立即分配 credential_id(UUID v4)+ credential_created_at;
	// 客户端首次扫 credentials show 拿到的 (UUID, created_at) 与 user create 时刻对齐。
	credID := uuid.NewString()
	credNow := time.Now().UTC().Unix()
	u, err := st.CreateUser(ctx, store.NewUser{
		Username:            username,
		PSKHash:             hash,
		IsAdmin:             *isAdmin,
		ExitAllowed:         *exitAllowed,
		AllowedPlatforms:    allowedPlatforms,
		CredentialID:        credID,
		CredentialCreatedAt: credNow,
	})
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	// 与 web(user_create)对等的审计:CLI 建号同样落 audit,便于事后归因。
	_ = st.Audit(ctx, "admin-cli", "user_create",
		fmt.Sprintf("user:%d", u.ID),
		fmt.Sprintf("username=%s admin=%v exit_allowed=%v platforms=%s", u.Username, *isAdmin, *exitAllowed, allowedPlatforms))

	type out struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		PSK      string `json:"psk"`
		Note     string `json:"note,omitempty"`
	}
	o := out{ID: u.ID, Username: u.Username, PSK: plain}
	if autogen {
		o.Note = opts.T("user.createNote")
	}
	if opts.json {
		return printJSON(opts.stdout, o)
	}
	fmt.Fprintln(opts.stdout, opts.T("user.created", u.ID, u.Username))
	fmt.Fprintln(opts.stdout, opts.T("user.pskLine", plain))
	if autogen {
		fmt.Fprintln(opts.stdout, opts.T("user.pskOnce"))
	}
	return nil
}

func cmdUserList(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("user list", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	all := fs.Bool("all", false, opts.T("user.flag.all"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usageError(opts.usage("nanotun-admin user list [--all]"))
	}
	var users []*store.User
	if *all {
		users, err = st.ListUsersAll(ctx)
	} else {
		users, err = st.ListUsers(ctx)
	}
	if err != nil {
		return err
	}
	if opts.json {
		views := make([]userView, 0, len(users))
		for _, u := range users {
			views = append(views, viewFromUser(u))
		}
		return printJSON(opts.stdout, views)
	}
	// P1#7(2026-05-26):多一列 STATUS 区分 enabled / disabled。
	// --all 才会出现 disabled 行;不带 --all 时 STATUS 全是 enabled,但保留这一列
	// 让两种模式下输出宽度一致,用户脚本 awk $5 不会因 mode 切换错位。
	t := newTable(opts.stdout, "ID", "USERNAME", "ADMIN", "EXIT", "STATUS", "CREATED_AT")
	for _, u := range users {
		status := "enabled"
		if u.DisabledAt != 0 {
			status = "disabled"
		}
		t.row(u.ID, u.Username, fmtBool(u.IsAdmin),
			fmtBool(u.ExitAllowed), status, fmtTimeUnix(u.CreatedAt))
	}
	return t.flush()
}

// userView 是 user list / show 在 --json 下的对外形态：去掉 psk_hash 等敏感字段。
//
// 0008 起 fixed_vip_* 不再在 users 视图里 —— 见 device set-fixed-vip / device show。
//
// P1#4(2026-05-26):0013 profile/credentials 解耦后,credential_id /
// credential_created_at 是 client / 运维下游脚本要按 UUID 索引的关键字段,
// 必须在 JSON 输出里。
//   - CredentialID:       老 user 未 backfill 时为空,omitempty 让 JSON 不出键;
//     backfill 后是 36 字符 UUID v4。
//   - CredentialCreatedAt: 用 *int64,nil = 「老 row 还没 rotate 过 / 还没发过 QR」,
//     0 = 不可能(rotate 路径会显式塞 now);用指针避免与 0 混淆,
//     omitempty 自动隐藏 nil 字段。
type userView struct {
	ID                  int64  `json:"id"`
	Username            string `json:"username"`
	IsAdmin             bool   `json:"is_admin"`
	ExitAllowed         bool   `json:"exit_allowed"`
	AllowedPlatforms    string `json:"allowed_platforms,omitempty"`
	MaxSessions         int    `json:"max_sessions"` // 0=跟随全局;>0=覆盖;-1=不限
	Role                string `json:"role"`
	CreatedAt           int64  `json:"created_at"`
	DisabledAt          int64  `json:"disabled_at,omitempty"`
	SSOProvider         string `json:"sso_provider,omitempty"`
	SSOSubject          string `json:"sso_subject,omitempty"`
	CredentialID        string `json:"credential_id,omitempty"`
	CredentialCreatedAt *int64 `json:"credential_created_at,omitempty"`
}

func viewFromUser(u *store.User) userView {
	v := userView{
		ID: u.ID, Username: u.Username, IsAdmin: u.IsAdmin,
		ExitAllowed: u.ExitAllowed, AllowedPlatforms: u.AllowedPlatforms,
		MaxSessions: u.MaxSessions, Role: u.Role,
		CreatedAt: u.CreatedAt, DisabledAt: u.DisabledAt,
		SSOProvider: u.SSOProvider, SSOSubject: u.SSOSubject,
		CredentialID: u.CredentialID,
	}
	if u.CredentialCreatedAt > 0 {
		ts := u.CredentialCreatedAt
		v.CredentialCreatedAt = &ts
	}
	return v
}

func cmdUserShow(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) != 1 {
		return usageError(opts.usage("nanotun-admin user show <username>"))
	}
	u, err := st.GetUserByUsername(ctx, args[0])
	if err != nil {
		return opts.notFoundErr(err, "user.notFound", args[0])
	}
	if opts.json {
		return printJSON(opts.stdout, viewFromUser(u))
	}
	// 字段标签走 opts.T(可 --lang 切换);%-20s 保持值列对齐,英文下与历史逐字节一致。
	// 说明:标签是「纯文本视图」的展示用途;--json 输出的字段 key 恒为英文(见 userView),
	// 脚本请以 --json 为准,不要 grep 本视图的本地化标签。
	fmt.Fprintf(opts.stdout, "%-20s%d\n", opts.T("user.show.id"), u.ID)
	fmt.Fprintf(opts.stdout, "%-20s%s\n", opts.T("user.show.username"), u.Username)
	fmt.Fprintf(opts.stdout, "%-20s%s\n", opts.T("user.show.isAdmin"), fmtBool(u.IsAdmin))
	fmt.Fprintf(opts.stdout, "%-20s%s\n", opts.T("user.show.exitAllowed"), fmtBool(u.ExitAllowed))
	fmt.Fprintf(opts.stdout, "%-20s%s\n", opts.T("user.show.allowedPlatforms"), dashIfEmpty(u.AllowedPlatforms))
	fmt.Fprintf(opts.stdout, "%-20s%s\n", opts.T("user.show.maxSessions"), formatMaxSessions(opts, u.MaxSessions))
	fmt.Fprintf(opts.stdout, "%-20s%s\n", opts.T("user.show.createdAt"), fmtTimeUnix(u.CreatedAt))
	if u.DisabledAt != 0 {
		fmt.Fprintf(opts.stdout, "%-20s%s\n", opts.T("user.show.disabledAt"), fmtTimeUnix(u.DisabledAt))
	}
	if u.SSOProvider != "" {
		fmt.Fprintf(opts.stdout, "%-20s%s/%s\n", opts.T("user.show.sso"), u.SSOProvider, u.SSOSubject)
	}
	// 0013(2026-05-25):凭证 UUID + 上次 rotate 时间。老 user(0013 之前建,credential_id
	// 仍为空)显示「(未生成)」,提示运维「下次跑 credentials show / reset-psk 会自动 backfill」。
	credIDStr := u.CredentialID
	if credIDStr == "" {
		credIDStr = opts.T("user.notGenerated")
	}
	credTimeStr := opts.T("user.notGenerated")
	if u.CredentialCreatedAt > 0 {
		credTimeStr = time.Unix(u.CredentialCreatedAt, 0).Local().Format(time.RFC3339)
	}
	fmt.Fprintf(opts.stdout, "%-20s%s\n", opts.T("user.show.credentialID"), credIDStr)
	fmt.Fprintf(opts.stdout, "%-20s%s\n", opts.T("user.show.credentialCreated"), credTimeStr)
	// 顺手列一下这个用户的所有设备 + 各自的 fixed_vip_*,方便管理员一眼看完。
	devs, err := st.ListDevicesByUser(ctx, u.ID)
	if err == nil && len(devs) > 0 {
		fmt.Fprintln(opts.stdout, opts.T("user.show.devices"))
		for _, d := range devs {
			fmt.Fprintf(opts.stdout, "  - id=%d name=%q platform=%s fixed_v4=%s fixed_v6=%s last_seen=%s\n",
				d.ID, d.DeviceName, dashIfEmpty(d.Platform),
				dashIfEmpty(d.FixedVIPv4), dashIfEmpty(d.FixedVIPv6),
				fmtTimeUnix(d.LastSeenAt))
		}
	}
	return nil
}

func cmdUserSetDisabled(ctx context.Context, st *store.Store, opts *globalOpts, args []string, disabled bool) error {
	if len(args) != 1 {
		if disabled {
			return usageError(opts.usage("nanotun-admin user disable <username>"))
		}
		return usageError(opts.usage("nanotun-admin user enable <username>"))
	}
	u, err := st.GetUserByUsername(ctx, args[0])
	if err != nil {
		return opts.notFoundErr(err, "user.notFound", args[0])
	}
	if disabled {
		if err := st.DisableUser(ctx, u.ID); err != nil {
			return err
		}
		// 与 web(user_disable)对等的审计。
		_ = st.Audit(ctx, "admin-cli", "user_disable",
			fmt.Sprintf("user:%d", u.ID), "username="+u.Username)
		fmt.Fprintln(opts.stdout, opts.T("user.disabled", u.Username))
		return nil
	}
	if err := st.EnableUser(ctx, u.ID); err != nil {
		return err
	}
	// 与 web(user_enable)对等的审计。
	_ = st.Audit(ctx, "admin-cli", "user_enable",
		fmt.Sprintf("user:%d", u.ID), "username="+u.Username)
	fmt.Fprintln(opts.stdout, opts.T("user.enabled", u.Username))
	return nil
}

func cmdUserDelete(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) != 1 {
		return usageError(opts.usage("nanotun-admin user delete <username>"))
	}
	u, err := st.GetUserByUsername(ctx, args[0])
	if err != nil {
		return opts.notFoundErr(err, "user.notFound", args[0])
	}
	if !opts.yes {
		ok, err := confirm(opts, opts.T("user.confirmDelete", u.Username))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
			return nil
		}
	}
	if err := st.DeleteUser(ctx, u.ID); err != nil {
		return err
	}
	// 与 web(user_delete)对等的审计:删号是最高破坏性操作,必须可归因。
	_ = st.Audit(ctx, "admin-cli", "user_delete",
		fmt.Sprintf("user:%d", u.ID), "username="+u.Username)
	fmt.Fprintln(opts.stdout, opts.T("user.deleted", u.Username, u.ID))
	return nil
}

func cmdUserResetPSK(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("user reset-psk", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	psk := fs.String("psk", "", opts.T("user.flag.resetPSK"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(opts.usage("nanotun-admin user reset-psk <username> [--psk PLAIN]"))
	}
	u, err := st.GetUserByUsername(ctx, pos[0])
	if err != nil {
		return opts.notFoundErr(err, "user.notFound", pos[0])
	}
	// P2#6(2026-05-26):禁用账号不允许 rotate-psk —— 「踢线」与「下发新凭证」语义
	// 矛盾(rotate 后 user_invalidate scan 仍会把这条踢掉,新 PSK 等于发了张废卡);
	// 也避免运维误以为 reset-psk 同时会 enable 用户。先 enable 再 rotate。
	if u.DisabledAt != 0 {
		return errors.New(opts.T("user.resetDisabled", u.Username, u.Username))
	}
	// 第十一轮深扫 MED:reset-psk 是破坏性操作(立即作废旧 PSK + 踢线该用户所有会话),main.go 顶部
	// 「危险操作(删用户 / 重置 PSK)需 --yes 二次确认」的契约点名要求它像 user delete 一样先确认。
	// 此前直接执行,误打用户名会静默把**错的人**的凭证换掉。--yes / -y 跳过(供脚本/自动化)。
	if !opts.yes {
		ok, _ := confirm(opts, opts.T("user.confirmResetPSK", u.Username))
		if !ok {
			fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
			return nil
		}
	}
	if *psk != "" {
		opts.warnPSKOnArgv()
	}
	plain := *psk
	autogen := false
	if plain == "" {
		gen, err := util.GeneratePSK()
		if err != nil {
			return err
		}
		plain = gen
		autogen = true
	}
	hash, err := auth.HashPSK(plain)
	if err != nil {
		return err
	}
	// 0013(2026-05-25):reset-psk 走统一入口刷 credential_created_at + 必要时
	// backfill credential_id;client 端按 UUID 索引,下次扫 credentials show 拿到
	// 同 UUID + 新 created_at + 新 PSK → 覆盖本地旧 PSK,达成「PSK rotate 后客户端
	// 无需手动删旧条目」的承诺。
	priorCredID := u.CredentialID
	newCredID, _, err := st.RotateUserPSKAndEnsureCredential(ctx, u, hash)
	if err != nil {
		// 第七轮深扫 P1:`ErrPSKConcurrentRotation` 是 CAS 失败 sentinel —— 别让
		// admin 看到 "store: PSK rotation lost CAS race (snapshot stale)" 这种
		// 实现层文案,直接给中文操作提示 + 写 audit。其它 err 透传(unique violation /
		// db error 等真错误)。
		if errors.Is(err, store.ErrPSKConcurrentRotation) {
			// 第九轮深扫 P2:三处 user_reset_psk_raced(cmd_user / cmd_credentials /
			// handler_users)统一 detail 为 `username=X reason=... via=Y`。运维
			// `audit list --action user_reset_psk_raced` 后能用同一 schema 解析,
			// 不必记 user= vs username= 双轨。via 见 `nanotun-admin/README.md`
			// audit detail 约定节。
			_ = st.Audit(ctx, "admin-cli", "user_reset_psk_raced",
				fmt.Sprintf("user:%d", u.ID),
				fmt.Sprintf("username=%s reason=concurrent_rotation_by_peer_admin via=user_reset_psk", u.Username))
			return errors.New(opts.T("user.resetRaced", u.Username))
		}
		return err
	}
	// audit:跟 user_create / user_disable 同 admin-cli actor;**严禁**把明文 PSK 写进 detail
	// (审计日志本身长期持久化,落 PSK 等同永久泄密)。detail 只带 username + credential_id 足够追溯;
	// 顺手把 backfill 事件并到这条 detail(老 user 首次 reset-psk 才会触发),省一条 audit 行。
	detail := fmt.Sprintf("user=%s credential_id=%s", u.Username, newCredID)
	if priorCredID == "" {
		detail += fmt.Sprintf(" backfilled credential_id=%s", newCredID)
	}
	_ = st.Audit(ctx, "admin-cli", "user_reset_psk",
		fmt.Sprintf("user:%d", u.ID), detail)

	if opts.json {
		return printJSON(opts.stdout, map[string]any{
			"id":       u.ID,
			"username": u.Username,
			"psk":      plain,
		})
	}
	fmt.Fprintln(opts.stdout, opts.T("user.pskReset", u.Username))
	fmt.Fprintln(opts.stdout, opts.T("user.resetNewPSK", plain))
	if autogen {
		fmt.Fprintln(opts.stdout, opts.T("user.resetOnce"))
	}
	return nil
}
