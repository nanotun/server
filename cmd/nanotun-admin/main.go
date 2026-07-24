// Command nanotun-admin 是 nanotun 自托管模式（PSK）的管理 CLI。
//
// 用法：
//
//	nanotun-admin [--db-path data/nanotun.db] [--json] <subcommand> [...]
//
// 子命令分组：user / device / lease / acl / setting / init。
// 详见 nanotun-admin/README.md，或 `nanotun-admin help`。
//
// 设计原则：
//  1. 直接读写 nanotun 的 SQLite 文件，不经过网络。
//     适合本地运维 / 服务器上 SSH 后用，跟 admin Web UI（M2）功能正交。
//  2. 默认人类可读 + 只读为主；危险操作（删除用户 / 重置 PSK）需要 --yes 二次确认。
//  3. 任何子命令异常都打印到 stderr 并以非 0 退出，便于脚本化。
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nanotun/server/store"
)

// version 由 build 脚本通过 -ldflags "-X main.version=..." 注入；默认 dev。
var version = "dev"

// globalOpts 由 main 解析后传给所有子命令。
type globalOpts struct {
	dbPath        string
	controlSocket string
	json          bool
	yes           bool
	lang          string // "en"(默认)/ "zh";--lang 或 env NANOTUN_LANG

	stdout io.Writer // 默认 os.Stdout；测试可替换
	stderr io.Writer
	stdin  io.Reader
}

func main() {
	opts := &globalOpts{
		stdout: os.Stdout,
		stderr: os.Stderr,
		stdin:  os.Stdin,
	}
	rest, err := parseGlobalFlags(os.Args[1:], opts)
	if err != nil {
		fmt.Fprintln(opts.stderr, err.Error())
		os.Exit(2)
	}
	if len(rest) == 0 {
		printUsage(opts.stderr, opts.lang)
		os.Exit(2)
	}

	exitCode := runRoot(rest, opts)
	os.Exit(exitCode)
}

// runRoot 是 main 的可测试入口：返回退出码而不是直接 os.Exit。
func runRoot(args []string, opts *globalOpts) int {
	subcmd, rest := args[0], args[1:]

	switch subcmd {
	case "help", "-h", "--help":
		printUsage(opts.stdout, opts.lang)
		return 0
	case "version", "--version":
		fmt.Fprintln(opts.stdout, "nanotun-admin", version)
		return 0
	case "init":
		return runWithStore(opts, false, func(ctx context.Context, st *store.Store) error {
			return cmdInit(ctx, st, opts, rest)
		})
	case "user":
		return runWithStore(opts, subIsReadOnly(subcmd, rest), func(ctx context.Context, st *store.Store) error {
			return cmdUser(ctx, st, opts, rest)
		})
	case "device":
		return runWithStore(opts, subIsReadOnly(subcmd, rest), func(ctx context.Context, st *store.Store) error {
			return cmdDevice(ctx, st, opts, rest)
		})
	case "lease":
		return runWithStore(opts, subIsReadOnly(subcmd, rest), func(ctx context.Context, st *store.Store) error {
			return cmdLease(ctx, st, opts, rest)
		})
	case "acl":
		return runWithStore(opts, subIsReadOnly(subcmd, rest), func(ctx context.Context, st *store.Store) error {
			return cmdACL(ctx, st, opts, rest)
		})
	case "setting":
		// 第十一轮深扫 LOW:`setting probe-dial-host` 只做 DNS/ICMP 探测,cmdSettingProbeDialHost
		// 根本不接收 *store.Store。此前它落入 subIsReadOnly=false 分支,为一条纯网络命令白开
		// read-write 连接并触发 st.Migrate(ctx) 写 —— DB 被 server 占写 / 磁盘只读 / 库尚未 init 时,
		// 探测会以完全无关的原因先行失败。这里在**打开 store 之前**直接短路到探测,零 DB 依赖。
		if len(rest) > 0 && rest[0] == "probe-dial-host" {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := cmdSettingProbeDialHost(ctx, opts, rest[1:]); err != nil {
				fmt.Fprintln(opts.stderr, opts.errText(err))
				return exitCodeForErr(err)
			}
			return 0
		}
		return runWithStore(opts, subIsReadOnly(subcmd, rest), func(ctx context.Context, st *store.Store) error {
			return cmdSetting(ctx, st, opts, rest)
		})
	case "profile":
		// 0013(2026-05-25)起 profile 不再嵌 PSK;0014(2026-05-25)起移除 pid 黑名单,
		// profile 只剩 show 子命令,永远只读。
		return runWithStore(opts, true, func(ctx context.Context, st *store.Store) error {
			return cmdProfile(ctx, st, opts, rest)
		})
	case "credentials", "cred":
		// 0013(2026-05-25):credentials show 默认只读(--psk 校验路径走 ensure 时
		// 老 user 会 backfill credential_id 一次,这属于写;--rotate-psk 总是写);
		// 保守按 credentialsIsReadOnly 判断,避免老 user 走只读连接撞 SQLITE_READONLY。
		return runWithStore(opts, credentialsIsReadOnly(rest), func(ctx context.Context, st *store.Store) error {
			return cmdCredentials(ctx, st, opts, rest)
		})
	case "audit":
		return runWithStore(opts, subIsReadOnly(subcmd, rest), func(ctx context.Context, st *store.Store) error {
			return cmdAudit(ctx, st, opts, rest)
		})
	case "reload":
		// reload 不需要打开 SQLite,直接走 control socket。
		if err := cmdReload(context.Background(), nil, opts, rest); err != nil {
			fmt.Fprintln(opts.stderr, opts.errText(err))
			return exitCodeForErr(err)
		}
		return 0
	case "kick":
		if err := cmdKick(context.Background(), nil, opts, rest); err != nil {
			fmt.Fprintln(opts.stderr, opts.errText(err))
			return exitCodeForErr(err)
		}
		return 0
	case "connection", "conn":
		return cmdConnection(opts, rest)
	case "backup":
		return runWithStore(opts, false, func(ctx context.Context, st *store.Store) error {
			return cmdBackup(ctx, st, opts, rest)
		})
	case "vacuum":
		return runWithStore(opts, false, func(ctx context.Context, st *store.Store) error {
			return cmdVacuum(ctx, st, opts, rest)
		})
	case "restore":
		return cmdRestore(opts, rest)
	case "route":
		// route list 是只读;approve/reject/delete 走写。
		return runWithStore(opts, routeIsReadOnly(rest), func(ctx context.Context, st *store.Store) error {
			return cmdRoute(ctx, st, opts, rest)
		})
	case "exit":
		// exit list 只读;designate/revoke 写 subnet_routes / devices。
		return runWithStore(opts, exitIsReadOnly(rest), func(ctx context.Context, st *store.Store) error {
			return cmdExit(ctx, st, opts, rest)
		})
	case "config":
		// J4(2026-05-22):config lint 走 strict 校验,不需要打开 SQLite。
		return cmdConfig(opts, rest)
	default:
		fmt.Fprintf(opts.stderr, "%s\n\n", opts.T("cli.unknownSubcommandBare", subcmd))
		printUsage(opts.stderr, opts.lang)
		return 2
	}
}

// subIsReadOnly 判断「<sub> <verb> ...」整体是否走 SQLite query_only。
//
// 凡是 list / show / get / 空 verb（user 等的「裸」默认= 用法）都按只读处理 ——
// 这条路径可以放心和 server 的写 conn 并行,WAL 共享锁不互阻。
// 其余(create/delete/disable/enable/set/...)按写处理,跑 migration + 写连接。
//
// 当 verb 不在白名单内时返回 false(更保守:误判成写最差是少一点并发性,误判成读
// 会让正常写被 SQLite 拒,损失更大)。
func subIsReadOnly(subcmd string, rest []string) bool {
	verb := ""
	if len(rest) > 0 {
		verb = rest[0]
	}
	switch verb {
	case "list", "show", "get", "":
		return true
	}
	return false
}

// routeIsReadOnly: route list 只读;approve/reject/delete 写 subnet_routes。
func routeIsReadOnly(rest []string) bool {
	if len(rest) == 0 {
		return true
	}
	switch rest[0] {
	case "list":
		return true
	case "approve", "reject", "delete":
		return false
	}
	return false
}

// credentialsIsReadOnly:credentials show 在以下情况会写 users 表,需走 read-write 连接:
//
//   - --rotate-psk:总是写(psk_hash + credential_created_at);
//   - --psk PLAIN:**绝大多数情况只读**,但若 user 是 0013 之前的老 row(credential_id
//     仍为 NULL),首次 store.EnsureUserCredentialID 会 backfill 一行 UUID v4。
//
// 区分两种 --psk 子情形需要先打开 DB 看 user.CredentialID,我们没法在 routing 层做到。
// 保守:任何 `credentials show` 都按写处理。代价是丢点 query_only 的并发性,但与 server
// 写 audit / lease 一起跑时,WAL 写连接互斥也只是几 ms 级阻塞。
func credentialsIsReadOnly(rest []string) bool {
	if len(rest) == 0 {
		return true
	}
	switch rest[0] {
	case "show":
		return false
	}
	return true
}

// runWithStore 打开 SQLite + 跑 migration，再交给 fn；任何错误打到 stderr。
//
// readOnly=true 时启动 SQLite query_only,只读子命令(list / show / audit list 等)
// 强烈推荐这条路径 —— 即便 server 进程正在写 audit / lease,admin 这边的读连接
// 也走 WAL 共享锁,与写并行不互阻。误调写 SQL 会被 SQLite 拒(SQLITE_READONLY),
// 起到守门作用。
func runWithStore(opts *globalOpts, readOnly bool, fn func(ctx context.Context, st *store.Store) error) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.Open(ctx, opts.dbPath, store.Options{ReadOnly: readOnly})
	if err != nil {
		fmt.Fprintf(opts.stderr, "open store %s: %v\n", opts.dbPath, err)
		return 1
	}
	defer st.Close()

	// 只读模式禁止跑 migration(会触发 CREATE TABLE,被 query_only 拒)。
	// migration 由写路径(init / 各 write 子命令)负责,只读路径假设 server
	// 已经把 schema 迁好;如果 admin 在 schema 不全的状态下跑只读命令,
	// 报 "no such table" 会立即让运维察觉。
	if !readOnly {
		if err := st.Migrate(ctx); err != nil {
			fmt.Fprintf(opts.stderr, "migrate: %v\n", err)
			return 1
		}
	}

	if err := fn(ctx, st); err != nil {
		fmt.Fprintln(opts.stderr, opts.errText(err))
		// 第十一轮深扫 LOW:usage/参数错误 → exit 2(与 restore / config lint / 顶层 dispatch 一致),
		// 其余运行期错误 → exit 1。
		return exitCodeForErr(err)
	}
	return 0
}

// parseGlobalFlags 抽出 --db-path / --json / --yes 等全局 flag，返回剩余 args。
//
// 故意手写，不用 flag.FlagSet：那东西遇到「子命令前没声明过的 flag」会直接 fail，
// 不利于把 flag 散布到各子命令；换成手写后 globalOpts 与子命令 flag 互不冲突。
func parseGlobalFlags(args []string, opts *globalOpts) ([]string, error) {
	opts.dbPath = "data/nanotun.db"
	if v := os.Getenv("NANOTUN_DB"); v != "" {
		opts.dbPath = v
	}

	// 语言:默认英文;env NANOTUN_LANG 覆盖;--lang 最高优先(下面循环里处理)。
	opts.lang = langDefault
	if v := os.Getenv("NANOTUN_LANG"); v != "" {
		if l, ok := normalizeLang(v); ok {
			opts.lang = l
		}
	}

	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--lang":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s expects an argument (en|zh)", a)
			}
			if l, ok := normalizeLang(args[i+1]); ok {
				opts.lang = l
			} else {
				return nil, fmt.Errorf("unsupported --lang %q (want en|zh)", args[i+1])
			}
			i++
		case strings.HasPrefix(a, "--lang="):
			v := a[len("--lang="):]
			if l, ok := normalizeLang(v); ok {
				opts.lang = l
			} else {
				return nil, fmt.Errorf("unsupported --lang %q (want en|zh)", v)
			}
		case a == "--db-path" || a == "--db":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s expects an argument", a)
			}
			opts.dbPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--db-path="):
			opts.dbPath = a[len("--db-path="):]
		case strings.HasPrefix(a, "--db="):
			opts.dbPath = a[len("--db="):]
		case a == "--json":
			opts.json = true
		case a == "--yes" || a == "-y":
			opts.yes = true
		case a == "--control-socket":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s expects an argument", a)
			}
			opts.controlSocket = args[i+1]
			i++
		case strings.HasPrefix(a, "--control-socket="):
			opts.controlSocket = a[len("--control-socket="):]
		default:
			out = append(out, a)
		}
	}
	return out, nil
}

const usageTextZH = `nanotun-admin: 自托管 nanotun 的本地管理工具

USAGE
  nanotun-admin [global flags] <subcommand> [args...]

GLOBAL FLAGS
  --db-path PATH         SQLite 路径（默认 data/nanotun.db；env NANOTUN_DB）
  --control-socket PATH  server 控制 socket（默认 /run/nanotun/control.sock；env NANOTUN_CONTROL_SOCKET）
  --lang en|zh           输出语言（默认 en；env NANOTUN_LANG）
  --json                 以 JSON 输出（脚本化用）
  --yes, -y              危险操作跳过二次确认

SUBCOMMANDS
  init [--reset-psk]                            首次部署向导：建库 + 创建第一个 admin（默认幂等；setup 完成后再跑为 noop）
  user create <username> [flags]                创建用户，PSK 默认随机生成并 print 到 stdout 一次
  user list [--all]                             列出用户(默认仅活跃;--all 含已禁用)
  user show <username>                          查看一个用户的详情
  user disable|enable <username>                禁用 / 重新启用
  user delete <username>                        物理删除（设备/lease/ACL 一起 cascade）
  user reset-psk <username> [--psk <plain>]     重置 PSK（不指定则随机生成）
  user set-bandwidth <username> [--up-mibs N|--up-bps N] [--down-mibs N|--down-bps N] [--no-refresh]
                                                user-level 带宽 quota(0012);0 = 不限;改后自动 control sock /users/rate/refresh
  user set-max-sessions <username> <n>          按账号并发会话上限(0021);>0 覆盖全局 / 0 跟随全局 / -1 该账号不限;仅对未来登录生效
  device create <username> --uuid <uuidv4> [--name N] [--platform P]
                                                用指定 UUID 预创建设备(先配后连;配合 exit designate 预置出口)
  device list [--user <username>] [--effective]
                                                列出设备(含 fixed_vip / 限速列);--effective 显示叠加 settings/toml/user 取 min 后的值
  device delete <device_id>                     删除一个设备及其 lease
  device set-fixed-vip <device_id> [--v4 IP] [--v6 IP] [--force]   按设备钉死 vIP(0008 起;空串清除)
  device set-rate <device_id> [--up-mibs N|--up-bps N] [--down-mibs N|--down-bps N] [--no-refresh]
                                                per-device 带宽限速(0011);0 = 清除回退全局默认;改后自动 control sock /rate/refresh
  lease list                                    列出全部 vIP 租约
  lease release <device_id>                     释放某设备的 lease
  lease set <device_id> [--v4 IP] [--v6 IP] [--manual]  手动指派 lease（管理员钉死）
  audit list [--since DURATION] [--limit N] [--action ACTION]
                                                列出最近的审计日志(--action 精确过滤,例:user_reset_psk / login.fail.bad_psk)
  acl list                                      列出 ACL 规则
  acl allow <src_user> <dst_user>               新增 allow 规则
  acl deny  <src_user> <dst_user>               新增 deny 规则
  acl del <id>                                  删除一条规则
  setting get <key>                             读取 app_settings
  setting set <key> <value>                     写入 app_settings
  setting list                                  列出 app_settings 全表
  setting rate [--up-mibs N|--up-bps N] [--down-mibs N|--down-bps N] [--burst-kib N] [--no-refresh]
                                                全局默认带宽限速(0011)+ rate.Limiter burst(0012);不传任何值 = dry-run 仅展示
  profile show [<username>] --host HOST [--node ...] [--format json|url|both|qr|qr-png]
                                                导出客户端可直接导入的 profile(仅服务器配置;PSK 已剥离到 credentials show)
                                                省略 <username> = server-level 模式(Hy2 mTLS 客户端证书 CN 用合成占位符,不绑 user;
                                                nanotun-web /server-qr 走这条路径)
  credentials show <username> [--psk P | --rotate-psk] [--format json|url|both|qr|qr-png] [--output FILE]
                                                导出客户端可扫码的凭据(username + PSK,UUID 索引)
  credentials list [--json]                     列出已发过凭证(credential_id 非空)的所有用户(含 disabled)
  reload [acl]                                  通过 control socket 让 server 热重载 ACL snapshot
  route list [--user U] [--device D] [--status pending|approved|rejected]
                                                列出 subnet_routes 表(子网路由声明)
  route approve <device_id> <cidr> [--force]    批准客户端声明的子网路由(0/0、::/0 有平台闸口,--force 越过)
  route reject  <device_id> <cidr> [--reason ...]  拒绝
  route delete  <device_id> <cidr>              物理删除一条路由声明
  exit designate <device_id> [--v4 IP] [--v6 IP] [--no-vip] [--force]
                                                一键指定出口:批准 0/0+::/0 + 钉死固定 vIP(默认焊死当前 lease)
  exit list [--json]                            列出所有出口节点(有 approved 0/0/::/0 的设备)及固定 vIP
  exit revoke <device_id> [--clear-vip]         撤销出口资格(删 0/0+::/0;--clear-vip 同时清固定 vIP)
  kick session <conn_id> [--reason TEXT]        踢一条会话
  kick user <username|u<id>> [--reason TEXT]    踢某 user 所有会话
  kick device <devices.id|device_uuid> [--reason TEXT]    踢某 device 所有会话(0011)
  connection list                               列出当前所有在线会话(从 server 实时拉)
  backup [--out PATH]                           SQLite VACUUM INTO 强一致快照
  restore <src.db> [--force-while-running]      用快照覆盖现役 DB(server 应停)
  vacuum                                        VACUUM 重建,回收空闲页
  config lint <config.toml>                     strict 校验 server 配置(未知字段 → 退出 3)
  help / version

更多细节：nanotun-admin/README.md
`

const usageTextEN = `nanotun-admin: local management tool for self-hosted nanotun

USAGE
  nanotun-admin [global flags] <subcommand> [args...]

GLOBAL FLAGS
  --db-path PATH         SQLite path (default data/nanotun.db; env NANOTUN_DB)
  --control-socket PATH  server control socket (default /run/nanotun/control.sock; env NANOTUN_CONTROL_SOCKET)
  --lang en|zh           output language (default en; env NANOTUN_LANG)
  --json                 output as JSON (for scripting)
  --yes, -y              skip confirmation for dangerous operations

SUBCOMMANDS
  init [--reset-psk]                            first-deploy wizard: create DB + first admin (idempotent by default; a no-op once setup is done)
  user create <username> [flags]                create a user; PSK is randomly generated and printed to stdout once by default
  user list [--all]                             list users (active only by default; --all includes disabled)
  user show <username>                          show details of a single user
  user disable|enable <username>                disable / re-enable
  user delete <username>                        hard delete (devices/leases/ACLs cascade together)
  user reset-psk <username> [--psk <plain>]     reset PSK (random if not specified)
  user set-bandwidth <username> [--up-mibs N|--up-bps N] [--down-mibs N|--down-bps N] [--no-refresh]
                                                user-level bandwidth quota (0012); 0 = unlimited; auto control sock /users/rate/refresh after change
  user set-max-sessions <username> <n>          per-user concurrent session cap (0021); >0 overrides global / 0 follows global / -1 unlimited for this user; future logins only
  device create <username> --uuid <uuidv4> [--name N] [--platform P]
                                                pre-create a device with a given UUID (configure before connecting; pairs with exit designate)
  device list [--user <username>] [--effective]
                                                list devices (incl. fixed_vip / rate columns); --effective shows the min across settings/toml/user
  device delete <device_id>                     delete a device and its lease
  device set-fixed-vip <device_id> [--v4 IP] [--v6 IP] [--force]   pin vIP per device (since 0008; empty string clears)
  device set-rate <device_id> [--up-mibs N|--up-bps N] [--down-mibs N|--down-bps N] [--no-refresh]
                                                per-device bandwidth limit (0011); 0 = clear and fall back to global default; auto control sock /rate/refresh after change
  lease list                                    list all vIP leases
  lease release <device_id>                     release a device's lease
  lease set <device_id> [--v4 IP] [--v6 IP] [--manual]  manually assign a lease (admin-pinned)
  audit list [--since DURATION] [--limit N] [--action ACTION]
                                                list recent audit logs (--action filters exactly, e.g. user_reset_psk / login.fail.bad_psk)
  acl list                                      list ACL rules
  acl allow <src_user> <dst_user>               add an allow rule
  acl deny  <src_user> <dst_user>               add a deny rule
  acl del <id>                                  delete a rule
  setting get <key>                             read app_settings
  setting set <key> <value>                     write app_settings
  setting list                                  list the whole app_settings table
  setting rate [--up-mibs N|--up-bps N] [--down-mibs N|--down-bps N] [--burst-kib N] [--no-refresh]
                                                global default bandwidth limit (0011) + rate.Limiter burst (0012); no values = dry-run (show only)
  profile show [<username>] --host HOST [--node ...] [--format json|url|both|qr|qr-png]
                                                export a client-importable profile (server config only; PSK moved to credentials show)
                                                omit <username> = server-level mode (Hy2 mTLS client cert CN uses a synthetic placeholder, not user-bound;
                                                nanotun-web /server-qr uses this path)
  credentials show <username> [--psk P | --rotate-psk] [--format json|url|both|qr|qr-png] [--output FILE]
                                                export scannable client credentials (username + PSK, indexed by UUID)
  credentials list [--json]                     list all users that have been issued credentials (credential_id non-empty; incl. disabled)
  reload [acl]                                  make the server hot-reload the ACL snapshot via the control socket
  route list [--user U] [--device D] [--status pending|approved|rejected]
                                                list the subnet_routes table (subnet route declarations)
  route approve <device_id> <cidr> [--force]    approve a subnet route declared by a client (0/0 and ::/0 pass a platform gate; --force overrides)
  route reject  <device_id> <cidr> [--reason ...]  reject
  route delete  <device_id> <cidr>              hard-delete a route declaration
  exit designate <device_id> [--v4 IP] [--v6 IP] [--no-vip] [--force]
                                                one-click designate exit: approve 0/0+::/0 + pin fixed vIP (welds the current lease by default)
  exit list [--json]                            list all exit nodes (devices with approved 0/0/::/0) and their fixed vIPs
  exit revoke <device_id> [--clear-vip]         revoke exit eligibility (remove 0/0+::/0; --clear-vip also clears the fixed vIP)
  kick session <conn_id> [--reason TEXT]        kick a single session
  kick user <username|u<id>> [--reason TEXT]    kick all sessions of a user
  kick device <devices.id|device_uuid> [--reason TEXT]    kick all sessions of a device (0011)
  connection list                               list all currently online sessions (fetched live from the server)
  backup [--out PATH]                           strongly-consistent snapshot via SQLite VACUUM INTO
  restore <src.db> [--force-while-running]      overwrite the live DB with a snapshot (server should be stopped)
  vacuum                                        VACUUM rebuild to reclaim free pages
  config lint <config.toml>                     strict-validate the server config (unknown field → exit 3)
  help / version

More details: nanotun-admin/README.md
`

func printUsage(w io.Writer, lang string) {
	if lang == langZH {
		fmt.Fprint(w, usageTextZH)
		return
	}
	fmt.Fprint(w, usageTextEN)
}
