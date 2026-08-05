package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
)

// Web 后台管理员的命令行入口。
//
// 为什么需要它:在这条命令出现之前,建后台管理员**只有**浏览器打开 /setup 一条路,而那个
// 页面在 web_admins 表为空时对全网公开 —— 谁先打开谁就是管理员。也就是说机器一装完、7443
// 一放行,到运维本人打开浏览器之间的这段时间是先到先得的(有 captcha + 自适应 PoW 抬成本,
// 但那是减速带不是门)。cmd/nanotun-web/handler_auth.go 里 AllowSetup 那段注释早就写着
// 「此时首个管理员改由 CLI provisioned」,缺的正是这个 CLI。
//
// 有了它,装机脚本可以在服务起来的同一分钟里把账号定下来,窗口宽度从「人什么时候想起来」
// 缩到零 —— 表一非空,/setup 自己就 302 到 /login 了,不需要额外开关。
//
// 密码为什么不做成 --password:命令行参数会进 argv,同机任何用户 ps 一眼就能看到,还会落进
// shell history 和 systemd 的 journal。所以只收三种来源:标准输入、环境变量、交互式隐藏输入。
func cmdWebAdmin(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return usageError(opts.usage("nanotun-admin webadmin <create|list> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return cmdWebAdminCreate(ctx, st, opts, rest)
	case "list", "ls":
		return cmdWebAdminList(ctx, st, opts, rest)
	default:
		return newLocErr("cli.unknownSubcommand", "webadmin", sub)
	}
}

// envWebAdminPassword 是无人值守时传密码的环境变量名。
//
// 环境变量在 /proc/<pid>/environ 里对同 uid 与 root 可见,不是完美方案;但比 argv 好一档
// (argv 对**所有**用户可见),而且是 CI / cloud-init 这类场景唯一顺手的通道。真在意的话用
// --password-stdin 从管道喂。
const envWebAdminPassword = "NANOTUN_WEB_ADMIN_PASSWORD"

func cmdWebAdminCreate(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("webadmin create", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	role := fs.String("role", "admin", opts.T("webadmin.flag.role"))
	pwStdin := fs.Bool("password-stdin", false, opts.T("webadmin.flag.passwordStdin"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError(opts.usage("nanotun-admin webadmin create <username> [--role admin|viewer] [--password-stdin]"))
	}

	username := strings.TrimSpace(pos[0])
	// 与 /setup 同一道门槛(handler_auth.go:116)。两个入口对同一个名字应当给同一个答复。
	if len([]rune(username)) < 3 {
		return newLocErr("webadmin.usernameMin3")
	}

	// 角色在这里先验一道,而不是留给 DAL。两条写入路径对同一个错值的反应本来是不一样的:
	// CreateWebAdmin 会拒(`invalid web admin role "superuser"`),而 CreateFirstWebAdmin
	// 压根不看这个字段(首位强制 admin)—— 于是同一条打错的命令,在有管理员的机器上报错,
	// 在全新机器上一声不吭地建成 admin。而全新机器恰恰是这条命令最常用的场合:装机时
	// 打错一个词,不但没人拦,还会以为自己建的是只读账号。
	switch *role {
	case "admin", "viewer":
	default:
		return newLocErr("webadmin.badRole", *role)
	}

	password, err := readWebAdminPassword(opts, *pwStdin)
	if err != nil {
		return err
	}
	if iss := auth.CheckWebPassword(password); iss != nil {
		return webPasswordIssueErr(iss)
	}

	hash, err := auth.HashPSK(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// 表空与非空走不同的写入路径,这不是可有可无的区分:
	//   * 表空 → CreateFirstWebAdmin。它是单条 INSERT ... WHERE NOT EXISTS,原子,
	//     且强制 admin 角色。如果这时候正好有人在抢 /setup,两边只有一个能落地,
	//     另一个拿 ErrSetupClosed —— 这正是我们要的:抢占窗口有且只有一个赢家。
	//   * 表非空 → CreateWebAdmin。走大小写不敏感去重,允许 viewer。
	n, err := st.CountWebAdmins(ctx)
	if err != nil {
		return err
	}
	in := store.NewWebAdmin{Username: username, PasswordHash: hash, Role: *role}
	var admin *store.WebAdmin
	if n == 0 {
		admin, err = st.CreateFirstWebAdmin(ctx, in)
		if errors.Is(err, store.ErrSetupClosed) {
			// 我们查到表空、写的时候却已经不空了 —— 有人在这几毫秒里抢先建成了。
			// 这句必须说清楚是「被别人抢先」,而不是含糊的写入失败:管理员是谁这件事
			// 事关整台机器的控制权,值得当场去查一眼。
			return newLocErr("webadmin.raceLost")
		}
	} else {
		admin, err = st.CreateWebAdmin(ctx, in)
	}
	if err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			return newLocErr("webadmin.duplicate", username)
		}
		return err
	}

	if opts.json {
		return printJSON(opts.stdout, webAdminView{
			ID: admin.ID, Username: admin.Username, Role: admin.Role,
			Enabled: admin.Enabled, CreatedAt: admin.CreatedAt,
		})
	}
	fmt.Fprintf(opts.stdout, opts.T("webadmin.created")+"\n", admin.ID, admin.Username, admin.Role)
	// 要了 viewer 却拿到 admin,必须当场说破。首位强制 admin 是 DAL 的硬规矩(首位若是
	// viewer,表一非空 /setup 就永久关闭,没人能提权,整个控制台锁成只读),但对着屏幕的人
	// 只会看到自己写了 viewer、上面那行印着 admin —— 不解释一句,他要么以为命令没生效,
	// 要么以为自己建了个只读账号,然后拿它去做只有 admin 能做的事。
	if n == 0 && *role != admin.Role {
		fmt.Fprintf(opts.stdout, opts.T("webadmin.firstRoleForced")+"\n", *role)
	}
	if n == 0 {
		// 首位建成之后 /setup 会自己 302 到 /login(handler 查 CountWebAdmins),
		// 不需要再动配置。明说一句,免得有人以为还得手工关。
		fmt.Fprintln(opts.stdout, opts.T("webadmin.setupClosedNote"))
	}
	return nil
}

func cmdWebAdminList(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("webadmin list", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	admins, err := st.ListWebAdmins(ctx)
	if err != nil {
		return err
	}
	if opts.json {
		out := make([]webAdminView, 0, len(admins))
		for _, a := range admins {
			out = append(out, webAdminView{
				ID: a.ID, Username: a.Username, Role: a.Role,
				Enabled: a.Enabled, CreatedAt: a.CreatedAt,
				LastLoginAt: a.LastLoginAt, TOTPEnabled: a.TOTPEnabled,
			})
		}
		return printJSON(opts.stdout, out)
	}
	t := newTable(opts.stdout, "ID", "USERNAME", "ROLE", "ENABLED", "TOTP", "CREATED_AT", "LAST_LOGIN")
	for _, a := range admins {
		t.row(a.ID, a.Username, a.Role, fmtBool(a.Enabled), fmtBool(a.TOTPEnabled),
			fmtTimeUnix(a.CreatedAt), fmtTimeUnix(a.LastLoginAt))
	}
	return t.flush()
}

// webAdminView 是 webadmin 一族 --json 的形状。密码哈希不出现在任何输出里。
type webAdminView struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   int64  `json:"created_at"`
	LastLoginAt int64  `json:"last_login_at,omitempty"`
	TOTPEnabled bool   `json:"totp_enabled,omitempty"`
}

// readWebAdminPassword 按三种来源取密码,优先级:--password-stdin > 环境变量 > 交互式提问。
//
// 顺序是这么排的:显式给了 --password-stdin 就说明调用方铁了心要从管道喂,不该被恰好存在的
// 环境变量截胡;环境变量则是无人值守场景;都没有才去问人,而问人需要真终端。
func readWebAdminPassword(opts *globalOpts, fromStdin bool) (string, error) {
	if fromStdin {
		b, err := io.ReadAll(opts.stdin)
		if err != nil {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		// 只剥尾部换行:`echo hunter2 | ...` 和 heredoc 都会带一个。其余空白照收 ——
		// 密码里的空格是合法的,替人 trim 会造出「存进去的和输进来的不是一个」。
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if v := os.Getenv(envWebAdminPassword); v != "" {
		return v, nil
	}

	f, ok := opts.stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		// 没有终端又没给密码:说清楚三条路怎么走,别只报一句「需要密码」。
		// 装机脚本、CI、cron 都会撞到这里,而它们看到的只有这一行。
		return "", newLocErr("webadmin.needPassword", envWebAdminPassword)
	}
	fd := int(f.Fd())
	fmt.Fprintf(opts.stderr, opts.T("webadmin.pwPrompt"), auth.MinWebPasswordLen)
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(opts.stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Fprint(opts.stderr, opts.T("webadmin.pwAgain"))
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(opts.stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(first) != string(second) {
		return "", newLocErr("webadmin.pwMismatch")
	}
	return string(first), nil
}

// webPasswordIssueErr 把 auth 包给的「哪一条没过」翻译成 CLI 的话。
// 文案与 Web 那边同义但各走各的目录 —— 判据共用,措辞不必强行一致。
func webPasswordIssueErr(iss *auth.PasswordIssue) error {
	switch iss.Kind {
	case auth.PasswordTooShort:
		return newLocErr("webadmin.pwTooShort", auth.MinWebPasswordLen, iss.Got)
	case auth.PasswordTooLong:
		return newLocErr("webadmin.pwTooLong", auth.MaxWebPasswordLen)
	case auth.PasswordBadChars:
		return newLocErr("webadmin.pwBadChars")
	default:
		return newLocErr("webadmin.pwTooFewClasses")
	}
}
