package main

// cmd_credentials.go(2026-05-25,0013):「profile / credentials 解耦」的服务端导出入口。
//
// 设计动机(对应 cmd_profile.go 顶部注释):
//   - profile QR 仅含服务器配置(host / reality / hy2 / nodes / ...),公开传阅 / 云同步友好;
//   - credentials QR 含敏感的 (username, psk),仅本地分发,client 持久化进 Keychain;
//   - 客户端按 credential_id(UUID v4)索引:同 UUID 新 QR 自动覆盖旧 PSK,达成
//     「server 端 rotate-psk → 用户重新扫码 → 本地 PSK 无缝更新」的承诺。
//
// 服务端用户模型 + 登录校验逻辑(auth/psk.go::VerifyLogin)**完全不变**:
// users.psk_hash 仍是单值;credential_id / credential_created_at 只供 admin / client
// 元数据流转用,登录路径不读。
//
// 调用形态:
//   nanotun-admin credentials show <user> --psk PLAIN          (必须验证 PSK 与现存 hash 匹配)
//   nanotun-admin credentials show <user> --rotate-psk         (生成新 PSK + 写库 + 输出)
//   nanotun-admin credentials show <user> --psk P --format qr  (终端二维码,适合 SSH 后扫码下发)
//
// `--format qr-png --output cred.png`:出 PNG 文件;`--format both`:JSON + URL 双输出。

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// 「credentials wire format」(schema + URL prefix + URL encoder)已统一抽到
// nanotun/util/credentials_url.go,admin CLI 与 nanotun-web 后台共用。详见那里。
// 本文件保留薄别名,避免一次性大改下游调用点。
const (
	credentialsSchemaVersion = util.CredentialsSchemaVersion
	credentialsURLPrefix     = util.CredentialsURLPrefix
)

// credentialsSchema = util.CredentialsSchema 的本地别名(json tag 与字段顺序由 util 那边定义)。
type credentialsSchema = util.CredentialsSchema

// cmdCredentials 派发 credentials 子命令。
//
// 子命令:
//   - show <user> [--psk P | --rotate-psk] [--format ...] [--output FILE]
//   - list                                  列出已发过凭证(credential_id 非空)的用户
func cmdCredentials(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return usageError(opts.usage("nanotun-admin credentials <show|list> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "show":
		return cmdCredentialsShow(ctx, st, opts, rest)
	case "list", "ls":
		return cmdCredentialsList(ctx, st, opts, rest)
	default:
		return newLocErr("cli.unknownSubcommand", "credentials", sub)
	}
}

// cmdCredentialsShow 导出可被客户端扫码的 credentials QR / JSON / URL。
//
// 设计:
//   - <username> 必填(positional);
//   - --psk PLAIN / --rotate-psk 二选一:与 profile show 的 PSK 解析对齐
//     (前者校验明文与现存 hash 匹配 → 不变 PSK 直接输出;后者生成新 PSK + 写库 + 输出);
//   - --format json|url|both|qr|qr-png:与 profile show 同名同义;
//   - --output FILE:写入文件(0600 权限,fsync 后关闭),不传时落 stdout(qr 例外:始终 stdout)。
//
// 输出内容 = (version, credential_id, username, plaintext_psk, credential_created_at)。
func cmdCredentialsShow(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("credentials show", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	pskPlain := fs.String("psk", "", opts.T("credentials.flag.psk"))
	rotatePSK := fs.Bool("rotate-psk", false, opts.T("credentials.flag.rotatePSK"))
	format := fs.String("format", "json", opts.T("credentials.flag.format"))
	output := fs.String("output", "", opts.T("credentials.flag.output"))
	// --force:覆盖已存在的 --output 目标(默认拒绝,防误覆盖含明文 PSK 的产物 / 符号链接跟随写)。
	forceOverwrite := fs.Bool("force", false, opts.T("profile.flag.force"))

	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		// 第十二轮深扫 MED:参数元数错误属**用法错误** → exit 2(此前 errors.New 恒 exit 1,与 restore /
		// 顶层 dispatch 的 usage 退出码不一致)。下面的空用户名 / flag 互斥同理。
		return usageError(opts.T("credentials.usage"))
	}
	username := strings.TrimSpace(pos[0])
	if username == "" {
		return usageError(opts.T("profile.usernameEmpty"))
	}
	if *pskPlain != "" && *rotatePSK {
		return usageError(opts.T("credentials.pskRotateMutex"))
	}
	if *pskPlain == "" && !*rotatePSK {
		return usageError(opts.T("credentials.pskOrRotate"))
	}
	if *pskPlain != "" {
		opts.warnPSKOnArgv()
	}
	if !validFormat(*format) {
		return errors.New(opts.T("credentials.formatInvalid", *format))
	}

	u, err := st.GetUserByUsername(ctx, username)
	if err != nil {
		return opts.notFoundErr(err, "user.notFound", username)
	}
	// P2#6(2026-05-26):rotate 路径与 user reset-psk 同款拒绝禁用账号 —— 「踢线」
	// 与「下发新凭证」语义矛盾,且禁用账号 rotate 出来的 PSK 立即被 user_invalidate
	// scan 踢掉,等于发废卡。读路径(--psk)允许:运维可能想给 disabled user 看
	// 「我现有 cred 长什么样」用作排查。
	if *rotatePSK && u.DisabledAt != 0 {
		return errors.New(opts.T("credentials.rotateDisabled", u.Username, u.Username))
	}

	// 记一下 caller 视角的「老 credential_id」,用于 rotate 路径下判断是否顺手
	// backfill 了 UUID(0013 之前的老 user 首次 rotate 才会发生)。审计 detail 里
	// 带上 "backfilled credential_id=..." 便于运维事后追溯,无需另开一条 audit。
	priorCredID := u.CredentialID

	// 第六/七轮深扫 HIGH:rotate 会在 resolveCredentialsPSK 里**先把新 PSK 写库**(旧 hash 即刻失效),之后才
	// emitCredentials 输出明文。任何**确定性**的输出前置失败若拖到 emit 才报,就会「PSK 已轮换、明文从未
	// 交付」→ 用户现有客户端立即断连、运维手里也没有新密钥,得再 rotate 一次才能恢复。第六轮只堵了「--output
	// 已存在且无 --force」这一种;本轮把所有能在落库前判定的输出前置条件统一前移(见 preflightCredentialsOutput),
	// 尤其 `--format qr-png` 缺 --output 这种最易复现的确定性失败。真正落盘仍走 os.Link 原子 no-clobber,本探测
	// 与落盘间的 TOCTOU 只影响「是否提前报错」,最终把关仍在落盘那道。
	if *rotatePSK {
		if err := preflightCredentialsOutput(*format, *output, *forceOverwrite, opts); err != nil {
			return err
		}
		// 第十一轮深扫 MED:--rotate-psk 会**立即**改写库里 PSK 并踢线该用户所有会话,是破坏性操作;
		// 且子命令 verb 是「show」(读感强),尤需显式确认防误触。与 user reset-psk / main.go 顶部
		// 「危险操作需 --yes 二次确认」契约一致。--yes / -y 跳过(供 provisioning 脚本)。确认放在
		// preflight 之后:确定性的输出前置失败仍先于交互提示短路,不让用户白确认一场。
		if !opts.yes {
			ok, _ := confirm(opts, opts.T("credentials.confirmRotate", u.Username))
			if !ok {
				fmt.Fprintln(opts.stdout, opts.T("common.canceled"))
				return nil
			}
		}
	}

	// 2026-05-26 wire 扩展:credentials QR 携带 host + server_id。
	//
	//  - host = app_settings.advertised_host(原 public_host;0015 migrate 改名)。
	//    未配则空字符串 — wire 允许(util.CredentialsSchema Host 是普通 string,
	//    空就空),client 收到回 "" 由 UI 显示「未指定」。
	//  - server_id = app_settings.server_id(0014 migrate 写入)。理论上 Migrate 已确保
	//    存在,这里读到空只可能是「db 跑过 migrate 但 server_id 写失败的极端故障」,
	//    fail-fast 不动 — 拿到啥就发啥,client 不会因此拒解 wire format。
	//
	// 这两个 read 都走 app_settings 表,与 cmd_setting.go 走同一套 KV 接口;读不到 key
	// 时返回 ("", nil),不报错 — 与 store/server_id.go::GetServerID 的契约一致。
	//
	// 第九轮深扫 MED:这两个 read 必须在 resolveCredentialsPSK(rotate 会**先把新 PSK
	// 写库**、旧 hash 即刻失效)**之前**完成。它们是**确定性**的 db io,若拖到 rotate
	// 之后才执行,一旦硬报错(io / ctx 取消)就会「PSK 已轮换、明文从未交付」—— 与本轮
	// preflightCredentialsOutput 前移同一动机(把所有能在落库前判定的失败统一前置)。
	// 二者与 rotate 无数据依赖,前移安全。
	advertisedHost, hostErr := st.GetAdvertisedHost(ctx)
	if hostErr != nil {
		// 不是预期的 not-found(那种会回 "",nil),是真正的 db io 错误 — 严格 fail。
		return fmt.Errorf("%s: %w", opts.T("credentials.readAdvertisedHost"), hostErr)
	}
	serverID, sidErr := st.GetServerID(ctx)
	if sidErr != nil {
		return fmt.Errorf("%s: %w", opts.T("credentials.readServerID"), sidErr)
	}

	pskOut, credID, createdAt, err := resolveCredentialsPSK(ctx, st, u, *pskPlain, *rotatePSK)
	if err != nil {
		return err
	}

	// 写路径(--rotate-psk)统一审计。**严禁**把明文 PSK / 完整 credentials URL 落库,
	// detail 仅 username + credential_id,既能追溯「哪个 admin 在何时 rotate 了谁」,
	// 又不会让 audit log 本身成为新的泄密面。其它 admin 子命令(user_create / device_set_*)
	// 同款做法。只读 show(`--psk PLAIN`)不审计,与 user_show / device_show 对齐。
	if *rotatePSK {
		detail := fmt.Sprintf("user=%s credential_id=%s", u.Username, credID)
		if priorCredID == "" {
			detail += fmt.Sprintf(" backfilled credential_id=%s", credID)
		}
		_ = st.Audit(ctx, "admin-cli", "credentials_rotate_psk",
			fmt.Sprintf("user:%d", u.ID), detail)
	}

	cred := credentialsSchema{
		Version:   credentialsSchemaVersion,
		ID:        credID,
		Username:  u.Username,
		PSK:       pskOut,
		CreatedAt: createdAt,
		Host:      advertisedHost,
		ServerID:  serverID,
	}
	return emitCredentials(&cred, *format, *output, *forceOverwrite, opts)
}

// resolveCredentialsPSK 解析 PSK 来源 + 落实 credential 元数据。返回 (psk, credentialID, createdAt)。
//
//   - rotate=true:生成新 PSK + hash → 走 store.RotateUserPSKAndEnsureCredential
//     (psk_hash + credential_created_at = now;若 user 是老 row 顺便 backfill UUID v4)。
//     返回的 (credID, now) 必然为最新的、入库后的权威值。
//   - rotate=false:supplied 与 user.PSKHash 必须匹配(否则会输出无效 PSK 让 client 跑空);
//     用 store.EnsureUserCredentialID 拿(可能新 backfill 的)credential_id;PSK 用 supplied 原样
//     返回(不动 db psk_hash,与 profile show 的 --psk 路径语义对齐)。
//
// 失败:
//   - rotate=false 且 PSK 不匹配 → 显式提示 "请用 --rotate-psk"。
//   - store 报错 → 透传 wrap。
func resolveCredentialsPSK(
	ctx context.Context, st *store.Store, u *store.User, supplied string, rotate bool,
) (psk, credentialID string, createdAt int64, err error) {
	if rotate {
		newPSK, err := util.GeneratePSK()
		if err != nil {
			return "", "", 0, fmt.Errorf("%s: %w", newLocErr("credentials.genNewPSK").Error(), err)
		}
		hash, err := auth.HashPSK(newPSK)
		if err != nil {
			return "", "", 0, fmt.Errorf("%s: %w", newLocErr("credentials.hashNewPSK").Error(), err)
		}
		credID, now, err := st.RotateUserPSKAndEnsureCredential(ctx, u, hash)
		if err != nil {
			// 第七轮深扫 P1:CAS race 显式中文提示,而不是把 sentinel 原文 wrap 给用户。
			if errors.Is(err, store.ErrPSKConcurrentRotation) {
				// 第八轮深扫 P1 + 第九轮 P2 detail 统一:与 cmd_user.go reset-psk
				// 路径对称写 audit,且 detail schema 统一为 `username=X reason=... via=Y`,
				// 与 web 路径一致(见 `nanotun-admin/README.md` audit detail 约定节)。
				// via=credentials_show 标识来源是 CLI `credentials show --rotate-psk`,
				// 区分于 via=user_reset_psk(cmd_user) / via=web_reset_psk(Web handler)。
				_ = st.Audit(ctx, "admin-cli", "user_reset_psk_raced",
					fmt.Sprintf("user:%d", u.ID),
					fmt.Sprintf("username=%s reason=concurrent_rotation_by_peer_admin via=credentials_show", u.Username))
				return "", "", 0, newLocErr("credentials.rotateRaced", u.Username)
			}
			return "", "", 0, fmt.Errorf("rotate user psk: %w", err)
		}
		return newPSK, credID, now, nil
	}
	// 用户提供了明文:校验后直接返回;不一致绝不输出,否则会构造无效 credentials。
	ok, err := auth.VerifyPSK(supplied, u.PSKHash)
	if err != nil {
		return "", "", 0, fmt.Errorf("%s: %w", newLocErr("credentials.verifyPSK").Error(), err)
	}
	if !ok {
		return "", "", 0, newLocErr("credentials.pskMismatch", u.Username)
	}
	credID, ts, err := st.EnsureUserCredentialID(ctx, u)
	if err != nil {
		return "", "", 0, fmt.Errorf("ensure credential id: %w", err)
	}
	return supplied, credID, ts, nil
}

// preflightCredentialsOutput 在 rotate **落库前**校验所有**确定性**的输出前置条件,避免「PSK 已轮换却因
// 输出注定失败而从未交付」。逻辑必须与 emitCredentials 的实际写盘分支保持同步:
//   - opts.json:无论 format 一律 openProfileOutput 写 JSON(output 空则落 stdout,非空则写文件);
//   - qr-png:必须写文件,--output 必填(缺失 → 落库后才报,正是要前移的坑);
//   - qr(非 --json):纯终端 stdout,忽略 output;
//   - json/url/both(默认):output 非空才写文件,否则 stdout。
//
// 只做能在落库前确定的判定;真正的原子 no-clobber 仍由落盘那道(os.Link)最终把关。
func preflightCredentialsOutput(format, output string, force bool, opts *globalOpts) error {
	f := strings.ToLower(strings.TrimSpace(format))
	out := strings.TrimSpace(output)
	// qr-png 缺 --output:emitCredentials 会在落库后才 error,这里前移。opts.json 时 format 被忽略(走 JSON),不适用。
	if !opts.json && f == "qr-png" && out == "" {
		return errors.New(opts.T("profile.qrPngNeedsOutput"))
	}
	// 是否会写文件:output 非空,且不是「纯终端 qr」(qr 在非 --json 下忽略 output 走 stdout)。
	writesToFile := out != "" && !(!opts.json && f == "qr")
	if writesToFile {
		// 第八轮深扫 HIGH:父目录必须**存在且是目录**,否则 writeFileTight 的 os.CreateTemp(dir,…) 会在
		// **落库之后**才失败 —— 新 PSK 已生效、旧 hash 已废、明文却从未交付。此前 preflight 只 Lstat 目标
		// 文件本身(下方 no-clobber),漏了「--output /不存在的目录/x.png」这一整类确定性失败。这里前移到落库前。
		dir := filepath.Dir(out)
		if fi, dErr := os.Stat(dir); dErr != nil || !fi.IsDir() {
			return errors.New(opts.T("credentials.badOutputDir", out))
		}
		if !force {
			if _, statErr := os.Lstat(out); statErr == nil {
				return errors.New(opts.T("credentials.refuseOverwrite", out))
			} else if !os.IsNotExist(statErr) {
				return fmt.Errorf("stat --output %s: %w", out, statErr)
			}
		}
	}
	return nil
}

// emitCredentials 按 --format 写出 credentials;qr / qr-png 编码 nanotun-cred:// URL(非裸 JSON)。
func emitCredentials(c *credentialsSchema, format, outputPath string, force bool, opts *globalOpts) error {
	// 全局 --json 强制 compact JSON,与其它子命令脚本管线一致。
	if opts.json {
		out, closeOut, err := openProfileOutput(outputPath, opts.stdout, force)
		if err != nil {
			return err
		}
		if err := writeCredentialsJSONCompact(out, c); err != nil {
			return err
		}
		return closeOut()
	}

	f := strings.ToLower(strings.TrimSpace(format))
	switch f {
	case "qr-png":
		if strings.TrimSpace(outputPath) == "" {
			return errors.New(opts.T("profile.qrPngNeedsOutput"))
		}
		url, err := credentialsToURL(c)
		if err != nil {
			return err
		}
		return writeQRPNG(opts, outputPath, url, force)
	case "qr":
		if strings.TrimSpace(outputPath) != "" {
			fmt.Fprintln(opts.stderr, opts.T("credentials.qrIgnoresOutput", outputPath))
		}
		url, err := credentialsToURL(c)
		if err != nil {
			return err
		}
		fmt.Fprintln(opts.stdout, opts.T("credentials.qrScanHint"))
		return writeQRTerminal(opts, opts.stdout, url)
	default:
		out, closeOut, err := openProfileOutput(outputPath, opts.stdout, force)
		if err != nil {
			return err
		}
		if err := writeCredentials(out, c, format); err != nil {
			return err
		}
		return closeOut()
	}
}

// credentialsToURL 是 util.EncodeCredentialsURL 的本地薄包装,保留旧 caller 命名。
func credentialsToURL(c *credentialsSchema) (string, error) {
	return util.EncodeCredentialsURL(c)
}

func writeCredentials(w io.Writer, c *credentialsSchema, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return writeCredentialsJSONPretty(w, c)
	case "url":
		return writeCredentialsURL(w, c)
	case "both":
		if err := writeCredentialsJSONPretty(w, c); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
		return writeCredentialsURL(w, c)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeCredentialsJSONPretty(w io.Writer, c *credentialsSchema) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}

func writeCredentialsJSONCompact(w io.Writer, c *credentialsSchema) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n")
	return err
}

func writeCredentialsURL(w io.Writer, c *credentialsSchema) error {
	url, err := credentialsToURL(c)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, url+"\n")
	return err
}

// cmdCredentialsList:列出已发过凭证(credential_id 非空)的所有用户。
//
// 设计动机:0013 之后管理员需要知道「哪些 user 已经下发过凭证 QR、UUID 是多少、
// 上次 rotate 是什么时候」,以便:
//   - 排查「客户端登录失败」时确认 rotate 后是否还没把新 QR 派下去;
//   - 给批量轮换 PSK 做参考清单。
//
// 输出走 store.ListUsersWithCredentials,只回 credential_id 非空 / 非空串的 user,
// **包含 disabled**(否则禁用账号在 admin 列表里隐身,违反「列表 = 全集」语义)。
// 表头与 `user list` 风格对齐,新增 CREDENTIAL_ID / CREATED_AT / DISABLED 三列。
func cmdCredentialsList(ctx context.Context, st *store.Store, opts *globalOpts, _ []string) error {
	users, err := st.ListUsersWithCredentials(ctx)
	if err != nil {
		return fmt.Errorf("list users with credentials: %w", err)
	}
	if opts.json {
		type row struct {
			Username            string `json:"username"`
			CredentialID        string `json:"credential_id"`
			CredentialCreatedAt int64  `json:"credential_created_at"`
			DisabledAt          int64  `json:"disabled_at,omitempty"`
		}
		out := make([]row, 0, len(users))
		for _, u := range users {
			out = append(out, row{
				Username:            u.Username,
				CredentialID:        u.CredentialID,
				CredentialCreatedAt: u.CredentialCreatedAt,
				DisabledAt:          u.DisabledAt,
			})
		}
		return printJSON(opts.stdout, out)
	}
	t := newTable(opts.stdout, "USERNAME", "CREDENTIAL_ID", "CREATED_AT", "DISABLED")
	for _, u := range users {
		t.row(
			u.Username,
			u.CredentialID,
			fmtTimeUnix(u.CredentialCreatedAt),
			fmtBool(u.DisabledAt != 0),
		)
	}
	return t.flush()
}

// 让编译器看到 io / os 的实际使用(防 vet 在新代码引用未触发其它路径时误报),
// 同时给未来扩展(stat / 文件大小提示)留位。
var _ = os.Stdout
var _ io.Writer = os.Stdout
