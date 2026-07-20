package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/nanotun/server/store"
)

// systemManagedSettingKeys 列出**禁止**通过 `setting set` 修改的 app_settings key —
// 它们的值由 Migrate / runtime hook 管理,手动覆盖会让客户端 / schema 状态机错乱。
//
// 设计:这是 `setting set` 入口的「last line of defense」,不是替代专用 CLI(rate
// 仍走 `setting rate`,advertised_host 仍走 web 端 POST 表单 + ValidateAdvertisedHost)。
//
// 列表里的每条都附 hint,run 时直接抛 error 提示 ops 用正确的工具;不静默允许是为了
// 避免 ops 看到 0 报错就以为生效(SQLite write 成功,但客户端语义已破坏)。
// value = i18n hint key(在 catEN / catZH 里),使用处用 opts.T 解析成当前语言。
var systemManagedSettingKeys = map[string]string{
	"server_id":      "setting.sysHint.serverId",
	"schema_version": "setting.sysHint.schemaVersion",
}

// validatedSettingKeys 列出可通过 `setting set` 修改、但**必须先走 schema 校验**的 key。
//
// 与 systemManagedSettingKeys 不同的地方:这里**允许写入**,只是绕开了 raw
// SettingsSet,改走 key-specific 的 validator 兜底。设计动机:
//
//   - ops 用 `setting set advertised_host vpn.example.com` 做脚本化部署是合理需求,
//     单纯 block(像 server_id 那样)会让 web UI 成为唯一入口,损失自动化能力;
//   - 但 web 端 POST /settings/advertised-host 在调 store.SetAdvertisedHost 前会先跑
//     store.ValidateAdvertisedHost,过滤 scheme / 端口 / 换行注入 / 长度上限等;
//     CLI raw 路径绕过 → ops 误打 `setting set advertised_host "http://..."` 能落库,
//     之后 server-QR 用这个 host 渲染会 fail / 撞下游 URL 解析。
//
// 实现:value 先过 validator,过 → SettingsSet;不过 → 返回 validator 自带的
// error(已含人类可读 hint)。
var validatedSettingKeys = map[string]func(string) error{
	"advertised_host": store.ValidateAdvertisedHost,
	// 2026-05-26 第六轮拆字段:server_dial_host 是客户端 PacketTunnel
	// `tunnelRemoteAddress` 目标,strict IPv4/IPv6/RFC1035 hostname。
	// CLI raw 写入路径必须走 validator 兜底,否则 ops 误打
	// `setting set server_dial_host test-203.0.113.10` 会让 server 端 QR
	// 生成成功但客户端隧道挂掉(末段纯数字 TLD DNS 不可解析)。
	"server_dial_host": store.ValidateServerDialHost,
}

func cmdSetting(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return errors.New(opts.usage("nanotun-admin setting <get|set|list|rate|probe-dial-host> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "rate":
		return cmdSettingRate(ctx, st, opts, rest)
	case "probe-dial-host":
		return cmdSettingProbeDialHost(ctx, opts, rest)
	case "get":
		if len(rest) != 1 {
			return errors.New(opts.usage("nanotun-admin setting get <key>"))
		}
		v, ok, err := st.SettingsGet(ctx, rest[0])
		if err != nil {
			return err
		}
		if !ok {
			return errors.New(opts.T("setting.notFound", rest[0]))
		}
		fmt.Fprintln(opts.stdout, v)
		return nil
	case "set":
		if len(rest) != 2 {
			return errors.New(opts.usage("nanotun-admin setting set <key> <value>"))
		}
		key, value := rest[0], rest[1]
		// 层 1:系统管 key → 硬拒。
		if hintKey, blocked := systemManagedSettingKeys[key]; blocked {
			return errors.New(opts.T("setting.blocked", key, opts.T(hintKey)))
		}
		// 层 2:已知 schema key → 走专用 validator 再写。
		if validator, ok := validatedSettingKeys[key]; ok {
			if verr := validator(value); verr != nil {
				return errors.New(opts.T("setting.validateFailed", key, opts.errText(verr)))
			}
		}
		// 层 3:其它 key → 原样落库(rate_* / acl_default_action 等有专用 CLI
		// 的 key 仍允许 raw 写,与改动前的行为对齐 — 避免 ops 习惯路径被破坏)。
		if err := st.SettingsSet(ctx, key, value); err != nil {
			return err
		}
		fmt.Fprintln(opts.stdout, opts.T("setting.written", key, value))
		return nil
	case "list", "ls":
		rows, err := st.DB().QueryContext(ctx, `SELECT key, value FROM app_settings ORDER BY key ASC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		t := newTable(opts.stdout, "KEY", "VALUE")
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				return err
			}
			t.row(k, v)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return t.flush()
	default:
		return newLocErr("cli.unknownSubcommand", "setting", sub)
	}
}

// cmdSettingRate(0011, 2026-05-23):全局默认带宽限速,对应 app_settings 两条 key
// rate_default_upload_bps / rate_default_download_bps。
//
// 用法:
//
//	nanotun-admin setting rate                          # 仅展示当前值
//	nanotun-admin setting rate --up-mibs 50             # 改上行(下行不变)
//	nanotun-admin setting rate --up-mibs 50 --down-mibs 100
//	nanotun-admin setting rate --up-mibs 0              # 清上行(回退 toml)
//	nanotun-admin setting rate --no-refresh             # 不推 active conn
//
// 与 device.set-rate 共用 parseRateFlag / pushRateRefresh 语义。
// 不传任何 --*-* 时**只展示**当前值,不修改 — 习惯 dry-run 的运维一打就能看清楚现状。
func cmdSettingRate(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("setting rate", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	upMibs := fs.String("up-mibs", "", opts.T("setting.rate.flagUpMibs"))
	upBps := fs.String("up-bps", "", opts.T("setting.rate.flagUpBps"))
	downMibs := fs.String("down-mibs", "", opts.T("setting.rate.flagDownMibs"))
	downBps := fs.String("down-bps", "", opts.T("setting.rate.flagDownBps"))
	burstKiB := fs.String("burst-kib", "", opts.T("setting.rate.flagBurstKiB"))
	noRefresh := fs.Bool("no-refresh", false, opts.T("setting.rate.flagNoRefresh"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return errors.New(opts.T("setting.rate.unexpectedPos", fmt.Sprintf("%v", pos)))
	}
	cur, err := st.GetRateDefaults(ctx)
	if err != nil {
		return err
	}

	anyChange := false
	newUp := cur.UploadBPS
	if v, perr := parseRateFlag(*upMibs, *upBps); perr == nil {
		newUp = v
		anyChange = anyChange || newUp != cur.UploadBPS
	} else if !errors.Is(perr, errRateUnset) {
		return perr
	}
	newDown := cur.DownloadBPS
	if v, perr := parseRateFlag(*downMibs, *downBps); perr == nil {
		newDown = v
		anyChange = anyChange || newDown != cur.DownloadBPS
	} else if !errors.Is(perr, errRateUnset) {
		return perr
	}
	newBurst := cur.BurstBytes
	if strings.TrimSpace(*burstKiB) != "" {
		b, perr := parseBurstFlagKiB(*burstKiB)
		if perr != nil {
			return perr
		}
		newBurst = b
		anyChange = anyChange || newBurst != cur.BurstBytes
	}

	if !anyChange {
		// dry-run / 仅展示。
		fmt.Fprintln(opts.stdout, opts.T("setting.rate.current",
			bytesPerSecondHuman(cur.UploadBPS), bytesPerSecondHuman(cur.DownloadBPS),
			burstBytesHuman(opts, cur.BurstBytes)))
		// N16(2026-05-24):区分「真没传 flag」跟「传了但跟现状一致」。
		// 后者(如 `--burst-kib 0` 但 cur.BurstBytes 已经是 0)运维容易误以为没生效,
		// 显式 echo 一行解释「值没变,跳过写库」让 audit 视角清晰。
		anyFlag := strings.TrimSpace(*upMibs) != "" || strings.TrimSpace(*upBps) != "" ||
			strings.TrimSpace(*downMibs) != "" || strings.TrimSpace(*downBps) != "" ||
			strings.TrimSpace(*burstKiB) != ""
		if anyFlag {
			fmt.Fprintln(opts.stdout, opts.T("setting.rate.noChange"))
		} else {
			fmt.Fprintln(opts.stdout, opts.T("setting.rate.hint"))
		}
		return nil
	}

	if err := st.SetRateDefaults(ctx, store.RateDefaults{UploadBPS: newUp, DownloadBPS: newDown, BurstBytes: newBurst}); err != nil {
		return err
	}
	_ = st.Audit(ctx, "admin-cli", "settings_rate_default_set", "",
		fmt.Sprintf("old_up_bps=%d new_up_bps=%d old_down_bps=%d new_down_bps=%d old_burst_bytes=%d new_burst_bytes=%d",
			cur.UploadBPS, newUp, cur.DownloadBPS, newDown, cur.BurstBytes, newBurst))

	fmt.Fprintln(opts.stdout, opts.T("setting.rate.updated",
		bytesPerSecondHuman(newUp), bytesPerSecondHuman(newDown), burstBytesHuman(opts, newBurst)))

	if !*noRefresh {
		// 全量刷:device_id=0
		if err := pushRateRefresh(opts, 0); err != nil {
			fmt.Fprintln(opts.stderr, opts.T("setting.rate.refreshWarn", err.Error()))
		}
	} else if newBurst != cur.BurstBytes {
		// M4(2026-05-24):burst 是 active conn 上的 rate.Limiter 桶容量,本次 --no-refresh
		// 跳过广播 → 新 burst 已落库但 active conn 仍走旧值。下次任何 /rate/refresh
		// (admin 改 rate / 设备改 rate / 重连)都会把这个 burst 推过去,行为隐式可能
		// 让运维事后困惑(「我那次改 burst 没用,怎么过几天突然变了」)。明示一下。
		fmt.Fprintln(opts.stderr, opts.T("setting.rate.burstNote"))
	}
	return nil
}

// cmdSettingProbeDialHost(2026-05-27 第十五轮 backlog#3):on-server `server_dial_host`
// 可达性验证工具,**只验证不落库**,opt-in。
//
// **设计动机**:`setting set server_dial_host <host>` 默认只做 [store.ValidateServerDialHost]
// 语法校验,不调 [store.ProbeServerDialHost](DNS + ICMP),因为 admin 笔记本网络环境
// 与 server 不同,在笔记本上做的可达性测试对 server 视角没意义(笔记本能 ping ≠
// server 能 ping;反之亦然)。Web 端 `POST /settings/server-dial-host` 跑 probe 是因为
// 那个 handler 跑在 server 进程里、与 server 共享出口路由。
//
// 但部分 ops 流程是「SSH 进 server → 直接跑 nanotun-admin」,此时 CLI 跑在 server 机器
// 上 — 与 web handler 同一网络视角,probe **是有意义的**。本子命令提供该 opt-in 验证,
// 让 ops 在 set 前先验证 host 可达;**不联动 SettingsSet**,验证结果由 ops 自行判断后
// 再决定要不要跑 `setting set server_dial_host <host>`。
//
// 用法:
//
//	nanotun-admin setting probe-dial-host vpn.example.com
//	nanotun-admin setting probe-dial-host vpn.example.com --skip-icmp
//	nanotun-admin setting probe-dial-host 203.0.113.10
//
// `--skip-icmp` 与 web 表单 `skip_probe` 同款语义:**仍做 DNS 解析**,只跳过 ICMP ping
// (Vultr / AWS 安全组默认 ban ICMP 时使用)。DNS 仍是硬错 — 域名解析不出来任何 IP
// 一定是配置问题,本工具的 skip-icmp 不会兜底。
//
// 退出码语义:
//
//   - 0  DNS + ICMP 全通过(或 skip-icmp 时 DNS 通过)
//   - 非 0  返回 error(语法 / DNS / ICMP / ctx 取消)— shell 脚本可 `vpn-port-admin … || handle`
//
// 三类失败用文本前缀区分(`✗ DNS 失败` / `⚠ ICMP 不通` / `✗ 语法校验失败`),
// 不细分自定义 exit code,避免与全局 main 退出码语义打架。
func cmdSettingProbeDialHost(ctx context.Context, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("setting probe-dial-host", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	skipICMP := fs.Bool("skip-icmp", false, opts.T("setting.probe.flagSkipICMP"))
	timeout := fs.Duration("timeout", 20*time.Second, opts.T("setting.probe.flagTimeout"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(opts.usage("nanotun-admin setting probe-dial-host <host> [--skip-icmp] [--timeout 20s]"))
	}
	host := strings.TrimSpace(pos[0])
	if host == "" {
		return errors.New(opts.T("setting.probe.hostEmpty"))
	}

	if verr := store.ValidateServerDialHost(host); verr != nil {
		fmt.Fprintln(opts.stdout, opts.T("setting.probe.syntaxFail", opts.errText(verr)))
		return verr
	}
	fmt.Fprintln(opts.stdout, opts.T("setting.probe.syntaxOk", host))

	if *skipICMP {
		// 与 web 端 skip_probe 同款:仅做 DNS。`ProbeServerDialHost` 是 all-in-one 路径,
		// 没有 SkipICMP option,这里直接调 net.DefaultResolver — 与 store/server_dial_host.go
		// 里 ProbeServerDialHost 域名分支用同一个 resolver,语义一致。
		//
		// 2026-05-27 第十六轮 P1 修复:DNS 解析后**必须**对每个返回 IP 跑
		// `store.CheckResolvedDialIPs` 黑名单(与 ProbeServerDialHost 域名分支同款),
		// 否则 DNS 投毒 / 私网 resolver 把域名解到 127.0.0.1 / link-local 时 CLI
		// 会假阳性 ✓ 通过,运维误以为可 set。
		if _, isLit := store.ParseLiteralIP(host); isLit {
			fmt.Fprintln(opts.stdout, opts.T("setting.probe.literalIP"))
			return nil
		}
		dnsCtx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		ips, dnsErr := net.DefaultResolver.LookupIPAddr(dnsCtx, host)
		if dnsErr != nil {
			fmt.Fprintln(opts.stdout, opts.T("setting.probe.dnsFail", dnsErr.Error()))
			return dnsErr
		}
		if len(ips) == 0 {
			fmt.Fprintln(opts.stdout, opts.T("setting.probe.dnsNoRecord"))
			return fmt.Errorf("no A/AAAA record: %s", host)
		}
		if rejectErr := store.CheckResolvedDialIPs(host, ips); rejectErr != nil {
			fmt.Fprintln(opts.stdout, opts.T("setting.probe.dnsSpecialIP", opts.errText(rejectErr)))
			return rejectErr
		}
		ipStrs := make([]string, 0, len(ips))
		for _, ip := range ips {
			ipStrs = append(ipStrs, ip.IP.String())
		}
		fmt.Fprintln(opts.stdout, opts.T("setting.probe.dnsOKSkipICMP",
			len(ips), strings.Join(ipStrs, ", ")))
		return nil
	}

	probeCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	probeErr := store.ProbeServerDialHost(probeCtx, host)
	if probeErr == nil {
		fmt.Fprintln(opts.stdout, opts.T("setting.probe.allOK"))
		return nil
	}
	if errors.Is(probeErr, store.ErrServerDialHostDNS) {
		fmt.Fprintln(opts.stdout, opts.T("setting.probe.dnsFailProbe", opts.errText(probeErr)))
		return probeErr
	}
	if errors.Is(probeErr, store.ErrServerDialHostICMPSoftFail) {
		fmt.Fprintln(opts.stdout, opts.T("setting.probe.icmpSoftFail", opts.errText(probeErr)))
		return probeErr
	}
	fmt.Fprintln(opts.stdout, opts.T("setting.probe.probeErr", opts.errText(probeErr)))
	return probeErr
}
