package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
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
	// 第十二轮深扫 HIGH:一次性 VIP 规范化的完成标记,由 store 的 canonicalizeStoredVIPs 迁移 hook 专管。
	// 手改会让下次 Migrate 跳过规范化,残留非规范 VIP → 去重失配 / 双占。DAL 的 reservedSettingKeys 已兜底,
	// 这里在 CLI 入口再拦一层并给出清晰 hint。
	"vip_canonicalized":    "setting.sysHint.vipCanonicalized",
	"vip_canonicalized_v2": "setting.sysHint.vipCanonicalized", // 第十六轮:当前版本键,同样系统托管
	// 第十八轮深扫 MED:mesh_cidrs 是 server 启动落库的本 mesh 网段快照,供批准子网路由时判交叠。DAL 的
	// reservedSettingKeys 已兜底,这里在 CLI 入口再拦一层并给出清晰 hint。
	store.MeshCIDRsKey: "setting.sysHint.meshCidrs", // "mesh_cidrs"
	// MagicDNS 后缀不是 DB 设置:运行期只从 config.toml 的 [server.magic_dns].domain_suffix 读
	// (magicDNSSuffixForClient / resolveMagicDNSConfig),app_settings 里的 magic_suffix 没有任何代码会看。
	// 早先它只是个未知 key —— 原样落库 + 泛泛的「unknown key」告警,运维极易以为改了后缀却零效果
	// (这正是「怎么又变回 lan 了」那类困惑的来源)。这里升级为硬拒 + 精确指路:config.toml /
	// scripts/set-magic-suffix.sh / 装机期 NANOTUN_MAGIC_SUFFIX。
	"magic_suffix": "setting.sysHint.magicSuffix",
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
	// 深扫第十轮 MED/LOW:安全相关的枚举/布尔 setting 走 raw `setting set` 时也必须校验,
	// 防拼错落库。acl_default_action 拼错会被数据面兜到 fail-closed(deny),mesh_enabled
	// 拼错会被兜到默认 on —— 两者都让运维误以为设成了别的值。
	"acl_default_action": store.ValidateACLDefaultActionSetting,
	"mesh_enabled":       store.ValidateMeshEnabledSetting,
	// 深扫第十一轮 MED:限速三键 raw 写入非数字会被 settingsGetInt64 静默当 0(= 不限速),
	// 与本意相反。加非负整数校验兜底(专用 CLI `setting rate` 仍是推荐路径)。
	// 深扫第十二轮 MED:rate_burst_bytes 单独用 clamp-aware 校验 —— 运行期 effectiveBurst 会把
	// (0,4KiB) / >16MiB 静默夹住,故写入区间外的值直接拒,避免「设了却被改」。
	"rate_default_upload_bps":   store.ValidateNonNegativeInt64Setting,
	"rate_default_download_bps": store.ValidateNonNegativeInt64Setting,
	"rate_burst_bytes":          store.ValidateRateBurstSetting,
}

// aclSnapshotSettingKeys:被 server 缓存进**内存 ACL snapshot**的 key —— 只写 DB 不通知,
// 数据面就一直按旧值跑,直到有人 SIGHUP / 重启。
//
// 2026-07-26 三机实测(与 acl allow/deny 那次 b83d4af 同一个根因,当时只补了规则那一半):
//   - `setting set mesh_enabled false`:`setting list` 显示 false,但 /status 的 mesh_enabled
//     仍是 true,A↔C 的 ping / MagicDNS 一路畅通,mesh_off_drops 恒为 0;`systemctl reload`
//     之后才当场断掉。反向打开同理。
//   - `setting set acl_default_action deny`:落库后 mesh 照通,acl_drop_total 不动。
//
// 这两个都是**全局**开关(前者一刀切断所有客户端互访,后者把默认动作翻成拒绝),多半是在
// 「出事了、先断网」的场合敲的 —— 敲完看到 written: 却什么都没发生,比没有这个开关更危险。
// 故写完主动走 notifyACLChanged(server 的 /reload?what=acl 会同时刷新规则集、default_action
// 与 mesh_enabled,见 reload 日志里那行 "[reload] acl_rules hot-reloaded")。
var aclSnapshotSettingKeys = map[string]bool{
	"mesh_enabled":       true,
	"acl_default_action": true,
}

// rateRefreshSettingKeys:限速三件套 —— 落库之后还得推 /rate/refresh 才会落到**在线会话**的
// rate.Limiter 上(专用 `setting rate` 走的就是这条路)。
//
// 2026-07-26 三机实测的坑比 mesh_enabled 那次更阴,因为它会把人**锁死**:
//   - `setting set rate_default_download_bps 100000` → written: + `setting rate` 显示 0.10 MiB/s,
//     而 A 经 mesh 下载实测仍有 620 KB/s(改成 200000 反而量到 299 KB/s —— 纯链路噪声,压根没限);
//   - 想用推荐路径补救:`setting rate --down-bps 100000` → 值与库里一致 → 走 !anyChange 分支
//     「跳过写库 / 不推刷新」,于是**唯一能生效的命令拒绝动手**;
//   - 结果是 setting list / setting rate / web 设置页三处都显示限着,数据面全速跑,
//     且没有任何一条命令能把两者对齐(除了改成别的值再改回来,或重启 server)。
//
// 故 raw 写入这三个 key 之后一律主动推一次全量刷新(device_id=0),与 `setting rate` 同口径。
var rateRefreshSettingKeys = map[string]bool{
	"rate_default_upload_bps":   true,
	"rate_default_download_bps": true,
	"rate_burst_bytes":          true,
}

// otherKnownSettingKeys:既不由系统托管、也没有专用 validator,但确实是本程序会读的 key。
// 与上面两张表合起来构成「已知 key」全集,供 warnIfUnknownSettingKey 判断拼写。
var otherKnownSettingKeys = []string{
	"setup_completed", // init 向导的完成标记(cmd_init.go)
}

// knownSettingKeys 返回已知 key 全集(排序后),用于未知 key 告警里的「相近 key」提示。
func knownSettingKeys() []string {
	out := make([]string, 0, len(systemManagedSettingKeys)+len(validatedSettingKeys)+len(otherKnownSettingKeys))
	for k := range systemManagedSettingKeys {
		out = append(out, k)
	}
	for k := range validatedSettingKeys {
		out = append(out, k)
	}
	out = append(out, otherKnownSettingKeys...)
	sort.Strings(out)
	return out
}

// warnIfUnknownSettingKey:`setting set` 对未知 key 是**有意**原样落库的(给新版本 / 别的组件
// 读的 key 留兼容口子,见下面第 3 层的注释)。代价是打错 key 也照样回报 "written:",看上去成功、
// 实际零效果 —— 2026-07-26 实测:`setting set default_rate_down_bps 1048576` 写进去了,而真正
// 的 key 是 rate_default_download_bps,在线会话的限速纹丝不动,控制面仍报 toml 默认值。
//
// 故保留写入,但在 stderr 打一行醒目告警(stdout 只留 "written:",不破坏脚本解析),并列出拼写
// 相近的已知 key。
func warnIfUnknownSettingKey(opts *globalOpts, key string) {
	if isKnownSettingKey(key) {
		return
	}
	fmt.Fprintf(opts.stderr, "%s\n", opts.T("setting.unknownKeyWarn", key))
	if near := nearSettingKeys(key); len(near) > 0 {
		fmt.Fprintf(opts.stderr, "%s\n", opts.T("setting.unknownKeyNear", strings.Join(near, ", ")))
	}
}

// warnACLDefaultActionDeny:把 acl_default_action 翻到 deny 之后,说清影响面。
//
// 这是这套设置里影响面最大的一次写入 —— 跨用户流量与**所有出公网**立刻改按白名单
// 裁决,而白名单此刻可能一条都没有。原本只回一句「已写入」,断了谁的网看不出来。
// 尤其反直觉的是出口:exit 与 user 是两套独立规则集,配满 user→user 的 allow 也
// 解不开上网(nanotund 侧 TestACLDropPacketDirected_UserRulesDoNotUnlockExit)。
//
// 规则集为空时再补一句:此刻是「谁都不通」,而不是「还没开始限制」。
// 只吼 deny 方向:翻回 allow 是放开,不会让人措手不及。
func warnACLDefaultActionDeny(ctx context.Context, st *store.Store, opts *globalOpts, key, value string) {
	if key != "acl_default_action" {
		return
	}
	if strings.ToLower(strings.TrimSpace(value)) != store.ACLDeny {
		return
	}
	fmt.Fprintln(opts.stderr, opts.T("acl.defaultActionDenyWarn"))
	rules, err := st.ListACLPairs(ctx)
	if err != nil {
		return
	}
	if len(rules) == 0 {
		fmt.Fprintln(opts.stderr, opts.T("acl.defaultActionEmptyDeny"))
		return
	}
	// 有规则但没有一条 exit 放行 → 上网仍然全断,而列表上没有一行跟出口有关。
	for _, r := range rules {
		if r != nil && r.DstKind == store.ACLDstKindExit && r.Action == store.ACLAllow {
			return
		}
	}
	fmt.Fprintln(opts.stderr, opts.T("acl.defaultActionNoExitAllow"))
}

// hintUnknownSettingKey:`setting get` 查不到时,只在 key 本身也不认识的情况下补一句相近拼写。
// 已知 key 查不到就是「还没设」,那是正常状态,不该借机敲打人。
func hintUnknownSettingKey(opts *globalOpts, key string) {
	if isKnownSettingKey(key) {
		return
	}
	if near := nearSettingKeys(key); len(near) > 0 {
		fmt.Fprintf(opts.stderr, "%s\n", opts.T("setting.unknownKeyNear", strings.Join(near, ", ")))
	}
}

func isKnownSettingKey(key string) bool {
	for _, k := range knownSettingKeys() {
		if k == key {
			return true
		}
	}
	return false
}

func nearSettingKeys(key string) []string {
	var near []string
	for _, k := range knownSettingKeys() {
		if settingKeysLookAlike(k, key) {
			near = append(near, k)
		}
	}
	return near
}

// settingKeysLookAlike:两个 setting key 是否「像是同一个东西的不同写法」。
//
// 单纯的编辑距离在这里不够用:实测踩到的 default_rate_down_bps ↔ rate_default_download_bps
// 距离远超阈值(词序整个颠倒了),但显然是同一个意图。故按 "_" 分词后比对词集合 —— 词相同、
// 或一个是另一个的前缀(down ↔ download)都算命中,命中占比 ≥ 半数即判相近。
// 编辑距离仍保留作为补充,覆盖「单纯打错几个字母」那类(rate_burst_byte ↔ rate_burst_bytes)。
func settingKeysLookAlike(a, b string) bool {
	if strings.Contains(a, b) || strings.Contains(b, a) || levenshtein(a, b) <= 3 {
		return true
	}
	at, bt := strings.Split(a, "_"), strings.Split(b, "_")
	hit := 0
	for _, x := range at {
		for _, y := range bt {
			if x == y || strings.HasPrefix(x, y) || strings.HasPrefix(y, x) {
				hit++
				break
			}
		}
	}
	return hit*2 >= max(len(at), len(bt))
}

// levenshtein:标准编辑距离,只用于上面的「相近 key」提示,key 都很短,朴素 DP 足够。
func levenshtein(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min(min(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

// canonicalizeValidatedSetting 把已通过校验的 validatedSettingKeys 值规范化后再落库。
// 深扫第十二轮 LOW:各 key 的规范形与读路径 / typed setter / migration seed 对齐 ——
//   - acl_default_action:ToLower(TrimSpace)(= "allow"/"deny",见 store 常量与 0003 seed);
//   - mesh_enabled:ParseBool → "true"/"false"(= store.SetMeshEnabled 的写法);
//   - 其余(advertised_host / server_dial_host):仅 TrimSpace;
//   - rate_*:校验器本就拒空白,值必无空白,TrimSpace 为 no-op。
func canonicalizeValidatedSetting(key, value string) string {
	v := strings.TrimSpace(value)
	switch key {
	case "acl_default_action":
		return strings.ToLower(v)
	case "mesh_enabled":
		if b, err := strconv.ParseBool(v); err == nil {
			return strconv.FormatBool(b)
		}
		return v
	default:
		return v
	}
}

func cmdSetting(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	if len(args) == 0 {
		return usageError(opts.usage("nanotun-admin setting <get|set|list|rate|probe-dial-host> [...]"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "rate":
		return cmdSettingRate(ctx, st, opts, rest)
	case "probe-dial-host":
		return cmdSettingProbeDialHost(ctx, opts, rest)
	case "get":
		if len(rest) != 1 {
			return usageError(opts.usage("nanotun-admin setting get <key>"))
		}
		v, ok, err := st.SettingsGet(ctx, rest[0])
		if err != nil {
			return err
		}
		if !ok {
			// 「这个键还没设」和「你把键名打错了」在这里长得一模一样,而两者该做的事
			// 完全相反。打错的那个人看到 "not found" 只会得出「还没配」,然后照着错
			// 键名再 set 一遍 —— set 那边的告警他刚才已经忽略过一次了。
			// 拼写提示的机器 set 已经有一套,这里复用同一套,免得两条命令口径不一。
			hintUnknownSettingKey(opts, rest[0])
			return errors.New(opts.T("setting.notFound", rest[0]))
		}
		if opts.json {
			return printJSON(opts.stdout, settingView{Key: rest[0], Value: v})
		}
		fmt.Fprintln(opts.stdout, v)
		return nil
	case "set":
		if len(rest) != 2 {
			return usageError(opts.usage("nanotun-admin setting set <key> <value>"))
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
			// 深扫第十二轮 LOW:校验通过后落**规范化**值,避免 DB 存下带空白 / 大小写不一的
			// 脏值(读路径虽已 trim/lower 容错,但 `setting list` 展示与未来读者不应看到毛刺;
			// 与 typed setter / migration seed 的写法对齐)。
			value = canonicalizeValidatedSetting(key, value)
		}
		// 层 3:其它 key → 原样落库。注意:acl_default_action / mesh_enabled / rate_default_* /
		// rate_burst_bytes 已在上面 validatedSettingKeys 里做写入校验(第十/十一轮),raw 写
		// 仍允许但会先过 validator;其余无专用校验的 key 才是真正的「原样落库」。
		// 原样落库保留,但完全不认识的 key 要吼一声,别让打错 key 的人看着 "written:" 以为生效了。
		warnIfUnknownSettingKey(opts, key)
		if err := st.SettingsSet(ctx, key, value); err != nil {
			return err
		}
		if opts.json {
			if err := printJSON(opts.stdout, settingView{Key: key, Value: value}); err != nil {
				return err
			}
		} else {
			fmt.Fprintln(opts.stdout, opts.T("setting.written", key, value))
		}
		// 翻到 deny 是这套设置里影响面最大的一次写入:跨用户流量与**所有出公网**
		// 立刻按白名单裁决,而白名单此刻可能是空的。原本只回一句 "已写入",看不出
		// 刚刚把谁的网断了 —— 与 acl.allowNeedsReverse 同一类提醒。
		warnACLDefaultActionDeny(ctx, st, opts, key, value)
		// 落库 ≠ 生效:有些 key 被 server 缓存在内存快照里,不通知就只是改了行 DB。见 aclSnapshotSettingKeys。
		if aclSnapshotSettingKeys[key] {
			if notifyACLChanged(opts) {
				fmt.Fprintln(opts.stderr, opts.T("setting.reloaded", key))
			} else {
				fmt.Fprintln(opts.stderr, opts.T("setting.reloadHint", key))
			}
		}
		// 限速三件套同理:在线会话的 rate.Limiter 是**连接上的对象**,不推 /rate/refresh 就只是改了行 DB。
		if rateRefreshSettingKeys[key] {
			if err := pushRateRefresh(opts, 0); err != nil {
				fmt.Fprintln(opts.stderr, opts.T("setting.reloadHint", key))
			} else {
				fmt.Fprintln(opts.stderr, opts.T("setting.reloaded", key))
			}
		}
		return nil
	case "unset", "delete", "rm":
		// 有 set 就得有 unset。set 有意收下不认识的 key(兼容口子),于是把 key 打错的人
		// 会在 `setting list` 里留下一行永久垃圾 —— 此前 CLI 一个删法都没有,只能去手
		// 改数据库,而那正是文档里反复劝阻的事。
		//
		// 三个名字都收:第一反应敲的是 delete 还是 unset,人各不同,为这个再吃一次
		// "unknown setting subcommand" 没有意义。
		if len(rest) != 1 {
			return usageError(opts.usage("nanotun-admin setting unset <key>"))
		}
		key := rest[0]
		if hintKey, blocked := systemManagedSettingKeys[key]; blocked {
			// 说「拒绝删除」而不是复用 set 那句「拒绝写入」:人刚才敲的是删,
			// 回一句答非所问的话会让他怀疑自己敲错了命令。
			return errors.New(opts.T("setting.blockedDelete", key, opts.T(hintKey)))
		}
		existed, err := st.SettingsDelete(ctx, key)
		if err != nil {
			return err
		}
		if !existed {
			hintUnknownSettingKey(opts, key)
			return errors.New(opts.T("setting.notFound", key))
		}
		if opts.json {
			if err := printJSON(opts.stdout, settingView{Key: key}); err != nil {
				return err
			}
		} else {
			fmt.Fprintln(opts.stdout, opts.T("setting.removed", key))
		}
		// 与 set 同理:删掉只是改了行 DB,跑着的 server 还拿着内存里的旧快照。
		// 已知 key 被删意味着回落到默认值,那同样是一次行为变化,得推下去。
		if aclSnapshotSettingKeys[key] {
			if notifyACLChanged(opts) {
				fmt.Fprintln(opts.stderr, opts.T("setting.reloaded", key))
			} else {
				fmt.Fprintln(opts.stderr, opts.T("setting.reloadHint", key))
			}
		}
		if rateRefreshSettingKeys[key] {
			if err := pushRateRefresh(opts, 0); err != nil {
				fmt.Fprintln(opts.stderr, opts.T("setting.reloadHint", key))
			} else {
				fmt.Fprintln(opts.stderr, opts.T("setting.reloaded", key))
			}
		}
		return nil
	case "list", "ls":
		rows, err := st.DB().QueryContext(ctx, `SELECT key, value FROM app_settings ORDER BY key ASC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		var all []settingView
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				return err
			}
			all = append(all, settingView{Key: k, Value: v})
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if opts.json {
			return printJSON(opts.stdout, all)
		}
		t := newTable(opts.stdout, "KEY", "VALUE")
		for _, s := range all {
			t.row(s.Key, s.Value)
		}
		return t.flush()
	default:
		return newLocErr("cli.unknownSubcommand", "setting", sub)
	}
}

// settingView 是 setting get / list 的 --json 形状。
//
// 补这个是因为 setting 曾是唯一无视 --json 的一族:全局 flag 明说了「输出 JSON(供脚本用)」,
// 而这两条照样吐表格和裸值。统一给所有命令加 --json 的封装脚本会在这里拿到喂不进 jq 的东西,
// 还没有任何报错提示 —— 而 server_dial_host 这类值恰恰是装机脚本最常读的。
type settingView struct {
	Key   string `json:"key"`
	Value string `json:"value"`
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
		// 第十五轮深扫 LOW:多余位置参数属用法错误 → exit 2(与 audit.noPositional / dispatch 一致)。
		return usageError(opts.T("setting.rate.unexpectedPos", fmt.Sprintf("%v", pos)))
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
			// 「值没变」不等于「在线会话已经是这个值」:库里的值可能是别的路径写进去的
			// (raw `setting set` 的老版本 / 直接改 DB / 迁移种子),那些路径不推刷新,
			// 于是显示限着、数据面全速跑,而本命令又因为值一致而不动手 —— 运维就此卡死
			// (2026-07-26 三机实测)。故传了 flag 就照推一次全量刷新:幂等、代价只有一次
			// control sock 调用,换来「跑一遍这条命令即可让库与在线会话对齐」的确定性。
			if !*noRefresh {
				if err := pushRateRefresh(opts, 0); err != nil {
					fmt.Fprintln(opts.stderr, opts.T("setting.rate.refreshWarn", err.Error()))
				} else {
					fmt.Fprintln(opts.stdout, opts.T("setting.rate.reapplied"))
				}
			}
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
//   - 非 0  返回 error(语法 / DNS / ICMP / ctx 取消)— shell 脚本可 `nanotun-admin … || handle`
//
// 三类失败用文本前缀区分(`✗ DNS 失败` / `⚠ ICMP 不通` / `✗ 语法校验失败`),
// 不细分自定义 exit code,避免与全局 main 退出码语义打架。
// 探测的两个外部依赖做成包级变量:DNS 与 ICMP 的结果取决于跑测试的机器能不能上网、
// 出口 ICMP 有没有被安全组 ban。真去查网络会让本文件的用例在离线 / 受限网络下随机红,
// 而这里要验的是**分支怎么分类结果**(DNS 硬错 / 无记录 / 特殊地址 / ICMP 软失败),
// 与真实网络无关。只有测试替换它们。
var (
	probeLookupIPAddr = net.DefaultResolver.LookupIPAddr
	probeDialHost     = store.ProbeServerDialHost
)

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
		return usageError(opts.usage("nanotun-admin setting probe-dial-host <host> [--skip-icmp] [--timeout 20s]"))
	}
	host := strings.TrimSpace(pos[0])
	if host == "" {
		return usageError(opts.T("setting.probe.hostEmpty"))
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
		ips, dnsErr := probeLookupIPAddr(dnsCtx, host)
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
	probeErr := probeDialHost(probeCtx, host)
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
		// 那条建议(--skip-icmp / 自己去 setting set)只对**直接敲这个子命令**的人成立。
		//
		// 向导也调 probe,而云厂商默认封 ping,所以这条软失败在向导里几乎每次都出现 ——
		// 出现的却是一条死路:nanotun-setup 没有 --skip-icmp 这个参数(实测 exit 2,打出用法),
		// 而后半句「直接跑 setting set」正是向导下面两行就要替他做的事。紧接着向导自己还会说
		// 「地址没填错的话直接继续即可」,两句话互相拆台 —— 而这恰好是新装机器上最常走到的一步。
		//
		// 与 cmd_webadmin.go 里那处同一个口径:判词照打,只把不适用的建议收起来。
		if os.Getenv("NANOTUN_SETUP_WIZARD") != "1" {
			fmt.Fprintln(opts.stdout, opts.T("setting.probe.icmpSoftFailHint"))
		}
		return probeErr
	}
	fmt.Fprintln(opts.stdout, opts.T("setting.probe.probeErr", opts.errText(probeErr)))
	return probeErr
}
