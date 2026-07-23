package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
)

// ACL 数据面 enforcement(P0-5,2026-05-22 扩展)
//
// 历史:P0-1(2026-05) 初版只支持 (src_user, dst_user, action) 粒度,且默认动作
// 硬编码为「无规则=放行」。P0-5 在 schema v3 下扩成 ACL v2:
//
//   • proto:''(任意) / tcp / udp / icmp / icmpv6;
//   • dst_port_lo..dst_port_hi:闭区间端口,仅对 tcp/udp 有意义;
//   • dst_kind:'user' = 目标是某 user 的 vIP;'exit' = 出口公网(dst 不在任何 vIP);
//   • default action:由 app_settings.acl_default_action 控制 'allow'(向后兼容)
//     或 'deny'(白名单模型)。无法识别的值 fail-closed 兜到 deny(见 readSettings /
//     buildACLSnapshot);逐条规则的 action 同样归一化,非 'allow' 一律按 'deny'
//     处理(见 normalizeACLAction)。
//
// 设计原则未变:
//   1) 全内存 immutable snapshot,atomic.Pointer 替换,reload(SIGHUP)时切换;
//   2) per-packet hot path 只做 map[int64] / map[aclPair] 查询 + 几次比较;
//      proto/port 命中由 ruleEntry 切片做逐条 evaluate,小规则集 O(K) 不昂贵;
//   3) 规则集为空 + default_action=allow 等价旧行为,**升级零破坏**。

// aclSnapshot 是裁决用的 immutable 视图。
//
// 内部按 (srcKey, dstKey) 索引规则集,命中后逐条 evaluate(proto, port);
// 收集所有匹配项,deny-first 仲裁(deny 命中即 drop;否则 allow 命中即放;
// 都没命中走 defaultAction)。
//
// user 路径与 exit 路径相互独立 —— exit 规则只在 dst 不属于任何 vIP 时被检查,
// 避免「禁某用户连别人 SSH」的规则误伤了「该用户经 VPN 出公网到外部 SSH」。
type aclSnapshot struct {
	// hasUserRules / hasExitRules:这两类规则集是否为空。供 fast-path 跳过整段裁决。
	hasUserRules bool
	hasExitRules bool

	// user-kind 规则索引(精确 + 通配 4 个桶)。
	userExact map[aclPair][]ruleEntry
	userBySrc map[int64][]ruleEntry // dst=* 时按 src 索引;ruleEntry.dst 已经是 0
	userByDst map[int64][]ruleEntry // src=* 时按 dst 索引
	userAll   []ruleEntry           // src=*,dst=*

	// exit-kind 规则:dst 永远为 0(由 store 写时强制);只按 src 索引。
	exitBySrc map[int64][]ruleEntry
	exitWild  []ruleEntry

	// defaultAction:store.ACLAllow(默认,向后兼容)或 store.ACLDeny(白名单)。
	// 仅在「规则集非空且所有匹配规则都没命中 proto/port」时兜底。
	// 注意:即使 hasUserRules / hasExitRules 为 false,只要 defaultAction == deny,
	// 也要丢弃所有跨用户流量 + 所有出口流量(否则白名单模型就是个笑话)。
	defaultAction string

	// meshEnabled(2026-05-23 引入):部署级总开关。
	//   - true(默认): 走正常 ACL 规则 / defaultAction 流程
	//   - false:跨用户 vIP→vIP 流量在 demux 入口直接丢弃,不查 ACL。
	//     注意这**包含**「借用他人设备做出口」的回程(出口机→server,dst=请求方 vIP,
	//     跨用户)——即关组网后他人出口不可用(去程可发、回程被拦,fail-closed,
	//     2026-07-19 深扫定稿:隔离闸不自动改道,宁断不漏)。user-internal、
	//     server 自出口与自己的出口不受影响(客户端仍能用 VPN 出公网)。
	// 来自 store.MeshEnabledKey;reload 时读一次后凝固到 snapshot。
	meshEnabled bool
}

// ruleEntry 是 store.ACLPair 在内存中的最小化拷贝(裁决路径只看这几个字段)。
type ruleEntry struct {
	action   string // "allow" / "deny"
	proto    string // "", "tcp", "udp", "icmp", "icmpv6"
	portLo   uint16
	portHi   uint16
	hasPorts bool // portLo != 0 || portHi != 0
}

type aclPair struct {
	src, dst int64
}

var (
	// aclCurrent 持有当前 effective 快照。init() 装载一份空白快照(default=allow),
	// 等价于「未启用 ACL」语义;reloadACLSnapshotFromStore 在启动/SIGHUP 时替换。
	aclCurrent atomic.Pointer[aclSnapshot]

	// aclDropCount 累计被 ACL 拒绝的包数(user + exit + default-deny 都统计在内)。
	// /metrics(P1#6)与 SIGHUP 后的 INFO 摘要均消费这个值。
	aclDropCount atomic.Uint64

	// aclExitDropCount 专门统计「出口流量被丢」的包数,便于 audit 区分误伤。
	aclExitDropCount atomic.Uint64

	// exitGateDropCount:P0-4 user-level 出口闸丢包总数(独立于 ACL 规则,
	// 由 c.exitAllowed=false 触发的 drop)。供 /metrics + 周期性 INFO 摘要消费。
	exitGateDropCount atomic.Uint64

	// meshOffDropCount(2026-05-23):mesh 总开关 = false 导致的跨用户流量丢包总数。
	// 单独统计便于运维区分「ACL 规则丢的」与「mesh 主动关闭丢的」。
	meshOffDropCount atomic.Uint64

	// srcSpoofDropCount(M2 源地址反欺骗):普通会话以非本会话 vIP 作源发包被丢的总数。
	// 持续增长 = 有会话在尝试冒充他人 vIP / 注入伪造回包。供 /metrics + control_socket 消费。
	srcSpoofDropCount atomic.Uint64

	// aclMalformedUserDropCount(fail-closed 加固):会话**有** userID 却解析不出 int64(损坏/异常身份)
	// 时按 fail-closed 丢包的总数。正常会话 userID 恒为 "u<id>",此计数应恒为 0;非 0 = 出现了异常身份会话。
	aclMalformedUserDropCount atomic.Uint64
)

// reloadACLSnapshotFromStore 从 store 拉取最新规则集与 default action,构建
// immutable 快照后原子替换。失败时返回 err 并**保留旧快照**(进程不退)。
//
// 同时也把 mesh_enabled setting(2026-05-23 引入的总开关)凝固进 snapshot,
// 这样数据面热路径不需要每包都去查 SettingsGet — reload 一次,新值生效。
func reloadACLSnapshotFromStore(st *store.Store) (int, error) {
	if st == nil {
		// 无 store(测试 helper 兜底):装一份默认 allow 的空快照,
		// aclAllows 永远 return true,与历史行为一致。
		aclCurrent.Store(&aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: true})
		return 0, nil
	}
	// 读一次 (default_action, mesh_enabled)。两者都 fail-closed:读真错(非「key 缺失」)
	// 时返回 err 保留旧快照,绝不因一次 DB 抖动把 default-deny 翻成 allow、或把关掉的 mesh
	// 重新放开。ok=false(key 不存在)才落到内置默认。
	readSettings := func(ctx context.Context) (def string, mesh bool, err error) {
		def = store.ACLAllow
		v, ok, serr := st.SettingsGet(ctx, "acl_default_action")
		if serr != nil {
			return "", false, fmt.Errorf("read acl_default_action: %w", serr)
		}
		if ok {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case store.ACLDeny:
				def = store.ACLDeny
			case store.ACLAllow:
				def = store.ACLAllow
			default:
				// 深扫第十轮 MED:无法识别的非空值(拼错,如 "deni" / "allo")过去静默保留
				// allow —— fail-open,把本想 default-deny 的部署敞开。改为 fail-closed 到
				// deny + Warn(与 exit_mode/exit_dns_redirect 的 fail-fast 同思路;这里不 Fatal,
				// 避免一次手抖 DB 编辑把在跑的数据面打挂——deny 是安全方向,修正值 reload 即恢复)。
				// CLI `setting set acl_default_action` 也已加 write 校验(见 cmd_setting.go),
				// 正常路径拼错根本落不了库,这里是最后一道兜底。
				logrus.WithField("acl_default_action", v).Warn(
					"[acl] 无法识别的 acl_default_action 值,按 fail-closed 处理为 deny;请改回 allow/deny")
				def = store.ACLDeny
			}
		}
		mesh, merr := st.GetMeshEnabled(ctx)
		if merr != nil {
			return "", false, fmt.Errorf("read mesh_enabled: %w", merr)
		}
		return def, mesh, nil
	}

	// 深扫第八轮 LOW:rules / default_action / mesh_enabled 是三条独立查询,中间夹着一次
	// admin 写(改 default_action / toggle mesh / 加删规则)会拼出「规则集 vs 兜底动作」
	// 不一致的快照。这里用「前读设置 → 读规则 → 后读设置,不一致就重试」把窗口收窄到近乎零:
	// 若一轮内设置没变,说明这轮读到的 rules 与 settings 相互一致。有界重试,兜底用末次读值
	// (低危,下次 reload/SIGHUP 会自愈)。
	//
	// 深扫第九轮 LOW:超时**按 attempt** 各给 5s,而不是一个 5s 摊到最多 9 次查询上 ——
	// 否则 DB 高延迟时后几次查询可能撞到已耗尽的 deadline,reloadACLSnapshotFromStore
	// 返回 err;而启动期该错误是 logrus.Fatal(见 server.go),会把进程直接打挂。
	var (
		rules []*store.ACLPair
		def   string
		mesh  bool
	)
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		def, mesh, rules = "", false, nil
		retry, err := func() (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			defBefore, meshBefore, err := readSettings(ctx)
			if err != nil {
				return false, err
			}
			rs, err := st.ListACLPairs(ctx)
			if err != nil {
				return false, err
			}
			defAfter, meshAfter, err := readSettings(ctx)
			if err != nil {
				return false, err
			}
			rules, def, mesh = rs, defAfter, meshAfter
			// 设置在读规则期间被改动 → 需要重试一轮取一致视图。
			return defBefore != defAfter || meshBefore != meshAfter, nil
		}()
		if err != nil {
			return 0, err
		}
		if !retry {
			break // 一致,采用本轮结果
		}
	}

	snap := buildACLSnapshot(rules, def)
	snap.meshEnabled = mesh
	aclCurrent.Store(snap)
	return len(rules), nil
}

// normalizeACLAction 把逐条规则的 action 归一到 store.ACLAllow / store.ACLDeny。
// 深扫第十二轮 MED:evaluateUser/evaluateExit 用 `e.action == store.ACLDeny` 判定,裸存
// r.Action 时,手抠 DB / 坏 SQL 写入的 "Deny" / "deny " / "" 等非规范值 != "deny",会被当成
// allow 命中,放行本该阻断的跨用户流量(方向与 default action 的 fail-closed 相反)。写路径
// 只收 allow/deny,所以正常数据无碍;这里对**未知/非规范一律兜成 deny**(fail-closed),
// 与 default action、buildACLSnapshot 的兜底方向一致。
func normalizeACLAction(a string) string {
	if strings.EqualFold(strings.TrimSpace(a), store.ACLAllow) {
		return store.ACLAllow
	}
	return store.ACLDeny
}

// buildACLSnapshot 把 store.ACLPair 切片折叠成查表友好的 immutable snapshot。
//
// 单独抽出来便于 unit test 不依赖 store。返回的 snapshot.meshEnabled 默认 true,
// reloadACLSnapshotFromStore 会在调用本函数后覆盖该字段。测试想模拟「mesh off」
// 直接给 snap.meshEnabled = false 赋值即可,不需要走 store。
//
// defaultAction 必须是 store.ACLAllow / store.ACLDeny;其它值会被规范化为 **deny**(fail-closed)。
// 深扫第十一轮 MED:与 readSettings 的 fail-closed(未知值→deny)对齐。生产 reload 路径传进来的
// 值已被 readSettings 规范化,不会命中这里;但本 helper 是导出给测试/未来调用方的独立入口,
// 兜底方向必须是 deny 而非 allow —— 否则任何绕过 readSettings 的调用会重开 fail-open 缺口。
func buildACLSnapshot(rules []*store.ACLPair, defaultAction string) *aclSnapshot {
	if defaultAction != store.ACLAllow && defaultAction != store.ACLDeny {
		defaultAction = store.ACLDeny
	}
	s := &aclSnapshot{defaultAction: defaultAction, meshEnabled: true}

	for _, r := range rules {
		if r == nil {
			continue
		}
		entry := ruleEntry{
			action:   normalizeACLAction(r.Action),
			proto:    r.Proto,
			portLo:   uint16(r.DstPortLo),
			portHi:   uint16(r.DstPortHi),
			hasPorts: r.DstPortLo != 0 || r.DstPortHi != 0,
		}
		switch r.DstKind {
		case store.ACLDstKindExit:
			if !s.hasExitRules {
				s.exitBySrc = map[int64][]ruleEntry{}
				s.hasExitRules = true
			}
			if r.SrcUserID == 0 {
				s.exitWild = append(s.exitWild, entry)
			} else {
				s.exitBySrc[r.SrcUserID] = append(s.exitBySrc[r.SrcUserID], entry)
			}
		default: // 视作 ACLDstKindUser(老数据 / 默认)
			if !s.hasUserRules {
				s.userExact = map[aclPair][]ruleEntry{}
				s.userBySrc = map[int64][]ruleEntry{}
				s.userByDst = map[int64][]ruleEntry{}
				s.hasUserRules = true
			}
			switch {
			case r.SrcUserID == 0 && r.DstUserID == 0:
				s.userAll = append(s.userAll, entry)
			case r.SrcUserID == 0:
				s.userByDst[r.DstUserID] = append(s.userByDst[r.DstUserID], entry)
			case r.DstUserID == 0:
				s.userBySrc[r.SrcUserID] = append(s.userBySrc[r.SrcUserID], entry)
			default:
				p := aclPair{src: r.SrcUserID, dst: r.DstUserID}
				s.userExact[p] = append(s.userExact[p], entry)
			}
		}
	}
	return s
}

// pktTuple 把数据面热路径上要参与 ACL 决策的字段固化下来,避免反复解析。
type pktTuple struct {
	src     netip.Addr // 源 IP（M2 源地址反欺骗用；v4-mapped 归一为 v4）
	dst     netip.Addr
	proto   string // "tcp" / "udp" / "icmp" / "icmpv6" / ""(未识别)
	dstPort uint16 // tcp/udp 才有意义;其他 0
}

// aclDropPacketDirected 是 demux 热路径上的入口:
//   - 解析包头(dst IP / L4 proto / dst port);
//   - 根据 dst 是否属于某 vIP 选 user 路径或 exit 路径;
//   - 走对应规则集 + default action 仲裁;
//   - drop 时计数器自增,调用方应当 `continue` 不要写 tunWriteChan。
//
// srcUserID == 0 表示「无 user 上下文」(parseUserIDStr 失败、测试用例等),
// 此时跳过 enforcement(与 P0-1 保留语义,避免误伤异常路径)。
func aclDropPacketDirected(srcUserID int64, packet []byte) bool {
	if srcUserID == 0 {
		return false
	}
	snap := aclCurrent.Load()
	if snap == nil {
		return false
	}
	t, ok := parsePacketTuple(packet)
	if !ok {
		return false
	}
	dstUserID, isVIP := lookupVIPOwner(t.dst)

	if isVIP {
		if dstUserID == srcUserID {
			return false
		}
		// mesh 总开关(2026-05-23):管理员通过 web/admin 关掉 mesh 时,**所有**跨用户
		// vIP→vIP 流量在这里就被截住,不再下沉到 ACL 引擎。语义上比 default=deny 更"硬":
		//   - default=deny 是「ACL 白名单」(允许 admin 配 allow 例外);
		//   - !meshEnabled 则是「整网组网开关」,无论 ACL 怎么配都丢。
		// 计数器独立(meshOffDropCount),便于运维区分丢包原因。注意 user-internal
		// (dstUserID == srcUserID)已经在上面提前返回,这里只影响真正的跨用户流量。
		//
		// 排障提示(2026-07-19 深扫定稿):「借用他人出口」的回程也命中这里——出口机
		// 送回的包 src_user=出口机主人、dst=请求方 vIP,跨用户即丢。故关组网后他人出口
		// 表现为「去程可发、回程全丢、连接超时」,drops 计在 mesh_off。这是有意的
		// fail-closed(隔离闸不自动改道他人流量),不是 bug;文案见 nav.meshConfirmOff。
		if !snap.meshEnabled {
			aclDropCount.Add(1)
			meshOffDropCount.Add(1)
			recordACLDrop("mesh_off", srcUserID, dstUserID, t.proto, t.dstPort)
			return true
		}
		// fast-path:hasUserRules=false 且 default=allow → 直接放;
		// default=deny 时即便 hasUserRules=false 也要丢(白名单语义)。
		if !snap.hasUserRules {
			if snap.defaultAction == store.ACLDeny {
				aclDropCount.Add(1)
				recordACLDrop("user", srcUserID, dstUserID, t.proto, t.dstPort)
				return true
			}
			return false
		}
		if evaluateUser(snap, srcUserID, dstUserID, t) == store.ACLDeny {
			aclDropCount.Add(1)
			recordACLDrop("user", srcUserID, dstUserID, t.proto, t.dstPort)
			return true
		}
		return false
	}

	// server 本地 / 网关地址(如 MagicDNS gateway:53、server 本机服务)不是「公网出口」流量,不应被 exit ACL
	// 约束(第四轮深扫 HIGH)。此前 exitDeniedForPacket / forwardPacketToExitNode / forwardPacketToSubnetRoute
	// 都已用 isLocalMeshDst 放行网关,唯独这里漏了:default=deny(或含 exit deny 规则)下,发往网关的 MagicDNS
	// 查询会被误判成 exit_acl 丢弃 → 整网 DNS 解析中断。注意 dst 若是某 vIP 已在上面的 isVIP 分支处理并返回,
	// 故这里 isLocalMeshDst 实际只会命中「server 自身网关地址」,不影响跨用户 vIP 的 exit 语义。
	if isLocalMeshDst(t.dst) {
		return false
	}

	// dst 不是任何 vIP → 出口流量(走 NAT 上公网)。
	if !snap.hasExitRules {
		if snap.defaultAction == store.ACLDeny {
			aclDropCount.Add(1)
			aclExitDropCount.Add(1)
			recordACLDrop("exit_acl", srcUserID, 0, t.proto, t.dstPort)
			return true
		}
		return false
	}
	if evaluateExit(snap, srcUserID, t) == store.ACLDeny {
		aclDropCount.Add(1)
		aclExitDropCount.Add(1)
		recordACLDrop("exit_acl", srcUserID, 0, t.proto, t.dstPort)
		return true
	}
	return false
}

// aclAllows 是「不带 packet 上下文」的粗粒度判定,只看 src→dst 维度的 user 规则,
// 不考虑 proto/port/exit。保留给 admin 旁路检查 / 旧测试。
//
// 数据面热路径请用 aclDropPacketDirected。
func aclAllows(src, dst int64) bool {
	if src == dst {
		return true
	}
	snap := aclCurrent.Load()
	if snap == nil {
		return true
	}
	// mesh 总开关 OFF 时跨用户永远拒(2026-05-23),与 aclDropPacketDirected 保持一致。
	// 否则会出现「admin 关了组网,CLI 还说 allow」的语义分裂。
	if !snap.meshEnabled {
		return false
	}
	if !snap.hasUserRules {
		return snap.defaultAction != store.ACLDeny
	}
	tuple := pktTuple{} // 无 proto/port → 仅匹配「任意 proto + 任意 port」规则
	return evaluateUser(snap, src, dst, tuple) != store.ACLDeny
}

// aclDeniesSubnetRoute（SR-M4）：子网路由数据面 ACL —— 请求方经宣告方访问其 LAN 子网时，按「请求方 user × 宣告方
// user」+ proto/port 裁决（复用 user-kind 规则与 mesh 语义：访问某宣告方背后的子网 == 能否与该宣告方 user 私有互通，
// 故一条 `A→B deny` 同时挡住 A 访问 B 的 vIP 和 B 宣告的子网）。返回 true = 拒绝（数据面 fail-closed 丢弃）。
//   - src/dst 为 0（无合法 user 上下文）或相等（自指）→ 放行（与 aclDropPacketDirected src==0 口径一致）；
//   - mesh 总开关关 → 一并拒（子网路由属跨用户私有连通，admin 关组网即整网锁死）；
//   - 无 user 规则：default=deny → 拒（白名单语义），default=allow → 放。
func aclDeniesSubnetRoute(srcUserID, dstUserID int64, packet []byte) bool {
	if srcUserID == 0 || dstUserID == 0 || srcUserID == dstUserID {
		return false
	}
	snap := aclCurrent.Load()
	if snap == nil {
		return false
	}
	if !snap.meshEnabled {
		return true
	}
	t, ok := parsePacketTuple(packet)
	if !ok {
		return false
	}
	if !snap.hasUserRules {
		return snap.defaultAction == store.ACLDeny
	}
	return evaluateUser(snap, srcUserID, dstUserID, t) == store.ACLDeny
}

// evaluateUser 在 user-kind 规则集里裁决(src,dst,tuple),返回 store.ACLAllow/ACLDeny。
//
// 收集所有从 (src,dst) 维度命中的 ruleEntry,再按 proto/port 二次过滤,
// 然后 deny-first;都没命中则返回 snap.defaultAction。
func evaluateUser(snap *aclSnapshot, srcUserID, dstUserID int64, t pktTuple) string {
	var allowHit, denyHit bool

	check := func(entries []ruleEntry) {
		for _, e := range entries {
			if !ruleMatchesPacket(e, t) {
				continue
			}
			if e.action == store.ACLDeny {
				denyHit = true
				return
			}
			allowHit = true
		}
	}
	check(snap.userExact[aclPair{src: srcUserID, dst: dstUserID}])
	if !denyHit {
		check(snap.userBySrc[srcUserID])
	}
	if !denyHit {
		check(snap.userByDst[dstUserID])
	}
	if !denyHit {
		check(snap.userAll)
	}
	if denyHit {
		return store.ACLDeny
	}
	if allowHit {
		return store.ACLAllow
	}
	return snap.defaultAction
}

// evaluateExit 在 exit-kind 规则集里裁决,语义同 evaluateUser 但只看 src + tuple。
func evaluateExit(snap *aclSnapshot, srcUserID int64, t pktTuple) string {
	var allowHit, denyHit bool
	for _, e := range snap.exitBySrc[srcUserID] {
		if !ruleMatchesPacket(e, t) {
			continue
		}
		if e.action == store.ACLDeny {
			return store.ACLDeny
		}
		allowHit = true
	}
	if !denyHit {
		for _, e := range snap.exitWild {
			if !ruleMatchesPacket(e, t) {
				continue
			}
			if e.action == store.ACLDeny {
				return store.ACLDeny
			}
			allowHit = true
		}
	}
	if allowHit {
		return store.ACLAllow
	}
	return snap.defaultAction
}

// ruleMatchesPacket 判断一条规则(已经在 src/dst 维度命中)是否在 proto/port 维度也命中。
//
//   - rule.proto 为空 → 匹配任意 proto;
//   - rule.proto 非空 → 必须等于 packet 的 proto;
//   - rule.hasPorts=false → 匹配任意端口;
//   - rule.hasPorts=true → packet 必须是 tcp/udp 且 dstPort 落在 [lo,hi] 闭区间。
//
// 没有 L4 信息(packet 不是 tcp/udp,或 packet 头被截断)时,带端口要求的规则视为
// 「不命中」,这样可以避免误伤 ICMP 等无端口流量。
func ruleMatchesPacket(r ruleEntry, t pktTuple) bool {
	if r.proto != "" && r.proto != t.proto {
		return false
	}
	if r.hasPorts {
		if t.proto != "tcp" && t.proto != "udp" {
			return false
		}
		if t.dstPort < r.portLo || t.dstPort > r.portHi {
			return false
		}
	}
	return true
}

// parsePacketTuple 从 IP 报文解析出 dst / proto / dstPort,失败时 ok=false。
//
// IPv4:Total Length / IHL 不验证(已经由 util.ValidIPPacket 兜底);
// IPv6:只支持「Next Header 直接是 L4」的简单情况,带扩展头时退化为 proto=""
// (与 ruleMatchesPacket 的"无 L4 信息 → 带端口规则不命中"策略配合,扩展头流量
// 仍然能匹配「任意 proto / 任意端口」的规则,语义可接受)。
func parsePacketTuple(p []byte) (pktTuple, bool) {
	if len(p) < 1 {
		return pktTuple{}, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return pktTuple{}, false
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || ihl > len(p) {
			return pktTuple{}, false
		}
		var src, dst [4]byte
		copy(src[:], p[12:16])
		copy(dst[:], p[16:20])
		out := pktTuple{src: netip.AddrFrom4(src), dst: netip.AddrFrom4(dst)}
		proto := p[9]
		switch proto {
		case 1:
			out.proto = "icmp"
		case 6:
			out.proto = "tcp"
			if len(p) >= ihl+4 {
				out.dstPort = binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
			}
		case 17:
			out.proto = "udp"
			if len(p) >= ihl+4 {
				out.dstPort = binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
			}
		}
		return out, true
	case 6:
		if len(p) < 40 {
			return pktTuple{}, false
		}
		var src, dst [16]byte
		copy(src[:], p[8:24])
		copy(dst[:], p[24:40])
		// Unmap:把 v4-mapped-in-v6（::ffff:a.b.c.d）归一成 v4，避免 vIP 反查 / 源校验因表示差异漏判。
		out := pktTuple{src: netip.AddrFrom16(src).Unmap(), dst: netip.AddrFrom16(dst).Unmap()}
		nh := p[6]
		switch nh {
		case 58:
			out.proto = "icmpv6"
		case 6:
			out.proto = "tcp"
			if len(p) >= 40+4 {
				out.dstPort = binary.BigEndian.Uint16(p[40+2 : 40+4])
			}
		case 17:
			out.proto = "udp"
			if len(p) >= 40+4 {
				out.dstPort = binary.BigEndian.Uint16(p[40+2 : 40+4])
			}
		}
		return out, true
	default:
		return pktTuple{}, false
	}
}

// connSourceSpoofed 判断会话 c 送来的包源 IP 是否为「伪造」——即普通会话以非本会话 vIP 作源（冒充他人 vIP /
// 注入伪造回包）。返回 true = 应丢弃。M2 源地址反欺骗，用于 readLoop 热路径。
//
// 语义（保守，避免误伤合法流量；顺序即优先级）：
//  1. 源恰为**本会话自己**的某 vIP → 合法(最常见,先判)。
//  2. 源是**另一在线会话**的 vIP（lookupVIPOwner 命中且非本会话)→ 冒充他人 vIP,**任何会话**(含出口 / 子网
//     宣告方)一律判伪造。合法的出口 / LAN 回程源是外网 / 内网地址,绝不会等于另一 VPN 客户端的 vIP。这条修掉了
//     「宣告方豁免过宽 → 可冒充他人 vIP 注入伪造回包」。
//  3. **已批准**的出口 / 子网转发者(advertisedExitApproved / advertisedSubnetApproved)合法中继外网 / LAN 回程
//     (源是任意非 vIP 地址)→ 豁免。用的是**已批准**闸而非「发过 advertise 帧」——否则任何认证客户端发一帧
//     RouteAdvertise 就能自我豁免、绕过 M2(见 Connection.advertisedExitApproved 注释)。
//  4. 其余(普通会话 / 未批准宣告方):仅在本会话已持同族(v4/v6)vIP 却与源对不上时判伪造;尚无该族 vIP 则无从
//     判定,放行交由后续 ACL / 出口闸处理——不在此环节误杀。
func connSourceSpoofed(c *Connection, payload []byte) bool {
	if c == nil {
		return false
	}
	t, ok := parsePacketTuple(payload)
	if !ok || !t.src.IsValid() {
		return false
	}
	src := t.src.Unmap()

	ips := c.safeClientIPs()
	sameFamily := false
	for _, a := range ips {
		pa, err := netip.ParseAddr(a.VirtualIP)
		if err != nil {
			continue
		}
		pa = pa.Unmap()
		if pa == src {
			return false // (1) 源恰为本会话某 vIP → 合法
		}
		if pa.Is4() == src.Is4() {
			sameFamily = true // 本会话持有同族 vIP，可作判定基准
		}
	}

	// (2) 源是另一在线会话的 vIP → 冒充他人,任何会话都不允许(含已批准出口 / 子网)。
	if _, owned := lookupVIPOwner(src); owned {
		return true
	}

	// (3) 已批准的出口 / 子网转发者:合法中继非 vIP 源的外网 / LAN 回程 → 豁免。
	if c.advertisedExitApproved.Load() || c.advertisedSubnetApproved.Load() {
		return false
	}

	// (4) 普通会话 / 未批准宣告方:有同族 vIP 却无一匹配 → 伪造。
	return sameFamily
}

// vipOwner: vIP 文本 → 拥有者 userID(int64)。
//
// ACL 数据面的核心反向表 —— 收到一个 IP 包,要知道「dst IP 属于哪个 user」才能查 ACL。
// 写者:handleVPNLink 完成 vIP 分配后注册;cleanupConnection 释放时注销。
// 读者:aclDropPacketDirected 在 LinkTypeIPPacket 入口热路径上。
//
// P3-b(2026-05-22):由 sync.RWMutex + map 切换到 atomic.Pointer[map] 快照(copy-on-write)。
// 读路径(lookupVIPOwner)完全 lock-free,每包查一次哈希表;
// 写路径(register/unregister)用 vipOwnerWriteMu 串行化,拷贝旧 map → 修改 → Store。
//
// 取舍:
//   - 写比读罕见数百倍以上(每次登录/登出 vs 每包),整张 map 拷贝(典型 100~1000 entries)
//     一次只几微秒~几十微秒,远低于 RWMutex 在高并发读时的争用开销。
//   - 拷贝路径足够简单(浅拷贝 netip.Addr → int64),不需要 RCU 或更复杂的并发数据结构。
//   - aclCurrent (ACL 快照) 已经用同样模式,保持一致风格。
// vipOwnerEntry 是 vipOwner 表的值:userID 供 ACL 反查;ownerConnID 作**注销守卫**(见 unregisterVIPOwners)。
type vipOwnerEntry struct {
	userID      int64
	ownerConnID uint32
}

var (
	vipOwnerCur     atomic.Pointer[map[netip.Addr]vipOwnerEntry]
	vipOwnerWriteMu sync.Mutex // 串行化写者,保证 copy-update-store 原子序
)

func init() {
	empty := map[netip.Addr]vipOwnerEntry{}
	vipOwnerCur.Store(&empty)
}

// vipOwnerCloneLocked 拷贝当前 map。调用方持 vipOwnerWriteMu。
// 复杂度 O(N),N=当前活跃 vIP 数。
func vipOwnerCloneLocked() map[netip.Addr]vipOwnerEntry {
	cur := vipOwnerCur.Load()
	out := make(map[netip.Addr]vipOwnerEntry, len(*cur)+4)
	for k, v := range *cur {
		out[k] = v
	}
	return out
}

// registerVIPOwners 在登录成功(或 takeover 过户)后批量登记 user 的 vIP 集合。
// userID == 0 表示「未知 user」(测试场景兜底),直接 no-op。ownerConnID 记录当前拥有连接,供注销守卫比对。
func registerVIPOwners(addrs []netip.Addr, userID int64, ownerConnID uint32) {
	if userID == 0 || len(addrs) == 0 {
		return
	}
	vipOwnerWriteMu.Lock()
	defer vipOwnerWriteMu.Unlock()
	next := vipOwnerCloneLocked()
	for _, a := range addrs {
		if a.IsValid() {
			next[a] = vipOwnerEntry{userID: userID, ownerConnID: ownerConnID}
		}
	}
	vipOwnerCur.Store(&next)
}

// unregisterVIPOwners 在 cleanupConnection 真正释放 vIP 时删除映射。**owner-guarded**:仅当该 vIP 当前 entry
// 仍属于 ownerConnID 时才删。
//
// 为何要守卫(修 P0-1 之外的竞态):老连接 cleanup 里「delete(clientIPUsed, vip)」与「unregisterVIPOwners」不在同一
// 临界区(前者持 clientIPUsedMu、后者不持)。老连接释放 clientIPUsed 后、调本函数前,**新连接**可能已 alloc 到同一
// vIP 并 registerVIPOwners(自己的 connID)。若此时老连接无条件 delete,会误删新连接刚建立的映射 → 新连接流量在
// aclDropPacketDirected 查不到 owner 被误判(exit/NAT 归类错乱 / 跨用户 ACL 漏查)。connID 唯一(含同 user 重连也
// 不同),比 userID 守卫更严:同 user 拿到同 vIP 的重连场景也不会互删。takeover 已在过户时把 ownerConnID 改成
// newConn(见 handleTakeoverLogin),故老连接 takenOver 分支即便调到这里也删不动(connID 不符),newConn 将来能正常注销。
func unregisterVIPOwners(addrs []netip.Addr, ownerConnID uint32) {
	if len(addrs) == 0 {
		return
	}
	vipOwnerWriteMu.Lock()
	defer vipOwnerWriteMu.Unlock()
	next := vipOwnerCloneLocked()
	changed := false
	for _, a := range addrs {
		if e, ok := next[a]; ok && e.ownerConnID == ownerConnID {
			delete(next, a)
			changed = true
		}
	}
	if changed {
		vipOwnerCur.Store(&next)
	}
}

// lookupVIPOwner 查 vIP 的拥有者 userID。完全 lock-free。
func lookupVIPOwner(a netip.Addr) (int64, bool) {
	m := vipOwnerCur.Load()
	e, ok := (*m)[a]
	if !ok {
		return 0, false
	}
	return e.userID, true
}

// serverGatewayAddrsT 是 server 自身 TUN 网关地址（v4/v6）的快照。
type serverGatewayAddrsT struct{ v4, v6 netip.Addr }

// serverGatewayAddrs 存 server 自身 TUN 网关地址，启动配置 TUN 后由 setServerGatewayAddrs 设一次（之后不变）。
// lock-free（atomic.Pointer，与 vipOwnerCur 同风格），供数据面热路径 isServerGatewayAddr 无锁读。
var serverGatewayAddrs atomic.Pointer[serverGatewayAddrsT]

// setServerGatewayAddrs 在 TUN 配好后记录网关 v4/v6（入参为网关 CIDR，如 "10.201.0.1/16"）。解析失败的族留零值（IsValid=false）。
func setServerGatewayAddrs(v4CIDR, v6CIDR string) {
	var g serverGatewayAddrsT
	if v4CIDR != "" {
		if a, err := netip.ParseAddr(gatewayAddrFromCIDR(v4CIDR)); err == nil {
			g.v4 = a
		}
	}
	if v6CIDR != "" {
		if a, err := netip.ParseAddr(gatewayAddrFromCIDR(v6CIDR)); err == nil {
			g.v6 = a
		}
	}
	serverGatewayAddrs.Store(&g)
}

// isServerGatewayAddr 判断 a 是否为 server 自身 TUN 网关地址（v4 或 v6）。未设置（测试 / 无 TUN）时恒 false。
func isServerGatewayAddr(a netip.Addr) bool {
	g := serverGatewayAddrs.Load()
	if g == nil {
		return false
	}
	return (g.v4.IsValid() && a == g.v4) || (g.v6.IsValid() && a == g.v6)
}

// isLocalMeshDst 判断目的地址是否属于「本 mesh 内部 / server 本地」——不应被当公网流量对待（既不转发给
// 出口 / 子网路由器，也不受 user.exit_allowed 公网闸拦截）。含两类：
//  1. 某客户端 vIP（mesh 互通，lookupVIPOwner 命中）；
//  2. server 自身 TUN 网关地址（如 10.201.0.1 / fd..::1）—— 客户端发往它的包是「访问 server 本机服务」，
//     典型是 MagicDNS resolver 监听的 gateway:53。
//
// 此前三处判定（forwardPacketToExitNode / forwardPacketToSubnetRoute / exitDeniedForPacket）只排除了 vIP、**漏了
// 网关**：选了 peer 出口的会话会把「发往网关:53 的 DNS 查询」当公网流量转发给出口节点 → 到不了 server 本地
// resolver → magic/公网 DNS 全断；无出口权限用户发往网关的 DNS 也会被 exit_allowed 闸误丢。统一收口于此，放行网关。
func isLocalMeshDst(a netip.Addr) bool {
	if _, ok := lookupVIPOwner(a); ok {
		return true
	}
	return isServerGatewayAddr(a)
}

// aclSummaryForLog 给启动 / SIGHUP 后的日志摘要用。
func aclSummaryForLog() logrus.Fields {
	snap := aclCurrent.Load()
	if snap == nil {
		return logrus.Fields{"snapshot": "nil"}
	}
	count := func(m map[int64][]ruleEntry) int {
		n := 0
		for _, v := range m {
			n += len(v)
		}
		return n
	}
	countPair := func(m map[aclPair][]ruleEntry) int {
		n := 0
		for _, v := range m {
			n += len(v)
		}
		return n
	}
	return logrus.Fields{
		"mesh_enabled":   snap.meshEnabled,
		"default_action": snap.defaultAction,
		"user_exact":     countPair(snap.userExact),
		"user_by_src":    count(snap.userBySrc),
		"user_by_dst":    count(snap.userByDst),
		"user_all":       len(snap.userAll),
		"exit_by_src":    count(snap.exitBySrc),
		"exit_wild":      len(snap.exitWild),
		"drops_total":    aclDropCount.Load(),
		"drops_exit":     aclExitDropCount.Load(),
		"drops_mesh_off": meshOffDropCount.Load(),
	}
}

// init 给 aclCurrent 装一份空白快照(default=allow,mesh on),防止 reloadACLSnapshotFromStore
// 还没被调用时 aclAllows / aclDropPacketDirected 拿到 nil。
func init() {
	aclCurrent.Store(&aclSnapshot{defaultAction: store.ACLAllow, meshEnabled: true})
}
