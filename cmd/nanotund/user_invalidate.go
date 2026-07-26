package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// P0-1 user invalidation:让 admin CLI 的 user disable / reset-psk / delete 操作
// 在 ≤ scanInterval 内主动踢掉对应会话,无需重启 server / 等客户端自然超时。
//
// 设计取舍:
//
//   1. **轮询而非事件流**:admin CLI 和 server 是两个进程,没有共享 channel;
//      改用 unix socket 推事件(P1#6 admin connection list 那条路径附带)成本更高。
//      改用「server 周期性 SELECT users 拿快照」一次几十毫秒,绝大多数情况下空跑;
//      只有 admin 真的改过 user 才会有踢线动作。scanInterval 默认 10s,可配置。
//
//   2. **去重扫描**:遍历 connIDMap 拿到的是 connection 列表,可能同一 userID 有
//      多条会话;先按 userID 去重,只查一次 DB,再决定要不要踢这个 userID 下所有
//      conn。N 用户 × O(1) 查询 = O(N),对千用户级别完全够用。
//
//   3. **失效判定逻辑**:
//        - users 表里查不到这个 userID(被 delete 了)         → kick all
//        - user.disabled_at != 0 (被 disable 了)              → kick all
//        - user.psk_hash != conn.pskHashAtLogin (被 reset 了) → kick all
//        - user.allowed_platforms 非空且 conn.platformAtLogin 不在白名单
//          (2026-07-18)                                       → kick **该 conn**
//          (平台是 per-conn 属性:同一 user 的 mac 会话合规、android 会话不合规,
//           只踢后者。close code 用 910 而非 905 —— 五端已把 910 当终止码处理:
//           停连不重连、保留 token、显示「此账号不支持在当前平台使用」;若用 905,
//           客户端会先重连一轮、再在登录时吃 910,多一次无谓握手。)
//        - user.exit_allowed / bandwidth_*_bps 改变           → **不踢**,延迟到下次重连
//          (踢线影响用户体感,只在「安全相关」字段变化时主动断;限速 / 出口策略
//           变化只用于新会话,旧会话拿历史值跑完)。
//
//   4. **踢线动作**:
//        a) 写一帧 LinkTypeClose(code 见 closeCodeForInvalidateReason, reason 文案);
//        b) Close c.linkConn,触发 readLoop EOF → cleanupConnection 释放 vIP / map。
//      cleanupConnection 内已经处理好「takenOver 路径不重复释放」,不需要在这里特判。
//
//   5. **审计**:每次踢线写一条 audit 行,target=userID,detail=reason。
//      自动失效 actor="user-invalidate"/action="kick_user_invalidate"
//      (admin 看 audit list 能直观看到「u3 被 disable 后 8s 内踢了 2 条会话」);
//      管理员经 /kick 端点主动踢的记 actor="admin-kick"/action="kick_session",
//      两者不混淆(见 isAccountInvalidationReason)。
//
//   6. **测试场景**:gw.store == nil 时 startUserInvalidationLoop 直接 no-op。
//
// 关闭:绑 globalContext;ctx 取消后退出。

// CloseCodeUserInvalidated:本次 close 由「user 被 disable / reset-psk / delete」触发。
// 客户端收到这个 code 后:不要立即重连,等用户重新输入 PSK / 联系管理员;
// 与 CloseCodeShutdown(902 维护中,鼓励重连)的语义区分开。
const CloseCodeUserInvalidated = 905

// userInvalidateScanInterval 是默认扫描周期。可通过 [server].user_invalidate_interval_sec 覆盖。
// 10s 是经验值:与 typical 网管巡检节奏对齐,数据库 IO 几乎可忽略。
const userInvalidateScanInterval = 10 * time.Second

// userInvalidateKickCount 累计因 user 失效踢线的会话数,/metrics 与日志摘要用。
var userInvalidateKickCount atomic.Uint64

// startUserInvalidationLoop 在后台开一条 goroutine 周期性扫描 user 失效并踢线。
// gw / gw.store 为 nil 时 no-op,与 startAuditGC 风格一致。
func startUserInvalidationLoop(gw *gatewayState, interval time.Duration) func() {
	if gw == nil || gw.store == nil {
		return func() {}
	}
	if interval <= 0 {
		interval = userInvalidateScanInterval
	}
	go safeGlobalGoroutine("userInvalidate", globalContextCancel, func() {
		runUserInvalidationLoop(globalContext, gw, interval)
	})
	return func() {}
}

// runUserInvalidationLoop 抽出来便于 unit test 注入更短的 interval。
//
// 进入立刻跑一次(覆盖「重启刚好错过 tick」);然后按 interval ticker 循环;ctx.Done 退出。
func runUserInvalidationLoop(ctx context.Context, gw *gatewayState, interval time.Duration) {
	if ctx == nil {
		ctx = context.Background()
	}
	doOnce := func() {
		scanAndKickInvalidUsers(ctx, gw)
	}
	doOnce()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logrus.Info("[user-invalidate] ctx 已取消,退出扫描循环")
			return
		case <-t.C:
			doOnce()
		}
	}
}

// scanAndKickInvalidUsers 一次扫描的核心:
//  1. 浅拷贝 connIDMap 出所有 (userID → [conn1,...]) 映射;
//  2. 对每个 userID 查 user 行,按上面 #3 的判定逻辑判断是否要踢;
//  3. 踢时锁外异步 close(避免持 connIDMapMu 时拖死 close I/O)。
func scanAndKickInvalidUsers(ctx context.Context, gw *gatewayState) {
	if gw == nil || gw.store == nil {
		return
	}

	type connSnap struct {
		c               *Connection
		userIDInt       int64
		pskHashAtLogin  string
		platformAtLogin string
	}
	byUserID := map[int64][]connSnap{}

	// P3-a:走 by-user 索引避免 O(N_total) 扫 connIDMap;每个 user 只查 1 次 DB。
	connIDMapMu.RLock()
	for userIDStr, sub := range connByUser {
		uid := parseUserIDStr(userIDStr)
		if uid <= 0 {
			continue
		}
		for _, c := range sub {
			if c == nil {
				continue
			}
			byUserID[uid] = append(byUserID[uid], connSnap{
				c:               c,
				userIDInt:       uid,
				pskHashAtLogin:  c.pskHashAtLogin,
				platformAtLogin: c.platformAtLogin,
			})
		}
	}
	connIDMapMu.RUnlock()

	if len(byUserID) == 0 {
		return
	}

	for uid, snaps := range byUserID {
		// user 维度判定(user_deleted / user_disabled) —— 命中即全员踢。
		// 这两个才是真正的「整账号失效」;PSK 轮换是 per-conn 判定(见下)。
		//
		// 2026-05-25:历史上还有 A2 per-conn profile_id 黑名单分支,与 P2#14 配套;
		// 0014 移除 pid 链路后此处只剩 user 维度 + 下面的 per-conn 判定。
		u, reason, kickAll := userInvalidStatus(ctx, gw.store, uid)
		if kickAll {
			for _, snap := range snaps {
				// 账号级失效:接管后的新会话同样该死 → 追。
				kickConnForUserInvalidate(ctx, gw, snap.c, uid, reason, kickFollowTakeover)
			}
			continue
		}
		if u == nil {
			continue // 临时性 DB 错误,本轮跳过(userInvalidStatus 已 Warn)
		}
		// per-conn 判定(psk_rotated / platform_denied)。二者都是**会话级**属性,
		// 必须逐条比对本连接**登录时的快照**,不能拿 snaps[0] 一条代表全体:
		//
		// 关键 bug(修复前):psk_rotated 曾用 snaps[0].pskHashAtLogin 判 kickAll。
		// snaps 来自 Go map 遍历,snaps[0] 是**随机**一条。admin reset-psk 后用户立刻
		// 用新 PSK 重登(新 conn 的 hash == DB 新值),而旧 PSK 会话还在(等本轮扫到踢):
		//   - 若 snaps[0] 恰是旧会话 → 判 kickAll → **刚登录的新会话被一起误踢**
		//     (close 905「请重新输入新 PSK」,用户刚输完就被踢,可能循环);
		//   - 若 snaps[0] 恰是新会话 → hash 匹配 → psk_rotated 根本没被检出 →
		//     该踢的旧 PSK 会话**逃过本轮**,安全动作被非确定性地延迟。
		// 逐连接比对同时消除这两个方向的错误。
		allowedEmpty := strings.TrimSpace(u.AllowedPlatforms) == ""
		dbHash := strings.TrimSpace(u.PSKHash)
		for _, snap := range snaps {
			// psk_rotated 优先:本连接登录时用的 PSK hash 与 DB 当下不一致 → 只踢这条。
			if snap.pskHashAtLogin != "" && dbHash != strings.TrimSpace(snap.pskHashAtLogin) {
				// 逐连接属性判据 → **不追**接管后的新会话:它可能已用新 PSK 合法重认证过(takeover 会盖上
				// DB 当下的哈希,正是为了免掉这次二次踢)。见 kickFollowPolicy。
				kickConnForUserInvalidate(ctx, gw, snap.c, uid, "psk_rotated", kickNoFollow)
				continue
			}
			// 平台白名单(2026-07-18):user 本身有效,但 admin 可能改过 allowed_platforms。
			// per-conn 判定(平台是会话属性,同 user 各端可分别合规/不合规),不合规只踢
			// 那一条。空快照(登录时没报 platform)在已设白名单时同样不合规 —— 与登录
			// 路径 AllowsPlatform 对空串的拒绝口径一致,重登也会吃 910,不存在误伤。
			if !allowedEmpty && !u.AllowsPlatform(snap.platformAtLogin) {
				// 同为逐连接属性(平台取自本连接登录时的上报)→ 不追,下一轮按新会话的平台重判。
				kickConnForUserInvalidate(ctx, gw, snap.c, uid, "platform_denied", kickNoFollow)
			}
		}
	}
}

// userInvalidStatus 查 user 当前状态:
//   - kickAll=true:整账号失效(user_deleted / user_disabled),reason 给出原因,
//     调用方应踢掉该 user 的全部会话;此时 u 可能为 nil(deleted)。
//   - kickAll=false 且 u != nil:user 有效,u 供调用方做 per-conn 级判定
//     (psk_rotated / 平台白名单)。
//   - kickAll=false 且 u == nil:临时性 DB 错误,本轮什么都不做(误伤 active 用户的成本
//     远大于让 admin 操作晚一个 tick 生效,下一轮扫描会再试)。
//
// 注意:PSK 轮换**不**在这里判 —— 它是 per-conn 的(见 scanAndKickInvalidUsers),
// 用整账号 kickAll 会把刚用新 PSK 重登的会话一起误踢。
func userInvalidStatus(ctx context.Context, st *store.Store, userID int64) (u *store.User, reason string, kickAll bool) {
	opCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	u, err := st.GetUser(opCtx, userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, "user_deleted", true
		}
		logrus.WithError(err).WithField("user_id", userID).Warn("[user-invalidate] 查 user 失败,跳过本轮")
		return nil, "", false
	}
	if u.DisabledAt != 0 {
		return u, "user_disabled", true
	}
	return u, "", false
}

// kickConnForUserInvalidate 给单条 conn 写一帧 LinkTypeClose(code=CloseCodeUserInvalidated),
// 然后 Close linkConn;readLoop 收 EOF 后 cleanupConnection 自然回收 vIP / connIDMap。
// maxKickTakeoverHops 限制 kickConnForUserInvalidate 沿「接管链」回溯的跳数。正常最多 1 跳(oldConn → newConn);
// 给几跳余量以容忍踢除与连续 takeover 撞在一起,同时防病态循环 / 自指把调用方钉死在这里。
const maxKickTakeoverHops = 4

// kickFollowPolicy 决定「目标已被 takeover 顶掉」时是否沿 connID 追到当前持有者。
//
// 第二十三轮深扫 MED:第二十二轮无条件追,踩坏了 takeover 的一条既有保护。判据分两类:
//
//   - **账号级 / 管理员显式指定**(user_deleted、user_disabled、control-socket kick):判据与被踢连接自身的
//     属性无关,接管后的新会话同样该死 → 必须追,否则一次性的 admin kick 会静默失效(见 kickFollowTakeover)。
//   - **逐连接属性**(psk_rotated、platform_denied):判据取自**被踢连接登录时的快照**。takeover 会给 newConn
//     盖上 DB 当下的真值(见 server.go 里 pskHashAtLogin 的注释),正是为了让「管理员改了 PSK → 用户用新 PSK
//     重连成功」的会话不被同周期再踢一次("踢-takeover-再被踢"抖动)。若这类踢除也追,就把那条保护废掉了:
//     周期扫描先在锁下快照到旧会话(陈旧哈希)再放锁判定,接管一旦落进这个间隙,追过去踢掉的正是刚刚合法
//     重认证过的新会话 → 必须**不追**。放掉它是安全的:下一 tick 会对新会话按其真实属性重判。
type kickFollowPolicy bool

const (
	kickNoFollow       kickFollowPolicy = false // 逐连接属性判据(psk_rotated / platform_denied)
	kickFollowTakeover kickFollowPolicy = true  // 账号级或管理员显式指定
)

func kickConnForUserInvalidate(ctx context.Context, gw *gatewayState, c *Connection, userID int64, reason string, follow kickFollowPolicy) bool {
	if c == nil {
		return false
	}
	if follow == kickNoFollow && c.takenOver.Load() {
		// takeover 路径下 oldConn 已处于「待回收」状态,不再写帧;而按本连接属性做的判定对接管后的新连接
		// 未必成立(理由见 kickFollowPolicy),交给下一轮扫描重判。
		return false
	}
	// 第二十二轮深扫 MED:c 已被 takeover 顶掉时**不能只是返回** —— 业务会话仍以**同一 connIDStr** 活在接管后的
	// 新 conn 上(takeover 只换底层链路,sid / vIP / 身份全继承)。调用方是在 connIDMapMu 下快照完就放锁的,快照
	// 与这里之间足够一次 takeover 提交完成,于是:管理员的 kick 打在一个已经作废的 oldConn 上 → 早退 → 真正在跑
	// 的 newConn 从头到尾没被踢,而 control-socket 还会把它计成「已踢除 N 条」回报给管理员(静默失败 + 虚假成功)。
	// 周期扫描(scanAndKickInvalidUsers)下一 tick 能自愈,一次性的 admin kick 不能。故沿 sid 重新解析当前持有者。
	//
	// 与 round-21 在 takeover **提交前**加的 superseded 复检互补:那条堵的是「kick 早于提交」,这条兜的是
	// 「kick 晚于提交」。两侧合起来才让 kick 对任意交错都生效。
	for hop := 0; c.takenOver.Load(); hop++ {
		if hop >= maxKickTakeoverHops {
			logrus.WithFields(logrus.Fields{
				"conn_id": c.connIDStr,
				"user_id": userID,
				"reason":  reason,
			}).Warn("[user-invalidate] 沿接管链回溯超过跳数上限,放弃本次踢除(下一轮扫描会重试)")
			return false
		}
		connIDMapMu.RLock()
		cur := connIDMap[c.connIDStr]
		connIDMapMu.RUnlock()
		if cur == nil || cur == c {
			// 接管后的新 conn 也已离场(cleanup 已把该 sid 摘除),或表里仍是自己(理论不会:提交时必被换成
			// newConn)。无活会话可踢,如实回 false,避免虚假成功计数。
			return false
		}
		// 追到的会话必须仍属同一 user 才踢。takeover 不换身份(同 sid + 同 takeoverSecret),故正常必然相等;
		// 这里防的是「sid 被复用到别的用户」这类不该发生但一旦发生就会踢错人的情形 —— 宁可漏踢(下一轮扫描
		// 会按新会话的真实归属重判),不可误踢无关用户。userID==0(调用方未能解析出目标 user)时跳过该校验。
		if userID != 0 {
			if curUID := parseUserIDStr(cur.userID); curUID != 0 && curUID != userID {
				logrus.WithFields(logrus.Fields{
					"conn_id":  c.connIDStr,
					"want_uid": userID,
					"got_uid":  curUID,
					"reason":   reason,
				}).Warn("[user-invalidate] 接管后的会话已不属目标 user,放弃踢除")
				return false
			}
		}
		c = cur
	}
	// exit-node/subnet route 黑洞修复:本 conn 即将被 close(admin kick / PSK 失效自动踢),立即标 superseded——
	// 使它**瞬间**从 by-device 转发目标(lookupRunningExitConnByDevice / lookupSubnetAdvertiserConnByDevice)与在线出口
	// (buildExitsList / lookupActiveConnByDevice)里摘除,不必等异步 cleanup。否则「已踢未清」窗口里若它是某 device
	// 的在跑出口/子网路由器,请求方流量会被投进它已关闭的链路黑洞(与同 device fresh 重登录 supersede 同类)。
	// atomic 一次性置真、不复位(被踢会话即将销毁);置位在 close 之前,lookups 立刻生效。见 Connection.superseded。
	c.superseded.Store(true)
	closeBody, err := util.MarshalCloseJSON(closeCodeForInvalidateReason(reason), userInvalidateClientMsg(reason))
	if err != nil {
		logrus.WithError(err).Warn("[user-invalidate] 构造 CloseMsg 失败,直接 Close linkConn")
	}

	// 第二十轮深扫 MED:抢 c.linkWrMu 之前先取消其 tunnel ctx,逼停可能卡在限速器 WaitN(持该锁)的下行 demux。
	// 否则低限速配置下 admin kick / PSK 失效自动踢的 Lock() 可能阻塞数秒(WaitN 不受下面钉的 SetWriteDeadline 约束)。
	forceCancelTunnel(c)
	c.linkWrMu.Lock()
	linkConn := c.linkConn
	if linkConn != nil && closeBody != nil {
		if dl, ok := linkConn.(interface{ SetWriteDeadline(time.Time) error }); ok {
			_ = dl.SetWriteDeadline(time.Now().Add(1 * time.Second))
			defer func() { _ = dl.SetWriteDeadline(time.Time{}) }()
		}
		// 帧写失败也继续 close,远端可能已经断网。
		_ = util.WriteLinkFrame(linkConn, util.LinkTypeClose, closeBody)
	}
	c.linkWrMu.Unlock()

	// 关 linkConn 让 readLoop EOF;cleanupConnection 走 defer 释放资源。
	if linkConn != nil {
		_ = linkConn.Close()
	}

	userInvalidateKickCount.Add(1)
	logrus.WithFields(logrus.Fields{
		"user_id": userID,
		"conn_id": c.connIDStr,
		"reason":  reason,
		"age":     time.Since(c.createdAt).Round(time.Second).String(),
	}).Warn("[user-invalidate] 主动踢线")

	// audit: 自动失效记 actor="user-invalidate",管理员主动踢记 actor="admin-kick"。
	// 之前一律写前者 —— `audit list` 里 admin kick 与「后台扫描发现账号失效」长得一模一样,
	// 排查「这个人是被谁踢下线的」时无从区分。
	if gw != nil && gw.store != nil {
		actor, action := "user-invalidate", "kick_user_invalidate"
		if !isAccountInvalidationReason(reason) {
			actor, action = "admin-kick", "kick_session"
		}
		auditCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		_ = gw.store.Audit(auditCtx, actor, action, userIDFromStoreID(userID), "reason="+reason+",conn="+c.connIDStr)
	}
	return true
}

// isAccountInvalidationReason 判定这次踢线是不是**真的账号失效**。
//
// 只有这四种由 userInvalidStatus / per-conn 判定产生的原因才是账号级失效;其余一律来自
// control socket 的 /kick 端点(`nanotun-admin kick`、Web 后台「断开会话」),那是
// **管理员主动断一条会话**,账号本身分毫未变。
//
// 白名单而非黑名单:Web 的 kick 允许管理员填任意 reason 字符串(handler_misc.go),
// 黑名单会把「填了自定义原因」的踢线误判成账号失效。
func isAccountInvalidationReason(reason string) bool {
	switch reason {
	case "user_disabled", "user_deleted", "psk_rotated", "platform_denied":
		return true
	default:
		return false
	}
}

// closeCodeForInvalidateReason 给踢线帧选 close code。
//
// platform_denied 用 910(util.CodePlatformNotAllowed)而非 905:五端已把 910 当
// **终止码**处理(停连不重连、保留 token、显示平台受限文案);905 在各端是「先重连
// 一轮 → 登录被 910 拒 → 才终止」,多一次无谓握手 + PoW + argon2。其余账号失效
// (disabled / psk_rotated / deleted)维持 905 —— 这些确实需要用户重新输入凭证 /
// 联系管理员,客户端对 905 的语义已固化。
//
// 管理员主动踢(kick session/device/user)改用 902:客户端把 902 当**瞬态**处理,
// 按 backoff 自动重连;905 及一切未知码都是终止码,`--auto-reconnect` 直接失效。
//
// 三机实测(2026-07-26):`nanotun-admin kick session <id>` 之后,开着 --auto-reconnect
// 的客户端打印「账号状态已变更,请重新登录」后退出 status=1 再也不回来 —— 而账号什么都没变。
// kick device 的既定用途(见 control_socket.go:改完 fixed_vip 踢一下让客户端拿新 IP)
// 因此完全落空:踢下去就再也起不来了,得人工上机重连。
func closeCodeForInvalidateReason(reason string) int {
	if reason == "platform_denied" {
		return util.CodePlatformNotAllowed
	}
	if !isAccountInvalidationReason(reason) {
		return CloseCodeShutdown
	}
	return CloseCodeUserInvalidated
}

// userInvalidateClientMsg 给 CloseMsg.Reason 选一段对用户更友好的中文。
func userInvalidateClientMsg(reason string) string {
	switch reason {
	case "user_disabled":
		return "账号已被管理员禁用,请联系管理员"
	case "psk_rotated":
		return "密钥已变更,请重新输入新 PSK"
	case "user_deleted":
		return "账号已被删除"
	case "platform_denied":
		// 与登录路径 clientLoginMessageForCode(910) 完全一致 —— 客户端两条路径
		// (登录被拒 / 在线被踢)看到同一句话。
		return "此账号不支持在当前平台使用"
	default:
		// 管理员主动断开某条会话。别再说「账号状态已变更」—— 账号没变,说了用户会去找
		// 管理员问一个不存在的问题,而真正的账号失效(上面四种)反倒没了区分度。
		return "本次会话已被管理员断开(账号正常),稍后将自动重连"
	}
}
