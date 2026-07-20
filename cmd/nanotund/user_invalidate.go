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
//        a) 写一帧 LinkTypeClose(code = CloseCodeUserInvalidated, reason 文案);
//        b) Close c.linkConn,触发 readLoop EOF → cleanupConnection 释放 vIP / map。
//      cleanupConnection 内已经处理好「takenOver 路径不重复释放」,不需要在这里特判。
//
//   5. **审计**:每次踢线写一条 audit 行,actor="user-invalidate",
//      action="kick_user_invalidate",target=userID,detail=reason
//      (admin 看 audit list 能直观看到「u3 被 disable 后 8s 内踢了 2 条会话」)。
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
				kickConnForUserInvalidate(ctx, gw, snap.c, uid, reason)
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
				kickConnForUserInvalidate(ctx, gw, snap.c, uid, "psk_rotated")
				continue
			}
			// 平台白名单(2026-07-18):user 本身有效,但 admin 可能改过 allowed_platforms。
			// per-conn 判定(平台是会话属性,同 user 各端可分别合规/不合规),不合规只踢
			// 那一条。空快照(登录时没报 platform)在已设白名单时同样不合规 —— 与登录
			// 路径 AllowsPlatform 对空串的拒绝口径一致,重登也会吃 910,不存在误伤。
			if !allowedEmpty && !u.AllowsPlatform(snap.platformAtLogin) {
				kickConnForUserInvalidate(ctx, gw, snap.c, uid, "platform_denied")
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
func kickConnForUserInvalidate(ctx context.Context, gw *gatewayState, c *Connection, userID int64, reason string) {
	if c == nil {
		return
	}
	if c.takenOver.Load() {
		// takeover 路径下 oldConn 已经处于「待回收」状态,不再写帧。
		return
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

	// audit: actor 标识为「user-invalidate」让管理员能在 audit list 区分这是自动触发的。
	if gw != nil && gw.store != nil {
		auditCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		_ = gw.store.Audit(auditCtx, "user-invalidate", "kick_user_invalidate", userIDFromStoreID(userID), "reason="+reason+",conn="+c.connIDStr)
	}
}

// closeCodeForInvalidateReason 给踢线帧选 close code。
//
// platform_denied 用 910(util.CodePlatformNotAllowed)而非 905:五端已把 910 当
// **终止码**处理(停连不重连、保留 token、显示平台受限文案);905 在各端是「先重连
// 一轮 → 登录被 910 拒 → 才终止」,多一次无谓握手 + PoW + argon2。其余 reason
// (disabled / psk_rotated / deleted)维持 905 —— 这些确实需要用户重新输入凭证 /
// 联系管理员,客户端对 905 的语义已固化。
func closeCodeForInvalidateReason(reason string) int {
	if reason == "platform_denied" {
		return util.CodePlatformNotAllowed
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
		return "账号状态已变更,请重新登录"
	}
}
