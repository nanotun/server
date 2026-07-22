package main

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// loginAuthError 是 authenticateLogin 返回的有损失败信息：包含要写回 LoginResp
// 的 (code, message)；调用方负责把它们写到客户端。
type loginAuthError struct {
	code    int
	message string
}

func (e *loginAuthError) Error() string { return e.message }

// loginAuthResult 包含成功登录后下游需要的所有上下文。
//
// PSK 模式下 User 非 nil;Device 仅当客户端上报了合法 device_uuid 时存在。
type loginAuthResult struct {
	UserID string
	User   *store.User
	Device *store.Device
}

// authenticateLogin 验证客户端首帧 LoginReq,返回登录成功后的会话上下文。
//
//   - 客户端在 LoginReq.Token 字段里携带 PSK 明文(保持协议字段复用,避免再加字段)。
//   - UserID 形如 "u1"、"u2"……由 store.users.id 派生,确保跨重启稳定。
//   - 如果客户端上报了合法 RFC 4122 v4 device_uuid,则同步 upsert 到 devices 表,
//     用于后续 vIP 持久化。
func authenticateLogin(gw *gatewayState, loginReq *util.LoginReq, connIDStr string) (*loginAuthResult, *loginAuthError) {
	_ = connIDStr // 历史 backend 路径用,PSK 模式无需(connIDStr 由调用方自行分配)
	return authenticatePSK(gw, loginReq)
}

func authenticatePSK(gw *gatewayState, loginReq *util.LoginReq) (*loginAuthResult, *loginAuthError) {
	if gw == nil || gw.authVerifier == nil || gw.store == nil {
		return nil, &loginAuthError{code: util.CodeServerError, message: "PSK 模式未初始化"}
	}
	if loginReq.Name == "" || loginReq.Token == "" {
		return nil, &loginAuthError{code: util.CodeTokenInvalid, message: "缺少用户名或 PSK"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := gw.authVerifier.VerifyLogin(ctx, loginReq.Name, loginReq.Token)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUnknownUser):
			return nil, &loginAuthError{code: util.CodeUserNotFound, message: "用户不存在"}
		case errors.Is(err, auth.ErrBadPSK):
			return nil, &loginAuthError{code: util.CodeTokenInvalid, message: "认证失败"}
		case errors.Is(err, auth.ErrUserDisabled):
			return nil, &loginAuthError{code: util.CodeUserBlacklisted, message: "用户已禁用"}
		default:
			logrus.WithError(err).Error("PSK 校验内部错误")
			return nil, &loginAuthError{code: util.CodeServerError, message: "服务器内部错误"}
		}
	}

	// 平台白名单(2026-07-18):user.AllowedPlatforms 非空时,只允许其中列出的平台登录。
	// 空 = 不设限(老 user / 默认新建 user 走这条,放行任何平台)。放在 device upsert
	// 之前 —— 被策略拒绝的登录不该在 devices 表留行。
	//
	// **计费 / 分级策略,非安全边界**:platform 客户端自报可伪造(见 util.CodePlatformNotAllowed)。
	// 回 910,客户端须当终止码处理(停连不重连、不清 token);server.go 侧不计入 PoW
	// 失败惩罚(正常策略拒绝不该抬难度 / 触发风控)。
	if !user.AllowsPlatform(loginReq.Platform) {
		logrus.WithFields(logrus.Fields{
			"user_id":           user.ID,
			"platform":          loginReq.Platform,
			"allowed_platforms": user.AllowedPlatforms,
		}).Warn("[login] 上报平台不在账号白名单,拒绝登录(910)")
		return nil, &loginAuthError{
			code:    util.CodePlatformNotAllowed,
			message: "平台不被允许: " + loginReq.Platform,
		}
	}

	out := &loginAuthResult{UserID: userIDFromStoreID(user.ID), User: user}

	// 客户端上报了 device_uuid 则同步 upsert（耗时几十微秒），
	// 这样后续按 device 路径就能在 leases 表里写入持久租约。
	//
	// 严格校验 RFC 4122 v4 + 归一大小写：
	//   - 不合规一律按「未提供 device_uuid」降级（log Warn,登录继续,vIP 走临时分配）
	//   - 避免恶意 / 老错客户端用 "garbage" 创建脏 device 行,占满 vIP 池
	//   - 大小写归一让同一物理设备无论客户端送哪种大小写都命中同一行
	normalizedUUID := util.NormalizeDeviceUUID(loginReq.DeviceUUID)
	if normalizedUUID != "" {
		if !util.IsValidUUIDv4(normalizedUUID) {
			logrus.WithFields(logrus.Fields{
				"user_id":     user.ID,
				"device_uuid": loginReq.DeviceUUID,
			}).Warn("device_uuid 不是合法 RFC 4122 v4,按未提供处理,vIP 走临时分配")
		} else {
			dev, err := upsertLoginDevice(ctx, gw, user.ID, normalizedUUID, loginReq.DeviceName, loginReq.Platform)
			if err != nil {
				// 2026-07-18 现场(GL-MT3000 出口"离线"事故):部署重启后客户端 4 秒内重连,
				// DB 还在被旧进程释放,UpsertDevice 超时。旧行为「登录继续但降级匿名」让这条
				// 会话 deviceID=0,后果链:
				//   - 固定 vIP 租约拉不到 → 分到临时 vIP;
				//   - route_advertise / 出口注册按 deviceID 鉴身份 → 被拒 → 出口显示"离线";
				//   - 客户端隧道本身是通的(status=Connected),**没有任何理由主动重连**,
				//     故障静默持续到人工重启客户端。
				// 改为:合法 UUID 的登录 upsert 失败时直接拒绝(500)。mac/iOS 把 500 列在
				// retryableLoginCodes,OpenWrt/Windows/Linux daemon 对非 401-409 业务码也走
				// 退避重连 —— 客户端几秒后重试,DB 就绪即恢复完整身份,故障自愈且不静默。
				//
				// 注意不能降低为「只对出口设备拒绝」:普通设备匿名降级同样丢固定 vIP,
				// 且登录时并不知道设备是否被用作出口。
				logrus.WithError(err).WithFields(logrus.Fields{
					"user_id":     user.ID,
					"device_uuid": normalizedUUID,
				}).Warn("upsert device 失败,拒绝本次登录让客户端退避重试(匿名降级会静默丢失固定 vIP / 出口身份)")
				return nil, &loginAuthError{code: util.CodeServerError, message: "upsert device 失败: " + err.Error()}
			}
			out.Device = dev
		}
	} else {
		// 2026-05-22 现场遇到:导入新 profile 的 Mac 客户端 LoginReq.DeviceUUID 为空,
		// 静默跳过 UpsertDevice + UpsertLease,本会话内 vIP 仅在内存 —— 用户能用,但
		// 服务端重启 / 客户端重连后**会拿到不同 vIP**(因为 dbReservedVIPs 拉不到这条
		// 历史 lease,allocator 可能把同一 vIP 分给别的设备)。
		//
		// 这是已知的「客户端行为不规范」降级路径,运维侧能做的就是知道它发生了。
		// 用 Info 而非 Warn:这条不是 server 端 bug,是客户端没上报;真正想修要去
		// 客户端 profile 生成路径补一个 device_uuid 兜底(参见 nanotun-admin/README
		// 的 profile 生成段;后续 profile 导入工具应当 server-side 兜底生成)。
		logrus.WithFields(logrus.Fields{
			"user_id":  user.ID,
			"platform": loginReq.Platform,
		}).Info("[login] 客户端未上报 device_uuid,vIP 仅在内存,重启 / 重连后不保证沿用同一 vIP")
	}

	return out, nil
}

// upsertLoginDevice 包装 gw.store.UpsertDevice,失败后原地重试一次。
//
// 动机(2026-07-18 GL-MT3000 事故):部署重启窗口内 DB 短暂不可写(旧进程尚未释放 /
// WAL busy),首次 upsert 可能吃掉登录 ctx 的剩余预算后以 context deadline exceeded
// 失败。直接拒绝登录会让客户端退避几秒再来一整轮(PoW + argon2 verify),而 DB 往往
// 几百毫秒后就绪 —— 先给一次原地重试,多数瞬态失败当场吸收;仍失败才上抛,由调用方
// 拒绝登录(见 authenticatePSK)。
//
// 重试**不继承**原 ctx:原 ctx 若已 deadline exceeded,继承则重试必然立刻失败,
// 等于没重试。独立预算 2s,加上登录 ctx 的 5s,最坏 ~7.3s,仍远小于客户端 15s
// 握手超时。
func upsertLoginDevice(ctx context.Context, gw *gatewayState, userID int64, uuid, name, platform string) (*store.Device, error) {
	dev, err := gw.store.UpsertDevice(ctx, userID, uuid, name, platform)
	if err == nil {
		return dev, nil
	}
	time.Sleep(300 * time.Millisecond)
	retryCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dev, err2 := gw.store.UpsertDevice(retryCtx, userID, uuid, name, platform)
	if err2 == nil {
		logrus.WithFields(logrus.Fields{
			"user_id":     userID,
			"device_uuid": uuid,
			"first_err":   truncateForLog(err.Error(), 200),
		}).Info("upsert device 首次失败,原地重试成功(瞬态 DB busy 已吸收)")
		return dev, nil
	}
	return nil, err2
}

// userIDFromStoreID 把 SQLite 主键转成 nanotun 协议层使用的 userID 字符串。
//
// 用「u<id>」前缀:与历史 UUID 风格区分开,日志一眼能看出来源。其它代码只把
// userID 当不透明字符串使用。
func userIDFromStoreID(id int64) string {
	return "u" + strconv.FormatInt(id, 10)
}

// parseUserIDStr 把 "u<id>" 字符串解析回 int64。
//
// 返回 0 表示「无法解析」,调用方应当把 0 当作「无 user 上下文」,跳过依赖 int64
// userID 的能力(如 ACL enforcement)。
//
// 解析非常宽松:只要 strconv.ParseInt 成功(去掉首字符 "u")就返回。任何错误都返回 0。
func parseUserIDStr(s string) int64 {
	if len(s) < 2 || s[0] != 'u' {
		return 0
	}
	n, err := strconv.ParseInt(s[1:], 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// clientFacingLoginCode 把「会泄漏账号是否存在」的内部失败码收敛成统一对外码,防用户名枚举。
//
// 内部码(authErr.code)**仍**用于 audit 子类与告警(auditActionForLoginCode / noteLoginUserNotFound),
// 只有**发给客户端**的 code + message 收敛:
//   - CodeUserNotFound(403 用户不存在)→ CodeTokenInvalid(401 用户名或密钥错误),与「PSK 错」在 wire 上不可区分。
//
// 其余码保持原样:CodeUserBlacklisted 仅在 auth.VerifyLogin **已验过正确 PSK** 后才可能返回(见其重排),不构成
// 枚举面,保留它给合法用户「账号被禁用」的明确提示;CodeVPNExpired / CodePlatformNotAllowed / CodeServerError
// 等也都不是「账号是否存在」的枚举面,不收敛。
func clientFacingLoginCode(code int) int {
	if code == util.CodeUserNotFound {
		return util.CodeTokenInvalid
	}
	return code
}

// clientLoginMessageForCode 把内部 (code, raw message) 映射成**安全可外发**的中文文案。
//
// 为什么需要:authErr.message 可能来自 DB 错误链(`UNIQUE constraint failed: ...`)
// 或其它内部信息,直接写回客户端会泄漏细节。这里把客户端可见文案收敛到固定白名单,
// raw message 只留在服务端日志(且服务端日志里也做长度截断,见 truncateForLog)。
//
// 文案以「让用户能判断该不该重试」为准:
//   - 401/403 类:让用户去重新输入用户名/PSK;
//   - 402 过期:让用户续费;
//   - 406 单机会话上限:提示踢老连接;
//   - 500 服务器内部:提示稍后重试;
//   - 其它未知 code:统一「认证失败」。
func clientLoginMessageForCode(code int) string {
	switch code {
	case util.CodeOK:
		return "ok"
	case util.CodeTokenInvalid:
		return "用户名或密钥错误"
	case util.CodeTokenExpired:
		return "登录凭据已过期,请重新登录"
	case util.CodeUserNotFound:
		return "用户不存在"
	case util.CodeUserBlacklisted:
		return "用户已被禁用"
	case util.CodeVPNExpired:
		return "VPN 服务已到期"
	case util.CodeSessionLimit:
		return "已达最大会话数,请先在其它设备断开"
	case util.CodeKickByAdmin:
		return "已被管理员踢下线"
	case util.CodeNodeLoginInvalid:
		return "节点信息无效"
	case util.CodeDuplicateJWT:
		return "同账号已在其它链路登录"
	case util.CodePowFailed:
		// P2#16:对外统一友好文案,不暴露内部 PoW 失败分支细节(签名错 / 过期 / 难度低 /
		// 限速 / 状态机违规)— 避免 attacker 通过响应差异分辨自己处在哪种防护机制下。
		// audit_logs 的 detail 字段会写明具体 reason,运维分析用。
		//
		// NOTE: 当前 PoW 失败走 LinkTypeClose 帧(server.go 内 writeCloseAndReturn),
		// 不走 writeLinkLoginResp → 这个文案在生产路径**不会被发到客户端**。
		// 保留此 case 用作 wire-level 兼容预留:future 如果改成走 LoginResp 路径
		// (例如想给客户端 UI 提示重试),已经有现成 message 可用,不必再补。
		return "登录请求过于频繁,请稍后再试"
	case util.CodePlatformNotAllowed:
		return "此账号不支持在当前平台使用"
	case util.CodeServerError:
		return "服务器内部错误,请稍后再试"
	default:
		return "认证失败"
	}
}

// truncateForLog 给 logrus 字段做长度截断,避免 DB / 第三方库返回 KB 级 message
// 把 vpn.log 撑爆 / 把单行 JSON 日志撑出 default 解析限制(很多 log shipper 默认 8KB)。
func truncateForLog(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + "...<truncated>"
}

// auditActionForLoginCode 把 auth code 映射到一个更细粒度的 audit action 名,
// 让 `nanotun-admin audit list --action login.fail.user_not_found` 这种过滤可用。
//
// 背景(2026-05-21 事故)：当时安装脚本切了 DB 路径但没迁用户,所有客户端登录返回 403
// "用户不存在"。journal 里只是 `level=warning msg="登录验证失败"`,audit_logs 里只
// 记一行 `action=login.fail detail=code=403`,既不在 ERROR 级别又不能按子类聚合,
// 等到用户感知(11 小时后)才发现。现在每个失败原因走独立 action 名,既能用 audit list
// 按子类做 SLO 报表,也能让运维一眼判断「是不是大面积用户不存在 → 怀疑 DB 路径漂移」。
//
// **命名风格(双轨制,第三轮深扫 P2-7)**:本函数返回的全部以 `login.` 开头的
// **dot-hierarchy** 形式,因为 admin 用 `--action-prefix login.fail` 需要一次性
// 抓全部失败子类。这是 server 自身热路径的「runtime action」命名约定,与 admin CLI /
// Web Console 的 `user_create` / `user_reset_psk` underscore 风格**并列**:
//   - dot / hierarchy → 可扇出子分类,支持 prefix 聚合(本函数);
//   - underscore / flat → 无子分类,精确匹配(`nanotun-admin/cmd_user.go` 等)。
//
// 详细约定见 `nanotun-admin/README.md` 「audit action 命名约定」一节 + `store/audit.go`
// 顶部注释。新增 login.* 错误码时维持 dotted,**不要**因「统一」改成 underscore。
func auditActionForLoginCode(code int) string {
	switch code {
	case util.CodeOK:
		return "login.success"
	case util.CodeTokenInvalid:
		return "login.fail.bad_psk"
	case util.CodeTokenExpired:
		return "login.fail.token_expired"
	case util.CodeUserNotFound:
		return "login.fail.user_not_found"
	case util.CodeUserBlacklisted:
		return "login.fail.user_disabled"
	case util.CodeVPNExpired:
		return "login.fail.vpn_expired"
	case util.CodeSessionLimit:
		return "login.fail.session_limit"
	case util.CodeKickByAdmin:
		return "login.fail.kick_by_admin"
	case util.CodeNodeLoginInvalid:
		return "login.fail.node_invalid"
	case util.CodeDuplicateJWT:
		return "login.fail.duplicate_jwt"
	case util.CodePowFailed:
		// P2#16:统一 action,具体 PoW 失败原因放 detail 字段(reason=pow.bad_sig 等)。
		// 便于 `nanotun-admin audit list --action login.fail.pow` 一键过滤。
		return "login.fail.pow"
	case util.CodePlatformNotAllowed:
		return "login.fail.platform_denied"
	case util.CodeServerError:
		return "login.fail.server_error"
	default:
		return "login.fail"
	}
}

// userNotFoundRateLimiter 60 秒窗口聚合 "用户不存在" 失败次数,超过阈值打 ERROR 级别
// 一次性总结(不是每条都 ERROR,避免日志爆量)。
//
// 触发场景(2026-05-21 事故场景):部署脚本把 DB 路径搬走但没迁数据 → 所有终端连续 403。
// 单条 warn 隐没在普通日志里,但「12 次/分钟以上 user_not_found」是非常异常的信号,
// 这里把它升级成 ERROR,运维 dashboard / log shipper 关键字告警都能直接命中。
//
// 阈值 12/min 不可配:够小到「正常错误率不会到」、够大到「单个用户输错三次密码不会触发」
// (一个真实用户重输 N 次也是 bad_psk 而非 user_not_found)。
const userNotFoundWarnThreshold = 12

type rateBucket struct {
	mu       sync.Mutex
	count    atomic.Int64
	windowAt int64
}

var loginUserNotFoundBucket rateBucket

// noteLoginUserNotFound 给每条 user_not_found 失败递增计数,每 60 秒窗口结束时
// 如果计数 ≥ 阈值就打一条 ERROR 总结。返回值仅用于测试。
//
// nowFn 是为了让测试注入时钟,生产代码传 nil 等价于 time.Now。
func noteLoginUserNotFound(nowFn func() time.Time) (triggered bool) {
	if nowFn == nil {
		nowFn = time.Now
	}
	now := nowFn().Unix()
	b := &loginUserNotFoundBucket
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.windowAt == 0 {
		b.windowAt = now
	}
	if now-b.windowAt >= 60 {
		c := b.count.Swap(0)
		windowStart := b.windowAt
		b.windowAt = now
		if c >= userNotFoundWarnThreshold {
			logrus.WithFields(logrus.Fields{
				"count":        c,
				"window_start": windowStart,
				"window_sec":   now - windowStart,
				"hint":         "若刚部署/换 DB 路径,先查 nanotun-admin user list;典型场景见 K1 install-self-hosted.sh 检查",
			}).Error("[audit] login.fail.user_not_found 速率异常,疑似 DB 路径漂移 / 整库被清空")
			triggered = true
		}
	}
	b.count.Add(1)
	return
}

// initAuthBackend 在 main 中初始化 PSK store + verifier,挂到 gw 上。
//
// 失败时返回 error,main 中应 Fatal。返回的 cleanup 在进程退出时调用(关闭 sqlite)。
func initAuthBackend(ctx context.Context, gw *gatewayState) (cleanup func(), err error) {
	dbPath := gw.cfg.Store.DBPath
	if dbPath == "" {
		dbPath = "data/nanotun.db"
	}
	st, err := store.Open(ctx, dbPath, store.Options{})
	if err != nil {
		return nil, err
	}
	if err := st.Migrate(ctx); err != nil {
		_ = st.Close()
		return nil, err
	}
	gw.store = st
	gw.authVerifier = auth.NewVerifier(st)
	logrus.WithField("db_path", dbPath).Info("已启用 PSK 模式(自托管)")
	return func() { _ = st.Close() }, nil
}
