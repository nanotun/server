package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// User 表示一个 nanotun 本地账号。
//
// 0008(2026-05-23) 起，「固定 vIP」从 users 迁到 devices 表 —— 因为协议层
// device_uuid 强制 RFC 4122 v4,(user_id, device_uuid) 在 devices 表本来就 UNIQUE,
// 「这台设备每次拿同一个 vIP」是更自然的 fixed 语义。多设备用户的每台机器都可独立钉。
// 参见 store/devices.go::SetDeviceFixedVIP。
//
// BandwidthUpBPS / BandwidthDownBPS 单位为字节/秒（0 = 不限）。M0 仅落库。
//
// 0013(2026-05-25) 起,**profile / credentials 解耦**:
//   - CredentialID         UUID v4,user create 时分配,**之后稳定不变**;
//     client 按 UUID 索引,rotate-psk 后扫新 QR 自然覆盖旧 PSK。
//   - CredentialCreatedAt  每次 psk_hash 变化时刷新(unix epoch seconds, UTC);
//     客户端展示「上次 PSK 更新时间」。
//
// 老 user(0001 ~ 0012 创建)这两列为空字符串 / 0;首次 `credentials show` 命中后
// 由上层 lazy backfill。登录路径(auth/psk.go)**不读这两列**。
type User struct {
	ID               int64
	Username         string
	PSKHash          string
	IsAdmin          bool
	BandwidthUpBPS   int64
	BandwidthDownBPS int64
	ExitAllowed      bool
	// AllowedPlatforms 是「允许登录的平台白名单」,逗号分隔 canonical token
	// (macos/ios/android/windows/linux/router)。
	// **空串 = 不设限**:任何平台(含未上报 platform)均放行 —— 老 user(迁移只
	// ADD COLUMN,存量行 NULL→"")与默认新建 user 都走这条,与历史行为完全一致。
	// 非空则登录时按 User.AllowsPlatform 精确匹配,不命中 → CodePlatformNotAllowed(910)。
	AllowedPlatforms string
	// MaxSessions(0021):按账号的并发会话上限,与全局 [server].max_sessions_per_user
	// 两级叠加:0 = 跟随全局(默认);>0 = 覆盖全局(可更松或更紧);-1 = 该账号显式不限。
	// 生效值登录时定格,改动仅对未来登录生效(与全局热更同口径)。
	MaxSessions         int
	Role                string
	SSOProvider         string
	SSOSubject          string
	CreatedAt           int64
	DisabledAt          int64  // 0 = 未禁用
	CredentialID        string // "" = 老 user 待 backfill
	CredentialCreatedAt int64  // 0 = 老 user 待 backfill
}

// CanonicalPlatforms 是登录 platform 白名单里允许出现的合法 token,与各端实际上报
// 的 loginReq.Platform 逐字一致:
//   - macos   PacketTunnel(#if os != iOS)
//   - ios     PacketTunnel(#if os(iOS))
//   - android 客户端 VpnService
//   - windows / linux  Win/Linux GUI + CLI 走 std::env::consts::OS
//   - router  OpenWrt(uci::HARDCODED_PLATFORM)
//
// 白名单只接受这几个 token —— NormalizePlatformCSV 会拒绝拼写错误,避免管理员写了个
// 永远匹配不上的值把用户锁死在门外。
var CanonicalPlatforms = []string{"macos", "ios", "android", "windows", "linux", "router"}

// ExitCapablePlatforms:能真正跑出口节点(--exit-node:根权限/CAP_NET_ADMIN +
// nftables/系统 NAT)的平台。iOS / Android 只有用户态 VPN 隧道,不能做出口主机;
// OpenWrt 上报 token 是 router(见 CanonicalPlatforms 注释)。
//
// 给 web「一键指定出口」下拉 / designate 接口过滤用;空 platform / 未知值一律不当出口候选
// (宁可漏、不可误选手机进出口池)。
var ExitCapablePlatforms = []string{"linux", "windows", "macos", "router"}

// IsExitCapablePlatform 判定某 devices.platform 是否可指定为出口节点。
// 大小写不敏感;空串 / 未知 token → false。
func IsExitCapablePlatform(platform string) bool {
	p := strings.ToLower(strings.TrimSpace(platform))
	if p == "" {
		return false
	}
	for _, c := range ExitCapablePlatforms {
		if p == c {
			return true
		}
	}
	return false
}

// NormalizePlatformCSV 把管理员输入的平台列表归一成入库形态:
//   - 逗号分隔,逐项 TrimSpace + ToLower;
//   - 空输入 → 返回 ""(= 不设限,存 NULL);
//   - 每个 token 必须属于 CanonicalPlatforms,否则返回 ErrInvalid(附非法 token);
//   - 去重后按输入顺序拼回,保证「设了白名单」时至少有一个合法 token。
func NormalizePlatformCSV(input string) (string, error) {
	if strings.TrimSpace(input) == "" {
		return "", nil
	}
	seen := make(map[string]bool, len(CanonicalPlatforms))
	var out []string
	for _, raw := range strings.Split(input, ",") {
		tok := strings.ToLower(strings.TrimSpace(raw))
		if tok == "" {
			continue
		}
		valid := false
		for _, c := range CanonicalPlatforms {
			if tok == c {
				valid = true
				break
			}
		}
		if !valid {
			return "", fmt.Errorf("store: unknown platform %q (allowed: %s): %w",
				tok, strings.Join(CanonicalPlatforms, ","), ErrInvalid)
		}
		if !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	if len(out) == 0 {
		return "", nil
	}
	return strings.Join(out, ","), nil
}

// AllowsPlatform 判定该用户是否允许在 platform 登录。
//
// AllowedPlatforms 为空(未设白名单)= 不限:任何 platform(含客户端未上报的空串)
// 一律放行,与老用户 / 默认新建用户的历史行为一致。
//
// 非空则按逗号分隔 token 做大小写不敏感精确匹配;此时若 platform 为空 / 不在集合内
// → 返回 false(拒绝)。platform 为空的拒绝仅发生在「已设白名单」的前提下。
func (u *User) AllowsPlatform(platform string) bool {
	wl := strings.TrimSpace(u.AllowedPlatforms)
	if wl == "" {
		return true
	}
	p := strings.ToLower(strings.TrimSpace(platform))
	if p == "" {
		return false
	}
	for _, tok := range strings.Split(wl, ",") {
		if strings.ToLower(strings.TrimSpace(tok)) == p {
			return true
		}
	}
	return false
}

// NewUser 是创建用户时的输入。Username + PSKHash 必填，其它使用零值即可。
//
// CredentialID + CredentialCreatedAt 在 0013 之后建议**总是非空**传入(由
// cmd_user.go 用 google/uuid + time.Now 生成);留空时入库 NULL,等首次 credentials
// show 触发 backfill。
type NewUser struct {
	Username            string
	PSKHash             string
	IsAdmin             bool
	BandwidthUpBPS      int64
	BandwidthDownBPS    int64
	ExitAllowed         bool
	AllowedPlatforms    string // 见 User.AllowedPlatforms;空 = 不限
	Role                string
	SSOProvider         string
	SSOSubject          string
	CredentialID        string
	CredentialCreatedAt int64
}

// ErrNotFound 表示数据库中没有匹配的记录。所有 DAL 方法都会复用这个错误。
var ErrNotFound = errors.New("store: not found")

// ErrInvalid:DAL 写入参数明显非法(负数限速、空 UUID、非法 IP 等)的归一化哨兵。
// 仅给「明显是 caller bug 或 UI 表单未校验」的场景用;真正的 DB 错误仍 wrap 原始 err。
// 调用方:`errors.Is(err, store.ErrInvalid)` 区分「400 Bad Request」与「500」。
var ErrInvalid = errors.New("store: invalid argument")

// ErrAmbiguousDevice:仅按 device_uuid(跨 user)解析设备时命中**多行**(同一 UUID 分属不同 user)。
//
// 第六轮深扫 HIGH:device_uuid 只在 (user_id, device_uuid) 上复合 UNIQUE,不是全局唯一,且 UUID 由客户端
// 自报。FRP 端口转发运行时按 target_device_uuid 解析 vIP,若某低权用户注册一个与他人设备**同名**的 UUID
// 并保持更近活跃,旧的「取 last_seen_at 最近一条」会把本该投给受害设备的入站转发**静默改投**到攻击者 vIP
// (跨租户劫持)。改为命中多行即返回本错误 → 调用方 fail-closed(该转发不建立),把「劫持」降级为「拒绝服务」
// (需攻击者主动制造 UUID 碰撞,留有可审计痕迹)。彻底根治应把转发规则绑定到设备主键 / user(需迁移)。
var ErrAmbiguousDevice = errors.New("store: device uuid resolves to multiple users")

// ErrDuplicate 用于把 SQLite UNIQUE 约束冲突归一化为可用 errors.Is 判别的 sentinel。
// 之前所有 DAL 都用 `fmt.Errorf("...: %w", err)` 透传 modernc.org/sqlite 的 ErrConstraintUnique,
// 调用方只能字符串匹配 / 类型断言去识别,实际上没人做。结果是:
//   - admin CLI 上「重复 username」、「重复 device_uuid」分不清 vs 其它 DB 错误;
//   - 登录路径上 lease UNIQUE 冲突(同一 vIP 被分给两个设备)被 Warn 吞掉,
//     导致 alloc 路径双重占用却继续登录(数据面 IP 漂移)。
//
// 现在 DAL 在 INSERT/UPSERT 检测到 UNIQUE 冲突时统一返回 fmt.Errorf("...: %w", ErrDuplicate),
// 调用方用 errors.Is(err, store.ErrDuplicate) 即可分支处理。
var ErrDuplicate = errors.New("store: unique constraint violation")

// ErrSetupClosed:首位 web 管理员创建失败,因为 web_admins 表已非空(setup 已完成或被并发请求抢占)。
// CreateFirstWebAdmin 用它把「原子首建的竞争失败」与真正的 DB 错误区分开;handleSetup 收到即 302 /login。
var ErrSetupClosed = errors.New("store: web admin setup already completed")

// ErrLastAdmin:某个禁用 / 删除 / 降级操作会导致系统中不再有任何「enabled 且 role=admin」的账号(控制台
// 将无人可登录),被原子事务拒绝(第四轮深扫 HIGH)。此前上层 ensureNotLastAdmin 是「先 Count 后写」的
// check-then-act,两个并发请求可同时看到 count=2 各自放行 → 双双成功 → 归零。DisableWebAdminEnsuringAdmin /
// DeleteWebAdminEnsuringAdmin / SetWebAdminRoleEnsuringAdmin 在单个事务里「先写后验 floor,违则回滚」返回它。
var ErrLastAdmin = errors.New("store: refuse to leave zero enabled admins")

// CreateUser 创建一个新用户并返回其完整记录（含自增 ID）。
func (s *Store) CreateUser(ctx context.Context, in NewUser) (*User, error) {
	// 第四轮深扫 MED(store #4/#15):用户名首尾空白**入库前统一裁剪**。此前 " alice " 会原样入库,与 "alice"
	// 表面同名却被 BINARY UNIQUE 视作不同行 → 登录 / 展示歧义、可被用来伪装。裁剪 + 下方 NOCASE 预检共同收敛。
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" {
		return nil, errors.New("store: empty username")
	}
	if strings.TrimSpace(in.PSKHash) == "" {
		return nil, errors.New("store: empty psk_hash")
	}
	// 大小写不敏感去重(应用层预检):列上的 UNIQUE 是 BINARY(区分大小写),挡不住 "Alice" vs "alice"。这里
	// 先按 COLLATE NOCASE 查重,命中即 ErrDuplicate。残留极小 TOCTOU 窗口(两个并发创建仅大小写不同的同名)
	// 由管理端低并发场景与 BINARY UNIQUE 兜底,实际不构成问题;不引入 NOCASE 唯一索引迁移是为了避免既有部署里
	// 历史大小写变体用户名让启动期迁移直接失败(宁可应用层收敛,不冒 brick 风险)。
	if exists, err := s.usernameExistsCI(ctx, in.Username, 0); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("store: create user username=%q (case-insensitive match): %w", in.Username, ErrDuplicate)
	}
	// 第四轮深扫 MED(store #10):与 SetUserBandwidth 对齐,创建时也拒绝负带宽。此前 CreateUser 不校验,
	// 负值会入库,被 effectiveRate 等消费方按无符号 / 意外语义解读(潜在限速绕过或整型回绕)。
	if in.BandwidthUpBPS < 0 || in.BandwidthDownBPS < 0 {
		return nil, fmt.Errorf("store: bandwidth must be >= 0 (got up=%d down=%d): %w",
			in.BandwidthUpBPS, in.BandwidthDownBPS, ErrInvalid)
	}
	role := in.Role
	if role == "" {
		role = "user"
	}
	now := nowUnix()

	// credential_id 留空 → NULL(老路径兼容);非空 → 入库(0013 之后的新 user)。
	// credential_created_at 同理:0 → NULL,非 0 → 入库。两者通常成对填或都缺。
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users(
			username, psk_hash, is_admin,
			bandwidth_up_bps, bandwidth_down_bps,
			exit_allowed, allowed_platforms, role, sso_provider, sso_subject,
			created_at,
			credential_id, credential_created_at
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		in.Username, in.PSKHash, boolToInt(in.IsAdmin),
		in.BandwidthUpBPS, in.BandwidthDownBPS,
		boolToInt(in.ExitAllowed), nullableString(in.AllowedPlatforms), role,
		nullableString(in.SSOProvider), nullableString(in.SSOSubject),
		now,
		nullableString(in.CredentialID), nullableInt64(in.CredentialCreatedAt),
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return nil, fmt.Errorf("store: create user username=%q: %w", in.Username, ErrDuplicate)
		}
		return nil, fmt.Errorf("store: create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: last insert id: %w", err)
	}
	return s.GetUser(ctx, id)
}

// usernameExistsCI 判断是否已存在大小写不敏感同名的 user(排除 excludeID,用于 update 场景;create 传 0)。
func (s *Store) usernameExistsCI(ctx context.Context, username string, excludeID int64) (bool, error) {
	var dummy int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM users WHERE username = ? COLLATE NOCASE AND id != ? LIMIT 1`,
		username, excludeID).Scan(&dummy)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: username ci check: %w", err)
	}
	return true, nil
}

// GetUser 按主键取用户。
func (s *Store) GetUser(ctx context.Context, id int64) (*User, error) {
	return s.scanUserRow(s.db.QueryRowContext(ctx, userSelectSQL+` WHERE id=?`, id))
}

// GetUserByUsername 按用户名取用户。
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return s.scanUserRow(s.db.QueryRowContext(ctx, userSelectSQL+` WHERE username=?`, username))
}

// ListUsers 按 id 升序返回所有未禁用的用户。
//
// **不**包含 disabled_at != 0 的行。这是 admin 后台 / CLI 默认列表的语义:
// 「我现在能登录的用户」。运维要看「禁用账号但仍持有未清理凭证」走 ListUsersAll
// 或 credentials list(后者本身也包括 disabled,见 ListUsersWithCredentials)。
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, userSelectSQL+` WHERE disabled_at IS NULL OR disabled_at = 0 ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := s.scanUserCols(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ListUsersAll 按 id 升序返回**全部**用户,含已 disable 的行。
//
// P1#7(2026-05-26)新增:CLI `user list --all` / Web `?show_disabled=1` 用。
// 与 ListUsers 区别仅在于 WHERE 子句 — 不去重 / 不过滤,以便 admin 看到完整账号
// 历史。disabled_at 字段从 user.DisabledAt 取(0 = 未禁用),caller 自行决定如何展示
// (典型:「STATUS」列加「禁用」标记 + 行视觉降级)。
func (s *Store) ListUsersAll(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, userSelectSQL+` ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list users (all): %w", err)
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := s.scanUserCols(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ListUsersWithCredentials 返回所有已发过凭证(credential_id 非空 / 非空串)的用户,
// 按 credential_created_at DESC、id ASC 排序(最近 rotate 在前,稳定 tiebreak)。
//
// 与 ListUsers 不同的是**不**过滤 disabled —— 管理员在 admin CLI / web 后台审视
// 凭证总览时,「禁用账号但还持有 UUID」也得能看到,否则会出现「list 看不到 → 误以为
// 已清理 → 实际上 UUID + psk_hash 还在」的盲区。disabled_at 列由 caller 自行决定是否展示。
//
// 0013(2026-05-25)新增。给 nanotun-admin credentials list + 未来 web 管理后台
// 「凭证总览」页面复用 — 直接在 store 层走 WHERE credential_id IS NOT NULL,比
// 应用层 ListUsers + 客户端 filter 省一轮 row scan + 减小老 user 多的库的内存峰值。
func (s *Store) ListUsersWithCredentials(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx,
		userSelectSQL+
			` WHERE credential_id IS NOT NULL AND credential_id <> ''`+
			` ORDER BY COALESCE(credential_created_at,0) DESC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list users with credentials: %w", err)
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := s.scanUserCols(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// RotateUserPSK 更新指定用户的 PSK hash + credential_created_at(刷新「PSK 更新时间」),
// **保留 credential_id 不变** —— 这是 client 端「同 UUID 新 QR 覆盖旧 PSK」的核心承诺。
//
// 0013(2026-05-25)起替代旧的 [UpdateUserPSKHash]:每次 PSK 变化都必须刷 credential_created_at,
// 否则 client 看到 created_at 没变会误以为没换 PSK。
//
// createdAt 由 caller 传入(通常 time.Now().UTC().Unix());store 不偷偷读时钟,
// 便于测试注入与跨进程一致性。
//
// 第六轮 P1#2 + 第七轮深扫:生产 caller 已全部迁移到 [Store.RotateUserPSKCAS] 或
// 高层 [Store.RotateUserPSKAndEnsureCredential]。无 CAS 版仅保留给:
//   - 单元测试(显式准备 hash 状态);
//   - cmd/nanotund/user_invalidate_test.go 模拟 admin 已 rotate 之后的 invalidate 行为。
//
// 生产 caller 误用无 CAS 版,在并发 admin 场景会重现「双赢家无效 QR」bug。
//
// Deprecated: 第六轮起请用 [Store.RotateUserPSKCAS] 或 [Store.RotateUserPSKAndEnsureCredential]。
func (s *Store) RotateUserPSK(ctx context.Context, id int64, pskHash string, createdAt int64) error {
	if strings.TrimSpace(pskHash) == "" {
		return errors.New("store: empty psk_hash")
	}
	if createdAt <= 0 {
		return fmt.Errorf("store: invalid credential_created_at %d: %w", createdAt, ErrInvalid)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET psk_hash=?, credential_created_at=? WHERE id=?`,
		pskHash, createdAt, id)
	if err != nil {
		return fmt.Errorf("store: rotate psk: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RotateUserPSKCAS 是 [RotateUserPSK] 的乐观锁(Compare-And-Swap)版本:
//
//	UPDATE ... SET psk_hash=?, credential_created_at=?
//	  WHERE id=? AND psk_hash=?  -- 关键:expectedOldHash 守门
//
// 返回 wrote = true 表示 CAS 成功;false 表示 row 存在但 psk_hash 已被别人改写
// (caller 的 user snapshot 已过期 — stale view race)。第六轮深扫 P1#2 引入:
// 两个 admin 几乎同时 reset-psk 同一 user 时,各自 GetUser 都看到 old hash,然后
// 用本地新 PSK rotate。无 CAS 时**双双成功**,后写者的 hash 留在 DB,前写者却
// 拿本地 plain 渲染了一张「客户端扫了登不上」的 QR。
//
// CAS 让失败者立即知道 stale → 拒绝展示 QR → 提示「请刷新页面」。
//
// expectedOldHash 不能为空(空 hash 没业务意义,而且会让任何空 psk_hash 行通过守门)。
func (s *Store) RotateUserPSKCAS(ctx context.Context, id int64, pskHash, expectedOldHash string, createdAt int64) (wrote bool, err error) {
	if strings.TrimSpace(pskHash) == "" {
		return false, errors.New("store: empty psk_hash")
	}
	if strings.TrimSpace(expectedOldHash) == "" {
		return false, i18nErr("store.users.emptyExpectedHash", "store: empty expected_old_hash (CAS 必须有 base)")
	}
	if createdAt <= 0 {
		return false, fmt.Errorf("store: invalid credential_created_at %d: %w", createdAt, ErrInvalid)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET psk_hash=?, credential_created_at=? WHERE id=? AND psk_hash=?`,
		pskHash, createdAt, id, expectedOldHash)
	if err != nil {
		return false, fmt.Errorf("store: rotate psk (cas): %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// 0 行可能是「id 不存在」也可能是「expectedOldHash 不匹配」。靠 GetUser
		// 区分两者太重,这里直接返回 wrote=false / nil err,caller 通过 GetUser
		// 重读判断 row 还在不在。CLI/Web 路径已经先 GetUser 过 user 了,这条 race
		// 落点几乎一定是 hash mismatch(user 不太可能在 rotate 几毫秒内被 delete)。
		return false, nil
	}
	return true, nil
}

// BackfillUserCredentialID 给老 user(credential_id IS NULL)首次分配 credential_id。
//
// **幂等**:credential_id 已非空时不写,返回 (false, nil) —— 调用方可以放心反复调。
// 这是 [RotateUserPSK] 不动 credential_id 承诺的对偶:0013 之前的 user 在第一次
// `credentials show` 时由上层生成 UUID v4 + 当前时间,然后调本方法一次性补齐。
//
// 返回 wrote = true 表示真的写了(caller 需要 reread user 拿新值);false 表示
// row 早就有 credential_id(caller 沿用已读到的旧值即可)。
func (s *Store) BackfillUserCredentialID(ctx context.Context, id int64, credentialID string, createdAt int64) (wrote bool, err error) {
	if strings.TrimSpace(credentialID) == "" {
		return false, errors.New("store: empty credential_id")
	}
	if createdAt <= 0 {
		return false, fmt.Errorf("store: invalid credential_created_at %d: %w", createdAt, ErrInvalid)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE users
		    SET credential_id = ?, credential_created_at = ?
		  WHERE id = ?
		    AND (credential_id IS NULL OR credential_id = '')`,
		credentialID, createdAt, id)
	if err != nil {
		if isUniqueConstraintErr(err) {
			// 极罕见(UUID v4 碰撞);把它归一化让 caller 重生成。
			return false, fmt.Errorf("store: backfill credential_id %q: %w", credentialID, ErrDuplicate)
		}
		return false, fmt.Errorf("store: backfill credential_id: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetUserFixedVIP — **已删除**(2026-05-23 / 0008)。
// 现在改用 store.SetDeviceFixedVIP(deviceID, v4, v6)。理由见 User.struct 上方注释。
// 老调用方在迁移完成后直接编译失败,提示开发者切到 device 路径。

// SetUserBandwidth(0012, 2026-05-23):更新 users.bandwidth_up_bps / bandwidth_down_bps。
//
// 历史:M0 落库时没暴露 update 路径,user-level bandwidth 只能在 CreateUser 时一次性给。
// 0011 起 per-device 限速可以热改 + 推送,user-level 不能改导致语义不对称 ——
// 本方法补齐:CLI `user set-bandwidth` 调它,改完搭配 control sock /users/rate/refresh
// 让 active conn 立刻热更。
//
// 与 device.rate_*_bps 的关系:effectiveLinkRates 最终对全部层取 min,任一层缩窄
// 都会让 active conn 看到更严的 cap。
//
// 负数视为非法 → ErrInvalid。0 = 「不限」(语义与 device 层一致)。
func (s *Store) SetUserBandwidth(ctx context.Context, id, upBPS, downBPS int64) error {
	if upBPS < 0 || downBPS < 0 {
		return fmt.Errorf("store: bandwidth must be >= 0 (got up=%d down=%d): %w",
			upBPS, downBPS, ErrInvalid)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET bandwidth_up_bps=?, bandwidth_down_bps=? WHERE id=?`,
		upBPS, downBPS, id)
	if err != nil {
		return fmt.Errorf("store: set user bandwidth: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserAllowedPlatforms 更新用户的登录平台白名单(见 User.AllowedPlatforms)。
//
// csv 由 caller 先经 NormalizePlatformCSV 归一 / 校验:空串 = 清除白名单(存 NULL,
// 恢复「不设限」);非空则为逗号分隔的 canonical token。
//
// 与 ExitAllowed 不同,平台白名单提供**建号后可改**的入口(exit_allowed 目前只能建号
// 时设)。caller 不必管踢线:server 的 user_invalidate 周期扫描(默认 10s)会按
// Connection.platformAtLogin 快照自动 close(910) 掉不合规的在线会话,新登录则在
// authenticatePSK 里即时拦截 —— 改完 ≤ 一个扫描周期全量生效。
func (s *Store) SetUserAllowedPlatforms(ctx context.Context, id int64, csv string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET allowed_platforms=? WHERE id=?`,
		nullableString(csv), id)
	if err != nil {
		return fmt.Errorf("store: set user allowed_platforms: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MaxSessionsCap 是按账号 max_sessions 的合理上限。>此值的配置没有实际意义
// (等价不限,直接用 -1),却可能是输入手滑(如 999999999999);统一在 store 层拒绝,
// web / CLI 引用同一常量,两个入口口径一致。
const MaxSessionsCap = 10000

// SetUserMaxSessions 设置按账号的并发会话上限。
// n:0 = 跟随全局;1..MaxSessionsCap = 覆盖全局;-1 = 该账号显式不限。其余值拒绝。
// 仅对未来登录生效(登录时定格到 Connection),现役会话不回踢。
func (s *Store) SetUserMaxSessions(ctx context.Context, id int64, n int) error {
	if n < -1 || n > MaxSessionsCap {
		return fmt.Errorf("store: bad max_sessions %d (want -1 / 0 / 1..%d): %w", n, MaxSessionsCap, ErrInvalid)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET max_sessions=? WHERE id=?`, n, id)
	if err != nil {
		return fmt.Errorf("store: set user max_sessions: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// DisableUser 禁用一个用户（保留历史，但拒绝登录）。
func (s *Store) DisableUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET disabled_at=? WHERE id=?`, nowUnix(), id)
	if err != nil {
		return fmt.Errorf("store: disable user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnableUser 撤销 DisableUser，把 disabled_at 清回 NULL。
func (s *Store) EnableUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET disabled_at=NULL WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: enable user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser 物理删除一个用户。其下设备 / 租约 / ACL 通过 ON DELETE CASCADE 一并清理。
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: delete user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountUsers 返回 users 表行数（含已禁用）。
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

const userSelectSQL = `SELECT
	id, username, psk_hash, is_admin,
	bandwidth_up_bps, bandwidth_down_bps, exit_allowed,
	COALESCE(allowed_platforms,''), COALESCE(max_sessions,0),
	role, COALESCE(sso_provider,''), COALESCE(sso_subject,''),
	created_at, COALESCE(disabled_at,0),
	COALESCE(credential_id,''), COALESCE(credential_created_at,0)
FROM users`

// rowScanner 抽象 *sql.Row / *sql.Rows，便于复用 scan 代码。
type rowScanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanUserRow(row *sql.Row) (*User, error) {
	u, err := s.scanUserCols(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) scanUserCols(sc rowScanner) (*User, error) {
	var u User
	var isAdmin, exitAllowed int64
	if err := sc.Scan(
		&u.ID, &u.Username, &u.PSKHash, &isAdmin,
		&u.BandwidthUpBPS, &u.BandwidthDownBPS, &exitAllowed,
		&u.AllowedPlatforms, &u.MaxSessions,
		&u.Role, &u.SSOProvider, &u.SSOSubject,
		&u.CreatedAt, &u.DisabledAt,
		&u.CredentialID, &u.CredentialCreatedAt,
	); err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	u.ExitAllowed = exitAllowed != 0
	return &u, nil
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// nullableInt64 把 0 视作 NULL,便于把"未设置"语义透到 SQL NULL。
// 0013(2026-05-25)起 users.credential_created_at 用它,避免把 0 错存成有效时间戳。
func nullableInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// truncateUTF8 按 UTF-8 边界把 s 截到 ≤ maxBytes。
//
// 用于像 device_name 这种「客户端来的字符串」入库前的尺寸兜底。
// 截断时若末字符是多字节 UTF-8 的中间位置，会一路回退到完整字符边界，保证存进 DB
// 的串总是合法 UTF-8（不会被中间切坏出现 mojibake）。
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// 从 maxBytes 往前找到一个 UTF-8 字符起始字节（高 2 位不是 10xxxxxx）。
	for i := maxBytes; i > 0; i-- {
		b := s[i]
		// UTF-8 续字节高 2 位是 10；起始字节是 0xxxxxxx / 110xxxxx / 1110xxxx / 11110xxx。
		if b&0xC0 != 0x80 {
			return s[:i]
		}
	}
	return ""
}
