package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/nanotun/server/util"
)

// Device 表示一个客户端设备记录。
//
// (UserID, DeviceUUID) 唯一。客户端通过 LoginReq.device_uuid + device_name 上报，
// 同一 (user, uuid) 的重复登录沿用同一行并刷新 LastSeenAt。
//
// FixedVIPv4 / FixedVIPv6（0008 引入）：管理员钉死的「这台设备每次登录都用这个 vIP」,
// 与 leases.vip_v4 / vip_v6 共同遵守全局 UNIQUE 约束(也就是说同一 vIP 不能既被某
// device 钉为 fixed,又同时被另一 device 拿到 lease)。登录路径的 preferredLeasedVIPs
// 会优先返回这两个值,然后才是 leases 上一次的分配。
type Device struct {
	ID         int64
	UserID     int64
	DeviceUUID string
	// DeviceName:客户端每次登录上报的名字(一般是主机名),UpsertDevice 会覆盖刷新。
	// 管理端想改展示名用 Alias,不要动这个字段(改了下次登录也会被冲回去)。
	DeviceName string
	// Alias(0020, 2026-07-19):管理员起的别名,"" = 未设。登录路径不写此列,永不被
	// 客户端上报覆盖。展示/下发一律走 DisplayName()。MagicDNS 仍基于 DeviceName。
	Alias      string
	Platform   string
	FixedVIPv4 string
	FixedVIPv6 string
	// RateUploadBPS / RateDownloadBPS(0011, 2026-05-23):per-device 限速,字节/秒。
	// 0 = 沿用全局默认(app_settings.rate_default_*_bps,再回退 toml [server].upload_rate)。
	// 与 users.bandwidth_*_bps 取 min(0 当 +∞)。详见 server/effectiveLinkRates。
	RateUploadBPS   int64
	RateDownloadBPS int64
	LastSeenAt      int64
	CreatedAt       int64
}

// DisplayName:人眼展示名 —— 管理员设了别名用别名,否则回落客户端上报名。
// exits-list / routes-list 下发与 web 各页展示统一走这里。
func (d *Device) DisplayName() string {
	if a := strings.TrimSpace(d.Alias); a != "" {
		return a
	}
	return d.DeviceName
}

// DeviceAliasMaxLen:alias 列的应用层长度上限(字节),与 DeviceNameMaxLen 同宽。
const DeviceAliasMaxLen = 128

// DeviceNameMaxLen 是 devices.device_name 列的应用层长度上限（字节，不是 rune）。
//
// SQLite TEXT 没硬限，但我们在 store 层 truncate 一下，避免恶意客户端塞超大 device_name
// 撑爆 DB。128 字节够日常「Wenhai's MacBook Pro 16-inch (M3 Max)」类全文展示。
const DeviceNameMaxLen = 128

// UpsertDevice 创建或更新设备记录。
//
// 若 (user_id, device_uuid) 已存在，则更新 device_name / platform / last_seen_at；
// 否则创建新行并返回。无论哪条路径，返回的都是 device_uuid 持久化后的最终行。
//
// uuid 会被强制 trim + ToLower —— 历史上 Swift / Rust 客户端都已小写,但
// SQLite TEXT BINARY 比较是大小写敏感的,这里兜底归一,让同一物理设备无论
// 客户端用什么大小写写入,都落到同一行 (user_id, device_uuid)。
//
// name 超过 DeviceNameMaxLen 会被截断（按字节,不破 UTF-8 边界）。
//
// 实现走单语句 `INSERT ... ON CONFLICT(user_id,device_uuid) DO UPDATE`,而不是
// 之前的「BEGIN tx → SELECT → INSERT/UPDATE → COMMIT」两段式 —— 后者在跨进程
// 并发首次登录同一台设备时会出现 TOCTOU:两边 SELECT 都 ErrNoRows,两边 INSERT,
// 后到的撞 UNIQUE 直接报错,该客户端 device_id 拿不到,vIP 不持久化。
// ON CONFLICT 单语句让 SQLite 在持有行锁的事务里完成 insert-or-update,无 race。
func (s *Store) UpsertDevice(ctx context.Context, userID int64, uuid, name, platform string) (*Device, error) {
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	if uuid == "" {
		return nil, errors.New("store: empty device uuid")
	}
	name = truncateUTF8(name, DeviceNameMaxLen)
	now := nowUnix()

	// 每用户设备名唯一（Tailscale 式）：若归一后与该用户**其它**设备撞名，追加 "-1"/"-2"… 直到唯一。MagicDNS 主机名
	// （host.user.suffix / 4via6 站点归属）以设备名为标签，重名会导致解析到错误设备；在注册这唯一写入 chokepoint 去重。
	//
	// **去 TOCTOU**：去重 SELECT 与 upsert INSERT 之间的窗口不能靠连接池大小消除（池默认已放宽到 4，见 sqlite.go）——
	// 两个同 user、同 hostname、不同 uuid 的并发 UpsertDevice 会各自读到「无撞名」再双双写入裸名。用进程内
	// deviceUpsertMu 串行化整段（去重 + 事务写），窗口彻底消除，不依赖 MaxOpenConns=1。归一按 util.NormalizeMagicHost
	// （与解析端同口径）。注：跨进程只有守护进程走登录写设备，admin CLI 不在并发登录路径改设备名，故进程内锁足够。
	s.deviceUpsertMu.Lock()
	defer s.deviceUpsertMu.Unlock()

	// 去重读与写**分离**,而非同处一个事务(修第三轮深扫 M2):此前 BeginTx(默认 DEFERRED)先跑
	// dedupe SELECT 建立读快照、再 INSERT 升级为写,若期间任何其它连接(Audit/UpsertLease/TouchDevice…)
	// 提交,写升级会返回 SQLITE_BUSY_SNAPSHOT —— 这类错**不受 busy_timeout 重试**,导致 UpsertDevice
	// 偶发失败(admin CLI `device create` 无重试兜底,会裸报驱动错)。
	//
	// 现改为:整段仍在 deviceUpsertMu 临界区内(串行化并发登录 UpsertDevice,dedupe 的 TOCTOU 窗口依旧
	// 关闭),但 dedupe 用 s.db 直接读(不开事务),随后单条 `INSERT ... ON CONFLICT` 走 autocommit ——
	// 该写以「取写锁」起手(不持陈旧读快照),纯锁争用只会得到 SQLITE_BUSY(由 busy_timeout 重试),
	// 不会再出现 BUSY_SNAPSHOT。设备名去重是尽力而为,读用 s.db 与后续 INSERT 之间除并发 UpsertDevice
	// (已被锁挡住)外,只有极罕见的管理端改名可能插入,不在并发登录热路径,可接受。
	if uniqueName, derr := dedupeDeviceName(ctx, s.db, userID, uuid, name); derr == nil {
		name = uniqueName
	}
	// SQLite 3.24+ 的 UPSERT 语法:冲突时只 update 业务字段,id / created_at 保留。
	// modernc.org/sqlite 内置版本远高于 3.24,放心用。
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO devices(user_id, device_uuid, device_name, platform, last_seen_at, created_at)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(user_id, device_uuid) DO UPDATE SET
		   device_name = excluded.device_name,
		   platform    = excluded.platform,
		   last_seen_at= excluded.last_seen_at`,
		userID, uuid, name, platform, now, now,
	); err != nil {
		if isUniqueConstraintErr(err) {
			return nil, fmt.Errorf("store: upsert device user_id=%d uuid=%q: %w",
				userID, uuid, ErrDuplicate)
		}
		return nil, fmt.Errorf("store: upsert device: %w", err)
	}

	// 单独 SELECT 拿回行(包含可能与 excluded.* 不同的 id / created_at)。仍在 deviceUpsertMu 临界区内
	// (defer 到函数返回才解锁),同 (user_id, uuid) 的并发 UpsertDevice 被串行化,不会读到中间态;
	// 且 (user_id, device_uuid) UNIQUE 不会重复行。
	row := s.db.QueryRowContext(ctx,
		deviceSelectSQL+` WHERE user_id=? AND device_uuid=?`,
		userID, uuid,
	)
	d, err := s.scanDeviceCols(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// ctxRowQuerier 抽象 QueryContext,让 dedupeDeviceName 既能吃 *sql.DB(autocommit 读)也能吃 *sql.Tx。
type ctxRowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// dedupeDeviceName 为 (userID, uuid) 计算一个在该用户下**归一化唯一**的设备名（Tailscale 式的 "-N" 后缀）。
//
// 用调用方给的 querier(UpsertDevice 传 s.db,不再包在事务里 —— 见 M2 说明)。TOCTOU 串行化由
// UpsertDevice 持有的进程级 s.deviceUpsertMu 保证（见 UpsertDevice），因此「SELECT 与 INSERT 之间被并发
// UpsertDevice 插入 → 两台同名都拿裸名」的窗口被 mutex 关掉,与是否同事务无关。
//
// 归一按 util.NormalizeMagicHost（与 MagicDNS 主机名解析同口径），故消除的是「DNS 名」层面的冲突——
// "home pi" / "home-pi" / "home_pi" 归一后同名也算撞名。比较时**排除本 uuid 自身**（重连不与自己冲突）。
// 返回**原始大小写**的最终名（仅撞名时追加 "-N"）。空名（归一为空）不参与去重（无 magic 名，原样返回）。
// 出错（如查询失败）时由调用方回退用原名 —— 去重是尽力而为，绝不因此阻断设备注册/登录。
func dedupeDeviceName(ctx context.Context, q ctxRowQuerier, userID int64, uuid, requested string) (string, error) {
	if util.NormalizeMagicHost(requested) == "" {
		return requested, nil // 空/纯符号名无 magic 主机名，无需去重
	}
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	rows, err := q.QueryContext(ctx,
		`SELECT device_uuid, device_name FROM devices WHERE user_id=?`, userID)
	if err != nil {
		return requested, err
	}
	defer rows.Close()
	used := make(map[string]struct{})
	for rows.Next() {
		var du, dn string
		if err := rows.Scan(&du, &dn); err != nil {
			return requested, err
		}
		if strings.ToLower(strings.TrimSpace(du)) == uuid {
			continue // 排除自身（重连时本设备的旧名不算冲突）
		}
		used[util.NormalizeMagicHost(dn)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return requested, err
	}
	if _, clash := used[util.NormalizeMagicHost(requested)]; !clash {
		return requested, nil
	}
	for k := 1; k < 100000; k++ {
		cand := fmt.Sprintf("%s-%d", requested, k)
		if _, clash := used[util.NormalizeMagicHost(cand)]; !clash {
			return cand, nil
		}
	}
	return requested, nil // 理论到不了（同名逾 10 万台）：兜底返回原名，不阻断注册
}

// GetDevice 按主键取设备。
func (s *Store) GetDevice(ctx context.Context, id int64) (*Device, error) {
	row := s.db.QueryRowContext(ctx, deviceSelectSQL+` WHERE id=?`, id)
	d, err := s.scanDeviceCols(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// GetDeviceByUUID 按 (user_id, uuid) 取设备。找不到返回 ErrNotFound。
//
// uuid 在查询前会被 trim + ToLower —— 与 UpsertDevice 写入时的归一保持一致,
// 否则大小写不一致的客户端 / admin / 测试会查不到自己刚写入的行。
func (s *Store) GetDeviceByUUID(ctx context.Context, userID int64, uuid string) (*Device, error) {
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	row := s.db.QueryRowContext(ctx, deviceSelectSQL+` WHERE user_id=? AND device_uuid=?`, userID, uuid)
	d, err := s.scanDeviceCols(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// GetDeviceByUUIDAny 仅按 device_uuid 取设备（跨 user）。找不到返回 ErrNotFound。
//
// 与 GetDeviceByUUID 的区别：后者按 (user_id, uuid) 精确取；本方法给「只握有 UUID、
// 不知 user」的调用方用（如 FRP 端口转发按 target_device_uuid 运行时解析 vIP）。
// (user_id, device_uuid) 是复合 UNIQUE，同一 UUID 可分属不同 user（设备 UUID 全局唯一是客户端惯例、
// 非 schema 强制，且 UUID 由客户端自报）。
//
// 第六轮深扫 HIGH:此前命中多行时「取 last_seen_at 最近一条」——攻击者(低权 VPN 用户)注册一个与受害
// 设备同名的 UUID 并保持更近活跃,即可把本该投给受害设备的 FRP 入站转发静默改投到自己 vIP(跨租户劫持)。
// 现在**命中多行即 fail-closed** 返回 ErrAmbiguousDevice —— 调用方(port_forward.resolveDeviceID /
// vIP 解析)按 err 直接放弃建立该转发。碰撞由「劫持」降级为「拒绝服务」(且需主动制造碰撞,可审计)。
// 用 LIMIT 2 判歧义:0 行→ErrNotFound;1 行→正常返回;≥2 行→ErrAmbiguousDevice。
func (s *Store) GetDeviceByUUIDAny(ctx context.Context, uuid string) (*Device, error) {
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	rows, err := s.db.QueryContext(ctx,
		deviceSelectSQL+` WHERE device_uuid=? ORDER BY last_seen_at DESC, id DESC LIMIT 2`, uuid)
	if err != nil {
		return nil, fmt.Errorf("store: get device by uuid any: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("store: get device by uuid any: %w", err)
		}
		return nil, ErrNotFound
	}
	d, err := s.scanDeviceCols(rows)
	if err != nil {
		return nil, err
	}
	if rows.Next() {
		// 同一 UUID 命中第二行 = 跨 user 碰撞 → 拒绝解析(fail-closed)。
		return nil, ErrAmbiguousDevice
	}
	return d, rows.Err()
}

// ListDevicesByUser 返回指定用户名下的全部设备，按 last_seen_at 倒序。
func (s *Store) ListDevicesByUser(ctx context.Context, userID int64) ([]*Device, error) {
	rows, err := s.db.QueryContext(ctx, deviceSelectSQL+` WHERE user_id=? ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list devices: %w", err)
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := s.scanDeviceCols(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// TouchDevice 仅刷新 last_seen_at（每次登录连接时调用）。
func (s *Store) TouchDevice(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen_at=? WHERE id=?`, nowUnix(), id)
	if err != nil {
		return fmt.Errorf("store: touch device: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// E1(2026-05-22):BatchTouchDevices 批量刷新 last_seen_at。
// lease_gc 跑前用这个把所有 active session 持有的 device 一次性顶上时间戳,避免
// 长会话(>30 天)期间的 vIP 被误回收。空 ids 直接 noop。
//
// 用 IN(...) 拼参数。第四轮深扫 MED:SQLite 的 host 参数上限(SQLITE_MAX_VARIABLE_NUMBER,老构建可能低至
// 999)不保证到 32k,超大 session 集会让整条 UPDATE 直接失败(整批 touch 丢失 → 长会话 vIP 被误 GC)。
// 改为分块(每块 batchTouchChunk 个 id),各块独立 UPDATE,规避变量上限;失败即返回。
func (s *Store) BatchTouchDevices(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	now := nowUnix()
	const batchTouchChunk = 500 // 远低于任何 SQLite 变量上限,单条 UPDATE(+1 个时间戳参数)始终安全
	for start := 0; start < len(ids); start += batchTouchChunk {
		end := start + batchTouchChunk
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		q := `UPDATE devices SET last_seen_at=? WHERE id IN (?` + strings.Repeat(`,?`, len(chunk)-1) + `)`
		args := make([]any, 0, len(chunk)+1)
		args = append(args, now)
		for _, id := range chunk {
			args = append(args, id)
		}
		if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("store: batch touch devices: %w", err)
		}
	}
	return nil
}

// DeleteDevice 删除设备（其租约通过 CASCADE 一起清掉）。
func (s *Store) DeleteDevice(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store: delete device: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// deviceSelectSQL 包含 0011 起的 rate_upload_bps / rate_download_bps。
// COALESCE 用 0 兜底:历史行经 ALTER TABLE 已带 NOT NULL DEFAULT 0,
// 这里冗余一层是为了即便未来迁移过程中残留 NULL 也不让 Scan 炸 int64 zero。
const deviceSelectSQL = `SELECT id, user_id, device_uuid, device_name, COALESCE(alias,''), platform,
	COALESCE(fixed_vip_v4,''), COALESCE(fixed_vip_v6,''),
	COALESCE(rate_upload_bps,0), COALESCE(rate_download_bps,0),
	last_seen_at, created_at
FROM devices`

func (s *Store) scanDeviceCols(sc rowScanner) (*Device, error) {
	var d Device
	if err := sc.Scan(
		&d.ID, &d.UserID, &d.DeviceUUID, &d.DeviceName, &d.Alias, &d.Platform,
		&d.FixedVIPv4, &d.FixedVIPv6,
		&d.RateUploadBPS, &d.RateDownloadBPS,
		&d.LastSeenAt, &d.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &d, nil
}

// SetDeviceAlias 设置/清除设备别名(空串 = 清除,展示回落客户端上报名)。
// 登录路径的 UpsertDevice 不触碰 alias 列,故别名一经设置不会被上报名覆盖。
func (s *Store) SetDeviceAlias(ctx context.Context, id int64, alias string) error {
	alias = truncateUTF8(strings.TrimSpace(alias), DeviceAliasMaxLen)
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET alias=? WHERE id=?`, alias, id)
	if err != nil {
		return fmt.Errorf("store: set device alias: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDeviceFixedVIP 修改 device 的固定 vIP(v4 / v6)。空字符串表示清除。
//
// 唯一性保证的**准确**范围(深扫第八轮 LOW 勘误):devices 表上的 UNIQUE 索引只保证
// fixed_vip_v4 / fixed_vip_v6 在 **devices↔devices** 之间不重复,撞到时返回
// fmt.Errorf("...: %w", ErrDuplicate),调用方通常把提示渲染回表单而非直接 500。
//
// 它**不**跨表约束到 leases:另一台设备**动态分配**到的 lease vIP(leases.vip_v4/v6)
// 与这里要钉的 fixed vIP 落在同一地址时,本 UNIQUE 索引查不到。这层 devices↔leases 的
// 冲突检查在应用层完成(web: checkFixedVIPConflict / CLI: findFixedVIPConflict,均扫描
// devices + leases 两张表),而 CLI 的 --force 会**跳过**该预检 —— 详见 cmd_device.go,
// 强推时调用方需自行承担 vIP 撞车后果(下次分配可能撞库/双分配)。
//
// 注意:这里**不**会去校验 fixed_vip 是否落在 server 的 vIP 网段内 — 那是 server
// 启动配置才知道的事;store 层语义只是「持久化」,网段校验由 server/admin/web 在
// 调用前做(参见 cmd/nanotund/alloc_lease.go::sameSubnet)。
//
// 2026-05-23:同步刷新该设备 leases 行的 manual 标记。
//
// 历史问题:fixed_vip 改了之后,leases.manual 仍然是 device 上次登录时 alloc_lease
// 路径写入的旧值。后果有二:
//
//	(1) UI 上 leases 列表展示 manual=✗ 与「已绑定 fixed vIP」语义不一致;
//	(2) lease_gc 用 manual=0 作为可回收条件,有可能误把这条「已被钉死」的 lease
//	    回收 — 虽然 alloc_lease 下次登录会再补上,但 GC 窗口里 vIP 短暂空缺,
//	    不优雅。
//
// 修法:本函数在 UPDATE devices 之后,顺手 UPDATE 这个 device 的 lease(如存在)的
// manual 字段。逻辑:
//   - lease.vip_v4 == new fixed_v4 (或 v6) → manual = 1
//   - 否则 manual = 0
//
// 用一个语句完成,避免事务复杂度;两个 UPDATE 之间发生进程崩溃的情况下,数据
// 不一致仅停留到该设备下次登录,可以接受。
// force(第四轮深扫修正):admin 显式覆盖。false 时下面的跨表守卫命中即回滚成 ErrDuplicate;
// true 时**不是无脑忽略冲突**(那会重新制造双占黑洞),而是在同一事务里先把**其它设备**动态
// lease 上占用该地址的 vip 释放(置 NULL,被夺设备下次登录 alloc_lease 会另分配),消除双占后再钉。
// CLI `--force` / exit designate `--force` 走 true,web(无 force,冲突时 409 前置拦截)与其它
// 内部调用走 false。
func (s *Store) SetDeviceFixedVIP(ctx context.Context, id int64, fixedV4, fixedV6 string, force bool) error {
	// **事务包住两条 UPDATE**:devices.fixed_vip_* 与 leases.manual 必须同生同死。此前是两条独立
	// ExecContext——若 devices 更新成功、leases 同步失败(锁 / IO),会留下「fixed_vip 已设但 leases.manual=0」
	// 的错位:GC 会把这个手钉 vIP 的 lease 当空闲回收,下次登录该设备可能拿不回固定地址(前一句注释说的
	// 「主语义已成功」其实掩盖了这个不一致)。放进一个 tx 里,任一失败整体回滚,fixed_vip 与 manual 保持一致。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: set fixed vip begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`UPDATE devices SET fixed_vip_v4=?, fixed_vip_v6=? WHERE id=?`,
		nullableString(fixedV4), nullableString(fixedV6), id,
	)
	if err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("store: set fixed vip device_id=%d v4=%q v6=%q: %w",
				id, fixedV4, fixedV6, ErrDuplicate)
		}
		return fmt.Errorf("store: set fixed vip: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}

	// 跨表守卫(第四轮深扫 HIGH):devices 上的 UNIQUE 索引只挡 device↔device 的 fixed_vip 撞车(上面的 UPDATE
	// 会直接抛 UNIQUE);它挡不住「**另一台**设备的动态 lease 正好占了这个要钉的地址」。若不查,fixed_vip 与他设备
	// lease 双占同一 vIP → 路由黑洞。
	if fixedV4 != "" || fixedV6 != "" {
		if force {
			// admin 显式 --force:先释放**其它设备**动态 lease 上占用该地址的 vip(置 NULL),消除跨表双占后再钉。
			// vip_v4/vip_v6 为 NULL 时不参与比较(SQL NULL 语义),故空 fixed 族天然是 no-op。
			if _, rerr := tx.ExecContext(ctx,
				`UPDATE leases
				    SET vip_v4 = CASE WHEN vip_v4 = ? THEN NULL ELSE vip_v4 END,
				        vip_v6 = CASE WHEN vip_v6 = ? THEN NULL ELSE vip_v6 END
				  WHERE device_id != ?
				    AND ( vip_v4 = ? OR vip_v6 = ? )`,
				nullableString(fixedV4), nullableString(fixedV6), id,
				nullableString(fixedV4), nullableString(fixedV6),
			); rerr != nil {
				return fmt.Errorf("store: set fixed vip force-release conflicting leases device_id=%d: %w", id, rerr)
			}
		} else {
			// 写后校验:另一 device 的 lease 持有该地址则回滚成 ErrDuplicate。
			var dummy int
			qerr := tx.QueryRowContext(ctx,
				`SELECT 1 FROM leases
				  WHERE device_id != ?
				    AND ( (vip_v4 IS NOT NULL AND vip_v4 = ?)
				       OR (vip_v6 IS NOT NULL AND vip_v6 = ?) )
				  LIMIT 1`,
				id, nullableString(fixedV4), nullableString(fixedV6)).Scan(&dummy)
			if qerr == nil {
				return fmt.Errorf("store: set fixed vip device_id=%d v4=%q v6=%q conflicts with another device lease: %w",
					id, fixedV4, fixedV6, ErrDuplicate)
			} else if !errors.Is(qerr, sql.ErrNoRows) {
				return fmt.Errorf("store: set fixed vip cross-table check: %w", qerr)
			}
		}
	}

	// 同步该 device 的 lease(第四轮深扫 MED,store #6 一并修):
	//   - 非空 fixed_vip 族:把 lease 的对应 vip **搬到** fixed 值 —— 否则旧的动态 vip 会与新 fixed 同时被
	//     AllUsedVIPs 计为「已用」,该设备白占两个地址直到下次登录 / GC;搬过来后旧地址立即释放。
	//   - 空 fixed_vip 族:保留 lease 里既有的动态 vip(ELSE 分支不动)。
	//   - manual:任一 fixed 非空即 1(手钉,GC 不回收),否则 0。
	// lease 行可能不存在(device 没登录过)→ UPDATE 影响 0 行不算错,下次登录 alloc_lease 会按 fixed 建。
	if _, err := tx.ExecContext(ctx,
		`UPDATE leases
		    SET vip_v4 = CASE WHEN ? <> '' THEN ? ELSE vip_v4 END,
		        vip_v6 = CASE WHEN ? <> '' THEN ? ELSE vip_v6 END,
		        manual = CASE WHEN (? <> '' OR ? <> '') THEN 1 ELSE 0 END
		  WHERE device_id=?`,
		fixedV4, fixedV4, fixedV6, fixedV6, fixedV4, fixedV6, id,
	); err != nil {
		if isUniqueConstraintErr(err) {
			return fmt.Errorf("store: set fixed vip lease move device_id=%d: %w", id, ErrDuplicate)
		}
		return fmt.Errorf("store: sync lease after fixed_vip: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: set fixed vip commit: %w", err)
	}
	return nil
}

// SetDeviceRateLimit(0011, 2026-05-23):per-device 带宽限速,字节/秒。
//
// 语义:
//   - upBPS / downBPS == 0 → 该方向跟随全局默认(app_settings.rate_default_*_bps,
//     再回退 toml [server].upload_rate / download_rate);
//   - >0 → 该 device 该方向硬 cap,与 user.bandwidth_*_bps 仍按 min(0=+∞) 取严。
//
// 持久化即返回;**热更**(同步给 active conn 的 rate.Limiter)走 control socket
// /rate/refresh-device,本函数不耦合 server 进程状态。
//
// 负数视为非法,直接 error;不做 silent clamp,避免上层 form 解析负号当成「重置为 0」
// 的歧义(0 才是「重置」)。
func (s *Store) SetDeviceRateLimit(ctx context.Context, id int64, upBPS, downBPS int64) error {
	if upBPS < 0 || downBPS < 0 {
		return fmt.Errorf("store: rate limit must be >= 0 (got up=%d down=%d): %w",
			upBPS, downBPS, ErrInvalid)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE devices SET rate_upload_bps=?, rate_download_bps=? WHERE id=?`,
		upBPS, downBPS, id,
	)
	if err != nil {
		return fmt.Errorf("store: set device rate: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAllDevices 返回全表 devices,按 user_id, last_seen_at DESC 排序。
// Web 后台 /devices 列表用。M0/M1 设备总量百千级,SELECT * 没问题。
func (s *Store) ListAllDevices(ctx context.Context) ([]*Device, error) {
	rows, err := s.db.QueryContext(ctx, deviceSelectSQL+` ORDER BY user_id ASC, last_seen_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list all devices: %w", err)
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := s.scanDeviceCols(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
