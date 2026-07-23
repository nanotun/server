// Package store 提供 nanotun 的本地状态持久化（SQLite）。
//
// 设计目标：
//  1. 让 nanotun 在 PSK 模式下具备自包含状态：用户、设备、vIP 租约、ACL 等。
//  2. 表结构为后续企业版 / 多管理员 / 审计 / SSO 留位（详见 migrations/0001_init.sql）。
//  3. 走 modernc.org/sqlite 纯 Go 驱动，保持 nanotun 二进制无 CGO 依赖。
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store 封装一个 SQLite 连接池。所有 DAL 方法都挂在 *Store 上。
type Store struct {
	db *sql.DB
	// path 仅供日志/诊断使用，可能是 ":memory:"。
	path string
	// mu 保护 Migrate 等串行操作，避免多个调用者同时执行。
	mu sync.Mutex
	// deviceUpsertMu 串行化 UpsertDevice 的「设备名去重 SELECT + upsert INSERT」临界区。
	// 历史实现靠 MaxOpenConns=1 隐式串行，但连接池默认已放宽到 4（见 sqlite.go Open）：
	// 多连接下两个同 user、同 hostname、不同 uuid 的并发 UpsertDevice 会在各自连接上
	// 先跑完去重 SELECT 再 INSERT，双双漏判撞名（MagicDNS 标签重复 / 或后写方撞
	// SQLITE_BUSY_SNAPSHOT 登录失败）。用进程内锁把该临界区显式串行化，不再依赖池大小。
	deviceUpsertMu sync.Mutex
}

// Options 用于配置 Store 行为。零值合理。
type Options struct {
	// BusyTimeout 是 SQLite busy 等待时长。默认 5s。
	BusyTimeout time.Duration

	// MaxOpenConns 控制 *sql.DB 连接池上限。
	//
	// SQLite WAL 模式下「多读单写」是原生支持的:写者拿独占锁,读者拿共享锁,
	// 互不阻塞。把 MaxOpenConns 设成 1(老默认)等于把所有 read/write 串行化,
	// 让 admin CLI 一次 `device list`(扫 users+devices+leases 三表 join)就能阻塞
	// 登录路径上的 audit/lease 写入到 5s busy_timeout。
	//
	// <= 0  → 默认 4:每条写串行,但同时允许 3 条只读并行(LoginVerify 拉 user、
	//          audit list、health probe 互不阻塞);Connection 上限按 modernc.org/sqlite
	//          建议 ≤ 16,4 在小机型上 RAM 友好且足够 saturate 写。
	// 1     → 老行为,留给特定测试场景显式声明。
	MaxOpenConns int

	// ReadOnly 为 true 时启动 `PRAGMA query_only = ON`,任何写 SQL 都会被 SQLite
	// 拒绝(SQLITE_READONLY)。专给 admin CLI 的"看"操作用 —— 即便实现误调了
	// CreateUser / Audit 之类的写路径,也会立刻报错而不是写穿生产 DB。
	//
	// 写路径(server / admin 写命令)保持 false。
	ReadOnly bool
}

// dbFileMode 是 *.db / *.db-wal / *.db-shm 文件的目标权限。
//
// SQLite 通过普通 open(2) 系统调用创建文件,默认 mode 受当前 umask 影响,
// root 跑 server 时通常落到 0644(group/other 可读)。但本库存有 PSK Argon2id
// hash、salt 与设备/lease/ACL 全量信息,即使 hash 不可反推 PSK,也不应让
// 同机其他账户随便读取。Open 后 chmod 一遍兜底,WAL/SHM 由 SQLite 在
// 首次写时创建,我们启用 WAL 后主动 ping 触发它们,再统一 chmod。
const dbFileMode os.FileMode = 0o600

// dbDirMode 是 DB 目录的目标权限,与 dbFileMode 一致(只让 owner 进入)。
const dbDirMode os.FileMode = 0o700

// Open 打开/创建一个 SQLite 数据库文件。path 为 ":memory:" 时使用纯内存数据库（测试用）。
//
// 调用方负责在停止时调用 (*Store).Close。
func Open(ctx context.Context, path string, opts Options) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: empty path")
	}
	if path != ":memory:" {
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, dbDirMode); err != nil {
				return nil, fmt.Errorf("store: mkdir %s: %w", dir, err)
			}
			// 已经存在但权限过松的目录也收紧一下(忽略错误,容忍非 root 路径)。
			_ = os.Chmod(dir, dbDirMode)
		}
	}

	busy := opts.BusyTimeout
	if busy <= 0 {
		busy = 5 * time.Second
	}

	// modernc.org/sqlite 支持 `?_pragma=...` 在 DSN 内启用 PRAGMA;**每条**新建
	// connection 都会自动应用,这是 SetMaxOpenConns>1 下保证 connection-level
	// pragma 一致性的唯一可靠路径(用 ExecContext 跑只会作用在 *本条* conn 上,
	// 池里后续新建的连接不会带上)。
	//
	// 这里放的全是 connection-level pragma:
	//   - busy_timeout:每条 conn 各自的 SQLITE_BUSY 等待窗口;
	//   - foreign_keys:cascade 删除依赖,每条 conn 必须 ON;
	//   - synchronous:见下方注释,per-connection,必须每条 conn 都设;
	//   - query_only(ReadOnly):admin 只读模式守门,误写直接 SQLITE_READONLY。
	// 真正 db-wide(写进库文件、一次即对所有 conn 生效)的只有 journal_mode=WAL,
	// 仍在 Open 后 ExecContext 跑;wal_autocheckpoint 显式声明默认值(1000),同样 Exec。
	dsn := path
	if path == ":memory:" {
		// 共享内存，便于测试中跨连接复用（modernc 需要这种 cache=shared 形式）。
		dsn = "file::memory:?cache=shared"
	}
	connPragmas := []string{
		fmt.Sprintf("busy_timeout(%d)", busy.Milliseconds()),
		"foreign_keys(1)",
		// 第八轮深扫 MED:synchronous 是 **per-connection** pragma(不像 journal_mode=WAL 会持久化进库文件)。
		// 此前用 ExecContext 跑 `PRAGMA synchronous=NORMAL` 只作用于池里那**一条** conn,其余(MaxOpenConns 默认 4)
		// 新建时回落 SQLite 默认 FULL —— 热写路径(audit / lease)白白多一次 fsync,悄悄抵消 WAL 调优。挪进 DSN
		// `_pragma=` 列表,让**每条**新建连接都是 NORMAL(1)。WAL 下 NORMAL 仍是崩溃安全的(仅极端断电可能丢
		// 最后若干已提交事务,不损坏库),对本网关的持久化要求足够。
		"synchronous(1)",
	}
	if opts.ReadOnly {
		connPragmas = append(connPragmas, "query_only(1)")
	}
	for _, p := range connPragmas {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn = dsn + sep + "_pragma=" + p
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// WAL 模式下「多读单写」原生支持(读拿共享锁,写拿独占锁,互不阻塞)。
	// 4 = 1 写 + 3 读并行的常见配置:让 admin CLI 的长读 query 不再卡 server
	// 路径上的 audit / lease 写入。仍保持 SQLite 写串行,不破坏一致性。
	// 详见 Options.MaxOpenConns。
	maxOpen := opts.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 4
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxOpen)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	// db-wide pragma:只跑一次即对整个数据库文件生效,后续新 conn 拿到的就是
	// 升级后的状态。connection-level pragma 已经在 DSN 里注入,见上方 dsn 拼装。
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		// synchronous 已移至 DSN `_pragma=synchronous(1)`(per-connection,见上方 connPragmas 注释)。
		// 默认 1000 pages (~4MB);PSK 网关写入少,这里保持默认但显式声明,
		// 防止以后改 page_size 后人忘了同步。长跑下若 -wal 仍膨胀,可调到 256~512。
		"PRAGMA wal_autocheckpoint = 1000",
	}
	for _, p := range pragmas {
		if _, err := db.ExecContext(ctx, p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: %s: %w", p, err)
		}
	}

	// WAL 模式下,首次 PRAGMA wal_autocheckpoint 已经触发了 -wal/-shm 文件创建。
	// 主 db 文件在 sql.Open 时若不存在也已创建。统一收紧到 0600,避免暴露 PSK hash。
	if path != ":memory:" {
		_ = os.Chmod(path, dbFileMode)
		_ = os.Chmod(path+"-wal", dbFileMode)
		_ = os.Chmod(path+"-shm", dbFileMode)
	}

	return &Store{db: db, path: path}, nil
}

// DB 返回底层 *sql.DB（仅供需要直接执行 SQL 的高级用例）。
func (s *Store) DB() *sql.DB { return s.db }

// Path 返回打开时使用的文件路径，用于日志。
func (s *Store) Path() string { return s.path }

// Close 关闭底层连接。
//
// 关闭前主动跑一遍 `PRAGMA wal_checkpoint(TRUNCATE)`,把 -wal 内容合并回主库并清空。
// 这样:
//  1. 备份场景只需要拷 *.db 单文件就能拿到一致快照(否则要同步 *.db + *.db-wal + *.db-shm 三件套);
//  2. systemd kill -9 / panic 出场不会留下 GB 级 -wal;
//  3. 下次启动 ReadOnly 工具直接看主库就是最新数据。
//
// checkpoint 失败不阻塞 Close(写时若 busy 也只是 wal 继续保留,无数据丢失风险)。
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	if s.path != ":memory:" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			// 已经在退出路径上,不让 checkpoint 失败掩盖 db.Close 的 error。
			// 上层一般也只是 log 一下。
			_ = err
		}
		cancel()
	}
	return s.db.Close()
}

// nowUnix 用统一时间戳，便于测试 mock。
var nowUnix = func() int64 { return time.Now().Unix() }
