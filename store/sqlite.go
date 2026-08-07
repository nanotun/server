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

// lockedHint 给开库失败的错误加一句「谁占着、该怎么办」—— 只在确实是被占着时加。
//
// SQLite 对这种情形只说一句 "database is locked (5) (SQLITE_BUSY)":没提 nanotun,
// 没提该做什么,而它出现的场合几乎只有一种 —— 照着「恢复数据库」那几步做,却只停了两个
// 服务中的一个,然后把备份 cp 回去。没停的那个还开着库,于是:
//
//   - 另一个服务从此 crash-loop,日志里翻来覆去就这一句;
//   - 没停的那个仍然 active,正拿着一个被人从底下换掉字节的库继续服务,一声不吭;
//   - 连重跑安装脚本都救不回来 —— 它第 5 步的 nanotun-admin init 撞的是同一堵墙,
//     报的也是同一句没头没尾的话。
//
// 出路很简单(实测:把两个服务都停掉就恢复了,-wal/-shm 由 SQLite 自己收干净),
// 但从那句原始错误里一个字也读不出来。所以在这里说全。
func lockedHint(path, op string, err error) error {
	if !isLockedErr(err) {
		// 开库失败的另一大来源是盘满 —— 而它同样只报一句 "disk I/O error"。
		// 建库要落盘,所以这条路比 Migrate 那条更早撞上:全新机器上盘一满,
		// 连 ping 都过不去。
		return diskFullHint(path, fmt.Errorf("store: %s: %w", op, err))
	}
	return fmt.Errorf("store: %s: %w\n"+
		"  这个库正被另一个进程占着 —— 多半是 nanotun 或 nanotun-web 还在跑。\n"+
		"  恢复备份时两个服务都要停,只停一个就会是现在这样:\n"+
		"    systemctl stop nanotun nanotun-web\n"+
		"    cp <备份> %s && chmod 600 %s\n"+
		"    systemctl start nanotun nanotun-web\n"+
		"  已经在没停全的时候拷过一次了的话,照上面重做一遍:那个没停的进程手里是换之前的库,\n"+
		"  不重启它,两边的数据对不上。", op, err, path, path)
}

// isLockedErr 判断这个错误是不是「库被别人占着」。
//
// 认字符串而不是错误码:驱动是 modernc.org/sqlite 的纯 Go 实现,它把 SQLITE_BUSY 包在
// 自己的错误类型里,为了取一个错误码去引它的内部包,换来的耦合比这里省下的稳当性还多。
// 判错了的代价也只是少给一段提示 —— 原始错误照样原样带出去。
func isLockedErr(err error) bool {
	s := err.Error()
	return strings.Contains(s, "SQLITE_BUSY") || strings.Contains(s, "database is locked")
}

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
	// identity 是开库那一刻 path 上的 dev/ino,用于事后发现文件被掉包
	// (restore / 手工 cp 都是换 inode,本进程会继续写已被 unlink 的旧文件)。
	// identityOK=false 表示内存库或平台不支持,检测整体跳过。见 file_identity.go。
	identity   FileIdentity
	identityOK bool
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
		return nil, lockedHint(path, "ping", err)
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
			// journal_mode 是开库路上第一个要拿写锁的动作,于是「有别人占着这个库」
			// 一律在这里现形,而 SQLite 只会说一句 "database is locked (5)
			// (SQLITE_BUSY)" —— 一个没提到 nanotun、没提到该做什么的错误。
			//
			// 现实里撞上它几乎只有一种走法:照着「恢复数据库」那几步做,却只停了两个服务
			// 中的一个,然后把备份 cp 回去。没停的那个还开着库,于是另一个从此
			// crash-loop,日志里翻来覆去就是这一句。更糟的是没停的那个仍然 active ——
			// 它正拿着一个被人从底下换掉字节的库继续服务,而那一半一声不吭。
			//
			// 所以这里把话说全:谁占着、该怎么办。
			return nil, lockedHint(path, p, err)
		}
	}

	// WAL 模式下,首次 PRAGMA wal_autocheckpoint 已经触发了 -wal/-shm 文件创建。
	// 主 db 文件在 sql.Open 时若不存在也已创建。统一收紧到 0600,避免暴露 PSK hash。
	if path != ":memory:" {
		_ = os.Chmod(path, dbFileMode)
		_ = os.Chmod(path+"-wal", dbFileMode)
		_ = os.Chmod(path+"-shm", dbFileMode)
	}

	st := &Store{db: db, path: path}
	st.identity, st.identityOK = fileIdentityOf(path)
	return st, nil
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
