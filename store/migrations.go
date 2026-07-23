package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate 顺序执行 migrations/ 目录下编号严格递增的 .sql 文件。
//
// 文件名约定：NNNN_<slug>.sql，NNNN 是 4 位起的整数，按数值升序执行。
// 已执行版本号记录在 app_settings.schema_version。重复运行幂等。
//
// I8: 跨进程互斥。Migrate 现在用 <db>.migrate.lock 上 flock(LOCK_EX) 串行化跨
// 进程并发(vpn-server + nanotun-admin 同时启动时尤其重要),内存库 / 空 path
// 自动 noop;Windows 上退化为单进程 sync.Mutex 行为(详见 migrate_lock_other.go)。
func (s *Store) Migrate(ctx context.Context) error {
	unlock, err := acquireMigrateLock(s.path)
	if err != nil {
		return err
	}
	defer unlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureSettingsTable(ctx); err != nil {
		return err
	}

	current, err := s.currentSchemaVersion(ctx)
	if err != nil {
		return err
	}

	files, err := listMigrations()
	if err != nil {
		return err
	}

	for _, m := range files {
		if m.version <= current {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + m.name)
		if err != nil {
			return fmt.Errorf("store: read migration %s: %w", m.name, err)
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin tx for %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: exec migration %s: %w", m.name, err)
		}
		// 写回 schema_version
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO app_settings(key,value) VALUES('schema_version',?)
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			strconv.Itoa(m.version),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: write schema_version for %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit %s: %w", m.name, err)
		}
	}

	// 运行时初始化 hook:Migration 之后兜底确保 `server_id` 已生成。
	//
	// 为什么不放进 SQL migration 文件?UUID v4 必须 Go 端生成,纯 SQL 没法做到
	// "首次落库随机 UUID,后续幂等"。这里用 Go hook 模拟「DEFAULT uuid_generate_v4()」
	// 语义:每个跑过 Migrate 的进程都触发一次 ensureServerID,first-writer-wins。
	//
	// 失败只 wrap 成 error 返回(让 Migrate 自身的 caller 决定 fatal / warn) —
	// 实务里只有写权限丢失才会失败,那时整个 schema 已经丢一半,这里 fail 也合理。
	if _, err := s.ensureServerID(ctx); err != nil {
		return fmt.Errorf("store: ensure server_id after migrate: %w", err)
	}
	return nil
}

// ensureSettingsTable 在 schema_version 还没记录时也能让首条 migration 顺利运行。
// app_settings 本身就在 0001_init.sql 里建出来；这里仅是兜底，避免 currentSchemaVersion
// 在尚未迁移过的库上炸 "no such table"。
func (s *Store) ensureSettingsTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS app_settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("store: create app_settings: %w", err)
	}
	return nil
}

func (s *Store) currentSchemaVersion(ctx context.Context) (int, error) {
	row := s.db.QueryRowContext(ctx, `SELECT value FROM app_settings WHERE key='schema_version'`)
	var v string
	if err := row.Scan(&v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 行不存在(全新库)视为 0。
			return 0, nil
		}
		// 真错误(I/O / ctx 取消)必须上报:若误当成 0,migration runner 会把
		// 非幂等的历史 migration 重跑一遍,破坏已有 schema。
		return 0, fmt.Errorf("store: read schema_version: %w", err)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("store: bad schema_version %q: %w", v, err)
	}
	return n, nil
}

type migrationFile struct {
	version int
	name    string
}

func listMigrations() ([]migrationFile, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations dir: %w", err)
	}
	var out []migrationFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		// 跳过 macOS resource fork（"._xxx.sql"）。本仓 source tree 不会有这种文件,
		// 但如果通过 macOS tar / zip 传输时带了 com.apple.provenance 等 xattr,
		// 元数据会以 `._0001_init.sql` 形式落到 migrations/ 目录,然后被
		// `//go:embed migrations/*.sql` 当成真 migration 拉进 binary,启动时
		// `strconv.Atoi("._0001")` 直接 fatal。这里 defensive 兜底,让任何打包
		// 路径都不会让服务起不来。
		if strings.HasPrefix(e.Name(), "._") {
			continue
		}
		idx := strings.IndexByte(e.Name(), '_')
		if idx <= 0 {
			return nil, fmt.Errorf("store: invalid migration name %q", e.Name())
		}
		v, err := strconv.Atoi(e.Name()[:idx])
		if err != nil {
			return nil, fmt.Errorf("store: invalid version in %q: %w", e.Name(), err)
		}
		out = append(out, migrationFile{version: v, name: e.Name()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("store: duplicate migration version %d", out[i].version)
		}
	}
	return out, nil
}

// SettingsGet/SettingsSet 提供给上层读写应用级元数据。
func (s *Store) SettingsGet(ctx context.Context, key string) (string, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT value FROM app_settings WHERE key=?`, key)
	var v string
	if err := row.Scan(&v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// key 不存在:正常「未设置」,由调用方决定默认值。
			return "", false, nil
		}
		// 真错误(I/O / ctx 取消 / 类型错)必须上报,不能与「未设置」混同——
		// 否则 fail-closed 的调用方(如 acl reload 读 acl_default_action / mesh_enabled)
		// 会把一次 DB 抖动误判成「未配置」而退回不安全默认。
		return "", false, fmt.Errorf("store: settings get %q: %w", key, err)
	}
	return v, true, nil
}

// reservedSettingKeys 是**系统托管**、禁止走通用 SettingsSet 写入的 app_settings key:
//   - server_id     由 ensureServerID / migration hook 用 INSERT OR IGNORE 专管(first-writer-wins),
//     覆盖它会破坏客户端按 server_id 的去重语义;
//   - schema_version 由 migrations runner 维护,手改会让 schema 状态机错乱、重复 / 跳过迁移。
//
// CLI `setting set` 入口已用 systemManagedSettingKeys 挡住这两个 key,这里在 DAL 再兜一层纵深防御,
// 防未来其它调用方(web handler / 新代码)绕过 CLI 直接调 SettingsSet 覆盖它们。二者各自的专用写路径
// (ensureServerID / migrations runner)都不经过本函数,加此守卫不影响正常初始化。
var reservedSettingKeys = map[string]bool{
	ServerIDKey:      true, // "server_id"
	"schema_version": true,
}

func (s *Store) SettingsSet(ctx context.Context, key, value string) error {
	if reservedSettingKeys[key] {
		return fmt.Errorf("store: setting %q is system-managed and must not be set via SettingsSet: %w", key, ErrInvalid)
	}
	// 第四轮深扫 MED(store #11):对**已知**的 rate 键在通用 setter 里也套上与 CLI raw 写路径同款的校验
	// (纵深防御)。此前只有 CLI 入口调 ValidateNonNegativeInt64Setting / ValidateRateBurstSetting,任何绕过
	// 它直接 SettingsSet(未来的 web / SDK / 脚本)可写入负值 / 非数 / 越界 burst,读路径 settingsGetInt64
	// 再把它静默当 0(= 不限速)或运行期把 burst 夹住 —— 「写得进却与本意不符」。此处按键分发到对应校验器。
	switch key {
	case settingRateDefaultUploadBPS, settingRateDefaultDownloadBPS:
		if err := ValidateNonNegativeInt64Setting(value); err != nil {
			return fmt.Errorf("store: set %s: %s: %w", key, err.Error(), ErrInvalid)
		}
	case settingRateBurstBytes:
		if err := ValidateRateBurstSetting(value); err != nil {
			return fmt.Errorf("store: set %s: %s: %w", key, err.Error(), ErrInvalid)
		}
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO app_settings(key,value) VALUES(?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("store: set %s: %w", key, err)
	}
	return nil
}
