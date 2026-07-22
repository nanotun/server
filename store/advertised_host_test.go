package store

import (
	"context"
	"path/filepath"
	"testing"
)

// TestValidateAdvertisedHost 锁住 ValidateAdvertisedHost 的语义边界,防止以后
// 加新规则时悄悄把它放松了。每条 case 注释里写明攻击场景或 UX 场景。
//
// 2026-05-26 改名:旧名 TestValidatePublicHost(public_host → advertised_host
// 重命名一起改),测试条目语义不变。
func TestValidateAdvertisedHost(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		wantErr bool
	}{
		// === 合法形式 ===
		{"空串视为清除", "", false},
		{"IPv4 字面量", "203.0.113.10", false},
		{"域名", "vpn.example.com", false},
		{"多级子域", "a.b.c.vpn.example.com", false},
		{"IPv6 带方括号", "[2001:db8::1]", false},
		{"IPv6 不带方括号(纯地址,无端口)", "2001:db8::1", false},
		{"含端口看起来的域名:不冒号:被 IPv6 检测放过", "vpn.example.com:abc", false}, // 后段非全数字 → 不当 host:port
		{"trim 前后空白", "  vpn.example.com  ", false},

		// === 拒绝 scheme ===
		{"http scheme", "http://vpn.example.com", true},
		{"https scheme", "https://vpn.example.com", true},
		{"ws scheme", "ws://vpn.example.com", true},
		{"wss scheme", "wss://vpn.example.com", true},
		{"大小写混合 scheme", "HTTPS://vpn.example.com", true},

		// === 拒绝 path / query / fragment ===
		{"path", "vpn.example.com/x", true},
		{"query", "vpn.example.com?y=1", true},
		{"fragment", "vpn.example.com#a", true},

		// === 拒绝 host:port ===
		{"IPv4:port", "203.0.113.10:8080", true},
		{"IPv6 带方括号:port", "[2001:db8::1]:8080", true},
		{"域名:port", "vpn.example.com:8080", true},

		// === 拒绝控制字符 ===
		{"换行注入", "vpn.example.com\nSet-Cookie: evil=1", true},
		{"回车注入", "vpn.example.com\rX", true},
		{"TAB", "vpn.example.com\tx", true},
		{"NUL", "vpn.example.com\x00x", true},

		// === 长度 ===
		{"恰好 253 字符通过", largeHost(253), false},
		{"254 字符被拒", largeHost(254), true},

		// === 2026-05-26 第六轮拆字段:label 场景(本轮起 advertised_host 不再兼任 dial,
		//     这些"看起来不像合法 IP/域名"但作 label 完全 OK 的字符串必须合法)===
		{"末段纯数字 label", "test-203.0.113.10", false},
		{"中文 label", "测试机", false},
		{"label 含空格", "Tokyo Prod 1", false},
		{"label 含 emoji", "服务器🚀-1", false},
		{"短数字 label", "1", false},
		{"prod 风格 label", "prod-tokyo-1", false},
	}
	for _, tc := range cases {
		err := ValidateAdvertisedHost(tc.host)
		if tc.wantErr && err == nil {
			t.Errorf("%s: ValidateAdvertisedHost(%q) = nil, want error", tc.name, tc.host)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: ValidateAdvertisedHost(%q) = %v, want nil", tc.name, tc.host, err)
		}
	}
}

func largeHost(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}

// TestMigration0015_RenameUnderAllPreexistingStates 锁住 0015 migration 在 4 种
// 起始 db 状态下都能正确执行,不会因为撞 PRIMARY KEY 让 Migrate 整 tx rollback。
//
// 历史教训(2026-05-26 自审第二轮):0015 最初写成
//
//	`UPDATE app_settings SET key='advertised_host' WHERE key='public_host'`,
//
// 看似简洁,但 4 种 db 状态里只有 3 种安全 — 状态 4(两 key 同时存在)会撞 PRIMARY
// KEY UNIQUE 让整条 migration 失败 + schema_version 卡在 14 + 服务起不来。状态 4 在
// 正常代码路径不会出现,但任何手动 sqlite3 干预 / 测试夹具 / 半截 migration 备份恢复
// 都能制造。改成 INSERT OR REPLACE + DELETE 两步后 4 种状态全安全。
//
// 测试构造 4 个独立 db,模拟 4 种状态,跑 Migrate 后断言结果。
func TestMigration0015_RenameUnderAllPreexistingStates(t *testing.T) {
	t.Run("only_public_host_present", func(t *testing.T) {
		ctx := t.Context()
		s, oldVer := openPreV15Store(ctx, t)
		// 状态 1:跑过 0001-0014,公网地址走老 key。
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO app_settings(key,value) VALUES('public_host','203.0.113.10')`); err != nil {
			t.Fatalf("seed public_host: %v", err)
		}
		_ = oldVer
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		assertAdvertisedHost(ctx, t, s, "203.0.113.10")
		assertPublicHostAbsent(ctx, t, s)
	})

	t.Run("only_advertised_host_present", func(t *testing.T) {
		ctx := t.Context()
		s, _ := openPreV15Store(ctx, t)
		// 状态 2:已迁移过的 db(或测试夹具直接写新 key)。
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO app_settings(key,value) VALUES('advertised_host','vpn.example.com')`); err != nil {
			t.Fatalf("seed advertised_host: %v", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		assertAdvertisedHost(ctx, t, s, "vpn.example.com")
		assertPublicHostAbsent(ctx, t, s)
	})

	t.Run("neither_key_present", func(t *testing.T) {
		ctx := t.Context()
		s, _ := openPreV15Store(ctx, t)
		// 状态 3:全新 admin 还没配过 host,两 key 都不存在 — no-op 路径。
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		assertAdvertisedHost(ctx, t, s, "")
		assertPublicHostAbsent(ctx, t, s)
	})

	t.Run("both_keys_present_old_takes_priority", func(t *testing.T) {
		ctx := t.Context()
		s, _ := openPreV15Store(ctx, t)
		// 状态 4(撞键 fail-fast 风险源):罕见但合法的 db 状态 — ops 手动 sqlite3 写
		// 过 advertised_host 后又把老 key 留下,或某条半截 migration 没收尾。
		// 关键不变量:不能炸 Migrate,而且要以**老 key 的 value 为权威源**(改名语义
		// = 老 key 才是 admin 真正配过的活值)。
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO app_settings(key,value) VALUES('public_host','203.0.113.10');
			INSERT INTO app_settings(key,value) VALUES('advertised_host','STALE_VALUE');
		`); err != nil {
			t.Fatalf("seed both: %v", err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate FAILED — 撞键回归,migration 0015 写法退步: %v", err)
		}
		assertAdvertisedHost(ctx, t, s, "203.0.113.10")
		assertPublicHostAbsent(ctx, t, s)
	})
}

// openPreV15Store 在临时目录开一个新 db,**手动**把 schema_version 钉到 14 让 Migrate
// 把 0015 当成「待执行」(否则 Migrate 跑全栈 0001-0015 后,advertised_host 已经被
// 0015 处理过,我们再灌 public_host 测撞键就没意义了)。
//
// 实现:先 Migrate 一次跑完 0001-0014,然后用 UPDATE 把 schema_version 写回 14。
// 0015 的 UPDATE 在没人写 public_host 的全新 db 上是 no-op,所以这条「重置」对
// 测试不变量没干扰。
func openPreV15Store(ctx context.Context, t *testing.T) (*Store, int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "migrate0015_test.db")
	s, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("initial Migrate (to head): %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE app_settings SET value='14' WHERE key='schema_version'`); err != nil {
		t.Fatalf("rewind schema_version to 14: %v", err)
	}
	// 顺便清掉 0015 第一次跑可能落下的 advertised_host(全新 db 上不会有,但
	// defensive — 让所有 sub-test 起始状态干净一致)。
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM app_settings WHERE key IN ('public_host','advertised_host')`); err != nil {
		t.Fatalf("clean host keys: %v", err)
	}
	// 本夹具把 schema_version 倒回 14,后续 Migrate 会**重跑** 0015..head。0015-0018
	// 都幂等(rename 走 INSERT OR REPLACE、0017/0018 是 CREATE TABLE IF NOT EXISTS),
	// 但裸 `ALTER TABLE ADD COLUMN` 不幂等(SQLite 无 ADD COLUMN IF NOT EXISTS)。
	// 首次全量 Migrate 已把 0019 的 allowed_platforms 加上,重跑会撞 duplicate column
	// 让整条 migration tx 回滚。这里把它 DROP 掉,恢复「干净的 v14 起点」。
	// 未来若再有 >14 的 ADD COLUMN 迁移,需在此比照补一条 DROP(测试失败会指到这)。
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE users DROP COLUMN allowed_platforms`); err != nil {
		t.Fatalf("drop allowed_platforms (rewind to pre-0019): %v", err)
	}
	// 同上:0020 的 devices.alias 也是裸 ADD COLUMN,重跑前先 DROP。
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE devices DROP COLUMN alias`); err != nil {
		t.Fatalf("drop alias (rewind to pre-0020): %v", err)
	}
	// 同上:0021 的 users.max_sessions 也是裸 ADD COLUMN,重跑前先 DROP。
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE users DROP COLUMN max_sessions`); err != nil {
		t.Fatalf("drop max_sessions (rewind to pre-0021): %v", err)
	}
	// 同上:0022 的 web_admins.totp_last_used_step 也是裸 ADD COLUMN,重跑前先 DROP。
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE web_admins DROP COLUMN totp_last_used_step`); err != nil {
		t.Fatalf("drop totp_last_used_step (rewind to pre-0022): %v", err)
	}
	// 同上:0024 的 web_admins.last_failure_at 也是裸 ADD COLUMN,重跑前先 DROP。
	// (0023/0025/0026 是幂等的 index / UPDATE 迁移,无需 rewind DROP。)
	if _, err := s.db.ExecContext(ctx,
		`ALTER TABLE web_admins DROP COLUMN last_failure_at`); err != nil {
		t.Fatalf("drop last_failure_at (rewind to pre-0024): %v", err)
	}
	return s, 14
}

func assertAdvertisedHost(ctx context.Context, t *testing.T, s *Store, want string) {
	t.Helper()
	got, err := s.GetAdvertisedHost(ctx)
	if err != nil {
		t.Fatalf("GetAdvertisedHost: %v", err)
	}
	if got != want {
		t.Errorf("advertised_host = %q, want %q", got, want)
	}
}

func assertPublicHostAbsent(ctx context.Context, t *testing.T, s *Store) {
	t.Helper()
	row := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM app_settings WHERE key='public_host'`)
	var n int
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count public_host: %v", err)
	}
	if n != 0 {
		t.Errorf("0015 之后 public_host 仍有 %d 行,应该被 DELETE 干净", n)
	}
}
