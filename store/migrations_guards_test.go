package store

// migrations_guards_test.go:迁移 runner、app_settings 通用读写、以及两个 Go 迁移 hook
// (server_id 生成 / 存量 VIP 归一)的失败行为。
//
// 迁移是唯一一处「出错就必须停」的代码:半途继续会把 schema_version 记成一个与实际 schema
// 不符的数字,下次启动跳过真正没跑的那几条,或者把非幂等的历史迁移重跑一遍。所以下面的用例
// 除了断言报错,还都要断言「版本号没有前进」。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newUnmigratedStore 开一个跑过 Open 但**没有** Migrate 的库,用来测 runner 本身。
func newUnmigratedStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "unmigrated.db")
	s, err := Open(t.Context(), path, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func schemaVersionRaw(t *testing.T, s *Store) string {
	t.Helper()
	var v string
	err := s.db.QueryRowContext(t.Context(),
		`SELECT value FROM app_settings WHERE key='schema_version'`).Scan(&v)
	if err != nil {
		t.Fatalf("读 schema_version: %v", err)
	}
	return v
}

func setSchemaVersionRaw(t *testing.T, s *Store, v string) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(),
		`UPDATE app_settings SET value=? WHERE key='schema_version'`, v); err != nil {
		t.Fatalf("改 schema_version: %v", err)
	}
}

func TestMigrate_RunsCleanOnAFreshDatabase(t *testing.T) {
	s, _ := newUnmigratedStore(t)
	ctx := t.Context()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("首次迁移: %v", err)
	}
	v1, ok, err := s.SchemaVersionIfInitialized(ctx)
	if err != nil || !ok || v1 <= 0 {
		t.Fatalf("version=%d initialized=%v err=%v", v1, ok, err)
	}
	// 幂等:再跑一次不该改动任何东西。生产上每个进程启动都会跑一次。
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("重复迁移: %v", err)
	}
	v2, _, err := s.SchemaVersionIfInitialized(ctx)
	if err != nil {
		t.Fatalf("SchemaVersionIfInitialized: %v", err)
	}
	if v2 != v1 {
		t.Fatalf("重复迁移把版本从 %d 改成了 %d", v1, v2)
	}
}

// TestMigrate_RefusesADatabaseFromTheFuture:库的 schema 比程序新(= 有人降级了)时必须停。
//
// runner 的循环只跳过 `<= current` 的迁移,所以这种库原本会一条不跑、静默返回 nil,旧二进制
// 就跑在一个它不认识的 schema 上 —— 报错要等到某次真实读写才发生,离病根十万八千里。
func TestMigrate_RefusesADatabaseFromTheFuture(t *testing.T) {
	ctx := t.Context()

	t.Run("版本高于内嵌的最高迁移号即拒绝", func(t *testing.T) {
		s := newTestStore(t)
		setSchemaVersionRaw(t, s, "9999")
		err := s.Migrate(ctx)
		if !errors.Is(err, ErrSchemaFromFuture) {
			t.Fatalf("想要 ErrSchemaFromFuture,拿到 %v", err)
		}
		// 报错要说清「库是多少、程序认到多少」,否则运维只知道起不来,不知道是降级导致的。
		if !strings.Contains(err.Error(), "9999") {
			t.Fatalf("报错里没有库的版本号: %v", err)
		}
		if got := schemaVersionRaw(t, s); got != "9999" {
			t.Fatalf("拒绝之后不该改动版本号,却成了 %s", got)
		}
	})

	t.Run("同版本的库照常放行", func(t *testing.T) {
		// 落后的库(部分迁移过)由 TestMigrate_RunsCleanOnAFreshDatabase 覆盖 —— 不在这里
		// 把版本号倒回去伪造:历史迁移里有裸 ALTER TABLE ADD COLUMN,在已经迁移完的库上重跑
		// 会撞 duplicate column,测出来的是伪造手法的毛病,不是守卫的。
		s := newTestStore(t)
		newest := schemaVersionRaw(t, s)
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("与程序同版本的库被误拦: %v", err)
		}
		if got := schemaVersionRaw(t, s); got != newest {
			t.Fatalf("放行后版本不该变,却从 %s 成了 %s", newest, got)
		}
	})
}

func TestMigrate_NeverAdvancesTheVersionPastAFailure(t *testing.T) {
	ctx := t.Context()

	t.Run("app_settings 都建不出来时立刻停", func(t *testing.T) {
		// 只读连接上跑迁移:第一步就该失败。若这里放过去,后面每条 DDL 都会失败,
		// 报出来的却是「no such table」之类看不出根因的错。
		path := filepath.Join(t.TempDir(), "empty.db")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatalf("建空文件: %v", err)
		}
		ro, err := Open(ctx, path, Options{ReadOnly: true})
		if err != nil {
			t.Fatalf("Open ro: %v", err)
		}
		t.Cleanup(func() { _ = ro.Close() })
		if err := ro.Migrate(ctx); err == nil {
			t.Fatal("只读连接上迁移成功了?")
		}
	})

	t.Run("拿不到跨进程锁时不硬着头皮迁移", func(t *testing.T) {
		// 锁文件建不出来就继续 = 两个进程可能同时 ALTER TABLE / CREATE INDEX,
		// SQLite 在那种并发下会报「table is locked」甚至留下对不上的元数据。
		if os.Geteuid() == 0 {
			t.Skip("root 无视目录权限")
		}
		dir := t.TempDir()
		s, err := Open(ctx, filepath.Join(dir, "locked.db"), Options{})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

		err = s.Migrate(ctx)
		if err == nil {
			t.Fatal("锁文件建不出来却照常迁移")
		}
		// 必须是「拿不到锁」这个原因。若这里因为别的写失败而报错,说明锁那一步其实被跳过了 ——
		// 换个锁文件仍可创建、但 db 目录可写的环境就会真的并发迁移。
		if !strings.Contains(err.Error(), "migrate lock") {
			t.Fatalf("报错原因不是拿不到锁: %v", err)
		}
	})

	t.Run("版本号读不出来时绝不当成 0", func(t *testing.T) {
		// 当成 0 会把非幂等的历史迁移(ALTER TABLE ADD COLUMN 之类)重跑一遍,
		// 直接把已有 schema 搞坏 —— 比启动失败严重得多。
		s := newTestStore(t)
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE app_settings RENAME COLUMN value TO value_drifted`); err != nil {
			t.Fatalf("改列名: %v", err)
		}
		if err := s.Migrate(ctx); err == nil {
			t.Fatal("读不到版本号却照常迁移")
		}
		// 探针也必须把它报成错误。若报成「未初始化」,运维会照提示跑一次迁移,
		// 等于在一个状态未知的库上重放历史迁移。
		if v, ok, err := s.SchemaVersionIfInitialized(ctx); err == nil {
			t.Fatalf("version=%d initialized=%v err=nil —— 读故障被说成了未初始化", v, ok)
		}
	})

	t.Run("版本号是非数字时报错", func(t *testing.T) {
		s := newTestStore(t)
		setSchemaVersionRaw(t, s, "v29")
		if err := s.Migrate(ctx); err == nil {
			t.Fatal("版本号不是数字却照常迁移")
		}
		if _, _, err := s.SchemaVersionIfInitialized(ctx); err == nil {
			t.Fatal("SchemaVersionIfInitialized 也该把它当错误,而不是 0")
		}
	})

	t.Run("某条迁移执行失败时版本号停在原处", func(t *testing.T) {
		// 把版本号往回拨,让一条非幂等迁移(0021 给 users 加列)再跑一次 —— 必然失败。
		// 这模拟的是「运维手改版本号」或「迁移文件与库不匹配」,期望是硬失败而非带病启动。
		s := newTestStore(t)
		setSchemaVersionRaw(t, s, "20")
		if err := s.Migrate(ctx); err == nil {
			t.Fatal("重跑一条非幂等迁移竟然成功了")
		}
		if got := schemaVersionRaw(t, s); got != "20" {
			t.Fatalf("版本号变成了 %q —— 失败的迁移不该记账,否则下次启动会跳过它", got)
		}
	})

	t.Run("记账写不进去时整条迁移一起回滚", func(t *testing.T) {
		// 迁移体成功但 schema_version 写失败:必须整体回滚。只提交一半的话,
		// 库里有了新对象、版本号却还是旧的,下次启动重跑同一条迁移(未必幂等)。
		s := newTestStore(t)
		latest := schemaVersionRaw(t, s)
		setSchemaVersionRaw(t, s, "29") // 只让 0030(幂等)重跑
		abortOnWhen(t, s, "app_settings", "UPDATE OF value", `NEW.key = 'schema_version'`)

		if err := s.Migrate(ctx); err == nil {
			t.Fatal("记账失败却报迁移成功")
		}
		if got := schemaVersionRaw(t, s); got != "29" {
			t.Fatalf("版本号 = %q(原本 29,库里最新是 %s)", got, latest)
		}
	})

	t.Run("server_id hook 失败会上报", func(t *testing.T) {
		s := newTestStore(t)
		if _, err := s.db.ExecContext(ctx,
			`UPDATE app_settings SET value='' WHERE key=?`, ServerIDKey); err != nil {
			t.Fatalf("清空 server_id: %v", err)
		}
		abortOnWhen(t, s, "app_settings", "UPDATE OF value",
			fmt.Sprintf("NEW.key = '%s'", ServerIDKey))
		if err := s.Migrate(ctx); err == nil {
			t.Fatal("server_id 补不上却报迁移成功")
		}
	})

	t.Run("VIP 归一 hook 失败会上报", func(t *testing.T) {
		s := newTestStore(t)
		if _, err := s.db.ExecContext(ctx,
			`DELETE FROM app_settings WHERE key=?`, vipCanonicalizedKey); err != nil {
			t.Fatalf("删归一标记: %v", err)
		}
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE leases RENAME COLUMN vip_v4 TO vip_v4_drifted`); err != nil {
			t.Fatalf("改列名: %v", err)
		}
		if err := s.Migrate(ctx); err == nil {
			t.Fatal("存量 VIP 扫不了却报迁移成功 —— 漏归一会让分配器认不出已占用的地址")
		}
	})
}

func TestSchemaVersionIfInitialized_TellsAnEmptyDatabaseApartFromABrokenOne(t *testing.T) {
	// 打错 --db-path 时 SQLite 会顺手建一个空库,之后每处读都报「no such table」,
	// 运维看不出真正原因是指错了库。这个探针就是为了给出「库未初始化」的明确提示。
	ctx := t.Context()

	t.Run("全新空库", func(t *testing.T) {
		s, _ := newUnmigratedStore(t)
		v, ok, err := s.SchemaVersionIfInitialized(ctx)
		if err != nil {
			t.Fatalf("空库上不该报错: %v", err)
		}
		if ok || v != 0 {
			t.Fatalf("version=%d initialized=%v,空库应当是 (0,false)", v, ok)
		}
	})

	t.Run("有表但版本号是 0 也算未初始化", func(t *testing.T) {
		s := newTestStore(t)
		setSchemaVersionRaw(t, s, "0")
		v, ok, err := s.SchemaVersionIfInitialized(ctx)
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if ok {
			t.Fatalf("version=%d 被判成已初始化 —— 迁移从没成功记账,读出来的一切都不可信", v)
		}
	})

	t.Run("库关掉之后报错而不是「未初始化」", func(t *testing.T) {
		dead := newDeadStore(t)
		if _, ok, err := dead.SchemaVersionIfInitialized(ctx); err == nil {
			t.Fatalf("initialized=%v err=nil —— 读故障被说成「库没初始化」,"+
				"运维会去跑一次迁移,把问题引向别处", ok)
		}
	})
}

func TestSettingsSet_RefusesValuesTheReadPathWouldSilentlyMisread(t *testing.T) {
	// 通用 setter 是 CLI / web / 未来 SDK 共用的入口。这里放行一个读路径解不出的值,
	// 运行期会静默退回默认:限速变成「不限」、mesh 开关拼错变成「保持开启」。
	// 所有校验必须留在 DAL,不能只靠 CLI 那一层。
	ctx := t.Context()
	s := newTestStore(t)

	t.Run("系统托管的键一律拒写", func(t *testing.T) {
		for _, key := range []string{ServerIDKey, "schema_version", vipCanonicalizedKey,
			"vip_canonicalized", MeshCIDRsKey} {
			if err := s.SettingsSet(ctx, key, "1"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("key=%s err=%v,想要 ErrInvalid —— 手改这些键会让状态机错乱", key, err)
			}
		}
	})

	t.Run("解不出来的值一律拒写", func(t *testing.T) {
		bad := []struct {
			key, val, because string
		}{
			{settingRateDefaultUploadBPS, "abc", "读路径 ParseInt 失败就当 0 = 不限速,与「设了个限速」相反"},
			{settingRateDefaultUploadBPS, " 42 ", "读路径不 trim,带空白的值会被当成 0"},
			{settingRateDefaultDownloadBPS, "-1", "负值没有意义"},
			{settingRateBurstBytes, "1", "落在区间外的 burst 运行期会被静默夹住"},
			{settingRateBurstBytes, "abc", "同上"},
			{"acl_default_action", "deni", "拼错的动作数据面认不出,兜底 deny,运维以为设的是别的"},
			{MeshEnabledKey, "flase", "布尔量拼错时兜底是 true —— 想关 mesh 却保持了互通"},
		}
		for _, tc := range bad {
			t.Run(tc.key+"="+tc.val, func(t *testing.T) {
				if err := s.SettingsSet(ctx, tc.key, tc.val); !errors.Is(err, ErrInvalid) {
					t.Fatalf("err=%v,想要 ErrInvalid。%s", err, tc.because)
				}
				if v, ok, err := s.SettingsGet(ctx, tc.key); err != nil {
					t.Fatalf("SettingsGet: %v", err)
				} else if ok && v == tc.val {
					t.Fatalf("被拒的值 %q 还是落库了", v)
				}
			})
		}
	})

	t.Run("合法值写得进也读得回", func(t *testing.T) {
		good := map[string]string{
			settingRateDefaultUploadBPS:   "1000",
			settingRateDefaultDownloadBPS: "0",
			settingRateBurstBytes:         fmt.Sprint(RateBurstBytesMin),
			"acl_default_action":          "deny",
			MeshEnabledKey:                "false",
		}
		for k, v := range good {
			if err := s.SettingsSet(ctx, k, v); err != nil {
				t.Fatalf("%s=%s 应当合法: %v", k, v, err)
			}
			got, ok, err := s.SettingsGet(ctx, k)
			if err != nil || !ok || got != v {
				t.Fatalf("%s 读回 %q ok=%v err=%v", k, got, ok, err)
			}
		}
	})

	t.Run("没设过的键返回 ok=false 而不是错误", func(t *testing.T) {
		v, ok, err := s.SettingsGet(ctx, "从来没设过的键")
		if err != nil || ok || v != "" {
			t.Fatalf("v=%q ok=%v err=%v", v, ok, err)
		}
	})

	t.Run("库关掉之后读写都报错", func(t *testing.T) {
		dead := newDeadStore(t)
		if err := dead.SettingsSet(ctx, "some_key", "v"); err == nil {
			t.Fatal("库已关闭却写成功")
		}
		if _, ok, err := dead.SettingsGet(ctx, "some_key"); err == nil {
			t.Fatalf("ok=%v err=nil —— 读故障必须与「未设置」区分开,"+
				"否则 fail-closed 的调用方会退回不安全默认", ok)
		}
	})
}

func TestAcquireMigrateLock(t *testing.T) {
	t.Run("内存库与空路径不需要文件锁", func(t *testing.T) {
		for _, p := range []string{":memory:", ""} {
			unlock, err := acquireMigrateLock(p)
			if err != nil {
				t.Fatalf("path=%q err=%v", p, err)
			}
			unlock()
		}
	})

	t.Run("锁文件建不出来时报错而不是不加锁就跑", func(t *testing.T) {
		// 拿不到锁却继续迁移 = 两个进程同时 ALTER TABLE,元数据可能对不上。
		if os.Geteuid() == 0 {
			t.Skip("root 无视目录权限")
		}
		dir := t.TempDir()
		sub := filepath.Join(dir, "ro")
		if err := os.Mkdir(sub, 0o500); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
		if _, err := acquireMigrateLock(filepath.Join(sub, "x.db")); err == nil {
			t.Fatal("目录不可写却拿到了锁")
		}
	})

	t.Run("同一路径重复加锁不自死锁", func(t *testing.T) {
		// Migrate 在同进程内会被反复调用(server + admin 在同一进程内跑测试时尤其明显)。
		path := filepath.Join(t.TempDir(), "x.db")
		first, err := acquireMigrateLock(path)
		if err != nil {
			t.Fatalf("首次: %v", err)
		}
		first()
		second, err := acquireMigrateLock(path)
		if err != nil {
			t.Fatalf("二次: %v", err)
		}
		second()
	})
}

// ---------- 存量 VIP 归一 hook ----------

// seedRawLease 绕过 DAL 直接写一条 lease,用来制造「第七轮修好写路径之前落库的非规范值」。
func seedRawLease(t *testing.T, s *Store, deviceID int64, v4, v6 string) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(),
		`INSERT INTO leases(device_id, vip_v4, vip_v6, manual, assigned_at) VALUES(?,?,?,0,?)`,
		deviceID, nullableString(v4), nullableString(v6), nowUnix()); err != nil {
		t.Fatalf("插 lease: %v", err)
	}
}

func clearCanonicalizedFlag(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(),
		`DELETE FROM app_settings WHERE key=?`, vipCanonicalizedKey); err != nil {
		t.Fatalf("删归一标记: %v", err)
	}
}

func canonicalizedFlag(t *testing.T, s *Store) string {
	t.Helper()
	v, ok, err := s.SettingsGet(t.Context(), vipCanonicalizedKey)
	if err != nil {
		t.Fatalf("读归一标记: %v", err)
	}
	if !ok {
		return "<缺失>"
	}
	return v
}

func TestCanonicalizeStoredVIPs_BringsLegacyRowsIntoTheSameTextDomain(t *testing.T) {
	// 分配器、去重、跨表守卫全都是按字面比较地址文本的。存量里留着 "FD00::2" 而新写入
	// 用 "fd00::2",就等于同一个地址在库里有两种写法 —— 谁都认不出它已被占用,
	// 于是同一地址被分配给第二台设备,路由变成黑洞。
	ctx := t.Context()

	t.Run("非规范写法被改写成规范形", func(t *testing.T) {
		s := newTestStore(t)
		d := seedOneDevice(t, s, "canon")
		seedRawLease(t, s, d.ID, "", "FD00:0:0:0:0:0:0:2")
		clearCanonicalizedFlag(t, s)

		if err := s.canonicalizeStoredVIPs(ctx); err != nil {
			t.Fatalf("canonicalizeStoredVIPs: %v", err)
		}
		l, err := s.GetLeaseByDevice(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetLeaseByDevice: %v", err)
		}
		if l.VIPv6 != "fd00::2" {
			t.Fatalf("归一后是 %q,期望 fd00::2", l.VIPv6)
		}
		if got := canonicalizedFlag(t, s); got != "1" {
			t.Fatalf("完成标记 = %q,全部成功时该落 1", got)
		}
	})

	t.Run("IPv4 映射写法也要折平", func(t *testing.T) {
		s := newTestStore(t)
		d := seedOneDevice(t, s, "mapped")
		seedRawLease(t, s, d.ID, "", "::ffff:10.0.0.5")
		clearCanonicalizedFlag(t, s)

		if err := s.canonicalizeStoredVIPs(ctx); err != nil {
			t.Fatalf("canonicalizeStoredVIPs: %v", err)
		}
		l, err := s.GetLeaseByDevice(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetLeaseByDevice: %v", err)
		}
		if l.VIPv6 == "::ffff:10.0.0.5" {
			t.Fatalf("映射写法没被折平 —— 与点分形失配,去重会漏判")
		}
	})

	t.Run("标记已是 1 时直接跳过", func(t *testing.T) {
		s := newTestStore(t)
		d := seedOneDevice(t, s, "flagged")
		seedRawLease(t, s, d.ID, "", "FD00::9")
		if err := s.canonicalizeStoredVIPs(ctx); err != nil {
			t.Fatalf("canonicalizeStoredVIPs: %v", err)
		}
		l, err := s.GetLeaseByDevice(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetLeaseByDevice: %v", err)
		}
		if l.VIPv6 != "FD00::9" {
			t.Fatalf("标记已完成却又扫了一遍(值变成 %q)", l.VIPv6)
		}
	})

	t.Run("跨表撞车时跳过并把标记留在未完成", func(t *testing.T) {
		// A 的 lease 是 "FD00::2",归一后会撞上 B 已钉住的 "fd00::2"。
		// 迁移不该替运维裁决谁是赢家,而是跳过 + 告警,并且**不**落完成标记,
		// 这样运维释放冲突方之后下次启动会自动收尾。
		s := newTestStore(t)
		a := seedOneDevice(t, s, "collide-a")
		b := seedOneDevice(t, s, "collide-b")
		seedRawLease(t, s, a.ID, "", "FD00::2")
		if _, err := s.db.ExecContext(ctx,
			`UPDATE devices SET fixed_vip_v6='fd00::2' WHERE id=?`, b.ID); err != nil {
			t.Fatalf("给 B 钉地址: %v", err)
		}
		clearCanonicalizedFlag(t, s)

		if err := s.canonicalizeStoredVIPs(ctx); err != nil {
			t.Fatalf("撞车不该让整条迁移失败: %v", err)
		}
		l, err := s.GetLeaseByDevice(ctx, a.ID)
		if err != nil {
			t.Fatalf("GetLeaseByDevice: %v", err)
		}
		if l.VIPv6 != "FD00::2" {
			t.Fatalf("撞车的行被改写成 %q —— 那就直接双占了", l.VIPv6)
		}
		if got := canonicalizedFlag(t, s); got != "0" {
			t.Fatalf("完成标记 = %q,有跳过时必须留 0,否则下次永久 no-op", got)
		}
	})

	t.Run("同表撞车时同样跳过", func(t *testing.T) {
		s := newTestStore(t)
		a := seedOneDevice(t, s, "same-a")
		b := seedOneDevice(t, s, "same-b")
		seedRawLease(t, s, a.ID, "", "FD00::3")
		seedRawLease(t, s, b.ID, "", "fd00::3")
		clearCanonicalizedFlag(t, s)

		if err := s.canonicalizeStoredVIPs(ctx); err != nil {
			t.Fatalf("撞车不该让整条迁移失败: %v", err)
		}
		if got := canonicalizedFlag(t, s); got != "0" {
			t.Fatalf("完成标记 = %q,有跳过时必须留 0", got)
		}
	})

	t.Run("各步失败都要上报", func(t *testing.T) {
		type tc struct {
			name  string
			setup func(t *testing.T, s *Store, deviceID int64)
		}
		cases := []tc{
			{"占位标记写不进去", func(t *testing.T, s *Store, _ int64) {
				clearCanonicalizedFlag(t, s)
				abortOn(t, s, "app_settings", "INSERT")
			}},
			{"扫表失败", func(t *testing.T, s *Store, _ int64) {
				clearCanonicalizedFlag(t, s)
				if _, err := s.db.ExecContext(t.Context(),
					`ALTER TABLE leases RENAME COLUMN vip_v4 TO vip_v4_drifted`); err != nil {
					t.Fatalf("改列名: %v", err)
				}
			}},
			{"跨表撞车检查失败", func(t *testing.T, s *Store, _ int64) {
				clearCanonicalizedFlag(t, s)
				if _, err := s.db.ExecContext(t.Context(),
					`ALTER TABLE devices RENAME COLUMN fixed_vip_v6 TO fixed_vip_v6_drifted`); err != nil {
					t.Fatalf("改列名: %v", err)
				}
			}},
			{"改写失败", func(t *testing.T, s *Store, _ int64) {
				clearCanonicalizedFlag(t, s)
				abortOn(t, s, "leases", "UPDATE")
			}},
			{"落完成标记失败", func(t *testing.T, s *Store, deviceID int64) {
				// 让本轮无需改写(值本来就规范),只在最后 finalize 那一步失败。
				if _, err := s.db.ExecContext(t.Context(),
					`UPDATE leases SET vip_v6='fd00::7' WHERE device_id=?`, deviceID); err != nil {
					t.Fatalf("改成规范值: %v", err)
				}
				clearCanonicalizedFlag(t, s)
				abortOnWhen(t, s, "app_settings", "UPDATE OF value",
					fmt.Sprintf("NEW.key = '%s'", vipCanonicalizedKey))
			}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				s := newTestStore(t)
				d := seedOneDevice(t, s, "fail")
				seedRawLease(t, s, d.ID, "", "FD00::8")
				c.setup(t, s, d.ID)

				err := s.canonicalizeStoredVIPs(ctx)
				if err == nil {
					t.Fatal("失败却报成功 —— 归一没做完却落了完成标记,存量永远不会再被处理")
				}
				if !strings.Contains(err.Error(), "canonicalize vips") {
					t.Fatalf("错误没带上下文,运维看不出是哪一步: %v", err)
				}
			})
		}
	})

	t.Run("库关掉之后报错", func(t *testing.T) {
		dead := newDeadStore(t)
		if err := dead.canonicalizeStoredVIPs(ctx); err == nil {
			t.Fatal("库已关闭却报成功")
		}
	})
}
