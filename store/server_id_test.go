package store

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func newTestStoreForServerID(t *testing.T) *Store {
	t.Helper()
	ctx := t.Context()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "server_id_test.db"), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return st
}

// TestGetOrInitServerID_LazyInit:首次调用必生成一个 valid UUID v4 并持久化。
func TestGetOrInitServerID_LazyInit(t *testing.T) {
	st := newTestStoreForServerID(t)
	ctx := t.Context()

	v, err := st.GetOrInitServerID(ctx)
	if err != nil {
		t.Fatalf("GetOrInitServerID: %v", err)
	}
	if v == "" {
		t.Fatal("server_id 不应为空")
	}
	// UUID v4 标准长度:36 字符含 4 个 hyphen,parse 必须成功。
	if _, err := uuid.Parse(v); err != nil {
		t.Fatalf("server_id %q 不是合法 UUID: %v", v, err)
	}
	if len(v) != 36 {
		t.Errorf("server_id 长度 %d,期望 36", len(v))
	}
	// 落库验证:再读一次 SettingsGet 应当与返回一致。
	stored, ok, err := st.SettingsGet(ctx, ServerIDKey)
	if err != nil || !ok || stored != v {
		t.Fatalf("settings 落库不一致:ok=%v err=%v stored=%q v=%q", ok, err, stored, v)
	}
}

// TestGetOrInitServerID_Idempotent:多次调用返回同一个值,绝对不变(身份指纹语义)。
func TestGetOrInitServerID_Idempotent(t *testing.T) {
	st := newTestStoreForServerID(t)
	ctx := t.Context()

	first, err := st.GetOrInitServerID(ctx)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	for i := 0; i < 20; i++ {
		v, err := st.GetOrInitServerID(ctx)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if v != first {
			t.Fatalf("iter %d: server_id 变了 %q → %q(违反「永久不变」)", i, first, v)
		}
	}
}

// TestGetOrInitServerID_ConcurrentFirstWriterWins:50 个 goroutine 同时跑首次 init,
// 所有人最终拿到同一个 UUID(first-writer-wins),不会出现多个不同值。
//
// 这是 Lazy init 模式的核心安全断言 —— 如果实现用 SettingsSet(UPSERT)就会
// race:两个 goroutine 各生成自己的 UUID 各自 UPSERT,后写者覆盖先写者,
// 不同时间点的 caller 拿到不同值,「永久」属性破灭。
func TestGetOrInitServerID_ConcurrentFirstWriterWins(t *testing.T) {
	st := newTestStoreForServerID(t)

	const N = 50
	results := make([]string, N)
	var wg sync.WaitGroup
	wg.Add(N)
	start := make(chan struct{}) // 同步起跑,让 race 触发概率最大化
	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			v, err := st.GetOrInitServerID(context.Background())
			if err != nil {
				t.Errorf("goroutine %d: %v", idx, err)
				return
			}
			results[idx] = v
		}(i)
	}
	close(start)
	wg.Wait()

	// 所有 goroutine 必须看到同一个 UUID。
	first := results[0]
	if first == "" {
		t.Fatal("results[0] 为空,goroutine 0 失败")
	}
	for i, v := range results {
		if v != first {
			t.Fatalf("goroutine %d 拿到 %q,期望 %q —— first-writer-wins 失败", i, v, first)
		}
	}
}

// TestGetServerID_ReadOnlyBeforeInit:GetServerID 在 server_id 不存在时返回
// 空 + nil error,**不**触发首次生成。
//
// 注:Migrate 现在挂 ensureServerID hook,所以 "Migrate 后 server_id 必存在",
// 走不到本测试想覆盖的「key 不存在」分支。这里手动绕过 Migrate,直接建空表,
// 验证 GetServerID 是纯只读 — 这是给 metrics / 诊断路径的安全合约,不应顺手写库。
func TestGetServerID_ReadOnlyBeforeInit(t *testing.T) {
	ctx := t.Context()
	st, err := Open(ctx, t.TempDir()+"/raw.db", Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// 不调 Migrate;只建 app_settings 表(GetServerID 内部 SELECT 需要这张表存在)。
	if err := st.ensureSettingsTable(ctx); err != nil {
		t.Fatalf("ensureSettingsTable: %v", err)
	}

	v, err := st.GetServerID(ctx)
	if err != nil {
		t.Fatalf("GetServerID(empty store): %v", err)
	}
	if v != "" {
		t.Errorf("expected empty server_id before init, got %q", v)
	}
	// 关键:GetServerID 不应顺手写库 — 这是「只读」语义合约。
	stored, ok, _ := st.SettingsGet(ctx, ServerIDKey)
	if ok || stored != "" {
		t.Errorf("GetServerID 不应顺手写库:ok=%v stored=%q", ok, stored)
	}
}

// TestGetServerID_ReadAfterInit:GetOrInitServerID 后 GetServerID 拿到同值。
func TestGetServerID_ReadAfterInit(t *testing.T) {
	st := newTestStoreForServerID(t)
	ctx := t.Context()

	first, _ := st.GetOrInitServerID(ctx)
	got, err := st.GetServerID(ctx)
	if err != nil {
		t.Fatalf("GetServerID: %v", err)
	}
	if got != first {
		t.Errorf("GetServerID = %q, want %q", got, first)
	}
}

// TestGetOrInitServerID_RescuesEmptyValue:历史上有人手动 SQL 把 server_id 改成
// 空串(不该发生但作为防御性测试)—— GetOrInitServerID 视作未初始化,自动回填。
func TestGetOrInitServerID_RescuesEmptyValue(t *testing.T) {
	st := newTestStoreForServerID(t)
	ctx := t.Context()

	// 模拟历史数据:写一个空串。
	_, err := st.db.ExecContext(ctx,
		`INSERT INTO app_settings(key, value) VALUES(?, '')
		 ON CONFLICT(key) DO UPDATE SET value=''`, ServerIDKey)
	if err != nil {
		t.Fatalf("seed empty: %v", err)
	}

	v, err := st.GetOrInitServerID(ctx)
	if err != nil {
		t.Fatalf("GetOrInitServerID: %v", err)
	}
	if v == "" {
		t.Fatal("空串未被自动回填")
	}
	if _, err := uuid.Parse(v); err != nil {
		t.Fatalf("回填值 %q 不是 UUID", v)
	}
	// 二次调用应该幂等。
	v2, _ := st.GetOrInitServerID(ctx)
	if v2 != v {
		t.Errorf("回填后第二次返回值不一致:%q vs %q", v, v2)
	}
	// 关键回归:空串场景下 INSERT OR IGNORE 会被现存 key 阻止 → 走「rescue」
	// 路径用 SettingsSet(UPSERT)覆盖空串。verify 是否真的覆盖成 UUID 了。
	stored, ok, _ := st.SettingsGet(ctx, ServerIDKey)
	if !ok || stored == "" {
		t.Errorf("rescue 后 settings 仍空:ok=%v stored=%q", ok, stored)
	}
	if !strings.Contains(stored, "-") {
		t.Errorf("rescue 后 settings 值 %q 不像 UUID", stored)
	}
}

// TestEnsureServerID_WroteFlagSignalsFirstWriter:2026-05-26·server_id 链路第五轮
// P2-2 引入。`ensureServerID` 返回 `(wrote bool, err error)`,语义:
//
//   - 首次 INSERT 落库 → wrote=true(Migrate hook 据此 log "initialized")
//   - 之后任何 caller 调用(行已存在,INSERT OR IGNORE 静默)→ wrote=false
//   - 历史空串被 rescue 覆盖 → wrote=true(rescue 也算"首次有了合法 UUID")
//
// 这条测试是 logging hook 的回归保护:有人若把 INSERT OR IGNORE 改回普通
// INSERT,RowsAffected 语义会变,wrote 标志失真,journalctl 里就会:
//   - 误报:重启 nanotun-web 每次 systemd restart 都打一条 "initialized";
//   - 漏报:全新部署没打,运维认为 server_id 没生成。
//
// 单测固化 wrote 语义,确保它跟 Migrate hook 的日志契约保持一致。
func TestEnsureServerID_WroteFlagSignalsFirstWriter(t *testing.T) {
	ctx := t.Context()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "wrote.db"), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.ensureSettingsTable(ctx); err != nil {
		t.Fatalf("ensureSettingsTable: %v", err)
	}

	// 首次:行不存在 → INSERT 成功 → wrote=true。
	wrote, err := st.ensureServerID(ctx)
	if err != nil {
		t.Fatalf("first ensureServerID: %v", err)
	}
	if !wrote {
		t.Error("首次 ensureServerID 应 wrote=true(INSERT 真写入)")
	}

	// 第二次:行已存在 → INSERT OR IGNORE 静默 → wrote=false。
	wrote, err = st.ensureServerID(ctx)
	if err != nil {
		t.Fatalf("second ensureServerID: %v", err)
	}
	if wrote {
		t.Error("第二次 ensureServerID 应 wrote=false(已存在,no-op)")
	}

	// rescue 场景:把 value 改成空串,再调一次 → rescue UPDATE 触发 → wrote=true。
	if _, err := st.db.ExecContext(ctx,
		`UPDATE app_settings SET value='' WHERE key=?`, ServerIDKey); err != nil {
		t.Fatalf("seed empty: %v", err)
	}
	wrote, err = st.ensureServerID(ctx)
	if err != nil {
		t.Fatalf("rescue ensureServerID: %v", err)
	}
	if !wrote {
		t.Error("rescue 场景应 wrote=true(空串被覆盖)")
	}
}
