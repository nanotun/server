package store

import (
	"path/filepath"
	"testing"
)

// 审计表是事后唯一能回答「谁在什么时候改了什么」的地方。写入和查询这两组方法
// 此前一条都没被测过 —— 而它们出问题的方式往往是静默的:写入失败被忽略、查询
// 把 limit 用在过滤之前导致「明明有记录却查不到」。

func TestAudit_WriteRequiresActorAndActionAndRecordsTime(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const t0 = 1_700_000_000
	advance := withFrozenClock(t, t0)

	if err := s.Audit(ctx, "alice", "user_create", "u:42", "username=bob"); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	advance(60)
	if err := s.Audit(ctx, "alice", "user_delete", "u:42", ""); err != nil {
		t.Fatalf("Audit(空 detail): %v", err)
	}

	// actor 与 action 缺一不可:一条不知道是谁干的、或者不知道干了什么的记录
	// 在事后追查时等于噪声,不如当场拒绝。
	for _, bad := range []struct{ actor, action string }{
		{"", "user_create"},
		{"alice", ""},
		{"", ""},
	} {
		if err := s.Audit(ctx, bad.actor, bad.action, "t", "d"); err == nil {
			t.Fatalf("actor=%q action=%q 应被拒", bad.actor, bad.action)
		}
	}

	// target / detail 可以为空(不是每个动作都有对象)。
	if err := s.Audit(ctx, "system", "acl.reload", "", ""); err != nil {
		t.Fatalf("无 target 的运行期动作应当能写: %v", err)
	}

	n, err := s.CountAudit(ctx)
	if err != nil {
		t.Fatalf("CountAudit: %v", err)
	}
	if n != 3 {
		t.Fatalf("应有 3 条,got %d(被拒的那几条不该落库)", n)
	}

	logs, err := s.QueryAudit(ctx, 0, t0+1000, 100)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("应查到 3 条,got %d", len(logs))
	}
	// 最新的在前:排查时先看最近发生了什么。
	for i := 1; i < len(logs); i++ {
		if logs[i-1].At < logs[i].At {
			t.Fatalf("应按时间倒序,%d 排在 %d 前面", logs[i-1].At, logs[i].At)
		}
	}
	if logs[0].At != t0+60 {
		t.Fatalf("最新一条的时间戳应是 %d,got %d", t0+60, logs[0].At)
	}
	for _, l := range logs {
		if l.Actor == "" || l.Action == "" {
			t.Fatalf("查出来的记录缺 actor/action: %+v", l)
		}
	}
}

// nil store 上调用不能 panic —— 这几个方法会在启动早期(store 还没建好)
// 被错误路径调到,那时崩掉会把真正的启动失败原因盖掉。
func TestAudit_NilStoreReturnsErrorInsteadOfPanicking(t *testing.T) {
	var s *Store
	ctx := t.Context()
	if err := s.Audit(ctx, "a", "b", "", ""); err == nil {
		t.Fatal("nil store 上 Audit 应报错")
	}
	if _, err := s.CountAudit(ctx); err == nil {
		t.Fatal("nil store 上 CountAudit 应报错")
	}
	if _, err := s.PruneAuditBefore(ctx, 0); err == nil {
		t.Fatal("nil store 上 PruneAuditBefore 应报错")
	}
}

// 时间区间是左闭右开。边界写错一天,导出的合规报表就会重复或漏掉一整天的记录。
func TestQueryAudit_RangeIsHalfOpenAndLimitIsBounded(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const t0 = 1_700_000_000
	advance := withFrozenClock(t, t0)

	for i := range 5 {
		if err := s.Audit(ctx, "alice", "user_create", "u", ""); err != nil {
			t.Fatalf("写第 %d 条: %v", i, err)
		}
		advance(10)
	}
	// 写入时刻:t0, t0+10, t0+20, t0+30, t0+40。

	logs, err := s.QueryAudit(ctx, t0, t0+40, 100)
	if err != nil {
		t.Fatalf("QueryAudit: %v", err)
	}
	if len(logs) != 4 {
		t.Fatalf("[t0, t0+40) 应含 4 条(右端开区间,t0+40 那条不算),got %d", len(logs))
	}
	if logs, _ = s.QueryAudit(ctx, t0, t0+41, 100); len(logs) != 5 {
		t.Fatalf("[t0, t0+41) 应含全部 5 条,got %d", len(logs))
	}
	if logs, _ = s.QueryAudit(ctx, t0+10, t0+30, 100); len(logs) != 2 {
		t.Fatalf("[t0+10, t0+30) 应含 2 条,got %d —— 左端是闭区间", len(logs))
	}

	// limit 生效,而且取最近的那些。
	logs, _ = s.QueryAudit(ctx, 0, t0+1000, 2)
	if len(logs) != 2 {
		t.Fatalf("limit=2 应只回 2 条,got %d", len(logs))
	}
	if logs[0].At != t0+40 {
		t.Fatalf("limit 应保留最新的,got 首条时间 %d", logs[0].At)
	}

	// limit<=0 或超大都被夹到上限,而不是被当成「不限」把整表拉进内存。
	for _, lim := range []int{0, -1, 999999} {
		if logs, err = s.QueryAudit(ctx, 0, t0+1000, lim); err != nil || len(logs) != 5 {
			t.Fatalf("limit=%d 应被夹到默认上限并回全部 5 条,got %d err=%v", lim, len(logs), err)
		}
	}
}

// 上一条只验了「limit<=0 时不报错」,验不出上限本身:表里才 5 行,夹不夹都一样。
// 这条把表撑到上限之上 —— 生产 audit 表是百万行级的,把 LIMIT 0 当「不限」意味着
// 一次 `audit list` 就能把整张表读进内存。
func TestQueryAudit_LimitIsClampedNotTreatedAsUnbounded(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const t0 = 1_700_000_000
	withFrozenClock(t, t0)

	// 用递归 CTE 一条语句灌 10005 行,比逐条 Audit 快得多。
	if _, err := s.DB().ExecContext(ctx, `
		WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 10005)
		INSERT INTO audit_logs(actor, action, target, detail, at)
		SELECT 'bulk', 'noise', '', '', ?  FROM seq`, t0); err != nil {
		t.Fatalf("批量写入: %v", err)
	}
	if n, _ := s.CountAudit(ctx); n != 10005 {
		t.Fatalf("预置应有 10005 行,got %d", n)
	}

	for _, lim := range []int{0, -1, 999999, 20000} {
		logs, err := s.QueryAudit(ctx, 0, t0+1, lim)
		if err != nil {
			t.Fatalf("limit=%d: %v", lim, err)
		}
		if len(logs) != 10000 {
			t.Fatalf("limit=%d 应被夹到 10000 条,got %d —— 不夹住的话一次查询会把整张表拉进内存",
				lim, len(logs))
		}
	}
	// 合法范围内的 limit 原样生效。
	if logs, _ := s.QueryAudit(ctx, 0, t0+1, 7); len(logs) != 7 {
		t.Fatalf("limit=7 应回 7 条,got %d", len(logs))
	}
	if logs, _ := s.QueryAuditByAction(ctx, 0, t0+1, "noise", 0); len(logs) != 10000 {
		t.Fatalf("按 action 查时 limit 同样要夹住,got %d", len(logs))
	}
}

// action 过滤必须下推到 SQL。在应用层过滤的话,LIMIT 先生效、过滤后生效,
// 结果是「明明有 100 条 acl.reload,查出来 0 条」这种反直觉的空结果。
func TestQueryAuditByAction_FiltersBeforeTheLimitApplies(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const t0 = 1_700_000_000
	advance := withFrozenClock(t, t0)

	// 先写 20 条噪声,再写 3 条目标动作 —— 目标动作是最早写的,
	// 如果 LIMIT 在过滤之前生效,取最近 10 条就一条都看不到。
	for range 3 {
		if err := s.Audit(ctx, "alice", "acl.reload", "", ""); err != nil {
			t.Fatalf("写目标动作: %v", err)
		}
		advance(1)
	}
	for range 20 {
		if err := s.Audit(ctx, "bob", "user_login", "", ""); err != nil {
			t.Fatalf("写噪声: %v", err)
		}
		advance(1)
	}

	logs, err := s.QueryAuditByAction(ctx, 0, t0+1000, "acl.reload", 10)
	if err != nil {
		t.Fatalf("QueryAuditByAction: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("应查到 3 条 acl.reload,got %d —— 数量不对说明过滤没下推到 SQL", len(logs))
	}
	for _, l := range logs {
		if l.Action != "acl.reload" {
			t.Fatalf("混进了别的动作: %+v", l)
		}
	}

	// 精确匹配,不做前缀模糊。
	if logs, _ = s.QueryAuditByAction(ctx, 0, t0+1000, "acl", 10); len(logs) != 0 {
		t.Fatalf("action 应精确匹配,\"acl\" 不该命中 \"acl.reload\",got %d 条", len(logs))
	}
	if logs, _ = s.QueryAuditByAction(ctx, 0, t0+1000, "no_such_action", 10); len(logs) != 0 {
		t.Fatalf("不存在的动作应回空,got %d", len(logs))
	}
	// limit 同样被夹住。
	if logs, err = s.QueryAuditByAction(ctx, 0, t0+1000, "user_login", 0); err != nil || len(logs) != 20 {
		t.Fatalf("limit=0 应夹到上限,got %d err=%v", len(logs), err)
	}
}

// 截尾是长跑环境的必需品:一台机器一天能写几十万条,不清理几个月就是几个 GB。
// 但它删的是审计记录 —— 边界多删一天就是把可能需要的证据烧了。
func TestPruneAuditBefore_DeletesStrictlyOlderThanCutoff(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const t0 = 1_700_000_000
	advance := withFrozenClock(t, t0)

	for range 3 {
		if err := s.Audit(ctx, "alice", "old", "", ""); err != nil {
			t.Fatalf("写旧记录: %v", err)
		}
	}
	advance(100)
	for range 2 {
		if err := s.Audit(ctx, "alice", "new", "", ""); err != nil {
			t.Fatalf("写新记录: %v", err)
		}
	}

	// cutoff 落在两批之间:只删旧的。
	n, err := s.PruneAuditBefore(ctx, t0+100)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 3 {
		t.Fatalf("应删 3 条,got %d", n)
	}
	// cutoff 是严格小于:恰好等于 cutoff 的那批必须留下。
	left, _ := s.CountAudit(ctx)
	if left != 2 {
		t.Fatalf("应剩 2 条(at == cutoff 的不删),got %d", left)
	}

	// 幂等:再跑一次删 0 条。
	if n, err = s.PruneAuditBefore(ctx, t0+100); err != nil || n != 0 {
		t.Fatalf("重复截尾应删 0 条,got n=%d err=%v", n, err)
	}
	// cutoff 在所有记录之前:一条都不删。
	if n, err = s.PruneAuditBefore(ctx, 1); err != nil || n != 0 {
		t.Fatalf("cutoff 早于全部记录时不该删,got n=%d err=%v", n, err)
	}
}

// 「指错了库文件」是运维踩过的真实坑:目录里留着一个空库,os.Stat 过得了,
// 每处读都撞 "no such table"。这个探测方法就是为了把那种情况说清楚。
func TestSchemaVersionIfInitialized_TellsAnEmptyFileApartFromARealDB(t *testing.T) {
	ctx := t.Context()

	t.Run("从未迁移过的库", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.db")
		s, err := Open(ctx, path, Options{})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer s.Close()

		v, initialized, err := s.SchemaVersionIfInitialized(ctx)
		if err != nil {
			t.Fatalf("探测不该报错(报错就把「库是空的」这个真相盖掉了): %v", err)
		}
		if initialized || v != 0 {
			t.Fatalf("空库应判为未初始化,got version=%d initialized=%v", v, initialized)
		}
	})

	t.Run("表建了但版本没记上", func(t *testing.T) {
		// migration 中途失败会留下这种状态:app_settings 在,schema_version 没写成。
		// 此时读出来的一切都不可信,必须和「空库」一样判为未初始化。
		s := newTestStore(t)
		if _, err := s.DB().ExecContext(ctx,
			`DELETE FROM app_settings WHERE key='schema_version'`); err != nil {
			t.Fatalf("模拟半迁移状态: %v", err)
		}
		v, initialized, err := s.SchemaVersionIfInitialized(ctx)
		if err != nil {
			t.Fatalf("探测: %v", err)
		}
		if initialized {
			t.Fatalf("版本为 %d 时应判为未初始化 —— 表在但没记账,说明 migration 没跑完", v)
		}
	})

	t.Run("迁移过的库", func(t *testing.T) {
		s := newTestStore(t)
		v, initialized, err := s.SchemaVersionIfInitialized(ctx)
		if err != nil {
			t.Fatalf("探测: %v", err)
		}
		if !initialized {
			t.Fatal("迁移过的库应判为已初始化")
		}
		if v <= 0 {
			t.Fatalf("版本号应为正,got %d", v)
		}
	})
}
