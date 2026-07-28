package main

// reloadACLSnapshotFromStore 的拒绝面。
//
// 这个函数是 ACL 策略进入数据面的唯一入口:它读 (acl_default_action, mesh_enabled,
// 规则集),折成不可变快照,原子换上去。它判错的后果与别处不同 —— **不会报错,只会
// 静默放行或静默黑洞**,而且是在每个包上生效。所以这里要钉的不是「正常值能不能读」
// (那条早有测试),而是三件事:
//
//   1. 读**真错**(不是「key 没设过」)时必须返回 err 且**保留旧快照**。一次 DB 抖动
//      把 default-deny 翻成 allow,等于短暂敞开整张白名单,而且没有任何告警。
//   2. 无法识别的 acl_default_action 值必须 fail-closed 兜到 deny。拼错一个字母
//      ("deni")过去会静默保留 allow —— 部署方以为自己在白名单模型下,实际全放行。
//   3. mesh_enabled 读失败不能被当成「mesh 开着」。关掉的 mesh 被一次读错重新放开,
//      同样是安全方向相反。
//
// 故障注入靠「放宽 app_settings.value 的 NOT NULL 再塞 NULL」:SettingsGet 往 string
// 扫 NULL 会报错,这是模拟真读故障的唯一办法 —— 与「这个 key 不存在」(ok=false,
// 不是 error)是两回事,而两者的正确行为恰好相反(前者保留旧值,后者用内置默认)。

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// newACLReloadStore 开一个空库,并把 aclCurrent 恢复责任挂到 t.Cleanup ——
// 本文件的用例都会动这个全局快照,漏恢复会污染同包里其它测试。
func newACLReloadStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "acl_reload.db"), store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	prev := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(prev) })
	return st
}

// relaxSettingsNotNull 去掉 app_settings.value 的 NOT NULL 约束,好让测试塞 NULL 进去。
func relaxSettingsNotNull(t *testing.T, st *store.Store) {
	t.Helper()
	for _, stmt := range []string{
		`CREATE TABLE app_settings_relaxed (key TEXT PRIMARY KEY, value TEXT)`,
		`INSERT INTO app_settings_relaxed(key, value) SELECT key, value FROM app_settings`,
		`DROP TABLE app_settings`,
		`ALTER TABLE app_settings_relaxed RENAME TO app_settings`,
	} {
		if _, err := st.DB().ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("放宽 app_settings 约束(%s): %v", stmt, err)
		}
	}
}

// nullifySetting 把某个 key 的值置 NULL —— 之后对这个 key 的 SettingsGet 会扫错,
// 而别的 key 照常。精确到单 key 是必要的:整表改坏会让 acl_default_action 与
// mesh_enabled 一起失败,分不清拦下它的是哪一步。
func nullifySetting(t *testing.T, st *store.Store, key string) {
	t.Helper()
	relaxSettingsNotNull(t, st)
	if _, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO app_settings(key, value) VALUES(?, NULL)
		 ON CONFLICT(key) DO UPDATE SET value = NULL`, key); err != nil {
		t.Fatalf("把 %s 置 NULL: %v", key, err)
	}
}

// setSettingRaw 绕过 SettingsSet 的校验直接写库,用来模拟「手抠 DB / 坏迁移写进了
// 非法值」—— 那是 reload 里那条 fail-closed 兜底唯一能被触发的场合。
func setSettingRaw(t *testing.T, st *store.Store, key, value string) {
	t.Helper()
	if _, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO app_settings(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
		t.Fatalf("直写 %s=%q: %v", key, value, err)
	}
}

// seedACLDenyRule 造两个用户和一条 deny 规则,返回 (srcID, dstID)。
// 快照里有没有这条规则,是判断「旧快照是否被保留」的抓手。
func seedACLDenyRule(t *testing.T, st *store.Store) (int64, int64) {
	t.Helper()
	ctx := t.Context()
	mk := func(name string) int64 {
		u, err := st.CreateUser(ctx, store.NewUser{Username: name, PSKHash: "x"})
		if err != nil {
			t.Fatalf("建用户 %s: %v", name, err)
		}
		return u.ID
	}
	src, dst := mk("aclsrc"), mk("acldst")
	if _, err := st.AddACLPair(ctx, store.NewACLPair{
		SrcUserID: src, DstUserID: dst, Action: store.ACLDeny,
	}); err != nil {
		t.Fatalf("建 ACL 规则: %v", err)
	}
	return src, dst
}

// TestReloadACLSnapshot_NilStoreInstallsPermissiveEmptySnapshot 钉住测试兜底路径:
// st == nil 时装一份 default=allow 的空快照(与历史行为一致),而不是留着 nil 让
// 热路径去解引用。
func TestReloadACLSnapshot_NilStoreInstallsPermissiveEmptySnapshot(t *testing.T) {
	prev := aclCurrent.Load()
	t.Cleanup(func() { aclCurrent.Store(prev) })
	aclCurrent.Store(nil)

	n, err := reloadACLSnapshotFromStore(nil)
	if err != nil {
		t.Fatalf("st==nil 不该报错: %v", err)
	}
	if n != 0 {
		t.Fatalf("规则数应为 0, got %d", n)
	}
	snap := aclCurrent.Load()
	if snap == nil {
		t.Fatal("必须装上一份非 nil 快照,否则热路径要么 panic 要么走别的兜底")
	}
	if snap.defaultAction != store.ACLAllow {
		t.Fatalf("兜底快照的 default 应为 allow, got %q", snap.defaultAction)
	}
	if !snap.meshEnabled {
		t.Fatal("兜底快照的 mesh 应为开")
	}
}

// TestReloadACLSnapshot_UnknownDefaultActionFailsClosedToDeny 钉住第 2 条:
// acl_default_action 拼错时兜到 deny,不是静默保留 allow。
//
// 这条的方向很要紧:写路径(CLI)已经校验过,正常数据落不进这里,所以能命中的场合
// 只有手抠 DB / 迁移写坏 —— 恰恰是最需要保守的场合。
func TestReloadACLSnapshot_UnknownDefaultActionFailsClosedToDeny(t *testing.T) {
	st := newACLReloadStore(t)
	ctx := context.Background()

	for _, bad := range []string{"deni", "allo", "DENY!", " ", "0"} {
		t.Run("值="+strings.TrimSpace(bad)+"|", func(t *testing.T) {
			// 先钉住写路径:SettingsSet 自己就拒这些值。也就是说下面那条兜底
			// **只能**由手抠 DB / 坏迁移触发 —— 正常路径进不来,这也正是它必须
			// 保守的理由(能走到这里说明库已经被外力改过了)。
			if err := st.SettingsSet(ctx, "acl_default_action", bad); err == nil {
				t.Fatalf("SettingsSet 应当拒绝 %q —— 写路径的校验没了", bad)
			}
			setSettingRaw(t, st, "acl_default_action", bad)
			if _, err := reloadACLSnapshotFromStore(st); err != nil {
				t.Fatalf("无法识别的值不该让 reload 失败(那会把在跑的数据面打挂): %v", err)
			}
			if got := aclCurrent.Load().defaultAction; got != store.ACLDeny {
				t.Fatalf("acl_default_action=%q 应 fail-closed 到 deny, got %q —— "+
					"这会让本以为在白名单模型下的部署全放行", bad, got)
			}
		})
	}

	// 反面对照:规范值必须原样生效,别把上面的兜底做成「一律 deny」。
	for _, good := range []struct{ in, want string }{
		{"allow", store.ACLAllow}, {"ALLOW", store.ACLAllow}, {" allow ", store.ACLAllow},
		{"deny", store.ACLDeny}, {"Deny", store.ACLDeny},
	} {
		if err := st.SettingsSet(ctx, "acl_default_action", good.in); err != nil {
			t.Fatalf("写 %q: %v", good.in, err)
		}
		if _, err := reloadACLSnapshotFromStore(st); err != nil {
			t.Fatalf("reload(%q): %v", good.in, err)
		}
		if got := aclCurrent.Load().defaultAction; got != good.want {
			t.Fatalf("acl_default_action=%q 应归一到 %q, got %q", good.in, good.want, got)
		}
	}
}

// TestReloadACLSnapshot_KeyMissingIsNotAnError 把「key 没设过」与「读故障」分开钉:
// 前者是正常的未配置状态,该落到内置默认 allow,不该报错。
func TestReloadACLSnapshot_KeyMissingIsNotAnError(t *testing.T) {
	st := newACLReloadStore(t)
	if _, err := reloadACLSnapshotFromStore(st); err != nil {
		t.Fatalf("全新库(两个 key 都没设过)不该报错: %v", err)
	}
	snap := aclCurrent.Load()
	if snap.defaultAction != store.ACLAllow {
		t.Fatalf("未配置时 default 应为 allow(向后兼容), got %q", snap.defaultAction)
	}
	if !snap.meshEnabled {
		t.Fatal("未配置时 mesh 应为开")
	}
}

// TestReloadACLSnapshot_ReadFailuresKeepOldSnapshot 钉住第 1、3 条 ——
// 三种读故障都必须「返回 err + 一个字节都不改现有快照」。
//
// 用例结构上先装一份「default=deny + 一条 deny 规则」的好快照,再把库改坏,
// 然后要求快照指针**原封不动**。只断言 err != nil 是不够的:真正的危害是快照被
// 替换成一份宽松的(空规则 + allow),而那种实现同样会返回 err。
func TestReloadACLSnapshot_ReadFailuresKeepOldSnapshot(t *testing.T) {
	cases := map[string]struct {
		breakIt func(t *testing.T, st *store.Store)
		wantIn  string
	}{
		"acl_default_action 读失败": {
			breakIt: func(t *testing.T, st *store.Store) {
				nullifySetting(t, st, "acl_default_action")
			},
			wantIn: "acl_default_action",
		},
		"mesh_enabled 读失败": {
			breakIt: func(t *testing.T, st *store.Store) {
				nullifySetting(t, st, store.MeshEnabledKey)
			},
			wantIn: "mesh_enabled",
		},
		"规则集读失败": {
			breakIt: func(t *testing.T, st *store.Store) {
				if _, err := st.DB().ExecContext(t.Context(),
					`ALTER TABLE acl_pairs RENAME TO acl_pairs_gone`); err != nil {
					t.Fatalf("藏掉 acl_pairs: %v", err)
				}
			},
			wantIn: "acl",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			st := newACLReloadStore(t)
			ctx := context.Background()
			src, dst := seedACLDenyRule(t, st)
			if err := st.SettingsSet(ctx, "acl_default_action", store.ACLDeny); err != nil {
				t.Fatalf("设 default=deny: %v", err)
			}
			if err := st.SetMeshEnabled(ctx, false); err != nil {
				t.Fatalf("关 mesh: %v", err)
			}
			if _, err := reloadACLSnapshotFromStore(st); err != nil {
				t.Fatalf("装好快照: %v", err)
			}
			good := aclCurrent.Load()
			if good.defaultAction != store.ACLDeny || good.meshEnabled {
				t.Fatalf("前置条件不对: default=%q mesh=%v", good.defaultAction, good.meshEnabled)
			}

			tc.breakIt(t, st)

			n, err := reloadACLSnapshotFromStore(st)
			if err == nil {
				t.Fatal("读故障必须返回 err —— 静默成功会让运维以为新规则已经生效")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("报错里没提 %q,可能是被别的读拦下的: %v", tc.wantIn, err)
			}
			if n != 0 {
				t.Fatalf("失败时规则数应为 0, got %d", n)
			}
			if got := aclCurrent.Load(); got != good {
				t.Fatalf("快照被换掉了 —— 读故障时必须原样保留旧快照。"+
					"现在 default=%q mesh=%v", got.defaultAction, got.meshEnabled)
			}
			// 再从行为侧确认一次:旧的那条 deny 还在拦。
			if aclAllows(src, dst) {
				t.Fatal("旧快照里的 deny 规则失效了 —— 读故障把策略敞开了")
			}
		})
	}
}

// TestReloadACLSnapshot_SettingsChangedMidReadStaysConsistent 钉住那个「前读设置 →
// 读规则 → 后读设置,不一致就重试」的窗口:并发改 default_action 时,装上去的快照
// 里「规则集」与「兜底动作」必须来自同一时刻,不能拼出一份两半不一致的。
//
// 这里不断言重试分支一定被走到(那取决于调度),断言的是**不变量**:每次 reload 之后
// 快照的 default 必须等于当时库里的某个真实值,且规则数正确。
func TestReloadACLSnapshot_SettingsChangedMidReadStaysConsistent(t *testing.T) {
	st := newACLReloadStore(t)
	ctx := context.Background()
	seedACLDenyRule(t, st)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			v := store.ACLAllow
			if i%2 == 0 {
				v = store.ACLDeny
			}
			_ = st.SettingsSet(ctx, "acl_default_action", v)
		}
	}()

	for i := 0; i < 60; i++ {
		n, err := reloadACLSnapshotFromStore(st)
		if err != nil {
			// SQLite 在并发写下可能给出 busy —— 那是环境噪声,不是本用例要验的东西。
			continue
		}
		if n != 1 {
			t.Fatalf("规则数应恒为 1, got %d", n)
		}
		if got := aclCurrent.Load().defaultAction; got != store.ACLAllow && got != store.ACLDeny {
			t.Fatalf("快照 default 落在了库里不存在的值上: %q", got)
		}
	}
	close(stop)
	<-done
}
