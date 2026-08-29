package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// `acl list` 与 `setting set acl_default_action` 对兜底动作的交代。
//
// 为什么值得钉:规则表在 allow / deny 两种兜底下长得一模一样而语义相反,零行更像
// 「没配策略」。web 列表页已经补了这一行,CLI 是同一个坑 —— 脚本和救场都走这条路,
// 真出事时人往往先敲 CLI。
//
// 归一化必须与数据面(cmd/nanotund/acl_runtime.go 的 readSettings)一致,否则会出现
// 「CLI 说通、包在丢」的语义分裂。

// aclCLIEnv 造一个已 migrate 的库 + 抓得住 stdout/stderr 的 opts。
func aclCLIEnv(t *testing.T, lang string) (*store.Store, *globalOpts, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	st := openStoreForTest(t, newInitializedDB(t, t.TempDir(), "acl.db"))
	t.Cleanup(func() { _ = st.Close() })
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	return st, &globalOpts{stdout: out, stderr: errb, lang: lang}, out, errb
}

// aclCLIUser 建一个用户并返回其 id(ACL 规则两端要的是 id)。
func aclCLIUser(t *testing.T, st *store.Store, name string) int64 {
	t.Helper()
	u, err := st.CreateUser(t.Context(), openStoreNewUser(name))
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", name, err)
	}
	return u.ID
}

// setDefaultActionRaw 绕过 DAL 校验直接写值(拼错值只可能这么来:手工改库,
// 或者写入校验落地之前的老版本)。
func setDefaultActionRaw(t *testing.T, st *store.Store, v string) {
	t.Helper()
	if _, err := st.DB().ExecContext(t.Context(),
		`INSERT INTO app_settings(key,value) VALUES('acl_default_action',?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, v); err != nil {
		t.Fatalf("写 acl_default_action=%q: %v", v, err)
	}
}

// 出厂状态:表后要说清「没命中规则时是放行的」。
func TestACLList_TellsYouTheDefaultActionIsAllow(t *testing.T) {
	st, opts, out, _ := aclCLIEnv(t, langZH)

	if err := cmdACLList(t.Context(), st, opts, nil); err != nil {
		t.Fatalf("acl list: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "没命中任何规则时:allow") {
		t.Errorf("没交代兜底动作是 allow,输出:\n%s", got)
	}
	if strings.Contains(got, "白名单") {
		t.Errorf("allow 状态却说白名单,输出:\n%s", got)
	}
}

// deny + 零规则:这是「谁都不通」,不是「还没开始限制」。
// 且必须点明出口是独立一类 —— 否则人会配满 user 规则再来问为什么还是上不了网。
func TestACLList_DenyWithNoRulesSaysEverythingIsRefused(t *testing.T) {
	st, opts, out, _ := aclCLIEnv(t, langZH)
	if err := st.SettingsSet(t.Context(), "acl_default_action", "deny"); err != nil {
		t.Fatalf("SettingsSet: %v", err)
	}

	if err := cmdACLList(t.Context(), st, opts, nil); err != nil {
		t.Fatalf("acl list: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "没命中任何规则时:deny") {
		t.Errorf("没交代兜底是 deny,输出:\n%s", got)
	}
	if !strings.Contains(got, "全部被拒") {
		t.Errorf("零规则 + deny 应说明当前全拒,输出:\n%s", got)
	}
	if !strings.Contains(got, "出公网是独立的一类") {
		t.Errorf("没点明出口是独立一类,人会配满 user 规则还上不了网,输出:\n%s", got)
	}
}

// 大小写与空白:手工写进 "DENY" / " deny " 时数据面按 deny 判,CLI 也必须这么说。
func TestACLList_DefaultActionNormalizationMatchesDataPlane(t *testing.T) {
	for _, raw := range []string{"DENY", "Deny", "  deny  ", "\tdeny\n"} {
		t.Run(raw, func(t *testing.T) {
			st, opts, out, _ := aclCLIEnv(t, langZH)
			setDefaultActionRaw(t, st, raw)
			if err := cmdACLList(t.Context(), st, opts, nil); err != nil {
				t.Fatalf("acl list: %v", err)
			}
			if got := out.String(); !strings.Contains(got, "没命中任何规则时:deny") {
				t.Errorf("%q 应归一成 deny,输出:\n%s", raw, got)
			}
		})
	}
}

// 拼错值:结论按 deny 报(与数据面 fail-closed 一致),同时把原始值回显 ——
// 否则运维看到 deny,却记得自己设的是别的,从输出里看不出库里躺着个拼错值。
func TestACLList_TypoedDefaultActionIsEchoedAndTreatedAsDeny(t *testing.T) {
	st, opts, out, errb := aclCLIEnv(t, langZH)
	setDefaultActionRaw(t, st, "alow")

	if err := cmdACLList(t.Context(), st, opts, nil); err != nil {
		t.Fatalf("acl list: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "没命中任何规则时:deny") {
		t.Errorf("拼错值应按 deny 报,输出:\n%s", got)
	}
	warn := errb.String()
	if !strings.Contains(warn, "alow") {
		t.Fatalf("原始值没回显,无从发现拼错,stderr:\n%s", warn)
	}
	if !strings.Contains(warn, "既不是 allow 也不是 deny") {
		t.Errorf("没解释这个值为什么被当成 deny,stderr:\n%s", warn)
	}
}

// --json 的形状不能变:它是脚本契约。补充信息只走人类输出。
//
// 这条同时挡住「顺手把 default_action 塞进 JSON」——那会把顶层从数组换成对象,
// 所有 `jq '.[]'` 当场失效,而 CI 里这类失效往往是静默的(拿到 null 继续往下跑)。
func TestACLList_JSONStaysABareArray(t *testing.T) {
	st, opts, out, _ := aclCLIEnv(t, langZH)
	if err := st.SettingsSet(t.Context(), "acl_default_action", "deny"); err != nil {
		t.Fatalf("SettingsSet: %v", err)
	}
	opts.json = true

	if err := cmdACLList(t.Context(), st, opts, nil); err != nil {
		t.Fatalf("acl list --json: %v", err)
	}
	got := strings.TrimSpace(out.String())
	if strings.HasPrefix(got, "{") {
		t.Fatalf("--json 顶层变成了对象,脚本的 jq '.[]' 会当场失效:\n%s", got)
	}
	if strings.Contains(got, "没命中任何规则时") {
		t.Errorf("人类文案漏进了 --json 输出:\n%s", got)
	}
}

// 读不到设置时:警告一声,但不能让 acl list 失败 —— 规则表本身是准的,
// 不该因为一句补充信息就看不到规则。也不猜方向。
func TestACLList_UnreadableDefaultActionWarnsbutStillLists(t *testing.T) {
	st, opts, out, errb := aclCLIEnv(t, langZH)
	if _, err := st.DB().ExecContext(t.Context(),
		`ALTER TABLE app_settings RENAME TO app_settings_hidden`); err != nil {
		t.Fatalf("藏掉 app_settings: %v", err)
	}

	if err := cmdACLList(t.Context(), st, opts, nil); err != nil {
		t.Fatalf("读不到设置不该让 acl list 失败: %v", err)
	}
	if !strings.Contains(errb.String(), "读不到 acl_default_action") {
		t.Errorf("没警告读取失败,stderr:\n%s", errb.String())
	}
	for _, guess := range []string{"没命中任何规则时:allow", "没命中任何规则时:deny"} {
		if strings.Contains(out.String(), guess) {
			t.Errorf("读失败却猜了一个方向(%q),输出:\n%s", guess, out.String())
		}
	}
}

// 翻到 deny 时要说清影响面,而不是只回一句「已写入」。
//
// 这是这套设置里影响面最大的一次写入:跨用户流量与所有出公网立刻改按白名单裁决,
// 而白名单此刻可能一条都没有。
func TestSettingSet_ACLDefaultActionDenyWarnsAboutBlastRadius(t *testing.T) {
	t.Run("零规则:说明现在全拒", func(t *testing.T) {
		st, opts, _, errb := aclCLIEnv(t, langZH)
		warnACLDefaultActionDeny(t.Context(), st, opts, "acl_default_action", "deny")

		warn := errb.String()
		if !strings.Contains(warn, "已切到白名单模型") {
			t.Errorf("没说影响面,stderr:\n%s", warn)
		}
		if !strings.Contains(warn, "全部被拒") {
			t.Errorf("零规则时没说明当前全拒,stderr:\n%s", warn)
		}
	})

	t.Run("只有 user 规则:出口仍全断,要单独吼", func(t *testing.T) {
		st, opts, _, errb := aclCLIEnv(t, langZH)
		u1 := aclCLIUser(t, st, "a")
		u2 := aclCLIUser(t, st, "b")
		if _, err := st.AddACLPairBasic(t.Context(), u1, u2, store.ACLAllow); err != nil {
			t.Fatalf("建 user allow 规则: %v", err)
		}
		warnACLDefaultActionDeny(t.Context(), st, opts, "acl_default_action", "deny")

		if warn := errb.String(); !strings.Contains(warn, "没有任何 kind=exit 的放行规则") {
			t.Errorf("只配了 user 规则,上网还是断的,必须单独吼一声,stderr:\n%s", warn)
		}
	})

	t.Run("已有出口放行:不再吼出口", func(t *testing.T) {
		st, opts, _, errb := aclCLIEnv(t, langZH)
		u := aclCLIUser(t, st, "c")
		if _, err := st.AddACLPair(t.Context(), store.NewACLPair{
			SrcUserID: u, Action: store.ACLAllow, DstKind: store.ACLDstKindExit,
		}); err != nil {
			t.Fatalf("建 exit allow 规则: %v", err)
		}
		warnACLDefaultActionDeny(t.Context(), st, opts, "acl_default_action", "deny")

		if warn := errb.String(); strings.Contains(warn, "没有任何 kind=exit 的放行规则") {
			t.Errorf("已有出口放行规则却还在吼出口全断,stderr:\n%s", warn)
		}
	})

	t.Run("翻回 allow 不吼", func(t *testing.T) {
		st, opts, _, errb := aclCLIEnv(t, langZH)
		warnACLDefaultActionDeny(t.Context(), st, opts, "acl_default_action", "allow")
		if warn := errb.String(); warn != "" {
			t.Errorf("放开方向不该警告,stderr:\n%s", warn)
		}
	})

	t.Run("别的 key 不吼", func(t *testing.T) {
		st, opts, _, errb := aclCLIEnv(t, langZH)
		warnACLDefaultActionDeny(t.Context(), st, opts, "mesh_enabled", "deny")
		if warn := errb.String(); warn != "" {
			t.Errorf("与本设置无关的 key 触发了警告,stderr:\n%s", warn)
		}
	})
}
