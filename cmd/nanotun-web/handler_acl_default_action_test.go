package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ACL 列表页顶部的「没命中任何规则时」一行。
//
// 为什么值得单独钉一组用例:一屏 allow 规则在 default=allow 和 default=deny 两种
// 部署下渲染出来是一模一样的表格,而语义相反。这一行是页面上唯一能区分两者的信息,
// 说反了比不显示更糟 —— 运维会照着它判断「现在到底通不通」。
//
// 展示逻辑必须与数据面(cmd/nanotund/acl_runtime.go 的 readSettings)一致,否则
// 会出现「页面说通、包在丢」的语义分裂。
//
// 每条都跑中英文两遍:这一行的全部价值在于把语义讲清楚,漏翻一边等于那种语言的
// 运维看不到结论(而 badge 本身两种语言长得一样,看不出漏了)。

// aclPhrases 是判定「页面表达了哪种语义」的关键短语。
type aclPhrases struct {
	label     string // 兜底动作那一行的引导语
	allowNote string // allow 语义
	denyNote  string // deny(白名单)语义
	unknown   string // 读取失败
	noneAllow string // 空规则集 + allow
	noneDeny  string // 空规则集 + deny
	rawWarn   string // 值拼错时的解释
	readOnly  string // 「控制台只读」
}

var aclPhrasesByLang = map[string]aclPhrases{
	LangZH: {
		label:     "没命中任何规则时",
		allowNote: "默认互通",
		denyNote:  "白名单模型",
		unknown:   "读取失败",
		noneAllow: "所有源 → 所有目的放行",
		noneDeny:  "全部被拒",
		rawWarn:   "既不是 allow 也不是 deny",
		readOnly:  "控制台只读",
	},
	LangEN: {
		label:     "When no rule matches",
		allowNote: "cross-user traffic is allowed by default",
		denyNote:  "whitelist model",
		unknown:   "read failed",
		noneAllow: "allows all sources",
		noneDeny:  "all cross-user traffic and all exit traffic is currently refused",
		rawWarn:   "neither allow nor deny",
		readOnly:  "read-only",
	},
}

// setACLDefaultActionRaw 绕过 DAL 校验直接写值。
//
// SettingsSet 会挡住 "alow" 这类拼错(store/migrations.go),所以拼错值只可能来自
// 手工改库或校验落地之前的老版本 —— 而那恰恰是最需要页面把原始值回显出来的场景。
func setACLDefaultActionRaw(t *testing.T, s *Server, v string) {
	t.Helper()
	if _, err := s.store.DB().ExecContext(t.Context(),
		`INSERT INTO app_settings(key,value) VALUES('acl_default_action',?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, v); err != nil {
		t.Fatalf("写 acl_default_action=%q: %v", v, err)
	}
}

// aclListBody 用指定语言渲染 /acl。
//
// 显式给语言而不是吃服务器默认:后者由 NANOTUN_LANG 决定,跟着环境变,断言会随机红。
func aclListBody(t *testing.T, s *Server, lang string) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleACLList(w, withLangCtx(adminGetReq("/acl"), lang))
	if w.Code != http.StatusOK {
		t.Fatalf("[%s] GET /acl code=%d body=%q, 期望 200", lang, w.Code, trimForLog(w.Body.String()))
	}
	return w.Body.String()
}

// forEachLang 对两种语言各跑一遍,并把该语言的关键短语交给用例。
func forEachLang(t *testing.T, fn func(t *testing.T, lang string, p aclPhrases)) {
	t.Helper()
	for _, lang := range []string{LangZH, LangEN} {
		p, ok := aclPhrasesByLang[lang]
		if !ok {
			t.Fatalf("测试自己漏了 %s 的短语表", lang)
		}
		t.Run(lang, func(t *testing.T) { fn(t, lang, p) })
	}
}

// 出厂状态(key 不存在)= allow。页面必须说「默认互通」,而不是留空让人自己猜。
func TestACLList_UnsetDefaultActionRendersAsAllow(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		s := aclGuardServer(t)
		body := aclListBody(t, s, lang)

		if !strings.Contains(body, p.label) {
			t.Fatalf("没有渲染兜底动作那一行, body=%q", trimForLog(body))
		}
		if !strings.Contains(body, p.allowNote) {
			t.Errorf("key 不存在时应显示 allow 语义, body=%q", trimForLog(body))
		}
		if strings.Contains(body, p.denyNote) {
			t.Errorf("未设置时不该显示 deny 语义, body=%q", trimForLog(body))
		}
	})
}

// 翻成 deny 后,同一张空表的含义正好相反:一条规则都没加 = 跨用户与出口流量全拒。
// 老文案写死了「系统当前对所有源 → 所有目的放行」,在 deny 下是把现场说反了 ——
// 而这正是最容易让人困惑的状态(「我一条规则都没加,怎么全断了」)。
func TestACLList_DenyFlipsTheMeaningOfAnEmptyRuleSet(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		s := aclGuardServer(t)
		if err := s.store.SettingsSet(t.Context(), "acl_default_action", "deny"); err != nil {
			t.Fatalf("SettingsSet deny: %v", err)
		}
		body := aclListBody(t, s, lang)

		if !strings.Contains(body, p.denyNote) {
			t.Errorf("deny 时应显示白名单语义, body=%q", trimForLog(body))
		}
		if !strings.Contains(body, p.noneDeny) {
			t.Errorf("空规则集 + deny 应说明当前是全拒, body=%q", trimForLog(body))
		}
		if strings.Contains(body, p.noneAllow) {
			t.Errorf("deny 下仍在说「全放行」,把现场说反了, body=%q", trimForLog(body))
		}
	})
}

// 大小写与空白不敏感,和数据面 readSettings / CLI 校验的归一化保持一致。
func TestACLList_DefaultActionNormalizationMatchesDataPlane(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		for _, raw := range []string{"DENY", "Deny", "  deny  ", "\tdeny\n"} {
			s := aclGuardServer(t)
			setACLDefaultActionRaw(t, s, raw)
			if body := aclListBody(t, s, lang); !strings.Contains(body, p.denyNote) {
				t.Errorf("%q 应被归一成 deny, body=%q", raw, trimForLog(body))
			}
		}
		for _, raw := range []string{"ALLOW", "  allow "} {
			s := aclGuardServer(t)
			setACLDefaultActionRaw(t, s, raw)
			if body := aclListBody(t, s, lang); !strings.Contains(body, p.allowNote) {
				t.Errorf("%q 应被归一成 allow, body=%q", raw, trimForLog(body))
			}
		}
	})
}

// 拼错值:数据面 fail-closed 当 deny,页面也必须显示 deny——但光显示裁决结果不够,
// 还要把原始值回显出来。否则运维看到 badge 是 deny,而他记得自己设的是 allow,
// 从页面上永远看不出「库里躺着一个 alow」。
func TestACLList_TypoedDefaultActionShowsDenyAndEchoesTheRawValue(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		s := aclGuardServer(t)
		setACLDefaultActionRaw(t, s, "alow")
		body := aclListBody(t, s, lang)

		if !strings.Contains(body, p.denyNote) {
			t.Errorf("无法识别的值应按 deny 展示(与数据面 fail-closed 一致), body=%q", trimForLog(body))
		}
		if !strings.Contains(body, "alow") {
			t.Fatalf("原始值没有回显,运维无从发现拼错, body=%q", trimForLog(body))
		}
		if !strings.Contains(body, p.rawWarn) {
			t.Errorf("应当解释这个值为什么被当成 deny, body=%q", trimForLog(body))
		}
	})
}

// 读设置失败时**不猜值**:说 allow 会让人以为网是通的,说 deny 会引发一次无谓的
// 排查。同时规则列表本身来自 acl_pairs,读得到就照常列 —— 不能因为一行补充信息
// 拿不到就把整页打成 500,那会在数据库局部异常时连规则都看不见。
//
// 这是与 /settings 页(读不出来直接 500)有意不同的取舍:那一页的全部内容就是
// 设置表,空表等于谎报;这一页设置只是顶部一行。
func TestACLList_UnreadableDefaultActionDoesNotGuessAndKeepsListingRules(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		s := aclGuardServer(t)
		form := aclForm(t, s, "keep-src", "keep-dst")
		w := httptest.NewRecorder()
		s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("前置建规则失败: code=%d body=%q", w.Code, trimForLog(w.Body.String()))
		}

		breakAppSettingsTable(t, s)
		body := aclListBody(t, s, lang)

		if !strings.Contains(body, p.unknown) {
			t.Errorf("读不到时应显式说读取失败, body=%q", trimForLog(body))
		}
		for _, guess := range []string{p.allowNote, p.denyNote} {
			if strings.Contains(body, guess) {
				t.Errorf("读失败却猜了一个方向(%q), body=%q", guess, trimForLog(body))
			}
		}
		if !strings.Contains(body, "keep-src") {
			t.Errorf("规则列表应当照常渲染, body=%q", trimForLog(body))
		}
	})
}

// 控制台**不提供**修改入口:这一项一翻就是瞬间全网通断,下拉框手滑的代价太大。
// 页面只能给出命令行办法。这条用例同时钉住「别哪天顺手加个表单」。
func TestACLList_DefaultActionIsReadOnlyAndPointsAtTheCLI(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		s := aclGuardServer(t)
		body := aclListBody(t, s, lang)

		if !strings.Contains(body, "nanotun-admin setting set acl_default_action") {
			t.Errorf("应当给出命令行改法, body=%q", trimForLog(body))
		}
		if !strings.Contains(body, p.readOnly) {
			t.Errorf("应当说明这一项控制台改不了, body=%q", trimForLog(body))
		}
		// 页面上不该出现任何指向 acl_default_action 的提交入口。
		for _, forbidden := range []string{
			`name="acl_default_action"`,
			`action="/settings/acl-default-action"`,
		} {
			if strings.Contains(body, forbidden) {
				t.Errorf("列表页出现了修改入口 %q —— 这一项应保持只读", forbidden)
			}
		}
	})
}
