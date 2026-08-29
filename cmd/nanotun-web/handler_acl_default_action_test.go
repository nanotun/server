package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
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
	label       string // 兜底动作那一行的引导语
	allowNote   string // allow 语义
	denyNote    string // deny(白名单)语义
	unknown     string // 读取失败
	noneAllow   string // 空规则集 + allow
	noneDeny    string // 空规则集 + deny
	noneUnfk    string // 空规则集 + 读不到兜底动作
	rawWarn     string // 值拼错时的解释
	readOnly    string // 「控制台只读」
	exitNote    string // deny 语义里「出口是独立一类」那半句
	kindHint    string // /acl/new「目标类型」旁边的两套规则集提示
	exitBlocked string // 路由页「ACL 把出口全拦了」横幅
}

var aclPhrasesByLang = map[string]aclPhrases{
	LangZH: {
		label:       "没命中任何规则时",
		allowNote:   "跨用户互访和出公网默认都通",
		denyNote:    "白名单",
		unknown:     "读取失败",
		noneAllow:   "所有源 → 所有目的放行",
		noneDeny:    "全部被拒",
		noneUnfk:    "没法从这里判断",
		rawWarn:     "既不是 allow 也不是 deny",
		readOnly:    "控制台只读",
		exitNote:    "出公网是独立的一类",
		kindHint:    "这是两套互不相干的规则集",
		exitBlocked: "ACL 正在拦掉所有出公网流量",
	},
	LangEN: {
		label:       "When no rule matches",
		allowNote:   "cross-user traffic and internet egress are both allowed by default",
		denyNote:    "whitelist",
		unknown:     "read failed",
		noneAllow:   "allows all sources",
		noneDeny:    "all cross-user traffic and all exit traffic is currently refused",
		noneUnfk:    "cannot tell you whether that traffic flows",
		rawWarn:     "neither allow nor deny",
		readOnly:    "read-only",
		exitNote:    "Internet egress is a separate class",
		kindHint:    "two unrelated rule sets",
		exitBlocked: "ACL is dropping all internet egress",
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

// 读失败 + 一条规则都没有:这一屏不能自相矛盾。
//
// 曾经就是:顶上 badge 显示「读取失败」,而表格里的空行照旧写着「所有源 → 所有目的放行」——
// 空行分支只判了 deny,读失败时 Action 是空串,于是落进 else 走了 allow 那句文案。
// 页面同时说着「我不知道」和「全放行」,后半句还正好是最危险的那个方向。
func TestACLList_UnreadableDefaultActionDoesNotClaimAllOpenOnTheEmptyTable(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		s := aclGuardServer(t)
		breakAppSettingsTable(t, s) // 一条规则都不建,走空表分支
		body := aclListBody(t, s, lang)

		if !strings.Contains(body, p.unknown) {
			t.Errorf("顶上应显示读取失败, body=%q", trimForLog(body))
		}
		if strings.Contains(body, p.noneAllow) {
			t.Fatalf("读不到兜底动作,空表却宣称全放行 —— 同一屏自相矛盾, body=%q", trimForLog(body))
		}
		if strings.Contains(body, p.noneDeny) {
			t.Errorf("读不到却断言全拒,方向同样是猜的, body=%q", trimForLog(body))
		}
		if !strings.Contains(body, p.noneUnfk) {
			t.Errorf("空表应说明「判断不了」并给出查证办法, body=%q", trimForLog(body))
		}
	})
}

// deny 文案必须讲明「出口是独立一类」。
//
// exit 与 user 是两套规则集:只加 user→user 的 allow 解不开出公网(nanotund 侧由
// TestACLDropPacketDirected_UserRulesDoNotUnlockExit 钉住)。只说「显式 allow 的才通」
// 会让人把互访规则配满,然后发现谁都上不了网,而列表上没有一行跟出口有关。
func TestACLList_DenyNoteSaysExitIsASeparateClass(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		s := aclGuardServer(t)
		if err := s.store.SettingsSet(t.Context(), "acl_default_action", "deny"); err != nil {
			t.Fatalf("SettingsSet deny: %v", err)
		}
		if body := aclListBody(t, s, lang); !strings.Contains(body, p.exitNote) {
			t.Errorf("deny 文案没讲出口是独立一类,等于在教人踩坑, body=%q", trimForLog(body))
		}
	})
}

// /acl/new 的说明必须用**实时值**,不能写死出厂默认。
//
// 此前那句写着「出厂值是 allow,也就是默认互通」。已经翻成 deny 的部署打开这一页,
// 读到的是与现场相反的结论 —— 而这一页恰恰是人要来加规则的地方,判断反了就会
// 按错误前提配策略。
func TestACLNew_IntroFollowsTheLiveDefaultAction(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		newBody := func(s *Server) string {
			t.Helper()
			w := httptest.NewRecorder()
			s.handleACLNew(w, withLangCtx(adminGetReq("/acl/new"), lang))
			if w.Code != http.StatusOK {
				t.Fatalf("GET /acl/new code=%d body=%q", w.Code, trimForLog(w.Body.String()))
			}
			return w.Body.String()
		}

		t.Run("未设置时说 allow", func(t *testing.T) {
			body := newBody(aclGuardServer(t))
			if !strings.Contains(body, p.allowNote) {
				t.Errorf("没按实时值渲染 allow 语义, body=%q", trimForLog(body))
			}
			if strings.Contains(body, p.denyNote) {
				t.Errorf("allow 状态却显示 deny 语义, body=%q", trimForLog(body))
			}
		})

		t.Run("翻成 deny 后跟着变", func(t *testing.T) {
			s := aclGuardServer(t)
			if err := s.store.SettingsSet(t.Context(), "acl_default_action", "deny"); err != nil {
				t.Fatalf("SettingsSet deny: %v", err)
			}
			body := newBody(s)
			if !strings.Contains(body, p.denyNote) {
				t.Errorf("已是 deny,页面还没跟上, body=%q", trimForLog(body))
			}
			if strings.Contains(body, p.allowNote) {
				t.Fatalf("deny 部署上仍在说默认互通 —— 正是要修掉的那句, body=%q", trimForLog(body))
			}
		})

		// 「目标类型」是这一页最容易配错的一格:选 user 配不出上网权限。
		t.Run("提示出口与 user 是两套规则集", func(t *testing.T) {
			if body := newBody(aclGuardServer(t)); !strings.Contains(body, p.kindHint) {
				t.Errorf("目标类型旁边没提示两套规则集互不相干, body=%q", trimForLog(body))
			}
		})
	})
}

// 路由页:ACL 把出口整体拦住时要说一声。
//
// default=deny 且没有 kind=exit 的放行规则时,批准哪台设备做出口都不通 —— 而路由页
// 本身会显示得像已经生效。缺这条提示时,现象是「批了出口还是上不了网」,人会去查
// 设备、平台、固定 IP,查不到 ACL 上。
func TestRouteList_WarnsWhenACLBlocksAllExitTraffic(t *testing.T) {
	forEachLang(t, func(t *testing.T, lang string, p aclPhrases) {
		routesBody := func(s *Server) string {
			t.Helper()
			w := httptest.NewRecorder()
			s.handleRouteList(w, withLangCtx(adminGetReq("/routes"), lang))
			if w.Code != http.StatusOK {
				t.Fatalf("GET /routes code=%d body=%q", w.Code, trimForLog(w.Body.String()))
			}
			return w.Body.String()
		}

		t.Run("default=allow 不该吓人", func(t *testing.T) {
			if body := routesBody(aclGuardServer(t)); strings.Contains(body, p.exitBlocked) {
				t.Errorf("ACL 其实是通的,却挂了「出口全断」横幅, body=%q", trimForLog(body))
			}
		})

		t.Run("deny 且无出口放行 → 警告", func(t *testing.T) {
			s := aclGuardServer(t)
			if err := s.store.SettingsSet(t.Context(), "acl_default_action", "deny"); err != nil {
				t.Fatalf("SettingsSet deny: %v", err)
			}
			if body := routesBody(s); !strings.Contains(body, p.exitBlocked) {
				t.Errorf("出口被 ACL 全拦却没提示, body=%q", trimForLog(body))
			}
		})

		t.Run("user 类放行不算解开出口", func(t *testing.T) {
			s := aclGuardServer(t)
			if err := s.store.SettingsSet(t.Context(), "acl_default_action", "deny"); err != nil {
				t.Fatalf("SettingsSet deny: %v", err)
			}
			// 配一条 user→user 的 allow:数据面上这解不开出公网,警告必须还在。
			form := aclForm(t, s, "ex-src", "ex-dst")
			form.Set("action", "allow")
			w := httptest.NewRecorder()
			s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
			if w.Code != http.StatusSeeOther {
				t.Fatalf("建 user allow 规则失败: code=%d", w.Code)
			}
			if body := routesBody(s); !strings.Contains(body, p.exitBlocked) {
				t.Errorf("只加了 user 类放行,出口仍是断的,警告不该消失, body=%q", trimForLog(body))
			}
		})

		t.Run("补上出口放行后撤掉警告", func(t *testing.T) {
			s := aclGuardServer(t)
			if err := s.store.SettingsSet(t.Context(), "acl_default_action", "deny"); err != nil {
				t.Fatalf("SettingsSet deny: %v", err)
			}
			u := newPRGTestUser(t, s, "exit-ok")
			if _, err := s.store.AddACLPair(t.Context(), store.NewACLPair{
				SrcUserID: u.ID, Action: store.ACLAllow, DstKind: store.ACLDstKindExit,
			}); err != nil {
				t.Fatalf("建 exit allow 规则: %v", err)
			}
			if body := routesBody(s); strings.Contains(body, p.exitBlocked) {
				t.Errorf("已有 kind=exit 的放行规则,警告应当撤掉, body=%q", trimForLog(body))
			}
		})
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
