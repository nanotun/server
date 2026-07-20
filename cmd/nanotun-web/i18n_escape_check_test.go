package main

import (
	"errors"
	"html/template"
	"io"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// TestCatalogParity 保证 catZH / catEN 的 key 集合完全一致,且 fmt 占位符数量对齐。
//
// 背景:translate() 在目标语言缺 key(!ok)时回落默认(zh)—— 对开发期发现漏翻是
// 好事,但也意味着「en 少一个 key」不会报错,而是**静默把中文漏进英文界面**。这个
// 测试把这类回归变成显式失败。
//
// 不校验「value 非空」:有些 key 的英文值是**有意的空串**(如中文量词后缀 " 条"
// 在英文里省略)。只要 key 在两张表都存在,translate() 就不会回落到中文。
//
// 校验 fmt 占位符数量对齐:某 key 在 zh 用了 "%s" 但 en 漏了(或多了),会导致
// translate() 走 fmt.Sprintf 时出现 %!s(MISSING) / %!(EXTRA ...),同样是 UI bug。
func TestCatalogParity(t *testing.T) {
	for key, zh := range catZH {
		en, ok := catEN[key]
		if !ok {
			t.Errorf("catEN 缺少 key %q(catZH 有:%q)", key, zh)
			continue
		}
		if got, want := countFmtVerbs(en), countFmtVerbs(zh); got != want {
			t.Errorf("key %q 占位符数量不一致:zh=%d en=%d(zh=%q en=%q)", key, want, got, zh, en)
		}
	}
	for key := range catEN {
		if _, ok := catZH[key]; !ok {
			t.Errorf("catZH 缺少 key %q(catEN 有,可能是拼写漂移)", key)
		}
	}
}

// countFmtVerbs 粗略统计 fmt 占位符个数:数 '%' 且下一个字符不是 '%'(转义的 %%)。
func countFmtVerbs(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '%' {
			i++ // 跳过 %% 转义
			continue
		}
		n++
	}
	return n
}

// TestAllTemplatesEscapeSafe 强制触发 html/template 的上下文自动转义静态分析。
//
// 背景:转义分析是**首次 Execute 时惰性**跑的,只覆盖被执行到的模板。i18n 改造
// 把 {{T}} 插进了 <script> / onclick / onsubmit 等 JS 上下文,若某处上下文不明确,
// escapeTemplate 会返回 *template.Error —— 但这只在该页真正被渲染时才暴露,build
// 与只渲染 users_list 的既有测试都盖不到。这里对每个页面模板 clone→bind→Execute
// 一遍(zh/en 各一次),用 errors.As 把「转义错误」和「数据缺失执行错误」区分开:
// 前者是本次改造的真实回归,后者(nil data)预期且忽略。
func TestAllTemplatesEscapeSafe(t *testing.T) {
	for _, lang := range []string{LangZH, LangEN} {
		tmpl, err := loadTemplates()
		if err != nil {
			t.Fatalf("loadTemplates(%s): %v", lang, err)
		}
		for _, tp := range tmpl.Templates() {
			name := tp.Name()
			if !strings.HasSuffix(name, ".html") || strings.HasPrefix(name, "partials/") {
				continue
			}
			clone, err := tmpl.Clone()
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			clone = clone.Funcs(i18nFuncs(lang))
			data := PageData{
				Lang:  lang,
				Title: "t",
				Admin: &store.WebAdmin{ID: 1, Username: "tester", Role: "admin", Enabled: true},
				Nav:   NavContext{Active: "dashboard", Version: "test", ServerHost: "host", MeshEnabled: true},
				Data:  map[string]any{},
			}
			err = clone.ExecuteTemplate(io.Discard, name, data)
			if err == nil {
				continue
			}
			// *template.Error = 转义/上下文分析失败(真实回归)。其余(text/template
			// ExecError,nil data 访问)预期忽略。
			var escErr *template.Error
			if errors.As(err, &escErr) {
				t.Errorf("template %q (lang=%s) 转义分析失败: %v", name, lang, err)
			}
		}
	}
}
