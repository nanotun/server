package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// audit_list_view_test.go(2026-07-19 易用性改版):
//
// 深扫回归保护:审计页快捷预设链接的过滤条件透传曾经踩过 html/template 的
// 双重转义坑 —— handler 预拼整段 "&actor=..." 塞进 href 的 query 位置,模板把
// `&`/`=` 也百分号转义,整段变成 range 参数的一部分,过滤条件静默丢失且 range
// 解析失败回落默认 7 天。修法是模板里字面拼 `&actor={{.Actor}}`(只有值走
// component 转义)。这个测试用真实模板渲染断言:
//
//  1. 预设链接保留 actor/action 条件,`&` 渲染为 HTML 实体 `&amp;`(浏览器
//     解码后是合法 query 分隔符),而**不是** `%26`(会吞进前一个参数的值);
//  2. 分页 prev/next 链接(handler 拼好的整 URL)原样可用;
//  3. datetime-local 输入框 value 正确回填。
func renderAuditList(t *testing.T, data map[string]any) string {
	t.Helper()
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	clone, err := tmpl.Clone()
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	pd := PageData{
		Title: "审计日志",
		Admin: &store.WebAdmin{ID: 1, Username: "tester", Role: "admin", Enabled: true},
		Data:  data,
		Nav:   NavContext{Active: "audit", Version: "test", ServerHost: "host", MeshEnabled: true},
	}
	var buf bytes.Buffer
	if err := clone.ExecuteTemplate(&buf, "audit_list.html", pd); err != nil {
		t.Fatalf("ExecuteTemplate: %v", err)
	}
	return buf.String()
}

func TestAuditListView_PresetLinksKeepFilters(t *testing.T) {
	html := renderAuditList(t, map[string]any{
		"Logs":       nil,
		"SinceStr":   "2026-07-12T16:00",
		"UntilStr":   "2026-07-19T16:00",
		"Limit":      200,
		"Offset":     0,
		"Actor":      "web:root",
		"Action":     "user_",
		"Range":      "24h",
		"PrevURL":    "",
		"NextURL":    "/audit?actor=web%3Aroot&offset=200&since=100&until=200",
		"LimitParam": "500",
		"ShownFrom":  1,
		"ShownTo":    0,
	})

	// 预设链接:模板字面 `&` 原样输出(html/template 不动模板作者写的字面文本),
	// 过滤条件保持为独立 query 参数,值走 component 转义(: → %3a)。
	if !strings.Contains(html, `href="/audit?range=1h&actor=web%3aroot&action=user_&limit=500"`) {
		t.Errorf("预设链接应携带 actor/action/limit 过滤条件\n%s", html)
	}
	// 双重转义回归探测:%26 意味着 & 被当作 range 值的一部分转义,过滤条件丢失。
	if strings.Contains(html, `%26actor`) || strings.Contains(html, `%26action`) {
		t.Errorf("预设链接出现 %%26(& 被二次转义),过滤条件会静默丢失\n%s", html)
	}

	// 分页链接:handler 拼好的整 URL,& 渲染为 &amp; 即可,不能被拆坏。
	if !strings.Contains(html, `href="/audit?actor=web%3Aroot&amp;offset=200&amp;since=100&amp;until=200"`) {
		t.Errorf("下一页链接应原样渲染(& → &amp;)\n%s", html)
	}

	// datetime-local 回填。
	if !strings.Contains(html, `value="2026-07-12T16:00"`) || !strings.Contains(html, `value="2026-07-19T16:00"`) {
		t.Errorf("since/until 输入框应回填 datetime-local 值\n%s", html)
	}
	// 当前激活的预设(24h)链接同样保留条件。
	if !strings.Contains(html, `href="/audit?range=24h&actor=web%3aroot`) {
		t.Errorf("24h 预设链接缺失\n%s", html)
	}
}

func TestAuditListView_NoFiltersNoPagination(t *testing.T) {
	html := renderAuditList(t, map[string]any{
		"Logs":       nil,
		"SinceStr":   "",
		"UntilStr":   "",
		"Limit":      200,
		"Offset":     0,
		"Actor":      "",
		"Action":     "",
		"Range":      "",
		"PrevURL":    "",
		"NextURL":    "",
		"LimitParam": "",
		"ShownFrom":  1,
		"ShownTo":    0,
	})
	// 无过滤条件时预设链接是干净的 ?range=xx。
	if !strings.Contains(html, `href="/audit?range=7d"`) {
		t.Errorf("无过滤时预设链接应为裸 ?range=7d\n%s", html)
	}
	// 无上一页/下一页时不渲染分页条。
	if strings.Contains(html, "上一页") || strings.Contains(html, "下一页") {
		t.Errorf("PrevURL/NextURL 为空时不应渲染分页链接\n%s", html)
	}
}
