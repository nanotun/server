package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 原生表单校验气泡的文案必须由我们提供,不能落回浏览器自带的那句。
//
// 浏览器对 required 字段弹的「请填写此字段。」跟的是**浏览器界面语言**,不是页面的 lang ——
// 于是英文界面上,中文版 Chrome 照样弹中文,整页只有这一个气泡不听话(2026-08-29 用户截图
// 报的就是它)。唯一的办法是在 invalid 事件里 setCustomValidity() 塞进自己的文案。
//
// 这条守卫钉三件事,少一件这个覆盖就是坏的:
//
//	① app.js 里的 invalid 监听必须用**捕获**——该事件不冒泡,挂在 document 上不加 true 收不到;
//	② 必须在 input/change 时清空 —— 自定义文案一旦设上会让字段**一直**被判为非法,
//	   少了这步「填对了也提交不了」,而且现场看不出为什么;
//	③ 文案得真的从模板渲染进 body 的 data-*,两种语言各自不同。
func TestNativeValidationMessagesAreOurs(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("static", "app.js"))
	if err != nil {
		t.Fatalf("读不到 app.js:%v", err)
	}
	js := string(b)

	// 不用「距离窗口」去匹配 —— 窗口大小是个魔数,处理器体一长就在干净代码上误报
	// (写这条时先踩了一次:体长 467 字符,窗口开了 400)。改成截到该监听器的收尾再判。
	inv := strings.Index(js, `addEventListener("invalid"`)
	if inv < 0 {
		t.Fatal("app.js 里找不到 invalid 监听 —— 原生校验气泡会退回浏览器语言")
	}
	end := strings.Index(js[inv:], "});")
	if end < 0 {
		t.Fatal("找不到 invalid 监听的收尾;若写法改了,请同步本守卫")
	}
	if !strings.Contains(js[inv:inv+end+3], ", true)") {
		t.Error("app.js 的 invalid 监听没用捕获(第三个参数 true):\n" +
			"  invalid 事件不冒泡,挂在 document 上收不到 —— 覆盖静默失效,气泡退回浏览器语言。")
	}
	if !strings.Contains(js, "setCustomValidity") {
		t.Error("app.js 里没有 setCustomValidity:那是唯一能改原生气泡文案的入口。")
	}
	for _, ev := range []string{`"input"`, `"change"`} {
		if !regexp.MustCompile(`addEventListener\(\s*` + ev + `\s*,\s*clearValidity`).MatchString(js) {
			t.Errorf("app.js 没有在 %s 时清空自定义校验文案:\n"+
				"  设过之后不清,字段会被永久钉成非法 —— 填对了也提交不了。", ev)
		}
	}

	// 文案确实按语言渲染进 body。
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	re := regexp.MustCompile(`data-msg-required="([^"]*)"`)
	seen := map[string]string{}
	for _, lang := range []string{LangEN, LangZH} {
		clone, err := tmpl.Clone()
		if err != nil {
			t.Fatal(err)
		}
		clone = clone.Funcs(i18nFuncs(lang))
		var buf bytes.Buffer
		data := PageData{
			Lang:  lang,
			Title: "t",
			Admin: &store.WebAdmin{ID: 1, Username: "t", Role: "admin", Enabled: true},
			Data:  map[string]any{"Users": nil, "ShowDisabled": false},
			Nav:   NavContext{Active: "users", Version: "t", ServerHost: "h"},
		}
		if err := clone.ExecuteTemplate(&buf, "users_list.html", data); err != nil {
			t.Fatalf("[%s] 渲染失败:%v", lang, err)
		}
		m := re.FindStringSubmatch(buf.String())
		if m == nil || strings.TrimSpace(m[1]) == "" {
			t.Fatalf("[%s] body 上没有 data-msg-required —— app.js 读不到文案,覆盖不会生效", lang)
		}
		seen[lang] = m[1]
	}
	if seen[LangEN] == seen[LangZH] {
		t.Errorf("两种语言的校验文案一样(%q):有一边没翻译,那一边的气泡会显示另一种语言。",
			seen[LangEN])
	}
}
