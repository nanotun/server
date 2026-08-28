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

// 状态徽标必须走 i18n,不许在模板里写死。
//
// 2026-08-28 之前有十来处写死的英文徽标(enabled / disabled / locked / allow / deny /
// approved / pending / ON / OFF / OK / DOWN)。它们不报错、不崩,只是中文界面上突然冒出
// 一串英文 —— 而这些恰恰是「这条记录现在什么状态」的唯一视觉线索,看不懂就只能猜。
//
// 判据取形态而不是列黑名单:徽标里的内容要么是模板动作({{T ...}} / {{.Field}}),要么就是
// 写死的字面量。这样以后新加一个徽标忘了翻译,不必等谁想起来去看中文界面。
//
// 例外:{{.Role}} / {{.Status}} / audit 的 {{.Action}} 这类**原样输出的数据值**不在此列 ——
// 它们是机器名(admin / viewer / snake_case action),两种语言下都该是同一个字符串,翻译
// 反而会让人对不上库里的值。它们本来就是模板动作,不会被这条规则命中。
func TestBadgesAreNotHardcoded(t *testing.T) {
	dir := filepath.Join("templates")
	// 徽标内容里没有 {{ 就是写死的
	hardcoded := regexp.MustCompile(`<span class="badge[^"]*">([^<{]+)</span>`)

	var bad []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range hardcoded.FindAllStringSubmatch(string(b), -1) {
			if strings.TrimSpace(m[1]) == "" {
				continue
			}
			bad = append(bad, path+": "+strings.TrimSpace(m[1]))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历模板失败:%v", err)
	}
	for _, b := range bad {
		t.Errorf("徽标里写死了字面量:%s\n"+
			"  改成 {{T \"...\"}} 并在 i18n_zh.go / i18n_en.go 各加一条 —— "+
			"写死的话另一种语言的界面上会突然冒出一串看不懂的词,而徽标正是状态的唯一线索。", b)
	}
}

// 端到端确认徽标真的跟着语言走。上面那条只保证「形态上走了 T」,这条保证两张目录都填了、
// 且渲染出来确实是两种语言 —— 少填一边时上面那条是绿的,这条会红。
func TestBadgesRenderInBothLanguages(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	users := []*store.User{
		{ID: 1, Username: "alice", IsAdmin: true, DisabledAt: 0, CreatedAt: 1700000000},
		{ID: 2, Username: "bob", IsAdmin: false, DisabledAt: 1700000001, CreatedAt: 1700000000},
	}
	for _, c := range []struct {
		lang    string
		want    []string
		notWant []string
	}{
		{LangZH, []string{"已启用", "已禁用", "管理员"}, []string{">enabled<", ">disabled<"}},
		{LangEN, []string{"Enabled", "Disabled", "Admin"}, []string{"已启用", "已禁用"}},
	} {
		clone, err := tmpl.Clone()
		if err != nil {
			t.Fatal(err)
		}
		clone = clone.Funcs(i18nFuncs(c.lang))
		var buf bytes.Buffer
		data := PageData{
			Lang:  c.lang,
			Title: "t",
			Admin: &store.WebAdmin{ID: 1, Username: "t", Role: "admin", Enabled: true},
			Data:  map[string]any{"Users": users, "ShowDisabled": true},
			Nav:   NavContext{Active: "users", Version: "t", ServerHost: "h", MeshEnabled: true},
		}
		if err := clone.ExecuteTemplate(&buf, "users_list.html", data); err != nil {
			t.Fatalf("[%s] 渲染失败:%v", c.lang, err)
		}
		got := buf.String()
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("[%s] 页面里找不到 %q", c.lang, w)
			}
		}
		for _, n := range c.notWant {
			if strings.Contains(got, n) {
				t.Errorf("[%s] 页面里仍有 %q —— 徽标没跟着语言走", c.lang, n)
			}
		}
	}
}
