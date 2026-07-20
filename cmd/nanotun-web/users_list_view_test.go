package main

// users_list_view_test.go(第三轮深扫 P2-5):
//
// `templates/users_list.html` 的 `?show_disabled=1` 模板分支 + DISABLED badge +
// opacity 降级三段 UI 是 0013 credentials 解耦后 P1 加进来的,但既没有 admin
// CLI 端那种 `TestUserCRUDFlow` 级别的回归保护,也没有模板编译时验证。
//
// 这就意味着:`userView` 字段名将来重命名(`DisabledAt → DisabledUnix`),或者
// handler 不再传 `ShowDisabled`,只有在 production 切换 toggle 时才会 panic / 渲染空白。
// 这个测试用真实 production 模板(`templatesFS` embed),三种状态喂数据,断言:
//
//   1. ShowDisabled=false → 顶栏出现「显示禁用」链接,disabled 用户 row 出现且打 badge;
//   2. ShowDisabled=true  → 顶栏出现「仅活跃」链接(toggle 反转);
//   3. CredentialID 短截显示 + tooltip 全 UUID,空时显示 "(未生成)"。

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// renderUsersList 调真实 loadTemplates() 出来的 *template.Template,
// 直接 ExecuteTemplate("users_list.html") 同 production 一致。
func renderUsersList(t *testing.T, users []*store.User, showDisabled bool) string {
	t.Helper()
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	clone, err := tmpl.Clone()
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	// 模板里 .Admin.Role / .Nav.Active 都有引用,layout 也读 .Admin.Username。
	// 喂一个最小化 admin context — 角色 admin 才能看到「+ 新建用户」按钮。
	data := PageData{
		Title: "用户管理",
		Admin: &store.WebAdmin{ID: 1, Username: "tester", Role: "admin", Enabled: true},
		Data: map[string]any{
			"Users":        users,
			"ShowDisabled": showDisabled,
		},
		Nav: NavContext{Active: "users", Version: "test", ServerHost: "host", MeshEnabled: true},
	}
	var buf bytes.Buffer
	if err := clone.ExecuteTemplate(&buf, "users_list.html", data); err != nil {
		t.Fatalf("ExecuteTemplate: %v", err)
	}
	return buf.String()
}

// TestUsersListView_ShowDisabledToggle:show_disabled true / false 两种状态下
// 顶栏 toggle 链接文案与目标 URL 必须互为反向,这是 UI 上"我能不能切回去"的
// 唯一保证。任一被模板字段名重构碰掉都会立刻反映在断言失败上。
func TestUsersListView_ShowDisabledToggle(t *testing.T) {
	users := []*store.User{
		{ID: 1, Username: "alice", IsAdmin: true, ExitAllowed: true,
			DisabledAt: 0, CredentialID: "0d4b1c4e-3a2f-4f7e-9c8d-12345678abcd", CreatedAt: 1700000000},
	}

	htmlOff := renderUsersList(t, users, false)
	if !strings.Contains(htmlOff, `href="/users?show_disabled=1"`) {
		t.Errorf("show_disabled=false 应展示「显示禁用」toggle,但没找到 href=/users?show_disabled=1\n%s", htmlOff)
	}
	if strings.Contains(htmlOff, `href="/users"`) && strings.Contains(htmlOff, "仅活跃") {
		// 反向 toggle 不该出现
		t.Errorf("show_disabled=false 不应同时展示「仅活跃」toggle\n%s", htmlOff)
	}

	htmlOn := renderUsersList(t, users, true)
	// "仅活跃" toggle 必须存在且 href 是裸 /users
	if !strings.Contains(htmlOn, "仅活跃") {
		t.Errorf("show_disabled=true 应展示「仅活跃」toggle 链接\n%s", htmlOn)
	}
	if strings.Contains(htmlOn, `href="/users?show_disabled=1"`) {
		t.Errorf("show_disabled=true 不应继续展示「显示禁用」toggle\n%s", htmlOn)
	}
}

// TestUsersListView_DisabledBadgeAndOpacity:disabled 用户必须:
// 1) <tr> 有 opacity:.5(灰化);
// 2) 状态列出 `badge warn` "disabled";
// 3) enabled 用户的 row 不灰化,badge 显示 "enabled"。
func TestUsersListView_DisabledBadgeAndOpacity(t *testing.T) {
	users := []*store.User{
		{ID: 1, Username: "alive", DisabledAt: 0, CreatedAt: 1700000000},
		{ID: 2, Username: "ghost", DisabledAt: 1700000099, CreatedAt: 1700000000},
	}
	html := renderUsersList(t, users, true)

	if !strings.Contains(html, `opacity:.5`) {
		t.Errorf("disabled 用户 row 应灰化,但没找到 opacity:.5\n%s", html)
	}
	if !strings.Contains(html, `>disabled<`) {
		t.Errorf("disabled badge 文案缺失\n%s", html)
	}
	if !strings.Contains(html, `>enabled<`) {
		t.Errorf("enabled badge 文案缺失(alive 用户)\n%s", html)
	}
	if !strings.Contains(html, ">alive<") || !strings.Contains(html, ">ghost<") {
		t.Errorf("两个用户名都应出现\n%s", html)
	}
}

// TestUsersListView_CredentialIDDisplay:CredentialID 非空时短截 8 字符 + tooltip
// 显示完整 UUID;为空时显示 "(未生成)"。这是 0013 后用户能看到的 cred 状态信号。
func TestUsersListView_CredentialIDDisplay(t *testing.T) {
	fullID := "0d4b1c4e-3a2f-4f7e-9c8d-12345678abcd"
	users := []*store.User{
		{ID: 1, Username: "withcred", CredentialID: fullID, CreatedAt: 1700000000},
		{ID: 2, Username: "nocred", CredentialID: "", CreatedAt: 1700000000},
	}
	html := renderUsersList(t, users, false)

	// 短截:`{{slice .CredentialID 0 8}}…` → "0d4b1c4e…",并带 title 全 UUID。
	if !strings.Contains(html, "0d4b1c4e") {
		t.Errorf("CredentialID 短截前缀应出现\n%s", html)
	}
	if !strings.Contains(html, `title="`+fullID+`"`) {
		t.Errorf("tooltip 应含全 UUID\n%s", html)
	}
	if !strings.Contains(html, "(未生成)") {
		t.Errorf("空 CredentialID 应显示 (未生成)\n%s", html)
	}
}
