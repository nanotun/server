package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 本文件覆盖审计页的时间窗与分页。
//
// 为什么值得单独测:今天刚在 CLI 的 `audit list` 上修过一个同类缺陷 —— QueryAudit
// 的上界是开区间而 at 只精确到秒,endAt 直接取 now 会把「本秒内刚写的记录」整批
// 排除,表现为「改完配置立刻查审计,什么都没有」。web 这边一直是 now+1(对的),
// 但没有任何测试钉住它,谁顺手"清理"掉那个 +1 都不会有人发现。

// newAuditTestServer 造一个带**真实模板**的 Server:审计页要断言渲染结果
// (分页链接、时间回填),空模板跑不起来。
func newAuditTestServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServerMinimal(t)
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	s.tmpl = tmpl
	return s
}

// getAudit 以 admin 身份 GET /audit?<query>,返回渲染出的 HTML。
func getAudit(t *testing.T, s *Server, query string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	target := "/audit"
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	admin := &store.WebAdmin{ID: 1, Username: "tester", Role: "admin", Enabled: true}
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, admin))
	w := httptest.NewRecorder()
	s.handleAuditList(w, req)
	return w, w.Body.String()
}

// writeAudit 同步写一条审计。
func writeAudit(t *testing.T, s *Server, actor, action string) {
	t.Helper()
	s.audit.Write(t.Context(),
		&store.WebAdmin{ID: 1, Username: actor, Role: "admin"}, action, "t/1", "")
}

// =========================================================================
// parseAuditTimeParam / auditRangeSeconds / fmtDatetimeLocal
// =========================================================================

// TestParseAuditTimeParam:同一个字段要同时吃 unix 秒(老书签)与 datetime-local
// 控件值(浏览器表单)。任一种解析挂掉都会静默回落到默认 7 天 —— 用户以为自己在
// 看指定时段,其实看的是别的窗口。
func TestParseAuditTimeParam(t *testing.T) {
	// 用固定时刻算出本地时区下的期望值,避免测试机时区不同就红。
	local := func(s string) int64 {
		tm, err := time.ParseInLocation("2006-01-02T15:04:05", s, time.Local)
		if err != nil {
			t.Fatalf("构造期望值 %q: %v", s, err)
		}
		return tm.Unix()
	}
	for _, c := range []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"   ", 0},
		{"1700000000", 1700000000},
		{"  1700000000  ", 1700000000},
		{"0", 0},
		{"-5", -5}, // ParseInt 收负数;caller 用 ==0 判默认,负值原样透传
		{"2026-01-02T15:04", local("2026-01-02T15:04:00")},
		{"2026-01-02T15:04:05", local("2026-01-02T15:04:05")},
		{"2026-01-02", 0},       // 只有日期,两种 layout 都不匹配
		{"2026-01-02 15:04", 0}, // 空格分隔(非 datetime-local 格式)
		{"not-a-time", 0},
		{"2026-13-45T99:99", 0}, // 数值越界
	} {
		if got := parseAuditTimeParam(c.in); got != c.want {
			t.Errorf("parseAuditTimeParam(%q) = %d, 期望 %d", c.in, got, c.want)
		}
	}
}

// TestAuditRangeSeconds:快捷预设只认这四个 key,其余一律不生效(caller 据 ok
// 决定是否清掉 rangeKey)。多认一个不存在的 key 会让 since 变成 0 = 从纪元查起。
func TestAuditRangeSeconds(t *testing.T) {
	for _, c := range []struct {
		key    string
		want   int64
		wantOK bool
	}{
		{"1h", 3600, true},
		{"24h", 24 * 3600, true},
		{"7d", 7 * 24 * 3600, true},
		{"30d", 30 * 24 * 3600, true},
		{"", 0, false},
		{"1H", 0, false},  // 大小写敏感
		{"60m", 0, false}, // 等价写法也不认
		{"1d", 0, false},
		{"999d", 0, false},
	} {
		got, ok := auditRangeSeconds(c.key)
		if got != c.want || ok != c.wantOK {
			t.Errorf("auditRangeSeconds(%q) = (%d,%v), 期望 (%d,%v)",
				c.key, got, ok, c.want, c.wantOK)
		}
	}
}

// TestFmtDatetimeLocal:0 与负数要渲染成空串,否则表单里会回填出 1970 年。
func TestFmtDatetimeLocal(t *testing.T) {
	if got := fmtDatetimeLocal(0); got != "" {
		t.Errorf("fmtDatetimeLocal(0) = %q, 期望空串", got)
	}
	if got := fmtDatetimeLocal(-1); got != "" {
		t.Errorf("fmtDatetimeLocal(-1) = %q, 期望空串", got)
	}
	want := time.Unix(1700000000, 0).Local().Format("2006-01-02T15:04")
	if got := fmtDatetimeLocal(1700000000); got != want {
		t.Errorf("fmtDatetimeLocal = %q, 期望 %q", got, want)
	}
}

// =========================================================================
// GET /audit
// =========================================================================

// TestAuditList_ShowsEntryWrittenThisSecond:本秒刚写的审计必须能查到。
//
// 这就是今天在 CLI 侧修掉的那个缺陷的 web 版回归:QueryAudit 上界是开区间
// (`at < until`)而 at 只精确到秒,until 取 now 就会把本秒的记录全部排除。
// 运维「改完配置立刻核对审计」是最常见的动作,查不到会让人以为审计根本没记。
func TestAuditList_ShowsEntryWrittenThisSecond(t *testing.T) {
	s := newAuditTestServer(t)
	writeAudit(t, s, "web:root", "zz_just_now_marker")

	w, html := getAudit(t, s, "")
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, 期望 200", w.Code)
	}
	if !strings.Contains(html, "zz_just_now_marker") {
		t.Fatalf("刚写入的审计没出现在默认时间窗里(until 少了 +1?)")
	}
}

// TestAuditList_DefaultWindowIsSevenDays:不带参数时窗口是最近 7 天。
//
// 用「7 天前之外的记录不出现、之内的出现」来验,而不是去读内部变量。
func TestAuditList_DefaultWindowIsSevenDays(t *testing.T) {
	s := newAuditTestServer(t)
	now := time.Now().Unix()
	// 直接插库,绕开 Auditor 的"当前时间"。
	insertAuditAt(t, s, now-8*24*3600, "zz_too_old")
	insertAuditAt(t, s, now-1*24*3600, "zz_in_window")

	_, html := getAudit(t, s, "")
	if strings.Contains(html, "zz_too_old") {
		t.Errorf("8 天前的记录不该出现在默认 7 天窗口里")
	}
	if !strings.Contains(html, "zz_in_window") {
		t.Errorf("1 天前的记录应当出现在默认窗口里")
	}
}

// TestAuditList_RangePresetOverridesWindow:range 预设覆盖 since/until。
func TestAuditList_RangePresetOverridesWindow(t *testing.T) {
	s := newAuditTestServer(t)
	now := time.Now().Unix()
	insertAuditAt(t, s, now-2*3600, "zz_two_hours_ago")
	insertAuditAt(t, s, now-10*60, "zz_ten_min_ago")

	_, html := getAudit(t, s, "range=1h")
	if strings.Contains(html, "zz_two_hours_ago") {
		t.Errorf("range=1h 不该包含 2 小时前的记录")
	}
	if !strings.Contains(html, "zz_ten_min_ago") {
		t.Errorf("range=1h 应包含 10 分钟前的记录")
	}

	// range 优先于显式 since:同时给两者时以 range 为准(handler 先算 since 再被 range 覆盖)。
	_, html = getAudit(t, s, fmt.Sprintf("range=1h&since=%d", now-24*3600))
	if strings.Contains(html, "zz_two_hours_ago") {
		t.Errorf("range 应覆盖显式 since,2 小时前的记录不该出现")
	}
}

// TestAuditList_UnknownRangeFallsBackToDefault:无法识别的 range 要被丢弃,
// 而不是让 since 保持 0(= 从 1970 年查起,把 10000 条上限吃满)。
func TestAuditList_UnknownRangeFallsBackToDefault(t *testing.T) {
	s := newAuditTestServer(t)
	now := time.Now().Unix()
	insertAuditAt(t, s, now-8*24*3600, "zz_too_old")
	insertAuditAt(t, s, now-60, "zz_recent")

	_, html := getAudit(t, s, "range=bogus")
	if strings.Contains(html, "zz_too_old") {
		t.Errorf("未知 range 应回落默认 7 天,8 天前的记录不该出现")
	}
	if !strings.Contains(html, "zz_recent") {
		t.Errorf("未知 range 回落后近期记录仍应出现")
	}
}

// TestAuditList_LimitIsClamped:limit 必须被钳在 (0,1000],否则一个
// `?limit=999999999` 就能让服务端一次性捞出全部审计行做渲染。
func TestAuditList_LimitIsClamped(t *testing.T) {
	s := newAuditTestServer(t)
	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		insertAuditAt(t, s, now-int64(i)-1, fmt.Sprintf("zz_row_%d", i))
	}

	for _, q := range []string{"limit=0", "limit=-1", "limit=99999999", "limit=abc"} {
		w, html := getAudit(t, s, q)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: code=%d, 期望 200", q, w.Code)
		}
		// 钳到默认 200 后,5 条记录应当全部显示。
		for i := 0; i < 5; i++ {
			if !strings.Contains(html, fmt.Sprintf("zz_row_%d", i)) {
				t.Errorf("%s: 缺少 zz_row_%d(limit 未被正确钳制?)", q, i)
			}
		}
	}
}

// TestAuditList_Pagination:分页要能翻,且「下一页」链接必须把时间窗**冻结**成
// 显式 unix 值、剥掉 range。
//
// 不冻结的话,翻页瞬间新写入的审计行会把窗口整体推移,第二页会重复出现第一页
// 已经看过的行 —— 审计场景里这种重复最容易让人漏读。
func TestAuditList_Pagination(t *testing.T) {
	s := newAuditTestServer(t)
	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		insertAuditAt(t, s, now-int64(i)-1, fmt.Sprintf("zz_page_%d", i))
	}

	_, html := getAudit(t, s, "range=24h&limit=2")
	if !strings.Contains(html, "offset=2") {
		t.Fatalf("共 5 条、每页 2 条,应有下一页链接(offset=2)\n%s", trimForLog(html))
	}
	// 冻结:next 链接里必须出现显式 since/until,且不带 range。
	if !strings.Contains(html, "since=") || !strings.Contains(html, "until=") {
		t.Errorf("下一页链接未冻结时间窗(缺 since/until)")
	}
	if strings.Contains(html, "offset=2&amp;range=") || strings.Contains(html, "range=24h&amp;offset=2") {
		t.Errorf("下一页链接不该继续带 range(会随时间漂移)")
	}

	// 第二页内容与第一页不重叠。
	_, page1 := getAudit(t, s, "range=24h&limit=2&offset=0")
	_, page2 := getAudit(t, s, "range=24h&limit=2&offset=2")
	for i := 0; i < 5; i++ {
		row := fmt.Sprintf("zz_page_%d", i)
		if strings.Contains(page1, row) && strings.Contains(page2, row) {
			t.Errorf("%s 同时出现在第一页和第二页", row)
		}
	}
}

// TestAuditList_OffsetBeyondEndIsEmptyNotError:offset 超出总数只应是空列表。
func TestAuditList_OffsetBeyondEndIsEmptyNotError(t *testing.T) {
	s := newAuditTestServer(t)
	writeAudit(t, s, "web:root", "zz_only_row")

	w, html := getAudit(t, s, "offset=9999")
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, 期望 200", w.Code)
	}
	if strings.Contains(html, "zz_only_row") {
		t.Errorf("offset 越界还显示了记录")
	}
	// 负 offset 被钳成 0,记录应当出现。
	if _, html = getAudit(t, s, "offset=-5"); !strings.Contains(html, "zz_only_row") {
		t.Errorf("负 offset 应钳成 0 并正常显示")
	}
}

// TestAuditList_ActorAndActionFilters:actor / action 是子串过滤。
func TestAuditList_ActorAndActionFilters(t *testing.T) {
	s := newAuditTestServer(t)
	writeAudit(t, s, "web:alice", "zz_user_create")
	writeAudit(t, s, "web:bob", "zz_device_delete")

	_, html := getAudit(t, s, "actor=alice")
	if !strings.Contains(html, "zz_user_create") || strings.Contains(html, "zz_device_delete") {
		t.Errorf("actor 过滤没生效")
	}
	_, html = getAudit(t, s, "action=device")
	if strings.Contains(html, "zz_user_create") || !strings.Contains(html, "zz_device_delete") {
		t.Errorf("action 过滤没生效")
	}
	// 两个条件同时给 = 与关系。
	_, html = getAudit(t, s, "actor=alice&action=device")
	if strings.Contains(html, "zz_user_create") || strings.Contains(html, "zz_device_delete") {
		t.Errorf("actor+action 应是与关系,不该有命中")
	}
}

// TestAuditList_RejectsNonGET:审计页是只读页,写方法一律 405。
func TestAuditList_RejectsNonGET(t *testing.T) {
	s := newAuditTestServer(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/audit", nil)
		admin := &store.WebAdmin{ID: 1, Username: "tester", Role: "admin", Enabled: true}
		req = req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, admin))
		w := httptest.NewRecorder()
		s.handleAuditList(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /audit code=%d, 期望 405", m, w.Code)
		}
	}
}

// TestAuditList_ViewerIsRejected:审计含用户名 / IP / 改密重置等敏感明细,仅 admin 可读。
//
// e2e 也断言了 viewer 拿 403,这里再钉一遍是因为 handler 内部这道 requireAdminRole
// 与中间件是两道独立的闸 —— 中间件那道放行只读页,这道才是审计专属的。
func TestAuditList_ViewerIsRejected(t *testing.T) {
	s := newAuditTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	viewer := &store.WebAdmin{ID: 2, Username: "v", Role: "viewer", Enabled: true}
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, viewer))
	w := httptest.NewRecorder()
	s.handleAuditList(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer 读审计 code=%d, 期望 403", w.Code)
	}
}

// insertAuditAt 按指定时间戳插一条审计行(Auditor 只会写"现在",构造历史数据得直插)。
func insertAuditAt(t *testing.T, s *Server, at int64, action string) {
	t.Helper()
	_, err := s.store.DB().ExecContext(t.Context(),
		`INSERT INTO audit_logs (at, actor, action, target, detail) VALUES (?,?,?,?,?)`,
		at, "web:root", action, "t/1", "")
	if err != nil {
		t.Fatalf("插入审计行 %s@%d: %v", action, at, err)
	}
}

// trimForLog 截断 HTML,失败输出不至于刷屏。
func trimForLog(s string) string {
	if len(s) > 1500 {
		return s[:1500] + "…(截断)"
	}
	return s
}
