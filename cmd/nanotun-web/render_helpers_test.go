package main

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 本文件收尾 render.go / view_sessions.go / control_client.go 里剩下的零覆盖函数。
//
// 它们大多是模板函数 —— 在 .html 里以 {{fmtBytes .N}} 的形式被调用,编译器管不着。
// 传错类型、算错单位、除零,统统要等到 admin 打开页面才现形,而且现形方式是
// 半张空白页(html/template 遇到 panic 会截断输出)。

// -------------------------------------------------------------------------
// renderStoreWriteErr:TOCTOU 窗口里的写失败该显示成什么
// -------------------------------------------------------------------------

// TestRenderStoreWriteErr_NotFoundIs404 覆盖「先 Get 校验存在,再写」这条路径上
// 那条窄窗口:两步之间该行被别人删了,写操作返回 ErrNotFound。这不是服务器故障,
// 是并发,应该告诉 admin「没了」而不是甩一个 500。
func TestRenderStoreWriteErr_NotFoundIs404(t *testing.T) {
	s := newMeTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/1/disable", nil)

	s.renderStoreWriteErr(w, r, fmt.Errorf("wrap: %w", store.ErrNotFound),
		"err.userNotFound", "err.userDisableFailed")

	if w.Code != http.StatusNotFound {
		t.Fatalf("code=%d, 期望 404", w.Code)
	}
}

// TestRenderStoreWriteErr_OtherErrorsStayOpaque 锁死第三轮深扫 L4:错误详情里可能
// 带 SQL 约束名、库文件路径、内部状态,而 viewer 角色也能触达部分写失败路径。
// 详情只许进日志,页面上只能是通用文案。
func TestRenderStoreWriteErr_OtherErrorsStayOpaque(t *testing.T) {
	s := newMeTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/users/1/disable", nil)

	secret := "UNIQUE constraint failed: /var/lib/nanotun/secret.db users.psk_hash"
	s.renderStoreWriteErr(w, r, errors.New(secret), "err.userNotFound", "err.userDisableFailed")

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
	body := w.Body.String()
	for _, leak := range []string{secret, "UNIQUE constraint", "/var/lib/nanotun", "psk_hash"} {
		if strings.Contains(body, leak) {
			t.Fatalf("错误页泄漏了内部细节 %q", leak)
		}
	}
	if strings.TrimSpace(body) == "" {
		t.Fatal("500 页是空的,admin 什么都看不到")
	}
}

// -------------------------------------------------------------------------
// 模板函数
// -------------------------------------------------------------------------

func TestFmtBytes_UnitBoundaries(t *testing.T) {
	const k = 1024
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{k - 1, "1023 B"}, // 进位前最后一个
		{k, "1.0 KiB"},    // 进位点
		{k*k - 1, "1024.0 KiB"},
		{k * k, "1.0 MiB"},
		{3 * k * k / 2, "1.5 MiB"},
		{k * k * k, "1.0 GiB"},
		{5 * k * k * k, "5.0 GiB"},
	}
	for _, tc := range cases {
		if got := fmtBytes(tc.in); got != tc.want {
			t.Errorf("fmtBytes(%d)=%q, 期望 %q", tc.in, got, tc.want)
		}
	}
	// 负数不该出现(计数器不会倒退),但真出现了也只能是难看,不能是 panic。
	if got := fmtBytes(-1); got == "" {
		t.Error("fmtBytes(-1) 返回空串")
	}
}

func TestFmtDurationSince_PicksTheRightUnit(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name string
		unix int64
		want string // 期望出现的数字+单位片段
	}{
		{"零值(从未发生)", 0, "-"},
		{"负数", -5, "-"},
		{"几秒前", now - 30, "30"},
		{"几分钟前", now - 90*60, "1"},
		{"几小时前", now - 5*3600, "5"},
		{"几天前", now - 3*24*3600, "3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fmtDurationSince(tc.unix)
			if got == "" {
				t.Fatal("返回空串")
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("fmtDurationSince=%q, 期望含 %q", got, tc.want)
			}
		})
	}
}

// TestFmtDurationSince_FutureTimestampsDoNotGoNegative:时钟回拨、或 server 与 web
// 不在同一台机器上时,时间戳会落在未来。显示 "-3m 前" 很难看,更怕的是负数被拿去
// 做除法或索引。
func TestFmtDurationSince_FutureTimestampsDoNotGoNegative(t *testing.T) {
	future := time.Now().Add(2 * time.Hour).Unix()
	got := fmtDurationSince(future)
	if strings.Contains(got, "-") {
		t.Fatalf("未来时间戳渲染成了 %q,带负号", got)
	}
}

// TestFmtDurationSinceLang_SuffixFollowsLanguage:后缀走 i18n,英文页不能出现「前」。
func TestFmtDurationSinceLang_SuffixFollowsLanguage(t *testing.T) {
	unix := time.Now().Add(-10 * time.Minute).Unix()
	zh, en := fmtDurationSinceLang("zh", unix), fmtDurationSinceLang("en", unix)
	if zh == en {
		t.Fatalf("中英文渲染结果相同(%q),i18n 没生效", zh)
	}
	if strings.Contains(en, "前") {
		t.Fatalf("英文页出现了中文后缀: %q", en)
	}
}

func TestIsEmpty_TreatsWhitespaceAsEmpty(t *testing.T) {
	// 模板用它决定「这一栏显示值还是显示占位符」。只判 == "" 的话,
	// 一个全是空格的备注字段会渲染成一片视觉上的空白,看着像渲染错了。
	for _, s := range []string{"", " ", "\t", "\n", "  \t\n "} {
		if !isEmpty(s) {
			t.Errorf("isEmpty(%q)=false", s)
		}
	}
	for _, s := range []string{"a", " a ", "0", "-"} {
		if isEmpty(s) {
			t.Errorf("isEmpty(%q)=true", s)
		}
	}
}

func TestToInt64_CoversEveryIntegerKindTemplatesSee(t *testing.T) {
	// 模板拿到的值来自 map[string]any,具体类型取决于 handler 塞进去的是什么;
	// JSON 解出来是 float64、store 出来是 int64、len() 是 int。漏一种就静默变 0。
	cases := []struct {
		in   any
		want int64
	}{
		{int(7), 7},
		{int32(-7), -7},
		{int64(1 << 40), 1 << 40},
		{uint(7), 7},
		{uint32(7), 7},
		{uint64(7), 7},
	}
	for _, tc := range cases {
		if got := toInt64(tc.in); got != tc.want {
			t.Errorf("toInt64(%#v)=%d, 期望 %d", tc.in, got, tc.want)
		}
	}
	// 不认识的类型退化成 0 而不是 panic —— 模板里 panic 会截断半张页面。
	for _, in := range []any{nil, "12", 1.5, struct{}{}, []int{1}} {
		if got := toInt64(in); got != 0 {
			t.Errorf("toInt64(%#v)=%d, 期望 0", in, got)
		}
	}
}

func TestQRPayload_IsUnpaddedBase32AndReversible(t *testing.T) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for _, in := range []string{"", "psk", "nanotun://join?psk=abc&host=1.2.3.4:7443"} {
		got := qrPayload(in)
		if strings.Contains(got, "=") {
			t.Errorf("qrPayload(%q)=%q 带了 padding,二维码里的 '=' 有些扫码器会吞", in, got)
		}
		back, err := enc.DecodeString(got)
		if err != nil {
			t.Errorf("qrPayload(%q)=%q 解不回来: %v", in, got, err)
			continue
		}
		if string(back) != in {
			t.Errorf("往返丢数据: %q → %q", in, string(back))
		}
	}
}

func TestSessionAge_ZeroAndFuture(t *testing.T) {
	if d := sessionAge(0); d != 0 {
		t.Fatalf("sessionAge(0)=%v, 期望 0", d)
	}
	if d := sessionAge(-1); d != 0 {
		t.Fatalf("sessionAge(-1)=%v, 期望 0", d)
	}
	d := sessionAge(time.Now().Add(-90 * time.Second).Unix())
	if d < 80*time.Second || d > 120*time.Second {
		t.Fatalf("sessionAge=%v, 期望 ~90s", d)
	}
}

func TestSessionView_HasAnyFixedVIP(t *testing.T) {
	cases := []struct {
		v4, v6 string
		want   bool
	}{
		{"", "", false},
		{"10.66.0.5", "", true},
		{"", "fd66::5", true},
		{"10.66.0.5", "fd66::5", true},
	}
	for _, tc := range cases {
		v := SessionView{FixedVIPv4: tc.v4, FixedVIPv6: tc.v6}
		if got := v.HasAnyFixedVIP(); got != tc.want {
			t.Errorf("HasAnyFixedVIP(v4=%q,v6=%q)=%v, 期望 %v", tc.v4, tc.v6, got, tc.want)
		}
	}
}

// -------------------------------------------------------------------------
// control_client 的分页 option
// -------------------------------------------------------------------------

// TestStatusOptions_LimitAndOffsetReachTheWire:dashboard 只要前 5 条,靠这两个
// option 让 server 端截断。option 要是没拼进 query,功能上「看起来正常」
// (页面照样只显示 5 条),代价是 N_conn 上千时每次刷新都整包传回来再丢掉。
func TestStatusOptions_LimitAndOffsetReachTheWire(t *testing.T) {
	fc := newFakeControl(t, map[string]http.HandlerFunc{
		"/status": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true,"sessions":[]}`))
		},
	})

	if _, err := fc.client.Status(t.Context(), WithLimit(5), WithOffset(10)); err != nil {
		t.Fatalf("Status: %v", err)
	}
	got := strings.Join(fc.requests(), "\n")
	if !strings.Contains(got, "limit=5") || !strings.Contains(got, "offset=10") {
		t.Fatalf("控制面收到的是 %q,缺 limit/offset", got)
	}

	// 不传 option 等价老行为:一个裸 /status,不能凭空冒出 limit=0
	// (server 侧可能把 limit=0 理解成「一条都不要」)。
	fc2 := newFakeControl(t, map[string]http.HandlerFunc{
		"/status": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true,"sessions":[]}`))
		},
	})
	if _, err := fc2.client.Status(t.Context()); err != nil {
		t.Fatalf("Status(无 option): %v", err)
	}
	if got := strings.Join(fc2.requests(), "\n"); strings.Contains(got, "limit=") || strings.Contains(got, "offset=") {
		t.Fatalf("没传 option 却发了分页参数: %q", got)
	}
}
