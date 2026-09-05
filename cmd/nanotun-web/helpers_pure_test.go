package main

import (
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件补一批一直没人测的纯函数。它们都短,但每一个都直接决定页面上显示什么数字、
// 什么名字、以及启动时那条「监听在公网」的警告要不要打。

// -------------------------------------------------------------------------
// 限速多层 cap
// -------------------------------------------------------------------------

func TestMinPositiveBPS(t *testing.T) {
	// 语义要点:0 / 负数 = 「这一层不限」= +∞,而不是「限到 0」。
	// 搞反了就是「设备限速填 0 想表示不限,结果被算成一字节都不给过」。
	cases := []struct{ a, b, want int64 }{
		{0, 0, 0},
		{0, 100, 100},
		{100, 0, 100},
		{-1, 100, 100},
		{100, -1, 100},
		{-1, -5, 0},
		{100, 200, 100},
		{200, 100, 100},
		{100, 100, 100},
		{1, 1 << 40, 1},
	}
	for _, tc := range cases {
		if got := minPositiveBPS(tc.a, tc.b); got != tc.want {
			t.Errorf("minPositiveBPS(%d,%d)=%d, 期望 %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestComputeEffectiveRateBPS(t *testing.T) {
	cases := []struct {
		name                         string
		device, settings, toml, user int64
		want                         int64
	}{
		{"全都不限", 0, 0, 0, 0, 0},
		{"只有设备限", 500, 0, 0, 0, 500},
		{"设备填 0 但上层还在卡", 0, 300, 0, 0, 300},
		{"取最严的那层(user)", 900, 800, 700, 600, 600},
		{"取最严的那层(device)", 100, 800, 700, 600, 100},
		{"中间层最严", 900, 200, 700, 600, 200},
		{"负数当作不限", -1, -1, 400, -1, 400},
		{"全部相等", 500, 500, 500, 500, 500},
	}
	for _, tc := range cases {
		got := computeEffectiveRateBPS(tc.device, tc.settings, tc.toml, tc.user)
		if got != tc.want {
			t.Errorf("%s: =%d, 期望 %d", tc.name, got, tc.want)
		}
	}
}

func TestComputeEffectiveRateBPS_OrderDoesNotMatter(t *testing.T) {
	// min 是可交换的,页面上换个层次顺序展示不该算出不同的数。
	vals := []int64{0, 100, 250, 999}
	for _, a := range vals {
		for _, b := range vals {
			for _, c := range vals {
				for _, d := range vals {
					x := computeEffectiveRateBPS(a, b, c, d)
					y := computeEffectiveRateBPS(d, c, b, a)
					if x != y {
						t.Fatalf("(%d,%d,%d,%d): 正序=%d 逆序=%d", a, b, c, d, x, y)
					}
				}
			}
		}
	}
}

func TestRateBurstHuman(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "—"},
		{-1, "—"},
		{1024, "1 KiB"},
		{64 * 1024, "64 KiB"},
		{1024 * 1024, "1.00 MiB"},
		{1536 * 1024, "1.50 MiB"},
	}
	for _, tc := range cases {
		if got := rateBurstHuman(tc.in); got != tc.want {
			t.Errorf("rateBurstHuman(%d)=%q, 期望 %q", tc.in, got, tc.want)
		}
	}
}

// -------------------------------------------------------------------------
// 设备搜索
// -------------------------------------------------------------------------

func TestDeviceMatchesQuery(t *testing.T) {
	d := &store.Device{
		DeviceName: "Alice-MacBook",
		Alias:      "办公本",
		DeviceUUID: "AB12-CD34",
		Platform:   "macos",
		FixedVIPv4: "10.66.0.7",
		FixedVIPv6: "fd66::7",
	}
	// 调用方传进来的 q 已经是小写(handler 里 ToLower 过),这里按同样口径测。
	hits := []string{"alice", "macbook", "办公", "ab12", "cd34", "macos", "10.66.0.7", "fd66::7", "-"}
	for _, q := range hits {
		if !deviceMatchesQuery(d, q) {
			t.Errorf("q=%q 应当命中", q)
		}
	}
	for _, q := range []string{"bob", "windows", "10.66.0.8", "zzz"} {
		if deviceMatchesQuery(d, q) {
			t.Errorf("q=%q 不该命中", q)
		}
	}
	// 空字段不参与匹配,否则「空查询」或「空别名」会把所有设备都匹上。
	empty := &store.Device{DeviceName: "x"}
	if deviceMatchesQuery(empty, "") {
		// 注意:strings.Contains(s, "") 恒真,所以空 q 会命中任何非空字段。
		// 这是 handler 侧「q 为空就不过滤」保证的,这里只是把行为记录下来。
		t.Log("空 q 会命中任何非空字段 —— 依赖 handler 侧先判空")
	}
	if deviceMatchesQuery(&store.Device{}, "anything") {
		t.Error("所有字段为空的设备不该命中任何查询")
	}
}

// -------------------------------------------------------------------------
// ACL 列表展示
// -------------------------------------------------------------------------

func TestIndexUsersByID(t *testing.T) {
	users := []*store.User{{ID: 1, Username: "a"}, {ID: 7, Username: "b"}}
	idx := indexUsersByID(users)
	if len(idx) != 2 || idx[1].Username != "a" || idx[7].Username != "b" {
		t.Fatalf("idx=%v", idx)
	}
	if got := indexUsersByID(nil); len(got) != 0 {
		t.Errorf("nil 输入应得空表, got %v", got)
	}
}

func TestNameOrAny(t *testing.T) {
	idx := indexUsersByID([]*store.User{{ID: 1, Username: "alice"}})
	// 0 是「任意用户」的哨兵值。若显示成 "uid=0",管理员会以为有个 id 为 0 的用户。
	if got := nameOrAny(idx, 0); got != "<any>" {
		t.Errorf("id=0 → %q, 期望 <any>", got)
	}
	if got := nameOrAny(idx, 1); got != "alice" {
		t.Errorf("id=1 → %q", got)
	}
	// 用户被删但规则还在:显示 uid 而不是空白,免得那一行看起来像「任意用户」。
	if got := nameOrAny(idx, 42); got != "uid=42" {
		t.Errorf("已删用户 → %q, 期望 uid=42", got)
	}
}

func TestPortRangeText(t *testing.T) {
	cases := []struct {
		lo, hi int
		want   string
	}{
		{0, 0, "*"},
		{80, 80, "80"},
		{80, 443, "80-443"},
		{1, 65535, "1-65535"},
		{0, 1024, "0-1024"},
	}
	for _, tc := range cases {
		if got := portRangeText(tc.lo, tc.hi); got != tc.want {
			t.Errorf("portRangeText(%d,%d)=%q, 期望 %q", tc.lo, tc.hi, got, tc.want)
		}
	}
}

// -------------------------------------------------------------------------
// 语言协商
// -------------------------------------------------------------------------

// 认得的语言按 header 走,认不得的回落到**这台服务器的**默认语言 —— 不是常量
// LangDefault。两者只在 NANOTUN_LANG 没设时相等,所以原来那份用 LangDefault 当期望值
// 的写法在装机时选了中文的机器上会假报失败(serverDefaultLang 是包级 var,进程启动就
// 从环境读定了,t.Setenv 拦不住)。这里改成存档-替换-还原,顺带把「选中文装机 → 控制台
// 对既不要中文也不要英文的浏览器也回落中文」这条本来无人覆盖的行为一起测掉。
func TestLangFromAcceptHeader(t *testing.T) {
	// 与 serverDefaultLang 无关的用例:header 里有认得的语言,一律照 header 走。
	fixed := []struct{ in, want string }{
		{"zh-CN,zh;q=0.9,en;q=0.8", "zh"},
		{"en-US,en;q=0.9", "en"},
		{"xx,en", "en"},             // 第一个不认识就看下一个
		{"  en-GB  ", "en"},         // 前后空白
		{"en;q=0.1,zh;q=0.9", "en"}, // 不做 q 值排序:按出现顺序取第一个认识的
	}
	for _, tc := range fixed {
		if got := langFromAcceptHeader(tc.in); got != tc.want {
			t.Errorf("langFromAcceptHeader(%q)=%q, 期望 %q", tc.in, got, tc.want)
		}
	}

	// 回落用例:header 空或全不认得时,跟这台服务器的默认语言一致。
	orig := serverDefaultLang
	t.Cleanup(func() { serverDefaultLang = orig })
	for _, def := range supportedLangs {
		serverDefaultLang = def
		for _, in := range []string{"", "fr-FR,de;q=0.9"} {
			if got := langFromAcceptHeader(in); got != def {
				t.Errorf("serverDefaultLang=%q 时 langFromAcceptHeader(%q)=%q, 期望回落到 %q",
					def, in, got, def)
			}
		}
	}
}

// -------------------------------------------------------------------------
// 监听地址是否暴露到公网
// -------------------------------------------------------------------------

func TestListenAddrIsPublic(t *testing.T) {
	// 判错的方向要分清:把公网误判成本地 → 启动时不打警告,管理后台裸奔在公网上
	// 却没人知道。所以未知/无法解析的一律按公网算(宁可多喊一声)。
	cases := []struct {
		addr string
		want bool
	}{
		{"0.0.0.0:7443", true},
		{":7443", true},
		{"[::]:7443", true},
		{"127.0.0.1:7443", false},
		{"[::1]:7443", false},
		{"localhost:7443", false},
		{"LOCALHOST:7443", false},
		{"127.0.0.2:7443", false},
		{"192.168.1.10:7443", true},
		{"1.2.3.4:7443", true},
		{"[2001:db8::1]:7443", true},
		{"127.0.0.1", false},
		{"0.0.0.0", true},
		{"", true},
		{"   ", true},
		{"garbage", true},
	}
	for _, tc := range cases {
		if got := listenAddrIsPublic(tc.addr); got != tc.want {
			t.Errorf("listenAddrIsPublic(%q)=%v, 期望 %v", tc.addr, got, tc.want)
		}
	}
}
