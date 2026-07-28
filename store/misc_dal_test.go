package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// acl_default_action 拼错的后果特别隐蔽:数据面读到一个不认识的值会 fail-closed
// 兜到 deny(见 acl_runtime.go),于是「设成 allow 却写成 alow」的结果是全网被拒,
// 而设置页面上明明白白显示着运维输入的那个词。写入路径必须当场拦住。
func TestValidateACLDefaultActionSetting_OnlyTwoWordsAreAcceptable(t *testing.T) {
	for _, ok := range []string{"allow", "deny", "ALLOW", "Deny", "  allow  ", "\tdeny\n"} {
		if err := ValidateACLDefaultActionSetting(ok); err != nil {
			t.Errorf("%q 应被接受(大小写与空白不敏感): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "  ", "alow", "deni", "allow deny", "permit", "0", "true", "allow;"} {
		err := ValidateACLDefaultActionSetting(bad)
		if err == nil {
			t.Errorf("%q 应被拒 —— 落库后数据面会 fail-closed 兜到 deny,而设置页显示的还是这个词", bad)
			continue
		}
		if !strings.Contains(err.Error(), bad) && bad != "" {
			t.Errorf("错误信息里应回显输入值 %q 方便运维看出打错了什么,实际 %v", bad, err)
		}
	}
}

func TestListACLPairs_ReturnsEverythingInStableOrder(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	if list, err := s.ListACLPairs(ctx); err != nil || len(list) != 0 {
		t.Fatalf("空库应回空列表,got %d 条 err=%v", len(list), err)
	}

	alice := mkUser(t, s, "alice")
	bob := mkUser(t, s, "bob")

	var want int
	for _, p := range []NewACLPair{
		{SrcUserID: alice.ID, DstUserID: bob.ID, Action: ACLAllow, DstKind: ACLDstKindUser},
		{SrcUserID: bob.ID, DstUserID: alice.ID, Action: ACLDeny, DstKind: ACLDstKindUser},
		{SrcUserID: alice.ID, Action: ACLDeny, DstKind: ACLDstKindExit},
	} {
		if _, err := s.AddACLPair(ctx, p); err != nil {
			t.Fatalf("AddACLPair(%+v): %v", p, err)
		}
		want++
	}

	list, err := s.ListACLPairs(ctx)
	if err != nil {
		t.Fatalf("ListACLPairs: %v", err)
	}
	if len(list) != want {
		t.Fatalf("应列出 %d 条,got %d —— 漏一条规则就是一条实际生效但运维看不见的策略",
			want, len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].ID >= list[i].ID {
			t.Fatalf("应按 id 升序,%d 排在 %d 前面", list[i-1].ID, list[i].ID)
		}
	}
	// deny 规则必须原样列出来 —— 列表是运维核对策略的唯一视图。
	var sawDeny, sawExit bool
	for _, p := range list {
		if p.Action == ACLDeny {
			sawDeny = true
		}
		if p.DstKind == ACLDstKindExit {
			sawExit = true
		}
	}
	if !sawDeny || !sawExit {
		t.Fatalf("deny 规则或 exit 规则没被列出来(sawDeny=%v sawExit=%v)", sawDeny, sawExit)
	}
}

// 手动释放租约要能区分「真的删了」和「device_id 传错了」。静默成功的话,
// 运维以为地址已经回收,实际那台设备还占着,下一次分配就撞上。
func TestDeleteLease_ReportsWhenThereWasNothingToRelease(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mkUser(t, s, "alice")
	dev, err := s.UpsertDevice(ctx, u.ID, "dev-uuid-0001", "laptop", "")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if _, err := s.UpsertLease(ctx, dev.ID, "10.80.0.5", "", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}

	if err := s.DeleteLease(ctx, dev.ID); err != nil {
		t.Fatalf("首次释放: %v", err)
	}
	if err := s.DeleteLease(ctx, dev.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("重复释放应回 ErrNotFound,got %v —— 静默成功会让运维以为地址回收了", err)
	}
	if err := s.DeleteLease(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在的 device_id 应回 ErrNotFound,got %v", err)
	}

	// 地址真的回收了:重新分配时不再被占用。
	v4, _, err := s.AllUsedVIPs(ctx)
	if err != nil {
		t.Fatalf("AllUsedVIPs: %v", err)
	}
	if v4["10.80.0.5"] {
		t.Fatal("释放之后这个地址不该还在已用集里")
	}
}

// 4via6 的 site_id 只对子网路由器有意义。这个查询绝不能顺手分配一个 —— 一旦给
// 普通设备发了 site_id,它就变成了一个「看起来能路由某个网段」的设备。
func TestSiteIDByDevice_LooksUpWithoutAllocating(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mkUser(t, s, "alice")
	plain, err := s.UpsertDevice(ctx, u.ID, "plain-uuid-0001", "phone", "")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}

	if _, err := s.SiteIDByDevice(ctx, plain.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("普通设备查不到 site_id 才对,got %v", err)
	}
	// 查过一次之后仍然不该有映射。
	if sites, err := s.ListVia6Sites(ctx); err != nil || len(sites) != 0 {
		t.Fatalf("只读查询不该产生映射,got %v err=%v —— 分配了就等于凭空多出一台子网路由器", sites, err)
	}

	router, err := s.UpsertDevice(ctx, u.ID, "router-uuid-0001", "gw", "")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	sid, err := s.GetOrAssignSiteID(ctx, router.ID)
	if err != nil {
		t.Fatalf("GetOrAssignSiteID: %v", err)
	}
	got, err := s.SiteIDByDevice(ctx, router.ID)
	if err != nil {
		t.Fatalf("已分配的设备应查得到: %v", err)
	}
	if got != sid {
		t.Fatalf("查到的 site_id 与分配的不符(%d vs %d)", got, sid)
	}
	// 正反查要闭环,否则数据面按 site_id 找不回宣告方设备。
	back, err := s.DeviceIDBySiteID(ctx, sid)
	if err != nil || back != router.ID {
		t.Fatalf("反查应回到同一台设备,got %d err=%v", back, err)
	}
	if _, err := s.DeviceIDBySiteID(ctx, 0xFFFE); !errors.Is(err, ErrNotFound) {
		t.Fatalf("未分配的 site_id 反查应回 ErrNotFound,got %v", err)
	}
}

// advertised_host 只是 UI 上的展示标签,可以是任意短语。唯一的硬约束是长度:
// 253 字节是域名总长上限,超过它没有任何合法用途,只可能是粘贴错了一大段东西。
func TestSetAdvertisedHost_TrimsAndCapsAtTheDomainLengthLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	if err := s.SetAdvertisedHost(ctx, "  东京 1 号  "); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.GetAdvertisedHost(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "东京 1 号" {
		t.Fatalf("应裁掉首尾空白,got %q", got)
	}

	// 空串 = 清除。
	if err := s.SetAdvertisedHost(ctx, "   "); err != nil {
		t.Fatalf("清除: %v", err)
	}
	if got, _ = s.GetAdvertisedHost(ctx); got != "" {
		t.Fatalf("应被清空,got %q", got)
	}

	// 恰好 253 字节放行,254 拒绝。
	if err := s.SetAdvertisedHost(ctx, strings.Repeat("a", 253)); err != nil {
		t.Fatalf("253 字节应放行: %v", err)
	}
	// 长度按裁掉空白之后算:前后多敲几个空格不该把一个合法标签顶出上限。
	if err := s.SetAdvertisedHost(ctx, "   "+strings.Repeat("a", 253)+"   "); err != nil {
		t.Fatalf("带空白的 253 字节标签应放行(长度按 trim 后算): %v", err)
	}
	err = s.SetAdvertisedHost(ctx, strings.Repeat("a", 254))
	if err == nil {
		t.Fatal("254 字节应被拒")
	}
	// 这条错误要能被 web 翻译成用户语言。
	var le interface{ LocaleKey() (string, []any) }
	if !errors.As(err, &le) {
		t.Fatalf("超长错误应是可本地化错误,got %T", err)
	}
	key, args := le.LocaleKey()
	if key == "" {
		t.Fatal("翻译 key 不该为空,否则 web 端只能显示中文原文")
	}
	if len(args) != 1 {
		t.Fatalf("应把实际长度作为参数传给翻译层,got %v", args)
	}
	if !strings.Contains(err.Error(), "253") {
		t.Fatalf("中文原文应说明上限,got %q", err.Error())
	}
}

// settingsGetInt64 把「没设过」和「设了个解析不了的值」都当成 0。这是有意的:
// 对调用方来说两者都表示「不限」。但 DB 层真出错时必须往上报,不能也吞成 0 ——
// 那会让一次读失败伪装成「用户没设限速」。
func TestSettingsGetInt64_ParseFailureIsZeroButDBErrorIsNot(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	n, err := s.settingsGetInt64(ctx, "never_set_key")
	if err != nil || n != 0 {
		t.Fatalf("没设过的 key 应回 (0,nil),got (%d,%v)", n, err)
	}

	for _, tc := range []struct {
		val  string
		want int64
	}{
		{"12345", 12345},
		{"-7", -7},
		{"0", 0},
		{"", 0},
		{"not-a-number", 0},
		{"12.5", 0},
		{"99999999999999999999999", 0},
	} {
		if err := s.SettingsSet(ctx, "probe_key", tc.val); err != nil {
			t.Fatalf("SettingsSet(%q): %v", tc.val, err)
		}
		got, err := s.settingsGetInt64(ctx, "probe_key")
		if err != nil {
			t.Fatalf("值为 %q 时不该报错(解析失败等价于未设置): %v", tc.val, err)
		}
		if got != tc.want {
			t.Fatalf("值为 %q 时得到 %d,want %d", tc.val, got, tc.want)
		}
	}

	// DB 真出错时必须往上报。吞成 0 的话,一次读失败会伪装成「这个用户没设限速」——
	// 结果是限速被静默摘掉,而没有任何地方报错。
	s2 := newTestStore(t)
	if err := s2.SettingsSet(ctx, "probe_key", "12345"); err != nil {
		t.Fatalf("预置: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, err := s2.settingsGetInt64(ctx, "probe_key"); err == nil {
		t.Fatalf("库已关闭时应报错,却回了 (%d,nil)", got)
	}
}

func TestStorePath_ReportsWhatWasOpened(t *testing.T) {
	path := filepath.Join(t.TempDir(), "somewhere.db")
	s, err := Open(t.Context(), path, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if s.Path() != path {
		t.Fatalf("Path()=%q,应回打开时用的 %q —— 日志里靠它确认到底连的哪个库", s.Path(), path)
	}
}
