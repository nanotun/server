package store

import (
	"errors"
	"fmt"
	"testing"
)

// AddACLPair 的入参闸门此前一条都没被执行过。这一层特别值得钉住:写进 acl_pairs 的规则
// 会被 nanotund 启动 / SIGHUP 时整表读进内存 snapshot,per-packet 按它裁决。一条语义
// 走形的规则不会报错,只会让流量被悄悄放行或悄悄丢掉 —— 正是「判错了静默出错」那一类。

// seedACLUsers 造 n 个用户并返回它们的 id。acl_pairs 的 src/dst 有外键指向 users,
// 拿凭空编的 id 插规则会被约束拦下(而不是走到我们想验的那条路径上)。
func seedACLUsers(t *testing.T, s *Store, n int) []int64 {
	t.Helper()
	ids := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		u, err := s.CreateUser(t.Context(), NewUser{
			Username: fmt.Sprintf("aclu%d", i), PSKHash: "h"})
		if err != nil {
			t.Fatalf("CreateUser %d: %v", i, err)
		}
		ids = append(ids, u.ID)
	}
	return ids
}

func TestAddACLPair_RejectsRulesTheDataPlaneCouldNotEvaluate(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	// 用真实用户 id:src/dst 有外键指向 users。若这里填凭空编的 id,任何一道闸被
	// 拆掉时 INSERT 都会撞外键而**照样报错** —— 测试看似抓住了,抓的其实是外键,
	// 被测的那道闸有没有根本看不出来。
	u := seedACLUsers(t, s, 2)

	bad := []struct {
		name    string
		in      NewACLPair
		because string
	}{
		{"action 不在白名单", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: "drop"},
			"runtime 只认 allow/deny;第三种值会落到裁决的默认分支,行为取决于实现细节而非运维意图"},
		{"action 拼错(deni)", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: "deni"},
			"拼错的 deny 若被放过,这条规则就完全不起作用,运维却以为已经拦了"},
		{"dst_kind 不在白名单", NewACLPair{SrcUserID: u[0], Action: ACLDeny, DstKind: "lan"},
			""},
		{"dst_kind=exit 却钉了 dst_user_id", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: ACLDeny, DstKind: ACLDstKindExit},
			"exit 规则匹配的是「dst 不属于任何 user」的出口流量,再钉一个 dst_user_id 自相矛盾"},
		{"proto 不认识", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: ACLAllow, Proto: "sctp"},
			""},
		{"proto 大小写不对", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: ACLAllow, Proto: "TCP"},
			"这里刻意不做大小写归一,免得库里出现两种写法、snapshot 比对时对不上"},
		{"端口为负", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: ACLAllow, Proto: "tcp", DstPortLo: -1, DstPortHi: 80},
			""},
		{"端口超过 65535", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: ACLAllow, Proto: "tcp", DstPortLo: 80, DstPortHi: 65536},
			""},
		{"lo > hi", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: ACLAllow, Proto: "tcp", DstPortLo: 8080, DstPortHi: 80},
			"倒序区间匹配不到任何端口,这条规则等于不存在"},
		{"icmp 带端口", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: ACLDeny, Proto: "icmp", DstPortLo: 80, DstPortHi: 80},
			"icmp 没有端口字段,带上端口的规则在裁决时无从匹配"},
		{"proto 为空却带端口", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: ACLDeny, DstPortLo: 443, DstPortHi: 443},
			"「任意协议的 443 端口」有歧义:icmp 报文没有端口,该算匹配还是不匹配?"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.AddACLPair(ctx, tc.in)
			if err == nil {
				t.Fatalf("应被拒绝,却写进了 %+v。%s", got, tc.because)
			}
		})
	}

	// 一条都不该落库 —— 否则 snapshot 里会多出没人预期的规则。
	rules, err := s.ListACLPairs(ctx)
	if err != nil {
		t.Fatalf("ListACLPairs: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("被拒的规则还是落库了: %+v", rules)
	}
}

func TestAddACLPair_DefaultsAreSpelledOutNotImplied(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := seedACLUsers(t, s, 2)

	// action 留空默认 allow。这条分支此前从没被执行过,而它的语义很重:一条忘了写
	// action 的规则会变成**放行**,不是拒绝。默认值选错方向就是默认放行漏洞。
	a, err := s.AddACLPair(ctx, NewACLPair{SrcUserID: u[0], DstUserID: u[1]})
	if err != nil {
		t.Fatalf("AddACLPair: %v", err)
	}
	if a.Action != ACLAllow {
		t.Fatalf("action = %q,留空时的默认值是 %q", a.Action, ACLAllow)
	}
	if a.DstKind != ACLDstKindUser {
		t.Fatalf("dst_kind = %q,留空时应默认 %q(与 v1 行为一致)", a.DstKind, ACLDstKindUser)
	}
}

func TestAddACLPair_SinglePortIsNormalizedNotWidenedToAnyPort(t *testing.T) {
	// 只给 lo 或只给 hi 时,另一端要被补成同一个值。补错的后果是静默放宽:
	// 区间变成 (0, 443) 这种「0 到 443」甚至被当成全 0 = 任意端口,
	// 一条本该只管 443 的 deny 规则就管到了别处,或者反过来什么都管不到。
	s := newTestStore(t)
	ctx := t.Context()
	u := seedACLUsers(t, s, 6)

	for _, tc := range []struct {
		name   string
		in     NewACLPair
		lo, hi int
	}{
		{"只给 hi", NewACLPair{SrcUserID: u[0], DstUserID: u[1], Action: ACLDeny, Proto: "tcp", DstPortHi: 443}, 443, 443},
		{"只给 lo", NewACLPair{SrcUserID: u[0], DstUserID: u[2], Action: ACLDeny, Proto: "tcp", DstPortLo: 8080}, 8080, 8080},
		{"两端都给且相等", NewACLPair{SrcUserID: u[0], DstUserID: u[3], Action: ACLDeny, Proto: "udp", DstPortLo: 53, DstPortHi: 53}, 53, 53},
		{"正常区间", NewACLPair{SrcUserID: u[0], DstUserID: u[4], Action: ACLDeny, Proto: "tcp", DstPortLo: 1000, DstPortHi: 2000}, 1000, 2000},
		{"全 0 = 任意端口", NewACLPair{SrcUserID: u[0], DstUserID: u[5], Action: ACLDeny, Proto: "tcp"}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.AddACLPair(ctx, tc.in)
			if err != nil {
				t.Fatalf("AddACLPair: %v", err)
			}
			if got.DstPortLo != tc.lo || got.DstPortHi != tc.hi {
				t.Fatalf("落库区间 = [%d,%d],期望 [%d,%d]", got.DstPortLo, got.DstPortHi, tc.lo, tc.hi)
			}
			// 从库里重新读一遍,确认不是只有返回值对。
			reread, err := s.GetACLPair(ctx, got.ID)
			if err != nil {
				t.Fatalf("GetACLPair: %v", err)
			}
			if reread.DstPortLo != tc.lo || reread.DstPortHi != tc.hi {
				t.Fatalf("重读区间 = [%d,%d],期望 [%d,%d]", reread.DstPortLo, reread.DstPortHi, tc.lo, tc.hi)
			}
		})
	}
}

func TestACLPairLookups_MissingIDIsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := seedACLUsers(t, s, 2)

	if _, err := s.GetACLPair(ctx, 123456); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetACLPair err=%v,想要 ErrNotFound", err)
	}
	if err := s.DeleteACLPair(ctx, 123456); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteACLPair err=%v,想要 ErrNotFound —— 静默成功会让 UI 显示「已删除」", err)
	}

	// AddACLPairBasic 是三参 helper,与 AddACLPair 走同一条校验链。
	got, err := s.AddACLPairBasic(ctx, u[0], u[1], ACLDeny)
	if err != nil {
		t.Fatalf("AddACLPairBasic: %v", err)
	}
	if got.Action != ACLDeny || got.SrcUserID != u[0] || got.DstUserID != u[1] {
		t.Fatalf("落库内容不对: %+v", got)
	}
	if _, err := s.AddACLPairBasic(ctx, u[0], u[1], "nonsense"); err == nil {
		t.Fatal("三参 helper 也必须走 action 白名单")
	}
	if err := s.DeleteACLPair(ctx, got.ID); err != nil {
		t.Fatalf("DeleteACLPair: %v", err)
	}
	if _, err := s.GetACLPair(ctx, got.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删完还能取到: %v", err)
	}
}

func TestValidateACLDefaultActionSetting_IsForgivingAboutShapeStrictAboutMeaning(t *testing.T) {
	// 这个校验挡的是 `setting set acl_default_action deni` 这类拼错。落库后数据面
	// 读不出合法值会 fail-closed 兜到 deny,运维却以为设成了 allow —— 全网断流,
	// 而且从配置上看不出原因。
	for _, ok := range []string{"allow", "deny", "ALLOW", "Deny", "  allow  ", "\tdeny\n"} {
		if err := ValidateACLDefaultActionSetting(ok); err != nil {
			t.Errorf("ValidateACLDefaultActionSetting(%q) = %v,应当接受(大小写与空白不敏感)", ok, err)
		}
	}
	for _, bad := range []string{"", "deni", "allowed", "drop", "0", "1", "true", "allow deny", "允许"} {
		if err := ValidateACLDefaultActionSetting(bad); err == nil {
			t.Errorf("ValidateACLDefaultActionSetting(%q) = nil,应当拒绝", bad)
		}
	}
}

func TestIsAllowed_DefaultsAndPrecedence(t *testing.T) {
	// IsAllowed 是后台粗判路径(不是数据面裁决,见函数注释)。它的三条默认值仍然要钉住,
	// 因为 admin CLI 的核对结论就来自这里,判反了会让人以为规则集是另一个样子。
	s := newTestStore(t)
	ctx := t.Context()
	u := seedACLUsers(t, s, 6)

	t.Run("同一 user 内部恒放行", func(t *testing.T) {
		ok, err := s.IsAllowed(ctx, u[0], u[0])
		if err != nil || !ok {
			t.Fatalf("got (%v,%v)", ok, err)
		}
	})

	t.Run("规则集为空时全放行", func(t *testing.T) {
		ok, err := s.IsAllowed(ctx, u[0], u[1])
		if err != nil || !ok {
			t.Fatalf("got (%v,%v) —— 没配 ACL 不该把人挡在外面", ok, err)
		}
	})

	t.Run("规则集非空且无命中则拒绝", func(t *testing.T) {
		if _, err := s.AddACLPairBasic(ctx, u[2], u[3], ACLAllow); err != nil {
			t.Fatalf("AddACLPairBasic: %v", err)
		}
		ok, err := s.IsAllowed(ctx, u[0], u[1])
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if ok {
			t.Fatal("规则集非空、这一对没有任何规则命中 → 应当默认拒绝")
		}
	})

	t.Run("deny 优先于 allow", func(t *testing.T) {
		if _, err := s.AddACLPairBasic(ctx, u[4], u[5], ACLAllow); err != nil {
			t.Fatalf("AddACLPairBasic allow: %v", err)
		}
		if _, err := s.AddACLPairBasic(ctx, u[4], u[5], ACLDeny); err != nil {
			t.Fatalf("AddACLPairBasic deny: %v", err)
		}
		ok, err := s.IsAllowed(ctx, u[4], u[5])
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if ok {
			t.Fatal("同一对上同时有 allow 和 deny 时必须 deny 优先")
		}
	})

	t.Run("通配 src 也算命中", func(t *testing.T) {
		s2 := newTestStore(t)
		u2 := seedACLUsers(t, s2, 2)
		if _, err := s2.AddACLPair(t.Context(), NewACLPair{DstUserID: u2[1], Action: ACLDeny}); err != nil {
			t.Fatalf("AddACLPair: %v", err)
		}
		ok, err := s2.IsAllowed(t.Context(), u2[0], u2[1])
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if ok {
			t.Fatal("src 通配的 deny 规则应当拦住任意 src")
		}
	})
}

func TestACLReads_SurfaceCorruptRowsAndDeadDB(t *testing.T) {
	t.Run("损坏行不被静默跳过", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		u := seedACLUsers(t, s, 2)
		got, err := s.AddACLPairBasic(ctx, u[0], u[1], ACLDeny)
		if err != nil {
			t.Fatalf("AddACLPairBasic: %v", err)
		}
		// dst_port_lo 写成非数字。若扫描失败被静默跳过,这条 deny 规则就从
		// snapshot 里凭空消失 —— 本该被拦的流量全部放行。
		if _, err := s.db.ExecContext(ctx,
			`UPDATE acl_pairs SET dst_port_lo='坏了' WHERE id=?`, got.ID); err != nil {
			t.Fatalf("注入损坏值: %v", err)
		}
		if _, err := s.ListACLPairs(ctx); err == nil {
			t.Fatal("ListACLPairs 遇到扫不出来的行应当报错,而不是把这条规则丢掉")
		}
		if _, err := s.GetACLPair(ctx, got.ID); err == nil {
			t.Fatal("GetACLPair 遇到损坏行应当报错")
		} else if errors.Is(err, ErrNotFound) {
			t.Fatalf("损坏被归一成 ErrNotFound: %v —— 会掩盖数据损坏", err)
		}
	})

	t.Run("库挂了每条路径都报错", func(t *testing.T) {
		s := newTestStore(t)
		u := seedACLUsers(t, s, 2)
		if _, err := s.AddACLPairBasic(t.Context(), u[0], u[1], ACLDeny); err != nil {
			t.Fatalf("AddACLPairBasic: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		ctx := t.Context()
		for name, run := range map[string]func() error{
			"AddACLPair":    func() error { _, e := s.AddACLPairBasic(ctx, u[0], u[1], ACLAllow); return e },
			"GetACLPair":    func() error { _, e := s.GetACLPair(ctx, 1); return e },
			"ListACLPairs":  func() error { _, e := s.ListACLPairs(ctx); return e },
			"DeleteACLPair": func() error { return s.DeleteACLPair(ctx, 1) },
			"IsAllowed":     func() error { _, e := s.IsAllowed(ctx, u[0], u[1]); return e },
		} {
			t.Run(name, func(t *testing.T) {
				if err := run(); err == nil {
					t.Fatal("库已关闭却报成功")
				}
			})
		}
	})

	// IsAllowed 有三条独立的查询,任一失败都必须**报错**而不是返回一个布尔值。
	// 返回 (true, nil) 会静默放行,返回 (false, nil) 会静默断流,两者都比报错糟。
	t.Run("IsAllowed 的每一条查询失败都要冒泡", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		u := seedACLUsers(t, s, 2)
		if _, err := s.AddACLPairBasic(ctx, u[0], u[1], ACLAllow); err != nil {
			t.Fatalf("AddACLPairBasic: %v", err)
		}
		// 把 action 列写成非法值不影响 COUNT,所以这里改用「删掉表」的办法制造读失败:
		// 三条查询都打在 acl_pairs 上,表没了每一条都会失败。
		if _, err := s.db.ExecContext(ctx, `DROP TABLE acl_pairs`); err != nil {
			t.Fatalf("DROP TABLE: %v", err)
		}
		ok, err := s.IsAllowed(ctx, u[0], u[1])
		if err == nil {
			t.Fatalf("表都没了却返回 (%v, nil)", ok)
		}
		if ok {
			t.Fatal("出错时还返回了 true —— 读不到规则就放行是最糟的失败方向")
		}
	})

	// IsAllowed 里有三条串联的查询。上面那个用例让**第一条**(COUNT(*))就失败,
	// 后两条根本没跑到。这里把 src_user_id 列改名:COUNT(*) 照常成功,规则匹配那条
	// 查询才失败 —— 打的是「前面都顺利、中途才出错」这条路径。对应的真实故障是
	// schema 漂移 / 迁移写歪。
	t.Run("中途查询失败也不能退化成一个布尔值", func(t *testing.T) {
		s := newTestStore(t)
		ctx := t.Context()
		u := seedACLUsers(t, s, 2)
		if _, err := s.AddACLPairBasic(ctx, u[0], u[1], ACLAllow); err != nil {
			t.Fatalf("AddACLPairBasic: %v", err)
		}
		if _, err := s.db.ExecContext(ctx,
			`ALTER TABLE acl_pairs RENAME COLUMN src_user_id TO src_user_id_drifted`); err != nil {
			t.Fatalf("改列名: %v", err)
		}
		ok, err := s.IsAllowed(ctx, u[0], u[1])
		if err == nil {
			t.Fatalf("规则匹配查询失败却返回 (%v, nil)", ok)
		}
		if ok {
			t.Fatal("出错时返回 true —— 会把「查不出来」当成「允许」")
		}
	})
}

func TestNullableInt_ZeroBecomesNULLSoWildcardsWork(t *testing.T) {
	// ACL 的通配是靠 src_user_id / dst_user_id 存 NULL 实现的,判定 SQL 写的是
	// `src_user_id=? OR src_user_id IS NULL`。若 0 被原样存成 0 而不是 NULL,
	// 通配规则就退化成「只匹配 user_id=0」—— 而 user id 从 1 开始,等于规则失效。
	if got := nullableInt(0); got != nil {
		t.Fatalf("nullableInt(0) = %v,必须是 nil(SQL NULL)", got)
	}
	for _, v := range []int64{1, 42, -1} {
		if got := nullableInt(v); got != any(v) {
			t.Fatalf("nullableInt(%d) = %v,非零值应原样返回", v, got)
		}
	}

	// 端到端确认:通配规则在库里确实是 NULL,读回来是 0。
	s := newTestStore(t)
	ctx := t.Context()
	got, err := s.AddACLPair(ctx, NewACLPair{Action: ACLDeny})
	if err != nil {
		t.Fatalf("AddACLPair: %v", err)
	}
	var srcNull, dstNull int
	if err := s.db.QueryRowContext(ctx,
		`SELECT src_user_id IS NULL, dst_user_id IS NULL FROM acl_pairs WHERE id=?`,
		got.ID).Scan(&srcNull, &dstNull); err != nil {
		t.Fatalf("查 NULL: %v", err)
	}
	if srcNull != 1 || dstNull != 1 {
		t.Fatalf("src_null=%d dst_null=%d,双通配规则两列都该是 NULL", srcNull, dstNull)
	}
	if got.SrcUserID != 0 || got.DstUserID != 0 {
		t.Fatalf("读回来 src=%d dst=%d,NULL 应经 COALESCE 变回 0", got.SrcUserID, got.DstUserID)
	}

}
