package store

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func mkUser(t *testing.T, s *Store, name string) *User {
	t.Helper()
	u, err := s.CreateUser(t.Context(), NewUser{Username: name, PSKHash: "hash-" + name})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", name, err)
	}
	return u
}

// mkUserWithCred 建一个「已经发过凭证」的账号。CreateUser 默认把 credential_id
// 留空(老路径兼容),要模拟发过码的账号得显式给。
func mkUserWithCred(t *testing.T, s *Store, name, credID string, ts int64) *User {
	t.Helper()
	u, err := s.CreateUser(t.Context(), NewUser{
		Username: name, PSKHash: "hash-" + name,
		CredentialID: credID, CredentialCreatedAt: ts,
	})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", name, err)
	}
	return u
}

// RotateUserPSKCAS 是「两个管理员同时给同一个用户重置 PSK」这个真实场景的守门人。
//
// 没有 CAS 时两个人都会成功:后写者的 hash 留在库里,前写者却拿着自己本地生成的
// 明文渲染了一张二维码交给用户 —— 那张码扫了登不上,而且没有任何地方会报错。
// CAS 让失败的那一方立刻知道自己看到的是旧状态。
func TestRotateUserPSKCAS_LoserOfTheRaceMustNotHandOutADeadQR(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mkUserWithCred(t, s, "alice", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1_700_000_000)

	// 两个管理员都读到了同一个旧 hash。
	staleView := u.PSKHash

	wrote, err := s.RotateUserPSKCAS(ctx, u.ID, "hash-from-admin-A", staleView, 1_700_000_100)
	if err != nil || !wrote {
		t.Fatalf("先手应写成功,got wrote=%v err=%v", wrote, err)
	}

	wrote, err = s.RotateUserPSKCAS(ctx, u.ID, "hash-from-admin-B", staleView, 1_700_000_200)
	if err != nil {
		t.Fatalf("后手不该报错,只该 wrote=false: %v", err)
	}
	if wrote {
		t.Fatal("后手基于过期视图也写成功了 —— 先手手里那张二维码已经作废却还会发给用户")
	}

	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.PSKHash != "hash-from-admin-A" {
		t.Fatalf("库里应是先手的 hash,got %q", got.PSKHash)
	}
	if got.CredentialCreatedAt != 1_700_000_100 {
		t.Fatalf("credential_created_at 应随 PSK 一起刷新,got %d", got.CredentialCreatedAt)
	}
	// credential_id 不变是「同一个 UUID、新二维码覆盖旧 PSK」这个承诺的核心。
	if got.CredentialID != u.CredentialID {
		t.Fatalf("rotate 不该动 credential_id(%q → %q)", u.CredentialID, got.CredentialID)
	}

	// 拿正确的当前 hash 做 base 就能写进去。
	if wrote, err := s.RotateUserPSKCAS(ctx, u.ID, "hash-C", got.PSKHash, 1_700_000_300); err != nil || !wrote {
		t.Fatalf("用最新 hash 做 base 应成功,got wrote=%v err=%v", wrote, err)
	}
}

func TestRotateUserPSKCAS_RejectsArgumentsThatWouldWeakenTheGuard(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mkUser(t, s, "alice")

	cases := []struct {
		name                 string
		newHash, expectedOld string
		createdAt            int64
		because              string
	}{
		{"新 hash 为空", "", u.PSKHash, 1_700_000_100,
			"写进去等于把这个账号变成空口令"},
		{"新 hash 只有空白", "   ", u.PSKHash, 1_700_000_100, ""},
		{"base 为空", "newhash", "", 1_700_000_100,
			"空 base 会让任何 psk_hash 为空的行通过守门 —— CAS 就白做了"},
		{"base 只有空白", "newhash", "  ", 1_700_000_100, ""},
		{"时间戳为 0", "newhash", u.PSKHash, 0,
			"credential_created_at 是客户端判断「我这张码是不是最新」的依据"},
		{"时间戳为负", "newhash", u.PSKHash, -1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrote, err := s.RotateUserPSKCAS(ctx, u.ID, tc.newHash, tc.expectedOld, tc.createdAt)
			if err == nil {
				t.Fatalf("应报错,got wrote=%v(%s)", wrote, tc.because)
			}
			if wrote {
				t.Fatal("报错时不该同时声称写入成功")
			}
		})
	}

	// 参数校验失败不能有副作用。
	got, _ := s.GetUser(ctx, u.ID)
	if got.PSKHash != u.PSKHash {
		t.Fatalf("非法调用改动了 psk_hash(%q → %q)", u.PSKHash, got.PSKHash)
	}
}

// 老账号补 credential_id 必须幂等:`credentials show` 会被反复调用,
// 每次都换一个新 UUID 的话,用户上一张二维码里的 ID 就对不上了。
func TestBackfillUserCredentialID_OnlyFillsTheHoleOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	// CreateUser 默认把 credential_id 留空,这正是 0013 之前建的老账号的样子。
	u := mkUser(t, s, "alice")

	wrote, err := s.BackfillUserCredentialID(ctx, u.ID, "11111111-1111-4111-8111-111111111111", 1_700_000_000)
	if err != nil || !wrote {
		t.Fatalf("首次补齐应写入,got wrote=%v err=%v", wrote, err)
	}

	wrote, err = s.BackfillUserCredentialID(ctx, u.ID, "22222222-2222-4222-8222-222222222222", 1_700_000_999)
	if err != nil {
		t.Fatalf("重复补齐不该报错: %v", err)
	}
	if wrote {
		t.Fatal("已有 credential_id 时不该覆盖 —— 用户手里那张二维码上的 ID 会立刻失效")
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.CredentialID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("credential_id 被改成了 %q", got.CredentialID)
	}

	for _, bad := range []struct {
		name      string
		id        string
		createdAt int64
	}{
		{"空 UUID", "", 1_700_000_000},
		{"只有空白", "   ", 1_700_000_000},
		{"时间戳为 0", "33333333-3333-4333-8333-333333333333", 0},
		{"时间戳为负", "33333333-3333-4333-8333-333333333333", -5},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if _, err := s.BackfillUserCredentialID(ctx, u.ID, bad.id, bad.createdAt); err == nil {
				t.Fatal("应报错")
			}
		})
	}
}

// EnsureUserCredentialID 是上面那个 backfill 的调用面:它要在「已有」「没有」
// 「并发已被别人补上」三种情况下都给出一个能用的 (id, ts)。
func TestEnsureUserCredentialID_AlwaysYieldsAUsablePair(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	t.Run("已有 credential_id 时原样返回", func(t *testing.T) {
		u := mkUserWithCred(t, s, "has-cred", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1_700_000_000)
		id, ts, err := s.EnsureUserCredentialID(ctx, u)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if id != u.CredentialID {
			t.Fatalf("不该换 ID(%q → %q)", u.CredentialID, id)
		}
		if ts <= 0 {
			t.Fatalf("时间戳应有值,got %d", ts)
		}
	})

	t.Run("老账号补一个新的", func(t *testing.T) {
		u := mkUser(t, s, "no-cred")
		u2, _ := s.GetUser(ctx, u.ID)

		id, ts, err := s.EnsureUserCredentialID(ctx, u2)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if id == "" {
			t.Fatal("应生成一个 UUID")
		}
		if ts <= 0 {
			t.Fatalf("时间戳应回落到 user.created_at 而不是 0,got %d", ts)
		}
		// 落库了,再调一次要拿到同一个。
		u3, _ := s.GetUser(ctx, u.ID)
		id2, _, err := s.EnsureUserCredentialID(ctx, u3)
		if err != nil || id2 != id {
			t.Fatalf("第二次应返回同一个 ID(%q vs %q,err=%v)", id, id2, err)
		}
	})

	t.Run("并发已被补上时重读拿权威值", func(t *testing.T) {
		// 库里已经有 credential_id,但调用方手里那份快照是补齐之前读的 —— 正是竞态后的状态。
		u := mkUserWithCred(t, s, "raced", "44444444-4444-4444-8444-444444444444", 1_700_000_000)
		stale := *u
		stale.CredentialID = ""

		id, _, err := s.EnsureUserCredentialID(ctx, &stale)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		authoritative, _ := s.GetUser(ctx, u.ID)
		if id != authoritative.CredentialID {
			t.Fatalf("竞态后应重读库里的权威值,got %q want %q", id, authoritative.CredentialID)
		}
	})

	if _, _, err := s.EnsureUserCredentialID(ctx, nil); err == nil {
		t.Fatal("nil user 应报错而不是 panic")
	}
}

// 禁用与启用要成对可逆。禁用只改 disabled_at,不删数据 —— 历史(设备、租约、审计)
// 都要留着,否则「先禁用观察一阵再决定删不删」这个常规操作就没法做。
func TestDisableEnableUser_IsReversibleAndReportsMissingRows(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const t0 = 1_700_000_000
	withFrozenClock(t, t0)
	u := mkUser(t, s, "alice")

	if u.DisabledAt != 0 {
		t.Fatalf("新建用户不该是禁用状态,got disabled_at=%d", u.DisabledAt)
	}

	if err := s.DisableUser(ctx, u.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.DisabledAt != t0 {
		t.Fatalf("disabled_at 应记录禁用时刻 %d,got %d", t0, got.DisabledAt)
	}
	if got.PSKHash != u.PSKHash || got.Username != u.Username {
		t.Fatal("禁用不该动其它字段 —— 它的语义是「保留历史但拒绝登录」")
	}

	if err := s.EnableUser(ctx, u.ID); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.DisabledAt != 0 {
		t.Fatalf("启用后 disabled_at 应清回 0,got %d", got.DisabledAt)
	}

	// 对不存在的用户操作要报 ErrNotFound,不能静默成功 —— CLI 靠它告诉运维「打错 id 了」。
	if err := s.DisableUser(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Disable 不存在的用户应回 ErrNotFound,got %v", err)
	}
	if err := s.EnableUser(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Enable 不存在的用户应回 ErrNotFound,got %v", err)
	}
}

// 两个列表方法的区别在于「看不看得见已禁用的账号」,这个差别直接决定运维会不会
// 产生盲区:一个被禁用但仍持有 UUID 和 psk_hash 的账号如果从凭证总览里消失,
// 运维会以为已经清理干净了。
func TestListUsersAllAndWithCredentials_DoNotHideDisabledAccounts(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	alice := mkUserWithCred(t, s, "alice", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 1_700_000_000)
	bob := mkUserWithCred(t, s, "bob", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 1_700_000_500)
	if err := s.DisableUser(ctx, bob.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	// carol 从没发过凭证:只该出现在 all 里。
	_ = mkUser(t, s, "carol")

	all, err := s.ListUsersAll(ctx)
	if err != nil {
		t.Fatalf("ListUsersAll: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListUsersAll 应含全部 3 个(含禁用),got %d", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].ID >= all[i].ID {
			t.Fatal("ListUsersAll 应按 id 升序")
		}
	}

	withCred, err := s.ListUsersWithCredentials(ctx)
	if err != nil {
		t.Fatalf("ListUsersWithCredentials: %v", err)
	}
	names := map[string]bool{}
	for _, u := range withCred {
		names[u.Username] = true
	}
	if !names["bob"] {
		t.Fatal("被禁用但仍持有凭证的 bob 必须出现在凭证总览里 —— " +
			"看不到就会以为已经清理了,而那把 UUID 和 psk_hash 还在库里")
	}
	if !names["alice"] {
		t.Fatal("正常账号 alice 应在凭证总览里")
	}
	if names["carol"] {
		t.Fatal("没有 credential_id 的账号不该出现在凭证总览里")
	}

	// 排序:最近 rotate 的排前面,方便一眼看到刚发出去的凭证。
	if _, err := s.RotateUserPSKCAS(ctx, alice.ID, "newhash", alice.PSKHash, 1_900_000_000); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	withCred, _ = s.ListUsersWithCredentials(ctx)
	if len(withCred) < 2 || withCred[0].Username != "alice" {
		t.Fatalf("最近 rotate 的应排最前,got %v", func() []string {
			var n []string
			for _, u := range withCred {
				n = append(n, u.Username)
			}
			return n
		}())
	}
}

func TestSetUserBandwidthAndPlatforms_RejectNegativesAndMissingRows(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u := mkUser(t, s, "alice")

	if err := s.SetUserBandwidth(ctx, u.ID, 1_000_000, 2_000_000); err != nil {
		t.Fatalf("SetUserBandwidth: %v", err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.BandwidthUpBPS != 1_000_000 || got.BandwidthDownBPS != 2_000_000 {
		t.Fatalf("限速没写进去: up=%d down=%d", got.BandwidthUpBPS, got.BandwidthDownBPS)
	}

	// 0 表示不限,是合法值,不能和负数一起被拒。
	if err := s.SetUserBandwidth(ctx, u.ID, 0, 0); err != nil {
		t.Fatalf("0 = 不限,应当接受: %v", err)
	}

	for _, bad := range [][2]int64{{-1, 0}, {0, -1}, {-1, -1}} {
		err := s.SetUserBandwidth(ctx, u.ID, bad[0], bad[1])
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("负限速 %v 应回 ErrInvalid,got %v —— 负数会被下游当成一个极小的 cap", bad, err)
		}
	}
	if err := s.SetUserBandwidth(ctx, 999999, 1, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在的用户应回 ErrNotFound,got %v", err)
	}

	// 平台白名单:空串等于清除限制(存 NULL),不是「一个都不允许」。
	if err := s.SetUserAllowedPlatforms(ctx, u.ID, "ios,android"); err != nil {
		t.Fatalf("SetUserAllowedPlatforms: %v", err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.AllowedPlatforms != "ios,android" {
		t.Fatalf("白名单没写进去,got %q", got.AllowedPlatforms)
	}
	if err := s.SetUserAllowedPlatforms(ctx, u.ID, ""); err != nil {
		t.Fatalf("清除白名单: %v", err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if got.AllowedPlatforms != "" {
		t.Fatalf("空串应清成「不设限」,got %q —— 存成空字符串而非 NULL 会让下游读成「零个平台被允许」", got.AllowedPlatforms)
	}
	if err := s.SetUserAllowedPlatforms(ctx, 999999, "ios"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在的用户应回 ErrNotFound,got %v", err)
	}
}

// truncateUTF8 给客户端上报的 device_name 之类的串做尺寸兜底。
// 从中间切断一个多字节字符会在库里留下非法 UTF-8,之后任何读取这一列的地方
// (JSON 序列化、模板渲染)都可能出问题,而且是很久以后才发作。
func TestTruncateUTF8_NeverSplitsARune(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		maxBytes int
		want     string
	}{
		{"短于上限时原样返回", "abc", 10, "abc"},
		{"恰好等于上限", "abc", 3, "abc"},
		{"纯 ASCII 直接切", "abcdef", 3, "abc"},
		{"切在汉字中间要退回边界", "中文", 4, "中"},
		{"上限落在汉字的第二个字节", "中文", 5, "中"},
		{"上限恰好是完整汉字边界", "中文", 3, "中"},
		{"四字节 emoji 放不下就整个丢掉", "😀", 3, ""},
		{"emoji 放得下", "😀", 4, "😀"},
		{"混排:ASCII 后接汉字", "ab中", 4, "ab"},
		{"上限为 0", "中", 0, ""},
		{"空串", "", 5, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateUTF8(tc.in, tc.maxBytes)
			if got != tc.want {
				t.Fatalf("truncateUTF8(%q, %d) = %q,want %q", tc.in, tc.maxBytes, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("结果不是合法 UTF-8: %q", got)
			}
			if len(got) > tc.maxBytes {
				t.Fatalf("结果 %d 字节,超过上限 %d", len(got), tc.maxBytes)
			}
		})
	}

	// 随手来一串长的,保证任何切点都不会切坏字符。
	long := strings.Repeat("中a文b", 50)
	for n := range len(long) + 1 {
		got := truncateUTF8(long, n)
		if !utf8.ValidString(got) {
			t.Fatalf("maxBytes=%d 时切出了非法 UTF-8: %q", n, got)
		}
		if len(got) > n {
			t.Fatalf("maxBytes=%d 时结果有 %d 字节", n, len(got))
		}
	}
}
