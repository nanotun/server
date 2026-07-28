package store

import (
	"errors"
	"testing"
)

// ConsumeTOTPStep 是 TOTP 的重放闸。一枚 6 位码在它那 30 秒时间步内是**可以被重复
// 提交**的 —— 肩窥、剪贴板、代理日志里抄到一枚码,只要还在窗口内就能再登一次。
// 这一整个防护就落在这一条 UPDATE 的 `totp_last_used_step < ?` 上,而它此前没有测试。
func TestConsumeTOTPStep_SameCodeCannotBeUsedTwice(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a := mkAdmin(t, s, "alice")

	const step = 56_789_012

	ok, err := s.ConsumeTOTPStep(ctx, a.ID, step)
	if err != nil {
		t.Fatalf("首次消费: %v", err)
	}
	if !ok {
		t.Fatal("第一次用这一步应当成功")
	}

	ok, err = s.ConsumeTOTPStep(ctx, a.ID, step)
	if err != nil {
		t.Fatalf("重放: %v", err)
	}
	if ok {
		t.Fatal("同一时间步被消费了两次 —— 抄到一枚码就能在 30 秒内反复登录")
	}

	// 更早的步(时钟漂移容忍窗口里的前一步)同样不能用:它对应的是一枚更旧的码。
	if ok, _ := s.ConsumeTOTPStep(ctx, a.ID, step-1); ok {
		t.Fatal("更早的时间步应被拒 —— 容忍窗口里的旧码也是重放")
	}

	// 下一步是新码,应当放行。
	if ok, _ := s.ConsumeTOTPStep(ctx, a.ID, step+1); !ok {
		t.Fatal("新的时间步应当放行,否则用户每 30 秒只能登一次也不对")
	}

	// 不存在的 admin:返回 (false, nil) 而不是报错 —— 登录路径把它当作「这次验证不算数」。
	ok, err = s.ConsumeTOTPStep(ctx, 999999, step)
	if err != nil || ok {
		t.Fatalf("不存在的 admin 应回 (false,nil),got (%v,%v)", ok, err)
	}
}

// 「先禁用、再用新 secret 重新绑定」如果落在同一个 30 秒时间步里,残留的旧步计数器
// 会把新 secret 的首次登录判成重放。用户看到的是「刚扫的码就说不对」,只能干等一分钟。
// 换新凭据必须同时把计数器归零。
func TestTOTPSecretRebind_ResetsTheReplayCounter(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a := mkAdmin(t, s, "alice")

	const step = 56_789_012
	if ok, _ := s.ConsumeTOTPStep(ctx, a.ID, step); !ok {
		t.Fatal("预置:消费一步")
	}

	// 换 secret(setup 第一步)应当把计数器清零。
	if err := s.SetWebAdminTOTPSecret(ctx, a.ID, "NEWSECRETBASE32AAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatalf("SetWebAdminTOTPSecret: %v", err)
	}
	if ok, _ := s.ConsumeTOTPStep(ctx, a.ID, step); !ok {
		t.Fatal("换了新 secret 之后,同一时间步应当能重新使用 —— 否则新绑定的第一次登录会被误判为重放")
	}

	// disable 同理:作废当前 secret,计数器一起归零。
	if err := s.DisableWebAdminTOTP(ctx, a.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if ok, _ := s.ConsumeTOTPStep(ctx, a.ID, step); !ok {
		t.Fatal("disable 后计数器也应归零")
	}
}

// 手动解锁要把三个字段一起清:只清 locked_until 而留着 failed_logins,
// 下一次输错就立刻又锁上(计数还压在阈值上),运维会觉得「解锁按钮没用」。
func TestResetWebAdminLockout_ClearsCounterNotJustTheLock(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a := mkAdmin(t, s, "alice")

	const maxFailures, lockSeconds = 3, 600
	var lockUntil int64
	for range maxFailures {
		var err error
		_, lockUntil, err = s.RecordWebAdminLoginFailure(ctx, a.ID, maxFailures, lockSeconds)
		if err != nil {
			t.Fatalf("RecordWebAdminLoginFailure: %v", err)
		}
	}
	if lockUntil == 0 {
		t.Fatal("预置:连续失败到阈值应当上锁")
	}

	if err := s.ResetWebAdminLockout(ctx, a.ID); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	got, err := s.GetWebAdmin(ctx, a.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LockedUntil != 0 {
		t.Fatalf("locked_until=%d,应清零", got.LockedUntil)
	}
	if got.FailedLogins != 0 {
		t.Fatalf("failed_logins=%d,应一并清零 —— 只解锁不清计数的话,下一次输错立刻又锁上",
			got.FailedLogins)
	}

	// 解锁后重新计数:再失败一次不该马上又到阈值。
	failed, lockUntil, err := s.RecordWebAdminLoginFailure(ctx, a.ID, maxFailures, lockSeconds)
	if err != nil {
		t.Fatalf("Record after reset: %v", err)
	}
	if failed != 1 || lockUntil != 0 {
		t.Fatalf("解锁后应从 1 重新数起,got failed=%d lockUntil=%d", failed, lockUntil)
	}

	if err := s.ResetWebAdminLockout(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("解锁一个不存在的 admin 应回 ErrNotFound,got %v", err)
	}
}

// DecoyWebAdminLoginFailure 存在的唯一理由是抹平时序差:登录失败的四种情况里,
// 只有「账号存在但密码错」会跑一次写事务,另外三种(查无此人 / 已禁用 / 已锁定)
// 不碰 DB。这个差是可测的,能用来枚举用户名。
//
// 它的正确性有两条:必须真的跑完一次同形状的事务(否则抹不平),以及绝不能有任何
// 副作用(否则一次探测就能把真实账号的失败计数推上去,变成免费的锁号手段)。
func TestDecoyWebAdminLoginFailure_RunsTheMotionsWithoutTouchingAnyone(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a := mkAdmin(t, s, "alice")
	b := mkAdmin(t, s, "bob")

	// 让 alice 先有一个非零的失败计数,这样「被 decoy 意外加一」能被看出来。
	if _, _, err := s.RecordWebAdminLoginFailure(ctx, a.ID, 10, 600); err != nil {
		t.Fatalf("预置失败计数: %v", err)
	}
	before := map[int64]*WebAdmin{}
	for _, id := range []int64{a.ID, b.ID} {
		got, err := s.GetWebAdmin(ctx, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		before[id] = got
	}

	for range 5 {
		s.DecoyWebAdminLoginFailure(ctx)
	}

	for id, was := range before {
		now, err := s.GetWebAdmin(ctx, id)
		if err != nil {
			t.Fatalf("Get after decoy: %v", err)
		}
		if now.FailedLogins != was.FailedLogins {
			t.Fatalf("admin %d 的 failed_logins 被 decoy 改了(%d → %d)—— 匿名探测就能把别人的号锁死",
				id, was.FailedLogins, now.FailedLogins)
		}
		if now.LockedUntil != was.LockedUntil {
			t.Fatalf("admin %d 的 locked_until 被 decoy 改了", id)
		}
	}

	// 也不能凭空造出一行(比如 id=0 的幽灵 admin)。
	n, err := s.CountWebAdmins(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 2 {
		t.Fatalf("decoy 之后 admin 行数变成 %d,应仍为 2", n)
	}
}

// ListWebAdmins 是后台账号页的数据来源。它必须**含禁用账号** —— 一个被禁用的
// 管理员账号从列表里消失,等于没人能再启用它,也没人会注意到它还在。
func TestListWebAdmins_IncludesDisabledOnesInStableOrder(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	if list, err := s.ListWebAdmins(ctx); err != nil || len(list) != 0 {
		t.Fatalf("空库应返回空列表,got %d 条 err=%v", len(list), err)
	}

	alice := mkAdmin(t, s, "alice")
	bob := mkAdmin(t, s, "bob")
	carol := mkAdmin(t, s, "carol")

	// 禁用 bob。alice 是唯一 admin 角色不能动,所以拿 carol 当第二个 admin 兜底。
	if err := s.SetWebAdminRole(ctx, carol.ID, "admin"); err != nil {
		t.Fatalf("SetWebAdminRole: %v", err)
	}
	if err := s.SetWebAdminEnabled(ctx, bob.ID, false); err != nil {
		t.Fatalf("SetWebAdminEnabled: %v", err)
	}

	list, err := s.ListWebAdmins(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("应列出 3 个账号(含禁用的),got %d", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].ID >= list[i].ID {
			t.Fatalf("列表未按 id 升序:%d 在 %d 之前", list[i-1].ID, list[i].ID)
		}
	}
	byName := map[string]*WebAdmin{}
	for _, a := range list {
		byName[a.Username] = a
	}
	if got, ok := byName["bob"]; !ok || got.Enabled {
		t.Fatalf("被禁用的 bob 应仍出现在列表里且标记为禁用,got %+v(ok=%v)", got, ok)
	}
	if byName["alice"].ID != alice.ID {
		t.Fatal("列表里的 id 与创建时不符")
	}
}
