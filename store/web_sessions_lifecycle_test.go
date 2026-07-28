package store

import (
	"errors"
	"fmt"
	"testing"
)

// web 会话的四个写/读方法此前一条语句都没被走到过。它们合起来决定「一枚被窃的
// cookie 到底能用多久」:
//
//   - 滑动窗口(Touch 顺延 expires_at)保证活跃用户不掉线,但单有它,一枚一直被
//     使用的 cookie 就**永不**过期;
//   - 30 天绝对上限是唯一的止损线。这条线要在读(Get)、续期(Touch)、列表
//     (List)三处判定一致 —— 任何一处漏判,要么线被「续」没了,要么 UI 上显示着
//     一个实际已经作废的设备。
//
// 这几处的一致性靠 nowUnix 这个包级时间钩子来验:直接把时钟推到 31 天后。

// withFrozenClock 把 store 的时间源钉在指定时刻,返回一个可以往前推的函数。
func withFrozenClock(t *testing.T, start int64) func(delta int64) {
	t.Helper()
	orig := nowUnix
	cur := start
	nowUnix = func() int64 { return cur }
	t.Cleanup(func() { nowUnix = orig })
	return func(delta int64) { cur += delta }
}

func mkAdmin(t *testing.T, s *Store, name string) *WebAdmin {
	t.Helper()
	a, err := s.CreateWebAdmin(t.Context(), NewWebAdmin{Username: name, PasswordHash: dummyPwdHash})
	if err != nil {
		t.Fatalf("CreateWebAdmin(%s): %v", name, err)
	}
	return a
}

func mkSession(t *testing.T, s *Store, adminID int64, id string, createdAt, expiresAt int64) {
	t.Helper()
	if err := s.CreateWebSession(t.Context(), WebSession{
		ID: id, AdminID: adminID, CreatedAt: createdAt, LastSeenAt: createdAt,
		ExpiresAt: expiresAt, IP: "10.0.0.9", UserAgent: "ua",
	}); err != nil {
		t.Fatalf("CreateWebSession(%s): %v", id, err)
	}
}

func TestTouchWebSession_SlidesTheWindowButNeverPastTheAbsoluteCap(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const t0 = 1_700_000_000
	advance := withFrozenClock(t, t0)

	a := mkAdmin(t, s, "alice")
	const sid = "sess_slide_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mkSession(t, s, a.ID, sid, t0, t0+3600)

	// 一次正常续期:expires_at 往后挪。
	advance(1800)
	if err := s.TouchWebSession(ctx, sid, 3600); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	got, err := s.GetWebSession(ctx, sid)
	if err != nil {
		t.Fatalf("Get after touch: %v", err)
	}
	if got.ExpiresAt != t0+1800+3600 {
		t.Fatalf("expires_at=%d,应顺延到 now+extendBy=%d", got.ExpiresAt, t0+1800+3600)
	}
	if got.LastSeenAt != t0+1800 {
		t.Fatalf("last_seen_at=%d,应刷新到 %d", got.LastSeenAt, t0+1800)
	}

	// extendBy<=0 只刷 last_seen,不动 expires —— 这是给「不该续期但要记活跃」的路径用的。
	prevExpires := got.ExpiresAt
	advance(60)
	if err := s.TouchWebSession(ctx, sid, 0); err != nil {
		t.Fatalf("Touch(0): %v", err)
	}
	got, _ = s.GetWebSession(ctx, sid)
	if got.ExpiresAt != prevExpires {
		t.Fatalf("extendBy=0 不该改 expires_at(%d → %d)", prevExpires, got.ExpiresAt)
	}
	if got.LastSeenAt != t0+1860 {
		t.Fatalf("extendBy=0 仍应刷新 last_seen,got %d", got.LastSeenAt)
	}

	// 续期不得把 expires_at 推过绝对截止点。走到第 29 天再续 7 天,应被夹在 created+30d。
	advance(29*24*3600 - 1860)
	if err := s.TouchWebSession(ctx, sid, 7*24*3600); err != nil {
		t.Fatalf("Touch at day29: %v", err)
	}
	got, _ = s.GetWebSession(ctx, sid)
	if want := t0 + WebSessionAbsoluteMaxAge; got.ExpiresAt != want {
		t.Fatalf("expires_at=%d,应被绝对上限夹到 %d —— 不夹住的话滑动窗口能一路把 30 天线推到无穷远",
			got.ExpiresAt, want)
	}
}

func TestTouchWebSession_RefusesSessionsPastTheAbsoluteCap(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const t0 = 1_700_000_000
	advance := withFrozenClock(t, t0)

	a := mkAdmin(t, s, "alice")
	const sid = "sess_stale_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// 一条创建于 31 天前、但 expires_at 还在未来的会话(被持续续期过的那种)。
	mkSession(t, s, a.ID, sid, t0, t0+WebSessionAbsoluteMaxAge+7*24*3600)
	advance(WebSessionAbsoluteMaxAge + 1)

	if err := s.TouchWebSession(ctx, sid, 3600); !errors.Is(err, ErrNotFound) {
		t.Fatalf("超过绝对上限的会话不该还能续期,got %v —— 续得动就等于这条止损线不存在", err)
	}
	if _, err := s.GetWebSession(ctx, sid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get 也该判它失效(与 Touch 同口径),got %v", err)
	}

	// Touch 一个根本不存在的 id 要报 ErrNotFound,不能静默成功 ——
	// 上层据此把请求当未登录处理。
	if err := s.TouchWebSession(ctx, "no_such_session_id_xxxxxxxxxxxxxxxx", 3600); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Touch 不存在的 session 应回 ErrNotFound,got %v", err)
	}
	if err := s.TouchWebSession(ctx, "no_such_session_id_xxxxxxxxxxxxxxxx", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("extendBy=0 分支同样要报 ErrNotFound,got %v", err)
	}
}

// 登出是幂等的,这是有意为之:用户点「退出」想要的是「这个 cookie 不再有效」,
// 已经不在了也算达成。对着已登出的用户弹一个错误页是更差的结果。
func TestDeleteWebSession_IsIdempotentOnPurpose(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a := mkAdmin(t, s, "alice")
	const sid = "sess_logout_aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	mkSession(t, s, a.ID, sid, nowUnix(), nowUnix()+3600)

	if err := s.DeleteWebSession(ctx, sid); err != nil {
		t.Fatalf("首次登出: %v", err)
	}
	if _, err := s.GetWebSession(ctx, sid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("登出后会话应消失,got %v", err)
	}
	if err := s.DeleteWebSession(ctx, sid); err != nil {
		t.Fatalf("重复登出应照常成功(幂等),got %v", err)
	}
	if err := s.DeleteWebSession(ctx, "never_existed_xxxxxxxxxxxxxxxxxxxxxx"); err != nil {
		t.Fatalf("登出一个不存在的 id 也应成功,got %v", err)
	}
}

// 改密 / 禁用 / 删号时要把该 admin 的会话一次清干净 —— 漏掉任何一条,
// 被改掉密码的那个人还能继续用旧 cookie。
func TestDeleteWebSessionsByAdmin_KicksOnlyThatAdmin(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	alice := mkAdmin(t, s, "alice")
	bob := mkAdmin(t, s, "bob")

	now := nowUnix()
	for i := range 3 {
		mkSession(t, s, alice.ID, fmt.Sprintf("alice_sess_%d_xxxxxxxxxxxxxxxxxxxxxx", i), now, now+3600)
	}
	// 一条已过期的也要一并删掉,不能因为它「反正也用不了」就留在库里。
	mkSession(t, s, alice.ID, "alice_dead_xxxxxxxxxxxxxxxxxxxxxxxxxxxx", now-7200, now-1)
	mkSession(t, s, bob.ID, "bob_sess_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", now, now+3600)

	n, err := s.DeleteWebSessionsByAdmin(ctx, alice.ID)
	if err != nil {
		t.Fatalf("DeleteWebSessionsByAdmin: %v", err)
	}
	if n != 4 {
		t.Fatalf("删了 %d 条,应为 4(3 条活的 + 1 条过期的)", n)
	}
	if _, err := s.GetWebSession(ctx, "bob_sess_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"); err != nil {
		t.Fatalf("不该动到别人的会话: %v", err)
	}

	n, err = s.DeleteWebSessionsByAdmin(ctx, alice.ID)
	if err != nil || n != 0 {
		t.Fatalf("重复调用应删 0 条且不报错,got n=%d err=%v", n, err)
	}
}

// 「当前活跃设备」列表是 admin 判断「我的号有没有被别人登着」的唯一依据。
// 它必须和 GetWebSession 的判定完全一致 —— 列出一条实际已失效的设备,
// admin 会以为需要手动踢;漏掉一条仍有效的,真正的入侵者就藏起来了。
func TestListWebSessionsByAdmin_ShowsExactlyWhatGetWouldAccept(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	const t0 = 1_700_000_000
	advance := withFrozenClock(t, t0)
	a := mkAdmin(t, s, "alice")
	other := mkAdmin(t, s, "bob")

	ids := map[string]struct {
		created, expires int64
		wantListed       bool
		why              string
	}{
		"live_recent_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx": {t0, t0 + 3600, true, "普通活跃会话"},
		"live_older_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": {t0 - 100, t0 + 1800, true, "老一点但仍有效"},
		"expired_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": {t0 - 7200, t0 - 1, false, "滑动窗口已过"},
		"overage_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": {
			t0 - WebSessionAbsoluteMaxAge - 1, t0 + 86400, false,
			"expires_at 还在未来,但已越过 30 天绝对上限。列出来会让 admin 以为它还能用"},
	}
	for id, sp := range ids {
		mkSession(t, s, a.ID, id, sp.created, sp.expires)
	}
	mkSession(t, s, other.ID, "bobs_own_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", t0, t0+3600)

	list, err := s.ListWebSessionsByAdmin(ctx, a.ID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[string]bool{}
	for _, ws := range list {
		got[ws.ID] = true
		if ws.AdminID != a.ID {
			t.Fatalf("列出了别人的会话 %s(admin_id=%d)", ws.ID, ws.AdminID)
		}
	}
	for id, sp := range ids {
		if got[id] != sp.wantListed {
			t.Errorf("%s 在列表里=%v,want %v(%s)", id, got[id], sp.wantListed, sp.why)
		}
		// 与 Get 的判定必须一致。
		_, gerr := s.GetWebSession(ctx, id)
		if (gerr == nil) != sp.wantListed {
			t.Errorf("%s:List 收录=%v 但 Get 接受=%v —— 两处判定漂移了", id, sp.wantListed, gerr == nil)
		}
	}

	// 按 last_seen 倒序:admin 扫一眼最上面那条就该是最近一次活动。
	if len(list) == 2 && list[0].LastSeenAt < list[1].LastSeenAt {
		t.Fatalf("列表未按 last_seen 倒序:%d 在 %d 之前", list[0].LastSeenAt, list[1].LastSeenAt)
	}

	// 时钟推过 30 天,所有会话都该从列表里消失。
	advance(WebSessionAbsoluteMaxAge + 1)
	if list, err = s.ListWebSessionsByAdmin(ctx, a.ID); err != nil || len(list) != 0 {
		t.Fatalf("超过绝对上限后列表应为空,got %d 条 err=%v", len(list), err)
	}
}
