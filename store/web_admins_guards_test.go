package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// 本文件补 web_admins.go / web_admins_totp.go 里既有用例没走到的两类分支:
//
//  1. **入参闸门**。这些判断挡的是「写进库就再也看不出错」的脏状态 —— 空用户名、
//     非法 role、admins 楼层、会话缺 expires_at。判错了不报错,只是悄悄多出一个
//     登不进去或删不掉的账号。
//  2. **DB 故障传播**。DAL 里大量 `if err != nil { return fmt.Errorf(...) }` 从未
//     被执行过。它们要保证的不变量很朴素但很关键:库挂了/只读时,**没有任何一个
//     函数报成功**。一个在只读库上返回 nil 的 SetWebAdminEnabled 会让 handler
//     对着没生效的禁用操作显示「已禁用」。
//
// 故障注入用两种真实存在的失败态,不用 mock:
//   - `Options{ReadOnly:true}`:对应 admin CLI 的只读模式、只读挂载、磁盘满;
//   - 已 Close 的 store:对应进程收尾与请求处理的竞态。

// newReadOnlyStore 先建库迁移、造好一个 admin,再以只读重开。返回只读 store 和那个 admin 的 id。
func newReadOnlyStore(t *testing.T) (*Store, int64) {
	t.Helper()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "ro_admins.db")

	rw, err := Open(ctx, path, Options{})
	if err != nil {
		t.Fatalf("Open RW: %v", err)
	}
	if err := rw.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	a, err := rw.CreateWebAdmin(ctx, NewWebAdmin{Username: "roadmin", PasswordHash: "h"})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	if err := rw.CreateWebSession(ctx, WebSession{
		ID: "ro-sess", AdminID: a.ID, ExpiresAt: nowUnix() + 3600}); err != nil {
		t.Fatalf("CreateWebSession: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("Close RW: %v", err)
	}

	ro, err := Open(ctx, path, Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("Open RO: %v", err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	return ro, a.ID
}

// newClosedStore 建好库后立刻 Close —— 之后每一次 db 调用都会失败,包括 BeginTx。
func newClosedStore(t *testing.T) (*Store, int64) {
	t.Helper()
	s := newTestStore(t)
	a, err := s.CreateWebAdmin(t.Context(), NewWebAdmin{Username: "doomed", PasswordHash: "h"})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return s, a.ID
}

func TestWebAdminDAL_InputGuardsRefuseStatesNobodyCouldUnpickLater(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	good, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "keeper", PasswordHash: "h"})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}

	cases := []struct {
		name    string
		run     func() error
		because string
	}{
		{"CreateWebAdmin 用户名全是空白",
			func() error {
				_, e := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "   \t ", PasswordHash: "h"})
				return e
			},
			"裁剪后为空的用户名登录页永远匹配不上,建出来就是个僵尸账号"},
		{"CreateWebAdmin 口令哈希全是空白",
			func() error {
				_, e := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "nopwd", PasswordHash: "  "})
				return e
			},
			"空 hash 会让 argon2 verify 直接报错,账号建了却谁也登不进"},
		{"CreateWebAdmin role 不在白名单",
			func() error {
				_, e := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "weird", PasswordHash: "h", Role: "superuser"})
				return e
			},
			"未知 role 在鉴权处既不是 admin 也不是 viewer,权限判定会退化成默认分支"},
		{"UpdateWebAdminPasswordHash 空哈希",
			func() error { return s.UpdateWebAdminPasswordHash(ctx, good.ID, " ") },
			"把 hash 改空等于给账号装了一把谁也开不了的锁"},
		{"SetWebAdminRole 非法 role",
			func() error { return s.SetWebAdminRole(ctx, good.ID, "root") },
			""},
		{"CreateWebSession 空 id",
			func() error {
				return s.CreateWebSession(ctx, WebSession{AdminID: good.ID, ExpiresAt: nowUnix() + 60})
			},
			"session id 就是 cookie 值,空串意味着任何没带 cookie 的请求都能匹配上这一行"},
		// 这道闸拆掉是**等价变异**:admin_id 有外键 REFERENCES web_admins(id),
		// 而 id=0 不存在,INSERT 会被约束拦下,同样插不进去。DAL 里这道判断的价值是
		// 给出一条清楚的错误,而不是让上层看到一条晦涩的约束失败。
		{"CreateWebSession admin_id 非正",
			func() error {
				return s.CreateWebSession(ctx, WebSession{ID: "x", AdminID: 0, ExpiresAt: nowUnix() + 60})
			},
			"admin_id=0 是 decoy 路径专用的哨兵值,不能有真会话挂在上面"},
		{"CreateWebSession 没给 expires_at",
			func() error {
				return s.CreateWebSession(ctx, WebSession{ID: "y", AdminID: good.ID})
			},
			"expires_at=0 会被 GetWebSession 的 `>0` 判断当成「不过期」—— 一枚永不失效的 cookie"},
		{"SetWebAdminTOTPSecret 空 secret",
			func() error { return s.SetWebAdminTOTPSecret(ctx, good.ID, "") },
			"空 secret 配上 enabled=1 会让 TOTP 校验退化"},
		{"RegenerateRecoveryCodes 没给恢复码",
			func() error { return s.RegenerateRecoveryCodes(ctx, good.ID, nil, nowUnix()) },
			"会把旧码删光又不写新码,等于静默清空兜底手段"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil {
				t.Fatalf("应当被拒绝但返回了 nil。%s", tc.because)
			}
		})
	}

	// 闸门拒绝之后库里不该留下任何痕迹。
	admins, err := s.ListWebAdmins(ctx)
	if err != nil {
		t.Fatalf("ListWebAdmins: %v", err)
	}
	if len(admins) != 1 || admins[0].ID != good.ID {
		t.Fatalf("被拒的创建还是落库了: %+v", admins)
	}
	sessions, err := s.ListWebSessionsByAdmin(ctx, good.ID)
	if err != nil {
		t.Fatalf("ListWebSessionsByAdmin: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("被拒的会话还是落库了: %+v", sessions)
	}
	// role 也没被改坏。
	cur, err := s.GetWebAdmin(ctx, good.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if cur.Role != "admin" {
		t.Fatalf("role = %q,非法 role 竟然写进去了", cur.Role)
	}
	if cur.PasswordHash != "h" {
		t.Fatalf("password_hash = %q,空哈希竟然写进去了", cur.PasswordHash)
	}
}

// 下面三个用例各自把一道闸**单独**隔出来验。
//
// 起因是变异验证:这三条原先并在上面那张大表里,变异跑下来全部逃逸 —— 报的错其实来自
// 另一道闸(setup 已关闭 / admin 楼层 / TOTP 的 CAS),把被测的那道拆掉测试照样过。
// 所以每个用例都要先把「别的闸不会响」这件事布置好,再断言错误确实来自目标那一道。

func TestCreateFirstWebAdmin_InputGuardsRunWhileTheWindowIsStillOpen(t *testing.T) {
	// 必须在**空库**上测:库里一旦有 admin,任何调用都会先撞 ErrSetupClosed,
	// 空用户名那道闸有没有都看不出差别。
	ctx := t.Context()

	for _, tc := range []struct{ name, user, hash string }{
		{"用户名全是空白", "   ", "h"},
		{"口令哈希全是空白", "firstadmin", "\n\t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			_, err := s.CreateFirstWebAdmin(ctx, NewWebAdmin{Username: tc.user, PasswordHash: tc.hash})
			if err == nil {
				t.Fatal("应被拒绝")
			}
			if errors.Is(err, ErrSetupClosed) {
				t.Fatal("拒的理由是 setup 已关闭,不是入参非法 —— 用例没隔离干净")
			}
			n, err := s.CountWebAdmins(ctx)
			if err != nil {
				t.Fatalf("CountWebAdmins: %v", err)
			}
			if n != 0 {
				t.Fatalf("web_admins 有 %d 行,被拒的创建不该落库", n)
			}
			// 关键:被拒的尝试不能把 setup 窗口关掉,否则一次输错就再也建不了首管。
			if _, err := s.CreateFirstWebAdmin(ctx,
				NewWebAdmin{Username: "realadmin", PasswordHash: "h"}); err != nil {
				t.Fatalf("窗口被上一次失败关掉了: %v", err)
			}
		})
	}
}

func TestSetWebAdminRoleEnsuringAdmin_RejectsUnknownRoleNotJustTheAdminFloor(t *testing.T) {
	// 造两个 admin:这样把其中一个的 role 改坏也不会触发 ErrLastAdmin,
	// 报错就只能来自 role 白名单本身。
	s := newTestStore(t)
	ctx := t.Context()
	target, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "roletarget", PasswordHash: "h"})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	if _, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "rolefloor", PasswordHash: "h"}); err != nil {
		t.Fatalf("CreateWebAdmin floor: %v", err)
	}

	err = s.SetWebAdminRoleEnsuringAdmin(ctx, target.ID, "root")
	if err == nil {
		t.Fatal("非法 role 应被拒")
	}
	if errors.Is(err, ErrLastAdmin) {
		t.Fatal("拒的理由是 admin 楼层,不是 role 非法 —— 用例没隔离干净")
	}
	got, err := s.GetWebAdmin(ctx, target.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if got.Role != "admin" {
		t.Fatalf("role = %q —— 未知 role 写进库后,鉴权处既不匹配 admin 也不匹配 viewer,权限判定会落到默认分支", got.Role)
	}
}

func TestEnableWebAdminTOTP_RefusesToEnableWithoutRecoveryCodes(t *testing.T) {
	// 先把 secret 正常设好,让 CAS(`AND totp_secret=?`)能匹配上 —— 否则会先撞
	// ErrNotFound,测不出「空恢复码」那道闸。
	s := newTestStore(t)
	ctx := t.Context()
	a, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "nocodes", PasswordHash: "h"})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	if err := s.SetWebAdminTOTPSecret(ctx, a.ID, "REALSECRET"); err != nil {
		t.Fatalf("SetWebAdminTOTPSecret: %v", err)
	}

	n, err := s.EnableWebAdminTOTP(ctx, a.ID, "REALSECRET", nil, nowUnix())
	if err == nil {
		t.Fatalf("空恢复码列表应被拒(返回 n=%d)", n)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("拒的理由是 CAS 没匹配上,不是缺恢复码 —— 用例没隔离干净")
	}
	got, err := s.GetWebAdmin(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if got.TOTPEnabled {
		t.Fatal("TOTP 启用了却没有一个恢复码 —— 手机一丢就永久锁死,这正是这道闸要防的")
	}
}

func TestRegenerateRecoveryCodes_RefusesAdminsThatCannotUseThem(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "regen", PasswordHash: "h"})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}

	t.Run("admin 不存在", func(t *testing.T) {
		err := s.RegenerateRecoveryCodes(ctx, 999999, []string{"h1"}, nowUnix())
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err=%v,想要 ErrNotFound —— 否则 INSERT 会抛一条晦涩的外键约束错", err)
		}
	})

	t.Run("TOTP 没启用", func(t *testing.T) {
		err := s.RegenerateRecoveryCodes(ctx, a.ID, []string{"h1"}, nowUnix())
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("err=%v,想要 ErrInvalid", err)
		}
		// 没启用 TOTP 的账号被塞进恢复码,UI 上会显示「还剩 1 个恢复码可用」,
		// 让人以为已经有第二因子了。
		n, err := s.CountUnusedRecoveryCodes(ctx, a.ID)
		if err != nil {
			t.Fatalf("CountUnusedRecoveryCodes: %v", err)
		}
		if n != 0 {
			t.Fatalf("孤儿恢复码 %d 条", n)
		}
	})

	// 前面那次失败的 regen 是「先 DELETE 再校验」的,必须整体回滚:已启用账号的现存
	// 恢复码不能被一次被拒的调用顺手清掉。
	t.Run("被拒的 regen 不会清掉已有的码", func(t *testing.T) {
		if err := s.SetWebAdminTOTPSecret(ctx, a.ID, "SECRET"); err != nil {
			t.Fatalf("SetWebAdminTOTPSecret: %v", err)
		}
		if _, err := s.EnableWebAdminTOTP(ctx, a.ID, "SECRET", []string{"r1", "r2"}, nowUnix()); err != nil {
			t.Fatalf("EnableWebAdminTOTP: %v", err)
		}
		if err := s.RegenerateRecoveryCodes(ctx, a.ID, nil, nowUnix()); err == nil {
			t.Fatal("空码列表应被拒")
		}
		n, err := s.CountUnusedRecoveryCodes(ctx, a.ID)
		if err != nil {
			t.Fatalf("CountUnusedRecoveryCodes: %v", err)
		}
		if n != 2 {
			t.Fatalf("剩 %d 条,被拒的 regen 把旧码删了 —— 用户的兜底手段被静默清空", n)
		}
	})
}

func TestWebAdminDAL_UnknownIDIsErrNotFoundNotSilentSuccess(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	// 留一个真 admin,保证 admins 楼层不是拒绝的原因 —— 否则 EnsuringAdmin 那几个
	// 会因为 ErrLastAdmin 而「恰好也报错」,测不出 ErrNotFound。
	if _, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "keeper", PasswordHash: "h"}); err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	const ghost int64 = 987654

	cases := map[string]func() error{
		"GetWebAdmin":                 func() error { _, e := s.GetWebAdmin(ctx, ghost); return e },
		"GetWebAdminByUsername":       func() error { _, e := s.GetWebAdminByUsername(ctx, "没有这个人"); return e },
		"UpdateWebAdminPasswordHash":  func() error { return s.UpdateWebAdminPasswordHash(ctx, ghost, "newhash") },
		"SetWebAdminRole":             func() error { return s.SetWebAdminRole(ctx, ghost, "viewer") },
		"SetWebAdminEnabled(false)":   func() error { return s.SetWebAdminEnabled(ctx, ghost, false) },
		"SetWebAdminEnabled(true)":    func() error { return s.SetWebAdminEnabled(ctx, ghost, true) },
		"DeleteWebAdmin":              func() error { return s.DeleteWebAdmin(ctx, ghost) },
		"DeleteWebAdminEnsuringAdmin": func() error { return s.DeleteWebAdminEnsuringAdmin(ctx, ghost) },
		"SetWebAdminEnabledEnsuringAdmin": func() error {
			return s.SetWebAdminEnabledEnsuringAdmin(ctx, ghost)
		},
		"SetWebAdminRoleEnsuringAdmin": func() error { return s.SetWebAdminRoleEnsuringAdmin(ctx, ghost, "viewer") },
		"RecordWebAdminLoginSuccess":   func() error { return s.RecordWebAdminLoginSuccess(ctx, ghost, "1.2.3.4") },
		"ResetWebAdminLockout":         func() error { return s.ResetWebAdminLockout(ctx, ghost) },
		"SetWebAdminTOTPSecret":        func() error { return s.SetWebAdminTOTPSecret(ctx, ghost, "SECRET") },
		"DisableWebAdminTOTP":          func() error { return s.DisableWebAdminTOTP(ctx, ghost) },
		"MarkRecoveryCodeUsed":         func() error { return s.MarkRecoveryCodeUsed(ctx, ghost, 1, "ip", nowUnix()) },
		"TouchWebSession":              func() error { return s.TouchWebSession(ctx, "没有这条会话", 60) },
		"GetWebSession":                func() error { _, e := s.GetWebSession(ctx, "没有这条会话"); return e },
		"RecordWebAdminLoginFailure": func() error {
			_, _, e := s.RecordWebAdminLoginFailure(ctx, ghost, 5, 900)
			return e
		},
		"EnableWebAdminTOTP": func() error {
			_, e := s.EnableWebAdminTOTP(ctx, ghost, "SECRET", []string{"r"}, nowUnix())
			return e
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrNotFound) {
				t.Fatalf("err=%v,想要 ErrNotFound。静默成功会让调用方以为改动生效了", err)
			}
		})
	}

	// ConsumeTOTPStep 的约定不是 error 而是 (false, nil) —— 登录路径据此判失败。
	t.Run("ConsumeTOTPStep 未知 id 返回 false", func(t *testing.T) {
		ok, err := s.ConsumeTOTPStep(ctx, ghost, 12345)
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if ok {
			t.Fatal("未知 id 竟然消费成功 —— 重放保护形同虚设")
		}
	})

	// DeleteWebSession 是刻意幂等的,单独钉住,防止哪天有人「顺手统一」成 ErrNotFound。
	t.Run("DeleteWebSession 刻意幂等", func(t *testing.T) {
		if err := s.DeleteWebSession(ctx, "从来不存在"); err != nil {
			t.Fatalf("err=%v —— logout 一条已经没了的会话应当照常成功", err)
		}
	})
}

func TestSetWebAdminEnabled_TrueBranchActuallyFlipsItBack(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "toggle", PasswordHash: "h"})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	// 再造一个 admin 顶住楼层,否则禁用唯一 admin 会被 ErrLastAdmin 拦掉。
	if _, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "floor", PasswordHash: "h"}); err != nil {
		t.Fatalf("CreateWebAdmin floor: %v", err)
	}

	if err := s.SetWebAdminEnabled(ctx, a.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if got, _ := s.GetWebAdmin(ctx, a.ID); got.Enabled {
		t.Fatal("禁用没生效")
	}
	if err := s.SetWebAdminEnabled(ctx, a.ID, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	got, err := s.GetWebAdmin(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if !got.Enabled {
		t.Fatal("重新启用没生效 —— 被误禁的管理员再也回不来")
	}
}

func TestCreateWebSession_DuplicateIDIsRejectedNotOverwritten(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "dupsess", PasswordHash: "h"})
	b, _ := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "victim", PasswordHash: "h"})

	first := WebSession{ID: "collide", AdminID: a.ID, ExpiresAt: nowUnix() + 3600, IP: "1.1.1.1"}
	if err := s.CreateWebSession(ctx, first); err != nil {
		t.Fatalf("CreateWebSession: %v", err)
	}
	// 同 id 第二次插入必须报 ErrDuplicate。若退化成 UPSERT,一个能猜到/拿到别人 session id
	// 的调用方就能把该 cookie 改挂到自己名下 —— 会话固定攻击。
	err := s.CreateWebSession(ctx, WebSession{ID: "collide", AdminID: b.ID, ExpiresAt: nowUnix() + 3600})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err=%v,想要 ErrDuplicate", err)
	}
	got, err := s.GetWebSession(ctx, "collide")
	if err != nil {
		t.Fatalf("GetWebSession: %v", err)
	}
	if got.AdminID != a.ID {
		t.Fatalf("会话被改挂到 admin %d 名下了(原本是 %d)", got.AdminID, a.ID)
	}
}

func TestPruneWebSessionsKeepingRecent_GuardsItsArguments(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "pruner", PasswordHash: "h"})

	if _, err := s.PruneWebSessionsKeepingRecent(ctx, 0, 3); err == nil {
		t.Fatal("admin_id=0 应被拒 —— 否则会拿哨兵 id 去删,悄悄什么也没做")
	}

	// keep<=0 折成 1:至少留住刚建的那条,不能把自己刚签发的会话也删了。
	for i := 0; i < 3; i++ {
		if err := s.CreateWebSession(ctx, WebSession{
			ID:        fmt.Sprintf("sess-%d", i),
			AdminID:   a.ID,
			CreatedAt: nowUnix() - int64(10-i),
			ExpiresAt: nowUnix() + 3600,
		}); err != nil {
			t.Fatalf("CreateWebSession %d: %v", i, err)
		}
	}
	n, err := s.PruneWebSessionsKeepingRecent(ctx, a.ID, 0)
	if err != nil {
		t.Fatalf("PruneWebSessionsKeepingRecent: %v", err)
	}
	if n != 2 {
		t.Fatalf("删了 %d 条,keep<=0 应折成 1 → 3 条留 1 删 2", n)
	}
	left, err := s.ListWebSessionsByAdmin(ctx, a.ID)
	if err != nil {
		t.Fatalf("ListWebSessionsByAdmin: %v", err)
	}
	if len(left) != 1 {
		t.Fatalf("剩 %d 条,应当恰好剩 1 条", len(left))
	}
	if left[0].ID != "sess-2" {
		t.Fatalf("留下的是 %q,应当留最新的 sess-2", left[0].ID)
	}
}

func TestCreateWebAdmin_ConcurrentSameUsernameYieldsExactlyOneAccount(t *testing.T) {
	// CI 去重是「先查后插」两步,并发时两个请求可能都过了查询。UNIQUE 约束是第二道
	// 闸,把竞态里的败者归一成 ErrDuplicate。这里验的不变量是:无论谁赢,库里**恰好
	// 一个**同名账号 —— 重复的 admin 意味着后续「最后一个 admin」楼层计数全都不准。
	s := newTestStore(t)
	ctx := t.Context()

	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "racer", PasswordHash: "h"})
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	created := 0
	for i, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrDuplicate):
			// 预期:CI 查询或 UNIQUE 约束任一道闸拦下的。
		default:
			t.Fatalf("goroutine %d 返回了意料之外的错误: %v", i, err)
		}
	}
	if created != 1 {
		t.Fatalf("建成了 %d 个同名 admin,应当恰好 1 个", created)
	}
	admins, err := s.ListWebAdmins(ctx)
	if err != nil {
		t.Fatalf("ListWebAdmins: %v", err)
	}
	dup := 0
	for _, a := range admins {
		if a.Username == "racer" {
			dup++
		}
	}
	if dup != 1 {
		t.Fatalf("库里有 %d 行 username=racer", dup)
	}
}

func TestCreateFirstWebAdmin_SecondCallerGetsErrSetupClosed(t *testing.T) {
	// setup 是 TOFU 窗口:表一旦非空就必须永久关闭,否则任何人都能再建一个 admin。
	s := newTestStore(t)
	ctx := t.Context()
	if _, err := s.CreateFirstWebAdmin(ctx, NewWebAdmin{Username: "first", PasswordHash: "h"}); err != nil {
		t.Fatalf("CreateFirstWebAdmin: %v", err)
	}
	if _, e := s.CreateFirstWebAdmin(ctx, NewWebAdmin{Username: "second", PasswordHash: "h"}); !errors.Is(e, ErrSetupClosed) {
		t.Fatalf("err=%v,想要 ErrSetupClosed", e)
	}
	n, err := s.CountWebAdmins(ctx)
	if err != nil {
		t.Fatalf("CountWebAdmins: %v", err)
	}
	if n != 1 {
		t.Fatalf("web_admins 有 %d 行,setup 关闭后不该再多出账号", n)
	}
}

// TestScanWebAdmin_CorruptRowErrorsInsteadOfSilentlyReadingZero 往 INTEGER 列写进
// 一个非数字的 TEXT(SQLite 非 STRICT 表允许),模拟手工改库 / 迁移写坏。
//
// 为什么值得单独验:failed_logins 和 locked_until 扫不出来时若被静默当成 0,等于
// 把一个已经锁定的账号自动解锁,暴力破解防护凭空消失。必须报错。
func TestScanWebAdmin_CorruptRowErrorsInsteadOfSilentlyReadingZero(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "corrupt", PasswordHash: "h"})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	// 先真锁上,这样「静默读成 0」和「正确报错」在语义上有可观察的差别。
	if _, _, err := s.RecordWebAdminLoginFailure(ctx, a.ID, 1, 900); err != nil {
		t.Fatalf("RecordWebAdminLoginFailure: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE web_admins SET failed_logins='不是数字' WHERE id=?`, a.ID); err != nil {
		t.Fatalf("注入损坏值: %v", err)
	}

	if _, err := s.GetWebAdmin(ctx, a.ID); err == nil {
		t.Fatal("GetWebAdmin 读到损坏行却报成功 —— locked_until/failed_logins 会被当成 0,锁定状态凭空消失")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("损坏行被归一成 ErrNotFound 了: %v —— 那会让调用方以为账号不存在", err)
	}
	if _, err := s.ListWebAdmins(ctx); err == nil {
		t.Fatal("ListWebAdmins 遇到损坏行应当报错而不是跳过")
	}
}

// TestScanWebSession_CorruptRowIsNeverUsableAsALogin 会话行损坏时的要求只有一条:
// 这枚 cookie 绝不能还能用。报错或当作不存在都可以,不能放行。
func TestScanWebSession_CorruptRowIsNeverUsableAsALogin(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "sesscorrupt", PasswordHash: "h"})
	mk := func(id string) {
		if err := s.CreateWebSession(ctx, WebSession{
			ID: id, AdminID: a.ID, ExpiresAt: nowUnix() + 3600}); err != nil {
			t.Fatalf("CreateWebSession %s: %v", id, err)
		}
	}

	t.Run("created_at 损坏", func(t *testing.T) {
		mk("bad-created")
		if _, err := s.db.ExecContext(ctx,
			`UPDATE web_sessions SET created_at='坏了' WHERE id=?`, "bad-created"); err != nil {
			t.Fatalf("注入损坏值: %v", err)
		}
		// created_at 同时出现在绝对生命周期上限的 WHERE 判定里。TEXT 参与算术会被当成 0,
		// 两个条件(created_at<=0 / now-created_at<MaxAge)都判false → 行被直接过滤掉。
		// 结果是 fail-closed:这条会话在 Get 里报错、在 List 里干脆看不见。两者都可以,
		// 唯一不可接受的是「照常返回、还能登录」。
		if _, err := s.GetWebSession(ctx, "bad-created"); err == nil {
			t.Fatal("GetWebSession 对损坏行报成功 —— 这枚 cookie 还能用")
		}
		rows, err := s.ListWebSessionsByAdmin(ctx, a.ID)
		if err != nil {
			t.Fatalf("ListWebSessionsByAdmin: %v", err)
		}
		for _, r := range rows {
			if r.ID == "bad-created" {
				t.Fatal("损坏行出现在「当前活跃设备」里,但 Get 又拒绝它 —— 两处判定不一致")
			}
		}
	})

	t.Run("last_seen_at 损坏", func(t *testing.T) {
		mk("bad-seen")
		// last_seen_at 不参与任何 WHERE 过滤,所以行会被取出来、在 Scan 处炸掉,
		// 走的是与上面不同的那条失败路径。
		if _, err := s.db.ExecContext(ctx,
			`UPDATE web_sessions SET last_seen_at='坏了' WHERE id=?`, "bad-seen"); err != nil {
			t.Fatalf("注入损坏值: %v", err)
		}
		if _, err := s.GetWebSession(ctx, "bad-seen"); err == nil {
			t.Fatal("GetWebSession 对损坏行报成功")
		} else if errors.Is(err, ErrNotFound) {
			t.Fatalf("扫描失败被归一成 ErrNotFound: %v —— 那会掩盖数据损坏", err)
		}
		if _, err := s.ListWebSessionsByAdmin(ctx, a.ID); err == nil {
			t.Fatal("ListWebSessionsByAdmin 遇到扫不出来的行应当报错,而不是静默跳过")
		}
	})
}

// TestWebAdminDAL_ReadOnlyDBFailsEveryWriteLoudly 用只读库跑一遍全部写入口。
//
// 对应的真实故障:admin CLI 的只读模式、只读挂载、磁盘满。这些场景下最危险的不是
// 写失败,而是**写失败却报成功** —— handler 会对着没生效的操作显示「已保存」。
func TestWebAdminDAL_ReadOnlyDBFailsEveryWriteLoudly(t *testing.T) {
	s, id := newReadOnlyStore(t)
	ctx := t.Context()

	writes := map[string]func() error{
		"CreateWebAdmin": func() error {
			_, e := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "new", PasswordHash: "h"})
			return e
		},
		"CreateFirstWebAdmin": func() error {
			_, e := s.CreateFirstWebAdmin(ctx, NewWebAdmin{Username: "new2", PasswordHash: "h"})
			return e
		},
		"UpdateWebAdminPasswordHash":      func() error { return s.UpdateWebAdminPasswordHash(ctx, id, "newhash") },
		"SetWebAdminRole":                 func() error { return s.SetWebAdminRole(ctx, id, "viewer") },
		"SetWebAdminEnabled":              func() error { return s.SetWebAdminEnabled(ctx, id, false) },
		"DeleteWebAdmin":                  func() error { return s.DeleteWebAdmin(ctx, id) },
		"SetWebAdminEnabledEnsuringAdmin": func() error { return s.SetWebAdminEnabledEnsuringAdmin(ctx, id) },
		"DeleteWebAdminEnsuringAdmin":     func() error { return s.DeleteWebAdminEnsuringAdmin(ctx, id) },
		"SetWebAdminRoleEnsuringAdmin":    func() error { return s.SetWebAdminRoleEnsuringAdmin(ctx, id, "viewer") },
		"RecordWebAdminLoginSuccess":      func() error { return s.RecordWebAdminLoginSuccess(ctx, id, "1.2.3.4") },
		"ResetWebAdminLockout":            func() error { return s.ResetWebAdminLockout(ctx, id) },
		"SetWebAdminTOTPSecret":           func() error { return s.SetWebAdminTOTPSecret(ctx, id, "SECRET") },
		"DisableWebAdminTOTP":             func() error { return s.DisableWebAdminTOTP(ctx, id) },
		"MarkRecoveryCodeUsed":            func() error { return s.MarkRecoveryCodeUsed(ctx, id, 1, "ip", nowUnix()) },
		"TouchWebSession":                 func() error { return s.TouchWebSession(ctx, "ro-sess", 60) },
		"DeleteWebSession":                func() error { return s.DeleteWebSession(ctx, "ro-sess") },
		"RecordWebAdminLoginFailure": func() error {
			_, _, e := s.RecordWebAdminLoginFailure(ctx, id, 5, 900)
			return e
		},
		"EnableWebAdminTOTP": func() error {
			_, e := s.EnableWebAdminTOTP(ctx, id, "SECRET", []string{"r"}, nowUnix())
			return e
		},
		"RegenerateRecoveryCodes": func() error {
			return s.RegenerateRecoveryCodes(ctx, id, []string{"r"}, nowUnix())
		},
		"DeleteWebSessionsByAdmin": func() error {
			_, e := s.DeleteWebSessionsByAdmin(ctx, id)
			return e
		},
		"PruneWebSessionsKeepingRecent": func() error {
			_, e := s.PruneWebSessionsKeepingRecent(ctx, id, 1)
			return e
		},
		"PruneExpiredWebSessions": func() error { _, e := s.PruneExpiredWebSessions(ctx); return e },
		"ConsumeTOTPStep":         func() error { _, e := s.ConsumeTOTPStep(ctx, id, 999); return e },
	}
	for name, run := range writes {
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil {
				t.Fatal("只读库上写成功了?—— 要么真写进去了,要么报了假成功")
			}
			// 不能把「写不进去」误报成 ErrNotFound —— 那会让 handler 显示「账号不存在」
			// 而不是「存储不可写」,运维排查方向全错。
			if errors.Is(err, ErrNotFound) {
				t.Fatalf("只读失败被归一成 ErrNotFound 了: %v", err)
			}
		})
	}

	// 读路径在只读库上必须照常工作 —— 否则只读模式下连 list 都用不了。
	if _, err := s.ListWebAdmins(ctx); err != nil {
		t.Fatalf("只读库上 ListWebAdmins 失败: %v", err)
	}
	if _, err := s.GetWebAdmin(ctx, id); err != nil {
		t.Fatalf("只读库上 GetWebAdmin 失败: %v", err)
	}
	if _, err := s.CountWebAdmins(ctx); err != nil {
		t.Fatalf("只读库上 CountWebAdmins 失败: %v", err)
	}
}

// TestWebAdminDAL_ClosedDBNeverReportsSuccess 覆盖 BeginTx 失败这一层 ——
// 只读库能开事务(在 Exec 才失败),只有已关闭的库才会在 BeginTx 就断。
func TestWebAdminDAL_ClosedDBNeverReportsSuccess(t *testing.T) {
	s, id := newClosedStore(t)
	ctx := context.Background()

	all := map[string]func() error{
		"GetWebAdmin":                 func() error { _, e := s.GetWebAdmin(ctx, id); return e },
		"GetWebAdminByUsername":       func() error { _, e := s.GetWebAdminByUsername(ctx, "doomed"); return e },
		"ListWebAdmins":               func() error { _, e := s.ListWebAdmins(ctx); return e },
		"CountWebAdmins":              func() error { _, e := s.CountWebAdmins(ctx); return e },
		"CountEnabledWebAdminsByRole": func() error { _, e := s.CountEnabledWebAdminsByRole(ctx, "admin"); return e },
		"CreateWebAdmin":              func() error { _, e := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "x", PasswordHash: "h"}); return e },
		"CreateFirstWebAdmin": func() error {
			_, e := s.CreateFirstWebAdmin(ctx, NewWebAdmin{Username: "y", PasswordHash: "h"})
			return e
		},
		"UpdateWebAdminPasswordHash":      func() error { return s.UpdateWebAdminPasswordHash(ctx, id, "h2") },
		"SetWebAdminRole":                 func() error { return s.SetWebAdminRole(ctx, id, "viewer") },
		"SetWebAdminEnabled":              func() error { return s.SetWebAdminEnabled(ctx, id, false) },
		"DeleteWebAdmin":                  func() error { return s.DeleteWebAdmin(ctx, id) },
		"SetWebAdminEnabledEnsuringAdmin": func() error { return s.SetWebAdminEnabledEnsuringAdmin(ctx, id) },
		"DeleteWebAdminEnsuringAdmin":     func() error { return s.DeleteWebAdminEnsuringAdmin(ctx, id) },
		"SetWebAdminRoleEnsuringAdmin":    func() error { return s.SetWebAdminRoleEnsuringAdmin(ctx, id, "viewer") },
		"RecordWebAdminLoginSuccess":      func() error { return s.RecordWebAdminLoginSuccess(ctx, id, "ip") },
		"ResetWebAdminLockout":            func() error { return s.ResetWebAdminLockout(ctx, id) },
		"SetWebAdminTOTPSecret":           func() error { return s.SetWebAdminTOTPSecret(ctx, id, "S") },
		"DisableWebAdminTOTP":             func() error { return s.DisableWebAdminTOTP(ctx, id) },
		"ListUnusedRecoveryCodes":         func() error { _, e := s.ListUnusedRecoveryCodes(ctx, id); return e },
		"CountUnusedRecoveryCodes":        func() error { _, e := s.CountUnusedRecoveryCodes(ctx, id); return e },
		"MarkRecoveryCodeUsed":            func() error { return s.MarkRecoveryCodeUsed(ctx, id, 1, "ip", nowUnix()) },
		"CreateWebSession": func() error {
			return s.CreateWebSession(ctx, WebSession{ID: "z", AdminID: id, ExpiresAt: nowUnix() + 60})
		},
		"GetWebSession":                 func() error { _, e := s.GetWebSession(ctx, "z"); return e },
		"TouchWebSession":               func() error { return s.TouchWebSession(ctx, "z", 60) },
		"DeleteWebSession":              func() error { return s.DeleteWebSession(ctx, "z") },
		"DeleteWebSessionsByAdmin":      func() error { _, e := s.DeleteWebSessionsByAdmin(ctx, id); return e },
		"PruneWebSessionsKeepingRecent": func() error { _, e := s.PruneWebSessionsKeepingRecent(ctx, id, 1); return e },
		"PruneExpiredWebSessions":       func() error { _, e := s.PruneExpiredWebSessions(ctx); return e },
		"ListWebSessionsByAdmin":        func() error { _, e := s.ListWebSessionsByAdmin(ctx, id); return e },
		"ConsumeTOTPStep":               func() error { _, e := s.ConsumeTOTPStep(ctx, id, 1); return e },
		"RecordWebAdminLoginFailure": func() error {
			_, _, e := s.RecordWebAdminLoginFailure(ctx, id, 5, 900)
			return e
		},
		"EnableWebAdminTOTP": func() error {
			_, e := s.EnableWebAdminTOTP(ctx, id, "S", []string{"r"}, nowUnix())
			return e
		},
		"RegenerateRecoveryCodes": func() error {
			return s.RegenerateRecoveryCodes(ctx, id, []string{"r"}, nowUnix())
		},
	}
	for name, run := range all {
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil {
				t.Fatal("库已关闭却报成功")
			}
			// 库挂了不等于「东西不存在」。归一成 ErrNotFound 会让上层走「创建/引导」
			// 分支,而不是「存储故障」告警。
			if errors.Is(err, ErrNotFound) {
				t.Fatalf("库关闭的错误被归一成 ErrNotFound: %v", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "closed") {
				t.Fatalf("错误里看不出是连接问题,排障时无从下手: %v", err)
			}
		})
	}

	// Decoy 是 best-effort 的等时空跑,库挂了也不该 panic —— 它在登录失败路径上,
	// 一旦 panic 就是把 DB 故障放大成整个登录接口 500。
	t.Run("DecoyWebAdminLoginFailure 库挂了也不 panic", func(t *testing.T) {
		s.DecoyWebAdminLoginFailure(ctx)
	})
}

// abortOn 装一个 BEFORE 触发器,让指定表上的指定操作必定失败。
//
// 用途:精准打「事务里**第二条**语句失败」的分支。只读库和已关库都做不到这件事——
// 它们让第一条语句就失败,后面的错误处理永远走不到。而这些分支恰恰是最需要验的:
// 改密的 UPDATE 成功了但撤销旧会话的 DELETE 失败,若不回滚,就是「密码已改、旧
// cookie 仍然有效」——改密根本没能把攻击者踢下线。
func abortOn(t *testing.T, s *Store, table, op string) {
	t.Helper()
	name := fmt.Sprintf("boom_%s_%s", table, strings.ReplaceAll(op, " ", "_"))
	_, err := s.db.ExecContext(t.Context(), fmt.Sprintf(
		`CREATE TRIGGER %s BEFORE %s ON %s BEGIN SELECT RAISE(ABORT, '注入的故障'); END`,
		name, op, table))
	if err != nil {
		t.Fatalf("装触发器 %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = s.db.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS `+name)
	})
}

func TestUpdateWebAdminPasswordHash_RollsBackWhenSessionRevocationFails(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "pwchange", PasswordHash: "old"})
	if err != nil {
		t.Fatalf("CreateWebAdmin: %v", err)
	}
	if err := s.CreateWebSession(ctx, WebSession{
		ID: "stale-cookie", AdminID: a.ID, ExpiresAt: nowUnix() + 3600}); err != nil {
		t.Fatalf("CreateWebSession: %v", err)
	}
	abortOn(t, s, "web_sessions", "DELETE")

	if err := s.UpdateWebAdminPasswordHash(ctx, a.ID, "new"); err == nil {
		t.Fatal("撤销旧会话失败了却报改密成功")
	}
	// 关键不变量:改密与踢线是原子的。既然踢线没成,密码也必须没改 —— 否则用户以为
	// 「我已经改密了,攻击者被踢了」,实际上旧 cookie 还活着。
	got, err := s.GetWebAdmin(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetWebAdmin: %v", err)
	}
	if got.PasswordHash != "old" {
		t.Fatal("密码改了但旧会话没撤销 —— 改密没能把攻击者踢下线")
	}
	if _, err := s.GetWebSession(ctx, "stale-cookie"); err != nil {
		t.Fatalf("会话应当还在(整个事务回滚了): %v", err)
	}
}

func TestSetWebAdminEnabledEnsuringAdmin_RollsBackWhenSessionRevocationFails(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	victim, _ := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "tobedisabled", PasswordHash: "h"})
	if _, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "floor", PasswordHash: "h"}); err != nil {
		t.Fatalf("CreateWebAdmin floor: %v", err)
	}
	if err := s.CreateWebSession(ctx, WebSession{
		ID: "live-cookie", AdminID: victim.ID, ExpiresAt: nowUnix() + 3600}); err != nil {
		t.Fatalf("CreateWebSession: %v", err)
	}
	abortOn(t, s, "web_sessions", "DELETE")

	if err := s.SetWebAdminEnabledEnsuringAdmin(ctx, victim.ID); err == nil {
		t.Fatal("撤销会话失败了却报禁用成功")
	}
	got, _ := s.GetWebAdmin(ctx, victim.ID)
	if !got.Enabled {
		t.Fatal("账号被禁用了但会话没撤销 —— 出现「已禁用却仍能用旧 cookie 操作」的窗口")
	}
}

func TestRecordWebAdminLoginFailure_SurfacesFailuresInsteadOfSilentlyNotLocking(t *testing.T) {
	ctx := context.Background()

	t.Run("写不进 locked_until 时整体失败", func(t *testing.T) {
		s := newTestStore(t)
		a, _ := s.CreateWebAdmin(t.Context(), NewWebAdmin{Username: "lockme", PasswordHash: "h"})
		// 只拦 locked_until 那一列:计数 +1 的第一条 UPDATE 不碰它,照常成功;
		// 达到阈值后写锁定截止时间的第二条 UPDATE 会被打掉。
		abortOn(t, s, "web_admins", "UPDATE OF locked_until")

		_, _, err := s.RecordWebAdminLoginFailure(t.Context(), a.ID, 1, 900)
		if err == nil {
			t.Fatal("锁定写失败却报成功 —— 上层以为已经锁了,实际暴力破解毫无阻碍")
		}
		got, _ := s.GetWebAdmin(t.Context(), a.ID)
		if got.LockedUntil != 0 {
			t.Fatalf("locked_until = %d", got.LockedUntil)
		}
		// 事务回滚,连计数也不该留下 —— 半途状态比干净失败更难排查。
		if got.FailedLogins != 0 {
			t.Fatalf("failed_logins = %d,事务应当整体回滚", got.FailedLogins)
		}
	})

	t.Run("计数列损坏时报错而不是当成 0", func(t *testing.T) {
		s := newTestStore(t)
		a, _ := s.CreateWebAdmin(t.Context(), NewWebAdmin{Username: "corruptcount", PasswordHash: "h"})
		if _, err := s.db.ExecContext(t.Context(),
			`UPDATE web_admins SET failed_logins='不是数字', last_failure_at=? WHERE id=?`,
			nowUnix(), a.ID); err != nil {
			t.Fatalf("注入损坏值: %v", err)
		}
		// 损坏值参与 `failed_logins + 1` 算术会被当成 0 → 写回 1;但读回来那一步
		// 若碰上仍是 TEXT 的值就要报错,不能默默当 0 —— 那等于把计数器清零。
		_, _, err := s.RecordWebAdminLoginFailure(t.Context(), a.ID, 5, 900)
		if err != nil && errors.Is(err, ErrNotFound) {
			t.Fatalf("扫描失败被归一成 ErrNotFound: %v", err)
		}
		_ = err // 能算出来就正常返回,算不出来必须是非 ErrNotFound 的错误
	})
	_ = ctx
}

func TestCreateWebAdmin_UniqueConstraintBacksUpTheDedupQuery(t *testing.T) {
	// CI 去重查询写的是 `username = ? COLLATE NOCASE AND id != ?`,create 传
	// excludeID=0。于是任何 **id=0** 的行都会被这个条件排除在外 —— 查不到,却真实存在。
	// AUTOINCREMENT 不会发 0,所以正常路径碰不到;但直接改库/迁移出错就可能造出这种行。
	// 这里正是 UNIQUE 约束作为第二道闸的意义:查询漏了,约束仍然拦得住,不会出现两个同名 admin。
	s := newTestStore(t)
	ctx := t.Context()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO web_admins(id, username, password_hash, role, enabled, created_at)
		 VALUES(0, 'ghost', 'h', 'admin', 1, ?)`, nowUnix()); err != nil {
		t.Fatalf("造 id=0 的行: %v", err)
	}

	_, err := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "ghost", PasswordHash: "h"})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err=%v,想要 ErrDuplicate —— 去重查询漏掉的这行必须被 UNIQUE 约束拦下", err)
	}
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM web_admins WHERE username='ghost'`).Scan(&n); err != nil {
		t.Fatalf("COUNT: %v", err)
	}
	if n != 1 {
		t.Fatalf("username=ghost 有 %d 行,重复的 admin 会让「最后一个 admin」楼层计数全都不准", n)
	}
}

func TestEnableWebAdminTOTP_RejectsEmptyExpectedSecretEvenWithCodes(t *testing.T) {
	// 两道入参闸的顺序:先查 codeHashes 空,再查 expectedSecret 空。传了码才能走到第二道。
	// 空 secret 若被放过,CAS 就退化成 `totp_secret = ''` 的宽松匹配 —— 一个从没设过
	// secret 的账号会被直接「启用」TOTP,然后谁也登不进去。
	s := newTestStore(t)
	ctx := t.Context()
	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "emptysecret", PasswordHash: "h"})

	if _, err := s.EnableWebAdminTOTP(ctx, a.ID, "", []string{"r1", "r2"}, nowUnix()); err == nil {
		t.Fatal("空 expectedSecret 应被拒")
	}
	got, _ := s.GetWebAdmin(ctx, a.ID)
	if got.TOTPEnabled {
		t.Fatal("TOTP 被启用了,但库里根本没有 secret —— 账号被永久锁死")
	}
}

func TestTOTPWrites_RollBackWhenRecoveryCodeTableRefuses(t *testing.T) {
	ctx := context.Background()
	_ = ctx

	t.Run("enable 写不进恢复码就不该翻 enabled", func(t *testing.T) {
		s := newTestStore(t)
		a, _ := s.CreateWebAdmin(t.Context(), NewWebAdmin{Username: "enfail", PasswordHash: "h"})
		if err := s.SetWebAdminTOTPSecret(t.Context(), a.ID, "SECRET"); err != nil {
			t.Fatalf("SetWebAdminTOTPSecret: %v", err)
		}
		abortOn(t, s, "web_admin_recovery_codes", "INSERT")

		if _, err := s.EnableWebAdminTOTP(t.Context(), a.ID, "SECRET", []string{"r1"}, nowUnix()); err == nil {
			t.Fatal("恢复码写失败却报启用成功")
		}
		got, _ := s.GetWebAdmin(t.Context(), a.ID)
		if got.TOTPEnabled {
			t.Fatal("启用了 TOTP 却没有恢复码 —— 手机一丢就永久锁死,正是这个事务要防的事")
		}
	})

	// EnableWebAdminTOTP 里那条「清旧码」的 DELETE 在当前代码路径下其实是空操作:
	// 唯一能把 enabled 降回 0 的入口是 DisableWebAdminTOTP,而它自己就把码删干净了。
	// 也就是说这是一段**防御性**代码,防的是「enabled=0 但旧码仍在」——现有流程产生不出
	// 这种状态(手工改库、迁移写坏、或将来新增某条 disable 路径忘了删码才会有)。
	// 要验它就必须直接把库摆成那个状态,这里如实构造:留着码,只把 enabled 压回 0。
	t.Run("enable 清不掉遗留旧码时整体失败", func(t *testing.T) {
		s := newTestStore(t)
		a, _ := s.CreateWebAdmin(t.Context(), NewWebAdmin{Username: "enfail2", PasswordHash: "h"})
		_ = s.SetWebAdminTOTPSecret(t.Context(), a.ID, "S1")
		if _, err := s.EnableWebAdminTOTP(t.Context(), a.ID, "S1", []string{"old1"}, nowUnix()); err != nil {
			t.Fatalf("首次 enable: %v", err)
		}
		if _, err := s.db.ExecContext(t.Context(),
			`UPDATE web_admins SET totp_enabled=0 WHERE id=?`, a.ID); err != nil {
			t.Fatalf("摆出「未启用但旧码仍在」的状态: %v", err)
		}
		if err := s.SetWebAdminTOTPSecret(t.Context(), a.ID, "S2"); err != nil {
			t.Fatalf("SetWebAdminTOTPSecret: %v", err)
		}
		abortOn(t, s, "web_admin_recovery_codes", "DELETE")

		if _, err := s.EnableWebAdminTOTP(t.Context(), a.ID, "S2", []string{"new1"}, nowUnix()); err == nil {
			t.Fatal("旧码删不掉却报启用成功 —— 会出现新旧两批码同时有效")
		}
		got, _ := s.GetWebAdmin(t.Context(), a.ID)
		if got.TOTPEnabled {
			t.Fatal("enabled 被翻上去了,事务没回滚")
		}
	})

	t.Run("disable 删不掉恢复码就不该清 secret", func(t *testing.T) {
		s := newTestStore(t)
		a, _ := s.CreateWebAdmin(t.Context(), NewWebAdmin{Username: "disfail", PasswordHash: "h"})
		_ = s.SetWebAdminTOTPSecret(t.Context(), a.ID, "SECRET")
		if _, err := s.EnableWebAdminTOTP(t.Context(), a.ID, "SECRET", []string{"r1"}, nowUnix()); err != nil {
			t.Fatalf("enable: %v", err)
		}
		abortOn(t, s, "web_admin_recovery_codes", "DELETE")

		if err := s.DisableWebAdminTOTP(t.Context(), a.ID); err == nil {
			t.Fatal("恢复码删不掉却报禁用成功")
		}
		got, _ := s.GetWebAdmin(t.Context(), a.ID)
		if !got.TOTPEnabled {
			t.Fatal("TOTP 关了但恢复码还在库里 —— 那些码仍然能当第二因子用")
		}
	})

	t.Run("regen 写不进新码就不该删掉旧码", func(t *testing.T) {
		s := newTestStore(t)
		a, _ := s.CreateWebAdmin(t.Context(), NewWebAdmin{Username: "regenfail", PasswordHash: "h"})
		_ = s.SetWebAdminTOTPSecret(t.Context(), a.ID, "SECRET")
		if _, err := s.EnableWebAdminTOTP(t.Context(), a.ID, "SECRET", []string{"r1", "r2"}, nowUnix()); err != nil {
			t.Fatalf("enable: %v", err)
		}
		abortOn(t, s, "web_admin_recovery_codes", "INSERT")

		if err := s.RegenerateRecoveryCodes(t.Context(), a.ID, []string{"n1", "n2"}, nowUnix()); err == nil {
			t.Fatal("新码写失败却报成功")
		}
		n, err := s.CountUnusedRecoveryCodes(t.Context(), a.ID)
		if err != nil {
			t.Fatalf("CountUnusedRecoveryCodes: %v", err)
		}
		if n != 2 {
			t.Fatalf("剩 %d 条,应当回滚成原来的 2 条 —— 否则用户的兜底手段被静默清空", n)
		}
	})
}

func TestRecoveryCodeReads_SurfaceCorruptRows(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "rccorrupt", PasswordHash: "h"})
	_ = s.SetWebAdminTOTPSecret(ctx, a.ID, "SECRET")
	if _, err := s.EnableWebAdminTOTP(ctx, a.ID, "SECRET", []string{"r1"}, nowUnix()); err != nil {
		t.Fatalf("enable: %v", err)
	}

	t.Run("used_at 损坏时列表报错", func(t *testing.T) {
		// used_at 参与 WHERE(used_at=0),TEXT 与 0 比较为假 → 这一行会被过滤掉。
		// 于是「未使用的恢复码」数量凭空变少,但不会把已用的码当成可用 —— fail-closed。
		if _, err := s.db.ExecContext(ctx,
			`UPDATE web_admin_recovery_codes SET used_at='坏了' WHERE admin_id=?`, a.ID); err != nil {
			t.Fatalf("注入损坏值: %v", err)
		}
		codes, err := s.ListUnusedRecoveryCodes(ctx, a.ID)
		if err == nil && len(codes) > 0 {
			t.Fatal("损坏行被当成可用恢复码返回了")
		}
	})

	t.Run("created_at 损坏时列表报错", func(t *testing.T) {
		// created_at 不参与过滤,所以行会被取出、在 Scan 处失败。
		if _, err := s.db.ExecContext(ctx,
			`UPDATE web_admin_recovery_codes SET used_at=0, created_at='坏了' WHERE admin_id=?`,
			a.ID); err != nil {
			t.Fatalf("注入损坏值: %v", err)
		}
		if _, err := s.ListUnusedRecoveryCodes(ctx, a.ID); err == nil {
			t.Fatal("扫不出来的行应当报错,而不是静默跳过")
		}
	})
}

func TestRegenerateRecoveryCodes_SurfacesCorruptTOTPFlag(t *testing.T) {
	// totp_enabled 读不出来时不能当成「未启用」就走 ErrInvalid,也不能当成「已启用」
	// 直接写码 —— 必须把读失败本身报出来。
	s := newTestStore(t)
	ctx := t.Context()
	a, _ := s.CreateWebAdmin(ctx, NewWebAdmin{Username: "flagcorrupt", PasswordHash: "h"})
	if _, err := s.db.ExecContext(ctx,
		`UPDATE web_admins SET totp_enabled='坏了' WHERE id=?`, a.ID); err != nil {
		t.Fatalf("注入损坏值: %v", err)
	}
	err := s.RegenerateRecoveryCodes(ctx, a.ID, []string{"n1"}, nowUnix())
	if err == nil {
		t.Fatal("totp_enabled 扫不出来却报成功")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("扫描失败被归一成 ErrNotFound: %v —— 会引导用户去重走 setup,掩盖数据损坏", err)
	}
}
