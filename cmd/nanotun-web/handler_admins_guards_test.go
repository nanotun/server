package main

// handler_admins_guards_test.go(第十八轮)——/admins 写路径的**失败侧**闸门。
//
// handler_admins_test.go 已经钉住了角色门禁、自我保护与「至少留一个启用中的
// admin」这条底线的正常路径。本文件补的是它们失败时的样子,每条都对应一个
// 真实会咬人的场景:
//
//   1. 名册读不出来不能渲染成空表;GetWebAdmin 出错不能当成 404
//      (「这个管理员不存在」会引出重建账号这种破坏性动作);
//   2. 改密任一步失败,库里必须还是旧密码 —— 半途而废的改密最坏:
//      管理员以为新密码生效、旧密码其实还能登,而且他自己也进不去;
//   3. 自改密码的 step-up 要在拿锁之后**重读**账号:快照与执行之间账号
//      可能已被停用/删除,凭旧快照放行等于把已经吊销的身份又用了一次;
//   4. 容量耗尽 / 时间步消费失败这类「非密码错」不能计进 IP 冷却,
//      否则库一抖动就把管理员自己锁在门外;
//   5. floor 守卫的真正兜底在 store 事务里:预检通过之后、事务提交之前,
//      并发的另一个禁用把最后一个 admin 拿走时,本次必须回滚并拒绝。
//
// 并发注入手法:用 SQLite 触发器在**同一事务内**代替「另一个管理员」动手 ——
// 比起真起 goroutine 抢时序,它是确定性的,失败也能一眼看懂。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// -------------------------------------------------------------------------
// 脚手架
// -------------------------------------------------------------------------

// breakWebPasswordHash 让 HashWebPassword 失败(等价 crypto/rand 故障)。
// 注意:createTestAdmin 也走这个函数,所以固定在建好账号之后再装。
//
// 返回值故意非空:要验证的是「那个 err 拦住了流程」,而不是「空 hash 被 store 的
// 空值校验挡了」—— 后者一旦哪天放宽,这条闸门就静默失效。
func breakWebPasswordHash(t *testing.T) {
	t.Helper()
	orig := HashWebPassword
	HashWebPassword = func(string) (string, error) {
		return "junk-not-a-phc-string", errors.New("injected: hash failure")
	}
	t.Cleanup(func() { HashWebPassword = orig })
}

// injectPeerAdminDisable 装一个触发器:目标行被改/删的**同一事务**里,把所有
// admin 账号一并停用 —— 等价于「另一个管理员在这条事务提交前抢先禁用了最后
// 一个 admin」。store 的 floor 守卫应当因此回滚并返回 ErrLastAdmin。
//
// SQLite 默认关闭递归触发器,内层那条 UPDATE 不会再次触发本触发器。
func injectPeerAdminDisable(t *testing.T, s *Server, name, op, when string) {
	t.Helper()
	cond := ""
	if when != "" {
		cond = " WHEN " + when
	}
	sql := "CREATE TRIGGER " + name + " AFTER " + op + " ON web_admins" + cond +
		" BEGIN UPDATE web_admins SET enabled=0 WHERE role='admin'; END"
	if _, err := s.store.DB().ExecContext(t.Context(), sql); err != nil {
		t.Fatalf("装并发禁用触发器 %s: %v", name, err)
	}
	t.Cleanup(func() { _, _ = s.store.DB().Exec("DROP TRIGGER IF EXISTS " + name) })
}

func pwdHashOf(t *testing.T, s *Server, id int64) string {
	t.Helper()
	return mustGetAdmin(t, s, id).PasswordHash
}

// selfResetPwdReq 造一个「自改密码」的 POST(可指定 IP / step-up 字段)。
func selfResetPwdReq(t *testing.T, me *store.WebAdmin, ip string, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admins/"+itoa(me.ID)+"/reset-pwd",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if ip != "" {
		req.RemoteAddr = ip + ":12345"
	}
	return withAdminCtx(req, me)
}

// -------------------------------------------------------------------------
// 读失败
// -------------------------------------------------------------------------

func TestAdminList_ReadFailureIsNotAnEmptyRoster(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	if err := s.store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleAdminList(w, withAdminCtx(httptest.NewRequest(http.MethodGet, "/admins", nil), me))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
}

// 读不到 ≠ 不存在。回 404 会让管理员以为账号被删了,进而去重建 —— 那才是真损害。
func TestAdminAction_ReadFailureIsNotMistakenFor404(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	other := createTestAdmin(t, s, "second", "pw-second-123456")
	if err := s.store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, tc := range []struct {
		name   string
		method string
		verb   string
	}{
		{"改密表单页", http.MethodGet, "reset-pwd"},
		{"停用", http.MethodPost, "disable"},
	} {
		req := httptest.NewRequest(tc.method, "/admins/"+itoa(other.ID)+"/"+tc.verb, nil)
		w := httptest.NewRecorder()
		s.handleAdminAction(w, withAdminCtx(req, me))
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s: code=%d body=%q, 期望 500", tc.name, w.Code, trimForLog(w.Body.String()))
		}
	}
}

// -------------------------------------------------------------------------
// POST /admins/new
// -------------------------------------------------------------------------

func TestAdminNew_HashFailureCreatesNothing(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	breakWebPasswordHash(t)

	w := postAdminNew(t, s, me, url.Values{
		"username": {"newbie"}, "role": {"admin"},
		"password": {"Str0ng-Passw0rd!x"}, "password_confirm": {"Str0ng-Passw0rd!x"},
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	// 空 password_hash 的管理员账号是纯粹的隐患:谁都不知道它能不能登进来。
	if a := adminByName(t, s, "newbie"); a != nil {
		t.Fatalf("哈希失败却建出了账号(hash=%q)", a.PasswordHash)
	}
}

func TestAdminNew_StoreFailureIsMaskedAndCreatesNothing(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	abortSQLiteWrites(t, s, "no_new_admins", "web_admins", "INSERT", "")

	w := postAdminNew(t, s, me, url.Values{
		"username": {"newbie"}, "role": {"admin"},
		"password": {"Str0ng-Passw0rd!x"}, "password_confirm": {"Str0ng-Passw0rd!x"},
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if adminByName(t, s, "newbie") != nil {
		t.Fatal("报错却把账号建出来了")
	}
	// 内部错误串(SQL / 触发器名 / 库路径)不许回显到页面。
	if strings.Contains(w.Body.String(), "no_new_admins") {
		t.Fatalf("内部错误细节泄漏: %q", trimForLog(w.Body.String()))
	}
	if n := countAudit(t, s, "webadmin_create"); n != 0 {
		t.Fatalf("没建成却写了 %d 条创建审计", n)
	}
}

// -------------------------------------------------------------------------
// 改密
// -------------------------------------------------------------------------

// 自改密码在拿锁之后要**重读**账号:请求初的快照与真正执行之间,账号可能已经
// 被应急停用或删除。凭旧快照放行,等于让一个已被吊销的身份又改了一次密码。
func TestAdminResetPwd_SelfRereadsTheAccountInsideTheLock(t *testing.T) {
	const pw = "pw-root-12345678"
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, s *Server, me *store.WebAdmin)
		want   int
	}{
		{
			name: "账号在这期间被删",
			mutate: func(t *testing.T, s *Server, me *store.WebAdmin) {
				if _, err := s.store.DB().ExecContext(t.Context(),
					`DELETE FROM web_admins WHERE id=?`, me.ID); err != nil {
					t.Fatalf("删账号: %v", err)
				}
			},
			want: http.StatusInternalServerError,
		},
		{
			name: "账号在这期间被停用",
			mutate: func(t *testing.T, s *Server, me *store.WebAdmin) {
				if err := s.store.SetWebAdminEnabled(t.Context(), me.ID, false); err != nil {
					t.Fatalf("停用账号: %v", err)
				}
			},
			want: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			me := createTestAdmin(t, s, "root", pw)
			createTestAdmin(t, s, "spare", "pw-spare-1234567")
			oldHash := pwdHashOf(t, s, me.ID)

			// 先占住 handler 会拿的那把锁,让它必然停在「重读之前」。
			unlock := s.lockTOTPVerify(me.ID)
			w := httptest.NewRecorder()
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.handleAdminAction(w, selfResetPwdReq(t, me, "198.51.100.7", url.Values{
					"current_password": {pw},
					"password":         {"Br4nd-New-Pass!x"},
					"password_confirm": {"Br4nd-New-Pass!x"},
				}))
			}()
			time.Sleep(50 * time.Millisecond)
			tc.mutate(t, s, me)
			unlock()
			wg.Wait()

			if w.Code != tc.want {
				t.Fatalf("code=%d body=%q, 期望 %d", w.Code, trimForLog(w.Body.String()), tc.want)
			}
			if a, err := s.store.GetWebAdmin(t.Context(), me.ID); err == nil &&
				a.PasswordHash != oldHash {
				t.Fatal("已经失效的身份还是把密码改掉了")
			}
		})
	}
}

// 排不上 argon2 的号是「暂时不可用」,不是「密码错」。计进冷却的话,库一忙
// 管理员就把自己锁在门外 —— 而这正是他最需要能改密码的时候。
func TestAdminResetPwd_SelfArgon2UnavailableIs503AndNotCounted(t *testing.T) {
	s := newMeTestServer(t)
	const pw = "pw-root-12345678"
	me := createTestAdmin(t, s, "root", pw)
	oldHash := pwdHashOf(t, s, me.ID)
	const ip = "198.51.100.21"

	stop := saturateArgon2(t, 4*time.Second)
	defer stop()

	var got503 bool
	for i := 0; i < 8 && !got503; i++ {
		req := selfResetPwdReq(t, me, ip, url.Values{
			"current_password": {pw},
			"password":         {"Br4nd-New-Pass!x"},
			"password_confirm": {"Br4nd-New-Pass!x"},
		})
		ctx, cancel := context.WithTimeout(req.Context(), 200*time.Millisecond)
		w := httptest.NewRecorder()
		s.handleAdminAction(w, req.WithContext(ctx))
		cancel()
		if w.Code == http.StatusServiceUnavailable {
			got503 = true
		}
	}
	if !got503 {
		t.Fatal("排不上号时没有回 503")
	}
	if n := s.stepUpFailures.Recent(ip); n != 0 {
		t.Fatalf("被记了 %d 次 step-up 失败 —— 容量问题不该算密码错", n)
	}
	if pwdHashOf(t, s, me.ID) != oldHash {
		t.Fatal("没验成密码却把密码改了")
	}
}

// 已开 2FA 的管理员自改密码必须再交一枚当前码:只要一个被劫持的会话 + 已知
// 旧密码就能改密,第二因子等于没开。
func TestAdminResetPwd_SelfWithTOTPNeedsAFreshCode(t *testing.T) {
	const pw = "pw-root-12345678"
	newForm := func(code string) url.Values {
		return url.Values{
			"current_password": {pw},
			"totp_code":        {code},
			"password":         {"Br4nd-New-Pass!x"},
			"password_confirm": {"Br4nd-New-Pass!x"},
		}
	}

	t.Run("不给码", func(t *testing.T) {
		s := newMeTestServer(t)
		me := createTestAdmin(t, s, "root", pw)
		enableTOTPDirect(t, s, me, 1)
		oldHash := pwdHashOf(t, s, me.ID)
		const ip = "198.51.100.31"

		w := httptest.NewRecorder()
		s.handleAdminAction(w, selfResetPwdReq(t, me, ip, newForm("")))
		if w.Code == http.StatusSeeOther {
			t.Fatal("没给第二因子就改成了")
		}
		if pwdHashOf(t, s, me.ID) != oldHash {
			t.Fatal("密码被改了")
		}
		// 漏填不是猜错,不该消耗冷却配额(否则手滑几次就把自己锁住)。
		if n := s.stepUpFailures.Recent(ip); n != 0 {
			t.Fatalf("空码被记了 %d 次失败", n)
		}
	})

	t.Run("码不对", func(t *testing.T) {
		s := newMeTestServer(t)
		me := createTestAdmin(t, s, "root", pw)
		enableTOTPDirect(t, s, me, 1)
		oldHash := pwdHashOf(t, s, me.ID)
		const ip = "198.51.100.32"

		w := httptest.NewRecorder()
		s.handleAdminAction(w, selfResetPwdReq(t, me, ip, newForm("000000")))
		if w.Code == http.StatusSeeOther {
			t.Fatal("错码改成了")
		}
		if pwdHashOf(t, s, me.ID) != oldHash {
			t.Fatal("密码被改了")
		}
		if n := s.stepUpFailures.Recent(ip); n != 1 {
			t.Fatalf("错码记了 %d 次失败, 期望 1(否则可以无限猜)", n)
		}
		assertAuditAction(t, s, "webadmin_reset_pwd_stepup_fail")
	})

	t.Run("时间步消费失败", func(t *testing.T) {
		s := newMeTestServer(t)
		me := createTestAdmin(t, s, "root", pw)
		secret, _ := enableTOTPDirect(t, s, me, 1)
		oldHash := pwdHashOf(t, s, me.ID)
		const ip = "198.51.100.33"
		// 只打掉「消费时间步」那条 UPDATE:码是对的,是库写不动。
		abortSQLiteWrites(t, s, "kill_step_consume_admin", "web_admins", "UPDATE",
			"NEW.totp_last_used_step <> OLD.totp_last_used_step")

		w := httptest.NewRecorder()
		s.handleAdminAction(w, selfResetPwdReq(t, me, ip, newForm(totpCodeFor(t, secret))))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("code=%d body=%q, 期望 503", w.Code, trimForLog(w.Body.String()))
		}
		if n := s.stepUpFailures.Recent(ip); n != 0 {
			t.Fatalf("库抖动被记了 %d 次失败", n)
		}
		if pwdHashOf(t, s, me.ID) != oldHash {
			t.Fatal("没验完第二因子却把密码改了")
		}
	})

	t.Run("码对了就放行", func(t *testing.T) {
		s := newMeTestServer(t)
		me := createTestAdmin(t, s, "root", pw)
		secret, _ := enableTOTPDirect(t, s, me, 1)
		oldHash := pwdHashOf(t, s, me.ID)

		w := httptest.NewRecorder()
		s.handleAdminAction(w, selfResetPwdReq(t, me, "198.51.100.34",
			newForm(totpCodeFor(t, secret))))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
		}
		if pwdHashOf(t, s, me.ID) == oldHash {
			t.Fatal("密码没改")
		}
		assertAuditAction(t, s, "webadmin_reset_pwd")
	})
}

// 哈希算不出来时,绝不能拿空 hash 去覆盖别人的密码 —— 那等于把这个账号
// 变成谁都登不进来(或谁都能登,取决于 verify 的实现)。
func TestAdminResetPwd_HashFailureKeepsTheOldPassword(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	oldHash := pwdHashOf(t, s, other.ID)
	breakWebPasswordHash(t)

	w := postAdminVerb(t, s, me, other.ID, "reset-pwd", url.Values{
		"password": {"Br4nd-New-Pass!x"}, "password_confirm": {"Br4nd-New-Pass!x"},
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if got := pwdHashOf(t, s, other.ID); got != oldHash {
		t.Fatalf("密码被改成了 %q", got)
	}
}

// 改密写不动时必须报错并保留旧密码。若照样 303 + 「已重置」,管理员会拿着一个
// 从未生效的新密码去登录,还以为是自己记错了。
func TestAdminResetPwd_WriteFailureKeepsTheOldPassword(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	oldHash := pwdHashOf(t, s, other.ID)
	abortSQLiteWrites(t, s, "no_pwd_change", "web_admins", "UPDATE OF password_hash", "")

	w := postAdminVerb(t, s, me, other.ID, "reset-pwd", url.Values{
		"password": {"Br4nd-New-Pass!x"}, "password_confirm": {"Br4nd-New-Pass!x"},
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if pwdHashOf(t, s, other.ID) != oldHash {
		t.Fatal("报错却改了密码")
	}
	if n := countAudit(t, s, "webadmin_reset_pwd"); n != 0 {
		t.Fatalf("失败却写了 %d 条改密审计", n)
	}
}

// -------------------------------------------------------------------------
// floor 守卫的事务内兜底
// -------------------------------------------------------------------------

// handler 里的 ensureNotLastAdmin 只是给单请求场景一句清晰文案;真正防并发的是
// store 事务内「先写后数」的 floor 校验。这里让「另一个管理员」在同一事务里把
// 最后的 admin 拿走,三个动作都必须回滚 + 400,绝不能把系统推成零可登录管理员。
func TestAdmins_FloorGuardCatchesAPeerDisableMidTransaction(t *testing.T) {
	cases := []struct {
		name    string
		op      string
		when    string
		verb    string
		form    url.Values
		checkOK func(t *testing.T, s *Server, targetID int64)
	}{
		{
			name: "禁用", op: "UPDATE", when: "NEW.role='viewer'", verb: "disable",
			checkOK: func(t *testing.T, s *Server, id int64) {
				if !mustGetAdmin(t, s, id).Enabled {
					t.Fatal("被拒的禁用却生效了(事务没回滚)")
				}
			},
		},
		{
			name: "删除", op: "DELETE", when: "OLD.role='viewer'", verb: "delete",
			checkOK: func(t *testing.T, s *Server, id int64) {
				if _, err := s.store.GetWebAdmin(t.Context(), id); err != nil {
					t.Fatalf("被拒的删除却生效了(事务没回滚): %v", err)
				}
			},
		},
		{
			name: "改角色", op: "UPDATE OF role", when: "NEW.role='admin'", verb: "set-role",
			form: url.Values{"role": {"admin"}},
			checkOK: func(t *testing.T, s *Server, id int64) {
				if r := mustGetAdmin(t, s, id).Role; r != "viewer" {
					t.Fatalf("被拒的改角色却生效了(role=%q)", r)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			me := createTestAdmin(t, s, "root", "pw-root-12345678")
			// 目标是 viewer:handler 的预检对它不适用,正好把断言压在 store 的兜底上。
			target := createTestAdmin(t, s, "watcher", "pw-watcher-12345")
			if err := s.store.SetWebAdminRole(t.Context(), target.ID, "viewer"); err != nil {
				t.Fatalf("SetWebAdminRole: %v", err)
			}
			injectPeerAdminDisable(t, s, "peer_disable", tc.op, tc.when)

			w := postAdminVerb(t, s, me, target.ID, tc.verb, tc.form)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("code=%d body=%q, 期望 400(最后一个 admin 守卫)",
					w.Code, trimForLog(w.Body.String()))
			}
			tc.checkOK(t, s, target.ID)
			// 兜底生效的标志:发起人自己还是启用中的 admin。
			if a := mustGetAdmin(t, s, me.ID); !a.Enabled || a.Role != "admin" {
				t.Fatal("并发禁用被提交了 —— 系统已经没有可登录的管理员")
			}
		})
	}
}

// -------------------------------------------------------------------------
// 其余写动作的失败侧
// -------------------------------------------------------------------------

func TestAdminAction_WriteFailuresAreReportedNotSwallowed(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, s *Server, target *store.WebAdmin)
		op      string
		when    string
		verb    string
		form    url.Values
		check   func(t *testing.T, s *Server, target *store.WebAdmin)
	}{
		{
			name: "禁用", op: "UPDATE OF enabled", verb: "disable",
			check: func(t *testing.T, s *Server, target *store.WebAdmin) {
				if !mustGetAdmin(t, s, target.ID).Enabled {
					t.Fatal("报错却把人禁了")
				}
			},
		},
		{
			name: "启用",
			prepare: func(t *testing.T, s *Server, target *store.WebAdmin) {
				if err := s.store.SetWebAdminEnabled(t.Context(), target.ID, false); err != nil {
					t.Fatalf("先停用: %v", err)
				}
			},
			op: "UPDATE OF enabled", verb: "enable",
			check: func(t *testing.T, s *Server, target *store.WebAdmin) {
				if mustGetAdmin(t, s, target.ID).Enabled {
					t.Fatal("报错却把人启用了")
				}
			},
		},
		{
			name: "删除", op: "DELETE", verb: "delete",
			check: func(t *testing.T, s *Server, target *store.WebAdmin) {
				if _, err := s.store.GetWebAdmin(t.Context(), target.ID); err != nil {
					t.Fatalf("报错却把人删了: %v", err)
				}
			},
		},
		{
			name: "改角色", op: "UPDATE OF role", verb: "set-role",
			form: url.Values{"role": {"viewer"}},
			check: func(t *testing.T, s *Server, target *store.WebAdmin) {
				if r := mustGetAdmin(t, s, target.ID).Role; r != "admin" {
					t.Fatalf("报错却把角色改成了 %q", r)
				}
			},
		},
		{
			name: "解锁",
			prepare: func(t *testing.T, s *Server, target *store.WebAdmin) {
				if _, err := s.store.DB().ExecContext(t.Context(),
					`UPDATE web_admins SET failed_logins=9, locked_until=? WHERE id=?`,
					time.Now().Unix()+600, target.ID); err != nil {
					t.Fatalf("造锁定状态: %v", err)
				}
			},
			op: "UPDATE OF failed_logins", verb: "unlock",
			check: func(t *testing.T, s *Server, target *store.WebAdmin) {
				if a := mustGetAdmin(t, s, target.ID); a.LockedUntil == 0 {
					t.Fatal("报错却把锁解了")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMeTestServer(t)
			me := createTestAdmin(t, s, "root", "pw-root-12345678")
			target := createTestAdmin(t, s, "second", "pw-second-123456")
			// 留够两个 admin,让 handler 的 floor 预检放行,断言才落在写失败上。
			createTestAdmin(t, s, "third", "pw-third-1234567")
			if tc.prepare != nil {
				tc.prepare(t, s, target)
			}
			abortSQLiteWrites(t, s, "no_admin_write", "web_admins", tc.op, tc.when)

			w := postAdminVerb(t, s, me, target.ID, tc.verb, tc.form)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
			}
			if strings.Contains(w.Body.String(), "no_admin_write") {
				t.Fatalf("内部错误细节泄漏: %q", trimForLog(w.Body.String()))
			}
			tc.check(t, s, target)
		})
	}
}

// 删除的成功路径:行真的没了,并且留下审计 —— 删管理员是不可逆动作,
// 事后要能查出是谁删的。
func TestAdminDelete_RemovesTheRowAndAudits(t *testing.T) {
	s := newMeTestServer(t)
	me, other := adminsFixture(t, s)
	createTestAdmin(t, s, "third", "pw-third-1234567")

	w := postAdminVerb(t, s, me, other.ID, "delete", nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
	}
	if _, err := s.store.GetWebAdmin(t.Context(), other.ID); err == nil {
		t.Fatal("账号还在")
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/admins") {
		t.Fatalf("Location=%q, 应回名册页", loc)
	}
	assertAuditAction(t, s, "webadmin_delete")
}

// ensureNotLastAdmin 的两种失败必须能分开:floor 哨兵 → 400 本地化文案;
// 读计数出错 → 500 且不外泄细节。把后者也当哨兵会变成「明明是库故障,
// 却告诉管理员这是最后一个 admin」,他会去建一个多余账号绕开。
func TestEnsureNotLastAdmin_CountFailureIsNotTheFloorSentinel(t *testing.T) {
	s := newMeTestServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	req := withAdminCtx(httptest.NewRequest(http.MethodPost, "/admins", nil), me)
	if err := s.store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err := s.ensureNotLastAdmin(req)
	if err == nil {
		t.Fatal("库都关了还说没问题")
	}
	if errors.Is(err, errLastEnabledAdmin) {
		t.Fatalf("库故障被当成 floor 哨兵: %v", err)
	}

	w := httptest.NewRecorder()
	s.renderEnsureAdminErr(w, req, err)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d, 期望 500", w.Code)
	}
}
