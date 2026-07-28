package main

// handler_users_guards_test.go(第十八轮)——/users 写路径的**失败侧**闸门。
//
// happy path 在 handler_write_paths_test.go / handler_user_action_test.go /
// handler_users_prg_test.go 里已经钉住了。本文件专门打那些「只在库写不动、
// crypto/rand 坏了、或者另一个管理员抢先一步时才走」的分支,它们各自守着一条
// 不能破的规矩:
//
//   1. 读列表失败绝不能渲染成「一个用户都没有」——运维会以为账号被清空;
//   2. 建号任一环节失败,库里绝不能留下半个账号(尤其不能留下空 psk_hash 的行);
//   3. PSK 只有一次明文露出机会:一次性 flash 拿不到 token 时,宁可 500,
//      也不能把 PSK 渲染在 POST 响应里(刷新即重发 POST → 再 rotate 一次,
//      用户刚抄下的那把当场失效);
//   4. rotate 失败 / 被别的管理员抢先,旧 PSK 必须原样保留,并且要留下能区分
//      「冲突」和「故障」的审计;
//   5. viewer 一个字节的 PSK 都看不到,也不能把 admin 的一次性 token 烧掉。
//
// 故障注入手法沿用 handler_auth_guards_test.go 的 abortSQLiteWrites(BEFORE
// 触发器 RAISE(ABORT)),外加两个只在测试里替换的生成器接缝(generateUserPSK /
// HashPSKForUser / flashGenerateToken,理由见各自定义处)。

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// -------------------------------------------------------------------------
// 脚手架
// -------------------------------------------------------------------------

// newUsersGuardServer 用**真实模板**建 Server。这一点是必须的:本文件大量断言长
// 「出错时不许退化成重新渲染那张带 PSK 的页面」,而不加载模板时 renderPage 会走
// plain-text fallback、同样返回 500 —— 两种行为在断言上没有区别,闸门等于没测。
func newUsersGuardServer(t *testing.T) *Server {
	t.Helper()
	return newMeTestServer(t)
}

// viewerReq 造一个 viewer 身份的请求(role != "admin")。
func viewerReq(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	return withAdminCtx(req, &store.WebAdmin{ID: 42, Username: "peeker", Role: "viewer"})
}

// adminGetReq 造一个 admin 身份的 GET。
func adminGetReq(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return withAdminCtx(req, &store.WebAdmin{ID: 1, Username: "tester", Role: "admin"})
}

// stubUserPSK 把 PSK 生成器换成固定返回值;hook 在返回前调用,用来模拟
// 「argon2 那几十毫秒里别人动了这行」。
//
// 注入失败时**同时**给一个非空 psk:真实的 crypto/rand 故障也可能返回半截缓冲区,
// 而且更重要的是,这样才能验证「是那个 err 拦住了流程」,而不是靠下游 store 的
// 空值校验兜住(前者才是本文件要钉的东西)。
func stubUserPSK(t *testing.T, psk string, genErr error, hook func()) {
	t.Helper()
	orig := generateUserPSK
	generateUserPSK = func() (string, error) {
		if hook != nil {
			hook()
		}
		return psk, genErr
	}
	t.Cleanup(func() { generateUserPSK = orig })
}

// breakUserPSKHash 让 PSK 哈希失败(等价 crypto/rand 故障)。返回值故意非空:
// 见 stubUserPSK 的说明 —— 要验证的是「err 拦住了流程」,不是「空串被 store 拒了」。
func breakUserPSKHash(t *testing.T) {
	t.Helper()
	orig := HashPSKForUser
	HashPSKForUser = func(string) (string, error) {
		return "junk-not-a-phc-string", errors.New("injected: hash failure")
	}
	t.Cleanup(func() { HashPSKForUser = orig })
}

// breakFlashTokens 让一次性 flash 拿不到 token(等价 crypto/rand 故障)。
func breakFlashTokens(t *testing.T) {
	t.Helper()
	orig := flashGenerateToken
	flashGenerateToken = func() (string, error) { return "", errors.New("injected: no entropy") }
	t.Cleanup(func() { flashGenerateToken = orig })
}

func pskHashOf(t *testing.T, s *Server, id int64) string {
	t.Helper()
	var h string
	if err := s.store.DB().QueryRowContext(t.Context(),
		`SELECT psk_hash FROM users WHERE id=?`, id).Scan(&h); err != nil {
		t.Fatalf("读 psk_hash(user %d): %v", id, err)
	}
	return h
}

func countUsers(t *testing.T, s *Server) int {
	t.Helper()
	users, err := s.store.ListUsersAll(t.Context())
	if err != nil {
		t.Fatalf("ListUsersAll: %v", err)
	}
	return len(users)
}

// assertNoAuditAction 断言某个 action **没有**被写下(用于「失败路径不许记成功」)。
func assertNoAuditAction(t *testing.T, s *Server, action string) {
	t.Helper()
	if n := countAudit(t, s, action); n != 0 {
		t.Fatalf("失败路径却写下了 %d 条 %q 审计", n, action)
	}
}

// -------------------------------------------------------------------------
// GET /users
// -------------------------------------------------------------------------

// 列表读不出来时必须报错。渲染成空列表是最坏的一种:运维看到「零用户」会以为
// 账号真被清空了,接下来的每一个决定都建立在假象上。
func TestUserList_ReadFailureIsNotAnEmptyList(t *testing.T) {
	for _, tc := range []struct{ name, target string }{
		{"默认列表", "/users"},
		{"含已停用", "/users?show_disabled=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newUsersGuardServer(t)
			u := newPRGTestUser(t, s, "alice")
			// 只让这一行扫不出来(created_at 写成非数字),库其余部分照常 ——
			// 这样「渲染成空列表」和「报错」两种行为在断言上才分得开。
			if _, err := s.store.DB().ExecContext(t.Context(),
				`UPDATE users SET created_at='not-a-number' WHERE id=?`, u.ID); err != nil {
				t.Fatalf("注入坏行: %v", err)
			}

			w := httptest.NewRecorder()
			s.handleUserList(w, adminGetReq(tc.target))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
			}
			if strings.Contains(w.Body.String(), "alice") {
				t.Fatal("出错页里还渲染了半截列表")
			}
		})
	}
}

// -------------------------------------------------------------------------
// POST /users/new
// -------------------------------------------------------------------------

func TestUserNew_ViewerCannotOpenOrSubmitTheForm(t *testing.T) {
	s := newUsersGuardServer(t)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		w := httptest.NewRecorder()
		s.handleUserNew(w, viewerReq(method, "/users/new"))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s /users/new: code=%d, 期望 403", method, w.Code)
		}
	}
	if n := countUsers(t, s); n != 0 {
		t.Fatalf("viewer 建出了 %d 个用户", n)
	}
}

func TestUserNew_RejectsOtherMethods(t *testing.T) {
	s := newUsersGuardServer(t)
	req := withAdminCtx(httptest.NewRequest(http.MethodPut, "/users/new", nil),
		&store.WebAdmin{ID: 1, Username: "tester", Role: "admin"})
	w := httptest.NewRecorder()
	s.handleUserNew(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d, 期望 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); !strings.Contains(allow, "POST") {
		t.Fatalf("Allow=%q, 应告知可用方法", allow)
	}
}

// 建号分四步:生成 PSK → 哈希 → 写库 → 存一次性 flash。前三步任一失败,库里都
// 不能留下痕迹 —— 特别是不能留下一个 psk_hash 为空的账号(那种行的 verify 行为
// 取决于实现,是纯粹的定时炸弹)。
func TestUserNew_AnyFailureBeforeTheRedirectLeavesNoAccount(t *testing.T) {
	form := func() url.Values { return url.Values{"username": {"newbie"}} }

	t.Run("PSK 生成失败", func(t *testing.T) {
		s := newUsersGuardServer(t)
		stubUserPSK(t, "half-baked-psk", errors.New("injected: no entropy"), nil)

		w := httptest.NewRecorder()
		s.handleUserNew(w, newAdminPostRequest(t, "/users/new", form()))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if n := countUsers(t, s); n != 0 {
			t.Fatalf("建出了 %d 个用户", n)
		}
	})

	t.Run("PSK 哈希失败", func(t *testing.T) {
		s := newUsersGuardServer(t)
		breakUserPSKHash(t)

		w := httptest.NewRecorder()
		s.handleUserNew(w, newAdminPostRequest(t, "/users/new", form()))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if n := countUsers(t, s); n != 0 {
			t.Fatalf("哈希失败却建出了 %d 个用户(可能带空 psk_hash)", n)
		}
	})

	t.Run("写库失败", func(t *testing.T) {
		s := newUsersGuardServer(t)
		abortSQLiteWrites(t, s, "no_new_users", "users", "INSERT", "")

		w := httptest.NewRecorder()
		s.handleUserNew(w, newAdminPostRequest(t, "/users/new", form()))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if n := countUsers(t, s); n != 0 {
			t.Fatalf("建出了 %d 个用户", n)
		}
		assertNoAuditAction(t, s, "user_create")
	})
}

// 一次性 flash 拿不到 token 时,PSK 绝不能顺手渲染在这个 POST 的响应里:
// 那个页面一刷新就重发 POST(create 有唯一约束兜底、reset-psk 会再 rotate 一次),
// 用户刚抄下的凭证当场作废。宁可 500 + 审计 + 指引去重置 PSK。
func TestUserNew_StashFailureNeverInlinesThePSK(t *testing.T) {
	const sentinel = "SENTINEL-PSK-MUST-NOT-LEAK"
	s := newUsersGuardServer(t)
	stubUserPSK(t, sentinel, nil, nil)
	breakFlashTokens(t)

	w := httptest.NewRecorder()
	s.handleUserNew(w, newAdminPostRequest(t, "/users/new", url.Values{"username": {"newbie"}}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if strings.Contains(w.Body.String(), sentinel) {
		t.Fatal("PSK 被渲染进了 POST 响应 —— 刷新就会重发 POST,用户抄下的凭证会作废")
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("失败却给了跳转 %q", loc)
	}
	// 账号确实已经建出来了(不能骗管理员说没建),所以要有审计留痕 + 明确指引。
	if _, err := s.store.GetUserByUsername(t.Context(), "newbie"); err != nil {
		t.Fatalf("账号应已建成: %v", err)
	}
	assertAuditAction(t, s, "user_create_stash_failed")
}

// -------------------------------------------------------------------------
// /users/{id} 读与角色门禁
// -------------------------------------------------------------------------

// 库读不动时必须 500。回 404 会让管理员以为账号被删了 —— 一个「不存在」的
// 结论比「暂时读不到」严重得多,后续动作(重建账号)会造成真实损害。
func TestUserAction_ReadFailureIsNotMistakenFor404(t *testing.T) {
	s := newUsersGuardServer(t)
	u := newPRGTestUser(t, s, "alice")
	if err := s.store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleUserAction(w, adminGetReq("/users/"+strconv.FormatInt(u.ID, 10)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
}

// viewer 不该看到 PSK。而且它连「试一下」都不该做成:一次性 token 只能被消费
// 一次,若角色校验排在 Pop 之后,viewer 一次访问就能把 admin 的凭证页烧掉。
func TestUserFlashPages_ViewerIsForbiddenAndBurnsNothing(t *testing.T) {
	s := newUsersGuardServer(t)
	u := newPRGTestUser(t, s, "alice")
	id := strconv.FormatInt(u.ID, 10)

	for _, tc := range []struct {
		verb string
		kind credentialsFlashKind
	}{
		{"created", credentialsFlashKindUserCreated},
		{"reset-psk-result", credentialsFlashKindUserResetPSK},
	} {
		t.Run(tc.verb, func(t *testing.T) {
			// 绑定到发起 stash 的那个 admin(adminGetReq 用的 ID=1),这样下面
			// 「admin 稍后仍能取到」才是在验 token 没被 viewer 烧掉。
			tok, err := s.credFlash.Stash(credentialsFlashPayload{
				Kind: tc.kind, UserID: u.ID, Username: "alice", PSK: "PLAIN-SECRET",
			}, 1)
			if err != nil {
				t.Fatalf("Stash: %v", err)
			}

			w := httptest.NewRecorder()
			s.handleUserAction(w, viewerReq(http.MethodGet, "/users/"+id+"/"+tc.verb+"?token="+tok))
			if w.Code != http.StatusForbidden {
				t.Fatalf("code=%d body=%q, 期望 403", w.Code, trimForLog(w.Body.String()))
			}
			if strings.Contains(w.Body.String(), "PLAIN-SECRET") {
				t.Fatal("viewer 看到了 PSK")
			}
			// token 还在:admin 稍后仍能正常看到那一次凭证。
			w = httptest.NewRecorder()
			s.handleUserAction(w, adminGetReq("/users/"+id+"/"+tc.verb+"?token="+tok))
			if w.Code == http.StatusGone {
				t.Fatal("viewer 的一次越权访问把 admin 的一次性 token 烧掉了")
			}
		})
	}
}

// -------------------------------------------------------------------------
// disable / enable / delete
// -------------------------------------------------------------------------

// 写不动就要说写不动。这三个动作此前只测了成功路径,而它们失败时若照样
// 303 + flash「已停用」,管理员会以为账号已经断掉,实际还在线。
func TestUserAction_WriteFailuresAreReportedNotSwallowed(t *testing.T) {
	t.Run("disable", func(t *testing.T) {
		s := newUsersGuardServer(t)
		u := newPRGTestUser(t, s, "alice")
		abortSQLiteWrites(t, s, "no_disable", "users", "UPDATE OF disabled_at", "")

		w := httptest.NewRecorder()
		s.handleUserAction(w, userActionReq(t, u.ID, "disable", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if mustGetUser(t, s, u.ID).DisabledAt != 0 {
			t.Fatal("库里竟然被停用了")
		}
		assertNoAuditAction(t, s, "user_disable")
	})

	t.Run("enable", func(t *testing.T) {
		s := newUsersGuardServer(t)
		u := newPRGTestUser(t, s, "alice")
		if err := s.store.DisableUser(t.Context(), u.ID); err != nil {
			t.Fatalf("DisableUser: %v", err)
		}
		abortSQLiteWrites(t, s, "no_enable", "users", "UPDATE OF disabled_at", "")

		w := httptest.NewRecorder()
		s.handleUserAction(w, userActionReq(t, u.ID, "enable", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if mustGetUser(t, s, u.ID).DisabledAt == 0 {
			t.Fatal("库里竟然被启用了")
		}
	})

	t.Run("delete", func(t *testing.T) {
		s := newUsersGuardServer(t)
		u := newPRGTestUser(t, s, "alice")
		abortSQLiteWrites(t, s, "no_delete_user", "users", "DELETE", "")

		w := httptest.NewRecorder()
		s.handleUserAction(w, userActionReq(t, u.ID, "delete", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if _, err := s.store.GetUser(t.Context(), u.ID); err != nil {
			t.Fatalf("报错却把用户删了: %v", err)
		}
		assertNoAuditAction(t, s, "user_delete")
	})
}

// -------------------------------------------------------------------------
// reset-psk
// -------------------------------------------------------------------------

// rotate 之前的任何失败都必须保住旧 PSK:用户手上那把还在用,悄悄换掉或换成
// 空值都等于把人踢下线。
func TestUserResetPSK_FailureBeforeRotateKeepsTheOldPSK(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"生成 PSK 失败", func(t *testing.T) {
			stubUserPSK(t, "half-baked-psk", errors.New("injected: no entropy"), nil)
		}},
		{"哈希失败", func(t *testing.T) { breakUserPSKHash(t) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newUsersGuardServer(t)
			u := newPRGTestUser(t, s, "alice")
			before := pskHashOf(t, s, u.ID)
			tc.setup(t)

			w := httptest.NewRecorder()
			s.handleUserAction(w, userActionReq(t, u.ID, "reset-psk", nil))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
			}
			if pskHashOf(t, s, u.ID) != before {
				t.Fatal("失败路径动了 psk_hash")
			}
			assertNoAuditAction(t, s, "user_reset_psk")
		})
	}
}

// rotate 本身写不动:旧 PSK 保留 + 落一条 user_reset_psk_failed。审计要能和
// 「并发冲突」区分开,否则运维分不清是库出问题还是两个管理员在抢。
func TestUserResetPSK_RotateFailureKeepsTheOldPSKAndAuditsAsFailure(t *testing.T) {
	s := newUsersGuardServer(t)
	u := newPRGTestUser(t, s, "alice")
	before := pskHashOf(t, s, u.ID)
	abortSQLiteWrites(t, s, "no_rotate", "users", "UPDATE OF psk_hash", "")

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "reset-psk", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if pskHashOf(t, s, u.ID) != before {
		t.Fatal("rotate 报错却改了 psk_hash")
	}
	assertAuditAction(t, s, "user_reset_psk_failed")
	assertNoAuditAction(t, s, "user_reset_psk_raced")
	assertNoAuditAction(t, s, "user_reset_psk")
}

// 另一个管理员在本次「读快照 → 算哈希」的窗口里先 rotate 了:CAS 必须失败,
// 回 409 而不是覆盖对方刚发下去的那把 PSK(否则对方发出的凭证静默作废)。
//
// 注入点选在 PSK 生成器里 —— 它正落在快照与 CAS 之间,等价于真实并发,但不用
// 靠 goroutine 抢时序,失败即确定性复现。
func TestUserResetPSK_PeerRotationIsAConflictNotAnOverwrite(t *testing.T) {
	s := newUsersGuardServer(t)
	u := newPRGTestUser(t, s, "alice")
	const peerHash = "peer-admin-rotated-first"

	stubUserPSK(t, "fresh-psk-value", nil, func() {
		if _, err := s.store.DB().ExecContext(t.Context(),
			`UPDATE users SET psk_hash=? WHERE id=?`, peerHash, u.ID); err != nil {
			t.Fatalf("模拟并发 rotate: %v", err)
		}
	})

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "reset-psk", nil))
	if w.Code != http.StatusConflict {
		t.Fatalf("code=%d body=%q, 期望 409", w.Code, trimForLog(w.Body.String()))
	}
	if got := pskHashOf(t, s, u.ID); got != peerHash {
		t.Fatalf("psk_hash=%q, 覆盖了对方刚 rotate 的值", got)
	}
	// 冲突单独归一个 action:运维要能按它统计「两个管理员在抢同一个账号」的频率。
	assertAuditAction(t, s, "user_reset_psk_raced")
	assertNoAuditAction(t, s, "user_reset_psk_failed")
	if strings.Contains(w.Body.String(), "CAS") {
		t.Fatalf("把实现层文案抛给了管理员: %q", trimForLog(w.Body.String()))
	}
}

// rotate 成功了但重读拿不到权威 credential_id:必须 500,不能拿过期快照去
// 拼二维码 —— 老账号首次 rotate 时 UUID 是这一步才 backfill 的,拿旧值生成的
// 凭证客户端扫进去是另一个身份。
func TestUserResetPSK_RereadFailureAfterRotateIsAnError(t *testing.T) {
	s := newUsersGuardServer(t)
	u := newPRGTestUser(t, s, "alice")
	before := pskHashOf(t, s, u.ID)

	// created_at 写成非数字:rotate 的 CAS 不读它,但之后的整行重读会 Scan 失败。
	stubUserPSK(t, "fresh-psk-value", nil, func() {
		if _, err := s.store.DB().ExecContext(t.Context(),
			`UPDATE users SET created_at='not-a-number' WHERE id=?`, u.ID); err != nil {
			t.Fatalf("注入坏 created_at: %v", err)
		}
	})

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "reset-psk", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if pskHashOf(t, s, u.ID) == before {
		t.Fatal("前置条件没成立:rotate 应该已经成功")
	}
	// 重读失败时还没到写审计那一步,不能记成一次成功的 reset。
	assertNoAuditAction(t, s, "user_reset_psk")
}

// reset-psk 的 stash 失败是最危险的一处:此前会把新 PSK 直接渲染在 POST 响应里,
// 刷新即再 rotate 一次,用户手抄的那把瞬间失效。现在必须 500 + 审计 + 不吐 PSK。
func TestUserResetPSK_StashFailureNeverInlinesThePSK(t *testing.T) {
	const sentinel = "SENTINEL-ROTATED-PSK"
	s := newUsersGuardServer(t)
	u := newPRGTestUser(t, s, "alice")
	before := pskHashOf(t, s, u.ID)
	stubUserPSK(t, sentinel, nil, nil)
	breakFlashTokens(t)

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "reset-psk", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if strings.Contains(w.Body.String(), sentinel) {
		t.Fatal("新 PSK 被渲染进了 POST 响应 —— 刷新会再 rotate 一次,这把当场作废")
	}
	if pskHashOf(t, s, u.ID) == before {
		t.Fatal("前置条件没成立:PSK 应该已经 rotate 过")
	}
	assertAuditAction(t, s, "user_reset_psk_stash_failed")
}

// -------------------------------------------------------------------------
// set-platforms / set-max-sessions
// -------------------------------------------------------------------------

func TestUserSetPlatforms_WriteFailureIsReported(t *testing.T) {
	s := newUsersGuardServer(t)
	u := newPRGTestUser(t, s, "alice")
	if err := s.store.SetUserAllowedPlatforms(t.Context(), u.ID, "macos"); err != nil {
		t.Fatalf("SetUserAllowedPlatforms: %v", err)
	}
	abortSQLiteWrites(t, s, "no_platforms", "users", "UPDATE OF allowed_platforms", "")

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "set-platforms",
		url.Values{"platforms": {"windows"}}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if got := mustGetUser(t, s, u.ID).AllowedPlatforms; got != "macos" {
		t.Fatalf("报错却把白名单改成了 %q", got)
	}
}

// 一个都不勾 = 不限。这时候的横幅必须是「已清空」,不能是「已设为空」那种
// 读起来像出了错的文案 —— 管理员会以为没生效而反复点。
func TestUserSetPlatforms_ClearingSaysCleared(t *testing.T) {
	s := newUsersGuardServer(t)
	u := newPRGTestUser(t, s, "alice")
	if err := s.store.SetUserAllowedPlatforms(t.Context(), u.ID, "macos"); err != nil {
		t.Fatalf("SetUserAllowedPlatforms: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleUserAction(w, userActionReq(t, u.ID, "set-platforms", url.Values{}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
	}
	if got := mustGetUser(t, s, u.ID).AllowedPlatforms; got != "" {
		t.Fatalf("白名单=%q, 期望清空", got)
	}
	loc := w.Header().Get("Location")
	probe := httptest.NewRequest(http.MethodGet, "/users", nil)
	want := tr(probe, "flash.userPlatformsCleared")
	if got := flashTextOf(t, loc); got != want {
		t.Fatalf("横幅=%q, 期望清空专用文案 %q", got, want)
	}
	if want == tr(probe, "flash.userPlatformsSet", "") {
		t.Fatal("清空与设置用了同一句文案,管理员分不出发生了什么")
	}
	assertAuditAction(t, s, "user_platforms_set")
}

func TestUserSetMaxSessions_AppliesAndReportsWriteFailure(t *testing.T) {
	t.Run("正常设置", func(t *testing.T) {
		s := newUsersGuardServer(t)
		u := newPRGTestUser(t, s, "alice")

		w := httptest.NewRecorder()
		s.handleUserAction(w, userActionReq(t, u.ID, "set-max-sessions",
			url.Values{"max_sessions": {"3"}}))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
		}
		if got := mustGetUser(t, s, u.ID).MaxSessions; got != 3 {
			t.Fatalf("max_sessions=%d, 期望 3", got)
		}
		assertAuditAction(t, s, "user_max_sessions_set")
	})

	t.Run("写失败", func(t *testing.T) {
		s := newUsersGuardServer(t)
		u := newPRGTestUser(t, s, "alice")
		abortSQLiteWrites(t, s, "no_max_sessions", "users", "UPDATE OF max_sessions", "")

		w := httptest.NewRecorder()
		s.handleUserAction(w, userActionReq(t, u.ID, "set-max-sessions",
			url.Values{"max_sessions": {"3"}}))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if got := mustGetUser(t, s, u.ID).MaxSessions; got != 0 {
			t.Fatalf("报错却把上限改成了 %d", got)
		}
	})
}

// -------------------------------------------------------------------------
// 一次性凭证页的归属校验
// -------------------------------------------------------------------------

// token 合法但拼到了别人的 {id} 上 → 410,并且这一次「试」就把 token 烧掉:
// 持有 token 却不知道归属的人无法枚举 URL 上的 id 去撞出正主。
func TestUserResetPSKResultFlash_ForeignUserIsGoneAndTokenIsBurned(t *testing.T) {
	s := newUsersGuardServer(t)
	alice := newPRGTestUser(t, s, "alice")
	bob := newPRGTestUser(t, s, "bob")

	tok, err := s.credFlash.Stash(credentialsFlashPayload{
		Kind: credentialsFlashKindUserResetPSK, UserID: alice.ID,
		Username: "alice", PSK: "PLAIN-ALICE",
	}, 1)
	if err != nil {
		t.Fatalf("Stash: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleUserResetPSKResultFlash(w, adminGetReq("/users/x/reset-psk-result?token="+tok), bob)
	if w.Code != http.StatusGone {
		t.Fatalf("code=%d, 期望 410", w.Code)
	}
	if strings.Contains(w.Body.String(), "PLAIN-ALICE") {
		t.Fatal("泄漏了另一个用户的 PSK")
	}

	// 正主也拿不到了 —— 一次性就是一次性,这是防枚举的代价,刻意如此。
	w = httptest.NewRecorder()
	s.handleUserResetPSKResultFlash(w, adminGetReq("/users/x/reset-psk-result?token="+tok), alice)
	if w.Code != http.StatusGone {
		t.Fatalf("第二次 code=%d, 期望 410(token 应已被消费)", w.Code)
	}
}

// -------------------------------------------------------------------------
// 凭证二维码
// -------------------------------------------------------------------------

// 二维码画不出来(payload 超出 QR 容量)时,URL 还是要给 —— 让用户能手抄,
// 而不是整个流程翻车。这条 fallback 的存在本身就是刻意的:调用方那时已经
// 把 PSK rotate 掉了,不能因为画图失败就让整个操作报错。
func TestBuildCredentialsQR_OversizedPayloadStillReturnsTheURL(t *testing.T) {
	credURL, qr := buildCredentialsURLAndQR("cred-uuid", strings.Repeat("u", 4096),
		"psk-value", 1700000000, "vpn.example.com", "srv-1")
	if credURL == "" {
		t.Fatal("URL 也没给,用户连手抄都做不到")
	}
	if qr != "" {
		t.Fatalf("超容量 payload 竟然画出了二维码(len=%d)", len(qr))
	}

	// 缺 credential_id / PSK 时两者都为空:模板据此渲染「凭证未生成」。
	if u, q := buildCredentialsURLAndQR("", "alice", "psk", 1, "", ""); u != "" || q != "" {
		t.Fatalf("缺 credential_id 应两者皆空, got (%q, %q)", u, q)
	}
	if u, q := buildCredentialsURLAndQR("cred", "alice", "", 1, "", ""); u != "" || q != "" {
		t.Fatalf("缺 PSK 应两者皆空, got (%q, %q)", u, q)
	}
}
