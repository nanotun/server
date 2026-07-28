package main

// handler_acl_guards_test.go(第二十轮)—— /acl 三个入口的失败侧。
//
// handler_acl_test.go 已经把「规则内容对不对」「reload 有没有如实报告」钉住了。
// 这里补的是出错时的表现:
//
//   - 列表读不出来时不能渲染成「一条规则都没有」—— ACL 是安全策略,
//     管理员看到空表会以为放行/拦截规则根本没建过,进而重复建或误判现场;
//   - viewer 不能建也不能删(只读账号绝不能改安全策略);
//   - 重复规则要打回表单重填(可恢复),而 store 的其它错必须是 500(不可误导成"重复");
//   - 删不存在的规则给 404,写失败给 500,两者不能混。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// aclGuardServer:真实模板 —— 本文件要区分「打回表单重填(200)」和
// 「内部错误页(500)」,不加载模板两者都会退化成纯文本,断言就没意义了。
func aclGuardServer(t *testing.T) *Server {
	t.Helper()
	return newMeTestServer(t)
}

// aclForm 造一份合法表单,便于各用例只改其中一项。
func aclForm(t *testing.T, s *Server, srcName, dstName string) url.Values {
	t.Helper()
	src := newPRGTestUser(t, s, srcName)
	dst := newPRGTestUser(t, s, dstName)
	return url.Values{
		"src_user_id": {strconv.FormatInt(src.ID, 10)},
		"dst_user_id": {strconv.FormatInt(dst.ID, 10)},
		"action":      {"deny"},
		"proto":       {"tcp"},
		"port_lo":     {"22"},
		"port_hi":     {"22"},
	}
}

// 规则列表读不出来必须报错。ACL 是安全策略,把读失败渲染成空表等于告诉管理员
// 「这里什么都没配」——他会照着这个假象去加规则或排查放行原因。
func TestACLList_ReadFailureIsNotAnEmptyRuleset(t *testing.T) {
	s := aclGuardServer(t)
	form := aclForm(t, s, "r-src", "r-dst")
	w := httptest.NewRecorder()
	s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("前置建规则失败: code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	// 把规则行的 created_at 写坏:这一行之后扫不出来,库其余部分照常。
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE acl_pairs SET created_at='not-a-number'`); err != nil {
		t.Fatalf("注入坏规则行: %v", err)
	}

	w = httptest.NewRecorder()
	s.handleACLList(w, adminGetReq("/acl"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
}

// 只读账号不能碰安全策略:建和删都要 403,而且不能留下任何痕迹。
func TestACL_ViewerCanNeitherCreateNorDelete(t *testing.T) {
	s := aclGuardServer(t)
	form := aclForm(t, s, "v-src", "v-dst")
	w := httptest.NewRecorder()
	s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("前置建规则失败: code=%d", w.Code)
	}
	pairs, _ := s.store.ListACLPairs(t.Context())
	if len(pairs) != 1 {
		t.Fatalf("前置应有 1 条规则,实际 %d", len(pairs))
	}
	id := strconv.FormatInt(pairs[0].ID, 10)

	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		target  string
	}{
		{"看新建表单", s.handleACLNew, http.MethodGet, "/acl/new"},
		{"提交新建", s.handleACLNew, http.MethodPost, "/acl/new"},
		{"删除", s.handleACLAction, http.MethodPost, "/acl/" + id + "/delete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.handler(w, viewerReq(tc.method, tc.target))
			if w.Code != http.StatusForbidden {
				t.Fatalf("code=%d, 期望 403", w.Code)
			}
		})
	}
	if n := aclCount(t, s); n != 1 {
		t.Fatalf("viewer 的尝试改动了规则条数,现在 %d 条", n)
	}
}

// /acl/new 只认 GET / POST。PUT 之类要 405 并如实列出 Allow,
// 而不是走到 default 里静默什么都不做。
func TestACLNew_RejectsOtherMethods(t *testing.T) {
	s := aclGuardServer(t)
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		w := httptest.NewRecorder()
		req := withAdminCtx(httptest.NewRequest(method, "/acl/new", nil),
			&store.WebAdmin{ID: 1, Username: "tester", Role: "admin"})
		s.handleACLNew(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: code=%d, 期望 405", method, w.Code)
		}
		allow := w.Header().Get("Allow")
		if !strings.Contains(allow, "GET") || !strings.Contains(allow, "POST") {
			t.Errorf("%s: Allow=%q, 期望同时含 GET 和 POST", method, allow)
		}
	}
}

// 重复提交同一条规则(双击 / 后退再交)要打回表单重填,而不是 500 —— 这是
// 可恢复的用户操作。而 store 的其它写错必须是 500:把它也说成"规则已存在"
// 会让管理员以为策略已就位,实际上根本没落库。
func TestACLNew_DuplicateRetriesButOtherErrorsAre500(t *testing.T) {
	t.Run("重复规则打回表单", func(t *testing.T) {
		s := aclGuardServer(t)
		form := aclForm(t, s, "dup-src", "dup-dst")
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
			if i == 0 {
				if w.Code != http.StatusSeeOther {
					t.Fatalf("第一次提交 code=%d, 期望 303", w.Code)
				}
				continue
			}
			if w.Code != http.StatusOK {
				t.Fatalf("重复提交 code=%d body=%q, 期望 200 打回表单",
					w.Code, trimForLog(w.Body.String()))
			}
			probe := httptest.NewRequest(http.MethodGet, "/acl/new", nil)
			if body := w.Body.String(); !strings.Contains(body, tr(probe, "acl.duplicate")) {
				t.Fatalf("打回的表单没说明是重复规则: %q", trimForLog(body))
			}
		}
		if n := aclCount(t, s); n != 1 {
			t.Fatalf("重复提交后应仍是 1 条,实际 %d 条", n)
		}
	})

	t.Run("写不进去是 500", func(t *testing.T) {
		s := aclGuardServer(t)
		form := aclForm(t, s, "w-src", "w-dst")
		abortSQLiteWrites(t, s, "no_acl_insert", "acl_pairs", "INSERT", "")

		w := httptest.NewRecorder()
		s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		probe := httptest.NewRequest(http.MethodGet, "/acl/new", nil)
		if body := w.Body.String(); strings.Contains(body, tr(probe, "acl.duplicate")) {
			t.Fatal("写失败被说成了「规则已存在」")
		}
		if n := aclCount(t, s); n != 0 {
			t.Fatalf("写失败却落库 %d 条", n)
		}
	})
}

// 删除的两种失败要分开:行本来就没了给 404(双击删除的常见情形),
// 写不动给 500 且规则必须还在 —— 页面说删掉了而策略仍生效是最危险的偏差。
func TestACLDelete_MissingIs404AndWriteFailureIs500(t *testing.T) {
	t.Run("规则已不存在", func(t *testing.T) {
		s := aclGuardServer(t)
		w := httptest.NewRecorder()
		s.handleACLAction(w, newAdminPostRequest(t, "/acl/4242/delete", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("code=%d body=%q, 期望 404", w.Code, trimForLog(w.Body.String()))
		}
	})

	t.Run("删不动", func(t *testing.T) {
		s := aclGuardServer(t)
		form := aclForm(t, s, "x-src", "x-dst")
		w := httptest.NewRecorder()
		s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("前置建规则失败: code=%d", w.Code)
		}
		pairs, _ := s.store.ListACLPairs(t.Context())
		id := strconv.FormatInt(pairs[0].ID, 10)
		abortSQLiteWrites(t, s, "no_acl_delete", "acl_pairs", "DELETE", "")

		w = httptest.NewRecorder()
		s.handleACLAction(w, newAdminPostRequest(t, "/acl/"+id+"/delete", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if n := aclCount(t, s); n != 1 {
			t.Fatalf("删除失败后规则应还在,实际 %d 条", n)
		}
	})
}
