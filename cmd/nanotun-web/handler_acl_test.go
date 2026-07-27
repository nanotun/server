package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// ACL 是 Web 侧唯一一组「写完还必须让数据面重新加载才算数」的规则。
// 管理员判断规则是否生效,全靠 aclChangeFlashQuery 给的那句话 —— 它要是把
// 「reload 失败」说成成功,页面上规则列得好好的、数据面却还按旧规则放行,
// 这正是历史上 CLI 侧踩过的坑,而 Web 侧此前一条测试都没有。

func aclCount(t *testing.T, s *Server) int {
	t.Helper()
	pairs, err := s.store.ListACLPairs(t.Context())
	if err != nil {
		t.Fatalf("ListACLPairs: %v", err)
	}
	return len(pairs)
}

// TestACLChangeFlash_ThreeBranches 三分支各说各的话,尤其是失败不能报成成功。
func TestACLChangeFlash_ThreeBranches(t *testing.T) {
	req := newAdminPostRequest(t, "/acl/new", nil)

	t.Run("未接控制面→提示手动重载", func(t *testing.T) {
		s := newTestServerMinimal(t)
		s.cfg.AutoReloadOnACLChange = true
		s.control = nil
		q := s.aclChangeFlashQuery(req, "flash.aclCreated")
		if k := flashKindOf(t, q); k != "warn" {
			t.Fatalf("控制面不可用时 flash_kind=%q, 期望 warn", k)
		}
	})

	t.Run("自动重载关闭→提示手动重载", func(t *testing.T) {
		s := newTestServerMinimal(t)
		s.cfg.AutoReloadOnACLChange = false
		s.control = newFakeControl(t, controlOK()).client
		q := s.aclChangeFlashQuery(req, "flash.aclCreated")
		if k := flashKindOf(t, q); k != "warn" {
			t.Fatalf("自动重载关闭时 flash_kind=%q, 期望 warn", k)
		}
	})

	t.Run("重载失败→必须报警而不是成功", func(t *testing.T) {
		s := newTestServerMinimal(t)
		s.cfg.AutoReloadOnACLChange = true
		fc := newFakeControl(t, controlBroken())
		s.control = fc.client
		q := s.aclChangeFlashQuery(req, "flash.aclCreated")
		if k := flashKindOf(t, q); k != "warn" {
			t.Fatalf("reload 失败却报 flash_kind=%q —— 管理员会以为规则已生效", k)
		}
		if !fc.sawPath("/reload") {
			t.Fatalf("没有真的去调控制面 reload, 收到的请求: %v", fc.requests())
		}
	})

	t.Run("重载成功→报成功", func(t *testing.T) {
		s := newTestServerMinimal(t)
		s.cfg.AutoReloadOnACLChange = true
		fc := newFakeControl(t, controlOK())
		s.control = fc.client
		q := s.aclChangeFlashQuery(req, "flash.aclCreated")
		if k := flashKindOf(t, q); k != "ok" {
			t.Fatalf("reload 成功却报 flash_kind=%q", k)
		}
		if !fc.sawPath("/reload") {
			t.Fatalf("没有真的去调控制面 reload, 收到的请求: %v", fc.requests())
		}
	})

	// 三种情形的文案必须彼此不同,否则「已生效」和「没生效」在页面上长得一样,
	// 分支写对了也没用。
	texts := map[string]string{}
	for _, c := range []struct {
		name  string
		setup func(s *Server)
	}{
		{"无控制面", func(s *Server) { s.cfg.AutoReloadOnACLChange = true; s.control = nil }},
		{"重载失败", func(s *Server) {
			s.cfg.AutoReloadOnACLChange = true
			s.control = newFakeControl(t, controlBroken()).client
		}},
		{"重载成功", func(s *Server) {
			s.cfg.AutoReloadOnACLChange = true
			s.control = newFakeControl(t, controlOK()).client
		}},
	} {
		s := newTestServerMinimal(t)
		c.setup(s)
		txt := flashTextOf(t, s.aclChangeFlashQuery(req, "flash.aclCreated"))
		for prev, ptxt := range texts {
			if ptxt == txt {
				t.Errorf("「%s」与「%s」的提示文案相同(%q) —— 管理员分不出规则是否生效",
					c.name, prev, txt)
			}
		}
		texts[c.name] = txt
	}
}

// TestParseFormInt64Strict 表单整数严格解析。
//
// 注释里写明了这条的由来:此前解析错误被丢弃、非法输入静默落 0,而 0 在 ACL 语义
// 里是「任意」—— 一次手滑就能把一条定向规则悄悄放大成全网规则。
func TestParseFormInt64Strict(t *testing.T) {
	ok := []struct {
		in   string
		want int64
	}{
		{"", 0}, {"0", 0}, {"123", 123}, {"  42  ", 42}, {"-1", -1},
	}
	for _, c := range ok {
		got, err := parseFormInt64Strict(c.in)
		if err != nil {
			t.Errorf("parseFormInt64Strict(%q) 意外报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseFormInt64Strict(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	// 这些必须报错,而不是静默变成 0 / 截断。
	for _, bad := range []string{"1e3", "8080x", "0x10", "8080.0", "abc", "  ", "99999999999999999999"} {
		if bad == "  " {
			continue // 纯空白等价空串,属合法「任意」
		}
		if got, err := parseFormInt64Strict(bad); err == nil {
			t.Errorf("parseFormInt64Strict(%q) 应报错, 却返回 %d", bad, got)
		}
	}
}

// TestHandleACLNew_CreatesRule 正向:表单落库 + 303 + 通知数据面。
func TestHandleACLNew_CreatesRule(t *testing.T) {
	s := newTestServerMinimal(t)
	s.cfg.AutoReloadOnACLChange = true
	fc := newFakeControl(t, controlOK())
	s.control = fc.client
	src := newPRGTestUser(t, s, "acl-src")
	dst := newPRGTestUser(t, s, "acl-dst")

	form := url.Values{
		"src_user_id": {strconv.FormatInt(src.ID, 10)},
		"dst_user_id": {strconv.FormatInt(dst.ID, 10)},
		"action":      {"deny"},
		"proto":       {"tcp"},
		"port_lo":     {"22"},
		"port_hi":     {"22"},
	}
	w := httptest.NewRecorder()
	s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	pairs, err := s.store.ListACLPairs(t.Context())
	if err != nil {
		t.Fatalf("ListACLPairs: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("应创建 1 条规则, 实际 %d 条", len(pairs))
	}
	p := pairs[0]
	if p.Action != "deny" || p.Proto != "tcp" || p.DstPortLo != 22 || p.DstPortHi != 22 {
		t.Fatalf("规则内容不符: %+v", p)
	}
	if p.SrcUserID != src.ID || p.DstUserID != dst.ID {
		t.Fatalf("src/dst 错位: src=%d dst=%d, 期望 %d/%d",
			p.SrcUserID, p.DstUserID, src.ID, dst.ID)
	}
	if !fc.sawPath("/reload") {
		t.Fatalf("建完规则没通知数据面 reload: %v", fc.requests())
	}
}

// TestHandleACLNew_ProtoAnyBecomesEmpty UI/curl 习惯传 any / *,store 用空串表达
// 「任意协议」。转换漏了会直接 400,或者更糟:把 "any" 当成一个协议名存进去。
func TestHandleACLNew_ProtoAnyBecomesEmpty(t *testing.T) {
	for _, proto := range []string{"any", "*", "ANY"} {
		s := newTestServerMinimal(t)
		src := newPRGTestUser(t, s, "p-src")
		dst := newPRGTestUser(t, s, "p-dst")
		form := url.Values{
			"src_user_id": {strconv.FormatInt(src.ID, 10)},
			"dst_user_id": {strconv.FormatInt(dst.ID, 10)},
			"action":      {"allow"},
			"proto":       {proto},
		}
		w := httptest.NewRecorder()
		s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("proto=%q: code=%d body=%q", proto, w.Code, w.Body.String())
		}
		pairs, _ := s.store.ListACLPairs(t.Context())
		if len(pairs) != 1 {
			t.Fatalf("proto=%q: 应创建 1 条, 实际 %d", proto, len(pairs))
		}
		if pairs[0].Proto != "" {
			t.Fatalf("proto=%q 应归一成空串(任意), 实际 %q", proto, pairs[0].Proto)
		}
	}
}

// TestHandleACLNew_BadNumbersDoNotCreateAnyRule 是这组里最重要的一条:
// 非法数字必须**整条打回**,绝不能落库。若静默变 0,一条本来指名道姓的规则就会
// 变成 src=任意 / dst=任意 / 端口=任意 —— 一条 allow 规则可以就此洞穿整个 ACL。
func TestHandleACLNew_BadNumbersDoNotCreateAnyRule(t *testing.T) {
	bad := []struct {
		name  string
		field string
		value string
	}{
		{"科学计数法用户 ID", "src_user_id", "1e3"},
		{"带尾巴的用户 ID", "dst_user_id", "12x"},
		{"科学计数法端口", "port_lo", "1e3"},
		{"带尾巴的端口", "port_hi", "8080x"},
		{"十六进制端口", "port_lo", "0x50"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			s := newTestServerMinimal(t)
			src := newPRGTestUser(t, s, "b-src")
			dst := newPRGTestUser(t, s, "b-dst")
			form := url.Values{
				"src_user_id": {strconv.FormatInt(src.ID, 10)},
				"dst_user_id": {strconv.FormatInt(dst.ID, 10)},
				"action":      {"allow"},
				"proto":       {"tcp"},
				"port_lo":     {"80"},
				"port_hi":     {"80"},
			}
			form.Set(c.field, c.value)
			w := httptest.NewRecorder()
			s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
			if w.Code == http.StatusSeeOther {
				t.Errorf("%s=%q 被当成合法输入接受了(303)", c.field, c.value)
			}
			if n := aclCount(t, s); n != 0 {
				pairs, _ := s.store.ListACLPairs(t.Context())
				t.Fatalf("%s=%q 竟落库 %d 条规则: %+v", c.field, c.value, n, pairs)
			}
		})
	}
}

// TestHandleACLAction_Delete 删除路径:成功删 + 通知数据面;非法 id 不能 500。
func TestHandleACLAction_Delete(t *testing.T) {
	s := newTestServerMinimal(t)
	s.cfg.AutoReloadOnACLChange = true
	fc := newFakeControl(t, controlOK())
	s.control = fc.client
	src := newPRGTestUser(t, s, "d-src")
	dst := newPRGTestUser(t, s, "d-dst")
	form := url.Values{
		"src_user_id": {strconv.FormatInt(src.ID, 10)},
		"dst_user_id": {strconv.FormatInt(dst.ID, 10)},
		"action":      {"deny"},
		"proto":       {"udp"},
	}
	w := httptest.NewRecorder()
	s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("前置创建失败: code=%d body=%q", w.Code, w.Body.String())
	}
	pairs, _ := s.store.ListACLPairs(t.Context())
	if len(pairs) != 1 {
		t.Fatalf("前置应有 1 条规则, 实际 %d", len(pairs))
	}
	id := strconv.FormatInt(pairs[0].ID, 10)

	w = httptest.NewRecorder()
	s.handleACLAction(w, newAdminPostRequest(t, "/acl/"+id+"/delete", nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	if n := aclCount(t, s); n != 0 {
		t.Fatalf("删除后仍剩 %d 条", n)
	}
	if !fc.sawPath("/reload") {
		t.Fatalf("删除后没通知数据面: %v", fc.requests())
	}
}

// TestHandleACLAction_BadInput 非法 id / 未知动作 / 错方法都应是 4xx,不能 5xx,
// 也不能误删别的规则。
func TestHandleACLAction_BadInput(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		method string
	}{
		{"非数字 id", "/acl/abc/delete", http.MethodPost},
		{"零 id", "/acl/0/delete", http.MethodPost},
		{"负 id", "/acl/-1/delete", http.MethodPost},
		{"缺动作段", "/acl/1", http.MethodPost},
		{"未知动作", "/acl/1/nuke", http.MethodPost},
		{"GET 删除", "/acl/1/delete", http.MethodGet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newTestServerMinimal(t)
			src := newPRGTestUser(t, s, "k-src")
			dst := newPRGTestUser(t, s, "k-dst")
			form := url.Values{
				"src_user_id": {strconv.FormatInt(src.ID, 10)},
				"dst_user_id": {strconv.FormatInt(dst.ID, 10)},
				"action":      {"deny"},
			}
			w := httptest.NewRecorder()
			s.handleACLNew(w, newAdminPostRequest(t, "/acl/new", form))
			before := aclCount(t, s)

			req := newAdminPostRequest(t, c.path, nil)
			req.Method = c.method
			w = httptest.NewRecorder()
			s.handleACLAction(w, req)

			if w.Code >= 500 {
				t.Errorf("%s → %d(5xx),坏输入应是 4xx: %q", c.path, w.Code, w.Body.String())
			}
			if w.Code == http.StatusSeeOther {
				t.Errorf("%s 不该当成一次成功删除", c.path)
			}
			if after := aclCount(t, s); after != before {
				t.Errorf("%s 改动了规则条数: %d → %d", c.path, before, after)
			}
		})
	}
}

// TestHandleACLList_RejectsNonGET 列表页只读。
func TestHandleACLList_RejectsNonGET(t *testing.T) {
	s := newTestServerMinimal(t)
	w := httptest.NewRecorder()
	s.handleACLList(w, newAdminPostRequest(t, "/acl", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /acl code=%d, 期望 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); !strings.Contains(allow, "GET") {
		t.Fatalf("405 应带 Allow: GET, 实际 %q", allow)
	}
}
