package main

// handler_routes_guards_test.go(第十九轮)——/routes 与 /routes/exit 的失败侧
// 与分支侧闸门。
//
// 已有测试盯的是「什么该批、什么不该批」。本文件盯的是这些判断**做不下去**时
// 的行为,以及只在特定数据形态下才走到的分支:
//
//   1. 读失败:路由 / 设备表读不出来时不能渲染成空列表 —— 「没有待批路由」这个
//      结论会让管理员漏掉真实的待批项;
//   2. 写失败:批准 / 拒绝 / 删除写不动时必须报错。页面报「已批准」而库里还是
//      pending,等于管理员以为放通了、客户端却一直不通;
//   3. 闸门 fail-closed:平台/归属检查本身出错时必须拒绝而不是放行 ——
//      闸门不能在系统异常的时刻恰好敞开;
//   4. 出口自荐被拒后的展示分支:同一台设备不能在三张卡里同时出现;
//   5. designate 的 vIP 降级:钉 IP 撞了或写失败时,出口批准不回滚,但横幅必须
//      如实说明「vIP 没钉上」,否则管理员以为地址已经固定了。

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// newRoutesGuardServer:真实模板 —— 列表页的断言要看渲染结果。
func newRoutesGuardServer(t *testing.T) *Server {
	t.Helper()
	return newMeTestServer(t)
}

// routeDevice 造一台指定平台的设备(可带 lease)。
func routeDevice(t *testing.T, s *Server, username, platform, leaseV4 string) *store.Device {
	t.Helper()
	u := newPRGTestUser(t, s, username)
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "uuid-"+username, username+"-box", platform)
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if leaseV4 != "" {
		if _, err := s.store.UpsertLease(t.Context(), d.ID, leaseV4, "", false); err != nil {
			t.Fatalf("UpsertLease: %v", err)
		}
	}
	return d
}

// routeStatusOrEmpty:行不存在时返回 ""(而不是 t.Fatal)。失败路径上「这条路由
// 压根没建出来」也是合格结果,不能因为查不到就把测试判成错误。
func routeStatusOrEmpty(t *testing.T, s *Server, deviceID int64, cidr string) string {
	t.Helper()
	r, err := s.store.GetRouteByDeviceCIDR(t.Context(), deviceID, cidr)
	if err != nil {
		return ""
	}
	return r.Status
}

func mustSetRouteStatus(t *testing.T, s *Server, deviceID int64, cidr, status, reason string) {
	t.Helper()
	if err := s.store.SetRouteStatus(t.Context(), deviceID, cidr, status, reason); err != nil {
		t.Fatalf("SetRouteStatus(%d, %s, %s): %v", deviceID, cidr, status, err)
	}
}

func exitActionReq(t *testing.T, verb string, form url.Values) *http.Request {
	t.Helper()
	return newAdminPostRequest(t, "/routes/exit/"+verb, form)
}

// =========================================================================
// GET /routes
// =========================================================================

func TestRouteList_RejectsNonGET(t *testing.T) {
	s := newRoutesGuardServer(t)
	w := httptest.NewRecorder()
	s.handleRouteList(w, newAdminPostRequest(t, "/routes", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d, 期望 405", w.Code)
	}
}

// 待批路由列表读不出来时必须报错。渲染成空表 = 告诉管理员「没有待批项」,
// 真实的待批请求就此消失在视野里。
func TestRouteList_ReadFailuresAreReported(t *testing.T) {
	t.Run("路由表读失败", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "")
		mustAdvertiseRoute(t, s, d.ID, "10.42.0.0/24")
		if _, err := s.store.DB().ExecContext(t.Context(),
			`UPDATE subnet_routes SET advertised_at='not-a-number' WHERE device_id=?`, d.ID); err != nil {
			t.Fatalf("注入坏路由行: %v", err)
		}

		w := httptest.NewRecorder()
		s.handleRouteList(w, adminGetReq("/routes"))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if strings.Contains(w.Body.String(), "10.42.0.0/24") {
			t.Fatal("出错页里还渲染了半截列表")
		}
	})

	t.Run("设备表读失败", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "")
		mustAdvertiseRoute(t, s, d.ID, "10.42.0.0/24")
		corruptDeviceRow(t, s, d.ID)

		w := httptest.NewRecorder()
		s.handleRouteList(w, adminGetReq("/routes"))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
	})
}

// 被拒的出口自荐必须能在页面上看见(否则误拒之后没有 UI 入口能恢复),但同一台
// 设备不能同时出现在「出口」「待批」「已拒绝」三张卡里 —— 那种页面没人看得懂。
func TestRouteList_RejectedExitIsVisibleButNotDuplicated(t *testing.T) {
	s := newRoutesGuardServer(t)
	// 只被拒:该出现在「已拒绝」卡里。
	rejected := routeDevice(t, s, "rejected-only", "linux", "")
	for _, cidr := range []string{util.ExitDefaultRouteV4, util.ExitDefaultRouteV6} {
		mustAdvertiseRoute(t, s, rejected.ID, cidr)
		mustSetRouteStatus(t, s, rejected.ID, cidr, store.RouteStatusRejected, "平台不合适")
	}
	// v4 已批准、v6 还留着 rejected 残留:不该在「已拒绝」卡里重复出现。
	mixed := routeDevice(t, s, "mixed", "linux", "")
	mustAdvertiseRoute(t, s, mixed.ID, util.ExitDefaultRouteV4)
	mustSetRouteStatus(t, s, mixed.ID, util.ExitDefaultRouteV4, store.RouteStatusApproved, "")
	mustAdvertiseRoute(t, s, mixed.ID, util.ExitDefaultRouteV6)
	mustSetRouteStatus(t, s, mixed.ID, util.ExitDefaultRouteV6, store.RouteStatusRejected, "残留")
	// 待批 + rejected 残留:同理只进「待批」卡。
	pending := routeDevice(t, s, "pending", "linux", "")
	mustAdvertiseRoute(t, s, pending.ID, util.ExitDefaultRouteV4)
	mustAdvertiseRoute(t, s, pending.ID, util.ExitDefaultRouteV6)
	mustSetRouteStatus(t, s, pending.ID, util.ExitDefaultRouteV6, store.RouteStatusRejected, "残留")

	w := httptest.NewRecorder()
	s.handleRouteList(w, adminGetReq("/routes"))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	if !strings.Contains(body, "平台不合适") {
		t.Fatal("被拒的出口自荐没露出拒绝原因 —— 误拒之后管理员没有恢复入口")
	}
	// 每台设备只该出现在一张卡里:数一下名字出现的次数最直白。
	if n := strings.Count(body, "mixed-box"); n > 2 {
		t.Fatalf("mixed-box 在页面上出现 %d 次,像是同时进了多张卡", n)
	}
	if n := strings.Count(body, "pending-box"); n > 2 {
		t.Fatalf("pending-box 在页面上出现 %d 次,像是同时进了多张卡", n)
	}
}

// 指定出口的下拉只能列出真的能当出口的设备。列错了不只是难看:管理员按下确认
// 就会造出一台**永远连不上**的出口(手机没有内核转发、被禁用的用户根本登不进来),
// 而所有客户端的出口下拉里都会挂着它。
func TestRouteList_ExitCandidatesExcludeIneligibleDevices(t *testing.T) {
	s := newRoutesGuardServer(t)
	ok := routeDevice(t, s, "linuxbox", "linux", "")
	phone := routeDevice(t, s, "phone", "ios", "")
	disabled := routeDevice(t, s, "disabled", "linux", "")
	if err := s.store.DisableUser(t.Context(), disabled.UserID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	already := routeDevice(t, s, "already", "linux", "")
	mustAdvertiseRoute(t, s, already.ID, util.ExitDefaultRouteV4)
	mustSetRouteStatus(t, s, already.ID, util.ExitDefaultRouteV4, store.RouteStatusApproved, "")

	w := httptest.NewRecorder()
	s.handleRouteList(w, adminGetReq("/routes"))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	// 下拉里每个候选都是一个 <option value="{id}">,拿它判定最准 —— 设备名在
	// 其它卡片里也会出现,直接找名字会误判。
	isCandidate := func(id int64) bool {
		return strings.Contains(body, `<option value="`+itoa(id)+`">`)
	}
	if !isCandidate(ok.ID) {
		t.Error("能当出口的 linux 设备没进候选下拉")
	}
	for _, tc := range []struct {
		why string
		id  int64
	}{
		{"手机", phone.ID},
		{"用户已被禁用", disabled.ID},
		{"已经是出口了", already.ID},
	} {
		if isCandidate(tc.id) {
			t.Errorf("%s 的设备(#%d)竟然进了候选下拉", tc.why, tc.id)
		}
	}
}

// =========================================================================
// POST /routes/exit/*
// =========================================================================

func TestExitAction_MethodRoleAndInputGuards(t *testing.T) {
	s := newRoutesGuardServer(t)
	d := routeDevice(t, s, "alice", "linux", "")

	t.Run("GET 不能改出口", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleExitAction(w, adminGetReq("/routes/exit/designate"))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code=%d, 期望 405", w.Code)
		}
	})

	t.Run("viewer 不能改出口", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleExitAction(w, viewerReq(http.MethodPost, "/routes/exit/designate"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("code=%d, 期望 403", w.Code)
		}
	})

	t.Run("device_id 不合法", func(t *testing.T) {
		for _, v := range []string{"", "abc", "0", "-1"} {
			w := httptest.NewRecorder()
			s.handleExitAction(w, exitActionReq(t, "designate", url.Values{"device_id": {v}}))
			if w.Code != http.StatusBadRequest {
				t.Errorf("device_id=%q: code=%d, 期望 400", v, w.Code)
			}
		}
	})

	t.Run("设备不存在", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleExitAction(w, exitActionReq(t, "designate", url.Values{"device_id": {"99999"}}))
		if w.Code != http.StatusNotFound {
			t.Fatalf("code=%d, 期望 404", w.Code)
		}
	})

	t.Run("设备行读不出来不是 404", func(t *testing.T) {
		s2 := newRoutesGuardServer(t)
		d2 := routeDevice(t, s2, "bob", "linux", "")
		corruptDeviceRow(t, s2, d2.ID)
		w := httptest.NewRecorder()
		s2.handleExitAction(w, exitActionReq(t, "designate",
			url.Values{"device_id": {itoa(d2.ID)}}))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
	})

	t.Run("动作缺失或未知", func(t *testing.T) {
		for _, target := range []string{"/routes/exit", "/routes/exit/nuke"} {
			w := httptest.NewRecorder()
			s.handleExitAction(w, newAdminPostRequest(t, target,
				url.Values{"device_id": {itoa(d.ID)}}))
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s: code=%d, 期望 400", target, w.Code)
			}
		}
	})
}

// 手机 / 未知平台不能当出口:UI 的下拉里本来就过滤掉了它们,但直接 POST 绕过 UI
// 也必须被拦 —— 把手机批成出口,等于把所有人的流量指到一台会随时熄屏断网的设备上。
func TestExitDesignate_OnlyExitCapablePlatforms(t *testing.T) {
	s := newRoutesGuardServer(t)
	for _, platform := range []string{"ios", "android", "toaster"} {
		d := routeDevice(t, s, "u-"+platform, platform, "")
		w := httptest.NewRecorder()
		s.handleExitAction(w, exitActionReq(t, "designate", url.Values{"device_id": {itoa(d.ID)}}))
		if w.Code != http.StatusBadRequest {
			t.Errorf("platform=%q: code=%d, 期望 400", platform, w.Code)
		}
		if got := routeStatusOrEmpty(t, s, d.ID, util.ExitDefaultRouteV4); got != "" {
			t.Errorf("platform=%q 被拦下了却还留了一条 %q 的出口路由", platform, got)
		}
	}
}

// designate 分两件事:批出口路由 + 把 vIP 焊死。后者失败(地址被别人占了 / 写不动)
// 时前者不回滚 —— 但横幅必须如实说明 vIP 没钉上,否则管理员以为出口地址已经稳定了。
func TestExitDesignate_VIPProblemsDegradeButStillApprove(t *testing.T) {
	t.Run("地址被别人占着", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "100.64.0.40")
		other := routeDevice(t, s, "bob", "linux", "")
		// 直接落库造出「另一台设备已经钉了这个地址」的状态:走 store 会被它自己的
		// 跨表冲突校验拦住(那条校验正是这里要验证 handler 侧预检有没有覆盖的东西)。
		if _, err := s.store.DB().ExecContext(t.Context(),
			`UPDATE devices SET fixed_vip_v4='100.64.0.40' WHERE id=?`, other.ID); err != nil {
			t.Fatalf("造占用状态: %v", err)
		}

		w := httptest.NewRecorder()
		s.handleExitAction(w, exitActionReq(t, "designate", url.Values{"device_id": {itoa(d.ID)}}))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("code=%d body=%q, 期望 303(出口照批)", w.Code, trimForLog(w.Body.String()))
		}
		if got := routeStatus(t, s, d.ID, util.ExitDefaultRouteV4); got != store.RouteStatusApproved {
			t.Fatalf("出口状态=%q, 期望 approved", got)
		}
		if got := mustGetDevice(t, s, d.ID).FixedVIPv4; got != "" {
			t.Fatalf("撞了还把 vIP 钉上去了: %q", got)
		}
		probe := httptest.NewRequest(http.MethodGet, "/routes", nil)
		if flash := flashTextOf(t, w.Header().Get("Location")); !strings.Contains(flash,
			tr(probe, "flash.exitDesignatedVipConflict")) {
			t.Fatalf("横幅=%q, 没说明 vIP 撞了", flash)
		}
	})

	t.Run("钉 vIP 写不动", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "100.64.0.41")
		abortSQLiteWrites(t, s, "no_fixed_vip", "devices", "UPDATE OF fixed_vip_v4", "")

		w := httptest.NewRecorder()
		s.handleExitAction(w, exitActionReq(t, "designate", url.Values{"device_id": {itoa(d.ID)}}))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
		}
		probe := httptest.NewRequest(http.MethodGet, "/routes", nil)
		if flash := flashTextOf(t, w.Header().Get("Location")); !strings.Contains(flash,
			tr(probe, "flash.exitDesignatedVipFailed")) {
			t.Fatalf("横幅=%q, 没说明 vIP 没钉上", flash)
		}
	})

	t.Run("设备从没上线过", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "") // 无 lease、无 fixed

		w := httptest.NewRecorder()
		s.handleExitAction(w, exitActionReq(t, "designate", url.Values{"device_id": {itoa(d.ID)}}))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("code=%d, 期望 303", w.Code)
		}
		probe := httptest.NewRequest(http.MethodGet, "/routes", nil)
		if flash := flashTextOf(t, w.Header().Get("Location")); !strings.Contains(flash,
			tr(probe, "flash.exitDesignatedNoVip")) {
			t.Fatalf("横幅=%q, 没提醒 vIP 还没固定", flash)
		}
	})
}

// designate 的写失败必须整单报错:半批准状态(v4 批了 v6 没批)会让客户端只有
// 一族流量走得通,现场表现是「有时能上外网有时不能」,极难查。
func TestExitDesignate_WriteFailuresAreReported(t *testing.T) {
	for _, tc := range []struct{ name, op, when string }{
		{"写不进自荐记录", "INSERT", ""},
		{"改不了批准状态", "UPDATE OF status", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRoutesGuardServer(t)
			d := routeDevice(t, s, "alice", "linux", "")
			// 两族都先落成 pending:这样「自荐记录写不进去」时后面那步改状态本来
			// 是**能**成功的 —— 若 handler 忽略前一步的错继续往下走,出口就会被静悄悄
			// 批准。先铺好行,这条测试才能把那种漏放行的写法逼出来。
			mustAdvertiseRoute(t, s, d.ID, util.ExitDefaultRouteV4)
			mustAdvertiseRoute(t, s, d.ID, util.ExitDefaultRouteV6)
			abortSQLiteWrites(t, s, "no_route_write", "subnet_routes", tc.op, tc.when)

			w := httptest.NewRecorder()
			s.handleExitAction(w, exitActionReq(t, "designate", url.Values{"device_id": {itoa(d.ID)}}))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
			}
			if got := routeStatusOrEmpty(t, s, d.ID, util.ExitDefaultRouteV4); got == store.RouteStatusApproved {
				t.Fatal("报错却把出口批了")
			}
		})
	}
}

// 归属检查读不出来时必须拒绝(fail-closed)。放行的话,闸门恰好在系统异常时敞开 ——
// 而那正是最不该放行的时刻。
func TestExitDesignate_OwnerLookupFailureIsFailClosed(t *testing.T) {
	s := newRoutesGuardServer(t)
	d := routeDevice(t, s, "alice", "linux", "")
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE users SET created_at='not-a-number' WHERE id=?`, d.UserID); err != nil {
		t.Fatalf("注入坏用户行: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleExitAction(w, exitActionReq(t, "designate", url.Values{"device_id": {itoa(d.ID)}}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if got := routeStatusOrEmpty(t, s, d.ID, util.ExitDefaultRouteV4); got == store.RouteStatusApproved {
		t.Fatal("读不到归属却把出口批了")
	}
}

func TestExitRevoke_DeleteFailureIsReported(t *testing.T) {
	s := newRoutesGuardServer(t)
	d := routeDevice(t, s, "alice", "linux", "")
	mustAdvertiseRoute(t, s, d.ID, util.ExitDefaultRouteV4)
	mustSetRouteStatus(t, s, d.ID, util.ExitDefaultRouteV4, store.RouteStatusApproved, "")
	abortSQLiteWrites(t, s, "no_route_delete", "subnet_routes", "DELETE", "")

	w := httptest.NewRecorder()
	s.handleExitAction(w, exitActionReq(t, "revoke", url.Values{"device_id": {itoa(d.ID)}}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if got := routeStatus(t, s, d.ID, util.ExitDefaultRouteV4); got != store.RouteStatusApproved {
		t.Fatalf("报错却把出口撤了(status=%q)", got)
	}
}

// 拒绝出口自荐:某一族没有记录时跳过、读不出来要报错、写不动要报错。
func TestExitReject_MissingFamilySkipsAndFailuresAreReported(t *testing.T) {
	t.Run("只有 v4 有记录", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "")
		mustAdvertiseRoute(t, s, d.ID, util.ExitDefaultRouteV4)

		w := httptest.NewRecorder()
		s.handleExitAction(w, exitActionReq(t, "reject", url.Values{
			"device_id": {itoa(d.ID)}, "reason": {"不批"},
		}))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
		}
		if got := routeStatus(t, s, d.ID, util.ExitDefaultRouteV4); got != store.RouteStatusRejected {
			t.Fatalf("v4 状态=%q, 期望 rejected", got)
		}
		assertAuditAction(t, s, "exit_reject")
	})

	t.Run("路由行读不出来", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "")
		mustAdvertiseRoute(t, s, d.ID, util.ExitDefaultRouteV4)
		if _, err := s.store.DB().ExecContext(t.Context(),
			`UPDATE subnet_routes SET advertised_at='not-a-number' WHERE device_id=?`, d.ID); err != nil {
			t.Fatalf("注入坏路由行: %v", err)
		}

		w := httptest.NewRecorder()
		s.handleExitAction(w, exitActionReq(t, "reject", url.Values{"device_id": {itoa(d.ID)}}))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
	})

	t.Run("状态写不动", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "")
		mustAdvertiseRoute(t, s, d.ID, util.ExitDefaultRouteV4)
		abortSQLiteWrites(t, s, "no_status_write", "subnet_routes", "UPDATE OF status", "")

		w := httptest.NewRecorder()
		s.handleExitAction(w, exitActionReq(t, "reject", url.Values{"device_id": {itoa(d.ID)}}))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if got := routeStatus(t, s, d.ID, util.ExitDefaultRouteV4); got != store.RouteStatusPending {
			t.Fatalf("报错却把状态改成了 %q", got)
		}
	})
}

// 出口相关的 flash 要能称呼设备。既没别名也没上报名时,回落成 device/{id} ——
// 横幅上出现空白名字会让人以为消息本身出错了。
func TestDeviceDisplayName_FallsBackToID(t *testing.T) {
	s := newRoutesGuardServer(t)
	u := newPRGTestUser(t, s, "nameless")
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "uuid-nameless", "", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if got := deviceDisplayName(d); got != "device/"+strconv.FormatInt(d.ID, 10) {
		t.Fatalf("称呼=%q, 期望回落成 device/%d", got, d.ID)
	}
}

// =========================================================================
// POST /routes/{id}/{cidr}/{verb}
// =========================================================================

// 出口批准的两道闸(平台、归属)自身出错时必须拒绝,不能放行。
func TestRouteApprove_ExitGateIsFailClosed(t *testing.T) {
	t.Run("设备行读不出来", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "")
		mustAdvertiseRoute(t, s, d.ID, util.ExitDefaultRouteV4)
		corruptDeviceRow(t, s, d.ID)

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t,
			routeActionPath(d.ID, util.ExitDefaultRouteV4, "approve"), nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if got := routeStatus(t, s, d.ID, util.ExitDefaultRouteV4); got == store.RouteStatusApproved {
			t.Fatal("闸门失效时反而放行了")
		}
	})

	t.Run("归属读不出来", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "")
		mustAdvertiseRoute(t, s, d.ID, util.ExitDefaultRouteV4)
		if _, err := s.store.DB().ExecContext(t.Context(),
			`UPDATE users SET created_at='not-a-number' WHERE id=?`, d.UserID); err != nil {
			t.Fatalf("注入坏用户行: %v", err)
		}

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t,
			routeActionPath(d.ID, util.ExitDefaultRouteV4, "approve"), nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if got := routeStatus(t, s, d.ID, util.ExitDefaultRouteV4); got == store.RouteStatusApproved {
			t.Fatal("闸门失效时反而放行了")
		}
	})
}

// 通用 approve 端点也要挡住不能当出口的平台 —— designate 那条路挡了不算,
// 直接对着 /routes/{id}/0.0.0.0%2F0/approve 提交同样能造出一台死出口。
func TestRouteApprove_ExitOnIncapablePlatformIsRejected(t *testing.T) {
	s := newRoutesGuardServer(t)
	for _, platform := range []string{"ios", "android"} {
		d := routeDevice(t, s, "u-"+platform, platform, "")
		mustAdvertiseRoute(t, s, d.ID, util.ExitDefaultRouteV4)

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t,
			routeActionPath(d.ID, util.ExitDefaultRouteV4, "approve"), nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("platform=%q: code=%d body=%q, 期望 400",
				platform, w.Code, trimForLog(w.Body.String()))
		}
		if got := routeStatus(t, s, d.ID, util.ExitDefaultRouteV4); got == store.RouteStatusApproved {
			t.Errorf("platform=%q 竟被批成了出口", platform)
		}
	}
}

// mesh 网段快照读不出来时也必须拒绝:这道闸挡的是「把发往 mesh 地址的包中继进
// 别人 LAN」的跨信任域泄漏,读不到就放行等于闸门形同虚设。
func TestRouteApprove_MeshOverlapCheckFailureIsFailClosed(t *testing.T) {
	s := newRoutesGuardServer(t)
	d := routeDevice(t, s, "alice", "linux", "")
	mustAdvertiseRoute(t, s, d.ID, "10.42.0.0/24")
	if _, err := s.store.DB().ExecContext(t.Context(),
		`ALTER TABLE app_settings RENAME TO app_settings_moved`); err != nil {
		t.Fatalf("改表名: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleRouteAction(w, newRouteActionRequest(t,
		routeActionPath(d.ID, "10.42.0.0/24", "approve"), nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if got := routeStatus(t, s, d.ID, "10.42.0.0/24"); got == store.RouteStatusApproved {
		t.Fatal("重叠检查做不了却放行了")
	}
}

// approve / reject / delete 的写失败都必须报错。页面说「已批准」而库里还是 pending,
// 管理员会以为放通了,客户端却一直不通 —— 这种偏差只能靠翻库才能发现。
func TestRouteAction_WriteFailuresAreReported(t *testing.T) {
	const cidr = "10.42.0.0/24"
	for _, tc := range []struct {
		name, verb, op string
		wantStatus     string
	}{
		{"批准", "approve", "UPDATE OF status", store.RouteStatusPending},
		{"拒绝", "reject", "UPDATE OF status", store.RouteStatusPending},
		{"删除", "delete", "DELETE", store.RouteStatusPending},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRoutesGuardServer(t)
			d := routeDevice(t, s, "alice", "linux", "")
			mustAdvertiseRoute(t, s, d.ID, cidr)
			abortSQLiteWrites(t, s, "no_route_mutation", "subnet_routes", tc.op, "")

			w := httptest.NewRecorder()
			s.handleRouteAction(w, newRouteActionRequest(t,
				routeActionPath(d.ID, cidr, tc.verb), url.Values{"reason": {"x"}}))
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
			}
			if strings.Contains(w.Body.String(), "no_route_mutation") {
				t.Fatalf("内部错误细节泄漏: %q", trimForLog(w.Body.String()))
			}
			if got := routeStatus(t, s, d.ID, cidr); got != tc.wantStatus {
				t.Fatalf("状态=%q, 期望仍是 %q", got, tc.wantStatus)
			}
		})
	}
}

// 拒绝路由前要先读它的当前状态:不存在 → 404;读不出来 → 500(不能当成
// 「不是 pending」而回 409,那会让人以为是别人已经处理过了)。
func TestRouteReject_ReadFailuresAreDistinguished(t *testing.T) {
	const cidr = "10.42.0.0/24"

	t.Run("路由不存在", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "")

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, cidr, "reject"), nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("code=%d, 期望 404", w.Code)
		}
	})

	t.Run("路由行读不出来", func(t *testing.T) {
		s := newRoutesGuardServer(t)
		d := routeDevice(t, s, "alice", "linux", "")
		mustAdvertiseRoute(t, s, d.ID, cidr)
		if _, err := s.store.DB().ExecContext(t.Context(),
			`UPDATE subnet_routes SET advertised_at='not-a-number' WHERE device_id=?`, d.ID); err != nil {
			t.Fatalf("注入坏路由行: %v", err)
		}

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, cidr, "reject"), nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
	})
}

// 只有 pending 的路由能被拒。已批准的必须给 409:SetRouteStatus 本身不看当前状态,
// 少了这道闸,拿一个陈旧的列表页(或手拼 POST)就能把线上正在用的路由悄悄翻成
// rejected —— 那等于一次隐式撤销,现场表现是流量突然不通而审计里只有一条"拒绝"。
// 撤销要走 delete,语义上让人看得见。
func TestRouteReject_OnlyTouchesPendingRoutes(t *testing.T) {
	const cidr = "10.42.0.0/24"
	for _, status := range []string{store.RouteStatusApproved, store.RouteStatusRejected} {
		t.Run(status, func(t *testing.T) {
			s := newRoutesGuardServer(t)
			d := routeDevice(t, s, "alice", "linux", "")
			mustAdvertiseRoute(t, s, d.ID, cidr)
			mustSetRouteStatus(t, s, d.ID, cidr, status, "")

			w := httptest.NewRecorder()
			s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, cidr, "reject"),
				url.Values{"reason": {"顺手点错了"}}))
			if w.Code != http.StatusConflict {
				t.Fatalf("code=%d body=%q, 期望 409", w.Code, trimForLog(w.Body.String()))
			}
			if got := routeStatus(t, s, d.ID, cidr); got != status {
				t.Fatalf("状态被改成了 %q, 应保持 %q", got, status)
			}
		})
	}
}

// 双击「批准」/ 对着陈旧列表页提交:行已经被别人删了,要给干净的 404,
// 而不是 500 + 一串 store 内部错误。
func TestRouteWrites_VanishedRowIsACleanNotFound(t *testing.T) {
	const cidr = "10.42.0.0/24"
	for _, verb := range []string{"approve", "delete"} {
		t.Run(verb, func(t *testing.T) {
			s := newRoutesGuardServer(t)
			d := routeDevice(t, s, "alice", "linux", "")

			w := httptest.NewRecorder()
			s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, cidr, verb), nil))
			if w.Code != http.StatusNotFound {
				t.Fatalf("code=%d body=%q, 期望 404", w.Code, trimForLog(w.Body.String()))
			}
		})
	}
}

func TestRouteAction_UnknownVerbAndShortPath(t *testing.T) {
	s := newRoutesGuardServer(t)
	d := routeDevice(t, s, "alice", "linux", "")

	for _, tc := range []struct {
		name   string
		target string
		want   int
	}{
		{"路径太短", "/routes/" + itoa(d.ID), http.StatusBadRequest},
		{"未知动作", routeActionPath(d.ID, "10.42.0.0/24", "nuke"), http.StatusBadRequest},
		{"device_id 非法", "/routes/abc/10.42.0.0/24/approve", http.StatusBadRequest},
	} {
		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, tc.target, nil))
		if w.Code != tc.want {
			t.Errorf("%s (%s): code=%d, 期望 %d", tc.name, tc.target, w.Code, tc.want)
		}
	}
}
