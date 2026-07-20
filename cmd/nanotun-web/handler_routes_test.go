package main

// handler_routes_test.go(第十三轮深扫):
//
// 回归:CIDR 含 "/",模板用 urlquery 编码成 %2F 拼进 path
// (/routes/{id}/10.0.0.0%2F24/approve),但 Go 把 r.URL.Path 解码回真斜杠 ——
// 旧代码按固定下标 segs[3] 取 verb 会拿到掩码("24"),approve/reject/delete
// 全部落 unknown action。修复后 verb 恒取最后一段、中间段合并回 CIDR,
// 编码形态(浏览器表单)与裸斜杠形态(curl 手拼)都必须可用。

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// newRouteActionRequest:构造带 admin 身份的 POST 请求(绕过 session 中间件,
// 直接往 ctx 塞 WebAdmin —— 只测 handleRouteAction 自身的 path 解析与写库)。
func newRouteActionRequest(t *testing.T, target string, form url.Values) *http.Request {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(http.MethodPost, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	admin := &store.WebAdmin{ID: 1, Username: "tester", Role: "admin"}
	return req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, admin))
}

func mustAdvertiseRoute(t *testing.T, s *Server, deviceID int64, cidr string) {
	t.Helper()
	if _, err := s.store.UpsertAdvertisedRoute(t.Context(), deviceID, cidr); err != nil {
		t.Fatalf("UpsertAdvertisedRoute(%d, %s): %v", deviceID, cidr, err)
	}
}

func routeStatus(t *testing.T, s *Server, deviceID int64, cidr string) string {
	t.Helper()
	rt, err := s.store.GetRouteByDeviceCIDR(t.Context(), deviceID, cidr)
	if err != nil {
		t.Fatalf("GetRouteByDeviceCIDR(%d, %s): %v", deviceID, cidr, err)
	}
	return rt.Status
}

// TestHandleRouteAction_EncodedSlashCIDR:浏览器表单形态 —— CIDR 以 %2F 编码在 path 里。
func TestHandleRouteAction_EncodedSlashCIDR(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "route-enc")
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "dev-enc", "dev-enc", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	mustAdvertiseRoute(t, s, d.ID, "10.42.0.0/24")

	id := strconv.FormatInt(d.ID, 10)
	req := newRouteActionRequest(t, "/routes/"+id+"/10.42.0.0%2F24/approve", nil)
	w := httptest.NewRecorder()
	s.handleRouteAction(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("approve(%%2F 形态) code=%d body=%q,想要 303", w.Code, w.Body.String())
	}
	if got := routeStatus(t, s, d.ID, "10.42.0.0/24"); got != store.RouteStatusApproved {
		t.Fatalf("approve 后 status=%q,想要 approved", got)
	}
}

// TestHandleRouteAction_RawSlashCIDR:curl 手拼形态 —— path 里就是裸斜杠。
func TestHandleRouteAction_RawSlashCIDR(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "route-raw")
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "dev-raw", "dev-raw", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	mustAdvertiseRoute(t, s, d.ID, "10.43.0.0/24")

	id := strconv.FormatInt(d.ID, 10)
	form := url.Values{"reason": {"nope"}}
	req := newRouteActionRequest(t, "/routes/"+id+"/10.43.0.0/24/reject", form)
	w := httptest.NewRecorder()
	s.handleRouteAction(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("reject(裸斜杠形态) code=%d body=%q,想要 303", w.Code, w.Body.String())
	}
	if got := routeStatus(t, s, d.ID, "10.43.0.0/24"); got != store.RouteStatusRejected {
		t.Fatalf("reject 后 status=%q,想要 rejected", got)
	}
}

// ---- /routes/exit/* ----

func exitForm(deviceID int64, extra url.Values) url.Values {
	form := url.Values{"device_id": {strconv.FormatInt(deviceID, 10)}}
	for k, vs := range extra {
		form[k] = vs
	}
	return form
}

// TestHandleExitAction_DesignateApprovesBoth:designate 一次批 v4+v6(设备未自荐也行)。
func TestHandleExitAction_DesignateApprovesBoth(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "exit-des")
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "dev-des", "dev-des", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	req := newRouteActionRequest(t, "/routes/exit/designate", exitForm(d.ID, nil))
	w := httptest.NewRecorder()
	s.handleExitAction(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("designate code=%d body=%q,想要 303", w.Code, w.Body.String())
	}
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		if got := routeStatus(t, s, d.ID, cidr); got != store.RouteStatusApproved {
			t.Fatalf("designate 后 %s status=%q,想要 approved", cidr, got)
		}
	}
}

// TestHandleExitAction_DesignateRejectsMobile:平台闸口 —— iOS 设备直接 POST 也要被 400。
func TestHandleExitAction_DesignateRejectsMobile(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "exit-ios")
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "dev-ios", "dev-ios", "ios")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	req := newRouteActionRequest(t, "/routes/exit/designate", exitForm(d.ID, nil))
	w := httptest.NewRecorder()
	s.handleExitAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("designate(ios) code=%d body=%q,想要 400", w.Code, w.Body.String())
	}
	if _, err := s.store.GetRouteByDeviceCIDR(t.Context(), d.ID, "0.0.0.0/0"); err == nil {
		t.Fatal("被拦的 designate 不应留下任何路由行")
	}
}

// TestHandleExitAction_DesignateRejectsDisabledOwner:禁用用户的设备指定为出口
// 只会得到永远离线的死出口(buildExitsList 连离线出口一起推进所有客户端下拉)。
func TestHandleExitAction_DesignateRejectsDisabledOwner(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "exit-dis")
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "dev-dis", "dev-dis", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if err := s.store.DisableUser(t.Context(), u.ID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	req := newRouteActionRequest(t, "/routes/exit/designate", exitForm(d.ID, nil))
	w := httptest.NewRecorder()
	s.handleExitAction(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("designate(禁用用户) code=%d body=%q,想要 400", w.Code, w.Body.String())
	}
	if _, err := s.store.GetRouteByDeviceCIDR(t.Context(), d.ID, "0.0.0.0/0"); err == nil {
		t.Fatal("被拦的 designate 不应留下路由行")
	}
}

// TestHandleExitAction_RejectOnlyPending:reject 只翻 pending;已 approved 的出口不受影响
// (防绕过 UI 直 POST 把 approved 出口隐式撤销成 rejected)。
func TestHandleExitAction_RejectOnlyPending(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "exit-rej")
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "dev-rej", "dev-rej", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	// v4 已批准(现役出口),v6 才是 pending 自荐。
	mustAdvertiseRoute(t, s, d.ID, "0.0.0.0/0")
	if err := s.store.SetRouteStatus(t.Context(), d.ID, "0.0.0.0/0", store.RouteStatusApproved, ""); err != nil {
		t.Fatalf("approve v4: %v", err)
	}
	mustAdvertiseRoute(t, s, d.ID, "::/0")

	req := newRouteActionRequest(t, "/routes/exit/reject", exitForm(d.ID, url.Values{"reason": {"no"}}))
	w := httptest.NewRecorder()
	s.handleExitAction(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("reject code=%d body=%q,想要 303", w.Code, w.Body.String())
	}
	if got := routeStatus(t, s, d.ID, "0.0.0.0/0"); got != store.RouteStatusApproved {
		t.Fatalf("approved v4 不该被 reject 波及,实际 status=%q", got)
	}
	if got := routeStatus(t, s, d.ID, "::/0"); got != store.RouteStatusRejected {
		t.Fatalf("pending v6 应翻 rejected,实际 status=%q", got)
	}
}

// TestHandleExitAction_RevokeClearsRows:revoke(含 mode=clear)删掉 0/0+::/0 两行。
func TestHandleExitAction_RevokeClearsRows(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "exit-rev")
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "dev-rev", "dev-rev", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	mustAdvertiseRoute(t, s, d.ID, "0.0.0.0/0")
	if err := s.store.SetRouteStatus(t.Context(), d.ID, "0.0.0.0/0", store.RouteStatusRejected, "nope"); err != nil {
		t.Fatalf("reject v4: %v", err)
	}

	req := newRouteActionRequest(t, "/routes/exit/revoke", exitForm(d.ID, url.Values{"mode": {"clear"}}))
	w := httptest.NewRecorder()
	s.handleExitAction(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("revoke(clear) code=%d body=%q,想要 303", w.Code, w.Body.String())
	}
	if _, err := s.store.GetRouteByDeviceCIDR(t.Context(), d.ID, "0.0.0.0/0"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("clear 后 0/0 行应已删除,err=%v", err)
	}
}

// ---- 全模板栈渲染 ----

// TestHandleRouteList_FullRender(第十七轮深扫):routes_list.html 十几轮改版从未被
// **执行**过 —— 解析通过不代表执行通过(字段名写错 / 管道类型不匹配都是 exec 期才爆,
// 症状是整页 500)。用真实嵌入模板栈渲染一次,数据铺满所有卡片与分支。
func TestHandleRouteList_FullRender(t *testing.T) {
	s := newTestServerMinimal(t)
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	s.tmpl = tmpl

	ctx := t.Context()
	u := newPRGTestUser(t, s, "render-u")
	mk := func(uuid, name, platform string) *store.Device {
		d, derr := s.store.UpsertDevice(ctx, u.ID, uuid, name, platform)
		if derr != nil {
			t.Fatalf("UpsertDevice(%s): %v", name, derr)
		}
		return d
	}
	// 出口卡:已批准出口(带固定 vIP)。
	exitDev := mk("11111111-aaaa-4bbb-8ccc-000000000001", "exit-box", "linux")
	for _, cidr := range []string{"0.0.0.0/0", "::/0"} {
		mustAdvertiseRoute(t, s, exitDev.ID, cidr)
		if err := s.store.SetRouteStatus(ctx, exitDev.ID, cidr, store.RouteStatusApproved, ""); err != nil {
			t.Fatalf("approve exit: %v", err)
		}
	}
	if err := s.store.SetDeviceFixedVIP(ctx, exitDev.ID, "100.64.0.77", ""); err != nil {
		t.Fatalf("SetDeviceFixedVIP: %v", err)
	}
	// 待批出口自荐:capable(linux)与 incapable(ios)各一。
	pendCap := mk("11111111-aaaa-4bbb-8ccc-000000000002", "pend-linux", "linux")
	mustAdvertiseRoute(t, s, pendCap.ID, "0.0.0.0/0")
	pendIOS := mk("11111111-aaaa-4bbb-8ccc-000000000003", "pend-ios", "ios")
	mustAdvertiseRoute(t, s, pendIOS.ID, "0.0.0.0/0")
	// 已拒出口自荐(带原因)。
	rejExit := mk("11111111-aaaa-4bbb-8ccc-000000000004", "rej-exit", "linux")
	mustAdvertiseRoute(t, s, rejExit.ID, "::/0")
	if err := s.store.SetRouteStatus(ctx, rejExit.ID, "::/0", store.RouteStatusRejected, "not-you"); err != nil {
		t.Fatalf("reject exit: %v", err)
	}
	// 子网路由三态。
	subDev := mk("11111111-aaaa-4bbb-8ccc-000000000005", "sub-box", "linux")
	mustAdvertiseRoute(t, s, subDev.ID, "10.10.0.0/24") // pending
	mustAdvertiseRoute(t, s, subDev.ID, "10.20.0.0/24")
	if err := s.store.SetRouteStatus(ctx, subDev.ID, "10.20.0.0/24", store.RouteStatusApproved, ""); err != nil {
		t.Fatalf("approve subnet: %v", err)
	}
	mustAdvertiseRoute(t, s, subDev.ID, "10.30.0.0/24")
	if err := s.store.SetRouteStatus(ctx, subDev.ID, "10.30.0.0/24", store.RouteStatusRejected, "bad-net"); err != nil {
		t.Fatalf("reject subnet: %v", err)
	}
	// 候选下拉:普通 linux 候选应出现;禁用用户的设备不应出现。
	mk("11111111-aaaa-4bbb-8ccc-000000000006", "cand-box", "windows")
	u2, err := s.store.CreateUser(ctx, store.NewUser{Username: "render-dis", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser dis: %v", err)
	}
	if _, err := s.store.UpsertDevice(ctx, u2.ID, "11111111-aaaa-4bbb-8ccc-000000000007", "dis-box", "linux"); err != nil {
		t.Fatalf("UpsertDevice dis: %v", err)
	}
	if err := s.store.DisableUser(ctx, u2.ID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	req := newRouteActionRequest(t, "/routes", nil)
	req.Method = http.MethodGet
	w := httptest.NewRecorder()
	s.handleRouteList(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /routes code=%d body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		"exit-box", "100.64.0.77", // 出口卡 + 固定 vIP
		"PENDING.EXIT", "pend-linux", "pend-ios", // 待批自荐卡
		"REJECTED.EXIT", "rej-exit", "not-you", // 已拒自荐卡 + 原因
		"10.10.0.0/24", "10.20.0.0/24", "10.30.0.0/24", "bad-net", // 子网三态
		"cand-box", // 候选下拉
	} {
		if !strings.Contains(body, want) {
			t.Errorf("渲染输出缺 %q", want)
		}
	}
	if strings.Contains(body, "dis-box") {
		t.Error("禁用用户的设备不应出现在页面任何位置(候选下拉已过滤)")
	}
}

// TestHandleRouteAction_IPv6CIDR:IPv6 CIDR(冒号 + 斜杠都会被编码)。
func TestHandleRouteAction_IPv6CIDR(t *testing.T) {
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "route-v6")
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "dev-v6", "dev-v6", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	mustAdvertiseRoute(t, s, d.ID, "fd00:dead::/64")

	id := strconv.FormatInt(d.ID, 10)
	target := "/routes/" + id + "/" + url.QueryEscape("fd00:dead::/64") + "/delete"
	req := newRouteActionRequest(t, target, nil)
	w := httptest.NewRecorder()
	s.handleRouteAction(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete(IPv6) code=%d body=%q,想要 303", w.Code, w.Body.String())
	}
	if _, err := s.store.GetRouteByDeviceCIDR(t.Context(), d.ID, "fd00:dead::/64"); err == nil {
		t.Fatal("delete 后记录仍存在")
	}
}
