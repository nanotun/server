package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/nanotun/server/store"
)

// 批准一条路由等于允许某台设备把流量中继进它所在的网段。这里的每道闸挡的都是
// 一种「批下去之后才发现坏了」的情况:批给手机的出口、批给已禁用账号的出口、
// 批一条与本机 mesh 网段重叠的子网(会把发往离线 mesh 地址的包泄漏进别人 LAN)。

func newRouteGuardEnv(t *testing.T, platform string) (*Server, *store.User, *store.Device) {
	t.Helper()
	s := newTestServerMinimal(t)
	u := newPRGTestUser(t, s, "route-guard-"+platform)
	d, err := s.store.UpsertDevice(t.Context(), u.ID, "dev-"+platform, "dev-"+platform, platform)
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	return s, u, d
}

func routeActionPath(deviceID int64, cidr, verb string) string {
	return "/routes/" + strconv.FormatInt(deviceID, 10) + "/" + cidr + "/" + verb
}

func TestHandleRouteAction_ExitRouteApprovalRefusesWhatCannotActuallyBeAnExit(t *testing.T) {
	t.Run("手机平台跑不了出口", func(t *testing.T) {
		s, _, d := newRouteGuardEnv(t, "android")
		mustAdvertiseRoute(t, s, d.ID, "0.0.0.0/0")

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "0.0.0.0/0", "approve"), nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400 —— 批下去就是往客户端下拉里塞一个用不了的出口", w.Code)
		}
		if got := routeStatus(t, s, d.ID, "0.0.0.0/0"); got == store.RouteStatusApproved {
			t.Fatal("被拒了却还是批准了")
		}
	})

	t.Run("账号已禁用的设备", func(t *testing.T) {
		s, u, d := newRouteGuardEnv(t, "linux")
		mustAdvertiseRoute(t, s, d.ID, "0.0.0.0/0")
		if err := s.store.DisableUser(t.Context(), u.ID); err != nil {
			t.Fatalf("DisableUser: %v", err)
		}

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "0.0.0.0/0", "approve"), nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400 —— 禁用账号的设备连不上服务端,批了就是个死出口挂在所有人的下拉里", w.Code)
		}
	})

	t.Run("设备已删", func(t *testing.T) {
		s, _, d := newRouteGuardEnv(t, "linux")
		mustAdvertiseRoute(t, s, d.ID, "0.0.0.0/0")
		if err := s.store.DeleteDevice(t.Context(), d.ID); err != nil {
			t.Fatalf("DeleteDevice: %v", err)
		}

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "0.0.0.0/0", "approve"), nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("code=%d want 404", w.Code)
		}
	})

	t.Run("v6 默认路由走同一道闸", func(t *testing.T) {
		s, _, d := newRouteGuardEnv(t, "ios")
		mustAdvertiseRoute(t, s, d.ID, "::/0")

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "::/0", "approve"), nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400 —— v4 挡了 v6 没挡,等于闸门只关了一半", w.Code)
		}
	})

	t.Run("合格的出口能批下去", func(t *testing.T) {
		s, _, d := newRouteGuardEnv(t, "linux")
		mustAdvertiseRoute(t, s, d.ID, "0.0.0.0/0")

		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "0.0.0.0/0", "approve"), nil))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
		}
		if got := routeStatus(t, s, d.ID, "0.0.0.0/0"); got != store.RouteStatusApproved {
			t.Fatalf("status=%q", got)
		}
	})
}

// 与本机 mesh 网段重叠的子网路由不能批:批了之后,发往「当前离线的 mesh 地址」的
// 包会被中继进宣告方的 LAN —— 跨信任域泄漏。
func TestHandleRouteAction_ApproveRefusesSubnetsOverlappingTheMesh(t *testing.T) {
	s, _, d := newRouteGuardEnv(t, "linux")
	if err := s.store.SetMeshCIDRs(t.Context(), []string{"10.80.0.0/16"}); err != nil {
		t.Fatalf("SetMeshCIDRs: %v", err)
	}

	mustAdvertiseRoute(t, s, d.ID, "10.80.5.0/24")
	w := httptest.NewRecorder()
	s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "10.80.5.0/24", "approve"), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code=%d want 400 —— 与 mesh 网段交叠的子网批下去会把流量泄漏进别人的 LAN", w.Code)
	}
	if got := routeStatus(t, s, d.ID, "10.80.5.0/24"); got == store.RouteStatusApproved {
		t.Fatal("被拒了却还是批准了")
	}

	// 不交叠的照批。
	mustAdvertiseRoute(t, s, d.ID, "192.168.7.0/24")
	w2 := httptest.NewRecorder()
	s.handleRouteAction(w2, newRouteActionRequest(t, routeActionPath(d.ID, "192.168.7.0/24", "approve"), nil))
	if w2.Code != http.StatusSeeOther {
		t.Fatalf("不交叠的子网应能批准,code=%d body=%q", w2.Code, w2.Body.String())
	}
}

// reject 只能作用于 pending 行。不加这道闸,绕过 UI 直接 POST 就能把已批准的路由
// 悄悄翻成 rejected —— 等价于一次不走 delete 审计口径的隐式撤销。
func TestHandleRouteAction_RejectOnlyAppliesToPendingRows(t *testing.T) {
	s, _, d := newRouteGuardEnv(t, "linux")
	mustAdvertiseRoute(t, s, d.ID, "10.44.0.0/24")

	// 先批准。
	w := httptest.NewRecorder()
	s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "10.44.0.0/24", "approve"), nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("approve code=%d", w.Code)
	}

	// 再 reject 应当被拒。
	w2 := httptest.NewRecorder()
	s.handleRouteAction(w2, newRouteActionRequest(t, routeActionPath(d.ID, "10.44.0.0/24", "reject"),
		url.Values{"reason": {"改主意了"}}))
	if w2.Code != http.StatusConflict {
		t.Fatalf("code=%d want 409", w2.Code)
	}
	if got := routeStatus(t, s, d.ID, "10.44.0.0/24"); got != store.RouteStatusApproved {
		t.Fatalf("状态被改成了 %q —— 撤销应该走 delete,那条才有对应的审计", got)
	}
}

func TestHandleRouteAction_DeleteRemovesTheRow(t *testing.T) {
	s, _, d := newRouteGuardEnv(t, "linux")
	mustAdvertiseRoute(t, s, d.ID, "10.45.0.0/24")

	w := httptest.NewRecorder()
	s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "10.45.0.0/24", "delete"), nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, w.Body.String())
	}
	if _, err := s.store.GetRouteByDeviceCIDR(t.Context(), d.ID, "10.45.0.0/24"); err == nil {
		t.Fatal("路由还在")
	}

	// 再删一次(双击 / 陈旧列表页重提交)要给干净的 404,不是 500。
	w2 := httptest.NewRecorder()
	s.handleRouteAction(w2, newRouteActionRequest(t, routeActionPath(d.ID, "10.45.0.0/24", "delete"), nil))
	if w2.Code != http.StatusNotFound {
		t.Fatalf("重复删除 code=%d want 404", w2.Code)
	}
}

func TestHandleRouteAction_RejectsMalformedPathsAndMethods(t *testing.T) {
	s, _, d := newRouteGuardEnv(t, "linux")
	mustAdvertiseRoute(t, s, d.ID, "10.46.0.0/24")
	ok := routeActionPath(d.ID, "10.46.0.0/24", "approve")

	t.Run("路径段不够", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, "/routes/5", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400", w.Code)
		}
	})

	t.Run("device_id 不是数字", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, "/routes/abc/10.0.0.0/24/approve", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400", w.Code)
		}
	})

	t.Run("不认识的动作", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "10.46.0.0/24", "自爆"), nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d want 400", w.Code)
		}
	})

	t.Run("路由不存在", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleRouteAction(w, newRouteActionRequest(t, routeActionPath(d.ID, "172.16.9.0/24", "approve"), nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("code=%d want 404", w.Code)
		}
	})

	t.Run("只收 POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, ok, nil)
		admin := &store.WebAdmin{ID: 1, Username: "tester", Role: "admin"}
		w := httptest.NewRecorder()
		s.handleRouteAction(w, req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, admin)))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code=%d want 405", w.Code)
		}
		if a := w.Header().Get("Allow"); a != "POST" {
			t.Fatalf("Allow=%q", a)
		}
	})

	t.Run("viewer 改不了", func(t *testing.T) {
		req := newRouteActionRequest(t, ok, nil)
		viewer := &store.WebAdmin{ID: 2, Username: "readonly", Role: "viewer"}
		w := httptest.NewRecorder()
		s.handleRouteAction(w, req.WithContext(context.WithValue(req.Context(), ctxKeyAdmin, viewer)))
		if w.Code == http.StatusSeeOther {
			t.Fatal("只读账号批准了一条路由")
		}
		if got := routeStatus(t, s, d.ID, "10.46.0.0/24"); got == store.RouteStatusApproved {
			t.Fatal("只读账号的操作落库了")
		}
	})
}
