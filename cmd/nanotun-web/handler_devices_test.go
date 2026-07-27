package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// 本文件覆盖设备与租约的写路径。
//
// 重点是固定 vIP 的冲突预检:同一条业务规则在系统里有**两份实现** ——
// web 的 checkFixedVIPConflict 与 CLI 的 findFixedVIPConflict(store/devices.go:411
// 的注释里点了名)。CLI 那份有测试(main_test.go 三个用例)、web 这份此前零覆盖,
// 两边可以悄悄分叉:web 放过一个 CLI 会拒的地址,结果就是两台设备抢同一个 IP。
// 下面按 CLI 那张场景表逐条对齐,任一边改了规则,两边测试会一起说话。

// devFixture 造一台属于新用户的设备,可选地给它一个 lease。
func devFixture(t *testing.T, s *Server, username, uuid string, leaseV4, leaseV6 string) *store.Device {
	t.Helper()
	u := newPRGTestUser(t, s, username)
	d, err := s.store.UpsertDevice(t.Context(), u.ID, uuid, username+"-box", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice %s: %v", username, err)
	}
	if leaseV4 != "" || leaseV6 != "" {
		if _, err := s.store.UpsertLease(t.Context(), d.ID, leaseV4, leaseV6, false); err != nil {
			t.Fatalf("UpsertLease %s: %v", username, err)
		}
	}
	return d
}

// setFixedVIP 直接落库,用来构造「别人已经钉了这个地址」的前置状态。
func setFixedVIP(t *testing.T, s *Server, deviceID int64, v4, v6 string) {
	t.Helper()
	if err := s.store.SetDeviceFixedVIP(t.Context(), deviceID, v4, v6, false); err != nil {
		t.Fatalf("SetDeviceFixedVIP(%d): %v", deviceID, err)
	}
}

func mustGetDevice(t *testing.T, s *Server, id int64) *store.Device {
	t.Helper()
	d, err := s.store.GetDevice(t.Context(), id)
	if err != nil {
		t.Fatalf("GetDevice(%d): %v", id, err)
	}
	return d
}

// postDeviceVerb 发一个 POST /devices/{id}/{verb}。
func postDeviceVerb(t *testing.T, s *Server, id int64, verb string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	target := fmt.Sprintf("/devices/%d/%s", id, verb)
	w := httptest.NewRecorder()
	s.handleDeviceAction(w, newAdminPostRequest(t, target, form))
	return w
}

// =========================================================================
// checkFixedVIPConflict —— 与 CLI findFixedVIPConflict 对齐的场景表
// =========================================================================

// TestCheckFixedVIPConflict_DetectsAllOccupancyKinds:一个地址可能被别的设备
// 以两种方式占着 —— 钉死(fixed_vip)或正在租用(lease)。少查任何一种,web 就会
// 放过一个 CLI 会拒的地址,最后撞在 DB UNIQUE 上变成 500,或者两台设备抢同一个 IP。
func TestCheckFixedVIPConflict_DetectsAllOccupancyKinds(t *testing.T) {
	for _, c := range []struct {
		name string
		// 在「别人」那台设备上布置的占用
		otherFixedV4, otherFixedV6 string
		otherLeaseV4, otherLeaseV6 string
		candidate                  string
		wantConflict               bool
	}{
		{name: "撞别人钉死的 v4", otherFixedV4: "100.64.0.10", candidate: "100.64.0.10", wantConflict: true},
		{name: "撞别人钉死的 v6", otherFixedV6: "fd00::10", candidate: "fd00::10", wantConflict: true},
		{name: "撞别人正租用的 v4", otherLeaseV4: "100.64.0.11", candidate: "100.64.0.11", wantConflict: true},
		{name: "撞别人正租用的 v6", otherLeaseV6: "fd00::11", candidate: "fd00::11", wantConflict: true},
		{name: "无人占用", otherFixedV4: "100.64.0.10", candidate: "100.64.0.99"},
		{name: "别人没有 lease 也不该报错", candidate: "100.64.0.99"},
		{name: "空候选值直接放行", otherFixedV4: "100.64.0.10", candidate: ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newTestServerMinimal(t)
			me := devFixture(t, s, "me", "11111111-1111-4111-8111-111111111111", "", "")
			other := devFixture(t, s, "other", "22222222-2222-4222-8222-222222222222",
				c.otherLeaseV4, c.otherLeaseV6)
			if c.otherFixedV4 != "" || c.otherFixedV6 != "" {
				setFixedVIP(t, s, other.ID, c.otherFixedV4, c.otherFixedV6)
			}

			got, err := s.checkFixedVIPConflict(t.Context(), c.candidate, me.ID)
			if err != nil {
				t.Fatalf("checkFixedVIPConflict: %v", err)
			}
			if c.wantConflict {
				if got == "" {
					t.Fatalf("候选 %s 已被占用,却报无冲突", c.candidate)
				}
				// 光「非空」不够:文案必须指认到**正确的那台**设备,否则运维照着
				// 提示去清理会清错人。
				if !strings.Contains(got, fmt.Sprintf("id=%d", other.ID)) {
					t.Errorf("冲突文案没指出占用者 id=%d: %q", other.ID, got)
				}
				if !strings.Contains(got, c.candidate) {
					t.Errorf("冲突文案没带上冲突地址 %s: %q", c.candidate, got)
				}
				return
			}
			if got != "" {
				t.Fatalf("候选 %s 无人占用,却报冲突: %q", c.candidate, got)
			}
		})
	}
}

// TestCheckFixedVIPConflict_SelfDoesNotConflict:跟自己撞不算冲突。
//
// 这是本命令最常见的用法 —— 管理员把设备当前动态拿到的 IP 钉死。把自己算成
// 冲突,这条主流程就直接不可用了(CLI 侧有对应用例 OwnLeaseNotCollision)。
func TestCheckFixedVIPConflict_SelfDoesNotConflict(t *testing.T) {
	s := newTestServerMinimal(t)
	me := devFixture(t, s, "me", "11111111-1111-4111-8111-111111111111", "100.64.0.20", "fd00::20")
	setFixedVIP(t, s, me.ID, "100.64.0.21", "")

	for _, candidate := range []string{"100.64.0.20", "fd00::20", "100.64.0.21"} {
		got, err := s.checkFixedVIPConflict(t.Context(), candidate, me.ID)
		if err != nil {
			t.Fatalf("checkFixedVIPConflict(%s): %v", candidate, err)
		}
		if got != "" {
			t.Errorf("自己占的 %s 不该算冲突, 得到 %q", candidate, got)
		}
	}
}

// =========================================================================
// POST /devices/{id}/set-fixed-vip
// =========================================================================

// TestSetFixedVIP_HappyPath:落库 + 303 + 审计。
func TestSetFixedVIP_HappyPath(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")

	w := postDeviceVerb(t, s, d.ID, "set-fixed-vip", url.Values{
		"fixed_vip_v4": {"100.64.0.7"},
		"fixed_vip_v6": {"fd00::7"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	got := mustGetDevice(t, s, d.ID)
	if got.FixedVIPv4 != "100.64.0.7" || got.FixedVIPv6 != "fd00::7" {
		t.Fatalf("落库 v4=%q v6=%q, 期望 100.64.0.7 / fd00::7", got.FixedVIPv4, got.FixedVIPv6)
	}
	assertAuditAction(t, s, "device_set_fixed_vip")
}

// TestSetFixedVIP_ConflictIsRejectedAndNothingWritten:撞别人 → 409,且**一个字节都不能落库**。
//
// 只检状态码不够:v4 通过、v6 撞车的话,如果实现先写了 v4 再检 v6,页面会报错
// 而库里已经改了一半 —— 运维看到红色报错,以为什么都没发生。
func TestSetFixedVIP_ConflictIsRejectedAndNothingWritten(t *testing.T) {
	s := newTestServerMinimal(t)
	me := devFixture(t, s, "me", "11111111-1111-4111-8111-111111111111", "", "")
	other := devFixture(t, s, "other", "22222222-2222-4222-8222-222222222222", "", "")
	setFixedVIP(t, s, other.ID, "100.64.0.10", "fd00::10")

	for _, c := range []struct {
		name string
		form url.Values
	}{
		{"v4 撞车", url.Values{"fixed_vip_v4": {"100.64.0.10"}}},
		{"v6 撞车", url.Values{"fixed_vip_v6": {"fd00::10"}}},
		{"v4 合法但 v6 撞车", url.Values{
			"fixed_vip_v4": {"100.64.0.77"}, "fixed_vip_v6": {"fd00::10"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := postDeviceVerb(t, s, me.ID, "set-fixed-vip", c.form)
			if w.Code != http.StatusConflict {
				t.Fatalf("code=%d body=%q, 期望 409", w.Code, w.Body.String())
			}
			got := mustGetDevice(t, s, me.ID)
			if got.FixedVIPv4 != "" || got.FixedVIPv6 != "" {
				t.Fatalf("冲突被拒后库里却有残留: v4=%q v6=%q", got.FixedVIPv4, got.FixedVIPv6)
			}
		})
	}
}

// TestSetFixedVIP_WebHasNoForceEscape:CLI 有 --force 可以顶替他人占用,web **没有**。
//
// 曾经有过 allow_collision 表单开关,2026-05-23 拿掉了(它并不能真的允许冲突,
// DB UNIQUE 仍会拒,只是把可读的 409 退化成 500)。这里钉住:随便往表单里塞
// force / allow_collision 都不该开出后门。
func TestSetFixedVIP_WebHasNoForceEscape(t *testing.T) {
	s := newTestServerMinimal(t)
	me := devFixture(t, s, "me", "11111111-1111-4111-8111-111111111111", "", "")
	other := devFixture(t, s, "other", "22222222-2222-4222-8222-222222222222", "", "")
	setFixedVIP(t, s, other.ID, "100.64.0.10", "")

	for _, extra := range []string{"force", "allow_collision", "--force"} {
		form := url.Values{"fixed_vip_v4": {"100.64.0.10"}, extra: {"on"}}
		w := postDeviceVerb(t, s, me.ID, "set-fixed-vip", form)
		if w.Code != http.StatusConflict {
			t.Fatalf("带 %s=on 时 code=%d, 期望仍是 409(web 无 force 逃生口)", extra, w.Code)
		}
	}
}

// TestSetFixedVIP_AddressFamilyIsChecked:v4 字段只收 v4,v6 字段只收 v6。
//
// 不查地址族的话,IPv6 字面量能存进 fixed_vip_v4 —— 落库成功、页面显示正常,
// 直到设备下次登录时分配逻辑静默忽略它,拿到的还是自动分配的地址。这类
// 「设置了但不生效、还不报错」的偏差最难查。
func TestSetFixedVIP_AddressFamilyIsChecked(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")

	for _, c := range []struct{ name, field, value string }{
		{"v6 字面量塞进 v4 字段", "fixed_vip_v4", "fd00::1"},
		{"v4 字面量塞进 v6 字段", "fixed_vip_v6", "100.64.0.1"},
		{"v4 映射地址塞进 v6 字段", "fixed_vip_v6", "::ffff:100.64.0.1"},
		{"v4 字段填垃圾", "fixed_vip_v4", "not-an-ip"},
		{"v6 字段填垃圾", "fixed_vip_v6", "zzzz::1"},
		{"v4 字段填带端口", "fixed_vip_v4", "100.64.0.1:8080"},
		{"v4 字段填 CIDR", "fixed_vip_v4", "100.64.0.0/24"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := postDeviceVerb(t, s, d.ID, "set-fixed-vip", url.Values{c.field: {c.value}})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("code=%d body=%q, 期望 400", w.Code, w.Body.String())
			}
			got := mustGetDevice(t, s, d.ID)
			if got.FixedVIPv4 != "" || got.FixedVIPv6 != "" {
				t.Fatalf("非法输入却落了库: v4=%q v6=%q", got.FixedVIPv4, got.FixedVIPv6)
			}
		})
	}
}

// TestSetFixedVIP_PinningOwnLeaseSucceeds:把自己当前租到的 IP 钉死 —— 主流程,必须放行。
func TestSetFixedVIP_PinningOwnLeaseSucceeds(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "100.64.0.30", "")

	w := postDeviceVerb(t, s, d.ID, "set-fixed-vip", url.Values{"fixed_vip_v4": {"100.64.0.30"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303(钉自己的 lease 不算冲突)", w.Code, w.Body.String())
	}
	if got := mustGetDevice(t, s, d.ID); got.FixedVIPv4 != "100.64.0.30" {
		t.Fatalf("落库 v4=%q, 期望 100.64.0.30", got.FixedVIPv4)
	}
}

// TestSetFixedVIP_ClearingIsAllowedAndDoesNotKick:两个字段都留空 = 解绑。
//
// 解绑不该踢线:在途会话继续用当前 IP 跑完,只是下次重连走自动池。
// 借解绑顺手踢人 = 无谓的断线。
func TestSetFixedVIP_ClearingIsAllowedAndDoesNotKick(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	setFixedVIP(t, s, d.ID, "100.64.0.40", "fd00::40")
	fc := newFakeControl(t, deviceStatusRoutes(nil))
	s.control = fc.client

	w := postDeviceVerb(t, s, d.ID, "set-fixed-vip", url.Values{
		"fixed_vip_v4": {""}, "fixed_vip_v6": {""},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	got := mustGetDevice(t, s, d.ID)
	if got.FixedVIPv4 != "" || got.FixedVIPv6 != "" {
		t.Fatalf("解绑后仍有残留: v4=%q v6=%q", got.FixedVIPv4, got.FixedVIPv6)
	}
	if fc.sawPath("/kick") {
		t.Fatalf("解绑不该踢线, 控制面收到: %v", fc.requests())
	}
}

// =========================================================================
// set-fixed-vip 的踢线决策(四个分支)
// =========================================================================

// deviceStatusRoutes 造一个把 /status 回成给定 session 列表的控制面。
func deviceStatusRoutes(sessions []map[string]any) map[string]http.HandlerFunc {
	routes := controlOK()
	routes["/status"] = func(w http.ResponseWriter, _ *http.Request) {
		if sessions == nil {
			sessions = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sessions": sessions})
	}
	return routes
}

// TestSetFixedVIP_KickDecision:改完固定 IP 要不要踢客户端,分四种情况。
//
// 两个方向都会出事:该踢不踢,客户端会一直用旧 IP 直到自己重连,管理员在页面上
// 看到的新 IP 是假的;不该踢乱踢,每次点保存都白白掐断一次连接。
func TestSetFixedVIP_KickDecision(t *testing.T) {
	const devUUID = "11111111-1111-4111-8111-111111111111"
	for _, c := range []struct {
		name      string
		sessions  []map[string]any // nil = 无在线会话
		noControl bool             // true = 控制面不可达
		newV4     string
		wantKick  bool
	}{
		{
			name:     "无在线会话则不踢(下次登录生效)",
			sessions: nil,
			newV4:    "100.64.0.50",
		},
		{
			name:     "在线 IP 已与新值一致则不踢",
			sessions: []map[string]any{{"conn_id": "c1", "device_id": 1, "vips": []string{"100.64.0.50"}}},
			newV4:    "100.64.0.50",
		},
		{
			name:     "在线 IP 与新值不同则必须踢",
			sessions: []map[string]any{{"conn_id": "c1", "device_id": 1, "vips": []string{"100.64.0.99"}}},
			newV4:    "100.64.0.50",
			wantKick: true,
		},
		{
			name:      "控制面拿不到状态时保守不踢",
			noControl: true,
			newV4:     "100.64.0.50",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newTestServerMinimal(t)
			d := devFixture(t, s, "alice", devUUID, "", "")
			// session 里的 device_id 要对得上真实 ID,否则 DeviceSessions 会把它过滤掉。
			for _, sess := range c.sessions {
				sess["device_id"] = d.ID
			}
			var fc *fakeControl
			if c.noControl {
				routes := controlOK()
				routes["/status"] = func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, "boom", http.StatusInternalServerError)
				}
				fc = newFakeControl(t, routes)
			} else {
				fc = newFakeControl(t, deviceStatusRoutes(c.sessions))
			}
			s.control = fc.client

			w := postDeviceVerb(t, s, d.ID, "set-fixed-vip", url.Values{"fixed_vip_v4": {c.newV4}})
			if w.Code != http.StatusSeeOther {
				t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
			}
			if got := fc.sawPath("/kick"); got != c.wantKick {
				t.Fatalf("踢线=%v, 期望 %v; 控制面收到: %v", got, c.wantKick, fc.requests())
			}
			// 无论踢不踢,新值都必须落库。
			if got := mustGetDevice(t, s, d.ID); got.FixedVIPv4 != c.newV4 {
				t.Errorf("落库 v4=%q, 期望 %q", got.FixedVIPv4, c.newV4)
			}
		})
	}
}

// TestSetFixedVIP_ReturnToCannotLeaveSite:return_to 是用户可控字段,不能变成开放重定向。
//
// 攻击者把 return_to 塞成自家站点,管理员点完「绑定」就被送到钓鱼页 —— 而且是
// 从可信的后台点出去的,警惕性最低的时刻。
func TestSetFixedVIP_ReturnToCannotLeaveSite(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	deviceDetail := fmt.Sprintf("/devices/%d", d.ID)

	for _, c := range []struct{ name, returnTo, wantPrefix string }{
		{"绝对 URL 被拒", "https://evil.example.com/x", deviceDetail},
		{"协议无关 URL 被拒", "//evil.example.com/x", deviceDetail},
		{"反斜杠绕过被拒", "/\\evil.example.com", deviceDetail},
		{"空值回设备详情页", "", deviceDetail},
		{"站内路径被采纳", "/sessions", "/sessions"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := postDeviceVerb(t, s, d.ID, "set-fixed-vip", url.Values{
				"fixed_vip_v4": {"100.64.0.60"},
				"return_to":    {c.returnTo},
			})
			if w.Code != http.StatusSeeOther {
				t.Fatalf("code=%d, 期望 303", w.Code)
			}
			loc := w.Header().Get("Location")
			if !strings.HasPrefix(loc, c.wantPrefix) {
				t.Fatalf("Location=%q, 期望以 %q 开头", loc, c.wantPrefix)
			}
			// 兜底:任何情况下都不能跳出本站。
			if strings.Contains(loc, "evil.example.com") {
				t.Fatalf("Location 跳出了本站: %q", loc)
			}
		})
	}
}

// =========================================================================
// 设备的其它写动作
// =========================================================================

// TestDeviceSetAlias_WritesAndNotifies:别名只影响展示,但出口/子网列表要重算。
func TestDeviceSetAlias_WritesAndNotifies(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	fc := newFakeControl(t, controlOK())
	s.control = fc.client

	w := postDeviceVerb(t, s, d.ID, "set-alias", url.Values{"alias": {"  机房A-出口  "}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	// 前后空白必须裁掉:别名会出现在客户端的节点列表里,带空格的名字看着像坏数据。
	if got := mustGetDevice(t, s, d.ID); got.Alias != "机房A-出口" {
		t.Fatalf("别名 = %q, 期望 %q", got.Alias, "机房A-出口")
	}
	assertAuditAction(t, s, "device_set_alias")

	// 清空别名同样合法。
	w = postDeviceVerb(t, s, d.ID, "set-alias", url.Values{"alias": {""}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("清空别名 code=%d, 期望 303", w.Code)
	}
	if got := mustGetDevice(t, s, d.ID); got.Alias != "" {
		t.Fatalf("别名未被清空: %q", got.Alias)
	}
}

// TestDeviceDelete_RemovesAndNotifiesRoutes:删设备要顺带让 server 重建子网路由表。
//
// 不通知的话,被删设备宣告的网段在数据面快照里还留着,使用方继续往那儿发包 ——
// 黑洞。审计也必须留痕:删设备是不可逆操作。
func TestDeviceDelete_RemovesAndNotifiesRoutes(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	fc := newFakeControl(t, controlOK())
	s.control = fc.client

	w := postDeviceVerb(t, s, d.ID, "delete", nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	if _, err := s.store.GetDevice(t.Context(), d.ID); err == nil {
		t.Fatalf("设备还在库里")
	}
	assertAuditAction(t, s, "device_delete")
	if !waitForControlPath(t, fc, "/reload") {
		t.Fatalf("删设备后没通知数据面重建路由, 控制面收到: %v", fc.requests())
	}
}

// TestDeviceSetRate_BadInputDoesNotPersist:限速填错必须整条打回。
//
// 静默落 0 在限速语义里等于「不限速」—— 一次手滑就把限制取消了,而页面还显示成功。
func TestDeviceSetRate_BadInputDoesNotPersist(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	if err := s.store.SetDeviceRateLimit(t.Context(), d.ID, 1024, 2048); err != nil {
		t.Fatalf("SetDeviceRateLimit: %v", err)
	}

	for _, c := range []struct{ name, up, down string }{
		{"上行非数字", "abc", "10"},
		{"下行负数", "10", "-1"},
		{"上行带单位后缀", "10x", "10"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := postDeviceVerb(t, s, d.ID, "set-rate", url.Values{
				"rate_upload_mibs": {c.up}, "rate_download_mibs": {c.down},
			})
			if w.Code != http.StatusBadRequest {
				t.Fatalf("code=%d body=%q, 期望 400", w.Code, w.Body.String())
			}
			got := mustGetDevice(t, s, d.ID)
			if got.RateUploadBPS != 1024 || got.RateDownloadBPS != 2048 {
				t.Fatalf("非法输入改动了原值: up=%d down=%d", got.RateUploadBPS, got.RateDownloadBPS)
			}
		})
	}
}

// TestDeviceAction_BadInput:路径与动作词的边界。
func TestDeviceAction_BadInput(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")

	for _, c := range []struct {
		name   string
		target string
		want   int
	}{
		{"设备 ID 非数字", "/devices/abc/delete", http.StatusBadRequest},
		{"设备 ID 为 0", "/devices/0/delete", http.StatusBadRequest},
		{"设备 ID 为负", "/devices/-1/delete", http.StatusBadRequest},
		{"设备不存在", "/devices/999999/delete", http.StatusNotFound},
		{"未知动作词", fmt.Sprintf("/devices/%d/frobnicate", d.ID), http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleDeviceAction(w, newAdminPostRequest(t, c.target, nil))
			if w.Code != c.want {
				t.Fatalf("code=%d body=%q, 期望 %d", w.Code, w.Body.String(), c.want)
			}
		})
	}
	// 设备还在:上面这些请求都不该产生副作用。
	mustGetDevice(t, s, d.ID)
}

// TestDeviceAction_RejectsGET:写动作只认 POST。
//
// GET 可写等于一张图片标签就能删设备(CSRF 中间件也拦不住 GET)。
func TestDeviceAction_RejectsGET(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/devices/%d/delete", d.ID), nil)
	req = req.WithContext(newAdminPostRequest(t, "/x", nil).Context())
	w := httptest.NewRecorder()
	s.handleDeviceAction(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d, 期望 405", w.Code)
	}
	mustGetDevice(t, s, d.ID) // 没被删
}

// =========================================================================
// POST /leases/{device_id}/release
// =========================================================================

// TestLeaseRelease_DeletesAndAudits:释放租约 → 库里没了 + 审计留痕。
func TestLeaseRelease_DeletesAndAudits(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "100.64.0.80", "")

	w := httptest.NewRecorder()
	target := fmt.Sprintf("/leases/%d/release", d.ID)
	s.handleLeaseAction(w, newAdminPostRequest(t, target, nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, w.Body.String())
	}
	if _, err := s.store.GetLeaseByDevice(t.Context(), d.ID); err == nil {
		t.Fatalf("租约还在")
	}
	assertAuditAction(t, s, "lease_release")
}

// TestLeaseRelease_DoubleClickIsCleanNotFound:重复释放要给干净的 404。
//
// 陈旧列表页重提交、或者手快点两下 —— 第二次不该是 500 加一串裸 store 错误。
func TestLeaseRelease_DoubleClickIsCleanNotFound(t *testing.T) {
	s := newTestServerMinimal(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "100.64.0.81", "")
	target := fmt.Sprintf("/leases/%d/release", d.ID)

	w := httptest.NewRecorder()
	s.handleLeaseAction(w, newAdminPostRequest(t, target, nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("首次释放 code=%d, 期望 303", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleLeaseAction(w, newAdminPostRequest(t, target, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("重复释放 code=%d body=%q, 期望 404", w.Code, w.Body.String())
	}
}

// TestLeaseAction_BadInput:路径边界。
func TestLeaseAction_BadInput(t *testing.T) {
	s := newTestServerMinimal(t)

	for _, c := range []struct {
		name   string
		target string
		want   int
	}{
		{"缺动作词", "/leases/1", http.StatusBadRequest},
		{"设备 ID 非数字", "/leases/abc/release", http.StatusBadRequest},
		{"设备 ID 为 0", "/leases/0/release", http.StatusBadRequest},
		{"未知动作词", "/leases/1/obliterate", http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleLeaseAction(w, newAdminPostRequest(t, c.target, nil))
			if w.Code != c.want {
				t.Fatalf("code=%d body=%q, 期望 %d", w.Code, w.Body.String(), c.want)
			}
		})
	}
}
