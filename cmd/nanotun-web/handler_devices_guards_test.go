package main

// handler_devices_guards_test.go(第十九轮)——/devices 与 /leases 的失败侧与
// 分支侧闸门。
//
// handler_devices_test.go 已经把固定 vIP 的冲突预检和踢线决策钉得很细。本文件补
// 三类此前没人看的地方:
//
//   1. 读失败:设备/租约列表读不出来时,绝不能渲染成「一台设备都没有」——
//      运维照着空列表做判断(以为客户端全掉线了)比看到报错糟得多;
//   2. 写失败:改别名 / 删设备 / 改限速 / 钉 IP 写不动时必须报错,
//      不能 303 + 「已保存」——页面上的值和库里的值从此对不上;
//   3. 分支:搜索过滤把整组隐藏、v6 方向的踢线判定、控制面拿不到限速配置时的
//      降级渲染、踢线失败的留痕。这些都只在特定输入下才走到。

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

// newDevicesGuardServer:带真实模板。渲染必须是真的 —— 本文件多处断言
// 「出错时页面上不能还留着半截数据」,不加载模板的话 renderPage 走 plain-text
// fallback,断言就失去意义(见 handler_users_guards_test.go 同款说明)。
func newDevicesGuardServer(t *testing.T) *Server {
	t.Helper()
	return newMeTestServer(t)
}

// corruptDeviceRow 把某台设备的 created_at 写成非数字:该行之后扫不出来,
// 库其余部分照常工作。用来只让「读这一行」失败。
func corruptDeviceRow(t *testing.T, s *Server, id int64) {
	t.Helper()
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE devices SET created_at='not-a-number' WHERE id=?`, id); err != nil {
		t.Fatalf("注入坏设备行: %v", err)
	}
}

// rateConfigRoutes:控制面 /rate/config 回一份限速配置。
func rateConfigRoutes(settingsUp, settingsDown, tomlUp, tomlDown int64) map[string]http.HandlerFunc {
	routes := controlOK()
	routes["/rate/config"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"settings_up_bps":   settingsUp,
			"settings_down_bps": settingsDown,
			"toml_up_bps":       tomlUp,
			"toml_down_bps":     tomlDown,
		})
	}
	return routes
}

func deviceGetReq(target string) *http.Request { return adminGetReq(target) }

// =========================================================================
// GET /devices
// =========================================================================

func TestDeviceList_RejectsNonGET(t *testing.T) {
	s := newDevicesGuardServer(t)
	w := httptest.NewRecorder()
	s.handleDeviceList(w, newAdminPostRequest(t, "/devices", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d, 期望 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "GET" {
		t.Fatalf("Allow=%q, 期望 GET", allow)
	}
}

// 用户表读不出来时要报错。渲染成空列表 = 告诉运维「没有任何设备」,
// 那是个会让人做出错误处置的假象。
func TestDeviceList_ReadFailureIsNotAnEmptyList(t *testing.T) {
	s := newDevicesGuardServer(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE users SET created_at='not-a-number' WHERE id=?`, d.UserID); err != nil {
		t.Fatalf("注入坏用户行: %v", err)
	}

	w := httptest.NewRecorder()
	s.handleDeviceList(w, deviceGetReq("/devices"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if strings.Contains(w.Body.String(), "alice") {
		t.Fatal("出错页里还渲染了半截列表")
	}
}

// ?q= 的三种命中方式必须都成立:命中用户名 → 该用户全部设备都留下;命中设备
// 字段 → 只留命中的那台;两边都不命中 → 整组从页面上消失(而不是留一个空壳分组)。
func TestDeviceList_SearchKeepsMatchesAndHidesEmptyGroups(t *testing.T) {
	s := newDevicesGuardServer(t)
	alice := devFixture(t, s, "alice", "aaaaaaaa-1111-4111-8111-111111111111", "", "")
	// alice 名下再挂一台**名字里不含 "alice"** 的设备:搜用户名时它也必须留下,
	// 这是「命中用户名 → 保留该用户全部设备」与「逐台过滤」的唯一区别所在。
	if _, err := s.store.UpsertDevice(t.Context(), alice.UserID,
		"cccccccc-3333-4333-8333-333333333333", "workstation", "linux"); err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	bob := devFixture(t, s, "bob", "bbbbbbbb-2222-4222-8222-222222222222", "", "")
	if err := s.store.SetDeviceAlias(t.Context(), bob.ID, "bob-phone"); err != nil {
		t.Fatalf("SetDeviceAlias: %v", err)
	}

	for _, tc := range []struct {
		name, q string
		want    []string
		absent  []string
	}{
		// 命中用户名:alice 的两台都留下,连名字与 q 无关的那台也在。
		{"命中用户名", "alice", []string{"alice-box", "workstation"}, []string{"bob"}},
		// 命中设备字段:同组里没命中的那台要被过滤掉。
		{"命中设备名", "workstation", []string{"workstation"}, []string{"alice-box", "bob"}},
		{"命中设备别名", "bob-phone", []string{"bob-phone"}, []string{"alice", "workstation"}},
		// 谁都不命中:两个分组整体消失,不留空壳。
		{"谁都不命中", "zzz-no-such-thing", nil, []string{"alice", "bob", "workstation"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.handleDeviceList(w, deviceGetReq("/devices?q="+url.QueryEscape(tc.q)))
			if w.Code != http.StatusOK {
				t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
			}
			body := w.Body.String()
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("搜 %q 没搜到 %q", tc.q, want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(body, absent) {
					t.Errorf("搜 %q 却把 %q 也列出来了", tc.q, absent)
				}
			}
		})
	}
}

// 控制面不可达时限速配置按零值降级,页面仍要渲染出来(设备自身的限速还是有用的
// 信息),只是标记控制面不可用。
func TestDeviceList_UnreachableControlStillRenders(t *testing.T) {
	s := newDevicesGuardServer(t)
	devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	fc := newFakeControl(t, map[string]http.HandlerFunc{})
	s.control = fc.client

	w := httptest.NewRecorder()
	s.handleDeviceList(w, deviceGetReq("/devices"))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q, 控制面不可达不该掀翻列表页", w.Code, trimForLog(w.Body.String()))
	}
}

// =========================================================================
// /devices/{id} 路由与读失败
// =========================================================================

func TestDeviceAction_PathAndMethodGuards(t *testing.T) {
	s := newDevicesGuardServer(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")

	t.Run("没带设备 id", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleDeviceAction(w, newAdminPostRequest(t, "/devices", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code=%d, 期望 400", w.Code)
		}
	})

	t.Run("详情页只收 GET", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleDeviceAction(w, newAdminPostRequest(t, fmt.Sprintf("/devices/%d", d.ID), nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code=%d, 期望 405", w.Code)
		}
	})

	t.Run("viewer 不能改设备", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleDeviceAction(w, viewerReq(http.MethodPost, fmt.Sprintf("/devices/%d/delete", d.ID)))
		if w.Code != http.StatusForbidden {
			t.Fatalf("code=%d, 期望 403", w.Code)
		}
		if _, err := s.store.GetDevice(t.Context(), d.ID); err != nil {
			t.Fatalf("viewer 把设备删了: %v", err)
		}
	})
}

// 设备行读不出来 ≠ 设备不存在。回 404 会让运维以为设备记录丢了。
func TestDeviceAction_ReadFailureIsNotMistakenFor404(t *testing.T) {
	s := newDevicesGuardServer(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	corruptDeviceRow(t, s, d.ID)

	w := httptest.NewRecorder()
	s.handleDeviceAction(w, deviceGetReq(fmt.Sprintf("/devices/%d", d.ID)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
}

// 详情页要把四层限速(设备 / settings / toml / 用户)都算出来给运维看。控制面
// 能拿到时用真实值,拿不到时按零值降级并标记 —— 后者不能悄悄显示成「不限速」。
func TestDeviceDetail_RendersEffectiveRateWithAndWithoutControl(t *testing.T) {
	const oneMiB = 1 << 20
	for _, tc := range []struct {
		name       string
		routes     map[string]http.HandlerFunc
		wantSubstr string
	}{
		{"控制面给出 settings cap", rateConfigRoutes(2*oneMiB, 2*oneMiB, 8*oneMiB, 8*oneMiB), "2"},
		{"控制面不可达", map[string]http.HandlerFunc{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDevicesGuardServer(t)
			d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "100.64.0.9", "")
			if err := s.store.SetDeviceRateLimit(t.Context(), d.ID, 4*oneMiB, 4*oneMiB); err != nil {
				t.Fatalf("SetDeviceRateLimit: %v", err)
			}
			fc := newFakeControl(t, tc.routes)
			s.control = fc.client

			w := httptest.NewRecorder()
			s.handleDeviceAction(w, deviceGetReq(fmt.Sprintf("/devices/%d", d.ID)))
			if w.Code != http.StatusOK {
				t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
			}
			if tc.wantSubstr != "" && !strings.Contains(w.Body.String(), tc.wantSubstr) {
				t.Errorf("详情页没体现 settings cap")
			}
		})
	}
}

// =========================================================================
// 写失败
// =========================================================================

// 写不动就得说写不动:页面报「已保存」而库里没变,是最难查的一类偏差 ——
// 运维会围着一个从未生效的配置反复排查。
func TestDeviceWrites_FailuresAreReportedNotSwallowed(t *testing.T) {
	cases := []struct {
		name  string
		op    string
		verb  string
		form  url.Values
		check func(t *testing.T, s *Server, d *store.Device)
	}{
		{
			name: "改别名", op: "UPDATE OF alias", verb: "set-alias",
			form: url.Values{"alias": {"new-name"}},
			check: func(t *testing.T, s *Server, d *store.Device) {
				if got := mustGetDevice(t, s, d.ID).Alias; got == "new-name" {
					t.Fatal("报错却把别名改了")
				}
			},
		},
		{
			name: "删设备", op: "DELETE", verb: "delete",
			check: func(t *testing.T, s *Server, d *store.Device) {
				if _, err := s.store.GetDevice(t.Context(), d.ID); err != nil {
					t.Fatalf("报错却把设备删了: %v", err)
				}
			},
		},
		{
			name: "改限速", op: "UPDATE OF rate_upload_bps", verb: "set-rate",
			form: url.Values{"rate_upload_mibs": {"2"}, "rate_download_mibs": {"2"}},
			check: func(t *testing.T, s *Server, d *store.Device) {
				if got := mustGetDevice(t, s, d.ID).RateUploadBPS; got != 0 {
					t.Fatalf("报错却把限速改成了 %d", got)
				}
			},
		},
		{
			name: "钉固定 IP", op: "UPDATE OF fixed_vip_v4", verb: "set-fixed-vip",
			form: url.Values{"fixed_vip_v4": {"100.64.0.77"}},
			check: func(t *testing.T, s *Server, d *store.Device) {
				if got := mustGetDevice(t, s, d.ID).FixedVIPv4; got != "" {
					t.Fatalf("报错却把固定 IP 钉成了 %q", got)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newDevicesGuardServer(t)
			d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
			abortSQLiteWrites(t, s, "no_device_write", "devices", tc.op, "")

			w := postDeviceVerb(t, s, d.ID, tc.verb, tc.form)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
			}
			if strings.Contains(w.Body.String(), "no_device_write") {
				t.Fatalf("内部错误细节泄漏: %q", trimForLog(w.Body.String()))
			}
			tc.check(t, s, d)
		})
	}
}

// 改限速的成功路径:落库 + 审计留下新旧值 + 立刻热更到在线连接(不需要客户端重连)。
func TestDeviceSetRate_PersistsAuditsAndPushes(t *testing.T) {
	s := newDevicesGuardServer(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	fc := newFakeControl(t, controlOK())
	s.control = fc.client

	w := postDeviceVerb(t, s, d.ID, "set-rate", url.Values{
		"rate_upload_mibs": {"1.5"}, "rate_download_mibs": {"3"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
	}
	got := mustGetDevice(t, s, d.ID)
	if got.RateUploadBPS != int64(1.5*(1<<20)) || got.RateDownloadBPS != 3*(1<<20) {
		t.Fatalf("落库 up=%d down=%d", got.RateUploadBPS, got.RateDownloadBPS)
	}
	assertAuditAction(t, s, "device_rate_set")
	// 不推给数据面的话,限速要等客户端下次重连才生效 —— 页面却已经说改好了。
	if !waitForControlPath(t, fc, "/rate/refresh") {
		t.Fatalf("改完限速没热更到数据面, 控制面收到: %v", fc.requests())
	}
}

// 冲突预检自己读不动库时,必须报错而不是「查不到冲突就放行」——后者会让两台
// 设备钉同一个 IP,DB 唯一索引兜底时报出来的是 500,现场更难判断。
func TestSetFixedVIP_ConflictCheckFailureBlocksTheWrite(t *testing.T) {
	for _, tc := range []struct{ name, field, value string }{
		{"v4", "fixed_vip_v4", "100.64.0.88"},
		{"v6", "fixed_vip_v6", "fd00::88"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDevicesGuardServer(t)
			me := devFixture(t, s, "alice", "aaaaaaaa-1111-4111-8111-111111111111", "", "")
			other := devFixture(t, s, "bob", "bbbbbbbb-2222-4222-8222-222222222222", "", "")
			// 让预检扫全表时撞上一行坏数据。
			corruptDeviceRow(t, s, other.ID)

			w := postDeviceVerb(t, s, me.ID, "set-fixed-vip", url.Values{tc.field: {tc.value}})
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
			}
			if d := mustGetDevice(t, s, me.ID); d.FixedVIPv4 != "" || d.FixedVIPv6 != "" {
				t.Fatalf("预检没跑完却把地址钉上去了: %+v", d)
			}
		})
	}
}

// 预检扫到某台设备的租约行坏掉时同样要报错 —— 「读不到租约」不等于「这个地址没人用」。
func TestCheckFixedVIPConflict_BrokenLeaseRowIsAnError(t *testing.T) {
	s := newDevicesGuardServer(t)
	me := devFixture(t, s, "alice", "aaaaaaaa-1111-4111-8111-111111111111", "", "")
	other := devFixture(t, s, "bob", "bbbbbbbb-2222-4222-8222-222222222222", "100.64.0.31", "")
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE leases SET assigned_at='not-a-number' WHERE device_id=?`, other.ID); err != nil {
		t.Fatalf("注入坏租约行: %v", err)
	}

	got, err := s.checkFixedVIPConflict(t.Context(), "100.64.0.31", me.ID)
	if err == nil {
		t.Fatalf("租约读不出来却报告无冲突(conflict=%q)", got)
	}
}

// v6 方向的踢线判定:两族都钉了,而在线会话只对上 v4 时必须踢 —— 否则客户端的
// v6 地址会一直停在旧值,页面显示的却是新值。
func TestSetFixedVIP_V6MismatchAlsoKicks(t *testing.T) {
	const devUUID = "11111111-1111-4111-8111-111111111111"
	for _, tc := range []struct {
		name     string
		vips     []string
		wantKick bool
	}{
		{"两族都对上则不踢", []string{"100.64.0.50", "fd00::50"}, false},
		{"只对上 v4 也要踢", []string{"100.64.0.50"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDevicesGuardServer(t)
			d := devFixture(t, s, "alice", devUUID, "", "")
			fc := newFakeControl(t, deviceStatusRoutes([]map[string]any{
				{"conn_id": "c1", "device_id": d.ID, "vips": tc.vips},
			}))
			s.control = fc.client

			w := postDeviceVerb(t, s, d.ID, "set-fixed-vip", url.Values{
				"fixed_vip_v4": {"100.64.0.50"}, "fixed_vip_v6": {"fd00::50"},
			})
			if w.Code != http.StatusSeeOther {
				t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
			}
			if got := fc.sawPath("/kick"); got != tc.wantKick {
				t.Fatalf("踢线=%v 期望 %v;控制面收到 %v", got, tc.wantKick, fc.requests())
			}
		})
	}
}

// 该踢却踢不动时:地址已经落库了(不能回滚,否则页面上的值又和库不一致),
// 但必须留审计 + 把横幅换成「已保存但踢线失败」,否则运维以为客户端已经换好 IP 了。
func TestSetFixedVIP_KickFailureIsAuditedAndFlagged(t *testing.T) {
	s := newDevicesGuardServer(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "", "")
	routes := deviceStatusRoutes([]map[string]any{
		{"conn_id": "c1", "device_id": d.ID, "vips": []string{"100.64.0.99"}},
	})
	routes["/kick"] = func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}
	fc := newFakeControl(t, routes)
	s.control = fc.client

	w := postDeviceVerb(t, s, d.ID, "set-fixed-vip", url.Values{"fixed_vip_v4": {"100.64.0.50"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q, 期望 303", w.Code, trimForLog(w.Body.String()))
	}
	if got := mustGetDevice(t, s, d.ID).FixedVIPv4; got != "100.64.0.50" {
		t.Fatalf("落库 v4=%q", got)
	}
	assertAuditAction(t, s, "device_set_fixed_vip_kick_fail")
	probe := httptest.NewRequest(http.MethodGet, "/devices", nil)
	if want := tr(probe, "flash.fixedVipUpdatedKickFailed"); flashTextOf(t,
		w.Header().Get("Location")) != want {
		t.Fatalf("横幅=%q, 期望 %q", flashTextOf(t, w.Header().Get("Location")), want)
	}
}

// =========================================================================
// /leases
// =========================================================================

func TestLeaseList_RejectsNonGET(t *testing.T) {
	s := newDevicesGuardServer(t)
	w := httptest.NewRecorder()
	s.handleLeaseList(w, newAdminPostRequest(t, "/leases", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code=%d, 期望 405", w.Code)
	}
}

// 租约页是运维排查「谁占了这个 IP」的入口。读失败必须报错 —— 空表会让人
// 得出「这个地址没人用」的相反结论。
func TestLeaseList_ReadFailuresAreReported(t *testing.T) {
	t.Run("查询失败", func(t *testing.T) {
		s := newDevicesGuardServer(t)
		devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "100.64.0.9", "")
		if _, err := s.store.DB().ExecContext(t.Context(),
			`ALTER TABLE leases RENAME TO leases_moved`); err != nil {
			t.Fatalf("改表名: %v", err)
		}

		w := httptest.NewRecorder()
		s.handleLeaseList(w, deviceGetReq("/leases"))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
	})

	t.Run("逐行扫描失败", func(t *testing.T) {
		s := newDevicesGuardServer(t)
		d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "100.64.0.9", "")
		if _, err := s.store.DB().ExecContext(t.Context(),
			`UPDATE leases SET assigned_at='not-a-number' WHERE device_id=?`, d.ID); err != nil {
			t.Fatalf("注入坏租约行: %v", err)
		}

		w := httptest.NewRecorder()
		s.handleLeaseList(w, deviceGetReq("/leases"))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if strings.Contains(w.Body.String(), "100.64.0.9") {
			t.Fatal("出错页里还渲染了半截租约")
		}
	})
}

func TestLeaseAction_MethodAndRoleGuards(t *testing.T) {
	s := newDevicesGuardServer(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "100.64.0.9", "")
	target := fmt.Sprintf("/leases/%d/release", d.ID)

	t.Run("GET 不能释放租约", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleLeaseAction(w, deviceGetReq(target))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("code=%d, 期望 405", w.Code)
		}
	})

	t.Run("viewer 不能释放租约", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleLeaseAction(w, viewerReq(http.MethodPost, target))
		if w.Code != http.StatusForbidden {
			t.Fatalf("code=%d, 期望 403", w.Code)
		}
	})

	// 两种拒绝之后租约都得还在。
	if _, err := s.store.GetLeaseByDevice(t.Context(), d.ID); err != nil {
		t.Fatalf("租约被释放了: %v", err)
	}
}

func TestLeaseRelease_WriteFailureIsReported(t *testing.T) {
	s := newDevicesGuardServer(t)
	d := devFixture(t, s, "alice", "11111111-1111-4111-8111-111111111111", "100.64.0.9", "")
	abortSQLiteWrites(t, s, "no_lease_delete", "leases", "DELETE", "")

	w := httptest.NewRecorder()
	s.handleLeaseAction(w, newAdminPostRequest(t, fmt.Sprintf("/leases/%d/release", d.ID), nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
	}
	if _, err := s.store.GetLeaseByDevice(t.Context(), d.ID); err != nil {
		t.Fatalf("报错却把租约释放了: %v", err)
	}
}
