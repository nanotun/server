package main

// handler_portforward_guards_test.go(第二十轮)—— /port-forwards 的读写失败侧
// 与页顶统计。
//
// 归属校验(防 SSRF)那条线在 handler_portforward_more_test.go 里已经钉死。这里补:
//
//   - 列表读不出来时不能渲染成「没有任何映射」。端口转发是把内网暴露到公网的开关,
//     管理员看到空表会以为没暴露过任何端口 —— 而实际上映射还在生效;
//   - 归属校验里那两次读(设备表、已有映射)失败时必须**拒绝创建**。这两处一旦
//     "读不到就当没冲突/当校验通过",就正好绕开了防 SSRF 与目标歧义两道闸;
//   - 写失败(创建 / 删除 / 启停)要报 500,且库里状态不许变;
//   - 页顶那四个统计格必须与运行态对得上:把 bind 失败的映射数成"监听中",
//     管理员就再也不会去看那条其实没生效的映射。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// pfStatusControl:让假控制面按给定运行态回 /portforward/status。
func pfStatusControl(t *testing.T, s *Server, items []map[string]any) *fakeControl {
	t.Helper()
	routes := controlOK()
	routes["/portforward/status"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"forwards": items})
	}
	fc := newFakeControl(t, routes)
	s.control = fc.client
	return fc
}

func pfListReq(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.handlePortForwardList(w, adminGetReq("/port-forwards"))
	return w
}

// -------------------------------------------------------------------------
// 列表读失败
// -------------------------------------------------------------------------

// 两张表任一读不出来都要报错。渲染成空表 = 告诉管理员「没有任何端口对外暴露」,
// 这个假象会直接影响他对当前暴露面的判断。
func TestPortForwardList_ReadFailuresAreNotAnEmptyList(t *testing.T) {
	t.Run("映射表读失败", func(t *testing.T) {
		s, _ := pfServer(t)
		dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
		makePF(t, s, dev, 9001)
		if _, err := s.store.DB().ExecContext(t.Context(),
			`UPDATE port_forwards SET created_at='not-a-number'`); err != nil {
			t.Fatalf("注入坏映射行: %v", err)
		}

		w := pfListReq(t, s)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if strings.Contains(w.Body.String(), "9001") {
			t.Fatal("出错页里还渲染了半截列表")
		}
	})

	t.Run("设备表读失败", func(t *testing.T) {
		s, _ := pfServer(t)
		dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
		makePF(t, s, dev, 9001)
		corruptDeviceRow(t, s, dev.ID)

		w := pfListReq(t, s)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
	})
}

// -------------------------------------------------------------------------
// 页顶统计
// -------------------------------------------------------------------------

// 四个统计格要与运行态一致。把 bind 失败的映射数成"监听中"最要命:那条映射其实
// 没在工作,而页面上一片正常,管理员根本不会想到去看它。
func TestPortForwardList_StatsReflectLiveState(t *testing.T) {
	s, _ := pfServer(t)
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	listening := makePF(t, s, dev, 9001)
	bindFailed := makePF(t, s, dev, 9002)
	degraded := makePF(t, s, dev, 9003)
	disabled := makePF(t, s, dev, 9004)
	unknown := makePF(t, s, dev, 9005) // server 没上报:既不算监听中也不算异常
	if err := s.store.SetPortForwardEnabled(t.Context(), disabled.ID, false); err != nil {
		t.Fatalf("SetPortForwardEnabled: %v", err)
	}
	pfStatusControl(t, s, []map[string]any{
		{"public_port": listening.PublicPort, "state": "listening"},
		{"public_port": bindFailed.PublicPort, "state": "bind_failed", "err": "端口已被占用"},
		{"public_port": degraded.PublicPort, "state": "route_degraded"},
		// 停用的那条即使 server 还报着 listening,也该算进「停用」而非「监听中」。
		{"public_port": disabled.PublicPort, "state": "listening"},
	})
	_ = unknown

	w := pfListReq(t, s)
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	body := w.Body.String()
	// 运行态的错误详情要能在页面上看到,否则「为什么没监听上」无从查起。
	if !strings.Contains(body, "端口已被占用") {
		t.Error("bind 失败的原因没露出来")
	}
	// 页顶四个统计格按 总数 / 监听中 / 异常 / 停用 的顺序渲染成
	// `<div class="value">N</div>`(见 port_forwards.html)。
	nums := pfStatValues(t, body)
	for i, want := range []int{5, 1, 2, 1} {
		names := []string{"总数", "监听中", "异常", "停用"}
		if nums[i] != want {
			t.Errorf("%s=%d, 期望 %d(全部统计: %v)", names[i], nums[i], want, nums)
		}
	}
}

// pfStatValues 从渲染结果里取出页顶四个统计数字。
func pfStatValues(t *testing.T, body string) []int {
	t.Helper()
	re := regexp.MustCompile(`<div class="value">(\d+)</div>`)
	ms := re.FindAllStringSubmatch(body, -1)
	if len(ms) < 4 {
		t.Fatalf("页面上只找到 %d 个统计数字,模板结构变了?", len(ms))
	}
	out := make([]int, 4)
	for i := 0; i < 4; i++ {
		n, err := strconv.Atoi(ms[i][1])
		if err != nil {
			t.Fatalf("统计数字 %q 解析失败: %v", ms[i][1], err)
		}
		out[i] = n
	}
	return out
}

// -------------------------------------------------------------------------
// 归属校验里的读失败必须 fail-closed
// -------------------------------------------------------------------------

// 设备表读不出来时不能放行:那两句归属校验(vIP / 已批准网段)全靠这张表,
// 读不到就"当校验通过"等于把防 SSRF 的闸门整个拿掉。
func TestValidatePortForwardInput_DeviceReadFailureRejects(t *testing.T) {
	s, _ := pfServer(t)
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	corruptDeviceRow(t, s, dev.ID)

	req := newAdminPostRequest(t, "/port-forwards/new", nil)
	msg := s.validatePortForwardInput(req, 9001, 8000, "10.66.0.5", dev.DeviceUUID)
	if msg == "" {
		t.Fatal("设备表读不出来却放行了(防 SSRF 的闸门被绕过)")
	}
}

// 已有映射读不出来时也不能放行:同一目标 IP 指向两台设备时数据面无法判断该投给谁,
// 这条歧义拦截读不到就"当没冲突",会造出一条永远行为不定的映射。
func TestCheckPortForwardTargetDeviceConflict_ReadFailureRejects(t *testing.T) {
	s, _ := pfServer(t)
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	makePF(t, s, dev, 9001)
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE port_forwards SET created_at='not-a-number'`); err != nil {
		t.Fatalf("注入坏映射行: %v", err)
	}

	req := newAdminPostRequest(t, "/port-forwards/new", nil)
	ip, err := netip.ParseAddr("10.66.0.5")
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if msg := s.checkPortForwardTargetDeviceConflict(req, ip, dev.DeviceUUID); msg == "" {
		t.Fatal("已有映射读不出来却当成没有冲突")
	}
}

// 库里存着一条 target_ip 解析不出来的旧映射(手改 / 历史数据)时,冲突预检要跳过它
// 继续检查其余行,而不是整体报错把新建路径堵死。
func TestCheckPortForwardTargetDeviceConflict_SkipsUnparsableRows(t *testing.T) {
	s, _ := pfServer(t)
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	pf := makePF(t, s, dev, 9001)
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE port_forwards SET target_ip='not-an-ip' WHERE id=?`, pf.ID); err != nil {
		t.Fatalf("弄坏 target_ip: %v", err)
	}

	req := newAdminPostRequest(t, "/port-forwards/new", nil)
	ip, _ := netip.ParseAddr("10.66.0.5")
	if msg := s.checkPortForwardTargetDeviceConflict(req, ip, "some-other-uuid"); msg != "" {
		t.Fatalf("坏行应被跳过,却报了冲突: %q", msg)
	}
}

// 宣告网段读不出来时,LAN 目标判定要返回 false(fail-closed):
// 读不到就"当在网段内"等于放开任意 LAN 地址。
func TestIPInApprovedAdvertisedSubnet_ReadFailureIsFalse(t *testing.T) {
	s, _ := pfServer(t)
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	approveRoute(t, s, dev.ID, "192.168.7.0/24", "approved")
	if _, err := s.store.DB().ExecContext(t.Context(),
		`UPDATE subnet_routes SET advertised_at='not-a-number' WHERE device_id=?`, dev.ID); err != nil {
		t.Fatalf("注入坏路由行: %v", err)
	}

	req := newAdminPostRequest(t, "/port-forwards/new", nil)
	ip, _ := netip.ParseAddr("192.168.7.9")
	if s.ipInApprovedAdvertisedSubnet(req, dev.ID, ip) {
		t.Fatal("路由表读不出来却判定为「在已批准网段内」")
	}
}

// -------------------------------------------------------------------------
// 写失败
// -------------------------------------------------------------------------

func TestPortForwardWrites_FailuresAreReportedNotSwallowed(t *testing.T) {
	t.Run("创建写不进去", func(t *testing.T) {
		s, fc := pfServer(t)
		dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
		abortSQLiteWrites(t, s, "no_pf_insert", "port_forwards", "INSERT", "")

		form := url.Values{
			"public_port": {"9001"}, "target_port": {"8000"},
			"target_ip": {"10.66.0.5"}, "device_uuid": {dev.DeviceUUID},
		}
		w := httptest.NewRecorder()
		s.handlePortForwardNew(w, newAdminPostRequest(t, "/port-forwards/new", form))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if n := pfCount(t, s); n != 0 {
			t.Fatalf("写失败却落库 %d 条", n)
		}
		if controlHits(fc, "/reload") != 0 {
			t.Fatal("没建成却通知了数据面重载")
		}
	})

	t.Run("删不动", func(t *testing.T) {
		s, _ := pfServer(t)
		me := createTestAdmin(t, s, "root", "pw-root-12345678")
		dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
		pf := makePF(t, s, dev, 9001)
		abortSQLiteWrites(t, s, "no_pf_delete", "port_forwards", "DELETE", "")

		w := postPFVerb(t, s, me, pf.ID, "delete")
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
		}
		if n := pfCount(t, s); n != 1 {
			t.Fatalf("删除失败后应还剩 1 条,实际 %d 条", n)
		}
	})

	for _, verb := range []string{"enable", "disable"} {
		t.Run(verb+" 改不动", func(t *testing.T) {
			s, _ := pfServer(t)
			me := createTestAdmin(t, s, "root", "pw-root-12345678")
			dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
			pf := makePF(t, s, dev, 9001)
			if verb == "enable" {
				if err := s.store.SetPortForwardEnabled(t.Context(), pf.ID, false); err != nil {
					t.Fatalf("前置停用: %v", err)
				}
			}
			abortSQLiteWrites(t, s, "no_pf_enable", "port_forwards", "UPDATE OF enabled", "")

			w := postPFVerb(t, s, me, pf.ID, verb)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("code=%d body=%q, 期望 500", w.Code, trimForLog(w.Body.String()))
			}
			got, err := s.store.GetPortForward(t.Context(), pf.ID)
			if err != nil {
				t.Fatalf("GetPortForward: %v", err)
			}
			wantEnabled := verb == "disable" // 改不动 → 保持原样
			if got.Enabled != wantEnabled {
				t.Fatalf("状态被改成了 enabled=%v, 应保持 %v", got.Enabled, wantEnabled)
			}
		})
	}

	// 启停一个已经消失的映射要给 404,而不是 500 —— 这是「对着陈旧页面点按钮」
	// 的常见情形,报 500 会让管理员以为系统坏了。
	t.Run("启停一个不存在的映射", func(t *testing.T) {
		s, _ := pfServer(t)
		me := createTestAdmin(t, s, "root", "pw-root-12345678")
		for _, verb := range []string{"enable", "disable"} {
			w := postPFVerb(t, s, me, 4242, verb)
			if w.Code != http.StatusNotFound {
				t.Errorf("%s: code=%d, 期望 404", verb, w.Code)
			}
		}
	})
}
