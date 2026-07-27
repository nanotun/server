package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nanotun/server/store"
)

// 本文件覆盖 /port-forwards —— 把 mesh 里的服务发布到公网端口。
// 与 handler_portforward_test.go 分工:那边是入参校验的基础表格,这边补
// 两块它没碰的 —— 归属校验的边界情形,以及三条写路径(new / enable / disable / delete)。
//
// 这是整个控制台上「把内网暴露出去」唯一的开关,校验一旦松掉就是一个现成的 SSRF:
// target_ip 若不做归属校验,管理员(或拿到管理员会话的人)可以把任意公网/内网地址
// 填进去,让 server 用**自己的**出口去连 —— 云上元数据地址 169.254.169.254 首当其冲。
//
// 闸门是 validatePortForwardInput 里那两句:target_ip 要么等于该设备的 vIP,
// 要么落在该设备**已批准**的宣告网段内。下面把这条线的每个缺口都摆出来测:
// 未批准的网段、被当作出口用的默认路由 0.0.0.0/0、以及同一 IP 指向不同设备的歧义。

// pfServer 造一个带模板 + 假控制面的 Server。
func pfServer(t *testing.T) (*Server, *fakeControl) {
	t.Helper()
	s := newMeTestServer(t)
	routes := controlOK()
	routes["/portforward/status"] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}
	fc := newFakeControl(t, routes)
	s.control = fc.client
	return s, fc
}

// controlHits 数某个路径被打了几次(sawPath 只回布尔,这里要看次数)。
func controlHits(fc *fakeControl, path string) int {
	n := 0
	for _, r := range fc.requests() {
		if strings.Contains(r, " "+path) {
			n++
		}
	}
	return n
}

// waitForControlHits 等到某路径至少被打了 want 次。通知是后台 goroutine 发的,
// handler 返回时可能一次都还没到。
func waitForControlHits(t *testing.T, fc *fakeControl, path string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if controlHits(fc, path) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s 只收到 %d 次, 期望 >=%d", path, controlHits(fc, path), want)
}

// approveRoute 让设备宣告一个网段并标记为已批准。
func approveRoute(t *testing.T, s *Server, deviceID int64, cidr, status string) {
	t.Helper()
	if _, err := s.store.UpsertAdvertisedRoute(t.Context(), deviceID, cidr); err != nil {
		t.Fatalf("UpsertAdvertisedRoute %s: %v", cidr, err)
	}
	if status != store.RouteStatusPending {
		if err := s.store.SetRouteStatus(t.Context(), deviceID, cidr, status, "test"); err != nil {
			t.Fatalf("SetRouteStatus %s=%s: %v", cidr, status, err)
		}
	}
}

func pfCount(t *testing.T, s *Server) int {
	t.Helper()
	l, err := s.store.ListPortForwards(t.Context())
	if err != nil {
		t.Fatalf("ListPortForwards: %v", err)
	}
	return len(l)
}

// -------------------------------------------------------------------------
// 目标归属校验(防 SSRF)
// -------------------------------------------------------------------------

func TestValidatePortForwardInput_TargetMustBelongToTheDevice(t *testing.T) {
	s, _ := pfServer(t)
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "fd66::5")
	approveRoute(t, s, dev.ID, "192.168.7.0/24", store.RouteStatusApproved)
	approveRoute(t, s, dev.ID, "172.20.0.0/16", store.RouteStatusPending)
	approveRoute(t, s, dev.ID, "0.0.0.0/0", store.RouteStatusApproved)
	// 另一台设备只钉固定 vIP、不发租约 —— 固定 vIP 会把租约一起改写,
	// 放在同一台上会把「租约地址仍然可用」这条盖掉。
	pinned := devFixture(t, s, "pin", "uuid-pin", "", "")
	setFixedVIP(t, s, pinned.ID, "10.66.0.99", "")

	req := httptest.NewRequest(http.MethodPost, "/port-forwards/new", nil)
	if msg := s.validatePortForwardInput(req, 9001, 80, "10.66.0.99",
		mustGetDevice(t, s, pinned.ID).DeviceUUID); msg != "" {
		t.Errorf("固定 vIP 被拒: %q", msg)
	}

	cases := []struct {
		name   string
		ip     string
		wantOK bool
	}{
		{"设备当前租约 v4", "10.66.0.5", true},
		{"设备当前租约 v6", "fd66::5", true},
		{"已批准网段内的 LAN 地址", "192.168.7.10", true},
		{"已批准网段的网络地址", "192.168.7.0", true},
		{"已批准网段外一格", "192.168.8.10", false},
		{"仅宣告未批准的网段", "172.20.3.4", false},
		{"别的设备的固定 vIP", "10.66.0.99", false},
		{"云元数据地址", "169.254.169.254", false},
		{"公网地址", "1.1.1.1", false},
		{"回环", "127.0.0.1", false},
	}
	for _, tc := range cases {
		msg := s.validatePortForwardInput(req, 9001, 80, tc.ip, dev.DeviceUUID)
		if gotOK := msg == ""; gotOK != tc.wantOK {
			t.Errorf("%s (%s): 通过=%v, 期望 %v (msg=%q)", tc.name, tc.ip, gotOK, tc.wantOK, msg)
		}
	}
}

func TestValidatePortForwardInput_DefaultRouteIsNotALANSubnet(t *testing.T) {
	s, _ := pfServer(t)
	dev := devFixture(t, s, "exit", "uuid-exit", "10.66.0.7", "")
	// 出口节点宣告的是 0.0.0.0/0 并且已批准。若把它当作「已批准网段」,
	// 那全互联网都落在里面 —— 端口转发的目标校验等于没有。
	approveRoute(t, s, dev.ID, "0.0.0.0/0", store.RouteStatusApproved)
	approveRoute(t, s, dev.ID, "::/0", store.RouteStatusApproved)

	req := httptest.NewRequest(http.MethodPost, "/port-forwards/new", nil)
	for _, ip := range []string{"8.8.8.8", "169.254.169.254", "10.0.0.1", "2001:4860:4860::8888"} {
		if msg := s.validatePortForwardInput(req, 9001, 80, ip, dev.DeviceUUID); msg == "" {
			t.Errorf("target=%s 借默认路由通过了校验", ip)
		}
	}
	// 而节点自身的 vIP 仍然可以转发。
	if msg := s.validatePortForwardInput(req, 9001, 80, "10.66.0.7", dev.DeviceUUID); msg != "" {
		t.Errorf("节点自身 vIP 被拒: %q", msg)
	}
}

func TestValidatePortForwardInput_SameIPCannotPointAtTwoDevices(t *testing.T) {
	s, _ := pfServer(t)
	a := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	b := devFixture(t, s, "bob", "uuid-bob", "10.66.0.6", "")
	approveRoute(t, s, a.ID, "192.168.7.0/24", store.RouteStatusApproved)
	approveRoute(t, s, b.ID, "192.168.7.0/24", store.RouteStatusApproved)

	if _, err := s.store.CreatePortForward(t.Context(), store.PortForward{
		PublicPort: 9001, Proto: "tcp", TargetDeviceUUID: a.DeviceUUID,
		TargetIP: "192.168.7.10", TargetPort: 80, Enabled: true,
	}); err != nil {
		t.Fatalf("CreatePortForward: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/port-forwards/new", nil)
	// 数据面按目的 IP 精确路由,同一个 IP 指向两台设备时无从判断该投给谁。
	if msg := s.validatePortForwardInput(req, 9002, 80, "192.168.7.10", b.DeviceUUID); msg == "" {
		t.Fatal("同一 target_ip 指向了另一台设备却通过了")
	}
	// 同 IP 同设备、不同端口是正常用法(一台机器上多个服务)。
	if msg := s.validatePortForwardInput(req, 9002, 443, "192.168.7.10", a.DeviceUUID); msg != "" {
		t.Fatalf("同设备不同端口被拒: %q", msg)
	}
}

func TestValidatePortForwardInput_V4InV6DoesNotDodgeConflictCheck(t *testing.T) {
	s, _ := pfServer(t)
	a := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	b := devFixture(t, s, "bob", "uuid-bob", "10.66.0.6", "")
	approveRoute(t, s, a.ID, "192.168.7.0/24", store.RouteStatusApproved)
	approveRoute(t, s, b.ID, "192.168.7.0/24", store.RouteStatusApproved)
	// 已有映射存的是 v4-in-v6 写法。这种数据不是 Web 表单能造出来的(4in6 过不了
	// 归属校验),但 CLI、迁移脚本、老版本留下的行都可能长这样。
	if _, err := s.store.CreatePortForward(t.Context(), store.PortForward{
		PublicPort: 9001, Proto: "tcp", TargetDeviceUUID: a.DeviceUUID,
		TargetIP: "::ffff:192.168.7.10", TargetPort: 80, Enabled: true,
	}); err != nil {
		t.Fatalf("CreatePortForward: %v", err)
	}

	// ::ffff:192.168.7.10 与 192.168.7.10 是同一个地址的两种写法,数据面按归一化后的
	// key 建表。冲突检测若按字符串比,这条新映射会被放行,然后两条规则在数据面抢同一个
	// 目的 IP —— 投给哪台设备变成看谁先写进 map。
	req := httptest.NewRequest(http.MethodPost, "/port-forwards/new", nil)
	if msg := s.validatePortForwardInput(req, 9002, 80, "192.168.7.10", b.DeviceUUID); msg == "" {
		t.Fatal("库里存的是 4in6 写法时,同 IP 歧义拦截被绕过了")
	}
	// 同设备仍然允许(不同端口发布同一台机器上的多个服务)。
	if msg := s.validatePortForwardInput(req, 9002, 443, "192.168.7.10", a.DeviceUUID); msg != "" {
		t.Fatalf("同设备不同端口被拒: %q", msg)
	}
}

func TestValidatePortForwardInput_PortsAndDevice(t *testing.T) {
	s, _ := pfServer(t)
	s.cfg.ListenAddr = "0.0.0.0:7443"
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	req := httptest.NewRequest(http.MethodPost, "/port-forwards/new", nil)

	cases := []struct {
		name     string
		pub, tgt int
		ip, uuid string
		wantOK   bool
	}{
		{"公网端口为 0", 0, 80, "10.66.0.5", dev.DeviceUUID, false},
		{"公网端口越界", 65536, 80, "10.66.0.5", dev.DeviceUUID, false},
		{"公网端口为负", -1, 80, "10.66.0.5", dev.DeviceUUID, false},
		{"目标端口为 0", 9001, 0, "10.66.0.5", dev.DeviceUUID, false},
		{"目标端口越界", 9001, 70000, "10.66.0.5", dev.DeviceUUID, false},
		{"占用 SSH", 22, 80, "10.66.0.5", dev.DeviceUUID, false},
		{"占用 DNS", 53, 80, "10.66.0.5", dev.DeviceUUID, false},
		{"占用 HTTPS", 443, 80, "10.66.0.5", dev.DeviceUUID, false},
		{"占用数据面 8443", 8443, 80, "10.66.0.5", dev.DeviceUUID, false},
		{"占用 web 自身端口", 7443, 80, "10.66.0.5", dev.DeviceUUID, false},
		{"目标 IP 非法", 9001, 80, "not-an-ip", dev.DeviceUUID, false},
		{"目标 IP 为空", 9001, 80, "", dev.DeviceUUID, false},
		{"没选设备", 9001, 80, "10.66.0.5", "", false},
		{"设备不存在", 9001, 80, "10.66.0.5", "uuid-ghost", false},
		{"边界端口 65535", 65535, 65535, "10.66.0.5", dev.DeviceUUID, true},
		{"正常", 9001, 80, "10.66.0.5", dev.DeviceUUID, true},
	}
	for _, tc := range cases {
		msg := s.validatePortForwardInput(req, tc.pub, tc.tgt, tc.ip, tc.uuid)
		if gotOK := msg == ""; gotOK != tc.wantOK {
			t.Errorf("%s: 通过=%v, 期望 %v (msg=%q)", tc.name, gotOK, tc.wantOK, msg)
		}
	}
}

func TestValidatePortForwardInput_DeviceUUIDIsCaseInsensitive(t *testing.T) {
	s, _ := pfServer(t)
	dev := devFixture(t, s, "alice", "UUID-MiXeD", "10.66.0.5", "")
	req := httptest.NewRequest(http.MethodPost, "/port-forwards/new", nil)
	// handler 把表单里的 uuid 转成小写再传进来,设备表里存的却可能是原始大小写。
	if msg := s.validatePortForwardInput(req, 9001, 80, "10.66.0.5",
		strings.ToLower(dev.DeviceUUID)); msg != "" {
		t.Fatalf("小写 uuid 匹配不上设备: %q", msg)
	}
}

func TestListenPort(t *testing.T) {
	s := newMeTestServer(t)
	for _, tc := range []struct {
		addr string
		want int
	}{
		{"0.0.0.0:7443", 7443},
		{"127.0.0.1:8080", 8080},
		{"[::1]:9000", 9000},
		{":7443", 7443},
		{"nonsense", 0},
		{"", 0},
		{"0.0.0.0:abc", 0},
	} {
		s.cfg.ListenAddr = tc.addr
		if got := s.listenPort(); got != tc.want {
			t.Errorf("listenPort(%q)=%d, 期望 %d", tc.addr, got, tc.want)
		}
	}
}

// -------------------------------------------------------------------------
// 写路径
// -------------------------------------------------------------------------

func postPFNew(t *testing.T, s *Server, me *store.WebAdmin, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/port-forwards/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.handlePortForwardNew(w, withAdminCtx(req, me))
	return w
}

func TestPortForwardNew_CreatesAuditsAndReloads(t *testing.T) {
	s, fc := pfServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")

	w := postPFNew(t, s, me, url.Values{
		"public_port": {"9001"}, "target_port": {"8000"},
		"target_ip": {"10.66.0.5"}, "device_uuid": {dev.DeviceUUID},
		"comment": {"内部看板"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	list, err := s.store.ListPortForwards(t.Context())
	if err != nil || len(list) != 1 {
		t.Fatalf("落库失败: err=%v n=%d", err, len(list))
	}
	got := list[0]
	if got.PublicPort != 9001 || got.TargetPort != 8000 || got.TargetIP != "10.66.0.5" {
		t.Fatalf("落库内容不对: %+v", got)
	}
	if !got.Enabled {
		t.Error("新建的映射应当默认启用")
	}
	if got.Comment != "内部看板" {
		t.Errorf("comment=%q", got.Comment)
	}
	assertAuditAction(t, s, "port_forward_create")
	// 不通知 server 的话,页面上显示已生效、实际端口没起来。
	waitForControlPath(t, fc, "/reload")
}

func TestPortForwardNew_DuplicatePublicPortIsConflict(t *testing.T) {
	s, _ := pfServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	form := url.Values{
		"public_port": {"9001"}, "target_port": {"8000"},
		"target_ip": {"10.66.0.5"}, "device_uuid": {dev.DeviceUUID},
	}
	if w := postPFNew(t, s, me, form); w.Code != http.StatusSeeOther {
		t.Fatalf("第一次 code=%d", w.Code)
	}
	// 同一个公网端口只能有一条映射,否则两个监听抢同一个端口,起来哪个看运气。
	w := postPFNew(t, s, me, form)
	if w.Code != http.StatusConflict {
		t.Fatalf("重复端口 code=%d, 期望 409", w.Code)
	}
	if n := pfCount(t, s); n != 1 {
		t.Fatalf("映射数=%d, 期望 1", n)
	}
}

func TestPortForwardNew_BadInputCreatesNothing(t *testing.T) {
	s, fc := pfServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")

	cases := []struct {
		name string
		form url.Values
	}{
		{"端口不是数字", url.Values{
			"public_port": {"九千"}, "target_port": {"8000"},
			"target_ip": {"10.66.0.5"}, "device_uuid": {dev.DeviceUUID}}},
		{"端口科学计数法", url.Values{
			"public_port": {"9e3"}, "target_port": {"8000"},
			"target_ip": {"10.66.0.5"}, "device_uuid": {dev.DeviceUUID}}},
		{"占用保留端口", url.Values{
			"public_port": {"22"}, "target_port": {"8000"},
			"target_ip": {"10.66.0.5"}, "device_uuid": {dev.DeviceUUID}}},
		{"目标不属于该设备", url.Values{
			"public_port": {"9001"}, "target_port": {"8000"},
			"target_ip": {"169.254.169.254"}, "device_uuid": {dev.DeviceUUID}}},
		{"设备不存在", url.Values{
			"public_port": {"9001"}, "target_port": {"8000"},
			"target_ip": {"10.66.0.5"}, "device_uuid": {"uuid-ghost"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := postPFNew(t, s, me, tc.form)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("code=%d, 期望 400", w.Code)
			}
		})
	}
	if n := pfCount(t, s); n != 0 {
		t.Fatalf("坏输入建出了 %d 条映射", n)
	}
	// 什么都没改,不该去打扰 server。
	if controlHits(fc, "/reload") != 0 {
		t.Fatalf("失败路径也触发了 reload(%d 次)", controlHits(fc, "/reload"))
	}
}

func TestPortForwardNew_ViewerAndMethodGates(t *testing.T) {
	s, _ := pfServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	viewer := createTestAdmin(t, s, "peeker", "pw-peeker-12345")
	if err := s.store.SetWebAdminRoleEnsuringAdmin(t.Context(), viewer.ID, "viewer"); err != nil {
		t.Fatalf("降级: %v", err)
	}
	viewer = mustGetAdmin(t, s, viewer.ID)
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	form := url.Values{
		"public_port": {"9001"}, "target_port": {"8000"},
		"target_ip": {"10.66.0.5"}, "device_uuid": {dev.DeviceUUID},
	}

	if w := postPFNew(t, s, viewer, form); w.Code != http.StatusForbidden {
		t.Fatalf("viewer code=%d, 期望 403", w.Code)
	}
	w := httptest.NewRecorder()
	s.handlePortForwardNew(w, withAdminCtx(
		httptest.NewRequest(http.MethodGet, "/port-forwards/new", nil), me))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET code=%d, 期望 405", w.Code)
	}
	if n := pfCount(t, s); n != 0 {
		t.Fatalf("建出了 %d 条映射", n)
	}
}

func makePF(t *testing.T, s *Server, dev *store.Device, port int) *store.PortForward {
	t.Helper()
	pf, err := s.store.CreatePortForward(t.Context(), store.PortForward{
		PublicPort: port, Proto: "tcp", TargetDeviceUUID: dev.DeviceUUID,
		TargetIP: "10.66.0.5", TargetPort: 8000, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreatePortForward: %v", err)
	}
	return pf
}

func postPFVerb(t *testing.T, s *Server, me *store.WebAdmin, id int64, verb string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/port-forwards/"+itoa(id)+"/"+verb, nil)
	w := httptest.NewRecorder()
	s.handlePortForwardAction(w, withAdminCtx(req, me))
	return w
}

func TestPortForwardAction_EnableDisableDelete(t *testing.T) {
	s, fc := pfServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	pf := makePF(t, s, dev, 9001)

	if w := postPFVerb(t, s, me, pf.ID, "disable"); w.Code != http.StatusSeeOther {
		t.Fatalf("disable code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if got, _ := s.store.GetPortForward(t.Context(), pf.ID); got.Enabled {
		t.Fatal("disable 之后仍是启用")
	}
	assertAuditAction(t, s, "port_forward_disable")

	if w := postPFVerb(t, s, me, pf.ID, "enable"); w.Code != http.StatusSeeOther {
		t.Fatalf("enable code=%d", w.Code)
	}
	if got, _ := s.store.GetPortForward(t.Context(), pf.ID); !got.Enabled {
		t.Fatal("enable 之后仍是停用")
	}
	assertAuditAction(t, s, "port_forward_enable")

	if w := postPFVerb(t, s, me, pf.ID, "delete"); w.Code != http.StatusSeeOther {
		t.Fatalf("delete code=%d", w.Code)
	}
	if n := pfCount(t, s); n != 0 {
		t.Fatalf("delete 之后还剩 %d 条", n)
	}
	assertAuditAction(t, s, "port_forward_delete")

	// 三次改动都得让 server 重载,否则库里改了、监听没动。
	waitForControlHits(t, fc, "/reload", 3)
}

func TestPortForwardAction_BadInput(t *testing.T) {
	s, _ := pfServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	pf := makePF(t, s, dev, 9001)

	cases := []struct {
		name, path, method string
		want               int
	}{
		{"缺动作", "/port-forwards/1", http.MethodPost, http.StatusBadRequest},
		{"id 不是数字", "/port-forwards/abc/delete", http.MethodPost, http.StatusBadRequest},
		{"id 为 0", "/port-forwards/0/delete", http.MethodPost, http.StatusBadRequest},
		{"id 为负", "/port-forwards/-1/delete", http.MethodPost, http.StatusBadRequest},
		{"不存在的 id", "/port-forwards/99999/delete", http.MethodPost, http.StatusNotFound},
		{"未知动作", "/port-forwards/" + itoa(pf.ID) + "/nuke", http.MethodPost, http.StatusBadRequest},
		{"GET 触发删除", "/port-forwards/" + itoa(pf.ID) + "/delete", http.MethodGet, http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		s.handlePortForwardAction(w, withAdminCtx(req, me))
		if w.Code != tc.want {
			t.Errorf("%s: code=%d, 期望 %d", tc.name, w.Code, tc.want)
		}
	}
	if n := pfCount(t, s); n != 1 {
		t.Fatalf("坏输入改动了数据(剩 %d 条)", n)
	}
}

func TestPortForwardAction_ViewerIsRejected(t *testing.T) {
	s, fc := pfServer(t)
	createTestAdmin(t, s, "root", "pw-root-12345678") // floor 守卫要求至少留一个 admin
	viewer := createTestAdmin(t, s, "peeker", "pw-peeker-12345")
	if err := s.store.SetWebAdminRoleEnsuringAdmin(t.Context(), viewer.ID, "viewer"); err != nil {
		t.Fatalf("降级: %v", err)
	}
	viewer = mustGetAdmin(t, s, viewer.ID)
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	pf := makePF(t, s, dev, 9001)

	for _, verb := range []string{"delete", "enable", "disable"} {
		if w := postPFVerb(t, s, viewer, pf.ID, verb); w.Code != http.StatusForbidden {
			t.Errorf("viewer %s: code=%d, 期望 403", verb, w.Code)
		}
	}
	if got, _ := s.store.GetPortForward(t.Context(), pf.ID); got == nil || !got.Enabled {
		t.Fatal("viewer 的请求改动了映射")
	}
	if controlHits(fc, "/reload") != 0 {
		t.Fatal("viewer 被拒后仍触发了 reload")
	}
}

func TestPortForwardList_RendersAndRejectsNonGET(t *testing.T) {
	s, _ := pfServer(t)
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	makePF(t, s, dev, 9001)

	w := httptest.NewRecorder()
	s.handlePortForwardList(w, withAdminCtx(
		httptest.NewRequest(http.MethodGet, "/port-forwards", nil), me))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d body=%q", w.Code, trimForLog(w.Body.String()))
	}
	if !strings.Contains(w.Body.String(), "9001") {
		t.Error("列表里没有那条映射的公网端口")
	}

	w = httptest.NewRecorder()
	s.handlePortForwardList(w, withAdminCtx(
		httptest.NewRequest(http.MethodPost, "/port-forwards", nil), me))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST code=%d, 期望 405", w.Code)
	}
}

func TestPortForwardList_SurvivesUnreachableControl(t *testing.T) {
	s := newMeTestServer(t)
	fc := newFakeControl(t, controlBroken()) // /portforward/status 未注册 → 404
	s.control = fc.client
	me := createTestAdmin(t, s, "root", "pw-root-12345678")
	dev := devFixture(t, s, "alice", "uuid-alice", "10.66.0.5", "")
	makePF(t, s, dev, 9001)

	// server 不可达时列表要降级为「运行态未知」,而不是整页 500 ——
	// 恰恰是 server 出问题的时候,管理员最需要能打开这一页看配置。
	w := httptest.NewRecorder()
	s.handlePortForwardList(w, withAdminCtx(
		httptest.NewRequest(http.MethodGet, "/port-forwards", nil), me))
	if w.Code != http.StatusOK {
		t.Fatalf("code=%d, 期望 200(降级渲染)", w.Code)
	}
}
