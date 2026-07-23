package main

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/nanotun/server/store"
)

// newPFTestServer 构造一个带 store 的最小 *Server + 一台设备 fixture，专门测端口转发入参校验。
// 设备：FixedVIPv4=10.201.0.6；已批准宣告网段 192.168.8.0/24；另有一条**未批准**的 192.168.9.0/24（pending）。
func newPFTestServer(t *testing.T) (*Server, *store.Device) {
	t.Helper()
	ctx := t.Context()
	st, err := store.Open(ctx, t.TempDir()+"/pf_test.db", store.Options{})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	u, err := st.CreateUser(ctx, store.NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "d2b65929-90c5-4382-a964-67c2009cd425", "gl-mt3000", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	// 钉死 vIP（node 目标校验用）。
	if err := st.SetDeviceFixedVIP(ctx, dev.ID, "10.201.0.6", "", false); err != nil {
		t.Fatalf("SetDeviceFixedVIP: %v", err)
	}
	// 已批准网段。
	if _, err := st.UpsertAdvertisedRoute(ctx, dev.ID, "192.168.8.0/24"); err != nil {
		t.Fatalf("UpsertAdvertisedRoute approved: %v", err)
	}
	if err := st.SetRouteStatus(ctx, dev.ID, "192.168.8.0/24", store.RouteStatusApproved, ""); err != nil {
		t.Fatalf("SetRouteStatus approved: %v", err)
	}
	// 待批准网段（应被越权/SSRF 校验拒绝）。
	if _, err := st.UpsertAdvertisedRoute(ctx, dev.ID, "192.168.9.0/24"); err != nil {
		t.Fatalf("UpsertAdvertisedRoute pending: %v", err)
	}
	// 重新取一遍带 fixed vIP 的设备行。
	dev, err = st.GetDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	s := &Server{store: st, cfg: Config{ListenAddr: "0.0.0.0:7443"}}
	return s, dev
}

func TestValidatePortForwardInput(t *testing.T) {
	s, dev := newPFTestServer(t)
	r := httptest.NewRequestWithContext(t.Context(), "POST", "/port-forwards/new", nil)
	uuid := dev.DeviceUUID

	cases := []struct {
		name       string
		publicPort int
		targetPort int
		targetIP   string
		deviceUUID string
		wantOK     bool // true = 校验通过（返回空串）
	}{
		{"node 目标(vIP)合法", 2222, 22, "10.201.0.6", uuid, true},
		{"LAN 目标(已批准网段)合法", 8022, 80, "192.168.8.5", uuid, true},

		{"LAN 目标落在未批准网段→拒(越权/SSRF)", 8023, 80, "192.168.9.5", uuid, false},
		{"target_ip 既非 vIP 也不在任何网段→拒", 8024, 80, "8.8.8.8", uuid, false},
		{"public_port 保留(22)→拒", 22, 22, "10.201.0.6", uuid, false},
		{"public_port 与 web 端口(7443)冲突→拒", 7443, 22, "10.201.0.6", uuid, false},
		{"public_port 越界(0)→拒", 0, 22, "10.201.0.6", uuid, false},
		{"public_port 越界(70000)→拒", 70000, 22, "10.201.0.6", uuid, false},
		{"target_port 越界→拒", 2223, 0, "10.201.0.6", uuid, false},
		{"target_ip 非法→拒", 2224, 22, "not-an-ip", uuid, false},
		{"设备未注册→拒", 2225, 22, "10.201.0.6", "ffffffff-0000-0000-0000-000000000000", false},
		{"未选设备→拒", 2226, 22, "10.201.0.6", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := s.validatePortForwardInput(r, tc.publicPort, tc.targetPort, tc.targetIP, tc.deviceUUID)
			gotOK := msg == ""
			if gotOK != tc.wantOK {
				t.Fatalf("wantOK=%v gotOK=%v (msg=%q)", tc.wantOK, gotOK, msg)
			}
		})
	}
}

// TestValidatePortForward_SameIPDifferentDeviceRejected 覆盖 #5 歧义拦截：同一 target_ip 不能指向不同设备，
// 但同一 target_ip 同一设备（不同端口）允许。
func TestValidatePortForward_SameIPDifferentDeviceRejected(t *testing.T) {
	s, devA := newPFTestServer(t)
	ctx := t.Context()

	// 设备 B，也批准同一 192.168.8.0/24（确保被拒是因「设备冲突」而非「网段未批准」）。
	u, err := s.store.CreateUser(ctx, store.NewUser{Username: "carol", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	devB, err := s.store.UpsertDevice(ctx, u.ID, "bbbbbbbb-0000-0000-0000-000000000002", "site-b", "linux")
	if err != nil {
		t.Fatalf("UpsertDevice B: %v", err)
	}
	if _, err := s.store.UpsertAdvertisedRoute(ctx, devB.ID, "192.168.8.0/24"); err != nil {
		t.Fatalf("UpsertAdvertisedRoute B: %v", err)
	}
	if err := s.store.SetRouteStatus(ctx, devB.ID, "192.168.8.0/24", store.RouteStatusApproved, ""); err != nil {
		t.Fatalf("SetRouteStatus B: %v", err)
	}

	// 既有映射：192.168.8.5 → 设备 A。
	if _, err := s.store.CreatePortForward(ctx, store.PortForward{
		PublicPort: 9001, Proto: "tcp", TargetDeviceUUID: devA.DeviceUUID, TargetIP: "192.168.8.5", TargetPort: 80, Enabled: true,
	}); err != nil {
		t.Fatalf("CreatePortForward existing: %v", err)
	}

	r := httptest.NewRequestWithContext(ctx, "POST", "/port-forwards/new", nil)
	// 同 IP、不同设备（B）→ 拒。
	if msg := s.validatePortForwardInput(r, 9002, 80, "192.168.8.5", devB.DeviceUUID); msg == "" {
		t.Fatal("同一 target_ip 指向不同设备应被拒（#5 歧义）")
	}
	// 同 IP、同设备（A）、不同端口 → 允许。
	if msg := s.validatePortForwardInput(r, 9003, 22, "192.168.8.5", devA.DeviceUUID); msg != "" {
		t.Fatalf("同一 target_ip 同一设备(不同端口)应允许, 得 %q", msg)
	}
}

// TestValidatePortForwardInput_LeaseVIP 验证 node 目标也接受 lease（非 fixed）vIP。
func TestValidatePortForwardInput_LeaseVIP(t *testing.T) {
	ctx := context.Background()
	s, _ := newPFTestServer(t)
	u, err := s.store.CreateUser(ctx, store.NewUser{Username: "bob", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	dev, err := s.store.UpsertDevice(ctx, u.ID, "aaaaaaaa-0000-0000-0000-000000000001", "phone", "ios")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	if _, err := s.store.UpsertLease(ctx, dev.ID, "10.201.0.9", "", false); err != nil {
		t.Fatalf("UpsertLease: %v", err)
	}
	r := httptest.NewRequestWithContext(t.Context(), "POST", "/port-forwards/new", nil)
	if msg := s.validatePortForwardInput(r, 2299, 22, "10.201.0.9", dev.DeviceUUID); msg != "" {
		t.Fatalf("lease vIP 应通过校验, 得 %q", msg)
	}
	// 用别的 IP（非该设备 vIP、非其网段）应拒。
	if msg := s.validatePortForwardInput(r, 2300, 22, "10.201.0.99", dev.DeviceUUID); msg == "" {
		t.Fatalf("非该设备 vIP 应被拒")
	}
}
