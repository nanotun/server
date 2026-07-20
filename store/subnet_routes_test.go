package store

import (
	"errors"
	"testing"
)

// 建一个 device 出来供 subnet_routes 关联(外键 device_id → devices.id 级联删除)。
func mustCreateDevice(t *testing.T, s *Store, userID int64, name string) int64 {
	t.Helper()
	ctx := t.Context()
	d, err := s.UpsertDevice(ctx, userID, name, name, "linux")
	if err != nil {
		t.Fatalf("UpsertDevice: %v", err)
	}
	return d.ID
}

func TestSubnetRoutes_UpsertAndStatusFlow(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	deviceID := mustCreateDevice(t, s, u.ID, "dev1")

	r, err := s.UpsertAdvertisedRoute(ctx, deviceID, "192.168.1.0/24")
	if err != nil {
		t.Fatalf("UpsertAdvertisedRoute: %v", err)
	}
	if r.Status != RouteStatusPending {
		t.Fatalf("status = %q, want pending", r.Status)
	}
	first := r.AdvertisedAt

	if _, err := s.UpsertAdvertisedRoute(ctx, deviceID, "192.168.1.0/24"); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	r2, err := s.GetRouteByDeviceCIDR(ctx, deviceID, "192.168.1.0/24")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if r2.AdvertisedAt < first {
		t.Fatalf("advertised_at not refreshed: %d < %d", r2.AdvertisedAt, first)
	}

	if err := s.SetRouteStatus(ctx, deviceID, "192.168.1.0/24", RouteStatusApproved, "looks good"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	r3, _ := s.GetRouteByDeviceCIDR(ctx, deviceID, "192.168.1.0/24")
	if r3.Status != RouteStatusApproved {
		t.Fatalf("status after approve = %q", r3.Status)
	}
	if r3.ApprovedAt == 0 {
		t.Fatal("approved_at not set")
	}
	if r3.Reason != "" {
		t.Fatalf("reason应被清空(非 rejected), got %q", r3.Reason)
	}

	if _, err := s.UpsertAdvertisedRoute(ctx, deviceID, "192.168.1.0/24"); err != nil {
		t.Fatalf("re-advertise after approve: %v", err)
	}
	r4, _ := s.GetRouteByDeviceCIDR(ctx, deviceID, "192.168.1.0/24")
	if r4.Status != RouteStatusApproved {
		t.Fatalf("re-advertise 不该回退 approved → pending, status=%q", r4.Status)
	}

	if err := s.SetRouteStatus(ctx, deviceID, "192.168.1.0/24", RouteStatusRejected, "private subnet conflict"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	r5, _ := s.GetRouteByDeviceCIDR(ctx, deviceID, "192.168.1.0/24")
	if r5.Status != RouteStatusRejected || r5.Reason != "private subnet conflict" {
		t.Fatalf("reject result wrong: %+v", r5)
	}
}

func TestSubnetRoutes_DeleteAdvertisedKeepsApproved(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u, _ := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	deviceID := mustCreateDevice(t, s, u.ID, "dev1")

	for _, c := range []string{"10.0.0.0/24", "10.0.1.0/24"} {
		if _, err := s.UpsertAdvertisedRoute(ctx, deviceID, c); err != nil {
			t.Fatalf("upsert %s: %v", c, err)
		}
	}
	if err := s.SetRouteStatus(ctx, deviceID, "10.0.0.0/24", RouteStatusApproved, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}

	n, err := s.DeleteAdvertisedRoutesForDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("DeleteAdvertisedRoutesForDevice: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d, want 1 (only pending 10.0.1.0/24)", n)
	}
	all, _ := s.ListRoutesByDevice(ctx, deviceID)
	if len(all) != 1 || all[0].CIDR != "10.0.0.0/24" {
		t.Fatalf("after delete pending: %+v", all)
	}
}

func TestSubnetRoutes_ListAndByStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u, _ := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	dev1 := mustCreateDevice(t, s, u.ID, "dev1")
	dev2 := mustCreateDevice(t, s, u.ID, "dev2")

	_, _ = s.UpsertAdvertisedRoute(ctx, dev1, "10.0.0.0/24")
	_, _ = s.UpsertAdvertisedRoute(ctx, dev1, "10.0.1.0/24")
	_, _ = s.UpsertAdvertisedRoute(ctx, dev2, "10.0.2.0/24")
	_ = s.SetRouteStatus(ctx, dev1, "10.0.0.0/24", RouteStatusApproved, "")

	pending, _ := s.ListRoutesByStatus(ctx, RouteStatusPending)
	if len(pending) != 2 {
		t.Fatalf("pending = %d, want 2", len(pending))
	}
	approved, _ := s.ListRoutesByStatus(ctx, RouteStatusApproved)
	if len(approved) != 1 || approved[0].CIDR != "10.0.0.0/24" {
		t.Fatalf("approved wrong: %+v", approved)
	}

	all, _ := s.ListAllRoutes(ctx)
	if len(all) != 3 {
		t.Fatalf("ListAllRoutes = %d, want 3", len(all))
	}
}

func TestSubnetRoutes_DeleteRoute(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u, _ := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	dev := mustCreateDevice(t, s, u.ID, "dev1")

	if _, err := s.UpsertAdvertisedRoute(ctx, dev, "192.168.0.0/24"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.DeleteRoute(ctx, dev, "192.168.0.0/24"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteRoute(ctx, dev, "192.168.0.0/24"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice want ErrNotFound, got %v", err)
	}
}

func TestSubnetRoutes_BadStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u, _ := s.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "h"})
	dev := mustCreateDevice(t, s, u.ID, "dev1")
	_, _ = s.UpsertAdvertisedRoute(ctx, dev, "10.0.0.0/24")

	if err := s.SetRouteStatus(ctx, dev, "10.0.0.0/24", "frobnicated", "x"); err == nil {
		t.Fatal("bad status should error")
	}
}
