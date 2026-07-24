package main

import "testing"

// TestDeviceReservedVIPExceptions_FixedAndLease(第十九轮深扫 MED):当 fixed≠lease 时,登录路径给 dbReservedVIPs
// 的 except 集必须同时包含设备**自身**的 fixed 与 lease 两者 —— 否则漏剔实际 lease → 本设备既复用不到、也回收
// 不了该地址 → 分到第三个地址,fixed 与新 lease 并存双占同一设备(小前缀白烧地址)。
func TestDeviceReservedVIPExceptions_FixedAndLease(t *testing.T) {
	setGlobalContextForTest(t)
	gw := newRouteTestGateway(t)
	_, deviceID := mustCreateUserAndDevice(t, gw, "alice")
	if err := gw.store.SetDeviceFixedVIP(t.Context(), deviceID, "10.201.0.6", "", false); err != nil { // fixed=.6
		t.Fatal(err)
	}
	if _, err := gw.store.UpsertLease(t.Context(), deviceID, "10.201.0.9", "", false); err != nil { // lease=.9(≠fixed)
		t.Fatal(err)
	}
	dev, err := gw.store.GetDevice(t.Context(), deviceID)
	if err != nil {
		t.Fatal(err)
	}
	res := &loginAuthResult{UserID: "1", Device: dev}

	// except 集应含 fixed .6 与 lease .9 两者。
	v4s, _ := deviceReservedVIPExceptions(gw, res)
	has := func(s []string, v string) bool {
		for _, x := range s {
			if x == v {
				return true
			}
		}
		return false
	}
	if !has(v4s, "10.201.0.6") || !has(v4s, "10.201.0.9") {
		t.Fatalf("except 集应同时含 fixed .6 与 lease .9,实际 %v", v4s)
	}

	// dbReservedVIPs:AllUsedVIPs 里本设备自身的 .6/.9 都应被剔除(不当他人占用挡住自己回收/复用)。
	resvV4, _ := dbReservedVIPs(gw, v4s, nil)
	if resvV4["10.201.0.6"] {
		t.Fatalf("本设备 fixed .6 不应留在 db 保留集:%v", resvV4)
	}
	if resvV4["10.201.0.9"] {
		t.Fatalf("本设备实际 lease .9 不应留在 db 保留集(此前只剔 fixed 的 bug):%v", resvV4)
	}
}
