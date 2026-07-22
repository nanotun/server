package main

import (
	"net/netip"
	"testing"
)

// P0-4 单元测试:user.exit_allowed=false 时,Connection.exitDeniedForPacket 必须
// 在 dst 不属于任何 vIP 时返回 true(丢出口流量);属于 vIP 时返回 false(继续走 ACL)。
func TestExitDeniedForPacket_ExitAllowedTrue(t *testing.T) {
	c := &Connection{userID: "u1", exitAllowed: true}
	pkt := udpPacketIPv4(t, [4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8}, 53)
	if c.exitDeniedForPacket(pkt) {
		t.Fatal("exitAllowed=true should never drop")
	}
}

func TestExitDeniedForPacket_NoUserID(t *testing.T) {
	c := &Connection{} // userID 空,exitAllowed=false
	pkt := udpPacketIPv4(t, [4]byte{10, 0, 0, 1}, [4]byte{8, 8, 8, 8}, 53)
	if c.exitDeniedForPacket(pkt) {
		t.Fatal("no user context should skip enforcement (兼容老路径)")
	}
}

func TestExitDeniedForPacket_DropsExitTraffic(t *testing.T) {
	c := &Connection{userID: "u9", exitAllowed: false}
	pkt := udpPacketIPv4(t, [4]byte{10, 0, 0, 99}, [4]byte{8, 8, 8, 8}, 53)
	if !c.exitDeniedForPacket(pkt) {
		t.Fatal("exit traffic should be dropped when exitAllowed=false")
	}
}

func TestExitDeniedForPacket_AllowsVIPTraffic(t *testing.T) {
	dstVIP := netip.MustParseAddr("10.0.0.50")
	registerVIPOwners([]netip.Addr{dstVIP}, 50, 1)
	defer unregisterVIPOwners([]netip.Addr{dstVIP}, 1)

	c := &Connection{userID: "u9", exitAllowed: false}
	pkt := udpPacketIPv4(t, [4]byte{10, 0, 0, 99}, [4]byte{10, 0, 0, 50}, 53)
	if c.exitDeniedForPacket(pkt) {
		t.Fatal("traffic to a vIP should not be exit-blocked (留给 ACL 裁决)")
	}
}

// P0-4 限速叠加:minPositiveBPS 取「更严」组合。
func TestMinPositiveBPS(t *testing.T) {
	cases := []struct {
		name     string
		platform int
		user     int64
		want     int
	}{
		{"both zero", 0, 0, 0},
		{"only platform", 1000, 0, 1000},
		{"only user", 0, 500, 500},
		{"user stricter", 1000, 500, 500},
		{"platform stricter", 200, 500, 200},
		{"negative user treated as unlimited", 1000, -1, 1000},
	}
	for _, c := range cases {
		got := minPositiveBPS(c.platform, c.user)
		if got != c.want {
			t.Errorf("%s: minPositiveBPS(%d,%d) = %d, want %d", c.name, c.platform, c.user, got, c.want)
		}
	}
}

// 帮助:构造 IPv4 UDP 包,IHL=5,proto=17,固定 8B UDP 头。
func udpPacketIPv4(t *testing.T, src, dst [4]byte, dstPort uint16) []byte {
	t.Helper()
	return []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00,
		src[0], src[1], src[2], src[3],
		dst[0], dst[1], dst[2], dst[3],
		0x12, 0x34, byte(dstPort >> 8), byte(dstPort & 0xff),
		0x00, 0x08, 0x00, 0x00,
	}
}
