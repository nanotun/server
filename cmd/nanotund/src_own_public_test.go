package main

import (
	"net/netip"
	"testing"
)

// TestLinkPeerIPFromRemote:"ip:port" / 裸 ip / 垃圾输入 的解析。
func TestLinkPeerIPFromRemote(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string // "" = 期望零值
	}{
		{"203.0.113.8:44321", "203.0.113.8"},
		{"203.0.113.8", "203.0.113.8"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"::ffff:203.0.113.8", "203.0.113.8"}, // v4-mapped 要 Unmap,否则和包里解出来的地址比不相等
		{"", ""},
		{"not-an-ip:99", ""},
	} {
		got := linkPeerIPFromRemote(tc.in)
		if tc.want == "" {
			if got.IsValid() {
				t.Errorf("linkPeerIPFromRemote(%q) = %v, want 零值", tc.in, got)
			}
			continue
		}
		if got != netip.MustParseAddr(tc.want) {
			t.Errorf("linkPeerIPFromRemote(%q) = %v, want %s", tc.in, got, tc.want)
		}
	}
}

// TestSrcOwnPublicClassification:被判伪造的包里,「源 == 本会话链路对端 IP」要记到
// srcOwnPublicDropCount,其余记到 srcSpoofDropCount。
//
// 这是 runLinkTunnel 里那段分流的逻辑等价物(那段在 demux 循环内,单测起不了整条隧道)。
// 分流的意义见 srcOwnPublicDropCount 的注释:全隧道客户端被互联网扫描时,回包源是它自己的
// 公网 IP,这类丢包会永久匀速增长;混进 src_spoof 就没人能靠后者判断「真有人在冒充」了。
func TestSrcOwnPublicClassification(t *testing.T) {
	mkPkt := func(src, dst string) []byte {
		s := netip.MustParseAddr(src).As4()
		d := netip.MustParseAddr(dst).As4()
		return []byte{
			0x45, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x00, 0x00,
			0x40, 0x11, 0x00, 0x00,
			s[0], s[1], s[2], s[3],
			d[0], d[1], d[2], d[3],
			0x12, 0x34, 0x00, 0x35,
			0x00, 0x08, 0x00, 0x00,
		}
	}
	// classify 复刻 runLinkTunnel 的分流判据。
	classify := func(remote string, pkt []byte) string {
		linkPeerAddr := linkPeerIPFromRemote(remote)
		if t, ok := parsePacketTuple(pkt); ok && linkPeerAddr.IsValid() && t.src == linkPeerAddr {
			return "own_public"
		}
		return "spoof"
	}

	// 客户端公网 IP 203.0.113.8:全隧道下它给互联网扫描源回的包,源就是这个地址。
	if got := classify("203.0.113.8:44321", mkPkt("203.0.113.8", "198.51.100.7")); got != "own_public" {
		t.Errorf("自己公网 IP 的不对称回程应记 own_public,得到 %s", got)
	}
	// 冒充别人 vIP:必须仍记进 src_spoof。
	if got := classify("203.0.113.8:44321", mkPkt("10.9.0.6", "8.8.8.8")); got != "spoof" {
		t.Errorf("冒充他人 vIP 应记 spoof,得到 %s", got)
	}
	// 冒充**别的**客户端的公网 IP 也是冒充(不等于本会话对端)。
	if got := classify("203.0.113.8:44321", mkPkt("203.0.113.9", "8.8.8.8")); got != "spoof" {
		t.Errorf("非本会话对端的公网源应记 spoof,得到 %s", got)
	}
	// remote 解析不出时不分类,保守记 spoof(不能因为拿不到对端地址就把冒充漏报成噪声)。
	if got := classify("garbage", mkPkt("203.0.113.8", "8.8.8.8")); got != "spoof" {
		t.Errorf("remote 无法解析时应保守记 spoof,得到 %s", got)
	}
}
