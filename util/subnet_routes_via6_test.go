package util

import "testing"

// TestNormalizeAdvertisedCIDR_RejectsVia6Space:4via6 是 mesh 内部合成地址空间,不是任何人身后的 LAN。
// 它落在 ULA fc00::/7 白名单里,若不单独挡掉就能被宣告 + 批准(三机实测批准成功),审批面上多出一条
// 「看起来管着全部 4via6」的记录。
func TestNormalizeAdvertisedCIDR_RejectsVia6Space(t *testing.T) {
	for _, c := range []string{"fdbc:4a60::/64", "fdbc:4a60:0:0:0:5::/96", "fdbc:4a60::1/128"} {
		if got, err := NormalizeAdvertisedCIDR(c); err == nil {
			t.Errorf("%s 应被拒(4via6 内部空间),却归一成 %s", c, got)
		}
	}
	// 相邻的普通 ULA 不该受影响。
	for _, c := range []string{"fd77:88::/64", "fdbc:4a61::/64", "fdbc::/32"} {
		if _, err := NormalizeAdvertisedCIDR(c); err != nil {
			t.Errorf("%s 是普通 ULA,不该被拒: %v", c, err)
		}
	}
}
