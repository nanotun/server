package store

import "testing"

// NormalizePlatformCSV:空 = 不限;归一大小写 / 去空白 / 去重;非 canonical token 报错。
func TestNormalizePlatformCSV(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"   ", "", false},
		{",, ,", "", false}, // 全是空段 → 视为不限
		{"macos", "macos", false},
		{" MacOS , IOS ", "macos,ios", false},
		{"router,router", "router", false}, // 去重
		{"macos,ios,android,windows,linux,router", "macos,ios,android,windows,linux,router", false},
		{"iphone", "", true},    // 非法 token
		{"macos,foo", "", true}, // 含一个非法即整体拒
	}
	for _, c := range cases {
		got, err := NormalizePlatformCSV(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizePlatformCSV(%q) 期望报错, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizePlatformCSV(%q) 意外报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizePlatformCSV(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsExitCapablePlatform(t *testing.T) {
	yes := []string{"linux", "Linux", " windows ", "macos", "MACOS", "router", "Router"}
	no := []string{"", "  ", "ios", "android", "iphone", "unknown"}
	for _, p := range yes {
		if !IsExitCapablePlatform(p) {
			t.Errorf("IsExitCapablePlatform(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if IsExitCapablePlatform(p) {
			t.Errorf("IsExitCapablePlatform(%q) = true, want false", p)
		}
	}
}

// AllowsPlatform:空白名单放行一切(含空平台);非空白名单精确匹配(大小写不敏感),
// 且此时空平台被拒。
func TestUserAllowsPlatform(t *testing.T) {
	empty := &User{AllowedPlatforms: ""}
	for _, p := range []string{"macos", "router", "windows", ""} {
		if !empty.AllowsPlatform(p) {
			t.Errorf("空白名单应放行 platform=%q", p)
		}
	}

	u := &User{AllowedPlatforms: "macos,ios"}
	if !u.AllowsPlatform("macos") || !u.AllowsPlatform("IOS") {
		t.Error("白名单内平台(含大小写变体)应放行")
	}
	if u.AllowsPlatform("router") {
		t.Error("白名单外平台应被拒")
	}
	if u.AllowsPlatform("") {
		t.Error("已设白名单时,空平台应被拒")
	}
}
