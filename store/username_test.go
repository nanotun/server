package store

import (
	"context"
	"strings"
	"testing"
)

func TestValidateUsername_RejectsNamesThatLieInTextViews(t *testing.T) {
	bad := map[string]string{
		"内嵌换行(会把 user list 撑成两行,凭空多一个用户)": "a\nb",
		"内嵌回车(真终端里回车覆盖,整行显示成后半段)":         "alice\rEVIL-ADMIN",
		"内嵌制表(错列)":         "tab\there",
		"ANSI 转义(重放进运维终端)": "zed\x1b[31m",
		"NUL":              "a\x00b",
		"DEL":              "a\x7fb",
	}
	for desc, name := range bad {
		t.Run(desc, func(t *testing.T) {
			if err := ValidateUsername(name); err == nil {
				t.Fatalf("应当拒绝 %q,却放行了", name)
			}
		})
	}

	if err := ValidateUsername(strings.Repeat("a", MaxUsernameRunes+1)); err == nil {
		t.Error("超长用户名应当被拒绝")
	}
	if err := ValidateUsername(""); err == nil {
		t.Error("空用户名应当被拒绝")
	}
}

func TestValidateUsername_AcceptsOrdinaryNames(t *testing.T) {
	for _, ok := range []string{
		"alice",
		"bob.smith",
		"user@example.com",
		"张三",         // 非 ASCII 是正常名字,不该被误伤
		"with space", // 名字里的空格无害:不断行、不移光标
		"a-b_c+d",
		strings.Repeat("a", MaxUsernameRunes), // 正好卡在上限
	} {
		if err := ValidateUsername(ok); err != nil {
			t.Errorf("%q 应当放行,却被拒:%v", ok, err)
		}
	}
}

// 设备名走过滤而非拒绝:它是客户端登录时上报的 hostname,不该因为带个怪字符就把人挡在网外。
func TestSanitizeDeviceName_StripsControlCharsButKeepsTheName(t *testing.T) {
	cases := map[string]string{
		"lap\ntop":    "laptop",
		"a\rEVIL-DEV": "aEVIL-DEV",
		"zed\x1b[31m": "zed[31m",
		"tab\there":   "tabhere",
		"  \r\n  ":    "", // 整个名字都是控制字符 → 归一成空
		"张三的 MacBook": "张三的 MacBook",
		"normal-host": "normal-host",
	}
	for in, want := range cases {
		if got := SanitizeDeviceName(in); got != want {
			t.Errorf("SanitizeDeviceName(%q) = %q,期望 %q", in, got, want)
		}
	}
}

// 关键在于这条路径跨了权限边界:设备名由普通用户的客户端提供,却要渲染进管理员的终端。
func TestUpsertDevice_SanitizesClientSuppliedName(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	u, err := st.CreateUser(ctx, NewUser{Username: "dave", PSKHash: "x"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dev, err := st.UpsertDevice(ctx, u.ID, "55555555-2222-4333-8444-555555555555", "lap\ntop\x1b[2K", "linux")
	if err != nil {
		t.Fatalf("upsert device: %v", err)
	}
	for _, bad := range []string{"\n", "\r", "\x1b", "\x7f"} {
		if strings.Contains(dev.DeviceName, bad) {
			t.Errorf("设备名里仍残留控制字符 %q:%q", bad, dev.DeviceName)
		}
	}
	if dev.DeviceName == "" {
		t.Error("过滤过头了,名字不该被清空")
	}
}

// 校验放在 store 层是为了让 CLI 和 Web 两条创建路径都过同一道门。
func TestCreateUser_RejectsControlCharacters(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if _, err := st.CreateUser(ctx, NewUser{Username: "alice\rEVIL", PSKHash: "x"}); err == nil {
		t.Fatal("CreateUser 放行了带回车的用户名")
	}
	if _, err := st.CreateWebAdmin(ctx, NewWebAdmin{Username: "root\nfake", PasswordHash: "x"}); err == nil {
		t.Fatal("CreateWebAdmin 放行了带换行的用户名")
	}
	if _, err := st.CreateFirstWebAdmin(ctx, NewWebAdmin{Username: "root\x1b[2K", PasswordHash: "x"}); err == nil {
		t.Fatal("CreateFirstWebAdmin 放行了带 ANSI 转义的用户名")
	}

	// 正常名字仍能创建,别把门关死了。
	if _, err := st.CreateUser(ctx, NewUser{Username: "alice", PSKHash: "x"}); err != nil {
		t.Fatalf("正常用户名创建失败:%v", err)
	}
}
