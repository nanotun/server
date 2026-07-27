package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nanotun/server/store"
)

// parsePlatformsForm 用给定的复选框取值调用 platformsFromForm。
func parsePlatformsForm(t *testing.T, values ...string) (string, error) {
	t.Helper()
	form := url.Values{}
	for _, v := range values {
		form.Add("platforms", v)
	}
	req := httptest.NewRequest("POST", "/users/1/set-platforms",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return platformsFromForm(req)
}

// TestPlatformsFromForm_AllCheckedMeansUnrestricted 守住这条最反直觉的规则:
// 六个复选框全勾必须归一成空串(= 不限),而不是把六个平台原样写成白名单。
//
// 两者今天等价,但一旦以后新增第七个平台,「显式六平台白名单」会立刻变成一条把
// 新平台锁在门外的限制规则 —— 而管理员当初只是「全勾表示不限」。
func TestPlatformsFromForm_AllCheckedMeansUnrestricted(t *testing.T) {
	got, err := parsePlatformsForm(t, store.CanonicalPlatforms...)
	if err != nil {
		t.Fatalf("全勾不应报错: %v", err)
	}
	if got != "" {
		t.Fatalf("全勾应归一成空串(不限), 实际 %q", got)
	}
}

// TestPlatformsFromForm_NoneCheckedMeansUnrestricted 全不勾同样是不限 ——
// 否则一次误提交就能把账号的所有平台都禁掉,把人锁死在门外。
func TestPlatformsFromForm_NoneCheckedMeansUnrestricted(t *testing.T) {
	got, err := parsePlatformsForm(t)
	if err != nil {
		t.Fatalf("全不勾不应报错: %v", err)
	}
	if got != "" {
		t.Fatalf("全不勾应为空串(不限), 实际 %q", got)
	}
}

// TestPlatformsFromForm_PartialSelection 部分勾选原样落库,包括「差一个就全选」
// 这个边界:只有**恰好全选**才塌缩成不限。
func TestPlatformsFromForm_PartialSelection(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		want  string
	}{
		{"两个", []string{"macos", "ios"}, "macos,ios"},
		{"单个", []string{"router"}, "router"},
		{"重复项去重", []string{"macos", "macos", "ios"}, "macos,ios"},
		{"大小写归一", []string{"MacOS", "IOS"}, "macos,ios"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parsePlatformsForm(t, c.input...)
			if err != nil {
				t.Fatalf("不应报错: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}

	// 边界:少勾一个就不能塌缩成「不限」。
	allButOne := store.CanonicalPlatforms[:len(store.CanonicalPlatforms)-1]
	got, err := parsePlatformsForm(t, allButOne...)
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if got == "" {
		t.Fatalf("勾了 %d/%d 个平台却被当成不限 —— 塌缩条件写宽了",
			len(allButOne), len(store.CanonicalPlatforms))
	}
	if strings.Contains(got, store.CanonicalPlatforms[len(store.CanonicalPlatforms)-1]) {
		t.Fatalf("未勾选的平台不该出现在结果里: %q", got)
	}
}

// TestPlatformsFromForm_RejectsUnknown 伪造的平台名必须整条拒绝,而不是静默丢弃。
// 静默丢弃会把「macos + 一个伪造值」变成「只有 macos」,或把整条变成空(不限)。
func TestPlatformsFromForm_RejectsUnknown(t *testing.T) {
	for _, bad := range [][]string{
		{"plan9"},
		{"macos", "windoze"},
		{"darwin", "ios"},
	} {
		got, err := parsePlatformsForm(t, bad...)
		if err == nil {
			t.Errorf("%v 应被拒绝, 却返回 %q", bad, got)
		}
		if got != "" {
			t.Errorf("被拒时不应返回部分结果, got %q", got)
		}
	}
}

// TestPlatformChecksFor 渲染侧:nil / 未设白名单都应全勾(默认不限)。
func TestPlatformChecksFor(t *testing.T) {
	assertAllChecked := func(t *testing.T, what string, checks []platformCheck) {
		t.Helper()
		if len(checks) != len(store.CanonicalPlatforms) {
			t.Fatalf("%s: 复选框 %d 个, 期望 %d 个", what, len(checks), len(store.CanonicalPlatforms))
		}
		for i, c := range checks {
			if c.Name != store.CanonicalPlatforms[i] {
				t.Errorf("%s: 第 %d 个是 %q, 期望按 canonical 顺序为 %q",
					what, i, c.Name, store.CanonicalPlatforms[i])
			}
			if !c.Checked {
				t.Errorf("%s: %q 应默认勾选", what, c.Name)
			}
		}
	}
	assertAllChecked(t, "新建表单(nil)", platformChecksFor(nil))
	assertAllChecked(t, "未设白名单", platformChecksFor(&store.User{AllowedPlatforms: ""}))

	checks := platformChecksFor(&store.User{AllowedPlatforms: "macos,ios"})
	for _, c := range checks {
		want := c.Name == "macos" || c.Name == "ios"
		if c.Checked != want {
			t.Errorf("白名单 macos,ios 下 %q 的勾选状态为 %v, 期望 %v", c.Name, c.Checked, want)
		}
	}
}

// TestPlatformsForm_RoundTrip 是这组的核心不变式:详情页渲染出的勾选状态原样提交
// 回去,白名单必须一字不差。
//
// 渲染(platformChecksFor)与解析(platformsFromForm)是两个独立函数,任何一侧改了
// 语义都会让「管理员只是打开页面点了保存」变成一次意外的白名单变更 —— 这类回归
// 在 UI 上完全看不出来。「不限」那一行同时解释了塌缩规则存在的理由:全勾进、
// 空串出,才能原样还原。
func TestPlatformsForm_RoundTrip(t *testing.T) {
	for _, stored := range []string{"", "macos", "macos,ios", "windows,linux,router"} {
		// 前置自检:入库值一定是 NormalizePlatformCSV 的输出(canonical 顺序)。
		// 用例本身若不是规范形态,后面的回环断言就失去意义。
		if norm, err := store.NormalizePlatformCSV(stored); err != nil || norm != stored {
			t.Fatalf("用例 %q 不是 canonical 形态(归一为 %q, err=%v), 需修正测试数据",
				stored, norm, err)
		}
		checks := platformChecksFor(&store.User{AllowedPlatforms: stored})
		var submitted []string
		for _, c := range checks {
			if c.Checked {
				submitted = append(submitted, c.Name)
			}
		}
		got, err := parsePlatformsForm(t, submitted...)
		if err != nil {
			t.Fatalf("白名单 %q 回环解析报错: %v", stored, err)
		}
		if got != stored {
			t.Errorf("白名单 %q 渲染成 %v 再提交回来变成了 %q —— 打开页面点保存就改了权限",
				stored, submitted, got)
		}
	}
}
