package auth

import "testing"

// Web 后台密码的判据现在被两个前端共用(网页 /setup 和 nanotun-admin webadmin create),
// 所以这张表就是「两边都认什么」的唯一定义。改动它等于同时改两个入口的门槛。

func TestCheckWebPassword(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want PasswordIssueKind // 0 = 合格
	}{
		{"够长且混合", "Str0ng-Console-Pass", 0},
		{"刚好 12 位", "abcdefghij12", 0},
		{"11 位差一点", "abcdefghi12", PasswordTooShort},
		{"空", "", PasswordTooShort},
		{"257 位", string(make([]byte, 257)), PasswordTooLong},
		{"全字母", "abcdefghijklmnop", PasswordTooFewClasses},
		{"全数字", "123456789012", PasswordTooFewClasses},
		{"字母加符号也算两类", "abcdefghij!!", 0},
		{"带换行", "Str0ng-Pass\nHere", PasswordBadChars},
		{"带制表符", "Str0ng-Pass\tHere", PasswordBadChars},
		{"带 NUL", "Str0ng-Pass\x00Here", PasswordBadChars},
		{"中文也算符号类", "密码密码密码密码密码密码a", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckWebPassword(tc.in)
			if tc.want == 0 {
				if got != nil {
					t.Fatalf("本该收下,却被拒:kind=%d", got.Kind)
				}
				return
			}
			if got == nil {
				t.Fatalf("本该拒(%d),却收下了", tc.want)
			}
			if got.Kind != tc.want {
				t.Fatalf("拒的理由不对:得到 %d,想要 %d", got.Kind, tc.want)
			}
		})
	}
}

// TestCheckWebPassword_TooShortReportsActualLength:文案要说「至少 12 位,你给了 7 位」,
// 少了实际长度那句话就只剩一句干巴巴的规则,人得自己数。
func TestCheckWebPassword_TooShortReportsActualLength(t *testing.T) {
	iss := CheckWebPassword("short1!")
	if iss == nil || iss.Kind != PasswordTooShort {
		t.Fatalf("没判成太短:%+v", iss)
	}
	if iss.Got != len("short1!") {
		t.Fatalf("实际长度报成了 %d,应为 %d", iss.Got, len("short1!"))
	}
}

// TestCheckWebPassword_LengthIsCheckedBeforeCharacterClasses:同一个烂密码在两个入口
// 应当拿到同一条理由,所以检查顺序也是契约的一部分 —— "aaa" 既太短又只有一类字符,
// 报的必须是「太短」(历史实现如此,网页上的提示文案也是照这个顺序写的)。
func TestCheckWebPassword_LengthIsCheckedBeforeCharacterClasses(t *testing.T) {
	iss := CheckWebPassword("aaa")
	if iss == nil || iss.Kind != PasswordTooShort {
		t.Fatalf("顺序变了:%+v", iss)
	}
}
