package auth

import "strings"

// Web 后台管理员密码的判据。
//
// 这几条规则原本只长在 cmd/nanotun-web 的 package main 里,因为当时只有 /setup 这一个
// 入口收密码。现在 nanotun-admin 也要建 Web 管理员(装机时就把后台账号定下来,不必去抢
// /setup 那个「谁先打开谁是管理员」的窗口),两个入口必须用同一套判据 —— 否则会出现
// 自相矛盾的局面:命令行收下的密码,拿到网页上改密时又被拒,而人完全看不出是哪一层在拒,
// 更看不出该改哪个才对。
//
// 这里只放规则,不放文案:auth 包不认识 i18n,而两个前端各有各的语言目录(web 的
// newLocErr / CLI 的 catZH+catEN)。所以返回的是「哪一条没过」的结构,由调用方翻译。
const (
	MinWebPasswordLen = 12
	MaxWebPasswordLen = 256
	// MinWebPasswordClasses:数字 / 字母 / 符号,至少占两类。挡的是 "aaaaaaaaaaaa"
	// 这种够长但一类字符的密码。
	MinWebPasswordClasses = 2
)

// PasswordIssueKind 是密码不合格的原因。
type PasswordIssueKind int

const (
	PasswordTooShort PasswordIssueKind = iota + 1
	PasswordTooLong
	PasswordBadChars
	PasswordTooFewClasses
)

// PasswordIssue 描述一处不合格。Got 是实际长度,给「至少 12 位,你给了 8 位」这类文案用。
type PasswordIssue struct {
	Kind PasswordIssueKind
	Got  int
}

// CheckWebPassword 检查 Web 后台密码是否够用,合格返回 nil。
//
// 不上 zxcvbn 之类的强度打分,理由与 cmd/nanotun-web/auth.go 顶部那段一致:这是给运维
// 自己用的后台,真实威胁是撞库和字典,而 argon2id + 登录锁定 + 限速已经把爆破成本抬起来了;
// 再苛刻只会把人逼去用密码本上抄的那一个。
//
// 检查顺序(长度 → 字符 → 类别)与历史实现一致:同一个烂密码在两个入口应当报同一条理由。
func CheckWebPassword(p string) *PasswordIssue {
	if len(p) < MinWebPasswordLen {
		return &PasswordIssue{Kind: PasswordTooShort, Got: len(p)}
	}
	if len(p) > MaxWebPasswordLen {
		return &PasswordIssue{Kind: PasswordTooLong, Got: len(p)}
	}
	// 控制字符会在 HTTP 表单、shell 变量、SQL 里各被截断一次,存进去和输进来的很可能
	// 不是同一串 —— 那种账号会以「密码明明对却登不进去」的形式暴露,极难自查。
	if strings.ContainsAny(p, "\n\r\t\x00") {
		return &PasswordIssue{Kind: PasswordBadChars}
	}
	if countPasswordClasses(p) < MinWebPasswordClasses {
		return &PasswordIssue{Kind: PasswordTooFewClasses}
	}
	return nil
}

// countPasswordClasses 数密码里出现了几类字符(数字 / 字母 / 其余一律算符号)。
func countPasswordClasses(p string) int {
	var hasDigit, hasLetter, hasSym bool
	for _, r := range p {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		default:
			hasSym = true
		}
	}
	n := 0
	for _, b := range []bool{hasDigit, hasLetter, hasSym} {
		if b {
			n++
		}
	}
	return n
}
