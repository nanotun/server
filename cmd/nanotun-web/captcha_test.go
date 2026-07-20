package main

import (
	"bytes"
	"crypto/rand"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 拿一个最小可用 SessionService 实例,只填充 captcha 必需字段。
// 用全 0 key 是 deterministic — 这里**只用在测试**,生产路径走 NewSessionService
// 的 crypto/rand 派生 key。
func newCaptchaTestService() *SessionService {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &SessionService{
		cookieSecure:   false, // 测试不走 https
		captchaHMACKey: key,
	}
}

// 拼 cookie 到 *http.Request 上 — httptest.ResponseRecorder 拿到的是
// SetCookie 设置的响应头,我们要把它"回送"成下一个请求的 Cookie 头。
func cookiesFromRecorder(rec *httptest.ResponseRecorder, req *http.Request) {
	resp := rec.Result()
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		// MaxAge<0 表示删除 — 跳过,模拟浏览器把它清掉。
		if c.MaxAge < 0 {
			continue
		}
		req.AddCookie(c)
	}
}

// TestRenderCaptchaPNG_Header 验证渲染出来的是合法 PNG,字符数对齐。
func TestRenderCaptchaPNG_Header(t *testing.T) {
	for _, a := range []string{"0000", "1234", "9876", "5555"} {
		b, err := renderCaptchaPNG(a)
		if err != nil {
			t.Fatalf("answer=%q render: %v", a, err)
		}
		if !bytes.HasPrefix(b, []byte{0x89, 0x50, 0x4E, 0x47}) {
			t.Fatalf("answer=%q: not a PNG (header=%x)", a, b[:4])
		}
		img, err := png.Decode(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("answer=%q: png decode: %v", a, err)
		}
		if img.Bounds().Dx() != captchaW || img.Bounds().Dy() != captchaH {
			t.Fatalf("answer=%q: bounds %dx%d, want %dx%d",
				a, img.Bounds().Dx(), img.Bounds().Dy(), captchaW, captchaH)
		}
	}
}

func TestRenderCaptchaPNG_WrongDigitCount(t *testing.T) {
	if _, err := renderCaptchaPNG("123"); err == nil {
		t.Fatal("want error for 3-digit answer, got nil")
	}
	if _, err := renderCaptchaPNG("12345"); err == nil {
		t.Fatal("want error for 5-digit answer, got nil")
	}
}

// TestRandomDigits_Distribution 不严格做 χ²,只确认输出全是数字 + 长度对。
func TestRandomDigits_Distribution(t *testing.T) {
	seen := map[byte]int{}
	for i := 0; i < 200; i++ {
		s, err := randomDigits(4)
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != 4 {
			t.Fatalf("len=%d want 4: %q", len(s), s)
		}
		for j := 0; j < len(s); j++ {
			if s[j] < '0' || s[j] > '9' {
				t.Fatalf("non-digit %q in %q", s[j], s)
			}
			seen[s[j]]++
		}
	}
	// 至少看到 5 种不同数字 — 200 次抽样下纯随机出现 <5 种概率几乎为 0。
	if len(seen) < 5 {
		t.Fatalf("digit coverage too low: %v", seen)
	}
}

func TestNormalizeAnswer(t *testing.T) {
	cases := map[string]string{
		"1234":      "1234",
		" 1 2 3 4 ": "1234",
		"abc12":     "12",
		"":          "",
		"42 X 7":    "427",
	}
	for in, want := range cases {
		got := normalizeAnswer(in)
		if got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCaptcha_RoundTrip:Issue 写 cookie + 模板拿到 DataURL,
// 用对的答案 Verify 通过。
func TestCaptcha_RoundTrip(t *testing.T) {
	s := newCaptchaTestService()

	// Issue 时把 cookie 写到 rec;我们再"假装"知道答案 — 测试里只能从渲染的
	// PNG 反推太昂贵,直接走构造内部:用同样 nonce/exp/key 重算 cookie 即可
	// 实际可信测正确路径(Verify 正答案过、错答案不过)。
	rec := httptest.NewRecorder()
	// 手工构造一对 (answer, cookie):
	nonce := make([]byte, 16)
	rand.Read(nonce)
	answer := "4271"
	exp := time.Now().Unix() + 60
	cookieVal := encodeCaptchaCookie(s.captchaHMACKey, answer, nonce, exp)

	req := httptest.NewRequest("POST", "/login", nil)
	req.AddCookie(&http.Cookie{Name: captchaCookieName, Value: cookieVal})

	if err := s.VerifyCaptcha(req, answer); err != nil {
		t.Fatalf("verify correct answer: %v", err)
	}

	// 服务端一次性消费:同一张 captcha(同 nonce)第二次提交,即便答案正确也应
	// 被判重放拒绝(防截获 cookie+answer 后重放试不同密码)。
	if err := s.VerifyCaptcha(req, answer); err != ErrCaptchaReplay {
		t.Fatalf("replay same captcha: want ErrCaptchaReplay, got %v", err)
	}

	// 换一张全新的 (answer, cookie) 验错答案 → ErrCaptchaWrong;验对答案 + 空格归一 → 通过。
	nonce2 := make([]byte, 16)
	rand.Read(nonce2)
	cookieVal2 := encodeCaptchaCookie(s.captchaHMACKey, answer, nonce2, exp)
	req2 := httptest.NewRequest("POST", "/login", nil)
	req2.AddCookie(&http.Cookie{Name: captchaCookieName, Value: cookieVal2})
	if err := s.VerifyCaptcha(req2, "0000"); err != ErrCaptchaWrong {
		t.Fatalf("verify wrong answer: want ErrCaptchaWrong, got %v", err)
	}
	// 错答案不消费 nonce,同一张图输对(带空格)仍应通过。
	if err := s.VerifyCaptcha(req2, " 4 2 7 1 "); err != nil {
		t.Fatalf("verify with spaces: %v", err)
	}

	_ = rec // 占位,后面其它子用例会用 recorder 走 IssueCaptcha 路径
}

// TestCaptcha_FullIssueVerify:走 IssueCaptcha 把 cookie 写进 ResponseWriter,
// 然后我们**不知道答案** —— 模拟 attacker;Verify 任何答案应当都 fail
// (除非恰好猜中,4 位数字 1/10000 概率,本测试取 10000 次内 90% 大概率不中)。
// 重点验证:cookie 有效签名 + Verify wrong 不会误判通过。
func TestCaptcha_FullIssueVerify(t *testing.T) {
	s := newCaptchaTestService()

	rec := httptest.NewRecorder()
	if _, err := s.IssueCaptcha(rec); err != nil {
		t.Fatalf("issue: %v", err)
	}
	req := httptest.NewRequest("POST", "/login", nil)
	cookiesFromRecorder(rec, req)

	// 没有 cookie 的请求
	emptyReq := httptest.NewRequest("POST", "/login", nil)
	if err := s.VerifyCaptcha(emptyReq, "1234"); err != ErrCaptchaInvalid {
		t.Fatalf("no cookie: want ErrCaptchaInvalid, got %v", err)
	}

	// 任意答案 — 不应通过(除非中签)。统计 12 个明显错答案。
	// 若碰巧中签,nonce 被一次性消费,后续同 cookie 提交会得 ErrCaptchaReplay,
	// 同样算"没通过"。
	wrongCount := 0
	for _, ans := range []string{"0000", "1111", "2222", "3333", "4444", "5555",
		"6666", "7777", "8888", "9999", "1234", "9876"} {
		err := s.VerifyCaptcha(req, ans)
		if err == ErrCaptchaWrong || err == ErrCaptchaReplay {
			wrongCount++
		} else if err != nil {
			t.Fatalf("unexpected err on %q: %v", ans, err)
		}
	}
	// 至少 11 / 12 应当 Wrong(只有 1 中签的概率极低)。
	if wrongCount < 11 {
		t.Fatalf("too few wrongs (%d/12) — verify too permissive?", wrongCount)
	}
}

// TestCaptcha_Expired:把 exp 设成过去,应当返回 ErrCaptchaExpired。
func TestCaptcha_Expired(t *testing.T) {
	s := newCaptchaTestService()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	cookieVal := encodeCaptchaCookie(s.captchaHMACKey, "1234", nonce, time.Now().Unix()-1)

	req := httptest.NewRequest("POST", "/login", nil)
	req.AddCookie(&http.Cookie{Name: captchaCookieName, Value: cookieVal})

	if err := s.VerifyCaptcha(req, "1234"); err != ErrCaptchaExpired {
		t.Fatalf("expired cookie: want ErrCaptchaExpired, got %v", err)
	}
}

// TestCaptcha_TamperHMAC:翻转 cookie 内任一字节,签名不再合法。
func TestCaptcha_TamperHMAC(t *testing.T) {
	s := newCaptchaTestService()
	nonce := make([]byte, 16)
	rand.Read(nonce)
	cookieVal := encodeCaptchaCookie(s.captchaHMACKey, "1234", nonce, time.Now().Unix()+60)
	// 翻转最后一字节(签名区)。
	tampered := []byte(cookieVal)
	if len(tampered) == 0 {
		t.Fatal("empty cookie")
	}
	tampered[len(tampered)-1] ^= 0x01

	req := httptest.NewRequest("POST", "/login", nil)
	req.AddCookie(&http.Cookie{Name: captchaCookieName, Value: string(tampered)})

	if err := s.VerifyCaptcha(req, "1234"); err != ErrCaptchaInvalid {
		t.Fatalf("tampered cookie: want ErrCaptchaInvalid, got %v", err)
	}
}

// TestCaptcha_KeyIsolation:同样 cookie 内容、不同 key 校验失败 → 证明 HMAC
// key 真的是隔离的(从而 captchaHMACKey 与 pendingHMACKey 不能互通)。
func TestCaptcha_KeyIsolation(t *testing.T) {
	a := newCaptchaTestService()
	b := newCaptchaTestService() // 独立随机 key
	nonce := make([]byte, 16)
	rand.Read(nonce)
	cookieVal := encodeCaptchaCookie(a.captchaHMACKey, "1234", nonce, time.Now().Unix()+60)
	req := httptest.NewRequest("POST", "/login", nil)
	req.AddCookie(&http.Cookie{Name: captchaCookieName, Value: cookieVal})

	if err := b.VerifyCaptcha(req, "1234"); err != ErrCaptchaInvalid {
		t.Fatalf("cross-key: want ErrCaptchaInvalid, got %v", err)
	}
}

// TestCaptcha_ClearCookie:ClearCaptcha 后再 Verify 拿不到 cookie → Invalid。
func TestCaptcha_ClearCookie(t *testing.T) {
	s := newCaptchaTestService()
	rec := httptest.NewRecorder()
	s.ClearCaptcha(rec)
	// 验证返回的 Set-Cookie MaxAge<0(浏览器会立即删)。
	found := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == captchaCookieName && c.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		dump := rec.Header().Get("Set-Cookie")
		t.Fatalf("clear didn't set MaxAge<0 cookie; got: %q", dump)
	}
}

// TestCaptcha_DigitGlyphs:位图表全 10 张都不能空、行宽 5、行数 7。
func TestCaptcha_DigitGlyphs(t *testing.T) {
	for d := 0; d < 10; d++ {
		g := digitGlyph[d]
		// 至少有一行有像素被点亮。
		anyOn := false
		for row := 0; row < 7; row++ {
			if g[row] != 0 {
				anyOn = true
			}
			if g[row]>>5 != 0 {
				t.Errorf("digit %d row %d: high bits set (%05b) — 只允许低 5 位",
					d, row, g[row])
			}
		}
		if !anyOn {
			t.Errorf("digit %d: all rows zero — 空字模会被画成空白", d)
		}
	}
}

// 防 import 集 trim — strings 在 normalize 已用,这条 Sanity check 已经隐式覆盖。
var _ = strings.Builder{}
