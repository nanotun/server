package main

// captcha.go - 登录 / setup 页的数字图形验证码(P3:防自动化暴力撞库)。
//
// 设计要点:
//   1) **零外部依赖**:画图只用 stdlib(image/png + math/rand);字体是
//      手画的 5×7 像素位图,N=10 张表覆盖 0..9。够看清楚 + 够防 OCR
//      初级脚本就行,本意不是对抗专门 CV 攻击(那个用 TOTP/锁号才靠谱)。
//
//   2) **无 server state**:答案不写库不写内存,而是 HMAC 签到 cookie 里。
//      cookie payload = SHA256(answer || nonce || key) | exp | nonce | HMAC。
//      校验时 server 拿用户输入算同样 hash 跟 cookie 里的对比,匹配则通过。
//      跟 pending2FA cookie 同模式,复用 SessionService 已有的 HMAC 模式。
//
//   3) **一次性**:验通 / 验失 都立刻 ClearCaptcha + 在 retry 页重签新 cookie。
//      防止 attacker 拿到一对 (cookie, answer) 后无限重放。
//
//   4) **过期**:5 分钟。够人填,attacker 也没什么余地批量预算 hash 字典
//      (4 位数字 1 万种,本来就是少量爆破 - 关键是限频 + 一次性 + 跟密码锁号
//      叠加,而不是 captcha 单独抗千次/秒)。

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	mathrand "math/rand"
	"net/http"
	"strings"
	"time"
)

const (
	captchaCookieName = "nanotun-web_captcha"
	captchaTTLSec     = int64(5 * 60)

	// 答案位数。4 位:1 万种,人快速能输入完;爆破成本 = 1/10000 * 限频上限。
	captchaDigits = 4

	// 画图尺寸。120×40 在桌面 + 移动都好看,放进 .field 不挤。
	captchaW = 130
	captchaH = 44
)

// =============================================================================
// 5×7 位图字体:0..9
//
// 每行一个 byte,从 bit4 (=最高位) 开始向 bit0 ,1 = 黑,0 = 透明。
// 字符宽 5 高 7。最初是常见 8-bit micro 时代字体的精简版,字符可读性优先。
// =============================================================================

// digitGlyph[d] 是一张 7 行的位图。每行只用低 5 位。
var digitGlyph = [10][7]uint8{
	// 0
	{0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110},
	// 1
	{0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110},
	// 2
	{0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111},
	// 3
	{0b11110, 0b00001, 0b00001, 0b01110, 0b00001, 0b00001, 0b11110},
	// 4
	{0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010},
	// 5
	{0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110},
	// 6
	{0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110},
	// 7
	{0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000},
	// 8
	{0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110},
	// 9
	{0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100},
}

// =============================================================================
// 公开 API:生成 + 校验
// =============================================================================

// CaptchaChallenge 是 IssueCaptcha 返回的视图模型。
// Cookie 已经 SetCookie 到 ResponseWriter,模板只需要把 DataURL 嵌进 <img>。
type CaptchaChallenge struct {
	// 显式用 template.URL —— html/template 默认对 <img src> 的 URL context
	// 做协议白名单(只许 http/https/mailto/tel/ftp);data: 不在白名单,会被
	// 替换成 "#ZgotmplZ" 让图片显示成 broken icon。template.URL 是「我信任
	// 这串,别 sanitize」的显式信号,与 me_totp_setup 那边的 QRDataURL 同套。
	DataURL template.URL
}

// IssueCaptcha 生成一个新 captcha:
//   - 抽 captchaDigits 位数字做答案
//   - 画 PNG → base64 data: URL
//   - 写 cookie(里面是 hash(answer)+nonce+exp+HMAC)
//
// 返回 CaptchaChallenge 给模板嵌图。
func (s *SessionService) IssueCaptcha(w http.ResponseWriter) (CaptchaChallenge, error) {
	answer, err := randomDigits(captchaDigits)
	if err != nil {
		return CaptchaChallenge{}, err
	}
	pngBytes, err := renderCaptchaPNG(answer)
	if err != nil {
		return CaptchaChallenge{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return CaptchaChallenge{}, err
	}
	exp := nowUnix() + captchaTTLSec

	cookieVal := encodeCaptchaCookie(s.captchaHMACKey, answer, nonce, exp)
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(captchaCookieName), // 第七轮深扫 MED:__Host- 前缀防同注册域 cookie-tossing 预置验证码
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(captchaTTLSec),
	})
	return CaptchaChallenge{
		DataURL: template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes)),
	}, nil
}

// VerifyCaptcha 比对用户提交的 userAnswer 与 cookie 里的 hash。
//
// 错误情形:
//   - cookie 不在 / 解码失败 / HMAC 不匹配 → ErrCaptchaInvalid
//   - cookie 已过期 → ErrCaptchaExpired
//   - hash 不匹配 → ErrCaptchaWrong
//
// 这些错误分得清是给 handler 写 audit 用的,**对用户统一展示同一个错误信息**,
// 避免侧信道告诉 attacker 是 cookie 没了还是答案错了。
//
// **重要**:任何一种错误,handler 都应该在 retry 页 IssueCaptcha 一张新的,
// 旧 cookie 不再可用。
var (
	ErrCaptchaInvalid = errors.New("captcha: invalid cookie")
	ErrCaptchaExpired = errors.New("captcha: expired")
	ErrCaptchaWrong   = errors.New("captcha: wrong answer")
	ErrCaptchaReplay  = errors.New("captcha: already used")
)

func (s *SessionService) VerifyCaptcha(r *http.Request, userAnswer string) error {
	ck, err := r.Cookie(s.cookieName(captchaCookieName))
	if err != nil || ck.Value == "" {
		return ErrCaptchaInvalid
	}
	nonce, exp, expectedHash, ok := decodeCaptchaCookie(s.captchaHMACKey, []byte(ck.Value))
	if !ok {
		return ErrCaptchaInvalid
	}
	if exp <= nowUnix() {
		return ErrCaptchaExpired
	}
	// 一次性消费:cookie 真实且未过期后**立即**烧掉该 nonce —— 无论后续答案对错(第三轮深扫 L8)。
	//
	// 此前仅在答案**正确**时才 LoadOrStore(nonce),留下致命窗口:attacker 攥着一张截获(或自己领取)
	// 的 captcha cookie,可在 5min TTL 内用同一 nonce 反复提交不同答案暴破 4 位数字(10^4 空间),
	// captcha 形同虚设。改为验证 cookie 签名 + 未过期后立刻消费:每张 captcha 只准一次校验尝试,
	// 答错即作废,retry 必须重新领图(受 GET 限流 / 自适应 PoW 约束)。LoadOrStore 让并发提交同 nonce
	// 也只有一次赢,其余判重放。
	if _, loaded := s.captchaUsed.LoadOrStore(string(nonce), exp); loaded {
		return ErrCaptchaReplay
	}
	got := normalizeAnswer(userAnswer)
	if got == "" {
		return ErrCaptchaWrong
	}
	// 拿用户输入 + 同 nonce / key,算同样 hash,跟 cookie 里 hash 比;
	// 常量时间比对避免 timing 泄漏(对 4 位 captcha 实际意义不大,
	// 但跟 pending2fa / CSRF 比对的姿态保持一致更卫生)。
	gotHash := answerHash(s.captchaHMACKey, got, nonce)
	if subtle.ConstantTimeCompare(gotHash, expectedHash) != 1 {
		return ErrCaptchaWrong
	}
	return nil
}

// ClearCaptcha 让 cookie 立刻失效。验通 / 验失 都该调一次,保证一次性。
func (s *SessionService) ClearCaptcha(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(captchaCookieName),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// =============================================================================
// cookie 编解码
// =============================================================================
//
// payload(64 字节):
//   [0..32)   answerHash = SHA256(answer || nonce || key)
//   [32..40)  exp big-endian uint64
//   [40..56)  nonce 16B
// HMAC(32B) 接在 payload 后,总 96 字节,base64url 编码 ≈ 128 字符。
//
// 注意:答案本身**不进 cookie**,只有 hash 进。即使用户主动让 attacker 看到自己
// cookie,attacker 也只能爆 4 位数字字典对比 hash —— 反正 attacker 可以直接
// 在自己浏览器里 GET /login 拿一张图自己看,这层 hash 不是关键防御,主要是让
// captcha cookie 不顺手就泄露明文答案给 logging / CDN / 浏览器扩展。

const (
	captchaHashLen = sha256.Size
	captchaExpLen  = 8
	captchaNonceLn = 16
	captchaPayLen  = captchaHashLen + captchaExpLen + captchaNonceLn // 56
	captchaSigLen  = sha256.Size                                     // 32
	captchaCookieB = captchaPayLen + captchaSigLen                   // 88
)

func encodeCaptchaCookie(key []byte, answer string, nonce []byte, exp int64) string {
	if len(nonce) != captchaNonceLn {
		panic("encodeCaptchaCookie: nonce must be 16B")
	}
	hash := answerHash(key, answer, nonce)

	payload := make([]byte, captchaPayLen)
	copy(payload[0:captchaHashLen], hash)
	binary.BigEndian.PutUint64(payload[captchaHashLen:captchaHashLen+captchaExpLen], uint64(exp))
	copy(payload[captchaHashLen+captchaExpLen:], nonce)

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	sig := mac.Sum(nil)

	full := make([]byte, 0, captchaCookieB)
	full = append(full, payload...)
	full = append(full, sig...)
	return base64.RawURLEncoding.EncodeToString(full)
}

// decodeCaptchaCookie 不返回 answer 明文(cookie 里本来就没有);
// 返回 "answer-equivalence":即 hash 字节本身,以及 exp。caller 拿用户输入
// 自己算 hash 来对比 — 这里返回 hash 是为了让 VerifyCaptcha 调用方便。
//
// 为了避免改 VerifyCaptcha 内部签名,实际改为内部计算:
//   - 取出 nonce + exp + hash
//   - 我们在 Verify 里:用「用户的答案 + nonce + key」再算一遍 hash,
//     与 cookie 里的对比。
//
// 所以 decode 应该返回 (nonce, exp, expectedHash, ok)。改下函数签名:
func decodeCaptchaCookie(key, cookieVal []byte) (nonce []byte, exp int64, expected []byte, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(string(cookieVal))
	if err != nil || len(raw) != captchaCookieB {
		return nil, 0, nil, false
	}
	payload := raw[:captchaPayLen]
	sig := raw[captchaPayLen:]

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	want := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sig, want) != 1 {
		return nil, 0, nil, false
	}

	expected = make([]byte, captchaHashLen)
	copy(expected, payload[0:captchaHashLen])
	exp = int64(binary.BigEndian.Uint64(payload[captchaHashLen : captchaHashLen+captchaExpLen]))
	nonce = make([]byte, captchaNonceLn)
	copy(nonce, payload[captchaHashLen+captchaExpLen:])
	return nonce, exp, expected, true
}

func answerHash(key []byte, answer string, nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte("nanotun-web_captcha_v1:"))
	h.Write([]byte(normalizeAnswer(answer)))
	h.Write([]byte{0})
	h.Write(nonce)
	h.Write([]byte{0})
	h.Write(key)
	return h.Sum(nil)
}

// =============================================================================
// 画图
// =============================================================================
//
// 简单 + 抗 100% 字符切割初级脚本就够。流程:
//   1) 白底
//   2) 散一些灰色噪点(背景)
//   3) 4 个数字逐位画到固定 cell,叠加 1~2 像素随机 jitter
//   4) 画两条随机灰色斜线穿过画布
//   5) PNG 编码
//
// 颜色选择:数字用深灰(#333),不是纯黑,避免与噪点对比太硬;
// 噪点和干扰线用中灰 ~#888,人能轻松忽略,OCR 容易把它当字符笔画。

var (
	colWhite = color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	colDigit = color.RGBA{0x20, 0x20, 0x28, 0xFF}
	colNoise = color.RGBA{0xA0, 0xA0, 0xA8, 0xFF}
	colLine  = color.RGBA{0x70, 0x70, 0x78, 0xFF}
)

func renderCaptchaPNG(answer string) ([]byte, error) {
	digits := normalizeAnswer(answer)
	if len(digits) != captchaDigits {
		return nil, fmt.Errorf("captcha: expect %d digits, got %d", captchaDigits, len(digits))
	}
	img := image.NewRGBA(image.Rect(0, 0, captchaW, captchaH))

	// 白底。
	for y := 0; y < captchaH; y++ {
		for x := 0; x < captchaW; x++ {
			img.Set(x, y, colWhite)
		}
	}

	// 用一个独立 PRNG 给当前图的扰动用 —— 不用 crypto/rand,这部分不影响安全,
	// 抽 4 位答案那里才用 crypto/rand。math/rand seed 用 unix nano + 答案,
	// 反正每张图 nonce 不同,扰动也不一样就行。
	r := mathrand.New(mathrand.NewSource(time.Now().UnixNano() ^ int64(digits[0])<<8 ^ int64(digits[len(digits)-1])))

	// 1) 噪点。
	noiseCount := 80
	for i := 0; i < noiseCount; i++ {
		px := r.Intn(captchaW)
		py := r.Intn(captchaH)
		img.Set(px, py, colNoise)
	}

	// 2) 数字。每位 cell 宽 = (W - 左右各 8 边距) / N。
	scale := 3 // 5x7 字符 → 15x21 像素;
	leftMargin := 12
	cellW := (captchaW - leftMargin*2) / captchaDigits

	for i, ch := range digits {
		d := int(ch - '0')
		if d < 0 || d > 9 {
			continue
		}
		// 单位水平/竖直 jitter:让排列不像栅格。
		jx := r.Intn(3) - 1
		jy := r.Intn(5) - 2
		cellLeft := leftMargin + i*cellW + (cellW-5*scale)/2 + jx
		cellTop := (captchaH-7*scale)/2 + jy
		drawGlyph(img, cellLeft, cellTop, scale, digitGlyph[d])
	}

	// 3) 干扰线。2 条贯穿全图,起点 / 终点都在边缘随机。
	for k := 0; k < 2; k++ {
		x0, y0 := r.Intn(captchaW/4), r.Intn(captchaH)
		x1, y1 := captchaW-1-r.Intn(captchaW/4), r.Intn(captchaH)
		drawLine(img, x0, y0, x1, y1, colLine)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawGlyph 把 5×7 位图按 scale 倍数画到 (x,y) 处。
func drawGlyph(img *image.RGBA, x, y, scale int, glyph [7]uint8) {
	for row := 0; row < 7; row++ {
		bits := glyph[row]
		for col := 0; col < 5; col++ {
			// 第 col 列对应 bit (4 - col)
			if (bits>>(4-uint(col)))&1 == 1 {
				// 画一个 scale×scale 块。
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						img.Set(x+col*scale+dx, y+row*scale+dy, colDigit)
					}
				}
			}
		}
	}
}

// drawLine 简易 Bresenham — 标准实现,不写注释解释算法本身。
func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	dx := absInt(x1 - x0)
	dy := -absInt(y1 - y0)
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	err := dx + dy
	for {
		if inBounds(img, x0, y0) {
			img.Set(x0, y0, c)
		}
		if x0 == x1 && y0 == y1 {
			return
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func inBounds(img *image.RGBA, x, y int) bool {
	b := img.Bounds()
	return x >= b.Min.X && x < b.Max.X && y >= b.Min.Y && y < b.Max.Y
}

// =============================================================================
// helpers
// =============================================================================

// randomDigits 用 crypto/rand 抽 n 位 0..9。安全度跟 4 位 captcha 本身的
// 抗暴力度等同(1/10000),用 crypto/rand 是为了避免 math/rand 全局 seed
// 被复用导致同一秒多请求碰撞。
func randomDigits(n int) (string, error) {
	if n <= 0 || n > 16 {
		return "", errors.New("captcha: bad digit count")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.Grow(n)
	for _, b := range buf {
		sb.WriteByte('0' + (b % 10))
	}
	return sb.String(), nil
}

// normalizeAnswer 把用户输入压成纯数字串(去空格、去非数字)。
// 用户在手机上输入很容易带个空格,不能因此拒答。
func normalizeAnswer(in string) string {
	var sb strings.Builder
	sb.Grow(len(in))
	for _, r := range in {
		if r >= '0' && r <= '9' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
