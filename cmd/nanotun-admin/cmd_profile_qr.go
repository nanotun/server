package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/mdp/qrterminal/v3"
	qrcode "github.com/skip2/go-qrcode"
)

// defaultQRPNGPixels PNG 边长(像素)。
//
// 历史:
//   - 256(2026-05 初):small profile (无 Hy2 mTLS) v ≈ 15 时还行,但 server-
//     profile + Hy2 mTLS 压到 v40(177×177 modules),256/177 ≈ 1.45 px/module,
//     截图二次压缩后边缘糊,iOS 相机识别率掉到 60%。
//   - 384(2026-05-26 第二轮):升到 2.17 px/module,屏幕直显能扫,但**跨屏摄像头
//     拍**仍偶现失败(用户反馈)— 主因是 HTML img 用 width="320" 反向缩小渲染,
//     浏览器 bilinear 0.83× 子像素采样让 module 边缘进一步糊。
//   - 1024(2026-05-26 第六轮):提到 5.78 px/module 原生密度,配合
//     server_qr_revealed.html 显式 width="512"(PNG 1024 → CSS 512 = 精确 2:1
//     downscale,Retina HDPI 屏直接 1:1 显示 1024 物理像素)。跨屏 + 普通屏 +
//     高 DPI 屏三类全覆盖。
//
// PNG 文件代价:1024×1024 1-bit colormap ≈ 18–25 KB,inline data: URL base64
// 后 ~30 KB,对浏览器渲染零压力;CLI 生成耗时仍 < 50 ms。
const defaultQRPNGPixels = 1024

// qrLowMaxURLBytes 是 v40-L (lowest practical level) 在 Byte mode 下可塞进 QR
// 的近似上限。ISO/IEC 18004 给的硬上限是 2953,但 go-qrcode 内部还要算 mode
// indicator / char count indicator / EC codewords,实际可用 ~2900 出头。
// 这里取 2900 做保守阈值,超过就直接给明确错误,而不是让 go-qrcode 抛
// "content too long to encode" 这种模糊提示。
const qrLowMaxURLBytes = 2900

// profileToURL 把 profile 编成 `nanotun://v{1|2}?d=<base64url(json)>`，与 writeURL 一致。
func profileToURL(p *profileSchema) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	return profileURLPrefixFor(p) + encoded, nil
}

// writeQRTerminal 在终端输出可扫的二维码(编码内容为 nanotun:// URL)。
//
// 容量与降级(2026-05-26):qrterminal 内部用 rsc.io/qr,编码失败时 **silently**
// 不输出任何内容(无 error,看不到提示),server profile 含 hy2 mTLS PEM 时
// URL ~2500 字节直接超 v40-M 上限 2331,直接走老路径 = admin 看到一片空白
// 不知发生啥。修法:调用前先用 go-qrcode.New 预试,失败时降级 qrterminal.L
// 并打 [warn]。super-long(>2900)直接给明确错误,不浪费 qrterminal 一次。
//
// 保留 qrterminal(而非全替 go-qrcode.ToSmallString):qrterminal 的 BlackChar
// / WhiteChar 用 ANSI 背景色 \033[40m / \033[47m 强制黑/白渲染,在深色终端
// (Terminal.app / iTerm dark theme)下也能正确扫码;go-qrcode 的 ToSmallString
// 只输出 Unicode 半块字符 ▀▄,前景色随终端主题反转 → 深色终端扫不到。
func writeQRTerminal(opts *globalOpts, w io.Writer, url string) error {
	if len(url) > qrLowMaxURLBytes {
		return newLocErr("profileqr.terminalOverflow", len(url), qrLowMaxURLBytes)
	}
	level := qrterminal.M
	if _, err := qrcode.New(url, qrcode.Medium); err != nil {
		// 预试 Medium 失败 → 试 Low。
		if _, errLow := qrcode.New(url, qrcode.Low); errLow != nil {
			return newLocErr("profileqr.terminalBothFail", err.Error(), errLow.Error())
		}
		level = qrterminal.L
		fmt.Fprintln(w, opts.T("profileqr.terminalDowngrade", len(url)))
	}
	qrterminal.GenerateWithConfig(url, qrterminal.Config{
		Level:     level,
		Writer:    w,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
	})
	_, err := io.WriteString(w, "\n")
	return err
}

// writeQRPNG 把 nanotun:// URL 写入 PNG 文件（供手机相册扫码或 M2 admin UI 下载）。
//
// 纠错级别策略(2026-05-26):
//  1. 先尝试 Medium(15% 纠错,行业默认);
//  2. Medium 容量超(v40-M 上限 ~2331 bytes,server profile 含 hy2 mTLS PEM 时
//     base64 后常 ~2.5KB)→ 自动降级 Low(7% 纠错,v40-L 上限 ~2953 bytes);
//  3. 连 Low 都装不下(> qrLowMaxURLBytes)→ 直接返回明确错误,避免让 caller
//     看到 go-qrcode 抛的「content too long to encode」模糊提示。
//
// 安全权衡:Low 纠错只能恢复 7% 损坏区域;但 server-profile / credentials QR
// 都是 admin 在 web 后台显示 / 扫自己手机,环境受控,7% 完全够。
func writeQRPNG(opts *globalOpts, path, url string) error {
	if len(url) > qrLowMaxURLBytes {
		return newLocErr("profileqr.pngOverflow", path, len(url), qrLowMaxURLBytes)
	}
	err := qrcode.WriteFile(url, qrcode.Medium, defaultQRPNGPixels, path)
	if err != nil {
		// go-qrcode 把所有 "too long" 都归到 errors.New("content too long to encode")。
		// 降级 Low 重试一次。
		errLow := qrcode.WriteFile(url, qrcode.Low, defaultQRPNGPixels, path)
		if errLow != nil {
			return newLocErr("profileqr.pngBothFail", path, err.Error(), errLow.Error())
		}
		// 写到 stderr 让运维看到 ——admin CLI 是 fork by nanotun-web 时,这条
		// stderr 进 web logrus,事后审计可查「这次 QR 降级了 Low」。
		fmt.Fprintln(opts.stderr, opts.T("profileqr.pngDowngrade", len(url)))
		return os.Chmod(path, 0o600)
	}
	return os.Chmod(path, 0o600)
}
