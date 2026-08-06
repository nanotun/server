package store

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxUsernameRunes 是用户名长度上限。够长到容纳邮箱式的名字,又不至于把表格撑烂、
// 把随二维码分发的档案撑大。
const MaxUsernameRunes = 64

// ValidateUsername 拦掉会让文本视图失真的用户名。
//
// 起因是名字里的**内嵌控制字符**能实打实地骗过运维的眼睛(首尾空白已由调用方 TrimSpace
// 收敛,这里管的是中间的):
//
//   - "a\nb" 会把 `user list` 撑成两行,凭空多出一个并不存在的用户;按行解析的脚本
//     跟着一起错。
//   - "alice\rEVIL" 在真终端里回车覆盖,整行显示成 EVIL,审计时看到的和库里存的不是
//     一回事。
//   - 名字里的 ANSI 转义会原样重放进运维的终端,能改颜色、擦行、移光标。
//
// 与本文件上游那次收敛(裁剪首尾空白 + 大小写去重,理由同样是「同名歧义、可被用来伪装」)
// 是同一条线。放在 store 层是因为 CLI 和 Web 两条创建路径都要过这里。
//
// 只在写入时校验:已有部署里的历史用户名不受影响,不会让升级后的启动迁移翻车。
func ValidateUsername(name string) error {
	if name == "" {
		return errors.New("store: empty username")
	}
	if n := utf8.RuneCountInString(name); n > MaxUsernameRunes {
		return fmt.Errorf("store: username too long (%d chars, max %d)", n, MaxUsernameRunes)
	}
	if !utf8.ValidString(name) {
		return errors.New("store: username is not valid UTF-8")
	}
	for _, r := range name {
		// C0 / DEL / C1:换行、回车、制表、ESC 都在其中。中文等可打印字符不受影响。
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return fmt.Errorf("store: username must not contain control characters (found %q)", r)
		}
	}
	if strings.ContainsRune(name, '\u0000') {
		return errors.New("store: username must not contain NUL")
	}
	return nil
}

// SanitizeDeviceName 抹掉设备名里的控制字符,后果与用户名那边一样:换行会把 `device list`
// 撑成两行、回车会覆盖整行、ANSI 转义会重放进运维的终端。
//
// 这里**过滤而不是拒绝**,和用户名的处理有意不同:用户名是管理员当场敲的,报错他立刻能改;
// 设备名却是客户端登录时上报的(auth_login.go → UpsertDevice),多半就是机器的 hostname。
// 因为主机名里有个怪字符就把人挡在网外,代价远大于收益 —— 何况这条路径上没人能看见错误。
//
// 更要紧的是这里跨了权限边界:设备名由普通用户的客户端提供,却渲染在管理员的终端里。
// 用户名只有管理员能写,设备名不是。
func SanitizeDeviceName(name string) string {
	if name == "" {
		return ""
	}
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, name)
	// 抹完可能只剩空白(比如整个名字就是一串 \r\n),归一成空,交由上游的重名/占位逻辑处理。
	return strings.TrimSpace(cleaned)
}
