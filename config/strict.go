package config

// J4(2026-05-22)config TOML strict 校验。
//
// 设计要点(必读):
//
//  1. **向后兼容优先**:默认 lenient,任何未知字段只 WARN 不 fail,
//     升级现有部署不会 break。
//  2. **可显式升级**:环境变量 NANOTUN_CONFIG_STRICT=1 → 任何未知字段直接 fail
//     (适合 CI、admin lint、新集群部署校验)。
//  3. **nanotun-admin config lint** 子命令 = 强制 strict + non-zero exit code,
//     运维可手动跑一次确认配置干净后再升级。
//
// 为什么这样设计:
//   - 用户写 `lease_gc_idle_day = 30`(漏 s)被 toml lib 静默忽略,server 启动看似
//     成功但实际跑默认值 30 天,这是真实出现过的故障;
//   - 直接 strict 升级会让现有 config 全部 break,跟运维体验冲突 ——
//     先 WARN 留 1~2 个版本周期,再考虑改默认。

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// StrictEnvVar 环境变量名:设为 "1"/"true"/"yes" 时未知字段升级为 fatal。
const StrictEnvVar = "NANOTUN_CONFIG_STRICT"

// StrictModeEnabled 检查 env 是否开启 strict。
func StrictModeEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(StrictEnvVar)))
	return v == "1" || v == "true" || v == "yes"
}

// StrictCheck 用 DisallowUnknownFields 第二次 decode 同一份 TOML 数据,
// 返回任何未知字段错误。**不修改** out。
//
// 调用方:
//   - server.loadConfig 已 lenient 解析成功后再走一遍 strict,失败按 strict 模式
//     决定 WARN or fatal;
//   - nanotun-admin config lint 直接调用本函数。
func StrictCheck(data []byte) error {
	var probe Config
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&probe); err != nil {
		var sErr *toml.StrictMissingError
		if errors.As(err, &sErr) {
			// StrictMissingError.String() 含未知字段的完整路径与位置,直接用。
			return fmt.Errorf("未知字段(疑似拼写错误或废弃配置):\n%s", sErr.String())
		}
		// 其它解析错误(语法错 / 类型错):理论上 lenient 已经报过,这里二次报无害。
		return err
	}
	return nil
}
