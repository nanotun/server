package store

import (
	"context"
	"fmt"
	"strings"
)

// AdvertisedHostKey 是 app_settings 表里持久化「服务器对外宣告的展示 label」的 key。
//
// 改名历史:
//   - 0015(2026-05-26):`public_host` → `advertised_host`,语义未变,只是字面更准确
//     —— admin 主动声明 "客户端展示成这个名字"(Kafka `advertised.listeners` / etcd
//     `--initial-advertise-peer-urls` 同款角色)。
//   - 0016(2026-05-26 第六轮):**advertised_host 不再兼任客户端 dial target**,
//     拆出独立 [`ServerDialHostKey`](`server_dial_host`)承担"真实可拨号地址"职责。
//     advertised_host 退化为**纯展示 label**:admin 起任意名字,客户端 UI 副标题展示,
//     不解析、不连接、不验证地址形态。
//
// 拆字段的现场动因:admin 把 advertised_host 配成 `test-203.0.113.10`(意图是带
// 测试前缀的标签),客户端历史上把它塞进 NEPacketTunnelNetworkSettings 的
// `tunnelRemoteAddress` 触发 `Invalid NETunnelNetworkSettings tunnelRemoteAddress`
// 隧道挂掉。本轮起 client dial 改用 [`ServerDialHostKey`](IPv4/IPv6/合法域名 strict
// validation),advertised_host 单纯做 label。
//
// 用途(2026-05-26 第六轮起):
//   - nanotun-web 的 /server-qr 生成服务器 profile QR 时,profile.`advertised_host`
//     字段从这里取(可选,空时 omitempty);
//   - credentials show / web 端 user create / reset PSK 出 QR 时,credentials.host
//     字段从这里取(展示用);
//   - **不再**用于 profile.host(client dial target),那个走 [`ServerDialHostKey`]。
//
// 一次配好后所有 QR / UI 都用同一个 label,语义稳定。server 不验证它指向本机。
const AdvertisedHostKey = "advertised_host"

// GetAdvertisedHost 读 advertised_host setting。空串表示未配置;调用方应 fallback 到
// "请先到 /settings 配置对外接入地址" 类提示,而不是用空字符串去 build profile。
//
// 任何 DB 错误返回 ("", err),让调用方决定是 abort 还是降级。
func (s *Store) GetAdvertisedHost(ctx context.Context) (string, error) {
	v, ok, err := s.SettingsGet(ctx, AdvertisedHostKey)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	return strings.TrimSpace(v), nil
}

// SetAdvertisedHost 写 advertised_host setting。空串视为「清除」,直接写空。
//
// 校验放在调用方(handler)做,这里只做最基本的空白裁剪 + 长度上限。
// 上限 253 字节是 RFC 1035 域名总长极限;IPv4/IPv6 字面量都远短于此。
func (s *Store) SetAdvertisedHost(ctx context.Context, host string) error {
	host = strings.TrimSpace(host)
	if len(host) > 253 {
		return i18nErr("store.advHost.setterTooLong",
			fmt.Sprintf("advertised_host 长度 %d 超过 RFC 1035 上限 253", len(host)), len(host))
	}
	return s.SettingsSet(ctx, AdvertisedHostKey, host)
}

// ValidateAdvertisedHost 校验 advertised_host setting 的格式。
//
// 2026-05-26 第六轮拆字段后,本 setting 退化为**展示 label**(详见
// [`AdvertisedHostKey`] doc);因此 validation 也放宽 —— admin 可以用任意短语作
// label(`prod-jp-1`、`测试机`、`东京 1 号`、`test-203.0.113.10`),客户端不解析、
// 不连接,只 UI 副标题展示。
//
// 仍然拒绝(防 header 注入 / 防误配进 URL):
//   - 包含 scheme(`http://` / `https://` / `ws://` / `wss://`)— label 不应是 URL;
//   - 包含 path / query / fragment(`/x` / `?y` / `#z`)— 防意外路径拼接;
//   - 包含端口号(`host:port` 形态);
//   - 控制字符(`\n` / `\r` / `\t` / NUL)— 防 header / log 注入;
//   - 长度 > 253(沿用 RFC 1035 上限作 sanity bound,label 也没必要更长)。
//
// 允许(本轮新支持的 label 场景,不再拒):
//   - 中文 / Unicode 字符(`测试机`);
//   - 末段纯数字(`test-203.0.113.10` —— 历史踩过坑的字符串,作为 label 现在合法);
//   - 自由短语,只要满足"无 scheme / path / port / 控制字符"。
//
// **关键不变量**:如果你需要的是"客户端实际能 dial 的地址",那个字段叫
// `server_dial_host`,走 [`ValidateServerDialHost`] 的 strict IPv4/IPv6/RFC1035
// 校验。本函数**不再保证** "通过校验的字符串能被 DNS 解析"。
//
// 空串视为合法(等同 "清除")。
func ValidateAdvertisedHost(host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return nil
	}
	if len(h) > 253 {
		return i18nErr("store.host.tooLong",
			fmt.Sprintf("长度 %d 超过 RFC 1035 上限 253", len(h)), len(h))
	}
	if strings.ContainsAny(h, "\n\r\t\x00") {
		return i18nErr("store.host.controlChars", "不允许换行 / TAB / NUL 等控制字符")
	}
	lo := strings.ToLower(h)
	if strings.HasPrefix(lo, "http://") || strings.HasPrefix(lo, "https://") ||
		strings.HasPrefix(lo, "ws://") || strings.HasPrefix(lo, "wss://") {
		return i18nErr("store.host.scheme", "请只填裸地址 / 域名,不要带 scheme(如 https://)")
	}
	if strings.ContainsAny(h, "/?#") {
		return i18nErr("store.host.pathChars", "不允许 path / query / fragment 字符(/、?、#)")
	}
	// IPv6 方括号包裹的情况是 OK 的,只要里面没有 ":port" 后缀
	// 简化处理:IPv6 字面量内部可以有冒号,但 IPv6 + 端口的形如 `[::1]:8080`
	// 才是 host:port,这里我们检测 `]:` 子串。
	if strings.Contains(h, "]:") {
		return i18nErr("store.host.portBracket", "不允许嵌入端口号 — profile 端口字段与 host 是分开的")
	}
	// 对非 IPv6(无 `[`)的情况,出现冒号就大概率是 host:port 或 IPv6 字面量未加括号。
	// 后者(纯 IPv6 文本)地址段中包含冒号但通常 >= 2 个,host:port 只有 1 个冒号且后半段全数字。
	if !strings.HasPrefix(h, "[") {
		if cnt := strings.Count(h, ":"); cnt == 1 {
			parts := strings.SplitN(h, ":", 2)
			if isAllDigit(parts[1]) {
				return i18nErr("store.host.portColon", "不允许嵌入端口号 — 检测到 host:port 形式")
			}
		}
	}
	return nil
}

// isAllDigit 是 ValidateAdvertisedHost 的 host:port 检测辅助。stdlib 的 unicode.IsDigit
// 行为对 ASCII 数字而言已经足够。
func isAllDigit(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
