package util

// credentials_url.go(2026-05-25,0013):「profile / credentials 解耦」共享 wire format。
//
// 之前 admin CLI (nanotun-admin/cmd_credentials.go) 与 web 管理后台 (nanotun-web)
// 各自序列化 `nanotun-cred://v1?d=<base64url(json)>` 的话两边格式定义容易漂(改一边
// 漏改另一边,客户端扫到老 admin 出的 QR 没事、扫新 web 出的 QR 解析失败)。把 schema
// 与编码逻辑提到 util 包,两边各自 import,保持二者**字节级**一致。
//
// Rust 客户端 (rust_vpn_client_lib_common/src/credentials.rs) 是第三方 — 改这里时
// 务必同步对面;两边都有自家单测保护,不会被无声破坏。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// CredentialsSchemaVersion / CredentialsURLPrefix:与 Rust `VpnPortCredentials` 严格对齐。
const (
	CredentialsSchemaVersion = 1
	CredentialsURLPrefix     = "nanotun-cred://v1?d="
)

// CredentialsSchema 是 credentials QR 的 wire format。
//
// **字段顺序固定**(json tag 不能改):
//   - version    :协议版本;client 反序列化前先校验。
//   - id         :credential UUID v4(36 字符含 "-");客户端 store 的主键。
//   - username   :对应 server 端 users.username,登录帧 LoginReq.username 即填这个。
//   - psk        :明文 PSK,client 加载到 Keychain 后即可销毁这份 wire data。
//   - created_at :unix epoch seconds(UTC),server 端 rotate / user create 那一刻;
//     client 按此排序展示「上次 PSK 更新时间」,以及决定「同 UUID 来了
//     新 QR 时是否真的更新(老 QR created_at 更小则不动)」。
//   - host       :credential 出自哪个服务器的 advertised_host(原 public_host;
//     2026-05-26 migration 0015 改名);**纯展示用**,客户端在
//     list / picker / main view 上始终可见,出错时一眼对得上是哪台机器。
//     允许为空(""):服务器尚未设 advertised_host 时,credentials show 仍能
//     正常发,客户端 UI 显示「未指定」。
//   - server_id  :server 端稳定 UUID,与 profile QR 携带的同名字段对齐;**程序匹配
//     用**:客户端将来可拿它去 ProfileStore 找对应 profile 自动绑定 /
//     警告绑错。生命周期内不变(server_id 由 0014 migrate 写入 app_settings,
//     迁机器 / 改 host 不影响)。允许为空(老 db 跑 migrate 之前)。
//
// 2026-05-26 wire format 扩展:加 host + server_id。**不**bump version — 新字段是
// additive(Rust 端 serde 默认忽略未知字段,老客户端兼容);本次扩展跟"profile QR
// 携带 host + server_id"的设计对齐,credentials 也带,语义对称且为客户端"按服务器
// 分组 / 出错诊断"提供数据基底。
type CredentialsSchema struct {
	Version   uint32 `json:"version"`
	ID        string `json:"id"`
	Username  string `json:"username"`
	PSK       string `json:"psk"`
	CreatedAt int64  `json:"created_at"`
	Host      string `json:"host"`
	ServerID  string `json:"server_id"`
}

// EncodeCredentialsURL 把 credentials 编成 `nanotun-cred://v1?d=<base64url(json)>`。
//
// 失败仅来自 json.Marshal — 我们的 schema 全是基本类型,实际上不可能 fail;留 error
// 是为了将来 schema 演化加 map / interface 时不被迫破坏 caller 签名。
func EncodeCredentialsURL(c *CredentialsSchema) (string, error) {
	if c == nil {
		return "", fmt.Errorf("util: EncodeCredentialsURL nil schema")
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("util: marshal credentials: %w", err)
	}
	return CredentialsURLPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}
