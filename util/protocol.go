package util

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// CloseMsg 关闭连接时发送的原因消息
type CloseMsg struct {
	Code   int    `json:"code"`   // 0=正常关闭,非 0=被踢(对应 util.Code* 登录错误码)
	Reason string `json:"reason"` // 关闭原因
}

// TakenOverMsg 链路类型 8（LinkTypeTakenOver）的负载：网关通知老链路被同账号新链路接管。
// 收到本消息的客户端应静默关闭本链路任务，**不**触发 on_disconnected / on_close_received。
// 字段供日志/UI 诊断使用，全部可选；未来可在不破坏兼容性的前提下追加字段。
type TakenOverMsg struct {
	NewSessionID string `json:"new_session_id,omitempty"` // 新 session 的 conn_id（与老的相同，沿用语义）
	NewTransport string `json:"new_transport,omitempty"`  // 新链路的传输标签，如 "hy2" / "reality"
}

// ConvSaltLite 链路类型 3 的 JSON：虚拟 IP 下发表，及可选 DNS（分 IPv4 / IPv6；旧版 dns_servers 仍可读）
type ConvSaltLite struct {
	VirtualIPAssignments []VirtualIPAssignment `json:"virtual_ip_assignments,omitempty"`
	DNSServersV4         []string              `json:"dns_servers_v4,omitempty"`
	DNSServersV6         []string              `json:"dns_servers_v6,omitempty"`
	// MagicDNSSuffix 是 server MagicDNS 的 domain_suffix（如 "lan"），仅在 magic_dns.enabled 且 listen_port==53 时下发。
	// 客户端（尤其 mac meshOnly：隧道 DNS 仅作附加 resolver，magic 名字易漏到物理网卡）据此把 *.<suffix> 强制走隧道 DNS。
	// 空 = 未启用 / 非 53 端口（此时 server 也不给客户端 prepend gateway DNS，见 magicDNSExtraDNS）。
	MagicDNSSuffix string `json:"magic_dns_suffix,omitempty"`
	// DeviceName 是 server 端**去重后**的最终设备名（每用户唯一，重名会被追加 "-N"，见 store.UpsertDevice）。
	// 客户端据此**回显真实名字**（Tailscale 式）——本机上报 "homepi" 但被去重成 "homepi-1" 时，UI 显示服务端的最终名，
	// 避免与出口/子网下拉、admin 后台看到的名字不一致。空 = 匿名会话（无 device_uuid / 写库失败），客户端回退本地名。
	DeviceName string `json:"device_name,omitempty"`
}

// 链路登录常用 transport 取值（客户端上报；服务端可记入会话或下发策略）
const (
	LinkTransportTCP       = "tcp"       // 历史：明文 TCP 直连帧（已弃用，数据面为 WS）
	LinkTransportWebSocket = "websocket" // HTTP Upgrade 后 WS Binary 承载链路帧
)

// LoginReq 客户端登录请求
//
// 智能模式（auto）下的「热切换接管」：
//   - Purpose == "" 或 "primary"：常规登录路径（旧行为）。
//   - Purpose == "takeover"：网关将根据 TakeoverSessionID 找到老 session，
//     校验 TakeoverSecret 一致后，复用其虚拟 IP 与 TunChan 交给本次新链路，
//     从而做到底层传输切换（如 reality → hy2）对上层零中断。
//
// PSK 自托管模式下:Token 字段实际承载 PSK 明文,服务端用 argon2id verify;
// Name/Password 仅历史协议保留(老客户端兼容),新版客户端可只填 Name+Token。
type LoginReq struct {
	Name      string `json:"name"`                // 用户名
	Token     string `json:"token,omitempty"`     // PSK 明文(自托管模式核心字段)
	Type      string `json:"type"`                // 类型（如 client、admin 等）
	Platform  string `json:"platform"`            // 平台（如 windows、linux、macos、ios、android 等）
	Transport string `json:"transport,omitempty"` // 本次会话传输协议，如 tcp、kcp、ws（遗留）

	// P3-d(2026-05-22):历史的 password 字段已从 wire 上下架。
	// 老客户端如果仍在 JSON 里上送 "password":"...",encoding/json 会忽略未知字段,
	// 不影响向后兼容;新版客户端禁止再写该字段。
	// 任何残留 "password" 内容只可能 leak 到 server 端 logrus,不再进入业务逻辑;
	// 保护它的最稳妥方法是从 wire schema 上彻底拿掉。

	// Purpose 区分常规登录 / 接管登录；空串等价于 "primary"。
	Purpose string `json:"purpose,omitempty"`
	// TakeoverSessionID 仅 Purpose=="takeover" 时使用：等于老 LoginResp.SessionID。
	TakeoverSessionID string `json:"takeover_session_id,omitempty"`
	// TakeoverSecret 仅 Purpose=="takeover" 时使用：等于老 LoginResp.TakeoverSecret。
	// 与 token 解耦，token 刷新不影响接管能力。
	TakeoverSecret string `json:"takeover_secret,omitempty"`

	// DeviceUUID 是客户端首次启动时生成、随后持久化保存的稳定 UUID（M0 PSK 模式新增）。
	// 用于在 nanotun 侧把同一物理设备的多次登录归一到同一 device 行，并以此持久化 vIP 租约。
	// 老版本客户端可能为空，此时服务端会回退到「按 (user, conn_id) 分配」的临时策略。
	DeviceUUID string `json:"device_uuid,omitempty"`
	// DeviceName 是用户给设备起的名字（如 "Wenhai's MacBook"），用于 admin 后台展示，可空。
	DeviceName string `json:"device_name,omitempty"`

	// Pow(P2#16,2026-05-24):前置 Proof-of-Work 答案。
	//
	// 服务端先在 WS 上发 LinkTypePoWChallenge(题目),客户端解出 nonce 后,
	// 把题目原元数据 + nonce 整体填入本字段,再随 LoginReq 提交。
	//
	// **始终必填**:server 决策永远启用 PoW(没有 enabled=false 开关),即使是
	// LoginReq.Type=admin 或测试客户端也要先解题再登录。`LoginReqPoW` 详细字段
	// 注释见结构体定义。
	//
	// 兼容:老客户端不会构造该字段,LoginReq 中 omitempty 缺失 → server 端按
	// "首帧不是 PoWChallengeReq" 路径处理,直接 close(CodePowFailed)。
	Pow LoginReqPoW `json:"pow,omitempty"`
}

// LoginReqPoW 是 LoginReq.Pow 子字段,装 PoW 的题目元数据 + 解出的 nonce。
//
// 前 5 字段必须**原样**复制 server 下发的 LinkPoWChallenge,任一字段被改动都会
// 让 server 端 HMAC 验签失败 → 拒登。Nonce 是客户端找到的解。
//
// 字段命名与 LinkPoWChallenge 对齐(都用 snake_case),便于 client 直接结构体复制。
type LoginReqPoW struct {
	ChallengeID string `json:"cid,omitempty"`        // 服务端下发的 challenge_id (base64 url, ~22 chars)
	Salt        string `json:"salt,omitempty"`       // base64 std 16B,服务端下发原样
	Difficulty  int    `json:"difficulty,omitempty"` // 服务端下发难度(bit)
	ExpiresAt   int64  `json:"expires_at,omitempty"` // 服务端下发过期 unix 秒
	Signature   string `json:"signature,omitempty"`  // 服务端 HMAC base64 std,**禁止修改**
	Nonce       uint64 `json:"nonce,omitempty"`      // 客户端求得的解(make sha256 前导零 ≥ difficulty)
}

// LinkPoWChallenge 是 LinkTypePoWChallenge(server → client)的 JSON 负载。
// 客户端解出 nonce 后,把这里的 5 字段 + nonce 一起塞进 LoginReq.Pow 提交。
type LinkPoWChallenge struct {
	ChallengeID string `json:"cid"`
	Salt        string `json:"salt"`
	Difficulty  int    `json:"difficulty"`
	ExpiresAt   int64  `json:"expires_at"`
	Signature   string `json:"signature"`
}

// PurposePrimary / PurposeTakeover：LoginReq.Purpose 取值常量（空串等价于 PurposePrimary）。
const (
	PurposePrimary  = "primary"
	PurposeTakeover = "takeover"
)

// LoginResp 服务端登录响应
//
// SessionID 与 TakeoverSecret 在常规（primary）登录成功时下发，客户端持有后
// 可用于将来基于另一条传输链路的接管登录。接管登录时新 session 继承老 session
// 的 SessionID（即 connIDStr 不变）与 TakeoverSecret，避免链式接管失败。
type LoginResp struct {
	Code    int    `json:"code"`              // 状态码：0 成功，非 0 失败
	Message string `json:"message"`           // 消息描述
	UserID  string `json:"user_id,omitempty"` // 登录成功时返回用户 ID

	// SessionID 等于网关侧 connIDStr。客户端在做 takeover 时填入 LoginReq.TakeoverSessionID。
	SessionID string `json:"session_id,omitempty"`
	// TakeoverSecret 32 字节随机 nonce 的十六进制（64 字符）。客户端做 takeover 时填入
	// LoginReq.TakeoverSecret，服务端用 subtle.ConstantTimeCompare 校验。
	TakeoverSecret string `json:"takeover_secret,omitempty"`
}

// TunPacket 池化 TUN 包：Buf 来自 tunReadBufPool，消费者用完后应归还 Buf
type TunPacket struct {
	Buf []byte
	N   int
}

// VirtualIPAssignment 一项虚拟 IP 下发：虚拟地址及网段信息（JSON 下发给客户端；TunChan 仅服务端内存用）
type VirtualIPAssignment struct {
	VirtualIP string          `json:"virtual_ip"`        // 服务端分配的虚拟 IP
	Mask      string          `json:"mask,omitempty"`    // 子网掩码
	Gateway   string          `json:"gateway,omitempty"` // 网关
	TunChan   chan *TunPacket `json:"-"`                 // TUN 写入通道（池化包），供 TUN 读线程 demux
}

// MarshalLoginReqJSON 链路 LinkTypeLoginReq 的 JSON 负载。
//
// P3-d:password 参数已 deprecated,内部不再写入 JSON;调用方应传空串。
// 函数签名保留 password 形参是为了客户端代码切换平滑(避免一次性大改),
// 但任何非空 password 都会被静默丢弃,不会落到 wire 上。
func MarshalLoginReqJSON(name, password, token, typ, platform, transport string) ([]byte, error) {
	_ = password // P3-d:故意丢弃
	msg := LoginReq{
		Name:      name,
		Token:     token,
		Type:      typ,
		Platform:  platform,
		Transport: transport,
	}
	return json.Marshal(msg)
}

// MarshalLoginReqWithDeviceJSON 是 MarshalLoginReqJSON 的扩展版（M0 新增）。
// 客户端在 PSK 模式下应改用本函数，传入稳定的 deviceUUID 与可选的 deviceName，
// 以便服务端持久化设备信息和 vIP 租约。任一字段为空则按老协议处理。
//
// P3-d:password 参数同样 deprecated 并被丢弃。
func MarshalLoginReqWithDeviceJSON(name, password, token, typ, platform, transport, deviceUUID, deviceName string) ([]byte, error) {
	_ = password
	msg := LoginReq{
		Name:       name,
		Token:      token,
		Type:       typ,
		Platform:   platform,
		Transport:  transport,
		DeviceUUID: deviceUUID,
		DeviceName: deviceName,
	}
	return json.Marshal(msg)
}

// MarshalLoginRespJSON 链路 LinkTypeLoginResp 的裸 JSON
func MarshalLoginRespJSON(code int, message, userID string) ([]byte, error) {
	return json.Marshal(LoginResp{Code: code, Message: message, UserID: userID})
}

// MarshalLoginReqTakeoverJSON 构造 PURPOSE_TAKEOVER 的 LoginReq JSON。
// 用于"热切换"路径：客户端在已经有一个 primary 会话的情况下，
// 用 takeoverSessionID + takeoverSecret 发起第二个连接接管原会话。
// 当 takeoverSessionID 与 takeoverSecret 任一为空时，行为仍然合法（server 会在
// handleTakeoverLogin 中用空值校验失败后拒绝），用以做协议兼容性回归。
func MarshalLoginReqTakeoverJSON(name, password, token, typ, platform, transport, takeoverSessionID, takeoverSecret string) ([]byte, error) {
	_ = password // P3-d:已下架,丢弃
	msg := LoginReq{
		Name:              name,
		Token:             token,
		Type:              typ,
		Platform:          platform,
		Transport:         transport,
		Purpose:           PurposeTakeover,
		TakeoverSessionID: takeoverSessionID,
		TakeoverSecret:    takeoverSecret,
	}
	return json.Marshal(msg)
}

// MarshalLoginRespFullJSON 同 MarshalLoginRespJSON，但额外携带 session_id 和 takeover_secret，
// 用于智能模式 takeover：primary 登录时 server 下发这两个字段，客户端缓存后用于将来发起 takeover login。
// 当 sessionID/takeoverSecret 为空时，序列化结果与 MarshalLoginRespJSON 一致（omitempty）。
func MarshalLoginRespFullJSON(code int, message, userID, sessionID, takeoverSecret string) ([]byte, error) {
	return json.Marshal(LoginResp{
		Code:           code,
		Message:        message,
		UserID:         userID,
		SessionID:      sessionID,
		TakeoverSecret: takeoverSecret,
	})
}

// MarshalCloseJSON 链路 LinkTypeClose 的裸 JSON
func MarshalCloseJSON(code int, reason string) ([]byte, error) {
	return json.Marshal(CloseMsg{Code: code, Reason: reason})
}

// MarshalTakenOverJSON 链路 LinkTypeTakenOver 的裸 JSON
func MarshalTakenOverJSON(newSessionID, newTransport string) ([]byte, error) {
	return json.Marshal(TakenOverMsg{NewSessionID: newSessionID, NewTransport: newTransport})
}

// MarshalLinkPoWChallengeJSON 链路 LinkTypePoWChallenge 的 JSON 负载。
// server → client 出题时调用。
func MarshalLinkPoWChallengeJSON(cid, salt string, difficulty int, expiresAt int64, signature string) ([]byte, error) {
	return json.Marshal(LinkPoWChallenge{
		ChallengeID: cid,
		Salt:        salt,
		Difficulty:  difficulty,
		ExpiresAt:   expiresAt,
		Signature:   signature,
	})
}

// ParseLinkPoWChallengePayload 解析 server 下发的 LinkTypePoWChallenge 负载。
// 客户端用,server 不调用。
func ParseLinkPoWChallengePayload(data []byte) (*LinkPoWChallenge, error) {
	var c LinkPoWChallenge
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ParseTakenOverLinkPayload 解析 LinkTypeTakenOver 的 JSON；空负载也返回零值（不报错）。
func ParseTakenOverLinkPayload(data []byte) (*TakenOverMsg, error) {
	var m TakenOverMsg
	if len(data) == 0 {
		return &m, nil
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// AssignmentsWireJSON 生成可序列化的虚拟 IP 列表（去掉 TunChan）
func AssignmentsWireJSON(in []VirtualIPAssignment) []VirtualIPAssignment {
	if len(in) == 0 {
		return nil
	}
	out := make([]VirtualIPAssignment, len(in))
	for i := range in {
		out[i] = in[i]
		out[i].TunChan = nil
	}
	return out
}

// SanitizeDNSServers 去掉空白与空串，只保留合法 IP（IPv4 或 IPv6），用于兼容旧字段 dns_servers
func SanitizeDNSServers(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		out = append(out, ip.String())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SanitizeDNSServersV4 只保留合法 IPv4 文本
func SanitizeDNSServersV4(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			continue
		}
		out = append(out, ip.To4().String())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SanitizeDNSServersV6 只保留合法 IPv6 文本（不含 IPv4 映射）
func SanitizeDNSServersV6(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() != nil {
			continue
		}
		out = append(out, ip.String())
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func splitDNSByIPVersion(all []string) (v4, v6 []string) {
	for _, s := range all {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, ip.To4().String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	return v4, v6
}

// ConvSaltEffectiveDNS 合并 v4+v6 顺序（供 resolvectl 等一次写入）
func ConvSaltEffectiveDNS(lite *ConvSaltLite) []string {
	if lite == nil {
		return nil
	}
	n := len(lite.DNSServersV4) + len(lite.DNSServersV6)
	if n == 0 {
		return nil
	}
	out := make([]string, 0, n)
	out = append(out, lite.DNSServersV4...)
	out = append(out, lite.DNSServersV6...)
	return out
}

// MarshalConvSaltLiteJSON 链路 LinkTypeConvSaltMsg 的裸 JSON（dnsV6 仅应在服务端已启用 IPv6 隧道时传入）。
// magicSuffix：MagicDNS domain_suffix（启用且 :53 时传，否则空串 → omitempty 不下发）。
// deviceName：server 去重后的最终设备名（供客户端回显；空串 → omitempty 不下发，客户端回退本地名）。
func MarshalConvSaltLiteJSON(assignments []VirtualIPAssignment, dnsV4, dnsV6 []string, magicSuffix, deviceName string) ([]byte, error) {
	v4 := SanitizeDNSServersV4(dnsV4)
	v6 := SanitizeDNSServersV6(dnsV6)
	lite := ConvSaltLite{
		VirtualIPAssignments: AssignmentsWireJSON(assignments),
		DNSServersV4:         v4,
		DNSServersV6:         v6,
		MagicDNSSuffix:       strings.TrimSpace(magicSuffix),
		DeviceName:           strings.TrimSpace(deviceName),
	}
	return json.Marshal(lite)
}

// LoginReq 字段长度上限。链路层 MaxLinkPayload=65534 字节本身已经限死单帧体积,
// 但 JSON 反序列化后单字段仍可以接近 64KB —— 后续走 argon2 verify / DB upsert /
// 内存 connIDStr lookup 这条链 64KB 字符串到处搬运也是浪费。这里在 parse 后
// 显式校验每个字段长度,异常请求第一时间拒绝,日志方便排查恶意客户端。
//
// 合理上限按字段语义给:
//   - Name(用户名):128。RFC 5322 email local-part 上限 64,加 emoji 等容错给 128;
//   - Token(PSK 明文):256。PSK 推荐 ≥16 字节,256 已足够 paranoia 密码长度;
//   - TakeoverSecret:64(hex 32 字节);
//   - TakeoverSessionID:64(util.GenerateID 输出长度上限);
//   - DeviceUUID:48(RFC 4122 是 36 字符,加大小写 + 容错给 48);
//   - DeviceName:128(用户友好名,通常 < 64);
//   - Platform / Transport / Purpose:32(枚举字符串,实际值都 < 16)。
const (
	maxLoginReqName              = 128
	maxLoginReqToken             = 256
	maxLoginReqTakeoverSecret    = 64
	maxLoginReqTakeoverSessionID = 64
	maxLoginReqDeviceUUID        = 48
	maxLoginReqDeviceName        = 128
	maxLoginReqShortEnum         = 32

	// P2#16:PoW 字段长度上限。每个字段都有自然边界(base64 编码长度可估算),
	// 这里给余量是为了未来微调算法参数不破协议。
	//
	// 单帧已经被 MaxPreLoginFrameBody=4KB 限死,Pow 子字段总长 ~400 字节,
	// LoginReq JSON 整体仍远小于上限。
	maxLoginReqPowCID       = 64 // base64 url 16B = 22 字符,留余量给将来 24B/32B
	maxLoginReqPowSalt      = 32 // base64 std 16B = 24 字符(含 padding)
	maxLoginReqPowSignature = 64 // base64 std HMAC-SHA256 32B = 44 字符
)

// ParseLoginReqLinkPayload 解析 LinkTypeLoginReq 的 JSON 负载,并对每个字段做长度
// 上限校验,防御恶意客户端塞超长字段。返回的 error 已经面向运维,日志直接显示足够。
func ParseLoginReqLinkPayload(data []byte) (*LoginReq, error) {
	var req LoginReq
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	if n := len(req.Name); n > maxLoginReqName {
		return nil, fmt.Errorf("login_req: name 字段过长(%d > %d)", n, maxLoginReqName)
	}
	if n := len(req.Token); n > maxLoginReqToken {
		return nil, fmt.Errorf("login_req: token 字段过长(%d > %d)", n, maxLoginReqToken)
	}
	if n := len(req.TakeoverSecret); n > maxLoginReqTakeoverSecret {
		return nil, fmt.Errorf("login_req: takeover_secret 字段过长(%d > %d)", n, maxLoginReqTakeoverSecret)
	}
	if n := len(req.TakeoverSessionID); n > maxLoginReqTakeoverSessionID {
		return nil, fmt.Errorf("login_req: takeover_session_id 字段过长(%d > %d)", n, maxLoginReqTakeoverSessionID)
	}
	if n := len(req.DeviceUUID); n > maxLoginReqDeviceUUID {
		return nil, fmt.Errorf("login_req: device_uuid 字段过长(%d > %d)", n, maxLoginReqDeviceUUID)
	}
	if n := len(req.DeviceName); n > maxLoginReqDeviceName {
		return nil, fmt.Errorf("login_req: device_name 字段过长(%d > %d)", n, maxLoginReqDeviceName)
	}
	if n := len(req.Platform); n > maxLoginReqShortEnum {
		return nil, fmt.Errorf("login_req: platform 字段过长(%d > %d)", n, maxLoginReqShortEnum)
	}
	if n := len(req.Transport); n > maxLoginReqShortEnum {
		return nil, fmt.Errorf("login_req: transport 字段过长(%d > %d)", n, maxLoginReqShortEnum)
	}
	if n := len(req.Purpose); n > maxLoginReqShortEnum {
		return nil, fmt.Errorf("login_req: purpose 字段过长(%d > %d)", n, maxLoginReqShortEnum)
	}
	// P2#16:PoW 子字段长度校验。语义校验(签名/数学)在 server PoWService.VerifyPoWProof 做,
	// 这里只挡过长字段防止解析阶段被恶意填充塞内存。
	if n := len(req.Pow.ChallengeID); n > maxLoginReqPowCID {
		return nil, fmt.Errorf("login_req: pow.cid 字段过长(%d > %d)", n, maxLoginReqPowCID)
	}
	if n := len(req.Pow.Salt); n > maxLoginReqPowSalt {
		return nil, fmt.Errorf("login_req: pow.salt 字段过长(%d > %d)", n, maxLoginReqPowSalt)
	}
	if n := len(req.Pow.Signature); n > maxLoginReqPowSignature {
		return nil, fmt.Errorf("login_req: pow.signature 字段过长(%d > %d)", n, maxLoginReqPowSignature)
	}
	return &req, nil
}

// ValidIPPacket 校验负载是否为合理 IPv4/IPv6 数据报（从首字节版本与长度判断）
func ValidIPPacket(p []byte) bool {
	_, ok := IPPacketTotalLen(p)
	return ok
}

// IPPacketTotalLen 返回 IP 报文头部**声明**的总长度(IPv4 Total Length / IPv6 40+PayloadLength),并报告
// p 是否为合理 IP 报文(与 ValidIPPacket 同一判定)。ok=false 时 total 无意义。
func IPPacketTotalLen(p []byte) (total int, ok bool) {
	if len(p) < 1 {
		return 0, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return 0, false
		}
		t := int(binary.BigEndian.Uint16(p[2:4]))
		if t < 20 || t > len(p) {
			return 0, false
		}
		return t, true
	case 6:
		if len(p) < 40 {
			return 0, false
		}
		t := 40 + int(binary.BigEndian.Uint16(p[4:6]))
		if t > len(p) {
			return 0, false
		}
		return t, true
	default:
		return 0, false
	}
}

// TrimIPPacketToTotalLen 把 p 截到其 IP 头声明的总长度,剥掉尾部多余字节——第四轮深扫 LOW:合法 IP 报文之后
// 可能被追加以太填充或**攻击者的隐蔽数据**,而 ValidIPPacket 只要求 total<=len(p)(允许尾随)。截断后下游
// ACL 判定 / 源校验 / 出口 NAT 转发 / TUN 写都只处理真实报文,不把尾随字节转发上公网或投给 mesh 对端。
// 非法 / 无需截断时原样返回(交由调用方先行的 ValidIPPacket 兜底)。
func TrimIPPacketToTotalLen(p []byte) []byte {
	if total, ok := IPPacketTotalLen(p); ok && total < len(p) {
		return p[:total]
	}
	return p
}

// ParseLoginRespLinkPayload 解析 LinkTypeLoginResp 的 JSON
func ParseLoginRespLinkPayload(data []byte) (*LoginResp, error) {
	var r LoginResp
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// convSaltWire 解析用：含旧版 dns_servers
type convSaltWire struct {
	VirtualIPAssignments []VirtualIPAssignment `json:"virtual_ip_assignments,omitempty"`
	DNSServersV4         []string              `json:"dns_servers_v4,omitempty"`
	DNSServersV6         []string              `json:"dns_servers_v6,omitempty"`
	LegacyDNSServers     []string              `json:"dns_servers,omitempty"`
	MagicDNSSuffix       string                `json:"magic_dns_suffix,omitempty"`
	DeviceName           string                `json:"device_name,omitempty"`
}

// ParseConvSaltLiteLinkPayload 解析 LinkTypeConvSaltMsg 的 JSON
func ParseConvSaltLiteLinkPayload(data []byte) (*ConvSaltLite, error) {
	var w convSaltWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, err
	}
	v4 := SanitizeDNSServersV4(w.DNSServersV4)
	v6 := SanitizeDNSServersV6(w.DNSServersV6)
	if len(v4) == 0 && len(v6) == 0 && len(w.LegacyDNSServers) > 0 {
		v4, v6 = splitDNSByIPVersion(SanitizeDNSServers(w.LegacyDNSServers))
	}
	return &ConvSaltLite{
		VirtualIPAssignments: w.VirtualIPAssignments,
		DNSServersV4:         v4,
		DNSServersV6:         v6,
		MagicDNSSuffix:       strings.TrimSpace(w.MagicDNSSuffix),
		DeviceName:           strings.TrimSpace(w.DeviceName),
	}, nil
}

// ParseCloseLinkPayload 解析 LinkTypeClose 的 JSON
func ParseCloseLinkPayload(data []byte) (*CloseMsg, error) {
	var c CloseMsg
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// CloseReasonForKick 生成 CloseMsg.Reason 文本（与历史 WebSocket Close 一致）
func CloseReasonForKick(code int, message string) string {
	if message == "" {
		return fmt.Sprintf("code=%d", code)
	}
	return fmt.Sprintf("code=%d %s", code, message)
}
