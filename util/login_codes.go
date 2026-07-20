package util

import (
	crand "crypto/rand"
	"encoding/hex"
)

// GenerateID 生成 16 字节十六进制随机 ID,用作 connIDStr / req_id。
//
// crypto/rand 失败时返回空串,调用方应当把空 ID 当作「entropy 故障」处理 ——
// 当前调用点 handleVPNLink 在 connIDStr=="" 时不会注册 connIDMap,等于拒绝该
// 连接进入活跃集合。
func GenerateID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// LoginResp.Code 值。
//
// 历史背景:这些数字最早是 旧集中式后端 WebSocket session_acquire 返回的
// 错误码,nanotun 直接透传给客户端。M0 切到自托管 PSK 模式后 旧后端已彻底
// 下线,但移动端客户端 (iOS/macOS/Rust) 仍按这套数值 + 文案分支去 UI 提示,所以
// 数值保持不变(变了等于强制客户端发版)。新增 code 时统一在 9xx 段,与历史
// 4xx/5xx 分开,便于一眼区分。
//
// 客户端可见文案见 clientLoginMessageForCode;audit_logs action 子类映射见
// auditActionForLoginCode。两边修改务必同步。
const (
	CodeOK               = 0
	CodeTokenInvalid     = 401
	CodeTokenExpired     = 402
	CodeUserNotFound     = 403
	CodeUserBlacklisted  = 404
	CodeVPNExpired       = 405
	CodeSessionLimit     = 406
	CodeKickByAdmin      = 407
	CodeNodeLoginInvalid = 408
	CodeDuplicateJWT     = 409

	// CodePowFailed(P2#16,2026-05-24):VPN 登录前置 PoW(Proof-of-Work)校验失败。
	// 涵盖:client 没发 PoWChallengeReq 直接发 LoginReq、PoWChallenge 签名错、challenge
	// 过期、nonce 不满足难度、challenge 重放、pre-login idle 超时、PoW 出题超频(IP 或全局)等。
	//
	// 对外统一一个 code:**故意不暴露内部细分原因**,避免 attacker 通过响应差异分辨自己
	// 处在哪种限速 / 防御机制下面。audit_logs 记 reason 子标签(`pow.fail.bad_signature`
	// 等),供运维分析。客户端 UI 文案统一「登录请求过于频繁,请稍后再试」或类似友好提示。
	CodePowFailed = 412

	CodeServerError = 500

	// CodePlatformNotAllowed(2026-07-18):该账号被限制只能在特定平台登录,而当前
	// 客户端上报的 platform 不在其白名单内。按顶部约定落在 9xx 段。
	//
	// **策略拒绝,非安全边界**:platform 由客户端自报(编译期写死 / std::env::consts::OS),
	// 技术用户可伪造 —— 仅用于计费 / 分级,不作安全用途。
	//
	// 客户端须把它当**终止码**:停止重连、**不清 token**、提示「此账号不支持在当前
	// 平台使用」。否则会像其它未识别业务码一样退避重连空转。服务端侧不计入 PoW
	// 失败惩罚(正常策略拒绝不该抬高难度 / 触发暴破风控,见 server.go MarkFailure)。
	CodePlatformNotAllowed = 910
)
