package util

import (
	"encoding/binary"
	"errors"
	"io"
)

// 链路帧：2 字节大端长度 L = 整帧去掉前 2 字节后的长度（含 1 字节类型 + 负载），即 L = 1 + len(payload)。

const (
	LinkTypeLoginReq    = 1 // 负载：UTF-8 JSON，LoginReq（含 platform、transport 等）
	LinkTypeLoginResp   = 2 // 负载：UTF-8 JSON，LoginResp
	LinkTypeConvSaltMsg = 3 // 负载：UTF-8 JSON，ConvSaltLite（虚拟 IP、可选 dns_servers_v4 / dns_servers_v6）
	LinkTypeClose       = 4 // 负载：UTF-8 JSON，CloseMsg
	LinkTypeIPPacket    = 5 // 负载：原始 IPv4/IPv6 数据报（从 IP 头开始）
	LinkTypePing        = 6 // 负载：可选（如 nonce）；对端应回 LinkTypePong 并原样回显负载
	LinkTypePong        = 7 // 负载：与对端 Ping 一致（回显）或空
	// LinkTypeTakenOver 网关→老链路：本 session 已被同账号新链路接管（智能模式 reality→hy2 等）。
	// 收到此帧的客户端应静默退出本链路 read/write 任务，**不**触发 on_disconnected / on_close_received，
	// 因为新链路已继承同一虚拟 IP 与 connIDStr，上层 VPN 视角下连续不中断。
	// 负载：UTF-8 JSON，TakenOverMsg（含新 session_id 与新 transport，便于客户端日志/UI 展示）。
	LinkTypeTakenOver = 8

	// 编号 9..14 历史上为 P2P/NAT 穿透 milestone 预留(2026-05-22 land,2026-05-24
	// 砍掉)—— 项目决策走中心化组网,不做 P2P。新加 LinkType 时这些编号可以释放复用,
	// 但需注意:**旧 Rust 客户端不会构造也不会解析**这些 type,server 侧历史上也没有
	// case 分支,收到一律走 default 静默丢弃。若复用,需协议 schema 升级 + 客户端
	// 同步,**不要**默认认为老客户端能识别。
	//
	// ──────────────────────────────────────────────────────────────────────────
	// 下方 RouteAdvertise / RouteApproveStatus 使用编号 **15 / 16**(跳过 9..14
	// 空缺),**不是**复用 P2P 编号 —— 选 15 而非 9 是为了让 9..14 在协议日志 /
	// 抓包工具里保持「未知 type」状态,便于将来一眼区分「P2P 时代遗留误发」与
	// 「新功能未识别」。后续新增 LinkType 默认从 17 开始递增,9..14 仍按 retired
	// 处理,长期不复用,直到 schema major bump。
	// ──────────────────────────────────────────────────────────────────────────
	//
	// P2#12(2026-05-22):subnet route advertise / 审批结果。控制面用,
	// 协议规范见 docs/DESIGN_SUBNET_ROUTES.md。
	//
	// LinkTypeRouteAdvertise:client → server,声明自己能 forward 的 CIDR 列表。
	//   body JSON: util.RouteAdvertise
	// LinkTypeRouteApproveStatus:server → client,通知客户端某 CIDR 的审批状态变化。
	//   body JSON: util.RouteApproveStatus
	LinkTypeRouteAdvertise     = 15
	LinkTypeRouteApproveStatus = 16

	// P2#16(2026-05-24):VPN 登录前置 Proof-of-Work 防护。
	//
	// 协议状态机(server 视角):
	//   1) WS handshake 完成,server 启动 pre-login idle deadline (30s);
	//   2) **首帧** 必须是 LinkTypePoWChallengeReq —— 否则直接 close(CodePowFailed);
	//   3) server 检查 per-IP / 全局出题限速,通过则下发 LinkTypePoWChallenge
	//      (题目元数据 + 签名),失败回 LinkTypeClose;
	//   4) **第二帧** 必须是 LinkTypeLoginReq,且 LoginReq.pow 子字段填好答案;
	//      server 验签 + 数学校验 + 防重放,通过后才走原本的 PSK verify 路径;
	//      期间客户端不允许再发 PoWChallengeReq(状态机一次性,防滥用)。
	//
	// LinkTypePoWChallengeReq:client → server,**body 必须为空**(future-proof:
	//   留空体允许将来加 capability JSON,server 现版本直接忽略 body)。
	// LinkTypePoWChallenge:server → client,body JSON = util.LinkPoWChallenge。
	//
	// 为什么不复用 LinkTypeLoginReq 直接带 pow 子字段就完事?
	//   - 老客户端(不带 pow)直接发 LoginReq,server 检测首帧 type=1 即可识别老版本
	//     拒登(早 fail-fast 比读完 JSON 再判 pow 缺失更早);
	//   - PoW 出题前要做 IP 限速,如果跟 LoginReq 同帧就要解析整个 JSON,放大解析成本。
	LinkTypePoWChallengeReq = 17
	LinkTypePoWChallenge    = 18

	// exit-node 特性(client → server 控制帧):使用方选择「公网出口」。
	//   body JSON = util.EgressSelect。Egress 为空 / "server" → 走 server 自出口(默认/历史行为);
	//   否则为某「已被 admin 批准为出口」的设备 UUIDv4,server 把本会话的公网流量中转给该出口客户端。
	// 登录成功后任意时刻可发(改选出口 / 退回 server)。老客户端不发此帧 → egress 恒为 server,行为不变。
	LinkTypeEgressSelect = 19
	// server → client:EgressSelect 的回执(util.EgressSelectAck),告知选择是否被接受及原因
	// (出口不存在 / 未批准 / 不在线 / exit_allowed=false 等)。
	LinkTypeEgressSelectAck = 20

	// exit-node 选择器:server → client **单向推送**「当前可选出口设备列表」(util.ExitsList)。
	//   - 客户端连上(且 exit_allowed)后,server 主动推一帧初始列表;
	//   - 之后某「在跑出口」设备上线/下线时,server 广播更新一帧 —— 客户端下拉**实时**反映在线出口。
	// 纯推送、无配套查询帧:客户端只听不问。老客户端忽略未知帧类型,无影响。
	LinkTypeExitsList = 21

	// subnet route(SR-M3):server → client **单向推送**「当前可用的已批准子网路由列表」(util.RoutesList)。
	//   - 客户端连上后,server 主动推一帧当前列表(pushInitialRoutesList,推给**所有**客户端——任意用户都可能要访问内网资源);
	//   - admin 改路由批准(/reload?what=routes)后,server 广播更新一帧。
	// 请求方据此把这些 CIDR 装进本机 TUN 路由(引流进隧道),发往这些内网网段的包才会到 server → 子网路由转发(SR-M1)。
	// 纯推送、无配套查询帧;老客户端忽略未知帧类型(22),无影响。与出口列表(ExitsList=21)并列、各自独立。
	LinkTypeRoutesList = 22
)

// MaxLinkFrameBody 单帧 L 的最大值（uint16）
const MaxLinkFrameBody = 65535

// MaxLinkPayload LinkTypeIPPacket 等类型的最大负载长度 = L - 1
const MaxLinkPayload = MaxLinkFrameBody - 1

// MaxPreLoginFrameBody 登录完成前(LoginReq 阶段)允许的最大帧体。
//
// I5: LoginReq JSON 已经在 ParseLoginReqLinkPayload 做了字段长度上限校验
// (Name/Token/TakeoverSecret/DeviceUUID 等),但攻击者可以构造一个 64KB 大的
// LoginReq 帧(只是字段 padding 不行),即使最终解码失败,服务器也已经为该
// 字节流分配了 64KB 缓冲 + 跑 json.Unmarshal,放大成 DoS 资源消耗。
//
// 真实的 LoginReq 即使最长(含 256B token + 128B device_name + 36B uuid + transport
// 字段 + JSON 包装)也很难超过 1KB;放到 4KB 留 4× 余量足够未来扩展(比如加
// reality short_id / hy2 obfs 上报字段)。任何 4KB 之上的「首帧」 都是异常,
// 直接断连。
//
// **登录完成后**(LinkTypeIPPacket 等)恢复 MaxLinkFrameBody 上限,IP 包不受影响。
const MaxPreLoginFrameBody = 4 * 1024

// ReadLinkFrame 读取一帧：先 2 字节 L，再读 L 字节得到 type + payload。
func ReadLinkFrame(r io.Reader) (typ byte, payload []byte, err error) {
	return readLinkFrameLimited(r, MaxLinkFrameBody)
}

// ReadLinkFramePreLogin 在登录完成之前调用,限制单帧 ≤ MaxPreLoginFrameBody。
//
// 调用点:handleVPNLink 读首帧时 ParseLoginReqLinkPayload 之前。一旦 LoginResp
// 下发完成,后续帧用普通 ReadLinkFrame 即可(因为 IP 包合法地可以接近 64KB)。
func ReadLinkFramePreLogin(r io.Reader) (typ byte, payload []byte, err error) {
	return readLinkFrameLimited(r, MaxPreLoginFrameBody)
}

func readLinkFrameLimited(r io.Reader, maxBody int) (typ byte, payload []byte, err error) {
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return 0, nil, err
	}
	L := binary.BigEndian.Uint16(lb[:])
	if L < 1 {
		return 0, nil, errors.New("link frame: length < 1")
	}
	if int(L) > maxBody {
		return 0, nil, errors.New("link frame: length too large")
	}
	body := make([]byte, L)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return body[0], body[1:], nil
}

// WriteLinkFrame 写入一帧：L = 1 + len(payload)，再写 type 与 payload。
// 单次 Write 写出完整帧，便于 WebSocket 等「按消息切段」的传输与 smux 流式语义一致。
func WriteLinkFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > MaxLinkPayload {
		return errors.New("link frame: payload too large")
	}
	L := uint16(1 + len(payload))
	buf := make([]byte, 2+int(L))
	binary.BigEndian.PutUint16(buf[:2], L)
	buf[2] = typ
	copy(buf[3:], payload)
	_, err := w.Write(buf)
	return err
}
