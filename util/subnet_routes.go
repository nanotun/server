package util

// P2#12(2026-05-22):subnet route advertise wire types。
//
// 这是 LinkType 15 / 16 的 JSON body 结构,server 与 client 共同遵守。
// 客户端实现见 docs/DESIGN_SUBNET_ROUTES.md。

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// RouteSchemaCurrent 是 wire schema 版本号;不兼容变更 → 自增 + bump server 校验。
const RouteSchemaCurrent = 1

// RouteAdvertise 是客户端 → server 的 LinkTypeRouteAdvertise(15) JSON body。
//
// 客户端在登录成功后任何时刻都可以发(更新声明);server 把每条 cidr upsert 到
// subnet_routes 表(status=pending,等 admin 审批)。已 approved 的条目若客户端
// 不再上报,server 不会自动 demote —— 路由生效与否由 admin 显式控制,避免短暂网络
// 抖动让 approved 状态丢失。
type RouteAdvertise struct {
	Schema int      `json:"schema"`
	Routes []string `json:"routes"` // CIDR 文本列表;空 / nil 视作"撤回所有未审批的路由声明"
	// Exit（exit-node 特性）：本帧是否为「出口节点」声明。
	//   - false（默认/老客户端）：Routes 走 NormalizeAdvertisedCIDR，**拒绝** 0/0、::/0；
	//   - true：本设备自荐为公网出口，Routes 允许携带 0.0.0.0/0 / ::/0（走 NormalizeExitAdvertisedCIDR）。
	// 仍需 admin 审批后才真正承载流量。空 Routes + Exit=true 语义同空 Routes（撤回 pending）。
	Exit bool `json:"exit,omitempty"`
}

// RouteApproveStatus 是 server → client 的 LinkTypeRouteApproveStatus(16) JSON body。
//
// server 在 admin 审批后主动推一帧给目标 device,告诉它哪些 CIDR 通过 / 拒绝。
// 客户端可据此提示 UI("等待管理员审批" → "已批准")。也可以在 LoginResp 之后
// server 主动 push 一次当前状态快照,让重连 client 同步。
type RouteApproveStatus struct {
	Schema  int                `json:"schema"`
	Updated []RouteStatusEntry `json:"updated"`
}

// RouteStatusEntry 描述一条 CIDR 的当前状态。
//
// Status 取值:"pending" / "approved" / "rejected"。
// Reason 仅在 rejected 时有值(可选,给客户端 UI 提示用)。
// At 是服务端的 Unix 秒,客户端用于显示时间戳。
type RouteStatusEntry struct {
	CIDR   string `json:"cidr"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	At     int64  `json:"at,omitempty"`
}

// Status 取值常量,与 store/subnet_routes.go 共享。
const (
	RouteStatusPending  = "pending"
	RouteStatusApproved = "approved"
	RouteStatusRejected = "rejected"
)

// MarshalRouteAdvertise / Parse 配套。
func MarshalRouteAdvertise(routes []string) ([]byte, error) {
	return json.Marshal(RouteAdvertise{Schema: RouteSchemaCurrent, Routes: routes})
}

func ParseRouteAdvertise(data []byte) (*RouteAdvertise, error) {
	var ra RouteAdvertise
	if err := json.Unmarshal(data, &ra); err != nil {
		return nil, fmt.Errorf("parse route advertise: %w", err)
	}
	if ra.Schema != RouteSchemaCurrent {
		return nil, fmt.Errorf("route advertise schema = %d, want %d", ra.Schema, RouteSchemaCurrent)
	}
	return &ra, nil
}

// MarshalRouteApproveStatus / Parse 配套。
func MarshalRouteApproveStatus(updated []RouteStatusEntry) ([]byte, error) {
	return json.Marshal(RouteApproveStatus{Schema: RouteSchemaCurrent, Updated: updated})
}

func ParseRouteApproveStatus(data []byte) (*RouteApproveStatus, error) {
	var rs RouteApproveStatus
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse route approve status: %w", err)
	}
	if rs.Schema != RouteSchemaCurrent {
		return nil, fmt.Errorf("route approve status schema = %d, want %d", rs.Schema, RouteSchemaCurrent)
	}
	return &rs, nil
}

// advertisableSubnetRanges 是允许作为**子网路由**(RouteAdvertise.Exit=false 帧)宣告的私有/保留网段白名单。
//
// 第八轮深扫 MED —— 为什么必须限私有段:子网路由的语义是「宣告方本机 LAN 背后可达的内网段」,数据面把它当
// **私有组网连通**处理:排在 user 出口闸(exit_allowed)**之前**、且只过 user-kind ACL、**不过出口 ACL**
// (见 cmd/nanotund/acl_runtime.go 与 server.go 转发顺序)。因此若放任宣告**公网** CIDR,一条被 admin 批准的
// 公网子网路由就成了**绕过 exit_allowed + 出口 ACL 的隐形出口**(confused-deputy);而 `0.0.0.0/1`+`128.0.0.0/1`
// 这两段 /1 更能在不触发旧「拒 /0」守卫的前提下覆盖整个 IPv4。公网出网有**专门且受出口闸 + 出口 ACL 管控**的
// 出口节点通道(Exit=true / NormalizeExitAdvertisedCIDR),故这里把子网路由收敛到私有/保留范围,让它与其名义
// (内网段)和 ACL 模型一致。已在库里的历史 approved 条目不因本校验回溯失效(仅约束新上报的宣告)。
var advertisableSubnetRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),  // RFC6598 CGNAT(mesh/隧道常用)
	netip.MustParsePrefix("169.254.0.0/16"), // IPv4 link-local
	netip.MustParsePrefix("fc00::/7"),       // IPv6 ULA
	netip.MustParsePrefix("fe80::/10"),      // IPv6 link-local
}

// prefixWithinAdvertisable 判断 p(已 mask 的网络前缀)是否**整段**落在某个允许的私有/保留范围内:
// 存在白名单 super-prefix S 使 S.Contains(p.Addr()) 且 p.Bits() >= S.Bits()(p 至少与 S 一样具体 → p ⊆ S)。
// 跨地址族由 netip.Prefix.Contains 天然返回 false;p 广于 S(bits 更小)则被 p.Bits() >= s.Bits() 挡下。
func prefixWithinAdvertisable(p netip.Prefix) bool {
	addr := p.Addr()
	for _, s := range advertisableSubnetRanges {
		if s.Contains(addr) && p.Bits() >= s.Bits() {
			return true
		}
	}
	return false
}

// NormalizeAdvertisedCIDR 把客户端送上来的**子网路由** CIDR 文本归一化:
//   - 必须 parse 成有效的 netip.Prefix;
//   - 拒绝 ::/0 与 0.0.0.0/0(避免误声明"全网代理");
//   - 第八轮深扫 MED:必须**整段落在私有/保留范围**(见 advertisableSubnetRanges)——公网 CIDR、以及
//     `0.0.0.0/1`+`128.0.0.0/1` 这类覆盖全网的宽段一律拒;公网出网请走出口节点(Exit=true);
//   - 把网络地址 mask 化(192.168.1.5/24 → 192.168.1.0/24)避免重复条目。
//
// 返回归一后的字符串 + 错误。
func NormalizeAdvertisedCIDR(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("empty cidr")
	}
	p, err := netip.ParsePrefix(in)
	if err != nil {
		return "", fmt.Errorf("invalid cidr %q: %w", in, err)
	}
	if p.Bits() == 0 {
		return "", errors.New("cidr /0 not allowed(请勿声明全网路由)")
	}
	masked := p.Masked()
	if !prefixWithinAdvertisable(masked) {
		// 收敛到私有/保留段:公网/宽段子网路由会绕过 exit_allowed + 出口 ACL(见 advertisableSubnetRanges)。
		return "", fmt.Errorf("cidr %q not allowed: subnet routes must be private/reserved "+
			"(RFC1918 / CGNAT 100.64.0.0/10 / ULA fc00::/7 / link-local); use an exit node for public egress", masked)
	}
	return masked.String(), nil
}

// ExitDefaultRouteV4 / ExitDefaultRouteV6 是「出口节点」声明用的全网路由（归一形态）。
// 出口能力即「我能 forward 任意目的地（公网）」，对应 0.0.0.0/0 与 ::/0。
const (
	ExitDefaultRouteV4 = "0.0.0.0/0"
	ExitDefaultRouteV6 = "::/0"
)

// IsExitDefaultRoute 判断一条已归一 CIDR 是否为出口全网路由（0.0.0.0/0 或 ::/0）。
func IsExitDefaultRoute(cidr string) bool {
	c := strings.TrimSpace(cidr)
	return c == ExitDefaultRouteV4 || c == ExitDefaultRouteV6
}

// NormalizeExitAdvertisedCIDR 是 [NormalizeAdvertisedCIDR] 的出口语境变体：**允许** 0/0 与 ::/0
// （出口节点声明「我能 forward 全网」），其余规则一致（须可解析、网络地址 mask 化）。
//
// 仅在 RouteAdvertise.Exit=true 的帧里对每条 CIDR 调用；非出口帧仍走 [NormalizeAdvertisedCIDR]
// 拒绝 /0，防普通设备误声明全网代理。
func NormalizeExitAdvertisedCIDR(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("empty cidr")
	}
	p, err := netip.ParsePrefix(in)
	if err != nil {
		return "", fmt.Errorf("invalid cidr %q: %w", in, err)
	}
	return p.Masked().String(), nil
}
